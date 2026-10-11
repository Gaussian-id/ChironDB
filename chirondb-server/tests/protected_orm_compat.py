#!/usr/bin/env python3
"""Full existing ORM fixtures over verified TLS on a fresh strict-scope root.

Use the Python environment from requirements-postgres-orm.txt. Build the Rust
fixture with its locked manifest first. Output must be a NEW private directory;
only report.json and redacted logs may be copied into acceptance artifacts.
The secrets/ directory, TLS private keys, and data/ remain private test state.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

import psycopg
from postgres_protected_driver_checks import check_cancellation, check_values


class Lab:
    def __init__(self, args):
        self.args = args
        self.root = args.output.resolve()
        self.root.mkdir(mode=0o700, parents=True)
        self.private = self.root / 'secrets'
        self.private.mkdir(mode=0o700)
        self.data = self.root / 'data'
        self.passwords = []
        self.server = None
        self.server_log = None
        self.shutdowns = []
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith(('CHIRONDB_', 'GAUSSDB_', 'OTEL_'))}
        self.ports = []
        held = []
        try:
            for _ in range(3):
                sock = socket.socket()
                sock.bind(('127.0.0.1', 0))
                held.append(sock)
                self.ports.append(sock.getsockname()[1])
        finally:
            for sock in held:
                sock.close()
        self.base = f'https://127.0.0.1:{self.ports[0]}/v1'
        self.checks = []
        self.driver_results = {}
        self.memory_observations = []

    def redact(self, value):
        for secret in self.passwords:
            value = value.replace(secret, '[REDACTED]')
            value = value.replace(urllib.parse.quote(secret, safe=''), '[REDACTED]')
        return value

    def run(self, name, command, env=None):
        result = subprocess.run([str(x) for x in command], env=env or self.env,
                                capture_output=True, text=True, timeout=180)
        (self.root / f'{name}.log').write_text(self.redact(result.stdout + result.stderr))
        if result.returncode:
            raise RuntimeError(f'{name} failed ({result.returncode}); inspect its redacted log')
        return result.stdout

    def setup(self):
        self.run('init', [self.args.ctl, 'security', 'init', '--data-dir', self.data,
                 '--tenant', 'acme', '--admin', 'admin', '--keyring-out', self.private / 'storage.json',
                 '--admin-key-out', self.private / 'admin.key'])
        self.bearer = (self.private / 'admin.key').read_text().strip()
        self.passwords.append(self.bearer)
        for migration in ['table-authority', 'sql-scopes', 'transaction-authority']:
            self.run(f'migrate-{migration}', [self.args.ctl, 'security', f'migrate-{migration}',
                     '--data-dir', self.data, '--keyring', self.private / 'storage.json'])
        assert (self.data / '.protected-installation').read_text().startswith('CHRNINSTALL6\n')
        if getattr(self.args, 'common_frontier', False):
            self.run('migrate-common-frontier', [self.args.ctl, 'security', 'migrate-common-frontier',
                     '--data-dir', self.data, '--keyring', self.private / 'storage.json'])
            assert (self.data / '.protected-installation').read_text().startswith('CHRNINSTALL7\n')
        self.run('ca', ['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                 '-keyout', self.private / 'ca.key', '-out', self.root / 'ca.pem', '-days', '1',
                 '-subj', '/CN=ChironDB ORM Test CA', '-addext', 'basicConstraints=critical,CA:TRUE',
                 '-addext', 'keyUsage=critical,keyCertSign,cRLSign'])
        self.run('csr', ['openssl', 'req', '-newkey', 'rsa:2048', '-nodes',
                 '-keyout', self.private / 'server.key', '-out', self.root / 'server.csr',
                 '-subj', '/CN=localhost'])
        (self.root / 'server.ext').write_text('basicConstraints=critical,CA:FALSE\n'
                 'keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n'
                 'subjectAltName=IP:127.0.0.1,DNS:localhost\n')
        self.run('certificate', ['openssl', 'x509', '-req', '-in', self.root / 'server.csr',
                 '-CA', self.root / 'ca.pem', '-CAkey', self.private / 'ca.key', '-CAcreateserial',
                 '-out', self.root / 'server.pem', '-days', '1', '-extfile', self.root / 'server.ext'])
        self.tls = ssl.create_default_context(cafile=str(self.root / 'ca.pem'))

    def start(self, label):
        self.server_log = (self.root / f'server-{label}.log').open('w')
        self.server = subprocess.Popen([str(self.args.server.resolve()), '--data-dir', str(self.data),
            '--encryption-keyring-file', str(self.private / 'storage.json'),
            '--tenant-enforcement', 'enforced', '--tls-cert', str(self.root / 'server.pem'),
            '--tls-key', str(self.private / 'server.key'), '--listen-http', f'127.0.0.1:{self.ports[0]}',
            '--listen-grpc', f'127.0.0.1:{self.ports[1]}', '--listen-wire', f'127.0.0.1:{self.ports[2]}'],
            env=self.env, stdout=self.server_log, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and self.server.poll() is None:
            try:
                with urllib.request.urlopen(self.base.removesuffix('/v1') + '/health',
                                             context=self.tls, timeout=1) as response:
                    if response.status == 200:
                        return
            except (OSError, urllib.error.URLError):
                time.sleep(0.1)
        raise RuntimeError('server did not become healthy')

    def stop(self):
        if self.server is not None:
            if self.server.poll() is None:
                self.server.terminate()
            try:
                code = self.server.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.server.kill()
                self.server.wait()
                raise RuntimeError('server shutdown timed out')
            finally:
                self.server = None
                self.server_log.close()
            self.shutdowns.append(code)
            assert code == 0, f'unclean shutdown: {code}'

    def post(self, route, value):
        request = urllib.request.Request(self.base + route, json.dumps(value).encode(), headers={
            'Authorization': 'Bearer ' + self.bearer, 'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, context=self.tls, timeout=20) as response:
            return json.load(response)

    def query(self, sql, mutate=False):
        if mutate:
            revision = self.query('SHOW SECURITY REVISION;')['rows'][0]['revision']
            sql = sql.rstrip(';') + f' IF REVISION {revision};'
        return self.post('/chironql', {'query': sql, 'confirm': True})

    def memory_quiescence(self, label):
        names = ['chirondb_pgwire_session_reserved_bytes',
                 'chirondb_pgwire_session_capacity_bytes',
                 'chirondb_sql_history_reserved_bytes',
                 'chirondb_sql_history_capacity_bytes']
        deadline = time.monotonic() + 5
        while True:
            request = urllib.request.Request(self.base + '/metrics', headers={
                'Authorization': 'Bearer ' + self.bearer})
            with urllib.request.urlopen(request, context=self.tls, timeout=2) as response:
                lines = response.read().decode().splitlines()
            values = {name: float(next(line.split()[1] for line in lines
                                      if line.startswith(name + ' '))) for name in names}
            assert values[names[1]] > 0 and values[names[3]] > 0, values
            if values[names[0]] == 0 and values[names[2]] == 0:
                self.memory_observations.append({'label': label, **values})
                self.checks.append(f'pgwire_memory_quiescent_{label}')
                self.checks.append(f'sql_history_memory_quiescent_{label}')
                return
            assert time.monotonic() < deadline, values
            time.sleep(0.02)

    def credential(self, user):
        users = self.query('SHOW USERS;')['rows']
        principal = next(row['id'] for row in users if row['name'] == user)
        revision = self.query('SHOW SECURITY REVISION;')['rows'][0]['revision']
        issued = self.post('/security/sql-credentials', {'principal': principal, 'expected_revision': revision})
        self.passwords.append(issued['password'])
        (self.private / f'{user}.password').write_text(issued['password'])
        return issued['password']

    def connect(self, user, password):
        return psycopg.connect(host='127.0.0.1', port=self.ports[2], user=user, dbname='gaussdb',
            password=password, sslmode='verify-full', sslrootcert=str(self.root / 'ca.pem'),
            connect_timeout=3, autocommit=True)

    def denied(self, user, password, sql, expected='42501'):
        with self.connect(user, password) as connection:
            try:
                connection.execute(sql).fetchall()
            except psycopg.Error as error:
                assert error.sqlstate == expected, error.sqlstate
            else:
                raise AssertionError('forbidden SQL succeeded')

    def exercise(self):
        self.query('CREATE USER migrator SET DEPARTMENT Engineering SET CLEARANCE INTERNAL;', True)
        self.query('CREATE ROLE migrations;', True)
        self.query('GRANT SCHEMA ON SYSTEM TO ROLE migrations;', True)
        self.query('GRANT ROLE migrations TO USER migrator;', True)
        password = self.credential('migrator')
        env = dict(self.env, CHIRONDB_PG_HOST='127.0.0.1', CHIRONDB_PG_PORT=str(self.ports[2]),
                   CHIRONDB_PG_USER='migrator', CHIRONDB_PG_DATABASE='gaussdb',
                   CHIRONDB_PG_SSLMODE='verify-full', CHIRONDB_PG_SSLROOTCERT=str(self.root / 'ca.pem'),
                   CHIRONDB_PG_PASSWORD_FILE=str(self.private / 'migrator.password'))
        python_output = self.run('python-orm', [sys.executable, Path(__file__).with_name('postgres_orm_compat.py')], env)
        python_result = json.loads(next(line.removeprefix('RESULT_JSON=') for line in python_output.splitlines() if line.startswith('RESULT_JSON=')))
        self.driver_results['python'] = python_result
        env['CHIRONDB_DATABASE_URL'] = (
            f'postgres://migrator:{urllib.parse.quote(password, safe="")}@127.0.0.1:{self.ports[2]}/gaussdb?'
            + urllib.parse.urlencode({'sslmode': 'verify-full', 'sslrootcert': str(self.root / 'ca.pem')}))
        rust_output = self.run('rust-orm', [self.args.rust_fixture.resolve()], env)
        rust_result = json.loads(next(line.removeprefix('RESULT_JSON=') for line in rust_output.splitlines() if line.startswith('RESULT_JSON=')))
        self.driver_results['rust'] = rust_result
        self.checks += ['complete_python_fixture', 'rust_fixture_without_preprovisioned_tables']
        with self.connect('migrator', password) as connection:
            values_result = check_values(connection)
            self.driver_results['typed_values'] = values_result
            cancellation_result = check_cancellation(connection)
            self.driver_results['cancellation'] = cancellation_result
        self.checks += ['psycopg_typed_roundtrips', 'libpq_cancel_and_rollback']
        self.query('CREATE USER reader SET DEPARTMENT Engineering SET CLEARANCE INTERNAL;', True)
        self.query('CREATE ROLE readers;', True)
        self.query('GRANT ROLE readers TO USER reader;', True)
        reader_password = self.credential('reader')
        with self.connect('migrator', password) as connection:
            connection.execute('CREATE TABLE grant_probe (id BIGINT PRIMARY KEY)')
            connection.execute('INSERT INTO grant_probe VALUES (7)')
        self.denied('reader', reader_password, 'SELECT * FROM grant_probe')
        self.query('GRANT READ ON TABLE grant_probe TO ROLE readers;', True)
        with self.connect('reader', reader_password) as connection:
            assert connection.execute('SELECT * FROM grant_probe').fetchall() == [(7,)]
            names = {row[0] for row in connection.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='public'")}
            assert names == {'grant_probe'}, names
            self.query('REVOKE READ ON TABLE grant_probe FROM ROLE readers;', True)
            try:
                connection.execute('SELECT * FROM grant_probe').fetchall()
            except psycopg.Error as error:
                assert error.sqlstate == '28000', error.sqlstate
            else:
                raise AssertionError('stale session published revoked data')
        self.denied('reader', reader_password, 'SELECT * FROM grant_probe')
        self.query('GRANT READ ON TABLE grant_probe TO ROLE readers;', True)
        self.denied('reader', reader_password, 'INSERT INTO grant_probe VALUES (8)')
        with self.connect('migrator', password) as connection:
            connection.execute('ALTER TABLE grant_probe RENAME TO grant_archive')
            connection.execute('CREATE TABLE grant_probe (id BIGINT PRIMARY KEY)')
            connection.execute('INSERT INTO grant_probe VALUES (99)')
        with self.connect('reader', reader_password) as connection:
            assert connection.execute('SELECT * FROM grant_archive').fetchall() == [(7,)]
        self.denied('reader', reader_password, 'SELECT * FROM grant_probe')
        self.query('REVOKE READ ON TABLE grant_archive FROM ROLE readers;', True)
        self.checks += ['sql_only_table_grant', 'catalog_visibility', 'live_revoke', 'fresh_revoke',
                        'readonly_denies_insert', 'rename_preserves_grant', 'replacement_name_denied']
        self.memory_quiescence('initial')
        self.stop()
        self.start('reopen')
        with self.connect('migrator', password) as connection:
            for table, expected in [('orm_accounts', 1), ('sqlx_accounts', 2), ('diesel_accounts', 2),
                                    ('grant_probe', 1), ('driver_types', 3), ('driver_cancel', 1)]:
                assert connection.execute(f'SELECT COUNT(*) FROM {table}').fetchone() == (expected,)
        self.denied('reader', reader_password, 'SELECT * FROM grant_archive')
        self.checks += ['reopen_creator_rights_and_rows', 'reopen_revocation']
        self.memory_quiescence('reopen')
        return {'python': python_result, 'rust': rust_result,
                'typed_values': values_result, 'cancellation': cancellation_result}


def main(args):
    os.umask(0o077)
    lab = Lab(args)
    report = {'passed': False, 'checks': lab.checks, 'drivers': lab.driver_results}
    try:
        lab.setup()
        lab.start('initial')
        report['drivers'] = lab.exercise()
        lab.stop()
        report['encryption'] = json.loads(lab.run('verify-encryption', [args.ctl, 'security', 'verify-encryption', '--data-dir', lab.data, '--keyring', lab.private / 'storage.json']))
        lab.run('verify-audit', [args.ctl, 'security', 'verify-audit', '--data-dir', lab.data,
                               '--keyring', lab.private / 'storage.json'])
        report['passed'] = True
    except Exception as error:
        report['error'] = lab.redact(str(error))
        raise
    finally:
        try:
            lab.stop()
        except Exception as error:
            report['passed'] = False
            report['shutdown_error'] = lab.redact(str(error))
        report['shutdown_codes'] = lab.shutdowns
        report['pgwire_memory'] = lab.memory_observations
        report['sslmode'] = 'verify-full'
        report['identity_mode'] = 'strict-sql-scopes'
        report['binaries'] = {str(path.resolve()): hashlib.file_digest(path.open('rb'), 'sha256').hexdigest()
                              for path in [args.server, args.ctl, args.rust_fixture]}
        (lab.root / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'passed': report['passed'], 'report': str(lab.root / 'report.json')}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', type=Path, required=True)
    parser.add_argument('--ctl', type=Path, required=True)
    parser.add_argument('--rust-fixture', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--common-frontier', action='store_true', help='exercise installation format 7')
    main(parser.parse_args())
