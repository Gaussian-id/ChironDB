#!/usr/bin/env python3
"""Bounded, synthetic protected-authentication checks against real TLS listeners."""
import argparse
import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import hmac
import json
import math
from pathlib import Path
import re
import secrets
import socket
import ssl
import struct
import time
import urllib.error
import urllib.request

import grpc

from security_installation_e2e import InstallationLab


QUERY = 'SHOW CURRENT USER;'
MAX_REPLY = 4 * 1024 * 1024


def read_exact(stream, size):
    if not 0 <= size <= MAX_REPLY:
        raise AssertionError('response exceeds fixture limit')
    data = bytearray()
    while len(data) < size:
        chunk = stream.recv(size - len(data))
        if not chunk:
            raise EOFError('response ended before complete frame')
        data.extend(chunk)
    return bytes(data)


def pg_send(stream, kind, body):
    stream.sendall(kind + struct.pack('!I', len(body) + 4) + body)


def pg_message(stream):
    header = read_exact(stream, 5)
    length = struct.unpack('!I', header[1:])[0]
    if not 4 <= length <= 65536:
        raise AssertionError('invalid PostgreSQL response length')
    return header[:1], read_exact(stream, length - 4)


def pg_code(body):
    return next((field[1:].decode() for field in body.split(b'\0')
                 if field.startswith(b'C')), None)


class AuthDenialLab(InstallationLab):
    def http(self, path, key, body=None):
        headers = {} if key is None else {'Authorization': 'Bearer ' + key}
        if body is not None:
            headers['Content-Type'] = 'application/json'
        request = urllib.request.Request(self.base + path,
            data=None if body is None else json.dumps(body).encode(), headers=headers)
        try:
            response = urllib.request.urlopen(request, context=self.tls, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            data = response.read(MAX_REPLY + 1)
            self.check('HTTP response is bounded', len(data) <= MAX_REPLY)
            self.redacted(data)
            return response.status, data

    def admin_json(self, path, body=None, sensitive=False):
        status, data = self.http(path, self.admin, body)
        self.check('administrator endpoint succeeds: ' + path, status == 200, status)
        result = json.loads(data)
        if sensitive:
            # Issuance is intentionally secret-bearing; retain it only in a mode-0600
            # fixture file, never in records, command arguments, or stdout.
            self.keys['sql_password'] = self.secrets / 'sql-password'
            self.keys['sql_password'].write_text(result['password'])
            self.keys['sql_password'].chmod(0o600)
            self.secret_values.append(result['password'])
        return result

    def redacted(self, data):
        if isinstance(data, str):
            data = data.encode()
        self.check('diagnostic contains no credential', all(
            value.encode() not in data for value in self.secret_values if value))

    def deny(self, state, key):
        for prefix in ['', '/v1']:
            status, body = self.http(prefix + '/chironql', key, {'query': QUERY})
            self.check(prefix + ' HTTP ' + state + ' is unauthenticated',
                       status == 401 and json.loads(body).get('error', {}).get('code')
                       == 'security.unauthenticated', {'status': status})
        status = self.grpc_status(key)
        self.check('gRPC ' + state + ' is unauthenticated', status == 'UNAUTHENTICATED', status)
        with self.tls.wrap_socket(socket.create_connection(
                ('127.0.0.1', self.args.port + 2), timeout=10),
                server_hostname='127.0.0.1') as stream:
            body = self.wpb.WireRequest(request_id=1, api_key=key or '',
                chironql=self.wpb.WireChironQlRequest(query=QUERY)).SerializeToString()
            stream.sendall(struct.pack('!I', len(body)) + body)
            raw = read_exact(stream, struct.unpack('!I', read_exact(stream, 4))[0])
            self.redacted(raw)
            reply = self.wpb.WireResponse.FromString(raw)
            self.check('ChironWire ' + state + ' is unauthenticated',
                       reply.error_code == 'UNAUTHENTICATED' and
                       json.loads(reply.error_details_json)['code'] == 'security.unauthenticated',
                       reply.error_code)

    def grpc_status(self, key):
        try:
            self.pbgrpc.ChironDbStub(self.channel).ExecuteQuery(
                self.pb.ChironQlRequest(query=QUERY),
                metadata=[] if key is None else [('authorization', 'Bearer ' + key)], timeout=10)
            return 'OK'
        except grpc.RpcError as error:
            # Check the status, never accept connection failures as security denials.
            self.redacted(error.details())
            return error.code().name

    def pg_login(self, username, password, state, allowed):
        stream = socket.create_connection(('127.0.0.1', self.args.port + 2), timeout=10)
        try:
            stream.sendall(struct.pack('!II', 8, 80877103))
            self.check('PostgreSQL accepts SSLRequest', read_exact(stream, 1) == b'S')
            stream = self.tls.wrap_socket(stream, server_hostname='127.0.0.1')
            startup = struct.pack('!I', 196608) + b'user\0' + username.encode() + b'\0database\0chiron\0\0'
            stream.sendall(struct.pack('!I', len(startup) + 4) + startup)
            kind, body = pg_message(stream)
            self.check('PostgreSQL requires SCRAM', kind == b'R' and
                       body == struct.pack('!I', 10) + b'SCRAM-SHA-256\0\0')
            nonce = secrets.token_urlsafe(18)
            first = 'n=' + username.replace('=', '=3D').replace(',', '=2C') + ',r=' + nonce
            initial = ('n,,' + first).encode()
            pg_send(stream, b'p', b'SCRAM-SHA-256\0' + struct.pack('!I', len(initial)) + initial)
            kind, body = pg_message(stream)
            self.check('PostgreSQL supplies SCRAM challenge', kind == b'R' and body[:4] == struct.pack('!I', 11))
            challenge = body[4:].decode()
            attrs = dict(part.split('=', 1) for part in challenge.split(','))
            iterations = int(attrs['i'])
            self.check('SCRAM challenge is bounded and extends nonce',
                       1 <= iterations <= 1_000_000 and attrs['r'].startswith(nonce) and len(attrs['r']) > len(nonce))
            salt = base64.b64decode(attrs['s'], validate=True)
            salted = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
            client_key = hmac.digest(salted, b'Client Key', 'sha256')
            final = 'c=biws,r=' + attrs['r']
            auth = (first + ',' + challenge + ',' + final).encode()
            signature = hmac.digest(hashlib.sha256(client_key).digest(), auth, 'sha256')
            proof = bytes(a ^ b for a, b in zip(client_key, signature))
            expected_server = hmac.digest(hmac.digest(salted, b'Server Key', 'sha256'), auth, 'sha256')
            pg_send(stream, b'p', (final + ',p=' + base64.b64encode(proof).decode()).encode())
            kind, body = pg_message(stream)
            if not allowed:
                self.redacted(body)
                self.check('PostgreSQL ' + state + ' rejects credential', kind == b'E' and pg_code(body) == '28P01',
                           {'message': kind.decode(), 'sqlstate': pg_code(body) if kind == b'E' else None})
                stream.close()
                return None
            self.check('PostgreSQL validates server SCRAM proof', kind == b'R' and
                       body == struct.pack('!I', 12) + b'v=' + base64.b64encode(expected_server))
            authenticated = False
            for _ in range(16):
                kind, body = pg_message(stream)
                if kind == b'R':
                    self.check('PostgreSQL AuthenticationOk', body == struct.pack('!I', 0))
                    authenticated = True
                if kind == b'Z':
                    self.check('PostgreSQL ' + state + ' reaches authenticated ReadyForQuery', authenticated)
                    return stream
                self.check('PostgreSQL startup message allowed', kind in (b'R', b'S', b'K'))
            raise AssertionError('PostgreSQL startup exceeded bounded message count')
        except BaseException:
            stream.close()
            raise

    def pg_query(self, stream, denied=False):
        pg_send(stream, b'Q', b'SELECT current_user\0')
        rows = 0
        for _ in range(16):
            kind, body = pg_message(stream)
            self.redacted(body)
            if denied:
                self.check('existing PostgreSQL session loses authority',
                           kind == b'E' and pg_code(body) == '28000',
                           {'message': kind.decode(), 'sqlstate': pg_code(body) if kind == b'E' else None})
                self.check('revoked PostgreSQL session closes', stream.recv(1) == b'')
                return
            self.check('authorized PostgreSQL query has no error', kind != b'E')
            rows += int(kind == b'D')
            if kind == b'Z':
                self.check('authorized PostgreSQL query returns identity', rows == 1, rows)
                return
        raise AssertionError('PostgreSQL query exceeded bounded message count')

    def metrics(self):
        status, body = self.http('/v1/metrics', self.admin)
        self.check('administrator reads telemetry', status == 200, status)
        values = {}
        for line in body.decode().splitlines():
            match = re.fullmatch(r'(chirondb_authentication_\w+)\{([^}]+)\} ([\d.eE+-]+)', line)
            if match:
                labels = dict(re.findall(r'(\w+)="([^"]*)"', match[2]))
                self.check('authentication metric has only fixed labels',
                           set(labels) <= {'transport', 'reason'} and
                           labels.get('transport') in {'http', 'grpc', 'chironwire', 'pgwire'} and
                           labels.get('reason') in {None, 'rate_limit', 'audit_unavailable'})
                values[(match[1], labels['transport'], labels.get('reason'))] = float(match[3])
        return values

    def verify(self):
        self.secret_values = []
        self.certificates()
        self.run(self.init_args())
        self.admin = self.keys['admin'].read_text().strip()
        self.secret_values.append(self.admin)
        self.tls = ssl.create_default_context(cafile=str(self.root / 'ca.pem'))
        self.start()
        self.query('admin', 'CREATE USER probe SET DEPARTMENT Testing SET CLEARANCE INTERNAL;')
        self.keys['probe'] = self.secrets / 'probe.key'
        self.query('admin', 'ISSUE API KEY FOR USER probe;', extra=['--key-out', self.keys['probe']])
        probe = self.keys['probe'].read_text().strip()
        wrong = 'synthetic-invalid-' + secrets.token_urlsafe(24)
        self.secret_values.extend([probe, wrong])
        for kind in ['http', 'http-v1', 'grpc', 'wire']:
            result = self.transport(kind, 'probe', QUERY)
            self.check(kind + ' authorized identity is probe', result['rows'][0]['name'] == 'probe')
        self.deny('missing', None)
        self.deny('wrong', wrong)
        status, identity = self.http('/v1/security/whoami', probe)
        self.check('probe identity lookup succeeds', status == 200)
        principal = json.loads(identity)['principal']
        revision = self.admin_json('/v1/security/whoami')['identity_revision']
        sql = self.admin_json('/v1/security/sql-credentials',
            {'principal': principal, 'expected_revision': revision}, sensitive=True)
        with self.pg_login(sql['username'], sql['password'], 'valid', True) as old_session:
            self.pg_query(old_session)
            self.pg_login(sql['username'], '', 'missing password', False)
            self.pg_login(sql['username'], wrong, 'wrong password', False)
            self.query('admin', "REVOKE API KEY '" + probe.split('.')[1] + "';")
            self.deny('revoked', probe)
            # Identity changes close the entire publication epoch. Reconnecting
            # with the independent SQL credential must still succeed until it,
            # too, is revoked; retaining the old session must never grant access.
            self.pg_query(old_session, denied=True)
            with self.pg_login(sql['username'], sql['password'], 'separate SQL credential', True) as sql_session:
                self.pg_query(sql_session)
                revision = self.admin_json('/v1/security/whoami')['identity_revision']
                self.admin_json('/v1/security/credentials/' + sql['id'] + '/revoke', {'expected_revision': revision})
                self.pg_query(sql_session, denied=True)
        self.pg_login(sql['username'], sql['password'], 'revoked password', False)
        self.keys['replacement'] = self.secrets / 'replacement.key'
        self.query('admin', 'ISSUE API KEY FOR USER probe;', extra=['--key-out', self.keys['replacement']])
        replacement = self.keys['replacement'].read_text().strip()
        self.secret_values.append(replacement)
        revision = self.admin_json('/v1/security/whoami')['identity_revision']
        sql = self.admin_json('/v1/security/sql-credentials',
            {'principal': principal, 'expected_revision': revision}, sensitive=True)
        self.query('admin', 'ALTER USER probe SET STATUS SUSPENDED;', extra=['--yes'])
        self.deny('suspended user', replacement)
        self.pg_login(sql['username'], sql['password'], 'suspended user', False)
        before = self.metrics()
        failures = 'chirondb_authentication_failures_total'
        suppressed = 'chirondb_authentication_audit_suppressed_total'
        for transport, minimum in [('http', 8), ('grpc', 4), ('chironwire', 4), ('pgwire', 4)]:
            actual = before.get((failures, transport, None), 0)
            self.check(transport + ' denial counter records attempts', actual >= minimum, actual)
        start = time.monotonic()
        with ThreadPoolExecutor(max_workers=4) as pool:
            statuses = list(pool.map(lambda _: self.grpc_status(wrong), range(128)))
        elapsed = time.monotonic() - start
        self.check('bounded authentication burst remains denied', all(s == 'UNAUTHENTICATED' for s in statuses))
        after = self.metrics()
        total = after.get((failures, 'grpc', None), 0) - before.get((failures, 'grpc', None), 0)
        dropped = after.get((suppressed, 'grpc', 'rate_limit'), 0) - before.get((suppressed, 'grpc', 'rate_limit'), 0)
        self.check('burst counts all failures and caps audit writes', total == 128 and dropped > 0 and
                   total - dropped <= 16 * (math.ceil(elapsed) + 1),
                   {'attempts': total, 'suppressed': dropped, 'elapsed_seconds': elapsed})
        self.check('authentication audit remains available', all(
            count == 0 for (name, _, reason), count in after.items() if name == suppressed and reason == 'audit_unavailable'))
        self.query('admin', 'SHOW CURRENT USER;')
        self.stop()
        self.redacted((self.root / 'server.log').read_bytes())
        self.redacted(json.dumps(self.records))
        self.run([self.bin / 'chironctl', 'security', 'verify-audit', '--data-dir', self.root / 'data', '--keyring', self.keyring])


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--bin-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--port', type=int, default=17601)
    lab = AuthDenialLab(parser.parse_args())
    passed = False
    try:
        lab.verify()
        passed = True
    finally:
        try:
            lab.stop()
        finally:
            lab.save(passed)
