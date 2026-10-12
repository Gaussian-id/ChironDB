#!/usr/bin/env python3
"""Fresh protected installation using public binaries only; no fixture metadata writes."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pexpect
import grpc


def sql_value(value):
    if isinstance(value, str):
        return "'" + value.replace("'", "''") + "'"
    if isinstance(value, dict):
        return '{' + ','.join(sql_value(k) + ':' + sql_value(v) for k, v in value.items()) + '}'
    if isinstance(value, list):
        return '[' + ','.join(sql_value(v) for v in value) + ']'
    return json.dumps(value)


class InstallationLab:
    def __init__(self, args):
        self.args = args
        self.root = args.output.resolve()
        self.root.mkdir(mode=0o700)
        self.secrets = self.root / 'secrets'
        self.secrets.mkdir(mode=0o700)
        self.bin = args.bin_dir.resolve()
        self.env = {k: v for k, v in os.environ.items()
                    if not k.startswith(('CHIRONDB_', 'GAUSSDB_', 'OTEL_'))}
        self.records = []
        self.server = None
        self.base = f'https://127.0.0.1:{args.port}'
        self.keys = {'admin': self.secrets / 'admin.key'}
        self.keyring = self.secrets / 'storage.json'
        self.channel = None
        self.wires = {}

    def check(self, name, passed, actual=None):
        self.records.append({'check': name, 'passed': bool(passed), 'actual': actual})
        if not passed:
            raise AssertionError(name + ': ' + str(actual))

    def run(self, argv, code=0, label=None):
        p = subprocess.run([str(x) for x in argv], env=self.env, text=True,
                           capture_output=True, timeout=60)
        self.records.append({'command': [str(x) for x in argv], 'expected_exit': code,
                             'exit': p.returncode, 'stdout': p.stdout, 'stderr': p.stderr,
                             'passed': p.returncode == code})
        if p.returncode != code:
            raise AssertionError((label or str(argv)) + ': ' + p.stdout + p.stderr)
        return p

    def init_args(self):
        return [self.bin / 'chironctl', 'security', 'init', '--data-dir', self.root / 'data',
                '--tenant', 'default', '--admin', 'admin', '--keyring-out', self.keyring,
                '--admin-key-out', self.keys['admin']]

    def cli_args(self, user):
        return [self.bin / 'chironql', '--url', self.base, '--ca-cert', self.root / 'ca.pem',
                '--api-key-file', self.keys[user], '--format', 'json']

    def query(self, user, query, code=0, extra=()):
        p = self.run(self.cli_args(user) + list(extra) + ['--exec', query], code)
        result = json.loads(p.stdout)
        if code == 1:
            self.check('denied by security authority: ' + query.split(';')[0][:80],
                       result.get('code', '').startswith('security.'), result.get('code'))
        return result

    def server_args(self):
        return [self.bin / 'chirondb', '--data-dir', self.root / 'data',
                '--encryption-keyring-file', self.keyring, '--tenant-enforcement', 'enforced',
                '--tls-cert', self.root / 'server.pem', '--tls-key', self.root / 'server.key',
                '--listen-http', f'127.0.0.1:{self.args.port}',
                '--listen-grpc', f'127.0.0.1:{self.args.port + 1}',
                '--listen-wire', f'127.0.0.1:{self.args.port + 2}']

    def start(self):
        log = (self.root / 'server.log').open('a')
        self.server = subprocess.Popen([str(x) for x in self.server_args()],
                                       env=self.env, stdout=log, stderr=log)
        log.close()
        context = ssl.create_default_context(cafile=str(self.root / 'ca.pem'))
        last_error = None
        for _ in range(200):
            if self.server.poll() is not None:
                raise AssertionError((self.root / 'server.log').read_text())
            try:
                with urllib.request.urlopen(self.base + '/health', context=context, timeout=.2) as r:
                    self.check('TLS readiness', r.status == 200)
                    return
            except (OSError, urllib.error.URLError) as error:
                last_error = error
                time.sleep(.05)
        raise AssertionError(f'server did not become ready: {last_error}')

    def stop(self):
        for stream in self.wires.values():
            stream.close()
        self.wires.clear()
        if self.channel is not None:
            self.channel.close()
            self.channel = None
        if self.server is not None:
            self.server.terminate()
            self.server.wait(timeout=15)
            self.check('server stopped by SIGTERM', self.server.returncode in (0, -15), self.server.returncode)
            self.server = None

    def certificates(self):
        self.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
                  '-subj', '/CN=ChironDB installation test CA', '-addext', 'basicConstraints=critical,CA:TRUE',
                  '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-keyout', self.root / 'ca.key',
                  '-out', self.root / 'ca.pem'])
        self.run(['openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-subj', '/CN=localhost',
                  '-keyout', self.root / 'server.key', '-out', self.root / 'server.csr'])
        extensions = self.root / 'extensions.cnf'
        extensions.write_text('subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
        self.run(['openssl', 'x509', '-req', '-in', self.root / 'server.csr', '-CA', self.root / 'ca.pem',
                  '-CAkey', self.root / 'ca.key', '-CAcreateserial', '-days', '2', '-extfile', extensions,
                  '-out', self.root / 'server.pem'])
        for name in ['ca.key', 'server.key']:
            (self.root / name).chmod(0o600)

    def terminal(self, user, attached=False):
        args = self.server_args() + ['--console', '--console-api-key-file', self.keys[user]] if attached else self.cli_args(user)
        child = pexpect.spawn(str(args[0]), [str(x) for x in args[1:]], env=self.env,
                              encoding='utf-8', timeout=25)
        try:
            child.expect_exact('chiron> ')
            banner = child.before
            self.check('authenticated CLI banner ' + user, f'authenticated as {user}' in banner, banner)
            child.sendline('SHOW CURRENT USER;')
            child.expect_exact('chiron> ')
            self.check('PTY identity ' + user, user in child.before, child.before)
            child.sendline('\\q')
            child.expect(pexpect.EOF)
            child.close()
            self.check('PTY exit ' + user, child.exitstatus == 0, child.exitstatus)
        finally:
            if child.isalive():
                child.terminate(force=True)

    def transport(self, kind, user, query, denied=False):
        secret = self.keys[user].read_text().strip()
        tls = ssl.create_default_context(cafile=str(self.root / 'ca.pem'))
        if kind in ('http', 'http-v1'):
            prefix = '/v1' if kind == 'http-v1' else ''
            request = urllib.request.Request(self.base + prefix + '/chironql',
                data=json.dumps({'query': query}).encode(),
                headers={'Authorization': 'Bearer ' + secret, 'Content-Type': 'application/json'})
            try:
                with urllib.request.urlopen(request, context=tls, timeout=15) as response:
                    result = json.load(response)
                    status = response.status
            except urllib.error.HTTPError as error:
                result, status = json.load(error), error.code
            rejected = status != 200
        else:
            if not hasattr(self, 'pb'):
                generated = self.root / 'generated'
                generated.mkdir()
                proto = Path(__file__).resolve().parents[2] / 'proto'
                self.run([sys.executable, '-m', 'grpc_tools.protoc', '-I' + str(proto),
                          '--python_out=' + str(generated), '--grpc_python_out=' + str(generated),
                          proto / 'chirondb/v1/compat.proto', proto / 'chirondb/v1/chirondb.proto'])
                sys.path.insert(0, str(generated))
                from chirondb.v1 import chirondb_pb2, chirondb_pb2_grpc, compat_pb2
                self.pb, self.pbgrpc, self.wpb = chirondb_pb2, chirondb_pb2_grpc, compat_pb2
            if kind == 'grpc':
                if self.channel is None:
                    self.channel = grpc.secure_channel(f'127.0.0.1:{self.args.port + 1}',
                        grpc.ssl_channel_credentials((self.root / 'ca.pem').read_bytes()))
                try:
                    reply = self.pbgrpc.ChironDbStub(self.channel).ExecuteQuery(self.pb.ChironQlRequest(query=query),
                        metadata=[('authorization', 'Bearer ' + secret)], timeout=15)
                    result = {'rows': [json.loads(row) for row in reply.rows_json]}
                    rejected, status = False, 'OK'
                except grpc.RpcError as error:
                    rejected, status, result = True, error.code().name, None
                    self.check('gRPC explicit authorization error', error.code() in
                               (grpc.StatusCode.PERMISSION_DENIED, grpc.StatusCode.UNAUTHENTICATED))
            else:
                if user not in self.wires:
                    self.wires[user] = tls.wrap_socket(socket.create_connection(('127.0.0.1', self.args.port + 2), timeout=10), server_hostname='127.0.0.1')
                stream = self.wires[user]
                request = self.wpb.WireRequest(request_id=len(self.records) + 1, api_key=secret,
                    chironql=self.wpb.WireChironQlRequest(query=query))
                body = request.SerializeToString()
                stream.sendall(struct.pack('!I', len(body)) + body)
                def read(size):
                    data = b''
                    while len(data) < size:
                        chunk = stream.recv(size - len(data))
                        if not chunk:
                            raise EOFError('wire closed before response')
                        data += chunk
                    return data
                reply = self.wpb.WireResponse.FromString(read(struct.unpack('!I', read(4))[0]))
                rejected, status = bool(reply.error_code), reply.error_code or 'OK'
                result = {'rows': [json.loads(row) for row in reply.chironql.rows_json]} if not rejected else None
        self.check(f'{kind} {user} allow/deny: {query}', rejected == denied,
                   {'status': status, 'result': result})
        return result

    def protected_retrieval(self, expected, users=None):
        """Text native/ChironQL parity through TLS, including closed legacy routes."""
        tls = ssl.create_default_context(cafile=str(self.root / 'ca.pem'))
        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'clients/python'))
        from chirondb_client import ChironDbClient
        os.environ['REQUESTS_CA_BUNDLE'] = str(self.root / 'ca.pem')
        def check_hits(label, hits, golden):
            self.check(label, [h['id'] for h in hits] == [h['id'] for h in golden] and
                       all(abs(h['score'] - g['score']) < 1e-7 and h['payload'] == g['payload']
                           for h, g in zip(hits, golden)), hits)
        def proto_hits(reply):
            self.check('protected response suppresses internal counts',
                       reply.searched == 0 and reply.elapsed_ms == 0 and not reply.degraded)
            return [{'id': h.id, 'score': h.score, 'payload': json.loads(h.payload_json)} for h in reply.hits]
        for user in users or ['admin', 'ops', 'writer', 'finance', 'hr']:
            secret = self.keys[user].read_text().strip()
            for vector in [[], [1, 0]]:
                query = {'vector': vector, 'query': 'synthetic', 'text_field': 'text', 'k': 10}
                ql = "HYBRID docs " + ("NEAR [1,0] " if vector else "") + "TEXT 'synthetic' FIELD text LIMIT 10;"
                golden = self.query(user, ql, 0 if user in expected else 1).get('rows', [])
                if user in expected:
                    self.check('text visible ID oracle ' + user, {r['id'] for r in golden} == expected[user], golden)
                    sdk = ChironDbClient(self.base, api_key=secret)
                    check_hits('Python SDK protected text ' + user,
                               sdk.text_hybrid_search('docs', vector, 'synthetic', 'text', 10)['hits'], golden)
                for kind in ['http', 'http-v1', 'grpc', 'wire']:
                    reply = self.transport(kind, user, ql, denied=user not in expected)
                    if user in expected:
                        check_hits(kind + ' ChironQL text parity ' + user, reply['rows'], golden)
                for prefix in ['', '/v1']:
                    request = urllib.request.Request(self.base + prefix + '/collections/docs/text_hybrid_search',
                        data=json.dumps(query).encode(),
                        headers={'Authorization': 'Bearer ' + secret, 'Content-Type': 'application/json'})
                    try:
                        with urllib.request.urlopen(request, context=tls, timeout=15) as response:
                            status, result = response.status, json.load(response)
                    except urllib.error.HTTPError as error:
                        status, result = error.code, json.load(error)
                    if user in expected:
                        self.check('native HTTP text admitted ' + user, status == 200, result)
                        check_hits(prefix + ' native HTTP text ' + user, result['hits'], golden)
                    else:
                        self.check('native HTTP text forbidden ' + user, status == 403, result)
                request = self.wpb.TextHybridSearchRequest(collection='docs', **query)
                for service in ['chirondb.v1.ChironDb', 'gaussdb.v1.GaussDb']:
                    rpc = self.channel.unary_unary('/' + service + '/TextHybridSearch',
                        request_serializer=self.wpb.TextHybridSearchRequest.SerializeToString,
                        response_deserializer=self.wpb.SearchResponse.FromString)
                    allowed = user in expected and service == 'chirondb.v1.ChironDb'
                    try:
                        reply = rpc(request, metadata=[('authorization', 'Bearer ' + secret)], timeout=15)
                        status = 'OK'
                    except grpc.RpcError as error:
                        status = error.code().name
                    self.check(service + ' native text scope ' + user,
                               status == ('OK' if allowed else 'PERMISSION_DENIED'), status)
                    if allowed:
                        check_hits('native gRPC text ' + user, proto_hits(reply), golden)
                with tls.wrap_socket(socket.create_connection(('127.0.0.1', self.args.port + 2), timeout=10),
                                     server_hostname='127.0.0.1') as stream:
                    body = self.wpb.WireRequest(request_id=1, api_key=secret,
                                               text_hybrid_search=request).SerializeToString()
                    stream.sendall(struct.pack('!I', len(body)) + body)
                    def read(size):
                        data = b''
                        while len(data) < size:
                            chunk = stream.recv(size - len(data))
                            if not chunk:
                                raise EOFError('wire closed before response')
                            data += chunk
                        return data
                    reply = self.wpb.WireResponse.FromString(read(struct.unpack('!I', read(4))[0]))
                if user in expected:
                    self.check('native wire text admitted ' + user, not reply.error_code, reply.error_code)
                    check_hits('native wire text ' + user, proto_hits(reply.search), golden)
                else:
                    self.check('native wire text forbidden ' + user, reply.error_code == 'PERMISSION_DENIED', reply.error_code)
            # MCP remains unavailable in protected mode.
            for prefix in ['', '/v1']:
                request = urllib.request.Request(self.base + prefix + '/mcp',
                    data=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'}).encode(),
                    headers={'Authorization': 'Bearer ' + secret, 'Content-Type': 'application/json'})
                try:
                    urllib.request.urlopen(request, context=tls, timeout=15)
                    status = 200
                except urllib.error.HTTPError as error:
                    status = error.code
                self.check('protected MCP remains closed ' + user, status == 403, status)

    def rejected_terminal(self, key):
        args = [self.bin / 'chironql', '--url', self.base, '--ca-cert', self.root / 'ca.pem']
        if key:
            args += ['--api-key-file', key]
        child = pexpect.spawn(str(args[0]), [str(x) for x in args[1:]], env=self.env, encoding='utf-8', timeout=15)
        try:
            child.expect(pexpect.EOF)
            output = child.before
            child.close()
            self.check('invalid credential rejected before prompt', 'chiron> ' not in output and child.exitstatus != 0, output)
        finally:
            if child.isalive():
                child.terminate(force=True)

    def observability(self, user, allowed):
        tls = ssl.create_default_context(cafile=str(self.root / 'ca.pem'))
        for prefix in ['', '/v1']:
            request = urllib.request.Request(self.base + prefix + '/metrics',
                headers={'Authorization': 'Bearer ' + self.keys[user].read_text().strip()})
            try:
                with urllib.request.urlopen(request, context=tls, timeout=15) as response:
                    status = response.status
                    response.read()
            except urllib.error.HTTPError as error:
                status = error.code
            self.check(f'{prefix}/metrics capability for {user}', status == (200 if allowed else 403), status)

    def script(self, text, code=0):
        command = [str(value) for value in self.cli_args('admin')]
        result = subprocess.run(command, input=text, env=self.env, text=True, capture_output=True, timeout=30)
        self.check('authenticated script exit', result.returncode == code,
                   {'command': command, 'script': text, 'stdout': result.stdout, 'stderr': result.stderr, 'exit': result.returncode})

    def verify(self):
        initial = json.loads(self.run(self.init_args()).stdout)
        self.check('initial authority has no fixture principals', initial['admin'] == 'admin' and initial['identity_revision'] == 1, initial)
        self.run(self.init_args(), 1)
        for path in [self.keyring, self.keys['admin']]:
            self.check('private secret ' + path.name, path.stat().st_mode & 0o777 == 0o600)
        self.certificates()
        self.start()
        self.run(self.init_args(), 1)
        self.run([self.bin / 'chironctl', 'security', 'recover-admin', '--data-dir', self.root / 'data',
                  '--keyring', self.keyring, '--admin-key-out', self.secrets / 'blocked-recovery.key', '--yes'], 1)
        self.check('running server blocks offline credential replacement', not (self.secrets / 'blocked-recovery.key').exists())
        self.terminal('admin')
        self.rejected_terminal(None)
        invalid_key = self.secrets / 'invalid.key'
        invalid_key.write_text('invalid-key\n')
        invalid_key.chmod(0o600)
        self.rejected_terminal(invalid_key)
        self.query('admin', 'CREATE PROTECTED COLLECTION docs DIM 2 METRIC cosine;')
        self.script('CREATE ROLE script_role;\nSHOW ROLE script_role PRIVILEGES;\n')
        self.script('CREATE PROTECTED COLLECTION docs DIM 2;\nCREATE ROLE must_not_execute;\n', 1)
        roles = self.query('admin', 'SHOW ROLES WITH USERS;')['rows']
        self.check('script stops after failed collection creation',
                   'must_not_execute' not in json.dumps(roles) and 'script_role' in json.dumps(roles))
        self.query('admin', 'CREATE PROTECTED COLLECTION docs DIM 2;', 1)
        empty = self.query('admin', 'SHOW COLLECTION docs SECURITY POLICY;')['rows'][0]['policy']
        self.check('new collection denies by default', empty == {'department_actions': [], 'owner_actions': [], 'templates': {}}, empty)
        self.query('admin', 'CREATE PROTECTED COLLECTION stale DIM 2 IF REVISION 1;', 1)
        self.query('admin', 'COUNT docs;', 1)
        for user, department, clearance in [('ops', 'Operations', 'INTERNAL'), ('writer', 'Ingestion', 'RESTRICTED'),
                                             ('finance', 'Finance', 'CONFIDENTIAL'), ('hr', 'HR', 'INTERNAL')]:
            self.query('admin', f'CREATE ROLE {user}_role;')
            if user == 'ops':
                self.query('admin', f'GRANT OBSERVE ON SYSTEM TO ROLE {user}_role;')
            else:
                actions = 'READ, SEARCH, CREATE, INGEST, UPDATE, DELETE' if user == 'writer' else 'READ, SEARCH'
                self.query('admin', f'GRANT {actions} ON COLLECTION docs TO ROLE {user}_role;')
            self.query('admin', f'CREATE USER {user} SET DEPARTMENT {department} SET CLEARANCE {clearance};')
            self.query('admin', f'GRANT ROLE {user}_role TO USER {user};')
            self.keys[user] = self.secrets / f'{user}.key'
            self.query('admin', f'ISSUE API KEY FOR USER {user};', extra=['--key-out', self.keys[user]])
        point = sql_value({'vector': [1, 0], 'payload': {'text': 'synthetic finance report'}})
        self.query('writer', f"CREATE POINTS INTO docs USING TEMPLATE finance {point} REQUEST 'before-policy';", 1)
        templates = {}
        for name, department, classification in [('finance', 'Finance', 'internal'), ('confidential', 'Finance', 'confidential'), ('hr', 'HR', 'internal')]:
            templates[name] = {'department': department, 'classification': classification,
                               'properties': {'/text': {'classification': classification, 'actions': ['read', 'query', 'write']}},
                               'representations': {'dense': {'source_fields': ['/text'], 'classification': classification}}}
        policy = {'department_actions': ['read', 'search'], 'owner_actions': ['read', 'search', 'update', 'delete'], 'templates': templates}
        self.query('admin', 'ALTER COLLECTION docs SET SECURITY POLICY ' + sql_value(policy) + ';')
        ids = {}
        for index, template in enumerate(templates):
            value = sql_value({'vector': [1, index], 'payload': {'text': 'synthetic ' + template}})
            rows = self.query('writer', f"CREATE POINTS INTO docs USING TEMPLATE {template} {value} REQUEST 'create-{index}';")['rows']
            self.check('server assigned one id ' + template, len(rows) == 1 and bool(rows[0]['id']))
            ids[template] = rows[0]['id']
        disposable = self.query('writer', "CREATE POINTS INTO docs USING TEMPLATE finance {vector:[1,0],payload:{text:'temporary'}} REQUEST 'writer-crud';")['rows'][0]['id']
        self.query('writer', f"UPDATE POINTS IN docs {{id:'{disposable}',vector:[0,1],payload:{{text:'updated'}}}};")
        updated = self.query('writer', f"GET docs POINTS '{disposable}';")['rows']
        self.check('writer updates its authorized object', len(updated) == 1 and updated[0]['payload']['text'] == 'updated')
        self.query('writer', f"DELETE FROM docs POINTS '{disposable}';", extra=['--yes'])
        self.check('writer deletion removes the authorized object', not self.query('writer', f"GET docs POINTS '{disposable}';").get('rows'))
        expected = {'writer': set(ids.values()), 'finance': {ids['finance'], ids['confidential']}, 'hr': {ids['hr']}}
        for user in ['admin', 'ops', 'writer', 'finance', 'hr']:
            self.observability(user, user in ['admin', 'ops'])
            if user in expected:
                rows = self.query(user, 'SCROLL docs LIMIT 10;')['rows']
                actual = {r['id'] for r in rows}
                self.check('independent visible ID oracle ' + user, actual == expected[user], sorted(actual))
                count = self.query(user, 'COUNT docs;')['rows'][0]['count']
                self.check('independent count ' + user, count == len(expected[user]), count)
                rows = self.query(user, 'SEARCH docs NEAR [1,0] LIMIT 10;')['rows']
                self.check('dense authorized domain ' + user, {r['id'] for r in rows} == expected[user], rows)
                vectors = {ids[name]: [1, index] for index, name in enumerate(templates)}
                for vector in [[1, 0], [0, 1]]:
                    scores = {point_id: sum(a * b for a, b in zip(vector, stored)) /
                              math.sqrt(sum(a * a for a in vector) * sum(b * b for b in stored))
                              for point_id, stored in vectors.items() if point_id in expected[user]}
                    ordered = sorted(scores, key=lambda point_id: -scores[point_id])
                    for limit in [1, 2]:
                        rows = self.query(user, f'SEARCH docs NEAR {json.dumps(vector)} LIMIT {limit};')['rows']
                        self.check(f'independent cosine top-{limit} {user} {vector}',
                                   [row['id'] for row in rows] == ordered[:limit] and
                                   all(abs(row['score'] - scores[row['id']]) < 0.000001 for row in rows),
                                   {'expected': [{'id': point_id, 'score': scores[point_id]} for point_id in ordered[:limit]], 'actual': rows})
            else:
                self.query(user, 'COUNT docs;', 1)
            if user != 'admin':
                self.query(user, 'CREATE PROTECTED COLLECTION forbidden DIM 2 IF REVISION 2;', 1)
                self.query(user, 'CREATE ROLE escalation;', 1)
                self.query(user, 'ALTER COLLECTION docs SET SECURITY POLICY ' + sql_value(policy) + ';', 1)
        hidden = self.query('finance', f"GET docs POINTS '{ids['hr']}';")
        missing = self.query('finance', "GET docs POINTS 'missing-id';")
        self.check('hidden and missing GET expose no rows', not hidden.get('rows') and not missing.get('rows'))
        self.query('finance', f"DELETE FROM docs POINTS '{ids['finance']}';", 1, extra=['--yes'])
        self.query('admin', 'GRANT IDENTITY_MANAGE ON SYSTEM TO ROLE ops_role;', 1)
        for kind in ['http', 'http-v1', 'grpc', 'wire']:
            revision = self.transport(kind, 'admin', 'SHOW CATALOG REVISION;')['rows'][0]['revision']
            collection = 'provision_' + kind.replace('-', '_')
            self.transport(kind, 'admin', f'CREATE PROTECTED COLLECTION {collection} DIM 2 IF REVISION {revision};')
            initial_policy = self.transport(kind, 'admin', f'SHOW COLLECTION {collection} SECURITY POLICY;')['rows'][0]
            self.check(kind + ' provisioned deny-all policy', initial_policy['policy'] == empty)
            self.transport(kind, 'admin', f'ALTER COLLECTION {collection} SET SECURITY POLICY ' + sql_value(policy) + f" IF REVISION {initial_policy['revision']};")
            configured = self.transport(kind, 'admin', f'SHOW COLLECTION {collection} SECURITY POLICY;')['rows'][0]
            self.check(kind + ' configured exact typed policy', configured['policy'] == policy)
            self.transport(kind, 'admin', 'SHOW COLLECTION docs SECURITY POLICY;')
            self.transport(kind, 'admin', 'COUNT docs;', denied=True)
            for user, allowed in expected.items():
                rows = self.transport(kind, user, 'SCROLL docs LIMIT 10;')['rows']
                self.check(f'{kind} independent ID oracle {user}', {r['id'] for r in rows} == allowed)
            self.transport(kind, 'finance', 'CREATE PROTECTED COLLECTION exploit DIM 2 IF REVISION 2;', denied=True)
        self.protected_retrieval(expected)
        self.query('admin', 'REVOKE ROLE finance_role FROM USER finance;')
        self.query('finance', 'COUNT docs;', 1)
        for kind in ['http', 'http-v1', 'grpc', 'wire']:
            self.transport(kind, 'finance', 'COUNT docs;', denied=True)
        self.protected_retrieval({k: v for k, v in expected.items() if k != 'finance'}, users=['finance'])
        self.query('admin', 'GRANT ROLE finance_role TO USER finance;')
        self.stop()
        self.terminal('admin', attached=True)
        self.start()
        self.check('encrypted restart preserves Finance domain', self.query('finance', 'COUNT docs;')['rows'][0]['count'] == 2)
        self.protected_retrieval(expected, users=['finance'])
        self.query('admin', f"ALTER POINT '{ids['finance']}' IN docs SET OWNER admin;")
        self.query('admin', 'GRANT ROLE finance_role TO USER admin;')
        self.check('explicit data role exposes only administrator-owned object',
                   {row['id'] for row in self.query('admin', 'SCROLL docs LIMIT 10;')['rows']} == {ids['finance']})
        credential_id = self.keys['admin'].read_text().strip().split('.')[1]
        self.query('admin', f"REVOKE API KEY '{credential_id}';")
        self.query('admin', 'SHOW CURRENT USER;', 1)
        self.stop()
        recovery_key = self.secrets / 'recovered.key'
        args = [self.bin / 'chironctl', 'security', 'recover-admin', '--data-dir', self.root / 'data',
                '--keyring', self.keyring, '--admin-key-out', recovery_key]
        self.run(args, 1)
        recovered = json.loads(self.run(args + ['--yes']).stdout)
        self.check('recovery changes immutable admin id', recovered['principal_id'] != initial['principal_id'])
        self.start()
        self.query('admin', 'SHOW CURRENT USER;', 1)
        self.rejected_terminal(self.keys['admin'])
        self.keys['old-admin'] = self.keys['admin']
        self.keys['admin'] = recovery_key
        self.check('recovered admin retains display name', self.query('admin', 'SHOW CURRENT USER;')['rows'][0]['name'] == 'admin')
        self.query('admin', 'CREATE PROTECTED COLLECTION recovered_docs DIM 2;')
        self.query('admin', 'COUNT docs;', 1)
        self.query('admin', 'GRANT ROLE finance_role TO USER admin;')
        self.check('recovery never transfers old ownership', self.query('admin', 'COUNT docs;')['rows'][0]['count'] == 0)
        self.query('admin', 'REVOKE ROLE finance_role FROM USER admin;')
        self.check('recovery preserves other-user grants', self.query('finance', 'COUNT docs;')['rows'][0]['count'] == 2)
        self.stop()
        self.run([self.bin / 'chironctl', 'security', 'verify-audit', '--data-dir', self.root / 'data', '--keyring', self.keyring])
        self.run([self.bin / 'chironctl', 'security', 'verify-encryption', '--data-dir', self.root / 'data', '--keyring', self.keyring])

    def save(self, passed):
        serialized = json.dumps(self.records, indent=2)
        for path in self.keys.values():
            if path.exists():
                secret = path.read_text().strip()
                assert not secret or secret not in serialized, 'credential appeared in evidence'
        report = {'passed': passed, 'checks': len(self.records), 'records': self.records,
                  'binary_sha256': {name: hashlib.sha256((self.bin / name).read_bytes()).hexdigest()
                                    for name in ['chirondb', 'chironql', 'chironctl']}}
        (self.root / 'report.json').write_text(json.dumps(report, indent=2))
        print(json.dumps({k: v for k, v in report.items() if k != 'records'}, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--bin-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--port', type=int, default=17501)
    lab = InstallationLab(parser.parse_args())
    passed = False
    try:
        lab.verify()
        passed = True
    finally:
        try:
            lab.stop()
        finally:
            lab.save(passed)
