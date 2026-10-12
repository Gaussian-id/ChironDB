#!/usr/bin/env python3
"""Real TLS server/CLI proof. First provision only chironql_empty_fixture.
Python requirements: grpcio==1.75.1 grpcio-tools==1.75.1 pexpect==4.9.0.
All query data is synthetic. Never include credential files in published evidence.
"""
import argparse
import io
import http.server
import ssl
import threading
import json
import math
import statistics
import os
from pathlib import Path
import socket
import shutil
import struct
import subprocess
import sys
import time
import traceback
os.environ.setdefault('GRPC_VERBOSITY', 'ERROR')
import grpc
import pexpect
from security_five_roles_e2e import Lab, digest, redacted

ROOT = Path(__file__).resolve().parents[2]
ADMIN = 'security-admin'
PROFILES = {
    'operations-admin': ('Operations', 'INTERNAL', [], ['OBSERVE']),
    'ingestion-writer': ('Ingestion', 'RESTRICTED', ['READ','SEARCH','CREATE','INGEST','UPDATE','DELETE'], []),
    'finance-reader': ('Finance', 'CONFIDENTIAL', ['READ','SEARCH'], []),
    'hr-reader': ('HR', 'INTERNAL', ['READ','SEARCH'], []),
}


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class ChironLab(Lab):
    def __init__(self, binary, cli, output):
        # Freeze the exact executables before starting; parallel cargo checks
        # must not change the binary fingerprint halfway through this proof.
        pinned = output / 'bin'
        pinned.mkdir()
        for name, source in [('chirondb', binary), ('chironql', cli), ('chironctl', cli.with_name('chironctl'))]:
            shutil.copy2(source, pinned / name)
            (pinned / name).chmod(0o700)
        super().__init__(pinned / 'chirondb', output)
        self.issued_secrets = {key['secret'] for key in self.credentials.values()}
        self.cli_binary = (pinned / 'chironql').resolve()
        self.grpc_port, self.wire_port = port(), port()
        self.transcript = []
        self.wires = {}
        generated = output / 'generated'
        generated.mkdir(exist_ok=True)
        subprocess.run([sys.executable, '-m', 'grpc_tools.protoc', '-I'+str(ROOT/'proto'),
                        '--python_out='+str(generated), '--grpc_python_out='+str(generated),
                        str(ROOT/'proto/chirondb/v1/compat.proto'), str(ROOT/'proto/chirondb/v1/chirondb.proto')], check=True)
        sys.path.insert(0, str(generated))
        from chirondb.v1 import chirondb_pb2, chirondb_pb2_grpc, compat_pb2, compat_pb2_grpc
        self.pb, self.pbgrpc, self.wpb, self.legacygrpc = chirondb_pb2, chirondb_pb2_grpc, compat_pb2, compat_pb2_grpc

    def start(self):
        super().start()
        self.channel = None

    def connect_grpc(self):
        if self.channel is not None:
            return
        self.channel = grpc.secure_channel(f'127.0.0.1:{self.grpc_port}', grpc.ssl_channel_credentials((self.output/'ca-cert.pem').read_bytes()))
        grpc.channel_ready_future(self.channel).result(timeout=10)
        self.stub = self.pbgrpc.ChironDbStub(self.channel)

    def stop(self, crash=False):
        for stream in self.wires.values():
            stream.close()
        self.wires = {}
        if getattr(self, 'channel', None) is not None:
            self.channel.close()
            self.channel = None
        super().stop(crash)

    def cli_args(self, role):
        return ['--url', f'https://127.0.0.1:{self.port}', '--ca-cert', str(self.output/'ca-cert.pem'),
                '--api-key-file', str(self.output/(role+'.key')), '--format', 'json']

    def cli(self, role, query, code=0, key_out=None, script=False, yes=False):
        args = [str(self.cli_binary)] + self.cli_args(role)
        if key_out:
            args += ['--key-out', str(self.output/key_out)]
        if yes:
            args += ['--yes']
        if not script:
            args += ['--exec', query]
        result = subprocess.run(args, input=query if script else None, capture_output=True, text=True, timeout=40)
        record = {'transport':'cli-script' if script else 'cli-exec','role':role,'query':query,
                  'expected_exit':code,'exit':result.returncode,'stdout':result.stdout,'stderr':result.stderr}
        self.transcript.append(record)
        self.check('CLI exit '+query.split(';')[0][:90], result.returncode == code, record)
        for credential in self.credentials.values():
            self.check('CLI does not print credential', credential['secret'] not in result.stdout+result.stderr)
        if code:
            return result
        lines, remaining = [], result.stdout.strip()
        while remaining:
            value, end = json.JSONDecoder().raw_decode(remaining)
            value.setdefault("rows", [])
            lines.append(value)
            remaining = remaining[end:].strip()
        self.check('CLI JSON response', bool(lines), record)
        return lines if script else lines[-1]

    def issue(self, user, key_out=None):
        path = key_out or user+'.key'
        result = self.cli(ADMIN, f"ISSUE API KEY FOR USER '{user}';", key_out=path)
        credential_id = next(row['credential_id'] for row in result['rows'] if 'credential_id' in row)
        secret = (self.output/path).read_text().strip()
        self.check('issued key has private mode', (self.output/path).stat().st_mode & 0o777 == 0o600)
        self.check('key absent from issue response', secret not in json.dumps(result))
        self.credentials[user] = {'id':credential_id,'secret':secret}
        self.issued_secrets.add(secret)
        return result

    def query(self, role, query, prefix='/v1', expected=200, confirm=False):
        return self.request(role, 'POST', prefix+'/chironql', {'query':query,'confirm':confirm}, expected=expected)

    def grpc(self, role, query, expected=None, metadata=None):
        self.connect_grpc()
        try:
            reply = self.stub.ExecuteQuery(self.pb.ChironQlRequest(query=query),
                metadata=metadata or [('authorization', 'Bearer '+self.credentials[role]['secret'])], timeout=15)
            self.check('gRPC success expected', expected is None, query)
            result = {'rows':[json.loads(row) for row in reply.rows_json], 'stats':json.loads(reply.stats_json)}
            self.requests.append({'transport':'grpc','role':role,'query':query,'status':'OK','response':result})
            return result
        except grpc.RpcError as error:
            self.requests.append({'transport':'grpc','role':role,'query':query,'status':error.code().name})
            self.check('gRPC denial', error.code() == expected, [query,error.code().name])
            return None

    def wire(self, role, query, denied=False):
        if role not in self.wires:
            self.wires[role] = self.tls.wrap_socket(socket.create_connection(('127.0.0.1',self.wire_port),timeout=10),server_hostname='127.0.0.1')
        stream = self.wires[role]
        request = self.wpb.WireRequest(request_id=len(self.requests)+1,api_key=self.credentials[role]['secret'],chironql=self.wpb.WireChironQlRequest(query=query))
        body = request.SerializeToString()
        stream.sendall(struct.pack('!I',len(body))+body)
        def read(n):
            value = b''
            while len(value)<n:
                chunk = stream.recv(n-len(value))
                if not chunk:
                    raise EOFError('wire response closed')
                value += chunk
            return value
        reply = self.wpb.WireResponse.FromString(read(struct.unpack('!I',read(4))[0]))
        self.check('Wire allow/deny', bool(reply.error_code) == denied, [query,reply.error_code])
        result = {'rows':[json.loads(row) for row in reply.chironql.rows_json]} if not denied else None
        self.requests.append({'transport':'wire','role':role,'query':query,'status':reply.error_code or 'OK','response':result})
        return result

    def ids_in(self, result):
        return {row['id'] for row in result['rows']}

    def pty(self):
        history = self.output/'pty.history'
        child = pexpect.spawn(str(self.cli_binary), self.cli_args(ADMIN)+['--history',str(history)],encoding='utf-8',timeout=20)
        output = io.StringIO()
        child.logfile_read = output
        child.expect_exact('chiron> ')
        child.sendline('CREATE ROLE pty_role; -- comment after terminator')
        child.expect_exact('chiron> ')
        child.sendline('DROP ROLE pty_role;')
        child.expect_exact('Type yes to proceed: ')
        child.sendline('no')
        child.expect_exact('chiron> ')
        child.sendline('DROP ROLE pty_role;')
        child.expect_exact('Type yes to proceed: ')
        child.sendline('yes')
        child.expect_exact('chiron> ')
        child.sendline('\\q')
        child.expect(pexpect.EOF)
        child.close()
        self.check('PTY exits successfully', child.exitstatus == 0, child.exitstatus)
        self.check('protected history disabled', not history.exists())
        self.transcript.append({'transport':'pty','role':ADMIN,'stdout':output.getvalue()})

    def client_transport_checks(self):
        # Trust must be explicit for the synthetic CA.
        args = self.cli_args(ADMIN)
        at = args.index('--ca-cert')
        del args[at:at+2]
        result = subprocess.run([str(self.cli_binary)]+args+['--exec','SHOW USERS;'],capture_output=True,text=True,timeout=15)
        self.check('CLI rejects untrusted TLS certificate',result.returncode==2)
        self.transcript.append({'transport':'cli-negative-tls','exit':result.returncode,'stdout':result.stdout,'stderr':result.stderr})
        # A redirect target must receive no authenticated retry.
        seen = []
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def do_POST(self):
                seen.append(self.path)
                self.rfile.read(int(self.headers.get('Content-Length','0')))
                self.send_response(307)
                self.send_header('Location',f'https://127.0.0.1:{self.server.server_port}/redirect-target')
                self.send_header('Content-Length','0')
                self.end_headers()
        def serve(cert,key):
            server = http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(str(cert),str(key))
            server.socket = context.wrap_socket(server.socket,server_side=True)
            thread = threading.Thread(target=server.serve_forever,daemon=True)
            thread.start()
            return server
        server = serve(self.output/'tls-cert.pem',self.output/'tls-key.pem')
        try:
            args = self.cli_args(ADMIN)
            args[args.index('--url')+1]=f'https://127.0.0.1:{server.server_port}'
            result = subprocess.run([str(self.cli_binary)]+args+['--exec','SHOW USERS;'],capture_output=True,text=True,timeout=15)
            self.check('CLI never follows credential-bearing redirects',result.returncode!=0 and seen==['/v1/chironql'],seen)
        finally:
            server.shutdown(); server.server_close()
        # Correct CA with the wrong hostname must still fail before HTTP.
        bad_key,bad_csr,bad_cert = [self.output/name for name in ['wrong-host-key.pem','wrong-host.csr','wrong-host-cert.pem']]
        commands = [
            ['openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=wrong.example','-keyout',str(bad_key),'-out',str(bad_csr)],
            ['openssl','x509','-req','-in',str(bad_csr),'-CA',str(self.output/'ca-cert.pem'),'-CAkey',str(self.output/'ca-key.pem'),'-CAcreateserial','-days','2','-sha256','-out',str(bad_cert)],
        ]
        for command in commands: subprocess.run(command,capture_output=True,check=True)
        bad_key.chmod(0o600)
        seen.clear()
        server = serve(bad_cert,bad_key)
        try:
            args = self.cli_args(ADMIN)
            args[args.index('--url')+1]=f'https://127.0.0.1:{server.server_port}'
            result = subprocess.run([str(self.cli_binary)]+args+['--exec','SHOW USERS;'],capture_output=True,text=True,timeout=15)
            self.check('CLI verifies hostname even with trusted CA',result.returncode==2 and seen==[])
        finally:
            server.shutdown(); server.server_close()

    def attached_consoles(self):
        self.stop()
        env = {k:v for k,v in os.environ.items() if not k.startswith(('CHIRONDB_', 'GAUSSDB_', 'OTEL_'))}
        counts = {ADMIN:None,'operations-admin':None,'ingestion-writer':4,'finance-reader':3,'hr-reader':2}
        for user,count in counts.items():
            args = ['--data-dir',str(self.output/'data'),'--listen-http',f'127.0.0.1:{self.port}',
                    '--listen-grpc',f'127.0.0.1:{self.grpc_port}','--listen-wire',f'127.0.0.1:{self.wire_port}',
                    '--tls-cert',str(self.output/'tls-cert.pem'),'--tls-key',str(self.output/'tls-key.pem'),
                    '--encryption-keyring-file',str(self.output/'encryption-keyring.json'),
                    '--api-key-file',str(self.output/'legacy-api-key.txt'),'--tenant-enforcement','enforced',
                    '--console','--console-role','admin','--console-api-key-file',str(self.output/(user+'.key'))]
            child = pexpect.spawn(str(self.binary),args,env=env,encoding='utf-8',timeout=25)
            output = io.StringIO()
            child.logfile_read = output
            try:
                child.expect_exact('chiron> ')
                child.sendline('\\format json')
                child.expect_exact('chiron> ')
                child.sendline('COUNT docs;')
                child.expect_exact('chiron> ')
                observed = child.before
                self.check('attached console role '+user,
                           'security.forbidden' in observed if count is None else f'"count": {count}' in observed, observed)
                if user == 'finance-reader':
                    self.cli(ADMIN,'REVOKE ROLE finance-reader_role FROM USER finance-reader;')
                    child.sendline('COUNT docs;')
                    child.expect_exact('chiron> ')
                    self.check('attached console live revoke', 'security.forbidden' in child.before, child.before)
                    self.cli(ADMIN,'GRANT ROLE finance-reader_role TO USER finance-reader;')
                child.sendline('\\q')
                child.expect(pexpect.EOF)
                child.close()
                self.check('attached explicit quit',child.exitstatus==0,child.exitstatus)
            finally:
                if child.isalive(): child.terminate(force=True)
                self.transcript.append({'transport':'attached-pty','role':user,'stdout':output.getvalue()})
        self.start()

    def run(self):
        self.migration_cli(locked=False)
        self.start()
        self.migration_cli(locked=True)
        self.client_transport_checks()
        self.check('bootstrap contains only root', len(self.cli(ADMIN,'SHOW USERS;')['rows']) == 1)
        self.check('bootstrap has no roles', self.cli(ADMIN,'SHOW ROLES WITH USERS;')['rows'] == [])
        self.cli(ADMIN, 'CREATE ROLE security_manager; GRANT GRANTS_MANAGE, LABELS_MANAGE, POLICY_MANAGE ON COLLECTION docs TO ROLE security_manager; GRANT ROLE security_manager TO USER security-admin;', script=True)
        for user,(department,clearance,actions,system) in PROFILES.items():
            role = user+'_role'
            self.cli(ADMIN, f"CREATE ROLE '{role}'; CREATE USER '{user}' SET DEPARTMENT '{department}' SET CLEARANCE {clearance};",script=True)
            self.check('new user has no credential',self.cli(ADMIN,f"SHOW API KEYS FOR USER '{user}';")['rows'] == [])
            if actions:
                self.cli(ADMIN, f"GRANT {', '.join(actions)} ON COLLECTION docs TO ROLE '{role}';")
            if system:
                self.cli(ADMIN, f"GRANT {', '.join(system)} ON SYSTEM TO ROLE '{role}';")
            self.cli(ADMIN, f"GRANT ROLE '{role}' TO USER '{user}';")
            self.issue(user)
        self.cli('finance-reader',"-- comment\nUSE docs; COUNT;",script=True)
        self.check('five users created through terminal',len(self.cli(ADMIN,'SHOW USERS;')['rows']) == 5)
        self.cli(ADMIN, 'ISSUE API KEY FOR USER finance-reader;',code=1)
        revision = self.cli(ADMIN,'SHOW SECURITY REVISION;')['rows'][0]['revision']
        self.cli(ADMIN,'ISSUE API KEY FOR USER finance-reader;',code=1,key_out='finance-reader.key')
        self.check('existing key destination rejects before mutation',self.cli(ADMIN,'SHOW SECURITY REVISION;')['rows'][0]['revision']==revision)
        for name,template,vector in [('finance','finance',[1,0]),('confidential','finance-confidential',[.8,.2]),('hr','hr',[0,1]),('locked','finance',[.5,.5]),('disposable','hr',[.1,.9])]:
            query = f"CREATE POINTS INTO docs USING TEMPLATE '{template}' {{vector:{vector},payload:{{text:'{name}',secret:'RESTRICTED_PAYROLL_MARKER'}}}} REQUEST 'create-{name}';"  # Synthetic example payload; this marker is not a credential.
            result = self.cli('ingestion-writer',query)
            self.ids[name] = result['rows'][0]['id']
            self.check('create idempotent retry',self.cli('ingestion-writer',query)['rows'] == result['rows'])
        self.cli(ADMIN,f"ALTER POINT '{self.ids['locked']}' IN docs SET OWNER finance-reader;")
        expected = {'ingestion-writer':{'finance','confidential','hr','disposable'},'finance-reader':{'finance','confidential','locked'},'hr-reader':{'hr','disposable'}}
        for prefix in ['', '/v1']:
            self.request(ADMIN,'POST',prefix+'/chironql/parse',{'query':'SHOW USERS;'})
            self.request('unknown','POST',prefix+'/chironql/parse',{'query':'SHOW USERS;'},expected=401)
            for user in [ADMIN]+list(PROFILES):
                self.query(user,'SHOW CURRENT USER;',prefix)
                self.query(user,'SHOW CURRENT USER PRIVILEGES;',prefix)
                if user not in expected:
                    for query in ['COUNT docs;','SCROLL docs LIMIT 20;','SEARCH docs NEAR [1,0] LIMIT 5 WITH PAYLOAD;']:
                        self.query(user,query,prefix,403)
                    continue
                wanted = {self.ids[name] for name in expected[user]}
                result = self.query(user,'SCROLL docs LIMIT 20;',prefix)
                self.check(user+' independent object oracle '+prefix,self.ids_in(result)==wanted,result)
                self.check(user+' count oracle',self.query(user,'COUNT docs;',prefix)['rows'][0]['count']==len(wanted))
                search = self.query(user,'SEARCH docs NEAR [1,0] LIMIT 10 WITH PAYLOAD;',prefix)
                self.check(user+' dense exact authorized domain',self.ids_in(search)==wanted,search)
                if user != 'ingestion-writer':
                    self.check('restricted field absent', 'RESTRICTED_PAYROLL_MARKER' not in json.dumps(result)+json.dumps(search))
                    self.query(user, f"DELETE FROM docs POINTS '{next(iter(wanted))}';",prefix,403)
        vectors = {'finance':[1,0],'confidential':[.8,.2],'hr':[0,1],'locked':[.5,.5],'disposable':[.1,.9]}
        query_vector = [.3,.7]
        def cosine(vector):
            return sum(a*b for a,b in zip(vector,query_vector))/(math.sqrt(sum(a*a for a in vector))*math.sqrt(sum(a*a for a in query_vector)))
        timings = {'rest':[], 'chironql':[]}
        for user,names in expected.items():
            oracle = sorted(((cosine(vectors[name]),self.ids[name]) for name in names),reverse=True)[:2]
            for iteration in range(12):
                for surface in ['rest','chironql']:
                    result = (self.request(user,'POST','/v1/collections/docs/search',{'vector':query_vector,'k':2,'with_payload':False})['hits']
                              if surface=='rest' else self.query(user,'SEARCH docs NEAR [0.3,0.7] LIMIT 2;')['rows'])
                    self.check('top-k independent cosine oracle '+surface+' '+user, [row['id'] for row in result]==[id for score,id in oracle])
                    self.check('scores depend only on visible vectors',all(abs(row['score']-score)<1e-6 for row,(score,id) in zip(result,oracle)))
                    if iteration >= 2: timings[surface].append(self.requests[-1]['elapsed_ms'])
        self.performance = {surface:{'samples':len(values),'median_ms':statistics.median(values),'p95_ms':sorted(values)[math.ceil(len(values)*.95)-1]} for surface,values in timings.items()}
        self.performance.update({'authorized_recall_at_2':1.0,'dataset':'five synthetic two-dimensional cosine vectors; independent department/owner/clearance oracle','caveat':'shared host compiling and running workspace/platform tests; diagnostic transport overhead only, no performance certification'})
        for user in PROFILES:
            for query in ['SHOW USERS;', 'SHOW ROLES WITH USERS;', 'CREATE ROLE escalated IF REVISION 1;', 'GRANT IDENTITY_MANAGE ON SYSTEM TO ROLE finance-reader_role IF REVISION 1;', 'ALTER USER finance-reader SET CLEARANCE RESTRICTED IF REVISION 1;']:
                self.cli(user,query,code=1)
        self.cli(ADMIN,'GRANT IDENTITY_MANAGE ON SYSTEM TO ROLE finance-reader_role;',code=1)
        self.cli(ADMIN,'GRANT EXPORT ON COLLECTION docs TO ROLE finance-reader_role;',code=1)
        for user in PROFILES:
            self.cli(user,'SHOW API KEYS FOR USER security-admin;',code=1)
        self.query('finance-reader',"COUNT docs WHERE secret = 'RESTRICTED_PAYROLL_MARKER';",expected=403)  # Synthetic example payload; this marker is not a credential.
        self.cli('ingestion-writer',f"ALTER POINT '{self.ids['finance']}' IN docs SET OWNER ingestion-writer IF REVISION 1;",code=1)
        self.cli('ingestion-writer',f"GRANT READ ON POINT '{self.ids['finance']}' IN docs TO USER ingestion-writer IF REVISION 1;",code=1)
        principal = {'id':self.request(ADMIN,'GET','/v1/security/whoami')['principal'], 'tenant':'acme','enabled':True, 'attributes':{'department':'Security','clearance':'restricted'},'grants':[],'installation_actions':['identity_manage'],'delegation':[]}
        self.request('ingestion-writer','PUT','/v1/security/principals',{'expected_revision':1,'value':principal},expected=403)
        target = self.cli('finance-reader','SHOW CURRENT USER;')['rows'][0]
        principal['id'] = target['id']
        revision = self.cli(ADMIN,'SHOW SECURITY REVISION;')['rows'][0]['revision']
        self.request(ADMIN,'PUT','/v1/security/principals',{'expected_revision':revision,'value':principal},expected=403)
        self.cli(ADMIN,'CREATE ROLE stale IF REVISION 1;',code=1)
        self.cli(ADMIN,'CREATE ROLE before_failure; CREATE ROLE before_failure; CREATE ROLE after_failure;',script=True,code=1)
        self.check('script stops on first failure',not any(row['role']=='after_failure' for row in self.cli(ADMIN,'SHOW ROLES WITH USERS;')['rows']))
        self.pty()
        self.attached_consoles()
        self.request('operations-admin','GET','/v1/metrics')
        self.request('finance-reader','GET','/v1/metrics',expected=403)
        # Each protocol uses the same independently listed allowed objects.
        for user in [ADMIN]+list(PROFILES):
            wanted = {self.ids[name] for name in expected.get(user,set())}
            for method in [self.grpc,self.wire]:
                if user in expected:
                    self.check('protocol independent object oracle '+user,
                               self.ids_in(method(user,'SCROLL docs LIMIT 20;'))==wanted)
                    method(user, "DELETE FROM docs POINTS 'missing';",
                           **({'expected':grpc.StatusCode.NOT_FOUND if user=='ingestion-writer' else grpc.StatusCode.PERMISSION_DENIED}
                              if method==self.grpc else {'denied':True}))
                else:
                    method(user,'COUNT docs;',**({'expected':grpc.StatusCode.PERMISSION_DENIED} if method==self.grpc else {'denied':True}))
        # Administrative mutations traverse both protobuf surfaces too.
        revision = self.cli(ADMIN,'SHOW SECURITY REVISION;')['rows'][0]['revision']
        self.grpc(ADMIN,f'CREATE ROLE grpc_role IF REVISION {revision};')
        revision = self.cli(ADMIN,'SHOW SECURITY REVISION;')['rows'][0]['revision']
        self.wire(ADMIN,f'CREATE ROLE wire_role IF REVISION {revision};')
        legacy = self.legacygrpc.GaussDbStub(self.channel)
        try:
            legacy.Count(self.wpb.CountRequest(collection='docs'),metadata=[('authorization','Bearer '+self.credentials['finance-reader']['secret'])],timeout=10)
            self.check('legacy gRPC remains closed',False)
        except grpc.RpcError as error:
            self.check('legacy gRPC remains closed',error.code()==grpc.StatusCode.PERMISSION_DENIED)
        self.grpc(ADMIN,'SHOW USERS;',grpc.StatusCode.UNAUTHENTICATED,
                  metadata=[('authorization','Bearer '+self.credentials[ADMIN]['secret']),('x-chirondb-api-key',self.credentials[ADMIN]['secret'])])
        # Establish persistent protocol connections, then change membership.
        for method in [self.grpc,self.wire]:
            self.check('protocol count',method('finance-reader','COUNT docs;')['rows'][0]['count']==3)
            method('finance-reader','SHOW USERS;',**({'expected':grpc.StatusCode.PERMISSION_DENIED} if method==self.grpc else {'denied':True}))
        self.cli(ADMIN,'REVOKE ROLE finance-reader_role FROM USER finance-reader;')
        self.grpc('finance-reader','COUNT docs;',grpc.StatusCode.PERMISSION_DENIED)
        self.wire('finance-reader','COUNT docs;',denied=True)
        self.cli('finance-reader','COUNT docs;',code=1)
        self.cli(ADMIN,'GRANT ROLE finance-reader_role TO USER finance-reader;')
        self.check('same connection reauthorized',self.grpc('finance-reader','COUNT docs;')['rows'][0]['count']==3)
        self.check('same Wire connection reauthorized',self.wire('finance-reader','COUNT docs;')['rows'][0]['count']==3)
        self.cli(ADMIN,'ALTER USER finance-reader SET STATUS SUSPENDED;',yes=True)
        self.grpc('finance-reader','SHOW CURRENT USER;',grpc.StatusCode.UNAUTHENTICATED)
        self.wire('finance-reader','SHOW CURRENT USER;',denied=True)
        self.cli(ADMIN,'ALTER USER finance-reader SET STATUS ACTIVE;')
        self.cli(ADMIN,'ALTER USER finance-reader SET CLEARANCE INTERNAL;')
        self.check('clearance reduction immediately filters',self.grpc('finance-reader','COUNT docs;')['rows'][0]['count']==2)
        self.cli(ADMIN,'ALTER USER finance-reader SET CLEARANCE CONFIDENTIAL;')
        # Cross-department explicit permit, deny-overrides, distinct delta revocation.
        point = self.ids['hr']
        self.cli(ADMIN,f"GRANT READ ON POINT '{point}' IN docs TO USER finance-reader;")
        self.check('explicit cross-department grant',self.cli('finance-reader','COUNT docs;')['rows'][0]['count']==4)
        self.cli(ADMIN,f"DENY READ ON POINT '{point}' IN docs TO USER finance-reader;")
        self.check('deny overrides permit',self.cli('finance-reader','COUNT docs;')['rows'][0]['count']==3)
        self.cli(ADMIN,f"REVOKE GRANT READ ON POINT '{point}' IN docs FROM USER finance-reader;")
        self.cli(ADMIN,f"REVOKE DENY READ ON POINT '{point}' IN docs FROM USER finance-reader;")
        self.check('revoked grant does not return with removed deny',self.cli('finance-reader','COUNT docs;')['rows'][0]['count']==3)
        # Identity rename preserves IDs and memberships; drop/recreate cannot inherit.
        before = self.cli('hr-reader','SHOW CURRENT USER;')['rows'][0]['id']
        self.cli(ADMIN,'RENAME USER hr-reader TO hr-renamed;')
        self.check('rename preserves immutable ID',self.cli('hr-reader','SHOW CURRENT USER;')['rows'][0]['id']==before)
        self.cli(ADMIN,'RENAME USER hr-renamed TO hr-reader;')
        self.cli(ADMIN,'RENAME ROLE hr-reader_role TO hr-renamed-role;')
        self.check('role rename preserves membership',self.cli('hr-reader','COUNT docs;')['rows'][0]['count']==2)
        self.cli(ADMIN,'RENAME ROLE hr-renamed-role TO hr-reader_role;')
        self.cli(ADMIN,'CREATE ROLE disposable_role; CREATE USER temporary SET DEPARTMENT External SET CLEARANCE INTERNAL; GRANT READ ON COLLECTION docs TO ROLE disposable_role; GRANT ROLE disposable_role TO USER temporary;',script=True)
        self.issue('temporary')
        self.cli(ADMIN,f"GRANT READ ON POINT '{self.ids['finance']}' IN docs TO USER temporary;")
        self.check('temporary direct object permit',self.cli('temporary','COUNT docs;')['rows'][0]['count']==1)
        self.cli(ADMIN,'DROP ROLE disposable_role;',yes=True)
        self.cli(ADMIN,'CREATE ROLE disposable_role;')
        self.cli('temporary','COUNT docs;',code=1)
        self.cli(ADMIN,'DROP USER temporary;',yes=True)
        self.cli(ADMIN,'CREATE USER temporary SET DEPARTMENT External SET CLEARANCE INTERNAL;')
        self.cli('temporary','SHOW CURRENT USER;',code=1)
        self.cli(ADMIN,'GRANT READ ON COLLECTION docs TO ROLE disposable_role; GRANT ROLE disposable_role TO USER temporary;',script=True)
        self.issue('temporary',key_out='temporary-recreated.key')
        (self.output/'temporary.key').write_text((self.output/'temporary-recreated.key').read_text())
        self.check('recreated username cannot inherit old direct object grant',self.cli('temporary','COUNT docs;')['rows'][0]['count']==0)
        # Mixed update is atomic; hidden and missing targets share one envelope.
        good,bad = self.ids['finance'],self.ids['locked']
        mixed_update = self.cli('ingestion-writer',f"UPDATE POINTS IN docs {{id:'{good}',vector:[1,0],payload:{{text:'must-not-commit'}}}},{{id:'{bad}',vector:[1,0],payload:{{text:'forbidden'}}}};",code=1)
        self.check('mixed update reaches object authorization',json.loads(mixed_update.stdout)['code']=='security.not_found')
        self.check('mixed update unchanged',self.cli('ingestion-writer',f"GET docs POINTS '{good}';")['rows'][0]['payload']['text']=='finance')
        hidden = self.query('ingestion-writer',f"UPDATE POINTS IN docs {{id:'{bad}',vector:[1,0],payload:{{text:'x'}}}};",expected=404)
        missing = self.query('ingestion-writer',"UPDATE POINTS IN docs {id:'missing',vector:[1,0],payload:{text:'x'}};",expected=404)
        self.check('hidden/missing error envelope matches', {k:v for k,v in hidden.items() if k!='query_id'}=={k:v for k,v in missing.items() if k!='query_id'})
        mixed_create = self.cli('ingestion-writer',"CREATE POINTS INTO docs USING TEMPLATE finance {vector:[1,0],payload:{text:'valid'}},{vector:[1],payload:{text:'invalid'}} REQUEST invalid-batch;",code=1)
        self.check('mixed create reaches core validation',json.loads(mixed_create.stdout)['code']=='security.invalid')
        self.check('mixed create remains atomic',self.cli('ingestion-writer','COUNT docs;')['rows'][0]['count']==4)
        # A readable object is not necessarily deletable. Preview is advisory;
        # confirmation must reauthorize after the role changes.
        temporary = self.cli('ingestion-writer',
            "CREATE POINTS INTO docs USING TEMPLATE finance {vector:[1,0],payload:{text:'filter-proof'}},{vector:[1,0],payload:{text:'filter-proof'}} REQUEST filter-proof;")
        owned, shared = [row['id'] for row in temporary['rows']]
        self.cli(ADMIN,f"ALTER POINT '{shared}' IN docs SET OWNER finance-reader;")
        self.cli(ADMIN,f"GRANT READ ON POINT '{shared}' IN docs TO USER ingestion-writer;")
        self.check('filter fixture has two readable objects',
                   self.cli('ingestion-writer',"COUNT docs WHERE text = 'filter-proof';")['rows'][0]['count']==2)
        filtered = "DELETE FROM docs WHERE text = 'filter-proof';"
        preview = self.cli('ingestion-writer',filtered,code=1)
        self.check('delete preview requires confirmation',json.loads(preview.stdout)['code']=='chironql.confirmation_required')
        self.check('delete preview contains no object identity or estimate',
                   all(value not in preview.stdout+preview.stderr for value in [owned,shared,'affected_estimate']))
        self.cli(ADMIN,'REVOKE DELETE ON COLLECTION docs FROM ROLE ingestion-writer_role;')
        self.cli('ingestion-writer',filtered,code=1,yes=True)
        self.check('confirmation cannot bypass revoked delete',
                   self.cli('ingestion-writer',"COUNT docs WHERE text = 'filter-proof';")['rows'][0]['count']==2)
        self.cli(ADMIN,'GRANT DELETE ON COLLECTION docs TO ROLE ingestion-writer_role;')
        deleted = self.cli('ingestion-writer',filtered,yes=True)
        self.check('filtered delete uses delete domain, not read domain',deleted['stats']['affected']==1)
        self.check('read-only shared object survives filtered delete',
                   self.cli('finance-reader',f"GET docs POINTS '{shared}';")['rows'][0]['id']==shared)
        self.cli(ADMIN,f"ALTER POINT '{shared}' IN docs SET OWNER ingestion-writer;")
        self.cli('ingestion-writer',f"DELETE FROM docs POINTS '{shared}';")
        self.cli('ingestion-writer',f"UPDATE POINTS IN docs {{id:'{good}',vector:[1,0],payload:{{text:'finance-updated'}}}};")
        self.cli('ingestion-writer',f"DELETE FROM docs POINTS '{self.ids['disposable']}';")
        self.cli('ingestion-writer',"CREATE POINTS INTO docs USING TEMPLATE hr {vector:[0,1],payload:{text:'different'}} REQUEST create-hr;",code=1)
        self.cli('ingestion-writer',"UPSERT INTO docs {id:'arbitrary',vector:[1,0]};",code=1)
        # Key rotation and revocation are durable, old credential is immediately rejected.
        old = self.credentials['hr-reader']['id']
        result = self.cli(ADMIN,f"ROTATE API KEY '{old}';",key_out='hr-replacement.key')
        self.cli('hr-reader','SHOW CURRENT USER;',code=1)
        replacement = (self.output/'hr-replacement.key').read_text().strip()
        self.issued_secrets.add(replacement)
        (self.output/'hr-reader.key').write_text(replacement)
        self.credentials['hr-reader']={'id':next(row['credential_id'] for row in result['rows'] if 'credential_id'in row),'secret':replacement}
        # Crash and retry a prior committed create: no duplicate or stale grant restoration.
        self.stop(crash=True)
        self.start()
        query = "CREATE POINTS INTO docs USING TEMPLATE hr {vector:[0, 1],payload:{text:'hr',secret:'RESTRICTED_PAYROLL_MARKER'}} REQUEST 'create-hr';"  # Synthetic example payload; this marker is not a credential.
        self.check('durable create retry after crash',self.cli('ingestion-writer',query)['rows'][0]['id']==self.ids['hr'])
        self.check('restart role and clearance persist',self.cli('finance-reader','COUNT docs;')['rows'][0]['count']==3)
        self.check('restart delete persists',self.cli('hr-reader','COUNT docs;')['rows'][0]['count']==1)
        self.cli(ADMIN,f"REVOKE API KEY '{self.credentials['hr-reader']['id']}';")
        self.grpc('hr-reader','COUNT docs;',grpc.StatusCode.UNAUTHENTICATED)
        self.wire('hr-reader','COUNT docs;',denied=True)
        self.issue('hr-reader',key_out='hr-final.key')
        (self.output/'hr-reader.key').write_text((self.output/'hr-final.key').read_text())
        old_root = self.credentials[ADMIN]['id']
        rotated = self.cli(ADMIN,f"ROTATE API KEY '{old_root}'; SHOW USERS;",key_out='root-replacement.key',script=True)
        self.check('root self-rotation continues with the new credential',len(rotated[1]['rows'])>=5)
        root_secret = (self.output/'root-replacement.key').read_text().strip()
        self.issued_secrets.add(root_secret)
        self.credentials[ADMIN]={'id':next(row['credential_id'] for row in rotated[0]['rows'] if 'credential_id' in row),'secret':root_secret}
        (self.output/'security-admin.key').write_text(root_secret)
        # Secret scans of public-facing artifacts and daemon logs.
        for log in self.output.glob('server-*.log'):
            text = log.read_text()
            self.check('server log excludes payload markers', 'RESTRICTED_PAYROLL_MARKER' not in text)
            for secret in self.issued_secrets:
                self.check('server log excludes every issued secret, including revoked keys',secret not in text)
        self.stop()

    def migration_cli(self, locked):
        args = [str(self.cli_binary.with_name('chironctl')), 'security', 'migrate-authority',
                '--data-dir', str(self.output/'data'), '--keyring', str(self.output/'encryption-keyring.json')]
        result = subprocess.run(args, capture_output=True, text=True, timeout=15)
        self.transcript.append({'transport':'offline-cli','operation':'migrate-authority',
                                'directory_locked':locked,'exit':result.returncode,
                                'stdout':result.stdout,'stderr':result.stderr})
        self.check('offline migration refuses active authority' if locked else 'v2 migration is idempotent',
                   result.returncode != 0 if locked else result.returncode == 0)
        if not locked:
            self.check('v2 authority is not rewritten',json.loads(result.stdout)=={'identity_format':2,'migrated':False})

    def save(self, error=None):
        # A later rotation must not erase the leak oracle for earlier keys.
        public = json.dumps([self.transcript, self.requests, self.checks, error])
        self.check('all issued and revoked keys excluded from exported evidence',
                   all(secret not in public for secret in self.issued_secrets))
        (self.output/'chironql-transcript.json').write_text(json.dumps(self.transcript,indent=2))
        (self.output/'chironql-requests.json').write_text(json.dumps(self.requests,indent=2))
        (self.output/'chironql-matrix.json').write_text(json.dumps(self.checks,indent=2))
        (self.output/'chironql-report.json').write_text(json.dumps({'status':'failed' if error else 'passed','error':error,'checks':len(self.checks),'failed':sum(not c['passed'] for c in self.checks),'requests':len(self.requests),'cli_commands':len(self.transcript),'server_starts':self.starts,'server_sha256':digest(self.binary),'cli_sha256':digest(self.cli_binary),'performance':getattr(self,'performance',None),'scope':'single-tenant single-node; synthetic exact authorized domain; not production certification'},indent=2))
        # Private active keys support separate verification, never published.
        (self.output/'credentials.json').write_text(json.dumps(self.credentials,indent=2))
        (self.output/'fixture.json').write_text(json.dumps({'tenant':'acme','ids':self.ids},indent=2))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--cli',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args = parser.parse_args()
    lab = ChironLab(args.binary,args.cli,args.output)
    error = None
    try:
        lab.run()
    except Exception:
        error = traceback.format_exc()
        raise
    finally:
        lab.stop()
        lab.save(error)
    print(json.dumps({'status':'passed','checks':len(lab.checks),'requests':len(lab.requests),'cli_commands':len(lab.transcript)}))

if __name__=='__main__':
    main()
