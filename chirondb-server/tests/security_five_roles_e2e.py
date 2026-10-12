#!/usr/bin/env python3
"""Real-process TLS E2E; invoked after trusted Rust fixture provisioning.
No third-party Python packages. Credentials stay in an owner-only local file.
"""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import time
import traceback


def digest(path):
    h = hashlib.sha256()
    with open(path, 'rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def redacted(value):
    if isinstance(value, dict):
        return {k: '[REDACTED]' if k.lower() in {'secret', 'key', 'password', 'key_base64'} else redacted(v) for k, v in value.items()}
    if isinstance(value, list):
        return [redacted(v) for v in value]
    return value


class Lab:
    def __init__(self, binary, output):
        self.binary = binary.resolve()
        self.output = output.resolve()
        self.fixture = json.loads((output / 'fixture.json').read_text())
        self.credentials = json.loads((output / 'credentials.json').read_text())
        self.ids = self.fixture['ids']
        self.checks = []
        self.requests = []
        self.process = None
        self.sessions = {}
        self.starts = 0
        self.log = None
        self.legacy_key = 'synthetic-legacy-fallback-must-not-authenticate-0001'
        path = output / 'legacy-api-key.txt'
        path.write_text(self.legacy_key)
        path.chmod(0o600)
        config = output / 'tls.cnf'
        config.write_text('[ext]\nsubjectAltName=IP:127.0.0.1,DNS:localhost\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n')
        ca_config = output / 'ca.cnf'
        ca_config.write_text('[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ext\n[dn]\nCN=ChironDB Synthetic E2E CA\n[ext]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n')
        commands = [
            ['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-config',str(ca_config),'-keyout',str(output/'ca-key.pem'),'-out',str(output/'ca-cert.pem')],
            ['openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=localhost','-keyout',str(output/'tls-key.pem'),'-out',str(output/'server.csr')],
            ['openssl','x509','-req','-in',str(output/'server.csr'),'-CA',str(output/'ca-cert.pem'),'-CAkey',str(output/'ca-key.pem'),'-CAcreateserial','-days','2','-sha256','-extfile',str(config),'-extensions','ext','-out',str(output/'tls-cert.pem')],
        ]
        for command in commands:
            result = subprocess.run(command,capture_output=True,text=True)
            if result.returncode:
                raise RuntimeError('test TLS certificate creation failed: '+result.stderr)
        for name in ['tls-key.pem','ca-key.pem']:
            (output/name).chmod(0o600)
        self.tls = ssl.create_default_context(cafile=str(output/'ca-cert.pem'))

    def check(self, case, condition, actual=None):
        self.checks.append({'case': case, 'passed': bool(condition), 'actual': redacted(actual)})
        if not condition:
            raise AssertionError(case + ': ' + str(redacted(actual)))

    def start(self):
        with socket.socket() as s:
            s.bind(('127.0.0.1', 0))
            self.port = s.getsockname()[1]
        self.starts += 1
        self.log = open(self.output / f'server-{self.starts}.log', 'wb')
        env = {k: v for k, v in os.environ.items() if not k.startswith(('CHIRONDB_', 'GAUSSDB_', 'OTEL_'))}
        args = [str(self.binary), '--data-dir', str(self.output / 'data'), '--listen-http', f'127.0.0.1:{self.port}', '--listen-grpc', f'127.0.0.1:{getattr(self, "grpc_port", 0)}', '--listen-wire', f'127.0.0.1:{getattr(self, "wire_port", 0)}', '--tls-cert', str(self.output / 'tls-cert.pem'), '--tls-key', str(self.output / 'tls-key.pem'), '--encryption-keyring-file', str(self.output / 'encryption-keyring.json'), '--api-key-file', str(self.output / 'legacy-api-key.txt'), '--tenant-enforcement', 'enforced']
        self.process = subprocess.Popen(args, stdout=self.log, stderr=subprocess.STDOUT, env=env)
        self.sessions = {}
        deadline = time.monotonic() + 30
        last_error = None
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError('server exited; inspect server log')
            try:
                conn = http.client.HTTPSConnection('127.0.0.1', self.port, context=self.tls, timeout=1)
                conn.request('GET', '/health')
                response = conn.getresponse()
                response.read()
                conn.close()
                if response.status == 200:
                    return
                last_error = 'HTTP status ' + str(response.status)
            except (OSError, http.client.HTTPException) as error:
                last_error = str(error)
            time.sleep(.05)
        raise TimeoutError('server TLS readiness timeout: ' + str(last_error))

    def stop(self, crash=False):
        for session in self.sessions.values():
            session.close()
        self.sessions = {}
        if self.process and self.process.poll() is None:
            self.process.send_signal(signal.SIGKILL if crash else signal.SIGINT)
            try:
                self.process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
                if not crash:
                    raise TimeoutError('graceful server shutdown failed')
        if self.log:
            self.log.close()

    def request(self, role, method, path, body=None, expected=200, headers=None, token=None):
        connection = self.sessions.setdefault(role, http.client.HTTPSConnection('127.0.0.1', self.port, context=self.tls, timeout=15))
        hdr = {'Content-Type': 'application/json'}
        if token is None and role in self.credentials:
            token = self.credentials[role]['secret']
        if token:
            hdr['Authorization'] = 'Bearer ' + token
        hdr.update(headers or {})
        start = time.monotonic()
        reused = connection.sock is not None
        connection.request(method, path, json.dumps(body).encode() if body is not None else None, hdr)
        response = connection.getresponse()
        raw = response.read()
        content_type = response.getheader('Content-Type', '')
        value = json.loads(raw) if 'application/json' in content_type else {'bytes': len(raw)}
        record = {'role': role, 'method': method, 'path': path, 'request': redacted(body), 'expected_status': expected, 'status': response.status, 'response': redacted(value), 'connection_reused': reused, 'elapsed_ms': round((time.monotonic()-start)*1000, 2)}
        self.requests.append(record)
        self.check(f'{role} {method} {path} status', response.status == expected, record)
        self.check(f'{role} {method} {path} no-store', response.getheader('Cache-Control') == 'no-store', response.getheader('Cache-Control'))
        if response.status >= 400:
            self.check(f'{role} {method} {path} rejected HTTP/1 connection closes explicitly', response.getheader('Connection') == 'close')
        if response.will_close:
            self.sessions.pop(role).close()
        return value

    def policy_revision(self):
        return self.request('security-admin', 'GET', '/v1/collections/docs/security/revision')['revision']

    def identity_revision(self):
        return self.request('security-admin', 'GET', '/v1/security/whoami')['identity_revision']

    def acl(self, document, grants):
        return self.request('security-admin', 'PUT', f'/v1/collections/docs/security/objects/{self.ids[document]}/grants', {'expected_revision': self.policy_revision(), 'value': {'grants': grants, 'parent': None}})

    def point(self, document, text):
        return {'id': self.ids[document], 'vector': [1.0, 0.0], 'payload': {'text': text, 'secret': 'RESTRICTED_PAYROLL_MARKER'}}

    def get(self, role, ids, prefix='/v1'):
        return self.request(role, 'POST', prefix+'/collections/docs/points/get', {'ids': ids})['points']

    def run(self):
        self.start()
        # Use the actual security API to apply each declared access profile.
        for principal in self.fixture['principals']:
            self.request('security-admin', 'PUT', '/v1/security/principals', {'expected_revision': self.identity_revision(), 'value': principal})
        expected = {'ingestion-writer': {'finance', 'confidential', 'hr', 'disposable'}, 'finance-reader': {'finance', 'confidential', 'locked'}, 'hr-reader': {'hr', 'disposable'}}
        for prefix in ['', '/v1']:
            for role in self.credentials:
                me = self.request(role, 'GET', prefix+'/security/whoami')
                self.check(role+' has catalog identity', me['principal'] == role and me['tenant'] == 'acme', me)
                self.check(role+' identity revision requires identity management '+prefix, ('identity_revision' in me) == (role == 'security-admin'), me)
                self.request(role, 'GET', prefix+'/metrics', expected=200 if role in {'security-admin', 'operations-admin'} else 403)
                if role not in expected:
                    for endpoint, body in [('count', {}), ('points/get', {'ids': list(self.ids.values())}), ('scroll', {'limit': 100}), ('search', {'vector': [1, 0], 'k': 10, 'with_payload': True})]:
                        self.request(role, 'POST', prefix+'/collections/docs/'+endpoint, body, expected=403)
                    continue
                visible = {self.ids[x] for x in expected[role]}
                count = self.request(role, 'POST', prefix+'/collections/docs/count', {})
                self.check(role+' exact authorized count '+prefix, count['count'] == len(visible), count)
                points = self.get(role, list(self.ids.values()), prefix)
                self.check(role+' exact get domain '+prefix, {p['id'] for p in points} == visible, points)
                page = self.request(role, 'POST', prefix+'/collections/docs/scroll', {'limit': 100})
                self.check(role+' exact scroll domain '+prefix, {p['id'] for p in page['points']} == visible, page)
                search = self.request(role, 'POST', prefix+'/collections/docs/search', {'vector': [1, 0], 'k': 10, 'with_payload': True})
                self.check(role+' exact search domain '+prefix, {p['id'] for p in search['hits']} == visible, search)
                if role.endswith('reader'):
                    self.check(role+' hidden field omitted '+prefix, all('secret' not in p['payload'] for p in points+page['points']+search['hits']))
                    self.request(role, 'POST', prefix+'/collections/docs/count', {'filter': {'secret': 'guess'}}, expected=403)
            for role in ['security-admin', 'operations-admin', 'finance-reader', 'hr-reader']:
                self.request(role, 'PUT', prefix+'/collections/docs/points', {'points': [self.point('finance','unauthorized')]}, expected=403)
                self.request(role, 'POST', prefix+'/collections/docs/points/delete', {'ids': [self.ids['finance']]}, expected=403)
                self.request(role, 'POST', prefix+'/collections/docs/points/delete/filter', {'filter': {'text': 'finance'}}, expected=403)
            filtered = self.request('ingestion-writer', 'POST', prefix+'/collections/docs/points/delete/filter', {'filter': {'text': 'locked'}})
            self.check('filtered deletion excludes non-writable object '+prefix,filtered['deleted']==0)
        # A hidden object and a nonexistent ID must have the same read envelope.
        self.check('hidden and missing read envelopes identical', self.get('finance-reader',[self.ids['hr']]) == self.get('finance-reader',['nonexistent-id']) == [])
        for role in ['operations-admin','ingestion-writer','finance-reader','hr-reader']:
            self.request(role,'GET','/v1/collections/docs/security/revision',expected=403)
            self.request(role,'PUT',f'/v1/collections/docs/security/objects/{self.ids["finance"]}/grants',{'expected_revision':self.policy_revision(),'value':{'grants':[],'parent':None}},expected=403)
            self.request(role,'POST','/v1/security/credentials',{'expected_revision':self.identity_revision(),'principal':role},expected=403)
        # Credential aliases and ambiguous/forged identity inputs.
        for alias in ['x-api-key','x-gaussdb-api-key','x-chirondb-api-key']:
            self.request('alias-'+alias,'GET','/v1/security/whoami',headers={alias:self.credentials['finance-reader']['secret']})
        self.request('anonymous','GET','/v1/security/whoami',expected=401)
        self.request('legacy-key','GET','/v1/security/whoami',token=self.legacy_key,expected=401)
        self.request('finance-reader','GET','/v1/security/whoami',headers={'x-api-key':self.credentials['finance-reader']['secret']},expected=401)
        self.request('finance-reader','GET','/v1/security/whoami',headers={'x-tenant-id':'forged'},expected=403)
        # Mixed valid/hidden mutation is all-or-nothing.
        before = self.get('finance-reader',[self.ids['finance']])
        hidden = self.request('ingestion-writer','PUT','/v1/collections/docs/points',{'points':[self.point('finance','batch-must-not-commit'),self.point('locked','forbidden')]},expected=404)
        missing = self.request('ingestion-writer','PUT','/v1/collections/docs/points',{'points':[{'id':'nonexistent-id','vector':[1,0],'payload':{'text':'x'}}]},expected=404)
        self.check('hidden and missing mutation errors identical',hidden == missing)
        self.check('denied mixed batch preserved valid target',self.get('finance-reader',[self.ids['finance']]) == before)
        self.request('ingestion-writer','POST','/v1/collections/docs/points/delete',{'ids':[self.ids['finance'],self.ids['locked']]},expected=404)
        self.check('denied mixed delete preserved valid target',self.get('finance-reader',[self.ids['finance']]) == before)
        forged = self.point('finance','forged')
        forged['payload']['owner']='finance-reader'
        self.request('ingestion-writer','PUT','/v1/collections/docs/points',{'points':[forged]},expected=403)
        self.check('forged security attributes did not mutate data',self.get('finance-reader',[self.ids['finance']]) == before)
        # Explicit sharing within one organization, clearance and deny.
        permit={'subject':{'kind':'principal','id':'hr-reader'},'effect':'permit','actions':['read','search'],'inherit':False}
        self.acl('finance',[permit])
        self.check('explicit cross-department grant works',len(self.get('hr-reader',[self.ids['finance']])) == 1)
        self.acl('confidential',[permit])
        self.check('grant cannot bypass classification',self.get('hr-reader',[self.ids['confidential']]) == [])
        stale = self.policy_revision()
        deny={**permit,'effect':'deny'}
        self.acl('finance',[permit,deny])
        self.check('deny overrides permit',self.get('hr-reader',[self.ids['finance']]) == [])
        self.request('security-admin','PUT',f'/v1/collections/docs/security/objects/{self.ids["finance"]}/grants',{'expected_revision':stale,'value':{'grants':[permit],'parent':None}},expected=409)
        self.check('stale update preserved deny',self.get('hr-reader',[self.ids['finance']]) == [])
        # Revoke on an already established TLS keep-alive session.
        old_hr=self.credentials['hr-reader'].copy()
        self.request('hr-reader','GET','/v1/security/whoami')
        self.request('security-admin','POST',f'/v1/security/credentials/{old_hr["id"]}/revoke',{'expected_revision':self.identity_revision()})
        self.request('hr-reader','POST','/v1/collections/docs/count',{},expected=401)
        self.check('revoked credential denied on the established connection',self.requests[-1]['connection_reused'])
        self.request('revoked-new-connection','GET','/security/whoami',token=old_hr['secret'],expected=401)
        fresh=self.request('security-admin','POST','/v1/security/credentials',{'expected_revision':self.identity_revision(),'principal':'hr-reader'})
        self.credentials['hr-reader']=fresh
        (self.output/'credentials.json').write_text(json.dumps(self.credentials,indent=2))
        self.request('hr-reader','GET','/v1/security/whoami')
        before_async = self.get('finance-reader',[self.ids['finance']])
        self.request('ingestion-writer','PUT','/v1/collections/docs/points',{'points':[self.point('finance','finance-queued')],'wait':False},expected=400)
        self.check('protected asynchronous refusal preserves data',self.get('finance-reader',[self.ids['finance']]) == before_async)
        self.request('ingestion-writer','PUT','/v1/collections/docs/points',{'points':[self.point('finance','finance-queued')],'wait':True})
        self.check('synchronous retry is visible',self.get('finance-reader',[self.ids['finance']])[0]['payload']=={'text':'finance-queued'})
        self.request('ingestion-writer','PUT','/v1/collections/docs/points',{'points':[self.point('finance','finance-updated')],'wait':True})
        self.check('allowed content update visible',self.get('finance-reader',[self.ids['finance']])[0]['payload']=={'text':'finance-updated'})
        self.request('ingestion-writer','POST','/v1/collections/docs/points/delete',{'ids':[self.ids['disposable']]})
        self.request('ingestion-writer','PUT','/v1/collections/docs/points',{'points':[self.point('disposable','cannot-recreate')]},expected=404)
        # Unsupported protected routes cannot reach a legacy permissive handler.
        for role in self.credentials:
            for path,body in [('/v1/admin/snapshot',{}),('/v1/collections/docs/hybrid_search',{}),('/v1/collections/docs/graph/traverse',{})]:
                self.request(role,'POST',path,body,expected=403)
        label = {'expected_revision':self.policy_revision(),'value':{'labels':{'owner':'hr-reader','department':'HR','classification':'internal','quarantined':False},'properties':{'/text':{'classification':'internal','actions':['read','query','write']},'/secret':{'classification':'restricted','actions':['read','write']}}}}
        self.request('security-admin','PUT',f'/v1/collections/docs/security/objects/{self.ids["hr"]}/labels',label)
        self.request('ingestion-writer','PUT','/v1/collections/docs/points',{'points':[self.point('hr','former-owner-cannot-write')]},expected=404)
        self.check('authorized ownership transfer preserves HR read',len(self.get('hr-reader',[self.ids['hr']]))==1)
        self.stop(crash=True)
        self.start()
        for role in self.credentials:
            self.request(role,'GET','/v1/security/whoami')
        self.request('revoked-after-restart','GET','/v1/security/whoami',token=old_hr['secret'],expected=401)
        self.check('content survives killed-process recovery',self.get('finance-reader',[self.ids['finance']])[0]['payload']=={'text':'finance-updated'})
        self.check('deny survives killed-process recovery',self.get('hr-reader',[self.ids['finance']]) == [])
        self.check('delete survives killed-process recovery',self.get('hr-reader',[self.ids['disposable']]) == [])
        self.check('HR authorized count after recovery',self.request('hr-reader','POST','/v1/collections/docs/count',{})['count']==1)
        self.stop()

    def report(self, error=None):
        report={'status':'failed' if error else 'http_passed_pending_core','error':error,'binary_sha256':digest(self.binary),'binary':str(self.binary),'transport':'real server process, TLS certificate and hostname verified, loopback only','storage':'encrypted keyring configured; Rust parent verifies encrypted tree and audit after shutdown','roles':[{k:v for k,v in principal.items()} for principal in self.fixture['principals']], 'server_starts':self.starts,'http_requests':len(self.requests),'checks':len(self.checks),'passed_checks':sum(x['passed'] for x in self.checks),'results':self.checks,'limitations':['No production non-loopback startup claim','No gRPC/ChironWire/pgwire positive protected support','Protected graph/hybrid/snapshot unavailable and tested for refusal only','Queued-body unit test and sequential keep-alive revoke are not exhaustive concurrent stream verification','Fixture is trusted offline preparation, not production migration tooling','No performance, full fuzz, four-platform or independent-review acceptance']}
        (self.output/'requests.jsonl').write_text(''.join(json.dumps(x)+'\n' for x in self.requests))
        (self.output/'report.json').write_text(json.dumps(report,indent=2))
        print(json.dumps({k:report[k] for k in ['status','http_requests','checks','passed_checks','server_starts']}))


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--binary',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    lab=Lab(args.binary,args.output)
    error=None
    try:
        lab.run()
    except Exception as exc:
        error=type(exc).__name__+': '+str(exc)
        traceback.print_exc()
    finally:
        lab.stop()
        lab.report(error)
    return 1 if error else 0


if __name__=='__main__':
    raise SystemExit(main())
