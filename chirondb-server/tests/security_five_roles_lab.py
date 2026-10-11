#!/usr/bin/env python3
"""Try the five synthetic profiles against a private copy of a passed E2E run.

This is a local test utility, not production provisioning or migration tooling.
Credential values are never printed or included in command-line arguments.
"""
import argparse
import http.client
import json
import os
from pathlib import Path
import shutil
import signal
from urllib.parse import urlsplit

from security_five_roles_e2e import Lab, digest, redacted


def private_json(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, 'w') as stream:
        json.dump(value, stream, indent=2)


def prepare(evidence, destination):
    report = json.loads((evidence / 'report.json').read_text())
    if report['status'] != 'passed':
        raise ValueError('only a fully passed E2E result can prepare the lab')
    binary = Path(report['binary'])
    if digest(binary) != report['binary_sha256']:
        raise ValueError('rebuild the tested binary or rerun E2E; the evidence binary has changed')
    destination.mkdir(mode=0o700)  # Never replace an existing lab or evidence.
    for name in ['data', 'fixture.json', 'credentials.json', 'encryption-keyring.json']:
        source = evidence / name
        if source.is_dir():
            shutil.copytree(source, destination / name)
        else:
            shutil.copy2(source, destination / name)
    # Preserve the tested executable even if later Cargo commands replace it.
    pinned_binary = destination / 'chirondb'
    shutil.copy2(binary, pinned_binary)
    pinned_binary.chmod(0o500)
    report['binary'] = str(pinned_binary.resolve())
    private_json(destination / 'report.json', report)
    print(json.dumps({'lab': str(destination.resolve()), 'source_evidence': str(evidence.resolve())}))


def serve(path):
    report = json.loads((path / 'report.json').read_text())
    binary = Path(report['binary'])
    if digest(binary) != report['binary_sha256']:
        raise ValueError('binary differs from the passed E2E evidence; rerun E2E first')
    lab = Lab(binary, path)
    connection_file = path / 'connection.json'

    def stop(_signal, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        lab.start()
        info = {'url': f'https://127.0.0.1:{lab.port}', 'ca_certificate': str(path.resolve() / 'ca-cert.pem'), 'supervisor_pid': os.getpid(), 'server_pid': lab.process.pid, 'binary_sha256': report['binary_sha256']}
        private_json(connection_file, info)
        print(json.dumps({**info, 'roles': list(lab.credentials)}), flush=True)
        lab.process.wait()
        raise RuntimeError('lab server exited unexpectedly; inspect server-1.log')
    except KeyboardInterrupt:
        pass
    finally:
        lab.stop()
        connection_file.unlink(missing_ok=True)


def request(path, args):
    import ssl
    info = json.loads((path / 'connection.json').read_text())
    url = urlsplit(info['url'])
    if url.scheme != 'https' or url.hostname != '127.0.0.1':
        raise ValueError('this lab client only connects to TLS loopback')
    if not args.path.startswith('/') or args.path.startswith('//'):
        raise ValueError('request path must be an absolute local API path')
    credentials = json.loads((path / 'credentials.json').read_text())
    token = credentials[args.role]['secret']
    context = ssl.create_default_context(cafile=info['ca_certificate'])
    connection = http.client.HTTPSConnection(url.hostname, url.port, context=context, timeout=15)
    try:
        body = None if args.body is None else json.dumps(json.loads(args.body)).encode()
        connection.request(args.method, args.path, body, {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'})
        response = connection.getresponse()
        raw = response.read()
        value = json.loads(raw) if 'application/json' in response.getheader('Content-Type', '') else {'bytes': len(raw)}
        print(json.dumps({'role': args.role, 'status': response.status, 'response': redacted(value)}, indent=2))
        return 0 if response.status < 400 else 1
    finally:
        connection.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--lab', type=Path, required=True)
    commands = parser.add_subparsers(dest='command', required=True)
    provision = commands.add_parser('prepare', help='copy a passed fixture to a new private directory')
    provision.add_argument('--evidence', type=Path, required=True)
    commands.add_parser('serve', help='start TLS loopback; Ctrl-C stops only this lab')
    commands.add_parser('roles', help='show the five capability profiles, without keys')
    call = commands.add_parser('request', help='send a request using a named profile')
    call.add_argument('--role', required=True, choices=['security-admin', 'operations-admin', 'ingestion-writer', 'finance-reader', 'hr-reader'])
    call.add_argument('--method', default='GET', choices=['GET', 'POST', 'PUT', 'DELETE'])
    call.add_argument('--path', default='/v1/security/whoami')
    call.add_argument('--body', help='JSON body; never pass credential secrets here')
    args = parser.parse_args()
    if args.command == 'prepare':
        prepare(args.evidence, args.lab)
    elif args.command == 'serve':
        serve(args.lab)
    elif args.command == 'roles':
        print(json.dumps(json.loads((args.lab / 'fixture.json').read_text())['principals'], indent=2))
    else:
        return request(args.lab, args)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
