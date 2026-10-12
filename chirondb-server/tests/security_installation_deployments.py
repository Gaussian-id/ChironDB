#!/usr/bin/env python3
"""Exercise the public installation flow under Compose or a real Linux systemd PID 1.

The systemd harness uses an isolated privileged Linux test container; this is
systemd integration evidence, not qualification of a particular production host.
"""
import argparse
import json
from pathlib import Path
import ssl
import subprocess
import time
import urllib.request

import pexpect
from security_installation_e2e import InstallationLab

ROOT = Path(__file__).resolve().parents[2]


class DeploymentLab(InstallationLab):
    def __init__(self, args):
        super().__init__(args)
        args.image = super().run(['docker', 'image', 'inspect', args.image, '--format', '{{.Id}}']).stdout.strip()
        if args.mode == 'systemd':
            args.systemd_image = super().run(['docker', 'image', 'inspect', args.systemd_image, '--format', '{{.Id}}']).stdout.strip()
        self.project = args.project
        self.compose = ['docker', 'compose', '-p', self.project, '-f', ROOT / 'deploy/protected/compose.yml']
        self.env.update(CHIRONDB_IMAGE=args.image, CHIRONDB_TLS_DIR=str(self.root / 'tls'),
                        CHIRONDB_HTTP_PORT=str(args.port), CHIRONDB_GRPC_PORT=str(args.port + 1),
                        CHIRONDB_WIRE_PORT=str(args.port + 2))
        self.running = False
        self.container = self.project + '-systemd'
        self.created = False
        self.delivery_dir = '/etc/chirondb/bootstrap' if args.mode == 'systemd' else '/run/chirondb-bootstrap'

    def prepare_systemd(self):
        if self.created:
            return
        super().run(['docker', 'run', '-d', '--name', self.container, '--privileged', '--cgroupns=private',
                     '--tmpfs', '/run', '--tmpfs', '/run/lock', '--tmpfs', '/tmp',
                     '-p', f'127.0.0.1:{self.args.port}:7401', '-p', f'127.0.0.1:{self.args.port+1}:7402',
                     '-p', f'127.0.0.1:{self.args.port+2}:7403', self.args.systemd_image])
        self.created = True
        super().run(['docker', 'exec', self.container, 'mkdir', '-p', '/etc/chirondb/tls', self.delivery_dir])
        super().run(['docker', 'exec', self.container, 'chown', '10001:10001', self.delivery_dir])
        super().run(['docker', 'exec', self.container, 'chmod', '0700', self.delivery_dir])
        for source, target in [('chirondb.toml', '/etc/chirondb/chirondb.toml'),
                               ('chirondb.service', '/etc/systemd/system/chirondb.service')]:
            super().run(['docker', 'cp', ROOT / 'deploy/protected' / source, self.container + ':' + target])
        super().run(['docker', 'exec', self.container, 'systemctl', 'daemon-reload'])

    def map_path(self, value):
        mappings = {str(self.root / 'data'): '/var/lib/chirondb/data',
                    str(self.keyring): '/etc/chirondb/secrets/storage-keyring.json'}
        text = str(value)
        if text in mappings:
            return mappings[text]
        if isinstance(value, Path) and value.parent == self.secrets:
            return self.delivery_dir + '/' + value.name
        return text

    def deliver(self, destination):
        if destination.exists():
            return
        if self.args.mode == 'systemd':
            container = self.container
        else:
            container = self.project + '-delivery'
            super().run(self.compose + ['run', '--name', container, '-d', '--no-deps', '--entrypoint', 'sleep', 'init', '60'])
        try:
            source = self.map_path(destination)
            super().run(['docker', 'cp', container + ':' + source, destination])
            destination.chmod(0o600)
        finally:
            if self.args.mode == 'compose':
                super().run(['docker', 'rm', '-f', container])

    def run(self, argv, code=0, label=None):
        if str(argv[0]) == str(self.bin / 'chironctl') and len(argv) > 2 and argv[1] == 'security':
            if self.args.mode == 'systemd':
                self.prepare_systemd()
                command = ['docker', 'exec', '--user', '10001:10001', self.container, 'chironctl']
            else:
                command = self.compose + ['run', '--rm', '--no-deps', 'init']
            p = super().run(command + [self.map_path(x) for x in argv[1:]], code, label)
            if p.returncode == 0 and argv[2] in ('init', 'recover-admin'):
                self.deliver(Path(argv[argv.index('--admin-key-out') + 1]))
                self.deliver(self.keyring)
            return p
        return super().run(argv, code, label)

    def certificates(self):
        super().certificates()
        tls = self.root / 'tls'
        tls.mkdir(mode=0o755)
        for name in ['server.pem', 'server.key', 'ca.pem']:
            if self.args.mode == 'systemd':
                super().run(['docker', 'cp', self.root / name, self.container + ':/etc/chirondb/tls/' + name])
                super().run(['docker', 'exec', self.container, 'chown', '10001:10001', '/etc/chirondb/tls/' + name])
            else:
                import shutil
                shutil.copyfile(self.root / name, tls / name)
                (tls / name).chmod(0o600 if name.endswith('.key') else 0o644)
        if self.args.mode == 'compose':
            # Model the operator's native-Linux ownership setup on these
            # disposable TLS files only. The service itself remains non-root.
            super().run(['docker', 'run', '--rm', '--user', '0', '--entrypoint', 'chown',
                         '-v', str(tls) + ':/tls', self.args.image, '10001:10001', '/tls/server.key'])

    def start(self):
        if self.args.mode == 'compose':
            super().run(self.compose + ['up', '-d', 'server'])
        else:
            super().run(['docker', 'exec', self.container, 'systemctl', 'start', 'chirondb'])
        self.running = True
        tls = ssl.create_default_context(cafile=str(self.root / 'ca.pem'))
        for _ in range(150):
            try:
                with urllib.request.urlopen(self.base + '/health', context=tls, timeout=.3) as response:
                    self.check('deployment TLS readiness', response.status == 200)
                    if self.args.mode == 'systemd':
                        super().run(['docker', 'exec', self.container, 'systemctl', 'is-active', 'chirondb'])
                    return
            except OSError:
                time.sleep(.2)
        if self.args.mode == 'compose':
            super().run(self.compose + ['logs', '--no-color', 'server'])
        else:
            super().run(['docker', 'exec', self.container, 'journalctl', '-u', 'chirondb', '--no-pager'])
        raise AssertionError('deployment failed readiness')

    def stop(self):
        super().stop()
        if self.running:
            if self.args.mode == 'compose':
                super().run(self.compose + ['stop', 'server'])
            else:
                super().run(['docker', 'exec', self.container, 'systemctl', 'stop', 'chirondb'])
            self.running = False

    def terminal(self, user, attached=False):
        if not attached:
            return super().terminal(user)
        if self.args.mode == 'compose':
            args = self.compose + ['run', '--rm', '--no-deps', '--service-ports',
                '-v', self.project + '_admin-delivery:/run/chirondb-bootstrap:ro', 'server',
                '--config', '/etc/chirondb/chirondb.toml', '--tenant-enforcement', 'enforced',
                '--console', '--console-api-key-file', self.delivery_dir + '/admin.key']
        else:
            args = ['docker', 'exec', '-it', '--user', '10001:10001', self.container, 'chirondb',
                '--config', '/etc/chirondb/chirondb.toml', '--tenant-enforcement', 'enforced',
                '--console', '--console-api-key-file', self.delivery_dir + '/admin.key']
        child = pexpect.spawn(str(args[0]), [str(x) for x in args[1:]], env=self.env, encoding='utf-8', timeout=30)
        try:
            child.expect_exact('chiron> ')
            self.check('deployment attached console identity', 'authenticated as admin' in child.before, child.before)
            child.sendline('SHOW CURRENT USER;')
            child.expect_exact('chiron> ')
            self.check('deployment attached console query', 'admin' in child.before, child.before)
            child.sendline('\\q')
            child.expect(pexpect.EOF)
            child.close()
            self.check('deployment attached console exit', child.exitstatus == 0, child.exitstatus)
        finally:
            if child.isalive():
                child.terminate(force=True)

    def deployment_checks(self):
        self.start()
        if self.args.mode == 'compose':
            result = super().run(self.compose + ['ps', '-q', 'server'])
            details = json.loads(super().run(['docker', 'inspect', result.stdout.strip()]).stdout)[0]
            self.check('normal server never mounts administrator delivery volume',
                       all(m['Destination'] != '/run/chirondb-bootstrap' for m in details['Mounts']))
            self.check('normal server is non-root', details['Config']['User'] == '10001:10001')
            for _ in range(20):
                state = json.loads(super().run(['docker', 'inspect', result.stdout.strip()]).stdout)[0]['State']
                if state.get('Health', {}).get('Status') == 'healthy':
                    break
                time.sleep(1)
            self.check('unauthenticated TLS Docker health check', state.get('Health', {}).get('Status') == 'healthy')
            super().run(self.compose + ['restart', 'server'])
        else:
            super().run(['docker', 'exec', self.container, 'systemctl', 'restart', 'chirondb'])
        time.sleep(1)
        self.query('finance', 'COUNT docs;')
        self.stop()

    def save(self, passed):
        image_id = self.args.systemd_image if self.args.mode == 'systemd' else self.args.image
        binaries = super().run(['docker', 'run', '--rm', '--entrypoint', 'sha256sum', image_id,
                               '/usr/local/bin/chirondb', '/usr/local/bin/chironql', '/usr/local/bin/chironctl']).stdout
        if self.args.mode == 'systemd':
            base = super().run(['docker', 'run', '--rm', '--entrypoint', 'sha256sum', self.args.image,
                               '/usr/local/bin/chirondb', '/usr/local/bin/chironql', '/usr/local/bin/chironctl']).stdout
            self.check('systemd harness contains the verified production binaries', base == binaries)
        super().save(passed)
        path = self.root / 'report.json'
        report = json.loads(path.read_text())
        report['client_binary_sha256'] = report.pop('binary_sha256')['chironql']
        report['runtime_image_id'] = image_id
        report['production_image_id'] = self.args.image
        report['runtime_binary_sha256'] = {line.split()[1]: line.split()[0] for line in binaries.splitlines()}
        report['deployment'] = self.args.mode
        report['systemd_environment'] = 'Linux container with systemd PID 1' if self.args.mode == 'systemd' else None
        path.write_text(json.dumps(report, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=['compose', 'systemd'], required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--systemd-image', default='chirondb-security-systemd-test:local')
    parser.add_argument('--project', required=True)
    parser.add_argument('--bin-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--port', type=int, default=17521)
    item = DeploymentLab(parser.parse_args())
    passed = False
    try:
        item.verify()
        item.deployment_checks()
        passed = True
    finally:
        try:
            item.stop()
        finally:
            item.save(passed)
