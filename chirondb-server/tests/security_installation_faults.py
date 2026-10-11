#!/usr/bin/env python3
"""Process-level onboarding/catalog failures, driven only through public commands."""
import argparse
import json
from pathlib import Path
import subprocess
import socket
import ssl
import time
from types import SimpleNamespace

from security_installation_e2e import InstallationLab


def exercise(args):
    args.output.mkdir(mode=0o700)
    summaries = []

    def lab(name):
        return InstallationLab(SimpleNamespace(output=args.output / name, bin_dir=args.bin_dir, port=args.port))

    def finish(item):
        item.stop()
        item.save(True)
        summaries.append({'case': item.root.name, 'checks': len(item.records), 'passed': True})

    item = lab('protected-startup')
    item.run(item.init_args())
    item.certificates()
    for case, removed, added, expected in [
        ('missing TLS', ['--tls-cert', '--tls-key'], [], 'TLS'),
        ('missing keyring', ['--encryption-keyring-file'], [], 'encryption'),
        ('disabled isolation', ['--tenant-enforcement'], ['--tenant-enforcement', 'disabled'], 'enforced'),
        ('insecure bypass', [], ['--allow-insecure-non-loopback'], 'insecure bypass'),
        ('legacy credential', [], ['--api-key-file', item.keys['admin']], 'legacy API key'),
        ('cluster', [], ['--cluster-node-id', '1'], 'single node'),
    ]:
        command = item.server_args()
        for flag in removed:
            index = command.index(flag)
            del command[index:index + 2]
        result = item.run(command + added, 1)
        item.check('startup rejects ' + case, expected.lower() in (result.stdout + result.stderr).lower())
    item.start()
    command = item.cli_args('admin')
    index = command.index('--ca-cert')
    del command[index:index + 2]
    item.run(command + ['--exec', 'SHOW CURRENT USER;'], 2)
    context = ssl.create_default_context(cafile=str(item.root / 'ca.pem'))
    try:
        with socket.create_connection(('127.0.0.1', args.port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname='wrong-host.invalid'):
                item.check('TLS rejects mismatched hostname', False)
    except ssl.SSLCertVerificationError:
        item.check('TLS rejects mismatched hostname', True)
    finish(item)

    for stage in ['prepared', 'key_delivered', 'authority_committed', 'ready']:
        item = lab('init-' + stage)
        item.env['CHIRONDB_FAILPOINT'] = 'exit:security_init.' + stage
        item.run(item.init_args(), 86)
        item.env.pop('CHIRONDB_FAILPOINT')
        item.certificates()
        delivered = item.keys['admin'].read_bytes() if item.keys['admin'].exists() else None
        if stage != 'ready':
            item.run(item.server_args(), 1)
            item.run(item.init_args() + ['--resume'])
        if delivered is not None:
            item.check('resume preserves exact delivered credential', delivered == item.keys['admin'].read_bytes())
        item.start()
        item.query('admin', 'SHOW CURRENT USER;')
        item.query('admin', 'CREATE PROTECTED COLLECTION docs DIM 2;')
        finish(item)

    item = lab('concurrent-init')
    marker = item.root / 'paused'
    item.env['CHIRONDB_FAILPOINT'] = 'pause:security_init.prepared'
    item.env['CHIRONDB_FAILPOINT_MARKER'] = str(marker)
    child = subprocess.Popen([str(x) for x in item.init_args()], env=item.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        for _ in range(200):
            if marker.exists():
                break
            time.sleep(.025)
        item.check('initialization holds lock at prepared boundary', marker.exists())
        item.env.pop('CHIRONDB_FAILPOINT')
        item.env.pop('CHIRONDB_FAILPOINT_MARKER')
        item.run(item.init_args(), 1)
    finally:
        child.kill()
        child.wait()
    item.run(item.init_args() + ['--resume'])
    finish(item)

    for stage in ['staged', 'committed', 'activated']:
        item = lab('collection-' + stage)
        item.run(item.init_args())
        item.certificates()
        item.env['CHIRONDB_FAILPOINT'] = 'exit:protected_collection.' + stage
        item.start()
        # A killed server cannot deliver the response; the client must report failure.
        item.run(item.cli_args('admin') + ['--exec', 'CREATE PROTECTED COLLECTION docs DIM 2;'], 2)
        item.server.wait(timeout=15)
        item.check('catalog process killed at boundary', item.server.returncode == 86)
        item.server = None
        item.env.pop('CHIRONDB_FAILPOINT')
        item.start()
        revision = item.query('admin', 'SHOW CATALOG REVISION;')['rows'][0]['revision']
        item.check('durable catalog revision after crash', revision == (1 if stage == 'staged' else 2), revision)
        if stage == 'staged':
            item.query('admin', 'CREATE PROTECTED COLLECTION docs DIM 2;')
        else:
            item.query('admin', 'CREATE PROTECTED COLLECTION docs DIM 2;', 1)
        policy = item.query('admin', 'SHOW COLLECTION docs SECURITY POLICY;')['rows'][0]['policy']
        item.check('recovered collection protected and deny by default', policy == {'department_actions': [], 'owner_actions': [], 'templates': {}}, policy)
        item.query('admin', 'COUNT docs;', 1)
        finish(item)

    for point, committed in [('wal.after_record_write', False), ('wal.after_sync', False),
                             ('transaction.before_commit_fsync', True)]:
        item = lab('catalog-failure-' + point.replace('.', '-'))
        item.run(item.init_args())
        item.certificates()
        item.env['CHIRONDB_FAILPOINT'] = 'error:' + point
        item.start()
        failure = json.loads(item.run(item.cli_args('admin') +
                                     ['--exec', 'CREATE PROTECTED COLLECTION docs DIM 2;'], 1).stdout)
        item.check('catalog failure reports the decision boundary',
                   failure['code'] == ('chironql.outcome_unknown' if committed else 'security.unavailable'),
                   failure['code'])
        result = item.query('admin', 'SHOW CURRENT USER;', 1)
        item.check('unresolved catalog commit closes protected admission', result['code'] == 'security.unavailable', result['code'])
        item.stop()
        item.env.pop('CHIRONDB_FAILPOINT')
        item.start()
        # PREPARE alone cannot create a collection. A written COMMIT whose sync
        # reports failure must reconcile to the complete protected generation.
        revision = item.query('admin', 'SHOW CATALOG REVISION;')['rows'][0]['revision']
        item.check('catalog recovery follows the canonical commit decision',
                   revision == (2 if committed else 1), revision)
        if committed:
            item.query('admin', 'CREATE PROTECTED COLLECTION docs DIM 2;', 1)
        else:
            item.query('admin', 'SHOW COLLECTION docs SECURITY POLICY;', 1)
            item.query('admin', 'CREATE PROTECTED COLLECTION docs DIM 2;')
        policy = item.query('admin', 'SHOW COLLECTION docs SECURITY POLICY;')['rows'][0]['policy']
        item.check('uncertain catalog commit recovers protected policy', policy == {'department_actions': [], 'owner_actions': [], 'templates': {}}, policy)
        item.query('admin', 'COUNT docs;', 1)
        finish(item)

    for stage in ['security_recover.prepared', 'security_init.key_delivered', 'security_init.authority_committed']:
        item = lab('recover-' + stage.replace('.', '-'))
        initial = json.loads(item.run(item.init_args()).stdout)
        replacement = item.secrets / 'replacement.key'
        command = [item.bin / 'chironctl', 'security', 'recover-admin', '--data-dir', item.root / 'data',
                   '--keyring', item.keyring, '--admin-key-out', replacement, '--yes']
        item.env['CHIRONDB_FAILPOINT'] = 'exit:' + stage
        item.run(command, 86)
        item.env.pop('CHIRONDB_FAILPOINT')
        item.certificates()
        item.run(item.server_args(), 1)
        recovered = json.loads(item.run(command + ['--resume']).stdout)
        item.check('resumed recovery replaces administrator', recovered['principal_id'] != initial['principal_id'])
        item.start()
        item.query('admin', 'SHOW CURRENT USER;', 1)
        item.keys['old-admin'] = item.keys['admin']
        item.keys['admin'] = replacement
        item.query('admin', 'SHOW CURRENT USER;')
        finish(item)

    for point in ['audit.before_append', 'audit.before_sync']:
        item = lab('failure-' + point.replace('.', '-'))
        item.env['CHIRONDB_FAILPOINT'] = 'error:' + point
        item.run(item.init_args(), 1)
        item.env.pop('CHIRONDB_FAILPOINT')
        item.certificates()
        item.run(item.server_args(), 1)
        item.run(item.init_args() + ['--resume'])
        item.start()
        item.query('admin', 'SHOW CURRENT USER;')
        finish(item)

    item = lab('unsafe-paths')
    item.root.joinpath('data').mkdir(mode=0o700)
    sentinel = item.root / 'data' / 'existing.txt'
    sentinel.write_text('existing user data')
    item.run(item.init_args(), 1)
    item.check('existing data preserved', sentinel.read_text() == 'existing user data' and not item.keyring.exists())
    # Corruption testing deliberately changes a separate disposable installation,
    # never the valid installation or its published evidence.
    finish(item)
    item = lab('corrupt-authority')
    item.run(item.init_args())
    authority = item.root / 'data' / 'security' / 'identity.catalog'
    if not authority.exists():
        authority = next((item.root / 'data' / 'security').iterdir())
    data = bytearray(authority.read_bytes())
    data[-1] ^= 1
    authority.write_bytes(data)
    item.certificates()
    item.run(item.server_args(), 1)
    item.run([item.bin / 'chironctl', 'security', 'recover-admin', '--data-dir', item.root / 'data',
              '--keyring', item.keyring, '--admin-key-out', item.secrets / 'no.key', '--yes'], 1)
    item.check('corruption never issues replacement key', not (item.secrets / 'no.key').exists())
    finish(item)
    for case in ['overlap', 'symlink-output', 'symlink-lock', 'umask-zero']:
        item = lab(case)
        command = item.init_args()
        if case == 'overlap':
            command[command.index('--keyring-out') + 1] = item.root / 'data' / 'storage.json'
        elif case == 'symlink-output':
            (item.root / 'alias').symlink_to(item.secrets, target_is_directory=True)
            command[command.index('--keyring-out') + 1] = item.root / 'alias' / 'storage.json'
        elif case == 'symlink-lock':
            victim = item.root / 'operator-file'
            victim.write_text('preserve operator file')
            (item.root / '.data.chirondb.lock').symlink_to(victim)
        if case == 'umask-zero':
            result = subprocess.run([str(value) for value in command], env=item.env, capture_output=True, text=True, timeout=30, umask=0)
            item.check('init succeeds with permissive process umask', result.returncode == 0, {'exit': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr})
            for path in [item.root / 'data', item.root / 'data' / 'security', item.secrets]:
                item.check('directory created privately under umask zero', path.stat().st_mode & 0o777 == 0o700, str(path))
            for path in [item.keyring, item.keys['admin']]:
                item.check('secret created privately under umask zero', path.stat().st_mode & 0o777 == 0o600, str(path))
        else:
            item.run(command, 1)
            item.check('unsafe path never receives a credential', not item.keys['admin'].exists())
            if case == 'symlink-lock':
                item.check('lock never follows or overwrites symlink target', victim.read_text() == 'preserve operator file')
        finish(item)

    for case in ['corrupt-marker', 'dangling-journal', 'delivery-collision']:
        item = lab(case)
        if case == 'delivery-collision':
            item.env['CHIRONDB_FAILPOINT'] = 'exit:security_init.prepared'
            item.run(item.init_args(), 86)
            item.env.pop('CHIRONDB_FAILPOINT')
            item.keys['admin'].write_text('unrelated operator file\n')
            item.keys['admin'].chmod(0o600)
            item.run(item.init_args() + ['--resume'], 1)
            item.check('resume never overwrites unrelated delivery file', item.keys['admin'].read_text() == 'unrelated operator file\n')
            # This file is deliberately not a credential.
            item.keys.clear()
        else:
            item.run(item.init_args())
            if case == 'corrupt-marker':
                (item.root / 'data' / '.protected-installation').write_text('invalid')
            else:
                (item.root / 'data' / '.security-onboarding').symlink_to(item.root / 'absent-journal')
        item.certificates()
        item.run(item.server_args(), 1)
        finish(item)
    (args.output / 'summary.json').write_text(json.dumps(summaries, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--bin-dir', type=Path, required=True, help='Binaries built with fault-injection')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--port', type=int, default=17511)
    exercise(parser.parse_args())
