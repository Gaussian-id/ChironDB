#!/usr/bin/env python3
"""Prove an actual old binary refuses even an empty protected installation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def file_hashes(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob('*')) if path.is_file()}


def main(args):
    root = args.output.resolve()
    root.mkdir(mode=0o700)
    secrets = root / 'secrets'
    secrets.mkdir(mode=0o700)
    env = {key: value for key, value in os.environ.items() if not key.startswith(('CHIRONDB_', 'GAUSSDB_', 'OTEL_'))}
    records = []
    def run(command):
        result = subprocess.run([str(x) for x in command], env=env, capture_output=True, text=True, timeout=60)
        records.append({'command': [str(x) for x in command], 'exit': result.returncode,
                        'stdout': result.stdout, 'stderr': result.stderr})
        return result
    initialized = run([args.ctl, 'security', 'init', '--data-dir', root / 'original',
                       '--tenant', 'default', '--admin', 'admin', '--keyring-out', secrets / 'storage.json',
                       '--admin-key-out', secrets / 'admin.key'])
    assert initialized.returncode == 0, initialized.stderr
    fences = []
    for case in ['root', 'generation']:
        target = root / case
        shutil.copytree(root / 'original', target)
        data = target if case == 'root' else target / 'generations' / (target / 'CURRENT').read_text().strip()
        before = file_hashes(target)
        keyring_before = hashlib.sha256((secrets / 'storage.json').read_bytes()).hexdigest()
        rejected = run([args.old_binary, '--data-dir', data, '--encryption-keyring-file', secrets / 'storage.json',
                        '--listen-http', '127.0.0.1:17551', '--listen-grpc', '127.0.0.1:17552', '--listen-wire', '127.0.0.1:17553'])
        assert rejected.returncode != 0 and 'failed to open data dir' in rejected.stderr, rejected
        assert 'expected value at line 1 column 1' in rejected.stderr, rejected.stderr
        after = file_hashes(target)
        changed = sorted(path for path in before.keys() | after.keys()
                         if before.get(path) != after.get(path))
        # The historical reader acquires its advisory lock before decoding the
        # protected marker. Compare every authoritative file, including additions.
        changed_data = [path for path in changed if not path.endswith('.chirondb.lock')]
        assert not changed_data, changed_data
        keyring_after = hashlib.sha256((secrets / 'storage.json').read_bytes()).hexdigest()
        assert keyring_before == keyring_after, 'old binary changed the storage keyring'
        fences.append({'case': case, 'unchanged_data_files': len(before),
                       'changed_data_paths': changed_data, 'advisory_lock_paths': changed,
                       'keyring_unchanged': True})
    report = {'passed': True, 'empty_catalog': True, 'records': records,
              'mutation_fences': fences,
              'old_binary_sha256': hashlib.sha256(args.old_binary.read_bytes()).hexdigest(),
              'ctl_sha256': hashlib.sha256(args.ctl.read_bytes()).hexdigest()}
    text = json.dumps(report, indent=2)
    assert (secrets / 'admin.key').read_text().strip() not in text
    (root / 'report.json').write_text(text)
    print(json.dumps({'passed': True, 'checks': len(records)}))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--ctl', type=Path, required=True)
    parser.add_argument('--old-binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    main(parser.parse_args())
