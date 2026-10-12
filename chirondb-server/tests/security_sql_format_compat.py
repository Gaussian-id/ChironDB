#!/usr/bin/env python3
"""Run an actual prior reader on a fenced, disposable protected fixture copy."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import time
import urllib.request


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def manifest(root):
    result = {}
    for path in sorted(root.rglob('*')):
        if path.is_symlink():
            raise ValueError('compatibility fixtures must not contain symlinks')
        if path.is_file():
            result[str(path.relative_to(root))] = digest(path)
    return result


def main(args):
    # mkdir without exist_ok prevents reusing or overwriting earlier evidence.
    root = args.output.resolve()
    data = root / 'probe'
    source = args.fixture.resolve()
    if root == source or source in root.parents:
        raise ValueError('evidence output must be outside the source fixture')
    original = manifest(source)
    before_version, after_version = {'sql-guard': (1, 2), 'table-authority': (2, 4),
                                     'sql-scopes': (4, 5)}[args.migration]
    if not (source / '.protected-installation').read_text().startswith(f'CHRNINSTALL{before_version}\n'):
        raise ValueError(f'control fixture must use installation format {before_version}')
    root.mkdir(mode=0o700, parents=True)
    control = root / 'control'
    shutil.copytree(source, control)
    shutil.copytree(source, data)
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('CHIRONDB_', 'GAUSSDB_', 'OTEL_'))}
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        control_port = listener.getsockname()[1]

    def old_command(directory, http_port):
        return [str(args.old_binary.resolve()), '--data-dir', str(directory),
                '--encryption-keyring-file', str(args.keyring.resolve()),
                '--tenant-enforcement', 'enforced',
                '--tls-cert', str(args.tls_cert.resolve()),
                '--tls-key', str(args.tls_key.resolve()),
                '--listen-http', f'127.0.0.1:{http_port}',
                '--listen-grpc', '127.0.0.1:0', '--listen-wire', '127.0.0.1:0']

    # A working prior reader is the control for the next-format refusal.
    prior = subprocess.Popen(old_command(control, control_port), env=env,
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    control_ready = False
    context = ssl._create_unverified_context()
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and prior.poll() is None:
            try:
                with urllib.request.urlopen(f'https://127.0.0.1:{control_port}/health',
                                            context=context, timeout=1) as response:
                    control_ready = response.status == 200
                if control_ready:
                    break
            except (OSError, ssl.SSLError):
                time.sleep(0.1)
    finally:
        if prior.poll() is None:
            prior.terminate()
        try:
            _, control_stderr = prior.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            prior.kill()
            _, control_stderr = prior.communicate(timeout=10)
    if not control_ready:
        raise RuntimeError(f'prior reader could not serve the format-{before_version} control: '
                           + control_stderr[-1000:])

    migrated = subprocess.run(
        [str(args.ctl.resolve()), 'security', f'migrate-{args.migration}', '--data-dir', str(data),
         '--keyring', str(args.keyring.resolve())],
        env=env, capture_output=True, text=True, timeout=60)
    if migrated.returncode != 0:
        raise RuntimeError('candidate guard migration failed: ' + migrated.stderr)
    if not (data / '.protected-installation').read_text().startswith(f'CHRNINSTALL{after_version}\n'):
        raise RuntimeError(f'candidate did not publish installation format {after_version}')
    before = manifest(data)
    command = old_command(data, 0)
    timed_out = False
    try:
        probe = subprocess.run(command, env=env, capture_output=True, text=True, timeout=30)
        code, stderr = probe.returncode, probe.stderr
    except subprocess.TimeoutExpired:
        timed_out, code, stderr = True, None, 'prior reader did not reject within 30 seconds'
    after = manifest(data)
    changed = sorted(key for key in before.keys() | after.keys() if before.get(key) != after.get(key))
    original_preserved = manifest(source) == original
    # A CLI parse error or generic startup failure is not format-refusal evidence.
    refused = code not in (None, 0) and 'security installation' in stderr.lower()
    passed = control_ready and refused and not timed_out and not changed and original_preserved
    report = {
        'passed': passed, 'control_served_health': control_ready,
        'migration': args.migration, 'before_format': before_version, 'after_format': after_version,
        'old_reader_exit': code, 'timed_out': timed_out,
        'format_refusal': refused, 'changed_paths': changed,
        'original_preserved': original_preserved, 'before': before, 'after': after,
        'old_binary_sha256': digest(args.old_binary),
        'ctl_sha256': digest(args.ctl),
    }
    (root / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': passed, 'changed_paths': changed, 'report': str(root / 'report.json')}))
    if not passed:
        raise SystemExit(1)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--ctl', type=Path, required=True)
    parser.add_argument('--old-binary', type=Path, required=True)
    parser.add_argument('--migration', choices=['sql-guard', 'table-authority', 'sql-scopes'], default='sql-guard')
    parser.add_argument('--fixture', type=Path, required=True)
    parser.add_argument('--keyring', type=Path, required=True)
    parser.add_argument('--tls-cert', type=Path, required=True)
    parser.add_argument('--tls-key', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    main(parser.parse_args())
