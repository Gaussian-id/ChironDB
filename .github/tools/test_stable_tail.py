#!/usr/bin/env python3
"""Run the physical deadline gate without other workspace tests competing for CPU."""
import argparse
import re
import subprocess
import sys


def run(command):
    result = subprocess.run(command, capture_output=True, text=True)
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    if result.returncode:
        raise SystemExit(result.returncode)
    return result.stdout


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--target')
    args = parser.parse_args()
    name = 'stable_tail::tests::real_shard_smoke_emits_both_modes'
    for binary in ['chironbench', 'gaussbench']:
        command = ['cargo', 'test', '-p', 'chirondb', '--bin', binary, '--locked', '-j', '2']
        if args.target:
            command += ['--target', args.target]
        command += [name, '--', '--exact']
        registered = run(command + ['--list'])
        if registered.splitlines().count(name + ': test') != 1:
            raise SystemExit('physical stable-tail test must be registered exactly once: ' + binary)
        executed = run(command + ['--test-threads=1'])
        if not re.search(r'^test result: ok\. 1 passed; 0 failed; 0 ignored;', executed, re.M):
            raise SystemExit('physical stable-tail test did not run and pass: ' + binary)


if __name__ == '__main__':
    main()
