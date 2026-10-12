#!/usr/bin/env python3
"""Check documentation coverage and execute protected examples in a new TLS installation."""
import argparse
import ast
import json
from pathlib import Path
import re
import ssl
import subprocess
import sys
import urllib.error
import urllib.request

import pexpect

from security_installation_e2e import InstallationLab

REPO = Path(__file__).resolve().parents[2]
CORPUS = REPO / 'chirondb-server/tests/fixtures/chironql_documentation.json'
DOCUMENTS = [REPO / 'docs/CHIRONQL_SECURITY.md', REPO / 'docs/CHIRONQL_LEGACY_EXAMPLES.md']


def enum_variants(path, name):
    body = re.search(r'pub enum ' + name + r' \{(.*?)\n\}', path.read_text(), re.S).group(1)
    return set(re.findall(r'^    ([A-Z]\w*)\b', body, re.M))


def check_coverage():
    corpus = json.loads(CORPUS.read_text())
    examples = corpus['examples']
    ids = [example['id'] for example in examples]
    assert len(ids) == len(set(ids)), 'Duplicate example ID'
    blocks = []
    for path in DOCUMENTS:
        blocks.extend(re.findall(r'<!-- chironql-example: ([\w-]+) -->\s*```sql\n(.*?)\n```',
                                 path.read_text(), re.S))
    assert len(blocks) == len(examples), 'Every corpus example needs one documented SQL block'
    documented = dict(blocks)
    assert len(documented) == len(blocks), 'Duplicate documented example'
    for example in examples:
        assert documented.get(example['id']) == example['sql'], 'Documentation drift: ' + example['id']
    security = enum_variants(REPO / 'chirondb-server/src/chironql_parser/security.rs', 'SecurityCommand')
    base = enum_variants(REPO / 'chirondb-server/src/chironql_parser.rs', 'Statement') - {'Security'}
    actual = {example['variant'] for example in examples}
    assert security <= actual, 'Undocumented security variants: ' + str(security - actual)
    assert {'base:' + name for name in base} <= actual, 'Undocumented base statements'
    actions = enum_variants(REPO / 'chirondb-types/src/security.rs', 'Action')
    snake = lambda name: re.sub(r'(?<!^)(?=[A-Z])', '_', name).lower()
    assert {'action-' + snake(name) for name in actions} <= set(ids), 'Undocumented action vocabulary'
    meta_source = (REPO / 'chirondb-server/src/chironql_repl.rs').read_text().split('fn meta_command', 1)[1].split('const HELP', 1)[0]
    meta_aliases = {name.replace('\\\\', '\\') for name in re.findall(r'"(\\\\[^\"]+)"', meta_source)} | {'clear;'}
    meta_examples = corpus['meta_commands']
    assert meta_aliases <= {entry['input'].split()[0] for entry in meta_examples}, 'Undocumented meta-command'
    text = '\n'.join(path.read_text() for path in DOCUMENTS)
    assert all(entry['input'] in text for entry in meta_examples), 'Missing meta-command example'
    return examples, {'examples': len(examples), 'security_variants': len(security),
                      'base_variants': len(base), 'actions': len(actions),
                      'meta_examples': len(meta_examples)}


class DocumentationLab(InstallationLab):
    def help_examples(self):
        document = DOCUMENTS[0].read_text()
        help_text = self.run([self.bin / 'chironql', '--help']).stdout
        flags = set(re.findall(r'--[a-z][a-z-]+', help_text))
        self.check('all standalone CLI flags documented',
                   all(flag in document for flag in flags), sorted(flags))
        help_text = self.run([self.bin / 'chironctl', 'security', '--help']).stdout
        commands = re.findall(r'^  ([a-z][a-z-]+)\s', help_text.split('Options:', 1)[0], re.M)
        self.check('all offline security commands documented',
                   all('security ' + command in document for command in commands), commands)
        for command in commands:
            if command == 'help':
                continue
            help_text = self.run([self.bin / 'chironctl', 'security', command, '--help']).stdout
            flags = set(re.findall(r'--[a-z][a-z-]+', help_text))
            self.check('offline flags documented: ' + command,
                       all(flag in document for flag in flags), sorted(flags))

    def terminal_examples(self):
        entries = json.loads(CORPUS.read_text())['meta_commands']
        args = [str(arg) for arg in self.cli_args('writer')]
        for quit_command in ['\\q', '\\quit']:
            child = pexpect.spawn(args[0], args[1:], env=self.env, encoding='utf-8', timeout=15)
            try:
                child.expect('chiron> ')
                commands = entries if quit_command == '\\q' else []
                for entry in commands:
                    command = entry['input']
                    if command in ['\\q', '\\quit']:
                        continue
                    child.sendline(command)
                    child.expect('chiron> ')
                    output = child.before
                    # Rustyline emits bracketed-paste/synchronized-output CSI
                    # controls on capable terminals. Compare visible text and
                    # remove only the exact command echo, retaining unexpected output.
                    visible = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', output)
                    lines = visible.splitlines()
                    while lines and not lines[0].strip():
                        lines.pop(0)
                    if lines and lines[0].strip() == command:
                        lines.pop(0)
                    body = '\n'.join(lines).strip()
                    expected = entry['expected_output']
                    matched = expected in body if expected else not body
                    self.check('PTY meta-command ' + command,
                               matched and ('chironql.protected_unsupported' in body) == entry['denied'], output)
                child.sendline(quit_command)
                child.expect(pexpect.EOF)
                child.close()
                # The REPL retains earlier query failures in its final exit status.
                expected_exit = 1 if any(entry['denied'] for entry in commands) else 0
                self.check('PTY quit alias ' + quit_command,
                           child.exitstatus == expected_exit, child.exitstatus)
            finally:
                if child.isalive():
                    child.terminate(force=True)

    def api_examples(self):
        # Generate schemas through the existing real transport probe.
        self.transport('grpc', 'admin', 'SHOW CURRENT USER;')
        document = DOCUMENTS[0].read_text()
        blocks = re.findall(r'<!-- executable-python: ([\w-]+) -->\s*```python\n(.*?)\n```', document, re.S)
        self.check('three complete API examples', len(blocks) == 3)
        env = dict(self.env, CHIRON_HOME=str(self.root), CHIRON_URL=self.base,
                   CHIRON_CA=str(self.root / 'ca.pem'), CHIRON_ADMIN_KEY=str(self.keys['admin']),
                   CHIRON_GRPC=f'localhost:{self.args.port + 1}', CHIRON_HOST='localhost',
                   CHIRON_WIRE_PORT=str(self.args.port + 2), PYTHONPATH=str(self.root / 'generated'))
        for name, code in blocks:
            source = self.root / (name + '.py')
            source.write_text(code + '\n')
            result = subprocess.run([sys.executable, str(source)], env=env, text=True,
                                    capture_output=True, timeout=20)
            rows = ast.literal_eval(result.stdout.splitlines()[0]) if result.returncode == 0 else []
            self.check('executable API example ' + name,
                       result.returncode == 0 and len(rows) == 1 and rows[0]['name'] == 'admin',
                       {'exit': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr})

    def execute_example(self, example, substitutions):
        sql = example['sql']
        for name in sorted(substitutions, key=len, reverse=True):
            sql = sql.replace(name, substitutions[name])
        if example.get('revision'):
            revision = self.query('admin', 'SHOW SECURITY REVISION;')['rows'][0]['revision']
            sql = sql.replace('IF REVISION 9', 'IF REVISION ' + str(revision))
        args = self.cli_args(example['actor'])
        if example.get('confirm'):
            args += ['--yes']
        issued = example.get('issue') or example.get('rotate')
        destination = self.secrets / (example['id'] + '.key') if issued else None
        if destination:
            args += ['--key-out', destination]
        result = self.run(args + ['--exec', sql], example.get('exit', 0))
        response = json.loads(result.stdout)
        self.executed.append({'id': example['id'], 'sql': sql, 'actor': example['actor'],
                              'exit': result.returncode, 'result': response})
        if result.returncode:
            expected = {'stale-revision': 'security.conflict', 'nondelegable': 'security.forbidden',
                        'legacy-upsert-denied': 'chironql.protected_unsupported'}[example['id']]
            self.check('expected error ' + example['id'], response['code'] == expected, response['code'])
        if destination:
            if example.get('rotate'):
                old = self.keys[issued]
                self.keys['old-' + issued] = old
            self.keys[issued] = destination
            key_id = destination.read_text().strip().split('.')[1]
            if issued == 'ana':
                substitutions['ROTATED_KEY_ID' if example.get('rotate') else 'KEY_ID'] = key_id
        rows = response.get('rows', [])
        if 'save' in example:
            self.check('one server-generated ID ' + example['id'], len(rows) == 1)
            substitutions[example['save']] = rows[0]['id']
        if 'save_batch' in example:
            self.check('batch ID count ' + example['id'], len(rows) == len(example['save_batch']))
            for key, row in zip(example['save_batch'], rows):
                substitutions[key] = row['id']
        if 'same_id' in example:
            self.check('idempotent example does not duplicate',
                       [row['id'] for row in rows] == [substitutions[example['same_id']]])
        if 'save_cursor' in example:
            self.check('cursor is returned', bool(response.get('next')))
            substitutions[example['save_cursor']] = response['next']
        if 'expected_rows' in example:
            self.check('row oracle ' + example['id'], len(rows) == example['expected_rows'], rows)
        if 'count' in example:
            self.check('count oracle ' + example['id'], rows[0]['count'] == example['count'], rows)
        if example['id'] in ['grant-point', 'deny-point', 'revoke-deny', 'revoke-grant']:
            allowed = example['id'] in ['grant-point', 'revoke-deny']
            rows = self.query('ben', "GET docs POINTS '" + substitutions['POINT_ID'] + "';").get('rows', [])
            self.check('cross-department ACL ' + example['id'], bool(rows) == allowed)
        if example['id'] == 'suspend-user':
            self.query('ana', 'SHOW CURRENT USER;', 1)
        if example['id'] == 'activate-user':
            self.query('ana', 'SHOW CURRENT USER;')
        if example['id'] == 'rotate-key':
            self.query('old-ana', 'SHOW CURRENT USER;', 1)
            self.query('ana', 'SHOW CURRENT USER;')
        if example['id'] == 'revoke-key':
            self.query('ana', 'SHOW CURRENT USER;', 1)

    def verify_examples(self, examples, coverage):
        self.executed = []
        self.help_examples()
        self.run(self.init_args())
        self.certificates()
        self.start()
        self.check('complete documented syntax inventory', True, coverage)
        tls = ssl.create_default_context(cafile=str(self.root / 'ca.pem'))
        secret = self.keys['admin'].read_text().strip()
        for example in examples:
            for prefix in ['', '/v1']:
                request = urllib.request.Request(self.base + prefix + '/chironql/parse',
                    data=json.dumps({'query': example['sql']}).encode(),
                    headers={'Authorization': 'Bearer ' + secret, 'Content-Type': 'application/json'})
                try:
                    with urllib.request.urlopen(request, context=tls, timeout=15) as response:
                        status, result = response.status, json.load(response)
                except urllib.error.HTTPError as error:
                    status, result = error.code, json.load(error)
                valid = status == 200 if example['mode'] != 'reject' else (
                    status == 400 and result.get('code', '').startswith('chironql.'))
                self.check('parse ' + prefix + ' ' + example['id'], valid,
                           {'status': status, 'response': result})
        substitutions = {}
        for example in examples:
            if example['mode'] == 'execute':
                self.execute_example(example, substitutions)
        self.terminal_examples()
        self.api_examples()
        self.stop()
        self.run([self.bin / 'chironctl', 'security', 'verify-audit', '--data-dir', self.root / 'data',
                  '--keyring', self.keyring])
        self.run([self.bin / 'chironctl', 'security', 'verify-encryption', '--data-dir', self.root / 'data',
                  '--keyring', self.keyring])
        (self.root / 'executed-examples.json').write_text(json.dumps(self.executed, indent=2) + '\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--check-only', action='store_true', help='Check source/document coverage without starting a server')
    parser.add_argument('--bin-dir', type=Path, default=REPO / 'target/debug')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--port', type=int, default=19651)
    args = parser.parse_args()
    examples, coverage = check_coverage()
    if args.check_only:
        print(json.dumps(coverage, indent=2))
    else:
        if args.output is None:
            parser.error('--output must name a new private directory')
        lab = DocumentationLab(args)
        passed = False
        try:
            lab.verify_examples(examples, coverage)
            passed = True
        finally:
            try:
                lab.stop()
            finally:
                lab.save(passed)
