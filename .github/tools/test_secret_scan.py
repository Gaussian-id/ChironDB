#!/usr/bin/env python3
"""Exercise the scanner's exit-status and redaction contract in disposable trees."""
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest


SCANNER = Path(__file__).with_name("secret_scan.sh")
RIPGREP = shutil.which("rg")


class SecretScanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="chiron-secret-scan-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.secret = "synthetic-" + "A" * 32
        self.env = dict(os.environ)

    def scan(self):
        return subprocess.run(
            ["/bin/bash", str(SCANNER)], cwd=self.root, env=self.env,
            capture_output=True, text=True, timeout=10,
        )

    def credential(self, value=None):
        (self.root / "config.txt").write_text('api_key = "' + (value or self.secret) + '"\n')

    def fake_rg(self, script):
        binary = self.root / "bin"
        binary.mkdir()
        executable = binary / "rg"
        executable.write_text("#!/bin/bash\n" + script)
        executable.chmod(0o700)
        self.env["PATH"] = str(binary)

    def test_clean_tree(self):
        self.assertEqual(self.scan().returncode, 0)

    def test_match_fails_without_printing_secret(self):
        self.credential()
        result = self.scan()
        self.assertEqual(result.returncode, 1)
        self.assertFalse(self.secret in result.stdout + result.stderr,
                         "scanner emitted matching credential bytes")

    def test_placeholder_is_not_a_finding(self):
        self.credential("replace-with-" + "A" * 32)
        self.assertEqual(self.scan().returncode, 0)

    def test_missing_scanner_fails(self):
        self.env["PATH"] = str(self.root / "absent")
        self.assertGreater(self.scan().returncode, 1)

    def test_search_error_fails(self):
        self.fake_rg("exit 2\n")
        self.assertGreater(self.scan().returncode, 1)

    def test_filter_error_fails_without_printing_secret(self):
        self.assertIsNotNone(RIPGREP, "rg is required to test the scanner")
        self.credential()
        self.fake_rg('if [[ "${1:-}" == "-v" ]]; then exit 2; fi\n'
                     'exec ' + shlex.quote(RIPGREP) + ' "$@"\n')
        result = self.scan()
        self.assertGreater(result.returncode, 1)
        self.assertFalse(self.secret in result.stdout + result.stderr,
                         "scanner emitted matching credential bytes on failure")


if __name__ == "__main__":
    unittest.main()
