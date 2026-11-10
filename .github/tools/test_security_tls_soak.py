#!/usr/bin/env python3
"""Reject false browser successes and credential-bearing client diagnostics."""
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import security_tls_soak as soak


class TlsFixtureTests(unittest.TestCase):
    def test_browser_requires_completed_body(self):
        with tempfile.TemporaryDirectory(prefix="chiron-tls-fixture-") as directory:
            root = Path(directory)
            args = SimpleNamespace(output=root / "evidence.json", page_port=18080, chrome="chrome", openssl="openssl")
            probe = soak.Soak(args, root, {"initial_cert": root / "initial.crt",
                                           "replacement_cert": root / "replacement.crt"})
            with patch.object(soak, "spki_pin", return_value="synthetic-pin"), \
                    patch.object(soak, "command") as client:
                for body in [
                    '<body>pending<script>const success = "grpc-web-passed";</script></body>',
                    '<body>grpc-web-failed</body>',
                ]:
                    client.return_value = SimpleNamespace(stdout=body)
                    with self.assertRaises(RuntimeError):
                        probe.browser()
                client.return_value = SimpleNamespace(stdout='<body>grpc-web-passed</body>')
                probe.browser()

    def test_legacy_tls_requires_server_rejection(self):
        with tempfile.TemporaryDirectory(prefix="chiron-tls-probe-") as directory:
            root = Path(directory)
            args = SimpleNamespace(output=root / "evidence.json", page_port=18080,
                                   http_port=17401, openssl="openssl")
            probe = soak.Soak(args, root, {"ca_cert": root / "ca.crt"})
            with patch.object(soak, "command"), patch.object(soak.subprocess, "run") as client:
                client.return_value = SimpleNamespace(returncode=1, stderr="no protocols available")
                with self.assertRaises(RuntimeError):
                    probe.tls_version_matrix()
                client.return_value = SimpleNamespace(returncode=1, stderr="SSL alert number 40")
                probe.tls_version_matrix()
                client.return_value = SimpleNamespace(returncode=0, stderr="")
                with self.assertRaises(RuntimeError):
                    probe.tls_version_matrix()

    def test_failed_client_diagnostics_do_not_disclose_credentials(self):
        secret = "synthetic-" + "sensitive-value"
        args = ["client", "--credential", secret]
        failure = subprocess.CalledProcessError(1, args, output=secret, stderr=secret)
        with patch.object(soak.subprocess, "run", side_effect=failure):
            with self.assertRaises(RuntimeError) as raised:
                soak.command(args)
        self.assertNotIn(secret, str(raised.exception))
        self.assertIn("client", str(raised.exception))

    def test_timeout_diagnostics_do_not_disclose_credentials(self):
        secret = "synthetic-" + "sensitive-value"
        args = ["client", "--credential", secret]
        failure = subprocess.TimeoutExpired(args, 30, output=secret, stderr=secret)
        with patch.object(soak.subprocess, "run", side_effect=failure):
            with self.assertRaises(RuntimeError) as raised:
                soak.command(args)
        self.assertNotIn(secret, str(raised.exception))
        self.assertIn("TimeoutExpired", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
