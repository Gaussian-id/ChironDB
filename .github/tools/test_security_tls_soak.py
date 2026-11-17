#!/usr/bin/env python3
"""Reject false browser successes and credential-bearing client diagnostics."""
from pathlib import Path
import http.client
import json
import socket
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import security_tls_soak as soak


class TlsFixtureTests(unittest.TestCase):
    def test_origin_waits_for_delayed_page(self):
        with tempfile.TemporaryDirectory(prefix="chiron-origin-ready-") as directory:
            root = Path(directory)
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            probe = soak.Soak(SimpleNamespace(output=root / "evidence.json", page_port=port), root, {})
            probe.browser_page.parent.mkdir()
            probe.browser_page.write_text("the expected fixture page")
            real_popen = subprocess.Popen

            def delayed_origin(argv, **kwargs):
                code = ("import runpy,sys,time;time.sleep(1);"
                        "sys.argv=['http.server',*sys.argv[1:]];"
                        "runpy.run_module('http.server',run_name='__main__')")
                return real_popen([argv[0], "-c", code, *argv[3:]], **kwargs)

            try:
                with patch.object(soak.subprocess, "Popen", side_effect=delayed_origin):
                    probe.start_browser_origin()
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=0.2)
                try:
                    connection.request("GET", "/")
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.read(), probe.browser_page.read_bytes())
                finally:
                    connection.close()
            finally:
                probe.close()

    def test_origin_rejects_exited_child(self):
        with tempfile.TemporaryDirectory(prefix="chiron-origin-exit-") as directory:
            root = Path(directory)
            probe = soak.Soak(SimpleNamespace(output=root / "evidence.json", page_port=18080), root, {})
            probe.browser_page.parent.mkdir()
            probe.browser_page.write_text("the expected fixture page")
            child = Mock()
            child.poll.return_value = 1
            try:
                with patch.object(soak.subprocess, "Popen", return_value=child):
                    with self.assertRaisesRegex(RuntimeError, "origin exited"):
                        probe.start_browser_origin()
            finally:
                probe.close()

    def test_generated_chains_pass_strict_certificate_validation(self):
        with tempfile.TemporaryDirectory(prefix="chiron-tls-pki-") as directory:
            pki = soak.generate_pki(Path(directory), "openssl")
            for name, purpose in [("initial", "sslserver"),
                                  ("replacement", "sslserver"),
                                  ("client", "sslclient")]:
                with self.subTest(certificate=name):
                    result = subprocess.run(
                        ["openssl", "verify", "-x509_strict", "-purpose", purpose,
                         "-CAfile", str(pki["ca_cert"]), str(pki[f"{name}_cert"])],
                        capture_output=True, text=True, timeout=10,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)

    def test_browser_requires_completed_body(self):
        with tempfile.TemporaryDirectory(prefix="chiron-tls-fixture-") as directory:
            root = Path(directory)
            args = SimpleNamespace(output=root / "evidence.json", page_port=18080, grpc_port=17402, chrome="chrome", openssl="openssl")
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

    def test_browser_failure_states_do_not_disclose_page_or_stderr(self):
        secret = "synthetic-" + "sensitive-value"
        with tempfile.TemporaryDirectory(prefix="chiron-browser-state-") as directory:
            root = Path(directory)
            args = SimpleNamespace(output=root / "evidence.json", page_port=18080, grpc_port=17402, chrome="chrome", openssl="openssl")
            probe = soak.Soak(args, root, {"initial_cert": root / "initial.crt",
                                         "replacement_cert": root / "replacement.crt"})
            with patch.object(soak, "spki_pin", return_value="synthetic-pin"), \
                    patch.object(soak, "command") as client:
                for state in ("pending", "grpc-web-failed", "grpc-web-error"):
                    with self.subTest(state=state):
                        client.return_value = SimpleNamespace(
                            stdout=f'<body>{state}<script>const key="{secret}";</script></body>',
                            stderr=secret + " ERR_CONNECTION_REFUSED",
                        )
                        with self.assertRaises(RuntimeError) as raised:
                            probe.browser()
                        self.assertIn(f"state={state}", str(raised.exception))
                        self.assertIn("network=ERR_CONNECTION_REFUSED", str(raised.exception))
                        self.assertNotIn(secret, str(raised.exception))

    def test_netlog_ignores_other_requests_and_unsafe_values(self):
        url = "https://127.0.0.1:17402/chirondb.v1.ChironDb/ExecuteQuery"
        with tempfile.TemporaryDirectory(prefix="chiron-netlog-") as directory:
            path = Path(directory) / "trace.json"
            events = [
                {"source": {"id": 1}, "params": {"url": url}},
                {"source": {"id": 1}, "params": {"net_error": -21}},
                {"source": {"id": 2}, "params": {"url": "https://background.invalid", "net_error": -102}},
            ]
            for value in [True, "sensitive-value", -1001, 0, 200, -21]:
                events.append({"source": {"id": 1}, "params": {"net_error": value}})
            path.write_text(json.dumps({"events": events}))
            self.assertEqual(soak.browser_target_net_errors(path, url), [-21])
            for payload in ["{", "{}", '{"events":[null]}']:
                path.write_text(payload)
                self.assertEqual(soak.browser_target_net_errors(path, url), [])
            path.unlink()
            self.assertEqual(soak.browser_target_net_errors(path, url), [])

    def test_browser_reports_only_safe_categories_and_removes_netlog(self):
        secret = "synthetic-" + "sensitive-value"
        with tempfile.TemporaryDirectory(prefix="chiron-browser-netlog-") as directory:
            root = Path(directory)
            args = SimpleNamespace(output=root / "evidence.json", page_port=18080,
                                   grpc_port=17402, chrome="chrome", openssl="openssl")
            probe = soak.Soak(args, root, {"initial_cert": root / "initial.crt",
                                         "replacement_cert": root / "replacement.crt"})
            traces = []

            def browser(argv):
                trace = Path(next(value.split("=", 1)[1] for value in argv if value.startswith("--log-net-log=")))
                traces.append(trace)
                self.assertEqual(trace.parent.stat().st_mode & 0o777, 0o700)
                url = "https://127.0.0.1:17402/chirondb.v1.ChironDb/ExecuteQuery"
                trace.write_text(json.dumps({"events": [
                    {"source": {"id": 1}, "params": {"url": url, "headers": secret}},
                    {"source": {"id": 1}, "params": {"net_error": -102}},
                ]}))
                return SimpleNamespace(
                    stdout='<body data-probe-phase="fetch" data-probe-error="TypeError">grpc-web-error</body>',
                    stderr=secret,
                )

            with patch.object(soak, "spki_pin", return_value="synthetic-pin"), \
                    patch.object(soak, "command", side_effect=browser):
                with self.assertRaises(RuntimeError) as raised:
                    probe.browser()
                message = str(raised.exception)
                self.assertIn("phase=fetch, error=TypeError, target_net_errors=[-102]", message)
                self.assertNotIn(secret, message)
            self.assertTrue(traces)
            self.assertTrue(all(not path.parent.exists() for path in traces))

    def test_browser_removes_private_trace_on_success_or_client_error(self):
        with tempfile.TemporaryDirectory(prefix="chiron-browser-cleanup-") as directory:
            root = Path(directory)
            args = SimpleNamespace(output=root / "evidence.json", page_port=18080,
                                   grpc_port=17402, chrome="chrome", openssl="openssl")
            probe = soak.Soak(args, root, {"initial_cert": root / "initial.crt",
                                         "replacement_cert": root / "replacement.crt"})
            for failure in (False, True):
                traces = []

                def browser(argv):
                    trace = Path(next(value.split("=", 1)[1] for value in argv if value.startswith("--log-net-log=")))
                    traces.append(trace)
                    trace.write_text("synthetic-sensitive-value")
                    if failure:
                        raise RuntimeError("external client chrome failed: TimeoutExpired")
                    return SimpleNamespace(stdout="<body>grpc-web-passed</body>")

                with self.subTest(client_failure=failure), \
                        patch.object(soak, "spki_pin", return_value="synthetic-pin"), \
                        patch.object(soak, "command", side_effect=browser):
                    if failure:
                        with self.assertRaises(RuntimeError):
                            probe.browser()
                    else:
                        probe.browser()
                self.assertTrue(traces)
                self.assertTrue(all(not path.parent.exists() for path in traces))

    def test_unknown_browser_exception_text_is_not_published(self):
        with tempfile.TemporaryDirectory(prefix="chiron-browser-category-") as directory:
            root = Path(directory)
            args = SimpleNamespace(output=root / "evidence.json", page_port=18080,
                                   grpc_port=17402, chrome="chrome", openssl="openssl")
            probe = soak.Soak(args, root, {"initial_cert": root / "initial.crt",
                                         "replacement_cert": root / "replacement.crt"})
            secret = "synthetic-" + "sensitive-value"
            with patch.object(soak, "spki_pin", return_value="synthetic-pin"), \
                    patch.object(soak, "command", return_value=SimpleNamespace(
                        stdout=f'<body data-probe-phase="{secret}" data-probe-error="{secret}">grpc-web-error</body>',
                        stderr=secret,
                    )):
                with self.assertRaises(RuntimeError) as raised:
                    probe.browser()
                self.assertIn("phase=none, error=none", str(raised.exception))
                self.assertNotIn(secret, str(raised.exception))

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
