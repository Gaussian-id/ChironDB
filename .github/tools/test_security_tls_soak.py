#!/usr/bin/env python3
"""Reject false browser successes and credential-bearing client diagnostics."""
from pathlib import Path
from contextlib import contextmanager
import threading
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

    @contextmanager
    def managed_driver(self, root, specs):
        target = "https://127.0.0.1:17402/chirondb.v1.ChironDb/ExecuteQuery"
        contexts = []
        pending = iter(specs)

        def new_context(**kwargs):
            spec = next(pending)
            events = {}
            page = Mock()
            page.on.side_effect = lambda name, callback: events.__setitem__(name, callback)
            handle = Mock()
            handle.json_value.return_value = spec.get("result", {"state": "grpc-web-passed"})
            page.wait_for_function.return_value = handle
            if spec.get("wait_error"):
                page.wait_for_function.side_effect = RuntimeError(spec["wait_error"])

            def navigate(*args, **options):
                if spec.get("response", True):
                    events["response"](SimpleNamespace(
                        url=target, status=200,
                        request=SimpleNamespace(method=spec.get("method", "POST")),
                    ))
                if spec.get("network"):
                    events["requestfailed"](SimpleNamespace(url=target, failure=spec["network"]))

            page.goto.side_effect = navigate
            context = Mock()
            context.new_page.return_value = page
            if spec.get("close_error"):
                context.close.side_effect = RuntimeError(spec["close_error"])
            contexts.append((context, page, kwargs))
            return context

        browser = Mock()
        browser.version = "157.0.8103.78"
        browser.new_context.side_effect = new_context
        driver = Mock()
        driver.chromium.launch.return_value = browser
        probe = soak.BrowserProbe("chrome", "http://127.0.0.1:18080/", target,
                                  "known-server-pins", root / "browser-netlog.json")
        with patch.object(soak, "start_browser_driver", return_value=driver), \
                patch("importlib.metadata.version", return_value="1.64.1"):
            yield probe, driver, browser, contexts

    def test_one_process_fresh_verified_contexts_and_real_completed_responses(self):
        with tempfile.TemporaryDirectory(prefix="chiron-managed-browser-") as directory:
            root = Path(directory)
            with self.managed_driver(root, [{}, {}]) as (probe, driver, browser, contexts):
                with probe:
                    probe.check()
                    probe.check()
                driver.chromium.launch.assert_called_once()
                options = driver.chromium.launch.call_args.kwargs
                self.assertNotIn("--ignore-certificate-errors", options["args"])
                self.assertIn("--ignore-certificate-errors-spki-list=known-server-pins", options["args"])
                self.assertNotIn("ignore_default_args", options)
                self.assertEqual(probe.metadata["contexts_created"], 2)
                self.assertTrue(all(options["ignore_https_errors"] is False for _, _, options in contexts))
                self.assertTrue(all(context.close.call_count == 1 for context, _, _ in contexts))
                browser.close.assert_called_once()
                driver.stop.assert_called_once()

    def test_completed_dom_without_real_post_response_cannot_pass(self):
        with tempfile.TemporaryDirectory(prefix="chiron-managed-response-") as directory:
            root = Path(directory)
            for spec in [{"response": False}, {"method": "GET"},
                         {"result": {"state": "pending<script>grpc-web-passed</script>"}}]:
                with self.subTest(spec=spec), self.managed_driver(root, [spec]) as (probe, *_):
                    with probe, self.assertRaises(RuntimeError):
                        probe.check()

    def test_managed_failure_reports_only_categories(self):
        secret = "synthetic-" + "sensitive-value"
        with tempfile.TemporaryDirectory(prefix="chiron-managed-error-") as directory:
            root = Path(directory)
            specs = [
                {"response": False, "network": "net::ERR_CERT_VERIFIER_CHANGED",
                 "result": {"state": "grpc-web-error", "phase": "fetch", "error": "TypeError"}},
                {"response": False, "network": "net::" + secret,
                 "result": {"state": secret, "phase": secret, "error": secret}},
            ]
            with self.managed_driver(root, specs) as (probe, _, _, contexts):
                with probe:
                    with self.assertRaises(RuntimeError) as raised:
                        probe.check()
                    self.assertIn("ERR_CERT_VERIFIER_CHANGED", str(raised.exception))
                    self.assertIn("phase=fetch, error=TypeError", str(raised.exception))
                    with self.assertRaises(RuntimeError) as raised:
                        probe.check()
                    self.assertIn("unclassified", str(raised.exception))
                    self.assertNotIn(secret, str(raised.exception))
                self.assertTrue(all(context.close.call_count == 1 for context, _, _ in contexts))

    def test_managed_driver_errors_and_cleanup_cannot_disclose_or_pass(self):
        secret = "synthetic-" + "sensitive-value"
        with tempfile.TemporaryDirectory(prefix="chiron-managed-cleanup-") as directory:
            root = Path(directory)
            for spec in [{"wait_error": secret}, {"close_error": secret}]:
                with self.subTest(spec=spec), self.managed_driver(root, [spec]) as (probe, _, _, contexts):
                    with probe, self.assertRaises(RuntimeError) as raised:
                        probe.check()
                    self.assertNotIn(secret, str(raised.exception))
                    contexts[0][0].close.assert_called_once()

    def test_private_netlog_is_removed_on_session_success_or_shutdown_failure(self):
        secret = "synthetic-" + "sensitive-value"
        with tempfile.TemporaryDirectory(prefix="chiron-managed-netlog-") as directory:
            root = Path(directory)
            for failed_shutdown in [False, True]:
                with self.subTest(failed_shutdown=failed_shutdown), self.managed_driver(root, []) as (probe, driver, browser, _):
                    probe.__enter__()
                    probe.netlog.write_text(json.dumps({"events": [], "private_header": secret}))
                    if failed_shutdown:
                        browser.close.side_effect = RuntimeError(secret)
                        with self.assertRaisesRegex(RuntimeError, "cleanup failed") as raised:
                            probe.__exit__(None, None, None)
                        self.assertNotIn(secret, str(raised.exception))
                    else:
                        probe.__exit__(None, None, None)
                    self.assertFalse(probe.netlog.exists())
                    driver.stop.assert_called_once()

    def test_browser_initialization_failure_is_counted_and_signalled(self):
        secret = "synthetic-" + "sensitive-value"
        with tempfile.TemporaryDirectory(prefix="chiron-managed-init-") as directory:
            root = Path(directory)
            args = SimpleNamespace(output=root / "evidence.json", page_port=18080,
                                   grpc_port=17402, chrome="chrome", openssl="openssl")
            instance = soak.Soak(args, root, {"initial_cert": root / "one", "replacement_cert": root / "two"})
            with patch.object(soak, "spki_pin", return_value="pin"), \
                    patch.object(soak, "BrowserProbe", side_effect=RuntimeError(secret)):
                instance.browser_worker()
            self.assertTrue(instance.browser_ready.is_set())
            self.assertTrue(instance.browser_start_error)
            self.assertEqual(instance.counts["browser_grpc_web"], {"success": 0, "failure": 1})
            self.assertNotIn(secret, str(instance.failures))

    def test_browser_lifecycle_stays_on_the_worker_thread(self):
        with tempfile.TemporaryDirectory(prefix="chiron-managed-thread-") as directory:
            root = Path(directory)
            args = SimpleNamespace(output=root / "evidence.json", page_port=18080,
                                   grpc_port=17402, chrome="chrome", openssl="openssl")
            instance = soak.Soak(args, root, {"initial_cert": root / "one", "replacement_cert": root / "two"})
            calls = []

            class Session:
                metadata = {"processes_started": 1}

                def __enter__(self):
                    calls.append(threading.get_ident())
                    return self

                def check(self):
                    calls.append(threading.get_ident())
                    instance.stop.set()

                def __exit__(self, *_):
                    calls.append(threading.get_ident())

            with patch.object(soak, "spki_pin", return_value="pin"), \
                    patch.object(soak, "BrowserProbe", return_value=Session()):
                worker = threading.Thread(target=instance.browser_worker)
                worker.start()
                worker.join(timeout=2)
            self.assertFalse(worker.is_alive())
            self.assertEqual(len(calls), 3)
            self.assertEqual(len(set(calls)), 1)
            self.assertNotEqual(calls[0], threading.get_ident())
            self.assertEqual(instance.counts["browser_grpc_web"], {"success": 1, "failure": 0})

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
