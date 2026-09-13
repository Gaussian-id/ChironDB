#!/usr/bin/env python3
"""External-client TLS rotation soak for the G7 acceptance gate."""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from typing import Callable


API_KEY = "tls-soak-" + ("a" * 32)


def command(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        argv,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        **kwargs,
    )


def require_tool(name: str) -> str:
    resolved = shutil.which(name)
    if not resolved:
        raise RuntimeError(f"required external client is missing: {name}")
    return resolved


def atomic_replace(source: Path, destination: Path) -> None:
    temporary = destination.with_name(f".{destination.name}.rotate-{os.getpid()}")
    with source.open("rb") as reader, temporary.open("wb") as writer:
        shutil.copyfileobj(reader, writer)
        writer.flush()
        os.fsync(writer.fileno())
    os.chmod(temporary, source.stat().st_mode & 0o777)
    os.replace(temporary, destination)
    directory = os.open(destination.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def generate_pki(root: Path, openssl: str) -> dict[str, Path]:
    pki = root / "pki"
    pki.mkdir()
    extension = pki / "extensions.cnf"
    extension.write_text(
        """
[server]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
[client]
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
""".strip()
        + "\n"
    )
    ca_key, ca_cert = pki / "ca.key", pki / "ca.crt"
    command([openssl, "genrsa", "-out", str(ca_key), "3072"])
    command(
        [
            openssl,
            "req",
            "-x509",
            "-new",
            "-key",
            str(ca_key),
            "-sha256",
            "-days",
            "2",
            "-subj",
            "/CN=ChironDB TLS Soak CA",
            "-out",
            str(ca_cert),
        ]
    )
    paths: dict[str, Path] = {"ca_key": ca_key, "ca_cert": ca_cert}
    for name, serial, section, common_name in (
        ("initial", "1001", "server", "localhost"),
        ("replacement", "1002", "server", "localhost"),
        ("client", "2001", "client", "chiron-soak-client"),
    ):
        key, csr, cert = pki / f"{name}.key", pki / f"{name}.csr", pki / f"{name}.crt"
        command([openssl, "genrsa", "-out", str(key), "2048"])
        command(
            [openssl, "req", "-new", "-key", str(key), "-subj", f"/CN={common_name}", "-out", str(csr)]
        )
        command(
            [
                openssl,
                "x509",
                "-req",
                "-in",
                str(csr),
                "-CA",
                str(ca_cert),
                "-CAkey",
                str(ca_key),
                "-set_serial",
                serial,
                "-days",
                "2",
                "-sha256",
                "-extfile",
                str(extension),
                "-extensions",
                section,
                "-out",
                str(cert),
            ]
        )
        os.chmod(key, 0o600)
        paths[f"{name}_key"] = key
        paths[f"{name}_cert"] = cert
    return paths


def spki_pin(openssl: str, cert: Path) -> str:
    public = command([openssl, "x509", "-in", str(cert), "-pubkey", "-noout"]).stdout
    der = subprocess.run(
        [openssl, "pkey", "-pubin", "-outform", "DER"],
        input=public.encode(),
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout
    return base64.b64encode(hashlib.sha256(der).digest()).decode()


def peer_serial(port: int, ca: Path, client: tuple[Path, Path] | None = None) -> str:
    context = ssl.create_default_context(cafile=str(ca))
    if client:
        context.load_cert_chain(str(client[0]), str(client[1]))
    with socket.create_connection(("127.0.0.1", port), timeout=5) as tcp:
        with context.wrap_socket(tcp, server_hostname="localhost") as tls:
            certificate = tls.getpeercert()
            return str(certificate["serialNumber"])


def wait_for_serial(port: int, ca: Path, expected: str, client: tuple[Path, Path] | None = None) -> None:
    deadline = time.monotonic() + 30
    last = "unavailable"
    while time.monotonic() < deadline:
        try:
            last = peer_serial(port, ca, client)
            if int(last, 16) == int(expected):
                return
        except (OSError, ssl.SSLError, KeyError):
            pass
        time.sleep(0.25)
    raise RuntimeError(f"new connections did not observe certificate serial {expected}; last={last}")


class LongLivedHttp:
    def __init__(self, port: int, ca: Path) -> None:
        context = ssl.create_default_context(cafile=str(ca))
        self.connection = http.client.HTTPSConnection("localhost", port, context=context, timeout=10)
        self.connection.connect()
        self.initial_serial = str(self.connection.sock.getpeercert()["serialNumber"])

    def health(self) -> int:
        self.connection.request("GET", "/health", headers={"Connection": "keep-alive"})
        response = self.connection.getresponse()
        response.read()
        return response.status

    def serial(self) -> str:
        return str(self.connection.sock.getpeercert()["serialNumber"])

    def close(self) -> None:
        self.connection.close()


class Soak:
    def __init__(self, args: argparse.Namespace, root: Path, pki: dict[str, Path]) -> None:
        self.args = args
        self.root = root
        self.pki = pki
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.counts: dict[str, dict[str, int]] = {}
        self.failures: list[str] = []
        self.server: subprocess.Popen[str] | None = None
        args.output.parent.mkdir(parents=True, exist_ok=True)
        self.server_log = args.output.parent / "tls-soak-server.log"
        self.page_server: subprocess.Popen[str] | None = None
        self.page_port = args.page_port
        self.active_cert = root / "server.crt"
        self.active_key = root / "server.key"
        self.data_dir = root / "data"
        self.snapshot_root = root / "snapshots"
        self.rbac = root / "rbac.json"
        self.keyring = root / "keyring.json"
        self.browser_page = root / "browser" / "index.html"

    def prepare_config(self) -> None:
        self.snapshot_root.mkdir()
        self.rbac.write_text(
            json.dumps(
                {
                    "keys": [
                        {
                            "id": "tls-soak-admin",
                            "key": API_KEY,
                            "tenant_id": "tls-soak",
                            "role": "admin",
                        }
                    ]
                }
            )
        )
        self.keyring.write_text(
            json.dumps(
                {
                    "version": 1,
                    "active_key_id": "tls-soak-key",
                    "keys": [
                        {
                            "id": "tls-soak-key",
                            "key_base64": base64.b64encode(os.urandom(32)).decode(),
                        }
                    ],
                }
            )
        )
        os.chmod(self.keyring, 0o600)
        atomic_replace(self.pki["initial_cert"], self.active_cert)
        atomic_replace(self.pki["initial_key"], self.active_key)
        browser_dir = self.browser_page.parent
        browser_dir.mkdir()
        self.browser_page.write_text(
            f"""<!doctype html><meta charset=utf-8><body>pending<script>
const body = new Uint8Array([0,0,0,0,0]);
fetch('https://127.0.0.1:{self.args.grpc_port}/chirondb.v1.ChironDb/Health', {{
  method: 'POST',
  mode: 'cors',
  headers: {{
    'content-type': 'application/grpc-web+proto',
    'x-grpc-web': '1',
    'x-chirondb-api-key': '{API_KEY}'
  }},
  body
}}).then(async response => {{
  const bytes = new Uint8Array(await response.arrayBuffer());
  document.body.textContent = response.ok && bytes.length > 5 ? 'grpc-web-passed' : 'grpc-web-failed';
}}).catch(error => document.body.textContent = 'grpc-web-error:' + error);
</script>"""
        )

    def server_command(self, mtls: bool) -> list[str]:
        result = [
            str(self.args.server),
            "--listen-http",
            f"0.0.0.0:{self.args.http_port}",
            "--listen-grpc",
            f"0.0.0.0:{self.args.grpc_port}",
            "--listen-wire",
            f"0.0.0.0:{self.args.wire_port}",
            "--data-dir",
            str(self.data_dir),
            "--api-key",
            API_KEY,
            "--rbac-config-file",
            str(self.rbac),
            "--encryption-keyring-file",
            str(self.keyring),
            "--snapshot-root",
            str(self.snapshot_root),
            "--tls-cert",
            str(self.active_cert),
            "--tls-key",
            str(self.active_key),
            "--cors-origin",
            f"http://127.0.0.1:{self.page_port}",
            "--enable-grpc-web",
        ]
        if mtls:
            result.extend(["--tls-client-ca", str(self.pki["ca_cert"])])
        return result

    def start_server(self, mtls: bool) -> None:
        log = self.server_log.open("a")
        self.server = subprocess.Popen(
            self.server_command(mtls), stdout=log, stderr=subprocess.STDOUT, text=True
        )
        deadline = time.monotonic() + 45
        client = (self.pki["client_cert"], self.pki["client_key"]) if mtls else None
        while time.monotonic() < deadline:
            if self.server.poll() is not None:
                raise RuntimeError(f"server exited during startup; inspect {self.server_log}")
            try:
                peer_serial(self.args.http_port, self.pki["ca_cert"], client)
                return
            except (OSError, ssl.SSLError, KeyError):
                time.sleep(0.25)
        raise RuntimeError("server did not accept TLS within 45 seconds")

    def stop_server(self) -> None:
        if not self.server:
            return
        self.server.terminate()
        try:
            self.server.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.server.kill()
            self.server.wait(timeout=5)
        self.server = None

    def start_browser_origin(self) -> None:
        self.page_server = subprocess.Popen(
            [sys.executable, "-m", "http.server", str(self.page_port), "--bind", "127.0.0.1"],
            cwd=self.browser_page.parent,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        time.sleep(0.5)

    def curl(self, mtls: bool = False) -> None:
        argv = [
            self.args.curl,
            "--fail",
            "--silent",
            "--show-error",
            "--cacert",
            str(self.pki["ca_cert"]),
            "--resolve",
            f"localhost:{self.args.http_port}:127.0.0.1",
        ]
        if mtls:
            argv.extend(["--cert", str(self.pki["client_cert"]), "--key", str(self.pki["client_key"])])
        argv.append(f"https://localhost:{self.args.http_port}/health")
        completed = command(argv)
        if json.loads(completed.stdout)["status"] != "ok":
            raise RuntimeError("curl health response was not ok")

    def grpcurl(self, mtls: bool = False) -> None:
        argv = [
            self.args.grpcurl,
            "-cacert",
            str(self.pki["ca_cert"]),
            "-authority",
            "localhost",
            "-H",
            f"authorization: Bearer {API_KEY}",
            "-import-path",
            str(self.args.proto_root),
            "-proto",
            "chirondb/v1/chirondb.proto",
        ]
        if mtls:
            argv.extend(["-cert", str(self.pki["client_cert"]), "-key", str(self.pki["client_key"])])
        argv.extend([f"127.0.0.1:{self.args.grpc_port}", "chirondb.v1.ChironDb.Health"])
        if json.loads(command(argv).stdout).get("status") != "ok":
            raise RuntimeError("grpcurl health response was not ok")

    def psql(self, mtls: bool = False) -> None:
        environment = os.environ.copy()
        environment.update(
            {
                "PGHOST": "localhost",
                "PGHOSTADDR": "127.0.0.1",
                "PGPORT": str(self.args.wire_port),
                "PGUSER": "tls-soak",
                "PGDATABASE": "tls-soak",
                "PGPASSWORD": API_KEY,
                "PGSSLMODE": "verify-full",
                "PGSSLROOTCERT": str(self.pki["ca_cert"]),
                "PGCONNECT_TIMEOUT": "5",
            }
        )
        if mtls:
            environment["PGSSLCERT"] = str(self.pki["client_cert"])
            environment["PGSSLKEY"] = str(self.pki["client_key"])
        result = command([self.args.psql, "-Atqc", "SELECT version()"], env=environment)
        if "ChironDB" not in result.stdout:
            raise RuntimeError("psql version response did not identify ChironDB")

    def wire(self, mtls: bool = False) -> None:
        argv = [
            str(self.args.wirectl),
            "--endpoint",
            f"127.0.0.1:{self.args.wire_port}",
            "--api-key",
            API_KEY,
            "--ca-cert",
            str(self.pki["ca_cert"]),
            "--tls-domain",
            "localhost",
        ]
        if mtls:
            argv.extend(["--client-cert", str(self.pki["client_cert"]), "--client-key", str(self.pki["client_key"])])
        argv.append("health")
        if json.loads(command(argv).stdout).get("status") != "ok":
            raise RuntimeError("ChironWire health response was not ok")

    def browser(self) -> None:
        profile = self.root / f"chrome-{time.time_ns()}"
        pins = ",".join(
            [
                spki_pin(self.args.openssl, self.pki["initial_cert"]),
                spki_pin(self.args.openssl, self.pki["replacement_cert"]),
            ]
        )
        try:
            result = command(
                [
                    self.args.chrome,
                    "--headless=new",
                    "--no-sandbox",
                    "--disable-gpu",
                    f"--user-data-dir={profile}",
                    f"--ignore-certificate-errors-spki-list={pins}",
                    "--virtual-time-budget=10000",
                    "--dump-dom",
                    f"http://127.0.0.1:{self.page_port}/",
                ]
            )
        finally:
            shutil.rmtree(profile, ignore_errors=True)
        if "grpc-web-passed" not in result.stdout:
            raise RuntimeError("browser gRPC-Web probe failed")

    def worker(self, name: str, operation: Callable[[], None], interval: float) -> None:
        with self.lock:
            self.counts[name] = {"success": 0, "failure": 0}
        while not self.stop.is_set():
            try:
                operation()
                outcome = "success"
            except Exception as error:  # evidence records the failure, then the gate fails
                outcome = "failure"
                with self.lock:
                    if len(self.failures) < 100:
                        self.failures.append(f"{name}: {error}")
            with self.lock:
                self.counts[name][outcome] += 1
            self.stop.wait(interval)

    def tls_version_matrix(self) -> None:
        for flag in ("-tls1_2", "-tls1_3"):
            command(
                [
                    self.args.openssl,
                    "s_client",
                    flag,
                    "-connect",
                    f"127.0.0.1:{self.args.http_port}",
                    "-servername",
                    "localhost",
                    "-CAfile",
                    str(self.pki["ca_cert"]),
                    "-verify_return_error",
                    "-brief",
                ],
                input="",
            )
        legacy = subprocess.run(
            [
                self.args.openssl,
                "s_client",
                "-tls1_1",
                "-connect",
                f"127.0.0.1:{self.args.http_port}",
                "-servername",
                "localhost",
            ],
            input="",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if legacy.returncode == 0:
            raise RuntimeError("TLS 1.1 unexpectedly negotiated")

    def mtls_matrix(self) -> None:
        self.curl(mtls=True)
        self.grpcurl(mtls=True)
        self.psql(mtls=True)
        self.wire(mtls=True)
        anonymous = subprocess.run(
            [
                self.args.curl,
                "--fail",
                "--silent",
                "--cacert",
                str(self.pki["ca_cert"]),
                "--resolve",
                f"localhost:{self.args.http_port}:127.0.0.1",
                f"https://localhost:{self.args.http_port}/health",
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if anonymous.returncode == 0:
            raise RuntimeError("mTLS listener accepted anonymous curl")

    def run(self) -> dict[str, object]:
        self.prepare_config()
        self.start_browser_origin()
        self.start_server(mtls=False)
        self.tls_version_matrix()
        initial_serial = peer_serial(self.args.http_port, self.pki["ca_cert"])
        long_connection = LongLivedHttp(self.args.http_port, self.pki["ca_cert"])
        if long_connection.health() != 200:
            raise RuntimeError("initial long-lived health request failed")

        workers = [
            threading.Thread(target=self.worker, args=("curl", self.curl, 1.0), daemon=True),
            threading.Thread(target=self.worker, args=("grpcurl", self.grpcurl, 1.0), daemon=True),
            threading.Thread(target=self.worker, args=("psql", self.psql, 1.0), daemon=True),
            threading.Thread(target=self.worker, args=("chironwire", self.wire, 1.0), daemon=True),
            threading.Thread(target=self.worker, args=("browser_grpc_web", self.browser, 30.0), daemon=True),
        ]
        for worker in workers:
            worker.start()
        started = time.monotonic()
        first_rotation = started + self.args.duration_seconds / 3
        invalid_rotation = started + self.args.duration_seconds * 2 / 3
        while time.monotonic() < first_rotation:
            time.sleep(min(1.0, first_rotation - time.monotonic()))

        atomic_replace(self.pki["replacement_key"], self.active_key)
        atomic_replace(self.pki["replacement_cert"], self.active_cert)
        wait_for_serial(self.args.http_port, self.pki["ca_cert"], "1002")
        replacement_serial = peer_serial(self.args.http_port, self.pki["ca_cert"])
        if long_connection.health() != 200 or long_connection.serial() != initial_serial:
            raise RuntimeError("valid rotation broke an established TLS connection")

        while time.monotonic() < invalid_rotation:
            time.sleep(min(1.0, invalid_rotation - time.monotonic()))
        invalid_cert, invalid_key = self.root / "invalid.crt", self.root / "invalid.key"
        invalid_cert.write_text("invalid certificate\n")
        invalid_key.write_text("invalid private key\n")
        atomic_replace(invalid_key, self.active_key)
        atomic_replace(invalid_cert, self.active_cert)
        time.sleep(3)
        if int(peer_serial(self.args.http_port, self.pki["ca_cert"]), 16) != 1002:
            raise RuntimeError("invalid rotation replaced the last valid certificate")
        if long_connection.health() != 200 or long_connection.serial() != initial_serial:
            raise RuntimeError("invalid rotation broke an established TLS connection")
        atomic_replace(self.pki["replacement_key"], self.active_key)
        atomic_replace(self.pki["replacement_cert"], self.active_cert)

        deadline = started + self.args.duration_seconds
        while time.monotonic() < deadline:
            time.sleep(min(1.0, deadline - time.monotonic()))
        actual_duration = time.monotonic() - started
        self.stop.set()
        for worker in workers:
            worker.join(timeout=45)
        long_connection.close()
        if any(worker.is_alive() for worker in workers):
            raise RuntimeError("a TLS soak worker did not stop")
        if self.failures:
            raise RuntimeError(f"concurrent client failures: {self.failures[:5]}")

        self.stop_server()
        self.start_server(mtls=True)
        self.mtls_matrix()
        self.stop_server()
        return {
            "schema_version": 1,
            "status": "passed" if actual_duration >= 3600 else "diagnostic",
            "verdict": "passed" if actual_duration >= 3600 else "diagnostic",
            "tested_sha": self.args.tested_sha,
            "core_tree_hash": self.args.core_tree_hash,
            "server_tree_hash": self.args.server_tree_hash,
            "actions_run_id": os.environ.get("GITHUB_RUN_ID"),
            "requested_duration_seconds": self.args.duration_seconds,
            "actual_duration_seconds": actual_duration,
            "load_counts": self.counts,
            "initial_serial": initial_serial,
            "replacement_serial": replacement_serial,
            "established_connection_retained_initial_serial": True,
            "invalid_rotation_retained_last_valid_serial": True,
            "tls_versions": {"1.2": "passed", "1.3": "passed", "1.1": "rejected"},
            "mtls_external_clients": ["curl", "grpcurl", "psql/libpq", "chironwirectl"],
            "browser_grpc_web": "passed",
            "failures": [],
        }

    def close(self) -> None:
        self.stop.set()
        self.stop_server()
        if self.page_server:
            self.page_server.terminate()
            try:
                self.page_server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.page_server.kill()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--wirectl", type=Path, required=True)
    parser.add_argument("--proto-root", type=Path, required=True)
    parser.add_argument("--grpcurl", default="grpcurl")
    parser.add_argument("--psql", default="psql")
    parser.add_argument("--chrome")
    parser.add_argument("--duration-seconds", type=int, default=3600)
    parser.add_argument("--http-port", type=int, default=17401)
    parser.add_argument("--grpc-port", type=int, default=17402)
    parser.add_argument("--wire-port", type=int, default=17403)
    parser.add_argument("--page-port", type=int, default=18080)
    parser.add_argument("--tested-sha", required=True)
    parser.add_argument("--core-tree-hash", required=True)
    parser.add_argument("--server-tree-hash", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.duration_seconds < 30:
        parser.error("--duration-seconds must be at least 30; only >=3600 can pass")
    args.server = args.server.resolve()
    args.wirectl = args.wirectl.resolve()
    args.proto_root = args.proto_root.resolve()
    args.openssl = require_tool("openssl")
    args.curl = require_tool("curl")
    args.grpcurl = require_tool(args.grpcurl)
    args.psql = require_tool(args.psql)
    args.chrome = args.chrome or next(
        (resolved for name in ("google-chrome", "chromium", "chromium-browser") if (resolved := shutil.which(name))),
        None,
    )
    if not args.chrome:
        parser.error("Chrome/Chromium is required for the real browser gRPC-Web probe")
    for path in (args.server, args.wirectl, args.proto_root):
        if not path.exists():
            parser.error(f"required path does not exist: {path}")
    return args


def write_report(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    os.replace(temporary, path)


def main() -> int:
    args = parse_args()
    root = Path(tempfile.mkdtemp(prefix="chirondb-tls-soak-"))
    soak: Soak | None = None
    try:
        pki = generate_pki(root, args.openssl)
        soak = Soak(args, root, pki)
        report = soak.run()
        write_report(args.output, report)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    except Exception as error:
        report = {
            "schema_version": 1,
            "status": "failed",
            "verdict": "failed",
            "tested_sha": args.tested_sha,
            "core_tree_hash": args.core_tree_hash,
            "server_tree_hash": args.server_tree_hash,
            "actions_run_id": os.environ.get("GITHUB_RUN_ID"),
            "error": str(error),
            "work_dir": str(root),
        }
        write_report(args.output, report)
        print(json.dumps(report, indent=2, sort_keys=True), file=sys.stderr)
        return 1
    finally:
        if soak:
            soak.close()


if __name__ == "__main__":
    raise SystemExit(main())
