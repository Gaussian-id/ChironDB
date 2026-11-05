#!/usr/bin/env python3
"""Exercise the example loader against a fresh, running qualification database.

The caller provides a server with the benchmark schema but no records. The
local forwarding proxy loses one successful edge ACK; this is a real retry
against the product, followed by resume and the independent full oracle.
"""
from __future__ import annotations

import argparse
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import runpy
import sqlite3
import threading
from types import SimpleNamespace
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
BENCH = runpy.run_path(str(Path(__file__).with_name("bulk_ingest_benchmark.py")))
BULK = runpy.run_path(str(ROOT / "examples/bulk_load.py"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    target = urlsplit(args.url)
    assert target.scheme == "http" and target.hostname == "127.0.0.1"
    lock, lost = threading.Lock(), []

    class Proxy(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_):
            pass

        def forward(self):
            payload = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            connection = http.client.HTTPConnection(target.hostname, target.port, timeout=120)
            headers = {key: value for key, value in self.headers.items() if key.lower() not in ("host", "connection")}
            connection.request(self.command, self.path, payload, headers)
            response = connection.getresponse()
            body = response.read()
            connection.close()
            with lock:
                drop = not lost and response.status == 200 and self.path.endswith("/edges/batch")
                if drop:
                    lost.append(json.loads(body)["edge_ids"])
            if drop:
                # The database has durably committed; the client sees EOF.
                self.close_connection = True
                return
            self.send_response(response.status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = do_PUT = forward

    proxy = ThreadingHTTPServer(("127.0.0.1", 0), Proxy)
    thread = threading.Thread(target=proxy.serve_forever, daemon=True)
    thread.start()
    state = args.output / "progress.sqlite"
    inputs = SimpleNamespace(url=f"http://127.0.0.1:{proxy.server_port}", collection="chunks", state=str(state), ca_cert=None,
                             **{phase: str(args.fixture / (phase + ".jsonl")) for phase in ("sql", "points", "edges")})
    try:
        report = {"initial": BULK["load"](inputs)}
        assert len(lost) == 1 and len(lost[0]) == 50, "ACK-loss injection was not reached"
        report["resume"] = BULK["load"](inputs)
        assert all(phase["batches_sent"] == 0 for phase in report["resume"]["phases"].values())
        # Emulate process loss after a committed batch, before SQLite checkpoint.
        with sqlite3.connect(state) as database:
            database.execute("DELETE FROM completed WHERE phase='edges' AND batch=0")
        report["ambiguous_resume"] = BULK["load"](inputs)
        assert report["ambiguous_resume"]["phases"]["edges"]["batches_sent"] == 1
        with sqlite3.connect(state) as database, (args.output / "edge-acks.jsonl").open("w") as receipts:
            for number, batch in enumerate(BULK["batches"](args.fixture / "edges.jsonl")):
                stored = database.execute("SELECT receipt FROM completed WHERE phase='edges' AND batch=?", (number,)).fetchone()
                assert stored, "missing completed edge batch"
                receipt = json.loads(stored[0])
                receipts.write(json.dumps({"batch": number, "edge_ids": receipt["edge_ids"],
                    "ordinals": [edge["properties"]["ordinal"] for edge in batch]}) + "\n")
        oracle_args = SimpleNamespace(engine="chiron", url=args.url, fixture=args.fixture, output=args.output)
        with (args.output / "oracle-requests.jsonl").open("w") as raw:
            oracle_http = BENCH["HTTP"](oracle_args, raw)
            manifest = json.loads((args.fixture / "manifest.json").read_text())
            BENCH["ready"](oracle_http, oracle_args, manifest)
            report["oracle"] = BENCH["validate_dataset"](oracle_http, oracle_args, manifest)
        report["lost_ack_edge_ids"] = lost[0]
        (args.output / "report.json").write_text(json.dumps(report, indent=2))
        print(json.dumps({"loader": "passed", "lost_ack_batches": len(lost), "oracle": report["oracle"]}))
    finally:
        proxy.shutdown()
        proxy.server_close()
        thread.join()


if __name__ == "__main__":
    main()
