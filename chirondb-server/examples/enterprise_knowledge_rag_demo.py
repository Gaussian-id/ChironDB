#!/usr/bin/env python3
"""Run a reproducible relational + vector + graph ChironDB terminal demo.

The script uses only Python's standard library. It starts one local ChironDB
server, drives queries through the real ``chironql`` terminal binary, restarts
the server on the same data directory, verifies recovery, and cleans up the
logical objects. Graph lifecycle/type setup uses the administrative HTTP API
because ChironQL 1.4 deliberately has no graph DDL.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


COLLECTION = "knowledge_chunks"
EDGE_TYPE = "CITES"
TABLE = "documents"


def stable_embedding(text: str) -> list[float]:
    """Return a deterministic four-dimensional local bag-of-concepts vector."""
    lowered = text.lower()
    concepts = (
        ("refund", "return", "pengembalian", "order"),
        ("security", "incident", "severity", "escalation"),
        ("database", "vector", "graph", "relational"),
        ("policy", "source", "approved", "governing"),
    )
    values = [float(sum(lowered.count(token) for token in group)) for group in concepts]
    if not any(values):
        digest = hashlib.sha256(text.encode("utf-8")).digest()
        values = [float(1 + digest[index]) for index in range(4)]
    norm = math.sqrt(sum(value * value for value in values))
    return [round(value / norm, 8) for value in values]


def compact(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class Demo:
    def __init__(self, args: argparse.Namespace) -> None:
        self.root = Path(__file__).resolve().parents[2]
        self.bin_dir = Path(args.bin_dir).resolve()
        self.server_bin = self.bin_dir / "chirondb"
        self.client_bin = self.bin_dir / "chironql"
        self.dataset_path = Path(args.dataset).resolve()
        self.output_dir = Path(args.output_dir).resolve()
        self.data_dir = self.output_dir / "data"
        self.base_url = f"http://127.0.0.1:{args.port}"
        self.ports = (args.port, args.port + 1, args.port + 2)
        self.transcript: list[str] = []
        self.steps: list[dict[str, Any]] = []
        self.server: subprocess.Popen[str] | None = None
        self.server_log = None
        self.dataset = json.loads(self.dataset_path.read_text(encoding="utf-8"))

    def record(self, line: str) -> None:
        rendered = f"[{time.strftime('%Y-%m-%dT%H:%M:%S%z')}] {line}"
        self.transcript.append(rendered)
        print(rendered, flush=True)

    def require_inputs(self) -> None:
        for binary in (self.server_bin, self.client_bin):
            if not binary.is_file() or not os.access(binary, os.X_OK):
                raise RuntimeError(f"missing executable: {binary}; build with cargo build -p chirondb --bins")
        if self.output_dir.exists():
            if not self.output_dir.is_dir() or any(self.output_dir.iterdir()):
                raise RuntimeError(f"output directory must be absent or empty: {self.output_dir}")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        for port in self.ports:
            with socket.socket() as probe:
                try:
                    probe.bind(("127.0.0.1", port))
                except OSError as error:
                    raise RuntimeError(f"port {port} is unavailable: {error}") from error

    def start_server(self, generation: int) -> None:
        log_path = self.output_dir / f"server-{generation}.log"
        self.server_log = log_path.open("w", encoding="utf-8")
        command = [
            str(self.server_bin),
            "--data-dir", str(self.data_dir),
            "--listen-http", f"127.0.0.1:{self.ports[0]}",
            "--listen-grpc", f"127.0.0.1:{self.ports[1]}",
            "--listen-wire", f"127.0.0.1:{self.ports[2]}",
        ]
        self.record("START " + " ".join(command))
        self.server = subprocess.Popen(
            command,
            cwd=self.root,
            stdout=self.server_log,
            stderr=subprocess.STDOUT,
            text=True,
        )
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.server.poll() is not None:
                raise RuntimeError(f"server exited with {self.server.returncode}; see {log_path}")
            try:
                health = self.http("GET", "/health", record=False)
                if health.get("status") == "ok":
                    self.record(f"READY generation={generation} health={compact(health)}")
                    return
            except (HTTPError, URLError, ConnectionError):
                time.sleep(0.2)
        raise RuntimeError(f"server did not become ready; see {log_path}")

    def stop_server(self) -> None:
        if self.server is None:
            return
        process = self.server
        self.record(f"STOP pid={process.pid} signal=SIGTERM")
        process.send_signal(signal.SIGTERM)
        try:
            code = process.wait(timeout=20)
        except subprocess.TimeoutExpired as error:
            process.kill()
            process.wait(timeout=5)
            raise RuntimeError("server did not stop after SIGTERM") from error
        if self.server_log is not None:
            self.server_log.close()
        self.server_log = None
        self.server = None
        if code not in (0, -signal.SIGTERM):
            raise RuntimeError(f"server stopped with status {code}")

    def http(self, method: str, path: str, body: Any = None, *, record: bool = True) -> Any:
        payload = None if body is None else json.dumps(body).encode("utf-8")
        request = Request(
            self.base_url + path,
            data=payload,
            method=method,
            headers={"content-type": "application/json"} if payload is not None else {},
        )
        with urlopen(request, timeout=10) as response:
            raw = response.read().decode("utf-8")
            value = json.loads(raw) if raw else None
        if record:
            self.record(f"HTTP {method} {path} request={compact(body)} response={compact(value)}")
            self.steps.append({"kind": "http", "method": method, "path": path, "response": value})
        return value

    def query(
        self,
        label: str,
        statement: str,
        parameters: list[dict[str, Any]] | None = None,
        retry_id: str | None = None,
        *,
        confirm: bool = False,
    ) -> dict[str, Any]:
        command = [str(self.client_bin), "--url", self.base_url, "--exec", statement]
        if parameters is not None:
            command.extend(["--params-json", json.dumps(parameters, separators=(",", ":"))])
        if retry_id is not None:
            command.extend(["--retry-id", retry_id])
        if confirm:
            command.append("--yes")
        completed = subprocess.run(command, cwd=self.root, text=True, capture_output=True, timeout=30)
        self.record(f"QUERY {label}\n{statement.strip()}")
        self.record(f"EXIT {completed.returncode} STDOUT {completed.stdout.strip()}")
        if completed.stderr.strip():
            self.record(f"STDERR {completed.stderr.strip()}")
        if completed.returncode != 0:
            raise RuntimeError(f"{label} failed with status {completed.returncode}")
        response = json.loads(completed.stdout)
        self.steps.append({"kind": "chironql", "label": label, "statement": statement, "response": response})
        return response

    @staticmethod
    def expect(condition: bool, message: str) -> None:
        if not condition:
            raise AssertionError(message)

    def seed_transaction(self, document: dict[str, str], position: int) -> dict[str, Any]:
        chunk_vector = stable_embedding(document["chunk_text"])
        source_vector = stable_embedding(document["source_text"])
        statement = f"""TRANSACTION {{
  SQL INSERT INTO {TABLE} (id, title, chunk_ref, source_ref)
      VALUES ('{document['id']}', '{document['title']}', RECORD_REF('{COLLECTION}', '{document['chunk_id']}'), RECORD_REF('{COLLECTION}', '{document['source_id']}'));
  VECTOR UPSERT INTO {COLLECTION}
      {{id: '{document['chunk_id']}', vector: {compact(chunk_vector)}, payload: {{kind: 'chunk', text: '{document['chunk_text']}'}}}},
      {{id: '{document['source_id']}', vector: {compact(source_vector)}, payload: {{kind: 'source', text: '{document['source_text']}'}}}};
  GRAPH CONNECT {COLLECTION} '{document['chunk_id']}' -> {EDGE_TYPE} -> '{document['source_id']}' SET {{revision: 1}};
}};"""
        response = self.query(f"seed-{document['id']}", statement, retry_id=f"rag-seed-{position}")
        self.expect(response.get("committed") is True, f"seed did not commit: {response}")
        self.expect(response.get("domains") == ["relational", "vector", "graph"], "wrong seed domains")
        self.expect(response.get("stats", {}).get("affected") == 4, "seed must affect row, two points, and edge")
        return response

    def edge_id(self, chunk_id: str) -> str:
        response = self.query(
            f"edge-{chunk_id}",
            f"TRAVERSE {COLLECTION} FROM '{chunk_id}' VIA {EDGE_TYPE} DEPTH 1 WITH PAYLOAD RETURN EDGES LIMIT 10;",
        )
        self.expect(len(response.get("rows", [])) == 1, f"expected one edge: {response}")
        return str(response["rows"][0]["id"])

    def run(self) -> None:
        self.require_inputs()
        self.start_server(1)
        try:
            created = self.query(
                "create-table",
                f"SQL CREATE TABLE {TABLE} (id TEXT PRIMARY KEY, title TEXT NOT NULL, chunk_ref RECORD_REF('{COLLECTION}') NOT NULL, source_ref RECORD_REF('{COLLECTION}') NOT NULL);",
            )
            self.expect(created.get("domains") == ["relational"], "CREATE TABLE was not relational")
            self.query("create-collection", f"CREATE COLLECTION {COLLECTION} DIM 4 METRIC cosine;")
            self.http("PUT", f"/v1/collections/{COLLECTION}/graph?wait=true")
            self.http(
                "PUT",
                f"/v1/collections/{COLLECTION}/graph/types/{EDGE_TYPE}",
                {"weight_property": None, "wait": True},
            )

            for index, document in enumerate(self.dataset["documents"], start=1):
                self.seed_transaction(document, index)

            typed = self.query(
                "typed-record-ref",
                f"SQL SELECT id, chunk_ref, source_ref FROM {TABLE} ORDER BY id LIMIT 10;",
            )
            self.expect(len(typed.get("rows", [])) == 2, "typed SELECT must return two rows")
            self.expect(
                all(row["chunk_ref"]["namespace"] == COLLECTION for row in typed["rows"]),
                "RECORD_REF namespace was not preserved",
            )
            self.expect(
                [column.get("kind") for column in typed.get("column_types", [])]
                == ["text", "record_ref", "record_ref"],
                f"unexpected typed columns: {typed.get('column_types')}",
            )

            query_vector = stable_embedding(self.dataset["query"])
            pipeline = self.query(
                "pipeline-vector-graph-relational",
                f"""PIPELINE
  VECTOR v {{ SEARCH {COLLECTION} NEAR $1 LIMIT 1 }}
  GRAPH g {{ TRAVERSE {COLLECTION} FROM v.record_ref VIA {EDGE_TYPE} DEPTH 1 RETURN NODES LIMIT 20 }}
  RELATIONAL r {{ SQL SELECT id, title, chunk_ref, source_ref FROM {TABLE} LIMIT 20 }}
  INNER JOIN r ON r.chunk_ref = v.record_ref
  LEFT JOIN g ON g.record_ref = r.source_ref
  RETURN r.id, r.title, r.chunk_ref, v.score, g.depth
  ORDER BY v.score DESC
  LIMIT 10;""",
                [{"type": "vector", "value": query_vector}],
            )
            self.expect(pipeline.get("domains") == ["relational", "vector", "graph"], "wrong pipeline domains")
            self.expect([row.get("id") for row in pipeline.get("rows", [])] == ["doc-refund"], "refund document was not the top result")
            self.expect(all(row.get("depth") == 1 for row in pipeline.get("rows", [])), "graph enrichment missing")

            refund_edge = self.edge_id("chunk-refund")
            updated_vector = stable_embedding("approved refund return policy source")
            updated = self.query(
                "atomic-update",
                f"""TRANSACTION {{
  SQL UPDATE {TABLE} SET title = 'Customer refund procedure v2' WHERE id = 'doc-refund';
  VECTOR UPSERT INTO {COLLECTION} {{id: 'chunk-refund', vector: {compact(updated_vector)}, payload: {{kind: 'chunk', revision: 2}}}};
  GRAPH UPDATE {COLLECTION} EDGE '{refund_edge}' SET PROPERTIES {{revision: 2}} REPLACE;
}};""",
                retry_id="rag-update-refund-v2",
            )
            self.expect(updated.get("committed") is True and updated.get("stats", {}).get("affected") == 3, "atomic update failed")

            security_edge = self.edge_id("chunk-security")
            deleted = self.query(
                "atomic-delete-security",
                f"""TRANSACTION {{
  SQL DELETE FROM {TABLE} WHERE id = 'doc-security';
  VECTOR DELETE FROM {COLLECTION} POINTS 'chunk-security', 'source-security-policy';
  GRAPH UNRELATE {COLLECTION} EDGE '{security_edge}';
}};""",
                retry_id="rag-delete-security",
            )
            self.expect(deleted.get("committed") is True and deleted.get("stats", {}).get("affected") == 4, "atomic delete failed")
            absent = self.query("verify-deleted-before-restart", f"SQL SELECT id FROM {TABLE} WHERE id = 'doc-security';")
            self.expect(absent.get("rows", []) == [], "deleted relational row is still visible")
            self.expect(
                self.query("verify-deleted-points-before-restart", f"GET {COLLECTION} POINTS 'chunk-security', 'source-security-policy';").get("rows", []) == [],
                "deleted vector points are still visible",
            )

            self.stop_server()
            self.start_server(2)
            recovered = self.query(
                "verify-recovery-row",
                f"SQL SELECT id, title, chunk_ref FROM {TABLE} ORDER BY id LIMIT 10;",
            )
            self.expect(
                recovered.get("rows")
                == [{"chunk_ref": {"namespace": COLLECTION, "id": "chunk-refund"}, "id": "doc-refund", "title": "Customer refund procedure v2"}],
                f"unexpected recovered relational state: {recovered.get('rows')}",
            )
            recovered_points = self.query(
                "verify-recovery-points",
                f"GET {COLLECTION} POINTS 'chunk-refund', 'source-refund-policy', 'chunk-security', 'source-security-policy';",
            )
            self.expect(len(recovered_points.get("rows", [])) == 2, "recovery exposed partial vector state")
            recovered_edge = self.query(
                "verify-recovery-edge",
                f"TRAVERSE {COLLECTION} FROM 'chunk-refund' VIA {EDGE_TYPE} DEPTH 1 WITH PAYLOAD RETURN EDGES LIMIT 10;",
            )
            self.expect(recovered_edge.get("rows", [{}])[0].get("properties") == {"revision": 2}, "graph update was not recovered")
            self.expect(
                self.query("verify-deleted-after-restart", f"SQL SELECT id FROM {TABLE} WHERE id = 'doc-security';").get("rows", []) == [],
                "deleted row reappeared after restart",
            )

            cleanup = self.query(
                "cleanup-atomic-delete-refund",
                f"""TRANSACTION {{
  SQL DELETE FROM {TABLE} WHERE id = 'doc-refund';
  VECTOR DELETE FROM {COLLECTION} POINTS 'chunk-refund', 'source-refund-policy';
  GRAPH UNRELATE {COLLECTION} EDGE '{refund_edge}';
}};""",
                retry_id="rag-cleanup-refund",
            )
            self.expect(cleanup.get("committed") is True, "cleanup transaction did not commit")
            self.query("cleanup-drop-table", f"SQL DROP TABLE {TABLE};")
            self.query("cleanup-drop-collection", f"DROP COLLECTION {COLLECTION};", confirm=True)
            collections = self.query("verify-cleanup", "SHOW COLLECTIONS;")
            self.expect(
                all(row.get("name") != COLLECTION for row in collections.get("rows", [])),
                "collection cleanup failed",
            )
        finally:
            self.stop_server()

        self.write_artifacts()

    def write_artifacts(self) -> None:
        manifest_path = self.output_dir / "manifest.json"
        self.record(f"PASS manifest={manifest_path}")
        transcript_path = self.output_dir / "transcript.log"
        transcript_path.write_text("\n".join(self.transcript) + "\n", encoding="utf-8")
        results_path = self.output_dir / "results.json"
        results_path.write_text(json.dumps(self.steps, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        source_path = Path(__file__).resolve()
        checksums = {}
        for path in (source_path, self.dataset_path, transcript_path, results_path, self.output_dir / "server-1.log", self.output_dir / "server-2.log"):
            checksums[str(path)] = hashlib.sha256(path.read_bytes()).hexdigest()
        git_status = subprocess.run(
            ["git", "status", "--short"], cwd=self.root, text=True, capture_output=True, check=True
        ).stdout
        manifest = {
            "schema_version": 1,
            "status": "pass-local-uncommitted",
            "date": time.strftime("%Y-%m-%d"),
            "server_version": subprocess.run([str(self.server_bin), "--version"], text=True, capture_output=True, check=True).stdout.strip(),
            "python_version": sys.version.split()[0],
            "base_url": self.base_url,
            "restart": "SIGTERM followed by reopen of the same data directory",
            "assertions": {
                "typed_record_ref": "pass",
                "pipeline_relational_vector_graph": "pass",
                "atomic_update": "pass",
                "atomic_delete": "pass",
                "restart_recovery_no_partial_state": "pass",
                "cleanup": "pass",
            },
            "dataset": self.dataset,
            "embeddings": {
                "query": stable_embedding(self.dataset["query"]),
                "documents": {
                    document["id"]: {
                        "chunk": stable_embedding(document["chunk_text"]),
                        "source": stable_embedding(document["source_text"]),
                    }
                    for document in self.dataset["documents"]
                },
            },
            "source_state": {
                "branch": subprocess.run(["git", "branch", "--show-current"], cwd=self.root, text=True, capture_output=True, check=True).stdout.strip(),
                "head": subprocess.run(["git", "rev-parse", "HEAD"], cwd=self.root, text=True, capture_output=True, check=True).stdout.strip(),
                "uncommitted": bool(git_status.strip()),
                "git_status_sha256": hashlib.sha256(git_status.encode()).hexdigest(),
            },
            "checksums": checksums,
            "limitations": [
                "local unprotected single-node demo",
                "deterministic four-dimensional illustrative embedding, not an embedding quality benchmark",
                "graceful restart, not process-kill or ENOSPC fault injection",
                "no W0 resource, recall, PostgreSQL compatibility, SSI, or exact-SHA CI claim",
            ],
        }
        manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    script_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", default="target/debug")
    parser.add_argument("--dataset", default=str(script_dir / "enterprise_knowledge_rag_dataset.json"))
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--port", type=int, default=17641)
    return parser.parse_args()


def main() -> int:
    demo = Demo(parse_args())
    try:
        demo.run()
    except Exception as error:  # evidence runner must preserve the exact failure
        demo.record(f"FAIL {type(error).__name__}: {error}")
        demo.output_dir.mkdir(parents=True, exist_ok=True)
        (demo.output_dir / "transcript.log").write_text("\n".join(demo.transcript) + "\n", encoding="utf-8")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
