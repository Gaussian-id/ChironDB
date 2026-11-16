#!/usr/bin/env python3
"""Reconstructed SciFact ingest qualification; never the historical P4 run.

Prepare fixed JSONL fixtures, then run against a fresh isolated database.
Deployment/resource manifests and five alternating rounds are collected by the
campaign runner. Every HTTP attempt, including admission retries, is retained.
"""
from __future__ import annotations

import argparse
import base64
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import hashlib
import http.client
import json
import math
import os
from pathlib import Path
import runpy
import struct
import threading
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
bulk = runpy.run_path(str(ROOT / "examples/bulk_load.py"))
encode, file_hash, batches = (bulk[name] for name in ("encode", "file_hash", "batches"))
SOURCE = {
    "dataset": "BEIR SciFact test; title + space + text; IDs sorted lexically",
    "zip_sha256": "536e14446a0ba56ed1398ab1055f39fe852686ecad24a6306c80c490fa8e0165",
    "model": "sentence-transformers/all-MiniLM-L6-v2",
    "model_revision": "1110a243fdf4706b3f48f1d95db1a4f5529b4d41",
    "normalize_embeddings": True, "max_sequence_length": 256,
    "torch_version": "2.8.0", "numpy_version": "2.2.6",
    "embedded_sha256": "b0dcebf3d3871133fe3c0a42c9cea0126aa43bf32b33cc5581314f3af5616e14",
}


def f32(value):
    return struct.unpack("<f", struct.pack("<f", value))[0]


def persisted_vector(vector):
    """Independent oracle for the existing power-of-two scaled IEEE-f16 rows.

    The normalized fixture is bounded by one. Compare exact decoded values,
    not a fitted tolerance; the larger fixture can cross the sealing boundary.
    """
    maximum = max(map(abs, vector), default=0)
    assert maximum <= 1, "this oracle is scoped to the normalized frozen fixture"
    scale = 2.0 ** (math.frexp(maximum)[1] - 16) if maximum else 1.0
    if maximum / scale > 65504:
        scale *= 2
    return [f32(struct.unpack("<e", struct.pack("<e", f32(value / scale)))[0] * scale) for value in vector]


def prepare(args):
    assert file_hash(Path(args.beir)) == SOURCE["embedded_sha256"], "qualification requires the frozen SciFact embeddings"
    corpus = json.loads(Path(args.beir).read_text())
    assert corpus["dim"] == 384 and len(corpus["corpus"]) == 5183 and len(corpus["queries"]) == 300
    source = sorted(corpus["corpus"], key=lambda row: row["id"])
    assert len({row["id"] for row in source}) == len(source)
    args.output.mkdir(parents=True, exist_ok=False)
    identities = sorted((row["id"] if copy == 0 else row["id"] + f"_copy{copy}", index)
                        for copy in range(args.scale) for index, row in enumerate(source))
    with (args.output / "points.jsonl").open("w") as points, (args.output / "sql.jsonl").open("w") as sql:
        for ordinal, (identity, index) in enumerate(identities):
            row = source[index]
            vector = [f32(value) for value in row["vector"]]
            assert len(vector) == 384 and all(math.isfinite(value) for value in vector)
            points.write(encode({"id": identity, "vector": vector, "payload": {"text": row["text"], "ordinal": ordinal}}).decode() + "\n")
            sql.write(encode({"statements": [{"sql": "INSERT INTO documents (id, ordinal) VALUES ($1,$2)",
                "parameters": [{"type": "text", "value": identity}, {"type": "integer", "value": ordinal}]}]}).decode() + "\n")
    with (args.output / "edges.jsonl").open("w") as edges:
        for ordinal in range(15545 * args.scale):
            source_index, shift = divmod(ordinal, 3)
            edges.write(encode({"source_point_id": identities[source_index][0],
                "target_point_id": identities[(source_index + shift + 1) % len(identities)][0],
                "edge_type": "cites", "properties": {"ordinal": ordinal}}).decode() + "\n")
    manifest = {"schema_version": 1, "classification": "reconstructed; graph synthetic", "source_sha256": file_hash(Path(args.beir)),
                "embedding_source": SOURCE, "seed": 20261103,
                "documents": len(identities), "edges": 15545 * args.scale, "dim": 384, "scale": args.scale,
                "graph_rule": "sorted source IDs; first 15545*scale edges to the next 1,2,3 IDs cyclically",
                "files": {name: file_hash(args.output / name) for name in ("points.jsonl", "sql.jsonl", "edges.jsonl")}}
    if args.scale == 10:
        manifest["vector_oracle"] = "exact f32 or exact decoded existing scaled IEEE-f16 row; no epsilon"
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2))
    print(json.dumps(manifest))


class HTTP:
    def __init__(self, args, raw):
        self.url = urlsplit(args.url)
        assert self.url.scheme == "http" and self.url.hostname in ("127.0.0.1", "localhost"), "qualification must use isolated loopback HTTP"
        self.engine = args.engine
        self.local = threading.local()
        self.raw, self.lock = raw, threading.Lock()
        self.headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if args.engine == "chiron":
            self.headers["Authorization"] = "Bearer " + os.environ["CHIRONDB_API_KEY"]
        else:
            credentials = os.environ["SURREALDB_USER"] + ":" + os.environ["SURREALDB_PASS"]
            self.headers.update({"Authorization": "Basic " + base64.b64encode(credentials.encode()).decode(),
                                 "Surreal-NS": "qualification", "Surreal-DB": "ingest", "Content-Type": "application/surrealql"})

    def request(self, method, path, value, phase):
        payload = value.encode() if isinstance(value, str) else encode(value)
        for attempt in range(8):
            if not getattr(self.local, "connection", None):
                self.local.connection = http.client.HTTPConnection(self.url.hostname, self.url.port, timeout=120)
            started = time.monotonic()
            status, raw, error = 0, b"", None
            try:
                self.local.connection.request(method, path, payload, self.headers)
                response = self.local.connection.getresponse()
                status, raw = response.status, response.read()
            except (OSError, http.client.HTTPException) as caught:
                error = type(caught).__name__
                self.local.connection.close()
                self.local.connection = None
            result, application_errors = None, []
            if status == 200 and not error:
                try:
                    result = json.loads(raw)
                    if self.engine == "surreal":
                        application_errors = [statement for statement in result if statement["status"] != "OK"]
                except (ValueError, KeyError, TypeError) as caught:
                    error = "invalid response: " + type(caught).__name__
            elapsed = time.monotonic() - started
            with self.lock:
                self.raw.write(json.dumps({"phase": phase, "method": method, "path": path, "status": status,
                    "seconds": elapsed, "attempt": attempt + 1, "bytes_sent": len(payload), "bytes_received": len(raw),
                    "error": error, "application_errors": application_errors,
                    "failure_body": raw[:1000].decode(errors="replace") if status != 200 else None}) + "\n")
                self.raw.flush()
            if error or status == 429 or status >= 500:
                if attempt == 7:
                    raise RuntimeError(f"terminal request failure in {phase}: status={status} error={error}")
                time.sleep(min(0.1 * 2**attempt, 2.0))
                continue
            if status != 200:
                raise RuntimeError(f"{phase}: HTTP {status}: {raw[:500]!r}")
            if self.engine == "surreal":
                if application_errors:
                    raise RuntimeError(f"SurrealDB {phase}: {application_errors}")
                return [statement["result"] for statement in result]
            return result


def parallel(items, send, workers=8):
    count = 0
    with ThreadPoolExecutor(max_workers=workers) as executor:
        pending = set()
        for item in items:
            while len(pending) >= 16:
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                for future in done:
                    future.result()
            pending.add(executor.submit(send, item))
            count += 1
        for future in pending:
            future.result()
    return count


def surreal_batch(http, table, rows, key, relation=False):
    # The marker and the mutation share one transaction, so an ambiguous ACK
    # can be retried while keeping SurrealDB-generated relation identities.
    marker = f"type::record('ingest_batches',{json.dumps(key)})"
    if relation:
        query = f"BEGIN TRANSACTION; IF !record::exists({marker}) {{ LET $ids = (INSERT RELATION INTO {table} [{','.join(rows)}] RETURN VALUE id); CREATE {marker} CONTENT {{edge_ids:$ids}} RETURN VALUE edge_ids; }} ELSE {{ SELECT VALUE edge_ids FROM {marker}; }}; COMMIT TRANSACTION;"
        result = http.request("POST", "/sql", query, table)
        ids = result[1][0]
        assert len(ids) == len(rows) and len(set(ids)) == len(ids)
        return ids
    query = f"BEGIN TRANSACTION; IF !record::exists({marker}) {{ INSERT INTO {table} [{','.join(rows)}] RETURN NONE; CREATE {marker} CONTENT {{done:true}} RETURN NONE; }}; COMMIT TRANSACTION;"
    http.request("POST", "/sql", query, table)


def sql(http, query, parameters=(), phase="oracle"):
    result = http.request("POST", "/v1/sql", {"statements": [{"sql": query, "parameters": list(parameters)}]}, phase)
    return [[value.get("value") for value in row] for row in result["results"][0]["rows"]]


def graph(http, ids, phase):
    # Every bound is explicit; the oracle requests one hop and all <=150
    # expected edges for a batch of 50 anchors, without accepting truncation.
    result = http.request("POST", "/v1/collections/chunks/graph/traverse", {
        "anchors": ids, "edge_types": ["cites"], "direction": "outgoing", "returns": "edges", "with_payload": True,
        "budget": {"max_depth": 1, "max_frontier": 10000, "max_visited": 10000,
                   "max_edges": 10000, "max_time_ms": 5000, "max_memory_bytes": 16 * 1024 * 1024, "cold": None},
    }, phase)
    assert result.get("truncation") is None and not result.get("warnings"), result
    return result["result"]["rows"]


def ready(http, args, manifest):
    first = next(batches(args.fixture / "points.jsonl", 1))[0]
    if args.engine == "chiron":
        deadline = time.monotonic() + 300
        while True:
            index = http.request("GET", "/v1/collections/chunks/index_status", {}, "readiness")
            if not index["build_in_flight"]:
                assert index["total_points"] == manifest["documents"]
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("index readiness deadline exceeded")
            time.sleep(0.05)
        assert http.request("POST", "/v1/collections/chunks/count", {}, "readiness")["count"] == manifest["documents"]
        assert sql(http, "SELECT COUNT(*) AS count FROM documents", phase="readiness") == [[manifest["documents"]]]
        hits = http.request("POST", "/v1/collections/chunks/search", {"vector": first["vector"], "k": 10}, "readiness")
        assert len(hits["hits"]) == 10 and not hits.get("degraded")
        term = first["payload"]["text"].split()[0]
        lexical = http.request("POST", "/v1/collections/chunks/text_hybrid_search", {"query": term, "text_field": "text", "k": 10}, "readiness")
        assert lexical["hits"] and not lexical.get("degraded")
        assert graph(http, [first["id"]], "readiness")
    else:
        deadline = time.monotonic() + 300
        while True:
            indices = http.request("POST", "/sql", "INFO FOR INDEX vector_idx ON chunks; INFO FOR INDEX text_idx ON chunks;", "readiness")
            states = [index["building"] for index in indices]
            if all(state["status"] == "ready" and state["pending"] == 0 and state["compacting"] is False for state in states):
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("SurrealDB index readiness deadline exceeded: " + json.dumps(states))
            time.sleep(0.05)
        counts = http.request("POST", "/sql", "SELECT count() AS count FROM documents GROUP ALL; SELECT count() AS count FROM chunks GROUP ALL; SELECT count() AS count FROM cites GROUP ALL;", "readiness")
        assert [row[0]["count"] for row in counts] == [manifest["documents"], manifest["documents"], manifest["edges"]]
        assert len(http.request("POST", "/sql", "SELECT id FROM chunks WHERE vector <|10,40|> " + json.dumps(first["vector"]) + ";", "readiness")[0]) == 10
        term = json.dumps(first["payload"]["text"].split()[0])
        assert http.request("POST", "/sql", "SELECT id FROM chunks WHERE text @@ " + term + " LIMIT 10;", "readiness")[0]


def validate_dataset(http, args, manifest):
    expected_edges = {}
    with (args.fixture / "edges.jsonl").open() as stream:
        for line in stream:
            edge = json.loads(line)
            expected_edges.setdefault(edge["source_point_id"], set()).add((edge["source_point_id"], edge["target_point_id"], edge["properties"]["ordinal"]))
    count, edge_ids, edge_identities = 0, set(), {}
    representations = {"f32": 0, "scaled_f16": 0}
    for expected in batches(args.fixture / "points.jsonl"):
        ids = [point["id"] for point in expected]
        if args.engine == "chiron":
            result = http.request("POST", "/v1/collections/chunks/points/get", {"ids": ids}, "oracle-points")
            actual = {point["id"]: point for point in result["points"]}
            assert set(actual) == set(ids)
            for point in expected:
                vector = [f32(value) for value in actual[point["id"]]["vector"]]
                if vector == point["vector"]:
                    representations["f32"] += 1
                else:
                    assert manifest.get("vector_oracle") == "exact f32 or exact decoded existing scaled IEEE-f16 row; no epsilon"
                    assert vector == persisted_vector(point["vector"]), "persisted vector oracle mismatch"
                    representations["scaled_f16"] += 1
                assert actual[point["id"]]["payload"] == point["payload"]
            # Check every primary key without materializing the whole SQL
            # relation inside a range/sort operator on the larger fixture.
            # Native SQL admits at most 32 statements in one request.
            rows = []
            for offset in range(0, len(ids), 32):
                keys = ids[offset:offset + 32]
                result = http.request("POST", "/v1/sql", {"statements": [
                    {"sql": "SELECT id, ordinal FROM documents WHERE id=$1",
                     "parameters": [{"type": "text", "value": identity}]}
                    for identity in keys]}, "oracle-sql")
                assert len(result["results"]) == len(keys)
                for item in result["results"]:
                    assert len(item["rows"]) == 1
                    rows.append([value.get("value") for value in item["rows"][0]])
            assert rows == [[point["id"], point["payload"]["ordinal"]] for point in expected]
            edges = graph(http, ids, "oracle-graph")
            actual_edges = {(edge["source"], edge["target"], edge["properties"]["ordinal"]) for edge in edges}
        else:
            records = ",".join("type::record('chunks'," + json.dumps(identity) + ")" for identity in ids)
            rows = http.request("POST", "/sql", "SELECT doc_id, vector, text, ordinal FROM [" + records + "];", "oracle-points")[0]
            actual = {point["doc_id"]: point for point in rows}
            assert set(actual) == set(ids)
            for point in expected:
                assert [f32(value) for value in actual[point["id"]]["vector"]] == point["vector"]
                representations["f32"] += 1
                assert actual[point["id"]]["text"] == point["payload"]["text"]
                assert actual[point["id"]]["ordinal"] == point["payload"]["ordinal"]
            metadata = http.request("POST", "/sql", "SELECT doc_id, ordinal FROM documents WHERE doc_id IN " + json.dumps(ids) + ";", "oracle-sql")[0]
            assert {row["doc_id"]: row["ordinal"] for row in metadata} == {point["id"]: point["payload"]["ordinal"] for point in expected}
            edges = http.request("POST", "/sql", "SELECT id, in.doc_id AS source, out.doc_id AS target, ordinal FROM cites WHERE in IN [" + records + "];", "oracle-graph")[0]
            actual_edges = {(edge["source"], edge["target"], edge["ordinal"]) for edge in edges}
        wanted = set().union(*(expected_edges.get(identity, set()) for identity in ids))
        assert actual_edges == wanted, "graph oracle mismatch"
        assert len(edges) == len(actual_edges), "duplicated logical edge"
        for edge in edges:
            identity = str(edge["id"])
            assert identity not in edge_ids, "duplicate edge identity"
            edge_ids.add(identity)
            ordinal = edge["properties"]["ordinal"] if args.engine == "chiron" else edge["ordinal"]
            assert ordinal not in edge_identities
            edge_identities[ordinal] = identity
        count += len(expected)
    assert count == manifest["documents"] and len(edge_ids) == manifest["edges"]
    acknowledgments = Path(args.output) / "edge-acks.jsonl" if getattr(args, "output", None) else None
    if acknowledgments and acknowledgments.is_file():
        expected_ids = {}
        for line in acknowledgments.read_text().splitlines():
            batch = json.loads(line)
            assert len(batch["ordinals"]) == len(batch["edge_ids"])
            for ordinal, identity in zip(batch["ordinals"], batch["edge_ids"]):
                assert ordinal not in expected_ids, "repeated batch acknowledgment"
                expected_ids[ordinal] = identity
        assert edge_identities == expected_ids, "stored edges differ from ordered ACK identities"
    return {"documents": count, "edges": len(edge_ids), "points_sql_graph": "pass",
            "vector_representations": representations,
            "edge_identity_sha256": hashlib.sha256(encode(sorted(edge_identities.items()))).hexdigest()}


def run(args):
    manifest = json.loads((args.fixture / "manifest.json").read_text())
    for name, digest in manifest["files"].items():
        assert file_hash(args.fixture / name) == digest, f"fixture changed: {name}"
    args.output.mkdir(parents=True, exist_ok=False)
    workers, batch_size = getattr(args, "workers", 8), getattr(args, "batch_size", 50)
    report = {"manifest": manifest, "engine": args.engine, "source": args.source, "workers": workers,
              "batch_size": batch_size, "baseline_single_edge": args.single_edge, "phases": {}, "status": "running"}
    with (args.output / "requests.jsonl").open("w") as raw, (args.output / "edge-acks.jsonl").open("w") as acknowledgments:
        http = HTTP(args, raw)
        ack_lock = threading.Lock()
        started = time.monotonic()
        report["timer_monotonic_started"] = started
        try:
            schema = time.monotonic()
            if args.engine == "chiron":
                http.request("POST", "/v1/collections", {"name": "chunks", "vector_dim": 384, "metric": "l2", "shards": 1, "replicas": 1}, "schema")
                http.request("POST", "/v1/sql", {"statements": [{"sql": "CREATE TABLE documents (id TEXT PRIMARY KEY, ordinal BIGINT NOT NULL)", "parameters": []}]}, "schema")
                http.request("PUT", "/v1/collections/chunks/graph", {}, "schema")
                http.request("PUT", "/v1/collections/chunks/graph/types/cites", {}, "schema")
            else:
                http.request("POST", "/sql", "DEFINE NAMESPACE qualification; USE NS qualification; DEFINE DATABASE ingest; USE DB ingest; DEFINE TABLE documents SCHEMALESS; DEFINE TABLE chunks SCHEMALESS; DEFINE TABLE cites TYPE RELATION IN chunks OUT chunks; DEFINE TABLE ingest_batches SCHEMALESS; DEFINE ANALYZER text_analyzer TOKENIZERS blank,class FILTERS lowercase; DEFINE INDEX text_idx ON chunks FIELDS text FULLTEXT ANALYZER text_analyzer BM25; DEFINE INDEX vector_idx ON chunks FIELDS vector HNSW DIMENSION 384 DIST EUCLIDEAN TYPE F32;", "schema")
            report["phases"]["schema"] = {"seconds": time.monotonic() - schema}
            for phase in ("sql", "points", "edges"):
                phase_started = time.monotonic()

                def send(item):
                    number, batch = item
                    key = f"qualification-{phase}-{number}"
                    if args.engine == "chiron":
                        if phase == "sql":
                            # One native multi-row INSERT keeps the product's
                            # 32-statement limit while committing the same 50
                            # rows as the comparison engine in one transaction.
                            parameters = [parameter for row in batch for parameter in row["statements"][0]["parameters"]]
                            values = ",".join(f"(${2 * index + 1},${2 * index + 2})" for index in range(len(batch)))
                            statement = {"sql": "INSERT INTO documents (id, ordinal) VALUES " + values, "parameters": parameters}
                            result = http.request("POST", "/v1/sql", {"statements": [statement], "idempotency_key": key}, phase)
                            assert result["committed"] is True
                        elif phase == "points":
                            http.request("PUT", "/v1/collections/chunks/points?wait=true", {"points": batch}, phase)
                        elif args.single_edge:
                            edge_ids = []
                            for index, edge in enumerate(batch):
                                result = http.request("POST", "/v1/collections/chunks/edges", {**edge, "wait": True, "idempotency_key": key + f"-{index}"}, phase)
                                edge_ids.append(result["edge_id"])
                        else:
                            result = http.request("POST", "/v1/collections/chunks/edges/batch", {"edges": batch, "wait": True, "idempotency_key": key}, phase)
                            assert len(result["edge_ids"]) == len(batch) and result["receipt"]["durable"]
                            edge_ids = result["edge_ids"]
                    elif phase == "sql":
                        rows = []
                        for row in batch:
                            values = row["statements"][0]["parameters"]
                            identity, ordinal = values[0]["value"], values[1]["value"]
                            rows.append("{id:type::record('documents'," + json.dumps(identity) + "),doc_id:" + json.dumps(identity) + ",ordinal:" + str(ordinal) + "}")
                        surreal_batch(http, "documents", rows, key)
                    elif phase == "points":
                        rows = ["{id:type::record('chunks'," + json.dumps(row["id"]) + "),doc_id:" + json.dumps(row["id"]) + ",vector:" + json.dumps(row["vector"]) + ",text:" + json.dumps(row["payload"]["text"]) + ",ordinal:" + str(row["payload"]["ordinal"]) + "}" for row in batch]
                        surreal_batch(http, "chunks", rows, key)
                    else:
                        rows = ["{in:type::record('chunks'," + json.dumps(row["source_point_id"]) + "),out:type::record('chunks'," + json.dumps(row["target_point_id"]) + "),ordinal:" + str(row["properties"]["ordinal"]) + "}" for row in batch]
                        edge_ids = surreal_batch(http, "cites", rows, key, relation=True)
                    if phase == "edges":
                        with ack_lock:
                            acknowledgments.write(json.dumps({"batch": number, "edge_ids": edge_ids,
                                "ordinals": [row["properties"]["ordinal"] for row in batch]}) + "\n")
                            acknowledgments.flush()

                count = parallel(enumerate(batches(args.fixture / (phase + ".jsonl"), batch_size)), send, workers)
                report["phases"][phase] = {"seconds": time.monotonic() - phase_started, "batches": count}
            report["load_seconds"] = time.monotonic() - started
            ready(http, args, manifest)
            report["ready_seconds"] = time.monotonic() - started
            report["timer_monotonic_ready"] = time.monotonic()
            if getattr(args, "on_ready", None):
                report["resources"] = args.on_ready()
            report["oracle"] = validate_dataset(http, args, manifest)
            report["status"] = "passed; campaign resource and repetition gates remain separate"
        except Exception as error:
            report.update(status="failed", error=str(error), elapsed_seconds=time.monotonic() - started)
            raise
        finally:
            attempts = [json.loads(line) for line in (args.output / "requests.jsonl").read_text().splitlines()]
            timed = [row for row in attempts if not row["phase"].startswith("oracle-")]
            report["transport"] = {
                "scope": "schema through readiness or terminal failure; oracle excluded",
                "requests": len(timed), "retries": sum(row["attempt"] > 1 for row in timed),
                "errors": sum(bool(row["error"] or row["status"] != 200 or row["application_errors"]) for row in timed),
                "timeouts": sum("timeout" in str(row["error"]).lower() for row in timed),
                "bytes_sent": sum(row["bytes_sent"] for row in timed),
                "bytes_received": sum(row["bytes_received"] for row in timed),
                "projection": "SQL/point mutation ACK; ordered edge IDs; no returned document/vector bodies",
            }
            for phase, noun in (("points", "documents"), ("edges", "edges")):
                if phase in report["phases"]:
                    report["phases"][phase][noun + "_per_second"] = manifest[noun] / report["phases"][phase]["seconds"]
            if "ready_seconds" in report:
                report["phases"]["readiness"] = {"seconds": report["ready_seconds"] - report["load_seconds"]}
            (args.output / "report.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare_parser = sub.add_parser("prepare")
    prepare_parser.add_argument("--beir", required=True)
    prepare_parser.add_argument("--scale", type=int, choices=(1, 10), default=1)
    prepare_parser.add_argument("--output", type=Path, required=True)
    run_parser = sub.add_parser("run")
    run_parser.add_argument("--engine", choices=("chiron", "surreal"), required=True)
    run_parser.add_argument("--url", required=True)
    run_parser.add_argument("--source", required=True)
    run_parser.add_argument("--fixture", type=Path, required=True)
    run_parser.add_argument("--output", type=Path, required=True)
    run_parser.add_argument("--single-edge", action="store_true")
    run_parser.add_argument("--workers", type=int, choices=(1, 8), default=8)
    run_parser.add_argument("--batch-size", type=int, choices=(1, 50), default=50)
    args = parser.parse_args()
    (prepare if args.command == "prepare" else run)(args)


if __name__ == "__main__":
    main()
