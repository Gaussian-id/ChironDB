#!/usr/bin/env python3
"""Load JSONL points, SQL requests and edges with bounded, resumable batches.

Uses only Python's standard library. The SQLite progress database belongs to
this loader, and must be retained/restored with the same target installation.
"""
from __future__ import annotations

import argparse
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import hashlib
import http.client
import json
import os
from pathlib import Path
import sqlite3
import ssl
import threading
import time
from urllib.parse import quote, urlsplit


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def batches(path, size=50):
    with path.open() as stream:
        batch = []
        for line in stream:
            if line.strip():
                item = json.loads(line)
                if not isinstance(item, dict):
                    raise ValueError(f"{path}: each JSONL item must be an object")
                batch.append(item)
                if len(batch) == size:
                    yield batch
                    batch = []
        if batch:
            yield batch


class Client:
    def __init__(self, url, key, ca_cert=None):
        self.url = urlsplit(url.rstrip("/"))
        if (self.url.scheme not in ("http", "https") or not self.url.hostname
                or self.url.username is not None or self.url.query or self.url.fragment):
            raise ValueError("URL must be an HTTP(S) base URL without credentials, query, or fragment")
        self.port = self.url.port
        self.key = key
        self.context = ssl.create_default_context(cafile=ca_cert)
        self.local = threading.local()

    def request(self, method, path, body):
        payload = b"" if body is None else encode(body)
        for attempt in range(8):
            connection = getattr(self.local, "connection", None)
            if connection is None:
                if self.url.scheme == "https":
                    connection = http.client.HTTPSConnection(self.url.hostname, self.port, timeout=120, context=self.context)
                else:
                    connection = http.client.HTTPConnection(self.url.hostname, self.port, timeout=120)
                self.local.connection = connection
            headers = {"Content-Type": "application/json"}
            if self.key:
                headers["Authorization"] = "Bearer " + self.key
            try:
                connection.request(method, self.url.path.rstrip("/") + path, payload, headers)
                response = connection.getresponse()
                raw = response.read()
                if response.status == 429:
                    if attempt == 7:
                        raise ValueError("server admission remained unavailable after bounded retries")
                    delay = response.getheader("Retry-After")
                    time.sleep(min(float(delay) if delay else 0.1 * 2**attempt, 2.0))
                    continue
                if response.status >= 500:
                    raise OSError(f"HTTP {response.status}; batch outcome may require reconciliation")
                if response.status != 200:
                    raise ValueError(f"HTTP {response.status}: {raw[:500].decode(errors='replace')}")
                return json.loads(raw)
            except (OSError, http.client.HTTPException):
                connection.close()
                self.local.connection = None
                if attempt == 7:
                    raise
                time.sleep(min(0.1 * 2**attempt, 2.0))


def load(args):
    inputs = {kind: Path(path).resolve() for kind in ("sql", "points", "edges") if (path := getattr(args, kind))}
    if not inputs:
        raise ValueError("at least one of --sql, --points or --edges is required")
    client = Client(args.url, os.environ.get("CHIRONDB_API_KEY", ""), args.ca_cert)
    manifest = encode({"url": args.url.rstrip("/"), "collection": args.collection,
                      "inputs": {kind: file_hash(path) for kind, path in inputs.items()}})
    state = sqlite3.connect(args.state)
    state.execute("PRAGMA journal_mode=WAL")
    state.execute("PRAGMA synchronous=FULL")
    state.execute("CREATE TABLE IF NOT EXISTS manifest (id INTEGER PRIMARY KEY CHECK(id=1), value BLOB NOT NULL)")
    state.execute("CREATE TABLE IF NOT EXISTS completed (phase TEXT, batch INTEGER, receipt TEXT NOT NULL, PRIMARY KEY(phase,batch))")
    stored = state.execute("SELECT value FROM manifest WHERE id=1").fetchone()
    if stored and stored[0] != manifest:
        raise ValueError("progress database belongs to different input files or target")
    state.execute("INSERT OR IGNORE INTO manifest VALUES (1,?)", (manifest,))
    state.commit()
    collection = quote(args.collection, safe="")
    identity = hashlib.sha256(manifest).hexdigest()

    def send(phase, number, batch):
        key = "bulk-" + hashlib.sha256(f"{identity}:{phase}:{number}".encode()).hexdigest()
        if phase == "points":
            result = client.request("PUT", f"/v1/collections/{collection}/points?wait=true", {"points": batch})
        elif phase == "edges":
            result = client.request("POST", f"/v1/collections/{collection}/edges/batch", {
                "edges": batch, "wait": True, "idempotency_key": key})
            if len(result["edge_ids"]) != len(batch) or not result["receipt"]["durable"]:
                raise ValueError("server did not return the complete durable edge batch")
        else:
            statements = [statement for item in batch for statement in item["statements"]]
            result = []
            # SQL admits at most 32 statements per transaction. Preserve the
            # input order and checkpoint only after every sub-batch is known.
            # A lost ACK replays the same sub-batch key, including after restart.
            for offset in range(0, len(statements), 32):
                receipt = client.request("POST", "/v1/sql", {
                    "statements": statements[offset:offset + 32], "idempotency_key": key + f"-{offset // 32}"})
                if receipt.get("committed") is not True:
                    raise ValueError("SQL batch did not return a committed receipt")
                result.append(receipt)
        return result

    report = {"phases": {}, "input_hashes": json.loads(manifest)["inputs"]}
    started = time.monotonic()
    try:
        with ThreadPoolExecutor(max_workers=8) as executor:
            for phase, path in inputs.items():
                phase_started = time.monotonic()
                pending = {}
                counts = {"items": 0, "batches_sent": 0, "batches_resumed": 0}

                def checkpoint(done):
                    for future in done:
                        number = pending.pop(future)
                        receipt = future.result()
                        state.execute("INSERT INTO completed VALUES (?,?,?)", (phase, number, json.dumps(receipt)))
                        state.commit()

                for number, batch in enumerate(batches(path)):
                    counts["items"] += len(batch)
                    if state.execute("SELECT 1 FROM completed WHERE phase=? AND batch=?", (phase, number)).fetchone():
                        counts["batches_resumed"] += 1
                        continue
                    while len(pending) >= 16:
                        done, _ = wait(pending, return_when=FIRST_COMPLETED)
                        checkpoint(done)
                    pending[executor.submit(send, phase, number, batch)] = number
                    counts["batches_sent"] += 1
                if pending:
                    done, _ = wait(pending)
                    checkpoint(done)
                counts["seconds"] = time.monotonic() - phase_started
                report["phases"][phase] = counts
        report["load_seconds"] = time.monotonic() - started
        if {kind: file_hash(path) for kind, path in inputs.items()} != report["input_hashes"]:
            raise ValueError("input changed during loading; reconcile it before resuming")
        deadline = time.monotonic() + 300
        while client.request("GET", f"/v1/collections/{collection}/index_status", None)["build_in_flight"]:
            if time.monotonic() >= deadline:
                raise TimeoutError("committed data is still waiting for index readiness; resume with the same progress file")
            time.sleep(0.1)
        readiness = {"index_ready": True, "sample_point": None, "dense_query_verified": False}
        if "points" in inputs:
            sample = next(batches(inputs["points"], 1), [])
            if sample:
                point = sample[0]
                result = client.request("POST", f"/v1/collections/{collection}/points/get", {"ids": [point["id"]]})
                if [row["id"] for row in result["points"]] != [point["id"]]:
                    raise ValueError("committed sample point is unavailable")
                readiness["sample_point"] = point["id"]
                query = {"vector": point.get("vector", []), "k": 1, "with_payload": False}
                if not query["vector"] and point.get("vectors"):
                    query["vector_name"] = sorted(point["vectors"])[0]
                    query["vector"] = point["vectors"][query["vector_name"]]
                if query["vector"]:
                    result = client.request("POST", f"/v1/collections/{collection}/search", query)
                    if not result["hits"] or result.get("degraded"):
                        raise ValueError("committed sample search is not ready")
                    readiness["dense_query_verified"] = True
        report["readiness"] = readiness
        report["ready_seconds"] = time.monotonic() - started
        return report
    finally:
        state.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--collection", required=True)
    parser.add_argument("--state", required=True, help="persistent SQLite loader progress file")
    parser.add_argument("--ca-cert")
    for kind in ("sql", "points", "edges"):
        parser.add_argument("--" + kind, help="JSONL input file")
    args = parser.parse_args()
    print(json.dumps(load(args), indent=2))


if __name__ == "__main__":
    main()
