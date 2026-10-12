#!/usr/bin/env python3
"""Seed and exercise the protected W-lite workload over authenticated TLS.

Run against a disposable copy of a protected installation with admin and writer
API keys. The caller owns container lifecycle and cgroup measurement. Defaults
are the W-lite data and ten-minute workload; smaller counts are for syntax and
transport smoke tests only. This script never prints credentials.
"""

import argparse
import concurrent.futures
import http.client
import json
from pathlib import Path
import ssl
import sys
import time


def sql_value(value):
    if isinstance(value, str):
        return "'" + value.replace("'", "''") + "'"
    if isinstance(value, dict):
        return "{" + ",".join(sql_value(k) + ":" + sql_value(v) for k, v in value.items()) + "}"
    if isinstance(value, list):
        return "[" + ",".join(sql_value(v) for v in value) + "]"
    return json.dumps(value)


class Client:
    def __init__(self, root, port, role, key_file=None, timeout_seconds=30):
        self.context = ssl.create_default_context(cafile=str(root / "ca.pem"))
        self.port = port
        self.timeout_seconds = timeout_seconds
        self.token = (key_file or root / "secrets" / f"{role}.key").read_text().strip()
        self.conn = None
        self.refusals = 0
        self.disconnects = 0

    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None

    def query(self, statement, *, idempotency_key=None, retry_on_429=True,
              retry_read_disconnect=False):
        body = {"query": statement}
        if idempotency_key:
            body["idempotency_key"] = idempotency_key
        payload = json.dumps(body, separators=(",", ":")).encode()
        for _ in range(60):
            if self.conn is None:
                self.conn = http.client.HTTPSConnection("127.0.0.1", self.port,
                                                        context=self.context,
                                                        timeout=self.timeout_seconds)
            started = time.monotonic()
            try:
                self.conn.request("POST", "/v1/chironql", payload,
                                  {"Authorization": "Bearer " + self.token,
                                   "Content-Type": "application/json"})
                response = self.conn.getresponse()
                result = json.loads(response.read())
            except (OSError, http.client.HTTPException):
                self.close()
                if not retry_read_disconnect:
                    raise
                self.disconnects += 1
                time.sleep(.02)
                continue
            if response.status == 429:
                self.refusals += 1
                self.close()
                if not retry_on_429:
                    return None, (time.monotonic() - started) * 1000
                time.sleep(.05)
                continue
            if response.status != 200:
                raise AssertionError((response.status, result.get("code"), result.get("message"),
                                      statement[:160]))
            return result, (time.monotonic() - started) * 1000
        raise AssertionError("sixty bounded admission retries exhausted")


def vector(index, dimensions):
    values = [0] * dimensions
    values[0 if index == 0 else 1] = 1
    return values


def admin_mutation(admin, statement, revision_scope):
    shown, _ = admin.query(revision_scope)
    revision = shown["rows"][0]["revision"]
    return admin.query(statement.rstrip().rstrip(";") + f" IF REVISION {revision};")


def seed(admin, writer, rows, points, edges, dimensions):
    if points < rows * 2 or dimensions < 2:
        raise ValueError("points must be at least twice rows and dimensions at least two")
    collection = "wlite"
    admin_mutation(admin, f"CREATE PROTECTED COLLECTION {collection} DIM {dimensions} METRIC cosine;",
                   "SHOW CATALOG REVISION;")
    admin_mutation(admin,
                   "GRANT READ, SEARCH, CREATE, INGEST, UPDATE, DELETE, GRAPH_READ, GRAPH_WRITE "
                   "ON COLLECTION wlite TO ROLE writer_role;", "SHOW SECURITY REVISION;")
    policy = {
        "department_actions": [],
        "owner_actions": ["read", "search", "update", "delete", "graph_read", "graph_write"],
        "templates": {"standard": {
            "department": "Ingestion", "classification": "internal",
            "properties": {"/text": {"classification": "internal",
                                     "actions": ["read", "query", "write"]}},
            "representations": {"dense": {"source_fields": ["/text"],
                                           "classification": "internal"}},
        }},
    }
    admin_mutation(admin, "ALTER COLLECTION wlite SET SECURITY POLICY " + sql_value(policy) + ";",
                   "SHOW SECURITY REVISION ON COLLECTION wlite;")
    admin.query("SQL CREATE TABLE wlite (id TEXT PRIMARY KEY, title TEXT NOT NULL, "
                "chunk RECORD_REF('wlite') NOT NULL, source RECORD_REF('wlite') NOT NULL);")
    admin_mutation(admin, "ALTER COLLECTION wlite SET GRAPH ENABLED;",
                   "SHOW SECURITY REVISION ON COLLECTION wlite;")
    admin_mutation(admin, "ALTER COLLECTION wlite SET EDGE TYPE cites;",
                   "SHOW SECURITY REVISION ON COLLECTION wlite;")
    ids = []
    started = time.monotonic()
    first = vector(0, dimensions)
    other = vector(1, dimensions)
    for index in range(rows):
        chunks = [first if index == 0 else other, other]
        statement = f"""TRANSACTION {{
 SQL INSERT INTO wlite (id,title,chunk,source) VALUES
   ('row-{index}','synthetic document {index}',RECORD_REF('wlite',NEW_RECORD('chunk')),
    RECORD_REF('wlite',NEW_RECORD('source')));
 VECTOR CREATE POINTS INTO wlite USING TEMPLATE standard
   {{binding:'chunk',point:{{vector:{sql_value(chunks[0])},payload:{{text:'synthetic chunk {index}'}}}}}},
   {{binding:'source',point:{{vector:{sql_value(chunks[1])},payload:{{text:'synthetic source {index}'}}}}}};
 GRAPH CONNECT wlite NEW chunk -> cites -> NEW source SET {{kind:'source'}};
}};"""
        result, _ = writer.query(statement, idempotency_key=f"wlite-row-{index}")
        if not result.get("committed"):
            raise AssertionError(("row did not commit", index))
        allocated = [row["record_ref"]["id"] for row in result["rows"]
                     if row.get("record_ref")]
        edge_ids = [row["edge_id"] for row in result["rows"] if row.get("edge_id")]
        if len(allocated) != 2 or len(edge_ids) != 1:
            raise AssertionError(("wrong insert receipt", index, len(allocated), len(edge_ids)))
        ids.extend(allocated)
        if (index + 1) % 100 == 0 or index + 1 == rows:
            print(json.dumps({"seed_rows": index + 1,
                              "elapsed_seconds": round(time.monotonic() - started, 1)}),
                  file=sys.stderr, flush=True)
    for start in range(rows * 2, points, 32):
        size = min(32, points - start)
        batch = ",".join("{vector:" + sql_value(other) + ",payload:{text:'synthetic extra "
                         + str(start + offset) + "'}}" for offset in range(size))
        result, _ = writer.query(f"CREATE POINTS INTO wlite USING TEMPLATE standard {batch} "
                                 f"REQUEST 'wlite-extra-{start}';")
        allocated = [row["id"] for row in result["rows"]]
        if len(allocated) != size:
            raise AssertionError(("wrong extra IDs", start, len(allocated)))
        ids.extend(allocated)
        if (start + size - rows * 2) % 1024 == 0 or start + size == points:
            print(json.dumps({"seed_points": start + size,
                              "elapsed_seconds": round(time.monotonic() - started, 1)}),
                  file=sys.stderr, flush=True)
    # The initial atomic INSERTs each made one edge. Add distinct directed
    # pairs in bounded transactions; every transaction carries a SQL and vector
    # stage so the protected graph path shares one durable commit decision.
    remaining = max(0, edges - rows)
    edge_number = 0
    while edge_number < remaining:
        count = min(64, remaining - edge_number)
        graph = []
        for offset in range(count):
            ordinal = edge_number + offset
            source = ids[ordinal % len(ids)]
            target = ids[(ordinal // len(ids) + ordinal + 2) % len(ids)]
            graph.append(f"GRAPH CONNECT wlite '{source}' -> cites -> '{target}' "
                         f"SET {{kind:'load',ordinal:{ordinal}}};")
        statement = ("TRANSACTION { SQL UPDATE wlite SET title='synthetic document 0' "
                     "WHERE id='row-0'; VECTOR UPSERT INTO wlite "
                     + "{id:'" + ids[0] + "',vector:" + sql_value(first)
                     + ",payload:{text:'synthetic chunk 0'}}; "
                     + " ".join(graph) + " };")
        result, _ = writer.query(statement, idempotency_key=f"wlite-edges-{edge_number}")
        if not result.get("committed"):
            raise AssertionError(("edge batch did not commit", edge_number))
        if sum(bool(row.get("edge_id")) for row in result.get("rows", [])) != count:
            raise AssertionError(("wrong edge receipt count", edge_number))
        edge_number += count
        if edge_number % 1024 == 0 or edge_number == remaining:
            print(json.dumps({"seed_edges": rows + edge_number,
                              "elapsed_seconds": round(time.monotonic() - started, 1)}),
                  file=sys.stderr, flush=True)
    return ids


def verify_counts(client, rows, points):
    sql, _ = client.query("SQL SELECT COUNT(*) AS n FROM wlite;")
    dense, _ = client.query("COUNT wlite;")
    actual = {"rows": sql["rows"][0]["n"], "points": dense["rows"][0]["count"]}
    if actual != {"rows": rows, "points": points}:
        raise AssertionError(("persisted counts differ", actual, rows, points))
    return actual


def load(root, port, seconds, dimensions):
    near = sql_value(vector(0, dimensions))
    profiles = {
        "sql": "SQL SELECT id,title FROM wlite WHERE id='row-0' LIMIT 1;",
        "vector": f"SEARCH wlite NEAR {near} LIMIT 10;",
        "bm25": "HYBRID wlite TEXT 'synthetic' FIELD text LIMIT 10;",
        "graph": (f"PIPELINE VECTOR v {{ SEARCH wlite NEAR {near} LIMIT 1 }}\n"
                  "GRAPH g { TRAVERSE wlite FROM v.record_ref VIA cites DEPTH 1 "
                  "RETURN NODES LIMIT 10 }\nRELATIONAL r { SQL SELECT id,chunk,source "
                  "FROM wlite WHERE id='row-0' LIMIT 1 }\n"
                  "INNER JOIN r ON r.chunk = v.record_ref\n"
                  "INNER JOIN g ON g.record_ref = r.source\n"
                  "RETURN r.id,g.depth\nLIMIT 1;"),
    }
    deadline = time.monotonic() + seconds
    started = time.monotonic()

    def worker(name, statement):
        client = Client(root, port, "writer")
        times = []
        next_progress = time.monotonic() + 60
        try:
            while time.monotonic() < deadline:
                result, elapsed = client.query(statement, retry_on_429=False,
                                               retry_read_disconnect=True)
                if result is None:
                    time.sleep(.02)
                else:
                    if not result.get("rows"):
                        raise AssertionError(("empty protected result", name))
                    if name == "graph" and result["rows"][0].get("depth") != 1:
                        raise AssertionError(("graph did not traverse", result["rows"][0]))
                    times.append(elapsed)
                if time.monotonic() >= next_progress:
                    print(json.dumps({"profile": name, "successful": len(times),
                                      "refusals": client.refusals,
                                      "disconnects": client.disconnects,
                                      "elapsed_seconds": round(time.monotonic() - started, 1)}),
                          file=sys.stderr, flush=True)
                    next_progress += 60
        finally:
            client.close()
        times.sort()
        if not times:
            raise AssertionError(("no successful protected requests", name))
        return {"requests": len(times), "refusals": client.refusals,
                "disconnects": client.disconnects,
                "p50_ms": times[len(times) // 2] if times else None,
                "p99_ms": times[min(len(times) - 1, int(len(times) * .99))] if times else None}

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = {name: pool.submit(worker, name, query) for name, query in profiles.items()}
        result = {name: future.result() for name, future in futures.items()}
    return {"elapsed_seconds": round(time.monotonic() - started, 3), "profiles": result}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--admin-key-file", type=Path)
    parser.add_argument("--rows", type=int, default=1000)
    parser.add_argument("--points", type=int, default=10000)
    parser.add_argument("--edges", type=int, default=40000)
    parser.add_argument("--dimensions", type=int, default=768)
    parser.add_argument("--seconds", type=int, default=600)
    parser.add_argument("--load-only", action="store_true")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not args.load_only:
        admin = Client(args.root, args.port, "admin", args.admin_key_file)
        writer = Client(args.root, args.port, "writer")
        try:
            ids = seed(admin, writer, args.rows, args.points, args.edges, args.dimensions)
        finally:
            admin.close()
            writer.close()
        if len(ids) != args.points:
            raise AssertionError(("wrong point count", len(ids), args.points))
    checker = Client(args.root, args.port, "writer")
    try:
        before = verify_counts(checker, args.rows, args.points)
    finally:
        checker.close()
    results = load(args.root, args.port, args.seconds, args.dimensions)
    checker = Client(args.root, args.port, "writer")
    try:
        after = verify_counts(checker, args.rows, args.points)
    finally:
        checker.close()
    report = {"fixture": {"rows": args.rows, "points": args.points,
                          "edges_from_receipts": args.edges if not args.load_only else None,
                          "dimensions": args.dimensions},
              "count_before": before, "count_after": after, "load": results}
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
