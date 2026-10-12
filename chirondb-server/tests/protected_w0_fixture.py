#!/usr/bin/env python3
"""Construct and independently census the canonical protected W0 dataset.

Default: 521,000 SQL rows, 100,000 768D vectors, 400,000 directed edges.
Use protected_w0_setup against a NEW disposable directory, supply trusted TLS
files, and start the server before running this external generator. Construction
has multiple durable phases and is not a production ingest atomicity test. An
interrupted construction after all vector/chunk allocations may use resume;
it remains incomplete until a full census succeeds. Never run against
customer data. Smaller --owners values are functional checks, not W0.

This slice implements preparation and census, not the timed 16-client workload,
paired runs, maintenance phases, resource attribution or ANN/BEIR certification.
"""

import argparse
import hashlib
import itertools
import json
from pathlib import Path
import struct
import sys
import time

from protected_wlite_mixed import Client, admin_mutation, sql_value


SEED = 20260914
DIMENSIONS = 768
MASK = (1 << 64) - 1
TABLES = ("w0_owners", "w0_documents", "w0_versions", "w0_chunks", "w0_edge_rows")


def mix(value):
    value = (value + 0x9E3779B97F4A7C15) & MASK
    value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & MASK
    value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & MASK
    return value ^ (value >> 31)


def vector(index):
    # Integer PRNG output is mapped to exact f32 dyadic values. No platform RNG
    # or JSON f64 -> f32 rounding differences enter the expected fixture.
    state = mix(SEED + index)
    result = []
    for _ in range(DIMENSIONS):
        state = mix(state)
        result.append(((state >> 40) - (1 << 23)) / (1 << 23))
    return result


def text(index):
    prefix = f"synthetic knowledge chunk {index:06d} seed {SEED} "
    return prefix + "x" * (512 - len(prefix))


def targets(index, count, topology):
    # Four distinct, non-self directed neighbours. Hub-skew separately puts
    # three edges into the first one percent; one remains globally distributed.
    selected = []
    state = mix(SEED ^ index)
    for slot in range(4):
        modulus = max(8, count // 100) if topology == "hub" and slot < 3 else count
        while True:
            state = mix(state)
            target = state % min(count, modulus)
            if target != index and target not in selected:
                selected.append(target)
                break
    return selected


def expected_rows(table, owners, topology):
    documents = owners * 10
    chunks = documents * 10
    if table == "w0_owners":
        for index in range(owners):
            yield {"id": index, "name": f"owner-{index}"}
    elif table == "w0_documents":
        for index in range(documents):
            yield {"id": index, "owner_id": index // 10, "title": f"document-{index}"}
    elif table == "w0_versions":
        for index in range(documents):
            yield {"id": index, "document_id": index, "revision": 1}
    elif table == "w0_chunks":
        for index in range(chunks):
            yield {"id": index, "version_id": index // 10, "text": text(index)}
    elif table == "w0_edge_rows":
        for source in range(chunks):
            for slot, target in enumerate(targets(source, chunks, topology)):
                yield {"id": source * 4 + slot, "source_id": source,
                       "target_id": target, "slot": slot,
                       "revision": 2 if source % 16 == 0 and slot == 0 else 1}
    else:
        raise ValueError(table)


def insert(client, table, rows, key):
    columns = list(rows[0])
    values = ",".join("(" + ",".join(sql_value(row[column]) for column in columns) + ")"
                      for row in rows)
    result, _ = client.query(f"SQL INSERT INTO {table} ({','.join(columns)}) VALUES {values};",
                            idempotency_key=key)
    if not result.get("committed"):
        raise AssertionError(("uncommitted SQL insert", table, key))


def progress(phase, count, started):
    print(json.dumps({"phase": phase, "count": count,
                      "elapsed_seconds": round(time.monotonic() - started, 3)}),
          file=sys.stderr, flush=True)


def seed_edge_rows(client, owners, topology, first_id, started):
    total = owners * 400
    if first_id < 0 or first_id > total or (first_id != total and first_id % 128):
        raise ValueError(("invalid committed SQL edge frontier", first_id, total))
    batch = []
    for row in itertools.islice(expected_rows("w0_edge_rows", owners, topology), first_id, None):
        row["revision"] = 1
        batch.append(row)
        if len(batch) == 128:
            insert(client, "w0_edge_rows", batch, f"w0-edge-rows-{batch[0]['id']}")
            count = batch[-1]["id"] + 1
            if count % 4096 == 0 or count == total:
                progress("sql_edge_rows", count, started)
            batch = []
    if batch:
        insert(client, "w0_edge_rows", batch, f"w0-edge-rows-{batch[0]['id']}")
        progress("sql_edge_rows", total, started)


def allocated_ids(root, count):
    ids = []
    with (root / "w0-allocated.jsonl").open() as allocation:
        for line in allocation:
            item = json.loads(line)
            if item["chunk"] != len(ids) or not isinstance(item["id"], str):
                raise AssertionError(("non-contiguous allocated identity", len(ids)))
            ids.append(item["id"])
    if len(ids) != count or len(set(ids)) != count:
        raise AssertionError(("incomplete/duplicate vector allocation", len(ids), count))
    return ids


def graph_frontier(root, count):
    next_source = 0
    path = root / "w0-graph-progress.jsonl"
    if path.exists():
        with path.open() as progress_file:
            for line in progress_file:
                item = json.loads(line)
                end = min(count, next_source + 16)
                if item != {"start": next_source, "end": end}:
                    raise AssertionError(("non-contiguous graph receipt", item, next_source))
                next_source = end
    return next_source


def seed_graph(client, root, ids, topology, started):
    first_source = graph_frontier(root, len(ids))
    path = root / "w0-graph-progress.jsonl"
    with path.open("a" if path.exists() else "x") as receipts:
        for start in range(first_source, len(ids), 16):
            end = min(len(ids), start + 16)
            points = ",".join(sql_value({"id": ids[index], "vector": vector(index),
                                        "payload": {"text": text(index)}})
                              for index in range(start, end))
            graph = []
            for source in range(start, end):
                for slot, target in enumerate(targets(source, len(ids), topology)):
                    graph.append(f"GRAPH CONNECT w0 {sql_value(ids[source])} -> cites -> "
                                 f"{sql_value(ids[target])} SET {{uid:{source * 4 + slot}}};")
            query = (f"TRANSACTION {{ SQL UPDATE w0_edge_rows SET revision=2 WHERE id={start * 4}; "
                     f"VECTOR UPSERT INTO w0 {points}; " + " ".join(graph) + " };")
            result, _ = client.query(query, idempotency_key=f"w0-graph-{start}")
            if not result.get("committed") or sum(bool(row.get("edge_id")) for row in result["rows"]) != len(graph):
                raise AssertionError(("wrong graph commit receipt", start))
            receipts.write(json.dumps({"start": start, "end": end}) + "\n")
            receipts.flush()
            if end % 1024 == 0 or end == len(ids):
                progress("graph_edges", end * 4, started)


def resume(client, root, owners, topology):
    started = time.monotonic()
    ids = allocated_ids(root, owners * 100)
    for table, expected in (("w0_owners", owners), ("w0_documents", owners * 10),
                            ("w0_versions", owners * 10), ("w0_chunks", owners * 100)):
        result, _ = client.query(f"SQL SELECT COUNT(*) AS n FROM {table};")
        if result["rows"][0]["n"] != expected:
            raise AssertionError(("incomplete pre-edge SQL phase", table, result["rows"][0]))
    points, _ = client.query("COUNT w0;")
    if points["rows"][0]["count"] != len(ids):
        raise AssertionError("incomplete vector phase")
    result, _ = client.query("SQL SELECT COUNT(*) AS n FROM w0_edge_rows;")
    first_id = result["rows"][0]["n"]
    if first_id:
        last, _ = client.query(f"SQL SELECT id FROM w0_edge_rows WHERE id={first_id - 1};")
        if last["rows"] != [{"id": first_id - 1}]:
            raise AssertionError(("missing edge-row frontier", first_id))
    next_row, _ = client.query(f"SQL SELECT id FROM w0_edge_rows WHERE id={first_id};")
    if next_row.get("rows", []):
        raise AssertionError(("edge-row frontier is not contiguous", first_id))
    if (root / "w0-graph-progress.jsonl").exists() and first_id != owners * 400:
        raise AssertionError("graph construction began before SQL edge rows completed")
    progress("resume_edge_frontier", first_id, started)
    seed_edge_rows(client, owners, topology, first_id, started)
    seed_graph(client, root, ids, topology, started)
    return time.monotonic() - started


def seed(client, root, owners, topology):
    started = time.monotonic()
    admin_mutation(client, "CREATE PROTECTED COLLECTION w0 DIM 768 METRIC cosine;",
                   "SHOW CATALOG REVISION;")
    policy = {"department_actions": [],
              "owner_actions": ["read", "search", "update", "delete", "graph_read", "graph_write"],
              "templates": {"standard": {"department": "Ingestion", "classification": "internal",
                  "properties": {"/text": {"classification": "internal",
                                              "actions": ["read", "query", "write"]}},
                  "representations": {"dense": {"source_fields": ["/text"],
                                                  "classification": "internal"}}}}}
    admin_mutation(client, "ALTER COLLECTION w0 SET SECURITY POLICY " + sql_value(policy) + ";",
                   "SHOW SECURITY REVISION ON COLLECTION w0;")
    admin_mutation(client, "ALTER COLLECTION w0 SET GRAPH ENABLED;",
                   "SHOW SECURITY REVISION ON COLLECTION w0;")
    admin_mutation(client, "ALTER COLLECTION w0 SET EDGE TYPE cites;",
                   "SHOW SECURITY REVISION ON COLLECTION w0;")
    for definition in (
        "w0_owners (id BIGINT PRIMARY KEY, name TEXT NOT NULL)",
        "w0_documents (id BIGINT PRIMARY KEY, owner_id BIGINT NOT NULL REFERENCES w0_owners(id), title TEXT NOT NULL)",
        "w0_versions (id BIGINT PRIMARY KEY, document_id BIGINT NOT NULL REFERENCES w0_documents(id), revision BIGINT NOT NULL)",
        "w0_chunks (id BIGINT PRIMARY KEY, version_id BIGINT NOT NULL REFERENCES w0_versions(id), text TEXT NOT NULL, record RECORD_REF('w0') NOT NULL)",
        "w0_edge_rows (id BIGINT PRIMARY KEY, source_id BIGINT NOT NULL REFERENCES w0_chunks(id), target_id BIGINT NOT NULL REFERENCES w0_chunks(id), slot BIGINT NOT NULL, revision BIGINT NOT NULL)",
    ):
        client.query("SQL CREATE TABLE " + definition + ";")
    for table in TABLES[:3]:
        batch = []
        for row in expected_rows(table, owners, topology):
            batch.append(row)
            if len(batch) == 256:
                insert(client, table, batch, f"{table}-{batch[0]['id']}")
                batch = []
        if batch:
            insert(client, table, batch, f"{table}-{batch[0]['id']}")
        progress(table, owners if table == TABLES[0] else owners * 10, started)
    ids = []
    # Publish mapping immediately after each durable point batch, so receipt
    # evidence survives a later SQL construction failure. No auto mutation
    # replay after disconnect is hidden by this harness.
    with (root / "w0-allocated.jsonl").open("x") as allocation:
        chunks = list(expected_rows("w0_chunks", owners, topology))
        for start in range(0, len(chunks), 32):
            batch = chunks[start:start + 32]
            points = ",".join(sql_value({"vector": vector(row["id"]),
                                        "payload": {"text": row["text"]}}) for row in batch)
            result, _ = client.query("CREATE POINTS INTO w0 USING TEMPLATE standard " + points
                                     + f" REQUEST 'w0-points-{start}';")
            allocated = [row["id"] for row in result["rows"]]
            if len(allocated) != len(batch):
                raise AssertionError(("wrong allocation count", start))
            for row, public_id in zip(batch, allocated):
                row["record"] = {"namespace": "w0", "id": public_id}
                allocation.write(json.dumps({"chunk": row["id"], "id": public_id}) + "\n")
            allocation.flush()
            # RECORD_REF is a SQL constructor, not a JSON object literal.
            values = ",".join(f"({row['id']},{row['version_id']},{sql_value(row['text'])},"
                              f"RECORD_REF('w0',{sql_value(public_id)}))"
                              for row, public_id in zip(batch, allocated))
            client.query("SQL INSERT INTO w0_chunks (id,version_id,text,record) VALUES "
                         + values + ";", idempotency_key=f"w0-chunks-{start}")
            ids.extend(allocated)
            if len(ids) % 1024 == 0 or len(ids) == len(chunks):
                progress("vectors_and_chunks", len(ids), started)
    seed_edge_rows(client, owners, topology, 0, started)
    # Each graph commit advances one linked SQL edge-row revision alongside
    # its vector projection. Persist acknowledged batch frontiers so a lost
    # HTTP response can be reconciled with the same idempotency key.
    seed_graph(client, root, ids, topology, started)
    return time.monotonic() - started


def census(client, owners, topology):
    started = time.monotonic()
    counts = {}
    hashes = {}
    scalar_bytes = {}
    ids = []
    for table in TABLES:
        oracle = iter(expected_rows(table, owners, topology))
        last = None
        count = 0
        digest = hashlib.sha256()
        utf8_bytes = 0
        while True:
            predicate = "" if last is None else f" WHERE id>{last}"
            response, _ = client.query(f"SQL SELECT * FROM {table}{predicate} ORDER BY id LIMIT 1024;")
            rows = response.get("rows", [])
            if not rows:
                break
            for row in rows:
                expected = next(oracle, None)
                if table == "w0_chunks":
                    ref = row.pop("record")
                    if ref["namespace"] != "w0" or not ref["id"]:
                        raise AssertionError(("invalid RECORD_REF", row["id"]))
                    ids.append(ref["id"])
                if row != expected:
                    raise AssertionError(("SQL census mismatch", table, row, expected))
                digest.update(json.dumps(row, sort_keys=True, separators=(",", ":")).encode() + b"\n")
                utf8_bytes += sum(len(value.encode()) for value in row.values() if isinstance(value, str))
                count += 1
                last = row["id"]
        if next(oracle, None) is not None:
            raise AssertionError(("missing SQL rows", table, count))
        counts[table] = count
        hashes[table] = digest.hexdigest()
        scalar_bytes[table] = utf8_bytes
        progress("sql_census_" + table, count, started)
    if len(set(ids)) != len(ids):
        raise AssertionError("duplicate server-allocated chunk identities")
    points, _ = client.query("COUNT w0;")
    if points["rows"][0]["count"] != len(ids):
        raise AssertionError("point census differs from chunk references")
    vector_hash = hashlib.sha256()
    for start in range(0, len(ids), 32):
        batch = ids[start:start + 32]
        response, _ = client.query("GET w0 POINTS " + ",".join(sql_value(value) for value in batch) + ";")
        returned = {row["id"]: row for row in response["rows"]}
        if len(response["rows"]) != len(batch) or set(returned) != set(batch):
            raise AssertionError(("missing/duplicate referenced vector", start))
        for offset, public_id in enumerate(batch):
            index = start + offset
            point = returned[public_id]
            actual = point["vector"]
            if len(actual) != DIMENSIONS or point["payload"] != {"text": text(index)}:
                raise AssertionError(("vector dimension/payload differs", index))
            packed = struct.pack("<768f", *actual)
            if packed != struct.pack("<768f", *vector(index)):
                raise AssertionError(("vector contents differ", index))
            vector_hash.update(packed)
        if (start + len(batch)) % 1024 == 0 or start + len(batch) == len(ids):
            progress("vector_census", start + len(batch), started)
    # Recover identities from persisted SQL, not the loader's allocation receipt.
    # The traversal result itself proves the graph projection and endpoints.
    graph_hash = hashlib.sha256()
    edge_ids = set()
    for source, public_id in enumerate(ids):
        response, _ = client.query(f"TRAVERSE w0 FROM {sql_value(public_id)} VIA cites DEPTH 1 "
                                   "WITH PAYLOAD RETURN EDGES LIMIT 5;")
        if response.get("stats", {}).get("truncation") or len(response["rows"]) != 4:
            raise AssertionError(("graph census truncated or wrong degree", source, len(response["rows"])))
        expected = {source * 4 + slot: ids[target] for slot, target in
                    enumerate(targets(source, len(ids), topology))}
        observed = {}
        for row in response["rows"]:
            uid = row["properties"]["uid"]
            if row["source"] != public_id or row["type"] != "cites" or row["id"] in edge_ids:
                raise AssertionError(("duplicate/invalid graph identity", source, uid))
            edge_ids.add(row["id"])
            observed[uid] = row["target"]
        if observed != expected:
            raise AssertionError(("graph logical endpoints differ", source, observed, expected))
        for uid, target in sorted(observed.items()):
            slot = uid % 4
            logical_target = targets(source, len(ids), topology)[slot]
            graph_hash.update(f"{uid}:{source}:{logical_target}\n".encode())
        if (source + 1) % 1024 == 0:
            progress("graph_census", len(edge_ids), started)
    if scalar_bytes["w0_chunks"] != len(ids) * 512:
        raise AssertionError("chunk scalar text mean differs from 512 UTF-8 bytes")
    return {"sql_counts": counts, "sql_total": sum(counts.values()),
            "vectors": len(ids), "dimensions": DIMENSIONS, "physical_edges": len(edge_ids),
            "sql_logical_sha256": hashes, "graph_endpoint_sha256": graph_hash.hexdigest(),
            "vector_f32_sha256": vector_hash.hexdigest(),
            "scalar_text_utf8_bytes": scalar_bytes,
            "census_seconds": time.monotonic() - started}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["seed", "resume", "census"])
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--owners", type=int, default=1000)
    parser.add_argument("--topology", choices=["uniform", "hub"], default="uniform")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if not 1 <= args.owners <= 1000:
        parser.error("--owners must be 1..1000")
    client = Client(args.root, args.port, "admin",
                    timeout_seconds=300 if args.mode in ("seed", "resume") else 30)
    report = {"seed": SEED, "owners": args.owners, "topology": args.topology,
              "canonical_w0_size": args.owners == 1000,
              "acceptance_complete": False}
    try:
        if args.mode == "seed":
            report["seed_seconds"] = seed(client, args.root, args.owners, args.topology)
        elif args.mode == "resume":
            report["resume_seconds"] = resume(client, args.root, args.owners, args.topology)
        report["census"] = census(client, args.owners, args.topology)
    finally:
        client.close()
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
