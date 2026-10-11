#!/usr/bin/env python3
"""Exercise 16 authenticated clients on a completed, disposable W0 fixture.

Run only after protected_w0_fixture.py has passed its independent census.
Writes set existing revisions to their expected values, leaving the fixture's
logical oracle unchanged for the required post-load and clean-reopen census.
The caller measures the container's RSS, CPU and storage independently.
"""

import argparse
import concurrent.futures
import http.client
import json
from pathlib import Path
import statistics
import sys
import time
import uuid

from protected_w0_fixture import vector
from protected_wlite_mixed import Client, sql_value


PROFILES = ("sql", "vector", "hybrid", "graph", "mutation")


def percentile(values, fraction):
    return values[min(len(values) - 1, max(0, int(len(values) * fraction)))]


def load(root, port, seconds, clients):
    if clients < len(PROFILES):
        raise ValueError("clients must cover all five workload profiles")
    run_id = uuid.uuid4().hex
    setup = Client(root, port, "admin")
    try:
        found, _ = setup.query("SQL SELECT record FROM w0_chunks WHERE id=0 LIMIT 1;")
        if len(found.get("rows", [])) != 1:
            raise AssertionError("W0 fixture must pass census before workload")
        public_id = found["rows"][0]["record"]["id"]
    finally:
        setup.close()
    near = sql_value(vector(0))
    statements = {
        "sql": "SQL SELECT id,revision FROM w0_edge_rows WHERE id=0 LIMIT 1;",
        "vector": f"SEARCH w0 NEAR {near} LIMIT 10;",
        "hybrid": "HYBRID w0 TEXT 'synthetic knowledge' FIELD text LIMIT 10;",
        "graph": f"TRAVERSE w0 FROM {sql_value(public_id)} VIA cites DEPTH 1 RETURN EDGES LIMIT 5;",
    }
    deadline = time.monotonic() + seconds
    started = time.monotonic()

    def worker(index):
        profile = PROFILES[index % len(PROFILES)]
        client = Client(root, port, "admin")
        latencies = []
        attempted = 0
        reconciliations = 0
        reconciliation_attempts = 0
        try:
            while time.monotonic() < deadline:
                if profile == "mutation":
                    # Each writer owns one already-revision-2 row; this is a
                    # durable SQL mutation without changing the census oracle.
                    row_id = (index + 1) * 64
                    statement = f"SQL UPDATE w0_edge_rows SET revision=2 WHERE id={row_id};"
                    key = f"w0-load-{run_id}-{index}-{attempted}"
                else:
                    statement = statements[profile]
                    key = None
                attempted += 1
                operation_started = time.monotonic()
                try:
                    result, elapsed = client.query(statement, idempotency_key=key,
                                                   retry_on_429=False,
                                                   retry_read_disconnect=profile != "mutation")
                except (OSError, http.client.HTTPException) as error:
                    if profile != "mutation":
                        raise AssertionError(("read transport failure", index, profile,
                                              attempted)) from error
                    # A lost response is an uncertain commit. Ask the core
                    # ledger for the same decision using the exact same key.
                    reconciliations += 1
                    reconcile_deadline = time.monotonic() + 180
                    last_error = "no response"
                    while time.monotonic() < reconcile_deadline:
                        reconciliation_attempts += 1
                        try:
                            result, _ = client.query(statement, idempotency_key=key,
                                                     retry_on_429=False,
                                                     retry_read_disconnect=False)
                        except (OSError, http.client.HTTPException) as retry_error:
                            last_error = type(retry_error).__name__
                        except AssertionError as retry_error:
                            raise AssertionError(("mutation reconciliation rejected", index,
                                                  attempted, key, str(retry_error))) from retry_error
                        else:
                            if result is not None:
                                break
                            last_error = "admission refused"
                        time.sleep(.25)
                    else:
                        raise AssertionError(("mutation outcome unresolved", index,
                                              attempted, key, last_error,
                                              reconciliation_attempts)) from error
                    elapsed = (time.monotonic() - operation_started) * 1000
                if result is None:
                    time.sleep(.02)
                    continue
                rows = result.get("rows", [])
                if profile == "sql" and rows != [{"id": 0, "revision": 2}]:
                    raise AssertionError((profile, rows))
                if profile in ("vector", "hybrid") and not rows:
                    raise AssertionError((profile, "empty retrieval"))
                if profile == "graph" and len(rows) != 4:
                    raise AssertionError((profile, "wrong edge degree", len(rows)))
                if profile == "mutation" and not result.get("committed"):
                    raise AssertionError((profile, "uncommitted update", row_id))
                latencies.append(elapsed)
        finally:
            client.close()
        if not latencies:
            raise AssertionError((profile, "no successful operations", index))
        latencies.sort()
        return {"worker": index, "profile": profile, "attempted": attempted,
                "successful": len(latencies), "refusals": client.refusals,
                "disconnects": client.disconnects,
                "reconciliations": reconciliations,
                "reconciliation_attempts": reconciliation_attempts,
                "p50_ms": percentile(latencies, .50),
                "p99_ms": percentile(latencies, .99),
                "max_ms": latencies[-1], "mean_ms": statistics.mean(latencies)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=clients) as pool:
        futures = [pool.submit(worker, index) for index in range(clients)]
        results = [future.result() for future in futures]
    elapsed = time.monotonic() - started
    return {"clients": clients, "run_id": run_id, "elapsed_seconds": elapsed,
            "successful": sum(item["successful"] for item in results),
            "refusals": sum(item["refusals"] for item in results),
            "disconnects": sum(item["disconnects"] for item in results),
            "reconciliations": sum(item["reconciliations"] for item in results),
            "reconciliation_attempts": sum(item["reconciliation_attempts"] for item in results),
            "throughput_qps": sum(item["successful"] for item in results) / elapsed,
            "workers": results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--seconds", type=int, default=600)
    parser.add_argument("--clients", type=int, default=16)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.seconds < 1:
        parser.error("--seconds must be positive")
    report = load(args.root, args.port, args.seconds, args.clients)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
