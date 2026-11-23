#!/usr/bin/env python3
"""Record local SQL commit overhead before/after source revision tracking.

This is a paired operational smoke, not a throughput or product-SLO benchmark.
AUTO stays disabled to separate commit-path bookkeeping from model training.
"""
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import subprocess
import time

from ml_auto_refresh_e2e import Daemon


def measure(daemon, count, start_value):
    timings = []
    for value in range(start_value + 1, start_value + count + 1):
        started = time.perf_counter_ns()
        daemon.sql(f"UPDATE commit_probe SET value = {value} WHERE id = 1")
        timings.append((time.perf_counter_ns() - started) / 1e6)
    ordered = sorted(timings)
    return {"samples_ms": timings, "count": count,
            "median_ms": statistics.median(timings), "mean_ms": statistics.mean(timings),
            "p95_ms": ordered[int(.95 * (count - 1))],
            "rss_kib": int(subprocess.check_output(["ps", "-o", "rss=", "-p", str(daemon.process.pid)], text=True).strip())}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--samples", type=int, default=200)
    args = parser.parse_args()
    if args.samples < 20:
        parser.error("at least 20 samples required")
    args.output.mkdir(parents=True, exist_ok=False)
    daemons = {}
    values = {}
    result = {"scope": "local operational smoke; AUTO disabled; no SLO claim", "runs": {}, "paired_order": [["baseline", "candidate"], ["candidate", "baseline"]]}
    try:
        for name, binary in (("baseline", args.baseline), ("candidate", args.candidate)):
            directory = args.output / name
            directory.mkdir()
            daemon = Daemon(binary.resolve(strict=True), directory)
            daemons[name] = daemon
            daemon.start()
            daemon.sql("CREATE TABLE commit_probe (id INTEGER PRIMARY KEY, value BIGINT)")
            daemon.sql("INSERT INTO commit_probe VALUES (1,0)")
            measure(daemon, 30, 0)
            values[name] = 30
            result["runs"][name] = {"binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "rounds": []}
        for order in result["paired_order"]:
            for name in order:
                result["runs"][name]["rounds"].append(measure(daemons[name], args.samples, values[name]))
                values[name] += args.samples
        for name, daemon in daemons.items():
            rows = daemon.sql("SELECT value FROM commit_probe WHERE id = 1")["results"][0]["rows"]
            result["runs"][name]["readback"] = rows
            assert rows == [[{"type": "integer", "value": 30 + 2 * args.samples}]], rows
        result["status"] = "passed"
    finally:
        for daemon in daemons.values():
            daemon.stop()
            daemon.receipts.close()
        (args.output / "overhead.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
