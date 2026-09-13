#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description="Run chironbench and enforce loose regression thresholds.")
    parser.add_argument("--points", type=int, default=100)
    parser.add_argument("--dim", type=int, default=16)
    parser.add_argument("--batch-size", type=int, default=25)
    parser.add_argument("--searches", type=int, default=50)
    parser.add_argument("--k", type=int, default=5)
    parser.add_argument("--max-search-p99-ms", type=float, default=50.0)
    parser.add_argument("--min-write-points-per-second", type=float, default=10.0)
    parser.add_argument("--min-search-queries-per-second", type=float, default=10.0)
    args = parser.parse_args()

    command = [
        "cargo",
        "run",
        "--quiet",
        "--bin",
        "chironbench",
        "--",
        "--points",
        str(args.points),
        "--dim",
        str(args.dim),
        "--batch-size",
        str(args.batch_size),
        "--searches",
        str(args.searches),
        "--k",
        str(args.k),
    ]
    completed = subprocess.run(command, check=True, text=True, capture_output=True)
    report = json.loads(completed.stdout)

    failures = []
    search_p99 = float(report["search_latency_ms"]["p99"])
    write_rate = float(report["write_points_per_second"])
    search_rate = float(report["search_queries_per_second"])
    if search_p99 > args.max_search_p99_ms:
        failures.append(
            f"search p99 {search_p99:.3f} ms exceeds {args.max_search_p99_ms:.3f} ms"
        )
    if write_rate < args.min_write_points_per_second:
        failures.append(
            f"write throughput {write_rate:.3f} points/s below {args.min_write_points_per_second:.3f}"
        )
    if search_rate < args.min_search_queries_per_second:
        failures.append(
            f"search throughput {search_rate:.3f} queries/s below {args.min_search_queries_per_second:.3f}"
        )

    print(json.dumps({"status": "failed" if failures else "ok", "report": report, "failures": failures}, indent=2))
    if failures:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
