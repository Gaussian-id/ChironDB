#!/usr/bin/env python3
"""Run chironrecall and enforce recall@k gates.

Two passes are run:
  1. Flat-index pass (below HNSW threshold, default 500 points).
  2. HNSW pass (above threshold, default 12_000 points) — only when --hnsw flag is
     set; add --hnsw to CI to validate HNSW recall without slowing fast gates.
"""
import argparse
import json
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description="Run chironrecall and enforce recall@k.")
    parser.add_argument("--points", type=int, default=500)
    parser.add_argument("--dim", type=int, default=128)
    parser.add_argument("--queries", type=int, default=50)
    parser.add_argument("--k", type=int, default=10)
    parser.add_argument("--min-recall", type=float, default=0.95)
    parser.add_argument(
        "--distribution",
        choices=["uniform", "clustered"],
        default="clustered",
        help="Vector distribution (clustered is more realistic)",
    )
    parser.add_argument(
        "--hnsw",
        action="store_true",
        help="Also run an HNSW-scale pass (12,000 points) to validate HNSW recall",
    )
    parser.add_argument("--hnsw-scale", type=int, default=12_000)
    args = parser.parse_args()

    command = [
        "cargo",
        "run",
        "--quiet",
        "--bin",
        "chironrecall",
        "--",
        "--points",
        str(args.points),
        "--dim",
        str(args.dim),
        "--queries",
        str(args.queries),
        "--k",
        str(args.k),
        "--min-recall",
        str(args.min_recall),
        "--distribution",
        args.distribution,
    ]
    if args.hnsw:
        command += ["--hnsw", "--hnsw-scale", str(args.hnsw_scale)]

    completed = subprocess.run(command, check=True, text=True, capture_output=True)
    report = json.loads(completed.stdout)
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
