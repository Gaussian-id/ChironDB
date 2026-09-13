#!/usr/bin/env python3
import argparse
import json
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(
        description="Run chironbench and enforce an analytical billion-scale footprint budget."
    )
    parser.add_argument("--points", type=int, default=1000)
    parser.add_argument("--dim", type=int, default=64)
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--searches", type=int, default=25)
    parser.add_argument("--k", type=int, default=10)
    parser.add_argument("--target-points", type=int, default=1_000_000_000)
    parser.add_argument("--max-projected-gib", type=float, default=4096.0)
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
        "--scale-projection-points",
        str(args.target_points),
    ]
    completed = subprocess.run(command, check=True, text=True, capture_output=True)
    report = json.loads(completed.stdout)

    projection = report["scale_projection"]
    projected_gib = float(projection["projected_compacted_gib"])
    failures = []
    if projected_gib > args.max_projected_gib:
        failures.append(
            f"projected compacted footprint {projected_gib:.3f} GiB exceeds "
            f"{args.max_projected_gib:.3f} GiB for {args.target_points} points"
        )

    print(
        json.dumps(
            {
                "status": "failed" if failures else "ok",
                "report": report,
                "failures": failures,
            },
            indent=2,
        )
    )
    if failures:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
