#!/usr/bin/env python3
"""Fail the native text hybrid quality gate against the identical main dataset."""
import argparse
import json
import math
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("native", type=Path)
    args = parser.parse_args()
    baseline = json.loads(args.baseline.read_text())
    native = json.loads(args.native.read_text())
    for field in ["dataset_sha256", "n_corpus", "n_queries"]:
        if baseline[field] != native[field]:
            parser.error(f"{field} differs; this is not an identical-dataset comparison")
    old = {mode["mode"]: mode["mean_ndcg_at_10"] for mode in baseline["modes"]}
    new = {mode["mode"]: mode["ndcg_at_10"] for mode in native["modes"]}
    if not all(math.isfinite(value) for value in [*old.values(), *new.values()]):
        parser.error("non-finite quality metric")
    dense_matches = abs(old["dense_only"] - new["dense"]) <= 1e-12
    delta = new["hybrid_native"] - old["hybrid_rrf"]
    passed = dense_matches and delta >= 0
    print(json.dumps({
        "dataset_sha256": native["dataset_sha256"],
        "queries": native["n_queries"],
        "dense_matches": dense_matches,
        "main_hybrid_ndcg_at_10": old["hybrid_rrf"],
        "native_hybrid_ndcg_at_10": new["hybrid_native"],
        "delta": delta,
        "passed": passed,
    }, indent=2))
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
