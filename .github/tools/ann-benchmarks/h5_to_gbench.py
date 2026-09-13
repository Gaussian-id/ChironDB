#!/usr/bin/env python3
"""Convert an ann-benchmarks HDF5 corpus to ChironDB's GBENCHv1 format."""

import argparse
import struct
import sys
from pathlib import Path

try:
    import h5py
    import numpy as np
except ImportError:
    print("missing dependencies: install h5py and numpy", file=sys.stderr)
    sys.exit(2)


MAGIC = b"GBENCHv1"
METRIC_BY_SUFFIX = {
    "euclidean": 0,
    "angular": 1,
    "ip": 2,
}


def detect_metric(name: str) -> int:
    for suffix, code in METRIC_BY_SUFFIX.items():
        if name.endswith(f"-{suffix}"):
            return code
    raise ValueError(
        f"cannot infer metric from filename {name!r}; "
        f"expected suffix in {list(METRIC_BY_SUFFIX)}"
    )


def write_rows(output, dataset, dtype: str, chunk_rows: int = 8192) -> None:
    for start in range(0, dataset.shape[0], chunk_rows):
        stop = min(start + chunk_rows, dataset.shape[0])
        chunk = np.asarray(dataset[start:stop], dtype=dtype)
        output.write(chunk.tobytes(order="C"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input_h5", type=Path)
    parser.add_argument("output_gbench", type=Path)
    parser.add_argument(
        "--metric",
        choices=("l2", "cosine", "dot"),
        help="override the metric inferred from the input filename",
    )
    args = parser.parse_args()
    metric = (
        {"l2": 0, "cosine": 1, "dot": 2}[args.metric]
        if args.metric
        else detect_metric(args.input_h5.stem)
    )

    with h5py.File(args.input_h5, "r") as source:
        train = source["train"]
        test = source["test"]
        neighbors = source["neighbors"]
        train_count, dimension = train.shape
        test_count, test_dimension = test.shape
        neighbor_rows, k = neighbors.shape
        if test_dimension != dimension:
            raise SystemExit(
                f"dimension mismatch: train={dimension} test={test_dimension}"
            )
        if neighbor_rows != test_count:
            raise SystemExit(
                f"test/neighbors row mismatch: test={test_count} neighbors={neighbor_rows}"
            )

        args.output_gbench.parent.mkdir(parents=True, exist_ok=True)
        with args.output_gbench.open("wb") as output:
            output.write(MAGIC)
            output.write(
                struct.pack("<QQII", train_count, test_count, dimension, k)
            )
            output.write(bytes([metric]))
            output.write(bytes(15))
            write_rows(output, train, "<f4")
            write_rows(output, test, "<f4")
            write_rows(output, neighbors, "<u4")

    print(
        f"wrote {args.output_gbench} "
        f"(train={train_count} test={test_count} dim={dimension} k={k} metric={metric})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
