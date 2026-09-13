#!/usr/bin/env python3
"""Create a byte-reproducible gzip-compressed tar release archive."""

from __future__ import annotations

import argparse
import gzip
import os
from pathlib import Path
import tarfile


def add_tree(archive: tarfile.TarFile, root: Path, epoch: int) -> None:
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        relative = path.relative_to(root)
        information = archive.gettarinfo(str(path), arcname=relative.as_posix())
        information.uid = 0
        information.gid = 0
        information.uname = "root"
        information.gname = "root"
        information.mtime = epoch
        if information.isdir():
            information.mode = 0o755
            archive.addfile(information)
        elif information.isfile():
            information.mode = 0o755 if os.access(path, os.X_OK) else 0o644
            with path.open("rb") as source:
                archive.addfile(information, source)
        else:
            raise RuntimeError(f"release staging contains unsupported entry: {path}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("staging", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--epoch", type=int, required=True)
    args = parser.parse_args()
    if not args.staging.is_dir():
        parser.error(f"staging directory does not exist: {args.staging}")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", compresslevel=9, fileobj=raw, mtime=args.epoch) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as archive:
                add_tree(archive, args.staging, args.epoch)


if __name__ == "__main__":
    main()
