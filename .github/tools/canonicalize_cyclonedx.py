#!/usr/bin/env python3
"""Make cargo-cyclonedx output stable without weakening its schema."""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
import uuid


def canonicalize(path: Path, epoch: int, tested_sha: str, target: str) -> None:
    document = json.loads(path.read_text())
    timestamp = dt.datetime.fromtimestamp(epoch, tz=dt.timezone.utc).isoformat().replace("+00:00", "Z")
    component = document.get("metadata", {}).get("component", {})
    identity = f"{tested_sha}:{target}:{component.get('name', path.name)}:{component.get('version', '')}"
    document["serialNumber"] = f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, identity)}"
    document.setdefault("metadata", {})["timestamp"] = timestamp
    properties = document["metadata"].setdefault("properties", [])
    properties = [
        entry
        for entry in properties
        if entry.get("name") not in {"chirondb:git-sha", "chirondb:target"}
    ]
    properties.extend(
        [
            {"name": "chirondb:git-sha", "value": tested_sha},
            {"name": "chirondb:target", "value": target},
        ]
    )
    document["metadata"]["properties"] = sorted(
        properties, key=lambda entry: (entry.get("name", ""), entry.get("value", ""))
    )
    path.write_text(json.dumps(document, indent=2, sort_keys=True, separators=(",", ": ")) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--epoch", type=int, required=True)
    parser.add_argument("--tested-sha", required=True)
    parser.add_argument("--target", required=True)
    args = parser.parse_args()
    paths = sorted(args.root.rglob("*.cdx.json"))
    if not paths:
        raise SystemExit(f"no CycloneDX JSON files found under {args.root}")
    for path in paths:
        canonicalize(path, args.epoch, args.tested_sha, args.target)
    print(f"canonicalized {len(paths)} CycloneDX files")


if __name__ == "__main__":
    main()
