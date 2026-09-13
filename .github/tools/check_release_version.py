#!/usr/bin/env python3
"""Fail when ChironDB release/version surfaces drift apart."""

from __future__ import annotations

import os
from pathlib import Path
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[2]
MANIFESTS = (
    "chirondb-types/Cargo.toml",
    "chirondb-core/Cargo.toml",
    "chirondb-server/Cargo.toml",
    "chirondb-ui-server/Cargo.toml",
    "clients/rust/Cargo.toml",
    "clients/rust-compat/Cargo.toml",
    "clients/python/pyproject.toml",
)


def load_toml(path: str) -> dict:
    with (ROOT / path).open("rb") as handle:
        return tomllib.load(handle)


def fail(message: str) -> None:
    print(f"release version check failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    expected = load_toml("chirondb-server/Cargo.toml")["package"]["version"]
    for path in MANIFESTS:
        actual = load_toml(path)["project" if path.endswith("pyproject.toml") else "package"][
            "version"
        ]
        if actual != expected:
            fail(f"{path} is {actual}, expected {expected}")

    toolchain = load_toml("rust-toolchain.toml")
    if toolchain["toolchain"]["channel"] != "1.92.0":
        fail("rust-toolchain.toml must pin 1.92.0")

    dockerfile = (ROOT / "Dockerfile").read_text()
    if f"ARG CHIRONDB_VERSION={expected}" not in dockerfile:
        fail("Dockerfile default version does not match the workspace")

    compose = (ROOT / "docker-compose.yml").read_text()
    if f"ghcr.io/gaussian-id/chirondb:{expected}" not in compose:
        fail("docker-compose.yml does not pin the workspace version")

    tag = os.environ.get("GITHUB_REF_NAME") if os.environ.get("GITHUB_REF_TYPE") == "tag" else None
    tag_version = tag.removeprefix("v") if tag else None
    if tag_version and tag_version != expected and not tag_version.startswith(f"{expected}-rc."):
        fail(f"tag {tag} does not match package version {expected}")

    print(f"ChironDB release surfaces agree on {expected}")


if __name__ == "__main__":
    main()
