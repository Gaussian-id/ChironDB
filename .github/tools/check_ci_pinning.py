#!/usr/bin/env python3
"""Fail on unpinned CI actions/images unless a time-bounded exception exists."""

from __future__ import annotations

import datetime as dt
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
EXCEPTIONS = json.loads((ROOT / "security/ci-pinning-exceptions.json").read_text())
expiry = dt.date.fromisoformat(EXCEPTIONS["expires"])
has_exceptions = bool(EXCEPTIONS["actions"] or EXCEPTIONS["containers"])
if has_exceptions and dt.date.today() > expiry:
    raise SystemExit(f"CI pinning exceptions expired on {expiry}")

actions: set[str] = set()
unpinned_cargo_tools: set[str] = set()
for workflow in (ROOT / ".github/workflows").glob("*.yml"):
    for line in workflow.read_text().splitlines():
        if "cargo install " in line and "--version " not in line:
            unpinned_cargo_tools.add(line.strip())
        match = re.search(r"\buses:\s*([^\s#]+)", line)
        if not match:
            continue
        action = match.group(1)
        ref = action.rsplit("@", 1)[-1]
        if not re.fullmatch(r"[0-9a-fA-F]{40}", ref):
            actions.add(action)

containers: set[str] = set()
for dockerfile in ROOT.glob("Dockerfile*"):
    for line in dockerfile.read_text().splitlines():
        syntax = re.match(r"\s*#\s*syntax=([^\s]+)", line, re.IGNORECASE)
        if syntax and "@sha256:" not in syntax.group(1):
            containers.add(syntax.group(1))
        match = re.match(r"\s*FROM\s+([^\s]+)", line, re.IGNORECASE)
        if match and "@sha256:" not in match.group(1):
            containers.add(match.group(1))

unknown_actions = sorted(actions - set(EXCEPTIONS["actions"]))
unknown_containers = sorted(containers - set(EXCEPTIONS["containers"]))
if unknown_actions or unknown_containers or unpinned_cargo_tools:
    print("unpinned dependencies without an approved exception:", file=sys.stderr)
    for item in unknown_actions + unknown_containers + sorted(unpinned_cargo_tools):
        print(f"  {item}", file=sys.stderr)
    raise SystemExit(1)

if has_exceptions:
    print(f"pinning policy passed; temporary exceptions expire {expiry}")
else:
    print("pinning policy passed; no exceptions")
