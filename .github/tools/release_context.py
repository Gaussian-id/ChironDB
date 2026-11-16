#!/usr/bin/env python3
"""Resolve an immutable release source without moving an existing tag."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import tomllib


def git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True, stderr=subprocess.PIPE).strip()


def resolve(event: str, ref: str, sha: str, retry_tag: str, default_branch: str) -> dict:
    tag = ""
    if event == "push" and ref.startswith("refs/tags/"):
        tag = ref.removeprefix("refs/tags/")
    elif event == "workflow_dispatch":
        tag = retry_tag
        if tag and ref != f"refs/heads/{default_branch}":
            raise ValueError("release retries must use the default-branch workflow")
    else:
        raise ValueError("unsupported release event")

    if tag:
        if not re.fullmatch(r"v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", tag):
            raise ValueError("release_tag must be a version tag, not a branch or SHA")
        tagged_sha = git("rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}")
        if event == "push" and tagged_sha != sha:
            raise ValueError("release tag moved after the triggering push")
        sha = tagged_sha
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", sha, f"origin/{default_branch}"],
            check=True,
        )
        manifest = tomllib.loads(git("show", f"{sha}:chirondb-server/Cargo.toml"))
        version = manifest["package"]["version"]
        if tag[1:] != version and not tag[1:].startswith(f"{version}-rc."):
            raise ValueError("release tag does not match its source package version")
    elif not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("qualification requires an immutable commit SHA")

    return {
        "publish": "true" if tag else "false",
        "source_sha": sha,
        "source_short_sha": sha[:7],
        "release_tag": tag,
        "version": tag.removeprefix("v"),
    }


def main() -> None:
    context = resolve(
        os.environ["RELEASE_EVENT"],
        os.environ["RELEASE_REF"],
        os.environ["RELEASE_SHA"],
        os.environ.get("RETRY_RELEASE_TAG", ""),
        os.environ["DEFAULT_BRANCH"],
    )
    with Path(os.environ["GITHUB_OUTPUT"]).open("a") as output:
        for key, value in context.items():
            output.write(f"{key}={value}\n")
    print(json.dumps(context, sort_keys=True))


if __name__ == "__main__":
    main()
