#!/usr/bin/env python3
"""Rehearse protected v3 RECORD_REF backfill through the real chironctl binary.

Build the core unit-test binary and both normal and fault-injection chironctl
binaries from one source checkout, then pass their paths to this runner.
"""

import argparse
import hashlib
import json
import os
import subprocess
import tempfile
import time
from pathlib import Path


CHILD = "relational::tests::offline_reference_index_migration_installed_child"
CUTS = (
    "relational_migration.after_segments",
    "relational_migration.after_manifest",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_child(test_binary: Path, root: Path, role: str) -> None:
    environment = os.environ.copy()
    environment["CHIRONDB_REFERENCE_INSTALLED_ROLE"] = role
    environment["CHIRONDB_REFERENCE_INSTALLED_ROOT"] = str(root)
    for name in (
        "CHIRONDB_FAILPOINT",
        "CHIRONDB_FAILPOINT_MARKER",
        "CHIRONDB_FAILPOINT_RELEASE",
    ):
        environment.pop(name, None)
    result = subprocess.run(
        [str(test_binary), "--exact", CHILD, "--nocapture"],
        env=environment,
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )
    if (
        result.returncode != 0
        or "running 1 test" not in result.stdout
        or "test result: ok. 1 passed" not in result.stdout
    ):
        raise AssertionError(
            f"fixture {role} did not execute successfully: "
            f"stdout={result.stdout}; stderr={result.stderr}"
        )


def migrate(cli: Path, root: Path) -> int:
    environment = os.environ.copy()
    for name in (
        "CHIRONDB_FAILPOINT",
        "CHIRONDB_FAILPOINT_MARKER",
        "CHIRONDB_FAILPOINT_RELEASE",
    ):
        environment.pop(name, None)
    result = subprocess.run(
        [
            str(cli),
            "security",
            "migrate-relational-indexes",
            "--data-dir",
            str(root / "data"),
            "--keyring",
            str(root / "storage.json"),
        ],
        env=environment,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(f"chironctl migration failed: {result.stderr}")
    value = json.loads(result.stdout)
    if set(value) != {"migrated_tables"} or type(value["migrated_tables"]) is not int:
        raise AssertionError(f"unexpected migration receipt: {value}")
    return value["migrated_tables"]


def fixture_root():
    return tempfile.TemporaryDirectory(prefix="chirondb-reference-migration-")


def normal_rehearsal(test_binary: Path, cli: Path) -> dict:
    with fixture_root() as directory:
        root = Path(directory).resolve()
        os.chmod(root, 0o700)
        run_child(test_binary, root, "setup")
        first = migrate(cli, root)
        second = migrate(cli, root)
        if (first, second) != (1, 0):
            raise AssertionError(f"non-idempotent migration: {(first, second)}")
        run_child(test_binary, root, "verify")
        return {"first_migrated_tables": first, "retry_migrated_tables": second}


def fault_rehearsal(test_binary: Path, cli: Path, cut: str) -> dict:
    with fixture_root() as directory:
        root = Path(directory).resolve()
        os.chmod(root, 0o700)
        run_child(test_binary, root, "setup")
        checkpoints = list((root / "data").rglob("relational/checkpoint.gdx"))
        if len(checkpoints) != 1:
            raise AssertionError(f"expected one relational checkpoint, got {checkpoints}")
        checkpoint = checkpoints[0]
        before = checkpoint.read_bytes()
        if not before.startswith(b"CHIRENC1"):
            raise AssertionError("legacy checkpoint was not encrypted")
        marker = root / "paused"
        environment = os.environ.copy()
        environment["CHIRONDB_FAILPOINT"] = f"pause:{cut}"
        environment["CHIRONDB_FAILPOINT_MARKER"] = str(marker)
        environment.pop("CHIRONDB_FAILPOINT_RELEASE", None)
        command = [
            str(cli),
            "security",
            "migrate-relational-indexes",
            "--data-dir",
            str(root / "data"),
            "--keyring",
            str(root / "storage.json"),
        ]
        process = subprocess.Popen(
            command,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            deadline = time.monotonic() + 30
            while not marker.exists():
                if process.poll() is not None:
                    stdout, stderr = process.communicate()
                    raise AssertionError(
                        f"{cut} exited before pause: {process.returncode}; "
                        f"stdout={stdout}; stderr={stderr}"
                    )
                if time.monotonic() >= deadline:
                    raise AssertionError(f"{cut} did not reach pause within 30 seconds")
                time.sleep(0.01)
            marker_text = marker.read_text()
            if f"pid={process.pid}" not in marker_text or f"failpoint={cut}" not in marker_text:
                raise AssertionError(f"foreign pause marker: {marker_text}")
            process.kill()
            process.communicate(timeout=10)
            if process.returncode != -9:
                raise AssertionError(f"{cut} exited with {process.returncode}, not SIGKILL")
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=10)

        published = cut.endswith("after_manifest")
        if (checkpoint.read_bytes() != before) != published:
            raise AssertionError(f"{cut} selected the wrong manifest generation")
        run_child(test_binary, root, "verify" if published else "verify-old")
        retried = migrate(cli, root)
        if retried != (0 if published else 1):
            raise AssertionError(f"{cut} retried {retried} tables")
        run_child(test_binary, root, "verify")
        return {
            "cut": cut,
            "signal": 9,
            "recovered_manifest": "v4" if published else "v3",
            "retry_migrated_tables": retried,
            "row_and_reference_guard": "verified before and after retry",
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    if os.name != "posix":
        parser.error("the SIGKILL rehearsal requires a POSIX host")
    parser.add_argument("--fixture-test", required=True, type=Path)
    parser.add_argument("--release-cli", required=True, type=Path)
    parser.add_argument("--fault-cli", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    test_binary = arguments.fixture_test.resolve(strict=True)
    release_cli = arguments.release_cli.resolve(strict=True)
    fault_cli = arguments.fault_cli.resolve(strict=True)
    result = {
        "fixture": "installed protected v3 with live SQL RECORD_REF and point",
        "fixture_test_sha256": sha256(test_binary),
        "release_cli_sha256": sha256(release_cli),
        "fault_cli_sha256": sha256(fault_cli),
        "normal": normal_rehearsal(test_binary, release_cli),
        "faults": [fault_rehearsal(test_binary, fault_cli, cut) for cut in CUTS],
    }
    arguments.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
