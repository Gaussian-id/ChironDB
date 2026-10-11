#!/usr/bin/env python3
"""Rehearse protected reference-index backfill after real filesystem ENOSPC.

The caller must mount a disposable filesystem and place the safety marker at
its root. The script fills only that filesystem, then removes its own files.
"""

import argparse
import errno
import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

from protected_reference_migration_cli import migrate, run_child, sha256


SAFETY_MARKER = ".chirondb-enospc-test-device"
CUT = "relational_migration.after_segments"


def fill_to_enospc(path: Path) -> int:
    written = 0
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        for size in (1024 * 1024, 4096, 512, 1):
            block = b"\0" * size
            while True:
                try:
                    count = os.write(descriptor, block)
                except OSError as error:
                    if error.errno != errno.ENOSPC:
                        raise
                    break
                if count <= 0:
                    raise AssertionError("filler write made no progress")
                written += count
        try:
            os.fsync(descriptor)
        except OSError as error:
            if error.errno != errno.ENOSPC:
                raise
    finally:
        os.close(descriptor)
    return written


def run(test_binary: Path, release_cli: Path, fault_cli: Path, mount: Path) -> dict:
    mount = mount.resolve(strict=True)
    if mount == Path("/") or not mount.joinpath(SAFETY_MARKER).is_file():
        raise AssertionError("dedicated ENOSPC filesystem marker is missing")
    if mount.stat().st_dev == mount.parent.stat().st_dev:
        raise AssertionError("ENOSPC root is not a separate mounted filesystem")

    root = mount / "reference-migration-fixture"
    filler = mount / "reference-migration-fill.bin"
    if root.exists() or filler.exists():
        raise AssertionError("ENOSPC fixture paths must be absent before the run")
    root.mkdir(mode=0o700)
    try:
        run_child(test_binary, root, "setup")
        checkpoints = list((root / "data").rglob("relational/checkpoint.gdx"))
        if len(checkpoints) != 1:
            raise AssertionError(f"expected one relational checkpoint: {checkpoints}")
        checkpoint = checkpoints[0]
        before = checkpoint.read_bytes()
        if not before.startswith(b"CHIRENC1"):
            raise AssertionError("legacy checkpoint was not encrypted")

        with tempfile.TemporaryDirectory(prefix="chirondb-migration-enospc-control-") as control:
            marker = Path(control) / "paused"
            release = Path(control) / "release"
            environment = os.environ.copy()
            environment["CHIRONDB_FAILPOINT"] = f"pause:{CUT}"
            environment["CHIRONDB_FAILPOINT_MARKER"] = str(marker)
            environment["CHIRONDB_FAILPOINT_RELEASE"] = str(release)
            process = subprocess.Popen(
                [
                    str(fault_cli),
                    "security",
                    "migrate-relational-indexes",
                    "--data-dir",
                    str(root / "data"),
                    "--keyring",
                    str(root / "storage.json"),
                ],
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
                            f"migration exited before {CUT}: {process.returncode}; "
                            f"stdout={stdout}; stderr={stderr}"
                        )
                    if time.monotonic() >= deadline:
                        raise AssertionError(f"migration did not reach {CUT}")
                    time.sleep(0.01)
                marker_text = marker.read_text()
                if f"pid={process.pid}" not in marker_text or f"failpoint={CUT}" not in marker_text:
                    raise AssertionError(f"foreign pause marker: {marker_text}")
                filled_bytes = fill_to_enospc(filler)
                free_bytes = os.statvfs(mount).f_bavail * os.statvfs(mount).f_frsize
                release.touch()
                stdout, stderr = process.communicate(timeout=120)
                if process.returncode == 0 or not (
                    "No space left on device" in stderr or "os error 28" in stderr
                ):
                    raise AssertionError(
                        f"expected physical ENOSPC, got {process.returncode}; "
                        f"stdout={stdout}; stderr={stderr}"
                    )
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate(timeout=10)
                if filler.exists():
                    filler.unlink()

        if checkpoint.read_bytes() != before:
            raise AssertionError("failed publication changed the v3 manifest")
        run_child(test_binary, root, "verify-old")
        if migrate(release_cli, root) != 1:
            raise AssertionError("retry did not backfill the v3 table")
        run_child(test_binary, root, "verify")
        return {
            "fault": "real filesystem ENOSPC after private segments",
            "cli_exit_code": process.returncode,
            "filler_bytes": filled_bytes,
            "free_bytes_at_release": free_bytes,
            "recovered_manifest": "v3",
            "retry_migrated_tables": 1,
            "row_and_reference_guard": "verified before and after retry",
        }
    finally:
        if filler.exists():
            filler.unlink()
        shutil.rmtree(root)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture-test", required=True, type=Path)
    parser.add_argument("--release-cli", required=True, type=Path)
    parser.add_argument("--fault-cli", required=True, type=Path)
    parser.add_argument("--mount-root", required=True, type=Path)
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
        "result": run(test_binary, release_cli, fault_cli, arguments.mount_root),
    }
    arguments.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
