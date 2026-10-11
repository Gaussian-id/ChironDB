#!/usr/bin/env bash
set -euo pipefail

expected_sha=${GITHUB_SHA:?GITHUB_SHA is required}
actual_sha=$(git rev-parse HEAD)
test "$actual_sha" = "$expected_sha" || {
  echo "checked out $actual_sha; expected $expected_sha" >&2
  exit 1
}

test "$(rustc --version)" = "rustc 1.92.0 (ded5c06cf 2025-12-08)"
test "$(cargo --version | cut -d' ' -f1-2)" = "cargo 1.92.0"
protoc --version
test -z "$(git status --porcelain)" || {
  git status --short
  echo "runner checkout is not clean" >&2
  exit 1
}
df -Pk .

if [ -n "${CHIRONDB_CI_TARGET:-}" ]; then
  rustup target list --installed | grep -Fx "$CHIRONDB_CI_TARGET"
fi

case ${RUNNER_OS:?RUNNER_OS is required} in
  macOS)
    test "$(uname -m)" = arm64
    arch -x86_64 /usr/bin/true
    rustup target list --installed | grep -Fx aarch64-apple-darwin
    rustup target list --installed | grep -Fx x86_64-apple-darwin
    ;;
  Linux)
    test "$(uname -m)" = x86_64
    docker version >/dev/null
    test -e /dev/loop-control
    scratch=$(mktemp -d)
    image="$scratch/preflight.img"
    mountpoint="$scratch/mnt"
    cleanup() {
      mountpoint -q "$mountpoint" && sudo umount "$mountpoint"
      rm -rf "$scratch"
    }
    trap cleanup EXIT
    truncate -s 8M "$image"
    mkfs.ext4 -q -F -m 0 "$image"
    mkdir "$mountpoint"
    sudo mount -o loop "$image" "$mountpoint"
    sudo chown "$(id -u):$(id -g)" "$mountpoint"
    touch "$mountpoint/.chirondb-runner-preflight"
    test -f "$mountpoint/.chirondb-runner-preflight"
    sudo umount "$mountpoint"
    rustup target list --installed | grep -Fx x86_64-unknown-linux-gnu
    ;;
  *)
    echo "unsupported runner OS: $RUNNER_OS" >&2
    exit 1
    ;;
esac
