#!/usr/bin/env bash
set -euo pipefail

directory=${1:?usage: check_binary_versions.sh <release-directory>}
extension=""
if [ ! -x "$directory/chirondb" ] && [ -f "$directory/chirondb.exe" ]; then
  extension=".exe"
fi

expected=$("$directory/chirondb$extension" --version | awk '{print $NF}')
bins="chirondb chironql chironmcp chironctl chironbench chirondrill chironrecall chirongrpcctl chironwirectl gaussdb gaussctl gaussbench gaussdrill gaussrecall gaussgrpcctl gausswirectl"

for bin in $bins; do
  actual=$("$directory/$bin$extension" --version | awk '{print $NF}')
  if [ "$actual" != "$expected" ]; then
    echo "$bin reports $actual, expected $expected" >&2
    exit 1
  fi
done

echo "all release binaries report $expected"
