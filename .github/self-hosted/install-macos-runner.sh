#!/usr/bin/env bash
set -euo pipefail

runner_version=2.337.0
runner_sha256=5a2cd92908a93d7276a194e1de6008099f3e7946f3f8e14aa7a1a7b4a31fdec2
repository_url=${REPOSITORY_URL:?set REPOSITORY_URL, for example https://github.com/owner/repository}
registration_token=${RUNNER_TOKEN:-}
if [ -z "$registration_token" ]; then
  read -r -s -p "One-time GitHub runner token: " registration_token
  printf '\n'
fi
test -n "$registration_token"
unset RUNNER_TOKEN
runner_root=${RUNNER_ROOT:-"$HOME/actions-runner-chirondb"}
archive="$runner_root/actions-runner-osx-arm64-$runner_version.tar.gz"

test "$(uname -m)" = arm64
test "$(rustc --version)" = "rustc 1.92.0 (ded5c06cf 2025-12-08)"
test "$(cargo --version | cut -d' ' -f1-2)" = "cargo 1.92.0"
protoc --version
arch -x86_64 /usr/bin/true
docker version >/dev/null
rustup target add \
  aarch64-apple-darwin \
  x86_64-apple-darwin \
  aarch64-unknown-linux-gnu
mkdir -p "$runner_root"
cd "$runner_root"
if [ ! -x ./config.sh ]; then
  curl --fail --location --output "$archive" \
    "https://github.com/actions/runner/releases/download/v$runner_version/actions-runner-osx-arm64-$runner_version.tar.gz"
  echo "$runner_sha256  $archive" | shasum -a 256 --check
  tar xzf "$archive"
  rm "$archive"
fi
installed_runner_version=$(
  ./bin/Runner.Listener --version 2>/dev/null \
    | grep -E '^[0-9]+\.[0-9]+\.[0-9]+$' \
    | tail -1
)
test "$installed_runner_version" = "$runner_version"

./config.sh --unattended --replace \
  --url "$repository_url" \
  --token "$registration_token" \
  --name "chirondb-macos-arm64" \
  --labels "chirondb-ci" \
  --work "$runner_root/_work"
registration_token=
sudo ./svc.sh install "$USER"
sudo ./svc.sh start
