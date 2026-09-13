#!/usr/bin/env bash
set -euo pipefail

image=${1:?usage: smoke_container.sh <image>}
container="chirondb-smoke-$$"
contender="${container}-contender"
volume="chirondb-smoke-data-$$"
expected_version=$(docker run --rm "$image" --version | awk '{print $NF}')
image_version=$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.version" }}' "$image")
image_source=$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.source" }}' "$image")
image_revision=$(docker image inspect --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$image")
test "$image_version" = "$expected_version"
test "$image_source" = "https://github.com/Gaussian-id/ChironDB"
test -n "$image_revision"
test "$image_revision" != unknown

cleanup() {
  docker rm -f "$container" "$contender" >/dev/null 2>&1 || true
  docker volume rm "$volume" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker volume create "$volume" >/dev/null
docker run -d --name "$container" \
  -e CHIRONDB_API_KEY=release-smoke-key \
  -e CHIRONDB_ALLOW_INSECURE_NON_LOOPBACK=true \
  -v "$volume:/var/lib/chirondb" \
  "$image" >/dev/null

for _ in $(seq 1 30); do
  if [ "$(docker inspect --format '{{.State.Health.Status}}' "$container")" = healthy ]; then
    break
  fi
  sleep 2
done

test "$(docker inspect --format '{{.State.Health.Status}}' "$container")" = healthy
test "$(docker inspect --format '{{.Config.User}}' "$container")" = chirondb
docker exec "$container" chironctl health | grep -F "$expected_version"
for bin in chirondb chironql chironmcp chironctl chironbench chirondrill chironrecall chirongrpcctl chironwirectl gaussdb gaussctl gaussbench gaussdrill gaussrecall gaussgrpcctl gausswirectl; do
  test "$(docker exec "$container" "$bin" --version | awk '{print $NF}')" = "$expected_version"
done
if docker exec -e CHIRONDB_API_KEY= -e GAUSSDB_API_KEY= "$container" chironctl list-collections >/dev/null 2>&1; then
  echo "unauthenticated API request unexpectedly succeeded" >&2
  exit 1
fi
docker exec "$container" chironctl list-collections >/dev/null
docker exec "$container" chironctl create-collection release_smoke 3 --metric cosine
docker exec "$container" chironctl insert release_smoke alpha 1,0,0
docker exec "$container" chironctl search release_smoke 1,0,0 -k 1 | grep -F alpha
docker exec "$container" chironql --exec 'COUNT release_smoke;' | grep -F '"count": 1'
docker exec "$container" chirongrpcctl health | grep -F "$expected_version"
docker exec "$container" chironwirectl health | grep -F "$expected_version"

# The lock must live on the shared volume, not in a container's writable layer.
docker run -d --name "$contender" \
  -e CHIRONDB_ALLOW_INSECURE_NON_LOOPBACK=true \
  -v "$volume:/var/lib/chirondb" "$image" >/dev/null
for _ in $(seq 1 20); do
  if [ "$(docker inspect --format '{{.State.Running}}' "$contender")" = false ]; then
    break
  fi
  sleep 0.5
done
locked_output=$(docker logs "$contender" 2>&1)
if [ "$(docker inspect --format '{{.State.Running}}' "$contender")" = true ]; then
  echo "a second server unexpectedly opened the same volume" >&2
  exit 1
fi
docker rm "$contender" >/dev/null
grep -F 'data directory is already locked' <<<"$locked_output"

docker restart "$container" >/dev/null
for _ in $(seq 1 30); do
  if [ "$(docker inspect --format '{{.State.Health.Status}}' "$container")" = healthy ]; then
    break
  fi
  sleep 2
done

test "$(docker inspect --format '{{.State.Health.Status}}' "$container")" = healthy
docker exec "$container" chironctl search release_smoke 1,0,0 -k 1 | grep -F alpha

# Old volume roots must fail visibly instead of looking like an empty database.
docker stop "$container" >/dev/null
for marker in catalog.json CURRENT; do
  docker run --rm --entrypoint sh -v "$volume:/var/lib/chirondb" "$image" \
    -c 'touch "/var/lib/chirondb/$1"' sh "$marker"
  if legacy_output=$(docker run --rm -v "$volume:/var/lib/chirondb" "$image" 2>&1); then
    echo "legacy volume layout unexpectedly accepted" >&2
    exit 1
  fi
  grep -F 'found a database at the volume root' <<<"$legacy_output"
  docker run --rm --entrypoint sh -v "$volume:/var/lib/chirondb" "$image" \
    -c 'rm "/var/lib/chirondb/$1"' sh "$marker"
done
