#!/usr/bin/env bash
set -euo pipefail

: "${REPOSITORY_URL:?set REPOSITORY_URL, for example https://github.com/owner/repository}"
registration_token=${RUNNER_TOKEN:-}
if [ -z "$registration_token" ]; then
  read -r -s -p "One-time GitHub runner token: " registration_token
  printf '\n'
fi
test -n "$registration_token"
export RUNNER_TOKEN=$registration_token
docker compose up --build --detach
unset registration_token RUNNER_TOKEN

deadline=$((SECONDS + 300))
until docker compose exec -T chirondb-linux-runner test -f /runner-state/.runner; do
  if [ "$SECONDS" -ge "$deadline" ]; then
    docker compose logs chirondb-linux-runner
    echo "runner registration did not finish within 300 seconds" >&2
    exit 1
  fi
  sleep 2
done

# Recreate the registered runner without the one-time token in its environment.
RUNNER_TOKEN= docker compose up --detach --force-recreate
