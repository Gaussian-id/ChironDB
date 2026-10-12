#!/usr/bin/env bash
set -euo pipefail

runner_root=/opt/actions-runner
state_root=/runner-state
mkdir -p "$state_root" "$runner_root/_work"
for name in .runner .credentials .credentials_rsaparams; do
  if [ ! -L "$runner_root/$name" ]; then
    test ! -e "$runner_root/$name" || mv "$runner_root/$name" "$state_root/$name"
    ln -s "$state_root/$name" "$runner_root/$name"
  fi
done

cd "$runner_root"
if [ ! -f .runner ]; then
  : "${REPOSITORY_URL:?set REPOSITORY_URL}"
  : "${RUNNER_TOKEN:?set the one-time repository runner token}"
  ./config.sh --unattended --replace \
    --url "$REPOSITORY_URL" \
    --token "$RUNNER_TOKEN" \
    --name "chirondb-linux-x64" \
    --labels "chirondb-ci" \
    --work "$runner_root/_work"
fi

test -S /var/run/docker.sock
docker_gid=$(stat -c '%g' /var/run/docker.sock)
docker_group=$(getent group "$docker_gid" 2>/dev/null | cut -d: -f1 || true)
if [ -z "$docker_group" ]; then
  docker_group=chirondb-docker
  sudo groupadd --gid "$docker_gid" "$docker_group"
fi
sudo usermod --append --groups "$docker_group" runner
exec sg "$docker_group" -c 'exec ./run.sh'
