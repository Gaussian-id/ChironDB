#!/usr/bin/env bash
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "wal power-cut harness requires Linux" >&2
  exit 2
fi
if [[ "${EUID}" -ne 0 ]]; then
  echo "wal power-cut harness must run as root" >&2
  exit 2
fi
if [[ "${CHIRONDB_POWERCUT_ACK:-}" != "I_UNDERSTAND_THIS_USES_DEVICE_MAPPER" ]]; then
  echo "set CHIRONDB_POWERCUT_ACK=I_UNDERSTAND_THIS_USES_DEVICE_MAPPER" >&2
  exit 2
fi
for command in dmsetup losetup mkfs.ext4 mount umount fsck.ext4 blockdev jq cargo truncate; do
  command -v "${command}" >/dev/null || {
    echo "required command is missing: ${command}" >&2
    exit 2
  }
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
evidence_path="${CHIRONDB_POWERCUT_EVIDENCE:-${repo_root}/wal-powercut-evidence.json}"
scratch="$(mktemp -d /tmp/chirondb-wal-powercut.XXXXXX)"
image="${scratch}/device.img"
mountpoint="${scratch}/mnt"
mapper_name="chirondb-wal-powercut-${$}"
loop_device=""
mounted=0

cleanup() {
  set +e
  if [[ "${mounted}" -eq 1 ]]; then
    umount -l "${mountpoint}"
  fi
  dmsetup remove --retry "${mapper_name}" >/dev/null 2>&1
  if [[ -n "${loop_device}" ]]; then
    losetup -d "${loop_device}" >/dev/null 2>&1
  fi
  rm -rf -- "${scratch}"
}
trap cleanup EXIT INT TERM

truncate -s "${CHIRONDB_POWERCUT_IMAGE_SIZE:-8G}" "${image}"
loop_device="$(losetup --find --show "${image}")"
sectors="$(blockdev --getsz "${loop_device}")"
dmsetup create "${mapper_name}" --table "0 ${sectors} flakey ${loop_device} 0 3600 1 1 drop_writes"
mapper="/dev/mapper/${mapper_name}"
mkfs.ext4 -q -F "${mapper}"
mkdir -p "${mountpoint}"
mount -o noatime,barrier=1 "${mapper}" "${mountpoint}"
mounted=1

cd "${repo_root}"
export TMPDIR="${mountpoint}/tmp"
mkdir -p "${TMPDIR}"
cargo test -p chirondb --features fault-injection --test process_kill -- --nocapture
cargo test -p chirondb-core --features fault-injection --test crash_consistency -- --nocapture
cargo build --release --locked -p chirondb --bin chirondrill

drill_data="${mountpoint}/durable-db"
drill_snapshot="${mountpoint}/durable-snapshot"
before_json="${scratch}/before.json"
after_json="${scratch}/after.json"
"${repo_root}/target/release/chirondrill" \
  --data-dir "${drill_data}" \
  --snapshot-dir "${drill_snapshot}" \
  --collection powercut \
  --points 1000 \
  --vector-dim 128 \
  --keep-data >"${before_json}"

# Drop the device without flushing, expose an error target, then reconstruct
# the original mapping from the loopback image. All device names are generated
# locally and cleanup is guarded by the exact mapper/loop identifiers above.
dmsetup suspend --noflush "${mapper_name}"
dmsetup reload "${mapper_name}" --table "0 ${sectors} error"
dmsetup resume "${mapper_name}"
umount -l "${mountpoint}" || true
mounted=0
dmsetup remove --retry "${mapper_name}"
dmsetup create "${mapper_name}" --table "0 ${sectors} flakey ${loop_device} 0 3600 1 1 drop_writes"
fsck.ext4 -p "${mapper}" || fsck.ext4 -y "${mapper}"
mount -o noatime,barrier=1 "${mapper}" "${mountpoint}"
mounted=1

"${repo_root}/target/release/chirondrill" \
  --data-dir "${drill_data}" \
  --collection powercut \
  --existing-recovery-profile \
  --expected-points 1000 >"${after_json}"

jq -n \
  --arg commit "$(git rev-parse HEAD)" \
  --arg kernel "$(uname -r)" \
  --slurpfile before "${before_json}" \
  --slurpfile after "${after_json}" \
  '{
    schema_version: 1,
    status: "passed",
    commit: $commit,
    kernel: $kernel,
    filesystem: "ext4",
    device_mapper: "dm-flakey+loopback",
    verified: [
      "fault-injection process-kill matrix on dm-flakey filesystem",
      "migration/key-rotation/restore crash consistency",
      "acknowledged-prefix reopen after no-flush device loss"
    ],
    drill_before_powercut: $before[0],
    drill_after_powercut: $after[0]
  }' >"${evidence_path}"

echo "power-cut evidence: ${evidence_path}"
