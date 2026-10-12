#!/usr/bin/env python3
"""Capture Linux cgroup and process-resource samples during a W-lite run."""

import argparse
import json
from pathlib import Path
import subprocess
import time


SCRIPT = """for item in cpu.max cpu.stat memory.max memory.current memory.peak memory.events pids.max pids.current pids.peak; do
  echo ===$item
  cat /sys/fs/cgroup/$item
done
echo ===status
cat /proc/1/status
echo ===fd_count
ls /proc/1/fd | wc -l
"""


def sample(container):
    result = subprocess.run(["docker", "exec", container, "sh", "-c", SCRIPT],
                            text=True, capture_output=True, timeout=15)
    if result.returncode:
        raise RuntimeError("docker exec failed: " + result.stderr[-500:])
    sections = {}
    current = None
    for line in result.stdout.splitlines():
        if line.startswith("==="):
            current = line[3:]
            sections[current] = []
        elif current:
            sections[current].append(line)
    def number(name):
        value = sections[name][0]
        return None if value == "max" else int(value)
    status = dict(line.split(":", 1) for line in sections["status"] if ":" in line)
    events = dict(line.split() for line in sections["memory.events"])
    cpu = dict(line.split() for line in sections["cpu.stat"])
    return {
        "cpu_max": " ".join(sections["cpu.max"]),
        "memory_max_bytes": number("memory.max"),
        "memory_current_bytes": number("memory.current"),
        "memory_peak_bytes": number("memory.peak"),
        "memory_events": {name: int(value) for name, value in events.items()},
        "pids_max": number("pids.max"),
        "pids_current": number("pids.current"),
        "pids_peak": number("pids.peak"),
        "process_rss_kib": int(status["VmRSS"].strip().split()[0]),
        "process_threads": int(status["Threads"].strip()),
        "process_fds": number("fd_count"),
        "cpu_stat": {name: int(value) for name, value in cpu.items()},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--seconds", type=float, default=600)
    parser.add_argument("--interval", type=float, default=5)
    args = parser.parse_args()
    if args.seconds <= 0 or args.interval <= 0:
        parser.error("seconds and interval must be positive")
    started = time.monotonic()
    with args.output.open("w") as output:
        while True:
            elapsed = time.monotonic() - started
            record = {"elapsed_seconds": round(elapsed, 3), **sample(args.container)}
            output.write(json.dumps(record, sort_keys=True) + "\n")
            output.flush()
            remaining = args.seconds - (time.monotonic() - started)
            if remaining <= 0:
                break
            time.sleep(min(args.interval, remaining))


if __name__ == "__main__":
    main()
