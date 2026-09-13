#!/usr/bin/env python3
"""Long-running graph/vector durability and RSS soak using only public HTTP APIs."""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import json
import math
import os
from pathlib import Path
import signal
import socket
import statistics
import subprocess
import sys
import time
from typing import Any
from urllib import error, parse, request


POINTS = 10_000
ANCHORS = 100
EDGES_PER_ANCHOR = 500
EDGE_TYPE = "soak_link"
COLLECTION = "graph_vector_soak"
DIMENSIONS = 8
MIN_DURATION_SECONDS = 86_400
MIN_QUERIES = 50_000
MIN_MUTATIONS = 10_000
MAX_RSS_BYTES = 2 * 1024**3


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def vector_for(index: int, seed: int) -> list[float]:
    values = [
        math.sin((index + 1) * (dimension + 3) * 0.017 + seed)
        + math.cos((index + seed + 1) * (dimension + 5) * 0.013)
        for dimension in range(DIMENSIONS)
    ]
    norm = math.sqrt(sum(value * value for value in values))
    return [value / norm for value in values]


def target_index(anchor: int, offset: int) -> int:
    return ANCHORS + ((anchor * 503 + offset) % (POINTS - ANCHORS))


class Api:
    def __init__(self, port: int):
        self.base = f"http://127.0.0.1:{port}/v1"

    def send(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        timeout: float = 60,
    ) -> dict[str, Any]:
        data = None if body is None else json.dumps(body).encode()
        call = request.Request(
            f"{self.base}{path}",
            data=data,
            method=method,
            headers={"Content-Type": "application/json"},
        )
        try:
            with request.urlopen(call, timeout=timeout) as response:
                payload = response.read()
        except error.HTTPError as failure:
            detail = failure.read().decode(errors="replace")
            raise RuntimeError(f"{method} {path} returned {failure.code}: {detail}") from failure
        return json.loads(payload) if payload else {}


class Soak:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.port = free_port()
        self.api = Api(self.port)
        self.process: subprocess.Popen[bytes] | None = None
        self.log = args.output.with_name(args.output.name + ".server.log").open("ab")
        self.started_at = utc_now()
        self.started = time.monotonic()
        self.last_checkpoint = self.started
        self.last_rss_sample = 0.0
        self.next_restart = self.started + args.restart_interval_seconds
        self.mutable_edges: dict[int, str] = {}
        self.rss_samples: list[dict[str, int | float]] = []
        self.errors: list[str] = []
        self.counts = {
            "traversals": 0,
            "dense_searches": 0,
            "hybrid_searches": 0,
            "durable_mutations": 0,
            "compactions": 0,
            "restarts": 0,
            "forced_restarts": 0,
            "unexpected_exits": 0,
        }
        self.interrupted = False

    def elapsed(self) -> float:
        return time.monotonic() - self.started

    def start_server(self) -> None:
        self.process = subprocess.Popen(
            [
                str(self.args.server),
                "--data-dir",
                str(self.args.data_dir),
                "--listen-http",
                f"127.0.0.1:{self.port}",
                "--listen-grpc",
                "127.0.0.1:0",
                "--listen-wire",
                "127.0.0.1:0",
                "--auto-compact-wal-bytes",
                str(1024 * 1024),
                "--auto-compact-interval-secs",
                "60",
            ],
            stdout=self.log,
            stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"server exited during startup with {self.process.returncode}")
            try:
                self.api.send("GET", "/health", timeout=2)
                return
            except (OSError, RuntimeError):
                time.sleep(0.2)
        raise RuntimeError("server did not become healthy within 60 seconds")

    def stop_server(self, forced: bool) -> None:
        if self.process is None or self.process.poll() is not None:
            return
        if forced:
            self.process.kill()
        else:
            self.process.send_signal(signal.SIGINT)
        try:
            self.process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=10)
        self.process = None

    def require_server(self) -> None:
        if self.process is None or self.process.poll() is not None:
            self.counts["unexpected_exits"] += 1
            code = None if self.process is None else self.process.returncode
            raise RuntimeError(f"server exited unexpectedly with {code}")

    def seed(self) -> None:
        self.api.send(
            "POST",
            "/collections",
            {
                "name": COLLECTION,
                "vector_dim": DIMENSIONS,
                "metric": "cosine",
                "shards": 1,
                "replicas": 1,
            },
        )
        for first in range(0, POINTS, 1_000):
            points = []
            for index in range(first, min(first + 1_000, POINTS)):
                points.append(
                    {
                        "id": point_id(index),
                        "vector": vector_for(index, self.args.seed),
                        "sparse_vector": {"indices": [index + 1], "values": [1.0]},
                        "payload": {"kind": "anchor" if index < ANCHORS else "node"},
                    }
                )
            self.api.send(
                "PUT",
                f"/collections/{COLLECTION}/points",
                {"points": points, "wait": True},
                timeout=120,
            )
        self.api.send("PUT", f"/collections/{COLLECTION}/graph?wait=true")
        self.api.send(
            "PUT",
            f"/collections/{COLLECTION}/graph/types/{EDGE_TYPE}",
            {"weight_property": "weight", "wait": True},
        )

        def relate(edge_number: int) -> tuple[int, dict[str, Any]]:
            anchor, offset = divmod(edge_number, EDGES_PER_ANCHOR)
            return edge_number, self.api.send(
                "POST",
                f"/collections/{COLLECTION}/edges",
                {
                    "source_point_id": point_id(anchor),
                    "target_point_id": point_id(target_index(anchor, offset)),
                    "edge_type": EDGE_TYPE,
                    "properties": {"weight": 1.0, "seed_offset": offset},
                    "idempotency_key": f"soak-seed-{edge_number}",
                    "wait": False,
                },
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            for first in range(0, ANCHORS * EDGES_PER_ANCHOR, 1_000):
                for edge_number, response in pool.map(relate, range(first, first + 1_000)):
                    anchor, offset = divmod(edge_number, EDGES_PER_ANCHOR)
                    if offset == 0:
                        self.mutable_edges[anchor] = response["edge_id"]
        time.sleep(1)
        self.api.send("POST", f"/collections/{COLLECTION}/compact", timeout=300)
        self.counts["compactions"] += 1
        self.validate_reopen()

    def traversal(self, anchor: int, full: bool = False) -> list[dict[str, Any]]:
        response = self.api.send(
            "POST",
            f"/collections/{COLLECTION}/graph/traverse",
            {
                "anchors": [point_id(anchor)],
                "edge_types": [EDGE_TYPE],
                "direction": "outgoing",
                "returns": "edges",
                "limit": 1_000 if full else 10,
                "with_payload": False,
            },
        )
        rows = response["result"]["rows"]
        if not rows:
            raise RuntimeError(f"anchor {anchor} returned no edges")
        return rows

    def search(self, anchor: int, hybrid: bool) -> None:
        target = target_index(anchor, 0)
        body: dict[str, Any] = {
            "vector": vector_for(target, self.args.seed),
            "k": 1,
            "graph": {
                "anchors": [point_id(anchor)],
                "edge_types": [EDGE_TYPE],
                "direction": "outgoing",
            },
        }
        path = "search"
        if hybrid:
            path = "hybrid_search"
            body.update(
                {
                    "sparse_vector": {"indices": [target + 1], "values": [1.0]},
                    "fusion": "rrf",
                }
            )
        response = self.api.send("POST", f"/collections/{COLLECTION}/{path}", body)
        if not response.get("hits") or response["hits"][0]["id"] != point_id(target):
            raise RuntimeError(f"{path} lost expected reachable target for anchor {anchor}")
        if "graph" not in response:
            raise RuntimeError(f"{path} omitted graph execution evidence")

    def mutate(self, mutation: int) -> None:
        anchor = mutation % ANCHORS
        token = self.mutable_edges[anchor]
        encoded = parse.quote(token, safe="")
        self.api.send(
            "PATCH",
            f"/collections/{COLLECTION}/edges/{encoded}",
            {"properties": {"revision": mutation}, "wait": True},
        )
        self.counts["durable_mutations"] += 1
        if mutation > 0 and mutation % 20 == 0:
            self.api.send(
                "DELETE",
                f"/collections/{COLLECTION}/edges/{encoded}?wait=true",
            )
            self.counts["durable_mutations"] += 1
            response = self.api.send(
                "POST",
                f"/collections/{COLLECTION}/edges",
                {
                    "source_point_id": point_id(anchor),
                    "target_point_id": point_id(target_index(anchor, 0)),
                    "edge_type": EDGE_TYPE,
                    "properties": {"weight": 1.0, "revision": mutation},
                    "idempotency_key": f"soak-recreate-{mutation}",
                    "wait": True,
                },
            )
            self.mutable_edges[anchor] = response["edge_id"]
            self.counts["durable_mutations"] += 1

    def validate_reopen(self) -> None:
        count = self.api.send("POST", f"/collections/{COLLECTION}/count", {})["count"]
        if count != POINTS:
            raise RuntimeError(f"point count changed after reopen: {count} != {POINTS}")
        for anchor, token in self.mutable_edges.items():
            rows = self.traversal(anchor, full=True)
            if len(rows) != EDGES_PER_ANCHOR:
                raise RuntimeError(
                    f"anchor {anchor} has {len(rows)} edges, expected {EDGES_PER_ANCHOR}"
                )
            if not any(row["id"] == token for row in rows):
                raise RuntimeError(f"acknowledged edge {token} missing after reopen")
        self.search(0, hybrid=False)
        self.search(0, hybrid=True)

    def restart(self) -> None:
        number = self.counts["restarts"] + 1
        forced = number % 4 == 0
        self.stop_server(forced)
        self.start_server()
        self.validate_reopen()
        self.counts["restarts"] = number
        if forced:
            self.counts["forced_restarts"] += 1

    def sample_rss(self) -> None:
        self.require_server()
        assert self.process is not None
        output = subprocess.check_output(
            ["ps", "-o", "rss=", "-p", str(self.process.pid)], text=True
        ).strip()
        if not output:
            raise RuntimeError("ps returned no RSS sample")
        self.rss_samples.append(
            {"elapsed_seconds": self.elapsed(), "rss_bytes": int(output) * 1024}
        )

    def report(self, final: bool) -> dict[str, Any]:
        elapsed = self.elapsed()
        first_window = [
            int(sample["rss_bytes"])
            for sample in self.rss_samples
            if 1_800 <= float(sample["elapsed_seconds"]) < 5_400
        ]
        final_window = [
            int(sample["rss_bytes"])
            for sample in self.rss_samples
            if float(sample["elapsed_seconds"]) >= max(1_800, elapsed - 3_600)
        ]
        first_median = int(statistics.median(first_window)) if first_window else None
        final_median = int(statistics.median(final_window)) if final_window else None
        peak = max((int(sample["rss_bytes"]) for sample in self.rss_samples), default=0)
        rss_limit = (
            max(int(first_median * 1.10), first_median + 64 * 1024**2)
            if first_median is not None
            else None
        )
        memory_passed = (
            peak < MAX_RSS_BYTES
            and first_median is not None
            and final_median is not None
            and rss_limit is not None
            and final_median <= rss_limit
        )
        candidate_ready = (
            elapsed >= MIN_DURATION_SECONDS
            and not self.errors
            and self.counts["unexpected_exits"] == 0
            and self.counts["restarts"] >= 23
            and self.counts["forced_restarts"] >= 5
            and self.counts["traversals"] >= MIN_QUERIES
            and self.counts["dense_searches"] >= MIN_QUERIES
            and self.counts["hybrid_searches"] >= MIN_QUERIES
            and self.counts["durable_mutations"] >= MIN_MUTATIONS
            and memory_passed
        )
        verdict = "failed" if self.errors else "running"
        if final:
            verdict = "passed" if candidate_ready else "failed"
        elif candidate_ready:
            verdict = "passed-checkpoint"
        return {
            "schema_version": 1,
            "verdict": verdict,
            "candidate_ready": candidate_ready,
            "tested_sha": self.args.tested_sha,
            "seed": self.args.seed,
            "started_at": self.started_at,
            "updated_at": utc_now(),
            "elapsed_seconds": elapsed,
            "workload": {
                "points": POINTS,
                "anchors": ANCHORS,
                "edges": ANCHORS * EDGES_PER_ANCHOR,
                "dimensions": DIMENSIONS,
            },
            "counts": self.counts,
            "errors": self.errors,
            "rss": {
                "samples": len(self.rss_samples),
                "first_post_warmup_hour_median_bytes": first_median,
                "final_hour_median_bytes": final_median,
                "allowed_final_median_bytes": rss_limit,
                "peak_bytes": peak,
                "peak_limit_bytes": MAX_RSS_BYTES,
                "passed": memory_passed,
            },
        }

    def checkpoint(self, final: bool = False) -> None:
        report = self.report(final)
        temporary = self.args.output.with_name(self.args.output.name + ".tmp")
        temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        os.replace(temporary, self.args.output)

    def run(self) -> int:
        try:
            self.start_server()
            self.seed()
            self.started_at = utc_now()
            self.started = time.monotonic()
            self.last_checkpoint = self.started
            self.last_rss_sample = self.started - 60
            self.next_restart = self.started + self.args.restart_interval_seconds
            mutation = 0
            while self.elapsed() < self.args.duration_seconds and not self.interrupted:
                self.require_server()
                anchor = mutation % ANCHORS
                self.traversal(anchor)
                self.counts["traversals"] += 1
                self.search(anchor, hybrid=False)
                self.counts["dense_searches"] += 1
                self.search(anchor, hybrid=True)
                self.counts["hybrid_searches"] += 1
                self.mutate(mutation)
                mutation += 1
                now = time.monotonic()
                if mutation % 10_000 == 0:
                    self.api.send("POST", f"/collections/{COLLECTION}/compact", timeout=300)
                    self.counts["compactions"] += 1
                if now >= self.next_restart:
                    self.restart()
                    self.next_restart = now + self.args.restart_interval_seconds
                if now - self.last_rss_sample >= 60:
                    self.sample_rss()
                    self.last_rss_sample = now
                if now - self.last_checkpoint >= 3_600:
                    self.checkpoint()
                    self.last_checkpoint = now
        except Exception as failure:  # evidence must survive the first hard failure
            self.errors.append(f"{type(failure).__name__}: {failure}")
        finally:
            self.stop_server(forced=False)
            self.checkpoint(final=True)
            self.log.close()
        return 0 if self.report(final=True)["candidate_ready"] else 1


def point_id(index: int) -> str:
    return f"point-{index:05}"


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--duration-seconds", type=int, required=True)
    parser.add_argument("--tested-sha", required=True)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--restart-interval-seconds", type=int, default=3_600)
    args = parser.parse_args()
    args.server = args.server.resolve()
    args.data_dir = args.data_dir.resolve()
    args.output = args.output.resolve()
    if not args.server.is_file():
        parser.error("--server must name a built ChironDB binary")
    if args.duration_seconds <= 0 or args.restart_interval_seconds <= 0:
        parser.error("durations must be positive")
    if len(args.tested_sha) != 40 or any(c not in "0123456789abcdef" for c in args.tested_sha):
        parser.error("--tested-sha must be a lowercase 40-character Git SHA")
    if args.data_dir.exists() and any(args.data_dir.iterdir()):
        parser.error("--data-dir must be absent or empty")
    args.data_dir.mkdir(parents=True, exist_ok=True)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    return args


def main() -> int:
    args = parse_args()
    soak = Soak(args)

    def interrupt(_signum: int, _frame: object) -> None:
        soak.interrupted = True

    signal.signal(signal.SIGINT, interrupt)
    signal.signal(signal.SIGTERM, interrupt)
    return soak.run()


if __name__ == "__main__":
    sys.exit(main())
