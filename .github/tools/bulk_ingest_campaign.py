#!/usr/bin/env python3
"""Run isolated, resource-equal persistent Docker ingest qualification.

Images must already be built/pulled. This never builds while measuring. Every
run gets a fresh labelled Linux-native volume. Successful volumes are removed;
failed containers/volumes are retained for diagnosis. No other resources change.
"""
from __future__ import annotations

import argparse
import http.client
import json
import os
from pathlib import Path
import runpy
import secrets
import socket
import subprocess
import threading
import time
from types import SimpleNamespace

BENCH = runpy.run_path(str(Path(__file__).with_name("bulk_ingest_benchmark.py")))
LABEL = "org.chirondb.qualification=beta3-ingest"
HELPER = "debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241"


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


class EngineHTTP(http.client.HTTPConnection):
    def __init__(self, endpoint):
        super().__init__("localhost", timeout=10)
        self.endpoint = endpoint

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.endpoint)


def sample(endpoint, name, stop, output):
    with output.open("w") as stream:
        while not stop.is_set():
            connection = EngineHTTP(endpoint)
            try:
                connection.request("GET", f"/containers/{name}/stats?stream=false&one-shot=true")
                response = connection.getresponse()
                value = json.loads(response.read())
                if response.status != 200:
                    raise RuntimeError(value)
                stream.write(json.dumps({"monotonic": time.monotonic(), "stats": value}) + "\n")
                stream.flush()
            except Exception as error:
                stream.write(json.dumps({"sampling_error": str(error)}) + "\n")
            finally:
                connection.close()
            stop.wait(0.5)


def stats(endpoint, name):
    connection = EngineHTTP(endpoint)
    try:
        connection.request("GET", f"/containers/{name}/stats?stream=false&one-shot=true")
        response = connection.getresponse()
        result = json.loads(response.read())
        assert response.status == 200, result
        return result
    finally:
        connection.close()


def wait_server(name, engine, url):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            connection = http.client.HTTPConnection("127.0.0.1", 18091, timeout=2)
            connection.request("GET", "/health" if engine == "chiron" else "/health")
            response = connection.getresponse()
            response.read()
            connection.close()
            if response.status in (200, 401):
                return
        except OSError:
            pass
        if docker("inspect", "--format", "{{.State.Running}}", name) != "true":
            raise RuntimeError(f"qualification server exited: {name}")
        time.sleep(0.1)
    raise RuntimeError(f"qualification startup timeout: {url}")


def summarize_resources(path):
    samples = [json.loads(line) for line in path.read_text().splitlines()]
    stats = [row["stats"] for row in samples if "stats" in row]
    if not stats or any("sampling_error" in row for row in samples):
        raise RuntimeError("resource sampling incomplete")
    def cpu(row):
        return row["cpu_stats"]["cpu_usage"]["total_usage"]
    return {"cpu_seconds": (cpu(stats[-1]) - cpu(stats[0])) / 1e9,
            "peak_sampled_cgroup_bytes": max(row["memory_stats"].get("usage", 0) for row in stats),
            "peak_sampled_anon_bytes": max(row["memory_stats"].get("stats", {}).get("anon", 0) for row in stats),
            "block_io": stats[-1].get("blkio_stats"), "samples": len(stats)}


def one(args, source, round_number, image, endpoint):
    name = f"chirondb-beta3-{source}-{round_number}-{secrets.token_hex(3)}"
    volume = name + "-data"
    output = args.output / f"round-{round_number}-{source}"
    # The benchmark owns this output directory and creates it itself.
    engine = "surreal" if source == "surreal" else "chiron"
    benchmark_args = SimpleNamespace(engine=engine, url="http://127.0.0.1:18091", source=image,
                                     fixture=args.fixture, output=output, single_edge=source == "baseline",
                                     workers=args.workers, batch_size=args.batch_size)
    docker("volume", "create", "--label", LABEL, volume)
    command = ["run", "-d", "--name", name, "--label", LABEL, "--user", "0:0", "--cpus", "4", "--memory", "8g",
               "--memory-swap", "8g", "--publish", "127.0.0.1:18091:7401", "--mount", f"type=volume,source={volume},target=/data"]
    if engine == "chiron":
        command += ["--env", "CHIRONDB_API_KEY", image, "--data-dir", "/data/db", "--listen-http", "0.0.0.0:7401",
                    "--listen-grpc", "127.0.0.1:7402", "--listen-wire", "127.0.0.1:7403", "--allow-insecure-non-loopback"]
    else:
        command += ["--env", "SURREAL_DATASTORE_SYNC=every", "--env", "SURREAL_USER=" + os.environ["SURREALDB_USER"],
                    "--env", "SURREAL_PASS=" + os.environ["SURREALDB_PASS"], image,
                    "start", "--bind", "0.0.0.0:7401", "rocksdb:/data/db?sync=every"]
    docker(*command)
    stop, sampler = threading.Event(), None
    passed = False
    try:
        wait_server(name, engine, benchmark_args.url)
        # Setup is timed by BENCH.run; startup is outside the agreed timer.
        # Start sampling before setup without precreating BENCH's directory.
        resource_path = args.output / (name + "-resources.jsonl")
        sampler = threading.Thread(target=sample, args=(endpoint, name, stop, resource_path), daemon=True)
        sampler.start()
        start_stats = stats(endpoint, name)

        def resource_boundary():
            end_stats = stats(endpoint, name)
            stop.set()
            sampler.join()
            usage = docker("run", "--rm", "--label", LABEL, "--pid", "container:" + name,
                           "--network", "none", "--read-only", "--cap-drop", "ALL", "--memory", "16m", "--cpus", "0.1",
                           "--mount", f"type=volume,source={volume},target=/data,readonly", HELPER,
                           "sh", "-c", "cat /proc/1/status; du -sb /data/db")
            (args.output / (name + "-ready-process.txt")).write_text(usage)
            rss = next(int(line.split()[1]) * 1024 for line in usage.splitlines() if line.startswith("VmHWM:"))
            disk = int(usage.splitlines()[-1].split()[0])
            resources = summarize_resources(resource_path)
            resources.update(cpu_seconds=(end_stats["cpu_stats"]["cpu_usage"]["total_usage"] - start_stats["cpu_stats"]["cpu_usage"]["total_usage"]) / 1e9,
                             peak_rss_bytes=rss, disk_bytes=disk, scope="schema through T_ready; VmHWM includes process startup")
            (args.output / (name + "-boundary-stats.json")).write_text(json.dumps({"start": start_stats, "ready": end_stats}, indent=2))
            return resources

        benchmark_args.on_ready = resource_boundary
        BENCH["run"](benchmark_args)
        stop.set()
        sampler.join()
        report = json.loads((output / "report.json").read_text())
        info = json.loads(docker("inspect", name))[0]
        report["deployment"] = {"image": info["Image"], "nano_cpus": info["HostConfig"]["NanoCpus"],
                                "memory_bytes": info["HostConfig"]["Memory"], "persistent_volume": volume,
                                "durable_contract": "wait=true / RocksDB sync=every and SURREAL_DATASTORE_SYNC=every; native Linux Docker volume",
                                "transport": "authenticated loopback HTTP; same host port; no TLS"}
        if source != "surreal" and args.read_guard and round_number == 1:
            guard = runpy.run_path(str(Path(__file__).with_name("ingest_read_guard.py")))
            corpus = json.loads(args.read_guard.read_text())
            assert BENCH["file_hash"](args.read_guard) == report["manifest"]["source_sha256"]
            with (output / "read-requests.jsonl").open("w") as raw:
                read_http = BENCH["HTTP"](benchmark_args, raw)
                report["quality"] = guard["quality"](read_http, corpus)
                report["read_guard"] = guard["reads"](read_http, corpus, output / "read-latencies.jsonl")
            attempts = [json.loads(line) for line in (output / "read-requests.jsonl").read_text().splitlines()]
            report["read_guard_transport"] = {"attempts": len(attempts),
                "retries": sum(row["attempt"] > 1 for row in attempts),
                "errors": sum(row["status"] != 200 or bool(row["error"]) for row in attempts)}
            # Retain measured latencies/quality even when the stricter
            # zero-error guard fails; do not turn a partial run into a pass.
            (output / "report.json").write_text(json.dumps(report, indent=2))
            assert all(row["status"] == 200 and row["attempt"] == 1 and not row["error"] for row in attempts), "read guard requires zero retries/errors"
        # No graceful flush: verify every acknowledged record after SIGKILL.
        docker("kill", "--signal", "KILL", name)
        docker("start", name)
        wait_server(name, engine, benchmark_args.url)
        with (output / "restart-requests.jsonl").open("w") as raw:
            http = BENCH["HTTP"](benchmark_args, raw)
            BENCH["ready"](http, benchmark_args, report["manifest"])
            report["restart_oracle"] = BENCH["validate_dataset"](http, benchmark_args, report["manifest"])
            if "quality" in report:
                report["restart_quality"] = guard["quality"](http, corpus)
                (output / "report.json").write_text(json.dumps(report, indent=2))
                assert report["restart_quality"] == report["quality"], "retrieval rankings changed after restart"
        (output / "report.json").write_text(json.dumps(report, indent=2))
        print(json.dumps({"source": source, "round": round_number, "ready_seconds": report["ready_seconds"],
                          "resources": report["resources"], "restart_oracle": report["restart_oracle"]}), flush=True)
        passed = True
        return report
    finally:
        stop.set()
        if sampler:
            sampler.join(timeout=15)
        (args.output / (name + "-server.log")).write_text(docker("logs", name))
        if passed:
            docker("rm", "--force", name)
            docker("volume", "rm", volume)
        else:
            # Keep failed evidence, but stop consuming CPU/port.
            docker("stop", "--time", "10", name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--baseline-image", required=True)
    parser.add_argument("--candidate-image", required=True)
    parser.add_argument("--surreal-image", required=True)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--workers", type=int, choices=(1, 8), default=8)
    parser.add_argument("--batch-size", type=int, choices=(1, 50), default=50)
    parser.add_argument("--read-guard", type=Path, help="pinned SciFact JSON; round1 runs the frozen read/quality guard")
    parser.add_argument("--sources", nargs="+", choices=("baseline", "candidate", "surreal"), default=("baseline", "candidate", "surreal"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    credentials = {"CHIRONDB_API_KEY": secrets.token_urlsafe(32), "SURREALDB_USER": "qualification", "SURREALDB_PASS": secrets.token_urlsafe(32)}
    credential_path = args.output / "credentials.json"
    descriptor = os.open(credential_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(credentials, stream)
    os.environ.update(credentials)
    context = json.loads(docker("context", "inspect"))[0]
    endpoint = context["Endpoints"]["docker"]["Host"].removeprefix("unix://")
    images = {source: getattr(args, source + "_image") for source in args.sources}
    manifest = {"classification": "reconstructed; synthetic graph", "images": {
        source: json.loads(docker("image", "inspect", image))[0]["Id"] for source, image in images.items()},
        "limits": {"cpus": 4, "memory_gib": 8, "swap": "disabled"}, "batch": args.batch_size, "concurrency": args.workers,
        "sampling": "Docker Engine cgroup stats at 0.5s; peak anon is sampled RSS proxy, not exact VmHWM",
        "host": json.loads(docker("info", "--format", "{{json .}}")),
        "baseline_semantics": f"logical batch{args.batch_size}; {args.batch_size} durable single-edge requests because old product lacks batch API"}
    manifest["harness_sha256"] = {str(path.relative_to(Path(__file__).resolve().parents[2])): BENCH["file_hash"](path)
        for path in [Path(__file__).resolve(), Path(__file__).with_name("bulk_ingest_benchmark.py").resolve(),
                     Path(__file__).with_name("ingest_read_guard.py").resolve(),
                     Path(__file__).resolve().parents[2] / "examples/bulk_load.py"]}
    (args.output / "campaign.json").write_text(json.dumps(manifest, indent=2))
    reports = []
    for number in range(1, args.rounds + 1):
        order = list(args.sources) if number % 2 else list(reversed(args.sources))
        for source in order:
            try:
                report = one(args, source, number, images[source], endpoint)
            except Exception as error:
                # A rejected baseline is a measured outcome, not a completed
                # ingest time. Keep its raw failures and continue the paired
                # candidate/comparator observations; either one's failure stops
                # qualification. The failed baseline volume remains retained.
                if source != "baseline":
                    raise
                report_path = args.output / f"round-{number}-{source}" / "report.json"
                if not report_path.is_file():
                    raise
                report = json.loads(report_path.read_text())
                report.update(campaign_status="failed", campaign_error=str(error))
                report_path.write_text(json.dumps(report, indent=2))
                print(json.dumps({"source": source, "round": number, "status": "failed", "error": str(error)}), flush=True)
            reports.append({"source": source, "round": number, "report": report})
            (args.output / "results.json").write_text(json.dumps(reports, indent=2))


if __name__ == "__main__":
    main()
