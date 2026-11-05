#!/usr/bin/env python3
"""Exercise a native binary set, including an acknowledged batch after SIGKILL."""
import argparse
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    args = parser.parse_args()
    binaries = args.bin_dir.resolve(strict=True)
    suffix = ".exe" if os.name == "nt" else ""
    sockets = [socket.socket() for _ in range(3)]
    for holder in sockets:
        holder.bind(("127.0.0.1", 0))
    ports = [holder.getsockname()[1] for holder in sockets]
    for holder in sockets:
        holder.close()
    env = dict(os.environ, CHIRONDB_API_KEY=secrets.token_urlsafe(32))
    # Do not inherit unrelated runtime configuration from a developer host.
    for name in list(env):
        if name.startswith(("CHIRONDB_", "GAUSSDB_")) and name != "CHIRONDB_API_KEY":
            del env[name]

    def request(method, path, body=None):
        connection = http.client.HTTPConnection("127.0.0.1", ports[0], timeout=10)
        try:
            connection.request(method, path, None if body is None else json.dumps(body),
                {"Authorization": "Bearer " + env["CHIRONDB_API_KEY"], "Content-Type": "application/json"})
            response = connection.getresponse()
            result = response.read()
            assert response.status == 200, (path, response.status, result[:500])
            return json.loads(result)
        finally:
            connection.close()

    with tempfile.TemporaryDirectory(prefix="chirondb-binary-smoke-") as directory:
        command = [str(binaries / ("chirondb" + suffix)), "--data-dir", str(Path(directory) / "db"),
            "--listen-http", f"127.0.0.1:{ports[0]}", "--listen-grpc", f"127.0.0.1:{ports[1]}",
            "--listen-wire", f"127.0.0.1:{ports[2]}"]
        process = None
        with (Path(directory) / "server.log").open("w+") as log:
            def start():
                server = subprocess.Popen(command, env=env, stdout=log, stderr=log)
                try:
                    deadline = time.monotonic() + 60
                    while time.monotonic() < deadline:
                        if server.poll() is not None:
                            raise RuntimeError("binary exited during startup")
                        try:
                            request("GET", "/health")
                            for name, endpoint in (("chirongrpcctl", f"http://127.0.0.1:{ports[1]}"),
                                                   ("chironwirectl", f"127.0.0.1:{ports[2]}")):
                                subprocess.run([str(binaries / (name + suffix)), "--endpoint", endpoint, "health"],
                                               env=env, check=True, capture_output=True, timeout=15)
                            return server
                        except (OSError, http.client.HTTPException, subprocess.CalledProcessError):
                            time.sleep(0.05)
                    raise TimeoutError("binary startup deadline exceeded")
                except BaseException:
                    if server.poll() is None:
                        server.kill()
                    server.wait(timeout=10)
                    raise

            try:
                process = start()
                request("POST", "/v1/collections", {"name": "release_smoke", "vector_dim": 2,
                    "metric": "l2", "shards": 1, "replicas": 1})
                base = "/v1/collections/release_smoke"
                request("PUT", base + "/graph", {})
                request("PUT", base + "/graph/types/cites", {})
                points = [{"id": name, "vector": vector, "payload": {"text": name}}
                          for name, vector in (("a", [1.0, 0.0]), ("b", [0.0, 1.0]))]
                request("PUT", base + "/points?wait=true", {"points": points})
                batch = {"edges": [{"source_point_id": source, "target_point_id": target, "edge_type": "cites",
                                    "properties": {"ordinal": number}}
                                   for number, (source, target) in enumerate((("a", "b"), ("b", "a")))],
                         "idempotency_key": "release-smoke-batch", "wait": True}
                acknowledged = request("POST", base + "/edges/batch", batch)
                assert len(set(acknowledged["edge_ids"])) == 2 and acknowledged["receipt"]["durable"]
                process.kill()
                process.wait(timeout=10)
                process = start()
                stored = request("POST", base + "/points/get", {"ids": ["a", "b"]})["points"]
                assert {point["id"]: (point["vector"], point["payload"]) for point in stored} == {
                    point["id"]: (point["vector"], point["payload"]) for point in points}
                hits = request("POST", base + "/search", {"vector": [1.0, 0.0], "k": 1})
                assert not hits.get("degraded") and hits["hits"][0]["id"] == "a"
                replay = request("POST", base + "/edges/batch", batch)
                assert replay["edge_ids"] == acknowledged["edge_ids"] and replay["receipt"]["replayed"]
                count = request("POST", base + "/graph/traverse", {"anchors": ["a", "b"], "edge_types": ["cites"],
                    "direction": "outgoing", "returns": "edges", "with_payload": True,
                    "budget": {"max_depth": 1, "max_frontier": 100, "max_visited": 100, "max_edges": 100,
                               "max_time_ms": 5000, "max_memory_bytes": 1048576, "cold": None}})
                assert not count.get("truncation")
                assert {edge["id"] for edge in count["result"]["rows"]} == set(acknowledged["edge_ids"])
                print(json.dumps({"binary_smoke": "passed", "protocols": ["HTTP", "gRPC", "ChironWire"],
                                  "points": 2, "durable_batch_edges": 2, "restart": "SIGKILL and receipt replay"}))
            except BaseException:
                log.flush()
                log.seek(0)
                print(log.read())
                raise
            finally:
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=10)


if __name__ == "__main__":
    main()
