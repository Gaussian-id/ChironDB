#!/usr/bin/env python3
"""MCP acceptance using the official Python SDK and real server/stdio processes.

Install mcp_requirements.txt. Pass --bins target/release; --real-dataset adds a
pinned MiniLM embedding service test using a fetch_and_embed.py dataset.
Temporary keys, databases and logs are isolated from the developer's server.
"""
import argparse
import asyncio
from contextlib import asynccontextmanager
import importlib
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import grpc
import httpx2
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client

ALICE = "test-alice-" + "a" * 32
BOB = "test-bob-" + "b" * 32
DENIED = "test-denied-" + "d" * 32
EMBEDDING_KEY = "test-embedding-" + "e" * 32


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Provider(BaseHTTPRequestHandler):
    mode = "ok"
    calls = []
    model = None
    last_vector = None
    fixtures = {}
    audit_directory = None

    def log_message(self, *_):
        pass

    def do_POST(self):
        assert self.headers.get("Authorization") == f"Bearer {EMBEDDING_KEY}"
        data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        Provider.calls.append(data)
        assert set(data) == {"model", "input"}
        if Provider.mode == "cancel":
            time.sleep(1)
        if Provider.mode == "slow":
            time.sleep(31)
        if Provider.mode == "redirect":
            self.send_response(302)
            self.send_header("Location", "/redirected")
            self.end_headers()
            return
        vector = [1.0, 0.0]
        if data["model"] == "beir-fixture":
            vector = Provider.fixtures[data["input"]]
        if data["model"] == "real-minilm":
            vector = Provider.model.encode(data["input"], normalize_embeddings=True).tolist()
            Provider.last_vector = vector
        if Provider.mode == "dimension":
            vector = [1.0]
        payload = {"data": [{"embedding": vector}]}
        if Provider.mode == "nonfinite":
            vector[0] = float("nan")
        if Provider.mode == "multiple":
            payload["data"] *= 2
        if Provider.mode == "audit_failure":
            audit = Provider.audit_directory
            with (audit / "audit.jsonl").open("r+b") as stream:
                stream.truncate(64 * 1024 * 1024)
            audit.rename(audit.with_name("audit-disabled"))
            audit.write_text("force an audit I/O failure in this temporary database")
        body = b"broken" if Provider.mode == "broken" else json.dumps(payload).encode()
        if Provider.mode == "oversized":
            body = b" " * 20000
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


@asynccontextmanager
async def session(url, key, modern):
    async def stateless(response):
        assert "mcp-session-id" not in response.headers
        if response.headers.get("content-type", "").startswith("application/json"):
            await response.aread()
            assert len(response.content) <= 256 * 1024
    async with httpx2.AsyncClient(event_hooks={"response": [stateless]}, headers={"Authorization": f"Bearer {key}"}, timeout=40) as client:
        async with streamable_http_client(url, http_client=client) as streams:
            async with ClientSession(*streams) as active:
                result = await (active.discover() if modern else active.initialize())
                if modern:
                    assert "2026-07-28" in result.supported_versions
                else:
                    assert result.protocol_version == "2025-11-25"
                yield active


def content(result):
    assert not result.is_error, result
    assert json.loads(result.content[0].text) == result.structured_content
    return result.structured_content


def assert_ranking(hits, expected):
    actual = [(hit["id"], hit["score"]) for hit in hits]
    assert [hit[0] for hit in actual] == [hit[0] for hit in expected], (actual, expected)
    assert all(abs(a[1] - b[1]) < 1e-7 for a, b in zip(actual, expected)), (actual, expected)


async def exercise(args, directory, process, ports, provider):
    base = f"http://127.0.0.1:{ports[0]}"
    async with httpx2.AsyncClient(base_url=base, headers={"Authorization": f"Bearer {ALICE}"}, timeout=40) as http:
        for _ in range(300):
            if process.poll() is not None:
                raise AssertionError((directory / "server.log").read_text())
            try:
                if (await http.get("/health")).status_code == 200:
                    break
            except httpx2.TransportError:
                pass
            await asyncio.sleep(0.1)
        else:
            raise AssertionError("server did not become ready")

        async def write(method, path, body, key=ALICE):
            response = await http.request(method, path, json=body, headers={"Authorization": f"Bearer {key}"})
            assert response.is_success, response.text
            return response.json()

        await write("POST", "/collections", {"name": "docs", "vector_dim": 2})
        await write("PUT", "/collections/docs/points", {"points": [
            {"id": "a", "vector": [1, 0], "payload": {"text": "refund policy", "title": "Returns", "source": "https://example.com/returns", "department": "service"}},
            {"id": "empty", "vector": [1, 0], "payload": {"text": ""}},
            {"id": "missing-text", "vector": [1, 0], "payload": {}},
            {"id": "large", "vector": [0, 1], "payload": {"text": "秘密" * 60000}},
        ]})
        await write("PUT", "/collections/docs/points", {"points": [{"id": "b", "vector": [1, 0], "payload": {"text": "refund policy"}}]}, BOB)
        query = {"vector": [1, 0], "query": "refund policy", "text_field": "text", "k": 5}
        native = await write("POST", "/collections/docs/text_hybrid_search", query)
        alias = await write("POST", "/v1/collections/docs/text_hybrid_search", query)
        assert native["hits"] == alias["hits"]
        assert not (await write("POST", "/collections/docs/text_hybrid_search", {**query, "k": 0}))["hits"]
        rejected = await http.post("/collections/docs/text_hybrid_search", json={**query, "graph": {}})
        assert rejected.status_code == 422
        expected = [(hit["id"], hit["score"]) for hit in native["hits"]]
        assert "b" not in dict(expected) and "missing-text" not in dict(expected)
        for modern in [False, True]:
            async with session(base + "/v1/mcp", ALICE, modern) as active:
                tools = (await active.list_tools()).tools
                assert {tool.name for tool in tools} == {"list_collections", "search_documents", "get_document"}
                assert all(tool.annotations.read_only_hint for tool in tools)
                assert content(await active.call_tool("list_collections", {}))["collections"] == ["docs"]
                result = content(await active.call_tool("search_documents", {"collection": "docs", "query": "refund policy"}))
                assert_ranking(result["hits"], expected)
                assert result["truncated"] and result["hits"][-1]["text_truncated"]
                filtered = content(await active.call_tool("search_documents", {"collection": "docs", "query": "refund", "filter": {"department": "service"}}))
                assert [hit["id"] for hit in filtered["hits"]] == ["a"]
                assert content(await active.call_tool("get_document", {"collection": "docs", "id": "a"}))["text"] == "refund policy"
                missing = await active.call_tool("get_document", {"collection": "docs", "id": "absent"})
                foreign = await active.call_tool("get_document", {"collection": "docs", "id": "b"})
                assert missing.is_error and missing.structured_content == foreign.structured_content
                large = await active.call_tool("get_document", {"collection": "docs", "id": "large"})
                assert large.is_error and large.structured_content["error"] == "response_too_large"
                before = len(Provider.calls)
                for invalid in [{"query": "x" * 8193}, {"limit": 21}, {"limit": 0}, {"tenant_id": "b"}, {"filter": {"tenant_id": "b"}}]:
                    result = await active.call_tool("search_documents", {"collection": "docs", "query": "refund", **invalid})
                    assert result.is_error
                assert len(Provider.calls) == before
        async with httpx2.AsyncClient(headers={"Authorization": f"Bearer {ALICE}", "Origin": "https://chat.example.com"}) as shared:
            async with streamable_http_client(base + "/mcp", http_client=shared) as streams:
                async with ClientSession(*streams) as active:
                    await active.discover()
                    assert content(await active.call_tool("get_document", {"collection": "docs", "id": "a"}))["id"] == "a"
                    shared.headers["Authorization"] = f"Bearer {BOB}"
                    assert (await active.call_tool("get_document", {"collection": "docs", "id": "a"})).is_error
                    assert content(await active.call_tool("get_document", {"collection": "docs", "id": "b"}))["id"] == "b"
        async with session(base + "/mcp", BOB, True) as active:
            result = content(await active.call_tool("search_documents", {"collection": "docs", "query": "refund"}))
            assert [hit["id"] for hit in result["hits"]] == ["b"]
        async with session(base + "/mcp", DENIED, True) as active:
            assert content(await active.call_tool("list_collections", {}))["collections"] == []
            before = len(Provider.calls)
            assert (await active.call_tool("search_documents", {"collection": "docs", "query": "refund"})).is_error
            assert len(Provider.calls) == before
        for headers, status in [({"Authorization": "Bearer invalid"}, 401), ({"Origin": "https://untrusted.example"}, 403), ({"Host": "untrusted.example"}, 403)]:
            response = await http.post("/mcp", headers=headers, json={})
            assert response.status_code == status, response.text

        async with session(base + "/mcp", ALICE, True) as active:
            for mode in ["dimension", "multiple", "broken", "oversized", "nonfinite", "redirect", "slow"]:
                Provider.mode = mode
                result = await active.call_tool("search_documents", {"collection": "docs", "query": "refund"})
                assert result.is_error, mode
            Provider.mode = "ok"

        async with session(base + "/mcp", ALICE, True) as active:
            Provider.mode = "cancel"
            count = len(Provider.calls)
            pending = asyncio.create_task(active.call_tool("search_documents", {"collection": "docs", "query": "refund"}))
            for _ in range(100):
                if len(Provider.calls) > count:
                    break
                await asyncio.sleep(0.01)
            assert len(Provider.calls) > count
            pending.cancel()
            try:
                await pending
            except asyncio.CancelledError:
                pass
            await asyncio.sleep(1.2)
            Provider.mode = "ok"
            assert content(await active.call_tool("get_document", {"collection": "docs", "id": "a"}))["id"] == "a"

        params = StdioServerParameters(command=str(args.bins / "chironmcp"), args=["--endpoint", base + "/v1/mcp"], env={**os.environ, "CHIRONDB_API_KEY": ALICE})
        for modern in [False, True]:
            stderr_path = directory / ("stdio-current.log" if modern else "stdio-legacy.log")
            with stderr_path.open("w") as stderr:
                async with stdio_client(params, errlog=stderr) as streams:
                    async with ClientSession(*streams) as active:
                        negotiated = await (active.discover() if modern else active.initialize())
                        if modern:
                            assert "2026-07-28" in negotiated.supported_versions
                        else:
                            assert negotiated.protocol_version == "2025-11-25"
                        assert len((await active.list_tools()).tools) == 3
                        assert content(await active.call_tool("list_collections", {}))["collections"] == ["docs"]
                        assert content(await active.call_tool("get_document", {"collection": "docs", "id": "a"}))["text"] == "refund policy"
                        result = content(await active.call_tool("search_documents", {"collection": "docs", "query": "refund policy"}))
                        assert_ranking(result["hits"], expected)
            assert "panic" not in stderr_path.read_text()

        sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "clients/python"))
        from chirondb_client import ChironDbClient
        sdk = ChironDbClient(base, api_key=ALICE)
        sdk_result = await asyncio.to_thread(sdk.text_hybrid_search, "docs", [1, 0], "refund policy", "text", 5)
        assert_ranking(sdk_result["hits"], expected)

        generated = directory / "generated"
        generated.mkdir()
        repo = Path(__file__).resolve().parents[2]
        subprocess.run([sys.executable, "-m", "grpc_tools.protoc", f"-I{repo / 'proto'}", f"--python_out={generated}", f"--grpc_python_out={generated}", "chirondb/v1/compat.proto", "chirondb/v1/chirondb.proto"], check=True)
        sys.path.insert(0, str(generated))
        pb = importlib.import_module("chirondb.v1.compat_pb2")
        primary = importlib.import_module("chirondb.v1.chirondb_pb2_grpc")
        compat = importlib.import_module("chirondb.v1.compat_pb2_grpc")
        request = pb.TextHybridSearchRequest(collection="docs", vector=[1, 0], query="refund policy", text_field="text", k=5)
        channel = grpc.insecure_channel(f"127.0.0.1:{ports[1]}")
        for module, name in [(primary, "ChironDbStub"), (compat, "GaussDbStub")]:
            stub = getattr(module, name)(channel)
            response = await asyncio.to_thread(stub.TextHybridSearch, request, metadata=[("authorization", f"Bearer {ALICE}")])
            assert [hit.id for hit in response.hits] == [hit[0] for hit in expected]
            assert all(abs(hit.score - score) < 1e-7 for hit, (_, score) in zip(response.hits, expected))
            empty = pb.TextHybridSearchRequest(collection="docs", vector=[1, 0], query="refund", text_field="text", k=0)
            assert not (await asyncio.to_thread(stub.TextHybridSearch, empty, metadata=[("authorization", f"Bearer {ALICE}")])).hits
        channel.close()
        reader, writer = await asyncio.open_connection("127.0.0.1", ports[2])
        for number, native_request in enumerate([request, empty], 1):
            frame = pb.WireRequest(request_id=number, api_key=ALICE, text_hybrid_search=native_request).SerializeToString()
            writer.write(struct.pack(">I", len(frame)) + frame)
            await writer.drain()
            length = struct.unpack(">I", await reader.readexactly(4))[0]
            response = pb.WireResponse.FromString(await reader.readexactly(length))
            assert not response.error_code, response
            ranking = expected if number == 1 else []
            assert [hit.id for hit in response.search.hits] == [hit[0] for hit in ranking]
            assert all(abs(hit.score - score) < 1e-7 for hit, (_, score) in zip(response.search.hits, ranking))
        writer.close()
        await writer.wait_closed()

        benchmark = None
        if args.benchmark_dataset:
            data = json.loads(args.benchmark_dataset.read_text())
            Provider.fixtures = {query["text"]: query["vector"] for query in data["queries"]}
            await write("POST", "/collections", {"name": "beir", "vector_dim": data["dim"], "metric": "cosine"})
            for offset in range(0, len(data["corpus"]), 128):
                await write("PUT", "/collections/beir/points", {"points": [{"id": doc["id"], "vector": doc["vector"], "payload": {"text": doc["text"]}} for doc in data["corpus"][offset:offset+128]]})
            await write("POST", "/collections/beir/compact", {})
            timings = []
            async with session(base + "/mcp", ALICE, True) as active:
                for query in data["queries"]:
                    start = time.perf_counter()
                    result = content(await active.call_tool("search_documents", {"collection": "beir", "query": query["text"], "limit": 10}))
                    mcp_ms = (time.perf_counter()-start)*1000
                    start = time.perf_counter()
                    native = await write("POST", "/collections/beir/text_hybrid_search", {"vector": query["vector"], "query": query["text"], "text_field": "text", "k": 10})
                    native_ms = (time.perf_counter()-start)*1000
                    assert_ranking(result["hits"], [(hit["id"], hit["score"]) for hit in native["hits"]])
                    timings.append({"query": query["id"], "mcp_total_ms": mcp_ms, "native_http_ms": native_ms, **result["timing_ms"]})
            benchmark = {"dataset": str(args.benchmark_dataset), "queries": len(timings), "provider": "pinned vector fixture; not model inference", "timings": timings}
            if args.benchmark_report:
                args.benchmark_report.write_text(json.dumps(benchmark, indent=2))
        real_timing = None
        if args.real_dataset:
            from sentence_transformers import SentenceTransformer
            data = json.loads(args.real_dataset.read_text())
            Provider.model = SentenceTransformer(data["provenance"]["model"], revision=data["provenance"]["model_revision"])
            await write("POST", "/collections", {"name": "real", "vector_dim": data["dim"]})
            await write("PUT", "/collections/real/points", {"points": [{"id": doc["id"], "vector": doc["vector"], "payload": {"text": doc["text"]}} for doc in data["corpus"][:30]]})
            async with session(base + "/mcp", ALICE, True) as active:
                result = content(await active.call_tool("search_documents", {"collection": "real", "query": data["queries"][0]["text"]}))
                native = await write("POST", "/collections/real/text_hybrid_search", {"vector": Provider.last_vector, "query": data["queries"][0]["text"], "text_field": "text", "k": 5})
                assert_ranking(result["hits"], [(hit["id"], hit["score"]) for hit in native["hits"]])
                real_timing = result["timing_ms"]
                example_env = {**os.environ, "PYTHONPATH": str(repo / "clients/python"), "CHIRONDB_URL": base, "CHIRONDB_API_KEY": ALICE, "CHIRONDB_MCP_MODEL": "real-minilm", "CHIRONDB_EMBEDDING_API_KEY": EMBEDDING_KEY, "CHIRONDB_EMBEDDING_ENDPOINT": f"http://127.0.0.1:{provider.server_port}/v1/embeddings"}
                completed = await asyncio.to_thread(subprocess.run, [sys.executable, str(repo / "clients/python/examples/mcp_ingest.py")], env=example_env, capture_output=True, text=True)
                assert completed.returncode == 0, completed.stderr
                assert json.loads(completed.stdout)["hits"][0]["id"] == "retur-001-chunk-01"

    records = [json.loads(line) for line in (directory / "data/audit/audit.jsonl").read_text().splitlines()]
    outcomes = [record for record in records if record.get("transport") == "mcp" and record.get("outcome") in ("success", "failure")]
    assert outcomes and any(record["outcome"] == "failure" for record in outcomes)
    assert all("duration_ms" in record["details"] for record in outcomes)
    assert all("refund policy" not in json.dumps(record) and ALICE not in json.dumps(record) for record in outcomes)
    async with session(base + "/mcp", ALICE, True) as active:
        Provider.audit_directory = directory / "data/audit"
        Provider.mode = "audit_failure"
        from mcp import MCPError
        try:
            await active.call_tool("search_documents", {"collection": "docs", "query": "refund"})
        except MCPError as error:
            assert error.code == -32603, error.error
            assert "audit_unavailable" in (directory / "server.log").read_text()
        else:
            raise AssertionError("audit write failure returned data")
    return {"real_timing_ms": real_timing, "benchmark_queries": benchmark["queries"] if benchmark else 0, "http_versions": ["2025-11-25", "2026-07-28"], "stdio": "passed", "native_protocol_parity": "passed", "failure_modes": "passed", "real_embedding": bool(args.real_dataset), "audited_tool_outcomes": len(outcomes)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bins", type=Path, required=True)
    parser.add_argument("--real-dataset", type=Path)
    parser.add_argument("--benchmark-dataset", type=Path)
    parser.add_argument("--benchmark-report", type=Path)
    args = parser.parse_args()
    args.bins = args.bins.resolve()
    with tempfile.TemporaryDirectory(prefix="chirondb-mcp-") as temporary:
        directory = Path(temporary)
        ports = [port() for _ in range(3)]
        provider = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
        threading.Thread(target=provider.serve_forever, daemon=True).start()
        keys = [{"id": name, "key": key, "role": "admin", "tenant_id": tenant, "allowed_collections": allowed} for name, key, tenant, allowed in [("alice", ALICE, "a", []), ("bob", BOB, "b", ["docs"]), ("denied", DENIED, "a", ["unconfigured"])]]
        (directory / "rbac.json").write_text(json.dumps({"keys": keys}))
        (directory / "server.toml").write_text(f'''[mcp]
allowed_origins = ["https://chat.example.com"]
[mcp.embedding]
endpoint = "http://127.0.0.1:{provider.server_port}/v1/embeddings"
api_key_env = "CHIRONDB_MCP_TEST_EMBEDDING_KEY"
[mcp.collections.docs]
model = "test"
dimensions = 2
text_field = "text"
title_field = "title"
source_field = "source"
[mcp.collections.beir]
model = "beir-fixture"
dimensions = 384
text_field = "text"
[mcp.collections.real]
model = "real-minilm"
dimensions = 384
text_field = "text"
''')
        command = [str(args.bins / "chirondb"), "--config", str(directory / "server.toml"), "--data-dir", str(directory / "data"), "--rbac-config-file", str(directory / "rbac.json"), "--tenant-enforcement", "enforced", "--listen-http", f"127.0.0.1:{ports[0]}", "--listen-grpc", f"127.0.0.1:{ports[1]}", "--listen-wire", f"127.0.0.1:{ports[2]}"]
        env = {**os.environ, "CHIRONDB_API_KEY": ",".join([ALICE, BOB, DENIED]), "CHIRONDB_MCP_TEST_EMBEDDING_KEY": EMBEDDING_KEY}
        with (directory / "server.log").open("w") as log:
            process = subprocess.Popen(command, env=env, stdout=log, stderr=log)
            try:
                print(json.dumps(asyncio.run(exercise(args, directory, process, ports, provider))))
            except BaseException:
                print((directory / "server.log").read_text()[-6000:], file=sys.stderr)
                raise
            finally:
                process.terminate()
                process.wait(timeout=20)
                provider.shutdown()


if __name__ == "__main__":
    main()
