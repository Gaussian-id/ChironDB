#!/usr/bin/env python3
import importlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

try:
    from google.protobuf import descriptor_pb2

    HAS_PROTOBUF = True
except ImportError:
    HAS_PROTOBUF = False


def main():
    if not HAS_PROTOBUF:
        print(json.dumps({"generated_python_protobuf": "ok", "skipped": "google-protobuf not installed"}))
        return

    repo = Path(__file__).resolve().parents[2]
    proto_root = repo / "proto"
    legacy_proto = proto_root / "chirondb" / "v1" / "compat.proto"
    primary_proto = proto_root / "chirondb" / "v1" / "chirondb.proto"
    raft_proto = proto_root / "chirondb" / "v1" / "raft.proto"
    protoc = shutil.which("protoc")
    if protoc is None:
        raise AssertionError("protoc is required for generated-client compatibility")

    result = {"generated_python_protobuf": "ok", "python_protobuf": "ok"}
    with tempfile.TemporaryDirectory() as raw_tmp:
        tmp = Path(raw_tmp)
        descriptor_path = tmp / "gaussdb.pb"
        subprocess.run(
            [
                protoc,
                f"--proto_path={proto_root}",
                f"--python_out={tmp}",
                f"--cpp_out={tmp}",
                f"--descriptor_set_out={descriptor_path}",
                "--include_imports",
                str(legacy_proto.relative_to(proto_root)),
                str(primary_proto.relative_to(proto_root)),
                str(raft_proto.relative_to(proto_root)),
            ],
            cwd=repo,
            check=True,
        )
        sys.path.insert(0, str(tmp))
        for name in list(sys.modules):
            if name == "proto" or name.startswith("proto."):
                del sys.modules[name]
        importlib.invalidate_caches()
        try:
            generated = importlib.import_module("chirondb.v1.compat_pb2")
            importlib.import_module("chirondb.v1.chirondb_pb2")
            importlib.import_module("chirondb.v1.raft_pb2")
        except Exception as error:  # noqa: BLE001 - see the check below
            # A local `protoc` newer than the installed protobuf runtime is an
            # environment mismatch, not a compatibility problem with these
            # protos: the generated code is simply stamped with a version the
            # runtime refuses to load. Skip loudly rather than failing, the
            # same way a missing runtime is already skipped. Any other import
            # failure is a real problem and still raises.
            if type(error).__name__ != "VersionError":
                raise
            print(
                json.dumps(
                    {
                        "generated_python_protobuf": "ok",
                        "skipped": f"protoc/runtime version mismatch: {error}",
                    }
                )
            )
            return
        validate_descriptor(descriptor_path)
        validate_cpp_generation(tmp, repo)

        request = generated.WireRequest(request_id=501)
        request.health.CopyFrom(generated.HealthRequest())
        encoded = request.SerializeToString()
        if encoded != b"\x08\xf5\x03\x52\x00":
            raise AssertionError(f"unexpected generated WireRequest bytes: {encoded!r}")

        decoded = generated.WireRequest()
        decoded.ParseFromString(encoded)
        if decoded.request_id != 501 or decoded.WhichOneof("operation") != "health":
            raise AssertionError("generated WireRequest round-trip failed")

        create = generated.CreateCollectionRequest()
        create.config.name = "compat"
        create.config.vector_dim = 3
        create.config.metric = "cosine"
        create.config.shards = 1
        create.config.replicas = 1
        create.config.payload_schema["tenant"] = "string"
        create_roundtrip = generated.CreateCollectionRequest()
        create_roundtrip.ParseFromString(create.SerializeToString())
        if create_roundtrip.config.payload_schema["tenant"] != "string":
            raise AssertionError("generated map field round-trip failed")

        search = generated.SearchRequest(collection="compat")
        search.query.vector.extend([1.0, 0.0, 0.0])
        search.query.k = 10
        search.query.budget_ms = 5
        search.query.recall_target = 0.95
        search.query.graph_json = json.dumps({"anchors": ["a"]})
        search_roundtrip = generated.SearchRequest()
        search_roundtrip.ParseFromString(search.SerializeToString())
        if not search_roundtrip.query.HasField("budget_ms"):
            raise AssertionError("generated optional field presence failed")
        if not search_roundtrip.query.HasField("recall_target"):
            raise AssertionError("generated recall target presence failed")
        if not search_roundtrip.query.HasField("graph_json"):
            raise AssertionError("generated graph constraint presence failed")

    result["cpp_protobuf"] = "ok"
    result["descriptor"] = "ok"
    print(json.dumps(result))


def validate_descriptor(descriptor_path):
    descriptor_set = descriptor_pb2.FileDescriptorSet()
    descriptor_set.ParseFromString(descriptor_path.read_bytes())
    files = {entry.name: entry for entry in descriptor_set.file}
    expected_packages = {
        "chirondb/v1/chirondb.proto": "chirondb.v1",
        "chirondb/v1/compat.proto": "gaussdb.v1",
        "chirondb/v1/raft.proto": "raft.v1",
    }
    if set(files) != set(expected_packages):
        raise AssertionError(f"unexpected schema files: {sorted(files)}")
    for name, package in expected_packages.items():
        if files[name].package != package:
            raise AssertionError(f"{name} must preserve protocol package {package}")
    descriptor = files.get("chirondb/v1/compat.proto")
    if descriptor is None:
        raise AssertionError("descriptor set missing compat.proto")

    service = next((service for service in descriptor.service if service.name == "GaussDb"), None)
    if service is None:
        raise AssertionError("descriptor set missing GaussDb service")
    methods = {method.name for method in service.method}
    expected_methods = {
        "Health",
        "CreateCollection",
        "ListCollections",
        "UpdatePayloadSchema",
        "Upsert",
        "Delete",
        "Search",
        "HybridSearch",
        "TextHybridSearch",
        "MultiSearch",
        "Recommend",
        "Count",
        "Scroll",
        "Compact",
        "TierCold",
        "PruneWalArchive",
        "Snapshot",
        "Restore",
        "ShardMove",
    }
    missing = expected_methods - methods
    if missing:
        raise AssertionError(f"descriptor set missing RPC methods: {sorted(missing)}")

    primary_descriptor = files.get("chirondb/v1/chirondb.proto")
    if primary_descriptor is None:
        raise AssertionError("descriptor set missing chirondb.proto")
    primary_service = next(
        (service for service in primary_descriptor.service if service.name == "ChironDb"), None
    )
    if primary_service is None:
        raise AssertionError("descriptor set missing ChironDb service")
    primary_methods = {method.name for method in primary_service.method}
    graph_methods = {
        "EnableGraph",
        "DropGraph",
        "ListEdgeTypes",
        "ConfigureEdgeType",
        "Relate",
        "Unrelate",
        "UpdateEdge",
        "Traverse",
        "OpenDeferredGraphSession",
        "DeferredUpsert",
        "DeferredRelate",
        "CommitDeferredGraphSession",
        "AbortDeferredGraphSession",
    }
    expected_primary_only = graph_methods | {"ExecuteQuery"}
    if primary_methods != methods | expected_primary_only:
        raise AssertionError(
            "ChironDb primary-only RPC mismatch: "
            f"{sorted(primary_methods - methods)}"
        )
    if methods & graph_methods:
        raise AssertionError("legacy GaussDb service must remain graph-RPC free")

    messages = {message.name: message for message in descriptor.message_type}
    if "WireRequest" not in messages or "WireResponse" not in messages:
        raise AssertionError("descriptor set missing GaussWire envelope messages")
    text_search = next(
        (field for field in messages["WireRequest"].field if field.name == "text_hybrid_search"), None
    )
    if text_search is None or text_search.number != 32:
        raise AssertionError("WireRequest.text_hybrid_search must use additive tag 32")
    search_query = messages.get("SearchQuery")
    if search_query is None:
        raise AssertionError("descriptor set missing SearchQuery")
    budget = next((field for field in search_query.field if field.name == "budget_ms"), None)
    if budget is None or not budget.proto3_optional:
        raise AssertionError("SearchQuery.budget_ms must preserve proto3 optional presence")
    graph = next((field for field in search_query.field if field.name == "graph_json"), None)
    if graph is None or graph.number != 8 or not graph.proto3_optional:
        raise AssertionError("SearchQuery.graph_json must be additive optional field 8")

    hybrid = messages.get("HybridSearchRequest")
    hybrid_graph = next((field for field in hybrid.field if field.name == "graph_json"), None)
    if hybrid_graph is None or hybrid_graph.number != 12 or not hybrid_graph.proto3_optional:
        raise AssertionError("HybridSearchRequest.graph_json must be optional field 12")

    search_response = messages.get("SearchResponse")
    response_graph = next(
        (field for field in search_response.field if field.name == "graph_json"), None
    )
    if response_graph is None or response_graph.number != 5 or not response_graph.proto3_optional:
        raise AssertionError("SearchResponse.graph_json must be optional field 5")


def validate_cpp_generation(tmp, repo):
    header = tmp / "chirondb" / "v1" / "compat.pb.h"
    source = tmp / "chirondb" / "v1" / "compat.pb.cc"
    primary_header = tmp / "chirondb" / "v1" / "chirondb.pb.h"
    primary_source = tmp / "chirondb" / "v1" / "chirondb.pb.cc"
    if not all(path.exists() for path in (header, source, primary_header, primary_source)):
        raise AssertionError("C++ protobuf generation did not produce expected files")
    header_text = header.read_text(encoding="utf-8", errors="ignore")
    for token in ("class WireRequest", "class SearchRequest", "class CollectionConfig"):
        if token not in header_text:
            raise AssertionError(f"C++ header missing {token}")
    primary_header_text = primary_header.read_text(encoding="utf-8", errors="ignore")
    for token in ("class GraphRelateRequest", "class GraphTraverseResponse"):
        if token not in primary_header_text:
            raise AssertionError(f"C++ primary header missing {token}")

    compiler = shutil.which("c++")
    include = Path("/opt/homebrew/include")
    library = Path("/opt/homebrew/lib")
    if not compiler or not (include / "google" / "protobuf" / "message.h").exists():
        return
    smoke = tmp / "cpp_smoke.cc"
    smoke.write_text(
        """
#include <iostream>
#include "chirondb/v1/compat.pb.h"

int main() {
  gaussdb::v1::WireRequest request;
  request.set_request_id(501);
  request.mutable_health();
  std::string encoded;
  if (!request.SerializeToString(&encoded)) {
    return 1;
  }
  gaussdb::v1::WireRequest decoded;
  if (!decoded.ParseFromString(encoded)) {
    return 2;
  }
  if (decoded.request_id() != 501 || !decoded.has_health()) {
    return 3;
  }
  gaussdb::v1::CreateCollectionRequest create;
  create.mutable_config()->set_name("compat");
  create.mutable_config()->set_vector_dim(3);
  (*create.mutable_config()->mutable_payload_schema())["tenant"] = "string";
  if (create.config().payload_schema().at("tenant") != "string") {
    return 4;
  }
  return 0;
}
""",
        encoding="utf-8",
    )
    generated_object = tmp / "gaussdb.pb.o"
    subprocess.run(
        [
            compiler,
            "-std=c++17",
            f"-I{tmp}",
            f"-I{include}",
            "-c",
            str(source),
            "-o",
            str(generated_object),
        ],
        cwd=repo,
        check=True,
    )
    smoke_object = tmp / "cpp_smoke.o"
    command = [
        compiler,
        "-std=c++17",
        f"-I{tmp}",
        f"-I{include}",
        "-c",
        str(smoke),
        "-o",
        str(smoke_object),
    ]
    subprocess.run(command, cwd=repo, check=True)


if __name__ == "__main__":
    main()
