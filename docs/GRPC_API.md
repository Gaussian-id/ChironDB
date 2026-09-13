# ChironDB gRPC API

ChironDB serves native gRPC on port `7402`. The primary service is
`chirondb.v1.ChironDb`; the deprecated `gaussdb.v1.GaussDb` service remains
available during the beta and reaches the same engine.

Start a server using [Getting started](GETTING_STARTED.md#1-build-and-start).
The recipes below assume `products` has the two example points. Creation needs
an unused name; destructive examples must be followed by re-creating that
setup before running more queries. Each JSON block is a request body for its
named RPC, not a complete shell command.

## Schemas and reflection

The primary service definition is
[`proto/chirondb/v1/chirondb.proto`](../proto/chirondb/v1/chirondb.proto).
Its request and response messages intentionally reuse
[`proto/chirondb/v1/compat.proto`](../proto/chirondb/v1/compat.proto) to keep
GaussDB alpha clients and ChironWire envelopes compatible.

All source schemas live under `proto/chirondb/v1/`. `compat.proto` retains
the `gaussdb.v1` protocol package, and `raft.proto` defines internal cluster
messages in `raft.v1`. Folder names do not change the service names or
encoded messages used by existing clients. Application clients need only
`chirondb.proto` and `compat.proto`.

Server reflection is enabled. Install [grpcurl](https://github.com/fullstorydev/grpcurl#installation)
(`brew install grpcurl` on macOS), then run:

```bash
grpcurl -plaintext 127.0.0.1:7402 list
grpcurl -plaintext 127.0.0.1:7402 list chirondb.v1.ChironDb
grpcurl -plaintext -d '{}' \
  127.0.0.1:7402 chirondb.v1.ChironDb/Health
```

The health response includes the running `version`; compare it with
`chirondb --version` before diagnosing client/server incompatibility.

## Postman and other gRPC clients

To call ChironDB from a GUI gRPC client such as Postman:

1. Create a gRPC request with server URL `127.0.0.1:7402`. Use plaintext for a
   local default server.
2. Use server reflection to load `chirondb.v1.ChironDb`. If the client cannot
   use reflection, import both `proto/chirondb/v1/chirondb.proto` and
   `proto/chirondb/v1/compat.proto`, with the repository's `proto` directory as
   the protobuf import path.
3. Select an RPC, open the message/body editor, and paste one of the JSON
   messages below.
4. When authentication is enabled, add gRPC metadata
   `authorization: Bearer <your-key>` or `x-chirondb-api-key: <your-key>`.
5. Click **Invoke**. For a remote server, enable TLS and configure the trusted
   CA and expected server name instead of using plaintext.

The examples use protobuf JSON names (`vectorDim`, `payloadJson`, `filterJson`,
and `noWait`). Tools that display the original `.proto` field names may show
their equivalent `snake_case` names.

## Authentication and TLS

When API-key authentication is enabled, send an authorization metadata value:

```bash
grpcurl -plaintext \
  -H "authorization: Bearer $CHIRONDB_API_KEY" \
  -d '{}' 127.0.0.1:7402 chirondb.v1.ChironDb/ListCollections
```

`x-chirondb-api-key` and the deprecated `x-gaussdb-api-key` metadata names are
also accepted. Use a TLS endpoint and trusted CA when connecting across a
network. The bundled client supports `--ca-cert`, `--tls-domain`,
`--client-cert`, and `--client-key` for TLS and mutual TLS.

The interceptor authenticates and attaches a stable principal; each RPC then
authorizes its action and collection. This applies to both service namespaces
and reflection. Authentication failures use `UNAUTHENTICATED`, role/collection
denials use `PERMISSION_DENIED`, audit failures use `UNAVAILABLE`, and bounded
resource overload uses `RESOURCE_EXHAUSTED`. Messages are limited to 64 MiB.

## Create, insert, and search with grpcurl

Create a collection:

```bash
grpcurl -plaintext \
  -d '{"config":{"name":"products","vectorDim":3,"metric":"cosine","shards":1,"replicas":1}}' \
  127.0.0.1:7402 chirondb.v1.ChironDb/CreateCollection
```

Insert points. gRPC payloads use `payloadJson` because the compatibility
protobuf stores arbitrary JSON as a string:

```bash
grpcurl -plaintext \
  -d '{
    "collection":"products",
    "points":[
      {"id":"phone","vector":[1,0,0],"payloadJson":"{\"category\":\"electronics\",\"price\":699}"},
      {"id":"book","vector":[0,0,1],"payloadJson":"{\"category\":\"media\",\"price\":15}"}
    ]
  }' \
  127.0.0.1:7402 chirondb.v1.ChironDb/Upsert
```

`noWait:false` is the safe protobuf default. Success is returned only after the
request WAL and required filesystem metadata are synchronized. Set it to
`true` only when losing the recent unflushed suffix after a crash is acceptable;
the internal background flusher runs every 200 ms.

Search:

```bash
grpcurl -plaintext \
  -d '{
    "collection":"products",
    "query":{"vector":[1,0,0],"k":2,"filterJson":"{\"category\":\"electronics\"}"}
  }' \
  127.0.0.1:7402 chirondb.v1.ChironDb/Search
```

Common RPCs include `Health`, `CreateCollection`, `ListCollections`,
`DeleteCollection`, `UpdatePayloadSchema`, `Upsert`, `GetPoints`, `SetPayload`,
`Delete`, `DeleteByFilter`, `Search`, `HybridSearch`, `MultiSearch`, `Recommend`,
`Count`, `Scroll`, `Compact`, `Snapshot`, and `Restore`. The primary service also
provides graph lifecycle, type-catalog, edge, traversal, and deferred-session
RPCs described below. The proto files are the authoritative field and RPC
reference.

## Copy-paste gRPC request messages

Select the named method under `chirondb.v1.ChironDb`, then paste its JSON into
the request message editor. The `collection` belongs in every collection-scoped
gRPC message because gRPC has no URL path parameters.

### Health and list collections

Use `{}` for both `Health` and `ListCollections`:

```json
{}
```

### CreateCollection

```json
{
  "config": {
    "name": "products",
    "vectorDim": 3,
    "metric": "cosine",
    "shards": 1,
    "replicas": 1,
    "payloadSchema": {
      "category": "string",
      "price": "number"
    }
  }
}
```

### DeleteCollection

```json
{
  "collection": "products"
}
```

### UpdatePayloadSchema

```json
{
  "collection": "products",
  "payloadSchema": {
    "category": "string",
    "price": "number",
    "featured": "optional_bool"
  }
}
```

### Upsert

```json
{
  "collection": "products",
  "points": [
    {
      "id": "phone",
      "vector": [1.0, 0.0, 0.0],
      "payloadJson": "{\"category\":\"electronics\",\"price\":699}"
    },
    {
      "id": "book",
      "vector": [0.0, 0.0, 1.0],
      "payloadJson": "{\"category\":\"media\",\"price\":15}"
    }
  ],
  "noWait": false
}
```

`payloadJson` is a string containing JSON, so quotes inside it must be escaped.
`noWait: false` waits for WAL and required filesystem metadata synchronization
and is the safe default. `noWait: true` may lose only a recent suffix after a
crash; recovery must not produce holes, phantom writes, or corrupt history.

### GetPoints

```json
{
  "collection": "products",
  "ids": ["phone", "book"]
}
```

### SetPayload

```json
{
  "collection": "products",
  "id": "phone",
  "payloadJson": "{\"featured\":true,\"price\":649}",
  "merge": true
}
```

### Delete and DeleteByFilter

Use this message with `Delete`:

```json
{
  "collection": "products",
  "ids": ["book"]
}
```

Use this message with `DeleteByFilter`:

```json
{
  "collection": "products",
  "filterJson": "{\"category\":\"archived\"}"
}
```

### Search

```json
{
  "collection": "products",
  "query": {
    "vector": [1.0, 0.0, 0.0],
    "k": 5,
    "filterJson": "{\"category\":\"electronics\"}",
    "budgetMs": 100,
    "recallTarget": 0.95
  }
}
```

### HybridSearch

```json
{
  "collection": "products",
  "vector": [1.0, 0.0, 0.0],
  "useDenseVector": true,
  "sparseVector": {
    "indices": [12, 98],
    "values": [1.2, 0.7]
  },
  "k": 5,
  "filterJson": "{\"category\":\"electronics\"}",
  "fusion": "rrf",
  "denseWeight": 1.0,
  "sparseWeight": 1.0
}
```

Set `useDenseVector` to `false` when intentionally sending a sparse-only
query. Sparse `indices` and `values` must have equal lengths.

### Native graph overlay

Graph RPCs exist only on `chirondb.v1.ChironDb`; the deprecated
`gaussdb.v1.GaussDb` service remains frozen. The primary service exposes
`EnableGraph`, `DropGraph`, `ListEdgeTypes`, `ConfigureEdgeType`, `Relate`,
`Unrelate`, `UpdateEdge`, `Traverse`, and the five explicit deferred-session
operations. All call the same scoped engine as HTTP and ChironQL.

Enable graph and configure a type:

```json
{"collection":"products","noWait":false}
```

```json
{
  "collection":"products",
  "name":"references",
  "weightProperty":"strength",
  "noWait":false
}
```

Create an edge with `Relate`:

```json
{
  "collection":"products",
  "sourcePointId":"phone",
  "targetPointId":"book",
  "edgeType":"references",
  "propertiesJson":"{\"strength\":0.8}",
  "scope":"local",
  "noWait":false
}
```

The returned `edgeId` is an opaque URL-safe token. Store and return it unchanged
to `UpdateEdge` or `Unrelate`; do not parse, sort, or infer topology from it.
Mutation receipts carry the actual `graphEpoch`, optional `operationLsn`,
`durable`, and `replayed` values. As elsewhere in the gRPC API,
`noWait:false` is the durable default.

`Traverse.requestJson` contains one JSON-encoded
`GraphTraversalQueryRequest`, preserving the HTTP/ChironQL fields and caps:

```json
{
  "collection":"products",
  "requestJson":"{\"anchors\":[\"phone\"],\"edge_types\":[\"references\"],\"returns\":\"edges\",\"limit\":10}"
}
```

The response includes the complete result in `resultJson` plus typed
`graphEpoch`, `statsJson`, optional `truncation`, and `warnings` fields.

Dense and hybrid retrieval accept an additive optional `graphJson` string:

```json
{
  "collection":"products",
  "query":{
    "vector":[0.0,0.0,1.0],
    "k":5,
    "graphJson":"{\"anchors\":[\"phone\"],\"edge_types\":[\"references\"]}"
  }
}
```

Graph-constrained responses return the common planner/expansion/fusion trace in
`graphJson`. The additive wire numbers are `SearchQuery.graph_json = 8`,
`HybridSearchRequest.graph_json = 12`, and `SearchResponse.graph_json = 5`.

Graph access requires explicit `graph:read`, `graph:write`, `graph:admin`, or
`graph:type_configure` capabilities independently from point roles. Collection
allowlists and authenticated tenant scope are still enforced during expansion.
Denials use `PERMISSION_DENIED`; graph failures carry the stable `graph.*` code,
message, optional item index, and retry hint as JSON in gRPC status details.

### MultiSearch

```json
{
  "collection": "products",
  "searches": [
    {"vector": [1.0, 0.0, 0.0], "k": 10},
    {"vector": [0.8, 0.2, 0.0], "k": 10}
  ],
  "fusion": "weighted",
  "fusedK": 5,
  "weights": [0.7, 0.3]
}
```

### Recommend

```json
{
  "collection": "products",
  "positive": ["phone"],
  "negative": ["book"],
  "k": 5,
  "filterJson": "{\"category\":\"electronics\"}"
}
```

### ExecuteQuery (ChironQL)

One ChironQL statement per call. The language reference is
[CHIRONQL.md](CHIRONQL.md).

Unlike every other rpc on this service, `ChironQlRequest` and
`ChironQlResponse` live in `chirondb.v1` rather than `gaussdb.v1`: ChironQL is
a new surface, and the legacy `gaussdb.v1.GaussDb` service is frozen at what it
shipped with, so it does not serve this rpc.

```bash
grpcurl -plaintext -d '{
  "query": "SEARCH products NEAR [1,0,0] LIMIT 5 WITH PAYLOAD;",
  "trace": true
}' 127.0.0.1:7402 chirondb.v1.ChironDb/ExecuteQuery
```

Rows, stats and the trace come back as JSON strings — payloads are arbitrary
JSON and protobuf has no native equivalent, the same reason `filter_json` is a
string elsewhere in this API:

```json
{
  "kind": "rows",
  "columns": ["id", "score", "payload"],
  "rowsJson": ["{\"id\":\"phone\",\"score\":0.9987,\"payload\":{}}"],
  "statsJson": "{\"took_ms\":3.1,\"searched\":1412,\"degraded\":false}",
  "queryId": "q_1a013b57ee2001"
}
```

`chirongrpcctl query` reassembles those into one JSON document:

```bash
chirongrpcctl --endpoint http://127.0.0.1:7402 query \
  "SEARCH products NEAR [1,0,0] LIMIT 5;" --trace
```

**Errors** arrive as a `Status` whose details carry the whole ChironQL error —
code, hint, caret position and the trace up to the failing stage — so a gRPC
caller loses nothing by not being an HTTP caller:

| Status code | When |
| --- | --- |
| `INVALID_ARGUMENT` | Parse reject or bad request |
| `PERMISSION_DENIED` | A write statement on a read-only caller |
| `NOT_FOUND` | Collection, point or named vector missing or not visible |
| `FAILED_PRECONDITION` | The statement is waiting on confirmation |
| `RESOURCE_EXHAUSTED` | Resource exhausted |
| `INTERNAL` | Storage or I/O failure |

`DELETE ... WHERE` counts first and refuses with `FAILED_PRECONDITION` and an
`affected_estimate` until `confirm: true` is set. Nothing is deleted by the
refused call.

### Count and Scroll

Use this message with `Count`:

```json
{
  "collection": "products",
  "filterJson": "{\"category\":\"electronics\"}"
}
```

Use this message with `Scroll`:

```json
{
  "collection": "products",
  "offset": "",
  "limit": 100,
  "filterJson": ""
}
```

Pass the response's `nextOffset` into the next request's `offset`. An empty
`nextOffset` means there are no more pages.

### Compact and maintenance RPCs

Use this message with `Compact` or `TierCold`:

```json
{
  "collection": "products"
}
```

Use this message with `PruneWalArchive`:

```json
{
  "collection": "products",
  "retainLast": 10
}
```

Snapshot and restore need the [snapshot root setup](HTTP_API.md#create-and-restore-a-snapshot).
The name below is relative to that root. Create the snapshot first, and restore
only when you intend to replace the live database with its saved state.

Use this message with `Snapshot`:

```json
{
  "path": "beta-smoke"
}
```

Use this message with `Restore`:

```json
{
  "path": "beta-smoke",
  "targetWalLsns": {},
  "targetWalUnixMs": {}
}
```

Archive-backed `Restore` preserves original collection-WAL LSNs and timestamps.
With `walRestoreArchiveDir` or `walRestoreObjectStoreDir`, target LSNs may
extend beyond the snapshot only through verified contiguous archive history.
Matching overlap is skipped; gaps, conflicting overlap/names and unsupported
plaintext-to-encrypted frame conversion reject before installation. Timestamp
targets select a contiguous prefix, including when the source clock moves back.
Graph-bearing seals archive their immutable WAL cut and finish configured mirrors
before the corresponding live prefix can retire; retention runs afterward. For a
backward target below the retained base, restore may reconstruct the WAL only in
its uninstalled staging generation when snapshot-local/imported archives provide
a checked contiguous chain from LSN 0. Gaps or divergence reject, so configured
archive retention bounds the available historical PITR window.

Use `{}` with `ShardMove`; it is a single-node no-op in this beta. Snapshot and
restore paths are paths on the ChironDB server or inside its container.
They must remain beneath configured `snapshot_root`; the RPCs are disabled
without a backing root and require an `admin` principal.
Restore drains in-flight operations and atomically installs a fully validated
staged generation. During restore, or after a WAL durability failure, `Health`
and data operations that cannot be served safely return gRPC `Unavailable`.

These guarantees assume local storage honors `fsync`. Replication, WAL
streaming, and quorum acknowledgement remain experimental scaffolding and are
not part of the single-node durability contract.

### Protobuf JSON rules

- `payloadJson` and `filterJson` contain JSON encoded as strings. Escape their
  inner double quotes as shown above.
- Omit optional fields you do not need. An empty `filterJson` means no filter,
  and an empty scroll `offset` starts at the beginning.
- Protobuf tools may render 64-bit integer fields as quoted decimal strings in
  responses. Standards-compliant clients accept those values when reused in a
  later request.
- A point's dense vector length must equal the collection's `vectorDim`.
- `Rerank` and HTTP batch search are HTTP-only beta endpoints; they are not RPCs
  on `chirondb.v1.ChironDb`.

## Bundled gRPC command-line client

Build the client from the repository root, then add the release directory to
`PATH` in this terminal:

```bash
cargo build --release --locked -p chirondb --bin chirongrpcctl
export PATH="$PWD/target/release:$PATH"
```

Against a running server, use an unused collection name for this recipe:

```bash
chirongrpcctl health
chirongrpcctl reflect-services
chirongrpcctl create-collection products 3 --metric cosine
chirongrpcctl insert products phone 1,0,0 \
  --payload '{"category":"electronics","price":699}'
chirongrpcctl search products 1,0,0 -k 2
```

Use `--endpoint`, `--api-key`, and the TLS options before the subcommand:

```bash
chirongrpcctl --endpoint https://db.example.com:7402 \
  --api-key "$CHIRONDB_API_KEY" \
  --ca-cert ./ca.pem health
```

Run `chirongrpcctl --help` and `chirongrpcctl <command> --help` for the exact
options included in your installed version.

## Generate a client

Generate both proto files so the primary service can resolve its reused
`gaussdb.v1` messages. From the repository root, activate the
[Python virtual environment](SDKS.md#python) first:

```bash
python -m pip install grpcio grpcio-tools
mkdir -p generated
python -m grpc_tools.protoc \
  -I proto \
  --python_out=generated \
  --grpc_python_out=generated \
  proto/chirondb/v1/compat.proto \
  proto/chirondb/v1/chirondb.proto
```

Other protobuf/gRPC toolchains should receive the same include path and both
input files. ChironDB does not yet publish generated gRPC packages, so pin the
schema files to the server release tag used by your application.

When regenerating Python clients, import shared messages from
`chirondb.v1.compat_pb2`; the primary stub is in
`chirondb.v1.chirondb_pb2_grpc`. Add the generated directory to your Python
import path. Existing compiled clients can continue using their original
modules and protocol names.

## gRPC-Web preview

Native gRPC is the supported beta path. Direct gRPC-Web is disabled by default
and remains a preview enabled with `--enable-grpc-web` plus explicit allowed
origins. Do not put a shared server API key in browser JavaScript; use the
preview BFF or another trusted gateway for browser authentication.

## Native text hybrid retrieval

Both `chirondb.v1.ChironDb` and the compatibility service `gaussdb.v1.GaussDb`
expose `TextHybridSearch(gaussdb.v1.TextHybridSearchRequest)`, returning the
existing `gaussdb.v1.SearchResponse`. Regenerate clients from both proto files
to use the new RPC. Existing RPCs and message field numbers are unchanged.

```protobuf
message TextHybridSearchRequest {
  string collection = 1;
  repeated float vector = 2;
  string query = 3;
  string text_field = 4;
  uint64 k = 5;
  string filter_json = 6;
  optional uint64 budget_ms = 7;
}
```

Pass the question embedding in `vector`, its text in `query`, and a top-level
string payload field in `text_field`. Set `k` explicitly (`0` returns no hits).
Use an empty `filter_json` for no filter, or an encoded JSON filter such as
`{"department":"service"}`. Authentication and tenant scope come from the
request credential. BM25 requires no caller-generated sparse vectors. See the
[HTTP contract](HTTP_API.md#native-text-hybrid-search) for retrieval and budget
semantics. ChironWire carries this same message in `WireRequest.text_hybrid_search`
(tag `32`) and returns the existing search response payload.
