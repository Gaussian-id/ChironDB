# ChironDB gRPC API

Protected user/role/key syntax, every statement example, revision semantics and
working TLS/API recipes: [ChironQL security reference](CHIRONQL_SECURITY.md).

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

## Native relational SQL preview

`chirondb.v1.ChironDb/ExecuteSql` accepts an atomic list of `SqlStatement`
messages. `SqlValue` is a protobuf `oneof`, so parameters and result rows retain
their boolean, integer, floating, decimal, text, bytes, date, UTC timestamp,
UUID, JSONB, vector, record-reference, or NULL type without string inference.
The additive fields are `bytes_value` (raw protobuf bytes), `date` (ISO
`YYYY-MM-DD`), and `jsonb` (validated JSON text).

```bash
grpcurl -plaintext -d '{
  "statements": [{
    "sql": "INSERT INTO documents VALUES ($1, $2)",
    "parameters": [
      {"integer": "7"},
      {"text": "Native SQL"}
    ]
  }],
  "retryId": "b2fdf70e-d474-476d-a1fa-f17b68f0d09e"
}' 127.0.0.1:7402 chirondb.v1.ChironDb/ExecuteSql
```

The RPC reaches the same executor and durable transaction journal as HTTP.
Each statement entry must be consumed completely. Multiple statements in one
entry or a trailing block terminator such as `INSERT INTO items VALUES (1) END`
reject before mutation. Use separate statement entries for an atomic batch.
`SqlExecutionRequest.idempotency_key` is optional field 3. It uses the same core
ledger as HTTP and ChironWire: identical SQL/parameters under the same installation,
principal and tenant return the original transaction decision and results.
`retry_id` remains audit correlation. A different fingerprint rejects; an expired
24-hour receipt never releases its consumed key. This currently covers standalone
mutating SQL; read-only and interactive statement requests reject the option.
See the [HTTP retry contract](HTTP_API.md#native-relational-sql-preview).

Supported ordered-page queries share the core encrypted-spill admission rules:
merge heads, expanded JSON values and decoding scratch are bounded before
allocation. Quota refusal returns `RESOURCE_EXHAUSTED`; scratch files are cleaned
up. See the [SQL resource contract](HTTP_API.md#native-relational-sql-preview).

Decoded disk-row values and version-chain metadata also use shared storage
admission and retain their reservations while readers hold them. Metadata copies
and growth are admitted before allocation. Checkpoint loading also admits parser
scratch and decoded schema/history/legacy rows before allocation; refused loads
leave the checkpoint unchanged. Storage-budget refusal returns
`RESOURCE_EXHAUSTED`. Checkpoint output also admits serialization/encryption
buffers and preserves atomic replacement. Capture and manifest/reference copies
retain their own metadata reservations. A capture refusal after commit preserves
the committed receipt and recoverable WAL. Runtime table schemas retain their
storage reservations across recovery, snapshots and prepared conflict checks;
ordinary row mutations share them. Schema-retention refusal rejects CREATE/ALTER
before commit and preserves the previous table. Scalar-index type metadata and
per-table index maps also retain reservations; mutation map copies are admitted
before allocation. Checkpoint replacement maps are prepared before publication.
Runtime table-name catalogs also retain reservations; snapshots and conflict
checks share names and persistent tree roots. Map mutations are admitted before
allocation. Checkpoint activation reserves its map before publication; concurrent
catalog growth can defer activation and WAL reclamation. Relational recovery
validates projection IDs, targets and batches against committed journal decisions
before using the logical sequence frontier for duplicates. Snapshots/checkpoints
no longer retain every past SQL commit ID; legacy lists are validated and discarded.
Durable retry receipts/consumed keys remain in the journal. Recovery verification
also admits cold journal records before reading payloads and retains decode
reservations through validation. New PREPAREs are encoded and decoded under
admission before journal writes or key consumption. A refusal allows retry with
the same key and transaction identity. Returned PREPAREs share immutable data and
its reservation; retained journal scan results and loaded retry receipt payloads
keep their decode reservations. A recovery refusal preserves the durable decision.
Live journal decision maps and active retry claims reserve metadata memory before
PREPARE or key insertion, including capacity for later COMMIT and publication
flags. Eviction retains the charge for allocated buckets; dropping the journal
releases it. Disk decision lookups and checkpoint metadata retain typed decode
reservations through validation and use. Decision flushing serializes borrowed
metadata, and consumed-key hashing streams the existing bytes. Reservations also
include their shared reservation controller overhead; new controllers allocate only
after quota admission. Retained transaction scans reserve container growth and
keep that reservation through consuming iteration. Streaming journal callbacks
can avoid retaining the full scan. Decision-map directory owners reserve path/root
memory before creating directories. Decision checkpoint serialization is bounded
during growth by the existing 64 KiB manifest limit; oversize output preserves
the previous generation.
Slice parser scratch is bounded by the longest encoded token and JSON nesting
depth; retained container admission follows element sizes and growth capacity.
Skipped JSON fields do not create retained container charges. Encryption rejects
plaintext exceeding its authenticated declared length before output growth.
Journal/WAL handles also admit selected path and root memory before startup
file mutations. On required Linux/macOS targets, directory reads use an admitted
fixed 64 KiB caller-owned buffer; inventories separately reserve container growth
and individual paths; filtering is in place, and consuming iterators retain their
container reservation. Moved paths keep admission in archive descriptors/readers.
Frozen descriptors admit their metadata and encoded sidecar copies. `wal.base`
keeps its existing 1 MiB encoded ceiling and now bounds plaintext to its fixed
28-byte format before decoding; admitted write refusal preserves the old frontier.
Checkpoint-prefix range buffers and positioned readers retain selected admission.
Persistence file/path and authenticated header/layout owners now retain admission
through shared file pins and final drop; temporary file-opening scratch releases
after construction. Streaming readers reserve retained chunk,
encoded frame and decrypted replacement overlap before reading the body. Fixed
key-id/wrapped-key lengths are validated before header buffers grow; unwrap errors
zeroize temporary keys. Plaintext-length inspection reads admitted header metadata
without copying the whole encrypted file. WAL reader overload stays a resource error. Returned range
buffers, decrypted cache owners/metadata and mmap residency still need accounting.
Native SQL results retain a shared storage reservation after execution and through
response encoding or PostgreSQL portal use. Retry receipts decode directly into an
admitted typed response. Output-retention refusal occurs before durable COMMIT;
a native COMMIT that has not started PREPARE keeps its live transaction available
for retry. A resource error from an interactive statement aborts that transaction;
use `ROLLBACK` or `ROLLBACK TO` a prior savepoint before repeating the statement.
HTTP, native SQL protobuf, and ChironWire JSON output have an 8 MiB encoding
limit and reserve receiving buffers before growth. A transport encoding failure
can follow a durable commit: reconcile the original key or transaction ID before
retrying a mutation. PostgreSQL wire never automatically retries a mutation.

Multi-model results now retain SQL, allocated binding and edge memory. Response
bindings are admitted and copied before COMMIT; replay decodes a borrowed typed
receipt without re-executing a consumed key. Protected atomic ChironQL retains
that result until publication, rechecks authorization, and reserves JSON row
construction before growth. ChironQL gRPC/ChironWire receiving strings,
containers and codec memory stay reserved through the last outgoing byte owner;
the encoded ChironQL protobuf response is limited to 8 MiB. Refusal while
forming a transport response can follow COMMIT: retain the original key and
reconcile its transaction before attempting the mutation again.

PostgreSQL receiving column/format metadata, row encoding scratch and outgoing
row/description frames reserve memory before allocation and retain it through
pending writes and final ownership. ChironQL SQL/pipeline receiving and HTTP
output also retain their reservations. PostgreSQL input/output buffer overload closes the
connection after its error; it cannot undo a durable COMMIT or authorize mutation replay.
See the PostgreSQL section of [HTTP API](HTTP_API.md) for framing and reconciliation.
PostgreSQL startup/session state and direct request copies now share frontend
admission; raw input and large control frames retain storage/receiving ownership.
Both native/protected wire sessions retain at most 32 prepared statements and
32 portals. Small control replies use fixed stack backing so overload/rollback
replies need no heap admission. Parser/authority and other catalog construction,
TLS/socket and complete engine/process accounting remain separate qualification
requirements.

PostgreSQL catalog probes reserve classification text and a conservative
producer bound before copying display fields. Catalog schemas share their existing
admitted backing without pinning row generations; collection probes copy names,
not full configuration maps. Native routing checks names without constructing a
catalog response or a temporary name set. Catalog results retain their reservation
through sending and native portal caching, until replacement/Close/Deallocate or
disconnect. Producer admission failure returns `53200` and never falls through to
SQL execution. Protected probes use current table identity grants and reacquire
publication permission before sending; denied names are filtered before copying.
These conservative bounds can refuse work before the process RSS limit is reached.

Remaining initial non-SQL engine/receipt conversions, ordinary public WAL payloads/results,
DDL/parser construction, other catalog results, operator scratch, index lookup/key scratch,
remaining mmap/cache/publication/cleanup backing and other SQL allocations still
require accounting. Typed result adoption transfers the existing SQL working-set
reservation; it does not establish allocation accounting for every operator.
These checks do not certify complete process memory
or recovery of every legacy large record under a constrained profile.

`SqlExecutionResponse` preserves the beta `committed` boolean and adds
`outcome`, optional `commit_sequence`, and `retryable`. SQL execution is
limited to 32 statements, an 8 MiB decoded request/write set/result, and
100,000 result rows even though the transport retains its broader 64 MiB
message ceiling for non-SQL APIs.
Its read profile includes non-recursive CTEs plus uncorrelated scalar,
`EXISTS`, and `IN` subqueries; recursive/correlated/lateral forms remain
unsupported. CTE and subquery tables are included in the statement analysis
used before execution.
DDL uses the same native catalog path. This includes dependency-aware
`ALTER TABLE ... DROP CONSTRAINT ... CASCADE`, which atomically removes the
selected PRIMARY KEY/UNIQUE owner and foreign keys bound to that exact owner.
`DROP TABLE ... CASCADE` removes external FK metadata and the target table in
the same journaled catalog batch; RESTRICT remains the default.
`ALTER TABLE ... DROP COLUMN ... CASCADE` performs the row rewrite together
with removal of local dependencies and external referencing FKs; unrelated
child constraints and indexes remain. Multiple comma-separated DROP COLUMN
actions use the same rewrite and transaction decision.
It exists only on the primary `chirondb.v1.ChironDb` service; the deprecated
`gaussdb.v1.GaussDb` service remains frozen. Protected-authority installations
bind relational requests to their durable principal/tenant, enforce table/action
grants and recheck permission before publishing output.
The executor checks current point `read` access for typed `RECORD_REF` writes
and result rows. Point retirement rejects while a live SQL row in that tenant
still refers to it. Standalone SQL supports one referenced point collection per
request; a later revoke or retirement can deny receipt replay without changing
the original commit. Protected SQL result bodies carrying typed references
recheck object access and retain the authority epoch during publication. See the
[protected HTTP contract](HTTP_API.md#protected-authority-preview).
Object-level revocation checks at final transport publication remain open.

Interactive transactions use `BeginSqlTransaction`, `ExecuteSqlTransaction`,
`CommitSqlTransaction`, and `RollbackSqlTransaction`. Pass the returned opaque
`handle` to each later RPC. BEGIN also returns the reserved `transaction_id`,
equal to that handle. Save it before COMMIT. Execute responses have
`committed:false`; COMMIT persists its decision with the same ID even for
empty/read-only transactions. Repeating `CommitSqlTransaction` with the same
handle reconciles that decision across transports and reopen. Receipts are
retained for at least 24 hours; expiry never allows the handle to execute again.
Active handles are principal/tenant-bound, expire after five minutes of inactivity,
and support SQL savepoints. Protected replay rechecks current permission; private
statements and rollback alone do not create a durable journal decision. These RPCs run blocking storage work on the server's
blocking worker pool and reach the same transaction manager as HTTP and
ChironWire. Separate handles can execute concurrently under shared resource admission;
operations on one handle serialize, with a 30-second limit when waiting for that handle.
COMMIT freezes its statements while running; a consumed handle excludes later
EXECUTE/ROLLBACK. Idle expiry releases
snapshot pins during subsequent SQL, handle or checkpoint activity.

If COMMIT fails before PREPARE, including receipt memory admission returning
`RESOURCE_EXHAUSTED`, the live session keeps its private statements and original
handle. Retry `CommitSqlTransaction` explicitly or roll back that handle before
idle expiry. This private state is lost on server restart. Once PREPARE starts,
the handle is consumed and retries reconcile its journal decision.

Transaction history (SQL, decoded parameters, savepoints and replay copies) has
shared and per-transaction byte admission in the core. Capacity is derived from
the runtime profile, up to 64 MiB shared and 16 MiB per transaction including
the active replay copy. Exhaustion returns `RESOURCE_EXHAUSTED`. A history
refusal during Execute aborts the transaction; use `ROLLBACK TO` a retained
savepoint or `RollbackSqlTransaction` to recover. Commit, rollback and idle
expiry release retained history. Parser/operator scratch is outside this budget.

```bash
# Open a session.
grpcurl -plaintext -d '{}' 127.0.0.1:7402   chirondb.v1.ChironDb/BeginSqlTransaction

# Substitute the returned handle.
grpcurl -plaintext -d '{
  "handle":"HANDLE",
  "request":{"statements":[{"sql":"SELECT id FROM documents LIMIT 10"}]}
}' 127.0.0.1:7402 chirondb.v1.ChironDb/ExecuteSqlTransaction

grpcurl -plaintext -d '{"handle":"HANDLE"}' 127.0.0.1:7402   chirondb.v1.ChironDb/CommitSqlTransaction
```

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

Legacy `hnswM`, `hnswEfConstruction` and `hnswEfSearch` fields retain
zero-as-default compatibility. `hnswM=1` returns `INVALID_ARGUMENT` before
collection mutation. Omitting these fields uses the engine defaults.

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
An omitted graph memory budget uses the process-profile share described in the
[HTTP traversal contract](HTTP_API.md#property-graph-overlay); supplied non-default
limits remain exact.

Graph access requires explicit `graph:read`, `graph:write`, `graph:admin`, or
`graph:type_configure` capabilities independently from point roles. Collection
allowlists and authenticated tenant scope are still enforced during expansion.
Denials use `PERMISSION_DENIED`; graph failures carry the stable `graph.*` code,
message, optional item index, and retry hint as JSON in gRPC status details.

Graph point hydration errors abort traversal and graph-constrained ranking rather
than omitting failed points. Node, edge and path results share this contract.
Mutation validation retains storage errors before committing a graph batch.
Protected endpoint visibility precedes payload reads, and protected failures
retain the existing sanitized error contract. Legacy traversal work-budget
truncation remains explicit and unchanged.

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

One top-level ChironQL 1.4 statement per call. A typed `TRANSACTION { ... }`
block remains one statement and atomically combines SQL DML, vector UPSERT/DELETE or protected CREATE POINTS,
and graph relations. `parameters` carries typed `$1…$n` values; `retry_id` is
audit correlation. Optional `idempotency_key` (field 7; ChironWire field 8) uses
the shared core ledger for standalone SQL mutations and atomic `TRANSACTION` blocks. Identical logical
requests under the same principal/tenant return the original transaction decision
across transports. Other statement families currently reject a supplied key.
A rejected standalone SQL decision returns `committed: false`. Rejected multi-model
decisions return `ABORTED` with `chironql.transaction_rejected` and the original ID/status
hint. Multi-model replay includes the same `edge_id` rows and `stats.replayed: true`;
its collection WAL position is absent. Uncertain commits return
`UNAVAILABLE` with `chironql.outcome_unknown` and a reconciliation hint.
The response adds column
types, execution domains, snapshot and transaction metadata. Protected `ExecuteQuery` graph stages
inside `PIPELINE` accept node/edge filters and `RETURN NODES`, with current endpoint/field authority
and publication guards; see [protected graph filters](CHIRONQL_SECURITY.md#protected-graph-filters). The language reference is
[CHIRONQL.md](CHIRONQL.md).

Optional `EXPECT SQL ROWS n;` immediately after a transaction's SQL stage guards sibling
vector/graph writes with the directly affected SQL row count. This is useful with revision
predicates. A mismatch returns `chironql.sql_row_precondition_failed` before the durable
commit decision; it has no committed receipt. Preserve the guard when retrying a consumed
key. Requests without it retain existing zero-row semantics. The same query text works on
all ChironQL transports and SDKs; older servers reject the stage before mutation.
See [row preconditions](CHIRONQL.md#sql-row-preconditions).

ChironQL SQL receiving rows, retrieval JSON rows, pipeline alias/join/sort/projection
allocations and output handoffs carry conservative process reservations. GET,
SCROLL, hit and graph conversion reserve containers/numeric arrays before growth
and move payloads and IDs. Protected conversion retains the source owner, polls
current authority during receiving work and rechecks it before publication.
Numeric/nested arrays poll cancellation at least every 1,024 items. Response
fields, omitted graph payloads and numeric JSON semantics remain unchanged. Limits can reject a
query with `chironql.resource_exhausted`; protected publication checks the current
authority again. Integer pipeline sort preserves exact integer order. HTTP,
gRPC and ChironWire encoding is capped at 8 MiB. A receiving/encoding failure
can follow COMMIT: reconcile the original key or transaction ID before retrying
that mutation. Conservative operation reservations remain until output consumption.

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
| `ABORTED` | A pipeline visibility frontier changed before publication |
| `UNAVAILABLE` | A common snapshot cannot start while commit publication is active |
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
Native snapshots include installation transaction control alongside the active
content generation, preserving copied SQL and collection state on reopen.
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

### Protected ChironQL 1.4 local preview

ChironQL **1.4** also exposes protected collection provisioning and typed policy
administration through this same RPC. Initialize the first administrator offline
using the [deployment runbook](../deploy/protected/README.md). Collection creation
uses `SHOW CATALOG REVISION`; policy updates use the collection security revision.
Neither operation grants document access to the administrator.

On a protected single-node installation, `chirondb.v1.ChironDb/ExecuteQuery`
executes the same authenticated ChironQL administration and data subset as HTTP.
`ExecuteSql`, `BeginSqlTransaction`, `ExecuteSqlTransaction`,
`CommitSqlTransaction`, and `RollbackSqlTransaction` also use the protected
identity catalog. `ExecuteQuery` accepts `GRANT ... ON TABLE ... TO ROLE ...
IF REVISION n` after the offline [table-authority migration](CHIRONQL_SECURITY.md#protected-relational-sql).
Those grants bind table ID and incarnation independently of vector collections.
After offline `migrate-sql-scopes`, collection-name permissions no longer
allow SQL. Existing permissions become exact table roles; newly created tables
confer SQL data rights on their immutable creator. Older receipts without saved
table authorization are denied without re-execution. See the
[strict migration contract](CHIRONQL_SECURITY.md#protected-relational-sql).

Exact table grants map Read/Create/Update/Delete to
SELECT/INSERT/UPDATE/DELETE, DDL requires installation action Schema, and the
identity publication guard remains attached through the encoded response body.
Use verified TLS and one API-key metadata header. Each RPC reauthenticates, including
RPCs on an already-open channel. Duplicate credential aliases are rejected. Legacy
`GaussDb` RPCs and other operations without a protected implementation remain closed.
Protected bounded dense/BM25/text-hybrid pipelines and INSERT/UPDATE/DELETE atomic multi-model blocks use the
same core as HTTP. Server-ID INSERT returns binding/reference/edge rows in `rows_json` and keeps
them on keyed replay. Graph schema commands require collection Schema and a current security
revision. See [atomic INSERT](CHIRONQL.md#protected-atomic-insert). Protected graph stages support
node/edge filters with node-only output. Standalone protected ChironQL `TRAVERSE` supports
nodes, edges and paths with authorized payloads; paths require `LIMIT`. See
[protected filters](CHIRONQL_SECURITY.md#protected-graph-filters).
Numeric sparse hybrid remains unavailable. PostgreSQL wire
uses the same protected authority after TLS `SSLRequest` and a separate
`SCRAM-SHA-256` SQL password; gRPC continues to use bearer credentials.

`ChironQlResponse.credential_json` is optional field **8**, added without changing
fields 1–7. It contains `{id, secret}` only after ISSUE/ROTATE API KEY. Never log or
render this field; consume it once into protected storage. All other responses omit
it. ChironWire `WireChironQlResponse` uses the same additive field 8 and execution
contract. The legacy service definition remains frozen.

Security mutations require `IF REVISION n`; read it using `SHOW SECURITY REVISION`
or `SHOW SECURITY REVISION ON COLLECTION name` for object ACL/label operations.
Do not automatically retry revision conflicts or credential issuance. Revoke invalidates
queued output before acknowledgement; publication is checked while encoding/body frames
are handed to the transport. Refer to [protected ChironQL administration](HTTP_API.md#protected-chironql-administration-language-12)
for grammar, key lifecycle, migration and the supported protected data subset.

## Protected native Point reads

On a protected installation, the primary `chirondb.v1.ChironDb` service also
accepts `GetPoints` and `Scroll`. ChironWire accepts the corresponding `get_points`
and `scroll` operations. They use the same `read` scope, object policy, visible
representations and payload projection as the protected HTTP routes. Supply one
API-key metadata header on gRPC or `WireRequest.api_key` on ChironWire; tenant and
principal come from that credential. Client identity overrides are rejected.
The compatibility `gaussdb.v1.GaussDb` service remains closed in protected mode.

`GetPoints` accepts at most 1,024 public IDs, preserves request order, and omits
absent or hidden points. `Scroll` defaults to 100 rows when protobuf `limit` is
zero, accepts up to 1,024 rows, and sorts by public ID. Pass its `next_offset` as
the next `offset`; an empty `next_offset` marks the last page. Filters obey the
same protected field-query rules as HTTP. Internal storage IDs are never returned.
The existing protobuf messages and field numbers are unchanged.

Protected Point copies, receiving protobuf containers/payload strings and encoding
workspace reserve shared memory before allocation. Responses retain that admission
through queuing and delivery, with authorization checked at publication and body
writes. Memory exhaustion or an encoded response over 8 MiB rejects the request;
an unreadable Point aborts the response. These bounds do not certify W0 process
memory or complete production readiness.

## Native text hybrid retrieval

Protected installations admit this RPC on the primary `chirondb.v1.ChironDb`
service with the authority rules below. The compatibility `gaussdb.v1.GaussDb`
service remains unavailable on protected installations. Legacy installations
use RBAC/tenant authorization.

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

An empty `vector` selects BM25 alone with raw BM25 scores. Protected installations
admit this method on `chirondb.v1.ChironDb` and ChironWire after binding the
credential to collection Search and per-object/per-field query authority. They
retain authorization through response publication. Only hits carry data;
`searched=0`, `elapsed_ms=0`, `degraded=false` are fixed compatibility defaults,
not measured diagnostics. Revocation/cancellation/budget exhaustion returns an
error without partial hits. The legacy `gaussdb.v1.GaussDb` service remains
unavailable on protected installations. See the protected rules in the HTTP
contract for corpus statistics, projected payloads and current scale limits.

Point hydration failures in native get, scroll, count, sparse retrieval and text
retrieval abort the affected request; they do not become missing points or a
successful partial response. Legitimately absent or hidden points retain their
existing behavior. Protected text retrieval on gRPC and ChironWire uses sanitized
error codes and details that omit storage paths and internal admission diagnostics.
This does not change legacy dense search budget/degraded-result semantics.
