# ChironDB HTTP API

ChironDB serves JSON over HTTP on port `7401`. New applications should use the
versioned `/v1` routes. The matching unversioned routes remain available during
the GaussDB compatibility period.

## Connect

Follow [build and startup](GETTING_STARTED.md#1-build-and-start) first. Leave
the server running in its terminal, then confirm its version from another:

```bash
curl --fail --connect-timeout 2 http://127.0.0.1:7401/health
```

The reference sections are independent recipes. Create `products` and insert
the two points below before running queries. Deletion, schema replacement, and
restore change that setup; re-create it before trying another recipe. For a
single ordered walkthrough, use [Getting started](GETTING_STARTED.md).

`GET /health` and `GET /v1/health` do not require authentication. A healthy
response includes only `status` and `version`; filesystem paths and collection
counts are available only through authenticated operational surfaces.

All data and administration routes require a key when the server starts with
`CHIRONDB_API_KEY` or `--api-key`:

```bash
curl --fail http://127.0.0.1:7401/v1/collections \
  -H "Authorization: Bearer $CHIRONDB_API_KEY"
```

`x-chirondb-api-key` is also accepted. The deprecated `x-gaussdb-api-key`
header remains available during the beta. A non-loopback listener fails startup
unless TLS, API credentials, RBAC with stable principal IDs, and an external
encryption keyring are configured. `CHIRONDB_ALLOW_INSECURE_NON_LOOPBACK=true`
is a logged/audited development escape hatch, not a production profile.

## Postman and other REST clients

Create these optional environment variables in your API client:

| Variable | Local value |
| --- | --- |
| `base_url` | `http://127.0.0.1:7401` |
| `collection` | `products` |
| `api_key` | The value of `CHIRONDB_API_KEY`, when authentication is enabled |

For each request:

1. Select the HTTP method shown in this guide and use a URL such as
   `{{base_url}}/v1/collections/{{collection}}/search`.
2. Select **Body → raw → JSON** and paste the JSON payload. Field names are
   case-sensitive and use `snake_case`.
3. Set `Content-Type: application/json` for requests with a JSON body.
4. If authentication is enabled, select **Authorization → Bearer Token** and
   enter `{{api_key}}`. Alternatively, add `x-chirondb-api-key: {{api_key}}`.

Local HTTP is plaintext. Use an `https://` URL and a trusted certificate for
any server exposed outside a trusted local network.

## Create a collection

```bash
curl --fail -X POST http://127.0.0.1:7401/v1/collections \
  -H 'Content-Type: application/json' \
  -d '{
    "name":"products",
    "vector_dim":3,
    "metric":"cosine",
    "shards":1,
    "replicas":1,
    "payload_schema":{"category":"string","price":"number"}
  }'
```

Supported metrics are `cosine`, `l2`, and `dot`. LS-VEC is the sole/default
index path; clients do not select HNSW as a separate persisted index.

List or delete collections:

```bash
curl --fail http://127.0.0.1:7401/v1/collections
curl --fail -X DELETE http://127.0.0.1:7401/v1/collections/products
```

## Insert or update points

```bash
curl --fail -X PUT http://127.0.0.1:7401/v1/collections/products/points \
  -H 'Content-Type: application/json' \
  -d '{
    "points":[
      {
        "id":"phone",
        "vector":[1.0,0.0,0.0],
        "sparse_vector":{"indices":[12,98],"values":[1.2,0.7]},
        "payload":{"category":"electronics","price":699}
      },
      {
        "id":"book",
        "vector":[0.0,0.0,1.0],
        "payload":{"category":"media","price":15}
      }
    ],
    "wait":true
  }'
```

`wait:true` is the safe default. A successful response means the request's WAL
record and required filesystem metadata have been synchronized; under the
documented local-storage assumptions, that acknowledged write survives a
process crash. `wait:false` returns `202 Accepted` and relies on the internal
200 ms background WAL flush. A crash may lose only the recent unflushed suffix;
recovery still rejects holes, phantom writes, and corrupt sealed history.

Graph-aware SDKs use this same endpoint for structural nodes and add
`X-Chiron-Structural-Points: 1`. That typed path rejects an all-zero unnamed
vector before WAL append; derive the vector from the node ID or label. A
compatibility import may additionally send
`X-Chiron-Unsafe-Structural-Embedding-Reason` as URL-safe, unpadded base64.
The decoded reason must be non-empty and at most 1,024 bytes. A successful
typed response adds `operation_lsn` and `unsafe_override_audited`; the durable
audit record contains the reason, actor, collection, counts, and SHA-256 point
ID digests, never raw point IDs. Generic upsert behavior and response shape are
unchanged.

Fetch points by ID:

```bash
curl --fail -X POST http://127.0.0.1:7401/v1/collections/products/points/get \
  -H 'Content-Type: application/json' \
  -d '{"ids":["phone","book"]}'
```

## Search

```bash
curl --fail -X POST http://127.0.0.1:7401/v1/collections/products/search \
  -H 'Content-Type: application/json' \
  -d '{
    "vector":[1.0,0.0,0.0],
    "k":2,
    "filter":{"category":"electronics"},
    "with_payload":true
  }'
```

The response contains `hits`, `degraded`, `searched`, and `elapsed_ms`. Each hit
contains `id`, `score`, and `payload`. Vector length must match the collection's
`vector_dim`.

Optional search fields include `vector_name`, `budget_ms`, `consistency`,
`ef_search`, `recall_target`, and `with_payload`. Prefer the collection defaults
unless a measured use case requires an override.

### Filter payloads

Filters are JSON objects keyed by payload field. Multiple fields are combined
with AND. A scalar means equality; the supported operators are `eq`, `ne`,
`gt`, `gte`, `lt`, `lte`, `in`, `text`, and `nested`.

```json
{
  "category": {"in": ["electronics", "appliances"]},
  "price": {"gte": 100, "lt": 1000},
  "description": {"text": "wireless phone"}
}
```

Nested fields can use dot notation such as `seller.country`. Filters are used
as the value of `filter` in search, count, scroll, rerank, recommendation, and
delete-by-filter bodies.

## Count and paginate

```bash
curl --fail -X POST http://127.0.0.1:7401/v1/collections/products/count \
  -H 'Content-Type: application/json' \
  -d '{"filter":{"category":"electronics"}}'

curl --fail -X POST http://127.0.0.1:7401/v1/collections/products/scroll \
  -H 'Content-Type: application/json' \
  -d '{"limit":100}'
```

Pass `next_offset` from a scroll response as the next request's `offset`.
ChironDB cursors are ID-based rather than numeric page offsets. A null
`next_offset` means the final page was returned.

## Delete data

Delete selected IDs:

```bash
curl --fail -X POST http://127.0.0.1:7401/v1/collections/products/points/delete \
  -H 'Content-Type: application/json' \
  -d '{"ids":["book"]}'
```

Delete by filter:

```bash
curl --fail -X POST http://127.0.0.1:7401/v1/collections/products/points/delete/filter \
  -H 'Content-Type: application/json' \
  -d '{"filter":{"category":"archived"}}'
```

## Additional copy-paste request bodies

The examples below are the complete raw JSON body to paste into Postman or
another REST client. Replace `products` in the URL, not in the body, for all
collection-scoped HTTP routes.

### Replace the payload schema

`PUT /v1/collections/products/payload_schema`

```json
{
  "payload_schema": {
    "category": "string",
    "price": "number",
    "featured": "optional_bool"
  }
}
```

Supported base types are `string`, `number`, `bool`, `object`, and `array`.
Each also has `optional_...` and `nullable_...` forms.

### Merge or replace one point's payload

`POST /v1/collections/products/points/payload`

```json
{
  "id": "phone",
  "payload": {
    "featured": true,
    "price": 649
  },
  "merge": true
}
```

`merge` defaults to `true`. Set it to `false` to replace the entire payload.

### Batch dense search

`POST /v1/collections/products/search/batch`

```json
{
  "searches": [
    {
      "vector": [1.0, 0.0, 0.0],
      "k": 2,
      "with_payload": true
    },
    {
      "vector": [0.0, 0.0, 1.0],
      "k": 2,
      "filter": {"price": {"lte": 100}}
    }
  ]
}
```

### Native text hybrid search

`POST /v1/collections/{collection}/text_hybrid_search` (also available without
`/v1`) combines the supplied query vector with native BM25 over a top-level
string payload field and returns the usual `SearchResponse`.

```json
{
  "vector": [1.0, 0.0, 0.0],
  "query": "refund policy",
  "text_field": "text",
  "k": 5,
  "filter": {"department": "service"},
  "budget_ms": 30000
}
```

The vector must match the collection dimension and the model/preprocessing used
at ingestion. Store document text in the named payload field; no `sparse_vector`
is needed. Both retrieval branches exclude points without a string in that
field, apply tenant and user filters, and combine ranks using RRF. Tenant-scoped
BM25 statistics exclude other tenants; ordinary filters select results without
redefining the scoring corpus. Payload changes and deletes update the text index.

`vector`, `query`, `text_field`, and `k` are required. Query text is limited to
8,192 UTF-8 bytes; `k=0` returns no hits. `filter` and `budget_ms` are optional;
the default search budget is 30,000 milliseconds.
Unknown fields, including graph and named-vector options, are rejected. Ranking
scores are not probabilities. `degraded=true` means the search was interrupted
or exhausted its budget. Existing `hybrid_search` sparse dimensions retain their
original meaning.

For natural-language input with server-side embedding, use the
[MCP interface](SDKS.md#mcp-clients).

### Hybrid dense and sparse search

`POST /v1/collections/products/hybrid_search`

```json
{
  "vector": [1.0, 0.0, 0.0],
  "sparse_vector": {
    "indices": [12, 98],
    "values": [1.2, 0.7]
  },
  "k": 5,
  "filter": {"category": "electronics"},
  "fusion": "rrf",
  "dense_weight": 1.0,
  "sparse_weight": 1.0
}
```

The `indices` and `values` arrays must have equal lengths. `fusion` is `rrf`
or `weighted`.

## Property-graph overlay

The graph vertex set is the collection's existing point set. Enable the
overlay, then configure a collection-global edge type:

```bash
curl --fail -X PUT \
  'http://127.0.0.1:7401/v1/collections/products/graph?wait=true'

curl --fail -X PUT \
  http://127.0.0.1:7401/v1/collections/products/graph/types/related_to \
  -H 'Content-Type: application/json' \
  -d '{"weight_property":"strength","wait":true}'
```

Lifecycle changes require the `admin` role plus `graph:admin`; type changes
require a write-capable role plus `graph:type_configure`. List configured types
with `GET /v1/collections/{name}/graph/types`. Drop the complete overlay with
`DELETE /v1/collections/{name}/graph?wait=true`; this advances the graph epoch
and does not delete the collection's points.

Create an edge between two existing points:

```bash
curl --fail -X POST \
  http://127.0.0.1:7401/v1/collections/products/edges \
  -H 'Content-Type: application/json' \
  -d '{
    "source_point_id":"phone",
    "target_point_id":"book",
    "edge_type":"related_to",
    "properties":{"strength":0.8},
    "idempotency_key":"import-row-42",
    "wait":true
  }'
```

The returned `edge_id` is an opaque, URL-safe token. Store and return it
unchanged; do not parse, order, or infer topology from it. `PATCH
/v1/collections/{name}/edges/{edge_id}` merges the body `properties`; `PUT`
replaces the complete property document. `DELETE` removes the edge and takes
`wait` as a query parameter. All edge mutations require a write-capable role
plus `graph:write`.

Traverse with one bounded request:

```bash
curl --fail -X POST \
  http://127.0.0.1:7401/v1/collections/products/graph/traverse \
  -H 'Content-Type: application/json' \
  -d '{
    "anchors":["phone"],
    "edge_types":["related_to"],
    "direction":"outgoing",
    "returns":"nodes",
    "limit":100,
    "with_payload":true,
    "budget":{
      "max_depth":2,
      "max_frontier":10000,
      "max_visited":100000,
      "max_edges":1000000,
      "max_time_ms":1000,
      "max_memory_bytes":67108864,
      "cold":null
    }
  }'
```

`returns` is `nodes`, `edges`, or `paths`; paths require an explicit `limit`.
The response reports `graph_epoch`, traversal statistics, truncation, and
warnings. Reading topology requires `graph:read`, independent of point-read
permission. Tenant-scoped callers cannot discover endpoints or edges owned by
another tenant. Cross-tenant relations are rejected by default and require
explicit `tenant:cross_write`, `tenant:cross_read`, and the
`admin_cross_tenant` relation scope.

Dense and hybrid request bodies may add the same statement-level constraint:

```json
{
  "vector": [1.0, 0.0, 0.0],
  "k": 5,
  "graph": {
    "anchors": ["phone"],
    "edge_types": ["related_to"],
    "direction": "outgoing"
  }
}
```

The constraint is applied before ranking/fusion. The response's `graph` object
contains the pinned `graph_epoch`, selected plan, estimator/expansion metadata,
fallback state, and warnings. `allow_degraded:true` is an explicit audited
opt-in; without it the engine uses an eligible exact fallback or returns
`graph.slo_unavailable`.

Explicit deferred endpoint imports use a durable session:

1. `POST /v1/collections/{name}/graph/deferred-sessions?wait=true`
2. `POST /v1/collections/{name}/graph/deferred-sessions/{session}/edges`
3. `POST /v1/collections/{name}/graph/deferred-sessions/{session}/points`
4. `POST /v1/collections/{name}/graph/deferred-sessions/{session}/commit?wait=true`

Abort instead with the matching `/abort` route. Session and edge identifiers
are both opaque. Pending edges remain invisible, and commit refuses while any
endpoint is unresolved.

### Multiple searches with fused results

`POST /v1/collections/products/multi_search`

```json
{
  "searches": [
    {"vector": [1.0, 0.0, 0.0], "k": 10},
    {"vector": [0.8, 0.2, 0.0], "k": 10}
  ],
  "fusion": "weighted",
  "fused_k": 5,
  "weights": [0.7, 0.3]
}
```

Omit `fusion`, `fused_k`, and `weights` to receive independent result sets
without a fused result.

### Recommend from stored point IDs

`POST /v1/collections/products/recommend`

```json
{
  "positive": ["phone"],
  "negative": ["book"],
  "k": 5,
  "filter": {"category": "electronics"}
}
```

### Payload-aware reranking

`POST /v1/collections/products/rerank`

```json
{
  "vector": [1.0, 0.0, 0.0],
  "k": 5,
  "prefetch_k": 20,
  "score_boosts": [
    {
      "field": "featured",
      "value": true,
      "boost": 1.25
    }
  ]
}
```

### Create and restore a snapshot

Snapshots are disabled until a root is configured. Stop the source-built
server, then restart the same database with a separate backup directory:

```bash
chirondb --data-dir ./data --snapshot-root ./backups
```

In another terminal, send the following bodies to the indicated endpoints.
`beta-smoke` is relative to the configured root and must be a new snapshot
name. Restore replaces the live database with that snapshot; use it only when
you intend to roll back changes made after the snapshot.

`POST /v1/admin/snapshot`

```json
{
  "path": "beta-smoke"
}
```

`POST /v1/admin/restore`

```json
{
  "path": "beta-smoke",
  "target_wal_lsns": {},
  "target_wal_unix_ms": {}
}
```

Snapshot paths are paths on the ChironDB server or inside its container, not
paths on the Postman workstation. They must resolve beneath the configured
`snapshot_root`; the endpoints are disabled when no snapshot backing root is
configured. Object-store restore URLs must match the configured origin and path
prefix. Snapshot and restore require the `admin` role.

Optional `wal_restore_archive_dir` or `wal_restore_object_store_dir` supplies
archived collection WAL from server-side storage. With archives, a collection's
`target_wal_lsns` value may exceed the snapshot's WAL end only when verified,
contiguous archive history covers that exact record boundary. Replay preserves
the original LSNs and timestamps, skips matching overlap, and rejects gaps,
divergent overlap, or conflicting archive names before installing the restore.
Timestamp targets select a contiguous WAL prefix, not isolated records whose
timestamps happen to match after a clock rollback. Unsupported plaintext-to-
encrypted frame conversion is rejected rather than changing WAL offsets.

Graph-bearing segment seals rotate the collection WAL at the graph/vector cut,
publish that immutable prefix to the local archive, and complete every configured
external-directory, object-store, and archive-command mirror before the sealed
generation may retire the live prefix. Local retention runs only after successful
publication. A mirror failure leaves the graph/vector generation unpublished and
the live WAL prefix replayable.

For a backward PITR target below the snapshot's retained WAL base, restore can use
archives already carried inside the snapshot (plus any imported archives) to
reconstruct a source-preserving WAL only in the uninstalled staging generation.
The archive chain must be contiguous from LSN 0 through the live suffix; missing,
partial, or divergent history rejects before installation. Archive retention can
therefore determine how far backward a later snapshot can be restored.

Snapshots are assembled and verified in a sibling staging directory and are
published only after the complete tree is synchronized. Restore uses an
exclusive maintenance window and a crash-recoverable journal: readiness is
lowered, current operations are drained, the staged generation is validated,
and the live directory is swapped atomically. After an interrupted restore,
startup selects either the complete old generation or the complete new one,
never a mixture.

`GET` requests, collection deletion, index status, and collection compaction
do not require a JSON body. In Postman, select **Body → none** for those calls.

## ChironQL

ChironQL is ChironDB's retrieval query language: one statement per request, no
JSON to hand-assemble. The full language reference is
[CHIRONQL.md](CHIRONQL.md).

```bash
curl --fail -X POST http://127.0.0.1:7401/v1/chironql \
  -H 'content-type: application/json' \
  -d '{"query": "SEARCH products NEAR [1,0,0] WHERE category = '"'"'electronics'"'"' LIMIT 5 WITH PAYLOAD;"}'
```

Example response shape; timing and query IDs vary between requests:

```json
{
  "kind": "rows",
  "columns": ["id", "score", "payload"],
  "rows": [{"id": "phone", "score": 1.0, "payload": {"category": "electronics", "price": 699}}],
  "stats": {"took_ms": 3.1, "searched": 1, "degraded": false},
  "query_id": "q_1a013b57ee2001"
}
```

`query_id` appears in the server's own log line for the statement, so a
reported failure can be found with `grep`.

### Request fields

| Field | Meaning |
| --- | --- |
| `query` | One ChironQL statement. Two statements in one request is an error. |
| `collection` | Session collection, as `USE <name>` would set. A collection named in the statement wins over it. HTTP has no session, so this does not persist between requests. |
| `trace` | Return the server's stage-by-stage execution trace on success. Failures carry it either way. |
| `confirm` | Proceed with a statement that stops and asks — see below. |

### Execution trace

`"trace": true` returns what the server actually did:

```json
{
  "trace": {
    "query_id": "q_1a013b586c9002",
    "stages": [
      {"name": "parse", "elapsed_us": 50, "outcome": "ok"},
      {"name": "authorize", "elapsed_us": 1, "outcome": "ok"},
      {"name": "resolve_collection", "elapsed_us": 20, "outcome": "ok"},
      {"name": "engine_search", "elapsed_us": 300, "outcome": "ok"},
      {"name": "render", "elapsed_us": 10, "outcome": "ok"}
    ]
  }
}
```

Stages that did not run are absent rather than present with a zero duration.
On a failure the trace stops at the stage that failed and is returned whether
or not it was requested. Trace detail is capped by the calling key's role.

### Errors

```json
{
  "error": "ChironQL filters are conjunctions — there is no OR",
  "code": "chironql.no_or_across_fields",
  "hint": "Single-field disjunction is IN: category IN ['a', 'b'].",
  "position": 34,
  "query_id": "q_1a013b58abd003",
  "trace": {"stages": [{"name": "parse", "outcome": "failed", "...": "..."}]}
}
```

`position` is a byte offset into the submitted query, for drawing a caret.

| Status | When |
| --- | --- |
| `400` | Parse reject or a bad request |
| `403` | A write statement on a read-only key |
| `404` | Collection, point, or named vector not found, or not visible to this key |
| `409` | The statement is waiting on confirmation |
| `507` | Resource exhausted |

### Filtered deletes stop and ask

`DELETE ... WHERE` counts what the filter matches and refuses until the caller
confirms, so the decision is made with a number in front of it:

```json
{
  "error": "this would delete 1204 point(s) from 'products'",
  "code": "chironql.confirmation_required",
  "affected_estimate": 1204
}
```

Re-send with `"confirm": true` to proceed. Nothing is deleted by the refused
request. This gate is server-side, so an API caller with no prompt gets the
same protection the terminal does.

### Validate without executing

`POST /v1/chironql/parse` checks a statement and touches no data — for showing
a user a generated query before it runs:

```bash
curl --fail -X POST http://127.0.0.1:7401/v1/chironql/parse \
  -H 'content-type: application/json' \
  -d '{"query": "DELETE FROM products WHERE category = '"'"'archived'"'"';"}'
```

```json
{"ok": true, "kind": "write", "statement": "DELETE", "collection": "products"}
```

`kind` classifies the statement. Collection DDL — `CREATE COLLECTION` and
`DROP COLLECTION` — is `write` and accepts a `read_write` or `admin` session.
`DROP` also needs the same `"confirm": true` the filtered delete needs. See
[CHIRONQL.md](CHIRONQL.md#collections).

## Multi-tenancy

When row-level tenant isolation is enabled, every request is scoped to the
tenant of the API key that made it, and writes are stamped with it. See
[TENANT_ISOLATION.md](TENANT_ISOLATION.md). It is off by default.

## Endpoint map

Every path below is also served without the `/v1` prefix during the beta.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET`, `POST` | `/v1/collections` | List or create collections |
| `DELETE` | `/v1/collections/{name}` | Delete a collection |
| `PUT` | `/v1/collections/{name}/payload_schema` | Replace payload schema |
| `PUT` | `/v1/collections/{name}/points` | Upsert points |
| `POST` | `/v1/collections/{name}/points/get` | Fetch points by ID |
| `POST` | `/v1/collections/{name}/points/payload` | Merge or replace a payload |
| `POST` | `/v1/collections/{name}/points/delete` | Delete IDs |
| `POST` | `/v1/collections/{name}/points/delete/filter` | Delete matching points |
| `POST` | `/v1/chironql` | Run one ChironQL statement |
| `POST` | `/v1/chironql/parse` | Validate a statement without running it |
| `PUT`, `DELETE` | `/v1/collections/{name}/graph` | Enable or drop the graph overlay |
| `GET` | `/v1/collections/{name}/graph/types` | List edge types |
| `PUT` | `/v1/collections/{name}/graph/types/{type}` | Configure an edge type |
| `POST` | `/v1/collections/{name}/edges` | Create an edge |
| `PATCH`, `PUT`, `DELETE` | `/v1/collections/{name}/edges/{edge_id}` | Merge/replace properties or remove an edge |
| `POST` | `/v1/collections/{name}/graph/traverse` | Run bounded exact traversal |
| `POST` | `/v1/collections/{name}/graph/deferred-sessions` | Open a deferred endpoint session |
| `POST` | `/v1/collections/{name}/graph/deferred-sessions/{session}/points` | Upsert and bind deferred endpoints |
| `POST` | `/v1/collections/{name}/graph/deferred-sessions/{session}/edges` | Add a deferred edge |
| `POST` | `/v1/collections/{name}/graph/deferred-sessions/{session}/commit` | Commit a deferred session |
| `POST` | `/v1/collections/{name}/graph/deferred-sessions/{session}/abort` | Abort a deferred session |
| `POST` | `/v1/collections/{name}/search` | Dense ANN search |
| `POST` | `/v1/collections/{name}/search/batch` | Batch dense search |
| `POST` | `/v1/collections/{name}/hybrid_search` | Dense and sparse fusion |
| `POST` | `/v1/collections/{name}/text_hybrid_search` | Dense vector + native text BM25 + RRF |
| `POST` | `/v1/mcp` (alias `/mcp`) | Configured read-only MCP tools |
| `POST` | `/v1/collections/{name}/multi_search` | Multiple searches with optional fusion |
| `POST` | `/v1/collections/{name}/recommend` | Positive/negative point recommendation |
| `POST` | `/v1/collections/{name}/rerank` | Payload-aware reranking |
| `POST` | `/v1/collections/{name}/count` | Count points |
| `POST` | `/v1/collections/{name}/scroll` | ID-cursor pagination |
| `GET` | `/v1/collections/{name}/index_status` | Index readiness |
| `POST` | `/v1/collections/{name}/compact` | Force compaction |
| `POST` | `/v1/admin/snapshot` | Create a snapshot |
| `POST` | `/v1/admin/restore` | Restore a snapshot |

Streaming, cold-tier, WAL-archive, WebSocket, and cluster-administration routes
are advanced beta surfaces. Inspect `chirondb-server/src/api.rs` and the request
types in `chirondb-types/src/model.rs` before using them operationally.

## Errors and compatibility

- Successful JSON requests return a `2xx` status.
- Invalid input returns `400`; failed authentication returns `401`; an
  authenticated principal denied by role/allowlist returns `403`.
- Audit-writer failure rejects the request with `503`; bounded execution
  overload returns `429`.
- Unknown collections or points return `404` where applicable.
- Graph failures return a stable `code` and `message` alongside `error`.
  Missing endpoints, edges, types, and deferred sessions return `404`;
  admission overload returns `429`; an unavailable recall contract returns
  `503`. Graph permission refusal returns `403` with
  `graph.permission_denied`.
- WAL/storage durability failures return `503`; reads remain available where
  safe, while `GET /health` and `GET /v1/health` return a degraded status and
  HTTP `503` until the process is repaired or restarted.
- Other server-side failures return `500` with a JSON error body.
- The deprecated GaussDB routes and authentication names are compatibility
  aliases over the same engine; they do not create a second data format.

Durability guarantees assume a local filesystem and storage stack that honors
`fsync`. Network filesystems or controllers that ignore flushes are outside
this guarantee. WAL streaming, replication, and quorum acknowledgement remain
experimental beta scaffolding; this single-node contract does not imply
replicated durability.

Request bodies are limited to 64 MiB. Collection dimensions are limited to
65,536, `k`/`prefetch_k` to 10,000, multi-search to 128 branches, upsert to
10,000 points, and serialized payloads to 1 MiB per point. Dense/sparse values
must be finite and filters have bounded nesting/container complexity.
