# ChironDB SDKs

The beta includes synchronous Python and asynchronous Rust clients for the HTTP
API. They are source-distributed in this repository and are not yet published
to PyPI or crates.io.

Start a server using [Getting started](GETTING_STARTED.md#1-build-and-start).
Each language's starter creates `products`; use an unused collection name or
skip creation if that collection already has the same three-dimensional
schema. Advanced snippets continue after the starter in the same script and
need both `phone` and `book`. Re-running an upsert restores either point.

## Python

Python `3.10+` is required. From an existing checkout, skip the first two commands.

```bash
git clone https://github.com/Gaussian-id/ChironDB.git
cd ChironDB
python3 -m venv .venv
source .venv/bin/activate
python -m pip install ./clients/python
```

Create a collection, insert points, and search:

```python
from chirondb_client import ChironDbClient

db = ChironDbClient(
    "http://127.0.0.1:7401",
    api_key=None,  # set this when CHIRONDB_API_KEY is enabled
)

print(db.health())

db.create_collection(
    name="products",
    vector_dim=3,
    metric="cosine",
    payload_schema={"category": "string", "price": "number"},
)

db.upsert(
    "products",
    [
        {
            "id": "phone",
            "vector": [1.0, 0.0, 0.0],
            "sparse_vector": {"indices": [12, 98], "values": [1.2, 0.7]},
            "payload": {"category": "electronics", "price": 699},
        },
        {
            "id": "book",
            "vector": [0.0, 0.0, 1.0],
            "payload": {"category": "media", "price": 15},
        },
    ],
    wait=True,
)

result = db.search(
    "products",
    vector=[1.0, 0.0, 0.0],
    k=2,
    filter={"category": "electronics"},
)
for hit in result["hits"]:
    print(hit["id"], hit["score"], hit["payload"])
```

Other available methods are `list_collections`, `delete_collection`,
`get_points`, `delete`, `set_payload`, `delete_by_filter`, `compact`, `count`,
`scroll`, and `scroll_all`.

Use the returned ID cursor for manual pagination:

```python
page = db.scroll("products", limit=100)
while page["next_offset"] is not None:
    page = db.scroll(
        "products",
        limit=100,
        offset=page["next_offset"],
    )
```

HTTP error responses raise `ChironDbError`, which exposes `status` and
`message`. A stopped server raises `requests.ConnectionError`; a request
that times out raises `requests.Timeout`. The client does not start a server.
Check `/health` and the configured address before retrying.

### Structural nodes and zero-vector safety

Property-graph structural nodes remain ordinary searchable points. Construct
them through `StructuralPoint.create`; it rejects a missing, non-finite, or
all-zero dense vector before network I/O:

```python
from chirondb_client import StructuralPoint

db.create_collection(name="assets", vector_dim=3, metric="cosine")
line = StructuralPoint.create({
    "id": "line-3",
    "vector": [0.2, 0.8, 0.1],  # demonstration embedding
    "payload": {"kind": "production_line"},
})
receipt = db.upsert_structural("assets", [line], wait=True)
print(receipt["operation_lsn"])
```

Legacy data that cannot yet be re-embedded has one deliberately explicit
escape hatch:

```python
from chirondb_client import UnsafeStructuralEmbeddingOverride

token = UnsafeStructuralEmbeddingOverride("legacy import awaiting re-embedding")
line = StructuralPoint.with_unsafe_zero_vector_override(
    {"id": "legacy-line", "vector": [0.0] * 3}, token
)
receipt = db.upsert_structural("assets", [line])
assert receipt["unsafe_override_audited"]
```

The server repeats validation before WAL append. The override reason, actor,
collection, operation LSN, counts, and SHA-256 point-ID digests enter the
durable audit chain; raw point IDs do not. Generic `upsert` remains unchanged
for compatibility and is not the graph-aware structural-node path.

### Property graph and constrained retrieval

Graph identity is intentionally opaque in the SDK. `relate` returns an
`EdgeToken`; pass that object back to update or delete the edge without parsing
its value. Enable the overlay and configure edge types before writing edges:

```python
from chirondb_client import GraphConstraint

db.enable_graph("products", wait=True)
db.configure_edge_type("products", "related_to", weight_property="weight")

edge = db.relate(
    "products",
    source_point_id="phone",
    target_point_id="book",
    edge_type="related_to",
    properties={"weight": 0.8},
)
db.merge_edge_properties("products", edge.edge_id, {"source": "catalog"})

reachable = db.search(
    "products",
    vector=[0.0, 0.0, 1.0],
    k=10,
    graph=GraphConstraint(
        anchors=("phone",),
        edge_types=("related_to",),
    ),
)
print(reachable["graph"]["graph_plan"])

edges = db.traverse(
    "products",
    anchors=["phone"],
    edge_types=["related_to"],
    returns="edges",
    limit=100,
)
db.unrelate("products", edge.edge_id)
```

The same `graph=` constraint is accepted by `hybrid_search`, where one
authorized reachable set gates both dense and sparse branches. It is not
accepted by `multi_search`: submit each constrained statement directly so it
retains one epoch, budget, trace, and recall-SLO decision.

For bulk data whose edges arrive before their point endpoints, use
`open_deferred_graph_session`, `deferred_relate`, `deferred_upsert`, and
`commit_deferred_graph_session`; call `abort_deferred_graph_session` to discard
an open window. Session IDs are opaque typed values too. `list_edge_types`,
`replace_edge_properties`, and `drop_graph` complete the graph lifecycle.

### Retrieval beyond dense search

```python
# Dense and lexical, fused by reciprocal rank.
db.hybrid_search(
    "products",
    vector=[0.1, 0.2, 0.3],
    sparse_vector={"indices": [12, 98], "values": [1.2, 0.7]},
    k=5,
)

# Several query vectors in one round trip.
db.multi_search(
    "products",
    searches=[{"vector": [1, 0, 0], "k": 5}, {"vector": [0, 1, 0], "k": 5}],
    fusion="rrf",
    fused_k=5,
)

# More like these, less like those, by stored point id.
db.recommend("products", positive=["phone"], negative=["book"], k=5)

# ANN prefetch, then rescoring with payload rules.
db.rerank(
    "products",
    vector=[0.1, 0.2, 0.3],
    k=5,
    score_boosts=[{"field": "featured", "value": True, "boost": 1.5}],
)
```

A `boost` is multiplied into the score and results are sorted descending, so
the sign of the score decides what it does: above `1.0` promotes on cosine and
inner-product collections, where scores are positive. On an L2 collection the
score is a negated distance, so a factor above `1.0` demotes — use a factor
between 0 and 1 to promote there.

## Rust

Create a Rust application next to your checkout (`cargo new chiron-example`),
then add these dependencies to its `Cargo.toml`. The path below assumes sibling
directories named `chiron-example` and `gauss-db`; adjust it to your checkout.
Paste the complete starter into `src/main.rs` and run `cargo run` from the
application directory. Insert advanced snippets before the starter's `Ok(())`;
wrap each snippet in its own `{ ... }` block to keep repeated imports scoped.

```toml
[dependencies]
chirondb-client = { path = "../gauss-db/clients/rust" }
serde_json = "1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

```rust
use chirondb_client::{
    ChironDbClient, CollectionConfig, Point, SearchQuery,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let db = ChironDbClient::new("http://127.0.0.1:7401");

    db.create_collection(CollectionConfig {
        name: "products".into(),
        vector_dim: 3,
        metric: "cosine".into(),
        shards: 1,
        replicas: 1,
        ..Default::default()
    })
    .await?;

    db.upsert(
        "products",
        vec![Point {
            id: "phone".into(),
            vector: vec![1.0, 0.0, 0.0],
            sparse_vector: Some(chirondb_client::SparseVector {
                indices: vec![12, 98], values: vec![1.2, 0.7],
            }),
            payload: serde_json::json!({
                "category": "electronics",
                "price": 699
            }),
            ..Default::default()
        }, Point {
            id: "book".into(),
            vector: vec![0.0, 0.0, 1.0],
            payload: serde_json::json!({"category": "media", "price": 15}),
            ..Default::default()
        }],
        true,
    )
    .await?;

    let result = db.search(
        "products",
        SearchQuery {
            vector: vec![1.0, 0.0, 0.0],
            k: 2,
            filter: Some(serde_json::json!({"category": "electronics"})),
            ..Default::default()
        },
    )
    .await?;

    for hit in result.hits {
        println!("{} {} {}", hit.id, hit.score, hit.payload);
    }

    Ok(())
}
```

The Rust client also provides `health`, `list_collections`,
`delete_collection`, `get_points`, `delete`, `set_payload`,
`delete_by_filter`, `count`, and `scroll`. Call `.with_api_key(key)` when the
server requires authentication. Connection failures return a client error;
start the server separately and verify its address before retrying.

### Structural nodes and zero-vector safety

```rust
use chirondb_client::{CollectionConfig, Point, StructuralPoint, UnsafeStructuralEmbeddingOverride};

db.create_collection(CollectionConfig {
    name: "assets".into(), vector_dim: 3, metric: "cosine".into(),
    shards: 1, replicas: 1, ..Default::default()
}).await?;
let line = StructuralPoint::new(Point {
    id: "line-3".into(),
    vector: vec![0.2, 0.8, 0.1], // demonstration embedding
    ..Default::default()
})?;
let receipt = db.upsert_structural("assets", vec![line], true).await?;
println!("operation LSN: {}", receipt.operation_lsn);

// Explicit compatibility exception; the server records this reason durably.
let token = UnsafeStructuralEmbeddingOverride::new(
    "legacy import awaiting re-embedding",
)?;
let legacy = StructuralPoint::with_unsafe_zero_vector_override(
    Point {
        id: "legacy-line".into(),
        vector: vec![0.0; 3],
        ..Default::default()
    },
    token,
)?;
let audited = db.upsert_structural("assets", vec![legacy], true).await?;
assert!(audited.unsafe_override_audited);
```

`StructuralPoint::new` rejects non-finite and all-zero vectors locally; the
server enforces the same rule before WAL append. One batch may carry at most
one unsafe reason.

### Property graph and constrained retrieval

The Rust SDK re-exports the canonical graph request/result types from
`chirondb-types`. This keeps EdgeId opaque and makes the HTTP, gRPC,
ChironWire, and SDK JSON contract share one schema:

```rust
use chirondb_client::{
    GraphConstraint, GraphDirection, GraphRelationScope,
    RelateRequest, SearchQuery, TraversalBudget,
};

db.enable_graph("products", true).await?;
db.configure_edge_type("products", "related_to", Some("weight".into()), true)
    .await?;
let edge = db.relate(
    "products",
    RelateRequest {
        source_point_id: "phone".into(),
        target_point_id: "book".into(),
        edge_type: "related_to".into(),
        properties: serde_json::json!({"weight": 0.8}),
        scope: GraphRelationScope::Local,
        idempotency_key: None,
    },
    true,
).await?;

let result = db.search(
    "products",
    SearchQuery {
        vector: vec![0.0, 0.0, 1.0],
        k: 10,
        graph: Some(GraphConstraint {
            anchors: vec!["phone".into()],
            edge_types: vec!["related_to".into()],
            direction: GraphDirection::Outgoing,
            node_filter: None,
            edge_filter: None,
            budget: TraversalBudget { max_depth: 1, ..Default::default() },
            allow_degraded: false,
        }),
        ..Default::default()
    },
).await?;
assert!(result.graph.is_some());

db.unrelate("products", &edge.edge_id, true).await?;
```

`GraphTraversalQueryRequest` drives `traverse`. Deferred bulk loading uses
`open_deferred_graph_session`, `deferred_relate`, `deferred_upsert`, and
`commit_deferred_graph_session`/`abort_deferred_graph_session`. The SDK also
exposes `list_edge_types`, both edge-property update modes, and `drop_graph`.
As in Python, graph constraints are supported by direct dense and hybrid
search, not `multi_search`.

### Retrieval beyond dense search

```rust
use chirondb_client::{
    Fusion, HybridQuery, MultiSearchQuery, RecommendQuery, RerankQuery, ScoreBoost, SearchQuery,
    SparseVector,
};

// Dense and lexical, fused by reciprocal rank.
db
    .hybrid_search(
        "products",
        HybridQuery {
            vector: Some(vec![0.1, 0.2, 0.3]),
            sparse_vector: Some(SparseVector {
                indices: vec![12, 98],
                values: vec![1.2, 0.7],
            }),
            k: 5,
            fusion: Fusion::Rrf,
            ..Default::default()
        },
    )
    .await?;

// Several query vectors in one round trip.
db
    .multi_search(
        "products",
        MultiSearchQuery {
            searches: vec![
                SearchQuery { vector: vec![1.0, 0.0, 0.0], k: 5, ..Default::default() },
                SearchQuery { vector: vec![0.0, 1.0, 0.0], k: 5, ..Default::default() },
            ],
            fusion: Some(Fusion::Rrf),
            fused_k: Some(5),
            ..Default::default()
        },
    )
    .await?;

// More like these, less like those.
db
    .recommend(
        "products",
        RecommendQuery {
            positive: vec!["phone".into()],
            negative: vec!["book".into()],
            k: 5,
            ..Default::default()
        },
    )
    .await?;

// ANN prefetch, then payload-aware rescoring.
db
    .rerank(
        "products",
        RerankQuery {
            vector: vec![0.1, 0.2, 0.3],
            k: 5,
            score_boosts: vec![ScoreBoost {
                field: "featured".into(),
                value: serde_json::json!(true),
                boost: 1.5,
            }],
            ..Default::default()
        },
    )
    .await?;

```

`SearchQuery` also carries `ef_search`, `recall_target` and `with_payload`.
`recall_target` states a target the engine tunes towards; no response field
reports an achieved recall, and the client does not invent one.

## GaussDB compatibility names

Existing alpha application imports remain supported during the beta:

```python
from gaussdb_client import GaussDbClient
```

The Rust `GaussDbClient` type alias remains in `chirondb-client`, and the
deprecated `gaussdb-client` compatibility crate re-exports the ChironDB HTTP
client. New code should use the ChironDB names.

## ChironQL from a client

Neither SDK wraps ChironQL. The language is for humans at a terminal — use
`chironql` for that, or `chirondb --console` on the server itself. Application
code should use the typed methods above, where a mistake is a compile error
rather than a string the server rejects at runtime.

`POST /v1/chironql` is a plain HTTP endpoint if you do want it from code; see
[HTTP_API.md](HTTP_API.md).

## SDK scope

- Both SDKs call the JSON HTTP API on port `7401`.
- Generated gRPC clients are not published; see [the gRPC guide](GRPC_API.md).
- The clients do not manage server lifecycle, TLS certificates, backups, or
  data-directory upgrades.
- Keep `wait=true` for durable writes: success then means the WAL and required
  filesystem metadata are synchronized. With `wait=false`, the server still
  returns `202 Accepted` and flushes in the background every 200 ms, but a crash
  may lose the recent unflushed suffix.
- Public deployments require server TLS, RBAC/API credential Secrets, and an
  external encryption keyring. SDK `401`/`403` responses distinguish invalid
  credentials from a principal denied by policy; `503` means the fail-closed
  audit path was unavailable.

## Disposable graph + vector preview

Run the complete local walkthrough without configuring a data directory or
external service:

```bash
cargo run --locked -p chirondb --example graph_vector_preview
```

The example binds only an ephemeral loopback port and stores data in a
temporary directory removed on exit. Through the typed Rust HTTP SDK it creates
a collection, enables/configures graph state, upserts dense+sparse points,
relates and traverses an opaque edge, runs graph-constrained dense and hybrid
search, merges edge properties, unrelates, creates one durable edge, restarts
the server, and proves the same collection/type/token/topology/search result
after reopen. Success prints a JSON report ending with
`"acceptance_claimed": false` and `"c10_started": false`.

The SDK `list_collections` methods decode the endpoint's top-level JSON array;
they do not expect a `{ "collections": ... }` wrapper.

Supported graph surfaces in the local candidate are:

| Surface | Status | Preview command coverage |
|---|---|---|
| Embedded `Db` | Shared engine path | Hosts both local server instances |
| HTTP legacy + `/v1` | Lifecycle, catalog, edge CRUD, traversal, constrained dense/hybrid, deferred sessions | Typed HTTP walkthrough exercises the legacy route; both prefixes share one router |
| Primary ChironDB gRPC | Same operations/results plus structured status details | Covered by native listener tests, not this single command |
| ChironWire | ChironQL 1.1 plus existing vector frames and structured graph errors | Covered by native listener tests, not this single command |
| Rust/Python SDK | Typed HTTP graph operations; opaque EdgeId/session values | Rust exercised here; both SDKs have live tests |
| PostgreSQL wire | Vector-only compatibility subset | Every graph construct rejects with SQLSTATE `0A000`; it is not a graph surface |

Preview limitations are deliberate: graph-aware multi-search is rejected;
submit direct dense/hybrid statements so each has one epoch, budget, trace, and
SLO decision. Distributed graph placement is outside G3. The preview also does
not replace the deferred crash, recall/calibration, resource, platform,
stress/soak, release, or two-arm 24-hour corruption-fuzz acceptance campaigns.

## Native text hybrid SDK methods

The new operation takes both the question text and its embedding. It reads BM25
terms from a top-level string field and does not require `sparse_vector`:

```python
result = db.text_hybrid_search(
    "sop", vector=question_embedding, query="refund policy",
    text_field="text", k=5, filter={"department": "service"},
    budget_ms=30000,
)
```

The Rust client exposes `text_hybrid_search(collection, TextHybridQuery)`:

```rust
use chirondb_client::TextHybridQuery;

let result = client.text_hybrid_search("sop", TextHybridQuery {
    vector: question_embedding,
    query: "refund policy".into(),
    text_field: "text".into(),
    k: 5,
    filter: None,
    budget_ms: Some(30_000),
}).await?;
```

Here `question_embedding` must come from the same model and preprocessing as the
stored document vectors. The embedded Rust engine exposes
`Db::text_hybrid_search_scoped` and
`Db::text_hybrid_search_with_cancellation_scoped`; the latter accepts an
`AtomicBool` cancellation flag. The native operation uses the existing
`SearchResponse` and retains the old sparse/hybrid API unchanged.

## MCP clients

ChironDB can expose three read-only MCP tools: `list_collections`,
`search_documents`, and `get_document`. Each document is one stored point/chunk,
not an automatically reconstructed PDF. HTTP uses `/v1/mcp` (alias `/mcp`) on the
existing HTTP listener. It supports stateless Streamable HTTP for protocol
versions `2026-07-28` and `2025-11-25`.

MCP is disabled unless the server's `--config` TOML contains this configuration:

```toml
[mcp.embedding]
endpoint = "http://127.0.0.1:8000/v1/embeddings"
api_key_env = "CHIRONDB_EMBEDDING_API_KEY"

[mcp.collections.sop]
model = "sentence-transformers/all-MiniLM-L6-v2"
dimensions = 384
text_field = "text"
title_field = "title"
source_field = "source"
```

Start the server with that file after adding the API-key and RBAC settings
described below:

```bash
chirondb --config ./chirondb.toml
```

`api_key_env` is optional for an embedding provider that needs no credential.
If configured, the named environment variable must contain a nonempty key at
startup. The provider accepts `{"model":"...","input":"question text"}` and
returns `{"data":[{"embedding":[0.1,0.2,...]}]}` with exactly one finite vector.
A provider failure returns a tool error; it does not switch to keyword-only
retrieval. Only the question is sent to this endpoint. Retrieved documents are
not sent to the embedding provider.

**The operator must know the model and preprocessing used to fill each
collection. Equal dimensions do not establish model compatibility.** ChironDB
validates vector dimensions and finite numbers; it does not select or operate
an inference model. Embedding endpoints require HTTPS outside loopback, and
redirects are rejected. Embedding credentials are separate from ChironDB API keys.

API-key authentication and RBAC are mandatory for MCP, including localhost.
Configure the existing server key source and RBAC file as described in
[Tenant isolation](TENANT_ISOLATION.md). Tenant-bearing keys also require
`--tenant-enforcement enforced`; MCP does not change or migrate tenant mode.
Only bindings allowed by the caller's RBAC permissions appear in tool results.
Each HTTP request authenticates independently.

Only loopback hosts are accepted by default. For an external deployment, add
an explicit host/origin list before the other MCP tables and configure the
existing listener's TLS/security settings:

```toml
[mcp]
allowed_hosts = ["db.example.com"]
allowed_origins = ["https://chat.example.com"]
```

An absent Origin header is allowed; a supplied Origin is rejected unless it
matches the explicit list. With no `allowed_origins`, all supplied origins are
rejected. OAuth is not provided; clients that require OAuth login are not
supported by this version.

A customer backend connects with its configured key in
`Authorization: Bearer <key>`. A local client can use the shipped stdio bridge:

```bash
chironmcp --endpoint http://127.0.0.1:7401/v1/mcp
```

Set `CHIRONDB_API_KEY` in that process's environment. `--api-key-env NAME` selects
another environment variable. Configure the MCP client to launch that command
and arguments; stdout carries only MCP messages. The bridge connects to the
HTTP server and does not open a database directory.

When a native Streamable HTTP client such as Open WebUI runs in Docker while
ChironDB runs on the host, `127.0.0.1` refers to the client container. For a
local Docker Desktop setup, use `http://host.docker.internal:7401/v1/mcp` and
add `host.docker.internal` to `mcp.allowed_hosts`. On Linux, configure the
equivalent host-gateway mapping explicitly. Use TLS and the externally reachable
server hostname outside a loopback-only development setup.

Example tool arguments:

```json
{
  "collection": "sop",
  "query": "Bagaimana prosedur pengembalian barang?",
  "limit": 5,
  "filter": {"department": "customer_service"}
}
```

`search_documents` defaults to five hits, allows 1–20, and accepts at most
8,192 UTF-8 bytes of question text. Results carry ID, text, optional title/source,
ranking score, `text_truncated`, `degraded`, `truncated`, and separate embedding,
search, and total timings. Scores are ranking values, not probabilities or recall
measurements. Tools return both `structuredContent` and compatible JSON text.
Treat retrieved text as source material, not instructions for the AI application.

Calls have a 30-second total deadline. The serialized response limit is 256 KiB,
including the duplicate text representation and protocol envelope. Search may
shorten snippets or omit tail hits and sets truncation flags. `get_document`
returns a size error if the complete projected document cannot fit. A missing
point and a point owned by another tenant both return `not_found`. Tool failures
are audited as failures even when the protocol response uses HTTP 200.

To populate a fresh `sop` collection, run the complete
[Python ingestion example](../clients/python/examples/mcp_ingest.py) after
installing the Python client above:

```bash
export CHIRONDB_URL=http://127.0.0.1:7401
export CHIRONDB_EMBEDDING_ENDPOINT=http://127.0.0.1:8000/v1/embeddings
python clients/python/examples/mcp_ingest.py
```

Provide the server key through `CHIRONDB_API_KEY`; set
`CHIRONDB_EMBEDDING_API_KEY` if the provider needs it. The example embeds a
chunk, stores its vector and text, embeds a question, and calls native hybrid
search. The MCP collection binding must use the same model. It does not create
sparse vectors.

Protocol references: [Build an MCP server](https://modelcontextprotocol.io/docs/2026-07-28/develop/build-server),
[Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http),
and [MCP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization).
