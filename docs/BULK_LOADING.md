# Bulk loading documents and relations

[`examples/bulk_load.py`](../examples/bulk_load.py) loads independent JSONL
records through reused HTTP(S) connections, eight workers, and at most 16
pending batches. It uses only Python's standard library (Python 3.9+). Create
the collection, SQL table, graph overlay and edge types first, using the same
authentication and tenant ownership as the loader.
The loader also needs collection read/index-status access for readiness checks.

For example, after provisioning a two-dimensional `chunks` collection, a
`documents (id TEXT PRIMARY KEY, ordinal BIGINT)` table and `cites` edge type,
these are separate lines in three input files:

`points.jsonl`:

```jsonl
{"id":"doc-1","vector":[1.0,0.0],"payload":{"text":"first document","ordinal":0}}
{"id":"doc-2","vector":[0.0,1.0],"payload":{"text":"second document","ordinal":1}}
```

`sql.jsonl`:

```jsonl
{"statements":[{"sql":"INSERT INTO documents (id, ordinal) VALUES ($1,$2)","parameters":[{"type":"text","value":"doc-1"},{"type":"integer","value":0}]}]}
{"statements":[{"sql":"INSERT INTO documents (id, ordinal) VALUES ($1,$2)","parameters":[{"type":"text","value":"doc-2"},{"type":"integer","value":1}]}]}
```

`edges.jsonl`:

```jsonl
{"source_point_id":"doc-1","target_point_id":"doc-2","edge_type":"cites","properties":{"ordinal":0}}
```

Run from the repository root:

```bash
python3 examples/bulk_load.py \
  --url http://127.0.0.1:7401 --collection chunks \
  --state ./load-progress.sqlite \
  --sql ./sql.jsonl --points ./points.jsonl --edges ./edges.jsonl
```

The loader reads `CHIRONDB_API_KEY` from the environment. For a TLS endpoint,
use `https://…` and optionally `--ca-cert /path/to/ca.pem`; hostname and
certificate verification stay enabled. Use a base URL without credentials,
query parameters or fragments; a proxy path prefix is supported. Invalid URL
configuration is rejected before creating the progress database.
The collection name is URL-encoded.
These native routes use the existing RBAC graph surface; initialized protected
installations continue to use their ChironQL transaction interface.

SQL completes before points, then edges. Records are independent across
batches; do not use this example for SQL statements that depend on another
batch's order. Points are upserted in batches of 50 with `wait=true`. Edges use
one atomic batch of up to 50 with one stable idempotency key. Arbitrary SQL
inputs are split at the server's 32-statement transaction limit, with a separate
stable key for each sub-batch. SQL statements inside one input record are not
guaranteed to share a transaction if they cross that boundary; use native SQL
directly when that atomicity is required. DDL must be submitted separately.

Under sustained SQL load, new writes can wait for an active checkpoint to
release retained memory before taking their transaction snapshot. Reads and
replays of already committed batches remain available. A cancelled waiting
write has not committed; retain its batch key when retrying.

Keep the SQLite progress database with the same target installation and input
files. Its manifest binds the base URL, collection and input hashes; changing
these rejects reuse. SQLite checkpoints use FULL synchronization. A completed
batch is skipped on resume. When a connection loses its ACK or a server returns
a temporary failure, retry retains the same key and payload, so the server
reconciles SQL/edge decisions before creating another mutation. Point retries
upsert the same public IDs. Retry/backoff and the pending queue are bounded.
Persist edge receipts and IDs; do not generate a replacement key for an
ambiguous batch. Batch receipts survive edge deletion, compaction and restart;
replay preserves the original IDs and rechecks current namespace permissions.
After 24 hours, the consumed batch key rejects replay.

The progress database is a client checkpoint, not a database backup. Do not
reuse it against a restored/recreated empty server at the same URL, or after
changing credentials/tenant ownership. Reconcile uncertain batches while their
server retention is valid. Keep progress and server backups consistent.

The printed `load_seconds` ends after loading. `ready_seconds` also includes
input-integrity revalidation, waiting for `index_status.build_in_flight` to become
false (including background segment sealing), fetching a sample point and
querying its vector when supplied. Readiness
waits at most five minutes; a timeout retains completed checkpoints so a resume
can finish waiting. Schema provisioning happens before this example starts;
include it separately in a full time-to-ready benchmark. Verify application
document/SQL/edge counts and retrieval quality before serving traffic. Loading
the three models is phased; only an individual SQL or edge batch is atomic
across its own operations.

A small collection can be fully searchable through the engine's exact live
search path while `indexed_points` is below `total_points`. Use
`build_in_flight` and verification queries to determine readiness.
