# ChironDB SDKs

Rust/Python source examples below run from their standalone SDK checkouts.
Rust wire DTO names and JSON representations are unchanged, but SDK and
embedded-engine structs are distinct Rust types. Compare or convert through
serialization when crossing that boundary.

## One client, three models

`client.vector()`, `client.graph()`, and `client.relational()` share one HTTP pool,
credentials and timeout. Existing direct methods remain available. Python view
construction is synchronous even for an async client; await its operations.

| View | Application operations |
| --- | --- |
| `vector()` | Collection config, points/structural points, dense/sparse/text/hybrid retrieval, count/scroll, compact |
| `graph()` | Lifecycle/types, edges, traversal, deferred ingestion, typed ChironQL query |
| `relational()` | Parameterized SQL, atomic statement batches, explicit interactive transactions, transaction status |
| `protected().vector()` | Server-ID create, existing-ID update, authorized reads/dense/text retrieval and deletes |
| `protected().graph()` | ChironQL query; protected traversal and graph stages use this language route |
| `protected().relational()` | The same SQL/transaction contract under current table and reference authority |

`query()` exposes ChironQL `SQL`, bounded read-only `PIPELINE`, and atomic
`TRANSACTION`. It accepts typed positional values; it does not interpolate SQL or
construct a second query language. See [the supported subset](CHIRONQL.md).
Protected pipelines return graph nodes only; standalone protected traversal also
supports edges/paths. Paths require `LIMIT`. Legacy graph REST calls remain
unavailable on protected installations. SQL-only interactive handles cannot stage
separate vector/graph HTTP calls into their transaction; use one ChironQL block.

```python
from chirondb_client import ChironDbClient, RelationalValue, SqlStatementRequest

with ChironDbClient("http://127.0.0.1:7401", timeout=30) as client:
    relational = client.relational()
    # documents is provisioned by the application/admin first.
    result = relational.sql("SELECT id, title FROM documents WHERE id=$1",
                            [RelationalValue("text", "doc-1")])
    for row in result.results[0].rows:
        print([cell.value for cell in row])
    tx = relational.begin()
    decision_id = tx.transaction_id  # Persist before COMMIT.
    tx.execute([SqlStatementRequest("UPDATE documents SET title=$1 WHERE id=$2",
        (RelationalValue("text", "Updated"), RelationalValue("text", "doc-1")))])
    receipt = tx.commit()  # Explicit. tx.rollback() discards private writes.
    status = relational.transaction_status(decision_id)
```

Python `relational()` and `query()` return typed contracts with `to_dict()` and
`from_dict()`. Existing `sql()/execute_sql()/chironql()` methods retain dictionary
responses and tagged-dictionary input. A `SqlExecutionRequest` or `ChironQlRequest`
can carry its complete options; do not combine one with separate request options.
Rust exports SDK-owned `RecordRef`, `RelationalType`, `RelationalValue`,
`SqlOutcome` and request/result types. `TransactionStatus` has `transaction_id`,
`state`, `commit_sequence`, `storage_projected`, and `audit_projected`.

Use explicit Python `RelationalValue(tag, value)` tags: `null`, `boolean`,
`integer`, `float`, `decimal`, `text`, `bytes`, `date`, `timestamp_utc`, `uuid`,
`json`, `vector`, and `record_ref`. Null has no value; JSON null is
`RelationalValue("json", None)`. Decimal uses an exact string, bytes a byte array,
integer an i64, and record references `RecordRef(namespace, id)`. JSON and vector
arrays are distinguished explicitly. Non-finite numbers reject before IO.
These native parameter values preserve large i64 values; the protected CREATE
POINTS literal helper still has the separate exact-f64 limitation described below.

```rust
use chirondb_client::{ChironDbClient, RelationalValue};

let client = ChironDbClient::new("http://127.0.0.1:7401");
let tx = client.relational().begin().await?;
let decision_id = tx.transaction_id.clone().expect("reserved at BEGIN");
tx.sql("UPDATE documents SET title=$1 WHERE id=$2", vec![
    RelationalValue::Text("Updated".into()), RelationalValue::Text("doc-1".into()),
]).await?;
let receipt = tx.commit().await?;
assert_eq!(receipt.transaction_id.as_deref(), Some(decision_id.as_str()));
let status = client.transaction_status(&decision_id).await?;
```

Dropping a transaction performs no network IO or implicit commit/rollback. Its
`opened` response describes BEGIN, rather than cached current authority/state.
The server enforces handle lifetime and current permissions. Retain the original
handle and transaction ID across disconnects. An explicit repeat of `commit()`
reconciles that same decision without resubmitting statements. Native SQL batches
and ChironQL atomic blocks can use a caller-owned idempotency key; preserve the
same content/key. `retry_id` is audit correlation. No mutation retries automatically.
On timeout/cancellation or lost acknowledgement, query transaction status or
explicitly reconcile the original handle/key. Receipt expiry or revoked access
never authorizes a new mutation under a consumed key. A read-only interactive
execute can have `committed=false` and no commit sequence; do not infer rollback.

Run these against separate fresh disposable legacy installations; each leaves
`sdk_chunks` and `sdk_documents` available for inspection:

```bash
python examples/multimodel_sync.py http://127.0.0.1:7401
python examples/multimodel_async.py http://127.0.0.1:7401
cargo run --locked -p chirondb-client --example sdk_multimodel -- http://127.0.0.1:7401
```

For protected use, provision `docs`, graph type `cites`, ingest template `finance`,
and SQL table `documents(id TEXT PRIMARY KEY, title TEXT, chunk RECORD_REF('docs'),
source RECORD_REF('docs'))`. Complete required offline table/scopes migrations
through the administrator CLI. Grant current SQL data actions, collection
Create/Read/Ingest/GraphWrite and endpoint object rights; graph reads also need
GraphRead. The SDK neither provisions authority nor upgrades installations.

```bash
python examples/multimodel_protected.py --url https://localhost:7401 \
  --api-key-file ./secrets/application.key --ca-cert ./secrets/ca.pem \
  --request-id document-import-1
```

This example atomically stores SQL metadata, server-allocated vector points and
their graph relation, then reconciles its decision. Reusing the same request ID
and input returns the same allocation rows. General query credential responses
are excluded from the Python typed result's representation; store explicit
issuance responses privately rather than logging/exporting them.

The SDK remains independently source-distributed beta.2. This interface does not certify
production relational/resource acceptance or engine benchmark improvements.

## Native relational SQL preview

The Rust and Python HTTP clients call `/v1/sql`, whose request body is the
atomic transaction boundary. The Rust SDK exports SDK-owned `SqlExecutionRequest`,
`SqlStatementRequest`, `RelationalValue`, `SqlExecutionResponse`, and
`SqlResult` with the existing JSON representations:

```rust
use chirondb_client::{
    ChironDbClient, RelationalValue, SqlExecutionRequest, SqlStatementRequest,
};

let response = ChironDbClient::new("http://127.0.0.1:7401")
    .execute_sql(&SqlExecutionRequest {
        statements: vec![SqlStatementRequest {
            sql: "INSERT INTO documents VALUES ($1, $2)".into(),
            parameters: vec![
                RelationalValue::Integer(7),
                RelationalValue::Text("Native SQL".into()),
            ],
        }],
        retry_id: Some("03c036f8-3746-4994-8729-f480c067c38b".into()),
        idempotency_key: Some("insert-document-7".into()),
    })
    .await?;
```

Python accepts the same tagged JSON value shape:

```python
response = client.sql(
    "INSERT INTO documents VALUES ($1, $2)",
    parameters=[
        {"type": "integer", "value": 7},
        {"type": "text", "value": "Native SQL"},
    ],
    retry_id="82f146d0-ad1f-4e3f-a046-75528e1d8296",
    idempotency_key="insert-document-7",
)
```

Successful responses keep `committed` for beta compatibility and also expose
`outcome`, `commit_sequence`, and `retryable`. An unknown outcome requires
reconciliation through transaction status or the same durable request identity.
A disconnected client must preserve the original key or transaction handle.

Supply one complete SQL statement per entry. Additional statements or an unread `END` suffix reject
before mutation. Use the statement list for an atomic batch.

Ordered-page queries may use encrypted temporary sort files. The server bounds
merge rows and decoding scratch before allocation and can return resource
exhaustion. Reduce the requested sort window when appropriate; see the
[SQL resource contract](HTTP_API.md#native-relational-sql-preview).

Disk-row decoding and version-chain metadata also use a shared storage budget.
Readers retain their reservations; mutation copies need additional capacity.
Storage pressure can return resource exhaustion even for a read. Checkpoint
loading also reserves parser and decoded-data memory; a refused load preserves
the checkpoint for a later reopen. Checkpoint output reserves serialization and
encryption buffers while preserving atomic replacement. Capture and manifest
copies also retain metadata reservations; a capture refusal after commit leaves
the durable receipt valid. Runtime schemas also retain storage reservations;
row mutations and snapshots share those schemas. Storage pressure can reject
CREATE/ALTER before commit while preserving the previous table. Index types and
per-table index maps also retain reservations; mutation map copies are admitted
before allocation and checkpoint replacements before publication. Runtime
table-name catalogs also retain reservations; snapshots and conflict checks share
names and persistent tree roots. Mutations admit changed paths before allocation.
Checkpoint activation reserves its map before publication; concurrent catalog
growth can defer activation and WAL reclamation. Relational recovery validates
projection IDs, targets and batches against committed journal decisions before
using the logical sequence frontier for duplicates. Snapshots/checkpoints no
longer retain every past SQL commit ID; legacy lists are validated and discarded.
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

`chironql_exec::execute_owned()` returns a non-Clone `QueryResult` with SQL
receiving and pipeline operation reservations. `consume()` retains them during
handoff; returned data requires its own receiving reservation. The embedded
`execute()` DTO interface remains available and transfers memory responsibility
to the application. SQL text/JSON payloads move during conversion/qualification;
join/projection copies and canonical join/sort keys reserve memory before growth.
The server uses owned results through admitted HTTP, gRPC and ChironWire encoding,
with an 8 MiB output limit. Protected SQL/pipelines recheck current authority and
poll its cancellation epoch during receiving work. Conservative operation charges
remain until output consumption and may reject queries before actual peak RSS.

Retrieval JSON rows reserve containers and numeric arrays before growth and move
projected payloads/IDs, including nested graph paths. Protected conversions keep
the core source owner until receiving admission is established; GET/SCROLL,
search/BM25/hybrid/count/graph and pipeline output retain QueryResult memory.
They poll current authority during conversion and recheck before publication.
Numeric/nested arrays poll cancellation at least every 1,024 items. Receiving
bounds are conservative; this does not change DTO fields or grant permissions.

Initial non-SQL source/catalog/mutation JSON and parser/trace/authority construction,
PostgreSQL parser/authority and other catalog construction, plus TLS/socket buffers,
other operator/index/WAL/mmap/cache allocations
and complete process bounds still require qualification. These focused ownership
checks do not establish final resource, benchmark or recovery acceptance.

For standalone SQL mutations, retry the same statement/parameters with the same
`idempotency_key` to obtain its original decision and `RETURNING` values. The key
is scoped to installation, principal and tenant and works across native transports.
`retry_id` may change on each attempt. A changed fingerprint rejects. Receipt expiry
after 24 hours preserves the consumed key. Read-only and interactive statement requests do not accept this option; use a request without a key in
the interactive examples below. See the [HTTP retry contract](HTTP_API.md#native-relational-sql-preview).

In protected mode, the SQL executor checks current point `read` access for typed
`RECORD_REF` values when written or included in results. A point with a live
SQL reference cannot be deleted until the row is unlinked or removed. If
access is revoked after a successful commit, replaying its receipt may be
denied; use the saved transaction ID and transaction-status API to reconcile
the original decision.
Protected SQL transports recheck typed references before publishing a result
and retain object authority while writing it. A revocation acknowledged
before publication prevents a queued reference result from being released.

Rust and Python also expose the same interactive transaction lifecycle:

```rust
let transaction = client.begin_sql_transaction().await?;
let decision_id = transaction.transaction_id.clone().expect("reserved at BEGIN");
let mut interactive_request = request.clone();
interactive_request.idempotency_key = None;
client.execute_sql_transaction(&transaction.handle, &interactive_request).await?;
let committed = client.commit_sql_transaction(&transaction.handle).await?;
assert_eq!(committed.transaction_id.as_deref(), Some(decision_id.as_str()));
```

```python
tx = client.begin_sql_transaction()
decision_id = tx["transaction_id"]  # Save before sending COMMIT.
client.execute_sql_transaction(tx["handle"], [
    {"sql": "SELECT id FROM documents LIMIT 10", "parameters": []}
])
receipt = client.commit_sql_transaction(tx["handle"])
assert receipt["transaction_id"] == decision_id
# client.rollback_sql_transaction(tx["handle"]) discards private writes.
```

After reconnect, repeating `commit_sql_transaction` with that saved handle
reconciles the original decision. It does not submit the SQL statements again.
Protected retries still require the current grants for the committed operation.
The SDK does not automatically retry a mutation after a network failure.
Use separate handles for concurrent units of work. Calls on one handle serialize; a busy-handle
wait can return a resource-limit error after 30 seconds. Other calls on that handle
wait while COMMIT runs; a consumed handle rejects later statement execution.
Shared resource admission and commit publication still apply
across handles.

A COMMIT failure before PREPARE, including a receipt memory-limit refusal, keeps
the live session's private statements and original handle. Retry COMMIT explicitly
or roll back that handle before idle expiry. This private state is lost on server
restart. After PREPARE starts, use the saved handle to reconcile the journal
decision; do not resend the statements as a new transaction.

Interactive history has a shared byte budget across protocols: retained SQL,
decoded parameters, savepoints and the active replay copy count toward it.
Runtime-derived limits are at most 16 MiB per transaction and 64 MiB shared.
If history admission fails during execution, roll back to an existing savepoint
or roll back the transaction. Commit, rollback and idle expiry release history;
releasing savepoints frees their names while retained buffer capacity stays
charged. This is separate from prepared-statement/portal memory and does not
measure parser/operator scratch or total RSS.

For ChironWire, `chironwirectl sql '<statement>' --parameters '<json-array>'`
accepts `--idempotency-key <key>` for standalone mutations and `--retry-id <id>` for
audit correlation. It
uses the additive `WireSqlRequest` frame and prints the typed JSON response.
The wire protocol also carries begin/execute/commit/rollback transaction
messages, although the command-line wrapper for those messages is still
pending. These interfaces expose the preview subset documented in
[HTTP API](HTTP_API.md#native-relational-sql-preview).
That subset includes non-recursive read-only CTEs and uncorrelated scalar,
`EXISTS`, and `IN` subqueries. Recursive, correlated, and lateral forms are
rejected explicitly.

### PostgreSQL driver and ORM preview

PostgreSQL receiving column/format metadata, row encoding scratch and outgoing
row/description frames reserve memory before allocation. Frames keep their
reservation during pending writes and until the final owner drops. Text/byte
fields and EXPLAIN lines are borrowed; typed JSON/vector fields encode directly
without an intermediate JSON value. Conservative numeric/array scratch bounds
may reject earlier than actual RSS. The existing 16 MiB per-message limit
includes its four-byte length field and excludes the one-byte message kind;
queries can stream multiple messages.

Receiving-memory refusal reports `53200`; framing-size refusal reports `54000`,
then closes the connection. A connection handler that exits or is aborted rolls
back its still-live private transaction. An earlier durable COMMIT remains
committed, even when its response cannot be delivered. PostgreSQL wire never
automatically replays a mutation: reconcile the original transaction identity
or application state before attempting another write.

Native and protected wire sessions share admitted startup/session containers,
prepared/parameter state and direct SQL request copies. A connection may retain
32 prepared statements and 32 portals, including unnamed objects. Replace an
existing name, `Close` it, or `DEALLOCATE` it to release state. Count exhaustion
returns `54000`; send `Sync` after an extended-protocol error, then rollback a
failed transaction. Runtime-derived byte limits are at most 64 MiB shared and
16 MiB per connection; clearing the maps retains their bounded capacity until
disconnect. Raw frames additionally own a shared storage/receiving reservation
before reading and through completion, I/O failure or task cancellation.
Native input remains limited to 16 MiB per message, protected input to 8 MiB;
protected startup/SCRAM messages remain limited to 4 KiB. Payload reads time out
after ten seconds. Empty controls and fixed small replies need no payload-sized
heap allocation; failed messages drain in 4 KiB chunks, and large control replies
retain admitted buffers. SCRAM scratch and cancellation entries are also admitted.

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

Embedded Rust callers can use `Db::relational_catalog_owned()` and
`Db::collection_names_owned(None)` for admitted metadata views. The former shares
immutable schema backing; its `iter()` borrows definitions and its `has_table()`/
`has_index()` methods inspect names. Pass `Some(&identity)` for protected collection
names. Schema views are trusted embedded metadata and are not automatically
filtered for a principal: use `view.permits_read(&table.name, &identity)` to filter
SQL table metadata and keep a fresh `Db::catalog_publication_permit(&identity)`
while publishing. Acquire the permit after gathering the views. Legacy catalog DTO adapters transfer output memory
ownership to their embedded caller; retain the owned views when engine accounting
must cover their lifetime.

For a stopped protected installation, embedded operators can call
`Db::migrate_transaction_authority_offline(data_dir)` after installing its process
keyring. It acquires an exclusive database lease, completes recovery, and writes
an audited, atomic transaction-format upgrade. The matching CLI is
`chironctl security migrate-transaction-authority --data-dir <dir> --keyring <file>`.
Transaction format 3 stores terminal decisions, consumed keys, retained retry
responses and SQL projection proofs independently of historical journal bodies.
Older readers refuse installation format 6. Keep the full journal for model
recovery until common-frontier reclamation is qualified. Client mutation DTOs and
request fingerprints remain unchanged.

Protected installations and activated transaction authority also bind catalog,
vector, graph and security WAL projections to the committed transaction's target
and mutation content. Changed or orphan projections refuse startup or cold
reload. Legacy unprotected collection-archive imports retain their existing
contract. Compact projection proofs still do not authorize full-database journal
reclamation; keep the complete history until common-frontier recovery is qualified.

Native snapshots copy installation transaction control alongside the active
content generation, preserving the copied SQL and collection state on reopen.

Parser/authority and other catalog construction, TLS/socket buffers, other engine/operator
allocations and backend cancellation during blocked output remain unqualified.
See [HTTP API](HTTP_API.md) for limits and transaction reconciliation.

The native relational PostgreSQL-wire path has a reproducible local smoke for
psycopg 3, SQLAlchemy 2, and Alembic. Start ChironDB with a disposable empty
data directory, install the three upstream packages in an isolated virtual
environment, and run:

```bash
python -m pip install -r chirondb-server/tests/requirements-postgres-orm.txt
python chirondb-server/tests/postgres_orm_compat.py
```

The script connects to `127.0.0.1:7403` by default. Override
`CHIRONDB_PG_HOST`, `CHIRONDB_PG_PORT`, `CHIRONDB_PG_USER`, or
`CHIRONDB_PG_DATABASE` when needed. It creates `orm_accounts`, `orm_parents`,
and `orm_children`, then checks prepared parameters, transactions, nullable
values, PK/UNIQUE/composite-FK reflection, and an identical-schema Alembic
comparison. Use a fresh database because the script intentionally creates
those fixed fixture tables.

The FK differential fixture sends one deterministic 160-statement history to
ChironDB and a real PostgreSQL server, comparing success/error SQLSTATE and the
complete contents of the parent plus five child tables after every statement:

```bash
CHIRONDB_DSN='host=127.0.0.1 port=7403 user=chiron dbname=gaussdb sslmode=disable' \
POSTGRES_DSN='host=127.0.0.1 port=5432 user=postgres password=secret dbname=postgres sslmode=disable' \
python chirondb-server/tests/postgres_fk_differential.py
```

The fixture explicitly enables psycopg's prepare threshold. Cleanup therefore
also exercises SQL `DEALLOCATE` against protocol-prepared statements.

Run the advanced deterministic profile with the same DSNs to compare
composite keys, `MATCH SIMPLE`/`MATCH FULL`, deferred validation,
`SET CONSTRAINTS`, self references, and a deferred self-cycle:

```bash
CHIRONDB_DSN='host=127.0.0.1 port=7403 user=chiron dbname=gaussdb sslmode=disable' \
POSTGRES_DSN='host=127.0.0.1 port=5432 user=postgres password=secret dbname=postgres sslmode=disable' \
python chirondb-server/tests/postgres_fk_advanced_differential.py
```

Rust PostgreSQL clients have a separate pinned compatibility fixture:

```bash
CHIRONDB_DATABASE_URL='postgres://chiron@127.0.0.1:7403/gaussdb?sslmode=disable' \
  cargo run --locked \
  --manifest-path chirondb-server/tests/postgres_rust_compat/Cargo.toml
```

It currently checks SQLx 0.8.6 and Diesel 2.3.13 using their public PostgreSQL
drivers: prepared binary parameters/results, nullable values, commit/rollback,
nested savepoint rollback, pool reconnect, Diesel query-builder INSERT, and
SQLSTATE `23505` mapping. The fixture enables `pq-sys/bundled` with TLS so
libpq and its OpenSSL link dependencies travel together. OpenSSL development
headers/libraries must be discoverable by `openssl-sys` (Homebrew OpenSSL on
macOS); no manual linker flags are required.

Run both complete fixtures against a fresh encrypted protected installation:

```bash
cargo build --release --bin chirondb --bin chironctl --locked
cargo build --manifest-path chirondb-server/tests/postgres_rust_compat/Cargo.toml --locked
python chirondb-server/tests/protected_orm_compat.py \
  --server target/release/chirondb --ctl target/release/chironctl \
  --rust-fixture chirondb-server/tests/postgres_rust_compat/target/debug/chirondb-postgres-rust-compat \
  --output /tmp/chirondb-protected-orm-new
```

Use the Python dependencies above and an output directory that does not exist.
The runner generates a test CA, verifies TLS (`verify-full`), issues durable
SQL passwords, migrates to strict SQL scopes and gives a non-admin application
principal only Schema permission. Drivers create their own SQL tables. It also
checks table grants, catalog visibility, revoke/regrant, rename/replacement,
reopen, encryption and audit verification. Additional psycopg checks cover
15 typed columns with text/binary parameters and results, NULLs, and cancellation
of simple, prepared and autocommit mutations. Keep `secrets/` and `data/` private;
only the sanitized `report.json` and redacted logs are acceptance artifacts.
This fixture is local compatibility evidence; the wider type, cancellation,
concurrency and release matrix remains required.

`TIMESTAMPTZ` text parameters accept RFC 3339 or ISO date/time with a numeric
offset and normalize to UTC at microsecond precision. Finer nonzero fractional
precision rejects with `0A000`; zone-less or invalid inputs reject with `22007`.
NUMERIC parameters currently require text encoding; binary NUMERIC results are
supported, while binary NUMERIC input rejects with `0A000` before mutation.

Protected sessions support SQL `DEALLOCATE` (including the `DEALLOCATE ALL`
cleanup issued by psycopg after rollback). Cancellation requires a TLS
CancelRequest using the connection's secret. Use psycopg `cancel_safe()` with
libpq 17 or newer and verified TLS; the older plaintext cancel method cannot
access a protected listener. An interrupted explicit transaction requires
ROLLBACK before further SQL (`25P02`). Cancellation can race commit, so a
disconnected client must reconcile application state instead of automatically
repeating a mutation. Synchronous SQL execution runs off the network workers;
request cancellation and server shutdown remain active together.

Protected PostgreSQL sessions report work-capacity overload as `53300`. A simple
query completes with ReadyForQuery; extended clients must send Sync after the
error. An active transaction becomes failed and must be rolled back. Sync,
Flush, Close and a simple-query `ROLLBACK` can run while work slots are full.
Payload-buffer exhaustion closes the session with `53300` before accepting the
payload. A small reserved TLS lane accepts only CancelRequest when ordinary
connection slots are full; cancellation can still fail if that lane is busy.
Cancelling or timing out SQL does not free its work slot until the worker exits.

Protected sessions also account retained prepared statements, portal parameters
and SQL request copies against per-session and shared byte pools. Capacities
follow the detected host/container resource profile, up to 16 MiB per session
and 64 MiB shared; the existing 32-statement/32-portal limits still apply.
Byte-capacity exhaustion returns `53200` (and closes the connection if session
setup cannot be admitted). For an extended-protocol error, send Sync; roll back
an aborted transaction, then Close unused objects or issue `DEALLOCATE ALL`.
Replacing a binding requires room for the new value while the old one is still
live. JSONB admission includes its decoded containers and strings. Prepared SQL
is shared by its portals, and an executing worker retains its request reservation
until it exits. These pools cover frontend ownership, not total process memory.

Authorized `/v1/metrics` exposes `chirondb_pgwire_session_reserved_bytes`,
`chirondb_pgwire_session_capacity_bytes` and
`chirondb_pgwire_memory_rejections_total`. Reserved bytes should return to zero
after all protected PostgreSQL sessions and their workers exit; this is a
reservation check, not an RSS measurement.

The Python fixture also executes a bounded Alembic upgrade/downgrade: create
table, add column, create unique index, write/read the migrated shape, drop the
index, drop the added column, verify the preserved row and reflected schema,
rename the remaining data column in both directions, rename the table in both
directions, alter the primary-key column from `INTEGER` to `BIGINT`, then drop
and restore a column's NOT NULL/static-default metadata. It also creates,
reflects, and drops named UNIQUE and PRIMARY KEY constraints through Alembic;
the server validates existing rows, keeps independent user-index ownership,
persists the exact key kind and name selected by each new FK, and rejects dropping that owner
with SQLSTATE `2BP01`. The migration also renames both key constraints through
the PostgreSQL dialect with `ALTER TABLE ... RENAME CONSTRAINT`, confirms their
reflected names, then creates a dependent table and executes
`DROP CONSTRAINT ... CASCADE`. Reflection confirms that the selected UNIQUE
owner and dependent FK disappear together before an orphan insert succeeds.
It separately verifies `DROP TABLE` dependency SQLSTATE `2BP01`, then executes
`DROP TABLE ... CASCADE`, reflects the surviving child without its old FK, and
inserts an orphan through the unchanged upstream driver.
It also proves `DROP COLUMN` returns `2BP01` while a key/FK depends on the
column, then executes comma-separated `DROP COLUMN ... CASCADE` plus a second
DROP COLUMN in one statement, reflects the surviving parent shape and child
without that FK, and inserts an orphan.
The fixture
then drops the table. It
queries the supported `information_schema.tables` and
`information_schema.columns` projection for the migrated relational catalog.
This is a preview boundary. Broader revision scripts and
large/online schema-alter paths, cross-family/`USING` column conversion,
cancellation under saturation and the broader protected driver matrix, the
complete binary type matrix, malformed-protocol fuzzing, and arbitrary catalog
queries remain open compatibility work.

Protected user/role/key syntax, every statement example, revision semantics and
working TLS/API recipes: [ChironQL security reference](CHIRONQL_SECURITY.md).

The beta includes synchronous/async Python and asynchronous Rust clients for the HTTP
API. SDK implementations now live in independent private repositories:
[chirondb-rust](https://github.com/Gaussian-id/chirondb-rust),
[chirondb-py](https://github.com/Gaussian-id/chirondb-py), and
[chirondb-js](https://github.com/Gaussian-id/chirondb-js). Registry publication
remains a separate release step. Ordinary server builds need no SDK access.

Start a server using [Getting started](GETTING_STARTED.md#1-build-and-start).
Each language's starter creates `products`; use an unused collection name or
skip creation if that collection already has the same three-dimensional
schema. Advanced snippets continue after the starter in the same script and
need both `phone` and `book`. Re-running an upsert restores either point.

## Python

Python `3.10+` is required. From an existing checkout, skip the first two commands.

```bash
git clone https://github.com/Gaussian-id/chirondb-py.git
cd chirondb-py
python3 -m venv .venv
source .venv/bin/activate
python -m pip install .
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

The Python client's legacy `hnsw_m`, `hnsw_ef_construction` and
`hnsw_ef_search` arguments accept zero as the engine default. `hnsw_m=1`
returns a request error before collection mutation. Omit these arguments for
normal LS-VEC use; they do not select a separate index.

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
that times out raises `requests.Timeout`. Error fields retain `status` and the original
`message`, plus optional `code`, `item_index`, `retry_after_ms`, `hint`, `query_id`,
`transaction_id`, `retryable`, and `position`. Async transport exceptions come from
HTTPX. The client does not start a server.
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
chirondb-client = { git = "https://github.com/Gaussian-id/chirondb-rust" }
# Pin a qualified full `rev` for reproducible applications.
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
server requires authentication. `Error::Api { status, message }` keeps its shape;
`api_details()` reads optional structured fields and returns `None` for non-JSON.
Connection failures return a client error;
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

The Rust SDK owns its graph request/result types and preserves their public
names and JSON contracts. EdgeId stays opaque. SDK and embedded-engine structs
have distinct Rust type identities:

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

### Tabular ML materialized views (local preview)

Python and Rust use the same argument order as ChironQL: `view`, `source`,
`target`, `features`, `task`, `model`. Calling `materialize_ml` again with the
same arguments refreshes from a new source snapshot. Poll `get_ml_job` until
`status` is `succeeded` before reading `get_ml_view`; use its `next` cursor
for additional pages. `drop_ml_view` removes the published table so a new
definition may reuse the name.

```python
job = client.materialize_ml(
    "sales_forecast", "sales", "demand", ["sale_date", "region", "price"],
    "regression", "decision_tree",
)
status = client.get_ml_job(job["rows"][0]["job_id"])
page = client.get_ml_view("sales_forecast", limit=100)
```

```rust
let job = client.materialize_ml(
    "sales_forecast", "sales", "demand", &["sale_date", "region", "price"],
    MlTask::Regression, MlModel::DecisionTree,
).await?;
let job_id = job.rows[0]["job_id"].as_str().unwrap();
let status = client.get_ml_job(job_id).await?;
let page = client.get_ml_view("sales_forecast", 100, None).await?;
```

These examples require the optional worker and an unprotected local server.
`status` may still be `queued` or `running` immediately after submission;
poll before relying on `page`. Models are `decision_tree` and `random_forest`
in Python, with the corresponding `MlModel` variants in Rust. Foundation-model
integration is removed; `tabfm`, `causilo`, `tabpfn` and `prior_labs` are rejected.
The ML worker remains a local evaluation preview, **not production ready**.
See [ChironQL](CHIRONQL.md#tabular-ml-materialization-preview).

The Rust client exposes `execute_chironql(&ChironQlRequest)`. The Python client
exposes `chironql(query, parameters=None, retry_id=None, ...)`. Both call the
same `/v1/chironql` analyzer and executor used by the terminal. Use typed API
methods when you do not need language composition; use ChironQL 1.4 `SQL`,
read-only `PIPELINE`, or the bounded atomic `TRANSACTION` block when one request
must express relational or multi-model work. The transaction block uses the
same request `parameters` and audit-correlation `retry_id` fields as standalone SQL.
For standalone SQL mutations and atomic `TRANSACTION` blocks, set
`ChironQlRequest.idempotency_key` in Rust or
pass `idempotency_key="operation-1"` to Python `chironql(...)`. Retries use the
same core ledger as the native SQL methods: keep SQL text and typed parameters
identical, preserve all vector/graph content for atomic blocks, and keep the key.
Atomic replay returns the same allocated `edge_id` rows and transaction ID. Protected INSERT
additionally returns `binding` and `record_ref` allocation rows. Other
ChironQL statement families currently
reject a supplied key. No SDK automatically repeats a mutation after disconnect.
See [HTTP_API.md](HTTP_API.md) and [CHIRONQL.md](CHIRONQL.md).

On a protected installation, standalone SQL and interactive SQL transactions
use the same durable identity as other protected routes. After the offline
[table-authority migration](CHIRONQL_SECURITY.md#protected-relational-sql), an
installation administrator uses ChironQL `GRANT ... ON TABLE ... TO ROLE ...`
to configure table ID/incarnation scopes with `read`, `create`, `update`, and
`delete`, without a vector collection. Grant installation action
`schema` only to principals that may run DDL. Protected applications use the
bounded `PIPELINE` and INSERT/UPDATE/DELETE `TRANSACTION` profiles in
[the protected reference](CHIRONQL_SECURITY.md). The INSERT form uses server IDs and explicit
`NEW_RECORD` bindings; collection graph setup requires `schema`. BM25 and dense+BM25 are available
standalone and in the PIPELINE retrieval stage; optional graph stages support node/edge filters
with node-only output. Standalone protected `TRAVERSE` through `chironql()` supports
nodes, edges and paths with authorized payloads; paths require `LIMIT`.
Numeric sparse hybrid remains unavailable. PostgreSQL clients require the separate protected SQL
password credential and verified TLS described in that reference.

After offline `migrate-sql-scopes`, collection-name permissions no longer
allow SQL. Existing permissions become exact table roles; newly created tables
confer SQL data rights on their immutable creator. Older receipts without saved
table authorization are denied without re-execution. See the
[strict migration contract](CHIRONQL_SECURITY.md#protected-relational-sql).

Optional `EXPECT SQL ROWS n;` immediately after a transaction's SQL stage guards sibling
vector/graph writes with the directly affected SQL row count. This is useful with revision
predicates. A mismatch returns `chironql.sql_row_precondition_failed` before the durable
commit decision; it has no committed receipt. Preserve the guard when retrying a consumed
key. Requests without it retain existing zero-row semantics. The same query text works on
all ChironQL transports and SDKs; older servers reject the stage before mutation.
See [row preconditions](CHIRONQL.md#sql-row-preconditions).

## SDK scope

- All three SDKs call the JSON HTTP API on port `7401`.
- Generated gRPC clients are not published; see [the gRPC guide](GRPC_API.md).
- The clients do not manage server lifecycle, TLS certificates, backups, or
  data-directory upgrades.
- The installation transaction journal durably decides mutations before WAL/audit
  projections. Legacy `wait=false` returns `202 Accepted` with a durable commit
  decision; recovery completes projections. Protected guarded mutations require
  `wait=true`. A lost response needs reconciliation, not an assumed rollback.
- Public deployments require server TLS, RBAC/API credential Secrets, and an
  external encryption keyring. SDK `401`/`403` responses distinguish invalid
  credentials from a principal denied by policy; `503` means the fail-closed
  audit path was unavailable.

## Disposable graph + vector preview

The server repository preserves the mixed embedded-engine/SDK walkthrough in
its separate authenticated integration harness. Fetch the pinned SDK dependencies
with authorized access, then run without configuring a data directory:

```bash
cargo run --locked --manifest-path sdk-integration/Cargo.toml --example graph_vector_preview
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

### Catalog-authenticated ChironQL

For a fresh server, first run `chironctl security init`, then provision collections
and ingest templates through ChironQL 1.3. See the [systemd/Compose deployment
runbook](../deploy/protected/README.md) for API-key delivery, TLS and recovery.
The SDKs do not initialize or reset the server authority.

For administrative automation use `chironql --api-key-file ... --ca-cert ...` and
`--key-out ...` for API-key issuance or rotation. The CLI handles expected revisions,
private file creation and secret redaction. Ordinary application users can execute
`SHOW CURRENT USER PRIVILEGES` and the protected GET/COUNT/SCROLL/dense subset.

Protected creation uses `CREATE POINTS ... USING TEMPLATE ... REQUEST 'stable-id'`
and returns server-generated IDs. Persist the request ID and identical input for
retry; changing the input under that ID conflicts. Replace existing objects with
`UPDATE POINTS`; legacy client-provided-ID UPSERT is rejected on protected collections.
A retry reauthorizes each object, including after restart or credential rotation.
The initial replay implementation requires Read capability. Direct API consumers
must not log the top-level `credential` field on ISSUE/ROTATE responses, must store
it privately, and must not retry issuance automatically after a lost response.
See [the complete terminal/API contract](HTTP_API.md#protected-chironql-administration-language-12).

## Native text hybrid SDK methods

These methods work on the legacy surface and the protected text-retrieval profile.
Use `client.protected().vector().text_hybrid_search(...)` for a protected hits-only
response. Collection/object Search and field Query permissions define its corpus.

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

For BM25 alone, pass `[]` as the Python vector or `vec![]` in `TextHybridQuery`.
Those results contain raw BM25 scores; supplying a vector returns RRF scores.
The same HTTP methods work with protected bearer credentials. Collection and
object Search plus field Query permissions determine the corpus; hidden fields
and documents cannot affect scores. Protected HTTP returns hits only (Rust's
legacy diagnostic fields deserialize to defaults). The embedded protected entry
point is `Db::text_hybrid_search_authorized`, returning `AuthorizedOutput` that
must be published through its authorization guard. Native text retrieval is
separate from MCP configuration below.

## MCP clients

MCP currently requires legacy API-key/RBAC configuration. It is unavailable on
protected installations initialized with `chironctl security init`; keep `[mcp]`
unset there. A protected administrator key does not enable MCP or grant document
access. See the [protected deployment runbook](../deploy/protected/README.md).

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
[Python ingestion example](https://github.com/Gaussian-id/chirondb-py/blob/main/examples/mcp_ingest.py) after
installing the Python client above:

```bash
export CHIRONDB_URL=http://127.0.0.1:7401
export CHIRONDB_EMBEDDING_ENDPOINT=http://127.0.0.1:8000/v1/embeddings
python examples/mcp_ingest.py
```

Provide the server key through `CHIRONDB_API_KEY`; set
`CHIRONDB_EMBEDDING_API_KEY` if the provider needs it. The example embeds a
chunk, stores its vector and text, embeds a question, and calls native hybrid
search. The MCP collection binding must use the same model. It does not create
sparse vectors.

Protocol references: [Build an MCP server](https://modelcontextprotocol.io/docs/2026-07-28/develop/build-server),
[Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http),
and [MCP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization).

## Async Python and connection lifetime

Install the optional async transport; ordinary sync installations still use `requests`:

```bash
python -m pip install '.[async]'
```

`AsyncChironDbClient` has the same operation arguments and result shapes as the
sync client. Each operation is awaited; `scroll_all` is an async iterator:

```python
from chirondb_client import AsyncChironDbClient, GraphConstraint

async def retrieve(base_url, api_key):
    async with AsyncChironDbClient(base_url, api_key=api_key, timeout=30) as db:
        result = await db.search(
            "products", vector=[0.0, 0.0, 1.0], k=5,
            graph=GraphConstraint(anchors=("phone",), edge_types=("related_to",)),
        )
        async for point in db.scroll_all("products", page_size=100):
            print(point["id"])
        return result
```

Keep a client alive across requests to reuse its connection pool, following the
[HTTPX async client lifecycle](https://www.python-httpx.org/async/). Use `with` or
`close()` for sync Python, and `async with` or `await aclose()` for async Python.
Async transport errors are HTTPX exceptions, including `httpx.ConnectError` and
`httpx.TimeoutException`; sync transport errors remain `requests` exceptions.
Canceling an async task cancels the HTTP request; it does not promise rollback
of a server mutation. Inspect/reconcile the original request identity before
resubmitting an ambiguous write. Closing the client does not commit or abort an
open deferred graph session.

Both Python clients accept `ca_cert="/path/to/ca.pem"` for a private CA and retain
certificate verification. Empty CA paths and boolean values are rejected. Rust uses `.with_ca_certificate(&pem_bytes)?`,
`.with_timeout(Duration::from_secs(30))`, or `.with_http_client(configured_client)`.
Supplying a CA replaces the Rust HTTP client; configure a custom client and inject
it when several transport options are needed. SDK-owned Rust requests default to
30 seconds, including requests made through an injected client. Python timeouts
use the transport's connection/read/write semantics rather than a promised total
wall-clock deadline. SDK-owned transports disable automatic retries. An injected
Rust HTTP client retains the caller's transport policy: configure it with
`.retry(reqwest::retry::never())` to keep the same no-retry contract.
Dynamic route identifiers are encoded as individual URL segments; dot segments
are rejected. Encoding does not relax server identifier rules.

## Typed graph evidence in Python

Existing graph dictionary results remain unchanged. Decode a result when typed
access is useful:

```python
from chirondb_client import (
    GraphDispatchTrace, GraphMutationReceipt, GraphTraversalQueryResult,
    TraversalBudget, ColdTraversalBudget,
)

edge = db.relate("products", "phone", "book", "related_to")
page = db.traverse("products", anchors=["phone"], returns="edges", limit=100)
traversal = GraphTraversalQueryResult.from_dict(page)
for row in traversal.result.rows:
    print(row.id)  # EdgeToken: persist/pass unchanged to unrelate or property updates

receipt = GraphMutationReceipt.from_dict(db.merge_edge_properties(
    "products", edge.edge_id, {"source": "catalog"},
))
print(receipt.operation_lsn, receipt.durable, receipt.replayed)
db.unrelate("products", edge.edge_id)
```

Node, edge, and path rows have distinct typed decoders. Traversal results retain
stats, epoch, warnings and truncation. `GraphDispatchTrace.from_dict(result["graph"])`
preserves the server's planner evidence for constrained search; it does not infer
achieved recall. Typed decoders ignore future unknown fields and preserve warning
strings. `TraversalBudget` accepts the canonical limits and an optional
`ColdTraversalBudget`; pass it to `GraphConstraint` or `traverse` wherever a budget
dictionary was accepted. An explicit `TraversalBudget()` defaults to depth 5;
omitting a constrained-search budget keeps the server's depth-1 default.
Path traversal requires an explicit `limit`; this caps returned rows separately
from traversal work limits.

## Collection recall and named vectors

Both SDKs accept `recall_sla` and `named_vector_dims` at collection creation and
retain them when decoding collection configuration:

```python
db.create_collection(
    "documents", vector_dim=3, metric="cosine", recall_sla=0.95,
    named_vector_dims={"title": 2},
)
```

The Rust `CollectionConfig` has matching fields, and `SearchQuery::default().k`
is 10. Existing exhaustive `CollectionConfig` literals must supply the new fields
or use `..Default::default()`. Exhaustive error matches must handle the new
`InvalidInput` validation variant; the `Api { status, message }` pattern stays
unchanged. `compact` is available in both SDKs. A collection SLA, a per-query
`recall_target`, and measured recall are separate concepts: request fields are
not measurements and SDK results do not manufacture achieved recall. Non-finite
recall values are rejected before a request is sent, rather than becoming `null`
and silently dropping the contract. In Rust this is a serialization/builder
`Http` error; Python raises `ValueError`.

## Protected application operations

Use `db.protected()` only against an installation already provisioned by the
administrator. It shares the parent's connection pool and credentials and offers
`whoami`, `create_points`, `update_points`, `get_points`, `count`, `scroll`, dense
`search`, `delete`, and `delete_by_filter`. Authentication/authorization is checked
by the server on every request; the SDK does not cache a permission decision.
An administrator key does not automatically grant document access.

The following example assumes a provisioned two-dimensional `docs` collection,
a `finance` ingest template that permits `/text` and its dense representation,
and an application credential with Create/Ingest/Read/Search/Update/Delete authority:

```python
import os
from chirondb_client import ChironDbClient

with ChironDbClient(
    os.environ["CHIRONDB_URL"], api_key=os.environ["CHIRONDB_API_KEY"],
    ca_cert=os.environ.get("CHIRONDB_CA_CERT"),
) as db:
    app = db.protected()
    points = [{"vector": [1.0, 0.0], "payload": {"text": "refund policy"}}]
    ids = app.create_points(
        "docs", template="finance", points=points,
        request_id="refund-policy-import-v1",
    )
    assert app.create_points("docs", "finance", points, "refund-policy-import-v1") == ids
    print(app.search("docs", [1.0, 0.0], k=5)["hits"])
    app.update_points("docs", [{
        "id": ids[0], "vector": [0.0, 1.0], "payload": {"text": "updated policy"},
    }], wait=True)
```

With `AsyncChironDbClient`, use `async with` and await these same methods.
Python returns `list[str]` from create, integer counts from update/delete, and
`{"hits": [...]}` from protected search. Rust returns `Vec<String>`, `u64`, and
`ProtectedSearchResponse { hits }`; its protected search request type is
`ProtectedSearchQuery` and creation accepts canonical `NewPoint` values:

```rust
use chirondb_client::{NewPoint, ProtectedSearchQuery};

let app = db.protected();
let points = vec![NewPoint {
    vector: vec![1.0, 0.0],
    vectors: Default::default(),
    sparse_vector: None,
    payload: serde_json::json!({"text": "refund policy"}),
}];
let ids = app.create_points("docs", "finance", points, "refund-policy-import-v1").await?;
let result = app.search("docs", ProtectedSearchQuery {
    vector: vec![1.0, 0.0], k: 5, ..Default::default()
}).await?;
println!("{} {}", ids[0], result.hits[0].id);
```

Protected creation requires a caller-supplied nonempty request ID and 1–1024
points without client IDs. Persist the original input and request ID: exact replay
returns the same allocated IDs; changed input conflicts. The current replay path
also requires Read authority. Creation is durable and exposes no `wait=false`
option. The helper escapes strings and recursively serializes ChironQL literals,
including nested payloads; non-finite numbers and integers outside the exact-f64
range (absolute value greater than 2^53) are rejected before network I/O.
The server's ChironQL parser uses f64 numbers; callers needing larger exact
integers should store strings or use an appropriate existing HTTP operation.

`update_points` updates existing IDs; legacy `upsert` is not protected creation.
Protected update requires `wait=true`; `wait=false` is rejected before mutation. Protected delete
operations use the main server's durable contract without a `wait` argument.
Protected search publishes only hits, not graph traces, elapsed/candidate metrics,
or achieved recall. `whoami.identity_revision` is absent unless the caller has
identity-management authority. Unsupported operations fail closed.

Protected SQL and interactive transactions are available through `relational()`.
Protected traversal, read pipelines and atomic SQL/vector/graph transactions run
through `query()`. Protected graph REST/deferred endpoints and numeric sparse
hybrid remain unavailable. User/role/key administration helpers are outside the
application SDK. No credentials are cached or substituted.

Run the async examples against the corresponding server configuration:

```bash
# Legacy graph server; choose a fresh collection name.
python examples/graph_app.py --collection sdk_graph_demo

# Protected server: supply application credentials and CA through the environment.
python examples/protected_app.py --request-id refund-policy-import-v1
```

The examples create application records and leave them available for inspection.
They do not initialize authority or issue credentials.

## Node.js / TypeScript

The [Node SDK](https://github.com/Gaussian-id/chirondb-js) provides camelCase
methods for the same HTTP contracts, with ESM/CommonJS exports and TypeScript
declarations. Install a qualified local npm tarball until a registry release
is explicitly published. Request/response DTO fields keep server snake_case.

```js
import { ChironDbClient } from 'chirondb-client';
const db = new ChironDbClient('http://127.0.0.1:7401', {
  apiKey: process.env.CHIRONDB_API_KEY, timeoutMs: 30000,
});
try {
  const rows = await db.relational().sql('SELECT $1', [
    {type: 'integer', value: 9223372036854775807n},
  ]);
  console.log(rows.results);
} finally { db.close(); }
```

Use `bigint` for large integer inputs and strings for typed SQL decimals.
Supply trusted PEM via `caCertificate` for custom CAs. A final `{signal}`
argument cancels a request; `close()` disposes pooled connections and pending
requests. Mutations have no automatic retries. Reconcile an uncertain COMMIT
using the original BEGIN transaction ID with `transactionStatus()` or the
transaction object's `reconcile()`. See each SDK repository's release guide
for package qualification and manual publication instructions.
