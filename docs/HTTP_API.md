# ChironDB HTTP API

Protected user/role/key syntax, every statement example, revision semantics and
working TLS/API recipes: [ChironQL security reference](CHIRONQL_SECURITY.md).

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
response reports process and durable-projection availability without filesystem
paths or collection counts; operational metadata requires authenticated
operational access. After a large recovery, validate a representative
authenticated SQL or retrieval query before routing production traffic:
`/health` can succeed while query indexes are still warming and a client
query can exceed its timeout.

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

## Transaction outcome and degraded writes

Every mutation is decided by the installation transaction journal before its
collection/catalog WAL and audit-log projections are published. Consequently,
`wait:false` still returns `202`, but the mutation's commit decision is durable;
it no longer means that the accepted write may disappear on process failure.

An initialized protected installation requires `wait:true` for point updates and
other guarded mutations. It rejects `wait:false` with HTTP `400` before mutation;
retry synchronously. The legacy profile retains the `202` behavior above.

If the server cannot prove whether the COMMIT frame reached durable storage, it
returns `503` with a reconciliation ID:

```json
{
  "code": "transaction.outcome_unknown",
  "error": "transaction outcome is unknown: 550e8400-e29b-41d4-a716-446655440000",
  "transaction_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

Query `GET /v1/transactions/{transaction_id}` (or the unversioned equivalent)
with the same authentication used for other data routes. The response reports
`state` as `committed`, `rejected`, `outcome_unknown`, or `expired`, plus the
commit sequence and whether storage and audit projections are complete. On a
protected installation, only the exact principal and tenant recorded in the
durable PREPARE may read that decision. Foreign, cross-tenant, and unknown IDs
all return `security.not_found`; this avoids exposing commit metadata through a
guessed UUID. Ordinary RBAC installations retain the `expired` response for an
ID no longer present in the journal.

After a durable COMMIT, failure of either projection does not turn the response
into a rejection. ChironDB publishes the committed result, changes `/health` to
`503` with `status: "degraded"`, keeps safe reads available, and rejects later
mutations until restart recovery has repaired both projections exactly once.

## Native relational SQL preview

`POST /v1/sql` and `POST /sql` execute the same native relational engine. One
request is the transaction boundary. DDL must be the only statement in its
request; multiple DML and read statements commit atomically. Mutating requests
always use the durable transaction journal and return a `transaction_id`.

```bash
curl --fail http://127.0.0.1:7401/v1/sql \
  -H 'content-type: application/json' \
  -d '{
    "statements": [{
      "sql": "INSERT INTO documents (id, title) VALUES ($1, $2)",
      "parameters": [
        {"type":"uuid","value":"550e8400-e29b-41d4-a716-446655440000"},
        {"type":"text","value":"Native relational"}
      ]
    }],
    "retry_id": "8367d0a8-471f-4f66-b2d4-f986f0b841a7",
    "idempotency_key": "create-document-550e8400"
  }'
```

`retry_id` is audit correlation. Optional `idempotency_key` deduplicates a
standalone mutating SQL request across HTTP, gRPC and ChironWire for the same
installation, principal and tenant. Keys contain 1–256 bytes without control
characters. The fingerprint includes the exact SQL statements and typed parameters;
changing a correlation ID or transport does not change it. Different SQL text,
parameters or operation with the same consumed key is rejected.

Each `statements[].sql` entry must contain one complete statement. Additional statements
or unread suffixes such as `INSERT INTO items VALUES (1) END` are rejected
before mutation; the executor does not commit only the recognized prefix.
Use separate entries in `statements` for a supported atomic SQL batch.

Supported single-table `ORDER BY ... LIMIT/OFFSET` queries can use encrypted
sort files when an encryption keyring is configured. Merge readers, decoded rows
(including JSON expansion), and frame/decryption scratch are admitted before
allocation against shares of the SQL request budget. Exhaustion rejects the query
with a resource error; temporary sort files are cleaned up on completion,
cancellation, or quota refusal. This does not yet cover every SQL operator or
parser allocation. No query-specific memory setting is required.

Reads from relational row runs admit typed payload memory against the shared
storage budget before decoding. Copies of a decoded row version share immutable
values and retain their reservation until the last reader releases them. Version
chain metadata is also admitted before disk collection, mutation copies and
growth, including the temporary overlap of old and new buffers. Snapshots share
the existing reservation; a private copy needs its own. Storage pressure can
therefore reject reads or writes with a resource error. A rejected copy or garbage
collection keeps the previously published row state.

Checkpoint loading also admits parser scratch and decoded schema, transaction
history and legacy inline rows before allocation. The decoded checkpoint retains
its reservation while recovery consumes it; quota refusal leaves the checkpoint
unchanged so it can be reopened when capacity is available. Capturing a checkpoint
and copying its manifest or segment references also reserve metadata memory;
reservations stay attached until those copies and their snapshot pins are dropped.
If capture is refused after a durable commit, the committed receipt remains valid
and WAL recovery retains the acknowledged write. Runtime table schemas keep
independent storage reservations after recovery. Table snapshots, ordinary row
mutations and prepared conflict checks share the immutable schema and its
reservation. Schema retention can refuse CREATE/ALTER before commit when storage
capacity is unavailable; the previous table remains usable. This does not yet
account for DDL/parser construction or other public catalog results. PostgreSQL
catalog producers have separate receiving reservations as described below. Scalar-index type
metadata and per-table index maps also own storage reservations. Snapshots share
them; mutation copies reserve map nodes and column-name keys before allocation.
Checkpoint replacement maps are prepared before publication. Runtime table-name
catalogs also reserve storage memory; snapshots and conflict checks share names
and persistent tree roots. Mutations admit changed tree paths before allocation.
Checkpoint activation reserves its map before publication; concurrent catalog
growth can defer activation and WAL reclamation. Relational recovery validates
projection IDs, targets and batches against committed journal decisions before
using the logical sequence frontier to skip duplicates. Snapshots/checkpoints
no longer retain an ID for every past SQL commit; legacy ID lists are validated
and discarded. Durable retry receipts and consumed keys remain in the journal.
Recovery verification
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
row/description frames reserve memory before allocation. A frame keeps its
reservation until its final owner drops, including while a write is pending.
ChironQL SQL/pipeline receiving and HTTP output also retain their reservations.
Remaining initial non-SQL engine/receipt conversions, ordinary public WAL payloads/results,
DDL/parser construction, other catalog results, operator scratch, index lookup/key scratch,
remaining mmap/cache/publication/cleanup backing and other SQL allocations still
require accounting. Typed result adoption transfers the existing SQL working-set
reservation; it does not establish allocation accounting for every operator.
These checks do not certify complete process memory
or recovery of every legacy large record under a constrained profile.

Checkpoint output reserves one serialization buffer, including growth overlap,
and bounded encryption scratch before writing. Persistence uses fixed-size
chunks and retains the existing atomic replacement protocol. Quota refusal or
cancellation detected while encoding or streaming leaves the previous checkpoint
intact; the WAL remains authoritative for writes not yet checkpointed.

An identical retry returns the original durable decision, transaction ID and
results, including `RETURNING` values. A mutation affecting zero rows also consumes
its key. PREPARE without COMMIT reconciles as rejected; an uncertain commit remains
`outcome_unknown` until journal recovery establishes the decision. Responses are
available for 24 hours; after that, the key remains consumed and cannot execute
again. Use the returned transaction ID with the transaction-status endpoint.
Current authorization still applies to replay; a receipt does not restore revoked
access. Rejection during validation before PREPARE does not consume a key.

Read-only SQL and interactive statement execution reject this option. Standalone
ChironQL SQL and atomic multi-model `TRANSACTION` requests use the same core ledger;
interactive native COMMIT uses its stable BEGIN identity instead of a request key.
The first valid keyed commit durably upgrades the journal to
format 2; protected installations publish their startup reader fence first.
Legacy snapshot/restore is not qualified to preserve this ledger. Production
backup/restore, journal reclamation and the complete retry surface remain open.

Value tags are `null`, `boolean`, `integer`, `float`, `decimal`, `text`,
`bytes`, `date`, `timestamp_utc`, `uuid`, `json`, `vector`, and `record_ref`.
`bytes` uses a JSON byte array and `json` carries the JSON value directly. A successful response contains the
snapshot sequence and one typed result per statement:

Parameters use PostgreSQL-style positional placeholders `$1` through `$n`.
The preview rejects `?` placeholders instead of assigning them dynamically.

```json
{
  "transaction_id": "5e9bca5a-6c75-4eeb-90b4-8adc598dd167",
  "snapshot": 3,
  "committed": true,
  "outcome": "committed",
  "commit_sequence": 3,
  "retryable": false,
  "results": [{"kind":"mutation","affected_rows":1}]
}
```

`outcome`, `commit_sequence`, and `retryable` are additive beta fields;
`committed` remains for compatibility. Standalone read-only responses have no
`commit_sequence`. An interactive execute that has not reached COMMIT reports
`committed:false` and no commit sequence. The native executor accepts at most
32 statements and bounds the decoded request, write set, and encoded result to
8 MiB each; the row ceiling remains 100,000.

The local preview implements typed tables, nullable columns, primary and unique
keys, CHECK constraints, scalar `CREATE/DROP INDEX`, and single/composite/self-referencing foreign
keys. Foreign keys support `MATCH SIMPLE/FULL`, immediate or deferred checking,
`SET CONSTRAINTS`, and `NO ACTION`, `RESTRICT`, `CASCADE`, `SET NULL`, or
`SET DEFAULT` for update/delete. DML supports `RETURNING`; insert supports
`ON CONFLICT ... DO NOTHING` and `ON CONFLICT ... DO UPDATE`. Conflict targets
may infer a declared primary/unique key by columns in either order, or name a
primary/unique constraint. `DO UPDATE` can read the existing row and
`excluded`, use integer/float arithmetic or text concatenation, apply a bounded
`WHERE`, and return the resulting row. Constraints and FK actions are checked
again after the update. A statement that would affect one row twice is rejected
atomically (PostgreSQL SQLSTATE `21000` on PostgreSQL wire). SELECT, UPDATE,
and DELETE predicates support comparisons, `AND`/`OR`/`NOT`, `IS NULL`,
`IN`/`NOT IN`, `BETWEEN`/`NOT BETWEEN`, and bare BOOLEAN columns with SQL
three-valued logic. CHECK constraints use the same NULL rules. SELECT also supports bounded
`INNER/LEFT` equijoins, projection, `SELECT DISTINCT`, `GROUP BY`, `HAVING`, `COUNT`, `SUM`,
`AVG`, `MIN`, `MAX`, `ORDER BY`, `LIMIT/OFFSET`, and `EXPLAIN`. Aggregates
ignore NULL except `COUNT(*)`; an ungrouped aggregate over no rows returns one
row with count zero and the other aggregates NULL. Integer `SUM` rejects on
64-bit overflow and `AVG` returns double precision. `ORDER BY` accepts source
columns, output aliases, and one-based output positions such as `ORDER BY 2
DESC`; zero and positions beyond the select list are rejected.
Read-only query composition supports non-recursive CTEs, uncorrelated scalar
subqueries, `EXISTS`/`NOT EXISTS`, and `IN`/`NOT IN` subqueries. CTEs are
materialized inside the statement snapshot; chained CTEs may reference earlier
CTEs. A scalar subquery returns NULL for zero rows and SQLSTATE `21000` over
PostgreSQL wire when it returns more than one row. Recursive CTEs, correlated
subqueries, lateral queries, set operations, and data-modifying CTEs remain
outside the preview.
`ALTER TABLE ... ADD COLUMN` supports nullable columns, `NOT NULL`, static
`DEFAULT`, and `CHECK`; existing rows are rewritten atomically. A required
column without a non-null default is rejected when the table already has rows.
`ALTER TABLE ... DROP COLUMN [IF EXISTS] <column> [RESTRICT|CASCADE]` rewrites
the table atomically and preserves the remaining row values. RESTRICT is the
default and rejects a column used by a primary key, unique/index definition,
foreign key, or CHECK constraint. CASCADE removes those local dependencies and
foreign keys in other native tables that reference the removed column in the
same journaled catalog transaction. Constraints and indexes that do not use the
column remain. Several DROP COLUMN actions may be combined with commas. The
whole target set is resolved before one row/index rewrite; a RESTRICT failure,
duplicate target, mixed non-DROP action, or attempt to remove every column
rolls back the entire statement.
PostgreSQL wire maps a RESTRICT dependency to SQLSTATE `2BP01` and a later
reference to the removed column to `42703`. This preview performs a bounded
whole-table rewrite; online schema change for large tables is not implemented.
`ALTER TABLE ... RENAME COLUMN <old> TO <new>` updates the column plus its
PK/UNIQUE/index/CHECK/FK metadata atomically, including self-references and
foreign keys in other native tables. Row values and physical catalog IDs are
preserved. Missing and duplicate names map to PostgreSQL SQLSTATE `42703` and
`42701`.
`ALTER TABLE <old> RENAME TO <new>` preserves rows, row identities, TableId,
IndexId, and active old snapshots while atomically updating self-referencing and
external foreign-key metadata. A reader started before the rename retains the
old catalog name; later readers see only the new name. PostgreSQL wire maps a
missing old name to `42P01` and an occupied destination to `42P07`. Column type
conversion supports atomic metadata/row rewrite within the integer,
floating-point, and text/`VARCHAR` storage families. Existing rows and static
defaults must satisfy the target bounds; otherwise the statement rolls back.
Physical TableId/IndexId/row identity remain stable and all scalar indexes are
rebuilt in the same commit. A one-sided change that would make an FK type pair
incompatible is rejected. Cross-family conversion and `USING` expressions
remain outside the preview.
`ALTER COLUMN ... SET NOT NULL` scans the current snapshot and rejects before
publication if any visible row is NULL. `DROP NOT NULL` is supported except on
primary-key and identity columns. `SET DEFAULT <literal>` and `DROP DEFAULT`
update the versioned catalog; defaults are typed static literals, apply only to
later inserts, and cannot make a NOT NULL column default to NULL. PostgreSQL
wire maps a NULL write against the resulting constraint to SQLSTATE `23502`.
`ALTER TABLE ... ADD CONSTRAINT ... PRIMARY KEY (...)` and `... UNIQUE (...)`
validate all visible rows before publishing the versioned catalog change.
Named constraints remain stable across restart and PostgreSQL catalog
reflection. A compatible user index may share the same physical index ID while
retaining independent catalog ownership. `DROP CONSTRAINT ... RESTRICT`
removes the constraint while preserving an independently owned user index, and
rejects a key that is still referenced by a foreign key; PostgreSQL wire maps
that dependency to SQLSTATE `2BP01`. A new FK persists the selected referenced key kind and name, keeping constraint
and user-index namespaces distinct. Another equivalent UNIQUE owner on the same
columns can therefore be dropped independently. Legacy preview catalogs without
this typed identity use a conservative column-based dependency check until
rewritten. `ALTER TABLE ... RENAME CONSTRAINT <old> TO <new>` renames PRIMARY
KEY, UNIQUE, FOREIGN KEY, or CHECK catalog ownership atomically. Renaming a
referenced primary/unique key updates every typed FK owner binding in the same
commit while older snapshots retain the old catalog. PostgreSQL wire returns
`42704` for a missing source and `42710` for a duplicate destination.
`DROP CONSTRAINT ... CASCADE` removes the selected PRIMARY KEY or UNIQUE owner
and every foreign key bound to that exact owner in the same catalog commit,
including self-references. Foreign keys bound to another key owner and
independently owned user indexes remain. Older snapshots retain the prior
constraint graph.
`DROP TABLE ... CASCADE` removes the table and every external foreign key that
references it in one catalog transaction. Other constraints and independently
owned child indexes remain. Plain `DROP TABLE` keeps RESTRICT behavior and
maps a dependent-object error to PostgreSQL SQLSTATE `2BP01` on that protocol.
Deferrable primary/unique constraints, `NULLS NOT DISTINCT`, and `USING INDEX`
remain outside the preview.
The scalar type profile distinguishes `SMALLINT`, `INTEGER`, `BIGINT`, `REAL`,
`DOUBLE PRECISION`, `NUMERIC(38,s)`, `TEXT`, bounded `VARCHAR(n)`, `BYTEA`,
`DATE`, UTC `TIMESTAMP WITH TIME ZONE`, `UUID`, and `JSONB`. It also supports
fixed-dimension `VECTOR(n)` and `RECORD_REF`. Integer and varchar ranges reject
before commit; BYTEA text literals use PostgreSQL hex form (`'\x00ff'`).
Integer columns may declare `GENERATED BY DEFAULT AS IDENTITY` or `GENERATED
ALWAYS AS IDENTITY`. Omitted identity values come from the durable hidden row
frontier and work with `RETURNING`; ALWAYS rejects explicit values. Custom sequence
options, standalone sequences, and identity alteration remain outside this preview.
Literal and parameter expressions accept `CAST(expr AS type)` and PostgreSQL
`expr::type` when source and destination use the same storage family (integer,
floating point, or text/varchar). Bounds are checked against both the cast target
and destination column. The complete PostgreSQL conversion matrix is not yet implemented.

Interactive transactions use opaque, owner-bound handles:

```bash
handle=$(curl --fail -s -X POST http://127.0.0.1:7401/v1/sql/transactions |   python3 -c 'import json,sys; print(json.load(sys.stdin)["handle"])')

curl --fail -X POST "http://127.0.0.1:7401/v1/sql/transactions/$handle/execute"   -H 'content-type: application/json'   -d '{"statements":[{"sql":"INSERT INTO documents VALUES ($1, $2)","parameters":[{"type":"integer","value":8},{"type":"text","value":"private until commit"}]}]}'

curl --fail -X POST   "http://127.0.0.1:7401/v1/sql/transactions/$handle/commit"
# Roll back instead: DELETE /v1/sql/transactions/$handle
```

An active handle expires after five minutes of inactivity and belongs to the
principal and tenant that opened it. `SAVEPOINT`, `ROLLBACK TO SAVEPOINT`, and
`RELEASE SAVEPOINT` are accepted inside the execute request.

Retained transaction SQL, decoded parameters, savepoints and replay copies share
a process-wide history budget across all transports. The runtime profile derives
its capacity, up to 64 MiB shared and 16 MiB per transaction, including an active
replay copy. Repeated savepoint names consume space because earlier definitions
remain available after releasing a later definition. A history refusal during
execute aborts the transaction; recover with `ROLLBACK TO` an existing savepoint
or roll back the handle. Truncated values release their reservations; nonempty
buffer capacity remains charged. Commit, rollback and idle expiry release the
history. This budget covers retained history, not parser or operator scratch.
Protected HTTP reports exhaustion as `429`/`security.budget_exceeded`; legacy
unprotected HTTP reports the existing `507` resource error.

Use separate handles for concurrent transactions. Operations on one handle are serialized;
other handles can execute concurrently, subject to shared resource admission and commit
publication. Waiting for a busy handle is bounded to 30 seconds before a resource-limit
error. COMMIT freezes the statement set; a later EXECUTE cannot append to that decision.
A racing COMMIT and ROLLBACK have one winning terminal operation. Expired idle handles release
their snapshot pins during subsequent SQL, transaction-handle or checkpoint activity; an
executing operation is not expired mid-statement.

BEGIN returns `transaction_id` equal to the session `handle`; save it before
sending COMMIT. Execute responses carry that reserved ID without claiming a
commit. COMMIT uses the same ID for its durable decision, including empty,
read-only and zero-row transactions. Repeating COMMIT with the same handle and
owner returns the original decision without executing the statements again,
including after reconnect or restart. This uses the same installation journal
and receipt-retention rules as keyed standalone SQL; no additional key is needed.

If COMMIT fails before PREPARE, including a memory-limit refusal while forming
its receipt, the live session keeps its private statements and original handle.
Retry COMMIT explicitly or roll back that handle. This requires the same live
server and an unexpired session; private state is not durable. Once PREPARE
starts, the handle is consumed and retries reconcile the journal decision.
Other calls on that handle wait while COMMIT runs; calls on other handles can
proceed independently.

Use `GET /v1/transactions/{transaction_id}` to reconcile a lost acknowledgement.
Private statement execution and ROLLBACK do not create a durable decision. If a
process dies before PREPARE, the private session is gone; status has no decision
(`expired` on the legacy route, not found on the protected owner route). A durable
PREPARE without COMMIT is `rejected`. Receipt bodies remain for at least 24 hours;
a consumed handle cannot execute again after receipt expiry. Protected commit
replay checks current grants against the original permission requirements and
publication authority. PostgreSQL wire never automatically repeats a mutation
after disconnection.

Column aggregates `COUNT`, `SUM`, `AVG`, `MIN`, and `MAX` accept `DISTINCT`
or explicit `ALL`. A DISTINCT aggregate is bounded to 100,000 unique typed
values and returns `resource_exhausted` rather than growing without limit.
`COUNT(DISTINCT *)` is rejected; callers must name a column.

Unsupported syntax is rejected before commit. `DISTINCT ON`, `FILTER`,
window/ordered aggregates, HAVING expressions outside projected group or
aggregate outputs, expression evaluation beyond the listed predicate and
upsert-expression subsets, tuple assignment in `DO UPDATE`, correlated/recursive
query composition, cross-family column conversion, and `ALTER COLUMN TYPE ... USING`
remain incomplete. Atomic row+vector+graph mutation is available through the bounded ChironQL
`TRANSACTION` profiles documented below. Protected INSERT uses server IDs and explicit bindings;
multiple collections and DDL remain outside those profiles. PostgreSQL wire now
routes native scalar SQL through the same executor and supports a preliminary
simple/extended-query transaction surface. Its preliminary `pg_catalog` shim
reports native relational tables and indexes with restart-stable synthetic OIDs
derived from durable catalog IDs, plus column type/nullability metadata. A
bounded `information_schema.tables`/`columns` surface is available for Tier-1
reflection fixtures; complete constraint/default/generated metadata and every
ORM query shape are not yet implemented. Tier-1 ORM compatibility is not yet
accepted.

## Protected authority preview

The security-layer preview selects a separate protected HTTP router whenever
the data directory contains a durable identity authority. It authenticates
against that authority on every request, including an existing connection.
Legacy configuration keys do not authenticate through this router. The
ordinary collection-creation, upsert and administration recipes later in this
guide describe the legacy router, not protected onboarding.

This preview supports a single organization with separate principal capability
profiles. Role names are descriptive principal IDs, not built-in privilege
presets. An operations administrator needs explicit `observe`; that capability
does not confer data access. Identity, grants and labels administration are
separate from `read`, `search`, `update` and `delete`. The active organization
comes from the trusted principal catalog. Client tenant/principal headers
cannot override it.

All routes below also exist without `/v1`. Send exactly one credential using
`Authorization: Bearer`, `x-api-key`, `x-chirondb-api-key`, or the compatibility
`x-gaussdb-api-key` header. Duplicate or conflicting credential headers fail
with `401`. Protected responses use `Cache-Control: no-store`. HTTP/1 error
responses explicitly close the connection; a client must open a new connection
for its next request. Credential revocation is still checked on the connection
that was established before revocation.

Point hydration failures during native get, scroll, count, sparse or text
retrieval abort the affected request instead of returning missing points or a
successful partial response. Payload updates that fail while reading their
existing point are rejected before committing that update. Legitimately absent
or unauthorized points retain their existing behavior. Protected errors omit
storage paths and internal diagnostics; this does not change legacy dense search
budget/degraded-result semantics.

Protected relational applications may call `POST /sql`, `POST /v1/sql`, and
the interactive transaction routes documented above. After the offline
[table-authority migration](CHIRONQL_SECURITY.md#protected-relational-sql),
`GRANT ... ON TABLE ... TO ROLE ... IF REVISION n` through `/chironql` or
`/v1/chironql` binds a SQL table ID and incarnation without a vector collection.
After offline `migrate-sql-scopes`, collection-name permissions no longer
allow SQL. Existing permissions become exact table roles; newly created tables
confer SQL data rights on their immutable creator. Older receipts without saved
table authorization are denied without re-execution. See the
[strict migration contract](CHIRONQL_SECURITY.md#protected-relational-sql).

`read` authorizes SELECT, `create` INSERT, `update` UPDATE,
and `delete` DELETE. DDL requires installation action `schema`. Every table
persists its owner tenant; another tenant receives `security.not_found` even if
a misconfigured grant names that table. FK parent checks and CASCADE/SET actions
add all affected table/action pairs before execution. Interactive commit
reauthorizes its complete accumulated statement set, and protected response
bodies remain guarded against acknowledged credential or role revocation.
Table names remain installation-global in this beta, so tenants must choose
distinct names; a conflicting cross-tenant name is deliberately hidden.

In protected SQL, the executor checks current point `read` access for typed
`RECORD_REF` values written to rows or included in results. A missing or hidden
point rejects the request. Deleting a point still named by a live SQL row in
the same tenant returns `409 security.conflict`; remove that reference first
or use a supported atomic SQL/vector transaction. Standalone SQL requests
with references are limited to one point collection. A committed retry receipt is not returned if
its referenced point has since been revoked or deleted; query transaction
status with the original transaction ID to reconcile the durable decision.
Protected HTTP, gRPC, ChironWire, ChironQL, and PostgreSQL wire responses that
contain typed point references recheck object access before publication and
retain the current authority epoch while writing the response. Revocation
acknowledged before publication prevents those queued references from being
released.

| Method and `/v1` path | Required action and request |
| --- | --- |
| `GET /security/whoami` | Valid catalog credential; returns principal and tenant. Only an identity manager receives the revision for identity mutations. |
| `PUT /security/principals` | Installation `identity_manage`; `{ "expected_revision": N, "value": PrincipalRecord }`. Delegation scope and classification ceilings are validated. |
| `POST /security/credentials` | Installation `identity_manage`; `{ "expected_revision": N, "principal": "principal-id" }`. Returns credential ID, one-time secret and resulting revision. |
| `POST /security/sql-credentials` | Installation `identity_manage`; `{ "expected_revision": N, "principal": "principal-id" }`. Atomically replaces the user's SQL password and returns `{id,username,password,revision}` once. The server generates the password; caller-selected passwords are not accepted. |
| `POST /security/credentials/{id}/revoke` | Installation `identity_manage`; `{ "expected_revision": N }`. Accepts bearer and SQL credential IDs. |
| `GET /metrics` | Installation `observe`; raw operator metrics. |
| `POST /sql` | Exact table grants for DML/read, or installation `schema` for DDL; one atomic SQL request. |
| `POST /sql/transactions` | Valid catalog identity; opens an owner/tenant-bound interactive snapshot. |
| `POST /sql/transactions/{handle}/execute` | Reauthorizes every statement and FK dependency before private execution. |
| `POST /sql/transactions/{handle}/commit` | Freezes and reauthorizes the accumulated statement set; retry reconciles its durable decision and current grants. Publication remains guarded. |
| `DELETE /sql/transactions/{handle}` | Same owner and tenant; discards private writes. |
| `GET /transactions/{transaction_id}` | Exact principal and tenant recorded by the transaction; returns its durable decision through a revocation-aware response guard. |
| `POST /collections/{collection}/points/get` | `read`; `{ "ids": ["server-issued-id"] }`. Returns `{ "points": [...] }` with authorized IDs and projected fields. |
| `POST /collections/{collection}/count` | `read`; `{}` or `{ "filter": {...} }`. Returns the authorized count. |
| `POST /collections/{collection}/scroll` | `read`; the ordinary scroll request, with authorized ID cursor and projected points. |
| `POST /collections/{collection}/search` | `search`; dense search request, returning `{ "hits": [...] }` without internal candidate counts. |
| `PUT /collections/{collection}/points` | `update`; `{ "points": [...], "wait": true }`. Only updates existing authorized IDs; returns `{ "updated": N }`. |
| `POST /collections/{collection}/points/delete` | `delete`; `{ "ids": [...] }`. A mixed authorized/unauthorized explicit batch fails atomically. |
| `POST /collections/{collection}/points/delete/filter` | `delete`; `{ "filter": {...} }`. Evaluates only the write-authorized domain. Returns `{ "deleted": N }`. |
| `GET /collections/{collection}/security/revision` | `grants_manage`; current policy revision. |
| `PUT /collections/{collection}/security/objects/{id}/grants` | `grants_manage`; `{ "expected_revision": N, "value": { "grants": [...], "parent": null } }`. |
| `PUT /collections/{collection}/security/objects/{id}/labels` | `labels_manage`; `{ "expected_revision": N, "value": { "labels": {...}, "properties": {...} } }`. |

PostgreSQL frontend reservations appear in `/v1/metrics` as
`chirondb_pgwire_session_reserved_bytes` and
`chirondb_pgwire_session_capacity_bytes`; refused byte reservations increment
`chirondb_pgwire_memory_rejections_total`. These cover startup/session containers
and request copies, not raw frame buffers or total RSS. Raw frontend and large
control frames use the shared storage/receiving reservation. See [SDK usage](SDKS.md)
for `53200` recovery and capacity.
Interactive history across transports additionally exposes
`chirondb_sql_history_reserved_bytes`, `chirondb_sql_history_capacity_bytes` and
`chirondb_sql_history_rejections_total`.

Object permissions, labels, principal records and their revision envelopes use
the typed structures in `chirondb-types/src/security.rs`. For example, an
explicit read/search permit in a grants request has this shape:

```json
{
  "subject": { "kind": "principal", "id": "hr-reader" },
  "effect": "permit",
  "actions": ["read", "search"],
  "inherit": false
}
```

A permit across departments does not override classification or an explicit
deny. Protected payload field names do not change ownership or permissions.
Field use in filters is authorized separately from reading the field.
Representation/source-field changes additionally require trusted `ingest`.

Protected updates accept at most 1,024 points. `wait` is a JSON body field,
defaults to `true`, and returns `200` after synchronization. `wait:false`
returns `202`; the installation journal's COMMIT is still synchronized before
that response. Failed storage/audit projections are repaired during restart;
background index work may continue independently.
Protected deletes and security changes synchronize before acknowledgement.
Updates cannot create arbitrary client IDs or reuse retired IDs. Hidden and
missing updates both return the same `404` envelope; get-by-ID omits both.

Security errors contain an opaque `error.code`: invalid credentials → `401`,
forbidden actions → `403`, hidden/missing mutation targets → `404`, stale
revision → `409`, invalid input → `400`, authority budget exhaustion → `429`,
and unavailable authority/storage → `503`. A queued response invalidated by
revocation fails its body stream without publishing the protected value; a
client must not infer that a lost response means its mutation did not commit.

Protected graph, sparse/BM25, hybrid, snapshot/restore, collection lifecycle and
HTTP create/reservation operations are not available yet. Unregistered paths
fail closed; they cannot reach a legacy permissive handler. Protected positive
gRPC/ChironWire/pgwire support, production migration, retry reservations,
public deployment and full security acceptance remain incomplete. The secure
public startup profile still requires enforced tenancy, a verified protected
catalog and single-node operation. Do not use the offline test fixture as
production migration tooling.

Legacy snapshot and restore also reject SQL-only protected installations. A
content-only snapshot cannot preserve their identity authority or safely
restore credentials and revocations.

The reproducible five-profile test uses a real TLS server process and an
encrypted synthetic fixture. Build the binary, choose a fresh output directory,
then run it separately because its encryption configuration is process-wide:

```bash
cargo build -p chirondb --bin chirondb --locked
CHIRONDB_SECURITY_E2E_BINARY="$PWD/target/debug/chirondb" \
CHIRONDB_SECURITY_E2E_OUTPUT="$PWD/target/five-role-evidence-new" \
  cargo test -p chirondb-core --lib --locked five_roles_over_real_tls \
  -- --ignored --nocapture --test-threads=1
```

The output directory must not already exist. Python 3 and OpenSSL are required.
The directory contains private test credentials and encryption/TLS keys; CI
uploads only the redacted report, requests and audit evidence. A separate local
lab copy can be started with `chirondb-server/tests/security_five_roles_lab.py`;
its `request` command selects a profile without exposing a secret in shell
arguments or output. These tests do not certify production security.

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

Legacy `hnsw_m`, `hnsw_ef_construction` and `hnsw_ef_search` fields retain
zero-as-default compatibility. A supplied `hnsw_m=1` is invalid and is rejected
before collection mutation; omit these fields to use the engine defaults.

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

This operation uses legacy RBAC/tenant authorization. Protected installations
initialized with `chironctl security init` reject it; use the protected dense
search or ChironQL subset until text retrieval supports the protected policy.

`POST /v1/collections/{collection}/text_hybrid_search` (also available without
`/v1`) searches native BM25 over a top-level string payload field. Supply a
query vector to fuse dense and BM25 ranks with RRF; omit `vector` or send `[]`
for BM25 scores alone.

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

A supplied nonempty vector must match the collection dimension and the model/preprocessing used
at ingestion. Store document text in the named payload field; no `sparse_vector`
is needed. Both retrieval branches exclude points without a string in that
field, apply tenant and user filters, and combine ranks using RRF. Tenant-scoped
BM25 statistics exclude other tenants; ordinary filters select results without
redefining the scoring corpus. Payload changes and deletes update the text index.

`query`, `text_field`, and `k` are required. Query text is limited to
8,192 UTF-8 bytes; `k=0` returns no hits. `filter` and `budget_ms` are optional;
the default search budget is 30,000 milliseconds.
Unknown fields, including graph and named-vector options, are rejected. Ranking
scores are not probabilities. On the legacy router, `degraded=true` means the
search was interrupted or exhausted its budget. Existing `hybrid_search` sparse
dimensions retain their original meaning.

On a protected installation this endpoint requires collection `Search`, object
search access, and `Query` permission/clearance for the exact top-level text
field. Unknown or unqueryable fields contribute no documents or statistics.
BM25 document count, average length and document frequency use only that
searchable field corpus; ordinary filters affect candidates without changing
IDF. Dense candidates also require the `dense` representation and its source
field permissions. Ties use public IDs. Payload fields are projected by policy.
The response is `{ "hits": [...] }`; physical candidate counts and timings are
omitted. Expiry, cancellation and authorization revocation reject the result
instead of returning a partial ranking. The default and maximum protected
budget is 30 seconds, and text field names are limited to 8,192 bytes. Current
protected dense ranking is exact and requires separate production-scale
qualification. Graph filters and numeric sparse hybrid remain unavailable on
this protected route.

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

When `budget` is omitted, traversal memory is chosen from the detected process
graph pool and query-worker share, capped by the historical 512 MiB default.
The same resolved limit applies to admission and traversal work. Non-default
`max_memory_bytes` values retain their exact limit and requests above pool
capacity return an overload error. A supplied value of 512 MiB is treated as
the historical default because the request format does not distinguish it
from an omitted value.

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

New snapshots use deterministic configuration checksums in marker version 3.
Existing v1/v2 snapshots retain strict validation; ambiguous legacy map checksums
can be verified against their retained transaction journal and converted into a
separate copy with `chironctl security convert-snapshot`. See
[snapshot compatibility and conversion](SNAPSHOTS.md) before upgrading readers
or restoring an older backup. Existing live-data formats are unchanged.

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
published only after the complete tree is synchronized. Native snapshots include
the installation transaction journal alongside the active content generation,
so copied SQL and collection state can reopen consistently. Restore uses an
exclusive maintenance window and a crash-recoverable journal: readiness is
lowered, current operations are drained, the staged generation is validated,
and the live directory is swapped atomically. After an interrupted restore,
startup selects either the complete old generation or the complete new one,
never a mixture.

Native restore requires every interactive SQL transaction to end first. Snapshot
and restore drain background SQL checkpoints before freezing the content tree.
Restore validates staged SQL data before activation, then switches SQL and
collection state together for all existing database handles. Subsequent SQL
commits use the installed content directory and survive reopen.

Restoring content retains the current installation's transaction decisions and
consumed idempotency keys, including writes made after the snapshot. An identical
retry returns its earlier committed outcome without executing again; it does not
reinsert content deliberately removed by the restore. Corrupt SQL data rejects
before activation; an ordinary SQL activation failure rolls back to the writable
old root.

`GET` requests, collection deletion, index status, and collection compaction
do not require a JSON body. In Postman, select **Body → none** for those calls.

## ChironQL

### Tabular ML jobs and result views (local preview)

Submit `ML MATERIALIZE ...;` as the `query` in `POST /v1/chironql` (or
`POST /chironql`). The response row contains `job_id`, `view`, and `status`.
The same text submits a refresh after source data changes. The optional Python
worker and supported models are described in [ChironQL](CHIRONQL.md#tabular-ml-materialization-preview).

```bash
curl http://127.0.0.1:7401/v1/ml/jobs/JOB_ID
curl 'http://127.0.0.1:7401/v1/ml/views/sales_forecast?limit=100'
curl -X DELETE http://127.0.0.1:7401/v1/ml/views/sales_forecast
```

The same routes exist without `/v1`. A job response includes status, error,
source version, row count, context rows, and duration when available. A view
response includes its published version, source version, columns, rows, and a
`next` cursor. Pass that cursor as `?cursor=...`; a refresh invalidates old
cursors with HTTP 409. A failed refresh does not change the published view.
The view is also readable by `SQL SELECT` through ChironQL or the native SQL
API. Delete requires a write-capable API key. ML routes return 403 while
tenant enforcement is active; this preview does not expose predictions through
the protected tenant executor.

ChironQL 1.4 is ChironDB's unified vector, graph, and native relational query
language: one statement per request. The full language reference is
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
| `query` | One top-level ChironQL statement. A typed `TRANSACTION { ... }` block remains one statement. |
| `collection` | Session collection, as `USE <name>` would set. A collection named in the statement wins over it. HTTP has no session, so this does not persist between requests. |
| `trace` | Return the server's stage-by-stage execution trace on success. Failures carry it either way. |
| `confirm` | Proceed with a statement that stops and asks — see below. |
| `parameters` | Typed positional values for `$1…$n`, encoded as `{ "type": "text", "value": "..." }`. |
| `retry_id` | Optional audit correlation forwarded to a relational mutation or atomic multi-model block. |
| `idempotency_key` | Optional durable key for a standalone `SQL` mutation or atomic `TRANSACTION`. It uses the same ledger and principal/tenant scope as `/v1/sql`. |

For keyed SQL, identical SQL text and typed parameters return the original decision,
transaction ID and result. `retry_id`, tracing and transport may change. A different
fingerprint rejects. Receipt bodies last at least 24 hours; consumed keys remain unavailable
for another mutation after expiry. Other statement families reject a supplied key with
`chironql.idempotency_unsupported`; read-only SQL also rejects a key. A recovered rejected
PREPARE returns `committed: false`, its transaction ID and no rows. An uncertain COMMIT
returns HTTP 503 with `chironql.outcome_unknown` and a reconciliation hint.

For an atomic block, the fingerprint also covers the collection, points, graph mutations
and protected operation. Claiming the key precedes ID allocation. Replay returns the
original transaction/snapshot and allocated edge IDs (ordinary blocks use `rows: [{"edge_id":"..."}]`;
protected INSERT also includes record allocation rows);
`stats.replayed` is true and `stats.operation_lsn` is absent. A recovered rejected
multi-model PREPARE returns HTTP 409, `chironql.transaction_rejected`, and its transaction
ID in the error/reconciliation hint. The consumed key cannot execute again.


Responses add `domains`, `column_types`, `snapshot_id`, `transaction_id`, and
`committed` when applicable. `SQL <statement>` uses the same executor as `/sql`.
Read-only `PIPELINE` combines bounded vector, graph, and relational stages. A
`TRANSACTION` block commits one SQL DML stage, one vector UPSERT/DELETE or protected CREATE POINTS, and
graph create/update/delete mutations through the same installation journal.
Protected SQL `INSERT ... ON CONFLICT DO UPDATE` requires both `create` and
`update` grants, including the affected foreign-key dependencies.
Protected storage accepts standalone `SQL`, bounded dense/BM25/text-hybrid `PIPELINE` with an
optional graph traversal, and the bounded multi-model INSERT/UPDATE/DELETE transaction
profiles. Those protected paths authorize every resource before work begins and
recheck permission revisions at response publication. Protected graph stages accept node and edge
filters with `RETURN NODES`. BM25/text hybrid is supported both standalone and inside the
`PIPELINE` VECTOR stage under the same field/object authority. Standalone protected ChironQL
`TRAVERSE` supports node/edge/path output and authorized payloads; paths require `LIMIT`.
See [protected graph filters](CHIRONQL_SECURITY.md#protected-graph-filters)
for endpoint/field authority, limits and unavailable output forms. Protected atomic INSERT returns `binding`, `record_ref`,
and `edge_id` rows; retries preserve the allocated IDs. Its server-ID syntax, current reference
checks and graph setup are documented in [ChironQL](CHIRONQL.md#protected-atomic-insert)
and the [protected reference](CHIRONQL_SECURITY.md#protected-graph-setup).

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

### Execution trace

`"trace": true` returns what the server actually did:

```json
{
  "trace": {
    "query_id": "q_1a013b586c9002",
    "stages": [
      {"name": "parse", "elapsed_us": 50, "outcome": "ok"},
      {"name": "classify", "elapsed_us": 1, "outcome": "ok"},
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
| `409` | The statement is waiting on confirmation, or a pipeline snapshot changed |
| `503` | A durable commit is still publishing and a common snapshot cannot start |
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
{"ok": true, "language_version": "1.4", "kind": "write", "class": "write", "statement": "DELETE", "domains": ["vector"], "resources": {"tables": [], "collections": ["products"]}}
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
| `POST` | `/v1/collections/{name}/text_hybrid_search` | Native BM25, optionally fused with dense using RRF |
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
- Graph point hydration failures abort traversal and graph-constrained ranking,
  including node, edge and path results. They are not missing endpoints or a
  successful partial graph result. Mutations that fail to read an existing point
  reject before committing their graph batch. Protected endpoint visibility is
  checked before payload reads; hidden endpoints keep their existing behavior.
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

### Protected ChironQL administration (language 1.2)

Single-node installations with a verified protected collection and durable identity
authority use the same ChironQL executor at `/chironql` and `/v1/chironql`.
`/chironql/parse` and `/v1/chironql/parse` require authentication; the protected
parse response reports the statement kind/class and language version, without
returning the query or literal values. Existing 1.0/1.1 syntax remains available
on ordinary collections. Protected collections deliberately reject unsupported
legacy operations instead of invoking legacy administrator privileges.

Use the actual `chironql` network client with a private credential file:

```bash
chironql --url https://localhost:7401 --ca-cert ./ca.pem \
  --api-key-file ./security-admin.key --exec 'SHOW CURRENT USER;'
```

For an empty server, use `chironctl security init` offline, then connect with
the generated administrator key. ChironQL **1.3** adds `CREATE PROTECTED COLLECTION`,
`SHOW CATALOG REVISION`, and `ALTER/SHOW COLLECTION ... SECURITY POLICY`; the existing
1.2 commands below remain available. See the [protected deployment runbook](../deploy/protected/README.md)
for systemd/Compose, TLS, exact revision domains, private credential delivery and
offline administrator recovery. Existing-data migration remains separate. An ordinary user starts with no privileges and
no credential. `IdentityManage` is a direct bootstrap capability that cannot be
granted by an ordinary role. Operations administrators do not receive data access.

```sql
CREATE ROLE finance_reader;
GRANT READ, SEARCH ON COLLECTION docs TO ROLE finance_reader;
CREATE USER ana SET DEPARTMENT Finance SET CLEARANCE CONFIDENTIAL;
GRANT ROLE finance_reader TO USER ana;
SHOW ROLE finance_reader PRIVILEGES;
SHOW ROLES WITH USERS;
```

Issue the credential separately. `--key-out` is required before issuance/rotation;
the destination is opened exclusively before any request, with private permissions.
An existing destination is rejected. The client writes and synchronizes the secret
to that file, then reports only the credential ID and whether it was saved.

```bash
chironql --url https://localhost:7401 --ca-cert ./ca.pem \
  --api-key-file ./security-admin.key --key-out ./ana.key \
  --exec 'ISSUE API KEY FOR USER ana;'
chironql --url https://localhost:7401 --ca-cert ./ca.pem \
  --api-key-file ./ana.key --exec 'COUNT docs;'
```

`--api-key-file` rejects symlinks and, on Unix, group/world-accessible files.
TLS certificate and hostname verification remain enabled. HTTP with a credential
is limited to literal loopback IPs; redirects and environment proxies are disabled.
Catalog-authenticated terminal sessions do not persist query history. Secret values
are never included in result tables or trace. If key delivery is interrupted, check
`SHOW API KEYS FOR USER ana` and revoke the credential ID before issuing another key;
issuance is not retried automatically. API consumers receive an optional top-level
`credential: {id, secret}` only on successful issue/rotate; store it securely and do
not log that response. Listing credentials returns ID, principal and revoked status,
with no secret or digest.

Supported administration syntax:

| Purpose | Statements |
|---|---|
| Users | `CREATE USER name SET DEPARTMENT dept SET CLEARANCE level`; `ALTER USER name SET STATUS ACTIVE/SUSPENDED`; `ALTER USER name SET DEPARTMENT dept SET CLEARANCE level`; `RENAME USER old TO new`; `DROP USER name` |
| Roles | `CREATE ROLE name`; `RENAME ROLE old TO new`; `DROP ROLE name`; `GRANT ROLE role TO USER user`; `REVOKE ROLE role FROM USER user` |
| Capabilities | `GRANT READ, SEARCH ON COLLECTION docs TO ROLE role`; `GRANT READ ON TABLE documents TO ROLE role` after table-authority migration; matching `REVOKE ... FROM ROLE role`; `GRANT OBSERVE ON SYSTEM TO ROLE operator` |
| Inspection | `SHOW CURRENT USER`; `SHOW CURRENT USER PRIVILEGES`; admin-only `SHOW USERS`, `SHOW ROLES [WITH USERS]`, `SHOW ROLE name PRIVILEGES`, `SHOW API KEYS FOR USER name` |
| Keys | `ISSUE API KEY FOR USER name`; `ROTATE API KEY 'credential-id'`; `REVOKE API KEY 'credential-id'` |
| Object grants | `GRANT READ ON POINT 'id' IN docs TO USER ana`; `DENY READ ...`; `REVOKE GRANT READ ... FROM USER ana`; `REVOKE DENY READ ... FROM USER ana`. `GROUP name` is also accepted for trusted existing groups. |
| Object labels | `ALTER POINT 'id' IN docs SET OWNER ana SET DEPARTMENT Finance SET CLASSIFICATION CONFIDENTIAL` |

Classification values are `PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`.
Role capabilities do not change department, clearance, ownership or explicit deny.
User/role names and department values are case-sensitive; classification keywords are not.
Names alias immutable IDs; rename preserves ownership/membership, while drop and
recreation never restores an old identity or its privileges. Collection grants bind
to the collection incarnation. Role inheritance, wildcard scopes, `PUBLIC` implicit
roles, passwords, SSO and `CREATE OR REPLACE` are unsupported.

Every security mutation requires `IF REVISION n` over HTTP. For convenience, the
CLI reads the current revision and adds it unless explicitly supplied. Object
label/ACL mutations use `SHOW SECURITY REVISION ON COLLECTION docs`; user/role/key
mutations use `SHOW SECURITY REVISION`. These commands require the corresponding
administrative authority. Ordinary users do not receive the global revision.
Conflicts fail without automatic retry. The revision from a confirmation preview
is retained; confirmation does not bypass authorization. Drop and suspension
require confirmation or CLI `--yes`. A script executes one transaction per statement
in order and stops at the first failure; earlier successful statements stay committed.

Protected data syntax:

```sql
CREATE POINTS INTO docs USING TEMPLATE finance
  {vector:[1,0],payload:{text:'quarterly report'}} REQUEST 'import-2026-001';
GET docs POINTS 'server-issued-id';
COUNT docs;
SCROLL docs LIMIT 20;
SEARCH docs NEAR [1,0] LIMIT 10 WITH PAYLOAD;
UPDATE POINTS IN docs
  {id:'server-issued-id',vector:[1,0],payload:{text:'revised report'}};
DELETE FROM docs POINTS 'server-issued-id';
DELETE FROM docs WHERE text = 'obsolete';
```

The fixture/example collection has dimension 2 and a trusted `finance` ingest
template. Create returns server-generated IDs; input IDs are forbidden. Its request
identity is durable and scoped to the principal, collection incarnation and request
digest. Retrying identical input returns the same IDs after reauthorizing the
objects; this initial implementation requires read access for replay. Different
input with the same request identity conflicts. Deleted objects are never recreated
by replay. Update replaces authorized existing objects. For a batch, separate point objects with commas (without an outer JSON array).
Mixed explicit batches are atomic; hidden and missing targets share the not-found envelope. Filtered delete
evaluates the delete-authorized domain and rechecks it after confirmation; the
protected confirmation error deliberately omits counts, avoiding an unguarded
metadata response.

Protected graph, sparse/BM25/hybrid, recommend, partial payload updates, lifecycle
DDL and the legacy `UPSERT` command are rejected. Use create/update as shown above.
Role/key/clearance changes revoke old contexts before acknowledgement; every new
query on an existing connection authenticates again. Output waiting in the application
queue remains guarded through its release to the transport. Bytes released before
acknowledgement cannot be recalled.

For an attached local terminal, start `chirondb --console` with
`--console-api-key-file ./operator.key` (and `--console-key-out` for issuance).
`--console-role admin` cannot open protected data. The attached terminal authenticates
against the same catalog and observes live revocation. PostgreSQL wire continues
to accept PostgreSQL syntax on ordinary RBAC deployments. It closes fail-closed
on a protected authority unless the client negotiates PostgreSQL `SSLRequest`,
completes verified TLS, and authenticates with a separately issued SQL password
using `SCRAM-SHA-256`. Its startup user resolves to the same durable principal,
tenant, grants, and revocation epoch as protected HTTP, gRPC, ChironWire, vector,
and graph APIs. The bearer key is not a SQL password. Unknown, disabled, or
incorrectly authenticated users receive generic SQLSTATE `28P01`; plaintext
startup is refused. `SCRAM-SHA-256-PLUS` is not supported. Native relational
simple/extended query, prepared/portal, transaction, and bounded catalog
surfaces use protected authorization. The six pgvector compatibility shapes
are available as simple queries; vector INSERT requires an administrator-
configured `pgvector` ingest template and exact collection grants. This does
not make the PostgreSQL wire a general PostgreSQL replacement or certify the
installation as production-ready. A protected installation has one tenant in
this beta; cross-tenant grants are not a substitute for multi-tenant authority.

PostgreSQL row and description messages retain the existing 16 MiB limit,
including the four-byte length field and excluding the one-byte message kind.
This is a per-message limit; a query can stream multiple messages. Receiving
memory refusal reports SQLSTATE `53200`; framing-size refusal reports `54000`.
The connection then closes. This does not undo an earlier durable COMMIT: use
the original transaction identity or application state to reconcile its outcome.
PostgreSQL wire never automatically replays a mutation. A still-live private
transaction is rolled back when its connection handler exits or is aborted.
Text and byte fields are borrowed during encoding; typed JSON/vector fields
encode directly into admitted buffers. Conservative numeric/array scratch
reservations can reject before actual RSS reaches its limit.

Both native and protected PostgreSQL sessions reserve startup strings/maps,
prepared statements, decoded parameters and direct SQL request copies. Each
connection accepts at most 32 prepared statements and 32 portals, including the
unnamed object. Replacing an existing name is allowed; `Close` and `DEALLOCATE`
release its retained state. The byte budget is derived from the runtime profile,
up to 64 MiB shared and 16 MiB per connection, with map capacity retained until
disconnect. An object-count refusal returns `54000` and remains recoverable with
`Sync`; an extended-protocol error aborts a live transaction until rollback.

Raw startup/authentication/frontend payloads reserve before allocation or reading
and retain admission through processing, I/O failure or task cancellation. Native
input keeps its 16 MiB message limit; protected input keeps 8 MiB, a 4 KiB startup
and 4 KiB SCRAM message limit. Payload reads have a ten-second timeout. Empty
`Sync`/`Flush`/`Terminate` controls allocate no payload. Failed extended-protocol
messages are discarded in fixed 4 KiB chunks. Small control replies use a fixed
1 KiB stack buffer, so overload errors and rollback replies do not need a heap
reservation; larger control replies retain admitted backing during writes.
SCRAM working memory and cancellation-registry entries also retain admission.

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

Parser/authority and other catalog construction, other engine/operator allocations, TLS/
socket buffers and backend cancellation while output is blocked still require
qualification. These bounds do not certify complete process memory or W0.

Identity authority format 2 is separate from content format 1. Stop the server and
perform the explicit exclusive-lock migration using a compatible binary:

```bash
chironctl security migrate-authority --data-dir ./data --keyring ./keyring.json
```

The optional keyring is required for encrypted authority. Migration preserves
principal IDs, direct grants, credential hashes and revocation, and introduces no
implicit roles. The mandatory authority file is replaced atomically in place;
there is no active old catalog alongside it. Old readers reject its envelope.
Rollback requires a format-aware binary; never downgrade or disable enforcement
to bypass a migration failure. This is an identity-catalog migration, not a content
migration or a production restore procedure.

The first SQL password issuance upgrades an initialized identity record to
format 4 (`CHRNID04`) through an atomic encrypted replacement. It preserves
users, bearer credentials and grants, and stores only a salted SCRAM verifier.
Before publishing that record, ChironDB durably advances the installation marker
to `CHRNINSTALL2`. Earlier installation readers reject this marker during startup.
An interrupted upgrade can leave the new marker with the previous authority;
the current binary supports that state. Recovery never lowers the marker version.

Existing SQL preview installations with a v4 authority and the earlier marker
must be fenced offline before the current server will open their content:

```bash
chironctl security migrate-sql-guard --data-dir ./data --keyring ./keyring.json
```

Stop the server first. The command requires the external storage keyring and an
exclusive data-directory lock, verifies the authority and audit, and atomically
advances the startup marker. It preserves the identity revision, credentials,
grants and content; repeating it reports `migrated: false`. Do not edit or remove
markers to downgrade a database. Offline `recover-admin` revokes both bearer and
SQL credentials belonging to the retired administrator and keeps the reader guard.
A replay using the exact prior binary and the full production migration/recovery
acceptance remain release requirements.
