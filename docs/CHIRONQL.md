# ChironQL

ChironQL is ChironDB's unified query language. Its verb-first statements cover dense, hybrid,
multi-vector and graph retrieval, while the additive `SQL` wrapper routes relational work to the
native ChironDB SQL executor. Read-only `PIPELINE` statements combine these domains in one bounded
request, while a typed `TRANSACTION` block commits one relational mutation, one vector upsert or
delete, and graph create/update/delete mutations under one durable decision.

**Evaluation only: ChironDB and these features are not production ready.**

**Status: 1.4 local preview.** The language is implemented and served on every ChironQL surface: the embedded server
console, the `chironql` client, `POST /v1/chironql`,
`chirondb.v1.ChironDb/ExecuteQuery`, and ChironWire `ExecuteChironQl`.

The 1.1 addition preserves the 1.0 statements and adds the property-graph vocabulary below. The
statements, clause names, error codes and rejection taxonomy are **stable**: a statement
that parses today parses in every later release of the language, and a `code` a client switches on
keeps its meaning. Additions are allowed; removals go through a deprecation cycle rather than
disappearing between releases. The language version is independent of the ChironDB release version —
the database is in public beta, the language it answers is not.

Version 1.2 adds catalog-authorized user, role, API-key and document-security administration.
Version 1.3 adds protected collection creation and typed ingestion-policy management.
Version 1.4 adds native relational routing, typed `RECORD_REF`, domain classification, bounded
read-only multi-model pipelines, and atomic multi-model mutation blocks. Statements from 1.0–1.3
retain their existing grammar and behavior.
For complete syntax with an example for every statement and action, use the
[ChironQL security reference](CHIRONQL_SECURITY.md) and
[base-language example index](CHIRONQL_LEGACY_EXAMPLES.md).
For deployment, follow the [protected deployment runbook](../deploy/protected/README.md)
and [authenticated administration reference](HTTP_API.md#protected-chironql-administration-language-12).
Protected collections support the documented dense, BM25/text hybrid and point operations.
Protected graph filters are available inside node-returning `PIPELINE` stages. Numeric sparse
hybrid and unsupported lifecycle operations remain explicitly denied.

The 17 September 2026 ChironQL 1.4 ADR supersedes the earlier decision that relational access would
never be part of ChironQL. Raw `SELECT` remains invalid; prefix exactly one native statement with
`SQL`. ChironDB does not embed PostgreSQL or another relational engine. The pgvector-compatible wire
subset on port `7403` remains a separate compatibility surface.
Every graph construct sent through that PostgreSQL-compatible surface is
rejected with SQLSTATE `0A000` and the stable `#graph` compatibility hint;
graph statements and `PIPELINE` run through ChironQL or a native ChironDB protocol.

Protected installations support standalone relational `SQL` through ChironQL, direct HTTP SQL,
gRPC, and ChironWire. A table name uses the protected catalog's exact collection-scope grant:
`read`, `create`, `update`, and `delete` map to SELECT, INSERT, UPDATE, and DELETE. DDL requires the
installation-scoped `schema` action. Every table persists its owning tenant; a name owned by a
different tenant is reported as not found. Foreign-key checks and referential actions expand the
authorization set before execution, and the identity revision is held through commit and checked
again when the transport publishes the result. Protected `PIPELINE` supports bounded dense search, BM25 or dense+BM25,
optional graph traversal, and relational SELECT after authorizing every resource before the first
read. Protected multi-model `TRANSACTION` supports the bounded INSERT/UPDATE/DELETE profiles described
below. Both paths recheck every participating permission revision at transport publication. Graph
node/edge filters use current endpoint and field authority; see
[protected graph filters](CHIRONQL_SECURITY.md#protected-graph-filters). Standalone protected `TRAVERSE` supports authorized node, edge and path output,
including field-projected payloads; path queries require `LIMIT`. Numeric sparse hybrid stages
remain fail-closed with `chironql.protected_unsupported`. PostgreSQL wire now binds a TLS/SCRAM SQL
password to that same durable identity and publication guard. SQL passwords
are issued separately from ChironQL bearer keys; see the
[protected HTTP reference](HTTP_API.md). The atomic multi-model mutation
profile remains a local preview limited to one collection per block.

## Tabular ML materialization preview

On an unprotected local installation with the optional [Python worker](../ml-worker/README.md),
one statement creates a durable prediction table. Repeating the **identical statement** takes a
new source snapshot and replaces its rows atomically after the job succeeds:

```sql
ML MATERIALIZE sales_forecast
FROM sales
TARGET demand
FEATURES (sale_date, region, price)
TASK REGRESSION
USING DECISION_TREE;
```

The same clause order and names apply to `TASK CLASSIFICATION` or `REGRESSION` and
`USING DECISION_TREE` or `RANDOM_FOREST`. The source needs a stable
primary key, at least one non-NULL target for training, and at least one `NULL` target for
prediction. List features explicitly; primary keys and target columns cannot be features.
Only existing source rows are materialized. The result table contains the primary key,
selected features, `actual`, `prediction`, `confidence` when available, and
`refresh_version`. Read it with `SQL SELECT * FROM sales_forecast;` or the ML view API.
Table output displays unavailable values as `NULL`; empty text stays empty. Regression
models currently return `NULL` confidence. Classification confidence is the selected
class probability, between 0 and 1; it is not measured accuracy. JSON retains `null`.

Submission returns a `job_id`, view name, and `queued` status. Poll the job endpoint
before reading the first generation. A failed refresh keeps the last published generation.
Changing any definition parameter under an existing view name is rejected; delete the view
through `DELETE /v1/ml/views/{name}` before defining it again. Direct SQL writes to ML result
tables and their catalog are rejected.
To compare models without replacing a result, use different view names:

```sql
ML MATERIALIZE demo_regression FROM ml_demo TARGET amount
FEATURES (price) TASK REGRESSION USING DECISION_TREE;

ML MATERIALIZE demo_regression_rf FROM ml_demo TARGET amount
FEATURES (price) TASK REGRESSION USING RANDOM_FOREST;
```

Current availability: decision tree and random forest use scikit-learn and train
from all labeled source rows on each refresh. The optional worker is for local
evaluation and is **not production ready**. Foundation-model integration has been
removed; `TABFM`, `CAUSILO`, `TABPFN` and `PRIOR_LABS` reject with `chironql.ml_model`.
Existing definitions using a removed model are not silently converted. Drop and
redefine them with a supported model. The protected tenant executor continues to
reject ML materialization and its HTTP result routes while tenant enforcement is active.

Source size is limited to 10,000 rows. The job reports labeled rows supplied to
`fit` as `context_rows`. This command does not fine-tune a foundation model.

## Native text retrieval

`HYBRID docs TEXT 'synthetic' FIELD text LIMIT 10;` runs BM25 only.
`HYBRID docs NEAR [1,0] TEXT 'synthetic' FIELD text LIMIT 10;` fuses the default
dense representation with BM25 using RRF. `WHERE`, `BUDGET` and `WITH PAYLOAD`
are accepted; quote the field name for literal punctuation. Text retrieval
rejects named vectors, graph clauses, branch weights and weighted fusion.
The existing numeric `TEXT {dimension:weight}` form keeps its original meaning.

Protected execution requires collection/object Search and Query permission for
the text field. Only that field's authorized corpus contributes BM25 statistics;
the dense branch additionally checks representation/source-field permissions.
Results use public IDs and projected payloads, and publication rechecks authority.
This form is available standalone or in the VECTOR stage of protected PIPELINE through all
ChironQL transports. PIPELINE binds retrieval, relational and optional graph authority before
reading data; all participating revisions are checked before publication. See the
[HTTP text contract](HTTP_API.md#native-text-hybrid-search) for limits and score semantics.

## Where to type it

For an initialized local protected installation using the paths from the
[setup example](CHIRONQL_SECURITY.md#concrete-local-setup-and-connection), connect with its API key and verified TLS:

```bash
chironql --url https://localhost:7401 \
  --ca-cert "$HOME/chirondb-secure/tls/ca.pem" \
  --api-key-file "$HOME/chirondb-secure/secrets/admin.key"
```

For a remote server, use its real hostname and matching installed CA/key files.
Interactive startup authenticates before displaying the prompt and shows the server-verified
principal. Permissions come from the identity catalog. An attached protected console uses
`--console-api-key-file`; `--console-role` controls legacy unprotected sessions only.
Initialize an empty installation with `chironctl security init` as described in the
[runbook](../deploy/protected/README.md), then manage users and collections through ChironQL.

The following local-development examples use an unprotected installation.

Build the tools and set your terminal's `PATH` as described in
[Getting started](GETTING_STARTED.md#1-build-and-start). Start a console only
when a server is not already running on those ports:

```bash
chirondb --console
```

For an existing local server, use a separate client:

```bash
chironql --url http://127.0.0.1:7401
```

After creating `products`, scripts can use a one-shot request:

```bash
chironql --url http://127.0.0.1:7401 --exec "COUNT products;"
```

A stopped server produces `chironql.connection_failed` and exit code `2` in
one-shot mode. Start the server or correct the URL before retrying. Query
errors exit `1`; successful requests exit `0`.

`POST /v1/chironql` and the `ExecuteQuery` rpc take the same statements — see
[HTTP_API.md](HTTP_API.md) and [GRPC_API.md](GRPC_API.md).

Meta-commands in the REPL: `\h` help, `clear;` (or `\clear`) clear the screen,
`\l` list collections, `\d <coll>` describe, `\c <coll>` use, `\trace` show the
server's execution trace, `\timing`, `\format table|json`, `\params [...]` set typed
parameters for the next statement, `\role`, `\q` quit. One-shot execution accepts
`--params-json` and `--retry-id`. `--exec` accepts exactly one ChironQL statement and
validates the complete input before execution; a second semicolon-delimited statement is rejected
without executing the first. Use piped/interactive input when a script intentionally runs multiple
independent ChironQL statements.

`\q`, `Ctrl-D`, or `Ctrl-C` on an empty line ends the session. In `chirondb --console`
that stops the server, because the console *is* the process you started. In the `chironql`
client it closes the client and leaves the server alone.

## Durable mutation retries

For a standalone SQL mutation or atomic `TRANSACTION`, set `idempotency_key` on the HTTP/gRPC/ChironWire
request or use the CLI flag:

```bash
chironql --url http://127.0.0.1:7401 \
  --exec 'SQL CREATE TABLE cli_retry (id BIGINT PRIMARY KEY)' \
  --idempotency-key cli-create-1 --retry-id attempt-1
```

Repeating this command with the same SQL and key returns the original transaction ID.
`retry_id` is audit correlation and may change on each attempt. Keys belong to the
installation, authenticated principal and tenant; the fingerprint covers SQL text and
typed parameters. Standalone ChironQL SQL and native SQL use the same ledger. Receipt
bodies remain available for at least 24 hours; expiry never allows a consumed key to
execute again. Replays still require current permission and publication checks.

Other statement families reject a supplied key with
`chironql.idempotency_unsupported`. Read-only SQL rejects keys as invalid requests.
A recovered PREPARE without COMMIT returns `committed: false`, its transaction ID and
no result rows. An uncertain COMMIT returns `chironql.outcome_unknown` with a hint to
query the transaction status or retry the identical keyed request. The client does not
automatically repeat a mutation after a transport failure.

For `TRANSACTION`, the fingerprint includes SQL/parameters, collection, vector points,
graph mutations and the protected operation. Named-vector map order does not change
identity; changing content does. The core claims the key before allocating IDs and
stores a versioned receipt with the journal PREPARE. An identical retry returns the
original transaction/snapshot and `edge_id` rows for allocated edges. Its graph stats
set `replayed: true` and omit `operation_lsn`; no second ID allocation or commit occurs.
A recovered rejected multi-model PREPARE returns `chironql.transaction_rejected` with
the original ID and status-lookup hint (HTTP 409 / gRPC ABORTED).

Protected retries check current SQL grants and collection/object permissions. DELETE
acknowledgement may refer to the same retained tombstone created by that commit; it
never restores a point. An older UPDATE receipt cannot bypass a later deletion or
permission revoke. Protected atomic INSERT remains outside the implemented profile.


## Shape

One top-level statement per request. Ordinary statements end at `;`; a `TRANSACTION { ... };` block
contains semicolon-terminated typed stages and is still one statement. Keywords are case-insensitive.
The collection name is positional and may be omitted once a session collection is set with `USE`,
except inside an atomic transaction where the collection must be explicit.

```sql
SEARCH products
  NEAR [1, 0, 0]
  WHERE category = 'electronics' AND price <= 700
  LIMIT 10
  WITH PAYLOAD;
```

Optional clauses may appear in any order, and each may appear at most once. `-- comments` run to the
end of the line.

## Statements

### Native relational SQL

Prefix one native SQL statement with `SQL`. Classification comes from the parsed SQL AST, so a
keyword in a comment or string cannot disguise a mutation.

```sql
SQL SELECT id, title
    FROM documents
    WHERE owner_id = $1
    ORDER BY created_at DESC
    LIMIT 20;
```

`SELECT` and `EXPLAIN` are reads; `INSERT`, `UPDATE`, and `DELETE` are writes;
`CREATE/ALTER/DROP TABLE` and `CREATE/DROP INDEX` are admin statements. The
current `ALTER TABLE` profile supports `ADD COLUMN` with `NULL`, `NOT NULL`,
static `DEFAULT`, and `CHECK`, plus comma-separated
`DROP COLUMN ... [RESTRICT|CASCADE]` with an atomic bounded rewrite. RESTRICT is
the default. CASCADE removes local PK/UNIQUE/index/FK/CHECK dependencies and
external FKs that reference the column while preserving unrelated metadata.
All targets share one dependency analysis and one rewrite; mixed ALTER actions,
duplicate targets, and dropping every column are rejected before publication.
`RENAME COLUMN` atomically updates
PK/UNIQUE/index/CHECK/FK metadata, including referencing native tables.
`ALTER TABLE <old> RENAME TO <new>` preserves stable physical identities and
updates self/external foreign-key targets in the same catalog transaction.
`ALTER COLUMN <name> TYPE <type>` performs an atomic rewrite for compatible
integer, float, and text/`VARCHAR` storage families, rejecting target-bound or
FK mismatches before publication. Cross-family conversion and `USING` are not
yet supported.
`ALTER COLUMN` also supports `SET/DROP NOT NULL` and typed static
`SET/DROP DEFAULT`. `SET NOT NULL` validates all currently visible rows;
primary-key and identity nullability cannot be weakened.
Named `ADD CONSTRAINT ... PRIMARY KEY/UNIQUE` validates existing data and
`DROP CONSTRAINT ... RESTRICT` preserves independently owned user indexes.
A key referenced by a foreign key cannot be dropped and maps to PostgreSQL
SQLSTATE `2BP01` on that protocol. New FKs retain the selected referenced key kind and name, allowing an equivalent
unreferenced owner on the same columns to be dropped independently.
For parent row changes over PostgreSQL wire, `ON UPDATE/DELETE RESTRICT`
violations use SQLSTATE `23001`; `NO ACTION` and other foreign-key violations
use `23503`. A conflicting primary/unique key on the same `UPDATE` reports
`23505` before a competing `RESTRICT` violation.
`RENAME CONSTRAINT <old> TO <new>` supports PRIMARY KEY, UNIQUE, FOREIGN KEY,
and CHECK constraints; referenced-key renames update dependent FK bindings in
the same catalog commit. `DROP CONSTRAINT ... CASCADE` removes the exact
PRIMARY KEY/UNIQUE owner and its dependent foreign keys atomically while
preserving unrelated FK bindings and independently owned user indexes.
`DROP TABLE ... CASCADE` removes the table plus every external FK that targets
it in one catalog commit; plain `DROP TABLE` remains RESTRICT and fails before
mutation when a dependent FK exists.
Deferrable primary/unique constraints, `NULLS NOT DISTINCT`, and `USING INDEX`
are not yet supported.
`EXPLAIN ANALYZE`
is rejected. Raw `SELECT` is rejected with the hint `Use SQL SELECT ...`. See
[HTTP API](HTTP_API.md#native-relational-sql-preview) for the supported
relational subset.

Upsert uses the same native executor and constraint engine:

```sql
SQL INSERT INTO documents (id, title, revision)
    VALUES ($1, $2, $3)
    ON CONFLICT (id) DO UPDATE
    SET title = excluded.title, revision = excluded.revision
    WHERE documents.revision < excluded.revision
    RETURNING id, title, revision;
```

The conflict target must infer a declared primary/unique key or name a
primary/unique constraint. `excluded.column` is the proposed row; an unqualified
column or `table.column` reads the existing row. A false/unknown `WHERE` returns
no row and creates no commit. The executor revalidates CHECK/UNIQUE/FK rules and
runs FK update actions within the same transaction.

Parameters use tagged JSON values. For example:

```bash
chironql --exec 'SQL SELECT id FROM documents WHERE owner_id = $1;' \
  --params-json '[{"type":"text","value":"owner-1"}]'
```

The native type profile distinguishes `SMALLINT`, `INTEGER`, `BIGINT`, `REAL`,
`DOUBLE PRECISION`, `NUMERIC`, `TEXT`, `VARCHAR(n)`, `BYTEA`, `DATE`, UTC
timestamps, `UUID`, `JSONB`, fixed-dimension `VECTOR`, and `RECORD_REF`.
Terminal parameter tags for the added binary/document types are `bytes` (a
byte array), `date` (`YYYY-MM-DD`), and `json` (a JSON value).

Grouped analytics use the native SQL executor:

```sql
SQL SELECT region,
           COUNT(*) AS rows,
           SUM(amount) AS total,
           AVG(amount) AS average
    FROM sales
    GROUP BY region
    HAVING SUM(amount) >= $1
    ORDER BY total DESC
    LIMIT 20;
```

The current aggregate profile accepts `COUNT(*)`, `COUNT(column)`, `SUM`,
`AVG`, `MIN`, and `MAX`. Column aggregates also accept explicit `ALL` or
`DISTINCT`, for example `COUNT(DISTINCT owner_id)` and
`SUM(DISTINCT amount)`. DISTINCT aggregate values are typed, duplicate NULLs
coalesce, and NULL remains excluded by the aggregate. Each DISTINCT aggregate
is capped at 100,000 unique values and fails with `resource_exhausted` beyond
that bound. `COUNT(DISTINCT *)` is rejected; name a column. Group keys and
HAVING/ORDER expressions are typed and validated before results are published.
`ORDER BY` accepts output aliases and one-based select-list positions in both
grouped and non-grouped relational queries.

`SELECT DISTINCT` removes duplicate projected rows before `OFFSET` and `LIMIT`.
NULL values compare equal for this deduplication, and an `ORDER BY` expression
must also appear in the select list, matching PostgreSQL's bounded profile.
Explicit `SELECT ALL` preserves duplicates. `DISTINCT ON` remains outside the
preview.

Native relational SQL accepts at most 32 statements and 8 MiB of decoded input
per request, including interactive requests. The combined serialized result is
limited to 8 MiB, with at most 100,000 rows per result. Plain single-table
SELECT and ungrouped COUNT scan visible rows without loading the full table.
Equality predicates backed by a scalar index stream matching row identities
from disk and the mutation delta. COUNT and a small LIMIT do not retain the
complete matching set; the result and operator limits still apply.
A plain single-table `ORDER BY` with a bounded `OFFSET` and `LIMIT` keeps only
that result window. With an installed encryption keyring, this path writes
encrypted sorted runs when its in-memory window is full, then merges them in
the same order. Per-query and process-wide disk quotas bound those runs;
cancellation and restart remove their temporary files. If a run, quota or
merge buffer cannot fit, the query returns `resource_exhausted`. Other large
sort and join working sets can still return `resource_exhausted` before
producing results. Without a keyring, this ordered path keeps its memory-only
limit and does not write plaintext spill files.

Relational predicates accept comparisons, `AND`/`OR`/`NOT`, `IS NULL`,
`IN`/`NOT IN`, `BETWEEN`/`NOT BETWEEN`, and bare BOOLEAN columns. They use SQL
three-valued logic: UNKNOWN is filtered by WHERE, `NOT UNKNOWN` remains UNKNOWN,
and CHECK rejects only FALSE.
Literal and parameter expressions also accept `CAST(expr AS type)` and
PostgreSQL `expr::type` for storage-compatible integer, floating, and text/varchar
families. This is a bounded ORM-oriented slice, not the complete PostgreSQL cast matrix.
Integer identity columns accept `GENERATED BY DEFAULT AS IDENTITY` and
`GENERATED ALWAYS AS IDENTITY`. Omit the identity column in INSERT to generate a
durable value; use `RETURNING` to receive it. ALWAYS rejects explicit values.

The `SQL` wrapper also accepts non-recursive, read-only CTEs and uncorrelated
scalar, `EXISTS`, and `IN` subqueries. They use the same relational snapshot and
typed parameters as the outer query. Recursive CTEs, correlated/lateral
subqueries, set operations, and data-modifying CTEs are rejected before
publication. Raw top-level `WITH ...` remains ChironQL syntax and is rejected;
write `SQL WITH ... SELECT ...` for a relational CTE.

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

### Read-only multi-model pipeline

`PIPELINE` has one bounded vector stage, an optional bounded graph traversal, one relational
`SQL SELECT`, typed equijoins, and a bounded final result:

```sql
PIPELINE
  VECTOR v { SEARCH chunks NEAR $1 LIMIT 50 }
  GRAPH g { TRAVERSE knowledge FROM v.record_ref VIA cites DEPTH 2 RETURN NODES LIMIT 200 }
  RELATIONAL r { SQL SELECT id, title, chunk_ref, source_ref FROM documents WHERE tenant_id = $2 }
  INNER JOIN r ON r.chunk_ref = v.record_ref
  LEFT JOIN g ON g.record_ref = r.source_ref
  RETURN r.id, r.title, v.score, g.depth
  ORDER BY v.score DESC
  LIMIT 10;
```

Stages and final clauses occupy separate lines in 1.4. Joins are `INNER` or `LEFT` equijoins.
For protected text retrieval, substitute `HYBRID chunks TEXT 'question' FIELD text LIMIT 50` or
`HYBRID chunks NEAR $1 TEXT 'question' FIELD text LIMIT 50` in the VECTOR stage. NEAR parameters
are typed vectors; missing or non-vector bindings return `security.invalid` on the protected path.
Mutation, correlated subqueries, Cartesian products, duplicate aliases, cycles, and unbounded vector
or final results are rejected before execution. `EXPLAIN PIPELINE ...` returns the dependency and
budget plan without running stages.

The executor validates one installation visibility frontier before publishing rows. A concurrent
commit returns `chironql.snapshot_changed`; a commit still publishing returns
`chironql.snapshot_busy`. No partial rows are published. On protected installations, every stage is
authorized before the first read and its permission revision is checked again when the transport
publishes the result. Long-running retained-version operation remains a later acceptance milestone.

`RECORD_REF('namespace')` is a relational type. `RECORD_REF('chunks', id)` constructs a value; vector
and graph stages emit the same `{namespace,id}` shape. Namespace or scalar-type mismatches are
errors. In 1.4 this is a typed join identity, not a cross-model foreign key.

### Atomic relational + vector + graph mutation

`TRANSACTION` uses explicit domain prefixes, so the analyzer can classify every body before any
mutation runs. Its first profile accepts exactly one SQL `INSERT`, `UPDATE`, or `DELETE`, exactly one
`VECTOR UPSERT`, `VECTOR DELETE`, or protected `VECTOR CREATE POINTS`, and one or more graph mutations: `GRAPH CONNECT`/`RELATE`,
`GRAPH UNRELATE`, or `GRAPH UPDATE EDGE`. Vector and graph stages must name the same collection.
`NO WAIT`, deferred graph endpoints, per-edge idempotency keys, DDL, and multiple collections are
rejected before commit. Protected INSERT uses server-allocated IDs and explicit bindings as shown
below; protected UPDATE/DELETE address existing authorized objects.

```sql
TRANSACTION {
  SQL INSERT INTO documents (id, title)
      VALUES ($1, $2);
  VECTOR UPSERT INTO chunks
      {id: 'chunk-1', vector: [1,0]},
      {id: 'source-1', vector: [0,1]};
  GRAPH CONNECT chunks 'chunk-1' -> CITES -> 'source-1'
      SET {kind: 'source'};
};
```

All stages share one transaction ID and commit sequence. The installation journal is the commit
authority; relational WAL, collection WAL, graph/vector state, and audit are idempotent projections.
A failure before durable COMMIT publishes nothing. A projection failure after COMMIT returns
`committed: true`, places the process in degraded read-only mode, and recovery finishes every
projection exactly once. Use `GET /v1/transactions/{transaction_id}` to reconcile an uncertain
network outcome.

#### Protected atomic INSERT

Provision graph support and an edge type with collection `SCHEMA` permission and the current
collection security revision; see [protected graph setup](CHIRONQL_SECURITY.md#protected-graph-setup).
The ingesting principal needs SQL table `create`, collection `create`, `read`, `ingest` for supplied
representations, and `graph_write`. The object policy must also allow reading each new record and
writing both graph endpoints. Configure a trusted template before ingestion.

```sql
TRANSACTION {
  SQL INSERT INTO docs (id, chunk, source)
      VALUES ('row-1', RECORD_REF('docs', NEW_RECORD('chunk')),
                       RECORD_REF('docs', NEW_RECORD('source')));
  VECTOR CREATE POINTS INTO docs USING TEMPLATE standard
      {binding:'chunk',point:{vector:[1,0],payload:{text:'chunk'}}},
      {binding:'source',point:{vector:[0,1],payload:{text:'source'}}};
  GRAPH CONNECT docs NEW chunk -> cites -> NEW source SET {kind:'source'};
};
```

Here `docs` is both the protected collection and a SQL table with `id TEXT PRIMARY KEY`,
`chunk RECORD_REF('docs') NOT NULL`, and `source RECORD_REF('docs') NOT NULL`.
Bindings are unique ASCII letters/digits/underscore names of 1–64 bytes, with 1–1,024 records.
The `point` object cannot contain an `id`. The server allocates public IDs, resolves
`NEW_RECORD('binding')` in INSERT VALUES, and validates every stored RECORD_REF before COMMIT.
Existing references must name readable objects in the same collection. Graph endpoints use
`NEW binding` or `EXISTING 'public-id'`; both require GraphWrite. An unknown binding, orphan
reference, unauthorized endpoint or constraint violation rejects the entire transaction.
`ON CONFLICT` and INSERT SELECT are unsupported in this create form.

Send an `idempotency_key` with the request and retain it across disconnects. The response has
`binding`, `record_ref`, and `edge_id` columns: one row per allocated record with a null edge ID,
then one row per edge with null binding/reference. Identical retries return the same rows and
transaction ID after checking current permissions. The embedded `Db::insert_multimodel_authorized`
API returns the same allocation map in `records`. No new physical identity is supplied by clients.

### SQL row preconditions

Within `TRANSACTION`, place optional `EXPECT SQL ROWS n;` immediately after its SQL stage.
The unsigned count must equal the rows directly inserted, updated or deleted by that SQL
statement, including DML with `RETURNING`. Cascading SQL writes, vector points and graph edges
are excluded. A mismatch returns `chironql.sql_row_precondition_failed` before a durable
commit decision, preserving all three models. Protected DELETE may withdraw already queued
results while leaving fresh reads usable. This validation rejection has no committed receipt
or transaction ID.

Use the guard with a revision predicate when sibling vector/graph writes must depend on a
successful metadata revision change: `SQL UPDATE documents SET revision=2 WHERE id=$1 AND
revision=1; EXPECT SQL ROWS 1;`. The table must have a revision column. Without a guard, SQL
zero-row semantics are preserved and sibling writes can still commit. Standalone SQL is
unchanged. The guard is part of the request fingerprint; changing or removing it conflicts
with an already consumed key. Guard-free requests preserve their existing retry identity.
Older servers reject the new `EXPECT` stage before execution. HTTP, gRPC, ChironWire and SDK
`chironql()` calls use the same syntax; there is no additional JSON/protobuf field.

Embedded callers use `Db::execute_multimodel_transaction_with_sql_rows`,
`Db::execute_multimodel_transaction_authorized_with_sql_rows`, or
`Db::insert_multimodel_authorized_with_sql_rows` with `Some(n)`; `None` preserves existing
behavior. Native requests with several DML statements use their total directly affected count.

An atomic update can replace the relational row, vector point, and edge properties together:

```sql
TRANSACTION {
  SQL UPDATE documents SET title = $1 WHERE id = $2;
  EXPECT SQL ROWS 1;
  VECTOR UPSERT INTO chunks {id: 'chunk-1', vector: [0.8,0.2]};
  GRAPH UPDATE chunks EDGE '<edge-token>' SET PROPERTIES {kind: 'revised'} REPLACE;
};
```

An atomic delete removes the relational row, vector point, and selected edge together:

```sql
TRANSACTION {
  SQL DELETE FROM documents WHERE id = $1;
  EXPECT SQL ROWS 1;
  VECTOR DELETE FROM chunks POINTS 'chunk-1';
  GRAPH UNRELATE chunks EDGE '<edge-token>';
};
```

The real terminal accepts the block as multi-line input and does not split on its internal
semicolons. One-shot execution can pass the same block through `--exec`; parameters and retry identity
use `--params-json` and `--retry-id`:

```bash
chironql --url http://127.0.0.1:7401 \
  --params-json '[{"type":"text","value":"doc-1"},{"type":"text","value":"Atomic document"}]' \
  --retry-id document-1-v1 \
  --exec "$(cat <<'CHIRONQL'
TRANSACTION {
  SQL INSERT INTO documents (id, title) VALUES ($1, $2);
  VECTOR UPSERT INTO chunks
      {id: 'chunk-1', vector: [1,0]},
      {id: 'source-1', vector: [0,1]};
  GRAPH CONNECT chunks 'chunk-1' -> CITES -> 'source-1';
};
CHIRONQL
)"
```

```
SEARCH    <coll> NEAR <vec> [USING <vector_name>] [WHERE <filter>]
                 [LIMIT <n>] [WITH PAYLOAD] [EF <n>] [RECALL <f>] [BUDGET <ms>]
                 [CONNECTED TO <id>[, …] [VIA <type>[, …]]
                  [DIRECTION OUT|IN|ANY] [WITHIN <h> HOPS] [ALLOW DEGRADED]]

HYBRID    <coll> NEAR <vec> TEXT <sparse> [USING <vector_name>]
                 [FUSION rrf|weighted] [DENSE <w>] [SPARSE <w>]
                 [WHERE <filter>] [LIMIT <n>]
                 [CONNECTED TO <id>[, …] [VIA <type>[, …]]
                  [DIRECTION OUT|IN|ANY] [WITHIN <h> HOPS] [ALLOW DEGRADED]]

MULTI     <coll> NEAR <vec>, NEAR <vec>, … [FUSION rrf|weighted]
                 [WEIGHTS <f>, <f>, …] [WHERE <filter>] [LIMIT <n>]

RECOMMEND <coll> LIKE <id>[, <id>…] [UNLIKE <id>[, <id>…]]
                 [USING <vector_name>] [WHERE <filter>] [LIMIT <n>]

COUNT     <coll> [WHERE <filter>]
SCROLL    <coll> [WHERE <filter>] [LIMIT <n>] [AFTER <cursor>]
GET       <coll> POINTS <id>[, <id>…]

SHOW COLLECTIONS
DESCRIBE  <coll>

UPSERT INTO <coll> <point>[, <point>…] [NO WAIT]
DELETE FROM <coll> POINTS <id>[, <id>…]
DELETE FROM <coll> WHERE <filter>
UPDATE <coll> POINT <id> SET PAYLOAD <object> [REPLACE]

RELATE   <coll> <source> -> <type> -> <target> [SET <properties>]
         [IDEMPOTENCY KEY <key>] [WITH DEFERRED ENDPOINTS] [NO WAIT]
UNRELATE <coll> EDGE <edge-token>[, …] [NO WAIT]
UPDATE   <coll> EDGE <edge-token> SET PROPERTIES <object> [REPLACE] [NO WAIT]

TRANSACTION {
  SQL <INSERT|UPDATE|DELETE>;
  VECTOR UPSERT INTO <coll> <point>[, <point>...]
    | VECTOR DELETE FROM <coll> POINTS <id>[, <id>...];
  GRAPH CONNECT|RELATE <coll> <source> -> <type> -> <target> [SET <properties>]
    | GRAPH UNRELATE <coll> EDGE <edge-token>[, ...]
    | GRAPH UPDATE <coll> EDGE <edge-token> SET PROPERTIES <object> [REPLACE];
  [... more GRAPH stages ...]
}

TRAVERSE <coll> FROM <id>[, …] [VIA <type>[, …]] [DIRECTION OUT|IN|ANY]
         [DEPTH <h>] [WHERE <node-filter>] [EDGE WHERE <edge-filter>]
         [BUDGET <ms> MS] [LIMIT <n>] [WITH PAYLOAD]
         [RETURN NODES|EDGES|PATHS]

CREATE COLLECTION <name> DIM <n> [METRIC cosine|l2|dot] [WITH <object>]
DROP COLLECTION <name> [IF EXISTS]

USE <coll>
```

## Vectors

| Form | Meaning |
| --- | --- |
| `[1.0, 0.0, 0.0]` | Inline dense vector |
| `@phone` | The stored vector of point `phone`; the server resolves it |
| `@phone USING image` | A specific named vector of that point |
| `{12: 1.2, 98: 0.7}` | Sparse vector (index → weight), valid only after `TEXT` |

`@id` costs one extra point fetch per query. That is fine for interactive use; do not put it on a
benchmark path.

## Filters

Filters are **conjunctions only**. Conditions are combined with `AND`, which maps directly onto the
engine's filter representation.

| Syntax | Meaning |
| --- | --- |
| `category = 'electronics'` | Equality |
| `category != 'media'` | Not equal |
| `price <= 700` | Numeric range — also `<`, `>`, `>=` |
| `category IN ['a', 'b']` | Membership |
| `title CONTAINS 'wireless'` | Text token intersection |
| `meta.brand = 'acme'` | Nested payload field, addressed by path |
| `… AND …` | Conjunction |

**There is no `OR`.** The engine's filter is a conjunction of per-field conditions, so a disjunction
across two different fields has no representation. Rather than translate it into something subtly
different, ChironQL rejects it:

```
chiron> SEARCH products NEAR [1,0,0] WHERE category = 'a' OR category = 'b';
 ✗ ChironQL filters are conjunctions — there is no OR
   hint: Single-field disjunction is IN: category IN ['a', 'b'].
```

Single-field disjunction — the common case — is `IN`.

Two conditions using the same operator on the same field (`price = 1 AND price = 2`) are rejected
rather than silently collapsed, because they cannot both hold. A range needs two *different*
operators: `price >= 100 AND price <= 700`.

## Property graph

Graph operations use the same collection and point IDs as vector retrieval. Graph lifecycle and
edge-type configuration must already be enabled by an administrative API. Callers need the
corresponding `graph:read` or `graph:write` capability in addition to their ordinary point role and
collection allowlist.

`TRAVERSE` is exact and deterministic. `RETURN NODES` emits distinct live nodes in hop-then-handle
order and excludes anchors unless `DEPTH 0`. `RETURN EDGES` emits each visible traversed EdgeId once;
parallel edges remain separate and IDs are opaque URL-safe tokens. `RETURN PATHS` enumerates simple
paths in breadth-first order, includes the anchor in each path, never repeats a node, and therefore
requires `LIMIT`.

`WHERE` filters neighbour payloads before they can be returned or expanded. Anchors are exempt only
while acting as expansion roots; at `DEPTH 0`, `WHERE` filters anchor output. `EDGE WHERE` filters
edge properties before traversal, while `VIA` filters only edge types. `WITH PAYLOAD` adds point
payloads to node rows and edge properties to edge/path rows.

`LIMIT` bounds returned rows; traversal budgets independently bound work. If either bound cuts a
result, `stats.truncation` identifies the reason and `stats.warnings` contains
`graph.result_truncated`. A path query without `LIMIT` is rejected before execution.
The implicit graph memory limit is derived from the detected process pool and query-worker
share, capped at the historical 512 MiB default; admission and expansion use that same limit.

First create and seed `products` using steps 2–3 of
[Getting started](GETTING_STARTED.md#2-create-a-collection), then enable its
graph and configure `related_to` with the first two
[graph HTTP commands](HTTP_API.md#property-graph-overlay). Now run:

```sql
RELATE products phone -> related_to -> book SET {strength: 0.8};

TRAVERSE products FROM phone VIA related_to DIRECTION OUT DEPTH 2
  EDGE WHERE strength >= 0.5 WITH PAYLOAD RETURN PATHS LIMIT 50;

SEARCH products NEAR [1,0,0] CONNECTED TO phone VIA related_to WITHIN 2 HOPS LIMIT 10;
```

`WITH DEFERRED ENDPOINTS` is valid only inside an explicitly opened, session-bound bulk-load
window. A stateless ChironQL request has no such binding and fails with
`chironql.deferred_session_required`; it never creates pending endpoints implicitly.

## Search tuning

| Clause | Effect |
| --- | --- |
| `LIMIT <n>` | Number of results. Defaults to 10. |
| `WITH PAYLOAD` | Include point payloads in the results. |
| `EF <n>` | Per-query `ef_search` override. Higher is more accurate and slower. |
| `RECALL <f>` | Target recall in `0.0..=1.0`. The engine picks `ef_search` from its calibration curve. |
| `BUDGET <ms>` | Time budget for the query. |

`RECALL` states a **target**, not an outcome. ChironQL never reports an achieved per-query recall
figure, because the engine does not measure one per query — anything printed in that shape would be a
guess wearing the costume of a measurement.

## Examples

These statements use the three-dimensional `products` collection and both
points from [Getting started, steps 2–3](GETTING_STARTED.md#2-create-a-collection).
Run one at a time. The write examples delete those sample points; reinsert
them before repeating retrieval examples. Confirm the filtered delete when
prompted, or add `--yes` to a one-shot client invocation.

```sql
-- semantic search with a business filter
SEARCH products NEAR [1,0,0] WHERE category = 'electronics' LIMIT 10 WITH PAYLOAD;

-- more like this one, but not that one
RECOMMEND products LIKE phone UNLIKE book LIMIT 5;

-- dense + lexical, reciprocal rank fusion
HYBRID products NEAR @phone TEXT {12:1.2, 98:0.7} FUSION rrf LIMIT 5;

-- ask for a recall target instead of tuning ef by hand
SEARCH products NEAR [1,0,0] LIMIT 10 RECALL 0.99;

-- two query vectors, weighted fusion
MULTI products NEAR [1,0,0], NEAR [0,1,0] FUSION weighted WEIGHTS 0.6, 0.4 LIMIT 8;

-- page through a collection
SCROLL products WHERE category = 'electronics' LIMIT 100;

-- writes
UPSERT INTO products {id: 'phone', vector: [1,0,0], payload: {category: 'electronics', price: 699}};
UPDATE products POINT phone SET PAYLOAD {featured: true};
DELETE FROM products POINTS phone, book;
DELETE FROM products WHERE category = 'archived';

-- session collection
USE products;
SEARCH NEAR [1,0,0] LIMIT 5;
```

Point objects accept relaxed JSON: unquoted keys, single-quoted strings, and bare words as strings.
Use `{id: 'phone', vector: [1,0,0]}` inside a ChironQL statement. String values
and quoted keys use single quotes; double a quote inside a string (`'Ana''s phone'`).
Ordinary double-quoted JSON is used for the HTTP request envelope, not as a
ChironQL object literal. The executable reference corpus checks this distinction.

For another page, add `AFTER '<cursor>'` with the returned point-ID cursor.
Omit it on the first request; do not invent an offset.

A named-vector example needs a configured space and a point containing it:

```sql
CREATE COLLECTION image_assets DIM 3 METRIC cosine WITH {named_vector_dims: {image: 3}};
UPSERT INTO image_assets {id: 'logo', vector: [1,0,0], vectors: {image: [0,1,0]}};
SEARCH image_assets NEAR @logo USING image LIMIT 20;
```

## Filtered deletes stop and ask

`DELETE ... WHERE` requires confirmation. On the legacy surface the server counts
what the filter matches and includes that count in its preview. Protected previews
omit counts and recheck the delete-authorized domain when confirmed. Legacy example:

```
chiron> DELETE FROM products WHERE category = 'archived';
this would delete 1204 point(s) from 'products'. Type yes to proceed: yes

 1204 affected · 82.1 ms · q_1a013b58ead004
```

Non-interactive callers have nothing to answer with, so they are refused until
they say so up front — `--yes` on the command line, `"confirm": true` in an
HTTP or gRPC request. Nothing is deleted by the refused attempt. Deleting by
id (`DELETE FROM c POINTS a, b`) is explicit already and does not ask.

## Collections

```sql
CREATE COLLECTION embeddings DIM 768 METRIC cosine;
DROP COLLECTION embeddings;
```

Two things are fixed when a collection is made and cannot be changed afterwards: its vector
dimension and its metric. They are grammar for that reason. Everything else `CollectionConfig`
carries — shards, replicas, quantization, payload schema, named vector dimensions, the HNSW build
parameters, `recall_sla`, `streamer_max_bytes` — arrives in one `WITH` object under its own field
name:

```sql
CREATE COLLECTION documents DIM 1536 METRIC cosine
  WITH {shards: 2, quantization: 'sq8', payload_schema: {category: 'string'}};
```

The names in `WITH` are the names `DESCRIBE` prints, so a collection can be read and rebuilt with
the same vocabulary — `CREATE COLLECTION` echoes the same `field`/`value` rows that `DESCRIBE`
returns. A key that is not a setting is **refused, not ignored**: a misspelt `shardz` that serde
silently dropped would create a collection quietly different from the one that was asked for.

`index_kind` is refused on purpose. LS-VEC is the sole index path, which is also why
`CREATE INDEX … USING hnsw` is rejected rather than honoured.

### Both statements need a write-capable role

`CREATE COLLECTION` and `DROP COLLECTION` are write statements. A `read_write` or `admin`
session may execute them; `read_only` is refused. The attached console defaults to `read_write`,
and `--console-role read_only` narrows it for inspection. `DROP COLLECTION` destroys the
collection and its data directory, so it also requires the confirmation described below.

### DROP counts first, then asks

The guardrail is the one `DELETE ... WHERE` uses, and for the same reason — the number belongs in
front of whoever decides:

```
chiron> DROP COLLECTION products;
this would drop 'products' and delete its 1204 point(s). Type yes to proceed: yes

 1204 affected · 96.4 ms · q_1a013b59aa1007
```

`--yes` or `"confirm": true` answers it where there is no prompt. `DROP COLLECTION … IF EXISTS`
reports `0 affected` for a collection that is not there instead of failing. Dropping the session's
own collection clears the `USE`, so later statements say what is wrong rather than reporting a
collection that "does not exist".

### While tenant enforcement is on, DDL is refused

`create_collection` and `delete_collection` have no tenant-scoped variant in the engine, so under
`enforced` there is no rule for who owns a new collection or who may destroy one. Both statements
refuse with `chironql.tenant_ddl_unsupported` rather than guess — the same fail-closed stance the
unscoped engine entry points take. Administer collections with `chironctl` in that deployment.

## Execution trace

Every statement can report what the server actually did:

```
chiron> \trace on
chiron> SEARCH products NEAR [1,0,0] LIMIT 1;

 trace  q_1a013b586c9002
   parse                 0.05 ms  ok    class=read statement=SEARCH
   authorize             0.00 ms  ok
   resolve_collection    0.02 ms  ok    collection=products dim=3
   engine_search         0.30 ms  ok    degraded=false hits=1 scanned=3
   render                0.01 ms  ok
```

On a failure the trace is printed whether or not it was asked for, and stops at
the stage that failed — so a broken query says whether the syntax, the
collection, the point id or the engine was the problem:

```
 ✗ point 'missing' not found in 'products'
   at resolve_vector · chironql.point_not_found
```

A stage that did not run is absent, not shown with a zero duration. Every
result also carries a `query_id` that appears in the server's own log line for
that statement, so `grep q_1a013b586c9002 server.log` finds the server's
account of it.

## Errors

Every rejection carries a stable `code`, a human-readable message, a hint where one helps, and a byte
`position` so a client can draw a caret. Unsupported constructs are recognised on purpose so they get
a specific answer instead of a generic parse failure.

| Code | Raised by |
| --- | --- |
| `chironql.idempotency_unsupported` | Request-level key on a statement family other than standalone SQL or atomic TRANSACTION |
| `chironql.outcome_unknown` | COMMIT acknowledgement is uncertain; reconcile the supplied transaction ID or retry with the same key |
| `chironql.not_sql` | `SELECT …`, `INSERT …` |
| `chironql.no_transactions` | `BEGIN`, `COMMIT`, `ROLLBACK`, `SAVEPOINT`, `START TRANSACTION` |
| `chironql.no_ddl` | `ALTER`, `TRUNCATE`, `CREATE INDEX`, `CREATE TABLE`, `DROP TABLE` — anything but collection DDL |
| `chironql.missing_dim` | `CREATE COLLECTION` without `DIM` |
| `chironql.unknown_metric` | `METRIC` that is not `cosine`, `l2` or `dot` |
| `chironql.unknown_collection_option` · `chironql.invalid_collection_options` | A `WITH` key that is not a setting, or a `WITH` that is not an object |
| `chironql.no_index_family` | `WITH {index_kind: …}` — LS-VEC is the only path |
| `chironql.tenant_ddl_unsupported` | Collection DDL while tenant enforcement is on |
| `chironql.no_cte` | Raw ChironQL `WITH … AS (…)`; relational CTEs require `SQL WITH …` |
| `chironql.no_explain` | `EXPLAIN` — use the execution trace instead |
| `chironql.no_aggregates` | Aggregate syntax in raw retrieval statements; native aggregates use the `SQL` wrapper |
| `chironql.no_or_across_fields` | `OR` in a filter |
| `chironql.no_like` | `LIKE` in a filter — use `CONTAINS` |
| `chironql.unbounded_delete` | `DELETE FROM c` with neither `POINTS` nor `WHERE` |
| `chironql.multiple_statements` | More than one statement in a single request |
| `chironql.duplicate_condition` | The same operator twice on one field |
| `chironql.duplicate_clause` | The same clause twice in one statement |
| `chironql.weight_arity` | `WEIGHTS` count does not match the `NEAR` count |
| `chironql.missing_near` · `chironql.missing_like` · `chironql.missing_point_id` | Required piece absent |
| `chironql.invalid_recall` · `chironql.invalid_count` · `chironql.invalid_number` | Out-of-range or malformed literal |

`LS-VEC is the sole index path`, so there is no index family to select and no `USING hnsw` to honour.
That rejection is a design statement, not a gap.

## What is deliberately absent

- **Cluster and lifecycle operations** — `COMPACT`, `SNAPSHOT`, `RESTORE`. Use `chironctl`.
- **`ALTER COLLECTION`** — a collection's dimension and metric are fixed when it is made. Rebuilding
  it is `DROP COLLECTION` then `CREATE COLLECTION`, which is honest about what it costs.
- **Transactions, joins, subqueries, aggregates** — not in the engine.
- **`OR` across fields** — reserved as a keyword so the grammar stays forward-compatible.
- **Multi-statement requests** — one statement per request; there are no transactions to give
  partial failure a coherent meaning.
