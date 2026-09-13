# ChironQL

ChironQL is ChironDB's retrieval query language. It is a small, verb-first language for asking
retrieval questions — dense, hybrid, multi-vector, graph-constrained and recommendation search,
plus point and graph writes.

**Status: 1.1.** The language is implemented and served on every ChironQL surface: the embedded server
console, the `chironql` client, `POST /v1/chironql`,
`chirondb.v1.ChironDb/ExecuteQuery`, and ChironWire `ExecuteChironQl`.

The 1.1 addition preserves the 1.0 statements and adds the property-graph vocabulary below. The
statements, clause names, error codes and rejection taxonomy are **stable**: a statement
that parses today parses in every later release of the language, and a `code` a client switches on
keeps its meaning. Additions are allowed; removals go through a deprecation cycle rather than
disappearing between releases. The language version is independent of the ChironDB release version —
the database is in public beta, the language it answers is not.

**ChironQL is not SQL and will not grow relational features.** It has no joins, no CTEs, no
subqueries, no aggregates and no transactions, because the engine underneath has none of those. If
you want relational queries, run PostgreSQL alongside ChironDB — the pgvector-compatible wire subset
on port `7403` is a separate, deliberately narrow surface with its own documentation.
Every graph construct sent through that PostgreSQL-compatible surface is
rejected with SQLSTATE `0A000` and the stable `#graph` compatibility hint;
graph statements run only through ChironQL or a native ChironDB protocol.

## Where to type it

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
server's execution trace, `\timing`, `\format table|json`, `\role`, `\q` quit.

`\q`, `Ctrl-D`, or `Ctrl-C` on an empty line ends the session. In `chirondb --console`
that stops the server, because the console *is* the process you started. In the `chironql`
client it closes the client and leaves the server alone.

## Shape

One statement per `;`. Keywords are case-insensitive. The collection name is positional and may be
omitted once a session collection is set with `USE`.

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
`{id: 'phone', vector: [1,0,0]}` and `{"id": "phone", "vector": [1,0,0]}` are the same point.

For another page, add `AFTER '<cursor>'` with the returned point-ID cursor.
Omit it on the first request; do not invent an offset.

A named-vector example needs a configured space and a point containing it:

```sql
CREATE COLLECTION image_assets DIM 3 METRIC cosine WITH {named_vector_dims: {image: 3}};
UPSERT INTO image_assets {id: 'logo', vector: [1,0,0], vectors: {image: [0,1,0]}};
SEARCH image_assets NEAR @logo USING image LIMIT 20;
```

## Filtered deletes stop and ask

`DELETE ... WHERE` never runs on the first attempt. The server counts what the
filter matches and refuses, carrying the number:

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
| `chironql.not_sql` | `SELECT …`, `INSERT …` |
| `chironql.no_transactions` | `BEGIN`, `COMMIT`, `ROLLBACK`, `SAVEPOINT`, `START TRANSACTION` |
| `chironql.no_ddl` | `ALTER`, `TRUNCATE`, `CREATE INDEX`, `CREATE TABLE`, `DROP TABLE` — anything but collection DDL |
| `chironql.missing_dim` | `CREATE COLLECTION` without `DIM` |
| `chironql.unknown_metric` | `METRIC` that is not `cosine`, `l2` or `dot` |
| `chironql.unknown_collection_option` · `chironql.invalid_collection_options` | A `WITH` key that is not a setting, or a `WITH` that is not an object |
| `chironql.no_index_family` | `WITH {index_kind: …}` — LS-VEC is the only path |
| `chironql.tenant_ddl_unsupported` | Collection DDL while tenant enforcement is on |
| `chironql.no_cte` | `WITH … AS (…)` |
| `chironql.no_explain` | `EXPLAIN` — use the execution trace instead |
| `chironql.no_aggregates` | `GROUP BY`, `COUNT(*)`, `*` projections |
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
