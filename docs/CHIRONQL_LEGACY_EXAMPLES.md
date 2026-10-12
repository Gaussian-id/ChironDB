# ChironQL 1.0–1.4 syntax examples

This is the complete base-statement example index, including optional forms. These examples are syntax-verified; they are **not** claims that each operation is available on a protected installation. Use the [security reference](CHIRONQL_SECURITY.md) for user/role management and the protected subset, and [ChironQL](CHIRONQL.md) for semantics, graph setup and errors.

For positive legacy execution, first create an ordinary `products` collection with dimension 3, ingest `phone` and `book`, configure named spaces where used, and enable/configure the graph before graph commands. Every call still requires the applicable legacy role, collection allowlist, tenant and graph permissions. Destructive examples modify or drop these fixtures; run individually in a disposable database. EDGE_ID and cursor values stand for real returned values. Pasting this whole reference as one script is not supported.

Keywords are case-insensitive, statements end in `;`, and `--` comments end at a newline. String values use single quotes and doubled apostrophes; double-quoted JSON text is not a ChironQL object literal. Numeric sparse `TEXT {12:1}` is distinct from native natural-language BM25. The legacy 1.0–1.3 statements retain their limits on raw SQL, `OR` filters, transactions and role inheritance. ChironQL 1.4 adds explicitly prefixed `SQL`, bounded read-only `PIPELINE`, and bounded multi-model `TRANSACTION`; raw relational SQL remains rejected.

## Legacy 1.0–1.1 reference

### base-create

Legacy collection creation; protected installations require CREATE PROTECTED COLLECTION. Syntax example; availability varies.

<!-- chironql-example: base-create -->
```sql
CREATE COLLECTION products DIM 3 METRIC cosine WITH {named_vector_dims:{image:3}};
```

### base-create-l2

Alternative Euclidean distance metric. Syntax example; availability varies.

<!-- chironql-example: base-create-l2 -->
```sql
CREATE COLLECTION euclidean DIM 3 METRIC l2;
```

### base-create-dot

Alternative dot-product metric. Syntax example; availability varies.

<!-- chironql-example: base-create-dot -->
```sql
CREATE COLLECTION dot_products DIM 3 METRIC dot;
```

### base-upsert

Explicit client IDs and asynchronous WAL acknowledgement on the legacy surface. Syntax example; availability varies.

<!-- chironql-example: base-upsert -->
```sql
UPSERT INTO products {id:'phone',vector:[1,0,0],vectors:{image:[0,1,0]},payload:{category:'electronics',price:699,title:'wireless phone',meta:{brand:'acme'}}}, {id:'book',vector:[0,1,0],payload:{category:'books',price:25}} NO WAIT;
```

### base-search

All ordinary search control clauses; RECALL is a target, not a measured result. Protected dense search uses exact evaluation. Syntax example; availability varies.

<!-- chironql-example: base-search -->
```sql
SEARCH products NEAR [1,0,0] LIMIT 5 WITH PAYLOAD EF 64 RECALL 0.95 BUDGET 1000;
```

### base-stored-vector

Stored-vector references require a readable existing point; unavailable on protected ChironQL. Syntax example; availability varies.

<!-- chironql-example: base-stored-vector -->
```sql
SEARCH products NEAR @phone LIMIT 5;
```

### base-named-vector

Named vector space must be configured and populated. Syntax example; availability varies.

<!-- chironql-example: base-named-vector -->
```sql
SEARCH products NEAR @phone USING image LIMIT 5;
```

### base-filter-eq

Equality, conjunction and a bounded numeric range. Syntax example; availability varies.

<!-- chironql-example: base-filter-eq -->
```sql
SEARCH products NEAR [1,0,0] WHERE category = 'electronics' AND price >= 100 AND price <= 700 LIMIT 5;
```

### base-filter-ne

Not-equal and strict numeric comparisons. Syntax example; availability varies.

<!-- chironql-example: base-filter-ne -->
```sql
COUNT products WHERE category != 'books' AND price > 100 AND price < 1000;
```

### base-filter-in

Single-field membership implements a disjunction without OR. Syntax example; availability varies.

<!-- chironql-example: base-filter-in -->
```sql
SCROLL products WHERE category IN ['electronics','books'] LIMIT 10;
```

### base-filter-contains

Token intersection on a string field. Syntax example; availability varies.

<!-- chironql-example: base-filter-contains -->
```sql
COUNT products WHERE title CONTAINS 'wireless phone';
```

### base-filter-nested

Dotted nested payload path. Syntax example; availability varies.

<!-- chironql-example: base-filter-nested -->
```sql
COUNT products WHERE meta.brand = 'acme';
```

### base-hybrid

Numeric sparse-vector fusion; TEXT is not a natural-language string or the native BM25 API. Syntax example; availability varies.

<!-- chironql-example: base-hybrid -->
```sql
HYBRID products NEAR [1,0,0] TEXT {12:1.2,98:0.7} FUSION rrf LIMIT 5;
```

### base-hybrid-weighted

Explicit dense/sparse weights. Syntax example; availability varies.

<!-- chironql-example: base-hybrid-weighted -->
```sql
HYBRID products NEAR [1,0,0] TEXT {12:1.2} FUSION weighted DENSE 0.7 SPARSE 0.3 LIMIT 5;
```

### base-hybrid-named

Named-vector hybrid with query filter. Syntax example; availability varies.

<!-- chironql-example: base-hybrid-named -->
```sql
HYBRID products NEAR [0,1,0] USING image TEXT {12:1} WHERE price <= 700 LIMIT 5;
```

### base-multi

Fuse multiple dense query vectors with matching weights. Syntax example; availability varies.

<!-- chironql-example: base-multi -->
```sql
MULTI products NEAR [1,0,0], NEAR [0,1,0] FUSION weighted WEIGHTS 0.6,0.4 LIMIT 5;
```

### base-multi-rrf

RRF multi-query fusion. Syntax example; availability varies.

<!-- chironql-example: base-multi-rrf -->
```sql
MULTI products NEAR [1,0,0], NEAR [0,1,0] FUSION rrf WHERE price <= 700 LIMIT 5;
```

### base-recommend

Positive and negative examples; existing points required. Syntax example; availability varies.

<!-- chironql-example: base-recommend -->
```sql
RECOMMEND products LIKE phone UNLIKE book LIMIT 5;
```

### base-recommend-named

Named-space recommendation. Syntax example; availability varies.

<!-- chironql-example: base-recommend-named -->
```sql
RECOMMEND products LIKE phone USING image WHERE price <= 700 LIMIT 5;
```

### base-count

Count matches on legacy authorization surface. Syntax example; availability varies.

<!-- chironql-example: base-count -->
```sql
COUNT products;
```

### base-scroll

ID-based cursor; use the previous response cursor. Syntax example; availability varies.

<!-- chironql-example: base-scroll -->
```sql
SCROLL products AFTER 'phone' LIMIT 20;
```

### base-get

Batch point retrieval. Syntax example; availability varies.

<!-- chironql-example: base-get -->
```sql
GET products POINTS phone, book;
```

### base-list

Not exposed by protected ChironQL; use known protected collection names. Syntax example; availability varies.

<!-- chironql-example: base-list -->
```sql
SHOW COLLECTIONS;
```

### base-describe

Legacy schema/config inspection; protected policy has SHOW COLLECTION ... SECURITY POLICY. Syntax example; availability varies.

<!-- chironql-example: base-describe -->
```sql
DESCRIBE products;
```

### base-update

Merge ordinary payload fields; protected partial update is not supported. Syntax example; availability varies.

<!-- chironql-example: base-update -->
```sql
UPDATE products POINT phone SET PAYLOAD {featured:true};
```

### base-replace

Replace the legacy payload object. Syntax example; availability varies.

<!-- chironql-example: base-replace -->
```sql
UPDATE products POINT phone SET PAYLOAD {category:'electronics',price:699} REPLACE;
```

### base-delete

Explicit ID deletion. Syntax example; availability varies.

<!-- chironql-example: base-delete -->
```sql
DELETE FROM products POINTS phone, book;
```

### base-delete-filter

Filtered deletion requires confirmation; legacy preview counts matches. Syntax example; availability varies.

<!-- chironql-example: base-delete-filter -->
```sql
DELETE FROM products WHERE category = 'archived';
```

### base-relate

Requires graph lifecycle and edge-type setup via a native administrative API. Syntax example; availability varies.

<!-- chironql-example: base-relate -->
```sql
RELATE products phone -> related_to -> book SET {strength:0.8} IDEMPOTENCY KEY 'relation-001' NO WAIT;
```

### base-deferred

Conditional: requires a server-bound deferred session; stateless requests reject it. Syntax example; availability varies.

<!-- chironql-example: base-deferred -->
```sql
RELATE products phone -> related_to -> book WITH DEFERRED ENDPOINTS;
```

### base-unrelate

Replace EDGE_ID with a returned opaque edge token, not a point ID. Syntax example; availability varies.

<!-- chironql-example: base-unrelate -->
```sql
UNRELATE products EDGE 'EDGE_ID' NO WAIT;
```

### base-edge-update

Merge edge properties. Syntax example; availability varies.

<!-- chironql-example: base-edge-update -->
```sql
UPDATE products EDGE 'EDGE_ID' SET PROPERTIES {strength:0.9} NO WAIT;
```

### base-edge-replace

Replace edge properties. Syntax example; availability varies.

<!-- chironql-example: base-edge-replace -->
```sql
UPDATE products EDGE 'EDGE_ID' SET PROPERTIES {strength:0.9} REPLACE NO WAIT;
```

### base-traverse-nodes

Exact traversal, requires enabled graph. Syntax example; availability varies.

<!-- chironql-example: base-traverse-nodes -->
```sql
TRAVERSE products FROM phone VIA related_to DIRECTION OUT DEPTH 2 LIMIT 20 WITH PAYLOAD RETURN NODES;
```

### base-traverse-edges

Incoming edges with a property filter. Syntax example; availability varies.

<!-- chironql-example: base-traverse-edges -->
```sql
TRAVERSE products FROM phone DIRECTION IN DEPTH 1 EDGE WHERE strength >= 0.5 LIMIT 20 RETURN EDGES;
```

### base-traverse-paths

Simple paths require LIMIT; WHERE is not a protected security policy. Syntax example; availability varies.

<!-- chironql-example: base-traverse-paths -->
```sql
TRAVERSE products FROM phone, book VIA related_to DIRECTION ANY DEPTH 2 WHERE price <= 700 EDGE WHERE strength >= 0.5 BUDGET 1000 MS LIMIT 20 WITH PAYLOAD RETURN PATHS;
```

### base-connected-search

Graph-constrained search; ALLOW DEGRADED does not bypass authorization. Syntax example; availability varies.

<!-- chironql-example: base-connected-search -->
```sql
SEARCH products NEAR [1,0,0] CONNECTED TO phone VIA related_to DIRECTION OUT WITHIN 2 HOPS ALLOW DEGRADED LIMIT 10;
```

### base-connected-hybrid

Graph-constrained numeric hybrid. Syntax example; availability varies.

<!-- chironql-example: base-connected-hybrid -->
```sql
HYBRID products NEAR [1,0,0] TEXT {12:1} CONNECTED TO phone VIA related_to DIRECTION ANY WITHIN 2 HOPS ALLOW DEGRADED LIMIT 10;
```

### base-drop

Destructive legacy lifecycle operation; protected drop remains rejected. Syntax example; availability varies.

<!-- chironql-example: base-drop -->
```sql
DROP COLLECTION products;
```

### base-drop-if-before

Equivalent placement of IF EXISTS before the collection name. Syntax example; availability varies.

<!-- chironql-example: base-drop-if-before -->
```sql
DROP COLLECTION IF EXISTS products;
```

### base-drop-if

Suppress a missing legacy collection error, not authorization errors. Syntax example; availability varies.

<!-- chironql-example: base-drop-if -->
```sql
DROP COLLECTION products IF EXISTS;
```

### base-use

Set the session collection. Syntax example; availability varies.

<!-- chironql-example: base-use -->
```sql
USE products;
```

### base-session-search

Run after USE products in the same session or pass --collection products. Syntax example; availability varies.

<!-- chironql-example: base-session-search -->
```sql
SEARCH NEAR [1,0,0] LIMIT 5;
```

## ChironQL 1.4 additive relational examples

The entries above remain the frozen 1.0–1.3 compatibility corpus. Version 1.4 adds these statement variants without changing their behavior.

### base-sql

One native SQL statement routed through the relational analyzer and executor.

<!-- chironql-example: base-sql -->
```sql
SQL SELECT id, title FROM documents LIMIT 20;
```

### base-pipeline

Bounded read-only vector and relational pipeline; protected execution remains fail-closed.

<!-- chironql-example: base-pipeline -->
```sql
PIPELINE
  VECTOR v { SEARCH chunks NEAR [1,0] LIMIT 20 }
  RELATIONAL r { SQL SELECT id, chunk_ref FROM documents LIMIT 20 }
  INNER JOIN r ON r.chunk_ref = v.record_ref
  RETURN r.id, v.score
  LIMIT 10;
```

### base-transaction-multimodel

One durable decision for a relational mutation, vector points, and graph relation.
Protected execution remains fail-closed until the graph and relational permissions
can be authorized as one request.

<!-- chironql-example: base-transaction-multimodel -->
```sql
TRANSACTION {
  SQL INSERT INTO documents (id, title) VALUES ('doc-1', 'Atomic document');
  VECTOR UPSERT INTO chunks {id: 'chunk-1', vector: [1,0]}, {id: 'source-1', vector: [0,1]};
  GRAPH CONNECT chunks 'chunk-1' -> CITES -> 'source-1';
};
```

## Traditional ML evaluation

Decision Tree and Random Forest are optional previews for unprotected installations.
Provision the worker separately as described in [ChironQL](CHIRONQL.md#tabular-ml-materialization-preview).
This example verifies the grammar; protected tenant enforcement rejects ML execution.
Regression confidence remains `NULL`. Use distinct view names to compare models.

<!-- chironql-example: base-ml-materialize -->
```sql
ML MATERIALIZE demo_regression FROM ml_demo TARGET amount FEATURES (price) TASK REGRESSION USING DECISION_TREE;
```
