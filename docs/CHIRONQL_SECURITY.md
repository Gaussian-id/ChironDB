# ChironQL security reference — language 1.4 local preview

Complete user, role, credential, document-security and protected-query reference for a **single-tenant, single-node** installation. This reference describes builds containing the protected security implementation; the database release version alone does not identify that build. See [deployment](../deploy/protected/README.md), [base language](CHIRONQL.md), [legacy examples](CHIRONQL_LEGACY_EXAMPLES.md), [HTTP](HTTP_API.md) and [gRPC](GRPC_API.md).

## Start here

- Already initialized and running locally: use the connection command below; do not initialize again.
- No installation yet: follow the empty-directory and TLS recipe below.
- Need to grant a role: create its collection/role/user first, then use [Roles and users](#roles-and-users).
- Need a new user's key: use [API keys](#api-keys) with `--key-out`.
- Need document access: both role capability and object policy must allow it; see [Protected data](#protected-data) and [Document ACL and labels](#document-acl-and-labels).
- Seeing `revision 9`: read [Three revision scopes](#three-revision-scopes).

## Protected relational SQL

Authenticated ChironQL `SQL ...`, HTTP `/sql` and `/v1/sql`, gRPC SQL RPCs,
and ChironWire SQL operations share the native protected relational executor.
A table name is installation-global and persists the tenant that created it;
another tenant receives `security.not_found` even if a misconfigured grant
names that table. SELECT/EXPLAIN requires `read`, INSERT requires `create`,
UPDATE requires `update`, DELETE requires `delete`, and DDL requires the
installation action `schema`. Foreign-key validation and referential actions
add the required parent/child grants before execution.

After the offline `migrate-table-authority` command below, an installation
administrator can grant SQL-only tables directly. The table and role must
already exist; a vector collection is not required:

```sql
GRANT READ, CREATE, UPDATE, DELETE ON TABLE documents TO ROLE editor;
REVOKE READ ON TABLE documents FROM ROLE editor;
```

The CLI supplies the current identity revision. HTTP, gRPC and ChironWire
callers append `IF REVISION n` from `SHOW SECURITY REVISION`. These four data
actions are the only supported table grants. Each grant binds the tenant,
persistent table ID and a random incarnation UUID. Rename preserves the
binding; drop/recreate does not transfer it to the replacement table, even
if a restored catalog later reuses a numeric ID. Table grants do not grant
vector or graph access. `SHOW ROLE editor PRIVILEGES` includes `table_grants`;
`SHOW CURRENT USER PRIVILEGES` includes `scope: "table"` rows with the current
`table` name and a null `collection`.

Stop the server, retain a verified backup and its keyring, then run:

```sh
chironctl security migrate-table-authority --data-dir "$CHIRON_HOME/data" --keyring "$CHIRON_HOME/secrets/storage-keyring.json"
chironctl security migrate-sql-scopes --data-dir "$CHIRON_HOME/data" --keyring "$CHIRON_HOME/secrets/storage-keyring.json"
```

Restart with the same candidate binary. The command requires exclusive
ownership of the data directory, no other embedded `Db` handles and no open
SQL transactions. It fences older binaries with installation format 4,
publishes identity authority version 5, then atomically adds missing table
incarnations to the checkpoint catalog. Existing row/index runs and commit
sequence numbers are preserved. After an interruption, rerun the same
command offline: the catalog contains either all old or all new table
identities. A failed catalog publication rejects further writes from that
process until reopen. Backup/archive capsules remain non-runnable format 3;
restore reconciles current authority and retains the format-4 reader fence.
Administrator recovery also retains that fence. Downgrading the binary or
manually removing the marker is unsupported.

The second command, `migrate-sql-scopes`, requires the completed table migration.
It converts legacy SQL name permissions onto **currently existing** tables and
publishes identity version 6 under installation reader format 5. Role collection
permissions are copied into exact table grants; direct principal permissions
become assigned `sql_migrated_<id>` roles, inspectable and revocable with the
normal role commands. Collection permissions keep their vector/graph meaning.
Names without a current table confer no future SQL rights. Disabled users stay
disabled; their existing table rights remain dormant. No old table acquires an
inferred creator. Over-budget conversion is rejected before authority publication;
reduce unnecessary grants before rerunning the offline migration.

The conversion publishes all grants in one authority generation, preserving the
catalog, rows, credentials and installation identity. Rerun offline after an
interruption; the installed authority is either the complete previous or complete
new generation. An uncertain publication closes authorization until reopen.
Administrator recovery and restore retain reader format 5 for this authority.
Backup/archive capsules retain non-runnable format 3. Use the candidate binary
and matching SDK; older binaries cannot open the upgraded installation.

In strict SQL scope mode, newly created tables record the creator's immutable
principal ID. The creator has Read/Create/Update/Delete on that table, so
protected PostgreSQL-wire or native transactions can CREATE and use a table
before COMMIT without a pre-existing name grant. Other users need `ON TABLE`
role grants after publication. DDL still requires installation Schema. Creator
rights do not grant vector/graph access or access to other existing tables.
They survive rename and reopen and are independent of role grants; revoking a
role does not remove creator rights. Disable/retire the principal to remove its
access. Creator transfer is not supported. Savepoint rollback removes later
private DDL; COMMIT rechecks accumulated permissions.

Standalone idempotency receipts written under identity version 5 or later save
table bindings. An identical retry after rename or reopen returns the original
decision, subject to current permissions. Interactive commit reconciliation also
rechecks these bindings. After strict migration, legacy successful standalone
receipts without saved authorization and interactive proofs using only table
names are denied. Their keys remain consumed: do not submit a new key to retry
an uncertain mutation. Reconcile its durable transaction status and application
state. Exact table-bound receipts continue to work.

Installations that have not run `migrate-sql-scopes` retain the legacy SQL name
fallback and do not have this table-isolation guarantee. The production candidate
requires both migrations. In strict mode, `ON COLLECTION` and direct principal
name scopes cannot authorize SQL, even when collection and table names match.
PostgreSQL catalog visibility follows table Read grants or creator rights; a
same-name vector collection cannot reveal another user's SQL columns. Privilege
listing rejects more than 4,096 table/action rows; SQL execution still authorizes
the individual table directly.

Interactive transaction handles are bound to their principal and tenant.
Commit reauthenticates the current identity revision and authorizes the full
accumulated statement set before publication. Protected `PIPELINE` authorizes
its dense/BM25/text-hybrid retrieval, optional graph traversal, and relational resources before the
first read, pins one multi-model frontier, and rechecks each participating
permission revision before transport publication. Graph node/edge filters are supported within
the node-returning graph stage described below. The VECTOR stage accepts dense SEARCH, BM25-only
HYBRID TEXT, or dense+BM25 HYBRID NEAR ... TEXT with the same authorized field corpus as standalone
text retrieval. Numeric sparse hybrid remains unavailable.

Protected multi-model `TRANSACTION` accepts the bounded SQL UPDATE/DELETE,
vector UPSERT/DELETE, and graph CONNECT/RELATE/UNRELATE/UPDATE EDGE profile.
Every stage is bound to the same tenant and collection authority before the
shared journal decision; row, vector, graph, security metadata, and audit are
projections of the same transaction ID. Request-level `idempotency_key` claims the shared
ledger before allocation and returns the same transaction/snapshot and allocated `edge_id`
rows on retry. Current SQL, object and graph-endpoint permissions apply to replay.
Edge-token updates/deletes require GraphWrite on both endpoints. A DELETE receipt can
acknowledge only its own retained tombstone; a prior UPDATE receipt cannot bypass a later
deletion. Transport publication retains the exact identity/policy epoch checked by the
core, including after DELETE rotates that epoch. Protected INSERT uses `VECTOR CREATE POINTS`,
server IDs and explicit `NEW_RECORD`/graph bindings; see [atomic INSERT](CHIRONQL.md#protected-atomic-insert).
Every stored reference is checked before COMMIT, and its allocated public IDs are retained in the
receipt. The new record and any existing reference must remain readable on replay.
An UPDATE/DELETE planner rejection before attempting the durable journal decision
leaves row, vector, graph and resource bindings unchanged and permits fresh reads.
A rejected DELETE may invalidate already queued results while it drains the old
authorization epoch. A failure after attempting the durable decision remains
fail closed until recovery and outcome reconciliation; it must not be treated as
a safe retry without checking the transaction outcome.
Protected PostgreSQL wire requires `SSLRequest`, TLS and a
separately issued `SCRAM-SHA-256` SQL password. The resulting principal,
tenant and revocation guard are the same authority used here; a ChironQL API
key is not accepted as the SQL password. Issue or rotate through
`POST /v1/security/sql-credentials` with a principal ID and current identity
revision, and revoke its returned ID through the existing credential revocation
route. The generated password is returned only once. Protected installations
remain single-tenant in this beta.

## Guarded metadata replacement

For a revision predicate to condition sibling vector and graph mutations, use
`EXPECT SQL ROWS 1;` immediately after the `TRANSACTION` SQL stage. A mismatch returns
`chironql.sql_row_precondition_failed` (HTTP 409; gRPC and ChironWire
`FAILED_PRECONDITION` with that code in their error details) before the durable decision and leaves SQL/content/graph state unchanged.
Fresh authorized reads remain usable; a rejected DELETE can withdraw old queued results.
The guard counts directly affected SQL rows, including `RETURNING`, and excludes cascades
and vector/graph mutations. It participates in the consumed key's request fingerprint.
Validation rejection has no durable receipt or transaction ID. Request without a guard keeps
existing zero-row semantics and retry identity. Older servers reject the new stage before
mutation. See [the grammar and embedded API](CHIRONQL.md#sql-row-preconditions).

## Protected graph setup

The installation administrator or a role with `SCHEMA ON COLLECTION docs` can enable graph
storage and configure edge types. These commands are available through the same authenticated
ChironQL HTTP, gRPC and ChironWire routes. They use the collection security revision displayed by
`SHOW SECURITY REVISION ON COLLECTION docs`; replace the example revisions with current values.

For the newly created empty `docs` collection in these examples, its initial
revision is 1. Enable graph storage, then use the resulting revision for the edge type.

<!-- chironql-example: enable-protected-graph -->
```sql
ALTER COLLECTION docs SET GRAPH ENABLED IF REVISION 1;
```

<!-- chironql-example: configure-protected-edge-type -->
```sql
ALTER COLLECTION docs SET EDGE TYPE cites IF REVISION 2;
```

A successful change advances the security revision and invalidates queued results from the old
revision. Repeating an unchanged setting with the current revision makes no new commit. A stale
revision rejects. `SET EDGE TYPE cites WEIGHT confidence` names the numeric edge property used
for weighting; omitting WEIGHT configures the type without a weight property. Enabling graph on a populated
collection starts bounded handle backfill, reported as `graph.backfill_in_progress`. Restart resumes
it. New public object IDs and object permissions are preserved. Configuration replies contain the
new `revision` and graph/type receipt.

`ALTER COLLECTION docs SET GRAPH DISABLED IF REVISION 4` removes graph visibility and requires
request `confirm: true` (the terminal confirmation flow handles this). It preserves vector content.
Graph configuration grants no document read/write permission. Ingestion roles separately need
`GRAPH_WRITE` and object policy permission on each endpoint; readers need `GRAPH_READ`.
Legacy graph management endpoints remain unavailable for protected collections.

## Protected graph filters

Within a protected `PIPELINE`, the graph stage accepts `WHERE` for node payloads and
`EDGE WHERE` for edge properties. For the `docs` table/collection from the
[atomic INSERT example](CHIRONQL.md#protected-atomic-insert):

```sql
PIPELINE
  VECTOR v { SEARCH docs NEAR [1,0] LIMIT 1 }
  GRAPH g { TRAVERSE docs FROM v.record_ref VIA cites DEPTH 1 WHERE text = 'source' EDGE WHERE kind = 'source' RETURN NODES LIMIT 20 }
  RELATIONAL r { SQL SELECT id, chunk, source FROM docs LIMIT 10 }
  INNER JOIN r ON r.chunk = v.record_ref
  INNER JOIN g ON g.record_ref = r.source
  RETURN r.id, g.depth
  LIMIT 10;
```

The retrieval stage may instead be `VECTOR v { HYBRID docs TEXT 'chunk' FIELD text LIMIT 1 }`
for BM25 or `VECTOR v { HYBRID docs NEAR [1,0] TEXT 'chunk' FIELD text LIMIT 1 }` for dense+BM25.
Both forms keep the same graph joins and typed record identities. A pipeline without a GRAPH stage
needs no GRAPH_READ grant. Search, SQL and optional graph authorities are all bound before retrieval,
and revocation prevents pending result publication. Literal or typed `$1`…`$n` vector values are
accepted in pipeline NEAR; absent or non-vector values return `security.invalid`.

Every visited endpoint requires current `GRAPH_READ`. Hidden nodes cannot act as intermediate
hops, and both endpoints are checked before reading or evaluating edge properties. Node predicates
add `Query` permission and clearance checks for each referenced payload field. A disallowed field
on a visible candidate rejects the query. Business edges do not grant access.

All properties on a relation share the visibility of its two endpoints; this profile has no separate
edge or edge-property ACL. Use protected records for content requiring stricter field permissions.
An unknown edge type yields no matching edges, like a type with no visible relations.

The protected graph stage returns public node IDs and depth, ordered by depth then public ID,
with its own `LIMIT` applied before the join. Empty anchors preserve the same typed output schema.
Within a `PIPELINE`, `RETURN EDGES`, `RETURN PATHS`, and graph `WITH PAYLOAD` reject with
`chironql.protected_unsupported` before stages execute.

Standalone protected `TRAVERSE` supports `RETURN NODES`, `RETURN EDGES`, and
`RETURN PATHS` through ChironQL on HTTP, gRPC and ChironWire. Paths require an explicit
`LIMIT`. `WITH PAYLOAD` projects node fields under their Read permissions; edge properties
require GraphRead on both endpoints. IDs and path endpoints are public record identities.
For example, using the chunk ID returned by an atomic INSERT:

```sql
TRAVERSE docs FROM '<chunk-id>' VIA cites DEPTH 1 WITH PAYLOAD RETURN EDGES LIMIT 10;
```

Legacy native graph query endpoints remain unavailable on protected collections.

Cancellation, deadline or traversal-budget exhaustion rejects the whole protected result;
no partial result from an exhausted work budget is published. Standalone traversal may apply
its visible row `LIMIT` and report `stats.truncation: "limit"` with
`graph.result_truncated`. The maximum traversal deadline is 30 seconds. A traversal
requiring unfinished handle backfill fails as unavailable. Physical storage counters and backfill
warnings are omitted; the embedded protected traversal result keeps those counters at zero.
Response hydration uses a quarter of the admitted graph memory reservation, capped at
64 MiB, with conservative JSON accounting before cloning payloads or properties. An output
that exceeds this reservation is refused. The serialized core response is limited to 8 MiB.
Identity and policy revisions are checked during traversal and again before publication. These
controls do not establish timing isolation or production resource/latency qualification.

## What grants access

An API key authenticates an immutable user identity. Roles add action capabilities on an exact collection incarnation, a migrated SQL table incarnation, or the installation. Department, clearance, ownership, direct/group/inherited grants, property rules, and explicit denies determine the accessible objects and fields. A role named `admin` has no special power. An empty role grants nothing. There is no implicit `PUBLIC` role.

The designated first administrator can provision protected collections, configure graph schema, and manage users/policies/labels/ACLs. It has no default document read/write/export permission. Operations administration and security administration are distinct. `IdentityManage` cannot be granted through an ordinary role; possession of a capability named `CollectionCreate` does not create the designated installation-administrator identity.
The designated installation administrator can delegate exact collection or SQL-table actions within its own tenant, including to itself. Each data read or write still needs an explicit grant; delegation cannot cross tenants or grant `IdentityManage` as a collection action.

| Profile used in the examples | Capabilities | Data boundary |
|---|---|---|
| `admin` | Bootstrap security management, provisioning, observation | No document access by default |
| `ops` / `operations` | `OBSERVE ON SYSTEM` | No document access |
| `writer` / `ingestion_writer` | Read/search/create/ingest/update/delete on `docs` | Trusted ingestion and authorized owned objects |
| `ana` / `finance_reader` | Read/search on `docs` | Finance, up to Confidential |
| `ben` / `hr_reader` | Read/search on `docs` | HR, up to Internal; explicit sharing may add objects |

Classification is ordered: `PUBLIC < INTERNAL < CONFIDENTIAL < RESTRICTED`. Missing, null, unknown or wrong-type mandatory attributes fail closed. Department names and user/role names are values: preserve their case (`Finance` and `finance` are different values). Keywords and classification/action tokens are case-insensitive. Name length is 1–128 ASCII characters drawn from letters, digits, `_`, `-`, `.`, `:`; quote punctuated names with single quotes. Individual resource types impose additional validation. No wildcard collection or tenant scope is added by these commands.

## Concrete local setup and connection

Run shell commands from the checkout containing the security implementation. Set paths once:

```sh
export CHIRON_BIN="$PWD/target/debug"
export CHIRON_HOME="$HOME/chirondb-secure"
export CHIRON_URL=https://localhost:7401
cargo build --locked -p chirondb --bin chirondb --bin chironctl --bin chironql
"$CHIRON_BIN/chironctl" security --help
```

**Only for a new installation**, with no server using the directory. The directories and output files must be new, private and owned by the initializing account. If the directory already contains your initialized installation, skip this block; never delete it merely to make initialization succeed.

```sh
mkdir -m 700 "$CHIRON_HOME"
mkdir -m 700 "$CHIRON_HOME/secrets"
"$CHIRON_BIN/chironctl" security init \
  --data-dir "$CHIRON_HOME/data" --tenant default --admin admin \
  --keyring-out "$CHIRON_HOME/secrets/storage-keyring.json" \
  --admin-key-out "$CHIRON_HOME/secrets/admin.key"
```

The output key file contains the administrator credential; the command never prints it. There is no `LOGIN admin` or password. Keep the storage keyring: administrator recovery cannot replace lost encryption material.

For **local testing only**, create a 30-day CA and server certificate. This recipe needs `openssl`; it covers `localhost` and `127.0.0.1` without changing system trust. Skip certificate creation if your matching certificates already exist. For a deployed server, use operator-provided certificates for its actual hostname as described in the [deployment runbook](../deploy/protected/README.md).

```sh
umask 077
mkdir -m 700 "$CHIRON_HOME/tls"
cat > "$CHIRON_HOME/tls/ca.cnf" <<'CA'
[req]
prompt = no
distinguished_name = dn
x509_extensions = ca_extensions
[dn]
CN = ChironDB local test CA
[ca_extensions]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
CA
cat > "$CHIRON_HOME/tls/server.cnf" <<'CERT'
subjectAltName=DNS:localhost,IP:127.0.0.1
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
CERT
openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
  -config "$CHIRON_HOME/tls/ca.cnf" \
  -keyout "$CHIRON_HOME/tls/ca.key" -out "$CHIRON_HOME/tls/ca.pem"
openssl req -newkey rsa:2048 -nodes -subj '/CN=localhost' \
  -keyout "$CHIRON_HOME/tls/server.key" -out "$CHIRON_HOME/tls/server.csr"
openssl x509 -req -in "$CHIRON_HOME/tls/server.csr" \
  -CA "$CHIRON_HOME/tls/ca.pem" -CAkey "$CHIRON_HOME/tls/ca.key" \
  -CAcreateserial -days 30 -extfile "$CHIRON_HOME/tls/server.cnf" \
  -out "$CHIRON_HOME/tls/server.pem"
openssl verify -CAfile "$CHIRON_HOME/tls/ca.pem" "$CHIRON_HOME/tls/server.pem"
```

Start the server in terminal A, only if it is not already running. Bind to loopback for this local example; initialization does not start the server.

```sh
"$CHIRON_BIN/chirondb" \
  --data-dir "$CHIRON_HOME/data" \
  --encryption-keyring-file "$CHIRON_HOME/secrets/storage-keyring.json" \
  --tenant-enforcement enforced \
  --tls-cert "$CHIRON_HOME/tls/server.pem" \
  --tls-key "$CHIRON_HOME/tls/server.key" \
  --listen-http 127.0.0.1:7401 \
  --listen-grpc 127.0.0.1:7402 \
  --listen-wire 127.0.0.1:7403
```

In terminal B set the same path variables, then connect:

```sh
"$CHIRON_BIN/chironql" --url "$CHIRON_URL" \
  --ca-cert "$CHIRON_HOME/tls/ca.pem" \
  --api-key-file "$CHIRON_HOME/secrets/admin.key"
```

The client authenticates before showing `chiron>`. Type `SHOW CURRENT USER;` and `SHOW CURRENT USER PRIVILEGES;` to verify identity and effective capability. `\role` describes connection enforcement; it is not a substitute for those catalog queries. Exiting the standalone client leaves the server running.

## Client flags, scripts and key delivery

For the examples in this section define a convenience function in the shell. It does not alter server privilege:

```sh
cq() {
  "$CHIRON_BIN/chironql" --url "$CHIRON_URL" \
    --ca-cert "$CHIRON_HOME/tls/ca.pem" \
    --api-key-file "$CHIRON_HOME/secrets/admin.key" "$@"
}
```

| Syntax | Example | Meaning/prerequisite |
|---|---|---|
| `--url URL` | `chironql --url https://localhost:7401 --ca-cert "$CHIRON_HOME/tls/ca.pem" --api-key-file "$CHIRON_HOME/secrets/admin.key"` | Real server URL; verification stays enabled |
| `--ca-cert FILE` | `cq --exec 'SHOW CURRENT USER;'` | The function supplies the actual CA file; a literal `/path/to/ca.pem` is not a certificate |
| `--api-key-file FILE` | `chironql --url "$CHIRON_URL" --ca-cert "$CHIRON_HOME/tls/ca.pem" --api-key-file "$CHIRON_HOME/secrets/ana.key"` | Switch identity by reconnecting with that user's issued key |
| `--exec STATEMENT` | `cq --exec 'SHOW USERS;'` | One statement; no stdin script is consumed |
| `--format table` | `cq --format table --exec 'SHOW ROLES;'` | Human-readable table |
| `--format json` | `cq --format json --exec 'SHOW CURRENT USER PRIVILEGES;'` | Machine-readable result |
| `--params-json JSON` | `--params-json '[{"type":"text","value":"owner-1"}]'` | Typed positional parameters for relational/atomic queries; see [parameter examples](CHIRONQL.md#native-relational-sql) |
| `--idempotency-key KEY` | `--idempotency-key document-1-v1` | Stable key for a SQL mutation; reuse with the same request when retrying |
| `--retry-id ID` | `--retry-id attempt-1` | Audit correlation for a relational or atomic multi-model mutation; separate from the durable idempotency key |
| `--trace` | `cq --trace --exec 'SHOW CURRENT USER;'` | Request trace; protected responses retain redaction rules |
| `--collection NAME` | `cq --collection docs --exec 'COUNT;'` | Set the session collection; still needs data permission, so this fails for the default administrator |
| `--yes` | `cq --yes --exec 'ALTER USER ana SET STATUS SUSPENDED;'` | Required confirmation for a script's destructive operation; adds no privilege |
| `--key-out FILE` | `cq --key-out "$CHIRON_HOME/secrets/ana.key" --exec 'ISSUE API KEY FOR USER ana;'` | New exclusive 0600 output; user must exist; secret is omitted from the result/history |
| `--history FILE` | `cq --history "$CHIRON_HOME/operator.history"` | Legacy history location; protected sessions suppress query history |
| `--api-key VALUE` | `chironql --url "$CHIRON_URL" --ca-cert "$CHIRON_HOME/tls/ca.pem" --api-key EXAMPLE_NOT_A_REAL_KEY --exec 'SHOW CURRENT USER;'` | Compatibility flag; this dummy credential deliberately fails. Prefer a file so real secrets do not appear in process arguments/history |
| `--help`, `-h` | `chironql --help` | List client flags |
| `--version`, `-V` | `chironql --version` | Database build version; distinct from language version |

Without `--api-key-file`, the key sources are `--api-key`, then `CHIRONDB_API_KEY`, then the compatibility `GAUSSDB_API_KEY`. A key file takes precedence and is validated before connection. Do not combine identities or send duplicate credential headers.

A script sends statements in order and stops at the first failure. Earlier successful statements remain committed. It is **not** one transaction. For example:

```sh
cat > "$CHIRON_HOME/check-access.chql" <<'QL'
SHOW CURRENT USER;
SHOW CURRENT USER PRIVILEGES;
SHOW ROLES WITH USERS;
QL
cq < "$CHIRON_HOME/check-access.chql"
```

CLI exits: `0` success, `1` query/authorization/confirmation failure, `2` connection or local setup failure. An interactive session retains earlier query failures: `\q` can exit with status `1` after a denied statement even though quitting itself succeeded. Each issuance/rotation needs a distinct `--key-out` filename; do not issue multiple keys in one script using one output path. To rotate, first inspect `SHOW API KEYS FOR USER ana;`, substitute its credential ID (not the secret) for `KEY_ID`, then run:

```sh
cq --key-out "$CHIRON_HOME/secrets/ana-rotated.key" \
  --exec "ROTATE API KEY 'KEY_ID';"
```

Reconnect using `ana-rotated.key`. The old credential stops working. A lost response must not trigger blind issuance retry; inspect the catalog/key delivery state. The secret is available only at issuance, not through `SHOW API KEYS`.

An attached console uses the same server arguments above plus `--console --console-api-key-file "$CHIRON_HOME/secrets/admin.key"`. For key issuance add `--console-key-out "$CHIRON_HOME/secrets/new-user.key"`. Run it only after stopping the unattended instance. Exiting this attached console stops its server. `--console-role admin` applies only to legacy sessions and cannot elevate a protected identity.

## Three revision scopes

| Revision | Read it with | Used by |
|---|---|---|
| Identity authority | `SHOW SECURITY REVISION;` | User/role membership, role privileges, user attributes, credentials |
| Collection catalog | `SHOW CATALOG REVISION;` | `CREATE PROTECTED COLLECTION` |
| Collection policy authority | `SHOW SECURITY REVISION ON COLLECTION docs;` | Policy replacement, document grants/denies, labels |

A result headed `revision` with value `9` means that authority is now at revision 9. It is not a count of users, roles or permissions. Do not substitute the collection catalog revision for the identity revision. Ordinary data generation and graph epochs are separate concepts; data create/update does not accept `IF REVISION` as an optimistic-write token.

The CLI reads the correct revision and appends it when you omit `IF REVISION`. To take explicit control, use the current number, for example `CREATE ROLE revision_guard IF REVISION 9;`. If an intervening administrator changes the authority, you get `security.conflict`; the client does not retry automatically. Re-read state, review the change and submit intentionally. `IF REVISION` is accepted only on security mutations, not `SHOW`, data create or ordinary search. A collection-creation success returns the collection name; not every mutation prints a revision table.

## How to read the statement examples

Every fenced SQL example below is paired with a coverage entry in [the example corpus](../chirondb-server/tests/fixtures/chironql_documentation.json). The complete validator is [security_documentation_examples.py](../chirondb-server/tests/security_documentation_examples.py). Reference sections are grouped for lookup, not meant to be pasted as one large script. The validator runs the necessary operations in dependency order on its own new installation.

`docs` is a collection created by the setup example. `ana`, `ben`, `writer`, and `ops` are users created in the reference. `POINT_ID`, `SECOND_ID`, `THIRD_ID`, `HR_ID` and `CURSOR_ID` represent actual returned values; ChironQL does not substitute these words itself. `KEY_ID` and `ROTATED_KEY_ID` are credential IDs from `SHOW API KEYS`. Replace them before manual execution. The validator captures and substitutes real values automatically. Security examples use single-quoted strings; escape a quote by doubling it (`'Ana''s report'`). JSON objects in SQL use unquoted or single-quoted keys. The **HTTP envelope** is ordinary double-quoted JSON, while its `query` string contains ChironQL.

For ingestion the role needs Create plus Ingest, a trusted template, matching vector dimensions, sufficient clearance and write permission on the supplied fields. The template assigns the authoritative department/classification/property and representation labels. Ordinary payload fields named `owner` or `department` cannot substitute for security metadata. Update replaces existing authorized objects, and explicit batches are atomic. Deleted IDs cannot be reused by replay.

A document permit does not override explicit deny, clearance, tenant boundaries or field rules. Reading a field and using it in filter/search are distinct. Inheritance/group membership must come from the trusted authority, not business graph edges. ChironQL 1.3 accepts point ACL subjects `USER` and `GROUP`, but has **no** group creation/membership or parent-inheritance editing syntax. Group examples are conditional on an already provisioned trusted group and are syntax-verified only.

Protected native SQL upsert (`INSERT ... ON CONFLICT DO UPDATE`) requires both
`create` and `update` grants for the target, plus applicable FK dependency grants.
Interactive BEGIN returns the future COMMIT transaction ID; retries of COMMIT
reconcile one durable decision and recheck the original permission requirements
against current authority, even if the table was subsequently dropped.

Protected support: GET/COUNT/SCROLL/USE, inline dense search, standalone BM25/text hybrid, server-ID create, existing-object replacement, ID/filter delete, standalone bounded `TRAVERSE` with node/edge/path output and authorized payloads, bounded dense/BM25/text-hybrid `PIPELINE` with optional node/edge-filtered graph traversal and relational SELECT, the bounded multi-model INSERT/UPDATE/DELETE `TRANSACTION` profiles, graph schema setup, and the security statements below. The protected dense implementation evaluates the authorized domain exactly under its budgets; `EF`/`RECALL` are not proof of ANN performance. Standalone graph mutation, graph edge/path/payload output inside PIPELINE, numeric sparse hybrid, multi-query fusion, recommend, stored-vector `@id`, partial payload update, ordinary UPSERT, collection drop/rename/legacy schema listing, snapshot/restore and MCP remain unavailable on this protected surface. They are denied rather than routed through legacy authorization. See [legacy syntax examples](CHIRONQL_LEGACY_EXAMPLES.md) for the separate language surface.

The 21 typed action names are documented at the end. Recognition by the parser does not mean the action is delegable or that its protected feature is implemented. Default bootstrap only has IdentityManage, CollectionCreate, PolicyManage, LabelsManage, GrantsManage, Observe and Schema on the installation; data scopes are explicitly assigned. Snapshot, restore, graph and export vocabulary does not enable an unsupported protected endpoint.

## Identity and revisions

### current-user

Inspect your server-authenticated identity; available to every active user. Actor: `admin`. Protected execution.

<!-- chironql-example: current-user -->
```sql
SHOW CURRENT USER;
```

### current-privileges

List effective action capabilities; this is not a list of every readable document. Actor: `admin`. Protected execution.

<!-- chironql-example: current-privileges -->
```sql
SHOW CURRENT USER PRIVILEGES;
```

### identity-revision

Read the identity/user/role/key catalog revision; administrative authority required. Actor: `admin`. Protected execution.

<!-- chironql-example: identity-revision -->
```sql
SHOW SECURITY REVISION;
```

### catalog-revision

Read the collection catalog revision; designated installation administrator required. Actor: `admin`. Protected execution.

<!-- chironql-example: catalog-revision -->
```sql
SHOW CATALOG REVISION;
```

### collection-revision

Read the policy/ACL/label revision for this collection, not the identity revision. Actor: `admin`. Protected execution.

<!-- chironql-example: collection-revision -->
```sql
SHOW SECURITY REVISION ON COLLECTION docs;
```

### explicit-revision

Use the current value returned by SHOW SECURITY REVISION. Here 9 is illustrative, not a reusable token. Actor: `admin`. Protected execution.

<!-- chironql-example: explicit-revision -->
```sql
CREATE ROLE revision_guard IF REVISION 9;
```

### stale-revision

Intentional conflict: revision zero is stale on an initialized installation. No role is created. Actor: `admin`. Protected execution.

<!-- chironql-example: stale-revision -->
```sql
CREATE ROLE stale_example IF REVISION 0;
```

## Collections and ingestion policy

### create-protected

Create a deny-all two-dimensional collection. Initially no ingest template exists. Actor: `admin`. Protected execution.

<!-- chironql-example: create-protected -->
```sql
CREATE PROTECTED COLLECTION docs DIM 2 METRIC cosine;
```

### show-policy

Inspect policy and its revision before replacing it. Actor: `admin`. Protected execution.

<!-- chironql-example: show-policy -->
```sql
SHOW COLLECTION docs SECURITY POLICY;
```

### set-policy

Replace the whole typed policy. Preserve required templates when editing; this is not a partial merge. Actor: `admin`. Protected execution.

<!-- chironql-example: set-policy -->
```sql
ALTER COLLECTION docs SET SECURITY POLICY {
  'department_actions': [
    'read',
    'search'
  ],
  'owner_actions': [
    'read',
    'search',
    'update',
    'delete'
  ],
  'templates': {
    'finance': {
      'department': 'Finance',
      'classification': 'internal',
      'properties': {
        '/text': {
          'classification': 'internal',
          'actions': [
            'read',
            'query',
            'write'
          ]
        }
      },
      'representations': {
        'dense': {
          'source_fields': [
            '/text'
          ],
          'classification': 'internal'
        }
      }
    },
    'hr': {
      'department': 'HR',
      'classification': 'internal',
      'properties': {
        '/text': {
          'classification': 'internal',
          'actions': [
            'read',
            'query',
            'write'
          ]
        }
      },
      'representations': {
        'dense': {
          'source_fields': [
            '/text'
          ],
          'classification': 'internal'
        }
      }
    }
  }
};
```

## Roles and users

### create-role

Create a role with zero permissions; its name has no special meaning. Actor: `admin`. Protected execution.

<!-- chironql-example: create-role -->
```sql
CREATE ROLE finance_reader;
```

### grant-collection

Allow read operations and dense search on the exact active docs incarnation. Actor: `admin`. Protected execution.

<!-- chironql-example: grant-collection -->
```sql
GRANT READ, SEARCH ON COLLECTION docs TO ROLE finance_reader;
```

### create-user

Both department and clearance are required. The new user is active but has no key or privileges. Actor: `admin`. Protected execution.

<!-- chironql-example: create-user -->
```sql
CREATE USER ana SET DEPARTMENT Finance SET CLEARANCE CONFIDENTIAL;
```

### grant-role

Assign the existing role to the existing user. Actor: `admin`. Protected execution.

<!-- chironql-example: grant-role -->
```sql
GRANT ROLE finance_reader TO USER ana;
```

### show-role

Inspect the role capability grants. Actor: `admin`. Protected execution.

<!-- chironql-example: show-role -->
```sql
SHOW ROLE finance_reader PRIVILEGES;
```

### show-roles

List role names; membership is requested separately with WITH USERS. Actor: `admin`. Protected execution.

<!-- chironql-example: show-roles -->
```sql
SHOW ROLES;
```

### show-memberships

List roles and their user names. Actor: `admin`. Protected execution.

<!-- chironql-example: show-memberships -->
```sql
SHOW ROLES WITH USERS;
```

### show-users

List users, trusted attributes, enabled status, and role names. Actor: `admin`. Protected execution.

<!-- chironql-example: show-users -->
```sql
SHOW USERS;
```

## Five-profile setup

### writer-role

Create a separate ingestion role. Actor: `admin`. Protected execution.

<!-- chironql-example: writer-role -->
```sql
CREATE ROLE ingestion_writer;
```

### writer-capabilities

Raw vector/source ingestion requires INGEST as well as CREATE/UPDATE. Actor: `admin`. Protected execution.

<!-- chironql-example: writer-capabilities -->
```sql
GRANT READ, SEARCH, CREATE, INGEST, UPDATE, DELETE ON COLLECTION docs TO ROLE ingestion_writer;
```

### writer-user

The ingestion principal has sufficient clearance to ingest the trusted templates. Actor: `admin`. Protected execution.

<!-- chironql-example: writer-user -->
```sql
CREATE USER writer SET DEPARTMENT Ingestion SET CLEARANCE RESTRICTED;
```

### writer-membership

Give the ingestion user only the defined writer role. Actor: `admin`. Protected execution.

<!-- chironql-example: writer-membership -->
```sql
GRANT ROLE ingestion_writer TO USER writer;
```

### ops-role

Create an operations role independently of the security administrator. Actor: `admin`. Protected execution.

<!-- chironql-example: ops-role -->
```sql
CREATE ROLE operations;
```

### grant-system

ON SYSTEM is for installation actions. OBSERVE permits operator metrics, not document access. Actor: `admin`. Protected execution.

<!-- chironql-example: grant-system -->
```sql
GRANT OBSERVE ON SYSTEM TO ROLE operations;
```

### ops-user

Create an operator identity. Actor: `admin`. Protected execution.

<!-- chironql-example: ops-user -->
```sql
CREATE USER ops SET DEPARTMENT Operations SET CLEARANCE INTERNAL;
```

### ops-membership

Assign observation privileges. Actor: `admin`. Protected execution.

<!-- chironql-example: ops-membership -->
```sql
GRANT ROLE operations TO USER ops;
```

### hr-role

Create a separate HR role. Actor: `admin`. Protected execution.

<!-- chironql-example: hr-role -->
```sql
CREATE ROLE hr_reader;
```

### hr-capabilities

Object policy still separates HR from Finance despite the same collection capability. Actor: `admin`. Protected execution.

<!-- chironql-example: hr-capabilities -->
```sql
GRANT READ, SEARCH ON COLLECTION docs TO ROLE hr_reader;
```

### hr-user

Create the HR reader. Actor: `admin`. Protected execution.

<!-- chironql-example: hr-user -->
```sql
CREATE USER ben SET DEPARTMENT HR SET CLEARANCE INTERNAL;
```

### hr-membership

Assign the HR reader role. Actor: `admin`. Protected execution.

<!-- chironql-example: hr-membership -->
```sql
GRANT ROLE hr_reader TO USER ben;
```

## API keys

### issue-writer

Use CLI --key-out with a new private filename. No secret is printed; each issuance creates a new credential. Actor: `admin`. Protected execution.

<!-- chironql-example: issue-writer -->
```sql
ISSUE API KEY FOR USER writer;
```

### issue-ana

Use CLI --key-out with a new private filename. No secret is printed; each issuance creates a new credential. Actor: `admin`. Protected execution.

<!-- chironql-example: issue-ana -->
```sql
ISSUE API KEY FOR USER ana;
```

### issue-ben

Use CLI --key-out with a new private filename. No secret is printed; each issuance creates a new credential. Actor: `admin`. Protected execution.

<!-- chironql-example: issue-ben -->
```sql
ISSUE API KEY FOR USER ben;
```

### issue-ops

Use CLI --key-out with a new private filename. No secret is printed; each issuance creates a new credential. Actor: `admin`. Protected execution.

<!-- chironql-example: issue-ops -->
```sql
ISSUE API KEY FOR USER ops;
```

### show-keys

List credential IDs and revocation status only; no secret or hash is recoverable here. Actor: `admin`. Protected execution.

<!-- chironql-example: show-keys -->
```sql
SHOW API KEYS FOR USER ana;
```

### rotate-key

Replace KEY_ID with the ID from SHOW API KEYS. Requires --key-out pointing to a new file; the old credential is revoked. Actor: `admin`. Protected execution.

<!-- chironql-example: rotate-key -->
```sql
ROTATE API KEY 'KEY_ID';
```

### revoke-key

Use the new credential ID for this example. Revocation cannot be undone by reactivating a user. Actor: `admin`. Protected execution.

<!-- chironql-example: revoke-key -->
```sql
REVOKE API KEY 'ROTATED_KEY_ID';
```

## Protected data

### create-point

Run as writer. Save the returned ID as POINT_ID; do not send an id field on create. Actor: `writer`. Protected execution.

<!-- chironql-example: create-point -->
```sql
CREATE POINTS INTO docs USING TEMPLATE finance {vector:[1,0],payload:{text:'finance report'}} REQUEST 'manual-finance-001';
```

### create-batch

Point objects are comma-separated without an outer array. Save the two returned IDs as SECOND_ID and THIRD_ID. Actor: `writer`. Protected execution.

<!-- chironql-example: create-batch -->
```sql
CREATE POINTS INTO docs USING TEMPLATE finance {vector:[0,1],payload:{text:'second report'}}, {vector:[1,1],payload:{text:'third report'}} REQUEST 'manual-finance-002';
```

### create-hr

The trusted template determines the department; it is not supplied as an authoritative payload field. Actor: `writer`. Protected execution.

<!-- chironql-example: create-hr -->
```sql
CREATE POINTS INTO docs USING TEMPLATE hr {vector:[0,1],payload:{text:'hr policy'}} REQUEST 'manual-hr-001';
```

### retry-create

Same principal, request ID and identical content returns the original IDs after reauthorization; it must not insert a duplicate. Actor: `writer`. Protected execution.

<!-- chironql-example: retry-create -->
```sql
CREATE POINTS INTO docs USING TEMPLATE finance {vector:[1,0],payload:{text:'finance report'}} REQUEST 'manual-finance-001';
```

### get-point

Use a real server-assigned ID. Hidden and missing IDs both yield no readable rows. Actor: `ana`. Protected execution.

<!-- chironql-example: get-point -->
```sql
GET docs POINTS 'POINT_ID';
```

### get-batch

Retrieve multiple IDs under the same access domain. Actor: `ana`. Protected execution.

<!-- chironql-example: get-batch -->
```sql
GET docs POINTS 'POINT_ID', 'SECOND_ID';
```

### count

Finance sees its three documents, not the HR document. Actor: `ana`. Protected execution.

<!-- chironql-example: count -->
```sql
COUNT docs;
```

### count-filter

Query permission on /text is required, independently of permission to read it. Actor: `ana`. Protected execution.

<!-- chironql-example: count-filter -->
```sql
COUNT docs WHERE text = 'finance report';
```

### scroll

Read an authorized page. For pagination use the response next cursor, not a numeric offset. Actor: `ana`. Protected execution.

<!-- chironql-example: scroll -->
```sql
SCROLL docs LIMIT 2;
```

### scroll-after

Replace CURSOR_ID with the preceding response next cursor. Actor: `ana`. Protected execution.

<!-- chironql-example: scroll-after -->
```sql
SCROLL docs AFTER 'CURSOR_ID' LIMIT 2;
```

### dense

Inline vectors must match the collection dimension. The result contains only authorized points. Actor: `ana`. Protected execution.

<!-- chironql-example: dense -->
```sql
SEARCH docs NEAR [1,0] LIMIT 10 WITH PAYLOAD;
```

### dense-filter

Filter fields require query permission; budget cannot increase the server ceiling. Actor: `ana`. Protected execution.

<!-- chironql-example: dense-filter -->
```sql
SEARCH docs NEAR [1,0] WHERE text CONTAINS 'finance' LIMIT 2 BUDGET 1000 WITH PAYLOAD;
```

### BM25 and text hybrid

`HYBRID docs TEXT 'synthetic' FIELD text LIMIT 10;` searches BM25 alone.
Add `NEAR [1,0]` before `TEXT` to combine the default dense vector with BM25
using RRF. Both forms support `WHERE`, `LIMIT` and `BUDGET`; fields are literal
top-level payload keys. Search access and Query permission/clearance on the
field define the scoring corpus. Unknown or unqueryable fields return no hits.
Adding hidden documents cannot change visible BM25 scores. Dense results also
require the representation's source-field permissions. Payload Read permissions
still control projection. Revocation or an exhausted budget rejects the entire
protected result, including data queued for transport. See the
[HTTP contract](HTTP_API.md#native-text-hybrid-search) for limits and the exact
protected dense path's current performance qualification status.

### use

Session collection selection requires Read on the collection. It does not grant access. Actor: `ana`. Protected execution.

<!-- chironql-example: use -->
```sql
USE docs;
```

### update-point

Replace an authorized existing object using its server ID; this is not a payload patch. Actor: `writer`. Protected execution.

<!-- chironql-example: update-point -->
```sql
UPDATE POINTS IN docs {id:'POINT_ID',vector:[1,0],payload:{text:'updated finance report'}};
```

### update-batch

A mixed unauthorized explicit batch is rejected atomically. Actor: `writer`. Protected execution.

<!-- chironql-example: update-batch -->
```sql
UPDATE POINTS IN docs {id:'SECOND_ID',vector:[0,1],payload:{text:'obsolete'}}, {id:'THIRD_ID',vector:[1,1],payload:{text:'third revised'}};
```

### delete-ids

Explicit IDs need Delete permission; read permission alone never permits deletion. Actor: `writer`. Protected execution.

<!-- chironql-example: delete-ids -->
```sql
DELETE FROM docs POINTS 'THIRD_ID';
```

### delete-filter

Requires confirmation (CLI --yes in scripts); selection uses the delete-authorized domain. Protected preview omits counts. Actor: `writer`. Protected execution.

<!-- chironql-example: delete-filter -->
```sql
DELETE FROM docs WHERE text = 'obsolete';
```

## Document ACL and labels

### grant-point

An explicit object grant can share across departments in the same tenant. READ does not automatically grant SEARCH. Actor: `admin`. Protected execution.

<!-- chironql-example: grant-point -->
```sql
GRANT READ, SEARCH ON POINT 'POINT_ID' IN docs TO USER ben;
```

### deny-point

Explicit deny overrides the permit, role and department. It does not raise clearance. Actor: `admin`. Protected execution.

<!-- chironql-example: deny-point -->
```sql
DENY READ, SEARCH ON POINT 'POINT_ID' IN docs TO USER ben;
```

### revoke-deny

Remove the deny while keeping the independent explicit permit. Actor: `admin`. Protected execution.

<!-- chironql-example: revoke-deny -->
```sql
REVOKE DENY READ, SEARCH ON POINT 'POINT_ID' IN docs FROM USER ben;
```

### revoke-grant

Remove the explicit permit. Department/owner/group/inherited permits may still apply. Actor: `admin`. Protected execution.

<!-- chironql-example: revoke-grant -->
```sql
REVOKE GRANT READ, SEARCH ON POINT 'POINT_ID' IN docs FROM USER ben;
```

### grant-group

Conditional syntax: payroll must already exist in the trusted identity authority. Group creation/membership has no ChironQL command in 1.3. Conditional; syntax verified only.

<!-- chironql-example: grant-group -->
```sql
GRANT READ ON POINT 'POINT_ID' IN docs TO GROUP payroll;
```

### deny-group

Conditional syntax: payroll must already exist in the trusted identity authority. Group creation/membership has no ChironQL command in 1.3. Conditional; syntax verified only.

<!-- chironql-example: deny-group -->
```sql
DENY READ ON POINT 'POINT_ID' IN docs TO GROUP payroll;
```

### revoke-grant-group

Conditional syntax: payroll must already exist in the trusted identity authority. Group creation/membership has no ChironQL command in 1.3. Conditional; syntax verified only.

<!-- chironql-example: revoke-grant-group -->
```sql
REVOKE GRANT READ ON POINT 'POINT_ID' IN docs FROM GROUP payroll;
```

### revoke-deny-group

Conditional syntax: payroll must already exist in the trusted identity authority. Group creation/membership has no ChironQL command in 1.3. Conditional; syntax verified only.

<!-- chironql-example: revoke-deny-group -->
```sql
REVOKE DENY READ ON POINT 'POINT_ID' IN docs FROM GROUP payroll;
```

### point-owner

Owner is resolved to an immutable user ID. Content writers cannot change this by editing payload. Actor: `admin`. Protected execution.

<!-- chironql-example: point-owner -->
```sql
ALTER POINT 'POINT_ID' IN docs SET OWNER ana;
```

### point-department

Changing the security department can change visibility; LabelsManage/delegation checks apply. Actor: `admin`. Protected execution.

<!-- chironql-example: point-department -->
```sql
ALTER POINT 'POINT_ID' IN docs SET DEPARTMENT HR;
```

### point-classification

Raising classification also tightens derived representation labels; existing lower-clearance readers lose access. Actor: `admin`. Protected execution.

<!-- chironql-example: point-classification -->
```sql
ALTER POINT 'POINT_ID' IN docs SET CLASSIFICATION RESTRICTED;
```

### point-combined

Several distinct SET clauses are one security transaction. Duplicate SET attributes are rejected. Actor: `admin`. Protected execution.

<!-- chironql-example: point-combined -->
```sql
ALTER POINT 'POINT_ID' IN docs SET OWNER writer SET DEPARTMENT Finance SET CLASSIFICATION RESTRICTED;
```

## User lifecycle and revocation

### alter-department

Changes trusted identity attributes and drains the old authorization context. Actor: `admin`. Protected execution.

<!-- chironql-example: alter-department -->
```sql
ALTER USER ana SET DEPARTMENT Finance;
```

### alter-clearance

A role does not change clearance; explicit identity administration does. Actor: `admin`. Protected execution.

<!-- chironql-example: alter-clearance -->
```sql
ALTER USER ana SET CLEARANCE INTERNAL;
```

### suspend-user

Requires confirmation; existing credentials stop authenticating while suspended. Actor: `admin`. Protected execution.

<!-- chironql-example: suspend-user -->
```sql
ALTER USER ana SET STATUS SUSPENDED;
```

### activate-user

Reactivate the identity; revoked credentials remain revoked. Actor: `admin`. Protected execution.

<!-- chironql-example: activate-user -->
```sql
ALTER USER ana SET STATUS ACTIVE;
```

### alter-combined

Apply several distinct identity attributes in one transaction. Actor: `admin`. Protected execution.

<!-- chironql-example: alter-combined -->
```sql
ALTER USER ana SET DEPARTMENT Finance SET CLEARANCE CONFIDENTIAL SET STATUS ACTIVE;
```

### revoke-role

Remove membership without deleting the role or user; existing sessions observe revocation. Actor: `admin`. Protected execution.

<!-- chironql-example: revoke-role -->
```sql
REVOKE ROLE finance_reader FROM USER ana;
```

### revoke-collection

Edit the role itself; this affects every member, unlike REVOKE ROLE ... FROM USER. Actor: `admin`. Protected execution.

<!-- chironql-example: revoke-collection -->
```sql
REVOKE SEARCH ON COLLECTION docs FROM ROLE finance_reader;
```

### revoke-system

Remove the installation action from all members of the role. Actor: `admin`. Protected execution.

<!-- chironql-example: revoke-system -->
```sql
REVOKE OBSERVE ON SYSTEM FROM ROLE operations;
```

### rename-user

Only the display name changes; ID, ownership and grants retain identity. Actor: `admin`. Protected execution.

<!-- chironql-example: rename-user -->
```sql
RENAME USER ana TO ana_archive;
```

### rename-role

Renaming preserves the internal role ID and memberships. Actor: `admin`. Protected execution.

<!-- chironql-example: rename-role -->
```sql
RENAME ROLE finance_reader TO finance_viewer;
```

### drop-role

Requires confirmation. Recreating the same name never restores old grants/memberships. Actor: `admin`. Protected execution.

<!-- chironql-example: drop-role -->
```sql
DROP ROLE finance_viewer;
```

### drop-user

Requires confirmation; retire the user and revoke credentials. Existing object ownership is not transferred. Actor: `admin`. Protected execution.

<!-- chironql-example: drop-user -->
```sql
DROP USER ana_archive;
```

## Deliberately rejected requests

### nondelegable

Identity management is bootstrap authority; this parses but authorization rejects it. Actor: `admin`. Protected execution.

<!-- chironql-example: nondelegable -->
```sql
GRANT IDENTITY_MANAGE ON SYSTEM TO ROLE operations;
```

### legacy-upsert-denied

Protected collections reject client-ID UPSERT; use CREATE POINTS or UPDATE POINTS. Actor: `admin`. Protected execution.

<!-- chironql-example: legacy-upsert-denied -->
```sql
UPSERT INTO docs {id:'chosen',vector:[1,0],payload:{text:'wrong create API'}};
```

## Rejected grammar

### bad-or

Intentional parser rejection; do not use this syntax. Expected parser rejection.

<!-- chironql-example: bad-or -->
```sql
COUNT docs WHERE text = 'a' OR text = 'b';
```

### bad-login

Intentional parser rejection; do not use this syntax. Expected parser rejection.

<!-- chironql-example: bad-login -->
```sql
LOGIN admin;
```

### bad-group-create

Intentional parser rejection; do not use this syntax. Expected parser rejection.

<!-- chironql-example: bad-group-create -->
```sql
CREATE GROUP payroll;
```

### bad-point-revoke

Intentional parser rejection; do not use this syntax. Expected parser rejection.

<!-- chironql-example: bad-point-revoke -->
```sql
REVOKE READ ON POINT 'POINT_ID' IN docs FROM USER ben;
```

### bad-create-id

Intentional parser rejection; do not use this syntax. Expected parser rejection.

<!-- chironql-example: bad-create-id -->
```sql
CREATE POINTS INTO docs USING TEMPLATE finance {id:'chosen',vector:[1,0]} REQUEST 'bad';
```

### bad-role-inherit

Intentional parser rejection; do not use this syntax. Expected parser rejection.

<!-- chironql-example: bad-role-inherit -->
```sql
GRANT ROLE finance_reader TO ROLE operations;
```

### bad-password

Intentional parser rejection; do not use this syntax. Expected parser rejection.

<!-- chironql-example: bad-password -->
```sql
CREATE USER password_user SET PASSWORD 'example';
```

### bad-show-revision

Intentional parser rejection; do not use this syntax. Expected parser rejection.

<!-- chironql-example: bad-show-revision -->
```sql
SHOW CURRENT USER IF REVISION 9;
```

### Double-quoted object rejection

HTTP JSON syntax is not a ChironQL object literal. Use single-quoted strings inside SQL. Expected parser rejection.

<!-- chironql-example: bad-double-quoted-object -->
```sql
CREATE POINTS INTO docs USING TEMPLATE finance {"vector":[1,0],"payload":{"text":"x"}} REQUEST 'bad-json';
```
## Action vocabulary

### action-read

Vocabulary example only: scope, administrator delegation and feature availability are checked separately. Syntax example; availability varies.

<!-- chironql-example: action-read -->
```sql
GRANT READ ON COLLECTION docs TO ROLE operations;
```

### action-search

Vocabulary example only: scope, administrator delegation and feature availability are checked separately. Syntax example; availability varies.

<!-- chironql-example: action-search -->
```sql
GRANT SEARCH ON COLLECTION docs TO ROLE operations;
```

### action-create

Vocabulary example only: scope, administrator delegation and feature availability are checked separately. Syntax example; availability varies.

<!-- chironql-example: action-create -->
```sql
GRANT CREATE ON COLLECTION docs TO ROLE operations;
```

### action-ingest

Vocabulary example only: scope, administrator delegation and feature availability are checked separately. Syntax example; availability varies.

<!-- chironql-example: action-ingest -->
```sql
GRANT INGEST ON COLLECTION docs TO ROLE operations;
```

### action-update

Vocabulary example only: scope, administrator delegation and feature availability are checked separately. Syntax example; availability varies.

<!-- chironql-example: action-update -->
```sql
GRANT UPDATE ON COLLECTION docs TO ROLE operations;
```

### action-delete

Vocabulary example only: scope, administrator delegation and feature availability are checked separately. Syntax example; availability varies.

<!-- chironql-example: action-delete -->
```sql
GRANT DELETE ON COLLECTION docs TO ROLE operations;
```

### action-graph_read

Vocabulary example only: scope, administrator delegation and feature availability are checked separately. Syntax example; availability varies.

<!-- chironql-example: action-graph_read -->
```sql
GRANT GRAPH_READ ON COLLECTION docs TO ROLE operations;
```

### action-graph_write

Vocabulary example only: scope, administrator delegation and feature availability are checked separately. Syntax example; availability varies.

<!-- chironql-example: action-graph_write -->
```sql
GRANT GRAPH_WRITE ON COLLECTION docs TO ROLE operations;
```

### action-traverse

Vocabulary example only: scope, administrator delegation and feature availability are checked separately. Syntax example; availability varies.

<!-- chironql-example: action-traverse -->
```sql
GRANT TRAVERSE ON COLLECTION docs TO ROLE operations;
```

### action-schema

Vocabulary example only: scope, administrator delegation and feature availability are checked separately. Syntax example; availability varies.

<!-- chironql-example: action-schema -->
```sql
GRANT SCHEMA ON COLLECTION docs TO ROLE operations;
```

### action-collection_create

Vocabulary example only: scope, administrator delegation and feature availability are checked separately. Syntax example; availability varies.

<!-- chironql-example: action-collection_create -->
```sql
GRANT COLLECTION_CREATE ON SYSTEM TO ROLE operations;
```

### action-collection_drop

Vocabulary example only: scope, administrator delegation and feature availability are checked separately. Syntax example; availability varies.

<!-- chironql-example: action-collection_drop -->
```sql
GRANT COLLECTION_DROP ON SYSTEM TO ROLE operations;
```

### action-maintain

Vocabulary example only: scope, administrator delegation and feature availability are checked separately. Syntax example; availability varies.

<!-- chironql-example: action-maintain -->
```sql
GRANT MAINTAIN ON SYSTEM TO ROLE operations;
```

### action-observe

Vocabulary example only: scope, administrator delegation and feature availability are checked separately. Syntax example; availability varies.

<!-- chironql-example: action-observe -->
```sql
GRANT OBSERVE ON SYSTEM TO ROLE operations;
```

### action-identity_manage

Vocabulary example only: scope, administrator delegation and feature availability are checked separately. Syntax example; availability varies.

<!-- chironql-example: action-identity_manage -->
```sql
GRANT IDENTITY_MANAGE ON SYSTEM TO ROLE operations;
```

### action-policy_manage

Vocabulary example only: scope, administrator delegation and feature availability are checked separately. Syntax example; availability varies.

<!-- chironql-example: action-policy_manage -->
```sql
GRANT POLICY_MANAGE ON COLLECTION docs TO ROLE operations;
```

### action-labels_manage

Vocabulary example only: scope, administrator delegation and feature availability are checked separately. Syntax example; availability varies.

<!-- chironql-example: action-labels_manage -->
```sql
GRANT LABELS_MANAGE ON COLLECTION docs TO ROLE operations;
```

### action-grants_manage

Vocabulary example only: scope, administrator delegation and feature availability are checked separately. Syntax example; availability varies.

<!-- chironql-example: action-grants_manage -->
```sql
GRANT GRANTS_MANAGE ON COLLECTION docs TO ROLE operations;
```

### action-export

Vocabulary example only: scope, administrator delegation and feature availability are checked separately. Syntax example; availability varies.

<!-- chironql-example: action-export -->
```sql
GRANT EXPORT ON COLLECTION docs TO ROLE operations;
```

### action-snapshot

Vocabulary example only: scope, administrator delegation and feature availability are checked separately. Syntax example; availability varies.

<!-- chironql-example: action-snapshot -->
```sql
GRANT SNAPSHOT ON SYSTEM TO ROLE operations;
```

### action-restore

Vocabulary example only: scope, administrator delegation and feature availability are checked separately. Syntax example; availability varies.

<!-- chironql-example: action-restore -->
```sql
GRANT RESTORE ON SYSTEM TO ROLE operations;
```

## HTTP API: the same statements

`POST /chironql` and `POST /v1/chironql` execute one statement. Their `/parse` counterparts authenticate and check grammar without executing it. The JSON body has `query`, optional `collection` (session default), `trace` and `confirm`. The CLI automatically obtains revisions; a direct API caller must supply `IF REVISION` on a security mutation using the appropriate revision query. The server never turns a body field or tenant header into trusted identity.

This executable Python example reads a key from a private file, verifies TLS/hostname, refuses redirects, shows the current user and creates a zero-permission role. Run only when the example role does not already exist. It deliberately does not retry a conflict. The environment variables allow the same example to target a disposable lab; defaults match the concrete local setup above.

<!-- executable-python: http-administration -->
```python
import json
import os
from pathlib import Path
import ssl
import urllib.request

root = Path(os.environ.get('CHIRON_HOME', str(Path.home() / 'chirondb-secure')))
base = os.environ.get('CHIRON_URL', 'https://localhost:7401')
ca = Path(os.environ.get('CHIRON_CA', str(root / 'tls/ca.pem')))
key_path = Path(os.environ.get('CHIRON_ADMIN_KEY', str(root / 'secrets/admin.key')))

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None

client = urllib.request.build_opener(
    NoRedirect(), urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(ca))))

def execute(query):
    request = urllib.request.Request(
        base + '/v1/chironql',
        data=json.dumps({'query': query, 'trace': False, 'confirm': False}).encode(),
        headers={'Authorization': 'Bearer ' + key_path.read_text().strip(),
                 'Content-Type': 'application/json'})
    with client.open(request, timeout=15) as response:
        return json.load(response)

print(execute('SHOW CURRENT USER;')['rows'])
revision = execute('SHOW SECURITY REVISION;')['rows'][0]['revision']
print(execute(f'CREATE ROLE api_example IF REVISION {revision};')['rows'])
```

Ordinary results use `rows`, `affected`, or empty kind; scroll additionally carries `next`. Sensitive raw query/storage metadata is omitted from protected traces. For ISSUE/ROTATE, the HTTP response additionally carries a one-time `credential` containing `id` and `secret`; do not log or print the whole response. Prepare exclusive private delivery before issuing; use the CLI's `--key-out` workflow when possible. `SHOW API KEYS` never returns that secret or its hash. An API consumer must handle a response lost after commit without blindly issuing again.

## Primary gRPC example

Generate clients from the matching source schemas (run from the checkout):

```sh
python3 -m grpc_tools.protoc -I proto \
  --python_out=. --grpc_python_out=. \
  proto/chirondb/v1/compat.proto proto/chirondb/v1/chirondb.proto
```

Install the pinned protocol dependencies in an isolated environment from [security_chironql_requirements.txt](../chirondb-server/tests/security_chironql_requirements.txt), or generate in a separate directory and add it to `PYTHONPATH`. The example uses `chirondb.v1.ChironDb/ExecuteQuery`. Legacy `gaussdb.v1.GaussDb` remains denied for protected execution. Reusing a channel does not retain revoked permission.

<!-- executable-python: grpc-current-user -->
```python
import json
import os
from pathlib import Path
import grpc
from chirondb.v1 import chirondb_pb2, chirondb_pb2_grpc

root = Path(os.environ.get('CHIRON_HOME', str(Path.home() / 'chirondb-secure')))
ca = Path(os.environ.get('CHIRON_CA', str(root / 'tls/ca.pem')))
key = Path(os.environ.get('CHIRON_ADMIN_KEY', str(root / 'secrets/admin.key'))).read_text().strip()
address = os.environ.get('CHIRON_GRPC', 'localhost:7402')
with grpc.secure_channel(address, grpc.ssl_channel_credentials(ca.read_bytes())) as channel:
    reply = chirondb_pb2_grpc.ChironDbStub(channel).ExecuteQuery(
        chirondb_pb2.ChironQlRequest(query='SHOW CURRENT USER;'),
        metadata=[('authorization', 'Bearer ' + key)], timeout=15)
    print([json.loads(row) for row in reply.rows_json])
```

Security mutation queries use the same `IF REVISION` convention. For issuance/rotation, `credential_json` is additive field 8: consume it privately once, do not render it. Authentication errors map to `UNAUTHENTICATED`; permission errors to `PERMISSION_DENIED`.

## ChironWire example

ChironWire shares TCP port 7403 with protocol detection. This example is ChironWire over TLS, not PostgreSQL SQL. Use the generated `compat_pb2` from the preceding step. A frame is a four-byte big-endian length followed by a protobuf message; the credential is sent inside TLS on each request.

<!-- executable-python: wire-current-user -->
```python
import json
import os
from pathlib import Path
import socket
import ssl
import struct
from chirondb.v1 import compat_pb2 as pb

root = Path(os.environ.get('CHIRON_HOME', str(Path.home() / 'chirondb-secure')))
ca = Path(os.environ.get('CHIRON_CA', str(root / 'tls/ca.pem')))
key = Path(os.environ.get('CHIRON_ADMIN_KEY', str(root / 'secrets/admin.key'))).read_text().strip()
host = os.environ.get('CHIRON_HOST', 'localhost')
port = int(os.environ.get('CHIRON_WIRE_PORT', '7403'))
context = ssl.create_default_context(cafile=str(ca))
with context.wrap_socket(socket.create_connection((host, port), timeout=15), server_hostname=host) as stream:
    message = pb.WireRequest(request_id=1, api_key=key,
        chironql=pb.WireChironQlRequest(query='SHOW CURRENT USER;')).SerializeToString()
    stream.sendall(struct.pack('!I', len(message)) + message)
    def read_exact(size):
        result = b''
        while len(result) < size:
            part = stream.recv(size - len(result))
            if not part:
                raise EOFError('connection ended before the response')
            result += part
        return result
    size = struct.unpack('!I', read_exact(4))[0]
    if size > 8 * 1024 * 1024:
        raise ValueError('response exceeds the protected frame budget')
    response = pb.WireResponse.FromString(read_exact(size))
    if response.error_code:
        raise RuntimeError(response.error_code)
    print([json.loads(row) for row in response.chironql.rows_json])
```

Protected ChironWire permits its ChironQL operation and reauthenticates every message. Other native operations without a protected implementation are rejected. Issuance uses the same private `credential_json` contract. PostgreSQL clients on the detected pgwire surface use PostgreSQL syntax; they cannot send these user/role statements.

## Every terminal meta-command

Meta-commands are client controls, not SQL statements or API query strings. They do not grant permission. Unless shown with a semicolon, type them on their own line without one.

| Command/aliases | Examples | Protected behavior |
|---|---|---|
| Help | `\h`, `\?`, `\help` | Display help; use this reference for the complete security vocabulary |
| Quit | `\q`, `\quit` | Close client; attached console also stops its server |
| Clear | `clear;`, `\clear` | Clear terminal display, not data or audit |
| List | `\l`, `\d` | Expands to legacy `SHOW COLLECTIONS`; rejected on protected installations |
| Describe | `\d docs` | Expands to legacy `DESCRIBE`; rejected on protected installations |
| Use collection | `\c docs`, `\use docs` | Expands to `USE docs`; requires Read on docs |
| Trace | `\trace`, `\trace on`, `\trace off` | Toggle/set request trace; never bypasses redaction |
| Timing | `\timing` | Toggle terminal timing display; `\timing on` is not a distinct setting syntax |
| Format | `\format table`, `\format json` | Change result formatting |
| Parameters | `\params []` | Set typed positional parameters for the next statement, including protected standalone `SQL` |
| Role display | `\role` | Report connection role/enforcement; use SHOW CURRENT USER PRIVILEGES for effective catalog capabilities |

## Offline security utilities: all subcommands

These run in the shell, not at `chiron>`. Stop the server for exclusive directory access. Direct directory access is an operator trust boundary; these are not ordinary tenant requests. Run as the directory owner. For init/recovery outputs, use private directories and new files. `--help` exists for the parent and every subcommand, for example `chironctl security recover-admin --help`.

| Command | Example | Scope and prerequisites |
|---|---|---|
| `init` | `chironctl security init --data-dir "$CHIRON_HOME/data" --tenant default --admin admin --keyring-out "$CHIRON_HOME/secrets/storage-keyring.json" --admin-key-out "$CHIRON_HOME/secrets/admin.key"` | Empty directory only; initializes protected storage and issues the first key |
| `init --resume` | `chironctl security init --data-dir "$CHIRON_HOME/data" --tenant default --admin admin --keyring-out "$CHIRON_HOME/secrets/storage-keyring.json" --admin-key-out "$CHIRON_HOME/secrets/admin.key" --resume` | Only resume the same recorded incomplete operation and paths; not a way to initialize twice |
| `recover-admin` | `chironctl security recover-admin --data-dir "$CHIRON_HOME/data" --keyring "$CHIRON_HOME/secrets/storage-keyring.json" --admin-key-out "$CHIRON_HOME/secrets/recovered-admin.key"` | Confirm interactively. Retires old administrator and revokes its credentials; preserves other users and old ownership |
| `recover-admin --yes` | `chironctl security recover-admin --data-dir "$CHIRON_HOME/data" --keyring "$CHIRON_HOME/secrets/storage-keyring.json" --admin-key-out "$CHIRON_HOME/secrets/recovered-admin.key" --yes` | Explicit noninteractive recovery, same prerequisites |
| `recover-admin --resume` | `chironctl security recover-admin --data-dir "$CHIRON_HOME/data" --keyring "$CHIRON_HOME/secrets/storage-keyring.json" --admin-key-out "$CHIRON_HOME/secrets/recovered-admin.key" --resume --yes` | Same recorded incomplete recovery; never silently creates another administrator |
| `inspect` | `chironctl security inspect --data-dir "$CHIRON_HOME/data"` | Offline layout/encryption inspection; for encrypted audit use verify-audit with the keyring rather than interpreting a keyless diagnostic as proof |
| `verify-encryption` | `chironctl security verify-encryption --data-dir "$CHIRON_HOME/data" --keyring "$CHIRON_HOME/secrets/storage-keyring.json"` | Verify encrypted files and audit using the real keyring |
| `verify-audit` | `chironctl security verify-audit --data-dir "$CHIRON_HOME/data" --keyring "$CHIRON_HOME/secrets/storage-keyring.json"` | Verify the hash chain; keyring is optional only for unencrypted compatible data |
| `migrate-authority` | `chironctl security migrate-authority --data-dir "$CHIRON_HOME/data" --keyring "$CHIRON_HOME/secrets/storage-keyring.json"` | Compatibility utility for old identity authority v1→v2; does not migrate content or convert an existing database into the v3 installation flow |
| `migrate-sql-guard` | `chironctl security migrate-sql-guard --data-dir "$CHIRON_HOME/data" --keyring "$CHIRON_HOME/secrets/storage-keyring.json"` | Offline, idempotent startup-marker upgrade for existing SQL preview installations; preserves authority revision, credentials, grants and content. New SQL credential issuance installs this reader guard automatically. |
| `migrate-table-authority` | `chironctl security migrate-table-authority --data-dir "$CHIRON_HOME/data" --keyring "$CHIRON_HOME/secrets/storage-keyring.json"` | Offline identity-v5/installation-format-4 upgrade and atomic SQL table incarnation backfill; enables `ON TABLE` role grants. Idempotent; stop the server and retain the keyring/verified backup first. |
| `migrate-sql-scopes` | `chironctl security migrate-sql-scopes --data-dir "$CHIRON_HOME/data" --keyring "$CHIRON_HOME/secrets/storage-keyring.json"` | Offline conversion of existing SQL name scopes into exact table roles; identity v6/reader format 5. Requires completed table-authority migration. Retires SQL name fallback and enables new-table creator rights. |
| `migrate-encryption` | `chironctl security migrate-encryption --data-dir "$CHIRON_HOME/data" --keyring "$CHIRON_HOME/secrets/storage-keyring.json"` | Existing legacy storage encryption utility, outside this protected onboarding/production migration acceptance |
| `rotate-key` | `chironctl security rotate-key --data-dir "$CHIRON_HOME/data" --keyring "$CHIRON_HOME/secrets/rotation-keyring.json"` | Storage encryption rewrapping, not API-key rotation. Requires a separately prepared keyring containing needed old keys and its intended new active key; the example does not generate that file |
| `backup` | `chironctl security backup --data-dir "$CHIRON_HOME/data" --destination "$CHIRON_HOME/backup" --keyring "$CHIRON_HOME/secrets/storage-keyring.json"` | Fenced encrypted content backup into a new destination; server stopped, generation storage and complete journals required. Rejects backups that would omit external cold-object files. |
| `journal-archive` | `chironctl security journal-archive --data-dir "$CHIRON_HOME/data" --destination "$CHIRON_HOME/journal-archive" --keyring "$CHIRON_HOME/secrets/storage-keyring.json"` | Export encrypted journal, identity and audit without another content copy; retain the matching content backup and keys separately. |
| `verify-backup` | `chironctl security verify-backup --backup "$CHIRON_HOME/backup" --keyring "$CHIRON_HOME/secrets/storage-keyring.json"` | Authenticate the fenced content artifact and inventory; verification does not start a server. |
| `verify-journal-archive` | `chironctl security verify-journal-archive --archive "$CHIRON_HOME/journal-archive" --keyring "$CHIRON_HOME/secrets/storage-keyring.json"` | Authenticate the journal/authority archive and its inventory. |
| `restore-backup` | `chironctl security restore-backup --backup "$CHIRON_HOME/backup" --authority-source "$CHIRON_HOME/journal-archive" --destination "$CHIRON_HOME/restored-data" --keyring "$CHIRON_HOME/secrets/storage-keyring.json"` | Restore into a new destination using a separately trusted latest authority from the same installation. The content backup alone cannot establish current credentials/revocations. |
| `migrate-transaction-authority` | `chironctl security migrate-transaction-authority --data-dir "$CHIRON_HOME/data" --keyring "$CHIRON_HOME/secrets/storage-keyring.json"` | Offline migration of durable transaction decisions, consumed keys and retained receipts. Keep recoverable backups and full journals. |
| `migrate-common-frontier` | `chironctl security migrate-common-frontier --data-dir "$CHIRON_HOME/data" --keyring "$CHIRON_HOME/secrets/storage-keyring.json"` | Activate coordinated SQL/vector/graph recovery offline; this does not qualify production journal pruning. |
| `migrate-relational-indexes` | `chironctl security migrate-relational-indexes --data-dir "$CHIRON_HOME/data" --keyring "$CHIRON_HOME/secrets/storage-keyring.json"` | Offline backfill of protected RECORD_REF indexes; retain the verified backup and keyring. |
| `help` | `chironctl security help recover-admin` | Show syntax without running recovery |

Recovery retires both bearer and SQL credentials of the replaced administrator and preserves the installation reader guard. Recovery does not recover a missing encryption key, repair corrupt authority/audit, restore old ACLs, transfer object ownership, or migrate existing content. Restart using the same current storage keyring and new administrator credential. Successful completion followed by a lost terminal response is different from an incomplete journal: inspect the already-created delivery file before attempting any resume. Do not delete markers or disable enforcement to work around admission failures. The [systemd/Compose runbook](../deploy/protected/README.md) contains stop/start, ownership, mounts, secure key transfer, and recovery steps.

## Troubleshooting and limits

| Symptom | Meaning | Action/example |
|---|---|---|
| `cannot read CA certificate` | Missing/unreadable path, often a copied placeholder | Use `--ca-cert "$CHIRON_HOME/tls/ca.pem"` after creating or installing the matching certificate |
| Certificate hostname/issuer error | Wrong hostname, CA, expired certificate or mismatched server | Use the hostname in SAN and its real CA; do not disable verification |
| `cannot read private API key file` | Missing file, wrong owner/mode, symlink or invalid private-file conditions | Use the issued file, owned by your account and mode 0600 in a private directory |
| `chironql.connection_failed` | No server or wrong address/port | Start the matching protected server; initialization alone does not start it |
| Statement says session is `read_write` | A legacy session/build/config is being used | Use the matching protected build and its catalog API key; `--console-role admin` is not elevation |
| `security.unauthenticated` | Invalid/revoked credential or suspended/retired principal | Use an active credential or authorized offline recovery |
| `security.forbidden` | Missing action/scope/authority | Inspect current privileges and grant an allowed role as a security administrator |
| Empty GET/SCROLL or lower COUNT | Object is absent or outside the authorized domain | Inspect policy/department/clearance/deny through the authorized management path |
| `security.conflict` | Stale revision, duplicate name, or conflicting idempotent input | Inspect current state; do not blindly retry |
| `chironql.key_output_required` | CLI issuance/rotation has no private destination | Add `--key-out` pointing to a new filename |
| `chironql.confirmation_required` | Destructive operation needs confirmation | Confirm interactively or pass `--yes`; this does not add authority |
| `chironql.protected_unsupported` | The grammar exists but this protected operation is not implemented | Use the supported protected subset; do not fall back to legacy credentials |
| `security.budget_exceeded` / `security.unavailable` | Evaluation budget exhausted or authority/storage cannot complete safely | No partial authorized success is returned; inspect operator evidence and resolve the cause |
| Unexpected character at `_`/flags/URL | Markdown escaping was pasted into a terminal | Type `finance_reader`, not `finance\_reader`; use plain URLs and `--flag`, not Markdown link syntax or `\--flag` |

Policy resource inheritance is bounded to 16 levels; group nesting to 8, group expansion to 4096 entities; cycles/cross-domain references fail closed. Security point batches are capped at 1024; protected scroll pages at 1024. Server budgets and response limits remain authoritative. Missing policy, exhausted budgets and unsupported operations never imply permission.

Acknowledged revoke prevents new commit/publication under the old context. Bytes already released to the transport cannot be recalled. User/root/process memory and the ingestion/security authorities are trusted boundaries; authorized recipients can copy data they already received. Shared engine resources do not promise constant-time behavior. Passing examples establish those tested behaviors, not complete production security or absence of vulnerabilities.

## Reproduce this reference

The validator refuses an existing output directory, uses separate ports and stops its disposable server. It does not modify an already-running installation or use demonstration credentials as deployment credentials.

```sh
python3 -m venv "$HOME/chironql-doc-test-env"
"$HOME/chironql-doc-test-env/bin/pip" install -r chirondb-server/tests/security_chironql_requirements.txt
"$HOME/chironql-doc-test-env/bin/python" chirondb-server/tests/security_documentation_examples.py --check-only
"$HOME/chironql-doc-test-env/bin/python" chirondb-server/tests/security_documentation_examples.py \
  --bin-dir target/debug --output "$HOME/chironql-doc-proof" --port 19651
```

Coverage checks compare the documented SQL blocks with the corpus and the source's complete base/security statement and action enums. All SQL examples are parsed at both authenticated HTTP prefixes; expected parser errors remain errors. Protected executable examples additionally run through real CLI commands with server-issued IDs, private credential delivery, ACL outcomes, revocation, audit and encrypted-tree verification. Legacy/group/action-vocabulary-only examples are explicitly not counted as successful protected execution. Adjacent lab files contain actual temporary secrets; share only the sanitized reports.
