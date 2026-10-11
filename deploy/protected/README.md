# Protected single-node deployment

This flow initializes an **empty** ChironDB installation with one tenant and bearer-key authentication; PostgreSQL clients can receive a separate SQL password afterward. The first administrator can provision protected collections and manage security; it has no document access until explicitly granted a data role. Use binaries or an image built from the security implementation being verified. The general development Compose file does not initialize this authority.

Existing database migration, multi-tenant activation, numeric sparse hybrid and distributed operation are outside this deployment flow. Offline protected backup, journal archive and restricted restore are described below; their production recovery and scale gates remain open. Never point an older binary at this data, including a generation subdirectory.

Protected BM25 and dense+BM25 text retrieval are available through the native
text endpoint and standalone ChironQL `HYBRID ... TEXT 'query' FIELD field`.
They require explicit content and field query grants; the administrator role
alone does not grant document access. See the [text contract](../../docs/HTTP_API.md#native-text-hybrid-search).
Production-scale retrieval qualification remains required.

## Native Linux with systemd

Build the reviewed source on the target platform, or transfer matching verified artifacts. Record SHA-256 checksums of all three binaries; a public beta tag alone does not identify an unmerged security build.

```sh
cargo build --release --locked -p chirondb --bin chirondb --bin chironql --bin chironctl
sha256sum target/release/chirondb target/release/chironql target/release/chironctl
sudo install -m 0755 target/release/chirondb target/release/chironql target/release/chironctl /usr/local/bin/
sudo useradd --system --home-dir /var/lib/chirondb --shell /usr/sbin/nologin chirondb
sudo install -d -o chirondb -g chirondb -m 0700 /var/lib/chirondb /etc/chirondb/secrets /secure/chirondb-bootstrap
sudo install -d -o root -g chirondb -m 0750 /etc/chirondb/tls
```

Provide a CA certificate, a server certificate and its private key. The server certificate's SAN must cover `db.example.com` for the client and `localhost` if using the local health command below. Install the key as `chirondb:chirondb`, mode `0600`; CA/certificate files may be `0644`. Do not place the storage keyring inside the data directory.

Run initialization while the service is stopped. The output directory must be on persistent storage, owned by the initializing account, mode `0700`. The command creates output files exclusively, mode `0600`, and prints only installation metadata.

```sh
sudo -u chirondb chironctl security init \
  --data-dir /var/lib/chirondb/data --tenant default --admin admin \
  --keyring-out /etc/chirondb/secrets/storage-keyring.json \
  --admin-key-out /secure/chirondb-bootstrap/admin.key
sudo install -m 0644 deploy/protected/chirondb.toml /etc/chirondb/chirondb.toml
sudo install -m 0644 deploy/protected/chirondb.service /etc/systemd/system/chirondb.service
sudo systemctl daemon-reload
sudo systemctl enable --now chirondb
sudo systemctl status chirondb
chironctl --endpoint https://localhost:7401 --ca-cert /etc/chirondb/tls/ca.pem health
```

Adapt the bind addresses and firewall to your network. Protected startup requires TLS on every enabled transport, enforced tenant isolation, external encryption keys and complete authority/audit state. Do not configure a legacy API key, RBAC file, cluster/Raft or insecure bypass flags alongside the initialized authority.

Transfer `admin.key` through a secure channel to the operator's private credential directory. Verify the transferred file without displaying its contents, then remove the bootstrap copy from the server or move it into storage inaccessible to the service account. Retain the storage keyring securely and back it up separately: admin-key recovery cannot recover a lost encryption key.

## Docker Compose

Build and identify the image:

```sh
docker build -t chirondb-protected:reviewed .
export CHIRONDB_IMAGE="$(docker image inspect chirondb-protected:reviewed --format '{{.Id}}')"
export CHIRONDB_TLS_DIR=/absolute/path/to/tls
# Directory contains server.pem, server.key, ca.pem.
# On native Linux, server.key must be readable by UID 10001, mode 0600.
# The directory needs traversal permission for UID 10001.
docker compose -f deploy/protected/compose.yml -p chirondb config --quiet
docker compose -f deploy/protected/compose.yml -p chirondb run --rm init
docker compose -f deploy/protected/compose.yml -p chirondb up -d server
docker compose -f deploy/protected/compose.yml -p chirondb ps
```

The image initializes ownership for its fresh named volumes. The data, storage keyring and administrator delivery volumes are separate. The normal server mounts no administrator delivery volume. It runs as UID/GID `10001`, with a read-only container filesystem, dropped capabilities, and a TLS-verified health check requiring no administrator key. Server startup never initializes a database or resets credentials.

Copy the first administrator key to a private operator directory using a short-lived delivery container. No secret is printed:

```sh
install -d -m 0700 "$HOME/.config/chirondb"
docker compose -f deploy/protected/compose.yml -p chirondb run -d \
  --name chirondb-key-delivery --entrypoint sleep init 300
docker cp chirondb-key-delivery:/run/chirondb-bootstrap/admin.key "$HOME/.config/chirondb/admin.key"
chmod 0600 "$HOME/.config/chirondb/admin.key"
docker rm -f chirondb-key-delivery
```

The delivery volume retains the original key until the operator removes it after verified transfer. Keep the volume offline from the running server. Never publish it, commit it or include it in support evidence. A repeated `init` fails instead of replacing an existing authority.

Default published addresses are loopback. Set `CHIRONDB_BIND_IP` deliberately for remote access; optional `CHIRONDB_HTTP_PORT`, `CHIRONDB_GRPC_PORT` and `CHIRONDB_WIRE_PORT` select host ports. `CHIRONDB_TENANT` and `CHIRONDB_ADMIN` apply only to explicit initialization. Changing them never renames an initialized tenant or administrator.

## Connect and provision through ChironQL

For every user/role/key/data statement with examples, revision meanings, a concrete
local CA recipe, and executable API samples, see the
[complete ChironQL security reference](../../docs/CHIRONQL_SECURITY.md).

There is no password or `LOGIN admin` statement. The API key selects your identity. `--console-role admin` does not elevate a protected session.

```sh
chironql --url https://db.example.com:7401 \
  --ca-cert /path/to/ca.pem --api-key-file "$HOME/.config/chirondb/admin.key"
```

Interactive startup authenticates before showing `chiron>`. Its banner shows the server-verified principal and security-administration capability. `SHOW CURRENT USER PRIVILEGES;` lists effective capabilities. The attached server console accepts an explicit `--console-api-key-file`; keep the normal service unattended.

ChironQL 1.3 adds protected provisioning:

```sql
SHOW CURRENT USER;
SHOW CATALOG REVISION;
CREATE PROTECTED COLLECTION docs DIM 2 METRIC cosine;
SHOW COLLECTION docs SECURITY POLICY;
ALTER COLLECTION docs SET SECURITY POLICY {
  department_actions: ['read', 'search'],
  owner_actions: ['read', 'search', 'update', 'delete'],
  templates: {
    finance: {
      department: 'Finance', classification: 'internal',
      properties: {'/text': {classification: 'internal', actions: ['read', 'query', 'write']}},
      representations: {dense: {source_fields: ['/text'], classification: 'internal'}}
    },
    hr: {
      department: 'HR', classification: 'internal',
      properties: {'/text': {classification: 'internal', actions: ['read', 'query', 'write']}},
      representations: {dense: {source_fields: ['/text'], classification: 'internal'}}
    }
  }
};
CREATE ROLE finance_reader;
GRANT READ, SEARCH ON COLLECTION docs TO ROLE finance_reader;
CREATE USER ana SET DEPARTMENT Finance SET CLEARANCE CONFIDENTIAL;
GRANT ROLE finance_reader TO USER ana;
SHOW ROLE finance_reader PRIVILEGES;
```

Protected collection names are limited to 128 characters. The collection is protected from its first visible state. Before a valid ingest template is configured, creation of points is denied. Policy objects use ChironQL single-quoted strings, not double-quoted JSON. Choose the vector dimension for the actual embedding model; this small example uses dimension 2.

Issue a user key into a new private file. Each issuance needs its own unused output path:

```sh
chironql --url https://db.example.com:7401 --ca-cert /path/to/ca.pem \
  --api-key-file "$HOME/.config/chirondb/admin.key" \
  --key-out "$HOME/.config/chirondb/ana.key" \
  --exec 'ISSUE API KEY FOR USER ana;'
```

Configure a writer through the same administrator session:

```sql
CREATE ROLE ingestion;
GRANT READ, SEARCH, CREATE, INGEST, UPDATE, DELETE ON COLLECTION docs TO ROLE ingestion;
CREATE USER writer SET DEPARTMENT Ingestion SET CLEARANCE RESTRICTED;
GRANT ROLE ingestion TO USER writer;
```

Issue its key with `--key-out`, then reconnect as that writer:

```sql
CREATE POINTS INTO docs USING TEMPLATE finance
  {vector:[1,0],payload:{text:'Synthetic Finance document'}} REQUEST 'finance-ingest-001';
```

The result contains a server-generated ID. A retry with the same request ID and content returns the authorized existing result; a different body conflicts. Reconnect using `ana.key` to run `COUNT docs;`, `SCROLL docs LIMIT 10;` or `SEARCH docs NEAR [1,0] LIMIT 10;`. Ana can read the Finance document but cannot mutate it. An HR reader requires a separate HR user and a data role; roles confer operations, while department, clearance, ownership and ACL govern objects. An operations role may receive `OBSERVE ON SYSTEM` without data or security-management access. `IdentityManage` cannot be delegated through ordinary roles.

For automation, use `--exec` or pipe a script into `chironql`. A script stops at its first failure; it is not one transaction. Exit codes: `0` success, `1` query/security error, `2` connection error. Issuance/rotation checks `--key-out` before making the request. Secrets never appear in the result table or history.

The CLI fetches an expected revision before each security mutation. For explicit concurrency control:

```sql
CREATE PROTECTED COLLECTION another DIM 2 IF REVISION 2;
ALTER COLLECTION docs SET SECURITY POLICY {department_actions:[],owner_actions:[],templates:{}} IF REVISION 2;
```

The create revision belongs to the catalog; policy revisions belong to the collection. Inspect the current revision instead of guessing these illustrative numbers. Conflicts are not automatically retried. After a lost creation response, inspect the collection before attempting another creation.

## HTTP, gRPC and ChironWire

The same statements execute at `/chironql` and `/v1/chironql`, primary gRPC `ExecuteQuery`, and the ChironWire ChironQL operation. Send an API key over verified TLS. Raw transports supply `IF REVISION` for mutations; the ChironQL terminal performs the lookup for you. Legacy collection-creation RPCs remain denied on initialized installations.

See [HTTP API](../../docs/HTTP_API.md#protected-chironql-administration-language-12) for authenticated requests, credential delivery and error envelopes, and [gRPC API](../../docs/GRPC_API.md) for `ExecuteQuery`. Unsupported protected operations return an explicit error; legacy roles never bypass the protected executor.

## PostgreSQL wire SQL password

PostgreSQL clients use a separate, server-generated SQL password. An identity
manager posts `{ "principal": "<durable-principal-id>",
"expected_revision": <current-identity-revision> }` to
`POST /v1/security/sql-credentials` over verified HTTPS, using its bearer key.
The response `{id,username,password,revision}` is delivered once; store it in
private client credential storage, not a shell history or log. Reissuance
atomically revokes the previous SQL password for that user. The existing
`POST /v1/security/credentials/{id}/revoke` route also revokes SQL credentials.
Bearer keys remain valid for vector, graph, HTTP, gRPC and ChironWire, but do
not authenticate PostgreSQL wire.

Set the PostgreSQL driver's TLS verification mode to require the deployment CA
and server hostname (for libpq, `sslmode=verify-full` with `sslrootcert`).
Protected pgwire requires `SSLRequest`, verified TLS and `SCRAM-SHA-256`.
Plaintext startup and `SCRAM-SHA-256-PLUS` are not supported. Relational
simple/extended queries use exact table grants; the supported pgvector
compatibility statements are simple-query only. Vector INSERT also requires
the administrator to configure an explicit `pgvector` ingest template on that
collection. This authentication milestone does not remove the other
single-node production blockers or enable more than one protected tenant per
installation.

## Restart, rotation and offline recovery

### Backfill protected SQL point-reference indexes

Installations that created protected tables with `RECORD_REF` columns before
checkpoint v4 keep the safe row-scan retirement guard. To backfill their disk
indexes, stop the server, retain a verified protected backup and external
keyring, then run the reviewed `chironctl` binary against the inactive data
directory:

```sh
sudo systemctl stop chirondb
sudo -u chirondb chironctl security migrate-relational-indexes \
  --data-dir /var/lib/chirondb/data \
  --keyring /etc/chirondb/secrets/storage-keyring.json
```

The JSON result reports `migrated_tables`. A second run returns zero. The
command requires exclusive ownership of the installation; it rejects an
active server. If interrupted, restart the same command with the same reviewed
binary and keyring. The relational checkpoint manifest selects either the
complete old or complete new row/index generation, and startup removes
unreferenced runs left by an interrupted attempt. Check the result and reopen
the server before admitting clients. This command only backfills protected
reference indexes; it does not perform the broader production format upgrade
or replace the required migration and recovery rehearsal.

### Offline protected backup and restricted restore

Stop the server before exporting. The commands acquire an exclusive installation lease and refuse
an active server. Keep the encrypted artifacts and the external keyring in separate protected
storage. Each export destination must be new and must not overlap the data directory. Record the
JSON manifests and independently verify the artifacts after transfer.

```sh
sudo systemctl stop chirondb
sudo -u chirondb chironctl security backup \
  --data-dir /var/lib/chirondb/data \
  --destination /secure/chirondb-backups/full-001 \
  --keyring /etc/chirondb/secrets/storage-keyring.json
sudo -u chirondb chironctl security verify-backup \
  --backup /secure/chirondb-backups/full-001 \
  --keyring /etc/chirondb/secrets/storage-keyring.json
sudo -u chirondb chironctl security journal-archive \
  --data-dir /var/lib/chirondb/data \
  --destination /secure/chirondb-backups/journal-002 \
  --keyring /etc/chirondb/secrets/storage-keyring.json
sudo -u chirondb chironctl security verify-journal-archive \
  --archive /secure/chirondb-backups/journal-002 \
  --keyring /etc/chirondb/secrets/storage-keyring.json
```

The journal archive contains the complete encrypted transaction journal, current identity and
audit history, but no content generation. It is not an incremental archive. A backup artifact is
fenced against direct server startup; use `restore-backup` to stage and validate it. On a recovery
host, transfer the matching keyring separately, verify both artifacts, establish which authority
archive is the latest trusted one, and restore into a new empty directory:

```sh
chironctl security restore-backup \
  --backup /secure/chirondb-backups/full-001 \
  --authority-source /secure/chirondb-backups/journal-002 \
  --destination /var/lib/chirondb/restored-001 \
  --keyring /etc/chirondb/secrets/storage-keyring.json
```

The service account must be able to write the **parent** of the restored
data directory. The exclusive lease lives beside that directory, for example
`/var/lib/chirondb/.restored-001.chirondb.lock`. In a container, mount the
restored data beneath a writable service-owned parent such as
`/var/lib/chirondb/data`; a private directory mounted directly at `/data`
fails if `/` is not writable. Mount the external keyring and TLS files
separately from the data directory. The image healthcheck probes loopback
HTTP, then loopback HTTPS for a TLS listener; the latter accepts the local
server certificate without requiring its CA in the image. The protected
Compose file uses its mounted CA for a certificate-verified HTTPS probe.
After a large restore, also run a representative authenticated SQL and
retrieval query, verify the expected transaction receipt, and only then
route production traffic. `/health` can succeed before those queries fit
their normal client timeouts while indexes warm.

The restore receipt reports the backup and active identity revisions and completed commit
frontiers. An older or divergent journal, a different installation, or a destination that already
exists is refused. Committed collection creation, deletion, and recreation after the full backup
are replayed from the archive, including later protected collection mutations. The tool cannot
establish that the supplied authority is newest: a stale archive can revive a later-revoked grant.
Confirm the archive's provenance and frontier against an independently kept
record before activating the restored directory. Validate access revocation, SQL/vector/graph
records and retry receipts on the recovered installation before changing the service data path.
In a local 4 vCPU/8 GiB W0 rehearsal with 521,000 SQL rows, 100,000
768D vectors and 400,000 graph edges, full backup took 37.6 minutes,
archive 6.1 minutes, and restore 6.9 minutes. A fresh container serving
only the restored data, keyring and TLS files proved the later revocation,
same idempotency decision and vector count about 23 minutes 50 seconds
after restore began, including a corrected mount attempt. This is below
the provisional one-hour W0 RTO. The archive retained every acknowledged
commit through its frontier; a scheduled 15-minute archive cadence,
separate-host recovery and physical-fault gates remain open. Keep enough
free space for a full backup copy and a restore staging copy plus journal
replay while rehearsing on this workload.

Normal restart preserves authority, revocations and content:

```sh
sudo systemctl restart chirondb
# or:
docker compose -f deploy/protected/compose.yml -p chirondb restart server
```

The service managers use a 15-second stop allowance; ChironDB's internal
deadline is fixed at 12 seconds. On the first `SIGTERM` or `SIGINT`, readiness
changes to unavailable, new HTTP/gRPC/ChironWire/PostgreSQL work is rejected,
listeners stop accepting, and active requests receive a five-second drain
window. Remaining work is cancelled before WAL, audit, and derived projections
are finalized. A second signal skips the request drain and forces a
recovery-safe exit.

Clean shutdown exits `0`. Deadline or final-sync fallback exits `2` before the
service manager can produce exit 137. Treat exit `2` as an incident: keep the
data directory and external keyring unchanged, inspect the sanitized final
log, restart once, verify readiness and transaction reconciliation, and run a
restore rehearsal if recovery reports corruption or an incomplete projection.
Never replay a mutation with an unknown outcome without its durable retry
identity.

For macOS, copy `com.chirondb.server.plist` to
`~/Library/LaunchAgents/`, adjust the binary/config/log paths, validate it with
`plutil -lint`, and load it with `launchctl bootstrap gui/$(id -u)`. The plist
sets `ExitTimeOut=15`; certificate and credential files still need the same
ownership and external-keyring separation described above.

Shutdown telemetry is intentionally tenant-neutral:
`chirondb_shutdown_phase`, `chirondb_shutdown_inflight_requests`,
`chirondb_shutdown_duration_seconds`, `chirondb_shutdown_total`,
`chirondb_audit_worker_wake_total`, `chirondb_audit_worker_flush_total`,
`chirondb_wal_flush_worker_wake_total`, and
`chirondb_wal_flush_worker_flush_total`.

For routine rotation, inspect `SHOW API KEYS FOR USER admin;`, then execute `ROTATE API KEY '<credential-id>';` with a fresh `--key-out`. Reconnect using the replacement file. Credential IDs are not secrets; `SHOW` never returns keys or hashes.

If the administrator key is lost, revoked, or the administrator is suspended, stop the server and recover offline with its current storage keyring:

```sh
sudo systemctl stop chirondb
sudo -u chirondb chironctl security recover-admin \
  --data-dir /var/lib/chirondb/data \
  --keyring /etc/chirondb/secrets/storage-keyring.json \
  --admin-key-out /secure/chirondb-bootstrap/recovered-admin.key
# Interactively confirm, or add --yes in controlled automation.
sudo systemctl start chirondb
```

Compose equivalent:

```sh
docker compose -f deploy/protected/compose.yml -p chirondb stop server
docker compose -f deploy/protected/compose.yml -p chirondb run --rm init \
  security recover-admin --data-dir /var/lib/chirondb/data \
  --keyring /etc/chirondb/secrets/storage-keyring.json \
  --admin-key-out /run/chirondb-bootstrap/recovered-admin.key --yes
docker compose -f deploy/protected/compose.yml -p chirondb up -d server
```

Transfer the replacement key through the same private delivery procedure. Recovery creates a new immutable administrator, retires the old one, and revokes its credentials. Other users and grants survive. Ownership remains attached to the old immutable ID; recovery does not transfer content, old role memberships or historical data permissions to the new administrator.

Interrupted initialization or recovery leaves admission closed. Resume the exact recorded operation using the same paths and arguments plus `--resume` (`recover-admin` still requires confirmation or `--yes`). The journal preserves one administrator and one credential delivery; unrelated files are never overwritten. If the process stopped after durable completion but before printing its result, the existing key file is already valid; repeated initialization is rejected. A failure before a recoverable journal exists, mismatched resume arguments, corruption or missing encryption material remains closed for operator investigation. Do not delete metadata or disable enforcement to open the installation.

## Reproduce the installation evidence

Use an empty output path and the pinned Python dependencies:

```sh
python3 -m venv /private/test-env
/private/test-env/bin/pip install -r chirondb-server/tests/security_chironql_requirements.txt
/private/test-env/bin/python chirondb-server/tests/security_installation_e2e.py \
  --bin-dir target/debug --output /private/fresh-installation-proof
cargo build -p chirondb --bin chirondb --bin chironql --bin chironctl --features fault-injection --locked
/private/test-env/bin/python chirondb-server/tests/security_installation_faults.py \
  --bin-dir target/debug --output /private/installation-fault-proof
```

Fault-injection binaries are test artifacts. Build normal binaries again before deployment. `security_installation_deployments.py` reuses the independent access matrix for Compose and a Linux systemd test environment. Evidence reports contain sanitized commands, outcomes and artifact hashes; their adjacent directories contain real test secrets and must not be published wholesale.

## Common recovery frontier review format

Common-frontier format 1 is an opt-in review candidate. It publishes one encrypted,
versioned manifest for SQL, catalog, vector and graph content plus installation,
transaction, security, audit and graph allocation bindings. Mutations and retry
semantics use the existing transaction journal. This does not certify production
recovery time, disk usage or disaster recovery.

Stop every process using the installation, retain an offline backup and its trusted
current authority, and migrate transaction authority before activation:

```bash
chironctl security migrate-transaction-authority \
  --data-dir /var/lib/chirondb/data --keyring /etc/chirondb/secrets/storage.json
chironctl security migrate-common-frontier \
  --data-dir /var/lib/chirondb/data --keyring /etc/chirondb/secrets/storage.json
```

Activation raises the installation reader fence to `CHRNINSTALL7`. Use a binary
supporting this format thereafter; older readers refuse it. Do not lower the marker
or replace current authority with control state from an older backup. The command
requires the exclusive offline lease and returns whether activation was new.

Startup validates the selected snapshot, installation, generation lineage,
collection incarnations, current authority, original journal/audit prefixes and
graph allocator before rebuilding a private content root from the immutable base
and committed suffix. Only a synchronized, validated root becomes current.
Missing, corrupted or foreign authoritative state refuses startup. Current
revocations, consumed keys, retained retry receipts and allocator authority stay
with the installation. Completed roots, journals and audit logs are retained;
only unpublished frontier staging directories are cleaned after validation.

Scheduled maintenance and shutdown attempt a coordinated checkpoint within their
existing deadlines. Busy storage, active interactive transactions, cancellation or
resource refusal leaves the prior frontier selected. Publication copies and hashes
the materialized base; startup currently reconstructs a complete private content
root. Neither operation is constant-time. Measure space and outage duration before
considering production adoption. Kernel I/O can exceed a userspace deadline.

A changed active key is supported while all previously referenced keys remain in
the keyring. Missing required keys refuse startup. **Envelope rewrapping is refused
before writes on format 7** until coordinated proof refresh is qualified. Keep the
existing keyring and encrypted bytes. Exported frontier-enabled journal archives
also carry graph allocation authority, and protected restore preserves activation
only after reconciling content with trusted current authority.

To exercise the supported protected driver fixture with this format:

```bash
python chirondb-server/tests/protected_orm_compat.py \
  --server target/release/chirondb --ctl target/release/chironctl \
  --rust-fixture chirondb-server/tests/postgres_rust_compat/target/debug/chirondb-postgres-rust-compat \
  --output /private/tmp/chirondb-frontier-drivers-new --common-frontier
```

The output directory must be new and private. Share only its redacted logs and
report; keep keys, credentials and persisted fixture data private.
