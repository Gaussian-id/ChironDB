# Getting started with ChironDB

Run ChironDB locally, write your first points, and try dense and hybrid search.
This guide follows the `0.1.0-beta.1` source tree and uses a small collection of
demonstration vectors. Generate real embeddings in your application before
sending them to ChironDB.

[README](../README.md) · [HTTP reference](HTTP_API.md) ·
[ChironQL reference](CHIRONQL.md) · [SDKs](SDKS.md) ·
[MCP clients](SDKS.md#mcp-clients)

## 1. Build and start

You need Git, a C/C++ build toolchain, [rustup](https://rustup.rs), and the
Protocol Buffers compiler, `protoc`. The pinned Rust version is `1.92.0`.
On macOS, install the command-line developer tools and `brew install protobuf`.
On Debian/Ubuntu, install `build-essential` and `protobuf-compiler`. The requests
also need `curl`.
If you already have a checkout, skip `git clone` and `cd`.

```bash
git clone https://github.com/Gaussian-id/ChironDB.git
cd ChironDB
cargo build --release --locked -p chirondb \
  --bin chirondb --bin chironql --bin chironmcp --bin chironctl
export PATH="$PWD/target/release:$PATH"
```

The `PATH` setting makes the bare tool names in the reference guides work.
Repeat it from the repository root in each new terminal, or use the
[one-time setup below](#make-the-commands-available-in-new-terminals).
`cargo build` creates executables in `target/release`; it does not install
`chirondb` as a shell command. `command not found: chirondb` means the shell
cannot find that executable. From the repository root, the full command
`./target/release/chirondb --console` works without changing `PATH`.

Check the selected HTTP address before starting another process:

```bash
curl --fail --connect-timeout 2 http://127.0.0.1:7401/health
```

If the response has `status: ok`, the server is running: continue at step 2
or attach the terminal client in step 5. A refused connection means no HTTP
listener is available there. Start one in the first terminal:

```bash
./target/release/chirondb --data-dir ./data
```

Leave that terminal running. In a second terminal, wait up to 30 seconds for
readiness:

```bash
curl --fail --retry 15 --retry-connrefused --retry-delay 1 --retry-max-time 30 \
  --max-time 2 http://127.0.0.1:7401/health
```

Expected response:

```json
{"status":"ok","version":"0.1.0-beta.1"}
```

By default, HTTP uses port `7401`, gRPC uses `7402`, and ChironWire plus the
PostgreSQL-compatible subset use `7403`. Local listeners bind to loopback.

If another instance already uses these ports, connect to it or start a separate
instance with its own data directory and all three addresses changed:

```bash
./target/release/chirondb --data-dir ./data-example \
  --listen-http 127.0.0.1:7501 \
  --listen-grpc 127.0.0.1:7502 \
  --listen-wire 127.0.0.1:7503
```

Use `7501` in the HTTP requests below for that instance.

### Make the commands available in new terminals

After building, run this once from the repository root on macOS or Linux:

```bash
mkdir -p "$HOME/.local/bin"
ln -s "$PWD/target/release/chirondb" "$HOME/.local/bin/chirondb"
ln -s "$PWD/target/release/chironql" "$HOME/.local/bin/chironql"
ln -s "$PWD/target/release/chironmcp" "$HOME/.local/bin/chironmcp"
ln -s "$PWD/target/release/chironctl" "$HOME/.local/bin/chironctl"
export PATH="$HOME/.local/bin:$PATH"
chirondb --version
```

These links use the binaries in this checkout, including subsequent rebuilds.
If a link already exists, inspect it before replacing it; `ln` deliberately
refuses to overwrite another installation. Moving the checkout requires
updating the links.

If your shell does not already include `$HOME/.local/bin` in `PATH`, add the
`export PATH="$HOME/.local/bin:$PATH"` line to `~/.zshrc` for zsh or `~/.bashrc`
for bash, then open a new terminal. In an already-open zsh terminal, `rehash`
refreshes command lookup. You can then run `chirondb --console` directly.

### Docker alternative

Use this instead of starting a source-built server. Docker must be installed
and its daemon running (`docker info` should succeed). Start from a repository
checkout and keep the host ports free. If the named container already exists,
use `docker start chirondb` instead of creating it again.

Build the current checkout locally. This path does not depend on a published
container image:

```bash
docker build --build-arg VCS_REF="$(git rev-parse HEAD)" -t chirondb:local .
docker volume create chirondb-data
docker run -d --name chirondb \
  -e CHIRONDB_ALLOW_INSECURE_NON_LOOPBACK=true \
  -p 127.0.0.1:7401:7401 \
  -p 127.0.0.1:7402:7402 \
  -p 127.0.0.1:7403:7403 \
  -v chirondb-data:/var/lib/chirondb \
  chirondb:local
```

The development escape hatch is needed because the container listens on its
internal network interface. Host ports are bound to loopback. Do not use this
profile for an externally reachable service. Wait for the health request above
to succeed; inspect startup with `docker logs chirondb` if needed.

The repository's [Compose file](../docker-compose.yml) instead pulls
`ghcr.io/gaussian-id/chirondb:0.1.0-beta.1`. Use it only when that image is
published and accessible to you. Available signed binaries will be listed on
the [Releases page](https://github.com/Gaussian-id/ChironDB/releases); a source
version number alone does not mean release artifacts have been published.

### Docker volume layout

The container stores the database in `/var/lib/chirondb/data`, inside the named
volume mounted at `/var/lib/chirondb`. The parent must also be writable: the
engine keeps its exclusive lock and restore staging directories beside the
database. Mount the parent volume, not just its `data` subdirectory.

Older containers may have stored `catalog.json`, `catalog_wal`, and
`collections` (or encrypted `CURRENT`/`generations`) directly at the volume
root. The new entrypoint refuses that
layout so an upgrade cannot silently open an empty database. Stop the old
server, keep a recoverable copy of its volume, and copy the **complete** old
database tree into a `data/` subdirectory of a new volume. Give UID/GID
`10001:10001` access to that volume and verify the collections after startup.
Keep the old volume until verification is complete. Persisted formats and
encryption keyrings are unchanged by this directory layout.

## 2. Create a collection

Run the rest of the guide against a fresh instance. If you already followed
the README console example, use a different collection name throughout or
skip creation and upsert the points below into `products`.

```bash
curl --fail -X POST http://127.0.0.1:7401/v1/collections \
  -H 'Content-Type: application/json' \
  -d '{"name":"products","vector_dim":3,"metric":"cosine","shards":1,"replicas":1}'
```

A collection groups points that share a vector dimension and distance metric.
Each point has a unique ID, a dense vector, and optional JSON payload, sparse
vector, or named vectors. Supported metrics are `cosine`, `l2`, and `dot`.
Dimensions and metric are fixed at collection creation; LS-VEC manages the
dense index automatically.

## 3. Insert points

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
        "sparse_vector":{"indices":[42],"values":[1.0]},
        "payload":{"category":"media","price":15}
      }
    ],
    "wait":true
  }'
```

Upserting an existing ID replaces that point. `wait:true` synchronizes the WAL
before acknowledgment. `wait:false` returns `202 Accepted` without waiting for
that synchronization; a crash can lose writes still waiting for a background
flush. See [durability semantics](HTTP_API.md#insert-or-update-points).

The sparse indices here are illustrative term IDs. Your application must use
the same encoder and vocabulary for stored points and queries; the database
does not turn this example's payload text into embeddings automatically.

## 4. Search and filter

Find the nearest electronics item:

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

`hits` contains `phone`, with its score and payload. The response also reports
`degraded`, `searched`, and `elapsed_ms`. Timing depends on your machine.
Every dense query vector must have the collection's configured dimension.

Combine semantic and sparse retrieval with reciprocal rank fusion:

```bash
curl --fail -X POST http://127.0.0.1:7401/v1/collections/products/hybrid_search \
  -H 'Content-Type: application/json' \
  -d '{
    "vector":[1.0,0.0,0.0],
    "sparse_vector":{"indices":[12,98],"values":[1.2,0.7]},
    "k":2,
    "fusion":"rrf"
  }'
```

This combines the dense and sparse rankings. Use the
[HTTP reference](HTTP_API.md) for weighted fusion, named vectors, multi-search,
filters, and request budgets. Recall targets guide search effort; they are not
a measurement of achieved recall on an individual query.

## 5. Use the terminal client

From the repository root in a second terminal:

```bash
./target/release/chironql --url http://127.0.0.1:7401
```

For the Docker alternative, the client is inside the container:

```bash
docker exec -it chirondb chironql
```

Run one statement at a time:

```sql
SHOW COLLECTIONS;
DESCRIBE products;
SEARCH products NEAR [1,0,0] WHERE category = 'electronics' LIMIT 5 WITH PAYLOAD;
HYBRID products NEAR [1,0,0] TEXT {12:1.2, 98:0.7} FUSION rrf LIMIT 2;
COUNT products;
SCROLL products LIMIT 10;
```

For a one-shot request:

```bash
./target/release/chironql --url http://127.0.0.1:7401 --exec 'COUNT products;'
```

For Docker, the equivalent one-shot command is
`docker exec chirondb chironql --exec 'COUNT products;'`.

`\h` lists commands, `\trace` shows execution details, and `\q` exits the
client while the server keeps running. By contrast, starting the server with
`--console` attaches the prompt to that server process: quitting it stops the
server too. Collection creation and deletion require a write-capable session;
see [collection rules](CHIRONQL.md#collections), including tenant restrictions.

## 6. Read, update, and delete

Fetch a point:

```bash
curl --fail -X POST http://127.0.0.1:7401/v1/collections/products/points/get \
  -H 'Content-Type: application/json' -d '{"ids":["phone"]}'
```

Merge payload fields without replacing the vector:

```bash
curl --fail -X POST http://127.0.0.1:7401/v1/collections/products/points/payload \
  -H 'Content-Type: application/json' \
  -d '{"id":"phone","payload":{"price":649},"merge":true}'
```

Page through points:

```bash
curl --fail -X POST http://127.0.0.1:7401/v1/collections/products/scroll \
  -H 'Content-Type: application/json' -d '{"limit":10}'
```

Pass the response's `next_offset` as the next request's `offset`. It is a
stable point-ID cursor, not a numeric page offset; `null` marks the last page.

To remove the example book, run this explicit deletion:

```bash
curl --fail -X POST http://127.0.0.1:7401/v1/collections/products/points/delete \
  -H 'Content-Type: application/json' -d '{"ids":["book"],"wait":true}'
```

## 7. Connect an application

The Python and Rust clients live in this repository. Follow
[SDK installation and examples](SDKS.md) for your language. There is no PyPI or
crates.io installation assumed by this guide.

AI hosts can instead use the three read-only MCP tools for collection discovery,
native text-hybrid search, and point/chunk retrieval. The basic unauthenticated
quickstart above leaves MCP disabled. Follow the [MCP client setup](SDKS.md#mcp-clients)
to configure the embedding endpoint, API keys, RBAC, tenant behavior, Streamable
HTTP endpoint, or the `chironmcp` stdio bridge.

After installing the Python client, search the collection you just created:

```python
from chirondb_client import ChironDbClient

db = ChironDbClient("http://127.0.0.1:7401")
result = db.search("products", vector=[1.0, 0.0, 0.0], k=2)
for hit in result["hits"]:
    print(hit["id"], hit["score"])
```

Use [gRPC](GRPC_API.md) for generated clients. The primary service is
`chirondb.v1.ChironDb`; legacy `gaussdb.v1.GaussDb` remains available for older
clients. New graph RPCs belong to the primary service.

## Property-graph retrieval

The beta graph overlay reuses collection points as vertices. Configure edge
types, connect points, and use bounded traversal or graph constraints on dense
and hybrid search. Follow the [graph HTTP examples](HTTP_API.md#property-graph-overlay)
and [ChironQL graph syntax](CHIRONQL.md#property-graph); lifecycle and edge-type
configuration must happen before graph statements can run.

Graph access has its own capabilities in addition to the ordinary point role
and collection allowlist. The overlay is single-node. Graph-aware multi-search,
distributed traversal, shortest-path algorithms, and graph statements over
PostgreSQL wire are outside the supported surface.

## PostgreSQL and pgvector boundary

Port `7403` accepts a deliberately small PostgreSQL wire compatibility surface:

| SQL shape | Behaviour |
| --- | --- |
| `CREATE EXTENSION vector` | Compatibility shim |
| `CREATE TABLE … vector(N)` | Creates a vector collection |
| `INSERT` | Writes vector points |
| `SELECT … ORDER BY <vector operator> LIMIT k` | Runs vector search |
| `DELETE` | Deletes matching points |
| `DROP TABLE` | Deletes the collection |

This is a vector-only subset, not general PostgreSQL compatibility. Joins,
CTEs, transactions, and `CREATE INDEX … USING hnsw` reject with SQLSTATE
`0A000`. Keep relational queries in PostgreSQL/pgvector. Graph statements use
ChironQL or native APIs, and ChironQL itself does not accept SQL `SELECT`.

## Authentication and network access

For a local instance, enable an API key by setting `CHIRONDB_API_KEY` before
starting the server. Generate it in your shell, then start the process:

```bash
export CHIRONDB_API_KEY="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
./target/release/chirondb --data-dir ./data
```

Stop any earlier instance before restarting with this configuration. In a
second terminal, set `CHIRONDB_API_KEY` to the same generated value; shell
exports do not propagate to terminals already open. `chironql` and `chironctl`
read it automatically. Supply it explicitly to HTTP requests:

```bash
curl --fail http://127.0.0.1:7401/v1/collections \
  -H "Authorization: Bearer $CHIRONDB_API_KEY"
```

`x-chirondb-api-key` is also supported; the legacy `x-gaussdb-api-key` header is
retained during beta. Remote instances require the complete security profile:
TLS, API credentials, RBAC with stable principal IDs, and an external encryption
keyring. Consult [SECURITY.md](../SECURITY.md), [HTTP authentication](HTTP_API.md#connect),
and [gRPC TLS](GRPC_API.md) before exposing a listener.

Tenant enforcement starts disabled. Existing points need an ownership migration
before enforcement is enabled. Follow [Tenant isolation](TENANT_ISOLATION.md).

## Stop, restart, and retain data

For a server started from source, use `Ctrl-C` and rerun the same start command
with the same data directory. For an attached console, `\q` stops the process.

For the Docker instance:

```bash
docker stop chirondb
docker start chirondb
```

The named volume retains the database. Removing a container does not remove
that volume. Do not delete the volume or data directory unless you intend to
remove the stored data. Snapshot, restore, and compaction commands live in
`chironctl`; inspect `./target/release/chironctl --help` and the
[HTTP administration reference](HTTP_API.md).

## Upgrading from GaussDB

Take a recoverable backup before reopening alpha data with ChironDB. Legacy plaintext WAL, segments, snapshots, and
metadata remain readable in local compatibility mode. ChironDB and the offline
migration tools acquire the same exclusive data-directory lock; never run two
processes against one directory.

Encrypted generation storage is an explicit offline migration. First pause
application writes and compact **every collection** while the plaintext server
is still running. Migration rejects nonempty active collection WAL files:

```bash
./target/release/chironctl list-collections
./target/release/chironctl compact products
```

Replace `products` with each collection name returned by the first command.
Keep writes paused until migration finishes. Stop the server cleanly after
all compactions succeed, and retain your recoverable backup. Prepare the
external keyring described in [encryption keyring setup](#encryption-keyring-setup)
and run these commands with the server stopped:

```bash
./target/release/chironctl security inspect --data-dir /path/to/gaussdb-data
./target/release/chironctl security migrate-encryption \
  --data-dir /path/to/gaussdb-data --keyring /run/secrets/chirondb/keyring.json
./target/release/chironctl security verify-encryption \
  --data-dir /path/to/gaussdb-data --keyring /run/secrets/chirondb/keyring.json
```

Keep the keyring outside the data directory. Secure mode refuses mixed plaintext
and encrypted data, and older binaries cannot open encrypted generations.
`CHIRONDB_*` variables override the matching `GAUSSDB_*` variables; compatibility
aliases are used only when the new name is absent.

## Encryption keyring setup

For the offline migration above, generate a keyring **outside** the database
directory. This example writes `./chiron-secrets/keyring.json` and refuses to
overwrite an existing keyring:

```bash
python3 - <<'PYKEY'
import base64, json, os, secrets
from pathlib import Path

folder = Path("chiron-secrets")
folder.mkdir(mode=0o700, exist_ok=True)
keyring = {
    "version": 1,
    "active_key_id": "key-1",
    "keys": [{"id": "key-1", "key_base64": base64.b64encode(secrets.token_bytes(32)).decode()}],
}
fd = os.open(folder / "keyring.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
with os.fdopen(fd, "w") as f:
    json.dump(keyring, f)
PYKEY
```

Replace `/run/secrets/chirondb/keyring.json` in the migration commands with
this file's absolute path, and `/path/to/gaussdb-data` with the database you
intend to migrate. These are templates, not literal paths to create. Back up
the keyring separately and keep it out of version control; losing it makes the
encrypted database unreadable. Once migrated, pass the same file on every start:

```bash
./target/release/chirondb --data-dir /path/to/gaussdb-data \
  --encryption-keyring-file /run/secrets/chirondb/keyring.json
```

Keyring setup alone does not configure a public listener. TLS certificates,
API credentials, and RBAC with stable principal IDs are also required.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `command not found: chirondb` | Run `./target/release/chirondb` from the checkout, set `PATH`, or complete command installation above. |
| Connection refused | Wait for startup, inspect the server log, and check the selected HTTP port. |
| Address already in use | Connect to the existing server or change all listener ports and the data directory. |
| Data directory locked | Stop its current owner; the retained lock file alone does not mean a process is running. |
| `401` or `403` | Supply the API key and verify its role, collection access, tenant, and graph capabilities. |
| Vector dimension error | Match the stored and query vector lengths to `vector_dim`. |
| Console does not appear | `--console` needs a terminal on stdin; use the separate `chironql` client for a daemon. |
| Non-loopback startup rejected | Configure the complete TLS/RBAC/keyring profile; the Docker escape hatch is for local development. |
| Container image not found | Build this checkout with the Docker alternative above. |
