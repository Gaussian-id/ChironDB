# Row-level tenant isolation

ChironDB can restrict every point to the tenant that owns it, so one deployment
can serve several customers without an application layer being the only thing
standing between them.

**It is off by default, and turning it on is a migration, not a flag.** Read
[Rolling it out](#rolling-it-out) before enabling it on a database that already
holds data.

## Where it is enforced

In `chirondb-core`, not in any one query surface. HTTP, gRPC, ChironWire, MCP,
the pgvector subset and ChironQL all reach the same engine, and a rule applied
in only one of them protects only that one.

A point's owner lives in its payload under the reserved field `tenant_id`. Only
the server ever writes it.

## The rules

### A write is stamped by the server

The tenant comes from the authenticated key, never from the payload. If a
payload arrives carrying a *different* `tenant_id`, the write is **rejected**
rather than corrected:

```
✗ payload declares tenant 'globex' but this principal writes as 'acme';
  writing for another tenant needs the tenant:cross_write capability
```

Silently rewriting it would hide a client bug; honouring it would be the
vulnerability. Reads follow the same rule — filtering on another tenant's
`tenant_id` is refused rather than quietly answered with your own rows.

### Cross-tenant access is a capability, not a role

Two capabilities, granted per key in the RBAC file:

| Capability | Grants |
| --- | --- |
| `tenant:cross_read` | Reading outside the key's own tenant |
| `tenant:cross_write` | Writing, stamping or deleting outside it |

**An `admin` role does not imply either.** Administering a cluster and reading
another customer's rows are different questions, so they get different answers.
Migration and repair go through `tenant:cross_write` instead of borrowing
ordinary write behaviour.

```json
{
  "keys": [
    { "id": "acme-app", "key": "example-only-acme-key-replace-before-use", "tenant_id": "acme", "role": "read_write" },
    { "id": "auditor", "key": "example-only-auditor-key-replace-before-use", "tenant_id": "acme", "role": "read_only",
      "capabilities": ["tenant:cross_read"] },
    { "id": "migrator", "key": "example-only-migrator-key-replace-before-use", "role": "read_write",
      "capabilities": ["tenant:cross_read", "tenant:cross_write"] }
  ]
}
```

Save the configuration as `rbac.json` outside the database directory. The
server also needs a separate API key source containing **exactly the same
keys**. From that directory, replace the sample keys with generated secrets
and create the matching key file:

```bash
python3 - <<'PY'
import json, os, secrets
from pathlib import Path

rbac = Path("rbac.json")
config = json.loads(rbac.read_text())
for entry in config["keys"]:
    entry["key"] = secrets.token_urlsafe(32)
fd = os.open("api-keys.txt", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
os.chmod(rbac, 0o600)
rbac.write_text(json.dumps(config, indent=2))
with os.fdopen(fd, "w") as f:
    f.write("\n".join(entry["key"] for entry in config["keys"]) + "\n")
PY
```

Run this setup once before starting the server; keep both files out of version
control. Do not rerun it to rotate live credentials. Supply the selected key
to clients, for example as `CHIRONDB_API_KEY` for `chironql` and `chironctl`.
Stable `id` values are required by secure mode and should survive key rotation.

An unknown capability name is ignored and logged. It never grants anything.

### Every cross-tenant access is audited

Emitted as a structured event on the `chirondb::tenant_audit` target, carrying
actor, operation, target tenant, own tenant, capability and timestamp — and no
payload contents:

```
INFO chirondb::tenant_audit: cross-tenant access
     actor="auditor" operation="read" target_tenant="*" own_tenant="acme"
     capability="tenant:cross_read" at_unix_ms=1787053669123
```

### A point with no tenant belongs to nobody

Once enforcement is on, a point without `tenant_id` is invisible to every
tenant, and cannot be modified by any of them either. Fail-open was rejected
deliberately: one un-migrated legacy row would become a cross-tenant leak, and
a leak is worse than an outage.

A key holding `tenant:cross_read` can still see them, which is how you find
them.

### Omission fails closed

The `Db` entry points that carry no tenant scope — `search`, `count`, `scroll`,
`get_points`, `upsert`, `delete`, `set_payload`, `delete_by_filter` — **refuse**
under `enforced` and name the `_scoped` variant instead. A surface that has not
been taught about tenants therefore denies visibly rather than serving unscoped
rows.

That is also the honest status of the surfaces today:

| Surface | Under `enforced` |
| --- | --- |
| ChironQL — console, `chironql`, `POST /v1/chironql` | Scoped by the caller's key |
| gRPC `ExecuteQuery` | Scoped by the caller's key |
| REST `/v1/collections/...` and native gRPC point/search RPCs | Scoped by the caller's key |
| MCP `/v1/mcp`, `/mcp`, and the `chironmcp` bridge | Requires API-key RBAC; tenant-bearing keys require enforcement, and BM25 results plus corpus statistics use the authorized tenant scope |
| ChironWire point/search and ChironQL frames | Scoped by the caller's key; graph operations also require explicit `graph:*` capabilities |
| pgvector subset point writes, deletes, and searches | Scoped by the caller's key |

Unscoped engine calls still refuse visibly. Collection administration remains
a separate role/allowlist check; ChironQL collection DDL refuses while
enforcement is enabled.

## Rolling it out

Use [the source setup](GETTING_STARTED.md#1-build-and-start) to build the tools
and add them to `PATH`. The following startup lines are alternatives: stop the
server before changing mode, and reuse its data directory and RBAC file.

```bash
chirondb --api-key-file ./api-keys.txt --rbac-config-file ./rbac.json --tenant-enforcement disabled
chirondb --api-key-file ./api-keys.txt --rbac-config-file ./rbac.json --tenant-enforcement dry-run
chirondb --api-key-file ./api-keys.txt --rbac-config-file ./rbac.json --tenant-enforcement enforced
```

Going straight to `enforced` on an existing database hides every point that
predates it. The order that works:

**1. Find the untenanted rows.** Reports without changing anything:

```bash
chironctl tenant-backfill products
```

```json
{
  "collection": "products",
  "scanned": 2,
  "untenanted": 2,
  "stamped": 0,
  "remaining_untenanted": 2,
  "ready_for_enforcement": false
}
```

**2. Stamp them.** `--tenant` makes it write; the stamp is merged, so the rest
of each payload is untouched:

```bash
chironctl tenant-backfill products --tenant acme
```

The CLI stamps **every unowned point in that collection** with the supplied
tenant. Use it only when all those points belong to that one tenant. For a
mixed collection, select and stamp each owner's point IDs using your own
migration script and the `points/payload` merge endpoint instead. Re-running
the CLI with another tenant does not reassign points already stamped.

**3. Confirm.** `ready_for_enforcement` turns true when nothing is left:

```json
{ "scanned": 2, "untenanted": 0, "remaining_untenanted": 0, "ready_for_enforcement": true }
```

**4. Observe.** Run with `--tenant-enforcement dry-run` for a while. Rules are
evaluated and violations reported, but nothing is blocked and no rows are
hidden — this is what tells you the migration is complete before an outage
does.

**5. Enforce.**

Repeat steps 1–3 for every collection. `ready_for_enforcement` is per
collection, not per database.

## What it does not do

- **It does not encrypt anything.** Tenants share storage; this controls who
  can address which rows, not how they are stored.
- **It does not scope collection administration.** Creating and deleting
  collections is governed by the role and `allowed_collections`, as before.
- **It is not a substitute for separate deployments** where a customer's
  requirement is physical separation.
