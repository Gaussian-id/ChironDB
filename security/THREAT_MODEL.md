# ChironDB G7 threat model

Status: implementation threat model for `feat/improve-security`. This document
defines controls and verification targets; it is not a SOC 2 certification or
a claim that every G7 acceptance gate has passed.

## Assets and security objectives

- API credentials, stable principal identity, tenant identity, and RBAC policy
  must remain confidential and must resolve to one fail-closed policy on every
  network protocol.
- Vectors, point IDs, payloads, schemas, indexes, WAL, snapshots, archives,
  cold-tier objects, audit records, and Raft scaffold state must be confidential
  and substitution/tamper evident at rest.
- A successful `wait=true` mutation must survive a process or host crash.
  Recovery must reject torn/corrupt records and select one complete generation.
- Audit records must form one ordered, verifiable chain. Mutation/admin work
  must not start until its durable intent is recorded.
- Public listeners must not expose plaintext credentials or data. Resource use
  by one principal or tenant must not starve the process or bypass quotas by
  adding credentials.

## Trust boundaries and data flows

1. HTTP, gRPC/gRPC-Web, direct-TLS ChironWire, and libpq pgwire clients cross
   the public listener boundary. Authentication resolves a `Principal`; handler
   authorization occurs only after the action and collection are known.
2. ChironQL crosses either a protected HTTP endpoint or the local console
   boundary. Parsed statements use the same role/action/collection policy.
3. The UI BFF is an untrusted network client of the upstream API. Its session
   cookie is not an upstream identity and it receives only the permissions of
   its configured upstream principal.
4. The engine crosses the persistence boundary through WAL-first mutations,
   immutable segments/indexes, catalog/checkpoint metadata, snapshots, WAL
   archives, and optional cold/object storage.
5. The external keyring and TLS/RBAC/API Secrets cross a deployment-secret
   boundary. They are mounted outside the data directory and are never included
   in a snapshot or archive.
6. Audit files and the data-directory lock remain outside the active generation.
   Restore swaps `CURRENT`; it cannot replace audit history or bypass exclusive
   process ownership.
7. The Kubernetes Operator/release pipeline crosses a supply-chain boundary:
   source, dependencies, actions, containers, binaries, SBOMs, provenance, and
   signatures must all be independently verifiable.

## Threats and controls

| Threat | Control | Verification |
|---|---|---|
| Legacy `/v1` or unknown-route auth bypass | Canonical HTTP route policy; unknown protected route fails closed | Alias/unknown-route matrix |
| gRPC, compatibility service, reflection, ChironWire, pgwire, or ChironQL bypass | Authentication resolves a principal; exhaustive per-operation authorization | Role × operation × namespace/protocol matrix |
| Cross-tenant point access | Tenant-scoped core entrypoints for every point/read operation | Tenant A/B protocol tests |
| Keyring/RBAC mismatch or unrestricted unknown key | Startup validation for duplicate/weak keys, IDs, capabilities, collection names, and exact key membership | Invalid-config table tests |
| Quota bypass with another key/name | Rate/resource key is tenant ID; allowlist check precedes accessible-collection quota | Multi-key and out-of-allowlist tests |
| Credential disclosure | TLS required off loopback; pgwire cleartext password only inside TLS; secrets excluded from audit | TLS/packet and persisted-tree scans |
| Public health metadata discloses storage topology | Health exposes only readiness status and version; data paths and collection counts are omitted | HTTPS health integration test |
| Persisted plaintext or file substitution | CHIRENC1 AES-256-GCM envelope, per-file DEK, metadata AAD, independent WAL/audit frames | Wrong-key/tamper/nonce/tree tests |
| Encrypted immutable-file recovery exhausts memory or reuses authenticated plaintext across files | 4 MiB authenticated range reads, per-open-file cache namespace, exact-length/trailing-byte validation, and temporary-buffer zeroization | Multi-chunk/random-access/corruption/streaming-write tests |
| Nonce reuse during append | Random file/frame UUID and deterministic per-file chunk nonce; WAL/audit frames are independent envelopes | Nonce uniqueness tests |
| Torn WAL accepted as EOF | Only zero header bytes is clean EOF; partial header is corruption; length/LSN/CRC/AEAD checked before allocation | Corrupt corpus and crash tests |
| Two processes or offline tools mutate one data directory | Stable canonical sibling lock, fail-fast owner metadata, shared ownership across `Db` clones, and one lock path for server/migration/verify/rotation | Same-path, symlink/normalized-alias, subprocess-kill, and offline-tool contention tests |
| Partial snapshot is published | Destination lock, CRC snapshot control journal, marker-last tree sync, and orphan-staging recovery | Snapshot publication crash matrix |
| Partial restore destroys live data | Validate/fsync staging, CRC journal v2 with legacy-v1 reader, admission barrier, and either atomic `CURRENT` switch or staged legacy swap | Kill-at-every-phase old/new-generation suite |
| Concurrent writers corrupt audit chain | One writer, ordered sequence/head, bounded admission, group commit, durable intent/outcome | Concurrent chain and failure tests |
| Audit failure becomes silent | Secure startup verifies all segments; queue/write errors reject requests with transport-specific unavailable errors | Disk-full/tamper/truncation tests |
| Certificate replacement serves invalid identity | Shared reloadable resolver validates before swap; last valid certificate remains active | Rotation integration test |
| Oversized/complex input exhausts resources | Protocol/body/count/dimension/payload caps, checked arithmetic, timeouts, global + per-tenant work bounds | Boundary and fuzz tests |
| Public Raft scaffold is impersonated | Non-loopback Raft bind is refused until node mTLS identity exists | Startup rejection test |
| Dependency/release compromise | Audit/deny, pin policy, secret scan, SBOM, provenance, cosign, clean-host verification | Security and release workflows |

## Abuse cases

- An attacker replays a valid API key against another transport or `/v1` alias.
  The key resolves to the same principal and cannot gain a different action or
  collection policy.
- A read-only principal embeds a write in ChironQL/SQL or selects a forbidden
  catalog collection. Statement classification and catalog filtering deny it.
- A tenant creates many API keys to multiply throughput. All keys with the same
  tenant ID share rate and execution admission accounting.
- An operator restores a path outside the configured snapshot root or points at
  a different object-store origin/prefix. The request is rejected before I/O.
- An attacker truncates WAL/audit/encrypted chunks. Startup/recovery reports
  typed corruption; it never treats partial framing as a clean end.
- A second server reaches the same data through a symlink or normalized alias.
  It resolves to the same sibling OS lock and fails before restore recovery,
  `CURRENT` selection, or persistence mutation.
- A key rotation is killed. The journal and atomic header replacement make the
  operation resumable; the old key remains required until verification reports
  no references.

## Assumptions and explicit non-goals

- The host kernel, root account, hypervisor, process memory, and secret-manager
  control plane are trusted. Compromised kernel/root and live memory scraping
  are out of scope.
- Traffic after an approved TLS terminator is trusted only when it reaches an
  all-loopback deployment; ChironDB itself otherwise requires TLS.
- Mounted keyring v1 is the external key-management boundary. Cloud-specific
  KMS SDKs, HSM integration, and FIPS certification are not claimed.
- The legacy `read_persistent` compatibility API still returns a complete
  `Vec`; production immutable indexes use bounded `PersistentFile` readers and
  legacy encrypted WAL archives use the streaming reader instead.
- Raft remains a scaffold, not production quorum durability. It may bind only
  to loopback until authenticated node mTLS is implemented.
- The single-node durability guarantee assumes a local filesystem and storage
  controller that honor file and directory `fsync`; network filesystems or
  controllers that ignore flushes are outside the guarantee.
- Security controls and evidence do not by themselves confer SOC 2 compliance.

## Residual risk and review triggers

Review this model whenever a protocol operation, persisted file type, external
store, identity field, deployment listener, or release channel is added. No new
network façade may call an unscoped core point operation while tenant enforcement
is active, and no new persisted artifact may bypass the encrypted durable-file
primitives.
