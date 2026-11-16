# Native snapshots and legacy checksum conversion

Native snapshot creation and restore use the same engine through HTTP, gRPC,
ChironWire and embedded Rust. See the [HTTP recipes](HTTP_API.md#create-and-restore-a-snapshot)
for the configured snapshot root, permissions and point-in-time restore options.
Restore replaces the target's content; retain the original data and verify the
restored collections and points before relying on a backup.

## Configuration checksum fix

New snapshots use marker version **3**, magic `GAUSSSN3`. The configuration CRC32
covers compact JSON with recursively sorted object keys, including payload
schemas and named-vector dimensions. Equivalent maps have the same checksum
after deserialization and restart. Configuration values remain covered.

Versions 1 and 2 serialized Rust hash maps directly. Their iteration order could
change on every load, causing an intact schema-bearing snapshot to fail with
`snapshot marker config checksum mismatch`. The original order was not always
saved in the catalog, so a catalog-only checksum rewrite cannot establish
integrity. Normal import and restore still refuse checksum mismatches.

| Data | Compatibility |
| --- | --- |
| Existing live WAL, catalog, checkpoints and segments | No format change or checksum rewrite; reopen normally with a compatible binary. |
| v1 `GAUSSSN1`, v2 `GAUSSSN2` snapshot | Original strict validation remains. Use explicit conversion when the old configuration checksum is ambiguous. |
| v3 `GAUSSSN3` snapshot | Requires a reader containing this fix. Older binaries reject its magic instead of using the wrong checksum algorithm. Retain original backups for rollback. |

This snapshot version is independent of transaction-journal, installation,
relational-checkpoint and segment versions. This fix does not downgrade them.

## Verify and convert a legacy snapshot

Build `chironctl` from the same fixed source as the server. Conversion is an
offline local operation; no server endpoint or API key is involved. Stop any
process using the source or destination directory. The source must be an
immutable native snapshot, not an already opened database directory.
Use the flat snapshot directory produced by the snapshot API. Installation
generation pointers, activation identity, protected security control or pending
restore journals cause refusal; do not delete those controls to bypass it.

```bash
cargo build --release --locked -p chirondb --bin chirondb --bin chironctl
./target/release/chironctl security convert-snapshot \
  --source ./backups/legacy-snapshot \
  --destination ./backups/verified-v3
```

For encrypted snapshots, supply the external keyring containing every required
historical key. Keyrings are not included in snapshots:

```bash
./target/release/chironctl security convert-snapshot \
  --source ./backups/encrypted-legacy \
  --destination ./backups/encrypted-v3 \
  --keyring /secure/chirondb-keyring.json
```

The destination must be new, with an existing writable parent, and must not
overlap the source. Allow disk space for a full separate copy. Conversion locks
both paths, copies into a temporary sibling directory, and checks the marker
framing and the complete retained committed transaction journal. Keep all of
`transactions/`, including its format marker, authority and retained records.
Missing creation history, inconsistent schema history, uncertain decisions or
unfinished storage/audit projections cause refusal.

The converter reconstructs collection creation, deletion/recreation and schema
epochs from that journal, then compares the full normalized configuration using
SHA-256. Only after agreement does it replace the ambiguous legacy configuration
CRC. Collection counts/names, schema epochs, point counts, segment IDs, WAL cuts
and v2 graph bindings retain ordinary strict validation. Valid graph WAL in a
v1 snapshot receives a graph binding in the new v3 marker. Referenced storage
artifacts must be available locally; this command has no external cold-store
configuration option.

The original source files are unchanged. The verified copy is synchronized and
renamed into place only after validation. Verification failures leave no
published output; an existing destination is never replaced. An I/O error
during final rename/directory synchronization can leave the checked destination
present despite an error result: retain the source and inspect that copy before
retrying. The output records an admin audit
event named `convert_legacy_snapshot` and prints a receipt with `source_version`,
`snapshot_version`, `verified_collections` and `verified_commit_frontier`.

Restore the new directory through the ordinary snapshot API with the fixed
reader, then verify configuration, named vectors, payloads and application
queries after restart. A checksum is an integrity check, not proof that an
untrusted backup or its journal is authentic. Keep trusted backups and keys.

Snapshots without the complete journal cannot be converted safely by this
command. Preserve them and recover from trusted original data or another
verified backup; do not edit the checksum, remove schema fields or fabricate a
journal. Protected installation backups use their separate
`security backup` / `verify-backup` / `restore-backup` workflow; this converter
refuses protected snapshots. General production disaster-recovery, external
object-store and protected backup qualification remain separate acceptance work.
