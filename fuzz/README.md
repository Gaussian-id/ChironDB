# ChironDB fuzzing

The fuzz package is a nested workspace, so normal root `cargo build`, `cargo test`, and release
builds do not compile `libfuzzer-sys` or the fuzz targets.

Install the pinned toolchain and runner:

```bash
rustup toolchain install nightly-2026-08-20
cargo +nightly-2026-08-20 install cargo-fuzz --version 0.13.2 --locked
```

Replay a deterministic PR-style corpus smoke:

```bash
cargo +nightly-2026-08-20 fuzz run wal_frame_record fuzz/corpus/wal_frame_record -- \
  -seed=1 -runs=256 -max_total_time=30 -timeout=5 -rss_limit_mb=2048 -max_len=1048576
```

Replace `wal_frame_record` with `catalog_wal`, `archive_manifest`, or `restore_journal` and use the
matching corpus directory. Release and nightly CI run every target for at most 900 seconds.

## Graph GDX checked loaders

`graph_gdx_loaders` selects one of the production `nid.gdx`, `edge.gdx`, `tdelta.gdx`,
`edgeid.gdx`, `edgeprop.gdx`, `fragdir.gdx`, or `graph_identity.gdx` loaders. Inputs can be raw
files or deterministic mutations of production-written plaintext/encrypted artifacts, and a
successful open is followed by deep reads rather than header-only validation.

Build and replay the deterministic corpus in separate writable directories so plaintext and
encrypted findings cannot contaminate one another:

```bash
cargo +nightly-2026-08-20 fuzz build graph_gdx_loaders

mkdir -p /tmp/chirondb-gdx-plaintext /tmp/chirondb-gdx-encrypted
cp fuzz/corpus/graph_gdx_loaders/* /tmp/chirondb-gdx-plaintext/
cp fuzz/corpus/graph_gdx_loaders/* /tmp/chirondb-gdx-encrypted/

cargo +nightly-2026-08-20 fuzz run graph_gdx_loaders /tmp/chirondb-gdx-plaintext -- \
  -runs=256 -timeout=10 -rss_limit_mb=4096 -max_len=1048576
CHIRONDB_GDX_FUZZ_ENCRYPTED=1 \
  cargo +nightly-2026-08-20 fuzz run graph_gdx_loaders /tmp/chirondb-gdx-encrypted -- \
  -runs=256 -timeout=10 -rss_limit_mb=4096 -max_len=1048576
```

These are harness smokes, not C10 evidence. C10 requires two independent uninterrupted supervisors,
each with `-max_total_time=86400`, retained corpus/binary/time manifests, and zero findings; a
restart resets that arm's duration.
