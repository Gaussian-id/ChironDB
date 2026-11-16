# ChironDB offline temporal source qualification

This internal workspace member stores boolean and non-NaN float64 sensor samples in an immutable in-memory segment and reads them from a seekable file or cursor. The library accepts unsorted input, groups by tenant/asset/property and orders by signed nanosecond event time. Exact duplicates collapse; mixed types and conflicting values fail before the encoder returns any bytes. Float equality for retries uses the exact bit pattern (including signed zero). See the runnable API example in the crate docs and [donor inventory](THIRD_PARTY.md).

`scan(&series, start, end)` returns ascending events in the half-open interval; an empty interval returns an empty vector, a reversed interval returns an error. `latest(&series)` returns an optional point, including the minimum and maximum i64 timestamps. An absent series has empty history. The caller owns a stable immutable source for the lifetime of a reader.

**Experimental layout.** Five header bytes (CTSG, version 1) precede contiguous TSM blocks, each with its upstream CRC32/IEEE. The same ordered index stores length-prefixed UTF-8 series identities, typed block extents and inclusive time bounds. A 16-byte footer stores the big-endian u64 index position, u32 index CRC and u32 CRC over the preceding 12 footer bytes. Open validates the header, footer, index and all extents. A scan validates each selected block before returning its samples. It skips untouched payload, so corruption there is detected when that block is read. Files contain at most 1,000 samples per block, 65,535 blocks per series and 64 MiB of index. The writer builds a whole segment in memory. CRC checks cover accidental corruption, with no authentication guarantee.

**Reproduce the gates from the workspace root.** Rust 1.92 and the workspace lockfile suffice for the default tests. They include independently generated Go and Java goldens. The live replay needs Go 1.25.9 or later, a JDK (tested with 17), Python 3.9+ and access to the pinned upstream sources/jars. Use a fresh temporary directory, not a database directory. The script verifies input file hashes, compiles the original source methods and executes the writer and readers in both directions. The temporal replay runs without a server. For the full workspace suite, put a Python interpreter with requests and a protobuf runtime compatible with protoc on PATH. The local qualification used protoc 36.2, Python protobuf 7.36.2 and requests 2.34.2 in a separate virtual environment, as required by the existing server compatibility tests.

```sh
cargo test --locked -p chirondb-temporal
python3 chirondb-temporal/verification/verify.py "$(mktemp -d)"
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --release --workspace --locked
cargo deny --locked check licenses
```

The 12 new file fixtures comprise edge values, an intentionally vulnerable key-length case, a 2,113-sample multiblock series and nine seeds with 400 series each. The script saves inputs, independent Go files, Rust files and a SHA-256 manifest in the specified directory. The prior campaign's raw archive was not recovered. A Go reference-index key length changed by one bit produces a different valid series mapping in the new fixture; opening the equivalent damaged private segment fails its index checksum. The Rust fault campaign flips every single bit and tries every truncation on both small private fixtures.

**Reproduce the TSBS sample and local cost measurements.** Build the official generator from commit `8323e59c74027b108f4ad5ec5d3e498b0101a02e` of `timescale/tsbs`. From that checkout:

```sh
go build -o /tmp/chiron-tsbs-generate ./cmd/tsbs_generate_data
/tmp/chiron-tsbs-generate --use-case=iot --format=influx --scale=4 --seed=20261106 --timestamp-start=2026-11-01T00:00:00Z --timestamp-end=2026-11-01T00:10:00Z --log-interval=10s > /tmp/chiron-tsbs.lp
```

From the workspace:

```sh
python3 chirondb-temporal/verification/tsbs_fixture.py /tmp/chiron-tsbs.lp /tmp/chiron-tsbs.tsv
cmp /tmp/chiron-tsbs.tsv chirondb-temporal/verification/fixtures/tsbs-iot.tsv
cargo build --release --locked -p chirondb-temporal --example source_cost
/usr/bin/time -l target/release/examples/source_cost /tmp/chiron-tsbs.tsv
```

On macOS `time -l` reports process peak resident bytes; on Linux use `/usr/bin/time -v` and convert the reported KiB to bytes. Repeat each fixture in three fresh processes, using the same binary. Encode time includes sorting/grouping and construction of the complete segment. Scan time covers reading and decoding selected history, including result allocation. Read bytes include header, footer and index. Block counts cover payload reads only. The complete process, including fixture parsing and the independent expected output, contributes to peak RSS. Offline source qualification does not establish a server, recovery or production SLO.
