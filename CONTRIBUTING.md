# Contributing to ChironDB

Help make ChironDB easier to use, more reliable, and better supported by
reproducible evidence. Bug reports, documentation fixes, tests, and focused
pull requests are welcome. Participation follows our
[Code of Conduct](CODE_OF_CONDUCT.md).

## Start with the problem

For a bug, include the version or commit, operating system and architecture,
deployment method, expected behaviour, actual behaviour, and the smallest
reproduction you can share. Remove credentials, customer payloads, and private
logs. Report suspected vulnerabilities privately via [SECURITY.md](SECURITY.md).

For a substantial feature or design change, describe the user problem in an
issue first. A proposal should improve one of these product pillars:

| Pillar | Focus |
| --- | --- |
| P1 — PostgreSQL-native vector + analytics | The supported vector-only PostgreSQL integration |
| P2 — Hybrid retrieval engine | Dense, sparse, and RAG retrieval workflows |
| P3 — Recall as a product SLO | Measured quality, targets, monitoring, and auditability |
| P4 — Algorithmic depth | The single LS-VEC engine and its internal stages |
| P5 — Distributed multi-tenant operations | Isolation, durability, and operational reliability |
| P6 — Code, security, & release standards | Maintainability, security, portability, and usable releases |

These are directions for contributions, not a claim that every capability is
production-ready. The [README](README.md#status) describes the current scope.

## Set up a checkout

Install Git, a C/C++ build toolchain, `protoc`, and Rust through rustup. The
repository pins Rust `1.92.0`. Follow the [usage guide](docs/GETTING_STARTED.md)
to start the server and try a collection.

```bash
git clone https://github.com/Gaussian-id/ChironDB.git
cd ChironDB
git switch -c codex/describe-your-change
```

Use a fork if you do not have write access. Keep one coherent change per pull
request and avoid unrelated cleanup.

## Keep changes in the right layer

| Location | Responsibility |
| --- | --- |
| `chirondb-types/` | Data types, models, filters, and errors; no I/O |
| `chirondb-core/` | Storage, indexes, search, recovery, and the shared engine |
| `chirondb-server/` | HTTP, gRPC, ChironWire, ChironQL, authentication, and CLI tools |
| `chirondb-ui-server/` | Preview UI backend |
| `clients/` | Python and Rust clients, including compatibility facades |
| `proto/` | Versioned RPC schemas and retained compatibility messages |
| `docs/` | Public usage documentation |

Preserve WAL-first mutations, per-collection locking, audit records, and legacy
data readers. Keep `db.rs` focused on orchestration. Implement engine behaviour
once and expose it consistently through the protocol layers. New HTTP routes
must serve both canonical `/v1` and retained legacy paths.

Use **ChironDB** and **ChironWire** in new public material. Do not rename
persisted GaussDB formats or compatibility interfaces just to change branding.
Avoid adding an index-family menu or customer-specific flags.

## Validate the change

For code changes, run the relevant regression tests and the standard gates:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
python3 .github/tools/check_release_version.py
```

When licensing or dependencies change, also run:

```bash
cargo deny --locked check licenses
```

For documentation-only changes, check relative links, render the Markdown,
and execute any changed examples against a disposable database. Do not report
unrun checks as passed. Maintainers record delivered changes and benchmark
evidence in the project's private engineering knowledge base; external
contributors do not need access to it.

Before merge, both [CI](.github/workflows/ci.yml) and the
[cross-platform matrix](.github/workflows/cross-platform-ci.yml) must pass.
Linux and macOS on x86-64 and ARM64 are required; Windows is best-effort.

Performance claims need an appropriate industry-standard workload: official
ann-benchmarks datasets such as SIFT, GloVe, Deep, or GIST; BEIR/MTEB tasks for
retrieval quality; or a recall-SLO regression. Record the dataset, revision,
hardware, settings, recall, throughput, and tail latency. A single local
throughput improvement does not establish a general performance claim.

## Prepare the pull request

Use [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/)
for commit subjects and PR titles:

```text
type(optional-scope): imperative description
```

Use a lowercase type: `feat`, `fix`, `docs`, `refactor`, `perf`, `test`,
`build`, `ci`, `chore`, `style`, or `revert`. An optional scope identifies the
subsystem, such as `storage`, `grpc`, or `release`. Keep the subject within
72 characters and omit a final period. Examples:

```text
fix(storage): preserve WAL recovery ordering
docs(grpc): explain client generation
```

Mark breaking changes with `!` before the colon and explain the migration
in a `BREAKING CHANGE:` footer. Keep each PR focused on one completed change;
maintainers should use a squash merge to keep the main history readable.
Describe:

1. The user problem, resulting behaviour, and pillar advanced.
2. The relevant benchmark or correctness evidence. For documentation, state
   that no algorithm changed and give the example/link checks instead.
3. The customer benefit and why it matters when evaluating alternatives.
4. Any lasting schema, API, protocol, or data-format change, its trade-offs,
   and compatibility plan.
5. The exact checks run and any remaining limitations.

Update public usage documentation when behaviour or examples change. Include
screenshots for visible documentation or UI changes. Keep credentials, runtime
data, build outputs, and unrelated files out of the diff.

## Contribution licensing

Contributions are accepted under [AGPL-3.0-only](LICENSE), the same license as
the current project. You retain your copyright. Submit only material you have
the right to contribute, and preserve third-party notices and attribution.
Check new dependency licenses with the repository's license gate; passing a
metadata check is not a substitute for understanding a dependency's terms.

Sign off your commits under the
[Developer Certificate of Origin 1.1](https://developercertificate.org/):

```bash
git commit -s -m "docs: clarify the ChironDB quickstart"
```

The sign-off records your certification that you have the right to submit the
contribution. It does not assign your copyright. For changes to a network-facing
interface, account for the Corresponding Source offer described in
[NOTICE](NOTICE) and AGPL Section 13.
