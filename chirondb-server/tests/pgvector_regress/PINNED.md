# pgvector regression suite — pinned source

Files under `sql/` are curated from upstream pgvector at the commit recorded
below. They are subsets — only the statement shapes covered by §3 of
`.SPEC/gaussdb-vector_cleaned.md` are exercised.

| Upstream | Commit | Date pinned |
|---|---|---|
| https://github.com/pgvector/pgvector | `v0.7.4` (commit pinned at next re-baseline) | 2026-06-14 |

## How to update

1. Refresh the upstream pgvector clone.
2. Diff against `sql/` here — keep only statements covered by `.SPEC/gaussdb-vector_cleaned.md`.
3. Bump the date above and the commit if a new tag.
4. Run `cargo test -p chirondb --test pgvector_conformance` and resolve any deltas in the same PR.
