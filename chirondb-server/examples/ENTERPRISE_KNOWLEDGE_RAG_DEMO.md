# Enterprise knowledge/RAG terminal demo

This local demo shows how one ChironDB server combines:

- relational document metadata with typed `RECORD_REF` columns;
- deterministic local vector embeddings and dense retrieval;
- graph citations from a chunk to its governing source;
- atomic row + vector + graph update/delete; and
- restart recovery on the same data directory.

It uses the real `chirondb` server and `chironql` terminal binaries. Python only
orchestrates processes, administrative graph HTTP calls, assertions, and the
evidence files. No framework, package installation, or external embedding API
is required.

From the repository root:

```bash
cargo build -p chirondb --bins
python3 chirondb-server/examples/enterprise_knowledge_rag_demo.py \
  --output-dir /tmp/chirondb-enterprise-rag-e2e
```

The output directory must be absent or empty. Ports `17641`–`17643` are used by
default; use `--port <http-port>` when they are occupied. The script creates
`transcript.log`, `results.json`, two server logs, the retained data directory,
and `manifest.json` with checksums and the exact local source state. Restart is
performed by SIGTERM followed by reopening the same directory; it is a restart
recovery check, not the separate process-kill fault campaign.

Expected final line:

```text
PASS manifest=/tmp/chirondb-enterprise-rag-e2e/manifest.json
```

The assertions require the unified pipeline to report domains
`relational`, `vector`, and `graph`; expose typed `RECORD_REF` values; preserve
an atomic update and delete after restart without partial state; and remove all
demo objects during logical cleanup. This is a functional single-node demo. It
does not replace process-kill/ENOSPC, W0 resource/recall, protected-mode,
PostgreSQL compatibility, SSI, scale, or exact-SHA runner acceptance.
