# Optional tabular ML worker

This local evaluation preview supports `DECISION_TREE` and `RANDOM_FOREST`
through ChironQL using scikit-learn. It is **not production ready**. TabFM
integration has been removed because the project does not have the required
model usage rights. No foundation-model weights or provisioning tool are supplied.
Removed models reject before scheduling; old definitions are not automatically
converted. Drop and redefine a view with a supported model to refresh it.

## Setup and one-command console

Use Python 3.10–3.12. Install dependencies and build explicitly:

```bash
python3.12 -m venv target/ml-worker-venv
target/ml-worker-venv/bin/python -m pip install -r ml-worker/requirements-traditional.txt
CARGO_TARGET_DIR=target/ml-isolated cargo build -j1 -p chirondb \
  --bin chirondb --bin chironql --locked
./scripts/chiron-ml
```

The launcher uses the worktree's `target/ml-isolated/debug/chirondb --console`,
`target/ml-worker-venv/bin/python`, and `ml-worker/chirondb_ml_worker.py`.
It honors `CHIRONDB_ML_WORKER_PYTHON` and `CHIRONDB_ML_WORKER_SCRIPT`.
No PyTorch, Hugging Face cache or model checkpoint is required.

Defaults are `target/ml-playground-data`, loopback HTTP/gRPC/ChironWire ports
7401/7402/7403, and an admin console for unprotected local evaluation.
Server arguments override the matching defaults:

```bash
./scripts/chiron-ml --data-dir ./target/another-playground \
  --listen-http 127.0.0.1:7411 --listen-grpc 127.0.0.1:7412 \
  --listen-wire 127.0.0.1:7413
```

Existing data is preserved. To open the earlier playground, explicitly pass
`--data-dir ./target/tabfm-playground-data`; this does not restore removed model
support. Materialized rows can still be inspected with SQL. Data under `target/`
is removed by `cargo clean`; choose a separate data directory for durable use.

The launcher requires an interactive terminal and checks the binary, interpreter,
worker and Python dependencies before starting. It does not build, install,
download, remove data, or stop an existing server. Protected-console credential
and tenant checks still apply. `\q` closes the console and stops its server;
restarting preserves the database.

## Queries and output

Create a source table containing a primary key, explicit features, labeled rows,
and rows with a NULL target. The worker trains on all labeled source rows and
predicts all source rows. Compare models using different view names:

```sql
ML MATERIALIZE demo_regression FROM ml_demo TARGET amount
FEATURES (price) TASK REGRESSION USING DECISION_TREE;
ML MATERIALIZE demo_regression_rf FROM ml_demo TARGET amount
FEATURES (price) TASK REGRESSION USING RANDOM_FOREST;
SQL SELECT * FROM demo_regression ORDER BY id;
```

Regression confidence is unavailable: SQL `NULL`, JSON `null`, and visible `NULL`
in both console and client tables. Classification confidence is numeric selected
class probability, not measured accuracy. Identical definitions refresh a view;
changing its model or other parameters returns `chironql.ml_definition_conflict`.
The source limit is 10,000 rows and each worker has a five-minute deadline.
ML is unavailable while protected tenant enforcement is enabled.

The worker receives only a JSON snapshot and a cleared environment, without
server credentials. It runs as the server user and is not a filesystem sandbox;
configure only a trusted local worker. Results replace the previous view atomically after success;
a failed refresh preserves the last published version.

With an unprotected local server on port 7401, the synthetic demo creates unique
source/result tables and retains them for inspection:

```bash
target/ml-worker-venv/bin/python ml-worker/try_ml.py
PYTHONPATH=ml-worker target/ml-worker-venv/bin/python -m unittest -v test_worker
```

These are functional checks, not model quality or production certification.
