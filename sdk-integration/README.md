# Standalone SDK compatibility gate

This test harness is outside the server Cargo workspace. Ordinary engine builds
and tests need no private SDK credential. Its tests preserve the prior typed,
protected, text-hybrid, Python smoke, SQL receipt and real-worker scenarios.

`sdk-lock.json` pins independently qualified SDK revisions. Trusted CI uses
`SDK_REPOS_READ_TOKEN` (Contents: read for the three SDK repositories) to fetch
those revisions and install the Python wheel. The token is not required by SDK
runtime code or by ordinary server builds. Run with exact candidate binaries via
`CHIRONDB_BIN_DIR`; real-worker checks use `CHIRONDB_ML_WORKER_PYTHON` and
`CHIRONDB_ML_WORKER_SCRIPT`. The worker's SDK probes use the installed Python
package and `CHIRONDB_ML_SDK_PYTHON` when a separate interpreter is required.

Run the default harness, then explicitly run all three ignored ML parents using
`cargo test --manifest-path sdk-integration/Cargo.toml --test ml_materialize -- --ignored`.
The snapshot/refresh race parent requires the server's `ml-worker/delayed_worker.py`
as its worker script, matching the main CI's explicit invocation.

## Configure the CI read credential

Local checkouts can use their existing Git login. GitHub Actions needs a separate
read credential to fetch the private SDKs. Create a
[fine-grained token](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-fine-grained-personal-access-token)
with resource owner `Gaussian-id`, repository access limited to `chirondb-rust`,
`chirondb-py`, and `chirondb-js`, and repository permission **Contents: read**.
Choose an expiration and complete organization approval when required.

Store the value as the Actions repository secret `SDK_REPOS_READ_TOKEN` in both
[gauss-db settings](https://github.com/Gaussian-id/gauss-db/settings/secrets/actions)
and [ChironDB settings](https://github.com/Gaussian-id/ChironDB/settings/secrets/actions),
using **New repository secret**. An organization secret with that same name and
access to both server repositories also works. See
[GitHub's secret setup](https://docs.github.com/en/actions/how-tos/write-workflows/choose-what-workflows-do/use-secrets).
The workflow already limits authenticated jobs to trusted repository code.
