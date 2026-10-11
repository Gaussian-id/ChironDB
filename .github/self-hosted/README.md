# ChironDB self-hosted CI runners

The public OSS workflows use GitHub-hosted native runners for the four required
Linux/macOS architectures. No self-hosted registration is needed for those gates.
The setup below describes optional self-hosted infrastructure for private workflows
and operator-managed qualification; it is not the OSS PR runner configuration.

The required workflows use two repository runners on one Apple Silicon Mac.
They execute only repository-owned branches and pull requests. Fork pull
requests fail the trust-boundary job before any checkout reaches a privileged
runner.

The runner release is pinned to `actions/runner` 2.337.0. Registration tokens
are one-time inputs and must never be stored in this repository, shell history,
Compose files, or CI secrets exported as artifacts.

## macOS ARM64 runner

Install Rust 1.92.0, Rosetta 2, Docker Desktop, and protobuf. The installer
verifies these tools and adds the `aarch64-apple-darwin`,
`x86_64-apple-darwin`, and `aarch64-unknown-linux-gnu` targets. Obtain a fresh
repository runner token from **Settings → Actions → Runners → New
self-hosted runner**, then run:

```bash
REPOSITORY_URL=https://github.com/OWNER/REPOSITORY \
bash .github/self-hosted/install-macos-runner.sh
```

The script asks for the token without echoing it or placing it in shell
history.

The registered labels must include `self-hosted`, `macOS`, `ARM64`, and
`chirondb-ci`. The x86_64 Darwin matrix uses this same runner through Rosetta.

## privileged Linux X64 runner

Build and start the amd64 container from this directory:

```bash
cd .github/self-hosted
REPOSITORY_URL=https://github.com/OWNER/REPOSITORY \
bash register-linux-runner.sh
```

The script prompts for the token, waits for registration, then recreates the
container without that token in its environment. The registration credentials
and work directory remain in named volumes. The
runner executable stays pinned in the image, so rebuilding cannot retain an
older executable from a state volume. The container is privileged because the
real ENOSPC gates, including protected reference-index migration, mount a
64 MiB ext4 loopback filesystem. It also receives the
Docker socket for image and deployment tests. Never assign this runner to a
public fork or another repository.

Both workflows begin with `.github/self-hosted/runner-preflight.sh`, which
verifies the exact checked-out SHA, runner architecture, Rust/protobuf tools,
Rosetta or Docker/loopback support, free space, and a clean checkout.

The Linux ARM matrix entry runs natively in the Apple Silicon runner's Linux
Docker VM using `Dockerfile.linux-arm64`. The pinned Rust image contains protobuf
and Python smoke-test dependencies; each stage includes the preceding checks.
Reproduce the full ARM gate with `docker build --platform linux/arm64 --file
.github/self-hosted/Dockerfile.linux-arm64 --target release .`. This CI image is
for qualification; release container compatibility is checked separately.
