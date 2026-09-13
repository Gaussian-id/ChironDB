# ChironDB Security Policy

ChironDB is under active beta development (`0.1.0-beta.1` in the source tree).
Security controls in a release are evidence for hardening work; they are not
a claim of SOC 2, FIPS, or other certification.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Contact
[Gaussian on LinkedIn](https://www.linkedin.com/company/gaussian-id/posts/)
by private message to arrange a confidential reporting channel. Keep the first
message brief; do not share exploit details in public posts or comments.
There is no dedicated security email address yet.

If GitHub private vulnerability reporting becomes available, you can also use
**Security → Report a vulnerability** on the
[repository security page](https://github.com/Gaussian-id/ChironDB/security).
A regular issue is not a confidential report.

Include:

- The affected version or commit, platform, and deployment mode.
- The suspected impact and the access an attacker would need.
- Minimal reproduction steps or a proof of concept using disposable data.
- Any proposed mitigation and your preferred contact for follow-up.

Do not include production API keys, encryption keys, customer payloads, or
unredacted audit logs.

We will acknowledge a report within two business days, provide an initial
triage within five business days, and coordinate disclosure after a fix is
available. Safe-harbor applies to good-faith research that avoids privacy
violations, service disruption, persistence, and access beyond what is needed
to demonstrate the issue.

## Supported versions

Security fixes currently land on `main`; there is no long-term-support line.
When tagged beta releases are published, only the latest beta is supported.
Operators should verify the checksums, signature, provenance, and SBOM supplied
with an artifact before upgrading.

## Secure deployment boundary

Non-loopback listeners require TLS, API credentials, RBAC with stable principal
IDs, a mounted encryption keyring, generation-based storage, explicit CORS
origins, and HTTPS or local object storage. Raft is a scaffold and must remain
loopback-only until node mTLS identity is implemented.

The threat model excludes a compromised kernel/root account and live process
memory scraping. Application-level encryption protects persisted artifacts and
transfers; it does not make a running compromised host trustworthy.

The legacy in-process flamegraph environment variables are intentionally
rejected because the profiler dependency chain does not meet the release
security policy. Use an operating-system profiler on an isolated diagnostic
host instead.

Keyring v1 key IDs use a fixed encoded width within one ring. This keeps
append-only WAL frame sizes—and therefore persisted LSN boundaries—stable when
KEKs are rotated. Monthly IDs such as `2026-08` and `2026-09` satisfy this
contract.

## Related documentation

- [Getting started](docs/GETTING_STARTED.md#authentication-and-network-access)
- [HTTP authentication and security configuration](docs/HTTP_API.md)
- [gRPC authentication and TLS](docs/GRPC_API.md)
- [Tenant isolation](docs/TENANT_ISOLATION.md)
