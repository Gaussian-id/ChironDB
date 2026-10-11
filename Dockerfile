# syntax=docker/dockerfile:1@sha256:ecfaec9ed6d810b56388c508f4121597bfbba70d41a6dfeee4d8cad5f295fc32

FROM rust:1.92.0-bookworm@sha256:e90e846de4124376164ddfbaab4b0774c7bdeef5e738866295e5a90a34a307a2 AS build
ARG TARGETARCH
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends protobuf-compiler \
    && rm -rf /var/lib/apt/lists/*
COPY . .
RUN --mount=type=cache,id=chirondb-cargo-registry-${TARGETARCH},target=/usr/local/cargo/registry \
    --mount=type=cache,id=chirondb-cargo-git-${TARGETARCH},target=/usr/local/cargo/git \
    --mount=type=cache,id=chirondb-target-${TARGETARCH},target=/app/target,sharing=locked \
    cargo clean -p chirondb -p chirondb-core -p chirondb-types \
    && cargo build --release --locked -p chirondb --features jemalloc --bins --jobs 1 \
    && mkdir -p /app/release \
    && for bin in chirondb chironql chironmcp chironctl chironbench chirondrill chironrecall chirongrpcctl chironwirectl gaussdb gaussctl gaussbench gaussdrill gaussrecall gaussgrpcctl gausswirectl; do cp "target/release/$bin" /app/release/; done

FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241
ARG CHIRONDB_VERSION=0.1.0-beta.2
ARG VCS_REF=unknown
LABEL org.opencontainers.image.title="ChironDB" \
      org.opencontainers.image.description="ChironDB public beta vector database" \
      org.opencontainers.image.source="https://github.com/Gaussian-id/ChironDB" \
      org.opencontainers.image.version="${CHIRONDB_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="AGPL-3.0-only"
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 chirondb \
    && useradd --uid 10001 --gid 10001 --create-home --home-dir /var/lib/chirondb --shell /usr/sbin/nologin chirondb
RUN mkdir -p /etc/chirondb/secrets /run/chirondb-bootstrap \
    && chown 10001:10001 /etc/chirondb/secrets /run/chirondb-bootstrap \
    && chmod 0700 /etc/chirondb/secrets /run/chirondb-bootstrap
COPY --from=build /app/release/ /usr/local/bin/
COPY LICENSE LICENSE-APACHE-2.0 NOTICE TRADEMARKS.md /usr/share/licenses/chirondb/
COPY --chmod=755 deploy/docker-entrypoint.sh /usr/local/bin/chirondb-entrypoint
USER chirondb
VOLUME ["/var/lib/chirondb"]
EXPOSE 7401 7402 7403
STOPSIGNAL SIGTERM
# The fallback probes TLS only on loopback and sends no credential. Protected
# installations supply their own CA, which is not necessarily in the image.
HEALTHCHECK --interval=10s --timeout=5s --start-period=15m --retries=6 CMD ["sh", "-c", "chironctl health >/dev/null 2>&1 || chironctl --endpoint https://127.0.0.1:7401 --danger-accept-invalid-certs health >/dev/null 2>&1"]
ENTRYPOINT ["chirondb-entrypoint"]
CMD ["--listen-http", "0.0.0.0:7401", "--listen-grpc", "0.0.0.0:7402", "--listen-wire", "0.0.0.0:7403", "--data-dir", "/var/lib/chirondb/data"]
