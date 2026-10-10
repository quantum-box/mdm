# syntax=docker/dockerfile:1.7

# The image is a portable origin runtime. It deliberately does not contain
# credentials or an enrollment CA; initialize and mount those separately.
FROM rust:1.95-bookworm AS builder

RUN apt-get update \
    && apt-get install --no-install-recommends -y pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY rust-toolchain.toml Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release --locked -p mdmd

FROM debian:bookworm-slim AS runtime-base

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates curl libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 mdmd \
    && useradd --system --uid 10001 --gid 10001 --home-dir /nonexistent \
        --shell /usr/sbin/nologin mdmd \
    && install -d -o 10001 -g 10001 -m 0700 /data /run/mdmsecrets

COPY deploy/docker/entrypoint.sh /usr/local/bin/mdmd-entrypoint
COPY deploy/docker/healthcheck.sh /usr/local/bin/mdmd-healthcheck
RUN chmod 0755 /usr/local/bin/mdmd-entrypoint /usr/local/bin/mdmd-healthcheck

# The data directory contains SQLite, its WAL/SHM files, and local backups.
# No EXPOSE is declared: publishing the listener is an explicit deployment
# decision in Compose, an orchestrator, or a host-level load balancer.
VOLUME ["/data"]

USER 10001:10001
ENTRYPOINT ["/usr/local/bin/mdmd-entrypoint"]
CMD ["serve"]

# The default container origin is loopback HTTP on 8080. Native TLS deployments
# set MDM_HEALTHCHECK_URL to an https:// URL whose certificate is trusted by the
# system bundle or by MDM_HEALTHCHECK_CA. MDM_HEALTHCHECK_RESOLVE can map the
# certificate hostname to the loopback listener. The probe never disables TLS
# verification.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/mdmd-healthcheck"]

# CI builds this target after the workspace job has produced
# target/release/mdmd. It reuses the same hardened runtime and does not invoke
# Cargo a second time. The normal `docker build .` remains the self-contained
# builder-backed runtime target below.
FROM runtime-base AS ci-runtime
COPY --chown=10001:10001 --chmod=0755 target/release/mdmd /usr/local/bin/mdmd

# Keep the builder-backed runtime as the default final stage.
FROM runtime-base AS runtime
COPY --from=builder --chown=10001:10001 --chmod=0755 /src/target/release/mdmd /usr/local/bin/mdmd
