# syntax=docker/dockerfile:1.7

FROM rust:1.94-bookworm AS builder

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        build-essential \
        ca-certificates \
        git \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true

COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY src ./src

RUN cargo build --locked --release --bin ostk-fleet-recall

FROM debian:bookworm-slim AS runtime

ARG VCS_REF=unknown
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.title="ostk-fleet-recall" \
      org.opencontainers.image.description="Distributed semantic memory for OSTK agent fleets" \
      org.opencontainers.image.source="https://github.com/os-tack/ostk-fleet-recall" \
      org.opencontainers.image.revision="$VCS_REF" \
      org.opencontainers.image.created="$BUILD_DATE" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        awscli \
        ca-certificates \
        curl \
    && groupadd --gid 10001 ostk \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin ostk \
    && install --directory --owner ostk --group ostk /opt/ostk/models \
    && install --directory --owner ostk --group ostk --mode 0555 /opt/ostk/demo \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /workspace/target/release/ostk-fleet-recall /usr/local/bin/ostk-fleet-recall
COPY --chmod=0555 deploy/container-entrypoint.sh /usr/local/bin/container-entrypoint
COPY --chown=10001:10001 --chmod=0444 examples/demo.ndjson /opt/ostk/demo/demo.ndjson

USER 10001:10001
WORKDIR /home/ostk

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/container-entrypoint"]
CMD ["demo", "--listen", "0.0.0.0:8080"]
