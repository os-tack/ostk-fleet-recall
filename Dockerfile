# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM rust:1.94-bookworm@sha256:6ae102bdbf528294bc79ad6e1fae682f6f7c2a6e6621506ba959f9685b308a55 AS builder

ARG VCS_REF=0000000000000000000000000000000000000000

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        build-essential \
        ca-certificates \
        git \
        jq \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true

COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY src ./src

RUN cargo build --locked --release --bin ostk-fleet-recall

# Generate the publication-safe demonstration corpus inside the reproducible
# build. The checked-in verifier is the gate; generated NDJSON never relies on
# an operator workstation artifact being present in the Docker context.
COPY README.md ./README.md
COPY .dockerignore .gitignore Dockerfile deny.toml ./
COPY .github ./.github
COPY contracts ./contracts
COPY demo ./demo
COPY docs ./docs
COPY deploy ./deploy
COPY examples ./examples
COPY tests ./tests
RUN install --directory /out \
    && RICH_DEMO_SOURCE_REVISION="$VCS_REF" \
       ./examples/rich-demo/generate.sh > /out/rich-demo.ndjson \
    && RICH_DEMO_EXPECTED_SOURCE_REVISION="$VCS_REF" \
       ./examples/rich-demo/verify.sh /out/rich-demo.ndjson

FROM golang:1.26.6-bookworm@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36 AS s5cmd-builder

RUN git clone --filter=blob:none https://github.com/peak/s5cmd.git /src \
    && cd /src \
    && git checkout --detach 991c9fbc16709341b4bac04513232a1445941f63 \
    && test "$(git rev-parse HEAD)" = 991c9fbc16709341b4bac04513232a1445941f63 \
    && CGO_ENABLED=0 go build -mod=vendor -trimpath \
        -ldflags "-s -w -buildid= \
          -X=github.com/peak/s5cmd/v2/version.Version=v2.3.0 \
          -X=github.com/peak/s5cmd/v2/version.GitCommit=991c9fb" \
        -o /out/s5cmd . \
    && install --directory /out/licenses \
    && cp LICENSE /out/licenses/s5cmd-LICENSE \
    && cp /usr/local/go/LICENSE /out/licenses/go-LICENSE \
    && find vendor -type f \
        \( -iname 'LICENSE*' -o -iname 'NOTICE*' -o -iname 'COPYING*' \) \
        -exec cp --parents '{}' /out/licenses/ \;

FROM public.ecr.aws/aws-cli/aws-cli:2.36.23@sha256:c7b16ed4f08f8a61634d9c219dd2388cf61c5425f3c096b5a5b235521d7ea5cc AS awscli

FROM public.ecr.aws/amazonlinux/amazonlinux:2023-minimal@sha256:97daa826f6597bd39ab9dee373290b6ce8220f1686fce5e83b51294a45f7484d AS runtime

ARG VCS_REF=0000000000000000000000000000000000000000
ARG BUILD_DATE=unknown

LABEL org.opencontainers.image.title="ostk-fleet-recall" \
      org.opencontainers.image.description="Distributed semantic memory for agent fleets" \
      org.opencontainers.image.source="https://github.com/os-tack/ostk-fleet-recall" \
      org.opencontainers.image.revision="$VCS_REF" \
      org.opencontainers.image.created="$BUILD_DATE" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"

RUN printf 'ostk:x:10001:\n' >>/etc/group \
    && printf 'ostk:x:10001:10001::/home/ostk:/sbin/nologin\n' >>/etc/passwd \
    && install --directory --owner ostk --group ostk /home/ostk \
    && install --directory --owner ostk --group ostk /opt/ostk/models \
    && install --directory --owner ostk --group ostk --mode 0555 /opt/ostk/demo

COPY --from=s5cmd-builder /out/s5cmd /usr/local/bin/s5cmd
COPY --from=builder /workspace/target/release/ostk-fleet-recall /usr/local/bin/ostk-fleet-recall
COPY --chmod=0555 deploy/container-entrypoint.sh /usr/local/bin/container-entrypoint
COPY --chown=10001:10001 --chmod=0444 examples/demo.ndjson /opt/ostk/demo/demo.ndjson
COPY --from=builder --chown=10001:10001 --chmod=0444 /out/rich-demo.ndjson /opt/ostk/demo/rich-demo.ndjson
COPY --from=s5cmd-builder /out/licenses /usr/share/licenses/s5cmd

USER 10001:10001
WORKDIR /home/ostk

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/container-entrypoint"]
CMD ["demo", "--listen", "0.0.0.0:8080"]

# The LocalStack harness also exercises Secrets Manager through the AWS CLI.
# Production uses the smaller S3-only client above; the ECS task role remains
# the privilege boundary and grants GetObject on exactly three model objects.
FROM runtime AS localstack

USER 0:0
COPY --from=awscli /usr/local/aws-cli /usr/local/aws-cli
RUN ln --symbolic /usr/local/aws-cli/v2/current/bin/aws /usr/local/bin/aws
USER 10001:10001

FROM runtime AS production
