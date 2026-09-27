# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# Build the repository's Linux image first; the agent image needs only its binary.
ARG RECALL_IMAGE=ostk-fleet-recall:local
FROM ${RECALL_IMAGE} AS recall

FROM node:24-bookworm-slim@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6
ARG CODEX_VERSION=0.157.1
ARG CLAUDE_VERSION=2.1.283
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates python3 git \
    && npm install --global --no-audit --no-fund \
        @openai/codex@${CODEX_VERSION} @anthropic-ai/claude-code@${CLAUDE_VERSION} \
    && groupadd --gid 10001 sandbox \
    && useradd --uid 10001 --gid 10001 --home-dir /home/sandbox --create-home sandbox \
    && install --directory --owner sandbox --group sandbox --mode 0750 /transcripts \
    && install --directory --mode 0555 /opt/fleet-sandbox

COPY --from=recall /usr/local/bin/ostk-fleet-recall /usr/local/bin/ostk-fleet-recall
COPY --chmod=0555 deploy/local/sandbox/entrypoint.py /opt/fleet-sandbox/entrypoint.py
COPY --chmod=0555 deploy/local/sandbox/synthetic.py /opt/fleet-sandbox/synthetic.py
COPY --chmod=0555 deploy/local/sandbox/recall-shim.py /usr/local/bin/recall-shim

ENV HOME=/home/sandbox
USER 10001:10001
WORKDIR /home/sandbox
ENTRYPOINT ["/opt/fleet-sandbox/entrypoint.py"]
