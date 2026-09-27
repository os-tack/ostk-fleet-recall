# Sandbox image

The image runs synthetic checks by default and can select Codex or Claude.
It contains the shim and shipper, without model weights or database credentials.
Build from the repository root after building a Linux Recall image:

```sh
docker build -f deploy/local/sandbox/Dockerfile \
  --build-arg RECALL_IMAGE=ostk-fleet-recall:local \
  -t ostk-sandbox:local .
```

Launcher examples use `ostk-fleet-recall` on `PATH`. After a local Cargo build,
use `target/debug/ostk-fleet-recall` instead if the command is not installed.

The Node 24 LTS base is pinned by OCI index digest. Codex 0.157.1 and Claude
Code 2.1.283 match the locally verified CLI versions. Both versions can be
changed explicitly through build arguments after compatibility testing.

An enrolled `launcher` identity mints a distinct agent grant and shipper grant.
The workstation uses `--url` to obtain grants, `--resource-url` as the exact
audience, and `--sandbox-url` for the container's network route:

```sh
ostk-fleet-recall launch up --backend docker --anchor local-key \
  --key-id launcher --scope TENANT_UUID/local-k0s --agent sandbox-one \
  --image ostk-sandbox:local --url http://localhost:8080/mcp \
  --sandbox-url http://host.docker.internal:8080/mcp
```

Set `FLEET_RECALL_LAUNCHER_KEY_HEX` in the launcher process only. Enrollment
must map the corresponding public key ID to a launcher role and the requested
scope. The launcher rejects a grant with another tenant, project, agent or
sandbox ID. `--anchor kubernetes` reads the projected token from
`--service-account-token-file` instead. It never mounts that token into the
workload.

Docker starts two containers sharing a named transcript volume; the shipper
mount is read-only. Kubernetes uses two containers in one Pod, with a native
sidecar that terminates after the agent, separate immutable Secrets, and no
automatically mounted service account token. Select `--backend kubernetes`,
`--namespace fleet-recall`, a cluster-reachable `--sandbox-url`, and optionally
`--runtime-class kata-qemu-runtime-rs`. Kubernetes needs native sidecar support.

The synthetic harness lists tools, checks status, records a labelled note,
reads it back, and writes native Claude JSONL turns. It makes no provider calls.
For Codex, explicitly supply only the saved login file:

```sh
ostk-fleet-recall launch up --backend docker --anchor local-key \
  --scope TENANT_UUID/local-k0s --agent sandbox-codex --image ostk-sandbox:local \
  --url http://localhost:8080/mcp \
  --sandbox-url http://host.docker.internal:8080/mcp \
  --harness codex --codex-auth-file "$HOME/.codex/auth.json" \
  --task 'Check Recall status, record a short note, and read it back.'
```

The login file must be a regular, private file. Its bounded contents enter
only the agent's private environment and temporary home; the user's config,
other MCP servers, hooks, plugins, and history are not copied. Codex uses the
saved login with `codex exec`; `--provider-key` instead explicitly forwards
`CODEX_API_KEY`. For Claude, `--harness claude --provider-key` forwards only
`ANTHROPIC_API_KEY`; the run is capped at five turns, $2, and the execution
deadline. `--model` selects a model; otherwise Codex uses its CLI default and
Claude uses Haiku. See official [Codex authentication](https://learn.chatgpt.com/docs/auth),
[headless execution](https://learn.chatgpt.com/docs/non-interactive-mode), and
[MCP configuration](https://learn.chatgpt.com/docs/extend/mcp?surface=cli).

All harnesses use a fresh home and Recall-only configuration. Selecting the
Codex harness preapproves exactly its scoped `recall` and `remember` tools;
shell execution stays read-only and other approval requests remain denied.
Provider auth
and logs stay outside the transcript volume. Only native transcript directories
are shared with the shipper. The shim receives just the agent's Recall token;
the shipper receives just its own grant. Tokens never appear in command arguments
or launcher output. Container-runtime administrators can inspect their containers
and Kubernetes Secrets, so those are trusted local infrastructure.

The launcher prints a private `launch-state.json` path. Stop the launch with:

```sh
ostk-fleet-recall launch down --state /absolute/private/path/launch-state.json
```

This stops the agent, allows a final shipper flush, revokes both grants, clears
local credential files, and preserves state snapshots. Failed teardown or
revocation remains marked `cleanup-pending`; rerun the same command after
restoring access. Docker transcript volumes remain available for audit.
Kubernetes `emptyDir` transcripts last until Pod teardown; use the remote spool
as the durable record. Keep the launcher anchor available for revocation.

Run the provider-free configuration tests with:

```sh
python3 -m unittest discover -s deploy/local/sandbox -p test_sandbox.py
cargo test --locked --lib launch::
```
