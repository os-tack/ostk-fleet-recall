# Command-line reference

[Documentation](../README.md) · [CLI](CLI.md) · [Configuration](CONFIGURATION.md)

Run commands from the repository root unless a linked deployment guide says
otherwise. Build and configure the binary using the
[local development tutorial](../tutorials/LOCAL_DEVELOPMENT.md), or use the
matching image and inputs from your deployment guide. The checked-in command
parser in [`src/main.rs`](../../src/main.rs) is the authority for flags;
`ostk-fleet-recall <command> --help` prints the installed release's interface.

## Main binary commands

| Command | Purpose and required authority | Detailed guidance |
| --- | --- | --- |
| `serve` | Private stdio MCP, bound to configured scope and agent, using the writer login. | [MCP](MCP.md) |
| `serve --http ADDRESS` | Authenticated HTTP MCP; enrollment and checked grants bind callers to scope and agent. | [Remote plane](../REMOTE_PLANE.md) |
| `demo` | Read-only HTTP `/`, `/healthz`, `/api/status`, `POST /api/recall`; requires the separate publication login. | [Development tutorial](../tutorials/LOCAL_DEVELOPMENT.md#5-exercise-the-http-demo) |
| `migrate` | Apply embedded CockroachDB schema migrations using the migrator. | [Migrations](../MIGRATIONS.md) |
| `health` | Check connectivity, schema prefix, required indexes, cosine support and active model identity using the writer. | [Configuration](CONFIGURATION.md) |
| `ingest --input PATH` | Import trusted NDJSON chunks with the writer; `-` reads stdin. | [Ingestion contract](COLLECTION.md#ingestion-contract) |
| `worker --once --sources PATH` | Admit configured git, transcript, CI and collected-item evidence, then project body/lexical/dense tiers. | [Worker](WORKER.md) |
| `collect` | Import, inspect or retire collected-item snapshots; inspect dead letters and retry exhausted hints. | [Collection](COLLECTION.md) |
| `ingress --sources PATH` | Receive signed provider hints with the dedicated ingress login and signing secrets. | [Webhooks](COLLECTION.md#receiving-provider-webhooks) |
| `model-digest BUNDLE` | Print the versioned digest of a local model bundle. | [Model setup](../tutorials/LOCAL_DEVELOPMENT.md#1-acquire-and-pin-the-local-embedding-model) |
| `enroll apply/list/revoke` | Manage explicit identity bindings with the separate enrollment login; `apply --prune` revokes bindings omitted from the complete document. | [Enrollment](../REMOTE_PLANE.md#prepare-the-database-and-enrollment-login) |
| `embed serve` | Serve the pinned embedding model without database credentials. | [Embedding tier](../REMOTE_PLANE.md#m3-embedding-tier) |
| `shim --url URL` | Forward sandbox MCP stdin/stdout to authenticated HTTP using its token. | [Sandboxes and transcripts](../REMOTE_PLANE.md#m3-sandboxes-and-transcripts) |
| `launch up/down` | Start a Docker or Kubernetes sandbox with separate agent/shipper grants; stop it and revoke both grants. | [Sandbox guide](../../deploy/local/sandbox/README.md) |
| `ship transcripts` | Tail complete Claude Code or Codex native transcript records to the remote spool with a shipper grant. | [Transcripts](../REMOTE_PLANE.md#m3-sandboxes-and-transcripts) |

Grant issuance and revocation are HTTP operations (`POST /v1/grants` and
`DELETE /v1/grants/{jti}`), also performed by `launch up/down`; there is no
`grant` subcommand. Use an enrolled launcher identity and follow the
[grant contract](../REMOTE_PLANE.md#other-anchors-and-grants). Keep launcher
authentication and provider credentials out of the Recall server environment.

Commands need different credentials. Do not reuse a migrator, enrollment,
publication or ingress environment as a writer environment. See
[configuration ownership](CONFIGURATION.md) and
[identities, URLs and secrets](../SECURITY.md#identities-urls-and-secrets).

## Private operator CLIs

`src/bin` holds private workstation tools. None is copied into the production
image or wired into Terraform, ECS, the public HTTP service, or normal
MCP/runtime startup. Each of the first eight below reads a dedicated private
database URL instead of the serving one. The last two,
`ostk-authority-install` and `ostk-spec`, read `FLEET_RECALL_DATABASE_URL`
like the `ostk-fleet-recall` commands: the installer as the migrator, like
`migrate`, and `ostk-spec` as the writer login, like `serve`.

- `ostk-control-bootstrap` accepts the out-of-band-pinned genesis bootstrap
  receipt into the append-only control ledger (Stage 2); see
  [private control-ledger bootstrap](../CONTROL_BOOTSTRAP.md).
- `ostk-registry-activate` performs the genesis Stage-3 registry activation.
- `ostk-registry-successor-activate` applies or inspects the one-time
  genesis-to-first-successor (`0 -> 1`) registry transition.
- `ostk-registry-generic-successor-activate` applies or inspects every later
  `N -> N+1` registry transition.
- `ostk-conflict-reconcile` is apply-only and materializes a new v2 conflict
  lineage for one immutable legacy conflict revision.
- `ostk-evidence-supersede` is apply-only (`apply --sources <file>
  [--dry-run]`) and closes the pre-profile-3 residual for git facts: it
  appends each raw fact's redacted rendering as a `supersedes` successor and
  removes the raw body, its derived rows, and its content object in the same
  transaction, leaving the raw event row as the tombstone; see
  [closing the pre-profile-3 residual](../guides/EVENT_FIRST_OPERATIONS.md#closing-the-pre-profile-3-residual)
  and the [security notes](../SECURITY.md#residual-sql-authority-and-recovery).
- `ostk-bootstrap-manifest-import` admits legacy chunks, claims, conflicts, and
  receipts as one signed, content-addressed bootstrap-manifest event.
- `ostk-observer-run` runs the exhaustive observer over one enum at one exact
  commit and emits a run receipt and typed observer result.
- `ostk-authority-install` takes one physical scope to an active generation-2
  registry head, or with `apply --target generation-3` to the generation-3
  collected-items package ([ADR 0008](../adr/0008-collected-items.md)), and
  prints the writer-authority pins. It runs as the schema owner/migrator, like
  `migrate`, and its fixture-key signatures are nominal; see the
  [writer-authority installer](../CONTROL_BOOTSTRAP.md#writer-authority-installer).
- `ostk-spec` runs the spec conformance chain (Stage 6):
  - `draft` binds exact byte spans of a spec document at one commit to a
    typed expectation (an enum in a Rust source file must or must not declare
    a member) under the active registry head;
  - `approve` signs the draft offline with one approver's Ed25519 seed;
  - `activate` verifies the approvals under the active activation policy,
    with `accepted_at` taken from the database clock, and compare-and-sets
    the statement into its binding family;
  - `check` judges one commit against the statement in force: it reads the
    source file the statement names through a memory-worker git source, runs
    the genesis-admitted observer, records one check (`conforming`,
    `nonconforming`, or `unknown` with reasons), and opens a
    `spec_nonconformance` discrepancy episode only for a verified
    nonconformance;
  - `episode resolve` and `episode dismiss` close an episode, which no check
    does (a fixing commit checks as `unknown`). `resolve` cites accepted
    events, or by default the latest check of the violated statement when
    that check can stand for a fix (an exhaustive check, not nonconforming,
    of a commit never judged nonconforming, recorded after the check that
    opened the episode). `dismiss` takes a reason and a rationale. Either
    appends a lifecycle event to the episode's history once (a retried
    closure reports the recorded one, and a closed episode is not closed
    again), after which `recall(discrepancies)` lists the episode only with
    `include_resolved`.

  Every subcommand except `approve`, which reads no environment, runs as
  `fleet_writer` (`FLEET_RECALL_DATABASE_URL`) with the writer-authority pins
  `ostk-authority-install apply` prints, and `check` also needs
  `FLEET_RECALL_CONTENT_KEK_HEX`. Its approvals are nominal: the active
  policy names the public fixture keys (seeds `0x01`/`0x02`), so anyone can
  produce both approvals, and the real gate is the `fleet_writer` credential
  `activate` needs. The observer `check` runs is attested only nominally too:
  its admitted executable digest is copied from the admission, never measured
  from the binary. See
  [ADR 0007 D10](../adr/0007-spec-conformance-chain.md).

The grants and gates these tools rely on are described in
[migration operations](../MIGRATIONS.md) and
[security policy](../SECURITY.md).
