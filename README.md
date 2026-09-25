# ostk-fleet-recall

> **Agents are replaceable. Their memory shouldn't be—and when two disagree,
> memory should say so.**

Fleet Recall is distributed, conflict-aware shared memory for agent fleets. It
keeps a durable semantic corpus and a typed-claim ledger in CockroachDB and
serves them over the two-tool Recall MCP contract, `recall` and `remember`, so
agents running in different processes and on different hosts can share what
they know, record what they decided, and see when they disagree. It works with
any MCP client; OSTK orchestration is an optional integration, not an install
or runtime requirement.

[`ostk-recall`](https://github.com/os-tack/ostk-recall) remains the private,
local-first corpus powered by LanceDB and SQLite. Fleet Recall is its
distributed sibling for agents that need to share memory across processes and
hosts ([ADR 0001](docs/adr/0001-product-and-backend-boundary.md)). The project
started as a CockroachDB AI Agents Hackathon entry.

## What runs today

The `ostk-fleet-recall` binary has these commands:

- `serve` speaks newline-delimited JSON-RPC/MCP on stdin/stdout with two tools:
  - `recall(search|get|conflicts|status)` reads the hybrid vector/lexical
    corpus and typed-claim state. `get` with `kind=conflict` returns one
    conflict by id in any state, with its members and its lifecycle history.
    Every conflict the private writer returns carries a `lifecycle` overlay:
    who acknowledged or waived it, and who closed it and how.
  - `recall(search|get, kind=evidence)` searches the connector evidence the
    [memory worker](#memory-worker) admits (git history, agent transcripts,
    CI runs). It is served wherever migration 30 is applied and the writer
    login holds the Stage-5 grants; elsewhere `tools/list` is unchanged.
    Every answer carries readiness, each source's status and newest coverage
    cursor, and an absence verdict: `absent` only when nothing matched over a
    current lexical tier with every source healthy, fresh, and completely
    covered, otherwise `unknown` with the reasons. `recall(status)` then adds
    an `evidence` block
    ([ADR 0006](docs/adr/0006-stage5-worker-and-evidence-recall.md)).
  - `recall(discrepancies)` lists the `spec_nonconformance` episodes
    `ostk-spec check` opened: by default those still open, acknowledged, or
    waived for a spec in force or scheduled to take effect, each with the
    statement it violates (spec document, cited spans, expectation) and the
    commit its check observed. `include_resolved` adds closed episodes and
    those of specs no longer in force (retired, superseded, or past their
    `effective_until`); `id` returns one episode with its lifecycle history.
    Every answer also carries each live spec's latest check (`nonconforming`,
    `conforming`, or `unknown` with reasons) and whether it is in force,
    scheduled, or expired at the database's time, because episodes record
    verified nonconformance only: an empty list is not proof of conformance. It is served wherever
    migration 31 is applied and the writer login may read the discrepancy,
    normative, and spec tables; elsewhere `tools/list` is unchanged.
    `recall(status)` then adds a `spec_conformance` block
    ([ADR 0007](docs/adr/0007-spec-conformance-chain.md)).
  - `remember(record)` records a deliberate typed claim with provenance,
    idempotent mutation receipts, and conflict detection.
  - `remember(retract)` retires a claim the calling agent authored. When no
    incompatible lifecycle-current pair remains on the claim's key, the
    detector closes that key's conflict and returns its disputed members to
    `active`.
  - `remember(supersede)` replaces a claim the calling agent authored with a
    successor of the same kind, key, and conflict eligibility. The predecessor
    becomes `superseded` and names its successor, which the detector checks
    like any recorded claim: a compatible successor lets the key's conflict
    close, and an incompatible one takes its predecessor's place in it.
  - `remember(acknowledge)` records that the calling agent has seen a
    conflict's current episode. It changes no claim and no conflict.
  - `remember(resolve)` concedes a conflict: it retracts the calling agent's
    own member claims it names, and closes the conflict only if the detector
    then finds no incompatible current pair. Otherwise nothing changes.
  - `remember(dismiss)` and `remember(waive)` are adjudication, off unless
    the deployment sets `FLEET_RECALL_CONFLICT_ADJUDICATION=enabled`. Only an
    agent that authored none of a conflict's member claims may use them.
    `dismiss` closes the conflict as not a real disagreement and returns its
    members to `active`; `waive` accepts its current episode until an expiry,
    and the conflict stays open and visible, reading `waived`.
- `demo` serves a bounded, read-only HTTP surface (`/`, `/healthz`,
  `/api/status`, and `POST /api/recall`). It exposes no mutation route.
- `migrate` applies the embedded CockroachDB schema migrations.
- `health` checks connectivity, the schema prefix, the required indexes,
  cosine support, and the active model identity.
- `ingest` is a trusted operator command that loads NDJSON into the active
  chunk corpus.
- `worker --once` runs one tick of the [memory worker](#memory-worker): it
  ingests the configured git refs, agent transcripts, and CI workflow runs as
  accepted evidence, then projects them into the body, lexical, and dense
  recall tiers.
- `model-digest` prints the versioned digest of a local model bundle.

Recall is hybrid: CockroachDB `VECTOR(512)` C-SPANN search and a stored
`TSVECTOR` inverted index, fused with reciprocal-rank fusion, over embeddings
from a pinned local model2vec model. Every claim mutation commits its claim,
support, conflict, receipt, corpus projection, and audit events in one
serializable transaction.

Conflict detection uses the `same_key_functional_value_v2` detector. A claim
key (`subject::predicate`) is functional over overlapping effective intervals:
two affirmations conflict when their typed values differ, an affirmation and a
negation conflict only when they name the same value, and two negations are
compatible. Conflicting claims become `disputed`, and recall surfaces the open
conflict with the exact members that caused it instead of silently choosing
one. The detector compares typed propositions; it performs no natural-language
inference.

A conflict is never resolved by fiat. An agent can retract, supersede, or
concede only its own claims, and a conflict closes only when the detector
re-checks the key and finds no incompatible current pair left
([ADR 0004](docs/adr/0004-serving-conflict-lifecycle.md)). The one exception
is adjudication, which a deployment must enable: an agent that authored none
of a conflict's members may dismiss it as not a real disagreement, and the
pairs it judged never keep that conflict open again. A later close that leaves
such pairs out says so with `resolution_kind` `no_undismissed_incompatibility`
instead of `no_current_incompatibility`. No action changes another agent's
claim value, author, or applicability, but every close returns the conflict's
disputed members, whoever wrote them, to `active` at a new revision (unless
another open conflict still holds them). Acknowledgements, waivers,
dismissals, and detector-verified closes are appended to a per-conflict
lifecycle log (migration 0029). The writer serves `acknowledge`, `resolve`, adjudication, the
overlay, and history only when its startup probe finds that log and the
runtime grants on it; otherwise it serves `retract` and `supersede` alone and
closes are audited in `memory_events` only.
On the private writer, chunk search also drops the synthetic `claim:{id}` hits of
claims that are no longer current, lists them in
`diagnostics.retrieval.lifecycle_hidden_claim_ids`, and refills the page from
lower-ranked results. Setting `FLEET_RECALL_REMEMBER_LIFECYCLE=disabled` (the
default is `enabled`) restores the record-only surface: the historical
`tools/list` byte for byte and unfiltered chunk search. The public demo always serves that record-only
surface.

The service contract also reserves further Recall actions (for example
`remember` forget/relate and `recall` surface/discover) and an attention
schema. These return an error or are unused today; see the
[roadmap](docs/ARCHITECTURE.md#roadmap-and-open-work).

## Private operator CLIs

`src/bin` holds private workstation tools. None is copied into the production
image or wired into Terraform, ECS, the public HTTP service, or normal
MCP/runtime startup, and each reads a dedicated private database URL instead
of the serving one.

- `ostk-control-bootstrap` accepts the out-of-band-pinned genesis bootstrap
  receipt into the append-only control ledger (Stage 2); see
  [private control-ledger bootstrap](docs/CONTROL_BOOTSTRAP.md).
- `ostk-registry-activate` performs the genesis Stage-3 registry activation.
- `ostk-registry-successor-activate` applies or inspects the one-time
  genesis-to-first-successor (`0 -> 1`) registry transition.
- `ostk-registry-generic-successor-activate` applies or inspects every later
  `N -> N+1` registry transition.
- `ostk-conflict-reconcile` is apply-only and materializes a new v2 conflict
  lineage for one immutable legacy conflict revision.
- `ostk-bootstrap-manifest-import` admits legacy chunks, claims, conflicts, and
  receipts as one signed, content-addressed bootstrap-manifest event.
- `ostk-observer-run` runs the exhaustive observer over one enum at one exact
  commit and emits a run receipt and typed observer result.
- `ostk-authority-install` takes one physical scope to an active generation-2
  registry head and prints the writer-authority pins. Unlike the tools above,
  it reads `FLEET_RECALL_DATABASE_URL` as the schema owner/migrator login,
  the same convention as `migrate`. Its fixture-key signatures are nominal; see
  [writer-authority installer](docs/CONTROL_BOOTSTRAP.md#writer-authority-installer).
- `ostk-spec` makes a spec statement normative (Stage 6): `draft` binds exact
  byte spans of a spec document at one commit to a typed expectation (an enum
  in a Rust source file must or must not declare a member) under the active
  registry head; `approve` signs the draft offline with one approver's
  Ed25519 seed; `activate` verifies the approvals under the active activation
  policy, with `accepted_at` taken from the database clock, and
  compare-and-sets the statement into its binding family; `check` judges one
  commit against the statement in force: it reads the source file the
  statement names through a memory-worker git source, runs the
  genesis-admitted observer, records one check (`conforming`,
  `nonconforming`, or `unknown` with reasons), and opens a
  `spec_nonconformance` discrepancy episode only for a verified
  nonconformance. No check closes an episode (a fixing commit checks as
  `unknown`), so `episode resolve` lets an operator resolve one, citing
  accepted events or by default the latest check of the violated statement
  when that check can stand for a fix (an exhaustive check, not
  nonconforming, of a commit never judged nonconforming, recorded after the
  check that opened the episode), and `episode dismiss` dismisses one with a
  reason and a rationale; either appends a lifecycle event to the episode's
  history once (a retried closure reports the recorded one, and a closed
  episode is not closed again), after which `recall(discrepancies)` lists it
  only with `include_resolved`.
  `draft`, `activate`, `check`, and `episode` run as `fleet_writer`
  (`FLEET_RECALL_DATABASE_URL`) with the writer-authority pins
  `ostk-authority-install apply` prints, and `check` also needs
  `FLEET_RECALL_CONTENT_KEK_HEX`; `approve` reads no environment. Its
  approvals are nominal: the active policy names the public fixture keys
  (seeds `0x01`/`0x02`), so anyone can produce both approvals, and the real
  gate is the `fleet_writer` credential `activate` needs. The observer
  `check` runs is attested only nominally too: its admitted executable
  digest is copied from the admission, never measured from the binary. See
  [ADR 0007 D10](docs/adr/0007-spec-conformance-chain.md).

The grants and gates these tools rely on are described in
[migration operations](docs/MIGRATIONS.md) and
[security policy](docs/SECURITY.md).

## Memory worker

`ostk-fleet-recall worker --once --sources <file> [--steps <groups>]` runs one
tick of the memory worker for the configured `(tenant, project)` and exits.
Each tick ingests every configured source and then projects what was
admitted, in this order:

- `ingest`: each transcript file, git ref, and CI workflow becomes its own
  connector instance. The worker admits new provider material as accepted
  evidence under a freshly verified generation-2 head, writes coverage
  receipts for what it read, and updates each source's status row in
  `memory_worker_sources_v1`.
- `project`: the body projector, then the lexical tier.
- `embed`: the dense tier, through the pinned model2vec embedder.

`--steps` takes a comma-separated list of those groups, or `all` (the
default). A failure stays inside its source or step: the worker records it
and continues. The tick's report goes to stdout as one JSON line, covering
every step's status and counters and every source's outcome and error. The
exit status is 1 when any step failed. A configuration or privilege problem
stops the run before the tick, prints no report, and also exits 1.

The command reads:

- the same writer configuration as `serve`: `FLEET_RECALL_DATABASE_URL` as
  `fleet_writer`, `FLEET_RECALL_TENANT_ID`, `FLEET_RECALL_PROJECT`,
  `FLEET_RECALL_AGENT`, and the model bundle variables;
- for `ingest` and `project`: the writer-authority pins that
  `ostk-authority-install apply` prints, and `FLEET_RECALL_CONTENT_KEK_HEX`;
- for `embed`: the pinned model bundle. Every dense row records
  `FLEET_RECALL_EMBEDDING_MODEL_SHA256`.

It needs migrations through 0030 and `deploy/cockroach/runtime-role-grants.sql`.
Before the tick it checks every privilege the selected steps use and names
the first one missing.

The git step runs `git` and the CI step runs `gh` (with the operator's `gh`
credential). The production image has neither, so run the ingest steps on a
host that has both tools, the repositories, and the transcript files.
`--steps project,embed` needs neither and is safe to run in the container.
[`examples/worker-sources.json`](examples/worker-sources.json) shows a sources
file with one source of each kind.

Each transcript file is read in windows of its group's `window_bytes` (4 MiB
by default, at most 8 MiB) behind a durable cursor. A line longer than the
window fails that file's source, naming the byte offset, until the group's
`window_bytes` is raised past the line; nothing after it is read meanwhile.
Turns staged from earlier windows are still admitted.

A CI source reads at most 512 settled runs per tick, starting after its
highest recorded window, or at its `first_run_number` (1 by default) when that
is higher. Until a tick reaches the newest settled run, the source's newest
receipt is partial and evidence answers stay `unknown`. `gh run list` reaches
back at most 1000 runs from the head, so for a workflow with a longer history,
set `first_run_number` near its current run number. Otherwise the source fails
with an error naming the lowest value the listing can reach. The worker never
skips runs on its own, and runs below `first_run_number` are never read.

A scope has exactly one sources file, and all of its ingest runs from one
host. When all three ingest steps run, the worker retires every active status
row whose instance its sources file does not configure. Two sources files for
one scope, say git and CI on one host and transcripts on another, would
retire each other's sources, and evidence recall would then vouch for an
empty answer from one host's sources alone.

The `project` step decrypts each governed content object with
`FLEET_RECALL_CONTENT_KEK_HEX` and writes its bytes in plaintext to
`memory_body_objects_v1`. The writer login, and so `serve`, can read that
table without the key. Once a body is projected, the key no longer limits
who can read it, and destroying the key no longer erases it: erasure must
also purge the body rows and the lexical and dense rows derived from them.
Git ingress redaction is deferred, so git bodies are raw commit text. The
lexical tier's recall text, which is all evidence recall returns, is
redacted; the body bytes are not.

There is no long-running loop, so `--once` is required. Schedule the command
with cron, a systemd timer, or a scheduled task, and run one worker per scope
at a time. For example, with the environment above in the crontab:

```text
*/15 * * * * ostk-fleet-recall worker --once --sources /etc/fleet-recall/worker-sources.json >>/var/log/fleet-recall/worker.jsonl
```

## Built but not yet wired

A larger dynamic-memory plane, specified in
[Dynamic corpus and causal runtime architecture](docs/DYNAMIC_MEMORY_ARCHITECTURE.md),
exists as library code with live CockroachDB tests, but no serving binary runs
it:

- the Stage-4 evidence ledger (`src/evidence_ledger`): accepted-event append,
  ingress quarantine, the envelope-encrypted governed content store (whose
  protection ends at projection: the worker's `project` step writes bodies in
  plaintext, see [memory worker](#memory-worker)), and the writer-authority
  witness;
- relation projection (`src/relation_projection`);
- connectors for git history, agent transcripts, and CI runs
  (`src/connectors`);
- the content-addressed body store and projector (`src/body_store`) and the
  lexical-first/dense-later recall projectors with per-row visibility
  (`src/projectors`), including `ChunkEmbedderProvider`, the production
  embedding provider that puts the pinned model2vec embedder behind the dense
  projection's `EmbeddingProvider` seam;
- the coverage runtime (`src/coverage_runtime`);
- the memory worker (`src/worker`), which the `worker --once` subcommand runs
  (see [memory worker](#memory-worker)). `serve` reads its projections
  through evidence recall;
- the evidence recall read library (`src/evidence_recall`) over those
  projections: a search returns hits with a snippet of recall text, readiness
  (evidence waiting for projection, transcript turns waiting in the outbox,
  lexical and dense currency), every active source's status and newest
  coverage cursor, and an absence verdict that is `absent` only when nothing
  matched over a current lexical tier with every source healthy, fresh, and
  completely covered, and `unknown`, with reasons, otherwise.
  `probe_evidence_recall` gates it on migration 30 and SELECT on every table
  it reads. `serve` answers `recall(kind=evidence)` through it wherever the
  probe passes ([ADR 0006](docs/adr/0006-stage5-worker-and-evidence-recall.md));
- the normative activation, observer, and discrepancy runtimes
  (`src/normative_runtime`, `src/observer_runtime`,
  `src/discrepancy_runtime`); only the observer has a runner, the private
  `ostk-observer-run`;
- `remember(action="assert")`, which the service routes but rejects because
  serving does not load a writer-authority configuration yet;
- the bootstrap-manifest import (`ostk-bootstrap-manifest-import`), which
  admits legacy chunks, claims, conflicts, and receipts as one signed event
  and records each imported row in `memory_bootstrap_import_rows`
  (migration 0028);
- contract vectors and pure contract modules for later stages (for example
  action, causal, consolidation, erasure, telemetry, and ledger epochs) under
  `contracts/dynamic-memory/v3` and `src/memory_contracts`.

Wiring this plane into the product needs, at minimum:

- the publication grant on the filtered views from migration 23 (the runtime
  policy in `deploy/cockroach/runtime-role-grants.sql` already grants
  `fleet_runtime` the tables from migrations 19–27 and 29–31; see
  [MIGRATIONS.md](docs/MIGRATIONS.md#privilege-separation)), and a content
  key-encryption key for the governed content store;
- a lighter writer-authority seam: evidence appends are authorized through the
  `memory_writer_authority_v1` view, whose rows only the signed registry
  ceremony writes today.

## Deployment

The checked-in AWS Terraform provisions ECS/Fargate task definitions and a
service, an ALB behind CloudFront, ECR, IAM roles, and CloudWatch logging. Tasks
load the pinned model from a private S3 prefix and receive separate migrator,
private-writer, or publication-reader database URLs from Secrets Manager
secrets created outside Terraform. The module passes `terraform validate` and
its Terraform tests, but its current form has not been applied. See the
[AWS Terraform runbook](deploy/aws/README.md),
[cloud onboarding](docs/CLOUD_ONBOARDING.md), and the
[LocalStack harness](deploy/localstack/README.md), which builds the real image
and exercises its S3 and Secrets Manager interfaces against a local
CockroachDB.

## Local quickstart

This path starts one disposable CockroachDB node, loads the pinned 512-dimension
model, ingests the synthetic demo corpus, exercises HTTP recall, and makes real
MCP calls. A single node is useful for application development; it does not
demonstrate CockroachDB's production availability or distributed topology.

### Prerequisites

- [Rust](https://rustup.rs/) 1.94 or newer, including Cargo, rustfmt, and
  Clippy. The crate's MSRV is 1.94.
- [Docker Engine](https://docs.docker.com/engine/install/). Docker Desktop is
  sufficient on macOS and Windows.
- CockroachDB 26.2.3. The quickstart uses the pinned official Docker image and
  invokes `cockroach sql` inside it, so a separate host CLI install is not
  required.
- The official Hugging Face
  [`hf` CLI](https://huggingface.co/docs/huggingface_hub/main/en/guides/cli).
- `curl` and `jq` for the HTTP smoke calls.
- Approximately 3 GB free for Rust dependencies, the CockroachDB image/data,
  and the 129 MB model weights.

Run all commands below from the repository root. First build the locked Rust
dependency graph:

```bash
rustc --version
cargo build --locked
export FLEET_RECALL_BIN="$PWD/target/debug/ostk-fleet-recall"
```

### 1. Acquire and pin the local embedding model

Fleet Recall uses MinishLab's
[`potion-retrieval-32M`](https://huggingface.co/minishlab/potion-retrieval-32M)
model, published under the MIT license. The command below pins the model
repository to commit
[`6fc8051fab2a1e0ee76689cf08c853792ac285e7`](https://huggingface.co/minishlab/potion-retrieval-32M/tree/6fc8051fab2a1e0ee76689cf08c853792ac285e7)
instead of following a mutable branch:

```bash
export FLEET_RECALL_MODEL_REVISION=6fc8051fab2a1e0ee76689cf08c853792ac285e7
export FLEET_RECALL_MODEL_STAGE="$PWD/.model-stage/potion-retrieval-32M"
export FLEET_RECALL_MODEL_DIR="$PWD/.models/potion-retrieval-32M-$FLEET_RECALL_MODEL_REVISION"

mkdir -p "$FLEET_RECALL_MODEL_STAGE" "$FLEET_RECALL_MODEL_DIR"
hf download minishlab/potion-retrieval-32M \
  config.json model.safetensors tokenizer.json \
  --local-dir "$FLEET_RECALL_MODEL_STAGE" \
  --revision "$FLEET_RECALL_MODEL_REVISION"

for file in config.json model.safetensors tokenizer.json; do
  cp -L "$FLEET_RECALL_MODEL_STAGE/$file" "$FLEET_RECALL_MODEL_DIR/$file"
  test -f "$FLEET_RECALL_MODEL_DIR/$file" && test ! -L "$FLEET_RECALL_MODEL_DIR/$file"
done
```

`hf download --local-dir` is the official local-folder flow. The explicit
`cp -L` creates a release bundle of regular, dereferenced files even if a local
Hugging Face cache uses links. Fleet Recall rejects a required bundle entry if
it is a symlink or not a regular file.

The repository revision pins the upstream source; Fleet Recall separately
pins the exact runtime bytes. Compute its domain-separated digest:

```bash
export FLEET_RECALL_EMBEDDING_MODEL_SHA256=$(
  "$FLEET_RECALL_BIN" model-digest "$FLEET_RECALL_MODEL_DIR"
)
printf '%s\n' "$FLEET_RECALL_EMBEDDING_MODEL_SHA256"
```

The digest covers the filename, size, and contents of exactly `config.json`,
`model.safetensors`, and `tokenizer.json`, sorted under the
`ostk-fleet-recall-model-bundle-v1` domain. Unrelated directory entries and the
host path are excluded. `migrate`, `ingest`, `health`, `demo`, and `serve`
verify this digest; model-loading paths verify before and after loading. The
database registry identity is the stable logical model ID plus this digest,
never a machine-specific path.

If maintainers intentionally advance the Hugging Face revision, keep the new
revision explicit, recompute the Fleet Recall digest, and use a new empty or
fully re-embedded corpus generation. Do not silently change model bytes under
an existing corpus.

### 2. Start a local CockroachDB 26.2 node

The image and command match the repository's live-test target and CockroachDB's
[`start-single-node`](https://www.cockroachlabs.com/docs/stable/cockroach-start-single-node)
development flow:

```bash
docker volume create ostk-fleet-recall-crdb
docker run --detach \
  --name ostk-fleet-recall-crdb \
  --hostname ostk-fleet-recall-crdb \
  --add-host cockroach:127.0.0.1 \
  --publish 127.0.0.1:26257:26257 \
  --publish 127.0.0.1:8081:8080 \
  --volume ostk-fleet-recall-crdb:/cockroach/cockroach-data \
  --volume "$PWD/deploy/cockroach:/localstack:ro" \
  cockroachdb/cockroach:v26.2.3 \
  start-single-node \
  --insecure \
  --http-addr=ostk-fleet-recall-crdb:8080 \
  --store=/cockroach/cockroach-data

FLEET_RECALL_CRDB_READY=0
for _attempt in $(seq 1 120); do
  if docker exec ostk-fleet-recall-crdb \
    cockroach sql --insecure --host=127.0.0.1:26257 \
    --execute='SELECT 1' >/dev/null 2>&1; then
    FLEET_RECALL_CRDB_READY=1
    break
  fi
  if [ "$(docker inspect --format '{{.State.Running}}' ostk-fleet-recall-crdb 2>/dev/null)" != true ]; then
    docker logs ostk-fleet-recall-crdb
    exit 1
  fi
  sleep 1
done
if [ "$FLEET_RECALL_CRDB_READY" -ne 1 ]; then
  docker logs ostk-fleet-recall-crdb
  exit 1
fi

docker exec ostk-fleet-recall-crdb \
  cockroach sql --insecure --host=127.0.0.1:26257 \
  --execute='
    CREATE DATABASE IF NOT EXISTS fleet_recall;
    CREATE USER IF NOT EXISTS fleet_migrator;
    ALTER USER fleet_migrator WITH LOGIN NOCREATEDB NOCREATEROLE;
    GRANT admin TO fleet_migrator;
  '
```

The SQL endpoint is `127.0.0.1:26257`; the local DB Console is
<http://127.0.0.1:8081>. The named volume keeps local data across container
restarts.

This node has no TLS, authentication, replication, or production isolation.
Fleet Recall accepts an insecure database URL only when
`FLEET_RECALL_ALLOW_INSECURE_LOCAL_DATABASE=1` and the host is loopback (or the
Compose-only `cockroach` hostname). Production configuration must omit that
escape hatch and use `sslmode=verify-full`.

### 3. Migrate through the private schema capability

Set every required runtime coordinate. Tenant, project, and agent are
deployment authority, not request routing fields. The sample tenant is non-nil;
generate a different stable UUID for every real fleet.

```bash
local_pg_scheme=postgresql
local_migrator_password=local-migrator-only
export FLEET_RECALL_DATABASE_URL="${local_pg_scheme}://fleet_migrator:${local_migrator_password}@127.0.0.1:26257/fleet_recall?sslmode=disable"
export FLEET_RECALL_ALLOW_INSECURE_LOCAL_DATABASE=1
export FLEET_RECALL_TENANT_ID=0198a849-f6ae-7d61-9800-000000000001
export FLEET_RECALL_PROJECT=quickstart
export FLEET_RECALL_AGENT=quickstart-agent
export FLEET_RECALL_MAX_CONNECTIONS=4
export FLEET_RECALL_EMBEDDING_MODEL=minishlab/potion-retrieval-32M
export FLEET_RECALL_EMBEDDING_MODEL_PATH="$FLEET_RECALL_MODEL_DIR"
export RUST_LOG=ostk_fleet_recall=info
```

This migrator URL is the only database capability in the process while it
applies the embedded schema. Do not start the public demo yet:

```bash
"$FLEET_RECALL_BIN" migrate
```

`migrate` applies every embedded migration in [`migrations/`](migrations) in
order. Most run without a wrapping SQL transaction because of CockroachDB
schema-changer and schema-lock constraints, so an interruption can leave
committed DDL behind; versions 12 through 14 run transactionally on a
dedicated migration session with `autocommit_before_ddl = false`. Never run
multiple migrators concurrently or run the migration files manually as a
substitute for that policy. See
[migration and recovery rules](docs/MIGRATIONS.md) before recovering a failed
migration.

`migrate` is the only command that authenticates as `fleet_migrator`.
`ingest`, `health`, and `serve` accept only the private `fleet_writer` login,
which does not exist until the next step provisions it.

### 4. Establish the database boundary and load the corpus as the writer

The checked-in boundary helper retires the migrator login, provisions the
private `fleet_writer` and the fixed `fleet_publication` login, applies the
reviewed runtime and publication-reader policies from `deploy/cockroach/`, and
only then enables the two logins. On a shared or production cluster, follow
the audit and change-freeze steps in [migration operations](docs/MIGRATIONS.md)
instead:

```bash
docker exec --interactive ostk-fleet-recall-crdb \
  /bin/sh -s < deploy/localstack/database-boundary.sh
```

Replace the retired migrator URL with the DML-only writer the helper
provisioned, and keep every other coordinate from step 3. Load the included
non-sensitive corpus and check readiness as that writer:

```bash
local_writer_password=local-writer-only
export FLEET_RECALL_DATABASE_URL="${local_pg_scheme}://fleet_writer:${local_writer_password}@127.0.0.1:26257/fleet_recall?sslmode=disable"

"$FLEET_RECALL_BIN" ingest --input examples/demo.ndjson
"$FLEET_RECALL_BIN" health
```

### 5. Exercise the HTTP demo

The public demo refuses to start while a private database URL is set. Remove
the writer URL and give it only the fixed publication login:

```bash
unset FLEET_RECALL_DATABASE_URL
local_publication_password=local-publication-only
export FLEET_RECALL_PUBLICATION_DATABASE_URL="${local_pg_scheme}://fleet_publication:${local_publication_password}@127.0.0.1:26257/fleet_recall?sslmode=disable"
```

The demo now has only its publication URL. On every new and reused pooled
connection it re-witnesses the fixed login, database, application name, and
canonical search path before any recall SQL runs. Start the local server, wait
for readiness, recall the ingested idea, and stop it:

```bash
"$FLEET_RECALL_BIN" demo --listen 127.0.0.1:8088 &
FLEET_RECALL_DEMO_PID=$!

FLEET_RECALL_DEMO_READY=0
for _attempt in $(seq 1 120); do
  if curl --fail --silent http://127.0.0.1:8088/healthz >/dev/null; then
    FLEET_RECALL_DEMO_READY=1
    break
  fi
  if ! kill -0 "$FLEET_RECALL_DEMO_PID" 2>/dev/null; then
    wait "$FLEET_RECALL_DEMO_PID"
    exit 1
  fi
  sleep 1
done
if [ "$FLEET_RECALL_DEMO_READY" -ne 1 ]; then
  kill "$FLEET_RECALL_DEMO_PID" 2>/dev/null || true
  wait "$FLEET_RECALL_DEMO_PID" || true
  exit 1
fi

curl --fail --silent --show-error http://127.0.0.1:8088/api/status | jq
curl --fail --silent --show-error \
  --header 'content-type: application/json' \
  --data '{"query":"What happens when fleet agents disagree?","limit":5}' \
  http://127.0.0.1:8088/api/recall | jq

kill "$FLEET_RECALL_DEMO_PID"
wait "$FLEET_RECALL_DEMO_PID" || true
```

The HTTP service exposes only `/`, `/healthz`, `/api/status`, and bounded
`POST /api/recall`. It is a demonstrator, not an authenticated multi-tenant
control plane. Its recall cards render the bounded inline Markdown retained by
the corpus and link every repository-backed documentation or code chunk to the
immutable source commit and exact inclusive line range recorded at ingestion;
synthetic records without a checked-in source stay visibly unlinked.

### 6. Exercise the MCP server

`serve` speaks newline-delimited JSON-RPC/MCP on stdin/stdout. The following is
a complete direct smoke exchange. Keep each JSON request on one physical line;
the initialized notification intentionally has no response. The public
capability is removed first and the step 4 writer URL restored, because MCP
includes the private `remember` tool; the boundary helper provisioned this
DML-only writer without DDL authority.

```bash
unset FLEET_RECALL_PUBLICATION_DATABASE_URL
local_writer_password=local-writer-only
export FLEET_RECALL_DATABASE_URL="${local_pg_scheme}://fleet_writer:${local_writer_password}@127.0.0.1:26257/fleet_recall?sslmode=disable"

"$FLEET_RECALL_BIN" serve <<'JSONRPC'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"readme-smoke","version":"1.0.0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}
{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"recall","arguments":{"action":"search","scope":{"project":"quickstart","agent":"quickstart-agent","session_id":"readme","privacy_tier":"t1_project"},"query":"How does fleet memory survive agent restarts?","kind":"chunk","limit":5}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"remember","arguments":{"action":"record","scope":{"project":"quickstart","agent":"quickstart-agent","session_id":"readme","privacy_tier":"t1_project"},"idempotency_key":"readme/single-migrator/v1","kind":"decision","text":"Fleet schema migration runs through one dedicated migrator before serving traffic.","subject":"fleet deployment","predicate":"migration strategy","value":"single dedicated migrator","actor":"quickstart-agent"}}}
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"recall","arguments":{"action":"search","query":"How should schema migration run?","kind":"claim","limit":5}}}
JSONRPC
```

Rerunning the same `remember` request with the same tenant-wide idempotency key
returns the stored mutation with `idempotent_replay` set and does not create a
second durable mutation. A changed full request using that key is rejected.
This is at-most-one committed mutation behavior, not exactly-once response
delivery; after an ambiguous response, retry the same full request and key.

To retire a claim it authored, an agent sends `remember(retract)` with the
claim id and the revision it last read, for example from `recall` `get` with
`kind=claim`. `reason` is an optional private audit note of at most 1,000
characters. On a writer that serves the conflict lifecycle log (below), a
retract or supersede that closes a conflict also records the note as the
close's cause in that conflict's history, which every agent in the project can
read:

```json
{"action":"retract","idempotency_key":"readme/retract/v1","claim_id":41,"expected_revision":2,"reason":"superseded by the migration review"}
```

The response's `data` holds the retracted `claim` and `conflicts_resolved`,
plus `claims_restored` when the close returned members to `active`. When the
key had an open conflict, `reevaluation` says whether it `closed` or is
`still_open` and which incompatible pairs remain. `conflicts` lists every
affected conflict in any state. Replays follow the same idempotency rules as
`record`, and a key used by one action (`record`, `retract`, or `supersede`)
cannot be reused for another.

The server checks the claim under row locks and refuses the request, before
anything is written, when the caller is not its author (`not_owner`), the claim
is not an `operator_asserted` assertion (`not_operator_asserted`), it is no
longer `active` or `disputed` (`not_current`), the revision moved
(`stale_revision`), no such claim exists in the project (`not_found`), its
key still has only an unreconciled legacy conflict lineage
(`legacy_lineage`), or the key has more than 256 current claims
(`bound_exceeded`). A refusal is a JSON-RPC `invalid_params` error, never an
unknown outcome, and it does not consume the idempotency key:

```json
{"code":-32602,"message":"remember(retract) refused: stale_revision: claim 41 is at revision 3 (disputed)","data":{"code":"stale_revision","outcome":"not_applied","retry":"nothing was committed and the idempotency_key was not consumed; re-read and send a corrected request","details":{"claim_id":41,"current_revision":3,"current_state":"disputed"}}}
```

To replace a claim it authored instead, an agent sends `remember(supersede)`
with the same `claim_id`, `expected_revision`, and optional `reason`, plus the
successor's `record` fields. The successor must keep the predecessor's `kind`,
its `subject`/`predicate` key after normalization (so `Fleet Store` matches
`fleet-store`), and its conflict eligibility, so a supersede can change what a
claim says but can never move it off its key or out of the detector's view:

```json
{"action":"supersede","idempotency_key":"readme/supersede/v1","claim_id":41,"expected_revision":2,"reason":"the migration review chose a single migrator","kind":"decision","text":"Fleet schema migration runs through one dedicated migrator job.","subject":"fleet deployment","predicate":"migration strategy","value":"single dedicated migrator job"}
```

A claim is conflict-eligible when it has a key, a `value`, and a `decision`,
`fact`, `constraint`, `preference`, or `procedure` kind. A keyed claim of those
kinds must therefore keep carrying a `value`, and a valueless one must not gain
one. The detector never compares a `note`, `observation`, or `open_question`,
or any keyless claim, so its successor may add or drop a `value`.

In the response, `data.claim` is the new successor and `data.superseded` is the
predecessor as the mutation left it: `{id, state:"superseded", revision,
superseded_by}`. The successor goes through the same conflict detection as a
recorded claim, so `conflicts_opened` lists a conflict it opened or reopened.
Then the key's open conflict is re-evaluated exactly as for a retract:
`conflicts_resolved`, `claims_restored`, and `reevaluation` report whether a
compatible successor let it close or an incompatible one keeps it `still_open`
with the successor as a member. The predecessor stays a historical member of
its conflicts, and `recall` `get` with `kind=claim` shows its `superseded_by`.

A supersede is refused for the same reasons as a retract, and also when the
successor changes the kind (`successor_kind_mismatch`), the normalized key
(`successor_key_mismatch`), or the conflict eligibility
(`successor_eligibility_mismatch`). A malformed successor is an ordinary
`invalid_params` error, exactly as for `record`.

To mark a conflict as seen, any agent in the project, including one whose
claim is in it, sends `remember(acknowledge)` with the conflict id and the
revision it last read, for example from `recall` `conflicts` or `get` with
`kind=conflict`:

```json
{"action":"acknowledge","idempotency_key":"readme/ack/v1","conflict_id":9,"expected_revision":1,"reason":"checking the migration runbook"}
```

An acknowledgement belongs to the conflict's current episode, its revision.
It never changes the conflict, its members, or its read side: an acknowledged
conflict still reads `open`. An agent's second acknowledgement of the same
episode commits with `applied:false` and `status:"already_acknowledged"`.
When `record` later reopens a closed conflict, the new episode starts with no
acknowledgements.

To concede, an agent sends `remember(resolve)` with the conflict's revision
and `member_count` as it read them, and `retract_claim_ids`, its own current
member claims to retract:

```json
{"action":"resolve","idempotency_key":"readme/resolve/v1","conflict_id":9,"expected_revision":1,"expected_member_count":2,"retract_claim_ids":[41],"reason":"the other value is the reviewed one"}
```

In one transaction the server retracts those claims exactly as `retract` would,
then asks the detector, in Rust and in SQL, whether any incompatible current
pair is left, not counting pairs an adjudicator dismissed in this conflict
(below). If none is, the conflict is `resolved`, its remaining disputed
members return to `active`, and the response carries `claims_retracted`,
`claims_restored`, `conflicts_resolved`, and the detector-attributed
`lifecycle_event`. If a pair is left, for example in a three-way conflict, the
whole request is refused as `still_incompatible` with the remaining `pairs`
and nothing is retracted. Omitting `retract_claim_ids` only asks the detector
to re-verify the conflict, which any agent may do. `resolve` never retracts
another agent's claim: naming one is refused as `not_owner`. The only other
claims a close touches are the disputed members it restores, whoever wrote
them: each returns to `active` at a new revision, so an agent holding one must
re-read it before sending its `expected_revision`. It is also
refused when a named claim is not a member (`not_member`) or no longer current
(`not_current`), when the conflict is closed (`not_open`), and when its
revision or member count moved (`stale_revision`, `stale_member_count`; an
open conflict gains members without a revision change).

With the lifecycle log available, every conflict `recall` returns carries a
`lifecycle` object: `state` (`open`, `acknowledged`, `waived`, `resolved`, or
`dismissed`), `read_side` (`open`, `waived`, or `clear`), the
`episode_revision` it describes, `acknowledged_by` (at most 16, with
`acknowledgers_truncated`), `waiver` for the episode's latest waiver (below),
`closed_by` for a closed conflict, or `closed_unlogged` when the close predates
the log. `conflict_coverage.lifecycle_overlay` is `evaluated`; if the overlay
read fails it is `unavailable`, a `lifecycle_overlay_unavailable` warning is
added, and the conflicts are still returned. `recall` `get` with
`kind=conflict` adds `history`, the conflict's newest events in order (at most
256, and fewer when their notes and payloads would not fit one response), with
`history_truncated` when older events were left out, and
`unlogged_transitions`, the revision ranges the conflict passed through
without a logged event, such as a reopen by `record`. Retract and supersede
closes are logged too, attributed to the detector with the caller's operation
and reason as the cause.

Adjudication is off unless the writer is started with
`FLEET_RECALL_CONFLICT_ADJUDICATION=enabled` (the default is `disabled`) and
its probe found the lifecycle log; with the switch set but no log, startup
logs an error and keeps it off. Then `tools/list` adds `dismiss` and `waive`,
for an agent that authored none of the conflict's member claims in any
episode. An author of any member is refused as `implicated`, and a conflict
with a member whose author was never recorded is refused as
`unattributed_member` for everyone, since no agent can be shown to be
uninvolved. Both actions take the conflict's revision and `member_count` as
the adjudicator read them, a `reason_kind` from the discrepancy contract's
closed vocabulary, and a required `rationale` of at most 1,000 characters,
which is kept in the conflict's lifecycle log (readable by every agent in the
project through the overlay and history) and never in the conflict row:

```json
{"action":"dismiss","idempotency_key":"readme/dismiss/v1","conflict_id":9,"expected_revision":1,"expected_member_count":2,"reason_kind":"false_positive","rationale":"the two values name different deployments of the migrator"}
```

A dismissal's `reason_kind` is `false_positive`, `duplicate_of_other_episode`,
`out_of_scope`, or `not_reproducible`. The conflict becomes `dismissed` with
`resolution_kind` `dismissed:<reason_kind>` and a fixed resolution reason, its
disputed members that no other open conflict holds return to `active`
(`claims_restored`), and a `dismissed` lifecycle event records every
incompatible current pair it judged (at most 1,024, or `bound_exceeded`). No
claim's value, author, or applicability changes. If `record` later reopens the
conflict with a new incompatible claim, the judged pairs no longer count: a
retract, supersede, or concession that leaves only dismissed pairs closes the
conflict, and its `reevaluation.excluded_dismissed_pairs` and close event
report how many were left out. A pair nobody dismissed still keeps it open.
Such a close is `resolved` by the detector, but because the dismissed pairs
are still current and still incompatible, the conflict's `resolution_kind` is
`no_undismissed_incompatibility`, not `no_current_incompatibility`. Its logged
`resolved` event keeps the reason kind `no_current_incompatibility`, the only
one the log admits for a detector close, and carries the count in its payload.
Every writer that can read the lifecycle log leaves recorded dismissals out,
including one that does not serve `dismiss` itself, such as a writer started
after adjudication was switched off.

```json
{"action":"waive","idempotency_key":"readme/waive/v1","conflict_id":9,"expected_revision":1,"expected_member_count":2,"reason_kind":"capacity_deferred","rationale":"the migrator review is scheduled for the next release","expires_in_hours":72,"review_in_hours":24}
```

A waiver's `reason_kind` is `capacity_deferred`, `cost_exceeds_risk`,
`upstream_blocked`, `policy_exception`, or `scheduled_remediation`, and it
lasts `expires_in_hours` (1 to 2,160, by the database clock), with an optional
`review_in_hours` no later than that. It changes no row: the conflict and its
members stay as they are, and the conflict keeps surfacing in every read with
its `lifecycle.waiver` context (`actor`, `reason_kind`, `rationale`,
`expires_at`, `review_by`, `review_due`, `member_count`, `active`, and
`void_reason`). It reads `waived` only while the waiver is unexpired and the
conflict still has the members it was waived with; after expiry
(`void_reason:"expired"`) or once a member joins
(`void_reason:"membership_changed"`) the same episode reads `open` again, with
the waiver kept as context. A later waiver replaces an earlier one. Both
actions are refused as `not_open` on a closed conflict and as
`stale_revision` or `stale_member_count` when the caller's view moved, and a
writer that does not serve them refuses them as `adjudication_disabled` (or
`lifecycle_unavailable` without the log) after the usual receipt check.

The log holds at most 4,096 events per conflict, and an event records at most
4,096 members. `acknowledge`, `dismiss`, and `waive`, whose record is their
event, are refused as `bound_exceeded` when the log cannot hold it, and so are
the conflict actions on a conflict with more than 4,096 members. A
detector-verified close is never refused for the log's capacity: a retract,
supersede, or resolve that closes such a conflict commits without its event (a
`resolve` response's `lifecycle_event` is then null), and the conflict reads
`closed_unlogged` with the close as an unlogged transition.

A writer that does not serve an action, such as one started with
`FLEET_RECALL_REMEMBER_LIFECYCLE=disabled` or one whose probe found no
lifecycle log, checks the key's receipt first: a request that already
committed under the key replays its stored result, any other use of the key is
an idempotency conflict, and only an unused key is refused as
`lifecycle_unavailable` (or, for `dismiss` and `waive` on a writer that serves
the conflict lifecycle, `adjudication_disabled`).

Most stdio MCP clients use a configuration shaped like the following. Replace
the absolute paths and digest; this example deliberately contains only local,
insecure development credentials. Client-specific configuration file names and
top-level keys vary.

```json
{
  "mcpServers": {
    "ostk-fleet-recall": {
      "command": "/absolute/path/to/ostk-fleet-recall/target/debug/ostk-fleet-recall",
      "args": ["serve"],
      "env": {
        "FLEET_RECALL_DATABASE_URL": "REPLACE_WITH_PRIVATE_WRITER_URL",
        "FLEET_RECALL_ALLOW_INSECURE_LOCAL_DATABASE": "1",
        "FLEET_RECALL_TENANT_ID": "0198a849-f6ae-7d61-9800-000000000001",
        "FLEET_RECALL_PROJECT": "quickstart",
        "FLEET_RECALL_AGENT": "quickstart-agent",
        "FLEET_RECALL_MAX_CONNECTIONS": "4",
        "FLEET_RECALL_EMBEDDING_MODEL": "minishlab/potion-retrieval-32M",
        "FLEET_RECALL_EMBEDDING_MODEL_PATH": "/absolute/path/to/ostk-fleet-recall/.models/potion-retrieval-32M-6fc8051fab2a1e0ee76689cf08c853792ac285e7",
        "FLEET_RECALL_EMBEDDING_MODEL_SHA256": "PASTE_MODEL_DIGEST_HERE",
        "RUST_LOG": "ostk_fleet_recall=info"
      }
    }
  }
}
```

Do not put a production CockroachDB URL into a checked-in MCP configuration.
Use the client's secret/environment facility and a TLS URL instead.

## Ingestion contract

`ingest --input PATH` reads NDJSON; `--input -` (the default) reads stdin:

```bash
"$FLEET_RECALL_BIN" ingest --input examples/demo.ndjson
"$FLEET_RECALL_BIN" ingest --input - < examples/demo.ndjson
```

Each nonblank line is one object:

```json
{"source":"markdown","source_id":"demo/architecture","text":"Fleet Recall keeps durable semantic memory in CockroachDB.","chunk_index":0,"facets":{"tags":["demo","architecture"]},"role":"primary"}
```

Required fields are `source`, `source_id`, and nonblank `text`. Optional fields
are `source_config_id` (default `fleet:ndjson:v1`), `chunk_index` (default 0),
RFC 3339 `ts`, `role` (`primary`, `evolution`, or `usage`), `links`, `facets`,
and object-valued `extra`. Unknown fields are rejected. Input cannot provide
tenant, project, agent, session, privacy, chunk ID, embedding, stale state, or
internal claim, conflict, or transcript-projection metadata. Trusted deployment
configuration supplies scope; the importer derives stable
chunk/content/embedding-input hashes.

The importer accepts at most 10,000 records, 1 MiB per physical line, 64 MiB
total input, and 256 KiB text per record, with additional facet/link bounds. It
also caps each whitespace-delimited text lexeme at 16,000 UTF-8 bytes, below
CockroachDB's 16,383-byte TSVECTOR lexeme limit. It parses, validates,
deduplicates, embeds, and vector-validates the full input before the first chunk
write. Upserts use stable IDs, so rerunning the same import is safe. A database
failure can leave a valid prefix applied; rerunning converges that prefix and
the remaining rows.

## Trust and safety boundaries

- A process is bound to one non-nil tenant, project, trusted agent, and current
  `t1_project` privacy tier. MCP may repeat project, agent, actor, or privacy as
  exact assertions; it cannot redirect them. Tenant is never a wire field.
- Session is a caller-selected subdivision under the trusted agent, not an
  authorization principal. Privacy narrowing is rejected because durable
  owner/tier row visibility is not implemented yet.
- Actor provenance is derived from the trusted deployment agent. A supplied
  `remember.actor` is only an exact assertion and is stripped at the MCP edge.
- Lifecycle authority is owner-only: `remember(retract)`,
  `remember(supersede)`, and the retractions of `remember(resolve)` change
  only an `operator_asserted` claim whose stored actor is the trusted
  deployment agent, and a successor keeps its predecessor's kind, key, and
  detector eligibility. No agent can retire another agent's claim; a close
  only returns the conflict's disputed members, whoever wrote them, to
  `active` at a new revision. A conflict closes only when the detector finds
  no incompatible lifecycle-current pair other than pairs an adjudicator
  dismissed in that conflict (such a close reads `resolution_kind`
  `no_undismissed_incompatibility`), or when an adjudicator dismisses it:
  `remember(dismiss)` and `remember(waive)` are off unless
  `FLEET_RECALL_CONFLICT_ADJUDICATION=enabled`, are refused to any author of
  any of the conflict's members, and fail closed when a member has no
  recorded author. A dismissal changes no claim's applicability, and a waiver
  changes no row at all. `remember(acknowledge)` is open to every agent
  because it changes nothing but the overlay. Every refusal rolls the whole
  transaction back. The lifecycle log is append-only for the runtime
  role and never granted to the publication reader. This authority is as
  strong as the deployment's `FLEET_RECALL_AGENT` binding over the shared
  writer credential.
- MCP frames, tool results, searches, conflict projections, claim passages,
  ingestion, and HTTP bodies/results are bounded. Backend details are redacted
  from protocol errors.
- Recalled chunks, claims, transcripts, telemetry, and Markdown are untrusted
  evidence, not instructions or authorization. Consumers must verify sources
  and apply external agent/operator policy before acting on them.
- Corpus rows use one registered 512-dimension embedding generation per
  tenant/project. A mismatched model path, digest, vector dimension, or active
  registry identity fails closed.
- Claim, support, conflict, receipt, corpus projection, and audit-event changes
  commit in one serializable mutation. Only CockroachDB SQLSTATE `40001`
  automatically retries the complete transaction.
- The serving and Stage-2 local `--insecure` database escape is
  development-only. Cloud and other non-loopback URLs must use TLS
  verification; Stage-3 activation always requires `sslmode=verify-full`, even
  on loopback.
- The HTTP demo exposes no MCP, ingest, bootstrap, activation, or mutation
  route. It also accepts only `FLEET_RECALL_PUBLICATION_DATABASE_URL` and
  rejects every private writer/control/test database variable. Its exact
  `fleet_publication_reader` role can read only the eight status/recall tables;
  it has no sequences, DML, DDL, system, delegation, or private-table
  authority. New and reused pool connections re-witness the fixed
  `fleet_publication` login, `fleet_recall` database,
  `ostk-fleet-recall-publication` application name, and canonical search path.
  Do not expose a future mutation route publicly without workload identity,
  authorization, rate limiting, and production network controls.
- In the AWS topology, CloudFront terminates viewer HTTPS with its default
  certificate (AWS fixes the generated-hostname policy at a TLSv1 minimum,
  although newer TLS can be negotiated) and reaches the ALB over restricted
  HTTP, guarded by the CloudFront origin-facing prefix list and a secret origin
  header. This is not end-to-end TLS.
- Migrations 12 through 14 reserve durable successor state, and a private
  successor repository, workstation CLI, and reviewed one-shot logical-role
  policy exist. The deny-only quarantine keeps their three tables away from
  runtime and the prior private roles. Only a separately provisioned login in
  the hardened `fleet_registry_successor_activation` role may receive the
  policy's exact table surface during an exclusive local ceremony; no AWS,
  image, startup, or serving credential is authorized. Repository code and
  contracts alone do not authorize a production write.
- The v2 conflict detector is proposition-aware: different affirmative values
  conflict; affirmation and negation conflict only for the same exact value;
  two negations are compatible. Legacy detector rows are immutable. The
  apply-only reconciliation CLI appends a separately versioned v2 lineage and
  preserves the legacy row, memberships, receipts, and transition history.

See [security and supply-chain policy](docs/SECURITY.md) and the
[architecture](docs/ARCHITECTURE.md) for the complete invariants.

## Development workflow

CI runs these checks (Rust 1.94):

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo deny check
node --test demo/tests/source-card-order.test.mjs
```

Database tests are named `live_*` and skip unless
`FLEET_RECALL_TEST_DATABASE_URL` points at a disposable CockroachDB 26.2
database. Each test migrates the schema it needs, some create roles, and the
plan test writes more than 10,000 fixture rows, so use a throwaway database and
a user with admin rights, never shared or valuable data. The conflict
reconciliation tests read `FLEET_RECONCILIATION_TEST_DATABASE_URL` instead. Run
the live tests serially:

```bash
export FLEET_RECALL_TEST_DATABASE_URL='postgresql://USER:PASSWORD@HOST:26257/DATABASE?sslmode=verify-full'
export FLEET_RECONCILIATION_TEST_DATABASE_URL="$FLEET_RECALL_TEST_DATABASE_URL"
cargo test --locked --all-targets -- live_ --test-threads=1
```

CI runs the same command against a single-node CockroachDB v26.2.3 container;
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) shows the exact setup.
`store::cockroach::tests::live_cockroach_dense_plan_uses_vector_index_when_configured`
asserts that representative dense, source-prefixed dense, and lexical queries
select their intended CockroachDB indexes. Two suites need more than the
database URL: `tests/dogfood_live.rs` also skips unless its
`FLEET_RECALL_DOGFOOD_*` inputs are set, and `tests/publication_reader_live.rs`
is `#[ignore]` and documents its environment at the top of the file.

## Documentation

- [Architecture](docs/ARCHITECTURE.md), including the roadmap and known
  technical debt.
- [Dynamic corpus and causal runtime architecture](docs/DYNAMIC_MEMORY_ARCHITECTURE.md):
  the target design for the dynamic-memory plane and its staged status.
- [Project primer](docs/PROJECT_PRIMER.md).
- [Migration operations](docs/MIGRATIONS.md) and
  [security policy](docs/SECURITY.md).
- [Private control-ledger bootstrap](docs/CONTROL_BOOTSTRAP.md).
- [Cloud onboarding](docs/CLOUD_ONBOARDING.md): AWS/CockroachDB account,
  approval, cost, identity, TLS, model, and teardown steps.
- [AWS Terraform runbook](deploy/aws/README.md) and
  [LocalStack harness](deploy/localstack/README.md).
- [Optional OSTK adapter demo](docs/OSTK_DEMO.md): coordinates bounded OSTK
  model sessions through a checked-in non-native stdio bridge; Fleet Recall
  itself requires no OSTK or LLM.
- Decision records: [product/backend boundary](docs/adr/0001-product-and-backend-boundary.md),
  [Stage-4 runtime foundations](docs/adr/0002-stage4-runtime-foundations.md),
  [consolidation and conflict tolerance](docs/adr/0003-consolidation-and-conflict-tolerance.md),
  [serving conflict lifecycle](docs/adr/0004-serving-conflict-lifecycle.md),
  [event-first assert and writer authority](docs/adr/0005-event-first-assert-and-writer-authority.md),
  [the Stage-5 worker and evidence recall](docs/adr/0006-stage5-worker-and-evidence-recall.md), and
  [the spec conformance chain](docs/adr/0007-spec-conformance-chain.md).
- [Dynamic memory contract corpus](contracts/dynamic-memory/README.md).

## Cleanup

Stop the local database while preserving its named volume:

```bash
docker stop ostk-fleet-recall-crdb
```

Restart it later with `docker start ostk-fleet-recall-crdb`. Removing the
container or volume is intentionally left as an explicit operator decision
because the volume contains the local memory corpus.

## License

Fleet Recall is available under either the Apache License 2.0 or MIT license.
The pinned MinishLab model is separately published under MIT; see its linked
model card for attribution and license metadata.
