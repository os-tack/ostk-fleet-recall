# Memory worker reference

[Documentation](../README.md) · [CLI](CLI.md) · [Configuration](CONFIGURATION.md)

Use this reference to configure sources and interpret one worker tick. For a
first run, follow [Memory pipelines](../tutorials/MEMORY_PIPELINES.md).
For an existing local HTTPS installation, start with the
[operations guide](../../deploy/local/https/OPERATIONS.md): the installed CronJob
already schedules ticks and must be coordinated with manual runs.

- [Tick order and prerequisites](#tick-order-and-prerequisites)
- [Collector configuration](#collector-configuration)
- [Transcripts and CI](#transcripts-and-ci)
- [Source ownership and projected content](#source-ownership-and-projected-content)
- [Scheduling](#scheduling)

## Tick order and prerequisites

`ostk-fleet-recall worker --once --sources <file> [--steps <groups>]` runs one
tick of the memory worker for the configured `(tenant, project)` and exits.
Each tick ingests every configured source and then projects what was
admitted, in this order:

- `ingest`: each transcript file, git ref, and CI workflow becomes its own
  connector instance. The worker admits new provider material as accepted
  evidence under a freshly verified generation-2 or generation-3 head, writes
  coverage receipts for what it read, and updates each source's status row in
  `memory_worker_sources_v1`.
- `collect`: runs each configured collector's pass, then drains the
  collector outbox (migrations 0033 and 0034,
  [ADR 0008](../adr/0008-collected-items.md) D4 and D8): items a collector
  staged are admitted under `connector.collected.<mode>` of the verified
  head, which needs a scope moved to generation 3. Below migration 34 it is
  skipped. The documents-directory collector (provider `docs`) is the first:
  each pass lists one root, stages the files whose content changed as
  sectioned parts, tombstones the ones that disappeared, and records coverage
  only when it read the whole root. The Slack collector (provider `slack`)
  pulls a workspace's channels through the Web API with a bot token, the
  Linear collector (provider `linear`) an organization's teams' issues and
  comments through the GraphQL API with an API key, and the Granola
  collector (provider `granola`) meeting notes' AI summaries (and, when
  asked, transcripts) through the public API with an API key. Last, it
  records the snapshot of every
  [import](COLLECTION.md#importing-collected-items) whose rows it admitted. `serve` reads
  what it admits as `recall(kind=item)` and `recall(kind=evidence)`.
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
  `FLEET_RECALL_AGENT`, and the pinned model configuration;
- for `ingest`, `collect`, and `project`: the writer-authority pins that
  `ostk-authority-install apply` prints, and `FLEET_RECALL_CONTENT_KEK_HEX`,
  the same key on every run and host of the scope;
- for `embed`: the pinned local model bundle, or the remote embedding URL,
  matching model name/digest and tier credential. Every dense row records
  `FLEET_RECALL_EMBEDDING_MODEL_SHA256`; the
  [embedding tier reference](../REMOTE_PLANE.md#m3-embedding-tier) describes
  remote configuration and failure behavior.

Its minimum feature gate is migration 0030 and the required runtime privileges;
the `collect` step needs migration 34 and a generation-3 head, and reads the
webhook hints of migration 36 where it is applied. Deploy the complete current
migration prefix and `deploy/cockroach/runtime-role-grants.sql` from the same
release, as the policy checks that prefix. Before the tick the worker checks
every privilege the selected steps use and names the first one missing. Each
collector's provider token comes from the variable its `settings.token_env`
names, in the worker's environment.

Configured git sources need `git`; configured CI sources need `gh` and the
operator's `gh` credential. The production image has neither, so those sources
must run on a host with their tools and repositories. Transcript-only ingest
can run in the container: the local remote-plane overlay uses
`--steps ingest,project,embed` against the mounted transcript spool with no git
or CI sources. `--steps project,embed` needs neither external tool.

## Collector configuration

### Documents

[`examples/worker-sources.json`](../../examples/worker-sources.json) shows a sources
file with one source of each kind, including a documents root:

```json
{"provider": "docs", "connector_principal": "principal.docs",
 "connector_instance": "docs.specs", "provider_scope_id": "specs",
 "audience": {"operator_declared": true},
 "settings": {"root": "/srv/fleet-recall/specs", "extensions": ["md"],
              "max_file_bytes": 1048576, "max_files": 5000}}
```

The operator declares the root visible to the whole project; the collector
refuses a root without that declaration. `extensions` is a subset of `md`,
`markdown`, `txt`, `rst`, and `adoc`; names beginning with `.` and symlinks
leading out of the root are skipped. A listing cut short by `max_files`, a
file over `max_file_bytes`, or one that is not UTF-8 leaves the root's
coverage partial, so an empty answer stays `unknown` until the next complete
pass. `ostk-spec check` reads the same file: the
git source it reads through must also carry `provider_repository_id` (the
provider's numeric repository id, from which a spec statement's subject is
derived), and the file must name an `observer` identity
(`connector_principal` and `connector_instance`) to append observer runs
under. The worker reads neither; [tutorial step 8](../tutorials/MEMORY_PIPELINES.md#8-run-the-memory-worker-over-a-scratch-repository) shows both.

### Slack

A Slack collector reads one workspace with an internal custom Slack app's
bot token; the sources file names the environment variable that holds it,
never the token:

```json
{"provider": "slack", "connector_principal": "principal.slack",
 "connector_instance": "slack.acme", "provider_scope_id": "T07ACME0001",
 "audience": {"private_containers": ["C07PRIVATE1"]},
 "settings": {"token_env": "FLEET_RECALL_SLACK_BOT_TOKEN",
              "channels": ["C07PLATENG1", "C07PRIVATE1"],
              "backfill_since": "2026-01-01T00:00:00Z", "rescan_days": 7,
              "reconcile_every_seconds": 86400, "max_pages_per_tick": 500}}
```

`provider_scope_id` pins the workspace: a token whose `auth.test` reports
another `team_id` reads nothing and fails the source. The app needs the
`channels:history`, `channels:read` (and `groups:history`, `groups:read` for
private channels) scopes and must be a member of every listed channel; a
channel it cannot read is reported partial. A public channel is visible to
the whole project; a private channel only when `audience.private_containers`
lists it; direct and group-direct conversations and Slack Connect channels
never are, and a channel that becomes private or shared is withdrawn and
hidden. Once every `reconcile_every_seconds` a pass re-reads every channel
from `backfill_since` (or its whole history) with every thread, and only that
reconciliation records coverage; the passes between read the trailing
`rescan_days` and the threads with new replies, which picks up new messages
and edits. A message missing from two consecutive complete reads is hidden as
deleted. Messages keep their exact `ts`, edits supersede, mentions and links
are rendered, and file content is never read (a file is a link, with its
token stripped). A rate limit or `max_pages_per_tick` ends a pass partial,
and the next pass resumes where it stopped: a channel's read continues
before the last message it settled, a reconciliation cut short is continued
rather than started over, and the next pass starts at the channel the last
one stopped at. A thread whose every reply was deleted has those replies
hidden too. A channel Slack no longer finds (deleted, or made private without
the app) is withdrawn and hidden unless listed.
`audience.private_containers` must name channel ids that `channels` lists.
Link unfurls are never message text. `api_base` (`https://slack.com/api` by
default) must be on Slack's own host over https, or a loopback address (a
local fake), and `token_env` must name a variable under
`FLEET_RECALL_SLACK_`: a sources file can send the token nowhere else, and
can never point a collector at a variable the worker holds for itself (the
content key, a database URL). A collector's `stale_after_seconds` may not be
shorter than its `reconcile_every_seconds`.

### Linear

A Linear collector reads one organization's teams with a personal API key
(`lin_api_...`, sent as the `Authorization` header itself) or an OAuth access
token (sent as `Bearer`); again the file names only the variable:

```json
{"provider": "linear", "connector_principal": "principal.linear",
 "connector_instance": "linear.acme",
 "provider_scope_id": "0a9c0000-0000-4000-8000-0000000ac3e1",
 "audience": {"private_containers": ["5f7c9e10-2b3c-4d4e-8f90-8b7c6d5e4f30"]},
 "settings": {"token_env": "FLEET_RECALL_LINEAR_API_KEY",
              "teams": ["4e6b8d0f-1a2b-4c3d-9e8f-7a6b5c4d3e2f",
                        "5f7c9e10-2b3c-4d4e-8f90-8b7c6d5e4f30"],
              "overlap_seconds": 300, "max_pages_per_tick": 500}}
```

`provider_scope_id` is the organization's id, and `teams` and
`audience.private_containers` name teams by id (lowercase UUIDs; a team key
such as `ENG` is a label that changes, never an id): a key of another
organization reads nothing and fails the source. A public team is visible to
the whole project; a private or restricted team only when
`audience.private_containers` lists it, and otherwise it is never read and
whatever was admitted from it is withdrawn and hidden. Every pass sweeps each
team's issues, then the comments on them, for what changed since the last
complete sweep less `overlap_seconds` (the whole team the first time),
archived and trashed issues included, and records coverage. An issue is its
title (with its `ENG-412` identifier), state, and markdown description; a
comment is threaded on its issue. A newer `updatedAt` with new content is a
new version that supersedes; a change that is not content (a label, an
assignee) stages nothing. A trashed issue is hidden with its comments; an
archived one stays searchable. An issue that moves into a read team brings
its older comments; one that moves into a team the collector does not
admit, or that the key can no longer see, is withdrawn with its comments, as
is a configured team the key can no longer see (unless listed). A parent
issue or a project is linked only when every team it belongs to is
admitted. A rate limit or `max_pages_per_tick` leaves a team partial, and
the next pass resumes its sweep from the page after the last one staged. The
report counts the fewest requests and complexity points Linear's
`x-ratelimit-*` headers said were left. `api_url`
(`https://api.linear.app/graphql` by default) must be on `api.linear.app`
over https, or a loopback address, and `token_env` must name a variable under
`FLEET_RECALL_LINEAR_`.

### Granola

A Granola collector reads the meeting notes one API key (`grn_...`, from a
Business or Enterprise workspace, sent as `Bearer`) can read, through the
official public API; Granola's encrypted desktop cache and its private API
are never read. The file names the variable, and declares which notes the
project may see, since a key has no audience of its own:

```json
{"provider": "granola", "connector_principal": "principal.granola",
 "connector_instance": "granola.acme",
 "provider_scope_id": "workspace.acme-robotics",
 "audience": {"operator_declared": true},
 "settings": {"token_env": "FLEET_RECALL_GRANOLA_API_KEY",
              "folders": ["fol_4y6LduVdwSKC27"],
              "include_transcript": false,
              "reconcile_every_seconds": 86400, "max_pages_per_tick": 500}}
```

The API names no workspace, so `provider_scope_id` is the operator's own pin
for it. `audience.operator_declared` is required, and so is exactly one of
`folders` (folder ids, `fol_...`: only a note in a listed folder is staged,
and every item of one that leaves them, its transcript too, is withdrawn and
hidden until it returns) and
`all_notes_visible_to_key: true` (every note the key reads). Each note
becomes its AI summary (`summary_markdown`, author kind `ai_summary`) and,
only with `include_transcript` (off by default), its transcript, one
`[hh:mm:ss] speaker: text` line per segment, split between segments; a note's
private notes and attendees are never read. The marker is the note's
`updated_at` with the content digest, so a regenerated summary supersedes
(one regenerated under the same `updated_at` is ordered when it was first
observed, so it never ties with the version it replaces).
Once every `reconcile_every_seconds` a pass lists every note and re-reads each
one, and only that reconciliation records coverage; the passes between list
the notes updated since the last one read and read those. A note missing from
two consecutive complete listings is hidden as revoked; a `404` for one note
never hides it. Requests are paced at five a second; a rate limit, a failed
request, or `max_pages_per_tick` ends a pass partial, and the next pass
resumes after the last note it settled. `api_base`
(`https://public-api.granola.ai/v1` by default) must be on
`public-api.granola.ai` over https, or a loopback address, and `token_env`
must name a variable under `FLEET_RECALL_GRANOLA_`.

## Transcripts and CI

### Transcript windows and Claude Code records

Each transcript file is read in windows of its group's `window_bytes` (4 MiB
by default, at most 8 MiB) behind a durable cursor. A line longer than the
window fails that file's source, naming the byte offset, until the group's
`window_bytes` is raised past the line; nothing after it is read meanwhile.
Turns staged from earlier windows are still admitted. The parser admits the
`user` and `assistant` turns of a Claude session file and counts every
bookkeeping record kind it knows as skipped: the session kinds (such as
`system`, `attachment`, `cost-state`, `relocated`, `worktree-state`, and
`continued-in`) and the subagent workflow journal kinds (`started`, `result`,
`failed`, `launched`, `agent-name`, and `fork-context-ref`). A record of any
other `type` that carries no `message` is skipped too, counted under
`records_unknown_skipped`, and named in the source's `skipped_kinds` (at most
8 names); one that carries a `message` fails that file's source the same way
as a line longer than the window, naming the type, until a release of the
parser admits it. Turn text is folded so it is always canonically encodable:
whitespace collapses, control scalars are dropped, and noncharacters and
private-use scalars become a space; the turn's source span still names the
raw bytes. Turns already staged keep their generation-3 parser identity;
turns staged after this release carry generation 4.

### Codex records and the remote spool

A transcript group sets `format` to `claude-code` (the default) or `codex`.
Its `dirs` are nonrecursive directories of JSONL files. The Codex adapter reads
native rollout `session_meta` and `response_item` message records, retains raw
byte spans, and skips duplicate event renderings, tool and reasoning material.
Unknown content-bearing response items fail closed. It uses its own frozen
parser identity and does not parse the different `codex exec --json` stdout
stream. See the [adapter](../../src/connectors/transcript/codex.rs).

With `FLEET_RECALL_TRANSCRIPT_SPOOL_DIR` set, the worker automatically adds its
scope's two format directories from the remote receiver. Use the same spool
mount and scope as the receiver; do not configure those directories twice.
[Sandbox shipping](../REMOTE_PLANE.md#m3-sandboxes-and-transcripts) explains
the separate shipper grant, byte acknowledgements, upload limits and cleanup.

### CI history

A CI source reads at most 512 settled runs per tick, starting after its
highest recorded window, or at its `first_run_number` (1 by default) when that
is higher. Until a tick reaches the newest settled run, the source's newest
receipt is partial and evidence answers stay `unknown`. `gh run list` reaches
back at most 1000 runs from the head, so for a workflow with a longer history,
set `first_run_number` near its current run number. Otherwise the source fails
with an error naming the lowest value the listing can reach. The worker never
skips runs on its own, and runs below `first_run_number` are never read.

## Source ownership and projected content

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
Every ingress redacts under one profile (redaction profile 3: the shared
shapes plus the provider shapes, Stripe included): a transcript turn before
the outbox, a git fact's message, author, committer, and path before its
ingress is built, and the lexical tier's recall text, which is all evidence
recall returns, once more before the row is written. A body admitted before
profile 3 keeps its raw bytes at rest; only its recall text is redacted, on
the first tick after deploy, which re-projects every lexical row stored
under an older normalization version (`rows_reprojected` in the `lexical`
and `dense` steps). The same first tick follows any later version, such as
normalization version 4, which lays a git fact out message first (a snippet
reads `commit <sha> <message> author …`) and, since it changes no body,
quarantines nothing. The git step walks only the commits past each ref's
latest receipt (`commits_walked`; `full_walks` is 1 for a ref with no receipt
or whose recorded revision has been pruned), so a historical commit whose
text is now redacted is re-presented, and quarantined as a preimage
disagreement, only on a full walk: expect a `quarantined` count equal to the
number of such commits on a full walk and zero on an incremental one (ADR
0006 D9). A history rewrite shows as `ref_rewritten` = 1, and that tick's ref
observation names the previous target.

## Scheduling

There is no long-running loop, so `--once` is required. On a standalone host,
schedule the command with cron, a systemd timer, or a scheduled task, and run
one worker per scope at a time. For example, with the environment above in
the crontab:

```text
*/15 * * * * ostk-fleet-recall worker --once --sources /etc/fleet-recall/worker-sources.json >>/var/log/fleet-recall/worker.jsonl
```

The checked-in local k0s [CronJob](../../deploy/local/kustomize/base/recall/worker-cronjob.yaml)
already runs every five minutes with `concurrencyPolicy: Forbid`. The base
profile selects `project,embed`; the remote-plane overlay adds transcript
`ingest`, and HTTPS cutover initially suspends it until authenticated acceptance.
After successful cutover/lifecycle recovery the helper resumes the prior
schedule. A manually created Job or a host process is outside the CronJob's
`Forbid` guarantee: suspend scheduling and drain active work before a manual
tick for the same scope. The lifecycle and sandbox rehearsal helpers implement
that maintenance coordination.

Inspect the tick's JSON step outcomes, source coverage and
[`recall(status)`](MCP.md#reading-status) after a configuration
change. Exit zero alone does not mean every source is fresh or coverage is
complete. [Telemetry](../TELEMETRY.md) documents worker snapshots, freshness
and duration alerts; [collection operations](../COLLECTED_ITEMS_RUNBOOK.md)
covers the first provider run and partial-coverage recovery.
