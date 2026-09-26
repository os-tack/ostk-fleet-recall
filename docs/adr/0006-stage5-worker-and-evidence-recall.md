# ADR 0006: The Stage-5 memory worker and evidence recall

- Status: accepted and implemented. `ostk-fleet-recall worker --once` runs
  every Stage-5 connector and projector for one scope in one tick and records
  each source's status; `ostk-fleet-recall serve` answers
  `recall(kind="evidence")` over the projected tiers, with readiness,
  per-source status and coverage, and an absence verdict, wherever the writer
  login may read the Stage-5 tables.
- Date: 2026-09-24
- Scope: how git history, agent transcripts, and CI runs become recallable
  evidence, what a tick records about each source, what an evidence answer
  claims, and how `serve` exposes it. It builds on ADR 0002 (the Stage-4
  runtime and grants) and ADR 0005 (the writer authority every event-first
  writer runs under).

## Context

The connectors (git, transcript, CI), the body projector, and the lexical and
dense projectors existed as libraries with their own tests, but nothing ran
them together, nothing said whether a source had been read recently, and no
agent could search what they produced. An empty search answer was therefore
unreadable: it could mean the evidence does not exist, or that the worker
never ran, failed, fell behind, or covered only part of a source.

## D1 — One worker command, run as `fleet_runtime`, one instance per source

**Decision.** `ostk-fleet-recall worker --sources <file> --once
[--steps <groups>]` runs one tick: transcript, git, and CI ingest (provider
material to accepted events), then bodies, lexical, and dense projection
(accepted events to recall tiers), in that order. `--steps` is a
comma-separated list of `all` (the default), `ingest`, `project` (bodies and
lexical), and `embed` (dense). It connects
as the `fleet_writer` login and so runs as `fleet_runtime`, like `serve`
(owner decision D6); no worker role exists.

- **Authority.** Every tick that ingests verifies the writer authority afresh
  (ADR 0005) and binds each connector schema from that tick's active package;
  every append re-reads the head in its own serializable transaction. Server
  time comes from `statement_timestamp()`.
- **Privileges.** Before a tick, a rolled-back probe plans an insert into each
  table the selected steps write and a `SELECT ... FOR UPDATE` on each table
  they lock. A missing privilege stops the run naming the table and
  `deploy/cockroach/runtime-role-grants.sql`.
- **Instances.** Each configured source is its own connector instance: a git
  ref and a CI workflow each name theirs, and each transcript file gets
  `<instance_prefix>.<sanitized stem>` (the first 16 hex characters of the
  file name's SHA-256 when that would be empty or exceed 128 bytes). A source's coverage
  cursors, receipts, and status row are keyed by its instance, so one source's
  failure or lag never hides behind another's.
- **Failure isolation.** A failed source is recorded and the tick continues;
  the report (one JSON line on stdout) carries every step and source outcome,
  and the exit status is 1 when any step failed.
- **Scheduling.** There is no loop: a deployment schedules the command (cron,
  a systemd timer, a scheduled task), one worker per `(tenant, project)` at a
  time. The git and CI steps shell out to `git` and `gh`, which the production
  image does not carry, so ingest runs on a host that has them and holds the
  writer login and the content key; `--steps project,embed` also runs in the
  container.

## D2 — What each source's newest coverage cursor means

**Decision.** Each connector's coverage domain is chosen so that the newest
cursor of an instance says something checkable:

- **git** observes its ref only when the ref's target differs from the
  revision of the instance's latest receipt; one observation covers `[1, 2)`
  of a domain whose target is `[1, 2)`, so it is complete. An unmoved ref is
  `unchanged` and opens no new domain.
- **transcript** drains one file's pending turns under a domain whose target
  is `[lowest pending ordinal, next ordinal)`. A tick that stages new turns
  opens a new domain, so the newest cursor says the newest drained slice is
  complete, not that the whole file is; older slices keep their own cursors.
  The file is read in windows of `window_bytes`; a line longer than the
  window fails the source (it never reads as `unchanged`), and a tick whose
  collection fails still drains the turns earlier windows staged.
- **CI** reads from the run after the highest measured window (or from the
  source's `first_run_number`, when higher) toward the provider's settled
  high-water mark: the highest run below the oldest run not yet completed
  among the 50 newest. One tick reads at most 512 runs, but the domain's
  target runs to the mark, so a tick that reads only part of a backlog writes
  a partial receipt and absence stays `unknown` until a later tick reaches
  the mark. `gh run list` reaches back at most 1000 runs from the head; a
  resume point further back fails the source with an error naming the lowest
  `first_run_number` the listing reaches. The worker never skips runs on its
  own.

  The mark stops below the oldest run still in flight. While such a run
  waits (for example on an environment approval), completed runs above it
  are neither read nor known to any receipt, and the source reports
  `unchanged`. A CI `absent` therefore covers only runs below the oldest
  in-flight run; reporting that blocker (a partial receipt or a distinct
  outcome, which migration 0030's outcome set does not allow) is deferred.

**Unregistered labels.** Receipts name the freshness rule
`coverage.freshness.worker_tick` and the proof method
`coverage.proof.enumerated_snapshot`. These are compile-time labels, not
entries of the active package: no package registers them and the coverage
runtime does not resolve them. Registering them is deferred.

## D3 — Worker source status and the staleness rule

**Decision.** Migration 0030 adds `memory_worker_sources_v1`, one row per
`(tenant_id, project, connector_instance_id)`, which the worker upserts after
every attempt: the source kind, `state` (`active` or `retired`), the outcome
(`ok`, `unchanged`, or `failed` with an error cut to 2048 bytes),
`last_attempt_at`, and `last_checked_at`, which only `ok` and `unchanged` set.
A source that has never completed a check has a null `last_checked_at`; a
source that fails on every tick still reports. When all three ingest steps
run, rows for instances the sources file no longer configures become
`retired` and leave every evidence answer.

Retirement treats one sources file as owning the whole scope: the table
records no owner, so a run retires every active row its file does not name.
A scope therefore has exactly one sources file, and its ingest runs from one
host. Two files for one scope (git and CI on one host, transcripts on
another) would retire each other's sources on every run, and evidence
recall would vouch for an empty answer from one host's sources alone.
Owner-scoped retirement needs an owner column, that is a new migration, and
is deferred.

A source is **stale** when `statement_timestamp() - last_checked_at` exceeds
its `stale_after_seconds`: 86400 by default, overridable per source, bounded
to `[60, 31536000]`. Freshness comes from this row, not from the cursor: a git
ref that has not moved is not re-observed, but each tick that checks it
records the check. The table is operational status, not evidence; it carries
no foreign key and is never granted to the publication reader.

## D4 — Absence is defined over the lexical tier

**Decision.** Every evidence answer carries a verdict. Any hit makes it
`present`. With no hit it is `absent` only when all of these hold, and
`unknown` otherwise, with every reason that applies:

- the query has lexical terms (`query_has_no_lexical_terms`), because the
  verdict is a claim about the lexical tier, whose matching is exact and
  reproducible;
- no accepted evidence event awaits the body projector
  (`body_projection_lag`) and no transcript turn awaits admission
  (`ingest_outbox_pending`);
- every body has been through the lexical projector
  (`lexical_projection_lag`);
- at least one source is active (`no_sources_registered`), and every active
  source's last outcome is not `failed` (`source_failed`), its last completed
  check exists (`source_never_checked`) and is not stale (`source_stale`), and
  its newest coverage cursor is complete (`incomplete_coverage`);
- the source listing (at most 256) was not cut (`listing_truncated`).

Each transcript file is its own source (D1), so a transcript directory with
more than 256 session files makes every empty answer `unknown`
(`listing_truncated`), and every search answer carries the full listing, up
to 256 sources. A compact search summary, with the verdict's source
conditions computed over every active row rather than over the capped
listing, is deferred.

The dense tier never blocks `absent`: its lag is reported, not required. The
verdict's `as_of` is the oldest last completed check among the active
sources. Reads run in the order that makes the verdict sound: sources, then
readiness, then the recall lanes, so a check the listing saw committed its
events before readiness counted them, and the lanes search a lexical tier at
least as new as the one readiness counted.

**Consequence for dense matches.** `serve` embeds every query, so the dense
lane runs whenever it is served. A dense neighbour whose cosine similarity
clears the chunk-recall floor (0.18) is a hit, so it makes the answer
`present`, flagged `matched_by: "dense"` with its similarity. `absent`
therefore also means no dense neighbour cleared the floor. How often a
loosely related neighbour clears 0.18 depends on the model; a floor of its
own for evidence, or a verdict over lexical hits alone, is an open
calibration decision.

**Consequence for lexical matches.** The lexical twin of the floor: a
lexical row whose `ts_rank` is below 0.001 is a co-occurrence (the query's
terms ten or more words apart), not a match, and does not count. A query
whose only lexical matches rank below that cutoff has no hits and follows
the readiness rules above, so its empty answer is `absent` or `unknown`
exactly as a query with no lexical row at all.

## D5 — `kind=evidence` is additive, not fused into chunk RRF

**Decision.** Evidence recall is a separate `kind` of the existing `recall`
tool with its own answer shape; chunk search and its reciprocal-rank fusion
are unchanged, and no evidence hit enters them.

- **When it is served.** `serve` probes once at startup: the schema must have
  reached migration 30 and the login must be able to `SELECT` every table
  evidence recall reads. There is no switch. Where the probe fails (a
  deployment without the Stage-5 grants), `tools/list`, every response, and
  every error text stay byte for byte what they were, and
  `recall(search|get, kind=evidence)` is refused exactly as any unsupported
  kind is. A failing probe is logged and never stops `serve`. The publication
  process never serves it: evidence recall reads private base tables only.
- **What is advertised.** `tools/list` adds `evidence` to `recall`'s `kind`
  enum, one description sentence, and a branch that allows only `search` and
  `get` with `kind=evidence` and forbids `source`, `max_per_source_id`,
  `min_score`, and `intent`; the server also refuses those and
  `include_history`. The `remember` tool is unchanged.
- **search** returns `data {hits, readiness, sources, absence}`. A hit carries
  its 64-hex content id, the lanes that matched it and their scores and the
  fused score, its media type, a 600-character snippet of the lexical tier's
  redacted recall text, and the accepted event that first produced it. The
  two lanes are each read five rows deep per hit asked for and fused by
  reciprocal rank (K = 60, the chunk lanes' constant, applied to the
  evidence lanes alone), so the hits are in fused order, highest `score`
  first. `warnings` name projection lag, pending ingest, a disabled dense
  lane, failed or stale sources (with their instances), a cut listing, and a
  query the model could not embed; `diagnostics.retrieval` is `{tier:
  "evidence", lanes, fusion: "rrf", dense_lane,
  dense_min_cosine_similarity}`; `conflict_coverage` is `not_evaluated`.
  A listed source's `kind` is its status row's stored `source_kind`. A kind
  this build does not know is listed as stored rather than failing the read,
  and it still counts toward the failed, stale, never-checked, and incomplete
  reasons of the absence verdict.
- **get** takes a hit's id and returns `data.evidence`: the body's full recall
  text (at most 256 KiB), its media type, visibility class, and first accepted
  event, or `null`.
- **status** adds `data.evidence {served, readiness, sources}` and the same
  warnings. A failed evidence read there, or one that takes longer than 10
  seconds, is a warning (`evidence_status_unavailable`), never a failed
  status.

**Cost.** Readiness counts the scope's body, lexical, and dense tiers, and
those tables have no narrow index to count through (each primary key stores
the body bytes, the recall text, or the 512-dimension vector), so every
evidence search and status read, and the startup foreign-model check, scans
work proportional to the evidence in the scope. The 10-second bound keeps
`status` answering; a readiness cache or a counting index (a new migration)
is deferred.

Snippets and fetched text are the lexical tier's text, never the stored body
bytes: that text is normalized and has every secret-shaped range replaced
before it is written.

## D6 — One embedding model per deployment

**Decision.** Every dense row records the digest of the model that embedded
it (the operator's `FLEET_RECALL_EMBEDDING_MODEL_SHA256`), and `serve` embeds
queries with the same pinned bundle. Every evidence dense query compares the
query vector only with rows whose `model_digest` is `serve`'s own: the filter
sits outside the nearest-neighbour subquery, so the vector index still serves
the scan, and a neighbour of another model is dropped rather than compared.
A worker that starts writing another model's vectors while `serve` runs (the
worker upgraded first, or host and container disagreeing on the digest)
therefore costs dense hits, never a false `present`. The startup probe also
checks once whether the scope's dense tier already holds a vector of another
model; if it does, the dense lane is off for the process
(`dense_lane: "disabled_foreign_model"`, logged at startup and warned on every
answer) and the lexical lane still serves.

A model change therefore needs `serve` and the worker to move together, and
a restart. The worker's `embed` step only embeds bodies that have no vector
yet, so it does not re-embed the old model's rows, and no re-embed step
ships. Evidence search is
not gated on the chunk corpus's embedding generation, which concerns a
different table.

## D7 — UPDATE on `memory_content_objects`, for `SELECT ... FOR UPDATE`

**Decision.** CockroachDB v26.2.3 requires `UPDATE` for `SELECT ... FOR
UPDATE`. The governed content store takes that lock whenever an append
deduplicates onto an existing content object, which the worker's transcript
path does whenever a resumed session file repeats a turn. `fleet_runtime`
therefore holds `UPDATE` on `memory_content_objects`, in the one Stage-5 block
of `deploy/cockroach/runtime-role-grants.sql`. No runtime statement updates
that table, but the grant is table-wide: a holder of the writer login could
rewrite a content row directly. The publication role gains nothing.

## D8 — The projector reads every evidence event; observer runs are counted, not recalled

**Decision.** The body projector consumes every `evidence.accepted` event in
the scope, not only the worker's. Observer-run records (from
`ostk-observer-run` and `ostk-spec check`) are such events, but their
resource, under the `identity.github.push` recipe both known packages use, is
an occurrence (`urn:ostk:occurrence:v1:provider_event:…`), not a source-object
version. The projector chunks only version-form resources, so it counts each
observer run in the `bodies` step's `events_unprojectable`, advances its
watermark past it, and writes no body; evidence recall never returns one.
`recall(discrepancies)` cites an observer run by `observer_event_id` instead.
The git blob fact `ostk-spec check` appends beside it is version-form and is
projected like the worker's git facts: its recall text is the fact (commit,
path, and blob id), not the blob's bytes. `memory.claim.accepted` events are
not evidence events and never reach the body plane.

This section first said observer runs became bodies with the media type
`application.ostk-observer-run-record-v1`. The end-to-end run against a fresh
database showed otherwise: a nonzero `events_unprojectable` after each
`ostk-spec check` is these records, and it is expected.

## D9 — Projection writes governed content in plaintext

**Decision.** The worker's `project` step builds the body plane from the
governed content store: it unwraps each content object with the body key
(`FLEET_RECALL_CONTENT_KEK_HEX`) and writes the decrypted bytes to
`memory_body_objects_v1.body_bytes`, because the lexical and dense projectors
read bodies, not ciphertext. That table is readable by the writer login
(`fleet_runtime`, `serve` included) without the key.

- Once a body is projected, the key no longer limits who can read that
  evidence. The writer login alone can read every projected git, CI, and
  transcript body. Since redaction profile 3 every ingress redacts under the
  crate's one redactor (`crate::redaction`: the six shared shapes plus the
  provider shapes, Stripe included): a transcript turn before the outbox, a
  git fact's message, author, committer, and path before its ingress is
  built. Residual: facts are content-addressed, so a body admitted before
  profile 3 stays raw at rest, and only its recall text is redacted, once the
  worker's lexical step re-projects every row stored under an older
  `LEXICAL_NORMALIZATION_VERSION` (`rows_reprojected` on the first tick after
  deploy, zero afterwards; the dense step of the same tick re-embeds). On
  that tick the git step re-walks each ref from the root, and every
  historical commit whose text is now redacted re-presents with a different
  payload under the same source-fact identity and is quarantined as a
  `PreimageDisagreement`: a one-time `quarantined` count equal to the number
  of such commits, visible in the report rather than a silent rewrite.
  Closing that residual needs supersession or erasure, which this ADR does
  not provide.
- Destroying the key no longer erases projected evidence. Erasure must also
  purge `memory_body_objects_v1` and the lexical and dense rows derived from
  it.
- What evidence recall returns is unaffected (D5): snippets and fetched text
  are the lexical tier's redacted recall text, never `body_bytes`.

The envelope encryption of the governed content store therefore protects
content until projection. A deployment that needs key-scoped confidentiality
after ingest must not run the `project` step, which leaves evidence recall
nothing to search. Only the owner can delete body rows; `fleet_runtime`
holds no `DELETE` on them.

## Consequences

- An agent can ask whether the fleet's own history, transcripts, or CI runs
  mention something, and learn from the same answer whether an empty result
  is trustworthy, and if not, which source or projection is why.
- `absent` is a strong claim and is reported rarely: any failing, stale, or
  never-checked source, any unprojected evidence, or a dense neighbour above
  the floor keeps the verdict `present` or `unknown`.
- Operators schedule the worker and watch its report and exit status; the
  status table is what evidence recall trusts, so a worker that stops running
  turns every empty answer `unknown` once its sources go stale.

**Deferred.** An `--interval` loop and managed scheduling; `git` and `gh` in
the production image; changed-path and incremental git scans; supersession
or erasure of bodies admitted before redaction profile 3 (the git ingress
redactor itself landed with profile 3, see D9); transcript tool-use,
tool-result, and thinking records;
publication-plane evidence recall; fusing evidence into chunk recall;
registering the coverage labels in a package; dense or semantic absence
verdicts and an evidence-specific dense floor; query-centred snippets;
owner-scoped source retirement (D3); a compact search source summary and a
verdict over every active source (D4); reporting a CI run in flight above
the settled mark (D2); a readiness cache or counting index (D5); a re-embed
step (D6); a body plane that stays encrypted at rest (D9).
