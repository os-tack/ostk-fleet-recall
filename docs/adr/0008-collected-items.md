# ADR 0008: Collected items from any source

- Status: accepted; D1 to D6 implemented. The generation-3 registry package
  is checked in, the strict witness recognizes it, and
  `ostk-authority-install apply --target generation-3` activates it and
  rebases the scope's normative families onto it. The collected-item
  envelope, its identity digests, and the pure collector pipeline (sanitizer,
  redactor, audience decision, splitter, and the `connector.collected.<mode>`
  binding) exist (see "The envelope" below). Migration 33 adds the sink: the
  staging outbox, the drain the worker's `collect` step runs, the item
  history and current-view heads, container audiences, and collector status
  (D4 to D6), and evidence recall withholds deleted and withdrawn items. No
  provider collector, agent capture, or item recall surface stages or reads
  items yet; those land with their own decisions.
- Date: 2026-09-25
- Scope: how specs and documents, Slack conversations, Linear tickets,
  Granola meetings, and anything else a collector can read become evidence
  that agents can recall, with provenance, coverage, and conflict awareness
  (docs/DYNAMIC_MEMORY_ARCHITECTURE.md, stage 7 onward). It builds on ADR 0005
  (the writer authority and the installer) and ADR 0006 (the worker and
  evidence recall).

## Context

Generation 2 admits exactly three connectors: git history, transcript
sessions, and CI runs. Its digest is frozen (ADR 0005 D1), because installed
heads name it, so it can never admit a fourth. The owner's direction is one
generic sink with many thin collectors: a normalized "collected item"
envelope with one admission path, fed by worker pulls, signed webhooks, agent
captures, and file imports. Adding a source must not need a new compiled
registry generation.

## D1 — One generic collected-item family, in generation 3

**Decision.** Generation 3 is generation 2 carried forward byte for byte,
plus one provider-parameterized family of 13 entries
(`src/memory_contracts/generation3_registry.rs`):

| Entry kind | Id | Notes |
|---|---|---|
| namespace | `namespace.collected.provider_scope` | keys `[provider_kind, provider_scope_id]`, NFC UTF-8 |
| resource kind | `collected_provider_scope` | entity |
| identity recipe | `identity.collected.provider_scope` | entity; every collected connector's provider-instance recipe |
| namespace | `namespace.collected.item` | key `[immutable_revision]`, hex bytes |
| resource kind | `collected_item_revision` | entity |
| resource kind | `collected_item_version` | version, parent `collected_item_revision` |
| identity recipe | `identity.collected.item_revision` | entity |
| identity recipe | `identity.collected.item_version` | version; the canonical-resource recipe the body plane accepts |
| evidence schema | `evidence.collected.item` | kind `collected.item`, the four carried governance policies, canonical payload required, no private raw default |
| connector schema ×4 | `connector.collected.pull`, `.push`, `.capture`, `.import` | one per trust channel |

- **The provider is data.** `slack`, `linear`, `granola`, `docs`, and any
  later provider are values of the `provider_kind` coordinate, and the
  provider's own scope (a Slack team, a Linear organization, a documents
  root) is the `provider_scope_id` coordinate. Both sit inside one
  provider-scope entity, so a new provider is a collector module and
  configuration, never a registry entry and never a generation 4.
- **The trust channel is governance.** A pulled or pushed item is verified by
  the collector; a captured or imported item is only reported. That
  difference is carried by the connector schema, and so by every
  representation and every URI derived under it, rather than by a field a
  payload could set.
- **The item chain keeps the generation-2 pattern.** Entity and version share
  one coordinate, the source fact's own `immutable_revision`, which admission
  re-checks against the candidate. The entity is honestly named
  `collected_item_revision`: a mutable item has one immutable revision per
  version, part, and channel. Continuity across an item's versions comes from
  the item key the envelope carries, not from a continuing-entity URI, so
  `identity.rs` does not change.
- **Governance is carried, not added.** The evidence schema names generation
  1's redaction, classifier, retention, and publication entries by digest,
  and the connectors reuse generation 1's consistency partition recipe. A
  second classifier would make every admission ambiguous.

Every family entry closes under the generic successor closure: each connector
names an entity-form provider recipe in its own provider namespace, and the
evidence schema names exactly the connector's canonical-resource recipe.

**The bytes are the artifact.** The canonical package is checked in at
`contracts/dynamic-memory/v3/collected-items/registry-package.jsonl` (digest
`b5103302073c26cd42d727e1f907acecb9803d7f3da7166dd0f98d29255ac54b`).
`KNOWN_PACKAGES` gains a third row, `KnownRegistryPackage::CollectedItemsGeneration3`,
that closes those compiled-in bytes, as generation 1's row does. A test
proves the composition reproduces them from the compiled generation-2
package, so the composition can never drift from what heads name.

**What would need a generation 4.** A new trust channel, per-connector
governance, an identity change that allows continuing-entity URIs, or a
change to any carried entry. Nothing a new provider needs.

**The envelope.** Every collector produces the same
`CollectedItemEnvelopeV1` (`src/memory_contracts/collected_item.rs`), media
type `application.ostk-collected-item-v1`: canonical JSON with no scope field,
whose title and text are the lowercase hex of sanitized, redacted UTF-8, so a
canonical envelope has no raw newline and the body projector reads it as
exactly one body. Identity keeps the generation-2 pattern: `item_key` (provider,
scope, object kind, external id) gives continuity across versions;
`version_key` adds the version marker, lifecycle, and content digest; and the
`immutable_revision`, which is also the staging id and the only locator
coordinate of `identity.collected.item_version`, adds the channel, a capture's
attesting principal, and the part. A capture and a pull of one message are
therefore separate source facts, two agents' captures are two attestations,
and renaming a channel or a team mints nothing. Where a provider has no version
marker of its own, the marker is `o<order_micros>:sha256:<content digest>`, so
reverting content from A to B and back to A is a third version. Golden vectors
are checked in beside the package (`vectors.jsonl`). The collected lexical
rendering indexes the title, text, author display name, container label, and
link labels, never an id or a digest, and a tombstone indexes nothing.

## D2 — Generation 3 is opt-in, and the rollout order is fixed

**Decision.** The installer's default target stays generation 2.
`ostk-authority-install apply --target generation-3` walks the same lineage one
generation further: `0 -> 1 -> 2 -> 3` on a fresh scope, or `2 -> 3` on an
installed one, with the same fixture signers, proposer, and author, and a
conformance result minted with its own fixed completion instant. It never
moves a head backwards: a head at or past a step's package reports that step
`already_present`, so the default target over a generation-3 head changes
nothing. A package at a generation the installer's own lineage would not have
put it at, such as generation 2 re-activated as generation 4 by a hand-run
revert, is refused rather than driven forward.

Rollout order, for every physical scope that is to collect items:

1. Ship binaries that recognize generation 3 to every process that verifies
   a head: every event-first writer, every `serve`, the worker on its ingest
   host, and the projector container (ADR 0006 D1). A binary without the
   generation-3 row refuses a generation-3 head as `UnknownActivePackage`.
2. Apply the release's migrations and re-apply the grant files. Migration 32
   (D3) lets a spec family be rebased; it adds no grant. Migration 33 (D4)
   adds the collected-item tables, which the runtime policy grants.
3. Run `ostk-authority-install apply --target generation-3`. The pins do not
   change, so no writer is reconfigured, and the run rebases every spec
   family onto the new head (D3).
4. Only then configure collectors, agent capture, or webhook ingress.

**Consequences an operator sees after the move.**

- **Representations are re-keyed.** `RepresentationIdentityV2` binds the
  registry head, so a source fact read again after the move is admitted as a
  second representation: a new accepted event beside the one generation 2
  accepted. Nothing already admitted is rewritten, body bytes are stored
  once by content, and the worker's cursors mean a source is read again only
  when it moves (for example, a git scan after a new commit walks the
  history behind it).
- **Claims keep their keys.** Every recipe an asserted claim key is derived
  under is carried byte for byte, so the same assertion keys identically
  under generation 2 and 3 and the conflict lifecycle is unchanged.
- **Spec families are rebased, drafts are not.** The move rebases every
  binding family whose statements' registry dependencies generation 3
  carries, which is every spec family (D3). A draft names the exact head it
  was made under, so one made before the move is refused as a stale head and
  must be redrafted after it.

## D3 — Moving a scope to generation 3 rebases its normative families

**Decision.** A binding family's head records the registry package and
activation policy it was last advanced under, and every activation into the
family compare-and-sets against them, so a registry transition strands the
family (ADR 0007 D11). `ostk-authority-install apply --target generation-3`
therefore ends with a normative rebase step. For every binding family of the
scope whose head names another registry head than the one the run leaves
active, it resolves what each live statement depends on, then, in one
serializable transaction per family
(`CockroachNormativeActivationRepository::rebase_family`):

1. it locks the family's head;
2. it requires the head's package digest to differ from the active one; a
   head already there is `already_current`, and nothing is written;
3. it requires the head to be at the revision the dependencies were resolved
   at, and the dependencies to describe exactly the family's durable live
   statements; a head that moved is re-read and resolved again;
4. it requires every registry entry a live statement depends on to be present,
   with the same id, version, and digest, in the active head's authority: its
   package, or the genesis package the scope's pinned bootstrap binds, which
   no successor transition changes;
5. it appends one `rebase` record at `log_seq + 1`;
6. it compare-and-sets the head's package and activation-policy digests with
   `head_revision + 1`, leaving the binding set as it was;
7. it advances the projection's cursor. The fold treats a `rebase` record as
   a no-op for resolution, so the statement in force does not change.

A spec statement depends on three entries: its applicability evaluator and
its predicate, which resolve in the genesis package (ADR 0007 D1), and the
`identity.github.repository` recipe of the package it was drafted under, which
a check re-derives the statement's subject with. Generation 3 carries all
three byte for byte, so every spec family moves.

The record is `NormativeHeadRebaseV1`
(`src/memory_contracts/normative_v2.rs`): the family, the from and to package
and policy digests, the new head's exact `registry_activation_id` (an
A -> B -> A rollback is a different activation), the sorted digests of the
carried entries, and `rebased_at`, the database's time. Its identity is a
digest under its own domain, `ostk-normative-head-rebase-v1`, so a family's
log shows when and onto what it moved, and a rebuilt projection replays it.

**A family that cannot be verified stays where it is.** A live statement
`ostk-spec` never recorded, one drafted under a package this build does not
recognize, or a dependency the new head does not carry, leaves the family on
its old head. The report's `normative_families` lists it as `stranded` with
the reason, and the CLI names it on stderr; the authority install itself
succeeds. ADR 0007 D11 then applies to that family.

**Opting out.** `--no-normative-rebase` skips the step and leaves every family
stranded, as an explicit choice. A later run without the flag rebases them,
and a re-run rebases nothing twice.

**Migration 32.** Migration 0024 constrains the log's `record_kind` to
`lifecycle` and `contest`. Migration 0032 adds `memory_normative_log_kind_v2`,
which also admits `rebase`, commits it, and only then drops the old
constraint, so every interruption leaves a kind check in force and 0024 stays
byte-identical. The installer refuses, before any write, to rebase a scope
that holds a family on a schema without migration 32. No grant changes: the
installer runs as the migrator, the runtime role already holds `INSERT` on the
log, and the runtime policy's schema gate stayed at migrations 1 to 31, since
nothing served needs 32. (Migration 33, D4, later moved the gate to 1 to 33.)

**What stays as ADR 0007 D11 describes.**

- A draft names the exact witnessed head, so a draft made before the move is
  refused as a stale head. The rebase moves families, never proposals.
- A move made any other way, such as a hand-run generic successor ceremony or
  `--no-normative-rebase`, rebases nothing, and the family's compare-and-set
  keeps refusing until a rebase.
- The rebase is nominal authority in the same sense as the installer's
  signatures (ADR 0005 D2): the gate is the migrator credential. The record
  proves only that the dependencies carried, which the runtime checked under
  the head lock.

**Deferred.** A rebase outside the installer's generation-3 run (an
`ostk-spec rebase`, or a rebase onto generation 2), and rebasing families whose
statements were not recorded by `ostk-spec`.

## D4 — One sink: staging, clocks, and the drain

**Decision.** Every collector hands drafts to one sink
(`src/collectors/sink.rs`), and nothing else writes the collector tables.

**Staging** (`CollectedItemSink::stage`) is one serializable transaction
(retried only on 40001), and every statement binds `(tenant_id, project)`
first:

1. It reads `statement_timestamp()` once: every row it stages is observed and
   received at that instant.
2. It records the container observations the collector made: a container
   whose audience is admissible is upserted with `access = 'ok'` and its basis;
   one whose audience no longer is (a channel made private and not listed) is
   set to `access = 'withdrawn'`, never deleted.
3. For each draft, in order: the provider and scope must be the instance's
   (else a `validation_failed` dead letter, `provider_scope_mismatch`); the
   audience is decided by the server (D6; a refusal is an `audience_refused`
   dead letter); the draft is sealed (sanitize, redact, split at most 32 KiB
   per part, one canonical envelope and stage id per part; a refusal is a
   `validation_failed`, `oversize`, or `redaction_withheld` dead letter); an
   item whose provider clock is ahead of the observation is a `clock_ahead`
   dead letter; and each part is inserted with `ON CONFLICT DO NOTHING` on its
   stage id, so re-reading an unchanged item stages nothing.
4. The collector's cursor advances and its status row are written in the same
   transaction (REPLAY-02), except that no cursor advances when an item was
   `clock_ahead`: the page is read again and what did stage replays.

A dead letter holds a closed reason, the digest of the draft (or of the
envelope), the stage id when there is one, the delivery id, and a static
diagnostic; never text. Its key is a digest of the instance, the reason, the
payload digest, and the stage id, so the same refusal on every tick is one
row.

**Clocks.** `observed_at = received_at` is the staging transaction's clock and
`occurred_at` is the envelope's provider clock (its `updated_at`, else its
`created_at`, else the observation). All three are stored on the row, so a
drain rebuilds a byte-identical candidate however often it runs, and a replay
is recognized rather than quarantined as a preimage disagreement.

**The drain** (`CollectedItemSink::drain`, `drain_stage_ids`) reads pending
rows oldest first and, for each, binds `connector.collected.<mode>` from the
tick's verified head, builds the candidate with the D1 binding (which refuses
an envelope whose provider, scope, channel, or instance is not the row's),
admits it, and appends it with `CollectedDrainProjection`: the governed
content object, the outbox row settled as `admitted` with its envelope set to
NULL, one `memory_collected_items_v1` row for the part, its link rows, and,
when the part completes its version, the head move (D5). All of it is one
transaction (EVENT-03).

| Outcome | Row |
|---|---|
| appended, or replayed because a concurrent drain admitted it | `admitted` |
| the ledger quarantined the event | `quarantined`, with its quarantine id |
| the binding or admission refused the candidate | `dead_lettered`, an `admission_refused` dead letter; the drain goes on |
| the head moved, the authority was unavailable, or storage failed | `attempts + 1`, retried by a later drain; the eighth failure is a `retry_exhausted` dead letter |
| the active package does not carry `connector.collected.<mode>` | stays `pending`; the worker's step fails naming `ostk-authority-install apply --target generation-3` |

A settled row keeps no text: a CHECK ties `state = 'pending'` to a non-NULL
envelope, and `envelope_sha256` remains. The redacted text lives only in the
governed content store and the body plane. Purging settled rows is deferred
(no runtime holds `DELETE`).

**The worker.** `worker --steps collect` (and `all`) runs a `collect` step
after `ci`: it drains at most 1,024 pending parts per tick under the head the
tick verified, then bodies, lexical, and dense project them like any other
evidence. The step needs the writer authority and the content key, like the
ingest steps, and its privileges are probed before the tick, but it is not
in the `ingest` group, so `--steps ingest` and source retirement are
unchanged. On a schema before migration 33 the step is `skipped`
(`schema_below_33`) and probes nothing when no collector is configured, and
fails, naming `ostk-fleet-recall migrate`, when one is. The sources file
gains `collectors`: one instance per provider scope, with its principal,
pinned scope, audience policy, and the provider adapter's settings. Instance
ids are unique across every connector, and a credential written inline (a
secret-shaped value, or a string under a credential-named key) is refused;
settings name environment variables. No provider adapter runs yet.

## D5 — The current view, supersession, and suppression

**Decision.** `memory_collected_items_v1` is append-only history, and
`memory_collected_item_heads_v1` holds one head per item and trust tier:
`verified` (pull, push) and `reported` (capture, import). The move rule is
pure (`src/collectors/heads.rs`) and runs under `SELECT ... FOR UPDATE` over
both tier rows in the drain's projection:

- **Only a complete version heads a tier.** A version completes when the last
  of its distinct part ordinals is admitted through that tier; a partially
  admitted version never becomes a head, and a second attester's copy of an
  admitted part completes nothing.
- **Forward only.** A complete version replaces the head only when its
  `(provider_order, redaction_profile)` is strictly greater: the provider's
  order decides what is newer, never the arrival order, and a strictly newer
  redaction profile at the same order moves the head to the better-redacted
  rendering. An older version arriving late is counted (`version_count`) and
  the head stays.
- **Ties are counted, and a tombstone wins them.** Two different versions
  at the same order and profile increment `order_ties`. A tombstone (deleted,
  trashed, revoked) beats a version that is not one, so a delete that shares
  the live version's order (a Slack parent kept as a `tombstone` at its own
  `ts`, an export that marks an item deleted without moving its clock) always
  hides it; between two versions of the same kind the greater version key
  wins. Either way the head is a function of the set of complete versions,
  whatever order they arrived in.
- **A report never displaces a verification.** Exactly one row per item is
  presented (a partial unique index): the verified head when one exists, else
  the reported one. The row that stops being presented is updated before the
  one that starts, inside the same transaction.
- **Disagreement.** The presented row is marked `disagreement` when the
  reported head is newer than the verified head and its content differs.

**Edits supersede, deletes hide.** An edit is a new version and moves the
head; older versions stay in the history and in `recall(kind=evidence)`. A
provider delete, trash, or revoke, or an absence-based tombstone, is a
version with empty text that becomes the head.

**Read-time suppression.** A collected body is withheld from recall when its
item's presented head is a tombstone or its container is `withdrawn`: inside
the lexical lane's `WHERE`, before ranking and before the `LIMIT`; as a
post-filter of the dense lane's nearest neighbours; and in evidence `get`. It
reads `memory_collected_items_body_idx`, so the cost is one index probe per
candidate. Deleted text stops being recallable at once, with no `DELETE`
grant and no projection rewritten. Physical erasure is deferred (ADR 0006 D9
applies).

**Evidence recall stays sound.** From migration 33 on, evidence recall probes
`SELECT` on the outbox, items, heads, containers, and collector status. When
the login may read them, readiness reports `items_awaiting_admission` (any
pending part makes an empty answer `unknown`, `ingest_outbox_pending`), live
and snapshot collectors are listed beside the worker's sources (kind
`collector`, with their provider, capped at 256 together) and judged by the
same rules, and suppression applies. When it may not, evidence recall is
still served, but it cannot tell deleted text from current text or a pending
item from none: every collected body is dropped from the answer and from
`get` (fail closed), and an empty answer is `unknown` with
`collector_state_unreadable`, never `absent`. The startup probe is only a
starting point: until the collector state is readable, every search, `get`,
and status read checks it again, and withholds collected bodies until it is.
A `serve` started before migration 33 (step 1 of the D2 rollout ships
binaries before step 2 migrates) therefore suppresses deleted and withdrawn
items and counts pending ones from the first read after the migration and
the grants, with no restart.

## D6 — Audience: server-derived, whole project only

**Decision.** In v1 every admitted item is visible to the whole project, so
the audience decision (`src/collectors/audience.rs`) only decides whether an
item may be admitted at all, and on what basis, from provider facts and
operator configuration, never from a pulled payload or an agent:

- a direct or group-direct conversation, and a container shared with another
  organization, are refused always;
- a public, unshared container is `provider_public`, and a public team
  `team_public`;
- a restricted container is admitted `operator_declared` only when the
  operator listed it; an operator-scoped source (a documents root, a Granola
  key, an import) only when the instance declares it;
- a capture is admitted `verified_container` only into a container a verified
  collector or an operator import recorded as readable, else
  `operator_capture_scope` when the operator listed the scope, else refused;
- a visibility hint from an importer or an agent can only narrow: `private`
  and `dm` refuse the item.

A refused item is a digest-only `audience_refused` dead letter. The package's
private/denied classification still applies to every admitted item, so none
becomes publishable, and the publication plane gains nothing: no collector
table is a publication table or granted to the publication reader, which a
connected test proves by reading each one and getting SQLSTATE `42501`.
Per-principal audiences, with clearance checked inside SQL, are deferred.
