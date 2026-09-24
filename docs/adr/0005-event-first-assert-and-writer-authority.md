# ADR 0005: Event-first `remember(assert)` and the writer authority it runs under

- Status: accepted and implemented. The strict witness recognizes the compiled
  generation-2 package; `ostk-authority-install apply` installs a writer
  authority for one physical scope; `WriterAuthorityRuntime` composes the pins,
  the witness, and the evidence ledger for every event-first writer; and
  `ostk-fleet-recall serve` serves `remember(action="assert")` over MCP wherever
  the writer-authority pins verify, beside or without the ADR 0004 lifecycle.
- Date: 2026-09-24
- Scope: how an agent's assertion becomes an accepted `memory.claim.accepted`
  event plus the legacy claim projection, under which authority, and what
  `serve` does when that authority is missing or wrong. It implements ADR 0002
  D3 and D4 and amends D3's wording in one place (D3 below).

## Context

ADR 0002 D3 added `assert` beside `record`, and D4 fixed how a writer proves
the active registry head. Until now the route failed closed in every
deployment: nothing could install a head the strict witness accepted for the
generation-2 package, `serve` loaded no pins, and the only remember route's
commit dimension could not be derived. Owner decisions D1 (the commit
derivation), D4 (nominal governance keys), and D5 (serve degrades rather than
fails) settle those three gaps; this record states what was built on them.

## D1 — Generation 2 is recognized by its compiled digest

**Decision.** `materialize_active_package` admits exactly two packages: the
frozen generation-1 Stage-4 package and the generation-2 connector package
composed from those same bytes. A head is recognized by its package digest,
never by its generation, so a rollback cannot change which admission rules run.
Any other digest is `UnknownActivePackage`.

**Deferred.** A generation-3 or later package. `memory_writer_authority_v1`
does not expose `memory_registry_transitions.canonical_package`, so a later
package needs either its own compiled-in bytes or an additive migration that
exposes the canonical package through the view. Guessing would run admission
rules the writer has never verified.

## D2 — The installer, and what its signatures are worth

**Decision.** `ostk-authority-install apply` (workstation only, not in the
production image) drives the control bootstrap, genesis activation, the
`0 -> 1` successor, and the `1 -> 2` successor for one physical
`(tenant_id, project)` under the schema owner/migrator login. It is idempotent
and prints the pin group every event-first writer for that scope exports:
`FLEET_RECALL_CONTRACT_TENANT_NAMESPACE`,
`FLEET_RECALL_CONTRACT_PROJECT_NAMESPACE`, and
`FLEET_RECALL_BOOTSTRAP_RECEIPT_DIGEST`.

**Nominal keys (owner decision D4).** Every ceremony signature is made with
the public Ed25519 fixture keys (seeds `0x01`/`0x02`) that the frozen receipt
and the compiled activation policy already name, so anyone can produce them.
Signing by hand would not help past generation 1, because generation 2 carries
the fixture-key activation policy forward. The real gates are database role
separation (only the owner/migrator login may write the control and registry
tables) and the out-of-band receipt-digest pin each writer holds. Deployment-
keyed governance needs a compiled package whose policy names deployment keys;
none exists yet.

## D3 — The MCP input is ergonomic; the server builds the candidate

**Decision.** An agent sends `remember` with `action: "assert"`, an
`idempotency_key`, and one `assertion` object: `kind`, `text`, `modality`,
`polarity` (default `affirms`), a tagged `value`, the `subject` and each
`applicability` dimension as locator COMPONENTS (for example
`provider_repository_id` or `commit_oid`), an optional effective interval, up
to 256 `support_evidence_event_ids`, and an optional compare-only `predicate`.
Unknown fields are refused. The agent never sends a URI, a registry reference,
an actor, a scope, a head, or a rule.

The server routes the one authenticated-actor remember rule of the active
package (zero or several fail closed), checks the text first against both the
claim projection's rules and the canonical assertion-text contract, rederives
every URI from its components, fills every registry reference from the route,
stamps `effective_from` with its own clock (microseconds) when omitted,
enforces the whole effective-interval rule (no future `effective_from`), and
only then builds the `RememberIngressCandidateV2` and the admitted statement.
The actor is `agent.<FLEET_RECALL_AGENT>`; the physical and semantic scope come
from deployment configuration.

**Amends ADR 0002 D3,** which said the tool carries a
`RememberIngressCandidateV2`. The frozen candidate is built server-side from
the ergonomic input instead, so no caller can smuggle in a URI or a reference
that admission would have to trust.

## D4 — The commit dimension is derived under the subject (owner decision D1)

**Decision.** The only active route, `remember.actor_assertion` over
`mcp.remember.allowed_actions`, requires a `repository_commit` dimension whose
recipe, `identity.github.commit`, is version-form with parent kind
`repository` but lives in a namespace with no repository recipe. The generic
same-namespace parent rule of `validate_locator` can therefore never derive it.
The route plans such a dimension as `VersionUnderSubject` exactly when that
generic parent is unresolvable and the recipe's parent kind is the predicate
subject's own resource kind; the commit URI is then derived with the
already-rederived subject repository as its parent. The helper applies every
other `validate_locator` check and additionally requires the exact parent kind,
the same scope, and an entity-form parent. This is the one relaxation of the
parent rule, and it is not reachable from any other derivation path.

## D5 — Claim key, and which detector compares assertions

**Decision.** An asserted claim's key is
`claim-v2:<coordinate id>:<modality>`. The coordinate binds the subject,
predicate, and applicability, and excludes the value, polarity, interval,
actor, and head, so two agents asserting about the same repository, commit,
and environment share a key and the unchanged legacy
`same_key_functional_value_v2` detector compares them. The modality suffix keeps
an intention from ever conflicting with an attestation. Every recipe is carried
byte for byte from generation 1 into generation 2, so a key survives that
upgrade.

## D6 — One transaction, event first

**Decision.** Outside any transaction, an assert replays a receipt already
committed under its key, re-verifies the writer authority, admits the
assertion against the package that head activates, and embeds its passages.
One serializable append then re-reads the head, inserts
`memory.claim.accepted`, and in the same transaction re-audits every support
event ID in this project, reserves the receipt naming the event, writes the
claim projection `record` writes (plus `accepted_event_id`), runs the detector,
writes the audit events, and completes the receipt. Any failure rolls the
event back with its projection; only SQLSTATE 40001 is retried. A head that
moved between admission and append is refused, never re-admitted behind the
caller's back. The identical statement under a new key (possible only with a
pinned `effective_from`) is not written twice: it is refused as
`already_asserted`, naming the claim, with no receipt, so that key stays free.
`record` is unchanged: its requests, responses, and receipts keep their bytes.

## D7 — The lifecycle acts on the projection only

**Decision.** `retract`, `resolve`, `acknowledge`, `dismiss`, and `waive` act
on an asserted claim's `memory_claims` row exactly as on a recorded one; the
accepted event stays in the ledger unchanged. `supersede` of an asserted claim
is refused by the successor key check, since `record` input cannot reproduce a
`claim-v2:` key. Event-first retraction, supersession, and correction are
deferred.

## D8 — No new grants; the public reader withholds assertions

**Decision.** `fleet_runtime` already holds the evidence-plane and
writer-authority view grants and table access on `memory_claims`,
`memory_events`, and the receipts. An assertion carries no governed content,
so it needs no content key and takes no `memory_content_objects` lock. The
publication role gains no grant, and the publication process never serves
assert.

The publication reader does hold table-level `SELECT` on `memory_claims` and
`memory_chunks`, where an assertion's projection lives, while the only
remember predicate's publication default is `denied`. So the public reader
withholds every asserted claim itself: the service `demo` builds
(`CockroachMemoryService::publication`) drops each claim with a non-null
`accepted_event_id` from claim search and `get`, its synthetic `claim:{id}`
chunk from chunk search and `get`, and every conflict with it as a member. A
withheld item reads exactly as an absent one, and nothing reports how many
were withheld. The demo may therefore read a physical project where assert is
enabled. This is a guarantee of the reviewed binary, not of the grant: a
holder of the `fleet_publication` credential can still select those rows
directly.

**Deferred.** Publishing an assertion whose predicate allows it. Until a
package carries such a predicate and the projection records it, every
asserted claim is withheld.

## D9 — Serve degrades to assert-off (owner decision D5)

**Decision.** The pin group is optional on `serve`:

- **No pins:** assert is not configured. `tools/list`, `recall(status)`, and
  every response are byte for byte what they were.
- **Pins that do not work** (a partial or malformed group, a head the strict
  witness rejects, a view this login cannot read, a `FLEET_RECALL_AGENT` that
  is not a contract actor, or a package without an assert route): `serve`
  logs the reason at error level and starts with assert off.
  `recall(status).remember_assert` reports `served: false` and the reason.
- **Pins that verify:** assert is served and advertised, independently of
  `FLEET_RECALL_REMEMBER_LIFECYCLE`. `tools/list` adds the `assert` action and
  the `assertion` object to `remember` (the recall tool is unchanged), and
  `recall(status).remember_assert` reports `served: true`, the verified head
  (`generation`, `activation_id`, `package`), and the route: the predicate, its
  value kind and modalities, and the locator component keys of the subject and
  of each applicability dimension.

The status is a startup snapshot for agents and operators. Nothing trusts it:
every assert re-verifies the head, and the append re-reads it in its own
transaction. An assert this writer does not serve is refused before any I/O
as `assert_unavailable`, never reported as an outcome to retry.
`recall(get, kind=claim)` adds `accepted_event_id` for an asserted claim and
nothing for any other.

**Deferred.** Replaying a committed assert receipt after assert is turned off:
until then, a writer with assert off refuses a retried assert as
`assert_unavailable` even when its key committed while assert was served.

## D10 — Refusal codes

Every refusal writes nothing and leaves the idempotency key free. Over MCP it
is `invalid_params` with `data.outcome = "not_applied"` and `data.code`:

| Code | When |
|---|---|
| `assert_unavailable` | This writer does not serve assert (no pins, or they did not verify at startup), or the active package verified for this request serves no assert route. |
| `writer_authority_unavailable` | The pinned writer authority did not verify for this request. |
| `assertion_not_admitted` | The route did not admit the assertion; `details.reason` is `text_invalid`, `predicate_mismatch`, `locator_invalid`, `value_invalid`, `modality_not_allowed`, `support_invalid`, `effective_interval_invalid`, or `assertion_not_admitted`. |
| `support_event_unknown` | A support event ID names no accepted event in this project. |
| `registry_head_changed` | The active head moved. At admission, the route and the verified head name different packages (`details.reason` is `registry_head_mismatch`); between admission and append, the append's fence failed (`details.mismatch` names the field). |
| `already_asserted` | This exact statement, with the same explicit `effective_from`, is already accepted under another key; `details` names the claim and the event. |

Reusing a key for a different request remains an idempotency conflict, as for
every other `remember` action.

## D11 — Asserted commit URIs are not joinable with observed or spec URIs

**Decision, stated so no later bridge assumes otherwise.** An asserted
`repository_commit` URI is `identity.github.commit` derived under the asserted
subject repository (D4). The Stage-5 connectors name commits through their own
content-addressed recipes, and the Stage-6 observer names an observed revision
by a digest over repository, commit, path, and blob. The same commit therefore
has different URIs on each path, and no read compares them. Relating an
assertion to an observation or a spec expectation needs an explicit, audited
mapping, not URI equality.

## Consequences

- An agent can assert one kind of claim today: `mcp.remember.allowed_actions`
  about a repository, at a commit, in a runtime environment. New predicates
  and rules, resource-valued claims, and other admission bases are package
  changes and are deferred.
- Asserted claims read, conflict, and move through the lifecycle like
  recorded ones, so every existing reader keeps working. Search and conflict
  projections do not carry `accepted_event_id`; only `recall(get, kind=claim)`
  does.
- The public demo withholds every asserted claim, its chunk, and its
  conflicts (D8), so it may read a physical project where assert is enabled.
  An assertion is not hidden from a holder of the publication credential who
  issues SQL directly.
