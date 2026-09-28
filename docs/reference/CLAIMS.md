# Claims and conflict lifecycle reference

[Documentation](../README.md) · [CLI](CLI.md) · [Configuration](CONFIGURATION.md)

Use `remember(record)` for deliberate typed claims. The
[Using Recall tutorial](../tutorials/USING_RECALL.md) shows a complete MCP
exchange; the [MCP reference](MCP.md#retrieval-and-conflict-behavior)
explains key normalization and conflict detection. Claim and conflict IDs in
examples below are illustrative: re-read the target in your own project and
use its current revision and member count before sending a mutation.

- [Claim and conflict lifecycle](#claim-and-conflict-lifecycle)
- [Asserting a claim](CLAIMS.md#asserting-a-claim)
- [Citing collected items](CLAIMS.md#citing-collected-items-in-a-claim)

## Claim and conflict lifecycle

Rerunning the same `remember` request with the same tenant-wide idempotency key
returns the stored mutation with `idempotent_replay` set and does not create a
second durable mutation. A changed full request using that key is rejected.
This is at-most-one committed mutation behavior, not exactly-once response
delivery; after an ambiguous response, retry the same full request and key.

### Retract a claim

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

### Supersede a claim

To replace a claim it authored instead, an agent sends `remember(supersede)`
with the same `claim_id`, `expected_revision`, and optional `reason`, plus the
successor's `record` fields. The successor must keep the predecessor's `kind`,
its `subject`/`predicate` key after normalization (whitespace, `_`, and `-`
are one separator, so `Fleet Store` and `fleet_store` match `fleet-store`),
and its conflict eligibility, so a supersede can change what a claim says but
can never move it off its key or out of the detector's view:

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

### Read claim history

On a private writer, `recall(get, kind=claim)` by id
also returns `history`: the claim's own lifecycle log oldest first (its
`recorded` birth, then every `state_transition` with `actor`, `reason` such
as `conflict_detected`, `retracted_by_author`, or `superseded_by_author`,
`from_state`, `to_state`, and what the transition named: `conflict_id`,
`successor_claim_id`, `revision_before`, the author's `note`), cut to the
newest events within the response budget with `history_truncated` saying so;
a successor's claim carries `supersedes`, the predecessor's id. Instead of an
id, `key` (the exact stored key) or `subject` and `predicate` (normalized as
`record` normalizes them) returns every lifecycle-current claim on that key
oldest first, each with its support and `conflict_ids`, the key's
`open_conflict`, and with `include_history` its superseded and retracted
claims too; `recall(conflicts)` takes the same `claim_key` filter. Claim
search hits carry their `value` (up to 2,000 bytes; `value_elided` otherwise)
with the claim's `revision` and `actor` repeated on the hit.

A supersede is refused for the same reasons as a retract, and also when the
successor changes the kind (`successor_kind_mismatch`), the normalized key
(`successor_key_mismatch`), or the conflict eligibility
(`successor_eligibility_mismatch`). A malformed successor is an ordinary
`invalid_params` error, exactly as for `record`.

### Legacy underscore keys

Before `_` became a key separator, a claim
recorded as `include_transcript_default` kept its underscores while
`include-transcript default` did not, so the two spellings took different keys
and no conflict between them was ever detected. No migration rewrites stored
keys. Instead `recall(status)` reports `legacy_claim_keys`: `count`, the
number of the project's `active` or `disputed` claims whose stored `subject`
and `predicate` no longer normalize to their stored key (a bounded read; at
256 `bound_exceeded` marks it a lower bound), and `sample`, up to ten of them
with `claim_id`, `claim_key`, and `actor`, with a `legacy_claim_keys` warning
while the count is above zero, because a claim recorded since under the same
words takes the current key and the two are not compared. A legacy claim is
still readable by its stored key: `recall(get, kind=claim, key=…)` returns
every claim on exactly that key. The exit is `remember(supersede)` with the same `subject`
and `predicate`: the successor check re-normalizes the predecessor's stored
parts, so the successor lands on the current key and goes through detection
there, and the `claim_superseded` event records the `predecessor_claim_key`
it left. Only a disposable quickstart or trial database may instead be recreated;
that discards its memory and is an explicit operator decision.

### Acknowledge a conflict

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

### Resolve a conflict

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

### Conflict history and lifecycle overlay

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

### Dismiss or waive a conflict

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
`review_in_hours` no later than that. It changes no claim or conflict row: the conflict and its
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

### Bounds and replay after a capability is disabled

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

## Asserting a claim

`remember(assert)` is the event-first counterpart of `record`
([ADR 0005](../adr/0005-event-first-assert-and-writer-authority.md)). An
agent sends one `assertion` object. It never sends a URI, a registry
reference, an actor, or a scope: it names the claim's subject and each
applicability dimension by their locator components, and the server
rederives every identity under the active registry package, admits the
statement, and appends it.

The scope is deliberately narrow. The active package admits exactly one
predicate, `mcp.remember.allowed_actions` (version 3): a boolean about one
GitHub repository (`subject.provider_repository_id`) at one commit
(`applicability.repository_commit.commit_oid`, 40 lowercase hex characters)
in one runtime environment
(`applicability.runtime_environment.environment_id`). Its modality is
`attested` (what the agent reports holds) or `intended` (what it plans), and
its `kind` is `decision`, `fact`, `constraint`, `preference`, or `procedure`.
`polarity` defaults to `affirms`, and `effective_from` defaults to the
server's clock and may not be in the future. `recall(status)` reports this
route under `remember_assert.route`, so an agent can read it rather than
assume it. Other predicates, resource-valued claims, and other admission
bases need a new compiled package and are deferred.

This call is the one the MCP live test makes
(`tests/remember_assert_live.rs`):

```json
{"action":"assert","idempotency_key":"readme/assert/v1","assertion":{"kind":"decision","text":"remember(assert) allowed is true at this commit in production.","modality":"attested","value":{"kind":"boolean","value":true},"subject":{"provider_repository_id":"908172635"},"applicability":{"repository_commit":{"commit_oid":"3d99ec111a583e80533cbbc0c06798bb628e0979"},"runtime_environment":{"environment_id":"production"}}}}
```

The response's `data.claim` is the claim projection, shaped as `record`
returns it, and `data.accepted_event` names the appended event (`event_id`,
`epoch_id`, `shard`, and `committed_offset`). `recall(get, kind=claim)` adds
`accepted_event_id` for an asserted claim. The claim key is
`claim-v2:<coordinate>:<modality>`. The coordinate binds the subject,
predicate, and applicability but not the value, so two agents asserting about
the same repository, commit, and environment share a key and the unchanged
detector compares them: different values open a conflict, and an `intended`
claim never conflicts with an `attested` one. The ADR 0004 lifecycle acts on
an asserted claim's projection exactly as on a recorded claim and leaves the
accepted event as it is. `supersede` cannot replace an asserted claim,
because no `record` successor can carry its `claim-v2:` key.

Replays follow `record`'s rules: the same key and request return the stored
result, and a changed request under a used key is an idempotency conflict.
Every refusal writes nothing, leaves the key unused, and is `invalid_params`
with `data.outcome` `not_applied` and one `data.code`:
`assert_unavailable` (this writer does not serve assert),
`writer_authority_unavailable`, `assertion_not_admitted` (with
`details.reason`, such as `text_invalid` or `locator_invalid`),
`support_event_unknown`, `registry_head_changed`, or `already_asserted` (the
identical statement, possible only with a pinned `effective_from`, is already
accepted under another key). ADR 0005 D10 says when each applies.

`serve` serves assert only when its writer-authority pins verify at startup
(see the [runbook](../guides/EVENT_FIRST_OPERATIONS.md)), whatever
`FLEET_RECALL_REMEMBER_LIFECYCLE` says. The actor is
`agent.<FLEET_RECALL_AGENT>`, so the agent name must be a contract id:
lowercase letters, digits, `_`, `-`, and `.`. Without pins, nothing changes.
With pins that do not verify, `serve` logs the reason, starts with assert off,
and `recall(status).remember_assert` reports `served: false` and the reason.
Each assert re-verifies the head, and its append re-reads it in the same
transaction.

The public demo withholds every asserted claim, its synthetic chunk, and its
conflicts, because the predicate's publication default is denied. That is a
property of the reviewed binary: the publication credential can still select
those rows (see [security policy](../SECURITY.md)).

## Citing collected items in a claim

A claim can rest on the collected items it was drawn from
([ADR 0008 D11](../adr/0008-collected-items.md)). `record`'s `support`
takes an entry `{"item": {...}, "relation": "supports"}` beside its corpus
snapshots, and `assert`'s `assertion.support_items` takes the same
references: `{"item_id": ...}` or `{"url": "https://..."}` cite the item's
current version and `{"version_id": ...}` exactly that version, at most 32 per
claim, as `recall(kind=item)` and `remember(capture)` return them. A URL names
the item a collector admitted under it before any capture that reports the
same URL, so an agent cannot take a collected message's permalink over:

```json
{"action":"record","idempotency_key":"readme/record-cites/v1","kind":"fact","text":"The heron retry budget is four attempts.","subject":"heron","predicate":"retry-budget","value":4,"support":[{"item":{"url":"https://acme.slack.com/archives/C07PLATENG1/p1790006860001100"},"relation":"quotes"}]}
```

The server resolves each reference in the claim's own project to the
accepted events of that version's parts: `assert` cites them among its
accepted event's `support_evidence_event_ids`, and `record` writes a support
row that names only a random link id (`source_config_id` `fleet.item`,
`source` `item-link`). A reference that names nothing admitted is refused as
`support_item_unknown`, an item staged but not yet admitted (a `stage_only`
capture the worker has not drained) as `support_item_pending`, and one
deleted or withdrawn, or a version admitted in a channel since made private,
as `support_item_withdrawn`. An assertion that lists a collected item's
accepted event directly in `support_evidence_event_ids` is checked the same
way and linked like a citation. Citing one version twice in
a record is `support_item_duplicate`, and a writer that does not serve
citations refuses them as `item_support_unavailable`. A refusal writes
nothing and leaves the key unused.

`recall(get, kind=claim)` then adds `support_items`: each cited item with its
provider, ids, trust tier (`verified` or `reported`), whether the cited
version is still current, why it is hidden if it now is, the cited bytes
themselves (`uri`, the cited version's URI, and `content_digests`, one per
cited part beside `accepted_event_ids`; `recall(get, kind=item)` with that
`uri` or with the `version_id` returns exactly that version), and
`content_trust: "untrusted_third_party"`; and `independent_sources`, the
number of distinct contents among the visible ones, counting each item once
however many of its versions are cited, so an edit, an echo, or a cross-post
counts once. `recall(get, kind=item)` adds
`cited_by`, the claims that cite the item and their state. Supersede,
retract, and resolve are unchanged, and a retired claim keeps its citations.
The public demo drops the `fleet.item` support rows and cannot read which
item a claim cites.

`serve` offers citations only where `recall(kind=item)` is served and
migration 35 and the runtime grants on `memory_claim_item_links_v1` are in
place (probed once at startup); elsewhere every tool schema is what it was.
