# MCP reference

[Documentation](../README.md) · [CLI](CLI.md) · [Configuration](CONFIGURATION.md)

Use this reference for tool behavior and response semantics. For a runnable
stdio exchange, follow [Using Recall](../tutorials/USING_RECALL.md). For
client enrollment, OAuth, HTTP transport and grants, use the
[remote plane runbook](../REMOTE_PLANE.md).

- [Tools and capability discovery](#tools-and-capability-discovery)
- [Retrieval and conflict behavior](#retrieval-and-conflict-behavior)
- [Start with a brief](#start-with-a-brief)
- [Reading status](#reading-status)
- [Trust and safety boundaries](#trust-and-safety-boundaries)

## Tools and capability discovery

`ostk-fleet-recall serve` speaks newline-delimited JSON-RPC/MCP on stdin/stdout.
`serve --http ADDRESS` serves authenticated MCP at `/mcp`. Both expose the two
tools `recall` and `remember`; available actions depend on the deployed schema,
privileges and configuration. Read `tools/list` and `recall(status)` before
using optional actions. Changing SQL role grants or enabling a capability
after startup may require restarting the serving process to repeat its probes.

- `recall(search|get|conflicts|status|brief)` reads the hybrid vector/lexical
  corpus and typed-claim state. `get` with `kind=conflict` returns one
  conflict by id in any state, with its members and its lifecycle history;
  `get` with `kind=claim` returns a claim with its own lifecycle history,
  or, given `key` (or `subject` and `predicate`), every claim on that key
  with the key's open conflict.
  Every conflict the private writer returns carries a `lifecycle` overlay:
  who acknowledged or waived it, and who closed it and how.
- `recall(brief)` is the first call of an agent session: with `subject`,
  every current claim whose key starts with that subject, the open
  conflicts on them, and the health of the sources those claims cite;
  without, the scope at a glance (the most recently changed claims, every
  open conflict, stale or failed sources, projection lag, legacy keys,
  quarantine, and the absence contract). Nothing in a brief is third-party
  text. See [Start with a brief](../tutorials/USING_RECALL.md#6-exercise-the-mcp-server).
- `recall(search|get, kind=evidence)` searches the connector evidence the
  [memory worker](WORKER.md) admits (git history, agent transcripts,
  CI runs). It is served wherever migration 30 is applied and the writer
  login holds the Stage-5 grants; elsewhere `tools/list` is unchanged.
  Every answer carries readiness, each source's status and newest coverage
  cursor, and an absence verdict: `present` when a hit matched the query's
  words or a dense-only neighbour reached cosine 0.45 (`present_by` names
  the lane; a raw git fact never counts that way), `absent` only when
  neither held over a current lexical tier with every source healthy,
  fresh, and completely covered, otherwise `unknown` with the reasons. A
  dense neighbour below the bound is still listed, counted in
  `weak_neighbours`, with `strongest_dense_similarity` and `strongest_hit`
  (its index into the hits) reported; one that scored 0.30 or more makes
  the verdict `unknown` with `dense_neighbour_below_bound` rather than
  `absent`, because memory then holds a candidate it cannot confirm: read
  `hits[strongest_hit]`, and if it answers, retry with its own words.
  `absent` is the strongest negative memory can give, not proof. `source`
  narrows an evidence search to `git`, `items`, or `sessions` (transcripts
  and CI runs), and the verdict then carries `scope.source` and judges
  only that source's health: a failed, stale, or unchecked source of
  another kind, or pending ingest of another kind, does not block
  `absent` (the listing, readiness, and warnings stay scope-wide). An
  edited document's unchanged sections are listed once, at the item's
  presented head, with the superseded copies counted in
  `duplicates_collapsed`.
  `recall(status)` then adds
  an `evidence` block
  ([ADR 0006](../adr/0006-stage5-worker-and-evidence-recall.md)), with a
  `collectors` count once migration 34 is applied. A hit on a collected
  item's body names the item, its trust tier, and whether its version is
  still current.
- `recall(search|get, kind=item)` searches the items collectors admit
  (Slack, Linear, Granola, documents, ...) as items: each item's current
  version, with its provider, container, attested author, trust tier
  (`verified` pull or push, `reported` capture or import), the versions it
  superseded, whether a newer report disagrees, and advisory
  `injection_signals`. `source` filters by provider and `include_history`
  adds superseded versions; a deleted or withdrawn item is never recalled.
  `get` takes an item id, a version URI, or the item's provider URL and
  returns its versions with provenance and its links; a version admitted
  in a container since withdrawn shows no text. Item text is
  third-party content, labelled `untrusted_third_party`, with markdown
  images defanged. The absence verdict is judged over the collectors alone,
  with the same lexical anchor and 0.45 dense bound as evidence.
  It is served wherever migration 34 is applied and the writer login holds
  the collector grants
  ([ADR 0008 D7](../adr/0008-collected-items.md)).
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
  verified nonconformance only: an empty list is not proof of conformance.
  It is served wherever migration 31 is applied and the writer login may
  read the discrepancy, normative, and spec tables; elsewhere `tools/list`
  is unchanged.
  `recall(status)` then adds a `spec_conformance` block
  ([ADR 0007](../adr/0007-spec-conformance-chain.md)).
- `remember(record)` records a deliberate typed claim with provenance,
  idempotent mutation receipts, and conflict detection.
- `remember(assert)` records a typed claim event-first: one serializable
  transaction appends an accepted `memory.claim.accepted` event under the
  verified writer authority and writes the same claim projection, conflict
  detection, and receipt `record` writes. Today it admits one predicate. It
  is served and advertised only where the writer-authority pins verify at
  startup; elsewhere `tools/list` is unchanged and an assert is refused as
  `assert_unavailable`. `recall(status)` then adds a `remember_assert`
  block. See [asserting a claim](CLAIMS.md#asserting-a-claim) and
  [ADR 0005](../adr/0005-event-first-assert-and-writer-authority.md).
- `remember(capture)` relays items the calling agent read through its own
  connectors (a Slack thread, a Linear issue, a Granola note) into the
  collected-item sink as `reported` items it attests, so the fleet recalls
  them with `recall(kind=item)` and a claim can cite them.
  The server decides who may read each item and redacts secrets. It is
  served only where `FLEET_RECALL_COLLECTED_CAPTURE` turns it on and its
  startup checks pass; elsewhere `tools/list` is unchanged and a capture is
  refused as `capture_unavailable`. `recall(status)` then adds a
  `remember_capture` block. See
  [capturing items an agent read](COLLECTION.md#capturing-items-an-agent-read) and
  [ADR 0008 D10](../adr/0008-collected-items.md).
- A claim written by `record` or `assert` can cite the collected items it
  rests on, by item id, version id, or provider URL; `recall(get)` shows a
  claim's cited items and an item's citing claims. It is offered only where
  `recall(kind=item)` is served and migration 35 and its grants are in
  place; elsewhere every tool schema is unchanged. See
  [citing collected items in a claim](CLAIMS.md#citing-collected-items-in-a-claim)
  and [ADR 0008 D11](../adr/0008-collected-items.md).
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

## Retrieval and conflict behavior

Recall is hybrid: CockroachDB `VECTOR(512)` C-SPANN search and a stored
`TSVECTOR` inverted index, fused with reciprocal-rank fusion, over embeddings
from a pinned local model2vec model. A query is searched as its words:
punctuation, including characters CockroachDB's text search would read as
operators, only separates them, and a query of stopwords alone has an empty
lexical lane. A query the model cannot embed (every token outside its
vocabulary) runs no dense lane and carries a `query_not_embedded` warning;
claim search, which is dense only, then returns no claims. Every claim mutation
commits its claim, support, conflict, receipt, corpus projection, and audit
events in one serializable transaction; an assert also appends its accepted
event in that transaction.

Conflict detection uses the `same_key_functional_value_v2` detector. A claim
key (`subject::predicate` for a recorded claim, and
`claim-v2:<coordinate>:<modality>` for an asserted one) is functional over
overlapping effective intervals:
two affirmations conflict when their typed values differ, an affirmation and a
negation conflict only when they name the same value, and two negations are
compatible. Conflicting claims become `disputed`, and recall surfaces the open
conflict with the exact members that caused it instead of silently choosing
one. The detector compares typed propositions; it performs no natural-language
inference.

An agent never disputes itself. Where the writer serves `supersede`, a
`record` whose value would conflict with a lifecycle-current claim the same
agent already holds on the key is refused as `own_current_claim_on_key`
before anything is written; the refusal's `details` name the `claim_id`,
`revision`, and `claim_key`, and the agent sends `supersede` with that
`claim_id` and `expected_revision` instead, so its change of mind is an
audited succession rather than an open conflict with itself. Another
agent's disagreement still opens a conflict as before.

A conflict is never resolved by fiat. An agent can retract, supersede, or
concede only its own claims, and a conflict closes only when the detector
re-checks the key and finds no incompatible current pair left
([ADR 0004](../adr/0004-serving-conflict-lifecycle.md)). The one exception
is adjudication, which a deployment must enable: an agent that authored none
of a conflict's members may dismiss it as not a real disagreement, and the
pairs it judged never keep that conflict open again. A later close that leaves
such pairs out says so with `resolution_kind` `no_undismissed_incompatibility`
instead of `no_current_incompatibility`. No action changes another agent's
claim value, author, or applicability, but every close returns the conflict's
disputed members, whoever wrote them, to `active` at a new revision (unless
another open conflict still holds them). Acknowledgements, waivers,
dismissals, and detector-verified closes are appended to a per-conflict
lifecycle log (migration 0029). The writer serves `acknowledge`, `resolve`,
adjudication, the overlay, and history only when its startup probe finds that
log and the runtime grants on it; otherwise it serves `retract` and
`supersede` alone and closes are audited in `memory_events` only.
On the private writer, chunk search also drops the synthetic `claim:{id}`
hits of claims that are no longer current, lists them in
`diagnostics.retrieval.lifecycle_hidden_claim_ids`, and refills the page from
lower-ranked results. Setting `FLEET_RECALL_REMEMBER_LIFECYCLE=disabled` (the
default is `enabled`) restores the record-only lifecycle surface and
unfiltered chunk search. `assert`, evidence recall, and discrepancies do not
depend on that switch, so on a writer that serves none of them `tools/list`
is then the historical one byte for byte. The public demo always serves the
record-only surface.

For mutation examples, refusal codes, lifecycle history, replay and adjudication
bounds, see the [claims reference](CLAIMS.md#claim-and-conflict-lifecycle).

The service contract also reserves further Recall actions (for example
`remember` forget/relate and `recall` surface/discover) and an attention
schema. These return an error or are unused today; see the
[roadmap](../ARCHITECTURE.md#roadmap-and-open-work).

## Remote HTTP MCP

`ostk-fleet-recall serve --http 127.0.0.1:8080` serves authenticated MCP at
`/mcp`; plain `serve` retains its stdio protocol. OIDC, local Ed25519 keys,
and signed AWS STS proofs resolve through an explicit principal registry.
Operators receive an enrolled tenant/project/agent binding; launchers mint
revocable agent or shipper grants. The server also supports the 2026-07-28
`server/discover` protocol alongside legacy initialization.

See the [remote plane runbook](../REMOTE_PLANE.md) for enrollment, HTTP
configuration, client setup, permission boundaries, and verification. The
[local environment](../../deploy/local/README.md) can run HTTP on the Mac against
secure k0s CockroachDB and Ory without LocalStack.

## Start with a brief

Call `recall(brief)` first: it composes, in one
call, what an agent otherwise assembles from four to six. With `subject`
(normalized as `record` normalizes a key part, so `Final Round` and
`final_round` are one subject), it lists every lifecycle-current claim whose
key starts with that subject followed by `::` or `-` (so `final round` covers
`final-round::batch-size` and `final-round-2::x`, not `final::x`), oldest
first within each key, with each claim's support rows and `conflict_ids`; the
open conflicts on those claims (with the lifecycle overlay where it is
served); on a private writer `cited_providers`, how many of the claims cite
items of each collected-item provider; and, where evidence recall is served,
the `sources` behind those providers (or the worker's own git, transcript,
and CI sources when nothing is cited) with the projection `readiness`:

```json
{"action":"brief","subject":"final round","limit":32}
```

Abbreviated response shape (`…` stands for omitted content):

```text
{"subject":"final-round","as_of":"…","claims":[…],"claims_truncated":false,"conflicts":[…],"conflicts_truncated":false,"cited_providers":{"slack":1},"sources":[…],"readiness":{…},"absence_contract":{…}}
```

Without `subject`, it is the scope at a glance: `recent_claims`, the most
recently changed lifecycle-current claims newest first; `open_conflicts`,
every open conflict oldest first (bounded at 256) with the overlay, beside the
`conflicts` counts `recall(status)` reports; `sources`, the stale or failed
sources in full with a count of the active ones, and `readiness`; and the
`legacy_claim_keys`, `quarantine` (private reads only), and
`absence_contract` blocks of `recall(status)`:

```json
{"action":"brief"}
```

Abbreviated response shape:

```text
{"as_of":"…","recent_claims":[…],"recent_claims_truncated":false,"open_conflicts":[…],"open_conflicts_truncated":false,"conflicts":{"open":2,"acknowledged":0,"waived":0,"oldest_open_at":"…","bound_exceeded":false},"sources":{"stale_or_failed":[…],"active":4,"truncated":false},"readiness":{…},"legacy_claim_keys":{…},"quarantine":{…},"absence_contract":{…}}
```

`limit` bounds the claims (default 32, at most 64), and the answer is cut to
the same response budget as `get`, with the `*_truncated` flags saying so.
Every block is read under the same deadline as `recall(status)`'s blocks, so a
failed or slow read is `null` with its `*_unavailable` warning and the brief
still answers; the answer carries the warnings of every read it composes. The
publication reader's brief withholds asserted claims and item support rows,
never reads the quarantine or the claim item links, and carries no overlay.
Nothing in a brief is third-party text: claim support carries digests, ids,
and the citing link, never an item.

## Reading status

`recall(status)` reports what an operator can act on: `conflicts` (`open`,
`acknowledged`, `waived`, `oldest_open_at`; the lifecycle counts are `null`
where the overlay is not served), `quarantine` (`by_reason` and the newest
`preimage_disagreement_sample`, read on private writers only),
[`legacy_claim_keys`](CLAIMS.md#legacy-underscore-keys), and, wherever an absence verdict is served,
`absence_contract`: the dense bound, the neighbour band floor below which a
verdict is `unknown` rather than `absent`, the media types excluded from the
dense vote, and that the verdict is anchored on the lexical lane.

For service liveness, database readiness, dependency failures and alert triage,
use the [local operations guide](../../deploy/local/https/OPERATIONS.md) and
[telemetry reference](../TELEMETRY.md). `recall(status)` is an authenticated
application report; it is distinct from `/healthz` and `/readyz`.

## Trust and safety boundaries

- Stdio binds one non-nil tenant, project, and trusted agent from deployment
  configuration. Authenticated HTTP derives those coordinates from the principal
  registry or a checked session grant. Both use the current `t1_project` privacy
  tier. MCP may repeat project, agent, actor, or privacy as exact assertions;
  it cannot redirect them. Tenant is never a wire field.
- Session is a caller-selected subdivision under the trusted agent, not an
  authorization principal. Privacy narrowing is rejected because durable
  owner/tier row visibility is not implemented yet.
- Actor provenance is derived from the trusted agent binding. A supplied
  `remember.actor` is only an exact assertion and is stripped at the MCP edge.
- Lifecycle authority is owner-only: `remember(retract)`,
  `remember(supersede)`, and the retractions of `remember(resolve)` change
  only an `operator_asserted` claim whose stored actor is the trusted
  agent binding, and a successor keeps its predecessor's kind, key, and
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
  changes no claim or conflict row. `remember(acknowledge)` is open to every agent
  because it changes nothing but the overlay. Every refusal rolls the whole
  transaction back. The lifecycle log is append-only for the runtime
  role and never granted to the publication reader. Stdio authority depends
  on the deployment's `FLEET_RECALL_AGENT` binding;
  HTTP authority depends on its enrolled identity or checked grant. Both
  ultimately use the shared writer credential and scoped repositories.
- Event-first writes (`remember(assert)`, the memory worker, and `ostk-spec`)
  append accepted events only under the registry head their pins verify,
  re-verified for every request, tick, or command. That head's governance
  signatures and `ostk-spec`'s approvals use public fixture keys and are
  nominal: the real gates are the migrator credential that installs a head
  and the shared `fleet_writer` credential every writer uses. The worker's
  `project` step writes governed content in plaintext to the body plane, which
  the writer login reads without the content key. See
  [security policy](../SECURITY.md#event-first-writers-and-the-content-key).
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
  The authenticated HTTP MCP plane has its own identity and authorization
  boundary; exposing the demo does not enable it. See the
  [remote security boundary](../SECURITY.md#authenticated-remote-plane).
- In the checked-in AWS publication-demo topology, CloudFront terminates viewer
  HTTPS with its default
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

See [security and supply-chain policy](../SECURITY.md) and the
[architecture](../ARCHITECTURE.md) for the complete invariants.
