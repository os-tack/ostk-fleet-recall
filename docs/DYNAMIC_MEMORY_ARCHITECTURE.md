# Dynamic corpus and causal runtime architecture

Status: **target architecture; stages 1–3 frozen; stage 4 partially implemented; stages 5–10 contract vectors in progress**

Fleet Recall currently serves a statically generated, revision-linked corpus
and a deliberate typed-claim ledger. This document defines the target model in
which that static corpus becomes a bootstrap snapshot and the durable memory is
a replayable projection of authenticated evidence events.

This is not a description of the judging deployment. The implemented system is
documented in [ARCHITECTURE.md](ARCHITECTURE.md), its security boundary in
[SECURITY.md](SECURITY.md), and the local-versus-fleet product decision in
[ADR 0001](adr/0001-product-and-backend-boundary.md).

No connector, webhook, queue, incident controller, asynchronous embedding
worker, or public mutation route is implied to exist today. The current source
does implement the bounded PUBLIC-03 publication identity and planned AWS task
input separation; those Terraform changes have not been applied.

## Purpose

The target system should retain the complete through-line from intent to
consequence:

```text
transcript -> decision -> code -> commit -> review -> merge -> CI
           -> artifact -> deployment -> runtime observation
           -> discrepancy -> investigation -> intervention -> verified outcome
```

An agent should be able to answer not only "what was decided?" but also:

- Which exact change implemented the decision?
- Which review and CI run accepted that revision?
- Which artifact and configuration reached an environment?
- What did that deployed workload do afterward?
- Which evidence supports or refutes a proposed cause?
- Which intervention restored the expected behavior?

The graph explains provenance and possible causation. It must never become a
loophole through which an unlinked code change avoids comparison with an active
specification.

## Baseline and target

| Concern | Implemented baseline | Target |
|---|---|---|
| Corpus | Bounded NDJSON is synchronously embedded and upserted through a trusted seed path | Bootstrap plus projections from an immutable event stream |
| Repository | Current coordinate-addressed chunks with exact source links | Content-addressed versions plus commit/ref membership |
| Evidence | Searchable chunks and exact hash-bound claim support | First-class immutable provider and collector evidence |
| Claims | Deliberate typed claims with validity and source support | Propositions with modality, authority, applicability, and derivation |
| Conflicts | Versioned functional-key exact-value/polarity conflicts | A generalized, non-destructive discrepancy ledger |
| Links | Claim-to-claim relationships are reserved in the schema | Heterogeneous provenance links and separately graded causal hypotheses |
| Events | Claim mutation audit events | Authenticated, versioned, replayable evidence inbox and outbox |
| Availability | Embedding completes before a corpus row is searchable | Lexical availability first; dense projection asynchronously follows |
| Runtime | CloudWatch application logs and deployment receipts outside memory | Bounded observation, alert, incident, action, and verification receipts |
| Public surface | Read-only routes plus a source-enforced publication database/IAM input boundary | Permanently isolated, least-privilege publication plane across the broader dynamic system |

The existing tables remain useful projections. They are not silently redefined
as the immutable source of truth.

## Vocabulary

### Evidence

Immutable bytes or provider observations: transcript turns, Git objects,
provider events, CI attempts, artifact manifests, deployment events, metric
windows, traces, logs, approvals, and action receipts.

Evidence proves only what its authority can observe. A Git commit proves exact
bytes and ancestry; it does not prove that the code is correct or deployed.

### Proposition

A typed statement derived from or explicitly supported by evidence. A
proposition includes a subject, predicate, value, modality, applicability, and
effective interval.

Supported modalities are:

- `normative`: what must be true;
- `observed`: what a bounded observer established;
- `intended`: what an actor proposes or plans;
- `attested`: what an actor says occurred.

### Provenance relation

A typed relationship whose proof can often be established from provider
identities, such as a build consuming a commit or a deployment selecting an
artifact digest.

### Causal hypothesis

An explanation for an outcome. Temporal proximity may propose a hypothesis,
but never verifies causation by itself.

### Discrepancy

A durable finding created by comparing compatible propositions or by detecting
a required lifecycle or provenance gap. Retrieval determines when a relevant
discrepancy is shown; retrieval does not determine whether it exists.

### Projection

A rebuildable materialized view of immutable events: searchable passages,
embeddings, current repository membership, active propositions, deployed
cohorts, open discrepancies, or the publication-approved public corpus.

## Stable invariant registry

Invariant identifiers are stable design references. Renumbering an invariant
must not disguise a semantic change.

### Evidence and identity

- **EVID-01 — Immutable evidence.** The accepted ledger envelope is append-only.
  Correction, deletion, and provider mutation create new events or lifecycle
  projections; they never rewrite that envelope. Canonical or raw governed
  payload bytes live behind typed content references unless their retention
  class explicitly permits immutable inline retention. A retention or erasure
  policy may cryptographically remove governed payloads while preserving only
  the immutable tombstone, digest, and lifecycle metadata policy permits.
- **EVID-02 — Exact coordinates.** Evidence retains a provider identity,
  immutable object version, payload digest, and bounded source coordinate or
  raw-artifact reference.
- **EVID-03 — Separate clocks.** Occurrence, provider observation, receipt, and
  projection times are distinct. Effective/event time and accepted/system time
  are both preserved so late evidence cannot rewrite what was knowable during
  an earlier incident. Ingestion order is not event order.
- **EVID-04 — No authority from payload routing.** Tenant, project, connector,
  and principal authority come from authenticated configuration or workload
  identity, never caller-selected payload fields.
- **EVID-05 — Secrets never enter recall.** Secrets are redacted before any
  durable outbox, searchable projection, or embedding operation. Non-secret
  private evidence may enter only a policy-authorized private projection and
  never the public publication projection. A private raw archive, when
  enabled, has a separate key, policy, and retention boundary.
- **EVID-06 — Recalled content is untrusted data.** Transcript turns, source
  text, review comments, logs, and provider payloads never supply instructions,
  identity, authority, tool permission, or action approval merely because they
  were retrieved.
- **EVID-07 — Visibility is enforced before retrieval.** Private, team, and
  public visibility are durable evidence attributes. Authorization predicates
  are applied inside lexical and ANN access paths before ranking; post-filtering
  an unauthorized result is not an isolation boundary.
- **EVID-08 — Erasure is policy-governed and evidenced.** When legal, privacy,
  or retention policy requires physical erasure, authorized private payloads,
  searchable text, embeddings, and encryption keys are removed. An immutable
  tombstone, digest, and erasure receipt remain only where policy permits.
  Append-only history does not mean indefinite retention of private bytes.
- **EVID-09 — Erasure dominates replay and restoration.** Active erasure
  tombstones and policy receipts are applied before any event, backup, archive,
  or historical representation may materialize a searchable payload, passage,
  embedding, exemplar, or private link. Reprojection and disaster recovery
  cannot resurrect erased content. Tombstones and digests remain only where
  governing policy permits.

### Predicates and propositions

- **PRED-01 — Typed comparison only.** Semantic similarity may nominate a
  candidate. It cannot open a verified discrepancy.
- **PRED-02 — Predicate-specific comparison.** Each automatically comparable
  predicate has a versioned value schema, unit, comparator, required scope,
  and absence semantics.
- **PRED-03 — Unknown remains unknown.** Missing context, unsupported
  predicates, and ambiguous values never silently mean agreement or `any`.
- **PRED-04 — Modality is explicit.** Normative, observed, intended, and
  attested propositions are not interchangeable.
- **PRED-05 — Derivation is reproducible.** Derived propositions retain exact
  supporting evidence, extractor/verifier identity and version, comparator
  version, and derivation receipt.

### Authority and applicability

- **AUTH-01 — Authority is predicate-specific.** No source or actor receives a
  global truth rank.
- **AUTH-02 — Provider facts remain bounded.** A verified Git object
  establishes bytes and parent identities for that object ID; a provider ref
  event establishes the provider's observed ref state. GitHub proves its
  PR/review/merge facts; CI proves a named attempt result. A deployment
  control-plane event proves only its registered predicates, such as desired
  state, cohort membership, or rollout status; request-serving identity needs
  workload/telemetry evidence. Telemetry proves a bounded measurement.
- **AUTH-03 — Agents cannot self-promote.** An agent assertion may declare an
  edge or proposition. It cannot turn itself into provider proof, approve its
  own production action, or silently resolve its own discrepancy.
- **AUTH-04 — Normativity is designated.** A Markdown path is not normative by
  default. A registry and its activation policy designate specifications,
  accepted ADRs, policies, SLOs, and ratified decisions.
- **APPL-01 — Required selectors resolve against one concrete context.** A
  comparison requires the same tenant, project, compatible predicate-schema
  version, canonical subject, and predicate. The versioned applicability
  evaluator must establish that every predicate-required selector matches the
  same concrete context. A dimension explicitly declared `any` need not be
  equal; a missing required dimension yields `unknown`. Proposition and
  discrepancy derivations retain the evaluator version.
- **APPL-02 — Null is not global.** Omitted applicability dimensions produce
  `unknown` unless a versioned rule explicitly declares `any`.
- **APPL-03 — Current is a projection.** Default-branch, PR-head, built,
  released, and deployed state are different projections and cannot silently
  substitute for one another.

### Coverage and absence

- **COVER-01 — Absence requires exhaustive coverage.** An AST/schema observer
  may prove an enum member absent after reading the exact complete revision. A
  failed semantic search may not.
- **COVER-02 — Missing links require watermarks.** A connector may establish a
  provenance gap only when its cursor or provider sequence proves complete
  coverage of the applicable scope and interval.
- **COVER-03 — Completeness and continuity are separate.** Every coverage
  receipt records `complete`, `partial`, or `unknown` coverage, current or stale
  freshness, and separately records whether the observed provider sequence is
  contiguous or has a known gap. `gap_detected` means a known acquisition or
  sequence gap makes coverage incomplete; it never proves semantic absence.
  Only complete, current coverage under a registered proof method can support a
  negative proposition or verified provenance gap.

### Events, relations, and replay

- **EVENT-01 — At-least-once transport, one semantic effect.** Exact replay is
  a no-op. Reprocessing a source fact under a new representation version
  supersedes its old representation without repeating its lifecycle effect.
  Different canonical bytes under the same source-fact and representation
  identity are quarantined as an integrity collision.
- **EVENT-02 — Mutable resources emit versions.** A changed PR, alert, flag, or
  deployment produces a new observation or transition rather than overwriting
  its earlier evidence.
- **REL-01 — Relation status is projected from evidence.** Relations receive
  append-only attestations that support or refute an exact typed edge.
  Untrusted payloads may contribute only declared or inferred attestations.
  Verified, refuted, and superseded states are rebuildable projector outcomes
  produced by registered proof recipes; no payload selects them directly.
- **PROV-01 — Exact identifiers bind lifecycle edges.** Reviews bind a head
  SHA, builds bind a source revision, artifacts bind a digest, and deployments
  bind exact artifact/configuration identities. Mutable labels are insufficient
  where immutable identities exist.
- **CAUS-01 — Proximity is not causality.** Time adjacency can create a causal
  hypothesis but not a verified provenance relation or ratified cause.
- **REPLAY-01 — Semantic projections are rebuildable.** Replaying accepted
  immutable events with the same registry and projector versions yields
  identical semantic identities, memberships, propositions, relation states,
  discrepancy fingerprints, and lifecycle state. Nondeterministic enrichment
  such as remotely generated embeddings is versioned separately and cannot
  affect those identities or discrepancy correctness.
- **REPLAY-02 — Each projection advances atomically.** Every projector advances
  its own cursor atomically with that stage's complete durable outputs.
  Lexical, dense, graph, and discrepancy projectors expose independent
  watermarks; asynchronous dense work does not block lexical acknowledgment.
- **EVENT-03 — One immutable write history.** Deliberate claims, decisions,
  relation attestations, discrepancy transitions, resolutions, waivers,
  authorizations, and action receipts are accepted as events before or
  atomically with their projections. Synchronous `remember` may commit its
  event and projection in one serializable transaction; it is not a second
  source of truth outside the event history.

### Discrepancies

- **DISC-01 — Evidence becomes a typed observation first.** Raw chunks do not
  participate directly in automatic incompatibility decisions.
- **DISC-02 — Provenance and compatibility are independent.** A missing causal
  link cannot hide a verified spec/code mismatch. Adding the link closes only
  the provenance gap.
- **DISC-03 — Findings are non-destructive.** Resolution appends evidence and
  ends or transitions the discrepancy occurrence's active interval. It does
  not alter a member proposition's applicability unless separate supersession,
  retraction, correction, or scope evidence does so. Prior finding and
  resolution history remains immutable.
- **DISC-04 — Surfacing is query-local and explainable.** A discrepancy
  surfaces through a retrieved member, exact cited evidence, or a versioned
  subject resolver that maps the query to the same canonical subject and
  returns its match explanation. Semantic similarity alone does not satisfy
  the subject-resolution branch. Unrelated queries do not receive global
  warnings.
- **DISC-05 — Waivers are durable policy.** A waiver is explicit, attributed,
  scoped, and expiring where practical. It does not rewrite evidence.
- **DISC-06 — Comparisons cite a registered comparator lineage.** A discrepancy
  envelope binds a `comparator_lineage_fingerprint` and its required
  applicability dimensions to the exact registered
  `RegistryEntryKind::ComparatorLineage` entry (`registry.comparator_lineage`,
  reserved generation-2-only by W0-REG-2), not to the producer's own
  declaration. That kind is generation-2 only, so no genesis, successor, or
  Stage-4 package admits it today: a comparator lineage is carriable through a
  manifest-verified registry package and structurally resolved, but full
  typed-body dispatch is deferred to a later generation. Comparison never runs
  against an unregistered or ad-hoc lineage.

### Consolidation lane

Reserved by ADR 0003 (`docs/adr/0003-consolidation-and-conflict-tolerance.md`),
which owns the full rationale. The ten definitions below are the ADR's own
one-line statements, reproduced verbatim so the registry stays the single place
an identifier is looked up. No CONS invariant has a runtime today; the
consolidation contract module implements the read side of conflict tolerance
only.

- **CONS-01 — Consolidation is derivation, never mutation.** It appends new
  claims, links, support, and lifecycle events. Replacement is supersession,
  which preserves history.
- **CONS-02 — Exact, atomic lineage.** Every derivative binds the exact sorted
  source claim ID+revision set, consolidator identity/version, registry digest,
  and derivation receipt. Claim, links, support, events, and receipt commit in
  one transaction. A consolidation that cannot record full lineage does not
  commit.
- **CONS-03 — No authority promotion.** Output kind, modality, and confidence
  are computed by a versioned policy and are never stronger than the weakest
  input. Consolidation cannot create normativity, verify the unverified, or
  close an `open_question`.
- **CONS-04 — Conflicts are non-launderable.** If any source is a member of a
  conflict in `open` or `waived` state, the run either fails closed or produces
  a `disputed` claim that preserves the disagreement and references the
  conflict. Consolidation never resolves, dismisses, waives, or hides a
  conflict. A waived conflict is still an open incompatibility for this rule.
- **CONS-05 — Deterministic identity, idempotent replay.** Re-running with the
  same inputs and idempotency key is a no-op. The same inputs under a new
  consolidator version produce an explicitly superseding derivation, not a
  duplicate.
- **CONS-06 — Scope containment.** Output tenant, project, and visibility are
  the server-derived intersection of input scopes. Cross-scope candidate sets
  fail closed. Private inputs never reach the publication projection through a
  summary.
- **CONS-07 — Erasure dominates derivatives.** Derivatives are indexed as
  materializations of every source. Source erasure or retention expiry forces
  re-derivation or tombstoning before the derivative is served; a derivative
  whose only reproducible support is gone becomes `unsupported` or
  `unverifiable`, and dependent conflicts are recomputed (EVID-08, EVID-09).
- **CONS-08 — Lifecycle coupling.** Supersession, retraction, or expiry of a
  source emits a re-evaluation event for its derivatives. A derivative whose
  entire live support is gone cannot silently remain `active`.
- **CONS-09 — Acyclic, depth-accounted lineage.** The derivation graph rejects
  cycles. Claims beyond a registered consolidation depth are excluded from
  candidate nomination unless a versioned policy explicitly permits deeper
  derivation.
- **CONS-10 — Detector re-entry.** A same-key relationship between a derivative
  and its own sources is governed by a registered comparator rule —
  transaction-atomic supersession or an explicit derivation exemption — never
  an ad-hoc detector skip.

Where ADR 0003's conflict-tolerance section and this document's discrepancy
model differ, this document's registry wins; ADR 0003's 2026-08-16 addendum
records that disposition and fixes the total, conservative mapping from the
six-state discrepancy lifecycle to the contract's three read-side states.

### Runtime and actions

- **RUN-01 — Telemetry is evidence, not causation.** A metric excursion is an
  anomaly until compared with an applicable SLO, invariant, or contract.
- **RUN-02 — Mixed rollouts remain mixed.** Environment-level observations
  cannot implicate one workload revision unless revision/cohort attribution is
  present.
- **RUN-03 — Material runtime inputs are registered.** Diagnosis compares all
  registered material inputs—code, configuration, flags, migrations,
  dependencies, infrastructure, traffic, and upstream state—and explicitly
  reports every unknown or unobserved dimension.
- **ACT-01 — Recommendation, authorization, execution, and verification are
  distinct authorities.** Confidence never grants permission.
- **ACT-02 — Approval binds immutable intent.** Authorization names the exact
  proposal digest, environment, current and target state, preconditions,
  scope, expiry, and permitted uses.
- **ACT-03 — Stale actions fail closed.** Execution rechecks current state with
  compare-and-swap semantics and uses an idempotency key. Reuse of an
  idempotency key with a different proposal digest or canonical execution
  request fails closed. Authorization expiry, remaining uses, and preconditions
  are revalidated immediately before execution.
- **ACT-04 — Recovery is not root-cause resolution.** Restored service may mark
  an incident mitigated while the defect and causal conclusion remain open.

### Public boundary

- **PUBLIC-01 — CloudFront is permanently read-only.** The publication plane
  exposes bounded UI, health, status, and recall operations only. `POST
  /api/recall` remains a read operation.
- **PUBLIC-02 — No shared control surface.** Ingestion, webhooks, connector
  administration, acknowledgment, resolution, authorization, and execution do
  not share the public router or hostname.
- **PUBLIC-03 — Least privilege is enforced below the router.** The public task
  uses a distinct ECS execution role authorized only for its reader secret, a
  distinct task/service role where applicable, and a CockroachDB read
  principal. It cannot read writer or action credentials. Absence of HTTP
  mutation routes alone is insufficient.
- **PUBLIC-04 — Public scope is fixed.** The publication projection contains
  only approved evidence under a server-bound tenant/project and exposes no
  caller-selected authority, actor, or private source coordinate.

The checked-in PUBLIC-03 implementation fixes the external login as
`fleet_publication` and its logical `NOLOGIN` role as
`fleet_publication_reader`. The role has only `CONNECT` on `fleet_recall`,
`USAGE` on `public`, and `SELECT` on the eight startup/status/recall tables; it
has no sequence, DML, DDL, system, delegation, or private-table authority. The
public process admits only `FLEET_RECALL_PUBLICATION_DATABASE_URL`, while its
pool witnesses the login, database, fixed application name, and canonical
search path on both new and reused connections. Checked-in Terraform supplies a
distinct publication secret, execution role, task role, and KMS scope, but that
plan remains unapplied.

## Epistemic contract registry

The registry is the next contract to define before transport or schema work.
It decides what evidence is comparable, what a source can prove, and where a
proposition applies.

Every registry snapshot has an immutable revision, content digest, activation
event, and effective interval. Propositions, relation attestations,
projections, and discrepancy derivations cite the exact registry digest rather
than a mutable policy name.

### Predicate schema

Each automatically evaluated predicate needs:

```text
schema ID and version
subject kind and canonical predicate
value schema and unit
cardinality: functional, set-valued, or another closed registered algebra
allowed modalities
comparator and incompatibility algorithm version
required applicability dimensions
closed-world/absence semantics
publication and sensitivity default
```

Unknown predicates remain searchable evidence but cannot automatically open a
verified discrepancy. Negative propositions require a coverage receipt.

The legacy `same_key_functional_value_v2` detector is intentionally narrower
than this target registry. It treats each conflict-eligible
`subject::predicate` key as functional: distinct affirmative values conflict,
affirmation and negation conflict only for the same exact value, and two
negations remain compatible. That rule must not be generalized to set-valued,
open-world, threshold, or finite-domain predicates. A target comparator must
bind cardinality together with polarity, modality compatibility, concrete
applicability, effective interval, and any coverage proof. Changing any of
those inputs creates a new comparator lineage and discrepancy family rather
than silently reinterpreting an earlier occurrence.

Examples include:

- `mcp.remember.allowed_actions`: a set derived exhaustively from an exact
  schema/AST revision;
- `deployment.artifact_digest`: exact digest equality;
- `review.approves_revision`: an exact reviewed head SHA;
- `http.route.error_rate`: a ratio, evaluation window, and scoped dimensions
  compared with an active threshold.

### Authority rule

An authority rule is a proof capability, not a trust score:

```text
rule ID and version
predicate schema and modality
admissible evidence kind and provider/connector
verifier or extractor identity and version
applicability selector
maximum authority outcome: provisional or verified
ratification policy: none or required
effective interval and activation evidence
```

Overlapping rules may coexist and corroborate. Incompatible authoritative
results or unresolved precedence/activation policy create a governance
discrepancy; neither rule silently wins.

### Applicability

Observed contexts are concrete:

```text
repository + commit + ref observation
environment + region
service + route template
deployment + workload revision + cohort
artifact + config + flag + migration digests
time window
```

Expectations select contexts with explicit operators such as exact match,
commit ancestry, interval overlap, or explicit `any`. Missing a required
dimension yields `unknown`.

### Coverage receipt

A coverage receipt establishes when absence is meaningful:

```text
observer or connector and version
exact scope/revision/window
cursor or provider sequence
coverage completeness: complete, partial, or unknown
freshness: current or stale under the registered rule
sequence continuity: contiguous or gap_detected
observed-through time
coverage proof/basis, such as an enumerated snapshot or closed cursor interval
source digest/count and evidence ID
```

The evaluated condition (`present`, `absent`, or `indeterminate`) is separate
from coverage completeness and sequence continuity.

This permits an unlinked code change to produce two independent findings:

- `spec_nonconformance`, when exhaustive code evidence contradicts an active
  normative proposition;
- `provenance_gap`, only when connector/graph coverage proves that no
  qualifying decision, task, or exception link exists.

### Proposition record

A proposition binds:

```text
proposition ID and predicate-schema version
canonical subject resource and predicate
canonical value, unit, and modality
concrete observation context or expectation selector
effective time/revision applicability and recorded time
supporting evidence IDs and coverage receipts
extractor/derivation identity and version
authority-rule evaluation result and registry snapshot
state and explicit supersession/retraction links
```

Authority is computed from evidence, rules, and applicability; it is not a
caller-selected proposition field.

## Canonical evidence event

The transport-neutral envelope should contain:

```text
credential-bound tenant and project
source-fact identity: connector/provider logical identity + immutable revision
representation key: source-fact identity + identity-recipe closure + schema/canonicalization/redaction versions
canonical payload digest: stored and verified separately from the representation key
schema name and version
authenticated connector principal and connector instance
provider and provider-reported actor identity
provider delivery ID: transport receipt only
logical event key defined by the connector schema
canonicalization profile ID and digest
provider object/event ID and immutable revision
entity kind, canonical resource ID, and identity-recipe ID/version/digest
occurred_at, observed_at, received_at
canonical payload digest plus typed content reference
optional inline canonical redacted bytes only when immutable retention is allowed
optional private raw-artifact reference and digest
redaction policy/version
integrity/signature state
server-derived visibility/protection domain and classifier policy version
server-derived retention class/policy and erasure-index scope references
server-derived publication classification and publication-policy version
```

The authenticated ingress principal does not authenticate the
provider-reported actor. The local collector redacts and writes the canonical
envelope to a durable outbox before delivery. Transport delivery IDs deduplicate
ingress attempts only. The semantic-effect key is the credential-bound
connector/provider logical fact identity plus immutable provider revision; it
excludes delivery, canonicalization, and redaction versions. Schema,
canonicalization, redaction-policy, and identity-recipe versions identify a
representation of that source fact. The identity-recipe digest is the closure
over its exact resource-kind schema and namespace-definition dependencies.
Reprocessing under a new representation version creates an
explicitly superseding representation and deterministic reprojection, not a
second provider fact or duplicate lifecycle transition. Different canonical
bytes for the same source-fact and representation identity are quarantined as
an integrity collision. Late and out-of-order events are expected.

## Ingestion and projections

```text
local transcript collectors --+
Git provider webhooks ----------+--> authenticate and bind scope
CI/build events ----------------+             |
release/deploy events ----------+             v
telemetry/alert events ---------+    schema-validate and canonicalize
                                              |
                                      redact and classify
                                              |
                                    durable transport queue
                                              |
                               append accepted immutable evidence
                                              |
                                          derive and link
                                              |
                              immediate lexical evidence projection
                                              |
                                    asynchronous embedding worker
                                              |
                       propositions, discrepancies, and current views
```

The queue and provider are implementation choices. Correctness belongs to the
event identity, registry, projector, and replay contracts. A transport delivery
is not evidence until it is authenticated, scope-bound, schema-validated,
canonicalized, redacted/classified, and appended to a retention-guaranteed
evidence store. Only then may the transport message be acknowledged. SQS or an
equivalent queue is transport, not the indefinite evidence ledger.

Local transcript collectors redact before writing their outbound outbox. Raw
provider deliveries, when retention is required, remain inside the separately
governed private archive boundary. Rejected deliveries create only bounded
quarantine records and never enter searchable projections.

Large raw logs, trace collections, and artifacts remain in their authoritative
provider or a private object archive. CockroachDB stores bounded summaries,
query/rule versions, hashes, exemplars, projection state, and durable links.

Every projected row or atomic batch retains:

```text
projection name and version
registry snapshot digest
source event IDs or closed input watermark
derivation digest
effective and recorded times
applicability context
readiness and completeness state
```

When provider ordering and graph reachability cannot establish one current
state, the projection remains ambiguous or `unknown`; it never invents a total
order from arrival time.

## Repository history

The target repository model does not duplicate every unchanged file for each
commit:

- blobs and chunks are content-addressed;
- a commit/ref projection records membership of exact chunk versions;
- unchanged content reuses its text and embedding;
- changed files produce new line-addressable versions;
- the observed default branch becomes one current view;
- PR heads and deployed releases remain separate views;
- force-pushed and superseded versions remain historical.

A verified provider ref update atomically advances that exact ref projection. A
merge contributes provenance, but it advances the default-branch view only when
provider evidence establishes that the configured default ref reaches the merge
result. It does not make the revision built, released, or deployed.

## Provenance graph and causal hypotheses

Relation types are versioned contracts:

```text
relation type and version
allowed endpoint resource kinds and direction
required applicability dimensions
proof recipe and verifier version
multiplicity and temporal semantics
```

An exact relation fingerprint receives append-only supporting or refuting
attestations. Each attestation records its kind (`declared`, `inferred`,
`provider_attested`, or `verifier_result`), evidence ID, verifier version, and
effective/recorded time. The current relation state is a rebuildable projection
over those attestations.

The desired provenance graph is illustrated below. It is a partial,
many-to-many graph rather than a required total order; individual edges enter
the verified projection only when their registered proof recipe succeeds.

```text
turn -> proposed decision -> ratified decision -> work item
     -> commit -> PR -> review at head SHA -> merge SHA
     -> CI attempt -> artifact digest -> deployment/cohort
```

One revision may have multiple reviews and CI attempts; CI may run before or
after merge; and commits, builds, artifacts, and deployments are not assumed to
be one-to-one. Some edges are provider-verifiable; others remain declared. In
particular, `turn -> commit` remains declared unless an independently trusted
attestor binds the repository, commit OID, tree, parents, and operation outcome
to the exact turn/tool receipt.

Explanatory causal hypotheses have two independent axes.

**Support level:** `possible`, `scope_associated`,
`mechanistically_corroborated`, or `intervention_supported`.

**Adjudication state:** `open`, `ratified`, `refuted`, or `superseded`.

Evidence may raise or lower support. An authorized incident conclusion changes
adjudication state but does not rewrite supporting or opposing evidence. These
labels are not opaque confidence scores.

## Discrepancy model

The generalized discrepancy envelope needs:

```text
type, state, and severity
stable fingerprint and episode identity
subject, predicate, and applicability
proposition and/or lifecycle members
supporting and opposing evidence
detector, comparator, registry, and extractor versions
coverage receipts
detected, effective, acknowledged, waived, and resolved times
append-only lifecycle events and resolution evidence
```

Finding types include:

- `claim_conflict`;
- `claim_evidence_contradiction`;
- `spec_nonconformance`;
- `documentation_drift`;
- `provenance_gap`;
- `lifecycle_gap`, with subtype `validation`;
- `runtime_nonconformance`, with subtype `slo_breach`;
- `configuration_drift`;
- `release_integrity_conflict`;
- `regression_candidate`;
- `telemetry_disagreement`.

Causal hypotheses are separate resources linked to incidents, discrepancies,
changes, and interventions; they are not discrepancy types.

Verification states are `candidate`, `verified`, `refuted`, and
`indeterminate`. Lifecycle states are `open`, `acknowledged`, `resolved`,
`waived`, `dismissed`, and `superseded`. Reopening creates a new lifecycle
event or episode; it does not clear prior resolution evidence.

Late or corrective evidence about the same effective interval appends to the
same episode. A recurrence after a resolved interval creates a new occurrence
linked by the stable discrepancy-family fingerprint. Verification state is
separate from lifecycle and changes without erasing lifecycle events.

## Runtime observations and incidents

Keep three resources distinct:

1. a bounded measurement receipt;
2. an SLO/rule evaluation;
3. an alert lifecycle event.

A measurement receipt binds:

```text
telemetry provider and query identity/version
query digest and durable provider link
window start/end and evaluation time
aggregation, unit, result, and sample count
dimensions, coverage, and missingness
deployment/workload/artifact/config identities when available
bounded exemplars and private raw-artifact reference
```

An SLO/rule evaluation binds the normative proposition or rule version, exact
measurement receipt IDs, comparator and applicability-evaluator versions,
concrete context, coverage result, and comparison outcome.

An elevated metric without an expectation is an anomaly. An applicable SLO or
runtime contract plus an incompatible measurement may create verified runtime
nonconformance only when rule authority, measurement integrity,
applicability, comparator, and required coverage all verify. Otherwise the
result remains candidate or unknown. A nearby deployment creates only a
regression candidate.

An incident traversal may then follow:

```text
alert -> metric window -> route -> serving cohorts -> deployment
      -> artifact -> build -> commit diff -> PR/review -> decision/spec
```

The investigation compares all registered material runtime inputs against the
last-known-healthy state and reports unknown dimensions. `last-known-healthy`
is itself a versioned projection whose selection rule, exact context, and
supporting healthy observation window are retained; an investigator cannot
choose it ad hoc. A rollback that restores the metric is intervention support
for a hypothesis, not by itself an absolute causal proof.

## Action protocol

Production response requires four distinct durable resources:

```text
action proposal
  exact operation/target, expected pre-state, desired outcome,
  expiry, risk, rollback plan, immutable proposal digest

authorization
  decision-maker, proposal digest, allowed scope/conditions/uses, expiry

execution attempt
  proposal and authorization IDs, attempt/idempotency key,
  revalidated authorization and pre-state, provider request ID, started time

execution receipt
  attempt ID, exact before/after identities, provider result,
  completion/error digest and reconciliation state

verification
  metric/query/rule, observation window, result, mitigation conclusion
```

Initial incident agents remain read-only. Automatic remediation is admissible
only under an explicit policy with a bounded blast radius, known-safe target,
compatible data/schema state, a pre-authorized policy ratified by a separate
principal, and an execution protocol that still binds the exact proposal,
current state, target, scope, and expiry.

An ambiguous provider outcome is `indeterminate`, not failure. The same attempt
is reconciled by provider request ID and read-after-write state; a timeout never
authorizes a new action identity.

## Public read plane and private control plane

The target is physically asymmetric:

| Public publication plane | Private ingestion/control plane |
|---|---|
| CloudFront demo hostname | Separate authenticated hostname or provider ingress |
| UI, health, status, bounded recall | Collector/webhook ingestion, projection control, incident mutation |
| Fixed tenant/project publication scope | Credential-bound connector/project authority |
| Publication-approved evidence only | Private evidence and operational receipts |
| Reader-only ECS execution/task roles and CockroachDB principal | Least-privilege writer/executor identities by role |
| No action credentials | Short-lived scoped action credentials |

The current source enforces the first bounded version of that asymmetry below
the router. `demo` rejects every private writer/control/test database variable
and accepts only the fixed `fleet_publication` URL for `fleet_recall`. Its
`fleet_publication_reader` role has database `CONNECT`, public-schema `USAGE`,
and `SELECT` on exactly `_sqlx_migrations`, `memory_corpus_models`,
`memory_chunks`, `memory_claim_embeddings`, `memory_claim_support`,
`memory_claims`, `memory_conflict_members`, and `memory_conflicts`. It has no
sequence or mutation/DDL authority. Every new and reused pooled connection
re-witnesses the fixed login, database, application name, and canonical search
path. Terraform now separates the publication secret, execution role, task
role, and customer-managed KMS key scope from writer paths.

That is source evidence, not a claim about the historical judging deployment.
The official CockroachDB v26.2.3 TLS wrapper and the full production-image
LocalStack smoke passed locally; LocalStack used an insecure database and no
real IAM or Fargate. Terraform remains unapplied, and the historical live
revision-10 route predates this boundary. A production activation must still
repeat the external cross-database/PUBLIC audit and directly verify live grants
and task inputs before serving.

## Failure, convergence, and history

- Connector lag and projection watermarks are visible; stale projections do
  not claim completeness.
- Invalid signatures, identity/payload collisions, and unauthorized scope are
  quarantined before projection.
- Projectors tolerate late and out-of-order events and recompute current views
  from provider ordering or graph reachability rather than arrival order.
- Embedding failure does not remove lexically available evidence. Dense
  readiness is explicit per projection.
- Resolution, waiver, failed hypotheses, ineffective actions, and force-pushed
  history remain recallable.
- Restored telemetry may close an active breach after its confirmation window
  while root cause remains unknown or the underlying defect remains open.

## Staged implementation after the invariants stabilize

The PUBLIC-03 source hardening is complete: the fixed database reader and the
distinct publication secret, execution role, task role, and KMS scope are
checked in. Before the next deployment, apply those bytes only after the
external cross-database/PUBLIC audit and then verify the live database grants,
secret injection, execution policy, task policy, and TLS identity directly.
This does not require or authorize dynamic ingestion.

1. **Checked in, offline/private only:** canonicalization profiles, genesis and
   successor packages/policies, identity recipes, normative-binding schemas,
   evidence envelopes, and replay fixtures. These bytes do not activate a
   serving runtime.
2. **Checked in, private only:** the append-only control-event ledger and exact
   one-time bootstrap receipt that pin the genesis profile, registry digest,
   signer set, and threshold.
3. **Checked in, private only:** genesis and first-successor activation
   repositories with compare-and-swap heads, replay, stale-candidate, and
   contested-history proofs. No deployment or serving path consumes those
   accepted heads yet.
4. Add general accepted-evidence and relation-attestation events. Make
   synchronous `remember` atomically append its event and projection. Prove
   immutability, scope binding, replay, and verified-versus-declared behavior.

   Partially implemented. Landed: migration 0018 (the evidence event/head pair,
   the quarantine table, the governed content table, the relation-projection
   pair, and the read-only writer-authority view); the generic accepted-event
   append seam with quarantine on integrity collision and preimage
   disagreement, exact-replay no-op, and per-shard chain audit; the
   writer-authority head witness read inside the append transaction; evidence
   v2 admission against the witnessed active package with a governed,
   content-addressed, per-object-encrypted content object committed in the same
   serializable transaction; relation-attestation append with an atomic durable
   projection and a monotonic per-edge watermark; the
   `remember(action="assert")` event-first route, wired beside the
   byte-identical `record` path but fenced off — it fails closed until the
   deployment carries the writer-authority configuration pins and a non-stub
   in-transaction witness (ADR 0002 D3/D4); the private bootstrap-manifest
   import CLI that admits legacy chunks, claims, conflicts, and receipts as one
   signed, content-addressed event; and the repeatable generic `N -> N+1`
   registry activation runtime with its private workstation CLI. These
   evidence, content, relation, and witness modules compile into the library
   but are not yet reachable from the running server; each carries live
   CockroachDB proofs that the official-binary lane discovers and runs by exact
   name. Still absent: enabling the `assert` route so synchronous `remember`
   itself appends-and-projects in one transaction (the configuration pins plus
   a witness loader that mints accepted events); wiring any of these dormant
   modules into a serving path; and the Stage-5 connectors and projectors
   below.
5. Project one local transcript connector and one Git history connector into
   content-addressed repository membership and lexical-first/dense-later evidence
   with local cursors and coverage receipts. Arrow IPC may carry bounded batches
   between collectors, projectors, embedding workers, and replay scanners, but
   canonical accepted-event bytes remain the identity and signature authority.
6. Admit one exhaustive code/spec observer and add basic discrepancy derivation.
7. Add authenticated private ingress, durable queueing, remote connector
   cursors, and dead-letter/quarantine behavior.
8. Add provider-verified PR, CI, artifact, and deployment relations.
9. Add observation receipts and read-only incident reconstruction.
10. Consider action proposal and authorization only after the read-only
    incident model is independently safe and replayable.

Existing chunks, claims, conflicts, and receipts enter the new history through
a signed, content-addressed bootstrap-manifest event. Imported records retain
honest legacy provenance; the migration does not fabricate historical provider
events or causal edges.

No stage adds mutation to the public CloudFront router.

### Arrow transport boundary

Arrow is a transport and derived-data optimization, not a second evidence
format. A batch schema is registry-versioned and carries the accepted-event ID,
canonical statement bytes or their governed content reference and digest, plus
non-semantic delivery and projection columns. Every consumer revalidates the
canonical preimage and digest before committing work. Batch boundaries,
dictionary encoding, compression, extension metadata, field ordering, and IPC
container bytes never enter event, source-fact, representation, checkpoint, or
signature identity. Embedding vectors and other disposable columnar projections
may remain Arrow-native because they are reproducible and cite the exact source
event and projector/model digests. Unknown schemas, duplicate event positions,
oversized batches, or row/preimage disagreement fail closed into quarantine.

## Design admission gates

No implementation stage begins until every contract consumed by that stage has
authoritative test vectors. Stages 1–9 require the applicable read-plane,
evidence, registry, replay, graph, discrepancy, redaction, and
privilege-separation vectors below. Stage 10 additionally requires action
proposal, authorization, execution-attempt, stale-precondition,
idempotency-collision, reconciliation, and verification vectors.

- Canonical resource identifiers and normalization rules
- Registry canonicalization, pinned genesis/bootstrap authority, prior-policy
  authorization, concurrent activation, rollback, and contested-overlap behavior
- Entity/version identity across rename, retry, force-push, mutable tags, digest
  algorithms, provider reinstall, and canonicalizer upgrade
- Predicate schemas and comparator behavior
- Authority and applicability registry precedence/conflict behavior
- Normative proposition activation, exact source binding, separation of duty,
  supersession, contested overlap, and retroactive-correction behavior
- Complete, partial, and missing coverage semantics
- Observer admission modes, unsupported syntax/configuration, skipped input,
  dependency drift, overlapping-observer disagreement, deterministic replay, and
  resource-exhaustion behavior
- Exact event replay and identity-collision quarantine
- Per-shard atomic append/cursor advancement, epoch transition, verified
  checkpoint-plus-tail replay, cross-shard reversed arrival/barriers, declared
  history horizon, and late-event repair
- Relation basis, verdict, and lifecycle projections, including refutation and
  supersession without history loss
- Branch, PR, release, environment, and rolling-cohort applicability
- Non-destructive discrepancy lifecycle and episode identity
- Late evidence that appends, splits, or combines canonical episodes; alert
  closure, waiver, rule change, deterministic opening, short/long observation
  gaps, and recurrence
- Redaction and publication classification before embedding
- Exact body-byte encoding and collision behavior; parser determinism on same and
  different sources; manifest collision, rechunking, stable source-span support,
  old-generation completion, and protection-domain-limited deduplication
- Erasure concurrent with projection/embedding, late redelivery, legal hold,
  parent-versus-child scope races, no-retainable matcher, checkpoint/backup
  restore, key destruction, and dependent-proposition re-evaluation
- Telemetry selection caps, deterministic sampling, withheld fields,
  canonical strata/restart replay, unavailable snapshots/identities,
  irreproducible populations, public reclassification, exemplar-only causal
  rejection, and exemplar erasure
- Public reader versus private writer privilege separation
- Causal support that remains open below intervention evidence, cause exposure
  after outcome onset, required coverage gaps, ambiguous/confounded intervention
  results, independent ratification, and later refutation
- Action proposal, approval, execution-attempt, ambiguous-outcome
  reconciliation, stale-precondition, idempotency-collision, and verification
  semantics before stage 10

## Foundational design decisions

These decisions remove ambiguity from the contracts consumed by stages 1–10.
They are target semantics, not claims about current implementation.

### Registry serialization, governance, and activation

The authoritative registry artifact is strict, schema-versioned canonical JSON
under the named `ostk-canonical-json-v1` profile.
Human commentary may live beside it, but YAML, Markdown, source-code defaults,
and database rows are not independent registry authorities. A registry package
contains its predicate schemas, authority rules, applicability evaluators,
coverage proof methods, relation proof recipes, publication rules, activation
policy, resource-kind schemas, provider/internal namespace definitions, identity
recipes, and positive and negative test-vector digests. Its identity is the
domain-separated digest
`SHA-256("ostk-registry-package-v1" || 0x00 || canonical_package_bytes)`.

The profile fixes schema validation, default expansion, NFC string handling,
ASCII identifier syntax, timestamp and decimal-string forms, and canonical
ordering. It rejects duplicate and unknown keys, floating-point values,
ambiguous timestamps, non-NFC strings, unsorted set fields, remote includes,
environment substitution, and executable policy. Defaults are materialized
before hashing. A manifest lists every `(kind, ID, version, entry digest)` in
canonical order. Every entry, package, activation statement, and resource locator
uses its fixed profile-owned prefix under
`SHA-256(prefix || 0x00 || canonical_bytes)`. Reordered object keys
preserve the digest; any ordered semantic change does not.

Checking a package into Git proposes it; merging it does not activate it. A
canonical activation proposal binds the exact package digest, tenant/project
scope, effective interval, test-vector result, and the expected active head:
predecessor activation ID, predecessor package digest, and activation-policy
digest. Its statement ID hashes the unsigned canonical statement. Approval
signatures are separate attestations and do not change that semantic ID.

The currently active governance policy—not the proposed package—decides eligible
principals and threshold, so a package cannot lower the threshold and authorize
itself. The accepted activation receipt binds sorted approval-attestation IDs and
the server-derived eligibility, threshold, and separation-of-duty verdict.
Production authority, publication, and action-policy changes require an approver
distinct from the package author. Activation compare-and-swaps the exact expected
head, not only its package digest; exactly one concurrent successor can commit.
For the frozen v1 rule this is existential: an otherwise eligible author
approval may still count toward the threshold, and the trusted proposer is not
automatically excluded from approving. A stronger disjoint-role requirement is
a versioned activation-policy change, never an unstated verifier convention.
This activation-ID binding rejects a stale proposal after an `A → B → A` package
sequence. Reverting means appending a new activation event for an earlier package
digest; no prior interval or activation identity is rewritten.

A pinned bootstrap receipt supplies the genesis package digest, canonicalization
profile, bootstrap signer set, and threshold. The genesis package cannot
authorize its own activation. Every later transition is governed by its
predecessor package; key revocation affects future attestations without erasing
historical activation evidence.

Deployment configuration pins the bootstrap-receipt digest out of band; no field
or signature inside that receipt establishes its own authority. Ambiguity
resolution is authorized only by the last common unambiguous predecessor policy
or a separately deployment-pinned break-glass policy and compare-and-swaps the
exact contested activation-ID set. Neither contested successor may authorize its
own selection.

If two activation events claim incompatible precedence for the same scope and
effective interval, the registry projection becomes `ambiguous`, opens a
governance discrepancy, and suspends affected automatic verification. Receipt
time never breaks the tie. Every projector retains the last unambiguous closed
watermark and reports that it is stale until an authorized contested-set
resolution event commits under the rule above.

### Canonical resource identity

Resource identity is a typed canonical locator, not a user-facing provider URL.
Each resource-kind schema defines required locator fields, normalization, and an
identity recipe declaring whether the resource is a continuing entity or an
immutable occurrence.
The credential-bound opaque tenant/project namespace is included by the server;
payloads cannot select it. Tenant and project remain mandatory authority columns
and are never inferred from the URI. A connector-supplied OSTK URI is only an
assertion; ingress reconstructs and verifies the locator. Canonical JSON locator
bytes yield three URI forms:

```text
urn:ostk:entity:v1:<kind>:sha256:<locator-digest>
urn:ostk:version:v1:<kind>:sha256:<version-locator-digest>
urn:ostk:occurrence:v1:<kind>:sha256:<occurrence-locator-digest>
```

Every locator includes the exact activated identity-recipe ID, version, and
digest. If the recipe is missing or its registry projection is contested,
identity creation fails closed. A recipe upgrade therefore mints a different URI
even when every provider field happens to normalize to the same bytes.

An entity URI names a continuing provider resource, such as one repository,
pull request, workflow, or service. A version URI includes exactly one
registry-declared continuing parent entity URI and immutable version coordinates,
such as a PR head SHA plus provider update version or telemetry rule version. An
occurrence URI names an intrinsically immutable resource with no continuing
parent, such as a content-addressed artifact or provider event. Each kind's
identity recipe selects exactly one form. Mutable labels, branch names, image
tags, display names, and URLs remain attributes or observations; they are never
substitutes for immutable version identity.

Deployment rollouts are immutable occurrences unless a provider supplies a
verified stable, non-reused deployment-object identity. A recipe or
canonicalizer upgrade mints new URIs and requires explicit verified equivalence
edges; it never reinterprets existing graph endpoints.

A provider instance is a stable authority namespace declared by its identity
recipe and bound to provider-controlled immutable identifiers or an out-of-band
pin—not credentials or connector-install IDs. Credential rotation and reinstall
reuse the namespace only when the same authority identity is verified. Otherwise
they mint a new namespace and may join it only through a verified equivalence
edge. OSTK-native binding families, decisions, and policies use an explicit
credential-bound internal authority namespace.

Provider-specific locators use provider-instance identity and immutable
provider IDs rather than owner/name strings when such IDs exist. Git object IDs
retain their declared object format. Artifact identities retain digest algorithm
and canonical digest bytes. A source span at a commit is a membership coordinate
linking repository version, tree/blob identity, exact path bytes, exact byte
span, and span digest; line numbers are display metadata only. Identical text in
two paths may share storage but not provenance. Normalization never guesses
across case, Unicode, repository, provider, or tenant boundaries. Unknown
locator versions remain opaque and non-comparable.

### Normative source activation

Normativity is an event-derived state, not a path convention. A candidate
specification, ADR, policy, SLO, or decision is evidence. A document never becomes
normative wholesale. A binding proposal enumerates exact typed proposition
fingerprints and binds:

```text
stable binding-family ID and expected active binding revision/set
exact repository, commit, blob, path, byte ranges, and selected-byte digests
extractor/parser artifact and configuration digest
enumerated proposition fingerprints and predicate-schema versions
applicability selector and effective interval
registry and currently active activation-policy digest
explicit supersession, if any
```

An extractor or agent may propose a binding but cannot activate it. Independent
approval attestations sign the canonical binding-statement digest under the
currently active governance policy. The document author or affected agent cannot
be the sole ratifier. The activation receipt binds the sorted approval-attestation
IDs and server-derived eligibility, threshold, and separation-of-duty verdict.
Only that derived verdict controls activation; a proposal cannot assert its own
authorization result.

Editing or merging the document creates new evidence but leaves the previously
active version normative until a valid activation, retirement, or supersession
event says otherwise. A supersession can change intent prospectively; it cannot
rewrite a historical nonconformance. A known incompatible overlap fails unless
the activation explicitly supersedes the active binding. `Contested` is reserved
for late/corrective or independently accepted evidence whose ordering cannot be
established; it makes dependent comparisons `unknown`. Waivers are separate,
scoped, expiring policy events and do not deactivate the underlying expectation.

Activation atomically compare-and-swaps the composite `(expected binding-family
revision/set, active registry digest, active activation-policy digest)` and
revalidates approval eligibility, expiry, revocation, threshold, and separation
of duty in that transaction. A policy or key change makes the proposal stale and
requires reauthorization. Retirement, retraction, and expiry are signed lifecycle
events governed by the same active policy. Normal policy forbids effective time
before accepted time; an exceptional retroactive correction requires a
separately named higher-threshold policy, appends a new bitemporal
interpretation, and preserves every prior as-known conclusion.

### Evidence ledger, retention, archive, and erasure

Accepted evidence enters a sharded append ledger with a transactional offset per
shard. Offsets order projector work only; they never establish provider event
order, authority, or causality. Semantic event identity never contains a shard
or physical partition key. An append position is `(ledger family, log epoch,
shard, committed offset)`. Shards are selected from credential-bound
tenant/project scope plus a stable hash. Changing the shard count creates a new
log epoch and checkpoint; evidence IDs do not change. Offset assignment,
accepted representation, and shard head advance commit in one transaction.
Failed transactions publish neither row nor offset.

That ledger is one semantic ledger realized as two physical ledgers (ADR 0002
D1). Governance events — control bootstrap and registry activation, family
`registry.activation` -- append to the control pair (`memory_control_events`
plus `memory_control_shard_heads`); general accepted events — evidence,
relation attestations, claims, and the later observer, discrepancy, and erasure
kinds — append to the evidence pair (`memory_evidence_events` plus
`memory_evidence_shard_heads`). Both pairs bind the same single log-epoch row,
the same partition recipe, seed, and shard count, the same append-position
algebra, the same append-chain digest recipe, and one `event_kind` /
`consistency_family` namespace. `ledger family` therefore selects a physical
table, never a second semantic ledger. A database CHECK forbids governance
kinds in the evidence plane and general kinds never appear in the control
plane, so an append position stays unique within `(ledger family, epoch, shard,
offset)`; projector cursors, cursor vectors, and evidence-compaction
checkpoints key their closed head vectors by `(ledger family, shard)`.

The split is a privilege boundary, not a semantic one: one shared physical
table would hand the serving process raw `INSERT` into the governance ledger.
For the same reason the evidence head table carries no foreign key to the
control epoch table — a foreign-key check runs with the writer's privileges,
so such a key would force a control-table `SELECT` grant on the serving role
and reopen the boundary it exists to close. Epoch binding is enforced inside
the append transaction instead: the writer reads the single genesis epoch
through the read-only writer-authority view and requires the evidence head's
epoch identity and shard count to equal it, so the single-epoch uniqueness
constraint stays literal. Evidence heads are bound through that authority view;
the events-to-heads foreign key inside the evidence plane remains.

The registry defines a consistency/partition key for each event kind, normally a
canonical entity or source-fact family. Related facts that require shard-local
ordering share that key. Each log epoch binds the domain-separated partition-hash
recipe, seed, shard count, and predecessor epoch. Epoch activation atomically
fences every old shard head at one closed vector and makes the new epoch active;
a concurrent old-epoch append that loses the fence retries under the new epoch.
The evidence-compaction checkpoint binds every closed old head, so shard-count
changes and reversed arrival remain deterministic under replay.

Every accepted event receives a server-derived retention and visibility class.
The immutable envelope, governed canonical redacted payload, optional private
raw payload, and large raw artifact may have different stores and retention
periods. Redaction removes secrets but does not imply that the remaining bytes
are non-personal or retainable forever. Every erasable canonical or raw payload
uses a separately addressable, envelope-encrypted content object indexed for
erasure. Mixed-scope archive segments and backups retain per-record/per-artifact
DEKs or erasable references; a monolithic segment is never the erasure unit.

Shard-local projectors advance one cursor atomically with complete local output.
Graph, discrepancy, absence, and other cross-shard join projectors consume a
closed input cursor-vector barrier and atomically publish one generation for that
vector. Negative or completeness-dependent conclusions cannot advance beyond the
closed vector. Processing the same facts in a different shard schedule must
produce the same generation. Late evidence publishes a later recomputed
generation and preserves the earlier as-known output.

Two checkpoint kinds remain distinct:

- an **evidence-compaction checkpoint** is a projector-neutral,
  content-addressed manifest of retained immutable evidence, tombstones, closed
  shard positions, append-chain/segment-manifest roots, and retained-evidence
  snapshot digest and may anchor the declared evidence replay horizon only after
  completeness is independently replay-verified;
- a **projector checkpoint** is a performance cache valid only for one exact
  projector and registry digest and can never justify pruning its evidence
  inputs.

A semantic replay begins from genesis or a verified evidence-compaction
checkpoint plus its retained event tail. Independent replay verifies the
checkpoint against the evidence authority. Projector checkpoints bind their
projector, registry, cursor vector, output digest, and verification receipt, but
never become a second authority. Projection tables remain disposable.

Moving a closed event segment from CockroachDB to a private object archive is
allowed only after a content-addressed segment manifest, durable-copy receipt,
and replay verification are accepted. The combined hot ledger, retained archive,
evidence-compaction checkpoints, and erasure tombstones satisfy the declared
replay horizon;
transport queues never do. A projection must state when its policy permits only
bounded historical replay rather than silently claiming genesis replayability.
It exposes `semantic_replay_from` separately from
`historical_content_available_from`.

Private raw payloads use separately scoped encryption keys and an erasure index
that maps authorized privacy subjects and evidence IDs to every materialization.
The private raw archive is optional supporting material, not a prerequisite for
ordinary projection replay. Each archived artifact has a unique data-encryption
key wrapped inside its protection domain; one shared bucket key is not sufficient
for artifact-scoped cryptographic erasure.

An erasure event has a typed scope (`representation`, `source_fact`, `resource`,
or `privacy_subject`), effective interval, policy basis/version, and separately
authorized prospective re-consent semantics. Acceptance atomically installs a
retrieval-deny tombstone and increments every indexed target epoch plus a
monotonic tenant/project erasure generation. Projection, embedding, cache, and
archive commits compare-and-swap a composite fence covering representation,
source-fact, resource, privacy-subject, and tenant/project scopes. Work begun
before a parent, subject, or child tombstone cannot commit afterward.

Cleanup then removes authorized raw bytes, searchable text, embeddings,
exemplars, cached renderings, object versions, local outbox/quarantine copies,
and keys. Receipts are `attempted` or `pending` while any residual remains and
become `complete` only after every governed store verifies removal. Minimal
digests or pseudonymous tombstones survive only where policy permits. A
prospective re-consent event may authorize a new source fact; it never revives an
erased representation or permits redelivery under its old identity.

Restore and reprojection load the current policy and erasure tombstone set before
making any reader available. Late or restored evidence covered by a tombstone is
suppressed or quarantined rather than rematerialized. A legitimately new event
may become visible only under a new policy/consent basis whose scope does not
conflict with the tombstone. Key destruction is not sufficient evidence of
erasure if plaintext or derived copies remain.

Erasure dominates checkpoints, but content-addressed checkpoints remain
immutable. An erasure appends an invalidation/tombstone, destroys governed
payload keys, and mints a new checkpoint at the higher erasure epoch; it never
redacts or advances the old object in place. No reader or restore may serve an
older checkpoint until the tombstone tail is applied and its derivatives are
purged. A checkpoint may retain only the digest/tombstone metadata policy
permits; it is never a lawful reason to retain erasable body bytes.

If policy forbids retaining even a pseudonymous matcher needed to suppress late
redelivery, the system disables and purges that connector/resource scope. It
does not promise replay-safe suppression while continuing to accept an event it
can no longer recognize.

If erased material was the only reproducible support for a proposition, its
historical existence remains but its current verification becomes `unsupported`
or `unverifiable`; dependent discrepancies are recomputed. If retained canonical
redacted evidence remains sufficient under policy, support may remain verified.
An erasure receipt distinguishes Fleet Recall deletion from deletion at the
authoritative provider.

Ordinary retention expiry of the sole reproducible support follows the same
`unsupported`/`unverifiable` transition and dependent recomputation before bytes
are pruned. Legal hold may defer removal but never makes held private content
public or bypasses retrieval authorization.

### Chunk and embedding identity across parser versions

The immutable source-object version is distinct from every searchable
representation. Exact canonical extracted bytes receive a reusable body-content
ID. The parser contract declares whether newline, Unicode, or other normalization
occurs; those rules are part of its configuration. The digest formula is
`SHA-256("ostk-body-v1" || uint64_be(byte_length) || exact_output_bytes)`.
Same digest with different retained bytes is an integrity collision. A chunk
occurrence ID additionally binds:

```text
source-object version URI
parser/extractor artifact digest, version, and configuration digest
ordered half-open source-byte spans, span digests, and ordinal
body-content ID
redaction and publication-classifier versions
```

The same body may reuse byte storage and embedding work where every embedding
input is identical, but occurrences in different sources or spans never collapse
their provenance. A parser/configuration change creates a new parse manifest and
occurrence set with explicit supersession links; it never silently reuses old
occurrence identities. Re-running the same parser key on the same source
representation and canonical inputs with a different manifest or occurrence set
is an integrity collision. The active current-view parser comes from the
registry. Source line numbers are display coordinates, not identity;
non-contiguous derived passages retain an ordered span list. Parser-added source
headers remain metadata rather than passage-body identity.

A parse run atomically emits its source representation, parser key, ordered
occurrences and spans, body digests, count/coverage receipt, and manifest digest.
The manifest ID is computed afterward from canonical run metadata and the ordered
occurrence IDs; occurrence identity never includes its manifest ID. The same
parser key on the same source representation and canonical inputs must reproduce
the same manifest. The same parser may legitimately produce a different manifest
for a different source representation.
Parser upgrades build a new generation in shadow and atomically change the
current-generation pointer only after coverage and determinism verification.
Late old-parser work remains historical and cannot reclaim that pointer.

Historical claims cite stable source-object/span evidence coordinates plus the
exact representation they observed, not a parser-local chunk ID alone. A verifier
may rederive equivalent support under a new parse manifest and append that support
without rewriting the original citation. Automatic equivalence requires the same
immutable source object plus identical ordered source-byte spans and span digests;
body similarity, shifted text, or semantic overlap is new support requiring fresh
verification.

An embedding identity additionally binds the body or occurrence input selected
by policy, model digest, tokenization/preprocessing version, distance metric, and
embedding dimensions. Embedding nondeterminism cannot alter lexical identity,
proposition identity, or discrepancy correctness.

Physical body deduplication for private data is limited to one protection domain
and exposes/stores only a domain-keyed external storage identity so digest
equality does not leak across tenants or visibility boundaries. Any unkeyed
integrity digest is encrypted or access-controlled against cross-domain joins.
Erasure removes an occurrence immediately and removes shared body/embedding
storage when no lawful occurrence references it; a checkpoint cannot pin bytes
that policy requires erased.

### Exhaustive-observer admission

Exhaustiveness is granted per observer version, predicate, input domain, and
configuration context—not to an observer globally. Registry admission grants one
mode:

- `candidate_only`: may nominate propositions or discrepancies;
- `positive_verified`: may verify an explicitly found value with exact proof but
  may not prove absence, cardinality, or an exact set;
- `closed_world_verified`: may additionally prove absence or an exact set inside
  its admitted closed domain.

LLM and semantic-search observers are always `candidate_only`. An observer may
support a verified negative proposition only after its exact executable and
dependency digests are independently admitted as `closed_world_verified` with an
exhaustive-proof contract:

```text
predicate and supported source/resource kinds
language, schema, compiler, or API versions
closed input boundary and required applicability dimensions
enumeration algorithm and unsupported-feature diagnostics
success, partial, stale, parse-failure, and timeout outcomes
coverage-receipt recipe
positive, negative, mutation, and adversarial test vectors
```

At runtime the observer must bind an immutable source version, prove the complete
registered input boundary was read, emit no unsupported or ambiguous construct,
and produce complete/current coverage plus contiguous sequencing when sequencing
applies. Otherwise its output is
`indeterminate` or provisional and cannot auto-open a verified discrepancy. A
search miss, truncated AST, generated code omitted from the closed boundary, or
unresolved macro/configuration path never proves absence.

Every run receipt enumerates included, excluded, skipped, and failed inputs,
exact applicability/configuration, input and output digests, coverage/freshness/
continuity, and exact evidence coordinates. Verified absence or exact-set output
requires zero skipped, failed, unsupported, and unknown inputs. A partially
covered run may still emit an individually proven positive only under a separate
`positive_verified` admission.

Observer upgrades create new derivations. Incompatible outputs constitute
`observer_derivation_disagreement` only when admitted domains, predicate versions,
and concrete applicability overlap. Every affected observation, negative
proposition, and dependent automatic discrepancy becomes `indeterminate` until a
rule narrows the domains or evidence resolves the disagreement. Registry-policy
conflict is a governance discrepancy; disagreement between telemetry
measurements is `telemetry_disagreement`. A `candidate_only` output remains
opposing candidate evidence and does not by itself invalidate an otherwise
complete verified proof. No ordering or authority score silently chooses a
winner.

Updating observer code, dependencies, parser, build features, admitted domain,
or coverage method requires a new admission and activation; the observer cannot
admit itself.

### Discrepancy families and episodes

A discrepancy-family fingerprint binds tenant/project, finding type, canonical
subject, predicate/comparator lineage, expectation/policy identity, normalized
applicability target, and episode-policy version. An episode is one continuous
effective-time interval in which that exact family is incompatible or missing
under its registered proof method.

The episode fingerprint hashes the family fingerprint, normalized continuity-key
values, deterministic opening-transition source-fact identity, and episode-policy
version. The opening transition is ordered by effective time, registered provider
order when available, and stable source-fact identity as the final tie-breaker;
receipt order is never used. Late evidence that changes that transition creates a
canonical replacement episode and supersedes the old projection without erasing
it.

Every discrepancy type registers its continuity-key dimensions, opening rule,
allowed observation gap, closing/confirmation rule, rule-change behavior, and
late-evidence behavior. Non-windowed state discrepancies open on the first
verified incompatible state and close only on verified compatibility,
supersession, or scope termination. A windowed runtime predicate without an
episode policy produces standalone evaluations; it cannot be grouped or
auto-resolved. Missing, stale, or unknown windows never prove recovery, and alert
closure never closes a discrepancy.

A missing/unknown interval no longer than the registered allowed gap may bridge
two violating evaluations in one episode, but remains recorded as incomplete. A
longer gap ends the known observed interval without asserting compatibility or
resolution; the prior occurrence becomes observation-indeterminate, and a later
violation opens a new episode linked by `possibly_continues`. Only verified
compatibility, supersession, retirement, or scope exit records a resolved end.

- Candidate-to-verified promotion, acknowledgment, waiver, member replacement,
  and additional supporting/opposing evidence remain in the same episode while
  the incompatible interval is continuous.
- A verified compatible interval, expectation retirement, or applicability exit
  ends the occurrence at its effective time. A later recurrence opens a new
  episode linked to the same family.
- A waiver changes workflow state but does not split or erase the underlying
  incompatible interval. Expiry returns the same continuing episode to `open`.
- Late evidence is inserted into the historical episode selected by effective
  interval. If it bridges or splits previously projected intervals, replay creates
  canonical replacement episodes and marks the earlier projections superseded,
  retaining explicit `combined_from` or `continues` relations.
- Material comparator or predicate-schema changes create a new family linked by
  supersession; detector upgrades under the same contract append derivations.
- Rolling cohorts and distinct environments have distinct applicability contexts.
  An aggregate environment episode cannot be attributed to one revision without
  cohort-aware evidence.
- A deployment during an active SLO breach does not split that breach. It may open
  a separate deployment-scoped regression candidate or causal hypothesis.

Lifecycle state and verification state therefore never define episode identity.

### Telemetry receipts and bounded exemplars

Telemetry providers are authoritative for their retained records and query
responses, not for completeness, correctness, or causal interpretation. A
measurement collects no exemplars unless a registered query-specific policy
permits them. The v1 private cap is eight structured exemplars, 1,024 UTF-8 bytes
each and 8 KiB total. The public default is zero; a separately activated and
independently approved public policy may expose at most three exemplars, 512 bytes
each and 1.5 KiB total, after public visibility has already been established.

The default selector is `deterministic_stratified_hash_v1`: define the exact
provider snapshot/query population, apply authorization and visibility, redact
and classify, and sort canonical normalized stratum keys. Inside each stratum,
order immutable provider-record identities by
`SHA-256(policy_digest || measurement_source_fact_id || provider_record_id)`,
then select round-robin in canonical stratum order until the cap. The hash has no
rotating secret or process-local seed. If the adapter cannot bind a bounded
population or deterministic provider snapshot and immutable candidate IDs,
selection returns none while preserving the aggregate receipt.
The policy version, population boundary, candidate/eligible/withheld/selected
counts, strata, selection inputs, omitted count, and truncation state are part of
the measurement receipt. Extrema sampling is allowed only under an explicitly
registered policy labeled as biased; it cannot support prevalence claims.

Redaction, visibility classification, and retention assignment occur before an
exemplar reaches an outbox, embedding worker, or searchable projection. Private
provider links and trace/log bodies never enter the public projection. Exemplars
illustrate an aggregate; their absence cannot prove an event did not occur. A
metric query may support exhaustive aggregate coverage only when its provider
contract and coverage receipt say so.

When source telemetry expires, the bounded receipt remains evidence of the
captured evaluation, not proof that the provider query can still be rerun. The
receipt preserves query/rule version, digest, window, dimensions, aggregation,
sample count, missingness, result, provider response digest, and durable link or
expiration metadata.

Default exemplar fields are bounded time, service/environment/region,
workload/cohort, route template, status/error class, duration, sanitized code
frames, and opaque trace coordinates. Headers, cookies, credentials, bodies,
query strings, environment values, user identifiers, IP addresses, database
values, stack locals, and arbitrary raw log lines are disallowed. Redaction or
classification failure withholds the exemplar while preserving the aggregate
receipt. An investigator cannot hand-pick a favored log line after viewing it;
that creates, at most, separately labeled attested evidence.

Exemplars alone establish neither prevalence nor exhaustive coverage and cannot
upgrade a hypothesis to `mechanistically_corroborated`. Causal use requires a
separately admitted verifier binding exact trace, workload, revision, and changed
behavior identities to the proposed mechanism.

### Causal support and ratification

Epistemic support and human adjudication remain independent. A principal may
ratify that root cause is still unknown or that a mitigation worked without
ratifying a causal claim. The v1 policy does not ratify a positive `caused_by`
conclusion below `intervention_supported`. Strong forensic or mechanistic
evidence may remain `mechanistically_corroborated/open`; operational resolution
does not require overstating causality.

Qualifying interventions include an authorized rollback/roll-forward, bounded
feature-flag or traffic-cohort isolation, controlled canary withdrawal, targeted
corrective change, deterministic replay, or faithful isolated reproduction.
Unsafe production reintroduction is never required. Intervention support binds:

```text
exact cause, outcome, workload, artifact, and environment identities
verified cause exposure beginning before outcome onset and overlapping it
verified outcome measurement or discrepancy
complete provenance to the exposed cohort
registered material-runtime-input delta inventory
pre-recorded mechanism and predicted outcome direction
exact authorized intervention/reproduction and provider receipt
compatible exposed/control or before/after measurement receipts
complete/current coverage and confirmation window
supporting, opposing, and confounding evidence
```

If multiple material inputs changed and their effects cannot be separated, an
execution outcome is ambiguous, coverage is partial/stale, cohorts are mixed, or
the prediction was written after observing the result, support cannot reach
`intervention_supported`. Recovery after rollback alone is insufficient.

V1 may ratify `contributing_cause` after one qualifying intervention with no
unresolved material confounder. `Primary_trigger` additionally requires an
independent second confirmation, such as withdrawal plus faithful reproduction,
controlled cohort isolation plus an exact mechanistic trace, or safe controlled
reintroduction. Universal `necessary_cause`, `sufficient_cause`, and unqualified
`root cause` claims remain unsupported until a predicate-specific methodology is
registered.

A second confirmation is independent only when it has distinct source-fact
identities and a materially different evidentiary failure mode. Re-querying the
same measurement, rerendering one trace, or deriving two propositions from one
provider receipt remains one evidentiary line.

Ratification records the exact hypothesis and evidence-bundle digests, causal
role and bounded scope, achieved support level, supporting and opposing evidence,
an explicit empty set of unresolved required coverage/material-input gaps, any
remaining non-blocking residual unknowns, policy version and closure watermark,
approver identity, and separation-of-duty result. All verified opposing evidence
must be reconciled or the causal claim remains open. The ratifier is distinct
from the proposing agent, action executor, and every author of the implicated
change. A human-role exception requires a previously activated signed
separation-of-duty policy; an agent never receives that exception.

A failed predicted outcome refutes only that hypothesis/intervention version; it
does not prove an alternative cause. Later evidence may append `refuted` or
`superseded` without erasing what was ratified with the evidence then available.

## Deferred provider and capacity choices

The following remain deployment choices rather than epistemic ambiguities:

- queue product, retry cadence, and dead-letter capacity;
- hot-ledger physical ranges and archive object sizing;
- private archive provider, key hierarchy, and retention durations;
- Git/CI/deployment/telemetry connector order;
- provider-specific query languages and lower operational exemplar caps within
  the fixed v1 ceilings;
- service sizing, autoscaling, and regional topology.

Each choice must still satisfy the invariant registry and admission gates. None
may alter semantic event identity, authority, applicability, replay, erasure,
discrepancy, causal, or public-boundary behavior.
