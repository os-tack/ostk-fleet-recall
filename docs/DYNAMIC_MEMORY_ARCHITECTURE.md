# Dynamic corpus and causal runtime architecture

Status: **draft target architecture; not implemented**

Fleet Recall currently serves a statically generated, revision-linked corpus
and a deliberate typed-claim ledger. This document defines the target model in
which that static corpus becomes a bootstrap snapshot and the durable memory is
a replayable projection of authenticated evidence events.

This is not a description of the judging deployment. The implemented system is
documented in [ARCHITECTURE.md](ARCHITECTURE.md), its security boundary in
[SECURITY.md](SECURITY.md), and the local-versus-fleet product decision in
[ADR 0001](adr/0001-product-and-backend-boundary.md).

No connector, webhook, queue, incident controller, asynchronous embedding
worker, or public mutation route is implied to exist today.

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
| Conflicts | Current same-key typed-value claim conflicts | A generalized, non-destructive discrepancy ledger |
| Links | Claim-to-claim relationships are reserved in the schema | Heterogeneous provenance links and separately graded causal hypotheses |
| Events | Claim mutation audit events | Authenticated, versioned, replayable evidence inbox and outbox |
| Availability | Embedding completes before a corpus row is searchable | Lexical availability first; dense projection asynchronously follows |
| Runtime | CloudWatch application logs and deployment receipts outside memory | Bounded observation, alert, incident, action, and verification receipts |
| Public surface | Read-only application routes | Permanently isolated, least-privilege publication plane |

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

- **EVID-01 — Immutable evidence.** Accepted evidence is append-only.
  Correction, deletion, and provider mutation create new events or lifecycle
  projections; they never rewrite the accepted event. A retention or erasure
  policy may cryptographically remove separately stored private raw bytes while
  preserving an immutable tombstone, digest, and lifecycle event.
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
allowed modalities
comparator and incompatibility algorithm version
required applicability dimensions
closed-world/absence semantics
publication and sensitivity default
```

Unknown predicates remain searchable evidence but cannot automatically open a
verified discrepancy. Negative propositions require a coverage receipt.

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
representation key: source-fact identity + schema/canonicalization/redaction versions
canonical payload digest: stored and verified separately from the representation key
schema name and version
authenticated connector principal and connector instance
provider and provider-reported actor identity
provider delivery ID: transport receipt only
logical event key defined by the connector schema
canonicalization version
provider object/event ID and immutable revision
entity kind and canonical resource ID
occurred_at, observed_at, received_at
canonical redacted payload and payload digest
optional private raw-artifact reference and digest
redaction policy/version
integrity/signature state
server-derived publication classification and classifier policy version
```

The authenticated ingress principal does not authenticate the
provider-reported actor. The local collector redacts and writes the canonical
envelope to a durable outbox before delivery. Transport delivery IDs deduplicate
ingress attempts only. The semantic-effect key is the credential-bound
connector/provider logical fact identity plus immutable provider revision; it
excludes delivery, canonicalization, and redaction versions. Schema,
canonicalization, and redaction-policy versions identify a representation of
that source fact. Reprocessing under a new representation version creates an
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

The current public application router already omits mutation routes. The
checked-in Terraform injects the same runtime database secret into the public
demo and writer task definitions, and the documented runtime role is
DML-capable. Thus the current deployment design does not enforce database-level
read-only access for the demo; live grants require their own direct audit. The
target requires a distinct reader even though application tests already prove
that `/api/remember` is absent.

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

Before the next deployment, independently harden the existing publication
plane with a distinct database reader, a publication execution role authorized
only for that reader secret, and a distinct task/service role where applicable;
this does not require or authorize dynamic ingestion.

1. Version the predicate, authority, applicability, and coverage registry.
2. Freeze canonical entity IDs and the evidence envelope with replay fixtures.
3. Add a local append-only accepted-evidence store and generic relation
   attestations. Make synchronous `remember` atomically append its attestation
   event and projection. Prove immutability, scope binding, replay, and
   verified-versus-declared behavior.
4. Project one local transcript connector and one Git history connector into
   lexical evidence with local cursors and coverage receipts.
5. Add content-addressed repository membership and lexical-first/dense-later
   projections.
6. Add one exhaustive code/spec observer and basic discrepancy derivation.
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

## Design admission gates

No implementation stage begins until every contract consumed by that stage has
authoritative test vectors. Stages 1–9 require the applicable read-plane,
evidence, registry, replay, graph, discrepancy, redaction, and
privilege-separation vectors below. Stage 10 additionally requires action
proposal, authorization, execution-attempt, stale-precondition,
idempotency-collision, reconciliation, and verification vectors.

- Canonical resource identifiers and normalization rules
- Predicate schemas and comparator behavior
- Authority and applicability registry precedence/conflict behavior
- Complete, partial, and missing coverage semantics
- Exact event replay and identity-collision quarantine
- Relation basis, verdict, and lifecycle projections, including refutation and
  supersession without history loss
- Branch, PR, release, environment, and rolling-cohort applicability
- Non-destructive discrepancy lifecycle and episode identity
- Redaction and publication classification before embedding
- Public reader versus private writer privilege separation
- Action proposal, approval, execution-attempt, ambiguous-outcome
  reconciliation, stale-precondition, idempotency-collision, and verification
  semantics before stage 10

## Open decisions

- Registry serialization and governance: checked-in declarative files, signed
  operator records, or both
- Canonical entity URI vocabulary across Git, CI, artifact, deployment, and
  telemetry providers
- Event-log and projection table partitioning and retention
- Private raw-artifact archive policy and deletion semantics
- Content-addressed chunk identity across parser-version changes
- Normative document activation and ratification workflow
- Which observers are exhaustive enough to auto-open verified discrepancies
- Discrepancy episode boundaries across repeated deployments and alert windows
- Telemetry provider integration and bounded exemplar policy
- Minimum intervention evidence required for a ratified causal conclusion
