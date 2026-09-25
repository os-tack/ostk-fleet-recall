# ADR 0007: The spec conformance chain

- Status: accepted and implemented. `ostk-spec draft|approve|activate` makes a
  signed spec statement normative under the active registry head;
  `ostk-spec check` judges one commit against the statement in force through
  the genesis-admitted observer and opens a `spec_nonconformance` episode in
  the 0027 discrepancy ledger only for a verified nonconformance;
  `ostk-spec episode resolve|dismiss` closes one; and
  `ostk-fleet-recall serve` answers `recall(action="discrepancies")` and a
  `spec_conformance` block in `recall(status)` wherever the writer login may
  read the tables involved.
- Date: 2026-09-25
- Scope: how a spec statement becomes normative, when a check of a commit
  records a discrepancy and when it records only a verdict, how episodes are
  grouped, opened, and closed, and what an agent can read about them. It
  builds on ADR 0005 (the writer authority every event-first writer runs
  under) and ADR 0006 (the memory worker whose git source a check reads
  through), and is separate from ADR 0004's conflict lifecycle.

## Context

The Stage-6 runtimes existed as libraries with their own tests: normative
activation (migration 0024), the exhaustive observer (whose only runner,
`ostk-observer-run`, emits receipts), and the discrepancy ledger (0027).
Nothing connected them. No statement could be activated under a head the
strict witness accepts, no observation was ever compared with a statement,
nothing wrote an episode, and no agent could read one. The observer also
verifies less than a spec needs: the genesis package admits it
`positive_verified`, so it can prove a member present but never absent.

## D1 — One operator CLI, run as `fleet_runtime`

**Decision.** `ostk-spec` (workstation only, not in the production image)
carries the chain:

- `draft` binds exact byte spans of a spec document at one commit (read
  through a local git reader, the span bytes digested) to one typed
  expectation: an enum in a Rust source file must, or must not, declare a
  member. The proposal names the witnessed registry head exactly, its
  predicate is the one the genesis package admits the observer for, and its
  subject is the repository entity the active package's recipe derives from
  the provider repository id. `approve` signs a draft offline with one
  Ed25519 seed.
- `activate` re-reads the strict witness, refuses a proposal that names any
  other head (the exact `activation_id` and effective interval, not only the
  package and policy digests), verifies the approvals under the active
  package's activation policy with `accepted_at` taken from the database
  clock, records the canonical proposal and expectation in
  `memory_normative_statements_v1`, and only then compare-and-sets the
  statement into its binding family in 0024. A lost compare-and-set leaves a
  harmless content-addressed statement row; a statement that is already live
  reports `already_active` and appends nothing.
- `check` judges one commit (D2 through D4 and D7), and
  `episode resolve|dismiss` closes an episode (D6).

Every command except `approve` connects as the `fleet_writer` login and so
runs as `fleet_runtime`, like `serve` and the worker (owner decision D6), with
the writer-authority pins `ostk-authority-install apply` prints required.
`check` also needs the content key: the blob fact and the observer run record
it appends are governed content.

## D2 — Only verified nonconformance opens an episode; every check is recorded

**Decision.** A check compares what the statement requires with what the
observer verified (D4). Only a discrepant comparison touches the discrepancy
ledger. Every comparison, whatever its verdict, records one
`SpecCheckRecordV1` in migration 0031's `memory_spec_checks_v1`: the
statement, the commit, the observer and blob events, the observed condition
and verification outcome, the verdict (`nonconforming`, `conforming`, or
`unknown` with reasons), and the episode it opened or joined. The record is
content-addressed and written with `ON CONFLICT DO NOTHING`, so a replayed
check under the same coverage receipt writes nothing new; the runtime holds
`SELECT` and `INSERT` on the table and nothing more. The observer event binds
the git source's latest coverage receipt (D4), and that receipt's digest is
part of the event's identity and so of the check's. Once the worker's git step
has written a newer receipt, a re-check of the same commit therefore appends a
new observer event and records a new check, which becomes the statement's
latest; the opening rule (D7) still joins the episode the commit was judged
into, so only the evidence and the check history grow.

**Why.** Episodes are findings, and a finding must be verified. Keeping the
check history (owner decision D3) is what lets an agent tell "checked and
conforming" and "checked but unknown" from "never checked": without it an
empty episode list would read as conformance.

## D3 — A family is one statement about one repository

**Decision.** A spec envelope's expectation policy is
`{binding_family_id, version 1, statement_id}`, its subject the statement's
repository entity, and its applicability `repository_commit: any`, declared
explicitly. Every commit of the repository judged against one statement
therefore falls in one discrepancy family. The opening transition's source
fact is the observer event's own source-fact identity, so each observed
commit seeds its own episode within that family. A new statement (a
supersession, or another statement in the binding family) is a new family.

## D4 — When a commit is judged

**Decision.** `check` selects the statement in force at the server's clock
(a library caller may pass a later `evaluated_through`), then compares both
sides over the one-microsecond interval starting at
`t = max(statement effective_from, commit instant)`. A commit older than the
statement is judged at the instant the statement took effect, which is what
lets an old commit be checked against the spec in force now.

- The normative side is complete only when the binding family resolves to
  exactly this statement; its window is the statement's own interval cut at
  the selection instant, because nothing later is known. A family with no
  statement in force, or a contested one, checks as `unknown` and writes
  nothing: there is no statement to record the check against.
- The observed side is complete only for a verified observation; its window
  starts at the commit's instant and never ends, because an immutable
  commit's content does not go stale.
- The observer reads the source file at the commit through the worker's own
  git source (principal, instance, installation, repository), so the blob
  event is an exact replay of what that source mints, never a second copy,
  and its coverage witness binds that source's latest coverage receipt. A
  source the worker has never covered is refused.

## D5 — The comparator lineage and episode policy are compiled in

**Decision.** A discrepancy envelope must cite a comparator lineage and an
episode policy by exact registry reference, but no active package registers
either kind: both are generation-2-only registry slots that no semantic
closure admits (the DISC-06 deferral). The two entries spec conformance needs
are therefore compiled in and resolved through the contract's own structural
resolvers: `comparator.remember_action_membership` v1 (a functional
comparison of one membership value between a normative and an observed side,
with `repository_commit` as its one required applicability dimension) and
`episode.spec_nonconformance_v2` v1 (no continuity key and no windowing).

They are not package-admitted, so an envelope that cites them is trusted only
as far as the deriver that built it. Their digests enter every spec family
and episode fingerprint, so they are never edited in place: a change is a new
version, and therefore a new family.

## D6 — What `positive_verified` can and cannot say

**Decision.** Under the genesis `positive_verified` admission the observer
verifies presence only:

- "must be absent" is the only expectation a commit can be verified to
  violate, and only by a member the observer verified present;
- "must be present" can be verified conforming, but a missing member checks
  as `unknown`, never `nonconforming`;
- a member that is not found, even by an exhaustive read, checks as
  `unknown` (`observed_unmeasured`, with `observed_unknown_coverage`, or
  `observed_partial_coverage` for a read that was not exhaustive), never
  `conforming`.

So a commit that fixes a violation never verifies the fix, and no check ever
closes an episode. An operator does: `ostk-spec episode resolve` cites
accepted events, by default the observer event of the violated statement's
latest check (typically the `unknown` check of the fixing commit). It refuses
to default when that statement was never checked, or its latest check is
nonconforming, did not read the whole enum (`observed_partial_coverage`),
re-read a commit already judged nonconforming under the statement, or does
not follow the check that opened the episode (recorded no later, compared at
an earlier instant, or that check is not recorded); the operator then cites
evidence explicitly. `ostk-spec episode dismiss` gives one
reason from the contract's closed taxonomy and a non-blank rationale. Either
appends one lifecycle event to the episode's 0027 log, effective at the
database's clock, checked against the stored envelope (scope, profile,
AUTH-03 self-implication, evidence and rationale shape) before and inside the
append. Nothing is rewritten, so the episode's history shows who closed it and
on what evidence. An episode is closed once: inside the append transaction, an
episode that is already resolved, dismissed, or superseded gets nothing
appended. The same transition (actor, and evidence or reason) is answered
with the event that already made it, so an operator can safely retry after
an outcome-unknown commit, and any other closure is refused.

## D7 — The opening rule is keyed on (statement, commit)

**Decision.** For a discrepant comparison, a check:

1. joins the episode a prior nonconforming check of the same statement at the
   same commit named (`already_judged`);
2. otherwise joins the family's standing (open, acknowledged, or waived)
   episode (`already_open`);
3. otherwise opens a new episode (`opened`).

A re-check of an already-judged commit therefore never re-opens an episode an
operator closed, even after a registry head change mints new blob and
observer events for that commit. Only a commit newly found nonconforming after
a closure opens another episode. The prior judgement is read from the check
history before the write; steps 2 and 3 are decided inside the append
transaction, which reads the family's standing episode and seeds the new one
only when none stands. Two concurrent checks of different commits therefore
conflict under serializable isolation: one opens the episode and the other,
retried, joins it, so a family never holds two standing episodes.

## D8 — Discrepancy writes are fenced by the witness binding

**Decision.** Each `check` and `episode` call verifies the strict witness
afresh and builds the discrepancy ledger from that witness's registry binding
(package and activation-policy digests); admission refuses an envelope whose
registry head names another package. The append transaction itself does not
re-read the registry head, so a head change that commits between the
verification and the append is not seen by that append. This matches the
normative runtime, whose compare-and-set compares the family head's stored
digests but not the live registry head. 0027 also does not check, inside the
transaction, that the evidence ids an envelope or lifecycle event cites
exist.

## D9 — Discrepancies are a separate recall action

**Decision.** `recall(action="discrepancies")` is its own action, not a
bridge into ADR 0004's conflict lifecycle: `recall(conflicts)` is unchanged,
`RecallResult.conflicts` stays empty for this action, no `claim_conflict`
episode is written to 0027, and agents cannot change an episode's lifecycle
over MCP.

- **When it is served.** `serve` probes once at startup: the schema must have
  reached migration 31 and the login must be able to `SELECT` the discrepancy
  projections, heads, and log, the normative projections, and both 0031
  tables (a `SELECT ... WHERE false` in a rolled-back transaction; 42501 means
  "not served"). There is no switch. Where the probe fails, `tools/list`,
  every response, and `recall(status)` stay byte for byte what they were, and
  the action is refused before any read. A failing probe is logged and never
  stops `serve`. The publication process never serves it.
- **What is advertised.** `tools/list` adds `discrepancies` to `recall`'s
  action enum, one description sentence (which says an empty list is not
  proof of conformance), and a branch that allows only `limit`,
  `include_resolved`, and an optional 64-hex episode `id`.
- **What it answers.** `data.discrepancies[]`: by default the standing
  episodes of live specs that have not expired, most recently changed first;
  with `include_resolved`, closed episodes and episodes of specs no longer in
  force (retired, superseded, or past their `effective_until`) too; with
  `id`, one episode in any state with its lifecycle history. Each carries the
  statement it violates (spec document, cited spans, effective interval,
  expectation) and what its opening check observed (commit, condition,
  verification outcome, observer event). `data.specs[]` carries every live
  spec with its latest check, `unknown` included, and its `effect` at the
  database's time: `in_force`, `scheduled`, or `expired`. The normative
  projection's live set is not filtered by time, so the reader classifies
  each statement against `statement_timestamp()` inside its transaction, the
  clock `check` selects at: only specs in force count as active, never
  checked, or unknown. The standing episodes of a scheduled spec are still
  listed and counted, since a check evaluated through a later instant
  verified them. `data.coverage` carries the counts and a note that episodes
  record verified nonconformance only. `recall(status)` adds
  `spec_conformance {served, active_specs, scheduled_specs, expired_specs,
  open_discrepancies, unknown_specs, never_checked_specs}`.

**Why.** The claim ledger's conflicts and the spec plane's episodes have
different authorities, lifecycles, and evidence. Keeping them apart keeps
`record`, `recall(conflicts)`, and the ADR 0004 lifecycle byte-stable, and a
writer never advertises an action its login cannot read.

## D10 — Approvals are nominal (owner decision D4)

**Decision.** Approvals verify under the active package's activation policy:
a domain-separated signature over the statement id, by an eligible signer
with the policy's key id, signed no later than acceptance, meeting the
threshold with no duplicate principal and with separation of duty (no
approver is the author or the proposer, and the author is not the proposer).
That policy names the public Ed25519 fixture keys (seeds `0x01`/`0x02`), so
anyone can produce valid approvals, exactly as for the registry ceremonies
(ADR 0005 D2). The real gate is the database role: only a login holding the
runtime grants can write the normative, spec, and discrepancy tables. The
author, proposer, approver, and episode-operator principals are payload
principals, not authenticated identities; each is only as strong as the
writer credential.

The observer's provenance is nominal in the same way. `check` builds the
observer's runtime declaration from the activated genesis entry itself
(`ObserverRuntimeDeclarationV1::from_activated_genesis`): the executable,
dependency-closure, and configuration digests are copied from that entry, and
the conformance-vector digests are placeholder constants. The admission seam
then compares the declaration with the same entry, so the comparison cannot
fail, and nothing measures the running `ostk-spec` binary. Every observer
result `check` appends, and every episode opened from one, therefore names
the admitted executable (`481cdae…`) and the fixture vector digests whatever
binary ran; a `verified_positive` outcome is as trustworthy as the build and
the host that ran `check`, not more. `ostk-observer-run` at least makes its
operator pass `--executable-digest`. Measuring the binary against the pinned
digest is deferred.

## D11 — Normative families strand after a registry head change

**Decision, stated so operators order their steps.** A binding family's head
stores the registry package and activation-policy digests it was last
advanced under, and every activation into the family compare-and-sets
against them, while a proposal must name the exact witnessed head. After a
registry transition that changes either digest (for example generation 1 to
generation 2), a draft made before it is refused as a stale head and must be
redrafted, and every activation into a family last advanced under the
previous head loses the compare-and-set: nothing more can be activated into
that family, not even a supersession of its statement. The family's
statements still resolve and are still checked, and D7 keeps their judged
commits from re-opening episodes. Install the writer authority to generation 2
(`ostk-authority-install apply`) before activating any spec; rebasing a
normative head after a transition is deferred.

**Amended by [ADR 0008](0008-collected-items.md) D3.** Moving a scope with
`ostk-authority-install apply --target generation-3` now rebases every binding
family whose live statements' registry dependencies the new head carries byte
for byte, which is every spec family: it appends a `rebase` row to the
family's log (migration 32) and moves the head's registry digests, so the
family takes activations and supersessions under generation 3. A draft made
before the move is still refused as a stale head and must be redrafted. A
family the rebase cannot verify, and every family after a move made without
it (`--no-normative-rebase`, or a hand-run generic successor ceremony), strands
exactly as described above until a later generation-3 install run rebases it.

## D12 — Spec commit URIs are not joinable with asserted ones

**Decision.** A check records the raw commit object id and the observer's
observed-revision URI, a digest over repository, commit, path, and blob. An
asserted `repository_commit` URI is `identity.github.commit` derived under
the asserted subject repository (ADR 0005 D11). The same commit therefore has
different URIs on each path, and no read compares them; relating an assertion
to a spec check needs an explicit, audited mapping, not URI equality.

## Consequences

- An operator can make one kind of spec normative (an enum in a Rust source
  file must or must not declare a member) and have every checked commit
  judged against it, and an agent can read, beside the recorded
  nonconformance, whether each spec was last found conforming, unknown, or
  never checked.
- A clean episode list is never evidence of conformance: under
  `positive_verified` absence is never verified, so "must be absent" specs
  read `unknown` on every commit that complies, and every episode is closed by
  an operator.
- Checks run on demand: an operator runs `ostk-spec check` after the worker's
  git step has covered the commit.

**Deferred.** `ostk-spec retire` and `inspect`; episode `acknowledge` and
`waive`; discrepancy lifecycle over MCP and a mapping from agents to contract
principals; a `claim_conflict` bridge into 0027 and any change to
`recall(conflicts)`; a `closed_world_verified` observer admission (verified
absence, auto-resolution, exact-set specs); package admission of the
comparator lineage and episode policy (D5); scope-exit dismissal in the
ledger; statements with more than one proposition; re-verifying source spans
at activate time; relations, contests, retroactive corrections, and waivers;
an in-transaction evidence-id existence check in 0027 (D8); rebasing normative
heads after a registry transition other than the installer's move to
generation 3 (D11, ADR 0008 D3); measuring the observer binary against
its pinned executable digest (D10); binding a re-check to the coverage receipt
of the commit's first check (D2); a spec-check worker step; other finding
types, predicates, and observers.
