# Dynamic memory Wave 0 / Wave 1 sign-off receipt

Date: 2026-08-16. Scope: the multi-agent build of the Stage-4 foundations
described in [`DYNAMIC_MEMORY_ARCHITECTURE.md`](../DYNAMIC_MEMORY_ARCHITECTURE.md),
under the decisions recorded in
[ADR 0002](../adr/0002-stage4-runtime-foundations.md) and
[ADR 0003](../adr/0003-consolidation-and-conflict-tolerance.md).

This record exists so a reader can tell what was merged, what was reviewed,
what was proven, and — most importantly — what is still missing. Every negative
claim below is part of the receipt.

## What this receipt is not

- It is **not** evidence of an AWS deployment. Nothing here was applied to a
  cloud environment.
- The Docker-based grant proofs
  (`runtime-role-grants.sh`, `publication-reader-role-grants.sh`,
  `successor-activation-role-grants.sh`) are **secondary parity lanes**. They
  run an insecure local container as root and cannot substitute for the
  checksum-pinned official-binary lane, for TLS, for password authentication,
  or for any deployed cluster. Each script says so in its own header; repeating
  it here is deliberate.
- The authoritative connected lane is
  `deploy/cockroach/tests/registry-activation-cli.sh` run against the official
  CockroachDB `v26.2.3` binary. Its result is a **local receipt** for the
  reviewed source tree, not evidence about any running system.
- No push to `origin` is claimed by this document, and no CI run backs it. The
  gates below were run on the workstation.

## Merged workstreams

Source: `.fleet-recall/fleet/WAVE_LOG.md` (chronology) and the branch history
`git log 78a0974..HEAD`. "Verdict" is the reviewer verdict recorded in the wave
log at the commit named.

| Workstream | Commits merged | Reviewer verdict |
| --- | --- | --- |
| Cycle-0 integrator: publication store pin + three orphan live tests | `fedf518` | integrator commit; verified by re-running the three tests on a secure single-node official binary |
| Cycle-0 integrator: Wave-0 module and digest-domain stubs | `779b9bc` | integrator commit; gates green |
| W0-REG (generation-2 registry composition) | `bbe795a`, `ecbaa07` | clean on review at `ecbaa07` |
| Integrator: consolidation summary-enrichment digest domain | `cac8f88` | integrator commit accepting the Kimi lane's digest-domain request |
| W0-SUCC (generic successor contracts, contested seam) | `1c8ac7a`, `1c264ba`, `0f34f72`, `7b84522`, `2aee9d4` | clean after three reviews, at `2aee9d4` |
| Kimi lane: consolidation contracts + ADR 0003 | `6a55dcc`, `cbec7f7`, `584379d`, `1bf238b` | adversarial re-review clean at `1bf238b` |
| W0-QUAR (quarantine / dead-letter contract) | `156f47c`, `9c72ac3`, `804eb71`, `80b3078` | closeout clean at `80b3078` |
| Kimi lane: ADR 0003 read-side mapping addendum | `8efe3a8` | accepted by the chair |
| W1-SCHEMA-RBAC (migration 0018, D2 grant matrix, pin audit) | `5dfe185`, `d9be7cb`, `f5dde38`, `34e2578`, `a280e3d`, `e908503`, `f004cf8` | final review clean at `96eb5a7`, merged as `f004cf8` |
| Integrator: Wave-1 module stubs and W1 digest slot | `cfacda6` | integrator commit |
| Integrator: typed canonical decode gate | `5a65b70` | integrator commit; closes the positional-array / omitted-`Option` class crate-wide |
| W1-SUCC (generic `N -> N+1` runtime + private CLI + live test) | `5733712`, `cb5fbdc`, `4fc86bb` | clean on first review at `b3ec6e1`, merged as `4fc86bb` |
| W0-CHUNK closeout (chunk and embedding identity) | `f2d92ef`, `b3f2e00`, `3aba77d`, `c26e16e` | closeout clean at `c26e16e` |
| W0-COVER closeout (`CoverageReceiptV1`) | `3a1fd67`, `c3205f7`, `f0b1202`, `ea35986`, `62a07d6` | closeout clean at `62a07d6` |
| W1-APPEND (evidence-ledger append seam + live proof) | `d257052`, `c6dd9f8`, `8122744` | **no reviewer verdict is recorded in the wave log** — the chronology's last entry is the W0-CHUNK/W0-COVER merge at `62a07d6`, which precedes this merge. `.fleet-recall/fleet/RESUME.md` carries one open observation against it (two `#[doc(hidden)] pub` constructors to tighten). Treat this row as merged-but-unrecorded, not as reviewed-clean. |
| W1-CLOSE (this bundle) | this branch | pending Fable's gate |

## Not merged, with residual blockers

Source: `.fleet-recall/fleet/W0_RESIDUAL_STATE.md`. Every commit on these
branches is preserved; each stopped at a review with open blockers, summarised
in one line here. The residual file holds the full text, file:line anchors, and
the "fix must" acceptance statement for each.

| Branch | Head | Open blockers (summary) |
| --- | --- | --- |
| `dm/W1-HEAD` | `fb27078` | 1 — `verify_descent`'s genesis-root policy gate and its predecessor-`NULL` guard have no isolating negative vector, so a silent mutation of either passes every gate. Reviewer notes also flag: the ambiguous two-row branch is uncovered, the decode-cache capacity test over-claims, and `profile_digest`/`vector_manifest_digest` are not compared. |
| `dm/W0-EPIS` | `27cdb55` | 4 — comparator-lineage registry binding is structurally unreachable (dead validation path); episode relations force `Superseded` with no scope/profile binding; a `combined_from` relation leaves both sources `Open`; `allowed_observation_gap_seconds` is read by no code path. |
| `dm/W0-OBS` | `30a9e11` | 1 — `detect_disagreement` never binds a result's predicate/applicability to its own admission and run receipt, so an observer admitted for one predicate can nullify a comparison about another. |
| `dm/W0-ERASE` | `a03ec04` | 3 — `LegalHoldV1::permits_removal` returns a permissive `bool` from an unvalidated record; `ErasureFenceV1::validate`'s length conjunct is an unpinned mutation survivor; systemically, 12 of 23 validation predicates survive mutation. |
| `dm/W0-LOG` | `5a90ec5` | 3 — `replay_tail` fails open on a forked append chain; `ReplayFrom::Genesis` silently accepts unknown fields (`deny_unknown_fields` has no effect on a unit variant of an internally tagged enum); generation identity is still schedule-dependent while the README claims otherwise. |
| `dm/W0-NORM` | `3ee5df7` | 3 (last recorded at `45d32cb`) — the receipt's fail-closed separation-of-duty clause is a surviving mutant; the effective interval is never exercised; a supersession lifecycle event may name itself as its own supersession target. |
| `dm/W0-TELEM` | `ac8d712` | 2 (last recorded at `525672f`) — the deterministic stratified-hash selection rule is pinned by nothing; the tombstone path is unvalidated, so the policy count cap can be exceeded via fabricated tombstones. |
| `dm/W0-CAUSE` | `23cecfb` | 2 — `evaluate_ratification` takes self-asserted `achieved_support` at face value; `project_adjudication_state` folds records for unrelated hypotheses and never checks the `supersedes` linkage. |
| `dm/W0-ACT` | `30af1ca` | 4 (last recorded at `f307ba3`) — a provider fact is never bound to the relation edge it admits; the revalidation/start temporal check is inverted; nothing verifies the attempt's proposal digest against the authorization; `reconcile_receipt` binds neither pre-state nor scope. |

For `dm/W0-NORM`, `dm/W0-TELEM`, and `dm/W0-ACT` the residual file records a
later `handoff:complete` than the last `review:blockers`, so the blocker list
shown is the most recent **reviewed** state and may already be partly closed on
the branch. It has not been re-reviewed.

## Proofs run

All four logs below are workstation runs, retained at
`.fleet-recall/fleet/`. Tails are copied verbatim.

**Official-binary connected lane, cycle 0** (`official-lane-c0.log`, on `fedf518`):

```
official-binary connected correctness proof passed
./deploy/cockroach/tests/registry-activation-cli.sh  474.54s user 90.29s system 123% cpu 7:38.62 total
EXIT=0
```

**Official-binary connected lane, Wave 1** (`official-lane-w1.log`, on `f004cf8`):

```
official-binary connected correctness proof passed
official EXIT=0
```

**Runtime-role grant proof** (`proof-runtime-w1.log`, on `f004cf8`; secondary
Docker parity only):

```
runtime-role grant proof passed on v26.2.3
runtime EXIT=0
```

**Publication-reader grant proof** (`proof-publication-w1.log`, on `f004cf8`;
secondary Docker parity only):

```
publication-reader grant proof passed
publication EXIT=0
```

**W1-CLOSE re-runs on this branch.** The official lane was re-run locally after
wiring twelve additional connected tests into it; it passed with exit 0 and the
new tests are visible in its output:

```
test live_generic_successor_activation_when_configured ... ok
test live_all_three_stage4_kinds_append_and_audit_when_configured ... ok
test live_chain_tamper_is_reported_by_the_audit_when_configured ... ok
test live_concurrent_appends_to_distinct_shards_keep_independent_heads_when_configured ... ok
test live_concurrent_appends_to_one_shard_form_one_chain_when_configured ... ok
test live_exact_replay_is_a_no_op_when_configured ... ok
test live_integrity_collision_is_quarantined_when_configured ... ok
test live_least_privilege_probe_role_appends_without_control_grants_when_configured ... ok
test live_preimage_disagreement_is_quarantined_when_configured ... ok
test live_single_append_and_shard_chain_audit_when_configured ... ok
test live_statement_bound_to_a_never_active_head_writes_nothing_when_configured ... ok
test live_witness_mismatch_writes_nothing_when_configured ... ok
official-binary connected correctness proof passed
```

The runtime-role and successor-activation grant proofs were also re-run on this
branch after the manifest refreeze (`runtime-role grant proof passed on
v26.2.3`; `secondary Docker successor-activation grant parity proof passed`) —
again, secondary Docker parity, not authoritative.

## Refreezes at this wave close

| Pin | Change |
| --- | --- |
| `runtime-role-grants.sh` reviewed source manifest, `src/config.rs` | `66e14bea…` → `22ebe3cf…` (W1-SUCC's two additive accessors; no database access path) |
| Runtime policy SQL digest | unchanged: `f9fcf11f…` |
| Runtime grant-matrix count | unchanged: 47 |
| Migration prefix | 18 (frozen earlier in the wave by W1-SCHEMA-RBAC) |
| LocalStack policy pins | unchanged, untouched |
| Successor-activation grant matrix | unchanged; the generic runtime is proven to be a subset of the existing grants |
| Rich-demo publication corpus | refreshed in this bundle; see that commit for the exact counts |

## Still absent, per stage

The status line in `DYNAMIC_MEMORY_ARCHITECTURE.md` now reads *stages 1–3
frozen; stage 4 partially implemented; stages 5–10 contract vectors in
progress*. Concretely:

**Stage 4 (partially implemented).** Landed: migration 0018; the generic
accepted-event append seam with quarantine, exact-replay no-op, and per-shard
chain audit; the in-transaction comparison of the append against
`memory_writer_authority_v1`; the generic `N -> N+1` activation runtime and its
private CLI. Still absent:

- the **evidence, relation, and remember event-first paths** — `remember` does
  not yet atomically append its accepted event and its projection; the `assert`
  action of ADR 0002 D3 is not implemented and legacy `record` is unchanged
  (W1-EVID, W1-REL, W1-REM);
- the **head witness producer** — `src/registry_witness/mod.rs` is a
  three-line stub. Reading the authority view outside a transaction, verifying
  descent from the pinned bootstrap root, caching that verdict per exact
  activation ID, and enforcing the `FleetConfig` namespace pins (ADR 0002 D4)
  all live on the unmerged `dm/W1-HEAD`. What exists today is the append
  transaction's own comparison and a deliberately non-authoritative witness
  value object (`src/evidence_ledger/witness.rs`);
- the **bootstrap-manifest import** — existing chunks, claims, conflicts, and
  receipts have not entered the new history; legacy `record` claims remain
  pre-history (W1-IMPORT);
- **connected-proof wiring for all of the above** (W1-PROOF). This bundle wires
  only what exists today; `tests/registry_witness_live.rs` is not wired because
  it does not exist on this base.

**Stages 5–10 (contract vectors in progress; no runtime).** No connector,
projector, observer admission, ingress, provider-verified relation, observation
receipt, or action path is implemented. Contract closeout is still pending for
every one of these families, each blocked on the branch named above:

| Family | Stage(s) | Branch |
| --- | --- | --- |
| EPIS — discrepancy episodes | 6 | `dm/W0-EPIS` |
| OBS — exhaustive-observer admission | 6 | `dm/W0-OBS` |
| ERASE — retention, holds, erasure fences | 5–7 | `dm/W0-ERASE` |
| LOG — log epochs, replay horizons, compaction | 5 | `dm/W0-LOG` |
| NORM — normative source activation | 6 | `dm/W0-NORM` |
| TELEM — telemetry receipts and bounded exemplars | 9 | `dm/W0-TELEM` |
| CAUSE — causal support and ratification | 9 | `dm/W0-CAUSE` |
| ACT — action proposal, authorization, execution | 10 | `dm/W0-ACT` |

The `CONS-01..10` consolidation family is registered in the invariant registry
and its contract module exists, but **no CONS invariant has a runtime**: the
module implements the read side of conflict tolerance only, and
`remember(consolidate)` is not built. `memory_conflicts` stays byte-stable; the
waiver columns ADR 0003 describes are explicitly deferred.

The public read plane gained nothing in these waves. PUBLIC-01 through
PUBLIC-04 hold exactly as they did before: the eight-table publication reader
is unchanged, and migration 0018's new tables — including
`memory_content_objects` — are deliberately outside it, which the publication
proof asserts directly.
