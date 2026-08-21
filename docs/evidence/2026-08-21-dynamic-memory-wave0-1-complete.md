# Dynamic memory Wave 0 / Wave 1 completion receipt

Date: 2026-08-21. Scope: the multi-agent completion of the Stage-4 foundations
described in [`DYNAMIC_MEMORY_ARCHITECTURE.md`](../DYNAMIC_MEMORY_ARCHITECTURE.md),
under the decisions in
[ADR 0002](../adr/0002-stage4-runtime-foundations.md) and
[ADR 0003](../adr/0003-consolidation-and-conflict-tolerance.md). This receipt
supersedes the 2026-08-16 sign-off
([`2026-08-16-dynamic-memory-wave0-1-signoff.md`](2026-08-16-dynamic-memory-wave0-1-signoff.md)),
which recorded the same waves at an earlier, partial state.

This record exists so a reader can tell what was merged, what was reviewed,
what was proven, and — most importantly — what is still missing. Every negative
claim below is part of the receipt.

## What this receipt is not

- It is **not** evidence of an AWS deployment. Nothing here was applied to a
  cloud environment.
- The Docker-based grant proofs
  (`runtime-role-grants.sh`, `publication-reader-role-grants.sh`,
  `successor-activation-role-grants.sh`, `registry-activation-role-grants.sh`,
  `control-role-grants.sh`, `conflict-reconciliation-role-grants.sh`) are
  **secondary parity lanes**. They run an insecure local container as root and
  cannot substitute for the checksum-pinned official-binary lane, for TLS, for
  password authentication, or for any deployed cluster. Each script says so in
  its own header; repeating it here is deliberate. Docker parity is never
  authoritative.
- The authoritative connected lane is
  `deploy/cockroach/tests/registry-activation-cli.sh` run against the official
  CockroachDB `v26.2.3` binary. Its result is a **local receipt** for the
  reviewed source tree, not evidence about any running system.
- The connected Docker grant proofs were **not** re-run for this bundle. The
  integrator ran the static-only source-shape assertions of the runtime-role
  proof and the official-binary lane on the workstation; the connected Docker
  parity lanes are deferred to the sign-off role.

## Merged workstreams

Base: `dm/integration` at `42aefee` (Wave-0 close, CI 31985339696 green). Head:
`17cb6df`, all fourteen items merged. Source: `.fleet-recall/fleet/WAVE_LOG.md`
(chronology and verdicts) and `git log 42aefee..17cb6df`. Each item was gated at
its cherry-pick onto `dm/integration` with `cargo +1.94 fmt --check`,
`check --locked --all-targets`, `test --locked --all-targets`, and
`clippy --locked --all-targets -- -D warnings`, all green; the integrator
re-verified all four green on the final head. "Mutation" cites the specific
survivor(s) the workstream's PREFLIGHT or reviewer killed where the wave log
records one.

| Workstream | Commits on `dm/integration` | Verdict | Mutation | Refreezes it caused |
| --- | --- | --- | --- | --- |
| **W0-REG-2** — `ComparatorLineage` + `ConsolidationPolicy` registry kinds (gen2-only) | `dd21a2e`, `cc0fce3` | clean; Codex/DeepSeek/Kimi gate lenses confirmed | reserved-slots proven carriable-but-never-admitted | none (r1 gen2 registry frozen unchanged; r2 additive) |
| **W0-NORM** — normative binding v2 (registry-head-bound) | `54449fa`, `f0636ce`, `637a002`, `0e33333`, `939befd`, `1753d33` | clean | `1753d33` kills six `NormativeBindingProposalV2::validate` survivors | none |
| **W1-HEAD** — writer-authority head witness (ADR 0002 D4) | `62e784f`, `e79e9d7`, `09a9fb0`, `8ba21db`, `0be13b9`, `2a58eaa`, `48eec73`, `7e43fc0`, `8977233` | clean | `8977233` kills the `framed_record` survivor | in-wave `7e43fc0` refroze `src/config.rs` + `src/main.rs` in the runtime manifest; `src/config.rs` re-refrozen at this wave close for the later KEK overlap |
| **W1-REL** — relation attestation append + durable projection | `7db58a9`, `21839d1`, `9c79111` | clean (Codex implementer pilot) | — | none |
| **W1-REM** — `remember(assert)` fail-closed disabled route (ADR 0002 D3/D4) | `a64b467` | clean | — | `src/service.rs` + `src/application.rs` refrozen in the runtime manifest at this wave close |
| **W0-OBS** — observer admission v2, run receipt, result event | `47ac50e`, `8afd988`, `9abd2f0`, `848bc7a`, `2b521d6`, `d10ea4b`, `5d6acad`, `346b5e7` | clean | observer fixtures canonicalized + asserted canonical | its own frozen observer vectors regenerated in-wave (`5d6acad`) |
| **W0-TELEM** — telemetry receipts + bounded exemplars | `d536804`, `05e9155`, `5dff269`, `d569e28`, `231891d`, `0052620`, `05daf0d` | clean | `05daf0d` kills three tombstone-shape survivors | its own v3 telemetry `vector-suite.jsonl` semantic ids pinned in-wave (`231891d`) |
| **W0-ACT** — action protocol + provider-attested relation admission v2 | `8a2da83`, `5e40d9e`, `706ff32`, `d647546`, `37ecaa7`, `85784c2`, `4372873`, `74f1a22` | clean | AUTH-02/03, ACT-02/03 conjuncts pinned | none |
| **W0-CAUSE** — causal hypothesis, intervention, ratification | `31331ad`, `29b80e8`, `8add29a`, `96d7149`, `1bc5a7e`, `70acbad`, `8349397` | clean | `1bc5a7e` pins the `causal_role` re-derivation conjunct | none |
| **W0-LOG** — ledger epochs, checkpoints, archive, replay barriers | `4349be5`, `4510c59`, `5ec4773`, `7e5ea2c`, `0119a55`, `bcf523b`, `ba81455`, `233a005`, `b7c39f7` | clean | round-3 blockers + three negative fixtures asserted canonical | none |
| **W1-EVID** — evidence v2 admission + governed content store | `f0754a0`, `4173e44`, `98bd5d6`, `a3cd2d5`, `5b7d91c` | clean (Opus) | `4173e44` proves event + content commit atomically | `src/config.rs` KEK pin (`f0754a0`) → refrozen in the runtime manifest at this wave close |
| **W1-IMPORT** — private bootstrap-manifest import CLI + append seam | `c8dde3f`, `a318f8c`, `4b71370`, `ef88e0c`, `ac223d7` | clean | `ac223d7` pins the exactly-MAX validation boundaries | its own v3 bootstrap-manifest vector suite re-frozen in canonical bytes in-wave (`ef88e0c`) |
| **W0-EPIS** — discrepancy families + episodes | `abcdac5`, `0f321d2`, `dd429a0`, `b8289bd`, `34dc517`, `4914875`, `0a83836` | clean (standalone pure-Opus review) | mutation 20/20 caught | none |
| **W0-ERASE** — erasure, tombstone, fence, legal hold | `5d0ea71`, `70d3ed9`, `889f33e`, `6a55f18`, `85394fd`, `6f55b20`, `d6d39a5`, `17cb6df` | clean (round 2) | `LegalHoldV1` zero-target-digest conjunct pinned; mutation 9/9 caught | none |

Two integrator commits sit in the same range and belong to no single
workstream: `c064c6d` adds a targeted `#[allow(clippy::too_many_lines)]` on
`DigestDomain::prefix` (the enum union across all merged workstreams exceeds the
pedantic cap), and `e56b621` is a `rustfmt` comment-indentation chore after the
`W0-EPIS` digest-domain pick. No frozen digest, fixture byte, or contract line
changed in either.

## Refreezes at this wave close

Recorded so a reviewer can re-derive every pin. The runtime manifest is
`deploy/cockroach/tests/runtime-role-grants.sh`
`expected_reviewed_source_manifest` (`shasum -a 256`).

| Pin | Change |
| --- | --- |
| Runtime manifest, `src/config.rs` | `5ddd1e20…` → `9c105844…` (W1-EVID KEK accessor + W1-HEAD writer-authority pins; only config accessors/pins, no new database access path) |
| Runtime manifest, `src/service.rs` | `6f0c6874…` → `c885c07b…` (W1-REM `RememberAction::Assert` variant + wire label only) |
| Runtime manifest, `src/application.rs` | `5c170770…` → `ee1d0b5a…` (W1-REM `assert_route_disabled()` fail-closed route only) |
| Runtime manifest, added Stage-4 source | `src/registry_witness/mod.rs`, `src/evidence_ledger/{admission,content_store}.rs`, `src/relation_projection/{mod,cockroach,projector,repository}.rs`, `src/memory_contracts/bootstrap_manifest.rs` — added to the reviewed-source freeze as dormant runtime source (compiled but not reachable from the running server) |
| Runtime policy SQL + LocalStack pins | unchanged, untouched (no new reachable database access path) |
| `registry-activation-cli.sh` official lane | 32 new connected tests wired (registry-witness ×13, evidence-admission ×10, relation-projection ×6, bootstrap-manifest ×3), each asserted complete; `ostk-bootstrap-manifest-import` built + asserted executable |
| `.github/workflows/ci.yml` | `ostk-bootstrap-manifest-import` added to the production-image `! -e` exclusion list |
| Rich-demo publication corpus | refreshed in this bundle; see that commit for the exact counts |
| All `contracts/dynamic-memory/v1\|v2\|v3` frozen digests and fixture bytes | unchanged |

## Proofs run

**Official-binary connected lane**, re-run on this wave-close branch
(`dm/W-CLOSE`) with `RUSTUP_TOOLCHAIN=1.94` against the checksum-verified
official CockroachDB `v26.2.3` darwin binary — no Docker. It exercised the full
matrix plus the 32 newly wired Stage-4 connected tests (writer-authority
witness ×13, evidence admission ×10, relation projection ×6, bootstrap
manifest ×3), all green. Tail:

```
test live_writer_authority_witness_materializes_the_stage4_head_when_configured ... ok
test live_admission_appends_event_and_content_atomically_when_configured ... ok
test live_attest_produces_projection_row_and_watermark_in_one_transaction ... ok
test live_bootstrap_manifest_scope_binding_when_configured ... ok
official-binary connected correctness proof passed
OFFICIAL_LANE_EXIT=0
```

The connected Docker grant-parity lanes (runtime, publication, successor,
control, activation, conflict-reconciliation) were **not** run in this bundle;
only the static source-shape assertions of the runtime-role proof were run
(`FLEET_RECALL_RUNTIME_RBAC_STATIC_ONLY=1` → `runtime-role static checks
complete`). The connected Docker lanes are secondary parity and are deferred to
the sign-off role; none of them is authoritative.

## Still absent, per stage

The status line in `DYNAMIC_MEMORY_ARCHITECTURE.md` reads *stages 1–3 frozen;
stage 4 partially implemented; stages 5–10 contract vectors in progress*.
Concretely:

**Stage 4 (partially implemented).** Landed this wave, in addition to the prior
append seam and generic activation runtime: the writer-authority head witness
(`src/registry_witness/`), evidence v2 admission with a governed
content-addressed content store (`src/evidence_ledger/{admission,content_store}.rs`),
relation-attestation append with an atomic durable projection
(`src/relation_projection/`), the `remember(assert)` event-first route
(`src/service.rs`, `src/application.rs`), and the private bootstrap-manifest
import CLI (`src/bin/ostk-bootstrap-manifest-import.rs`). Still absent:

- **an enabled `assert` route.** `remember(action="assert")` is wired beside the
  byte-identical `record` path but fails closed with a typed error: the
  deployment carries neither the ADR 0002 D4 writer-authority configuration pins
  nor a non-stub in-transaction witness loader, so synchronous `remember` does
  not yet append its accepted event and its projection in one transaction.
  `record` is unchanged.
- **a serving path.** The evidence, content, relation, and witness modules
  compile into the library but are not reachable from the running server:
  `src/main.rs` wires none of them. Their database paths are exercised only by
  the live CockroachDB proofs the official-binary lane runs by exact name.
- **the enabled bootstrap import.** The import CLI exists and is proven
  connected, but no existing chunks, claims, conflicts, or receipts have been
  imported into the new history; legacy `record` claims remain pre-history.

**Stages 5–10 (contract vectors landed; no runtime).** Every Wave-0 contract
family now has byte-frozen positive and negative vectors and a merged contract
module — normative binding (NORM), observer admission (OBS), telemetry (TELEM),
causal support (CAUSE), ledger epochs (LOG), discrepancy episodes (EPIS),
erasure and legal hold (ERASE), and action protocol (ACT). None has a runtime:
no connector, projector, observer executor, ingress, provider-verified relation
producer, observation-receipt, or action path is built. Stage 5 (connectors and
projectors) is the next wave.

The `CONS-01..10` consolidation family remains registered in the invariant
registry with a contract module implementing the read side of conflict
tolerance only; **no CONS invariant has a runtime**, and `remember(consolidate)`
is not built. `memory_conflicts` stays byte-stable.

The public read plane gained nothing in these waves. PUBLIC-01 through PUBLIC-04
hold exactly as before: the eight-table publication reader is unchanged, and
migration 0018's new tables — including `memory_content_objects` — are
deliberately outside it.
