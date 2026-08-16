# ADR 0002: Stage-4 runtime foundations — one semantic ledger, two physical ledgers, and a narrow writer

- Status: accepted (fleet panel 2026-08-16: correctness lens, invariant/security lens, chair Fable)
- Date: 2026-08-16
- Scope: the six decisions (D1–D6) that every Stage-4 runtime workstream (Wave 1) depends on.
  Target semantics are defined by `docs/DYNAMIC_MEMORY_ARCHITECTURE.md`; this record fixes the
  implementation choices where that document leaves latitude. Panel evidence (file:line) is
  retained in the fleet wave log; only conclusions and their cascade are recorded here.

## D1 — General accepted events: one semantic ledger, two physical ledgers

**Decision.** General accepted events (`evidence.accepted`, `relation.attestation.accepted`,
`memory.claim.accepted`, and later observer/discrepancy/erasure kinds) are appended to a new
physical pair `memory_evidence_events` + `memory_evidence_shard_heads` that structurally mirrors
`memory_control_events` + `memory_control_shard_heads` (every 0003 CHECK, the events→heads FK,
`UNIQUE (tenant_id, project, event_id)`, and the 0005 predecessor-unique index). They share ONE
semantic ledger contract with the control ledger: the same genesis log-epoch row (the evidence
head table's composite FK targets `memory_control_log_epochs (tenant_id, project, epoch_id,
shard_count)`; `UNIQUE (tenant_id, project)` on epochs is untouched, so the single-epoch invariant
stays literal), the same partition recipe/seed/shard count (16), the same `AppendPositionV1`
algebra, the same `derive_append_chain_digest` chain recipe, the same FOR UPDATE head lock plus
CAS advance, and one `event_kind` / `consistency_family` namespace across both ledgers.

Governance kinds (`control.bootstrap.accepted`, `registry.genesis.activated`,
`registry.successor.activated`, family `registry.activation`) never appear in the evidence ledger;
`memory_evidence_events` carries a CHECK forbidding them. General kinds never appear in the
control ledger. An append position is therefore unique within `(ledger_family, epoch, shard,
offset)` with `ledger_family ∈ {control, evidence}`; projector cursors, cursor vectors, and
evidence-compaction checkpoints (W0-LOG) key their closed head vectors by `(ledger_family, shard)`.

Evidence shard heads are seeded lazily by the appender inside the append transaction
(`INSERT … ON CONFLICT DO NOTHING`) at offset 0 with a deterministic genesis chain digest under a
NEW domain `ostk-evidence-genesis-chain-v1` (framed over `epoch_id`, `shard`), never
`DigestDomain::GenesisChain`. A head row is fully determined by `(epoch, shard)`, so lazy seeding
grants no forgeable authority; a CHECK pinning the offset-0 digest shape is recommended where the
SQL is expressible.

**Why.** Table-level grants are the only privilege primitive this schema relies on. Sharing
`memory_control_events` would hand the serving process raw INSERT into the governance ledger —
exactly the wedge that migration 0005's comment names — and would force re-audit of every bounded
control/registry audit. Splitting only the physical table keeps every semantic property the doc's
"one ledger" protects. This is a wording amendment to the doc (to be applied by the integrator),
not a relaxation of any invariant (EVENT-03, REPLAY-01/02, EVID-01).

## D2 — Appending role: extend `fleet_runtime`, narrowly, once

**Decision.** `remember` must commit its accepted event and its projection in ONE serializable
transaction (EVENT-03); one transaction is one connection is one role, so the appending identity is
`fleet_runtime`. It gains exactly: `SELECT, INSERT` on `memory_evidence_events`; `SELECT, INSERT,
UPDATE` on `memory_evidence_shard_heads`; `SELECT, INSERT` on `memory_content_objects` (D5);
`SELECT` on the read-only view `memory_writer_authority_v1` (D4). It gains NO privilege on any
`memory_control_*` or `memory_registry_*` base table; the control and successor policies' REVOKE
lists stay byte-identical. The runtime-role proof's exact matrix count is recomputed from the
final grant list, and every source-manifest / policy-digest / LocalStack refreeze for D2+D3+D4
happens ONCE at wave close (W1-PROOF), not per commit.

Residual accepted and documented: a compromised runtime can wedge its own evidence shards (never
the governance ledger); detection is the chain audit, remedy is a successor log epoch (W0-LOG).

## D3 — Remember v2: a new `assert` action beside legacy `record`

**Decision.** The MCP `remember` tool gains action `assert` carrying a
`RememberIngressCandidateV2` plus the existing `idempotency_key`; `record` stays byte-identical in
wire schema and behaviour, the reference agent and MCP tests keep passing unchanged. The server
routes `assert` to the unique active admission rule for (trusted scope, predicate schema, basis),
rederives the subject from the activated identity recipe, re-audits applicability dimensions and
support event IDs, builds the production `AdmittedRememberStatementV2`, appends
`memory.claim.accepted`, and writes `memory_claims` (+ `memory_events`, receipt) with the new
`accepted_event_id` in the SAME serializable transaction. Zero or multiple matching rules,
un-canonicalizable input, or a missing/contested head fail closed with a typed error; nothing is
downgraded into a synthesized canonical event (APPL-01/02, PRED-03, AUTH-03). The legacy
idempotency receipt sits IN FRONT of the append: replay returns the stored event ID and never
mints a second event under a newer head (EVENT-01). Legacy `record` claims enter history only via
the signed bootstrap-manifest event (W1-IMPORT).

## D4 — Head witness: per-transaction read, compared on the exact activation ID

**Decision.** Inside the same serializable transaction that appends, the writer SELECTs (plain
SELECT, LIMIT 2) the current head through `memory_writer_authority_v1`, requires exactly one row
with `head_state = 'active'`, compares the exact `activation_id` (never the package digest),
`generation`, the `canonical_head` bytes against the `RegistryHeadBindingV1` the statement carries,
and the contract tenant/project namespaces against config pins. Any deviation (0 rows, 2 rows,
non-active, mismatch, decode failure) fails the append closed; there is no last-known-head
fallback. Serializable isolation is the fence — no separate CAS. A decode cache keyed by the exact
`canonical_head` bytes is permitted; nothing else is cached in the authority path. Descent from
the pinned bootstrap root is verified at startup and on any observed activation-ID change, with
the verdict cached per exact activation ID.

`FleetConfig` gains `FLEET_RECALL_CONTRACT_TENANT_NAMESPACE`,
`FLEET_RECALL_CONTRACT_PROJECT_NAMESPACE`, `FLEET_RECALL_BOOTSTRAP_RECEIPT_DIGEST` (all three
required for the event-first path; when absent the `assert` route is disabled and every legacy
behaviour is byte-stable) and an optional break-glass `FLEET_RECALL_EXPECTED_ACTIVATION_ID` that
must match exactly when set.

## D5 — Governed content store: minimal, now

**Decision.** `EvidenceStatementV2` already references content by `GovernedContentIdentityV1`
with no inline bytes, and the activated `retention.default v3` says governed/erasure-indexed.
Migration 0018 therefore adds `memory_content_objects` keyed by
`(tenant_id, project, storage_identity)` with `protection_domain_id`, `media_type`, `byte_length`,
`content_digest`, `retention_class`, retention-policy reference, a per-object DEK wrapped under a
config-provided KEK (`FLEET_RECALL_CONTENT_KEK_HEX`, AES-256-GCM via the already-pinned `ring`),
the envelope-encrypted bytes, and erasure-index keys for the four `ErasureScopeKind` axes. The
table is NEVER in the publication reader's eight tables (its proof asserts the exclusion).
`memory.claim.accepted` keeps its inline assertion text and is classified immutable-inline with a
documented erasure limitation. Tombstone/fence/generation machinery is W0-ERASE's contract and is
not built here.

## D6 — Parsers and dependencies

**Decision.** Transcript parser: hand-written streaming `serde_json` over line-delimited session
files, in-tree, with an explicit parser artifact/configuration digest (W0-CHUNK `ParserKeyV1`);
no dependency on `ostk-recall-scan`. Git objects (Wave 2): a hardened `git cat-file --batch`
subprocess reader (`GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_PAGER=cat`,
`--no-optional-locks`, sanitized environment) that recomputes every object ID from the returned
`<type> SP <len> NUL <payload>` framing so the subprocess is untrusted and interchangeable; `gix`
(pure Rust, MIT/Apache) is the designated in-process replacement if one becomes mandatory; `git2`
is excluded (C build). Arrow: deferred entirely — no `arrow` crate before W2-PROJ lands. Net new
third-party dependencies from Wave 1 and Wave 2: zero.

## Migration 0018 shape (single additive migration for Wave 1)

`memory_evidence_shard_heads`, `memory_evidence_events` (D1, with the governance-kind CHECK and
0005-style predecessor-unique index); `memory_evidence_quarantine` (W0-QUAR record: quarantine ID,
scope, connector principal/instance, delivery ID + attempt count, optional source-fact ID /
representation key, canonical payload DIGEST only, bounded diagnostic BYTES ≤ 4096, reason,
received_at; no payload bytes column); `memory_content_objects` (D5);
`memory_relation_projection_v1` + `memory_relation_projection_watermarks_v1` (W1-REL: current
relation state per fingerprint + per-shard cursor advanced atomically with the projection);
`memory_claims.accepted_event_id BYTES NULL CHECK (octet_length = 32)` and
`memory_mutation_receipts.accepted_event_id BYTES NULL` (D3); the view
`memory_writer_authority_v1` (D4). No change to migrations 0001–0017 bytes.

## Consequences

- Waves 1–3 build on a writer that can never touch the governance ledger; the control/registry
  proofs stay untouched.
- One refreeze at Wave-1 close: the eight-file runtime source manifest, the runtime policy
  digest (LocalStack `smoke.sh` / `database-boundary.sh` / README), the migration-prefix pins
  (17 → 18), and the exact grant-matrix count.
- The doc's "one ledger" wording is amended to name the two physical ledgers under one epoch.
- Legacy `record` remains a pre-history projection until imported by the bootstrap-manifest event.
