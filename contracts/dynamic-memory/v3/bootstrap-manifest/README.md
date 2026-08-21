# Canonical bootstrap-manifest v1 contract vectors (W1-IMPORT)

These fixtures freeze the signed, content-addressed bootstrap-manifest event
`docs/DYNAMIC_MEMORY_ARCHITECTURE.md`'s "Staged implementation" section names
as the way "existing chunks, claims, conflicts, and receipts enter the new
history." Every `.jsonl` file contains one canonical JSON record plus exactly
one repository-framing LF. The LF is excluded from every *contract* digest —
it is trailing whitespace to the frozen canonicalization profile's parser, not
part of the canonical document — but it is included in the pinned raw *file*
SHA-256 constants in `src/memory_contracts/bootstrap_manifest.rs`, which hash
the file exactly as it sits in the repository.

None of the fixture scope, registry head, or digest carries runtime
authority — these are structural assertions, not active-registry or
admission witnesses. Deserializing and structurally validating a
`BootstrapManifestAcceptedStatementV1` cannot admit it for append; only
`crate::evidence_ledger::AppendableAcceptedEvent::bootstrap_manifest`, given a
same-transaction `WriterAuthorityWitness`, can.

## What `BootstrapManifestV1` is, and is not

A manifest asserts exactly: one authenticated tenant/project scope, the fixed
`provenance_kind` `"legacy_import"` (there is no other value), and a sorted,
deduplicated list of `(table, primary_key) -> row_digest` identities drawn
from the closed five-table set migration 0001 defines:
`memory_chunks`, `memory_claims`, `memory_conflicts`,
`memory_conflict_members`, `memory_mutation_receipts`. It asserts no provider
event, no causal edge, and no projector state, and it never carries a legacy
row's own bytes — only `legacy_row_digest`'s digest of the operator's own
canonical row encoding (EVID-01, EVID-05).

`rows` must already be in strict ascending `(table, primary_key)` order with
no duplicate identity when a `BootstrapManifestV1` is constructed;
`validate_shape` fails closed with `ContractError::NonCanonicalSet { field:
"rows" }` rather than silently sorting, exactly like
`remember_v2::SemanticClaimV2` requires its own `applicability` list
pre-sorted. Two independent enumerations of the same row set are therefore
byte-identical, and so carry an identical `manifest_digest`, once each is
built from its rows in that one canonical order.

`BootstrapManifestAcceptedStatementV1` binds a manifest to one profile, scope,
and exact active-head binding (`RegistryHeadBindingV1`), mirroring
`remember_v2::RememberAcceptedStatementV2`. Its `accepted_event_id` is a
digest of the *whole* accepted-event preimage under
`DigestDomain::AcceptedEvent`; `manifest_digest` is a separate,
content-addressed digest of *only* the row enumeration under the new
`DigestDomain::BootstrapManifestV1`, so the same row set imported under two
different registry generations carries the same `manifest_digest` but two
different `accepted_event_id`s.

## Ledger seam

`AcceptedEventKindV1::BootstrapManifest` (`bootstrap.manifest.accepted`) is
`SemanticIdentityRuleV1::UniquePreimage`, keyed on `manifest_digest`: EVENT-01
applies literally, exactly as it does for `evidence.accepted`. This kind
carries no `EvidenceDeliveryContextV1`/`EvidenceIdentityLinks` pair (a legacy
import has no connector delivery), so a preimage disagreement at the ledger
level fails closed through `EvidenceAppendError::LedgerIntegrity` rather than
a `QuarantineRecordV1` row — the same backstop
`RelationAttestation`/`MemoryClaim` use for their own same-event-ID byte
divergence (see `evidence_ledger::appendable`'s module documentation).

A *different* kind of collision — a second, genuinely distinct manifest (a
different `manifest_digest`) that names a legacy row an earlier accepted
manifest already imported, with different bytes — is not something the
ledger's own replay classification can see (the two accepted events have
different `semantic_object_digest` values). It is caught by
`evidence_ledger::BootstrapImportProjection`, which fails the whole append
transaction closed (no event insert survives, no head advance) when it finds a
`(table, row_key)` already recorded in the proposed
`memory_bootstrap_import_rows` side table under a different `row_digest`. The
projection itself returns `EvidenceAppendError::LedgerIntegrity`, but that
value crosses the generic `AppendProjection` trait boundary before reaching a
caller of `AcceptedEventRepository::append` — `append_in_transaction` converts
any projection error through `EvidenceAppendError -> FleetError ->
EvidenceAppendError::Storage`, so the caller-visible shape is
`Err(EvidenceAppendError::Storage(FleetError::Memory(message)))` carrying this
projection's message text, not the `LedgerIntegrity` variant directly. See
`tests/bootstrap_manifest_live.rs` for the connected proof.

## Fixtures in this directory

- `bootstrap-manifest-v1.jsonl` — one positive `BootstrapManifestV1`: two
  rows (`memory_chunks`, `memory_claims`), already sorted.
- `bootstrap-manifest-accepted-statement-v1.jsonl` — the accepted-event
  preimage binding that manifest to a profile/scope/registry-head triple.
- `negative-unsorted-rows.jsonl` — the same manifest with its two rows
  swapped: rejected by the strict-sort check, not silently re-sorted.
- `negative-duplicate-row.jsonl` — the same manifest with a second entry for
  `memory_chunks`/`chunk-1` carrying a *different* `row_digest`: still
  rejected by the strict-sort check, because it compares only
  `(table, primary_key)`, never `row_digest`.
- `negative-foreign-scope.jsonl` — the accepted statement with its `scope`
  changed to a tenant/project the manifest does not carry: rejected because
  `statement.scope != statement.manifest.scope`.
- `negative-unknown-field.jsonl` — the positive manifest with an extra
  `legacy_row_bytes` key spliced in at the top level: rejected at decode time
  by `#[serde(deny_unknown_fields)]`, never reaching `validate_shape`.

## Regenerating

`cargo +1.94 test --locked --lib \
memory_contracts::bootstrap_manifest::tests::regenerate_bootstrap_manifest_contract_artifacts \
-- --ignored --nocapture` with `BOOTSTRAP_MANIFEST_VECTOR_OUTPUT=<this
directory>` set rewrites every fixture above from the exact Rust values the
non-ignored tests in `src/memory_contracts/bootstrap_manifest.rs` pin against,
and prints the two frozen digest constants those tests assert.
