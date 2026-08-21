//! Generic accepted-event append repository over the Stage-4 evidence ledger.
//!
//! # One semantic ledger, two physical ledgers (ADR 0002 D1)
//!
//! General accepted events — `evidence.accepted`,
//! `relation.attestation.accepted`, and `memory.claim.accepted` — are appended
//! to `memory_evidence_events` + `memory_evidence_shard_heads`, the physical
//! mirror of the control ledger. Both physical ledgers share ONE semantic
//! ledger contract: the same genesis log epoch, the same partition recipe and
//! seed, the same [`AppendPositionV1`] algebra, the same
//! `derive_append_chain_digest` recipe, the same `FOR UPDATE` head lock plus
//! compare-and-swap advance, and one `event_kind` / `consistency_family`
//! namespace. Governance kinds never appear here: they are unconstructible in
//! [`AcceptedEventKindV1`], forbidden by migration 0018's
//! `memory_evidence_event_governance_exclusion` CHECK, and unreachable through
//! `fleet_runtime`'s grants, which include no `memory_control_*` or
//! `memory_registry_*` base table at all (ADR 0002 D2).
//!
//! [`AppendPositionV1`]: crate::memory_contracts::bootstrap::AppendPositionV1
//!
//! # The append transaction
//!
//! [`AcceptedEventRepository::append`] runs the whole sequence inside ONE
//! serializable transaction, which is what makes EVENT-03 mechanical rather
//! than aspirational:
//!
//! 1. **Head witness fence (D4).** A plain `SELECT … LIMIT 2` of
//!    `memory_writer_authority_v1` must return exactly one `active` row, and
//!    every field the caller's [`WriterAuthorityWitness`] claims — the exact
//!    ABA-safe activation ID (never the package digest alone), the generation,
//!    the log-epoch ID, the whole partition recipe, and the contract
//!    namespaces — must equal it. Serializable isolation is the fence; there is
//!    no separate compare-and-swap and no last-known-head fallback.
//! 2. **Statement head binding (D4).** The head binding the accepted statement
//!    itself carries — retained on the [`AppendableAcceptedEvent`] since its
//!    construction — is compared field-by-field and then byte-for-byte against
//!    the `canonical_head` that same view read returned. Step 1 alone would not
//!    imply this: a caller can hold two witnesses, construct the appendable
//!    under one and append under the other, so only a direct
//!    statement-versus-view comparison proves the bytes about to be stored
//!    assert the head that is active in this very transaction. A disagreement
//!    is [`EvidenceAppendError::StatementAuthority`], and it is what stops an
//!    admission stage that prepared under generation N from minting an event
//!    asserting generation N after a successor moved the head to N+1
//!    (EVENT-01, ADR 0002 D3).
//! 3. **Shard selection.** `partition_for_epoch` over
//!    `(epoch id, canonical scope, consistency family, key digest)` — the exact
//!    function the control ledger uses for its own events.
//! 4. **Lazy head seed.** `INSERT … ON CONFLICT DO NOTHING` at offset 0 with
//!    the deterministic genesis chain digest below. The head table carries no
//!    foreign key to any control table, precisely so this seed needs no
//!    control-plane `SELECT` grant (ADR 0002 D1 amendment).
//! 5. **`SELECT … FOR UPDATE`** on the head row.
//! 6. **Replay and integrity classification, before any insert.** See below.
//! 7. **Event insert** with `previous_chain_digest` = the locked chain and
//!    `chain_digest = derive_append_chain_digest(locked, event_id, position)`.
//! 8. **The caller's projection**, in this same transaction (EVENT-03,
//!    REPLAY-02).
//! 9. **Head compare-and-swap** against the exact locked offset and chain.
//!
//! # Offset-zero framing
//!
//! `H0 = framed(ostk-evidence-genesis-chain-v1, [epoch_id_bytes,
//! shard_as_u32_big_endian])`, i.e.
//!
//! ```text
//! SHA-256( "ostk-evidence-genesis-chain-v1" || 0x00
//!          || u64_be(32) || epoch_id[0..32]
//!          || u64_be(4)  || u32_be(shard) )
//! ```
//!
//! [`evidence_genesis_chain_digest`] is the single implementation and carries a
//! pinned unit vector. This is deliberately NOT `DigestDomain::GenesisChain`:
//! the control ledger's offset-zero digest frames the bootstrap receipt digest,
//! the epoch ID, and a `u16` shard under a different domain, so no evidence
//! seed can be replayed as a control one.
//!
//! # Replay, collision, and disagreement
//!
//! | condition | outcome |
//! | --- | --- |
//! | same `event_id`, byte-identical canonical event | [`AppendOutcome::Replayed`] — no insert, no head advance, **projection not re-run** |
//! | same `event_id`, different bytes | [`AppendOutcome::Quarantined`] with `integrity_collision`; head untouched |
//! | same `semantic_object_digest` under a different `event_id` (evidence only) | [`AppendOutcome::Quarantined`] with `preimage_disagreement`; head untouched |
//!
//! Exact replay skips the projection because EVENT-03 already committed that
//! projection in the same transaction as the original append: re-running it
//! would let at-least-once transport repeat a lifecycle effect the accepted
//! event only ever had once (EVENT-01). A projector that must rebuild replays
//! from `memory_evidence_events`, which is the only authority (REPLAY-01).
//!
//! The `preimage_disagreement` rule applies only where the doc states it.
//! EVENT-01 is literal for evidence: *different canonical bytes under the same
//! source-fact and representation identity are quarantined*. Relation
//! attestations (REL-01) and remember assertions accumulate many legitimate
//! events per semantic object, so for those kinds `semantic_object_digest` is a
//! projector coordinate rather than a uniqueness key — see
//! [`SemanticIdentityRuleV1`].
//!
//! Both quarantine reasons require a source-fact *and* a representation
//! identity (`W0-QUAR`), which only `evidence.accepted` carries. A relation or
//! claim event whose stored bytes diverge under one accepted-event ID therefore
//! fails closed with [`EvidenceAppendError::LedgerIntegrity`] instead of
//! inventing an invalid dead-letter shape — that condition is a stored-ledger
//! tamper, not a connector delivery.

mod admission;
mod appendable;
mod cockroach;
mod content_store;
mod error;
mod repository;
mod witness;

pub use admission::{
    ActiveStage4Package, AdmittedEvidenceStatementV2, ClockOrderKind, EvidenceAdmissionError,
    EvidenceAdmissionRequestV1, EvidenceIngressLocatorsV1, ResourceIdentityKind, admit_evidence,
    derive_integrity_state,
};
pub use appendable::{
    AcceptedEventKindV1, AppendableAcceptedEvent, EvidenceDeliveryContextV1, SemanticIdentityRuleV1,
};
pub use cockroach::CockroachAcceptedEventRepository;
pub use content_store::{
    CONTENT_KEY_ENCRYPTION_KEY_ENV, ContentKeyEncryptionKey, ContentObjectWrite,
    GovernedContentAssociatedDataV2, GovernedContentObjectV1, GovernedContentProjection,
    MAX_GOVERNED_CONTENT_BYTES, SealedContentObject, fetch_governed_content,
    store_governed_content,
};
pub use error::{
    AuthorityUnavailableKind, EvidenceAppendError, EvidenceAppendResult, WitnessMismatchKind,
};
pub use repository::{
    AcceptedEventRepository, AppendOutcome, AppendProjection, FnProjection, NoProjection,
    ProjectionContext, ShardChainAudit, ShardChainDivergence, ShardChainDivergenceKind,
};
pub use witness::{WriterAuthoritySnapshot, WriterAuthorityWitness, evidence_genesis_chain_digest};
