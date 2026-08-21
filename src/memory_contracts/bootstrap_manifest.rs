//! Bootstrap-manifest import contract (W1-IMPORT).
//!
//! `docs/DYNAMIC_MEMORY_ARCHITECTURE.md`'s "Staged implementation" section is
//! explicit: *"Existing chunks, claims, conflicts, and receipts enter the new
//! history through a signed, content-addressed bootstrap-manifest event.
//! Imported records retain honest legacy provenance; the migration does not
//! fabricate historical provider events or causal edges."*
//!
//! This module is contract-only, exactly like
//! [`super::evidence_v2`] and [`super::remember_v2`]: [`BootstrapManifestV1`]
//! and [`BootstrapManifestAcceptedStatementV1`] are identity-bearing data, not
//! proof of active-registry authority or that a row was honestly enumerated
//! from the legacy tables. A later repository seam must independently supply
//! both facts from one transaction before it may append an event
//! ([`crate::evidence_ledger::AppendableAcceptedEvent::bootstrap_manifest`]).
//!
//! # What a manifest asserts, and what it deliberately does not
//!
//! A [`BootstrapManifestV1`] asserts exactly: one scope, the fixed
//! `provenance_kind` `"legacy_import"`, and a sorted, deduplicated list of
//! `(table, primary_key) -> row_digest` identities drawn from the closed
//! [`LegacyTableV1`] set. It asserts no provider event, no causal edge, and no
//! projector state — a legacy `memory_claims` row becoming a `memory.claim`
//! projection, for instance, is a separate, later projection concern, not
//! something this import event claims for itself. The manifest also never
//! carries a legacy row's own bytes, only its digest: no legacy payload
//! becomes ledger content by this import (EVID-01, EVID-05).
//!
//! # Deterministic sort, not runtime normalization
//!
//! [`BootstrapManifestV1::validate_shape`] requires `rows` to already be in
//! strict ascending `(table, primary_key)` order with no duplicate identity —
//! it fails closed rather than silently sorting, exactly like
//! [`super::remember_v2::SemanticClaimV2`] requires its own `applicability`
//! list pre-sorted. Two independent enumerations of the same row set are
//! therefore byte-identical, and so carry an identical
//! [`BootstrapManifestV1::manifest_digest`], once each is built from its rows
//! in that one canonical order; the discipline lives in the shared sort
//! recipe every caller uses before construction, not in normalization inside
//! this type.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{
    ContractError, ContractResult,
    bootstrap::ConsistencyPartitionKeyV1,
    canonical::encode_canonical,
    common::{AuthenticatedProjectScopeV1, ContractId, ProfileReferenceV1},
    digest::{DigestDomain, Sha256Digest, body_digest, domain_separated_digest},
    evidence::AcceptedEventId,
    evidence_v2::RegistryHeadBindingV1,
};

const BOOTSTRAP_MANIFEST_SCHEMA_VERSION: u32 = 1;
const BOOTSTRAP_MANIFEST_ACCEPTED_SCHEMA_VERSION: u32 = 1;
/// `event_kind` stored with the accepted event row.
pub const BOOTSTRAP_MANIFEST_ACCEPTED_EVENT_KIND: &str = "bootstrap.manifest.accepted";
/// The only admitted `provenance_kind`. There is no other value.
pub const LEGACY_IMPORT_PROVENANCE_KIND: &str = "legacy_import";
const BOOTSTRAP_MANIFEST_CONSISTENCY_FAMILY: &str = "bootstrap_manifest";
/// Bounded by the canonical JSON profile's own array-element limit
/// (`MAX_COLLECTION_ELEMENTS`); stated explicitly here so a manifest's own
/// shape check, not just the canonical encoder, rejects an oversized list.
const MAX_MANIFEST_ROWS: usize = 4_096;
const MAX_PRIMARY_KEY_COMPONENTS: usize = 4;

/// Closed set of legacy tables a bootstrap manifest may enumerate rows from.
///
/// Stage-4 admits exactly these five: the pre-ledger corpus (`memory_chunks`),
/// claims (`memory_claims`), conflicts and their membership
/// (`memory_conflicts`, `memory_conflict_members`), and idempotency receipts
/// (`memory_mutation_receipts`) — the pre-ledger tables migration 0001
/// defines. No other legacy table may be named: adding one is a deliberate
/// edit here, never an open string a caller supplies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegacyTableV1 {
    MemoryChunks,
    MemoryClaims,
    MemoryConflicts,
    MemoryConflictMembers,
    MemoryMutationReceipts,
}

impl LegacyTableV1 {
    /// Exact table name this variant enumerates rows from.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MemoryChunks => "memory_chunks",
            Self::MemoryClaims => "memory_claims",
            Self::MemoryConflicts => "memory_conflicts",
            Self::MemoryConflictMembers => "memory_conflict_members",
            Self::MemoryMutationReceipts => "memory_mutation_receipts",
        }
    }
}

/// One primary-key column value, in a representation independent of any
/// particular database driver's type system.
///
/// `tenant_id`/`project` are never encoded here: a manifest's own `scope`
/// field already binds every row it enumerates to one tenant/project pair
/// (EVID-04), so repeating those columns per row would let a row's bytes
/// assert a scope the manifest's own field does not carry.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LegacyPrimaryKeyComponentV1 {
    Text { value: String },
    Integer { value: i64 },
}

/// Exact identity of one legacy row admitted into the new history.
///
/// `row_digest` is the caller's [`legacy_row_digest`] over that row's own
/// canonical byte encoding — a recipe this contract does not further
/// constrain beyond fixing the hash function, because legacy rows carry
/// columns (`memory_chunks.embedding` is `VECTOR(512)`) the float-forbidding
/// canonical JSON profile cannot represent. The manifest carries only the
/// digest, never the row bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapManifestRowV1 {
    pub table: LegacyTableV1,
    pub primary_key: Vec<LegacyPrimaryKeyComponentV1>,
    pub row_digest: Sha256Digest,
}

impl BootstrapManifestRowV1 {
    fn validate_shape(&self) -> ContractResult<()> {
        if self.primary_key.is_empty()
            || self.primary_key.len() > MAX_PRIMARY_KEY_COMPONENTS
            || self.row_digest == Sha256Digest::ZERO
        {
            return Err(ContractError::Schema(
                "invalid bootstrap manifest row identity".into(),
            ));
        }
        Ok(())
    }

    /// `(table, primary_key)`: the identity a manifest may claim at most once.
    /// `row_digest` is deliberately excluded, so two rows sharing this key
    /// with disagreeing digests are adjacent under the sort and therefore
    /// caught by [`strictly_sorted_rows`] as a non-strict pair, not silently
    /// accepted as two distinct entries.
    fn identity_key(&self) -> (LegacyTableV1, &[LegacyPrimaryKeyComponentV1]) {
        (self.table, &self.primary_key)
    }
}

/// Deterministic, content-addressed enumeration of legacy rows admitted by
/// exactly one bootstrap-manifest import.
///
/// No provider event, causal edge, or projector state is asserted here: only
/// row identity and content digest, under `provenance_kind` fixed at
/// `"legacy_import"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapManifestV1 {
    pub schema_version: u32,
    pub scope: AuthenticatedProjectScopeV1,
    pub provenance_kind: ContractId,
    pub rows: Vec<BootstrapManifestRowV1>,
}

impl BootstrapManifestV1 {
    /// Validate byte shape, the fixed provenance kind, and canonical row
    /// order only. This cannot prove the rows were honestly enumerated from
    /// the legacy tables or that `scope` is authenticated; those are
    /// repository admission witnesses.
    pub fn validate_shape(&self) -> ContractResult<()> {
        if self.schema_version != BOOTSTRAP_MANIFEST_SCHEMA_VERSION
            || self.provenance_kind.as_str() != LEGACY_IMPORT_PROVENANCE_KIND
            || self.rows.is_empty()
            || self.rows.len() > MAX_MANIFEST_ROWS
        {
            return Err(ContractError::Schema("invalid bootstrap manifest".into()));
        }
        for row in &self.rows {
            row.validate_shape()?;
        }
        if !strictly_sorted_rows(&self.rows) {
            return Err(ContractError::NonCanonicalSet { field: "rows" });
        }
        encode_canonical(self)?;
        Ok(())
    }

    /// Content-addressed identity of the exact row enumeration.
    pub fn manifest_digest(&self) -> ContractResult<BootstrapManifestDigestV1> {
        self.validate_shape()?;
        Ok(BootstrapManifestDigestV1::from_digest(
            domain_separated_digest(DigestDomain::BootstrapManifestV1, &encode_canonical(self)?),
        ))
    }
}

fn strictly_sorted_rows(rows: &[BootstrapManifestRowV1]) -> bool {
    rows.windows(2)
        .all(|pair| pair[0].identity_key() < pair[1].identity_key())
}

/// Content-addressed identity of one [`BootstrapManifestV1`] row enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BootstrapManifestDigestV1(Sha256Digest);

impl BootstrapManifestDigestV1 {
    #[must_use]
    pub const fn from_digest(digest: Sha256Digest) -> Self {
        Self(digest)
    }

    #[must_use]
    pub const fn digest(self) -> Sha256Digest {
        self.0
    }
}

impl std::fmt::Display for BootstrapManifestDigestV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for BootstrapManifestDigestV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BootstrapManifestDigestV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Sha256Digest::deserialize(deserializer).map(Self)
    }
}

/// Immutable accepted-event preimage for one admitted bootstrap-manifest
/// import.
///
/// Mirrors [`super::remember_v2::RememberAcceptedStatementV2`]: profile,
/// scope, and the exact active-head binding travel with the statement so the
/// append seam can prove it was admitted under the head asserted here
/// (ADR 0002 D4). It contains no row ID, receipt clock, storage locator,
/// epoch, shard, offset, or append-chain field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapManifestAcceptedStatementV1 {
    pub schema_version: u32,
    pub event_kind: ContractId,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub registry: RegistryHeadBindingV1,
    pub manifest: BootstrapManifestV1,
    pub manifest_digest: BootstrapManifestDigestV1,
}

impl BootstrapManifestAcceptedStatementV1 {
    /// Validate structural bindings only. This does not admit the statement.
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.profile.require_frozen_runtime_profile()?;
        self.registry.validate_shape()?;
        self.manifest.validate_shape()?;
        if self.schema_version != BOOTSTRAP_MANIFEST_ACCEPTED_SCHEMA_VERSION
            || self.event_kind.as_str() != BOOTSTRAP_MANIFEST_ACCEPTED_EVENT_KIND
            || self.scope != self.manifest.scope
            || self.manifest_digest != self.manifest.manifest_digest()?
        {
            return Err(ContractError::Schema(
                "invalid accepted bootstrap manifest statement".into(),
            ));
        }
        encode_canonical(self)?;
        Ok(())
    }

    /// Semantic accepted-event identity. Receipt and append metadata cannot
    /// affect it because those values are not fields in this preimage.
    pub fn accepted_event_id(&self) -> ContractResult<AcceptedEventId> {
        self.validate_shape()?;
        Ok(AcceptedEventId::from_digest(domain_separated_digest(
            DigestDomain::AcceptedEvent,
            &encode_canonical(self)?,
        )))
    }

    /// Registry-controlled consistency family and logical key. The manifest
    /// digest is the key: two accepted statements naming the same content
    /// enumeration share a shard, exactly like [`super::evidence_v2`]'s
    /// source-fact partitioning.
    pub fn consistency_partition_key(&self) -> ContractResult<ConsistencyPartitionKeyV1> {
        self.validate_shape()?;
        Ok(ConsistencyPartitionKeyV1 {
            family: ContractId::new(BOOTSTRAP_MANIFEST_CONSISTENCY_FAMILY)?,
            key_digest: self.manifest_digest.digest(),
        })
    }
}

/// Opaque authority capability consumed by the evidence-ledger append seam.
///
/// No production constructor exists in this contract-only stage. Deserializing
/// or structurally validating [`BootstrapManifestAcceptedStatementV1`] cannot
/// create it.
#[derive(Debug)]
pub struct AdmittedBootstrapManifestStatementV1 {
    statement: BootstrapManifestAcceptedStatementV1,
}

impl AdmittedBootstrapManifestStatementV1 {
    #[must_use]
    pub const fn statement(&self) -> &BootstrapManifestAcceptedStatementV1 {
        &self.statement
    }

    #[cfg(test)]
    pub(crate) fn from_test_witness(
        statement: BootstrapManifestAcceptedStatementV1,
    ) -> ContractResult<Self> {
        statement.validate_shape()?;
        Ok(Self { statement })
    }
}

/// Recipe every caller must use to derive [`BootstrapManifestRowV1::row_digest`]
/// from a legacy row's own canonical byte encoding.
///
/// This is [`super::digest::body_digest`] (exact bytes plus explicit byte
/// length), not the strict canonical JSON profile: legacy columns such as
/// `memory_chunks.embedding` (`VECTOR(512)`) cannot be represented in the
/// float-forbidding canonical JSON profile, so the row-serialization scheme
/// is the caller's own documented column encoding, and only its resulting
/// bytes are pinned by this function.
#[must_use]
pub fn legacy_row_digest(canonical_row_bytes: &[u8]) -> Sha256Digest {
    body_digest(canonical_row_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_contracts::canonical::{decode_strict, require_canonical};

    fn scope() -> AuthenticatedProjectScopeV1 {
        AuthenticatedProjectScopeV1::from_trusted_context(
            ContractId::new("tenant.w1-import").unwrap(),
            ContractId::new("project.fleet-recall").unwrap(),
        )
    }

    fn row(table: LegacyTableV1, key: i64, digest_byte: u8) -> BootstrapManifestRowV1 {
        BootstrapManifestRowV1 {
            table,
            primary_key: vec![LegacyPrimaryKeyComponentV1::Integer { value: key }],
            row_digest: Sha256Digest::from_bytes([digest_byte; 32]),
        }
    }

    fn manifest() -> BootstrapManifestV1 {
        BootstrapManifestV1 {
            schema_version: BOOTSTRAP_MANIFEST_SCHEMA_VERSION,
            scope: scope(),
            provenance_kind: ContractId::new(LEGACY_IMPORT_PROVENANCE_KIND).unwrap(),
            rows: vec![
                row(LegacyTableV1::MemoryChunks, 1, 0x11),
                row(LegacyTableV1::MemoryClaims, 1, 0x22),
                row(LegacyTableV1::MemoryClaims, 2, 0x33),
                row(LegacyTableV1::MemoryConflicts, 1, 0x44),
            ],
        }
    }

    fn head_binding() -> RegistryHeadBindingV1 {
        use crate::memory_contracts::registry::RegistryHeadV1;
        RegistryHeadBindingV1 {
            head: RegistryHeadV1 {
                activation_id: Sha256Digest::from_bytes([0xaa; 32]),
                package_digest: Sha256Digest::from_bytes([0xbb; 32]),
                activation_policy_digest: Sha256Digest::from_bytes([0xcc; 32]),
            },
            effective_from: crate::memory_contracts::common::CanonicalTimestamp::parse(
                "2026-08-14T00:00:00.000000000Z",
            )
            .unwrap(),
            effective_until: None,
        }
    }

    fn statement() -> BootstrapManifestAcceptedStatementV1 {
        let manifest = manifest();
        let manifest_digest = manifest.manifest_digest().unwrap();
        BootstrapManifestAcceptedStatementV1 {
            schema_version: BOOTSTRAP_MANIFEST_ACCEPTED_SCHEMA_VERSION,
            event_kind: ContractId::new(BOOTSTRAP_MANIFEST_ACCEPTED_EVENT_KIND).unwrap(),
            profile: crate::memory_contracts::common::frozen_profile_reference_v1(),
            scope: scope(),
            registry: head_binding(),
            manifest,
            manifest_digest,
        }
    }

    #[test]
    fn legacy_table_names_are_the_five_pre_ledger_tables() {
        let names: Vec<&str> = [
            LegacyTableV1::MemoryChunks,
            LegacyTableV1::MemoryClaims,
            LegacyTableV1::MemoryConflicts,
            LegacyTableV1::MemoryConflictMembers,
            LegacyTableV1::MemoryMutationReceipts,
        ]
        .into_iter()
        .map(LegacyTableV1::as_str)
        .collect();
        assert_eq!(
            names,
            vec![
                "memory_chunks",
                "memory_claims",
                "memory_conflicts",
                "memory_conflict_members",
                "memory_mutation_receipts",
            ]
        );
    }

    #[test]
    fn manifest_digest_is_stable_across_two_independent_constructions() {
        // Two independently built manifests over the exact same row set, in
        // the one canonical sort order, must digest identically.
        let first = manifest();
        let second = manifest();
        assert_eq!(
            first.manifest_digest().unwrap(),
            second.manifest_digest().unwrap()
        );
        assert_eq!(
            encode_canonical(&first).unwrap(),
            encode_canonical(&second).unwrap()
        );
    }

    #[test]
    fn one_byte_of_one_row_changes_the_manifest_digest() {
        let base = manifest();
        let mut mutated = base.clone();
        mutated.rows[0].row_digest = Sha256Digest::from_bytes([0x99; 32]);
        assert_ne!(
            base.manifest_digest().unwrap(),
            mutated.manifest_digest().unwrap()
        );
    }

    #[test]
    fn unsorted_rows_are_rejected() {
        let mut unsorted = manifest();
        unsorted.rows.swap(0, 1);
        assert_eq!(
            unsorted.validate_shape(),
            Err(ContractError::NonCanonicalSet { field: "rows" })
        );
    }

    #[test]
    fn duplicate_row_identity_is_rejected() {
        let mut duplicated = manifest();
        let mut repeat = duplicated.rows[0].clone();
        // Same (table, primary_key) as rows[0], different row_digest: still a
        // non-strict adjacent pair once sorted next to its twin, and the
        // strict-sort check does not compare digests, so this must still fail
        // even though the two entries are not byte-identical.
        repeat.row_digest = Sha256Digest::from_bytes([0xfe; 32]);
        duplicated.rows.insert(1, repeat);
        assert_eq!(
            duplicated.validate_shape(),
            Err(ContractError::NonCanonicalSet { field: "rows" })
        );
    }

    #[test]
    fn wrong_provenance_kind_is_rejected() {
        let mut wrong = manifest();
        wrong.provenance_kind = ContractId::new("source_derived").unwrap();
        assert!(wrong.validate_shape().is_err());
    }

    #[test]
    fn empty_manifest_is_rejected() {
        let mut empty = manifest();
        empty.rows.clear();
        assert!(empty.validate_shape().is_err());
    }

    #[test]
    fn zero_row_digest_is_rejected() {
        let mut zeroed = manifest();
        zeroed.rows[0].row_digest = Sha256Digest::ZERO;
        assert!(zeroed.validate_shape().is_err());
    }

    #[test]
    fn empty_primary_key_is_rejected() {
        let mut empty_key = manifest();
        empty_key.rows[0].primary_key.clear();
        assert!(empty_key.validate_shape().is_err());
    }

    #[test]
    fn primary_key_exceeding_max_components_is_rejected() {
        let mut oversized_key = manifest();
        oversized_key.rows[0].primary_key = (0..=MAX_PRIMARY_KEY_COMPONENTS)
            .map(|value| LegacyPrimaryKeyComponentV1::Integer {
                value: i64::try_from(value).unwrap(),
            })
            .collect();
        assert_eq!(
            oversized_key.rows[0].primary_key.len(),
            MAX_PRIMARY_KEY_COMPONENTS + 1
        );
        assert!(oversized_key.validate_shape().is_err());
    }

    #[test]
    fn manifest_wrong_schema_version_is_rejected() {
        let mut wrong = manifest();
        wrong.schema_version = BOOTSTRAP_MANIFEST_SCHEMA_VERSION + 1;
        assert!(wrong.validate_shape().is_err());
    }

    #[test]
    fn manifest_rows_exceeding_max_is_rejected() {
        let mut oversized = manifest();
        oversized.rows = (0..=MAX_MANIFEST_ROWS)
            .map(|index| BootstrapManifestRowV1 {
                table: LegacyTableV1::MemoryClaims,
                primary_key: vec![LegacyPrimaryKeyComponentV1::Integer {
                    value: i64::try_from(index).unwrap(),
                }],
                row_digest: Sha256Digest::from_bytes([0x5a; 32]),
            })
            .collect();
        assert_eq!(oversized.rows.len(), MAX_MANIFEST_ROWS + 1);
        assert!(
            strictly_sorted_rows(&oversized.rows),
            "fixture must be sorted so only the length bound is exercised"
        );
        assert!(oversized.validate_shape().is_err());
    }

    #[test]
    fn accepted_statement_scope_must_equal_manifest_scope() {
        let mut foreign = statement();
        foreign.scope = AuthenticatedProjectScopeV1::from_trusted_context(
            ContractId::new("tenant.other").unwrap(),
            ContractId::new("project.other").unwrap(),
        );
        assert!(foreign.validate_shape().is_err());
    }

    #[test]
    fn accepted_statement_manifest_digest_must_match_the_manifest() {
        let mut mismatched = statement();
        mismatched.manifest_digest =
            BootstrapManifestDigestV1::from_digest(Sha256Digest::from_bytes([0x77; 32]));
        assert!(mismatched.validate_shape().is_err());
    }

    #[test]
    fn accepted_statement_event_kind_must_be_exact() {
        let mut wrong = statement();
        wrong.event_kind = ContractId::new("evidence.accepted").unwrap();
        assert!(wrong.validate_shape().is_err());
    }

    #[test]
    fn accepted_statement_wrong_schema_version_is_rejected() {
        let mut wrong = statement();
        wrong.schema_version = BOOTSTRAP_MANIFEST_ACCEPTED_SCHEMA_VERSION + 1;
        assert!(wrong.validate_shape().is_err());
    }

    #[test]
    fn accepted_statement_wrong_profile_is_rejected() {
        let mut wrong = statement();
        wrong.profile.profile_digest = Sha256Digest::ZERO;
        assert!(wrong.validate_shape().is_err());
    }

    #[test]
    fn accepted_statement_invalid_registry_head_is_rejected() {
        let mut wrong = statement();
        wrong.registry.head.activation_id = Sha256Digest::ZERO;
        assert!(wrong.validate_shape().is_err());
    }

    #[test]
    fn accepted_statement_invalid_manifest_is_rejected() {
        let mut wrong = statement();
        wrong.manifest.rows.clear();
        assert!(wrong.validate_shape().is_err());
    }

    #[test]
    fn accepted_event_id_is_deterministic_and_content_bound() {
        let mut statement = statement();
        let id_one = statement.accepted_event_id().unwrap();
        let id_two = statement.accepted_event_id().unwrap();
        assert_eq!(id_one, id_two);

        statement.manifest.rows[0].row_digest = Sha256Digest::from_bytes([0x66; 32]);
        statement.manifest_digest = statement.manifest.manifest_digest().unwrap();
        assert_ne!(statement.accepted_event_id().unwrap(), id_one);
    }

    #[test]
    fn consistency_partition_key_is_keyed_by_manifest_digest() {
        let statement = statement();
        let key = statement.consistency_partition_key().unwrap();
        assert_eq!(key.family.as_str(), BOOTSTRAP_MANIFEST_CONSISTENCY_FAMILY);
        assert_eq!(key.key_digest, statement.manifest_digest.digest());
    }

    #[test]
    fn legacy_row_digest_commits_to_length_and_exact_bytes() {
        assert_eq!(legacy_row_digest(b"same"), legacy_row_digest(b"same"));
        assert_ne!(legacy_row_digest(b"same"), legacy_row_digest(b"same\n"));
    }

    #[test]
    fn deny_unknown_fields_on_row_and_manifest_and_statement() {
        let mut row_value = serde_json::to_value(row(LegacyTableV1::MemoryChunks, 1, 1)).unwrap();
        row_value
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), serde_json::json!("x"));
        assert!(serde_json::from_value::<BootstrapManifestRowV1>(row_value).is_err());

        let mut manifest_value = serde_json::to_value(manifest()).unwrap();
        manifest_value
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), serde_json::json!("x"));
        assert!(serde_json::from_value::<BootstrapManifestV1>(manifest_value).is_err());

        let mut statement_value = serde_json::to_value(statement()).unwrap();
        statement_value
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), serde_json::json!("x"));
        assert!(
            serde_json::from_value::<BootstrapManifestAcceptedStatementV1>(statement_value)
                .is_err()
        );
    }

    #[test]
    fn structural_bytes_cannot_enter_the_append_typestate() {
        let statement = statement();
        let admitted =
            AdmittedBootstrapManifestStatementV1::from_test_witness(statement.clone()).unwrap();
        assert_eq!(
            admitted.statement().accepted_event_id().unwrap(),
            statement.accepted_event_id().unwrap()
        );
    }

    // ---- Frozen fixtures (contracts/dynamic-memory/v3/bootstrap-manifest/) ----

    const MANIFEST_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/bootstrap-manifest/bootstrap-manifest-v1.jsonl"
    );
    const ACCEPTED_STATEMENT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/bootstrap-manifest/bootstrap-manifest-accepted-statement-v1.jsonl"
    );
    const NEGATIVE_UNSORTED_ROWS_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/bootstrap-manifest/negative-unsorted-rows.jsonl"
    );
    const NEGATIVE_DUPLICATE_ROW_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/bootstrap-manifest/negative-duplicate-row.jsonl"
    );
    const NEGATIVE_FOREIGN_SCOPE_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/bootstrap-manifest/negative-foreign-scope.jsonl"
    );
    const NEGATIVE_UNKNOWN_FIELD_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/bootstrap-manifest/negative-unknown-field.jsonl"
    );
    const VECTOR_SUITE_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/bootstrap-manifest/vector-suite.jsonl");
    const VECTOR_SUITE_RAW_SHA256: &str =
        "1d8032e4e77ddccd1383ad74064f53a53ab9c4e48fd27d8643f6ae6d54fa9371";

    const MANIFEST_DIGEST: &str =
        "d0c4448b3cc623c6f242feaa655c57aa3952c7c2cb15576c5dc60d670f50846c";
    const ACCEPTED_EVENT_ID: &str =
        "cfbd357f02f3d7cdeba7ee0acdf73c2bef51e7dcac0d44e4e6e1d010caa9c094";

    const MANIFEST_FIXTURE_RAW_SHA256: &str =
        "0ee4228131757eb495ac2b1c07725458325835570200f20dbc89cc7648d98543";
    const ACCEPTED_STATEMENT_FIXTURE_RAW_SHA256: &str =
        "2ab2e57b29356baef00e3d1d4661098d41a33bd16918844c56421ed4969dfb9c";
    const NEGATIVE_UNSORTED_ROWS_RAW_SHA256: &str =
        "950873f9979e6dc798bfdbe27379acd2672e779927fa864b0589eb9560939154";
    const NEGATIVE_DUPLICATE_ROW_RAW_SHA256: &str =
        "3809878505f594807ced630ae2f9c7cb283c398f7c25c3eacc5e2a66e173b179";
    const NEGATIVE_FOREIGN_SCOPE_RAW_SHA256: &str =
        "d3c300ba8b0c7dee0a4a4fdb16fc9fe508883d23349b5ed8a9761653f5a57b86";
    const NEGATIVE_UNKNOWN_FIELD_RAW_SHA256: &str =
        "e2cbc6730e88e0143e2d6c2dad06917915bee8e8dcf9304a97de08363fd3d2b7";

    fn raw_sha256(bytes: &[u8]) -> String {
        use sha2::{Digest as _, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hex::encode(hasher.finalize())
    }

    /// Strip the one repository-framing trailing LF every fixture carries, the
    /// same way `quarantine.rs`'s own frozen fixtures do.
    fn fixture_body(fixture: &[u8]) -> &[u8] {
        fixture
            .strip_suffix(b"\n")
            .expect("fixture must end in exactly one repository-framing LF")
    }

    #[test]
    fn positive_manifest_fixture_is_pinned() {
        assert_eq!(
            raw_sha256(MANIFEST_FIXTURE),
            MANIFEST_FIXTURE_RAW_SHA256,
            "fixture bytes drifted"
        );
        require_canonical(fixture_body(MANIFEST_FIXTURE))
            .expect("fixture must be exactly its own canonical form");
        let decoded: BootstrapManifestV1 =
            decode_strict(MANIFEST_FIXTURE).expect("valid bootstrap manifest");
        decoded.validate_shape().expect("fixture must validate");
        let digest = decoded.manifest_digest().unwrap();
        assert_eq!(digest.to_string(), MANIFEST_DIGEST);
        // Determinism: recomputation yields the exact same identity.
        assert_eq!(decoded.manifest_digest().unwrap(), digest);
    }

    #[test]
    fn positive_accepted_statement_fixture_is_pinned() {
        assert_eq!(
            raw_sha256(ACCEPTED_STATEMENT_FIXTURE),
            ACCEPTED_STATEMENT_FIXTURE_RAW_SHA256,
            "fixture bytes drifted"
        );
        require_canonical(fixture_body(ACCEPTED_STATEMENT_FIXTURE))
            .expect("fixture must be exactly its own canonical form");
        let decoded: BootstrapManifestAcceptedStatementV1 =
            decode_strict(ACCEPTED_STATEMENT_FIXTURE).expect("valid accepted statement");
        decoded.validate_shape().expect("fixture must validate");
        let id = decoded.accepted_event_id().unwrap();
        assert_eq!(id.to_string(), ACCEPTED_EVENT_ID);
        assert_eq!(decoded.accepted_event_id().unwrap(), id);
    }

    #[test]
    fn negative_unsorted_rows_fixture_is_rejected() {
        assert_eq!(
            raw_sha256(NEGATIVE_UNSORTED_ROWS_FIXTURE),
            NEGATIVE_UNSORTED_ROWS_RAW_SHA256,
            "fixture bytes drifted"
        );
        let decoded: BootstrapManifestV1 =
            decode_strict(NEGATIVE_UNSORTED_ROWS_FIXTURE).expect("decodable but invalid");
        assert_eq!(
            decoded.validate_shape(),
            Err(ContractError::NonCanonicalSet { field: "rows" })
        );
    }

    #[test]
    fn negative_duplicate_row_fixture_is_rejected() {
        assert_eq!(
            raw_sha256(NEGATIVE_DUPLICATE_ROW_FIXTURE),
            NEGATIVE_DUPLICATE_ROW_RAW_SHA256,
            "fixture bytes drifted"
        );
        let decoded: BootstrapManifestV1 =
            decode_strict(NEGATIVE_DUPLICATE_ROW_FIXTURE).expect("decodable but invalid");
        assert_eq!(
            decoded.validate_shape(),
            Err(ContractError::NonCanonicalSet { field: "rows" })
        );
    }

    #[test]
    fn negative_foreign_scope_fixture_is_rejected() {
        assert_eq!(
            raw_sha256(NEGATIVE_FOREIGN_SCOPE_FIXTURE),
            NEGATIVE_FOREIGN_SCOPE_RAW_SHA256,
            "fixture bytes drifted"
        );
        let decoded: BootstrapManifestAcceptedStatementV1 =
            decode_strict(NEGATIVE_FOREIGN_SCOPE_FIXTURE).expect("decodable but invalid");
        assert!(decoded.validate_shape().is_err());
    }

    #[test]
    fn negative_unknown_field_fixture_fails_to_decode() {
        assert_eq!(
            raw_sha256(NEGATIVE_UNKNOWN_FIELD_FIXTURE),
            NEGATIVE_UNKNOWN_FIELD_RAW_SHA256,
            "fixture bytes drifted"
        );
        let result: ContractResult<BootstrapManifestV1> =
            decode_strict(NEGATIVE_UNKNOWN_FIELD_FIXTURE);
        assert!(result.is_err());
    }

    #[test]
    fn vector_suite_fixture_is_pinned() {
        assert_eq!(
            raw_sha256(VECTOR_SUITE_FIXTURE),
            VECTOR_SUITE_RAW_SHA256,
            "vector-suite.jsonl drifted"
        );
        // Canonicality is pinned like every sibling fixture: the suite index's
        // own bytes must already be in the frozen canonical profile (sorted
        // keys, one LF stripped as repository framing), not merely decode to a
        // canonical meaning.
        require_canonical(fixture_body(VECTOR_SUITE_FIXTURE))
            .expect("vector-suite.jsonl must be exactly its own canonical form");

        // The suite must literally enumerate every positive AND negative
        // fixture in this directory by file path, and its embedded identities
        // must equal the pinned digest constants (declared == enforced).
        let suite: serde_json::Value =
            decode_strict(VECTOR_SUITE_FIXTURE).expect("suite is strict JSON");
        let file_of = |case: &serde_json::Value| -> String {
            case.get("file")
                .and_then(serde_json::Value::as_str)
                .expect("each case names its fixture file")
                .to_owned()
        };
        let positives = suite["positive_cases"].as_array().unwrap();
        let negatives = suite["negative_cases"].as_array().unwrap();
        let mut enumerated: Vec<String> = positives
            .iter()
            .chain(negatives.iter())
            .map(file_of)
            .collect();
        enumerated.sort();
        assert_eq!(
            enumerated,
            vec![
                "bootstrap-manifest-accepted-statement-v1.jsonl".to_owned(),
                "bootstrap-manifest-v1.jsonl".to_owned(),
                "negative-duplicate-row.jsonl".to_owned(),
                "negative-foreign-scope.jsonl".to_owned(),
                "negative-unknown-field.jsonl".to_owned(),
                "negative-unsorted-rows.jsonl".to_owned(),
            ],
            "suite must enumerate exactly the six frozen fixtures by file path"
        );
        assert_eq!(
            positives[0]["manifest_digest"].as_str().unwrap(),
            MANIFEST_DIGEST,
            "suite's manifest_digest must match the pinned constant"
        );
        assert_eq!(
            positives[1]["accepted_event_id"].as_str().unwrap(),
            ACCEPTED_EVENT_ID,
            "suite's accepted_event_id must match the pinned constant"
        );
    }

    /// Maintainer-only regeneration of the frozen fixtures above. Run with
    /// `BOOTSTRAP_MANIFEST_VECTOR_OUTPUT=<dir> cargo test -p ostk-fleet-recall
    /// --lib memory_contracts::bootstrap_manifest::tests::regenerate -- --ignored --nocapture`.
    #[test]
    #[ignore = "maintainer-only canonical fixture regeneration"]
    #[allow(clippy::too_many_lines)] // one linear maintainer emitter per fixture, incl. the suite index
    fn regenerate_bootstrap_manifest_contract_artifacts() {
        use std::{fs, path::Path};

        fn framed(bytes: &[u8]) -> Vec<u8> {
            let mut framed = bytes.to_vec();
            framed.push(b'\n');
            framed
        }

        fn write(output: &Path, name: &str, bytes: &[u8]) {
            fs::write(output.join(name), framed(bytes)).unwrap();
        }

        let output = std::env::var_os("BOOTSTRAP_MANIFEST_VECTOR_OUTPUT")
            .map(std::path::PathBuf::from)
            .expect("BOOTSTRAP_MANIFEST_VECTOR_OUTPUT is required");
        fs::create_dir_all(&output).unwrap();

        let manifest = manifest();
        let statement = statement();
        write(
            &output,
            "bootstrap-manifest-v1.jsonl",
            &encode_canonical(&manifest).unwrap(),
        );
        write(
            &output,
            "bootstrap-manifest-accepted-statement-v1.jsonl",
            &encode_canonical(&statement).unwrap(),
        );

        let mut unsorted = manifest.clone();
        unsorted.rows.swap(0, 1);
        write(
            &output,
            "negative-unsorted-rows.jsonl",
            &encode_canonical(&unsorted).unwrap(),
        );

        let mut duplicated = manifest.clone();
        let mut repeat = duplicated.rows[0].clone();
        repeat.row_digest = Sha256Digest::from_bytes([0xfe; 32]);
        duplicated.rows.insert(1, repeat);
        write(
            &output,
            "negative-duplicate-row.jsonl",
            &encode_canonical(&duplicated).unwrap(),
        );

        let mut foreign = statement.clone();
        foreign.scope = AuthenticatedProjectScopeV1::from_trusted_context(
            ContractId::new("tenant.other").unwrap(),
            ContractId::new("project.other").unwrap(),
        );
        write(
            &output,
            "negative-foreign-scope.jsonl",
            &encode_canonical(&foreign).unwrap(),
        );

        let mut unknown_field = serde_json::to_value(&manifest).unwrap();
        unknown_field
            .as_object_mut()
            .unwrap()
            .insert("legacy_row_bytes".into(), serde_json::json!("smuggled"));
        write(
            &output,
            "negative-unknown-field.jsonl",
            &serde_json::to_vec(&unknown_field).unwrap(),
        );

        // The suite index is regenerated through the same canonical encoder as
        // every fixture it names, so it is byte-canonical (sorted keys) by
        // construction. Every positive AND negative fixture in this directory
        // is enumerated by its own file path, and the domain prefixes and
        // digests are derived from the contract, never hand-asserted.
        let legacy_tables: Vec<&str> = [
            LegacyTableV1::MemoryChunks,
            LegacyTableV1::MemoryClaims,
            LegacyTableV1::MemoryConflicts,
            LegacyTableV1::MemoryConflictMembers,
            LegacyTableV1::MemoryMutationReceipts,
        ]
        .into_iter()
        .map(LegacyTableV1::as_str)
        .collect();
        let suite = serde_json::json!({
            "schema_version": BOOTSTRAP_MANIFEST_SCHEMA_VERSION,
            "digest_domain_prefix": DigestDomain::BootstrapManifestV1.prefix(),
            "accepted_event_digest_domain_prefix": DigestDomain::AcceptedEvent.prefix(),
            "provenance_kind": LEGACY_IMPORT_PROVENANCE_KIND,
            "legacy_tables": legacy_tables,
            "positive_cases": [
                {
                    "file": "bootstrap-manifest-v1.jsonl",
                    "kind": "manifest",
                    "manifest_digest": manifest.manifest_digest().unwrap().to_string(),
                },
                {
                    "file": "bootstrap-manifest-accepted-statement-v1.jsonl",
                    "kind": "accepted_statement",
                    "accepted_event_id": statement.accepted_event_id().unwrap().to_string(),
                },
            ],
            "negative_cases": [
                { "case": "unsorted_rows", "file": "negative-unsorted-rows.jsonl" },
                { "case": "duplicate_row_identity", "file": "negative-duplicate-row.jsonl" },
                { "case": "foreign_scope", "file": "negative-foreign-scope.jsonl" },
                { "case": "unknown_field", "file": "negative-unknown-field.jsonl" },
            ],
        });
        write(
            &output,
            "vector-suite.jsonl",
            &encode_canonical(&suite).unwrap(),
        );

        println!("MANIFEST_DIGEST {}", manifest.manifest_digest().unwrap());
        println!(
            "ACCEPTED_EVENT_ID {}",
            statement.accepted_event_id().unwrap()
        );
    }
}
