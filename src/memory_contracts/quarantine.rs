//! Quarantine / dead-letter record for rejected deliveries; never projected.
//!
//! "Ingestion and projections" (`docs/DYNAMIC_MEMORY_ARCHITECTURE.md`) is
//! explicit: rejected deliveries create only bounded quarantine records and
//! never enter searchable projections; transport delivery IDs deduplicate
//! ingress only. "Failure, convergence, and history" adds that invalid
//! signatures, identity/payload collisions, and unauthorized scope are
//! quarantined before projection, and the Arrow transport boundary fails
//! closed into quarantine on unknown schemas, duplicate event positions,
//! oversized batches, or row/preimage disagreement.
//!
//! [`QuarantineRecordV1`] is deliberately thin: an authenticated scope, a
//! connector identity, a transport delivery ID and attempt count, an
//! optional best-effort source-fact/representation link, a payload *digest*
//! (never bytes), a closed [`QuarantineReasonV1`], one bounded
//! [`BoundedDiagnosticV1`], and a receipt timestamp. It has no field that
//! could hold raw payload bytes, no scope field a payload could select
//! (EVID-04), and no "release to projection" affordance (EVID-05): a JSON
//! delivery that tries to add any of those keys is rejected by
//! `#[serde(deny_unknown_fields)]` before it is ever interpreted, and a
//! delivery that omits a required field never decodes at all.
//!
//! Resolution is external and additive: a quarantined delivery is resolved
//! only by a *new* accepted event under a corrected representation, linked
//! back to this record only through `source_fact_id` when one was
//! derivable. This module exposes no method that edits a record's reason,
//! diagnostic, or any other field — the only operations are construction,
//! validation, and reading.
//!
//! See [`NotProjectable`] for the exact, honestly-scoped shape of the
//! "cannot become an accepted event or projection input" guarantee.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{
    ContractError, ContractResult,
    canonical::encode_canonical,
    common::{AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, HexBytes},
    digest::{DigestDomain, Sha256Digest, domain_separated_digest},
};

const QUARANTINE_SCHEMA_VERSION: u32 = 1;

/// Hard byte bound on a bounded diagnostic message.
///
/// This is deliberately far below the frozen canonical-string ceiling
/// (`MAX_STRING_BYTES`, 65,536): a diagnostic explains a rejection, it does
/// not retain the rejected bytes.
pub const MAX_DIAGNOSTIC_MESSAGE_BYTES: usize = 512;

/// Upper bound on a recorded redelivery attempt count. At-least-once
/// transport can retry, but an unbounded counter is not a contract value.
pub const MAX_ATTEMPT_COUNT: u32 = 1_000_000;

/// Hard byte bound on `transport_delivery_id`, tighter than the generic
/// [`HexBytes`] 4,096-byte ceiling.
///
/// This field exists to deduplicate ingress attempts, not to carry payload:
/// every real transport delivery identifier (a UUID, a provider-issued
/// opaque token) fits in a handful of bytes. Bounding it here — rather than
/// only at the generic newtype level — is itself the leakage guarantee: no
/// non-digest field on this record can ever carry more than this many bytes
/// of provider- or payload-controlled data, so at most
/// `MAX_TRANSPORT_DELIVERY_ID_BYTES` bytes could ever "ride in" through this
/// field, however the delivering transport chooses to populate it.
pub const MAX_TRANSPORT_DELIVERY_ID_BYTES: usize = 64;

/// Closed rejection-cause taxonomy for one quarantined delivery.
///
/// This list is exhaustively matched everywhere a reason is interpreted.
/// Adding a cause is a schema-version change, not a silent extension: an
/// unrecognized string fails closed at deserialization rather than falling
/// back to a default reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReasonV1 {
    /// EVENT-01: different canonical bytes were observed for the same
    /// source-fact and representation identity.
    IntegrityCollision,
    /// EVID-06 / "Failure, convergence, and history": the delivery's
    /// signature did not verify, so its payload is not evidence.
    InvalidSignature,
    /// EVID-04 / "Failure, convergence, and history": the authenticated
    /// connector is not authorized for the server-bound tenant/project scope.
    UnauthorizedScope,
    /// Arrow transport boundary: the batch declared a schema name/version
    /// absent from the active registry.
    UnknownSchema,
    /// Arrow transport boundary: the batch exceeded its registered byte
    /// bound.
    Oversize,
    /// Arrow transport boundary: two rows in the same batch claimed the same
    /// event position.
    DuplicatePosition,
    /// Arrow transport boundary: a row's canonical statement bytes disagreed
    /// with the digest cited by its content reference on revalidation.
    PreimageDisagreement,
    /// EVID-05: redaction could not be confirmed complete before the durable
    /// outbox write, so the delivery never reached the outbox.
    RedactionFailure,
    /// "Canonical evidence event": the delivery named a schema/
    /// canonicalization/redaction representation version absent from the
    /// active registry snapshot.
    UnknownRepresentationVersion,
}

/// A bounded, non-payload explanation of one rejection.
///
/// `message` is a plain canonical string (NFC, control-scalar free, per the
/// frozen canonicalization profile) capped at [`MAX_DIAGNOSTIC_MESSAGE_BYTES`],
/// far below the ordinary canonical-string ceiling. `redaction_required`
/// records that this diagnostic itself still needs redaction review before
/// any future export; validation never clears it — only a separate,
/// out-of-scope redaction workflow may do that, and it would still never
/// rewrite this record (see the module documentation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundedDiagnosticV1 {
    pub message: String,
    pub redaction_required: bool,
}

impl BoundedDiagnosticV1 {
    pub fn validate(&self) -> ContractResult<()> {
        if self.message.is_empty() || self.message.len() > MAX_DIAGNOSTIC_MESSAGE_BYTES {
            return Err(ContractError::Schema(
                "quarantine diagnostic is empty or exceeds the bounded byte limit".into(),
            ));
        }
        Ok(())
    }
}

/// Deterministic identity of one exact quarantine record.
///
/// This is computed by [`QuarantineRecordV1::quarantine_id`], never stored as
/// a field on the record it identifies, so no field can silently diverge
/// from its own preimage the way a redundant stored digest could.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QuarantineRecordId(Sha256Digest);

impl QuarantineRecordId {
    pub const fn from_digest(digest: Sha256Digest) -> Self {
        Self(digest)
    }

    pub const fn digest(self) -> Sha256Digest {
        self.0
    }
}

impl Serialize for QuarantineRecordId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for QuarantineRecordId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Sha256Digest::deserialize(deserializer).map(Self)
    }
}

/// Bounded dead-letter record for one rejected delivery.
///
/// Every field is either server-derived (`scope`, via
/// [`AuthenticatedProjectScopeV1::from_trusted_context`], never a payload
/// claim), transport/connector metadata, a digest, a closed reason, or a
/// bounded diagnostic. There is no field that can hold raw payload bytes and
/// no field a rejected delivery's own payload could use to select its own
/// tenant, project, or disposition. `source_fact_id` and
/// `representation_key` are best-effort: many rejection reasons (an unknown
/// schema, an oversized batch, an unverified signature) fire before any
/// identity could be trusted, so both are `None` in those cases. When
/// present, they carry the exact digest bytes of the corresponding accepted-
/// evidence identity so that trusted resolution code can compare them by
/// value without this module depending on the evidence contracts' concrete
/// types or versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantineRecordV1 {
    pub schema_version: u32,
    pub scope: AuthenticatedProjectScopeV1,
    pub connector_principal_id: ContractId,
    pub connector_instance_id: ContractId,
    pub transport_delivery_id: HexBytes,
    pub attempt_count: u32,
    pub source_fact_id: Option<Sha256Digest>,
    pub representation_key: Option<Sha256Digest>,
    pub canonical_payload_digest: Sha256Digest,
    pub reason: QuarantineReasonV1,
    pub diagnostic: BoundedDiagnosticV1,
    pub received_at: CanonicalTimestamp,
}

impl QuarantineRecordV1 {
    /// Validate canonical public shape only. This does not authenticate the
    /// scope, connector, or delivery: trusted ingress code derives `scope`
    /// itself and is the only legitimate caller of a production constructor
    /// once one exists (see [`NotProjectable`]).
    pub fn validate(&self) -> ContractResult<()> {
        self.diagnostic.validate()?;
        if self.schema_version != QUARANTINE_SCHEMA_VERSION
            || self.attempt_count == 0
            || self.attempt_count > MAX_ATTEMPT_COUNT
            || self.canonical_payload_digest == Sha256Digest::ZERO
            || self.source_fact_id == Some(Sha256Digest::ZERO)
            || self.representation_key == Some(Sha256Digest::ZERO)
            || !self.received_at.is_microsecond_aligned()
            || self.transport_delivery_id.as_bytes().len() > MAX_TRANSPORT_DELIVERY_ID_BYTES
        {
            return Err(ContractError::Schema("invalid quarantine record".into()));
        }
        self.validate_reason_conditioned_identity()?;
        encode_canonical(self)?;
        Ok(())
    }

    /// Enforce the per-reason presence rule the module and README document:
    /// `integrity_collision` and `preimage_disagreement` are only defined
    /// relative to a source-fact *and* representation identity (EVENT-01),
    /// so both links must be derivable; `redaction_failure` means redaction
    /// could not be confirmed, so the diagnostic must say so. This match is
    /// exhaustive over the closed [`QuarantineReasonV1`] enum — adding a
    /// tenth reason without extending this match is a compile error, so the
    /// "exhaustively matched" claim in the module doc comment stays true.
    fn validate_reason_conditioned_identity(&self) -> ContractResult<()> {
        match self.reason {
            QuarantineReasonV1::IntegrityCollision | QuarantineReasonV1::PreimageDisagreement => {
                if self.source_fact_id.is_none() || self.representation_key.is_none() {
                    return Err(ContractError::Schema(
                        "integrity_collision and preimage_disagreement require both source_fact_id and representation_key".into(),
                    ));
                }
            }
            QuarantineReasonV1::RedactionFailure => {
                if !self.diagnostic.redaction_required {
                    return Err(ContractError::Schema(
                        "redaction_failure requires diagnostic.redaction_required".into(),
                    ));
                }
            }
            QuarantineReasonV1::InvalidSignature
            | QuarantineReasonV1::UnauthorizedScope
            | QuarantineReasonV1::UnknownSchema
            | QuarantineReasonV1::Oversize
            | QuarantineReasonV1::DuplicatePosition
            | QuarantineReasonV1::UnknownRepresentationVersion => {}
        }
        Ok(())
    }

    /// Deterministic identity of this exact rejection: every field
    /// participates, so two records differing only in diagnostic wording or
    /// attempt count are distinct dead-letter rows.
    pub fn quarantine_id(&self) -> ContractResult<QuarantineRecordId> {
        self.validate()?;
        Ok(QuarantineRecordId::from_digest(domain_separated_digest(
            DigestDomain::QuarantineRecordV1,
            &encode_canonical(self)?,
        )))
    }
}

/// Marker for types that structurally cannot supply accepted-event or
/// projection-admission input.
///
/// This is a documentation and API-shape guarantee, not a compiler-enforced
/// seal: Rust has no mechanism to forbid a future `impl From<QuarantineRecordV1>
/// for SomeAcceptedEventType` in another module, and this trait cannot close
/// that door by itself. What *is* true today, and checked by
/// `not_projectable_types_expose_no_conversion` below, is narrower and
/// concrete: neither [`QuarantineRecordV1`] nor [`QuarantinedDeliveryV1`]
/// implements `From`/`Into` for any type in this crate, neither exposes a
/// method returning an evidence or remember accepted-event type, and
/// [`QuarantinedDeliveryV1`]'s only field is private with no production
/// constructor at this contract-only stage. A reviewer adding a conversion
/// later must delete or contradict this trait's documentation to do it,
/// which is the intended friction.
pub trait NotProjectable {}

impl NotProjectable for QuarantineRecordV1 {}
impl NotProjectable for QuarantinedDeliveryV1 {}

/// The durable dead-letter form of one validated [`QuarantineRecordV1`].
///
/// No production constructor exists in this contract-only stage; only test
/// code may witness one, mirroring `remember_v2::AdmittedRememberStatementV2`.
/// A quarantined delivery is never mutated in place: resolution is a wholly
/// separate, unrelated accepted event under a corrected representation,
/// linked back only by `source_fact_id` when one was recorded. This type
/// therefore exposes no `&mut self` method and no setter of any kind — only
/// construction (test-only) and read access.
#[derive(Debug)]
pub struct QuarantinedDeliveryV1 {
    record: QuarantineRecordV1,
}

impl QuarantinedDeliveryV1 {
    pub const fn record(&self) -> &QuarantineRecordV1 {
        &self.record
    }

    pub fn quarantine_id(&self) -> ContractResult<QuarantineRecordId> {
        self.record.quarantine_id()
    }

    #[cfg(test)]
    fn from_test_witness(record: QuarantineRecordV1) -> ContractResult<Self> {
        record.validate()?;
        Ok(Self { record })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_contracts::canonical::decode_strict;

    const INTEGRITY_COLLISION_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/quarantine/quarantine-integrity-collision.jsonl"
    );
    const INVALID_SIGNATURE_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/quarantine/quarantine-invalid-signature.jsonl"
    );
    const UNAUTHORIZED_SCOPE_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/quarantine/quarantine-unauthorized-scope.jsonl"
    );
    const UNKNOWN_SCHEMA_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/quarantine/quarantine-unknown-schema.jsonl"
    );
    const OVERSIZE_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/quarantine/quarantine-oversize.jsonl");
    const DUPLICATE_POSITION_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/quarantine/quarantine-duplicate-position.jsonl"
    );
    const PREIMAGE_DISAGREEMENT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/quarantine/quarantine-preimage-disagreement.jsonl"
    );
    const REDACTION_FAILURE_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/quarantine/quarantine-redaction-failure.jsonl"
    );
    const UNKNOWN_REPRESENTATION_VERSION_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/quarantine/quarantine-unknown-representation-version.jsonl"
    );
    const NEGATIVE_RAW_PAYLOAD_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/quarantine/negative-raw-payload-field.jsonl"
    );
    const NEGATIVE_OVERSIZED_DIAGNOSTIC_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/quarantine/negative-oversized-diagnostic.jsonl"
    );
    const NEGATIVE_PAYLOAD_TENANT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/quarantine/negative-payload-selected-tenant-field.jsonl"
    );
    const NEGATIVE_MISSING_DELIVERY_ID_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/quarantine/negative-missing-delivery-id.jsonl"
    );
    const NEGATIVE_RELEASE_TO_PROJECTION_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v3/quarantine/negative-release-to-projection-field.jsonl"
    );

    const INTEGRITY_COLLISION_RAW_SHA256: &str =
        "c411c6a154083f6596b670943d503ffad8e15538614dfe41957a3d11c5c997ee";
    const INTEGRITY_COLLISION_ID: &str =
        "596a89d0158a062c87f4ed98fa1bd875c1d9d7deb8b33a1f4cd136977dcef83b";
    const INVALID_SIGNATURE_RAW_SHA256: &str =
        "4e57de9e6043dcd286e073617ecfaf35fb8f14891dc85e8440eb556e144380dd";
    const INVALID_SIGNATURE_ID: &str =
        "20bf032d415b58f2e8fc5439a21c0ffa8a705d6449cf9f9e54a330b47190699f";
    const UNAUTHORIZED_SCOPE_RAW_SHA256: &str =
        "95be635fdbce6f9eccb0f4e1de3fc5a9162f66c6bcd8099e62c2ba3d0e366d55";
    const UNAUTHORIZED_SCOPE_ID: &str =
        "7ce49698579dd3c6d7f83934f3b81dc6658bb417f1d977e8a8c9d3f34ea5bdc3";
    const UNKNOWN_SCHEMA_RAW_SHA256: &str =
        "fe08edb166f414bb0c76f1622326cfa908e7452237532d99fcc4abb909211ba3";
    const UNKNOWN_SCHEMA_ID: &str =
        "9f2a68aaf032fde60be6eb7cb54f04d2634fe46de873c2be506f9039aeeb1593";
    const OVERSIZE_RAW_SHA256: &str =
        "5a762f09b1f99ed9278df8b5c956cf897716615abdc7b6117055ebda9c4e5d2b";
    const OVERSIZE_ID: &str = "d9ce7dd66fc4e525034e9b2cb9596834a4c7eb47d8c4225ea5d3f205aba05e6b";
    const DUPLICATE_POSITION_RAW_SHA256: &str =
        "93e7e87d4a9a2077c5dbb588fa35f69508b3c45e09c32d9ab63dfb99cfca5513";
    const DUPLICATE_POSITION_ID: &str =
        "f00ef0090dbc703a60cb9df80aa6fce29e0ae8765e3f010400bffc27f68fd045";
    const PREIMAGE_DISAGREEMENT_RAW_SHA256: &str =
        "a2bcd590a46676a4ae9f4d41074f609bd6d5fb0e32e6a05cde48d664b211f1b0";
    const PREIMAGE_DISAGREEMENT_ID: &str =
        "ffe01c5a37d4445dcc3ea88a9b049172d1fd5ff1d2f34ba04598053678d8710e";
    const REDACTION_FAILURE_RAW_SHA256: &str =
        "a33e40ccea5eb4bad8581cdfc3eef3d2e8ec91480ffb8c8ff0b7bb52d251802e";
    const REDACTION_FAILURE_ID: &str =
        "512089675dc6fa91e7bc13b75033a193e6a67afc289ac5520548dc63d01b9a88";
    const UNKNOWN_REPRESENTATION_VERSION_RAW_SHA256: &str =
        "564197a05ec35e747b0b9aac0b6e763caa91e97d323e8b3019b1556ef93cd79b";
    const UNKNOWN_REPRESENTATION_VERSION_ID: &str =
        "58bd1b257fcfec9ccf245e24bfcced39f0d9366393180ba937b303cecaa2431d";

    const NEGATIVE_RAW_PAYLOAD_RAW_SHA256: &str =
        "9dab9a7dc0c058db6fe6609cb04f40e43cd06af3d915341c1f25cd75ca38bff4";
    const NEGATIVE_OVERSIZED_DIAGNOSTIC_RAW_SHA256: &str =
        "d74aa2f604d4f5d7ea9e5390fccb3ce7d0197d99061663badaa6c2cc1c71ad88";
    const NEGATIVE_PAYLOAD_TENANT_RAW_SHA256: &str =
        "19a81915b788d691ab01cf339b3ac8311429b9c6cf2dd1707530b1d158a7b090";
    const NEGATIVE_MISSING_DELIVERY_ID_RAW_SHA256: &str =
        "1b69007e9dadef694b0e5b012266104d37e12a97d2bf834acf721a42539436d6";
    const NEGATIVE_RELEASE_TO_PROJECTION_RAW_SHA256: &str =
        "7ab927ba7a9c8a75411e9220352691d0c8ce53ed748ca0523d860b032efe41a4";

    const VECTOR_SUITE_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v3/quarantine/vector-suite.jsonl");
    const VECTOR_SUITE_RAW_SHA256: &str =
        "70d648fdae83d88bda66709d1b9ae8687241b319a766cb21edc3cab90d943f1a";

    fn raw_sha256(bytes: &[u8]) -> String {
        use sha2::{Digest as _, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hex::encode(hasher.finalize())
    }

    fn assert_positive_fixture(
        fixture: &[u8],
        expected_raw_sha256: &str,
        expected_reason: QuarantineReasonV1,
        expected_id: &str,
    ) {
        assert_eq!(
            raw_sha256(fixture),
            expected_raw_sha256,
            "raw fixture bytes drifted"
        );
        let record: QuarantineRecordV1 = decode_strict(fixture).expect("valid quarantine record");
        record.validate().expect("fixture must validate");
        assert_eq!(record.reason, expected_reason);
        let id = record.quarantine_id().expect("id computable");
        assert_eq!(id.digest().to_string(), expected_id);
        // Determinism: recomputation yields the exact same identity.
        assert_eq!(record.quarantine_id().unwrap(), id);
    }

    #[test]
    fn positive_integrity_collision_vector() {
        assert_positive_fixture(
            INTEGRITY_COLLISION_FIXTURE,
            INTEGRITY_COLLISION_RAW_SHA256,
            QuarantineReasonV1::IntegrityCollision,
            INTEGRITY_COLLISION_ID,
        );
    }

    #[test]
    fn positive_invalid_signature_vector() {
        assert_positive_fixture(
            INVALID_SIGNATURE_FIXTURE,
            INVALID_SIGNATURE_RAW_SHA256,
            QuarantineReasonV1::InvalidSignature,
            INVALID_SIGNATURE_ID,
        );
    }

    #[test]
    fn positive_unauthorized_scope_vector() {
        assert_positive_fixture(
            UNAUTHORIZED_SCOPE_FIXTURE,
            UNAUTHORIZED_SCOPE_RAW_SHA256,
            QuarantineReasonV1::UnauthorizedScope,
            UNAUTHORIZED_SCOPE_ID,
        );
    }

    #[test]
    fn positive_unknown_schema_vector() {
        assert_positive_fixture(
            UNKNOWN_SCHEMA_FIXTURE,
            UNKNOWN_SCHEMA_RAW_SHA256,
            QuarantineReasonV1::UnknownSchema,
            UNKNOWN_SCHEMA_ID,
        );
    }

    #[test]
    fn positive_oversize_vector() {
        assert_positive_fixture(
            OVERSIZE_FIXTURE,
            OVERSIZE_RAW_SHA256,
            QuarantineReasonV1::Oversize,
            OVERSIZE_ID,
        );
    }

    #[test]
    fn positive_duplicate_position_vector() {
        assert_positive_fixture(
            DUPLICATE_POSITION_FIXTURE,
            DUPLICATE_POSITION_RAW_SHA256,
            QuarantineReasonV1::DuplicatePosition,
            DUPLICATE_POSITION_ID,
        );
    }

    #[test]
    fn positive_preimage_disagreement_vector() {
        assert_positive_fixture(
            PREIMAGE_DISAGREEMENT_FIXTURE,
            PREIMAGE_DISAGREEMENT_RAW_SHA256,
            QuarantineReasonV1::PreimageDisagreement,
            PREIMAGE_DISAGREEMENT_ID,
        );
    }

    #[test]
    fn positive_redaction_failure_vector() {
        assert_positive_fixture(
            REDACTION_FAILURE_FIXTURE,
            REDACTION_FAILURE_RAW_SHA256,
            QuarantineReasonV1::RedactionFailure,
            REDACTION_FAILURE_ID,
        );
    }

    #[test]
    fn positive_unknown_representation_version_vector() {
        assert_positive_fixture(
            UNKNOWN_REPRESENTATION_VERSION_FIXTURE,
            UNKNOWN_REPRESENTATION_VERSION_RAW_SHA256,
            QuarantineReasonV1::UnknownRepresentationVersion,
            UNKNOWN_REPRESENTATION_VERSION_ID,
        );
    }

    #[test]
    fn all_nine_reasons_have_distinct_identities() {
        let fixtures = [
            INTEGRITY_COLLISION_FIXTURE,
            INVALID_SIGNATURE_FIXTURE,
            UNAUTHORIZED_SCOPE_FIXTURE,
            UNKNOWN_SCHEMA_FIXTURE,
            OVERSIZE_FIXTURE,
            DUPLICATE_POSITION_FIXTURE,
            PREIMAGE_DISAGREEMENT_FIXTURE,
            REDACTION_FAILURE_FIXTURE,
            UNKNOWN_REPRESENTATION_VERSION_FIXTURE,
        ];
        let mut ids = Vec::with_capacity(fixtures.len());
        for fixture in fixtures {
            let record: QuarantineRecordV1 = decode_strict(fixture).unwrap();
            ids.push(record.quarantine_id().unwrap());
        }
        for (index, left) in ids.iter().enumerate() {
            for right in &ids[index + 1..] {
                assert_ne!(left, right, "two distinct rejections collided");
            }
        }
    }

    #[test]
    fn negative_raw_payload_field_is_rejected_as_unknown_key() {
        assert_eq!(
            raw_sha256(NEGATIVE_RAW_PAYLOAD_FIXTURE),
            NEGATIVE_RAW_PAYLOAD_RAW_SHA256
        );
        let result: ContractResult<QuarantineRecordV1> =
            decode_strict(NEGATIVE_RAW_PAYLOAD_FIXTURE);
        assert!(result.is_err(), "a raw-payload field must not decode");
    }

    #[test]
    fn negative_oversized_diagnostic_decodes_but_fails_validation() {
        assert_eq!(
            raw_sha256(NEGATIVE_OVERSIZED_DIAGNOSTIC_FIXTURE),
            NEGATIVE_OVERSIZED_DIAGNOSTIC_RAW_SHA256
        );
        let record: QuarantineRecordV1 =
            decode_strict(NEGATIVE_OVERSIZED_DIAGNOSTIC_FIXTURE).expect("shape decodes");
        assert!(
            record.validate().is_err(),
            "a diagnostic over the byte bound must fail validation"
        );
    }

    #[test]
    fn negative_payload_selected_tenant_field_is_rejected_as_unknown_key() {
        assert_eq!(
            raw_sha256(NEGATIVE_PAYLOAD_TENANT_FIXTURE),
            NEGATIVE_PAYLOAD_TENANT_RAW_SHA256
        );
        let result: ContractResult<QuarantineRecordV1> =
            decode_strict(NEGATIVE_PAYLOAD_TENANT_FIXTURE);
        assert!(
            result.is_err(),
            "a second payload-declared scope field must not decode"
        );
    }

    #[test]
    fn negative_missing_delivery_id_does_not_decode() {
        assert_eq!(
            raw_sha256(NEGATIVE_MISSING_DELIVERY_ID_FIXTURE),
            NEGATIVE_MISSING_DELIVERY_ID_RAW_SHA256
        );
        let result: ContractResult<QuarantineRecordV1> =
            decode_strict(NEGATIVE_MISSING_DELIVERY_ID_FIXTURE);
        assert!(result.is_err(), "a missing delivery ID must not decode");
    }

    #[test]
    fn negative_release_to_projection_field_is_rejected_as_unknown_key() {
        assert_eq!(
            raw_sha256(NEGATIVE_RELEASE_TO_PROJECTION_FIXTURE),
            NEGATIVE_RELEASE_TO_PROJECTION_RAW_SHA256
        );
        let result: ContractResult<QuarantineRecordV1> =
            decode_strict(NEGATIVE_RELEASE_TO_PROJECTION_FIXTURE);
        assert!(
            result.is_err(),
            "a release-to-projection affordance must not decode"
        );
    }

    #[test]
    fn quarantined_record_does_not_contain_the_payloads_canonical_bytes() {
        use crate::memory_contracts::digest::body_digest;

        let raw_payload = b"the entire secret request body that must never be recalled".to_vec();
        let payload_digest = body_digest(&raw_payload);

        let record = QuarantineRecordV1 {
            schema_version: QUARANTINE_SCHEMA_VERSION,
            scope: AuthenticatedProjectScopeV1::from_trusted_context(
                ContractId::new("tenant.leakage").unwrap(),
                ContractId::new("project.leakage").unwrap(),
            ),
            connector_principal_id: ContractId::new("connector.leakage-check").unwrap(),
            connector_instance_id: ContractId::new("connector-instance.leakage").unwrap(),
            transport_delivery_id: HexBytes::new(vec![0xab; 16]).unwrap(),
            attempt_count: 1,
            source_fact_id: None,
            representation_key: None,
            canonical_payload_digest: payload_digest,
            reason: QuarantineReasonV1::RedactionFailure,
            diagnostic: BoundedDiagnosticV1 {
                message: "redaction could not be confirmed before the outbox write".into(),
                redaction_required: true,
            },
            received_at: CanonicalTimestamp::parse("2026-08-15T09:30:00.000000000Z").unwrap(),
        };
        record.validate().unwrap();

        let canonical_record_bytes = encode_canonical(&record).unwrap();

        // The record never contains the raw payload as a byte substring...
        assert!(
            !contains_subslice(&canonical_record_bytes, &raw_payload),
            "the canonicalized record must not contain the payload's raw bytes"
        );
        // ...nor as its hex-encoded wire projection: every byte-bearing field
        // on this record (HexBytes, Sha256Digest) is rendered as lowercase
        // hex in canonical JSON, so a substring check restricted to raw
        // bytes alone would miss payload bytes smuggled in through a field
        // that hex-encodes on the wire (exactly how a naive raw-byte-only
        // check missed the original transport_delivery_id leak).
        let raw_payload_hex = hex::encode(&raw_payload);
        assert!(
            !contains_subslice(&canonical_record_bytes, raw_payload_hex.as_bytes()),
            "the canonicalized record must not contain the payload's hex-encoded bytes either"
        );
        // ...nor the payload's own canonical/content digest bytes rendered as
        // hex, beyond the one digest field the record is defined to carry.
        let payload_digest_hex = payload_digest.to_hex();
        let occurrences = canonical_record_bytes
            .windows(payload_digest_hex.len())
            .filter(|window| *window == payload_digest_hex.as_bytes())
            .count();
        assert_eq!(
            occurrences, 1,
            "the payload digest must appear exactly once, in canonical_payload_digest"
        );
        assert_ne!(canonical_record_bytes, raw_payload);

        // No field other than canonical_payload_digest can carry more than
        // MAX_TRANSPORT_DELIVERY_ID_BYTES of payload-derived bytes: an
        // attempt to smuggle a large slice of the payload through the one
        // other byte-bearing field on this record must fail closed at
        // validate(), before it could ever reach a canonicalized, searchable
        // dead-letter row.
        let mut smuggling_attempt = record;
        let mut smuggled = raw_payload;
        smuggled.resize(MAX_TRANSPORT_DELIVERY_ID_BYTES + 1, 0);
        smuggling_attempt.transport_delivery_id = HexBytes::new(smuggled).unwrap();
        assert!(
            smuggling_attempt.validate().is_err(),
            "a delivery ID built from payload bytes beyond the bound must fail closed"
        );
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        needle.is_empty()
            || haystack
                .windows(needle.len())
                .any(|window| window == needle)
    }

    #[test]
    fn diagnostic_rejects_empty_and_oversized_messages() {
        assert!(
            BoundedDiagnosticV1 {
                message: String::new(),
                redaction_required: false,
            }
            .validate()
            .is_err()
        );
        assert!(
            BoundedDiagnosticV1 {
                message: "x".repeat(MAX_DIAGNOSTIC_MESSAGE_BYTES + 1),
                redaction_required: false,
            }
            .validate()
            .is_err()
        );
        assert!(
            BoundedDiagnosticV1 {
                message: "x".repeat(MAX_DIAGNOSTIC_MESSAGE_BYTES),
                redaction_required: false,
            }
            .validate()
            .is_ok()
        );
    }

    #[test]
    fn zero_digests_are_rejected() {
        let mut record = sample_record();
        record.canonical_payload_digest = Sha256Digest::ZERO;
        assert!(record.validate().is_err());

        let mut record = sample_record();
        record.source_fact_id = Some(Sha256Digest::ZERO);
        assert!(record.validate().is_err());

        let mut record = sample_record();
        record.representation_key = Some(Sha256Digest::ZERO);
        assert!(record.validate().is_err());
    }

    #[test]
    fn attempt_count_bounds_are_enforced() {
        let mut record = sample_record();
        record.attempt_count = 0;
        assert!(record.validate().is_err());

        let mut record = sample_record();
        record.attempt_count = MAX_ATTEMPT_COUNT + 1;
        assert!(record.validate().is_err());

        let mut record = sample_record();
        record.attempt_count = MAX_ATTEMPT_COUNT;
        assert!(record.validate().is_ok());
    }

    #[test]
    fn received_at_must_be_microsecond_aligned() {
        // Two records identical except for sub-microsecond precision on
        // `received_at` must not be admitted: an unaligned nanosecond value
        // cannot round-trip through CockroachDB's microsecond `TIMESTAMPTZ`
        // without changing bytes, which would make `quarantine_id()`
        // unreproducible from the durably stored row (EVENT-01).
        let mut record = sample_record();
        record.received_at = CanonicalTimestamp::parse("2026-08-15T09:31:00.123456789Z").unwrap();
        assert!(
            record.validate().is_err(),
            "a nanosecond-precision received_at must fail closed"
        );

        let mut record = sample_record();
        record.received_at = CanonicalTimestamp::parse("2026-08-15T09:31:00.123456000Z").unwrap();
        assert!(
            record.validate().is_ok(),
            "a microsecond-aligned received_at must be admitted"
        );
    }

    #[test]
    fn transport_delivery_id_is_bounded() {
        // The generic HexBytes newtype alone would admit up to 4,096 bytes
        // here; validate() imposes its own, much tighter, delivery-ID-shaped
        // bound so a rejected delivery's transport-supplied ID cannot become
        // a vector for smuggling arbitrary payload bytes into a searchable
        // dead-letter record (EVID-05).
        let mut record = sample_record();
        record.transport_delivery_id =
            HexBytes::new(vec![0xcd; MAX_TRANSPORT_DELIVERY_ID_BYTES]).unwrap();
        assert!(
            record.validate().is_ok(),
            "a delivery ID at the bound must be admitted"
        );

        let mut record = sample_record();
        record.transport_delivery_id =
            HexBytes::new(vec![0xcd; MAX_TRANSPORT_DELIVERY_ID_BYTES + 1]).unwrap();
        assert!(
            record.validate().is_err(),
            "a delivery ID one byte over the bound must fail closed"
        );

        let mut record = sample_record();
        record.transport_delivery_id = HexBytes::new(vec![0xcd; 4_096]).unwrap();
        assert!(
            record.validate().is_err(),
            "a maximal HexBytes payload must still fail closed under the tighter bound"
        );
    }

    #[test]
    fn reason_conditioned_identity_requirements_are_enforced() {
        // integrity_collision and preimage_disagreement are only defined
        // relative to a source-fact AND representation identity (EVENT-01);
        // a record with either link missing must fail closed.
        for reason in [
            QuarantineReasonV1::IntegrityCollision,
            QuarantineReasonV1::PreimageDisagreement,
        ] {
            let mut record = sample_record();
            record.reason = reason;
            record.source_fact_id = None;
            record.representation_key = Some(Sha256Digest::from_bytes([0x33; 32]));
            assert!(
                record.validate().is_err(),
                "{reason:?} with no source_fact_id must fail closed"
            );

            let mut record = sample_record();
            record.reason = reason;
            record.source_fact_id = Some(Sha256Digest::from_bytes([0x33; 32]));
            record.representation_key = None;
            assert!(
                record.validate().is_err(),
                "{reason:?} with no representation_key must fail closed"
            );

            let mut record = sample_record();
            record.reason = reason;
            record.source_fact_id = Some(Sha256Digest::from_bytes([0x33; 32]));
            record.representation_key = Some(Sha256Digest::from_bytes([0x44; 32]));
            assert!(
                record.validate().is_ok(),
                "{reason:?} with both identity links present must be admitted"
            );
        }

        // redaction_failure means redaction could not be confirmed; a
        // diagnostic that clears redaction_required contradicts the reason
        // it is attached to and must fail closed.
        let mut record = sample_record();
        record.reason = QuarantineReasonV1::RedactionFailure;
        record.diagnostic.redaction_required = false;
        assert!(
            record.validate().is_err(),
            "redaction_failure with redaction_required=false must fail closed"
        );

        let mut record = sample_record();
        record.reason = QuarantineReasonV1::RedactionFailure;
        record.diagnostic.redaction_required = true;
        assert!(
            record.validate().is_ok(),
            "redaction_failure with redaction_required=true must be admitted"
        );
    }

    #[test]
    fn admitted_dead_letter_wraps_a_validated_record_and_exposes_no_mutation() {
        let record = sample_record();
        let expected_id = record.quarantine_id().unwrap();
        let admitted = QuarantinedDeliveryV1::from_test_witness(record).unwrap();
        assert_eq!(admitted.quarantine_id().unwrap(), expected_id);
        assert_eq!(
            admitted.record().reason,
            QuarantineReasonV1::InvalidSignature
        );
    }

    /// A minimal, structural check for the [`NotProjectable`] contract: both
    /// types implement the marker, so this compiles. The stronger, honestly
    /// scoped claim (no `From`/`Into`, no accepted-event-shaped accessor) is
    /// documented on the trait itself and enforced by review, not by the
    /// compiler — see that doc comment for exactly what is and is not proven.
    #[test]
    fn not_projectable_types_expose_no_conversion() {
        const fn assert_not_projectable<T: NotProjectable>() {}
        assert_not_projectable::<QuarantineRecordV1>();
        assert_not_projectable::<QuarantinedDeliveryV1>();
    }

    fn sample_record() -> QuarantineRecordV1 {
        QuarantineRecordV1 {
            schema_version: QUARANTINE_SCHEMA_VERSION,
            scope: AuthenticatedProjectScopeV1::from_trusted_context(
                ContractId::new("tenant.sample").unwrap(),
                ContractId::new("project.sample").unwrap(),
            ),
            connector_principal_id: ContractId::new("connector.sample").unwrap(),
            connector_instance_id: ContractId::new("connector-instance.sample").unwrap(),
            transport_delivery_id: HexBytes::new(vec![0x11; 8]).unwrap(),
            attempt_count: 1,
            source_fact_id: None,
            representation_key: None,
            canonical_payload_digest: Sha256Digest::from_bytes([0x22; 32]),
            reason: QuarantineReasonV1::InvalidSignature,
            diagnostic: BoundedDiagnosticV1 {
                message: "signature verification failed".into(),
                redaction_required: true,
            },
            received_at: CanonicalTimestamp::parse("2026-08-15T09:31:00.000000000Z").unwrap(),
        }
    }

    #[test]
    fn vector_suite_fixture_is_pinned() {
        assert_eq!(raw_sha256(VECTOR_SUITE_FIXTURE), VECTOR_SUITE_RAW_SHA256);
    }
}
