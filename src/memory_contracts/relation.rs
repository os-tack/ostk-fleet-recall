//! Canonical directional relation edges, immutable attestations, and replay projection.
//!
//! The public wire values in this module establish shape and semantic identity only.
//! In particular, deserializing a registry head, principal ID, verifier reference, or
//! `verifier_result` basis does not prove that it was active, authenticated, or
//! successfully executed. Runtime admission must establish those facts from durable
//! trusted witnesses before append.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{
    ContractError, ContractResult,
    bootstrap::ConsistencyPartitionKeyV1,
    canonical::encode_canonical,
    common::{
        AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, ProfileReferenceV1,
        RegistryReferenceV1,
    },
    digest::{DigestDomain, Sha256Digest, domain_separated_digest},
    evidence::AcceptedEventId,
    evidence_v2::RegistryHeadBindingV1,
    identity::ResourceUri,
};

const RELATION_SCHEMA_VERSION: u32 = 1;
const RELATION_ATTESTATION_EVENT_KIND: &str = "relation.attestation.accepted";
const RELATION_CONSISTENCY_FAMILY: &str = "relation";
const MAX_APPLICABILITY_DIMENSIONS: usize = 64;
const MAX_EVIDENCE_EVENT_IDS: usize = 256;

/// Stable semantic identity of one exact directional edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelationFingerprint(Sha256Digest);

impl RelationFingerprint {
    pub const fn from_digest(digest: Sha256Digest) -> Self {
        Self(digest)
    }

    pub const fn digest(self) -> Sha256Digest {
        self.0
    }
}

impl fmt::Display for RelationFingerprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Serialize for RelationFingerprint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RelationFingerprint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Sha256Digest::deserialize(deserializer).map(Self)
    }
}

/// One concrete, exact applicability coordinate.
///
/// A resource URI is required deliberately: `null`, an omitted scalar, a mutable
/// display name, and an implicit `any` cannot masquerade as a concrete context.
/// The active relation-proof entry decides which dimension IDs are required.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConcreteApplicabilityDimensionV1 {
    pub dimension_id: ContractId,
    pub resource: ResourceUri,
}

/// Exact, directional relation identity.
///
/// `source -> target` is ordered. The exact registry activation (including its
/// ABA-safe activation ID), relation-proof entry, and concrete applicability set
/// are part of the fingerprint. Evidence, attestors, effective time, receipt time,
/// and all append coordinates are deliberately absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationEdgeV1 {
    pub schema_version: u32,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub registry: RegistryHeadBindingV1,
    pub relation_proof: RegistryReferenceV1,
    pub source: ResourceUri,
    pub target: ResourceUri,
    pub applicability: Vec<ConcreteApplicabilityDimensionV1>,
}

impl RelationEdgeV1 {
    /// Validate closed wire shape only; this does not prove active-registry authority.
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.profile.validate()?;
        self.registry.validate_shape()?;
        self.relation_proof.validate()?;
        if self.schema_version != RELATION_SCHEMA_VERSION
            || self.applicability.len() > MAX_APPLICABILITY_DIMENSIONS
            || !strictly_sorted_by_dimension(&self.applicability)
        {
            return Err(ContractError::Schema("invalid relation edge".into()));
        }
        Ok(())
    }

    /// Derive identity from edge semantics alone.
    pub fn fingerprint(&self) -> ContractResult<RelationFingerprint> {
        self.validate_shape()?;
        Ok(RelationFingerprint::from_digest(domain_separated_digest(
            DigestDomain::RelationFingerprint,
            &encode_canonical(self)?,
        )))
    }

    /// Stable logical serialization key for all attestations of this edge.
    ///
    /// Epoch, shard count, seed, selected shard, and append position remain a
    /// separate physical mapping and therefore cannot affect event identity.
    pub fn consistency_partition_key(&self) -> ContractResult<ConsistencyPartitionKeyV1> {
        Ok(ConsistencyPartitionKeyV1 {
            family: ContractId::new(RELATION_CONSISTENCY_FAMILY)?,
            key_digest: self.fingerprint()?.digest(),
        })
    }
}

/// Semantic source of an attestation. This field is descriptive until trusted
/// admission binds it to an authenticated principal or admitted verifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RelationAttestorIdentityV1 {
    AuthenticatedActor {
        principal_id: ContractId,
    },
    RegisteredVerifier {
        principal_id: ContractId,
        verifier: RegistryReferenceV1,
    },
}

impl RelationAttestorIdentityV1 {
    fn validate_shape(&self) -> ContractResult<()> {
        if let Self::RegisteredVerifier { verifier, .. } = self {
            verifier.validate()?;
        }
        Ok(())
    }
}

/// Closed attestation basis taxonomy. None of these variants is itself a grant
/// of verification authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationAttestationBasisV1 {
    Declared,
    Inferred,
    ProviderAttested,
    VerifierResult,
}

/// Whether this attestation supports or refutes the exact edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationAttestationVerdictV1 {
    Supports,
    Refutes,
}

/// Immutable semantic relation-attestation event.
///
/// The event contains no `state`, `verified`, receipt timestamp, storage identity,
/// epoch, shard, offset, or append-chain field. `supersedes_attestation_id` retires
/// exactly one prior attestation for the same fingerprint; it never suppresses
/// independent evidence or erases history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelationAttestationEventV1 {
    pub schema_version: u32,
    pub event_kind: ContractId,
    pub profile: ProfileReferenceV1,
    pub scope: AuthenticatedProjectScopeV1,
    pub edge: RelationEdgeV1,
    pub relation_fingerprint: RelationFingerprint,
    pub basis: RelationAttestationBasisV1,
    pub verdict: RelationAttestationVerdictV1,
    pub evidence_event_ids: Vec<AcceptedEventId>,
    pub effective_at: CanonicalTimestamp,
    pub attestor: RelationAttestorIdentityV1,
    pub supersedes_attestation_id: Option<AcceptedEventId>,
}

impl RelationAttestationEventV1 {
    /// Validate canonical semantic bindings only. Active registry, scope, actor,
    /// evidence existence, and proof execution remain runtime admission checks.
    pub fn validate_shape(&self) -> ContractResult<()> {
        self.profile.validate()?;
        self.edge.validate_shape()?;
        self.attestor.validate_shape()?;
        let basis_matches_attestor = matches!(
            (&self.basis, &self.attestor),
            (
                RelationAttestationBasisV1::Declared | RelationAttestationBasisV1::ProviderAttested,
                RelationAttestorIdentityV1::AuthenticatedActor { .. }
            ) | (
                RelationAttestationBasisV1::Inferred | RelationAttestationBasisV1::VerifierResult,
                RelationAttestorIdentityV1::RegisteredVerifier { .. }
            )
        );
        if self.schema_version != RELATION_SCHEMA_VERSION
            || self.event_kind.as_str() != RELATION_ATTESTATION_EVENT_KIND
            || self.profile != self.edge.profile
            || self.scope != self.edge.scope
            || self.relation_fingerprint != self.edge.fingerprint()?
            || self.evidence_event_ids.is_empty()
            || self.evidence_event_ids.len() > MAX_EVIDENCE_EVENT_IDS
            || !strictly_sorted(&self.evidence_event_ids)
            || !basis_matches_attestor
        {
            return Err(ContractError::Schema(
                "invalid relation attestation event".into(),
            ));
        }
        Ok(())
    }

    /// Derive the semantic accepted-event identity. Physical append and receipt
    /// metadata cannot affect this value because those fields are absent.
    pub fn accepted_event_id(&self) -> ContractResult<AcceptedEventId> {
        self.validate_shape()?;
        Ok(AcceptedEventId::from_digest(domain_separated_digest(
            DigestDomain::AcceptedEvent,
            &encode_canonical(self)?,
        )))
    }
}

/// Opaque authority capability.
///
/// It is produced only after trusted runtime admission has matched scope and
/// active head, resolved the relation-proof closure, verified every evidence
/// event, and successfully executed the registered proof.
///
/// This contract-only seam intentionally exposes no production constructor. A
/// later repository seam must construct it from those durable witnesses; callers
/// cannot deserialize, fabricate fields, or promote a public candidate.
#[derive(Debug)]
pub struct VerifiedRelationBasis {
    event: RelationAttestationEventV1,
}

impl VerifiedRelationBasis {
    pub const fn event(&self) -> &RelationAttestationEventV1 {
        &self.event
    }

    #[cfg(test)]
    fn from_test_witness(event: RelationAttestationEventV1) -> ContractResult<Self> {
        event.validate_shape()?;
        if !matches!(
            event.basis,
            RelationAttestationBasisV1::ProviderAttested
                | RelationAttestationBasisV1::VerifierResult
        ) {
            return Err(ContractError::Schema(
                "declared or inferred relation cannot become a verified basis".into(),
            ));
        }
        Ok(Self { event })
    }
}

/// Opaque admission capability for a declared or inferred attestation.
///
/// Runtime construction must bind trusted scope and actor, exact active registry
/// head and proof closure, referenced evidence, and any exact-predecessor
/// supersession authorization. Public wire bytes cannot construct this type.
#[derive(Debug)]
pub struct AdmittedRelationAttestation {
    event: RelationAttestationEventV1,
}

impl AdmittedRelationAttestation {
    pub const fn event(&self) -> &RelationAttestationEventV1 {
        &self.event
    }

    #[cfg(test)]
    fn from_test_witness(event: RelationAttestationEventV1) -> ContractResult<Self> {
        event.validate_shape()?;
        if !matches!(
            event.basis,
            RelationAttestationBasisV1::Declared | RelationAttestationBasisV1::Inferred
        ) {
            return Err(ContractError::Schema(
                "provider or verifier relation requires a verified basis".into(),
            ));
        }
        Ok(Self { event })
    }
}

/// An opaque projector input. Public event bytes cannot enter either path;
/// possession of the corresponding admission capability is mandatory.
#[derive(Debug, Clone, Copy)]
pub struct RelationProjectionInput<'a> {
    event: &'a RelationAttestationEventV1,
    verified: bool,
}

impl<'a> RelationProjectionInput<'a> {
    pub const fn admitted(attestation: &'a AdmittedRelationAttestation) -> Self {
        Self {
            event: attestation.event(),
            verified: false,
        }
    }

    pub const fn verified(basis: &'a VerifiedRelationBasis) -> Self {
        Self {
            event: basis.event(),
            verified: true,
        }
    }
}

/// Rebuildable state of the exact relation fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RelationProjectionStateV1 {
    Declared,
    Verified,
    Refuted,
    Contested,
}

/// Server-derived projection. It is serializable for deterministic comparison,
/// but deliberately not deserializable as authority-bearing input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RelationProjectionV1 {
    pub relation_fingerprint: RelationFingerprint,
    pub state: RelationProjectionStateV1,
    pub active_attestation_ids: Vec<AcceptedEventId>,
    pub superseded_attestation_ids: Vec<AcceptedEventId>,
    pub active_unverified_attestation_ids: Vec<AcceptedEventId>,
    pub active_verified_support_ids: Vec<AcceptedEventId>,
    pub active_verified_refute_ids: Vec<AcceptedEventId>,
}

/// Deterministically replay one exact edge from a closed input set.
///
/// Input order and exact retries cannot affect the result. Supersession removes
/// only its exact predecessor from the active set. A missing predecessor fails
/// closed because a partial history cannot establish lifecycle state. Opposing
/// active verified results are `contested`; receipt order never breaks the tie.
pub fn project_relation(
    relation_fingerprint: RelationFingerprint,
    inputs: &[RelationProjectionInput<'_>],
) -> ContractResult<RelationProjectionV1> {
    let mut records: BTreeMap<AcceptedEventId, (&RelationAttestationEventV1, bool)> =
        BTreeMap::new();

    for input in inputs {
        input.event.validate_shape()?;
        if input.event.relation_fingerprint != relation_fingerprint {
            return Err(ContractError::Schema(
                "relation projection mixed fingerprints".into(),
            ));
        }
        let eligible = matches!(
            (input.verified, input.event.basis),
            (
                true,
                RelationAttestationBasisV1::ProviderAttested
                    | RelationAttestationBasisV1::VerifierResult
            ) | (
                false,
                RelationAttestationBasisV1::Declared | RelationAttestationBasisV1::Inferred
            )
        );
        if !eligible {
            return Err(ContractError::Schema(
                "relation basis reached an ineligible projection path".into(),
            ));
        }
        let event_id = input.event.accepted_event_id()?;
        match records.get_mut(&event_id) {
            Some((existing, verified)) if *existing == input.event => {
                *verified |= input.verified;
            }
            Some(_) => {
                return Err(ContractError::Schema(
                    "accepted relation event ID collision".into(),
                ));
            }
            None => {
                records.insert(event_id, (input.event, input.verified));
            }
        }
    }

    if records.is_empty() {
        return Err(ContractError::Schema(
            "relation projection requires admitted history".into(),
        ));
    }

    let superseded = collect_superseded(&records)?;

    let mut active_attestation_ids = Vec::new();
    let mut active_unverified_attestation_ids = Vec::new();
    let mut active_verified_support_ids = Vec::new();
    let mut active_verified_refute_ids = Vec::new();
    for (event_id, (event, verified)) in &records {
        if superseded.contains(event_id) {
            continue;
        }
        active_attestation_ids.push(*event_id);
        if *verified {
            match event.verdict {
                RelationAttestationVerdictV1::Supports => {
                    active_verified_support_ids.push(*event_id);
                }
                RelationAttestationVerdictV1::Refutes => {
                    active_verified_refute_ids.push(*event_id);
                }
            }
        } else {
            active_unverified_attestation_ids.push(*event_id);
        }
    }

    let state = match (
        active_verified_support_ids.is_empty(),
        active_verified_refute_ids.is_empty(),
    ) {
        (false, false) => RelationProjectionStateV1::Contested,
        (false, true) => RelationProjectionStateV1::Verified,
        (true, false) => RelationProjectionStateV1::Refuted,
        (true, true) => RelationProjectionStateV1::Declared,
    };

    Ok(RelationProjectionV1 {
        relation_fingerprint,
        state,
        active_attestation_ids,
        superseded_attestation_ids: superseded.into_iter().collect(),
        active_unverified_attestation_ids,
        active_verified_support_ids,
        active_verified_refute_ids,
    })
}

fn collect_superseded(
    records: &BTreeMap<AcceptedEventId, (&RelationAttestationEventV1, bool)>,
) -> ContractResult<BTreeSet<AcceptedEventId>> {
    let mut superseded = BTreeSet::new();
    for (event_id, (event, _)) in records {
        if let Some(predecessor_id) = event.supersedes_attestation_id {
            let Some((predecessor, predecessor_verified)) = records.get(&predecessor_id) else {
                return Err(ContractError::Schema(
                    "invalid or missing same-edge supersession predecessor".into(),
                ));
            };
            let successor_verified = records[event_id].1;
            if predecessor_id == *event_id
                || predecessor.attestor != event.attestor
                || predecessor.basis != event.basis
                || *predecessor_verified != successor_verified
            {
                return Err(ContractError::Schema(
                    "unauthorized or cross-authority relation supersession".into(),
                ));
            }
            superseded.insert(predecessor_id);
        }
    }

    reject_supersession_cycles(records)?;
    Ok(superseded)
}

/// A finite one-predecessor graph must terminate. Detect a forged cycle
/// explicitly rather than letting it deactivate every node.
fn reject_supersession_cycles(
    records: &BTreeMap<AcceptedEventId, (&RelationAttestationEventV1, bool)>,
) -> ContractResult<()> {
    let mut completed = BTreeSet::new();
    for start in records.keys().copied() {
        if completed.contains(&start) {
            continue;
        }
        let mut path = Vec::new();
        let mut path_set = BTreeSet::new();
        let mut cursor = start;
        loop {
            if completed.contains(&cursor) {
                break;
            }
            if !path_set.insert(cursor) {
                return Err(ContractError::Schema(
                    "cyclic relation attestation supersession".into(),
                ));
            }
            path.push(cursor);
            match records[&cursor].0.supersedes_attestation_id {
                Some(predecessor) => cursor = predecessor,
                None => break,
            }
        }
        completed.extend(path);
    }
    Ok(())
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn strictly_sorted_by_dimension(values: &[ConcreteApplicabilityDimensionV1]) -> bool {
    values
        .windows(2)
        .all(|pair| pair[0].dimension_id < pair[1].dimension_id)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::memory_contracts::{
        canonical::{decode_strict, encode_canonical, require_canonical},
        common::frozen_profile_reference_v1,
        registry::RegistryHeadV1,
    };

    const EDGE_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v2/relation/relation-edge.jsonl");
    const DECLARED_EVENT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/relation/declared-attestation-event.jsonl"
    );
    const VERIFIED_EVENT_FIXTURE: &[u8] = include_bytes!(
        "../../contracts/dynamic-memory/v2/relation/verifier-support-attestation-event.jsonl"
    );
    const VECTOR_SUITE_FIXTURE: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v2/relation/vector-suite.jsonl");

    const RELATION_FINGERPRINT: &str =
        "cf9c6b0a6e2b36523a69ad376a9f8ae77e73be53e2e42f7d240e7da67f38c2b2";
    const DECLARED_EVENT_ID: &str =
        "fa9782a4254a4f704e9f7f7966c08a81e847065a66811d412d95c3a85aae1f14";
    const VERIFIED_SUPPORT_EVENT_ID: &str =
        "75d1127fb64287fbd999e88442fbb76d54caaedab461787110b207472ae9d287";
    const VECTOR_SUITE_DIGEST: &str =
        "533685efc9b239269a922b549b6edd501437e1d94e525106f392301bc19a9ed2";

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct RelationVectorSuiteV1 {
        schema_version: u32,
        fixture_authority: String,
        relation_edge_path: String,
        relation_fingerprint: RelationFingerprint,
        declared_event_path: String,
        declared_event_id: AcceptedEventId,
        consistency_key_digest: Sha256Digest,
        consistency_key_family: ContractId,
        verified_support_event_path: String,
        verified_support_event_id: AcceptedEventId,
        negative_cases: Vec<String>,
    }

    fn record(artifact: &'static [u8]) -> &'static [u8] {
        let body = artifact
            .strip_suffix(b"\n")
            .expect("contract artifact must have one repository-framing LF");
        assert!(!body.ends_with(b"\n"));
        assert!(!body.contains(&b'\r'));
        body
    }

    fn digest(value: &str) -> Sha256Digest {
        Sha256Digest::from_str(value).unwrap()
    }

    fn scope() -> AuthenticatedProjectScopeV1 {
        AuthenticatedProjectScopeV1::from_trusted_context(
            ContractId::new("tenant.fixture").unwrap(),
            ContractId::new("project.fixture").unwrap(),
        )
    }

    fn registry_binding() -> RegistryHeadBindingV1 {
        RegistryHeadBindingV1 {
            head: RegistryHeadV1 {
                activation_id: digest(
                    "5a7263f5c98e75b94e82341d2a7729e9578d4691691b5a8401e1c37a83931261",
                ),
                package_digest: digest(
                    "5a931fd5551bec47f83adb019f3e794d1b6a759f4501e7ea26a83076d9518177",
                ),
                activation_policy_digest: digest(
                    "6f92f99ff35969845f08f9b64cee7d86fa42dc6165ebc617d950be8960b86968",
                ),
            },
            effective_from: CanonicalTimestamp::parse("2026-08-15T04:00:00.000000000Z").unwrap(),
            effective_until: None,
        }
    }

    fn reference(id: &str, digest_value: &str) -> RegistryReferenceV1 {
        RegistryReferenceV1 {
            entry_id: ContractId::new(id).unwrap(),
            version: 1,
            entry_digest: digest(digest_value),
        }
    }

    fn resource(kind: &str, digit: char) -> ResourceUri {
        format!(
            "urn:ostk:version:v1:{kind}:sha256:{}",
            digit.to_string().repeat(64)
        )
        .parse()
        .unwrap()
    }

    fn edge() -> RelationEdgeV1 {
        RelationEdgeV1 {
            schema_version: 1,
            profile: frozen_profile_reference_v1(),
            scope: scope(),
            registry: registry_binding(),
            relation_proof: reference(
                "relation.repository_parent",
                "d0b7d4e7b630ce599389e50948541e21b4aa24d4d030860f6cfcaf7508d49df4",
            ),
            source: resource("repository", '1'),
            target: resource("repository", '2'),
            applicability: vec![
                ConcreteApplicabilityDimensionV1 {
                    dimension_id: ContractId::new("repository_commit").unwrap(),
                    resource: resource("commit", '3'),
                },
                ConcreteApplicabilityDimensionV1 {
                    dimension_id: ContractId::new("runtime_environment").unwrap(),
                    resource: resource("environment", '4'),
                },
            ],
        }
    }

    fn evidence_id(digit: char) -> AcceptedEventId {
        AcceptedEventId::from_digest(digest(&digit.to_string().repeat(64)))
    }

    fn event(
        basis: RelationAttestationBasisV1,
        verdict: RelationAttestationVerdictV1,
        evidence_digit: char,
        supersedes: Option<AcceptedEventId>,
    ) -> RelationAttestationEventV1 {
        let edge = edge();
        let attestor = match basis {
            RelationAttestationBasisV1::Declared | RelationAttestationBasisV1::ProviderAttested => {
                RelationAttestorIdentityV1::AuthenticatedActor {
                    principal_id: ContractId::new("principal.connector").unwrap(),
                }
            }
            RelationAttestationBasisV1::Inferred | RelationAttestationBasisV1::VerifierResult => {
                RelationAttestorIdentityV1::RegisteredVerifier {
                    principal_id: ContractId::new("principal.projector").unwrap(),
                    verifier: reference(
                        "observer.rust_enum",
                        "36660875b3d71595ccb4b5dfbc17c4c0fe546eec0fa4b8da6a63b17fec074586",
                    ),
                }
            }
        };
        RelationAttestationEventV1 {
            schema_version: 1,
            event_kind: ContractId::new(RELATION_ATTESTATION_EVENT_KIND).unwrap(),
            profile: frozen_profile_reference_v1(),
            scope: scope(),
            relation_fingerprint: edge.fingerprint().unwrap(),
            edge,
            basis,
            verdict,
            evidence_event_ids: vec![evidence_id(evidence_digit)],
            effective_at: CanonicalTimestamp::parse("2026-08-15T04:05:00.000000000Z").unwrap(),
            attestor,
            supersedes_attestation_id: supersedes,
        }
    }

    #[test]
    fn hard_coded_edge_and_events_match_canonical_vectors() {
        for bytes in [
            EDGE_FIXTURE,
            DECLARED_EVENT_FIXTURE,
            VERIFIED_EVENT_FIXTURE,
            VECTOR_SUITE_FIXTURE,
        ] {
            require_canonical(record(bytes)).unwrap();
        }

        let expected_edge = edge();
        assert_eq!(
            encode_canonical(&expected_edge).unwrap(),
            record(EDGE_FIXTURE)
        );
        let decoded_edge: RelationEdgeV1 = decode_strict(record(EDGE_FIXTURE)).unwrap();
        decoded_edge.validate_shape().unwrap();
        assert_eq!(decoded_edge, expected_edge);

        let declared = event(
            RelationAttestationBasisV1::Declared,
            RelationAttestationVerdictV1::Supports,
            '5',
            None,
        );
        assert_eq!(
            encode_canonical(&declared).unwrap(),
            record(DECLARED_EVENT_FIXTURE)
        );
        let verified = event(
            RelationAttestationBasisV1::VerifierResult,
            RelationAttestationVerdictV1::Supports,
            '6',
            None,
        );
        assert_eq!(
            encode_canonical(&verified).unwrap(),
            record(VERIFIED_EVENT_FIXTURE)
        );

        let suite: RelationVectorSuiteV1 = decode_strict(record(VECTOR_SUITE_FIXTURE)).unwrap();
        assert_eq!(suite.schema_version, 1);
        assert_eq!(
            domain_separated_digest(
                DigestDomain::TestVectorManifest,
                record(VECTOR_SUITE_FIXTURE)
            ),
            digest(VECTOR_SUITE_DIGEST)
        );
        assert_eq!(
            expected_edge.fingerprint().unwrap().digest(),
            digest(RELATION_FINGERPRINT)
        );
        assert_eq!(
            suite.relation_fingerprint,
            RelationFingerprint::from_digest(digest(RELATION_FINGERPRINT))
        );
        assert_eq!(
            declared.accepted_event_id().unwrap().digest(),
            digest(DECLARED_EVENT_ID)
        );
        assert_eq!(suite.declared_event_id.digest(), digest(DECLARED_EVENT_ID));
        assert_eq!(
            verified.accepted_event_id().unwrap().digest(),
            digest(VERIFIED_SUPPORT_EVENT_ID)
        );
        assert_eq!(
            suite.verified_support_event_id.digest(),
            digest(VERIFIED_SUPPORT_EVENT_ID)
        );
        assert_eq!(
            suite.consistency_key_family.as_str(),
            RELATION_CONSISTENCY_FAMILY
        );
        assert_eq!(suite.consistency_key_digest, digest(RELATION_FINGERPRINT));
        assert!(suite.fixture_authority.starts_with("none;"));
        assert!(strictly_sorted(&suite.negative_cases));
    }

    #[test]
    fn fingerprint_is_directional_and_excludes_attestation_data() {
        let first = edge();
        let fingerprint = first.fingerprint().unwrap();
        let consistency_key = first.consistency_partition_key().unwrap();
        assert_eq!(consistency_key.family.as_str(), RELATION_CONSISTENCY_FAMILY);
        assert_eq!(consistency_key.key_digest, fingerprint.digest());
        let mut reversed = first.clone();
        std::mem::swap(&mut reversed.source, &mut reversed.target);
        assert_ne!(fingerprint, reversed.fingerprint().unwrap());

        let declared = event(
            RelationAttestationBasisV1::Declared,
            RelationAttestationVerdictV1::Supports,
            '5',
            None,
        );
        let mut later = declared.clone();
        later.effective_at = CanonicalTimestamp::parse("2026-08-15T05:00:00.000000000Z").unwrap();
        later.evidence_event_ids = vec![evidence_id('7')];
        assert_eq!(declared.relation_fingerprint, later.relation_fingerprint);
        assert_ne!(
            declared.accepted_event_id().unwrap(),
            later.accepted_event_id().unwrap()
        );

        let mut other_activation = first;
        other_activation.registry.head.activation_id =
            digest("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_ne!(fingerprint, other_activation.fingerprint().unwrap());
    }

    #[test]
    fn physical_append_and_receipt_fields_are_absent_and_rejected() {
        let attestation = event(
            RelationAttestationBasisV1::Declared,
            RelationAttestationVerdictV1::Supports,
            '5',
            None,
        );
        let canonical = encode_canonical(&attestation).unwrap();
        let text = std::str::from_utf8(&canonical).unwrap();
        for forbidden in [
            "\"accepted_at\"",
            "\"append_position\"",
            "\"epoch_id\"",
            "\"shard\"",
            "\"committed_offset\"",
            "\"previous_chain_digest\"",
            "\"append_chain_digest\"",
            "\"consistency_partition_key\"",
        ] {
            assert!(!text.contains(forbidden), "forbidden field {forbidden}");
        }

        let mut value: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
        value.as_object_mut().unwrap().insert(
            "accepted_at".into(),
            serde_json::Value::String("2026-08-15T04:06:00.000000000Z".into()),
        );
        assert!(
            decode_strict::<RelationAttestationEventV1>(&serde_json::to_vec(&value).unwrap())
                .is_err()
        );
    }

    #[test]
    fn applicability_and_evidence_sets_are_strict() {
        let mut duplicate_dimension = edge();
        duplicate_dimension.applicability[1].dimension_id =
            duplicate_dimension.applicability[0].dimension_id.clone();
        assert!(duplicate_dimension.validate_shape().is_err());

        let mut reversed_dimensions = edge();
        reversed_dimensions.applicability.reverse();
        assert!(reversed_dimensions.validate_shape().is_err());

        let mut empty_evidence = event(
            RelationAttestationBasisV1::Declared,
            RelationAttestationVerdictV1::Supports,
            '5',
            None,
        );
        empty_evidence.evidence_event_ids.clear();
        assert!(empty_evidence.validate_shape().is_err());

        let mut duplicate_evidence = event(
            RelationAttestationBasisV1::Declared,
            RelationAttestationVerdictV1::Supports,
            '5',
            None,
        );
        duplicate_evidence.evidence_event_ids.push(evidence_id('5'));
        assert!(duplicate_evidence.validate_shape().is_err());

        let mut reversed_evidence = duplicate_evidence;
        reversed_evidence.evidence_event_ids = vec![evidence_id('6'), evidence_id('5')];
        assert!(reversed_evidence.validate_shape().is_err());
    }

    #[test]
    fn payload_fields_cannot_select_verified_projection() {
        let asserted_verifier_result = event(
            RelationAttestationBasisV1::VerifierResult,
            RelationAttestationVerdictV1::Supports,
            '6',
            None,
        );
        let fingerprint = asserted_verifier_result.relation_fingerprint;
        assert!(
            AdmittedRelationAttestation::from_test_witness(asserted_verifier_result.clone())
                .is_err()
        );

        let declared = event(
            RelationAttestationBasisV1::Declared,
            RelationAttestationVerdictV1::Supports,
            '5',
            None,
        );
        assert!(VerifiedRelationBasis::from_test_witness(declared).is_err());

        let verified = VerifiedRelationBasis::from_test_witness(asserted_verifier_result).unwrap();
        let admitted = [RelationProjectionInput::verified(&verified)];
        assert_eq!(
            project_relation(fingerprint, &admitted).unwrap().state,
            RelationProjectionStateV1::Verified
        );
    }

    #[test]
    fn verified_opposition_is_contested_and_order_independent() {
        let support_event = event(
            RelationAttestationBasisV1::VerifierResult,
            RelationAttestationVerdictV1::Supports,
            '6',
            None,
        );
        let refute_event = event(
            RelationAttestationBasisV1::VerifierResult,
            RelationAttestationVerdictV1::Refutes,
            '7',
            None,
        );
        let fingerprint = support_event.relation_fingerprint;
        let support = VerifiedRelationBasis::from_test_witness(support_event).unwrap();
        let refute = VerifiedRelationBasis::from_test_witness(refute_event).unwrap();
        let forward = [
            RelationProjectionInput::verified(&support),
            RelationProjectionInput::verified(&refute),
        ];
        let reverse = [
            RelationProjectionInput::verified(&refute),
            RelationProjectionInput::verified(&support),
        ];
        let forward = project_relation(fingerprint, &forward).unwrap();
        let reverse = project_relation(fingerprint, &reverse).unwrap();
        assert_eq!(forward, reverse);
        assert_eq!(forward.state, RelationProjectionStateV1::Contested);
    }

    #[test]
    fn supersession_is_exact_and_preserves_independent_evidence() {
        let old_declaration = event(
            RelationAttestationBasisV1::VerifierResult,
            RelationAttestationVerdictV1::Supports,
            '5',
            None,
        );
        let old_id = old_declaration.accepted_event_id().unwrap();
        let mut independent_refute_event = event(
            RelationAttestationBasisV1::VerifierResult,
            RelationAttestationVerdictV1::Refutes,
            '7',
            None,
        );
        if let RelationAttestorIdentityV1::RegisteredVerifier { principal_id, .. } =
            &mut independent_refute_event.attestor
        {
            *principal_id = ContractId::new("principal.independent_projector").unwrap();
        }
        let independent_id = independent_refute_event.accepted_event_id().unwrap();
        let replacement_event = event(
            RelationAttestationBasisV1::VerifierResult,
            RelationAttestationVerdictV1::Supports,
            '8',
            Some(old_id),
        );
        let replacement_id = replacement_event.accepted_event_id().unwrap();
        let fingerprint = old_declaration.relation_fingerprint;
        let old_declaration = VerifiedRelationBasis::from_test_witness(old_declaration).unwrap();
        let independent =
            VerifiedRelationBasis::from_test_witness(independent_refute_event).unwrap();
        let replacement = VerifiedRelationBasis::from_test_witness(replacement_event).unwrap();
        let inputs = [
            RelationProjectionInput::verified(&old_declaration),
            RelationProjectionInput::verified(&independent),
            RelationProjectionInput::verified(&replacement),
        ];
        let projection = project_relation(fingerprint, &inputs).unwrap();
        assert_eq!(projection.state, RelationProjectionStateV1::Contested);
        assert_eq!(projection.superseded_attestation_ids, vec![old_id]);
        assert!(projection.active_attestation_ids.contains(&independent_id));
        assert!(projection.active_attestation_ids.contains(&replacement_id));
        assert!(!projection.active_attestation_ids.contains(&old_id));

        let missing_predecessor = event(
            RelationAttestationBasisV1::Declared,
            RelationAttestationVerdictV1::Supports,
            '9',
            Some(evidence_id('a')),
        );
        let missing_predecessor =
            AdmittedRelationAttestation::from_test_witness(missing_predecessor).unwrap();
        assert!(
            project_relation(
                fingerprint,
                &[RelationProjectionInput::admitted(&missing_predecessor)]
            )
            .is_err()
        );
    }

    #[test]
    fn supersession_cannot_downgrade_authority_and_forks_remain_visible() {
        let verified_old_event = event(
            RelationAttestationBasisV1::ProviderAttested,
            RelationAttestationVerdictV1::Supports,
            '6',
            None,
        );
        let old_id = verified_old_event.accepted_event_id().unwrap();
        let forged_replacement_event = event(
            RelationAttestationBasisV1::Declared,
            RelationAttestationVerdictV1::Refutes,
            '7',
            Some(old_id),
        );
        let fingerprint = verified_old_event.relation_fingerprint;
        let verified_old = VerifiedRelationBasis::from_test_witness(verified_old_event).unwrap();
        let forged_replacement =
            AdmittedRelationAttestation::from_test_witness(forged_replacement_event).unwrap();
        assert!(
            project_relation(
                fingerprint,
                &[
                    RelationProjectionInput::verified(&verified_old),
                    RelationProjectionInput::admitted(&forged_replacement),
                ]
            )
            .is_err()
        );

        let fork_root_event = event(
            RelationAttestationBasisV1::VerifierResult,
            RelationAttestationVerdictV1::Supports,
            '8',
            None,
        );
        let fork_root_id = fork_root_event.accepted_event_id().unwrap();
        let fork_support_event = event(
            RelationAttestationBasisV1::VerifierResult,
            RelationAttestationVerdictV1::Supports,
            '9',
            Some(fork_root_id),
        );
        let fork_refute_event = event(
            RelationAttestationBasisV1::VerifierResult,
            RelationAttestationVerdictV1::Refutes,
            'a',
            Some(fork_root_id),
        );
        let fork_support_id = fork_support_event.accepted_event_id().unwrap();
        let fork_refute_id = fork_refute_event.accepted_event_id().unwrap();
        let fork_root = VerifiedRelationBasis::from_test_witness(fork_root_event).unwrap();
        let fork_support = VerifiedRelationBasis::from_test_witness(fork_support_event).unwrap();
        let fork_refute = VerifiedRelationBasis::from_test_witness(fork_refute_event).unwrap();
        let projection = project_relation(
            fingerprint,
            &[
                RelationProjectionInput::verified(&fork_root),
                RelationProjectionInput::verified(&fork_support),
                RelationProjectionInput::verified(&fork_refute),
            ],
        )
        .unwrap();
        assert_eq!(projection.state, RelationProjectionStateV1::Contested);
        assert_eq!(projection.superseded_attestation_ids, vec![fork_root_id]);
        assert!(projection.active_attestation_ids.contains(&fork_support_id));
        assert!(projection.active_attestation_ids.contains(&fork_refute_id));
    }

    #[test]
    fn forged_supersession_cycle_fails_closed() {
        let first_id = evidence_id('a');
        let second_id = evidence_id('b');
        let first = event(
            RelationAttestationBasisV1::Declared,
            RelationAttestationVerdictV1::Supports,
            '5',
            Some(second_id),
        );
        let second = event(
            RelationAttestationBasisV1::Declared,
            RelationAttestationVerdictV1::Refutes,
            '6',
            Some(first_id),
        );
        let records = BTreeMap::from([(first_id, (&first, false)), (second_id, (&second, false))]);
        assert!(reject_supersession_cycles(&records).is_err());
    }

    #[test]
    fn malformed_bindings_and_unknown_fields_fail_closed() {
        let mut wrong_fingerprint = event(
            RelationAttestationBasisV1::Declared,
            RelationAttestationVerdictV1::Supports,
            '5',
            None,
        );
        wrong_fingerprint.relation_fingerprint = RelationFingerprint::from_digest(digest(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ));
        assert!(wrong_fingerprint.validate_shape().is_err());

        let mut wrong_scope = event(
            RelationAttestationBasisV1::Declared,
            RelationAttestationVerdictV1::Supports,
            '5',
            None,
        );
        wrong_scope.scope.project_namespace = ContractId::new("project.other").unwrap();
        assert!(wrong_scope.validate_shape().is_err());

        let mut wrong_attestor = event(
            RelationAttestationBasisV1::Declared,
            RelationAttestationVerdictV1::Supports,
            '5',
            None,
        );
        wrong_attestor.attestor = RelationAttestorIdentityV1::RegisteredVerifier {
            principal_id: ContractId::new("principal.projector").unwrap(),
            verifier: reference(
                "observer.rust_enum",
                "36660875b3d71595ccb4b5dfbc17c4c0fe546eec0fa4b8da6a63b17fec074586",
            ),
        };
        assert!(wrong_attestor.validate_shape().is_err());

        let canonical = record(EDGE_FIXTURE);
        let mut value: serde_json::Value = serde_json::from_slice(canonical).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("verified".into(), serde_json::Value::Bool(true));
        assert!(decode_strict::<RelationEdgeV1>(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn exact_replay_has_one_effect_and_empty_projection_fails_closed() {
        let declaration = event(
            RelationAttestationBasisV1::Declared,
            RelationAttestationVerdictV1::Supports,
            '5',
            None,
        );
        let fingerprint = declaration.relation_fingerprint;
        let declaration = AdmittedRelationAttestation::from_test_witness(declaration).unwrap();
        let replayed = [
            RelationProjectionInput::admitted(&declaration),
            RelationProjectionInput::admitted(&declaration),
        ];
        let projection = project_relation(fingerprint, &replayed).unwrap();
        assert_eq!(projection.state, RelationProjectionStateV1::Declared);
        assert_eq!(projection.active_attestation_ids.len(), 1);

        assert!(project_relation(fingerprint, &[]).is_err());
    }
}
