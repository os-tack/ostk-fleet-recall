use std::str::FromStr;

use sha2::{Digest as _, Sha256};

use super::*;
use crate::memory_contracts::{
    canonical::{decode_strict, decode_typed_canonical, require_canonical},
    common::frozen_profile_reference_v1,
};

const ERASURE_EVENT_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/erasure/erasure-event-representation.jsonl");
const ERASURE_EVENT_PRIVACY_SUBJECT_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/erasure/erasure-event-privacy-subject.jsonl");
const TOMBSTONE_DIGEST_ONLY_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/erasure/erasure-tombstone-digest-only.jsonl");
const TOMBSTONE_WITH_METADATA_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/erasure/erasure-tombstone-with-metadata.jsonl"
);
const FENCE_GENESIS_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/erasure/erasure-fence-genesis.jsonl");
const FENCE_ADVANCED_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/erasure/erasure-fence-advanced.jsonl");
const FENCE_GENERATION_ONLY_ADVANCE_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/erasure/erasure-fence-generation-only-advance.jsonl"
);
const FENCE_PRIVACY_SUBJECT_ONLY_ADVANCE_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/erasure/erasure-fence-privacy-subject-only-advance.jsonl"
);
const FENCE_REPRESENTATION_ONLY_ADVANCE_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/erasure/erasure-fence-representation-only-advance.jsonl"
);
const RECEIPT_PENDING_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/erasure/erasure-receipt-pending.jsonl");
const RECEIPT_COMPLETE_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/erasure/erasure-receipt-complete.jsonl");
const LEGAL_HOLD_ACTIVE_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/erasure/legal-hold-active.jsonl");
const RETAINABLE_MATCHER_FORBIDDEN_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/erasure/retainable-matcher-forbidden.jsonl");
const RESTORE_GATE_QUARANTINED_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/erasure/restore-gate-quarantined.jsonl");
const DEPENDENT_TRANSITION_UNVERIFIABLE_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/erasure/dependent-support-transition-unverifiable.jsonl"
);
const CHECKPOINT_RULE_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/erasure/checkpoint-erasure-rule.jsonl");
const VECTOR_SUITE_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/erasure/vector-suite.jsonl");

const NEGATIVE_TOMBSTONE_PAYLOAD_BYTES_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/erasure/negative-tombstone-payload-bytes.jsonl"
);
const NEGATIVE_RECEIPT_COMPLETE_WITH_RESIDUAL_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/erasure/negative-receipt-complete-with-residual.jsonl"
);
const NEGATIVE_RECEIPT_COMPLETE_RESIDUAL_DESPITE_KEY_DESTROYED_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/erasure/negative-receipt-complete-residual-despite-key-destroyed.jsonl"
);
const NEGATIVE_FENCE_MISSING_SCOPE_FIXTURE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v3/erasure/negative-fence-missing-scope.jsonl");
const NEGATIVE_EVENT_EFFECTIVE_BEFORE_POLICY_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/erasure/negative-event-effective-before-policy-basis.jsonl"
);
const NEGATIVE_LEGAL_HOLD_PUBLICATION_VISIBILITY_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/erasure/negative-legal-hold-publication-visibility.jsonl"
);
const NEGATIVE_CHECKPOINT_SAME_DIGEST_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/erasure/negative-checkpoint-same-digest.jsonl"
);
const NEGATIVE_DEPENDENT_TRANSITION_CONTRADICTION_FIXTURE: &[u8] = include_bytes!(
    "../../contracts/dynamic-memory/v3/erasure/negative-dependent-transition-contradiction.jsonl"
);

const EVENT_RAW_SHA256: &str = "aaf2b43c93722e29a7597e8314b53bb9e70d62aed83498aba42f92546455e94f";
const EVENT_PRIVACY_SUBJECT_RAW_SHA256: &str =
    "fc5450cd58e3ecd598edbbc2068e0c30cd0a777d9b52b015150028e06158cf2b";
const TOMBSTONE_DIGEST_ONLY_RAW_SHA256: &str =
    "06d1fd3080df8b6b31ff65f0c28db932e6e5c8c05f2f6c4c0db98afdc4c25697";
const TOMBSTONE_WITH_METADATA_RAW_SHA256: &str =
    "43cf525bfd163f7daa58713fc7a3687e164dffcf6f2338d627cf050538de022e";
const FENCE_GENESIS_RAW_SHA256: &str =
    "c304c6dc2737fcd1e06ddc6b98575411e5bab964252584e74738de5f728de0b8";
const FENCE_ADVANCED_RAW_SHA256: &str =
    "2a14a5116838ba3f2c36940386426b3ea76892e3eaf6a0145e4cc2dfa7c5e935";
const FENCE_GENERATION_ONLY_ADVANCE_RAW_SHA256: &str =
    "41b1de5e55ba11e49728d8596111cd6894c1940aaff459c9804ace98cb7c3108";
const FENCE_PRIVACY_SUBJECT_ONLY_ADVANCE_RAW_SHA256: &str =
    "c08ebbb1eaf85cbd221ba173b19f92178d94637eb5269704be0357c60771bdaf";
const FENCE_REPRESENTATION_ONLY_ADVANCE_RAW_SHA256: &str =
    "e2408179f10ebf7b01bd3d3ed2f824e0c9d6f362a38fa56762cbe03e6132cde5";
const RECEIPT_PENDING_RAW_SHA256: &str =
    "c555bc876c40b80d59a4097897d733cab27c93fb6e358a8ad3751e1931e08e34";
const RECEIPT_COMPLETE_RAW_SHA256: &str =
    "aa42cb2037f281597b961efe23b0eb8f2a2e00e83b8d81f7c41940ed41e704ff";
const LEGAL_HOLD_ACTIVE_RAW_SHA256: &str =
    "586821cd43f81e07dc83d0aee1d49d0086c3fb4d9fddcc520cbac0c49ea82aee";
const RETAINABLE_MATCHER_FORBIDDEN_RAW_SHA256: &str =
    "ee23b0640acd9ee6f58bab284692486a96e2e4b46933bcbc803770eb15a867bd";
const RESTORE_GATE_QUARANTINED_RAW_SHA256: &str =
    "39f95767f885d1ba9203d6c0042db3a502d8db9769f21a551c62f081e5cc3ec5";
const DEPENDENT_TRANSITION_UNVERIFIABLE_RAW_SHA256: &str =
    "dd59e4c40c99112408ec84c2b53666fddc4ee631841d652eb336a2b27810e355";
const CHECKPOINT_RULE_RAW_SHA256: &str =
    "209a78376cba81b37a84bf6e964bb1020689c58bf81df0b708b2fc866820b9a4";
const VECTOR_SUITE_RAW_SHA256: &str =
    "f4655abf09783f04a4291c08805dfdb5ecbe1ca96b99ee2bcf24820e47631673";

const NEGATIVE_TOMBSTONE_PAYLOAD_BYTES_RAW_SHA256: &str =
    "73bc971338b53b4d9a4c2a367fa360afaba779c43590dc5010a0dc48a0f23dc1";
const NEGATIVE_RECEIPT_COMPLETE_WITH_RESIDUAL_RAW_SHA256: &str =
    "606949c8ba313c2292ab566670887c04fb9371126d2e02cb9b7d51d725262518";
const NEGATIVE_RECEIPT_COMPLETE_RESIDUAL_DESPITE_KEY_DESTROYED_RAW_SHA256: &str =
    "63a770367f7cb6ca769e4b5d1c5e459f3a0cc4253de2f476c85dd5685bbc49f7";
const NEGATIVE_FENCE_MISSING_SCOPE_RAW_SHA256: &str =
    "e756d74843605c550000bbc70681ca660e7ff692c6f7610af1ccaa08c2ca91ab";
const NEGATIVE_EVENT_EFFECTIVE_BEFORE_POLICY_RAW_SHA256: &str =
    "ee34d4a521822ab59fa0373a86eaca1bd98947944f618b9bc57ff55befec2710";
const NEGATIVE_LEGAL_HOLD_PUBLICATION_VISIBILITY_RAW_SHA256: &str =
    "233dfcd14b4d95749e38760cd347879a86399e9670d537b427e1bf64c7ffa850";
const NEGATIVE_CHECKPOINT_SAME_DIGEST_RAW_SHA256: &str =
    "47c38e6210f278ce19e04620f5aa697965cfbc34550dfa34319c1f47db84e830";
const NEGATIVE_DEPENDENT_TRANSITION_CONTRADICTION_RAW_SHA256: &str =
    "1bb57031518350db795ec0857e16e935c946ee811c9cbdf06a781f25c250fbea";

const EVENT_ACCEPTED_EVENT_ID: &str =
    "3c3b6bd2d6f9ad4a1e66a74cf51ca3380e747dd7bd332aa2bb6169294c61e6af";
const EVENT_PRIVACY_SUBJECT_ACCEPTED_EVENT_ID: &str =
    "1c27e30e7bad9e8a2d049adf89a4b1468a244b933d334cad7b1e355e9556320c";

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ErasureVectorSuiteV1 {
    schema_version: u32,
    fixture_authority: String,
    erasure_event_id: AcceptedEventId,
    erasure_event_privacy_subject_id: AcceptedEventId,
    negative_cases: Vec<ContractId>,
}

impl ErasureVectorSuiteV1 {
    fn validate(&self) -> ContractResult<()> {
        if self.schema_version != ERASURE_SCHEMA_VERSION
            || self.negative_cases.is_empty()
            || !strictly_sorted(&self.negative_cases)
        {
            return Err(ContractError::Schema("invalid erasure vector suite".into()));
        }
        encode_canonical(self)?;
        Ok(())
    }
}

fn vector_suite() -> ErasureVectorSuiteV1 {
    ErasureVectorSuiteV1 {
        schema_version: 1,
        fixture_authority: "none; structural fixtures are assertions, not active-policy \
                             or repository-acceptance witnesses"
            .to_owned(),
        erasure_event_id: event_representation().accepted_event_id().unwrap(),
        erasure_event_privacy_subject_id: event_privacy_subject().accepted_event_id().unwrap(),
        negative_cases: vec![
            ContractId::new("checkpoint_same_digest").unwrap(),
            ContractId::new("dependent_transition_contradiction").unwrap(),
            ContractId::new("event_effective_before_policy_basis").unwrap(),
            ContractId::new("fence_missing_scope").unwrap(),
            ContractId::new("legal_hold_publication_visibility").unwrap(),
            ContractId::new("receipt_complete_residual_despite_key_destroyed").unwrap(),
            ContractId::new("receipt_complete_with_residual").unwrap(),
            ContractId::new("tombstone_payload_bytes").unwrap(),
        ],
    }
}

fn record(bytes: &[u8]) -> &[u8] {
    let body = bytes
        .strip_suffix(b"\n")
        .expect("contract artifact must have exactly one framing LF");
    assert!(!body.ends_with(b"\n"));
    assert!(!body.contains(&b'\r'));
    body
}

fn raw_sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
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

fn labelled_digest(label: &str) -> Sha256Digest {
    domain_separated_digest(DigestDomain::RegistryEntry, label.as_bytes())
}

fn policy_basis() -> RegistryReferenceV1 {
    RegistryReferenceV1 {
        entry_id: ContractId::new("policy.retention.privacy_erasure").unwrap(),
        version: 1,
        entry_digest: labelled_digest("policy.retention.privacy_erasure"),
    }
}

fn target_representation() -> ErasureScope {
    ErasureScope {
        kind: ErasureScopeKind::Representation,
        target_digest: labelled_digest("representation.fixture.one"),
    }
}

fn target_privacy_subject() -> ErasureScope {
    ErasureScope {
        kind: ErasureScopeKind::PrivacySubject,
        target_digest: labelled_digest("privacy_subject.fixture.one"),
    }
}

fn event_representation() -> ErasureEventV1 {
    ErasureEventV1 {
        schema_version: 1,
        event_kind: ContractId::new(ERASURE_ACCEPTED_EVENT_KIND).unwrap(),
        profile: frozen_profile_reference_v1(),
        scope: scope(),
        target: target_representation(),
        effective: EffectiveIntervalV1 {
            effective_from: CanonicalTimestamp::parse("2026-08-16T00:00:00.000000000Z").unwrap(),
            effective_until: None,
        },
        policy_basis: policy_basis(),
        policy_basis_effective_from: CanonicalTimestamp::parse("2026-01-01T00:00:00.000000000Z")
            .unwrap(),
        re_consent: ProspectiveReConsentV1::NotAuthorized {},
        requested_at: CanonicalTimestamp::parse("2026-08-16T00:00:00.000000000Z").unwrap(),
    }
}

fn event_privacy_subject() -> ErasureEventV1 {
    ErasureEventV1 {
        target: target_privacy_subject(),
        re_consent: ProspectiveReConsentV1::AuthorizedForNewSourceFact {
            consent_policy: policy_basis(),
        },
        ..event_representation()
    }
}

fn tombstone_digest_only() -> ErasureTombstoneV1 {
    ErasureTombstoneV1 {
        schema_version: 1,
        deny_mode: TombstoneDenyModeV1::RetrievalDeny,
        target: target_representation(),
        erasure_event_id: event_representation().accepted_event_id().unwrap(),
        policy_basis: policy_basis(),
        lifecycle: TombstoneLifecycleV1::DigestOnly {},
    }
}

fn tombstone_with_metadata() -> ErasureTombstoneV1 {
    ErasureTombstoneV1 {
        lifecycle: TombstoneLifecycleV1::DigestAndMetadata {
            installed_at: CanonicalTimestamp::parse("2026-08-16T00:00:01.000000000Z").unwrap(),
            superseded_by: None,
        },
        ..tombstone_digest_only()
    }
}

fn generation(value: u64) -> ErasureGenerationV1 {
    ErasureGenerationV1 {
        scope: scope(),
        value,
    }
}

fn fence(entries: Vec<ErasureFenceEntryV1>, generation_value: u64) -> ErasureFenceV1 {
    ErasureFenceV1 {
        schema_version: 1,
        scope: scope(),
        entries,
        generation: generation(generation_value),
    }
}

fn genesis_fence() -> ErasureFenceV1 {
    fence(
        REQUIRED_FENCE_KINDS
            .iter()
            .map(|kind| ErasureFenceEntryV1 {
                kind: *kind,
                epoch: 0,
            })
            .collect(),
        0,
    )
}

fn advanced_fence() -> ErasureFenceV1 {
    fence(
        REQUIRED_FENCE_KINDS
            .iter()
            .map(|kind| ErasureFenceEntryV1 {
                kind: *kind,
                epoch: u64::from(*kind == ErasureScopeKind::Representation),
            })
            .collect(),
        1,
    )
}

/// Generation advanced, every per-kind epoch unchanged from genesis.
/// Isolates the `same_generation` conjunct of `may_commit`: no epoch
/// entry differs, so a CAS that only checked epochs would wrongly permit
/// this commit.
fn fence_generation_only_advance() -> ErasureFenceV1 {
    fence(
        REQUIRED_FENCE_KINDS
            .iter()
            .map(|kind| ErasureFenceEntryV1 {
                kind: *kind,
                epoch: 0,
            })
            .collect(),
        1,
    )
}

/// Only the `privacy_subject` epoch advanced; generation and every other
/// epoch unchanged from genesis. This is the parent-side half of the
/// parent-vs-child scope race: work captured the genesis fence, then a
/// `privacy_subject` tombstone landed. Isolates the `no_epoch_advanced`
/// conjunct of `may_commit` (generation alone would wrongly permit it).
fn fence_privacy_subject_only_advance() -> ErasureFenceV1 {
    fence(
        REQUIRED_FENCE_KINDS
            .iter()
            .map(|kind| ErasureFenceEntryV1 {
                kind: *kind,
                epoch: u64::from(*kind == ErasureScopeKind::PrivacySubject),
            })
            .collect(),
        0,
    )
}

/// Only the `representation` epoch advanced; generation and every other
/// epoch unchanged from genesis. The mirrored, child-side half of the
/// same race: a `representation` projection commit racing a
/// `representation`-kind tombstone, with no generation movement to lean
/// on. Also isolates the `no_epoch_advanced` conjunct of `may_commit`.
fn fence_representation_only_advance() -> ErasureFenceV1 {
    fence(
        REQUIRED_FENCE_KINDS
            .iter()
            .map(|kind| ErasureFenceEntryV1 {
                kind: *kind,
                epoch: u64::from(*kind == ErasureScopeKind::Representation),
            })
            .collect(),
        0,
    )
}

fn receipt_pending() -> ErasureReceiptV1 {
    ErasureReceiptV1 {
        schema_version: 1,
        erasure_event_id: event_representation().accepted_event_id().unwrap(),
        state: ErasureReceiptStateV1::Pending,
        residual_inventory: vec![
            ErasureStoreResidualV1 {
                store_id: ContractId::new("store.cache").unwrap(),
                deletion_actor: ErasureDeletionActorV1::FleetRecall,
                residual_present: true,
            },
            ErasureStoreResidualV1 {
                store_id: ContractId::new("store.index").unwrap(),
                deletion_actor: ErasureDeletionActorV1::FleetRecall,
                residual_present: false,
            },
        ],
        key_destroyed: false,
        issued_at: CanonicalTimestamp::parse("2026-08-16T00:00:02.000000000Z").unwrap(),
    }
}

fn receipt_complete() -> ErasureReceiptV1 {
    ErasureReceiptV1 {
        state: ErasureReceiptStateV1::Complete,
        residual_inventory: vec![
            ErasureStoreResidualV1 {
                store_id: ContractId::new("store.cache").unwrap(),
                deletion_actor: ErasureDeletionActorV1::FleetRecall,
                residual_present: false,
            },
            ErasureStoreResidualV1 {
                store_id: ContractId::new("store.index").unwrap(),
                deletion_actor: ErasureDeletionActorV1::AuthoritativeProvider,
                residual_present: false,
            },
        ],
        key_destroyed: true,
        ..receipt_pending()
    }
}

/// `state: complete`, `key_destroyed: true`, and exactly one governed
/// store still showing a residual. Isolates the `any_residual_present`
/// half of the `complete` conjunction: key destruction alone, even when
/// it genuinely happened, is not sufficient evidence of erasure while
/// plaintext or a derived copy remains anywhere in the inventory.
fn receipt_complete_residual_despite_key_destroyed() -> ErasureReceiptV1 {
    ErasureReceiptV1 {
        schema_version: 1,
        erasure_event_id: event_representation().accepted_event_id().unwrap(),
        state: ErasureReceiptStateV1::Complete,
        residual_inventory: vec![ErasureStoreResidualV1 {
            store_id: ContractId::new("store.archive").unwrap(),
            deletion_actor: ErasureDeletionActorV1::FleetRecall,
            residual_present: true,
        }],
        key_destroyed: true,
        issued_at: CanonicalTimestamp::parse("2026-08-16T00:00:03.000000000Z").unwrap(),
    }
}

fn legal_hold_active() -> LegalHoldV1 {
    LegalHoldV1 {
        schema_version: 1,
        target: target_representation(),
        policy_basis: policy_basis(),
        placed_at: CanonicalTimestamp::parse("2026-08-16T00:00:00.000000000Z").unwrap(),
        released_at: None,
        visibility_ceiling: VisibilityClass::Private,
    }
}

fn retainable_matcher_forbidden() -> RetainableMatcherPolicyV1 {
    RetainableMatcherPolicyV1::PseudonymousMatcherForbidden {}
}

fn restore_gate_quarantined() -> RestoreGateV1 {
    RestoreGateV1 {
        schema_version: 1,
        tombstone_tail_applied: true,
        covered_by_tombstone: true,
        quarantine_preferred: true,
    }
}

fn dependent_transition_unverifiable() -> DependentSupportTransitionV1 {
    DependentSupportTransitionV1 {
        schema_version: 1,
        erasure_event_id: event_representation().accepted_event_id().unwrap(),
        next_state: SupportVerificationStateV1::Unverifiable,
        sufficient_redacted_evidence_remains: false,
        recompute_targets: vec![AcceptedEventId::from_digest(labelled_digest(
            "discrepancy.fixture.one",
        ))],
    }
}

fn checkpoint_rule() -> CheckpointErasureRuleV1 {
    CheckpointErasureRuleV1 {
        schema_version: 1,
        previous_checkpoint_digest: labelled_digest("checkpoint.fixture.previous"),
        previous_generation: generation(0),
        new_checkpoint_digest: labelled_digest("checkpoint.fixture.new"),
        new_generation: generation(1),
    }
}

#[test]
fn erasure_event_shape_and_identity() {
    let event = event_representation();
    event.validate_shape().unwrap();
    assert!(event.accepted_event_id().is_ok());

    let mut wrong_kind = event.clone();
    wrong_kind.event_kind = ContractId::new("erasure.proposed").unwrap();
    assert!(wrong_kind.validate_shape().is_err());

    let mut zero_target = event.clone();
    zero_target.target.target_digest = Sha256Digest::ZERO;
    assert!(zero_target.validate_shape().is_err());

    // Foreign/unfrozen profile: `profile` is in the `ostk-erasure-event-v1`
    // digest preimage and is this candidate's anchor to the frozen
    // runtime profile. Nothing else in `validate_shape` rejects a
    // candidate under a different profile, so this must be pinned
    // directly.
    let mut foreign_profile = event.clone();
    foreign_profile.profile.profile_digest = Sha256Digest::ZERO;
    assert_eq!(
        foreign_profile.validate_shape(),
        Err(ContractError::ProfileMismatch)
    );
    assert_eq!(
        foreign_profile.accepted_event_id(),
        Err(ContractError::ProfileMismatch)
    );

    // Bounded interval, positive case: `effective_until` set strictly
    // after `effective_from` must validate. Every other fixture in this
    // module leaves `effective_until: null`, so without this the
    // `until.is_microsecond_aligned() && *until > self.effective_from`
    // branch has no fixture exercising it at all.
    let mut bounded_interval = event.clone();
    bounded_interval.effective.effective_until =
        Some(CanonicalTimestamp::parse("2026-09-16T00:00:00.000000000Z").unwrap());
    bounded_interval.validate_shape().unwrap();

    // Bounded interval, negative case: `effective_until` at or before
    // `effective_from` must fail closed. This isolates
    // `*until > self.effective_from` from the alignment check next to it.
    let mut inverted_interval = event.clone();
    inverted_interval.effective.effective_until =
        Some(inverted_interval.effective.effective_from.clone());
    assert_eq!(
        inverted_interval.validate_shape(),
        Err(ContractError::Schema(
            "invalid erasure effective interval".into()
        ))
    );

    // `requested_at` misalignment, isolated from every other conjunct:
    // an otherwise shape-valid event whose `requested_at` carries a
    // sub-microsecond nanosecond value must fail closed.
    let mut misaligned_requested_at = event.clone();
    misaligned_requested_at.requested_at =
        CanonicalTimestamp::parse("2026-08-16T00:00:00.000000001Z").unwrap();
    assert_eq!(
        misaligned_requested_at.validate_shape(),
        Err(ContractError::Schema(
            "invalid erasure event candidate".into()
        ))
    );

    // Equal-instant boundary, positive case: `effective_from` exactly
    // equal to `policy_basis_effective_from` must validate. Every other
    // fixture in this module leaves a strict gap between the two
    // timestamps, so without this the `effective_from <
    // policy_basis_effective_from` conjunct's boundary is never
    // exercised and a `<` -> `<=` mutation there is invisible: it would
    // wrongly reject this exact case.
    let mut effective_equal_to_policy = event.clone();
    effective_equal_to_policy.effective.effective_from = effective_equal_to_policy
        .policy_basis_effective_from
        .clone();
    effective_equal_to_policy.validate_shape().unwrap();

    let mut effective_before_policy = event;
    effective_before_policy.effective.effective_from =
        CanonicalTimestamp::parse("2025-01-01T00:00:00.000000000Z").unwrap();
    assert_eq!(
        effective_before_policy.validate_shape(),
        Err(ContractError::Schema(
            "invalid erasure event candidate".into()
        ))
    );

    let negative_event: ErasureEventV1 =
        decode_strict(record(NEGATIVE_EVENT_EFFECTIVE_BEFORE_POLICY_FIXTURE)).unwrap();
    // Distinguishing property: this fixture decodes to an otherwise
    // shape-valid event whose effective interval starts strictly before
    // the policy basis it claims to act under.
    assert!(negative_event.effective.effective_from < negative_event.policy_basis_effective_from);
    assert_eq!(
        negative_event.validate_shape(),
        Err(ContractError::Schema(
            "invalid erasure event candidate".into()
        ))
    );
}

#[test]
fn re_consent_policy_reference_must_itself_validate() {
    let unverifiable_re_consent = ProspectiveReConsentV1::AuthorizedForNewSourceFact {
        consent_policy: RegistryReferenceV1 {
            entry_id: ContractId::new("policy.bogus").unwrap(),
            version: 0,
            entry_digest: Sha256Digest::ZERO,
        },
    };
    let mut event = event_privacy_subject();
    event.re_consent = unverifiable_re_consent.clone();
    assert!(
        event.validate_shape().is_err(),
        "an event candidate must not shape-validate with an unverifiable re-consent policy \
         reference"
    );
    assert!(
        event.accepted_event_id().is_err(),
        "accepted_event_id must refuse a candidate whose re-consent policy reference does \
         not validate"
    );

    let different_target = ErasureScope {
        kind: ErasureScopeKind::Representation,
        target_digest: labelled_digest("representation.fixture.two"),
    };
    assert!(
        !re_consent_permits_new_source_fact(
            &tombstone_digest_only(),
            &unverifiable_re_consent,
            &different_target
        )
        .unwrap(),
        "an unverifiable consent-policy reference must never permit a new source fact"
    );
}

#[test]
fn admitted_event_is_unconstructible_outside_test_witness() {
    let admitted = AdmittedErasureEventV1::from_test_witness(event_representation()).unwrap();
    assert_eq!(
        admitted.accepted_event_id(),
        event_representation().accepted_event_id().unwrap()
    );
    assert_eq!(admitted.event(), &event_representation());
}

#[test]
fn tombstone_validates_and_carries_no_payload() {
    tombstone_digest_only().validate().unwrap();
    tombstone_with_metadata().validate().unwrap();

    let mut zero_target = tombstone_digest_only();
    zero_target.target.target_digest = Sha256Digest::ZERO;
    assert!(zero_target.validate().is_err());

    // A tombstone that binds to no erasure event at all (the zero
    // digest) must never validate: it would otherwise get a stable
    // tombstone_id while asserting retrieval-deny for an event that
    // does not exist.
    let mut zero_event_id = tombstone_digest_only();
    zero_event_id.erasure_event_id = AcceptedEventId::from_digest(Sha256Digest::ZERO);
    assert!(zero_event_id.validate().is_err());

    // `DigestAndMetadata.installed_at` must itself be microsecond-aligned;
    // an unaligned nanosecond value must fail closed.
    let mut misaligned_installed_at = tombstone_with_metadata();
    let TombstoneLifecycleV1::DigestAndMetadata { installed_at, .. } =
        &mut misaligned_installed_at.lifecycle
    else {
        unreachable!("tombstone_with_metadata always uses DigestAndMetadata");
    };
    *installed_at = CanonicalTimestamp::parse("2026-08-16T00:00:00.000000001Z").unwrap();
    assert!(misaligned_installed_at.validate().is_err());

    // `superseded_by`, when present, must not be the zero digest -- a
    // tombstone cannot claim supersession by an event that does not
    // exist.
    let mut zero_superseded_by = tombstone_with_metadata();
    let TombstoneLifecycleV1::DigestAndMetadata { superseded_by, .. } =
        &mut zero_superseded_by.lifecycle
    else {
        unreachable!("tombstone_with_metadata always uses DigestAndMetadata");
    };
    *superseded_by = Some(AcceptedEventId::from_digest(Sha256Digest::ZERO));
    assert!(zero_superseded_by.validate().is_err());

    // A tombstone must not name its own `erasure_event_id` as the event
    // that supersedes it -- a tombstone cannot be its own successor.
    let mut self_superseded = tombstone_with_metadata();
    let own_event_id = self_superseded.erasure_event_id;
    let TombstoneLifecycleV1::DigestAndMetadata { superseded_by, .. } =
        &mut self_superseded.lifecycle
    else {
        unreachable!("tombstone_with_metadata always uses DigestAndMetadata");
    };
    *superseded_by = Some(own_event_id);
    assert!(self_superseded.validate().is_err());

    // The type itself has no field that could carry payload bytes; a
    // fixture attempting to add one is rejected by
    // `#[serde(deny_unknown_fields)]`, exercised below against the
    // on-disk fixture.
    assert!(
        decode_strict::<ErasureTombstoneV1>(record(NEGATIVE_TOMBSTONE_PAYLOAD_BYTES_FIXTURE))
            .is_err()
    );

    assert_ne!(
        tombstone_digest_only().tombstone_id().unwrap(),
        tombstone_with_metadata().tombstone_id().unwrap()
    );
}

/// EVID-01/EVID-05: a bare *unit* variant of an internally-tagged enum
/// does not enforce `deny_unknown_fields` (serde issue #1358) -- serde
/// buffers every wire key into a `Content` tree keyed only by the tag
/// before dispatching to the variant deserializer, and for a unit
/// variant that dispatch calls `deserialize_unit`, which accepts and
/// silently drops any sibling key. Reproduced against all three of this
/// module's fieldless-by-design variants: each smuggled-key form below
/// decodes cleanly under an unpatched unit-variant declaration and
/// reproduces the clean record's identity -- carrying the exact erased
/// plaintext straight through a tombstone, an erasure event's re-consent
/// claim, or a retainable-matcher policy. Declaring each variant as a
/// fieldless *struct* variant (`Variant {}`, wire-identical to a unit
/// variant) instead dispatches through `deserialize_struct` with an
/// empty field list, which does enforce `deny_unknown_fields` and
/// rejects every case below at DECODE -- matching the `Contiguous {}`
/// fix in `coverage.rs`'s `SequenceContinuityV1`.
#[test]
fn fieldless_variants_reject_unknown_fields_at_decode() {
    let clean_tombstone_bytes = std::str::from_utf8(record(TOMBSTONE_DIGEST_ONLY_FIXTURE)).unwrap();
    let smuggled_tombstone_bytes = clean_tombstone_bytes.replace(
        r#""lifecycle":{"kind":"digest_only"}"#,
        r#""lifecycle":{"canonical_text":"THE ERASED PLAINTEXT","kind":"digest_only"}"#,
    );
    assert_ne!(smuggled_tombstone_bytes, clean_tombstone_bytes);
    assert!(
        decode_strict::<ErasureTombstoneV1>(smuggled_tombstone_bytes.as_bytes()).is_err(),
        "an unknown field riding inside TombstoneLifecycleV1::DigestOnly must be rejected \
         at decode, not silently dropped"
    );

    let clean_event_bytes = std::str::from_utf8(record(ERASURE_EVENT_FIXTURE)).unwrap();
    let smuggled_event_bytes = clean_event_bytes.replace(
        r#""re_consent":{"kind":"not_authorized"}"#,
        r#""re_consent":{"exfiltrated":"THE ERASED PLAINTEXT","kind":"not_authorized"}"#,
    );
    assert_ne!(smuggled_event_bytes, clean_event_bytes);
    assert!(
        decode_strict::<ErasureEventV1>(smuggled_event_bytes.as_bytes()).is_err(),
        "an unknown field riding inside ProspectiveReConsentV1::NotAuthorized must be \
         rejected at decode, not silently dropped"
    );

    let clean_matcher_bytes =
        std::str::from_utf8(record(RETAINABLE_MATCHER_FORBIDDEN_FIXTURE)).unwrap();
    let smuggled_matcher_bytes = clean_matcher_bytes.replace(
        r#"{"kind":"pseudonymous_matcher_forbidden"}"#,
        r#"{"exfiltrated":"THE ERASED PLAINTEXT","kind":"pseudonymous_matcher_forbidden"}"#,
    );
    assert_ne!(smuggled_matcher_bytes, clean_matcher_bytes);
    assert!(
        decode_strict::<RetainableMatcherPolicyV1>(smuggled_matcher_bytes.as_bytes()).is_err(),
        "an unknown field riding inside \
         RetainableMatcherPolicyV1::PseudonymousMatcherForbidden must be rejected at \
         decode, not silently dropped"
    );
}

#[test]
#[allow(clippy::too_many_lines)] // one test isolating every conjunct of ErasureFenceV1::validate
fn fence_requires_all_four_scope_kinds_exactly_once() {
    genesis_fence().validate().unwrap();
    advanced_fence().validate().unwrap();

    let mut missing_scope = genesis_fence();
    missing_scope.entries.pop();
    assert!(missing_scope.validate().is_err());

    // A fence whose generation names a different tenant/project than the
    // fence itself must fail closed: the fence's own scope binding
    // (`self.generation.scope != self.scope`) is what ties an
    // otherwise-well-formed fence to one tenant/project, and nothing else
    // in this shape catches a mismatch here.
    let mut mismatched_generation_scope = genesis_fence();
    mismatched_generation_scope.generation.scope =
        AuthenticatedProjectScopeV1::from_trusted_context(
            ContractId::new("tenant.other").unwrap(),
            ContractId::new("project.other").unwrap(),
        );
    assert_eq!(
        mismatched_generation_scope.validate(),
        Err(ContractError::Schema(
            "erasure fence must cover exactly the four scope kinds once each".into()
        ))
    );

    // Isolate the `covers_every_required_kind` conjunct from the
    // `entries.len() != 4` check: four entries, strictly sorted, but one
    // kind duplicated and another kind entirely absent. The length check
    // alone cannot catch this -- only the coverage check can.
    let mut duplicate_kind_missing_scope = genesis_fence();
    duplicate_kind_missing_scope.entries = vec![
        ErasureFenceEntryV1 {
            kind: ErasureScopeKind::PrivacySubject,
            epoch: 0,
        },
        ErasureFenceEntryV1 {
            kind: ErasureScopeKind::PrivacySubject,
            epoch: 1,
        },
        ErasureFenceEntryV1 {
            kind: ErasureScopeKind::Representation,
            epoch: 0,
        },
        ErasureFenceEntryV1 {
            kind: ErasureScopeKind::Resource,
            epoch: 0,
        },
    ];
    assert_eq!(
        duplicate_kind_missing_scope.entries.len(),
        REQUIRED_FENCE_KINDS.len()
    );
    assert!(strictly_sorted(&duplicate_kind_missing_scope.entries));
    assert!(duplicate_kind_missing_scope.validate().is_err());

    // Isolate `strictly_sorted(&self.entries)` from both of the above:
    // four entries, one of each required kind, but out of order.
    let mut unsorted_but_complete = genesis_fence();
    unsorted_but_complete.entries.swap(0, 1);
    assert_eq!(
        unsorted_but_complete.entries.len(),
        REQUIRED_FENCE_KINDS.len()
    );
    assert!(REQUIRED_FENCE_KINDS.iter().all(|kind| {
        unsorted_but_complete
            .entries
            .iter()
            .any(|entry| entry.kind == *kind)
    }));
    assert!(!strictly_sorted(&unsorted_but_complete.entries));
    assert!(unsorted_but_complete.validate().is_err());

    // Isolate `entries.len() != REQUIRED_FENCE_KINDS.len()` from both the
    // coverage and sortedness checks: five entries, strictly sorted, and
    // covering all four required kinds -- PrivacySubject duplicated with
    // two different epochs. Neither `covers_every_required_kind` nor
    // `strictly_sorted` rejects this; only the length conjunct does. This
    // matters beyond the shape check itself: a fence like this is exactly
    // what `ErasureFenceCasV1::may_commit` must never treat as a sound
    // `expected` snapshot (see `single_epoch_for_kind`).
    let duplicate_kind_five_entries = ErasureFenceV1 {
        entries: vec![
            ErasureFenceEntryV1 {
                kind: ErasureScopeKind::PrivacySubject,
                epoch: 0,
            },
            ErasureFenceEntryV1 {
                kind: ErasureScopeKind::PrivacySubject,
                epoch: 1,
            },
            ErasureFenceEntryV1 {
                kind: ErasureScopeKind::Representation,
                epoch: 0,
            },
            ErasureFenceEntryV1 {
                kind: ErasureScopeKind::Resource,
                epoch: 0,
            },
            ErasureFenceEntryV1 {
                kind: ErasureScopeKind::SourceFact,
                epoch: 0,
            },
        ],
        ..genesis_fence()
    };
    assert_eq!(duplicate_kind_five_entries.entries.len(), 5);
    assert!(strictly_sorted(&duplicate_kind_five_entries.entries));
    assert!(REQUIRED_FENCE_KINDS.iter().all(|kind| {
        duplicate_kind_five_entries
            .entries
            .iter()
            .any(|entry| entry.kind == *kind)
    }));
    assert!(duplicate_kind_five_entries.validate().is_err());

    // Two ADJACENT, byte-identical entries (same kind, same epoch) --
    // the exact shape `strictly_sorted`'s `< -> <=` mutation would admit.
    // Unlike the reordering fixture above, this pins the fixed four-slot
    // fence's actual defense: a duplicate entry always displaces one of
    // the four required kinds (here `SourceFact` is missing), so
    // `covers_every_required_kind` rejects it independently of
    // `strictly_sorted`. The shared `strictly_sorted` mutation is killed
    // by the receipt and recompute-target fixtures below, where no
    // fixed-arity coverage guard exists to catch it; this fixture
    // documents that the fence's own rejection of a duplicate entry does
    // not depend on that shared helper alone.
    let mut adjacent_duplicate_entries = genesis_fence();
    adjacent_duplicate_entries.entries = vec![
        ErasureFenceEntryV1 {
            kind: ErasureScopeKind::PrivacySubject,
            epoch: 0,
        },
        ErasureFenceEntryV1 {
            kind: ErasureScopeKind::PrivacySubject,
            epoch: 0,
        },
        ErasureFenceEntryV1 {
            kind: ErasureScopeKind::Representation,
            epoch: 0,
        },
        ErasureFenceEntryV1 {
            kind: ErasureScopeKind::Resource,
            epoch: 0,
        },
    ];
    assert_eq!(
        adjacent_duplicate_entries.entries[0],
        adjacent_duplicate_entries.entries[1]
    );
    assert!(!strictly_sorted(&adjacent_duplicate_entries.entries));
    assert_eq!(
        adjacent_duplicate_entries.validate(),
        Err(ContractError::Schema(
            "erasure fence must cover exactly the four scope kinds once each".into()
        ))
    );

    let negative_fence: ErasureFenceV1 =
        decode_strict(record(NEGATIVE_FENCE_MISSING_SCOPE_FIXTURE)).unwrap();
    // Distinguishing property, not just the shared error string: this
    // fixture decodes to a fence with only three scope-kind entries.
    assert_eq!(negative_fence.entries.len(), 3);
    assert_eq!(
        negative_fence.validate(),
        Err(ContractError::Schema(
            "erasure fence must cover exactly the four scope kinds once each".into()
        ))
    );

    assert_ne!(
        genesis_fence().fence_id().unwrap(),
        advanced_fence().fence_id().unwrap()
    );
}

/// `single_epoch_for_kind` -- the primitive `may_commit`'s
/// `no_epoch_advanced` is built on -- must stay sound even when handed
/// entries that `ErasureFenceV1::validate` would already reject. A
/// duplicate-kind lookup must answer `None` (ambiguous), never either
/// candidate epoch, so a forged five-entry `expected` fence can never
/// forge agreement with a genuine four-entry `current` fence. This holds
/// independently of the `entries.len()` arity guard in
/// `ErasureFenceV1::validate`.
#[test]
fn single_epoch_for_kind_is_ambiguous_on_duplicate_and_absent_on_missing() {
    let duplicate = [
        ErasureFenceEntryV1 {
            kind: ErasureScopeKind::PrivacySubject,
            epoch: 0,
        },
        ErasureFenceEntryV1 {
            kind: ErasureScopeKind::PrivacySubject,
            epoch: 1,
        },
    ];
    assert_eq!(
        single_epoch_for_kind(&duplicate, ErasureScopeKind::PrivacySubject),
        None
    );
    assert_eq!(
        single_epoch_for_kind(&duplicate, ErasureScopeKind::Representation),
        None
    );

    let single = [ErasureFenceEntryV1 {
        kind: ErasureScopeKind::Resource,
        epoch: 7,
    }];
    assert_eq!(
        single_epoch_for_kind(&single, ErasureScopeKind::Resource),
        Some(7)
    );

    // The exploit shape from the prior review round: a strictly sorted,
    // all-four-kinds-covered, five-entry `expected` fence (PrivacySubject
    // duplicated) can never read as "no epoch advanced" against a
    // genuine four-entry `current` fence, because the ambiguous
    // PrivacySubject lookup on `expected` alone forces `no_epoch_advanced`
    // to `false` regardless of what `current` says.
    let forged_expected = [
        ErasureFenceEntryV1 {
            kind: ErasureScopeKind::PrivacySubject,
            epoch: 0,
        },
        ErasureFenceEntryV1 {
            kind: ErasureScopeKind::PrivacySubject,
            epoch: 1,
        },
        ErasureFenceEntryV1 {
            kind: ErasureScopeKind::Representation,
            epoch: 0,
        },
        ErasureFenceEntryV1 {
            kind: ErasureScopeKind::Resource,
            epoch: 0,
        },
        ErasureFenceEntryV1 {
            kind: ErasureScopeKind::SourceFact,
            epoch: 0,
        },
    ];
    assert_eq!(
        single_epoch_for_kind(&forged_expected, ErasureScopeKind::PrivacySubject),
        None
    );
}

#[test]
fn fence_cas_rejects_a_commit_after_concurrent_erasure() {
    let concurrent_erasure = ErasureFenceCasV1 {
        expected: genesis_fence(),
        current: advanced_fence(),
    };
    assert_eq!(concurrent_erasure.may_commit(), Ok(false));

    let no_interleaving_erasure = ErasureFenceCasV1 {
        expected: genesis_fence(),
        current: genesis_fence(),
    };
    assert_eq!(no_interleaving_erasure.may_commit(), Ok(true));

    let cross_scope = ErasureFenceCasV1 {
        expected: genesis_fence(),
        current: ErasureFenceV1 {
            scope: AuthenticatedProjectScopeV1::from_trusted_context(
                ContractId::new("tenant.other").unwrap(),
                ContractId::new("project.other").unwrap(),
            ),
            generation: ErasureGenerationV1 {
                scope: AuthenticatedProjectScopeV1::from_trusted_context(
                    ContractId::new("tenant.other").unwrap(),
                    ContractId::new("project.other").unwrap(),
                ),
                value: 0,
            },
            ..genesis_fence()
        },
    };
    assert!(cross_scope.may_commit().is_err());

    // Isolate the `same_generation` conjunct: the generation alone
    // advances while every per-kind epoch stays at genesis. A CAS that
    // dropped the epoch check entirely (kept only the generation check)
    // would still catch this one -- the point is that dropping the
    // *generation* check must not let it slip through, which the next
    // two cases confirm from the other side.
    let generation_only: ErasureFenceV1 =
        decode_strict(record(FENCE_GENERATION_ONLY_ADVANCE_FIXTURE)).unwrap();
    assert_eq!(generation_only.generation.value, 1);
    assert!(generation_only.entries.iter().all(|entry| entry.epoch == 0));
    assert_eq!(
        ErasureFenceCasV1 {
            expected: genesis_fence(),
            current: generation_only,
        }
        .may_commit(),
        Ok(false),
        "a generation-only advance with every epoch unchanged must still fail closed"
    );

    // Isolate the `no_epoch_advanced` conjunct, parent side: only the
    // `privacy_subject` epoch moves and the generation does not move at
    // all. A CAS that dropped the epoch check (kept only the generation
    // check) would wrongly permit this -- the mechanical form of "a
    // privacy_subject tombstone racing representation-scoped work".
    let privacy_subject_only: ErasureFenceV1 =
        decode_strict(record(FENCE_PRIVACY_SUBJECT_ONLY_ADVANCE_FIXTURE)).unwrap();
    assert_eq!(privacy_subject_only.generation.value, 0);
    assert_eq!(
        privacy_subject_only
            .entries
            .iter()
            .find(|entry| entry.kind == ErasureScopeKind::PrivacySubject)
            .unwrap()
            .epoch,
        1
    );
    assert_eq!(
        ErasureFenceCasV1 {
            expected: genesis_fence(),
            current: privacy_subject_only.clone(),
        }
        .may_commit(),
        Ok(false),
        "a privacy_subject-only epoch advance must fail closed even with no generation move"
    );

    // Mirrored, child side of the same race: only `representation`
    // moves, generation unchanged.
    let representation_only: ErasureFenceV1 =
        decode_strict(record(FENCE_REPRESENTATION_ONLY_ADVANCE_FIXTURE)).unwrap();
    assert_eq!(representation_only.generation.value, 0);
    assert_eq!(
        representation_only
            .entries
            .iter()
            .find(|entry| entry.kind == ErasureScopeKind::Representation)
            .unwrap()
            .epoch,
        1
    );
    assert_eq!(
        ErasureFenceCasV1 {
            expected: genesis_fence(),
            current: representation_only,
        }
        .may_commit(),
        Ok(false),
        "a representation-only epoch advance must fail closed even with no generation move"
    );

    // The two single-epoch-advance fences differ from each other only in
    // which kind moved, and from genesis in exactly one entry -- proof
    // that `may_commit` distinguishes per-kind epochs rather than
    // reasoning about the fence as an undifferentiated blob.
    assert_ne!(
        privacy_subject_only.fence_id().unwrap(),
        genesis_fence().fence_id().unwrap()
    );
}

#[test]
fn re_consent_never_revives_the_erased_identity() {
    let tombstone = tombstone_digest_only();
    let authorized = ProspectiveReConsentV1::AuthorizedForNewSourceFact {
        consent_policy: policy_basis(),
    };
    let different_target = ErasureScope {
        kind: ErasureScopeKind::Representation,
        target_digest: labelled_digest("representation.fixture.two"),
    };
    assert!(
        re_consent_permits_new_source_fact(&tombstone, &authorized, &different_target).unwrap()
    );
    assert!(
        !re_consent_permits_new_source_fact(&tombstone, &authorized, &tombstone.target).unwrap()
    );
    assert!(
        !re_consent_permits_new_source_fact(
            &tombstone,
            &ProspectiveReConsentV1::NotAuthorized {},
            &different_target
        )
        .unwrap()
    );

    // A tombstone this module cannot validate must never yield a
    // permissive answer, no matter how "different" the candidate target
    // looks from its (unverifiable) target digest.
    let mut invalid_tombstone = tombstone;
    invalid_tombstone.target.target_digest = Sha256Digest::ZERO;
    assert!(invalid_tombstone.validate().is_err());
    assert!(
        re_consent_permits_new_source_fact(&invalid_tombstone, &authorized, &different_target)
            .is_err(),
        "an invalid tombstone must fail closed, never report permitted"
    );
}

#[test]
fn acceptance_effect_ties_tombstone_fence_and_generation_atomically() {
    let admitted = AdmittedErasureEventV1::from_test_witness(event_representation()).unwrap();
    let effect = ErasureAcceptanceEffectV1::from_test_witness(
        admitted,
        tombstone_digest_only(),
        vec![ErasureFenceEntryV1 {
            kind: ErasureScopeKind::Representation,
            epoch: 1,
        }],
        generation(0),
        generation(1),
    )
    .unwrap();
    assert_eq!(effect.generation_before().value, 0);
    assert_eq!(effect.generation_after().value, 1);
    assert_eq!(effect.advanced_entries().len(), 1);

    let mismatched_target =
        AdmittedErasureEventV1::from_test_witness(event_privacy_subject()).unwrap();
    assert!(
        ErasureAcceptanceEffectV1::from_test_witness(
            mismatched_target,
            tombstone_digest_only(),
            vec![ErasureFenceEntryV1 {
                kind: ErasureScopeKind::PrivacySubject,
                epoch: 1,
            }],
            generation(0),
            generation(1),
        )
        .is_err()
    );

    let admitted_again = AdmittedErasureEventV1::from_test_witness(event_representation()).unwrap();
    assert!(
        ErasureAcceptanceEffectV1::from_test_witness(
            admitted_again,
            tombstone_digest_only(),
            vec![ErasureFenceEntryV1 {
                kind: ErasureScopeKind::Representation,
                epoch: 1,
            }],
            generation(1),
            generation(1),
        )
        .is_err(),
        "generation must strictly advance"
    );
}

#[test]
#[allow(clippy::too_many_lines)] // one exhaustive receipt-shape test, incl. the mutation-killing duplicate/cap/sortedness fixtures
fn receipt_complete_requires_no_residual_and_key_destroyed() {
    receipt_pending().validate().unwrap();
    receipt_complete().validate().unwrap();

    let mut key_not_destroyed = receipt_complete();
    key_not_destroyed.key_destroyed = false;
    assert!(key_not_destroyed.validate().is_err());

    // A `complete` receipt with an EMPTY `residual_inventory` is vacuous
    // completion: zero stores verified, yet the receipt claims full
    // cleanup. `any_residual_present` over an empty vector is trivially
    // `false`, so only the standalone `residual_inventory.is_empty()`
    // guard catches this.
    let mut empty_inventory = receipt_complete();
    empty_inventory.residual_inventory = Vec::new();
    assert!(empty_inventory.residual_inventory.is_empty());
    assert_eq!(
        empty_inventory.validate(),
        Err(ContractError::Schema("invalid erasure receipt".into()))
    );

    // Isolate `strictly_sorted(&self.residual_inventory)`: the same two
    // rows as `receipt_pending()`, only reordered. Every other conjunct
    // still passes (non-empty, within the size cap, `pending` so the
    // `complete` conjunction never applies, `issued_at` aligned, a
    // non-zero `erasure_event_id`) -- only the ordering is wrong.
    let mut unsorted_residuals = receipt_pending();
    unsorted_residuals.residual_inventory.reverse();
    assert_eq!(unsorted_residuals.residual_inventory.len(), 2);
    assert!(!strictly_sorted(&unsorted_residuals.residual_inventory));
    assert!(unsorted_residuals.validate().is_err());

    // Two ADJACENT, byte-identical residual rows -- the shape
    // `strictly_sorted`'s `< -> <=` mutation admits but reordering does
    // not: reversing two distinct rows still produces a strictly
    // descending pair under either operator, so it cannot distinguish
    // `<` from `<=`. A duplicate row can: nothing else in `validate`
    // rejects a `pending` receipt that names the same store twice, so
    // this fixture flips from rejected to accepted under that mutation
    // alone.
    let mut duplicate_residual_rows = receipt_pending();
    duplicate_residual_rows.residual_inventory =
        vec![duplicate_residual_rows.residual_inventory[0].clone(); 2];
    assert_eq!(
        duplicate_residual_rows.residual_inventory[0],
        duplicate_residual_rows.residual_inventory[1]
    );
    assert!(!strictly_sorted(
        &duplicate_residual_rows.residual_inventory
    ));
    assert_eq!(
        duplicate_residual_rows.validate(),
        Err(ContractError::Schema("invalid erasure receipt".into()))
    );

    // Isolate `residual_inventory.len() > MAX_RESIDUAL_STORES`: a
    // strictly-sorted, `pending` (so the `complete` conjunction never
    // applies), otherwise entirely valid receipt naming one more
    // governed store than the cap permits. No fixture carries this --
    // `MAX_RESIDUAL_STORES` is 64, too large for a byte-frozen `.jsonl`
    // record -- so it is pinned directly against the constant.
    let mut over_cap_residuals = receipt_pending();
    over_cap_residuals.residual_inventory = (0..=MAX_RESIDUAL_STORES)
        .map(|index| ErasureStoreResidualV1 {
            store_id: ContractId::new(format!("store.{index:03}")).unwrap(),
            deletion_actor: ErasureDeletionActorV1::FleetRecall,
            residual_present: false,
        })
        .collect();
    assert_eq!(
        over_cap_residuals.residual_inventory.len(),
        MAX_RESIDUAL_STORES + 1
    );
    assert!(strictly_sorted(&over_cap_residuals.residual_inventory));
    assert_eq!(
        over_cap_residuals.validate(),
        Err(ContractError::Schema("invalid erasure receipt".into()))
    );
    // The boundary itself -- exactly `MAX_RESIDUAL_STORES` rows -- must
    // still validate, so the rejection above is specifically about
    // exceeding the cap, not merely about having many rows.
    let mut at_cap_residuals = receipt_pending();
    at_cap_residuals.residual_inventory = (0..MAX_RESIDUAL_STORES)
        .map(|index| ErasureStoreResidualV1 {
            store_id: ContractId::new(format!("store.{index:03}")).unwrap(),
            deletion_actor: ErasureDeletionActorV1::FleetRecall,
            residual_present: false,
        })
        .collect();
    assert_eq!(
        at_cap_residuals.residual_inventory.len(),
        MAX_RESIDUAL_STORES
    );
    at_cap_residuals.validate().unwrap();

    // A receipt bound to no erasure event at all (the zero digest) must
    // never validate: it is the record that discharges EVID-08, and it
    // must name the event it discharges.
    let mut zero_event_id = receipt_complete();
    zero_event_id.erasure_event_id = AcceptedEventId::from_digest(Sha256Digest::ZERO);
    assert!(zero_event_id.validate().is_err());

    let negative_receipt: ErasureReceiptV1 =
        decode_strict(record(NEGATIVE_RECEIPT_COMPLETE_WITH_RESIDUAL_FIXTURE)).unwrap();
    // Distinguishing property, not just the shared error string: this
    // fixture claims `complete` while `key_destroyed` is still `false`
    // *and* a governed store still shows a residual -- it fails the
    // `complete` conjunction for two independent reasons at once, so it
    // alone cannot isolate the `any_residual_present` half of that
    // conjunction (see `receipt_complete_residual_despite_key_destroyed`
    // below for the fixture that does).
    assert_eq!(negative_receipt.state, ErasureReceiptStateV1::Complete);
    assert!(!negative_receipt.key_destroyed);
    assert!(
        negative_receipt
            .residual_inventory
            .iter()
            .any(|residual| residual.residual_present)
    );
    assert_eq!(
        negative_receipt.validate(),
        Err(ContractError::Schema("invalid erasure receipt".into()))
    );

    // Isolates the `any_residual_present` half specifically: the key
    // genuinely was destroyed (`key_destroyed: true`), yet exactly one
    // governed store still shows a residual. Key destruction alone, with
    // plaintext or a derived copy still resident anywhere in the
    // inventory, is not sufficient evidence of erasure -- this is the
    // one case in the suite where `key_destroyed` cannot be blamed for
    // the rejection.
    let residual_despite_key_destroyed: ErasureReceiptV1 = decode_strict(record(
        NEGATIVE_RECEIPT_COMPLETE_RESIDUAL_DESPITE_KEY_DESTROYED_FIXTURE,
    ))
    .unwrap();
    assert_eq!(
        residual_despite_key_destroyed.state,
        ErasureReceiptStateV1::Complete
    );
    assert!(residual_despite_key_destroyed.key_destroyed);
    assert!(
        residual_despite_key_destroyed
            .residual_inventory
            .iter()
            .any(|residual| residual.residual_present)
    );
    assert_eq!(
        residual_despite_key_destroyed.validate(),
        Err(ContractError::Schema("invalid erasure receipt".into()))
    );
    assert_eq!(
        residual_despite_key_destroyed,
        receipt_complete_residual_despite_key_destroyed()
    );

    assert_ne!(
        receipt_pending().receipt_id().unwrap(),
        receipt_complete().receipt_id().unwrap()
    );
}

#[test]
fn legal_hold_defers_removal_and_never_widens_visibility() {
    let hold = legal_hold_active();
    hold.validate().unwrap();
    assert!(hold.hold_id().is_ok());
    let before = CanonicalTimestamp::parse("2026-08-16T00:00:00.000000000Z").unwrap();
    let during = CanonicalTimestamp::parse("2026-08-17T00:00:00.000000000Z").unwrap();
    assert!(!hold.permits_removal(&before).unwrap());
    assert!(!hold.permits_removal(&during).unwrap());

    let mut released = hold;
    released.released_at =
        Some(CanonicalTimestamp::parse("2026-08-18T00:00:00.000000000Z").unwrap());
    assert!(
        released
            .permits_removal(&CanonicalTimestamp::parse("2026-08-19T00:00:00.000000000Z").unwrap())
            .unwrap()
    );
    assert!(!released.permits_removal(&during).unwrap());

    let negative_hold: LegalHoldV1 =
        decode_strict(record(NEGATIVE_LEGAL_HOLD_PUBLICATION_VISIBILITY_FIXTURE)).unwrap();
    // Distinguishing property: this fixture decodes to a hold whose
    // ceiling is exactly the one class that would let a held record
    // become public.
    assert_eq!(
        negative_hold.visibility_ceiling,
        VisibilityClass::PublicationApproved
    );
    assert_eq!(
        negative_hold.validate(),
        Err(ContractError::Schema("invalid legal hold".into()))
    );
}

/// An unvalidatable hold (`released_at` precedes `placed_at`) must never
/// answer `permits_removal` with a permissive `true`: it must fail
/// `validate()` and `permits_removal` must propagate that as `Err`, never
/// a bare bool. This kills the `*released > self.placed_at` mutation
/// (`&& true`) directly: with the conjunct neutered, `validate()` would
/// wrongly accept this hold and `permits_removal` would wrongly permit
/// removal at a time after the (invalid) release.
#[test]
fn permits_removal_fails_closed_on_release_before_placement() {
    let mut hold = legal_hold_active();
    hold.released_at = Some(CanonicalTimestamp::parse("2020-01-01T00:00:00.000000000Z").unwrap());
    assert_eq!(
        hold.validate(),
        Err(ContractError::Schema("invalid legal hold".into()))
    );
    assert_eq!(
        hold.permits_removal(&CanonicalTimestamp::parse("2026-08-16T00:00:00.000000000Z").unwrap()),
        Err(ContractError::Schema("invalid legal hold".into()))
    );
}

/// The equality boundary: a `released_at` that exactly equals
/// `placed_at` -- a zero-duration "release" recorded at the instant of
/// placement. This must fail exactly like the strictly-before case
/// above; the prior test alone cannot distinguish `*released >
/// self.placed_at` from `*released >= self.placed_at`, since both
/// operators reject a strictly-earlier release identically. Only this
/// equal-instant fixture flips outcome between the two operators: under
/// `>=` it would validate, and `permits_removal` would then answer
/// `true` for every `at >= placed_at`, lifting a hold that was supposed
/// to defer removal for its entire active interval.
#[test]
fn permits_removal_fails_closed_on_release_equal_to_placement() {
    let mut hold = legal_hold_active();
    hold.released_at = Some(hold.placed_at.clone());
    assert_eq!(
        hold.validate(),
        Err(ContractError::Schema("invalid legal hold".into()))
    );
    assert_eq!(
        hold.permits_removal(&CanonicalTimestamp::parse("2026-08-20T00:00:00.000000000Z").unwrap()),
        Err(ContractError::Schema("invalid legal hold".into()))
    );
}

/// `validate`'s disjunction relies on Rust binding `&&` tighter than
/// `||`; a fold of that disjunction to `&&` would silently AND the
/// `target.target_digest == Sha256Digest::ZERO` conjunct into the rest
/// instead of independently rejecting it, admitting a legal hold that
/// names the null/sentinel target. This isolates that conjunct alone:
/// every other field of the hold is otherwise fully valid (correct
/// schema version, microsecond-aligned `placed_at`, no `released_at`,
/// `visibility_ceiling` below the publication ceiling), so only the
/// zero target digest can cause the rejection.
#[test]
fn legal_hold_fails_closed_on_zero_target_digest() {
    let mut hold = legal_hold_active();
    hold.target.target_digest = Sha256Digest::ZERO;
    assert_eq!(
        hold.validate(),
        Err(ContractError::Schema("invalid legal hold".into()))
    );
}

#[test]
fn forbidden_matcher_forces_disable_and_purge() {
    assert_eq!(
        retainable_matcher_forbidden().required_scope_action(),
        Ok(RetainableMatcherScopeActionV1::DisableAndPurge)
    );
    assert_eq!(
        RetainableMatcherPolicyV1::PseudonymousMatcherAllowed {
            matcher_policy: policy_basis()
        }
        .required_scope_action(),
        Ok(RetainableMatcherScopeActionV1::Retain)
    );

    let mut zero_digest_matcher = RetainableMatcherPolicyV1::PseudonymousMatcherAllowed {
        matcher_policy: policy_basis(),
    };
    if let RetainableMatcherPolicyV1::PseudonymousMatcherAllowed { matcher_policy } =
        &mut zero_digest_matcher
    {
        matcher_policy.entry_digest = Sha256Digest::ZERO;
    }
    assert!(
        zero_digest_matcher.required_scope_action().is_err(),
        "an unverifiable matcher policy must never report Retain"
    );
}

#[test]
fn restore_gate_refuses_a_decision_before_the_tail_is_applied() {
    assert_eq!(
        restore_gate_quarantined().outcome(),
        Ok(RestoreGateOutcomeV1::Quarantined)
    );
    let mut suppressed = restore_gate_quarantined();
    suppressed.quarantine_preferred = false;
    assert_eq!(suppressed.outcome(), Ok(RestoreGateOutcomeV1::Suppressed));
    let mut serve = restore_gate_quarantined();
    serve.covered_by_tombstone = false;
    assert_eq!(serve.outcome(), Ok(RestoreGateOutcomeV1::Serve));
    let mut undecided = restore_gate_quarantined();
    undecided.tombstone_tail_applied = false;
    assert!(undecided.outcome().is_err());

    // An unrecognized schema_version must never be silently decided
    // under this version's truth table -- in particular it must never
    // be read as `Serve`, even when every other field looks servable.
    let mut unrecognized_schema = restore_gate_quarantined();
    unrecognized_schema.schema_version = 99;
    unrecognized_schema.covered_by_tombstone = false;
    assert!(unrecognized_schema.outcome().is_err());
    let mut unrecognized_schema_zero = restore_gate_quarantined();
    unrecognized_schema_zero.schema_version = 0;
    assert!(unrecognized_schema_zero.outcome().is_err());
}

#[test]
fn dependent_support_transition_requires_consistent_recompute_list() {
    dependent_transition_unverifiable().validate().unwrap();

    // The mandatory erasure-event binding must not be the zero digest.
    let mut zero_event_id = dependent_transition_unverifiable();
    zero_event_id.erasure_event_id = AcceptedEventId::from_digest(Sha256Digest::ZERO);
    assert!(zero_event_id.validate().is_err());

    // Nor may any individual recompute target be the zero digest.
    let mut zero_recompute_target = dependent_transition_unverifiable();
    zero_recompute_target.recompute_targets =
        vec![AcceptedEventId::from_digest(Sha256Digest::ZERO)];
    assert!(zero_recompute_target.validate().is_err());

    // Isolate `sufficient_redacted_evidence_remains == downgrades` from
    // the recompute-list conjuncts: `next_state` downgrades and
    // `recompute_targets` is non-empty, so both list-consistency
    // conjuncts already pass on their own -- only the direct
    // contradiction between `sufficient_redacted_evidence_remains` and
    // `downgrades` (asserting redacted evidence remains sufficient while
    // simultaneously downgrading support) catches this.
    let mut contradicts_downgrade = dependent_transition_unverifiable();
    assert!(!matches!(
        contradicts_downgrade.next_state,
        SupportVerificationStateV1::Verified
    ));
    assert!(!contradicts_downgrade.recompute_targets.is_empty());
    contradicts_downgrade.sufficient_redacted_evidence_remains = true;
    assert_eq!(
        contradicts_downgrade.validate(),
        Err(ContractError::Schema(
            "invalid dependent support transition".into()
        ))
    );

    // Isolate `!downgrades && !self.recompute_targets.is_empty()` from
    // the contradiction conjunct next to it:
    // `negative-dependent-transition-contradiction.jsonl` cannot do
    // this alone, because it also sets `sufficient_redacted_evidence_
    // remains: false` under `next_state: verified`, which trips
    // `sufficient_redacted_evidence_remains == downgrades` (false ==
    // false) at the same time. Setting `sufficient_redacted_evidence_
    // remains: true` instead makes that half of the disjunction `false`
    // (true == false), so only the non-empty recompute list under a
    // non-downgrading `next_state` is left to explain the rejection.
    let mut verified_with_recompute_targets = dependent_transition_unverifiable();
    verified_with_recompute_targets.next_state = SupportVerificationStateV1::Verified;
    verified_with_recompute_targets.sufficient_redacted_evidence_remains = true;
    assert!(!verified_with_recompute_targets.recompute_targets.is_empty());
    assert_ne!(
        verified_with_recompute_targets.sufficient_redacted_evidence_remains,
        !matches!(
            verified_with_recompute_targets.next_state,
            SupportVerificationStateV1::Verified
        ),
        "the contradiction conjunct must not also be tripped by this fixture"
    );
    assert_eq!(
        verified_with_recompute_targets.validate(),
        Err(ContractError::Schema(
            "invalid dependent support transition".into()
        ))
    );

    let negative_transition: DependentSupportTransitionV1 =
        decode_strict(record(NEGATIVE_DEPENDENT_TRANSITION_CONTRADICTION_FIXTURE)).unwrap();
    // Distinguishing property: this fixture claims `next_state:
    // verified` (support fully intact) while still naming a nonempty
    // recompute list -- a verified proposition has nothing left to
    // recompute.
    assert_eq!(
        negative_transition.next_state,
        SupportVerificationStateV1::Verified
    );
    assert!(!negative_transition.recompute_targets.is_empty());
    assert_eq!(
        negative_transition.validate(),
        Err(ContractError::Schema(
            "invalid dependent support transition".into()
        ))
    );
}

#[test]
fn dependent_support_transition_bounds_and_sorts_recompute_targets() {
    // Two ADJACENT, byte-identical recompute targets -- the shape
    // `strictly_sorted`'s `< -> <=` mutation admits, and simultaneously
    // the shape that neuters `:880`'s `(len > MAX) || !strictly_sorted`
    // if that `||` is mutated to `&&`: with only two targets (well under
    // the cap), the left side of the disjunction is false, so an `&&`
    // mutant would make the whole clause false regardless of sortedness.
    // Every other conjunct passes: `next_state` downgrades, the list is
    // non-empty, no target is the zero digest.
    let mut duplicate_recompute_targets = dependent_transition_unverifiable();
    let one_target = duplicate_recompute_targets.recompute_targets[0];
    duplicate_recompute_targets.recompute_targets = vec![one_target, one_target];
    assert!(!duplicate_recompute_targets.recompute_targets.is_empty());
    assert!(!strictly_sorted(
        &duplicate_recompute_targets.recompute_targets
    ));
    assert_eq!(
        duplicate_recompute_targets.validate(),
        Err(ContractError::Schema(
            "invalid dependent support transition".into()
        ))
    );

    // Isolate `self.recompute_targets.len() > MAX_RECOMPUTE_TARGETS`: a
    // strictly-sorted, otherwise entirely valid transition naming one
    // more recompute target than the cap permits. Kills both `> -> ==`
    // (which would reject only an exact `MAX + 1`-length list, not this
    // over-cap one) and confirms the cap fires at all.
    let mut over_cap_targets = dependent_transition_unverifiable();
    over_cap_targets.recompute_targets = (0..=MAX_RECOMPUTE_TARGETS)
        .map(|index| {
            AcceptedEventId::from_digest(labelled_digest(&format!(
                "dependent-transition.recompute.over.{index:04}"
            )))
        })
        .collect();
    over_cap_targets.recompute_targets.sort();
    assert_eq!(
        over_cap_targets.recompute_targets.len(),
        MAX_RECOMPUTE_TARGETS + 1
    );
    assert!(strictly_sorted(&over_cap_targets.recompute_targets));
    assert_eq!(
        over_cap_targets.validate(),
        Err(ContractError::Schema(
            "invalid dependent support transition".into()
        ))
    );

    // The boundary itself -- exactly `MAX_RECOMPUTE_TARGETS` entries --
    // must still validate, so the rejection above is specifically about
    // exceeding the cap. This also kills `> -> >=`, which would reject
    // this exact-cap fixture.
    let mut at_cap_targets = dependent_transition_unverifiable();
    at_cap_targets.recompute_targets = (0..MAX_RECOMPUTE_TARGETS)
        .map(|index| {
            AcceptedEventId::from_digest(labelled_digest(&format!(
                "dependent-transition.recompute.at.{index:04}"
            )))
        })
        .collect();
    at_cap_targets.recompute_targets.sort();
    assert_eq!(
        at_cap_targets.recompute_targets.len(),
        MAX_RECOMPUTE_TARGETS
    );
    at_cap_targets.validate().unwrap();
}

#[test]
fn checkpoint_rule_requires_a_strictly_higher_generation_and_new_digest() {
    checkpoint_rule().validate().unwrap();
    let negative_rule: CheckpointErasureRuleV1 =
        decode_strict(record(NEGATIVE_CHECKPOINT_SAME_DIGEST_FIXTURE)).unwrap();
    // Distinguishing property: this fixture decodes to a rule whose old
    // and new checkpoint digests are identical -- the "old never
    // advanced in place" invariant made concrete.
    assert_eq!(
        negative_rule.previous_checkpoint_digest,
        negative_rule.new_checkpoint_digest
    );
    assert_eq!(
        negative_rule.validate(),
        Err(ContractError::Schema(
            "invalid checkpoint erasure rule".into()
        ))
    );

    // Zero previous digest, isolated: an otherwise-valid rule (distinct
    // nonzero digests, a strictly advancing generation, the correct
    // schema version) whose `previous_checkpoint_digest` is the zero
    // digest must still fail closed. This is the sole assertion
    // distinguishing `||` from `&&` at the join between the
    // `schema_version` conjunct and this one: under `&&`, a wrong
    // `schema_version` alone would no longer reject (masked unless this
    // conjunct also held), and under the next join's `&&` a zero
    // previous digest alone would no longer reject (masked unless the
    // zero-new-digest conjunct also held) -- so this single fixture
    // kills both adjacent `|| -> &&` mutants.
    let mut zero_previous_digest = checkpoint_rule();
    zero_previous_digest.previous_checkpoint_digest = Sha256Digest::ZERO;
    assert_eq!(
        zero_previous_digest.validate(),
        Err(ContractError::Schema(
            "invalid checkpoint erasure rule".into()
        ))
    );

    // Zero new digest, isolated: mirrors the previous-digest case above
    // so the `new_checkpoint_digest == ZERO` conjunct is pinned in its
    // own right, independent of the zero-previous-digest fixture.
    let mut zero_new_digest = checkpoint_rule();
    zero_new_digest.new_checkpoint_digest = Sha256Digest::ZERO;
    assert_eq!(
        zero_new_digest.validate(),
        Err(ContractError::Schema(
            "invalid checkpoint erasure rule".into()
        ))
    );

    // Unrecognized schema_version, isolated: an otherwise-valid rule
    // under a schema version this module does not recognize must fail
    // closed, independent of every digest/generation conjunct.
    let mut wrong_schema_version = checkpoint_rule();
    wrong_schema_version.schema_version = ERASURE_SCHEMA_VERSION + 1;
    assert_eq!(
        wrong_schema_version.validate(),
        Err(ContractError::Schema(
            "invalid checkpoint erasure rule".into()
        ))
    );
}

/// EVID-01/EVID-09: same-ID-different-bytes forms that survive the
/// fieldless-variant fix above because they do not touch a tagged enum
/// at all. A derived `Deserialize` on a plain struct accepts a
/// well-typed positional JSON array in a nested struct's place exactly
/// as readily as an object, and an `Option` field accepts its wire key
/// whether present-as-`null` or omitted entirely -- so each fixture
/// below decodes under `decode_strict` alone to a value `==` the clean
/// fixture and binds the identical content-addressed identity, exactly
/// the same-ID-different-bytes collision `coverage.rs` documents for
/// `CoverageReceiptV1`. `decode_typed_canonical` is the required
/// ingress gate that closes this, generically, by re-encoding the
/// decoded value and rejecting the input unless the bytes match.
#[test]
fn same_id_different_bytes_forms_decode_under_decode_strict_but_are_rejected_by_decode_typed_canonical()
 {
    // Omitted optional key: `legal-hold-active.jsonl` minus its
    // `"released_at":null` entry.
    let clean_hold_bytes = std::str::from_utf8(record(LEGAL_HOLD_ACTIVE_FIXTURE)).unwrap();
    let omitted_released_at = clean_hold_bytes.replace(r#""released_at":null,"#, "");
    assert_ne!(omitted_released_at, clean_hold_bytes);
    require_canonical(omitted_released_at.as_bytes()).unwrap_or_else(|error| {
        panic!("omitted released_at: expected a canonical document, got {error:?}")
    });
    let decoded_hold: LegalHoldV1 =
        decode_strict(omitted_released_at.as_bytes()).unwrap_or_else(|error| {
            panic!("omitted released_at: expected decode_strict to accept, got {error:?}")
        });
    assert_eq!(decoded_hold, legal_hold_active());
    decoded_hold.validate().unwrap();
    assert_eq!(
        decoded_hold.hold_id().unwrap(),
        legal_hold_active().hold_id().unwrap(),
        "must bind the identical hold_id under decode_strict alone"
    );
    assert_eq!(
        decode_typed_canonical::<LegalHoldV1>(omitted_released_at.as_bytes()),
        Err(ContractError::NotCanonical)
    );

    // Omitted optional key: `erasure-tombstone-with-metadata.jsonl`
    // minus its `,"superseded_by":null` entry.
    let clean_tombstone_bytes =
        std::str::from_utf8(record(TOMBSTONE_WITH_METADATA_FIXTURE)).unwrap();
    let omitted_superseded_by = clean_tombstone_bytes.replace(r#","superseded_by":null"#, "");
    assert_ne!(omitted_superseded_by, clean_tombstone_bytes);
    require_canonical(omitted_superseded_by.as_bytes()).unwrap_or_else(|error| {
        panic!("omitted superseded_by: expected a canonical document, got {error:?}")
    });
    let decoded_tombstone: ErasureTombstoneV1 = decode_strict(omitted_superseded_by.as_bytes())
        .unwrap_or_else(|error| {
            panic!("omitted superseded_by: expected decode_strict to accept, got {error:?}")
        });
    assert_eq!(decoded_tombstone, tombstone_with_metadata());
    decoded_tombstone.validate().unwrap();
    assert_eq!(
        decoded_tombstone.tombstone_id().unwrap(),
        tombstone_with_metadata().tombstone_id().unwrap(),
        "must bind the identical tombstone_id under decode_strict alone"
    );
    assert_eq!(
        decode_typed_canonical::<ErasureTombstoneV1>(omitted_superseded_by.as_bytes()),
        Err(ContractError::NotCanonical)
    );

    // Positional-array form of a nested struct: `erasure-fence-genesis
    // .jsonl` with its `privacy_subject` entry rewritten from
    // `{"epoch":0,"kind":"privacy_subject"}` (field order: `kind`, then
    // `epoch`) to `["privacy_subject",0]`.
    let clean_fence_bytes = std::str::from_utf8(record(FENCE_GENESIS_FIXTURE)).unwrap();
    let positional_fence = clean_fence_bytes.replace(
        r#"{"epoch":0,"kind":"privacy_subject"}"#,
        r#"["privacy_subject",0]"#,
    );
    assert_ne!(positional_fence, clean_fence_bytes);
    require_canonical(positional_fence.as_bytes()).unwrap_or_else(|error| {
        panic!("positional fence entry: expected a canonical document, got {error:?}")
    });
    let decoded_fence: ErasureFenceV1 =
        decode_strict(positional_fence.as_bytes()).unwrap_or_else(|error| {
            panic!("positional fence entry: expected decode_strict to accept, got {error:?}")
        });
    assert_eq!(decoded_fence, genesis_fence());
    decoded_fence.validate().unwrap();
    assert_eq!(
        decoded_fence.fence_id().unwrap(),
        genesis_fence().fence_id().unwrap(),
        "must bind the identical fence_id under decode_strict alone"
    );
    assert_eq!(
        decode_typed_canonical::<ErasureFenceV1>(positional_fence.as_bytes()),
        Err(ContractError::NotCanonical)
    );
}

/// EVID-01: every fixture in the directory that decodes at all --
/// positive and negative alike -- must decode through the required
/// `decode_typed_canonical` ingress gate the module doc comment names,
/// not merely through `require_canonical` (which
/// `hard_coded_contract_vectors_match_independent_ids` already proves
/// for every fixture). `negative-tombstone-payload-bytes.jsonl` is the
/// sole exception: it does not decode as `ErasureTombstoneV1` under
/// plain `decode_strict` either, and `decode_typed_canonical` must
/// refuse it too, since it delegates to `decode_strict` first.
#[test]
#[allow(clippy::too_many_lines)]
fn every_decodable_fixture_decodes_through_the_typed_canonical_gate() {
    for bytes in [
        ERASURE_EVENT_FIXTURE,
        ERASURE_EVENT_PRIVACY_SUBJECT_FIXTURE,
        NEGATIVE_EVENT_EFFECTIVE_BEFORE_POLICY_FIXTURE,
    ] {
        decode_typed_canonical::<ErasureEventV1>(record(bytes)).unwrap();
    }
    for bytes in [
        TOMBSTONE_DIGEST_ONLY_FIXTURE,
        TOMBSTONE_WITH_METADATA_FIXTURE,
    ] {
        decode_typed_canonical::<ErasureTombstoneV1>(record(bytes)).unwrap();
    }
    assert!(
        decode_typed_canonical::<ErasureTombstoneV1>(record(
            NEGATIVE_TOMBSTONE_PAYLOAD_BYTES_FIXTURE
        ))
        .is_err()
    );
    for bytes in [
        FENCE_GENESIS_FIXTURE,
        FENCE_ADVANCED_FIXTURE,
        FENCE_GENERATION_ONLY_ADVANCE_FIXTURE,
        FENCE_PRIVACY_SUBJECT_ONLY_ADVANCE_FIXTURE,
        FENCE_REPRESENTATION_ONLY_ADVANCE_FIXTURE,
        NEGATIVE_FENCE_MISSING_SCOPE_FIXTURE,
    ] {
        decode_typed_canonical::<ErasureFenceV1>(record(bytes)).unwrap();
    }
    for bytes in [
        RECEIPT_PENDING_FIXTURE,
        RECEIPT_COMPLETE_FIXTURE,
        NEGATIVE_RECEIPT_COMPLETE_WITH_RESIDUAL_FIXTURE,
        NEGATIVE_RECEIPT_COMPLETE_RESIDUAL_DESPITE_KEY_DESTROYED_FIXTURE,
    ] {
        decode_typed_canonical::<ErasureReceiptV1>(record(bytes)).unwrap();
    }
    for bytes in [
        LEGAL_HOLD_ACTIVE_FIXTURE,
        NEGATIVE_LEGAL_HOLD_PUBLICATION_VISIBILITY_FIXTURE,
    ] {
        decode_typed_canonical::<LegalHoldV1>(record(bytes)).unwrap();
    }
    decode_typed_canonical::<RetainableMatcherPolicyV1>(record(
        RETAINABLE_MATCHER_FORBIDDEN_FIXTURE,
    ))
    .unwrap();
    decode_typed_canonical::<RestoreGateV1>(record(RESTORE_GATE_QUARANTINED_FIXTURE)).unwrap();
    for bytes in [
        DEPENDENT_TRANSITION_UNVERIFIABLE_FIXTURE,
        NEGATIVE_DEPENDENT_TRANSITION_CONTRADICTION_FIXTURE,
    ] {
        decode_typed_canonical::<DependentSupportTransitionV1>(record(bytes)).unwrap();
    }
    for bytes in [
        CHECKPOINT_RULE_FIXTURE,
        NEGATIVE_CHECKPOINT_SAME_DIGEST_FIXTURE,
    ] {
        decode_typed_canonical::<CheckpointErasureRuleV1>(record(bytes)).unwrap();
    }
    decode_typed_canonical::<ErasureVectorSuiteV1>(record(VECTOR_SUITE_FIXTURE)).unwrap();
}

#[test]
#[allow(clippy::too_many_lines)]
fn hard_coded_contract_vectors_match_independent_ids() {
    for (bytes, expected_raw_sha256) in [
        (ERASURE_EVENT_FIXTURE, EVENT_RAW_SHA256),
        (
            ERASURE_EVENT_PRIVACY_SUBJECT_FIXTURE,
            EVENT_PRIVACY_SUBJECT_RAW_SHA256,
        ),
        (
            TOMBSTONE_DIGEST_ONLY_FIXTURE,
            TOMBSTONE_DIGEST_ONLY_RAW_SHA256,
        ),
        (
            TOMBSTONE_WITH_METADATA_FIXTURE,
            TOMBSTONE_WITH_METADATA_RAW_SHA256,
        ),
        (FENCE_GENESIS_FIXTURE, FENCE_GENESIS_RAW_SHA256),
        (FENCE_ADVANCED_FIXTURE, FENCE_ADVANCED_RAW_SHA256),
        (
            FENCE_GENERATION_ONLY_ADVANCE_FIXTURE,
            FENCE_GENERATION_ONLY_ADVANCE_RAW_SHA256,
        ),
        (
            FENCE_PRIVACY_SUBJECT_ONLY_ADVANCE_FIXTURE,
            FENCE_PRIVACY_SUBJECT_ONLY_ADVANCE_RAW_SHA256,
        ),
        (
            FENCE_REPRESENTATION_ONLY_ADVANCE_FIXTURE,
            FENCE_REPRESENTATION_ONLY_ADVANCE_RAW_SHA256,
        ),
        (RECEIPT_PENDING_FIXTURE, RECEIPT_PENDING_RAW_SHA256),
        (RECEIPT_COMPLETE_FIXTURE, RECEIPT_COMPLETE_RAW_SHA256),
        (LEGAL_HOLD_ACTIVE_FIXTURE, LEGAL_HOLD_ACTIVE_RAW_SHA256),
        (
            RETAINABLE_MATCHER_FORBIDDEN_FIXTURE,
            RETAINABLE_MATCHER_FORBIDDEN_RAW_SHA256,
        ),
        (
            RESTORE_GATE_QUARANTINED_FIXTURE,
            RESTORE_GATE_QUARANTINED_RAW_SHA256,
        ),
        (
            DEPENDENT_TRANSITION_UNVERIFIABLE_FIXTURE,
            DEPENDENT_TRANSITION_UNVERIFIABLE_RAW_SHA256,
        ),
        (CHECKPOINT_RULE_FIXTURE, CHECKPOINT_RULE_RAW_SHA256),
        (VECTOR_SUITE_FIXTURE, VECTOR_SUITE_RAW_SHA256),
        (
            NEGATIVE_TOMBSTONE_PAYLOAD_BYTES_FIXTURE,
            NEGATIVE_TOMBSTONE_PAYLOAD_BYTES_RAW_SHA256,
        ),
        (
            NEGATIVE_RECEIPT_COMPLETE_WITH_RESIDUAL_FIXTURE,
            NEGATIVE_RECEIPT_COMPLETE_WITH_RESIDUAL_RAW_SHA256,
        ),
        (
            NEGATIVE_RECEIPT_COMPLETE_RESIDUAL_DESPITE_KEY_DESTROYED_FIXTURE,
            NEGATIVE_RECEIPT_COMPLETE_RESIDUAL_DESPITE_KEY_DESTROYED_RAW_SHA256,
        ),
        (
            NEGATIVE_FENCE_MISSING_SCOPE_FIXTURE,
            NEGATIVE_FENCE_MISSING_SCOPE_RAW_SHA256,
        ),
        (
            NEGATIVE_EVENT_EFFECTIVE_BEFORE_POLICY_FIXTURE,
            NEGATIVE_EVENT_EFFECTIVE_BEFORE_POLICY_RAW_SHA256,
        ),
        (
            NEGATIVE_LEGAL_HOLD_PUBLICATION_VISIBILITY_FIXTURE,
            NEGATIVE_LEGAL_HOLD_PUBLICATION_VISIBILITY_RAW_SHA256,
        ),
        (
            NEGATIVE_CHECKPOINT_SAME_DIGEST_FIXTURE,
            NEGATIVE_CHECKPOINT_SAME_DIGEST_RAW_SHA256,
        ),
        (
            NEGATIVE_DEPENDENT_TRANSITION_CONTRADICTION_FIXTURE,
            NEGATIVE_DEPENDENT_TRANSITION_CONTRADICTION_RAW_SHA256,
        ),
    ] {
        assert_eq!(raw_sha256(bytes), expected_raw_sha256);
    }

    for bytes in [
        ERASURE_EVENT_FIXTURE,
        ERASURE_EVENT_PRIVACY_SUBJECT_FIXTURE,
        TOMBSTONE_DIGEST_ONLY_FIXTURE,
        TOMBSTONE_WITH_METADATA_FIXTURE,
        FENCE_GENESIS_FIXTURE,
        FENCE_ADVANCED_FIXTURE,
        FENCE_GENERATION_ONLY_ADVANCE_FIXTURE,
        FENCE_PRIVACY_SUBJECT_ONLY_ADVANCE_FIXTURE,
        FENCE_REPRESENTATION_ONLY_ADVANCE_FIXTURE,
        RECEIPT_PENDING_FIXTURE,
        RECEIPT_COMPLETE_FIXTURE,
        LEGAL_HOLD_ACTIVE_FIXTURE,
        RETAINABLE_MATCHER_FORBIDDEN_FIXTURE,
        RESTORE_GATE_QUARANTINED_FIXTURE,
        DEPENDENT_TRANSITION_UNVERIFIABLE_FIXTURE,
        CHECKPOINT_RULE_FIXTURE,
        VECTOR_SUITE_FIXTURE,
        NEGATIVE_TOMBSTONE_PAYLOAD_BYTES_FIXTURE,
        NEGATIVE_RECEIPT_COMPLETE_WITH_RESIDUAL_FIXTURE,
        NEGATIVE_RECEIPT_COMPLETE_RESIDUAL_DESPITE_KEY_DESTROYED_FIXTURE,
        NEGATIVE_FENCE_MISSING_SCOPE_FIXTURE,
        NEGATIVE_EVENT_EFFECTIVE_BEFORE_POLICY_FIXTURE,
        NEGATIVE_LEGAL_HOLD_PUBLICATION_VISIBILITY_FIXTURE,
        NEGATIVE_CHECKPOINT_SAME_DIGEST_FIXTURE,
        NEGATIVE_DEPENDENT_TRANSITION_CONTRADICTION_FIXTURE,
    ] {
        require_canonical(record(bytes)).unwrap();
    }

    assert_eq!(
        encode_canonical(&event_representation()).unwrap(),
        record(ERASURE_EVENT_FIXTURE)
    );
    assert_eq!(
        encode_canonical(&event_privacy_subject()).unwrap(),
        record(ERASURE_EVENT_PRIVACY_SUBJECT_FIXTURE)
    );
    assert_eq!(
        encode_canonical(&tombstone_digest_only()).unwrap(),
        record(TOMBSTONE_DIGEST_ONLY_FIXTURE)
    );
    assert_eq!(
        encode_canonical(&tombstone_with_metadata()).unwrap(),
        record(TOMBSTONE_WITH_METADATA_FIXTURE)
    );
    assert_eq!(
        encode_canonical(&genesis_fence()).unwrap(),
        record(FENCE_GENESIS_FIXTURE)
    );
    assert_eq!(
        encode_canonical(&advanced_fence()).unwrap(),
        record(FENCE_ADVANCED_FIXTURE)
    );
    assert_eq!(
        encode_canonical(&fence_generation_only_advance()).unwrap(),
        record(FENCE_GENERATION_ONLY_ADVANCE_FIXTURE)
    );
    assert_eq!(
        encode_canonical(&fence_privacy_subject_only_advance()).unwrap(),
        record(FENCE_PRIVACY_SUBJECT_ONLY_ADVANCE_FIXTURE)
    );
    assert_eq!(
        encode_canonical(&fence_representation_only_advance()).unwrap(),
        record(FENCE_REPRESENTATION_ONLY_ADVANCE_FIXTURE)
    );
    assert_eq!(
        encode_canonical(&receipt_pending()).unwrap(),
        record(RECEIPT_PENDING_FIXTURE)
    );
    assert_eq!(
        encode_canonical(&receipt_complete()).unwrap(),
        record(RECEIPT_COMPLETE_FIXTURE)
    );
    assert_eq!(
        encode_canonical(&legal_hold_active()).unwrap(),
        record(LEGAL_HOLD_ACTIVE_FIXTURE)
    );
    assert_eq!(
        encode_canonical(&retainable_matcher_forbidden()).unwrap(),
        record(RETAINABLE_MATCHER_FORBIDDEN_FIXTURE)
    );
    assert_eq!(
        encode_canonical(&restore_gate_quarantined()).unwrap(),
        record(RESTORE_GATE_QUARANTINED_FIXTURE)
    );
    assert_eq!(
        encode_canonical(&dependent_transition_unverifiable()).unwrap(),
        record(DEPENDENT_TRANSITION_UNVERIFIABLE_FIXTURE)
    );
    assert_eq!(
        encode_canonical(&checkpoint_rule()).unwrap(),
        record(CHECKPOINT_RULE_FIXTURE)
    );
    assert_eq!(
        encode_canonical(&vector_suite()).unwrap(),
        record(VECTOR_SUITE_FIXTURE)
    );

    let event_id = event_representation().accepted_event_id().unwrap();
    let event_privacy_subject_id = event_privacy_subject().accepted_event_id().unwrap();
    assert_eq!(event_id.digest(), digest(EVENT_ACCEPTED_EVENT_ID));
    assert_eq!(
        event_privacy_subject_id.digest(),
        digest(EVENT_PRIVACY_SUBJECT_ACCEPTED_EVENT_ID)
    );
    assert_ne!(event_id, event_privacy_subject_id);

    let suite: ErasureVectorSuiteV1 = decode_strict(record(VECTOR_SUITE_FIXTURE)).unwrap();
    suite.validate().unwrap();
    assert_eq!(suite, vector_suite());
}
