//! Connected proof for the discrepancy ledger runtime (W3-DISC, Stage 6).
//!
//! Set `FLEET_RECALL_TEST_DATABASE_URL` to a disposable `CockroachDB` 26.2
//! database. Every test here is inert otherwise. Nothing in this file starts
//! a database process, invokes Docker, or targets a cloud service.
//!
//! These tests exercise the real runtime against migration 0027's four
//! tables and reproduce, at the DB level, exactly the definition of done:
//! * an envelope is admitted, lifecycle events append, and the projection is
//!   durable — and a rebuild from the database alone reproduces the stored
//!   projection byte for byte;
//! * replayed appends are idempotent, never double-applied;
//! * receipt order does not move the projection: the same events ingested in
//!   a different order (a late event arriving last) leave byte-identical
//!   stored projections;
//! * per-detection identity is immutable: a divergent envelope for a seeded
//!   episode is refused;
//! * fail-closed paths write nothing: an event without an envelope, a
//!   self-implicated dismissal (AUTH-03), a foreign-scope payload, and a
//!   cross-family relation are all refused;
//! * a superseding relation freezes its source episode's projection.
//!
//! The ledger tables are keyed by the trusted `(tenant, project)` pair; a
//! fresh unique physical scope per test isolates them. The semantic scope is
//! decoded from the frozen v1 bootstrap-receipt fixture — the discrepancy
//! runtime is a standalone projector bound to scope and to an already-active
//! registry head, so no genesis/successor ceremony is needed here.

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use ostk_fleet_recall::FleetScope;
use ostk_fleet_recall::control_log::TrustedControlScope;
use ostk_fleet_recall::discrepancy_runtime::{
    CockroachDiscrepancyLedgerRepository, DiscrepancyAppendOutcomeV1,
    DiscrepancyEnvelopeCandidateV1, DiscrepancyLedgerRepository, DiscrepancyRegistryBindingV1,
};
use ostk_fleet_recall::memory_contracts::bootstrap::BootstrapReceiptV1;
use ostk_fleet_recall::memory_contracts::canonical::{
    CanonicalValue, decode_strict, encode_canonical,
};
use ostk_fleet_recall::memory_contracts::common::{
    AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, RegistryReferenceV1,
    frozen_profile_reference_v1,
};
use ostk_fleet_recall::memory_contracts::digest::{
    DigestDomain, Sha256Digest, domain_separated_digest,
};
use ostk_fleet_recall::memory_contracts::discrepancy::{
    ApplicabilityDimensionV1, ApplicabilityDimensionValueV1, CardinalityAlgebraV1,
    ComparatorLineageRegistrationV1, ComparatorLineageV1, DiscrepancyActorV1,
    DiscrepancyEnvelopeV1, DiscrepancyEpisodeFingerprintV1, DiscrepancyEpisodePreimageV1,
    DiscrepancyEpisodeRelationV1, DiscrepancyFamilyFingerprintV1, DiscrepancyFamilyPreimageV1,
    DiscrepancyLifecycleEventV1, DiscrepancySeverityV1, DismissalReasonKindV1, DismissalReasonV1,
    EffectiveIntervalRuleV1, EpisodeClosingRuleV1, EpisodeOpeningRuleV1, EpisodePolicyV2,
    EpisodeRelationKindV1, EpisodeWindowingV1, FindingType, LateEvidenceBehaviorV1, LifecycleState,
    LifecycleTransitionV1, ModalityCompatibilityRuleV1, OpeningTransitionCandidateV1,
    PolarityRuleV1, RuleChangeBehaviorV1, StructurallyResolvedComparatorLineageV1,
    StructurallyResolvedEpisodePolicyV2, VerificationState, WaiverReasonKindV1, WaiverRecordV1,
};
use ostk_fleet_recall::memory_contracts::evidence::{AcceptedEventId, SourceFactId};
use ostk_fleet_recall::memory_contracts::evidence_v2::RegistryHeadBindingV1;
use ostk_fleet_recall::memory_contracts::genesis::PropositionModalityV1;
use ostk_fleet_recall::memory_contracts::identity::ResourceUri;
use ostk_fleet_recall::memory_contracts::registry::{
    RegistryEntryKind, RegistryEntryV1, RegistryHeadV1,
};
use ostk_fleet_recall::store::cockroach::{CockroachStore, PoolConfig, RetryPolicy};
use ostk_recall_core::PrivacyTier;
use sqlx::PgPool;
use tokio::sync::Mutex;
use uuid::Uuid;

const BOOTSTRAP_RECEIPT: &[u8] =
    include_bytes!("../contracts/dynamic-memory/v1/bootstrap-receipt.jsonl");

/// The schema is shared, so migration is serialized and runs once per process.
static MIGRATED: Mutex<bool> = Mutex::const_new(false);

fn record(artifact: &'static [u8]) -> &'static [u8] {
    artifact
        .strip_suffix(b"\n")
        .expect("contract JSONL must have exactly one framing LF")
}

fn label(value: &str) -> Sha256Digest {
    domain_separated_digest(DigestDomain::RegistryEntry, value.as_bytes())
}

fn digest(value: &str) -> Sha256Digest {
    Sha256Digest::from_str(value).unwrap()
}

fn timestamp(value: &str) -> CanonicalTimestamp {
    CanonicalTimestamp::parse(value).expect("fixture timestamp must be canonical")
}

fn semantic_scope() -> AuthenticatedProjectScopeV1 {
    let receipt: BootstrapReceiptV1 = decode_strict(record(BOOTSTRAP_RECEIPT)).unwrap();
    receipt.statement.scope
}

fn physical_scope(name: &str) -> FleetScope {
    FleetScope::new(
        Uuid::now_v7(),
        format!("discrepancy-ledger-{name}-{}", Uuid::now_v7()),
        "discrepancy-ledger-connected-test",
        None,
        PrivacyTier::T1Project,
    )
    .expect("connected-test scope must be valid")
}

const fn retry_policy() -> RetryPolicy {
    RetryPolicy {
        max_attempts: 24,
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(60),
    }
}

async fn live_pool(database_url: &str) -> PgPool {
    let store = CockroachStore::connect(
        database_url,
        physical_scope("pool"),
        PoolConfig {
            max_connections: 10,
            ..PoolConfig::default()
        },
    )
    .await
    .expect("connected test must reach the disposable database");
    {
        let mut migrated = MIGRATED.lock().await;
        if !*migrated {
            store.migrate().await.expect("migration prefix must apply");
            *migrated = true;
        }
    }
    store.pool().clone()
}

fn registry_binding() -> DiscrepancyRegistryBindingV1 {
    DiscrepancyRegistryBindingV1 {
        registry_package_digest: label("registry-package"),
        activation_policy_digest: label("activation-policy"),
    }
}

fn registry_head_binding() -> RegistryHeadBindingV1 {
    RegistryHeadBindingV1 {
        head: RegistryHeadV1 {
            activation_id: label("activation"),
            package_digest: registry_binding().registry_package_digest,
            activation_policy_digest: registry_binding().activation_policy_digest,
        },
        effective_from: timestamp("2026-01-01T00:00:00.000000000Z"),
        effective_until: None,
    }
}

fn resource(form: &str, kind: &str, digit: char) -> ResourceUri {
    format!(
        "urn:ostk:{form}:v1:{kind}:sha256:{}",
        digit.to_string().repeat(64)
    )
    .parse()
    .unwrap()
}

fn source_fact_id(digit: char) -> SourceFactId {
    SourceFactId::from_digest(digest(&digit.to_string().repeat(64)))
}

fn evidence_id(digit: char) -> AcceptedEventId {
    AcceptedEventId::from_digest(digest(&digit.to_string().repeat(64)))
}

fn reference(id: &str, digest_hex: &str) -> RegistryReferenceV1 {
    RegistryReferenceV1 {
        entry_id: ContractId::new(id).unwrap(),
        version: 1,
        entry_digest: digest(digest_hex),
    }
}

fn comparator_lineage() -> ComparatorLineageV1 {
    ComparatorLineageV1 {
        schema_version: 1,
        comparator_id: ContractId::new("comparator.exact_value_v1").unwrap(),
        comparator_version: 1,
        cardinality: CardinalityAlgebraV1::Functional,
        polarity_rule: PolarityRuleV1::AffirmationNegationConflictOnSameValue,
        modality_compatibility: vec![ModalityCompatibilityRuleV1 {
            left: PropositionModalityV1::Attested,
            right: PropositionModalityV1::Normative,
        }],
        concrete_applicability_required: true,
        effective_interval_rule: EffectiveIntervalRuleV1::OverlapRequired,
        coverage_proof_required: false,
    }
}

fn episode_policy() -> EpisodePolicyV2 {
    EpisodePolicyV2 {
        schema_version: 1,
        policy_id: ContractId::new("episode.non_windowed_state_v1").unwrap(),
        version: 1,
        continuity_key_dimension_ids: vec![ContractId::new("runtime_environment").unwrap()],
        windowing: EpisodeWindowingV1::NonWindowed,
        opening_rule: EpisodeOpeningRuleV1::FirstVerifiedIncompatibleObservation,
        allowed_observation_gap_seconds: Some(3_600),
        closing_rule: EpisodeClosingRuleV1::VerifiedCompatibleSupersessionOrScopeExit,
        rule_change_behavior: RuleChangeBehaviorV1::NewFamilyLinkedBySupersession,
        late_evidence_behavior: LateEvidenceBehaviorV1::EffectiveIntervalReplayWithSupersession,
    }
}

fn resolved_episode_policy() -> StructurallyResolvedEpisodePolicyV2 {
    let policy = episode_policy();
    let body_bytes = encode_canonical(&policy).unwrap();
    let body: CanonicalValue = decode_strict(&body_bytes).unwrap();
    let entry = RegistryEntryV1 {
        schema_version: 1,
        kind: RegistryEntryKind::EpisodePolicy,
        entry_id: policy.policy_id.clone(),
        version: policy.version,
        entry_schema_id: ContractId::new("registry.episode_policy").unwrap(),
        entry_schema_version: 1,
        body,
        positive_vector_digest: digest(&"a".repeat(64)),
        negative_vector_digest: digest(&"b".repeat(64)),
    };
    StructurallyResolvedEpisodePolicyV2::from_registry_entry(&entry).unwrap()
}

fn resolved_comparator_lineage() -> StructurallyResolvedComparatorLineageV1 {
    let registration = ComparatorLineageRegistrationV1 {
        schema_version: 1,
        lineage: comparator_lineage(),
        required_applicability_dimension_ids: vec![ContractId::new("runtime_environment").unwrap()],
    };
    let body_bytes = encode_canonical(&registration).unwrap();
    let body: CanonicalValue = decode_strict(&body_bytes).unwrap();
    let entry = RegistryEntryV1 {
        schema_version: 1,
        kind: RegistryEntryKind::ComparatorLineage,
        entry_id: registration.lineage.comparator_id.clone(),
        version: registration.lineage.comparator_version,
        entry_schema_id: ContractId::new("registry.comparator_lineage").unwrap(),
        entry_schema_version: 1,
        body,
        positive_vector_digest: digest(&"c".repeat(64)),
        negative_vector_digest: digest(&"d".repeat(64)),
    };
    StructurallyResolvedComparatorLineageV1::from_registry_entry(&entry).unwrap()
}

fn applicability() -> Vec<ApplicabilityDimensionV1> {
    vec![
        ApplicabilityDimensionV1 {
            dimension_id: ContractId::new("repository_commit").unwrap(),
            value: ApplicabilityDimensionValueV1::Concrete {
                resource: resource("version", "commit", '3'),
            },
        },
        ApplicabilityDimensionV1 {
            dimension_id: ContractId::new("runtime_environment").unwrap(),
            value: ApplicabilityDimensionValueV1::Concrete {
                resource: resource("entity", "environment", '4'),
            },
        },
    ]
}

/// A shape-valid envelope for the bootstrap semantic scope, bound to the
/// exact resolved policy and lineage this file registers. `opening_digit`
/// picks the opening-transition source fact, so distinct digits mint
/// distinct episodes within one family.
fn envelope(opening_digit: char) -> DiscrepancyEnvelopeV1 {
    let scope = semantic_scope();
    let lineage = resolved_comparator_lineage();
    let policy = resolved_episode_policy();
    let lineage_fingerprint = lineage.lineage().fingerprint().unwrap();
    let required_applicability_dimension_ids =
        lineage.required_applicability_dimension_ids().to_vec();
    let continuity_key_dimension_ids = policy.policy().continuity_key_dimension_ids.clone();
    let episode_policy_reference = policy.registry_reference().clone();
    let expectation_policy = reference(
        "policy.database_choice_v1",
        "d0b7d4e7b630ce599389e50948541e21b4aa24d4d030860f6cfcaf7508d49df4",
    );
    let predicate = reference(
        "predicate.database_choice_v1",
        "36660875b3d71595ccb4b5dfbc17c4c0fe546eec0fa4b8da6a63b17fec074586",
    );
    let detector = reference(
        "detector.claim_conflict_v1",
        "8a12f99ff35969845f08f9b64cee7d86fa42dc6165ebc617d950be8960b86111",
    );
    let opening_transition = OpeningTransitionCandidateV1 {
        effective_at: timestamp("2026-08-15T04:05:00.000000000Z"),
        provider_order: 0,
        source_fact_id: source_fact_id(opening_digit),
    };
    let family_fingerprint = DiscrepancyFamilyPreimageV1 {
        schema_version: 1,
        profile: frozen_profile_reference_v1(),
        scope: scope.clone(),
        finding_type: FindingType::ClaimConflict,
        canonical_subject: resource("entity", "repository", '1'),
        predicate: predicate.clone(),
        comparator_lineage_fingerprint: lineage_fingerprint,
        expectation_policy: expectation_policy.clone(),
        required_applicability_dimension_ids: required_applicability_dimension_ids.clone(),
        applicability: applicability(),
        episode_policy_version: episode_policy_reference.version,
    }
    .fingerprint()
    .unwrap();
    let episode_fingerprint = DiscrepancyEpisodePreimageV1 {
        schema_version: 1,
        family_fingerprint,
        continuity_key: vec![applicability()[1].clone()],
        opening_transition_source_fact_id: opening_transition.source_fact_id,
        episode_policy_version: episode_policy_reference.version,
    }
    .fingerprint()
    .unwrap();
    DiscrepancyEnvelopeV1 {
        schema_version: 1,
        event_kind: ContractId::new("discrepancy.envelope.accepted").unwrap(),
        profile: frozen_profile_reference_v1(),
        scope,
        finding_type: FindingType::ClaimConflict,
        severity: DiscrepancySeverityV1::Medium,
        canonical_subject: resource("entity", "repository", '1'),
        predicate,
        comparator_lineage_fingerprint: lineage_fingerprint,
        expectation_policy,
        episode_policy: episode_policy_reference,
        required_applicability_dimension_ids,
        applicability: applicability(),
        continuity_key_dimension_ids,
        family_fingerprint,
        opening_transition,
        episode_fingerprint,
        registry: registry_head_binding(),
        detector,
        extractor: None,
        member_evidence_ids: vec![evidence_id('6'), evidence_id('7')],
        supporting_evidence_ids: vec![evidence_id('8')],
        opposing_evidence_ids: vec![],
        coverage_receipt_ids: vec![],
        implicated_actor_ids: vec![
            ContractId::new("principal.author_a").unwrap(),
            ContractId::new("principal.author_b").unwrap(),
        ],
        initial_verification_state: VerificationState::Candidate,
        detected_at: timestamp("2026-08-15T04:06:00.000000000Z"),
        effective_from: timestamp("2026-08-15T04:05:00.000000000Z"),
        effective_until: None,
    }
}

fn candidate(envelope: DiscrepancyEnvelopeV1) -> DiscrepancyEnvelopeCandidateV1 {
    DiscrepancyEnvelopeCandidateV1 {
        envelope,
        resolved_episode_policy: resolved_episode_policy(),
        resolved_comparator_lineage: resolved_comparator_lineage(),
    }
}

fn lifecycle_event(
    target: &DiscrepancyEnvelopeV1,
    effective_at: &str,
    transition: LifecycleTransitionV1,
    evidence_digit: char,
) -> DiscrepancyLifecycleEventV1 {
    DiscrepancyLifecycleEventV1 {
        schema_version: 1,
        event_kind: ContractId::new("discrepancy.lifecycle.accepted").unwrap(),
        profile: target.profile.clone(),
        scope: target.scope.clone(),
        episode_fingerprint: target.episode_fingerprint,
        effective_at: timestamp(effective_at),
        verification_update: None,
        lifecycle_transition: Some(transition),
        evidence_event_ids: vec![evidence_id(evidence_digit)],
    }
}

fn acknowledge_event(
    target: &DiscrepancyEnvelopeV1,
    effective_at: &str,
) -> DiscrepancyLifecycleEventV1 {
    lifecycle_event(
        target,
        effective_at,
        LifecycleTransitionV1::Acknowledge {
            actor: DiscrepancyActorV1 {
                principal_id: ContractId::new("principal.on_call").unwrap(),
            },
        },
        '9',
    )
}

fn waive_event(
    target: &DiscrepancyEnvelopeV1,
    effective_at: &str,
    expiry_at: &str,
) -> DiscrepancyLifecycleEventV1 {
    lifecycle_event(
        target,
        effective_at,
        LifecycleTransitionV1::Waive {
            waiver: WaiverRecordV1 {
                actor: DiscrepancyActorV1 {
                    principal_id: ContractId::new("principal.on_call").unwrap(),
                },
                reason_kind: WaiverReasonKindV1::CapacityDeferred,
                rationale: "capacity deferred to next sprint".into(),
                applicability_scope: vec![],
                expiry_at: timestamp(expiry_at),
                review_by: None,
            },
        },
        'a',
    )
}

fn dismiss_event(
    target: &DiscrepancyEnvelopeV1,
    effective_at: &str,
    actor_id: &str,
) -> DiscrepancyLifecycleEventV1 {
    lifecycle_event(
        target,
        effective_at,
        LifecycleTransitionV1::Dismiss {
            actor: DiscrepancyActorV1 {
                principal_id: ContractId::new(actor_id).unwrap(),
            },
            reason: DismissalReasonV1 {
                kind: DismissalReasonKindV1::NotReproducible,
                rationale: "unable to reproduce after three attempts".into(),
            },
        },
        'c',
    )
}

/// One live ledger bound to a unique physical scope.
fn ledger(pool: &PgPool, name: &str) -> Arc<CockroachDiscrepancyLedgerRepository> {
    let physical = physical_scope(name);
    let trusted = TrustedControlScope::from_trusted_context(&physical, semantic_scope()).unwrap();
    Arc::new(
        CockroachDiscrepancyLedgerRepository::new(
            pool.clone(),
            trusted,
            registry_binding(),
            retry_policy(),
        )
        .expect("bound registry head must be non-zero"),
    )
}

fn assert_appended(
    outcome: &DiscrepancyAppendOutcomeV1,
    expected_seq: Option<u64>,
) -> Sha256Digest {
    match outcome {
        DiscrepancyAppendOutcomeV1::Appended(transition) => {
            assert_eq!(transition.log_seq, expected_seq);
            transition.record_id
        }
        DiscrepancyAppendOutcomeV1::AlreadyRecorded { .. } => {
            panic!("expected a fresh append, got AlreadyRecorded")
        }
    }
}

// --- the definition-of-done round trip ---

#[tokio::test]
async fn live_envelope_admission_is_durable_and_projection_reloads_identically() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let repository = ledger(&pool, "roundtrip");
    let detection = envelope('5');

    let outcome = repository
        .admit_envelope(&candidate(detection.clone()))
        .await
        .unwrap();
    assert_appended(&outcome, Some(1));

    let ack = acknowledge_event(&detection, "2026-08-15T05:00:00.000000000Z");
    let waive = waive_event(
        &detection,
        "2026-08-15T05:10:00.000000000Z",
        "2026-09-01T00:00:00.000000000Z",
    );
    assert_appended(
        &repository.append_lifecycle_event(&ack).await.unwrap(),
        Some(2),
    );
    assert_appended(
        &repository.append_lifecycle_event(&waive).await.unwrap(),
        Some(3),
    );

    // The envelope reloads exactly as admitted.
    let reloaded = repository
        .read_envelope(detection.episode_fingerprint)
        .await
        .unwrap()
        .expect("an admitted envelope must be durable");
    assert_eq!(reloaded, detection);

    // The stored projection reflects the full replay...
    let stored = repository
        .read_projection(detection.episode_fingerprint)
        .await
        .unwrap()
        .expect("an admitted episode must have a durable projection");
    assert_eq!(stored.cursor_seq, 3);
    assert_eq!(stored.lifecycle_state, LifecycleState::Waived);
    assert_eq!(stored.verification_state, VerificationState::Candidate);
    assert_eq!(
        stored.evaluated_at,
        timestamp("2026-08-15T05:10:00.000000000Z")
    );

    // ...and a rebuild from the database alone reproduces it byte for byte.
    let rebuilt = repository
        .rebuild_projection(detection.episode_fingerprint)
        .await
        .unwrap();
    assert_eq!(rebuilt, stored);
}

// --- idempotent replay ---

#[tokio::test]
async fn live_replayed_appends_are_idempotent_and_do_not_move_the_projection() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let repository = ledger(&pool, "idempotent");
    let detection = envelope('5');

    repository
        .admit_envelope(&candidate(detection.clone()))
        .await
        .unwrap();
    let replayed = repository
        .admit_envelope(&candidate(detection.clone()))
        .await
        .unwrap();
    assert!(matches!(
        replayed,
        DiscrepancyAppendOutcomeV1::AlreadyRecorded { .. }
    ));

    let ack = acknowledge_event(&detection, "2026-08-15T05:00:00.000000000Z");
    repository.append_lifecycle_event(&ack).await.unwrap();
    let before = repository
        .read_projection(detection.episode_fingerprint)
        .await
        .unwrap()
        .unwrap();

    let replayed = repository.append_lifecycle_event(&ack).await.unwrap();
    assert!(matches!(
        replayed,
        DiscrepancyAppendOutcomeV1::AlreadyRecorded { .. }
    ));
    let after = repository
        .read_projection(detection.episode_fingerprint)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after, before);
    assert_eq!(
        repository
            .read_log(detection.episode_fingerprint)
            .await
            .unwrap()
            .len(),
        2
    );
}

// --- receipt order does not move the projection ---

#[tokio::test]
async fn live_event_receipt_order_does_not_move_the_projection() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let detection = envelope('5');
    let ack = acknowledge_event(&detection, "2026-08-15T05:00:00.000000000Z");
    let dismiss = dismiss_event(
        &detection,
        "2026-08-15T05:30:00.000000000Z",
        "principal.on_call",
    );

    // Ledger A receives the events in effective order.
    let ordered = ledger(&pool, "order-effective");
    ordered
        .admit_envelope(&candidate(detection.clone()))
        .await
        .unwrap();
    ordered.append_lifecycle_event(&ack).await.unwrap();
    ordered.append_lifecycle_event(&dismiss).await.unwrap();

    // Ledger B receives the LATE event last: the dismissal (later effective
    // time) arrives before the acknowledgement it post-dates.
    let late = ledger(&pool, "order-late");
    late.admit_envelope(&candidate(detection.clone()))
        .await
        .unwrap();
    late.append_lifecycle_event(&dismiss).await.unwrap();
    late.append_lifecycle_event(&ack).await.unwrap();

    let stored_ordered = ordered
        .read_projection(detection.episode_fingerprint)
        .await
        .unwrap()
        .unwrap();
    let stored_late = late
        .read_projection(detection.episode_fingerprint)
        .await
        .unwrap()
        .unwrap();
    // Byte-identical stored projections despite the different receipt order.
    assert_eq!(
        stored_late.canonical_projection,
        stored_ordered.canonical_projection
    );
    assert_eq!(stored_late.evaluated_at, stored_ordered.evaluated_at);
    assert_eq!(stored_ordered.lifecycle_state, LifecycleState::Dismissed);
    // And both rebuild to exactly what they stored.
    assert_eq!(
        late.rebuild_projection(detection.episode_fingerprint)
            .await
            .unwrap(),
        stored_late
    );
}

// --- fail-closed negatives ---

#[tokio::test]
async fn live_a_divergent_envelope_for_a_seeded_episode_is_refused() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let repository = ledger(&pool, "divergent");
    let detection = envelope('5');
    repository
        .admit_envelope(&candidate(detection.clone()))
        .await
        .unwrap();

    // Same episode fingerprint (severity is not identity-bearing), different
    // envelope bytes: per-detection identity may not be rewritten.
    let mut divergent = detection.clone();
    divergent.severity = DiscrepancySeverityV1::Critical;
    assert_ne!(
        divergent.envelope_id().unwrap(),
        detection.envelope_id().unwrap()
    );
    assert_eq!(divergent.episode_fingerprint, detection.episode_fingerprint);
    assert!(
        repository
            .admit_envelope(&candidate(divergent))
            .await
            .is_err()
    );

    // Nothing was appended by the refused attempt.
    assert_eq!(
        repository
            .read_log(detection.episode_fingerprint)
            .await
            .unwrap()
            .len(),
        1
    );
    let reloaded = repository
        .read_envelope(detection.episode_fingerprint)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reloaded.severity, DiscrepancySeverityV1::Medium);
}

#[tokio::test]
async fn live_a_lifecycle_event_without_an_admitted_envelope_is_refused() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let repository = ledger(&pool, "no-envelope");
    let detection = envelope('5');
    let ack = acknowledge_event(&detection, "2026-08-15T05:00:00.000000000Z");
    assert!(repository.append_lifecycle_event(&ack).await.is_err());
    assert!(
        repository
            .read_projection(detection.episode_fingerprint)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn live_a_self_implicated_dismissal_is_refused_and_writes_nothing() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let repository = ledger(&pool, "auth03");
    let detection = envelope('5');
    repository
        .admit_envelope(&candidate(detection.clone()))
        .await
        .unwrap();

    // AUTH-03: principal.author_a is implicated by the envelope itself.
    let self_dismiss = dismiss_event(
        &detection,
        "2026-08-15T05:30:00.000000000Z",
        "principal.author_a",
    );
    assert!(
        repository
            .append_lifecycle_event(&self_dismiss)
            .await
            .is_err()
    );

    let stored = repository
        .read_projection(detection.episode_fingerprint)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.cursor_seq, 1);
    assert_eq!(stored.lifecycle_state, LifecycleState::Open);
    assert_eq!(
        repository
            .read_log(detection.episode_fingerprint)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn live_a_foreign_scope_envelope_is_refused_before_touching_the_database() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let repository = ledger(&pool, "foreign-scope");
    let detection = envelope('5');

    // A candidate whose envelope declares a scope other than the runtime's
    // bound scope. The fingerprints self-verify for THAT scope, so only the
    // runtime's binding refuses it.
    let foreign = AuthenticatedProjectScopeV1::from_trusted_context(
        ContractId::new("tenant.foreign").unwrap(),
        ContractId::new("project.foreign").unwrap(),
    );
    let mut foreign_envelope = detection.clone();
    foreign_envelope.scope = foreign.clone();
    let family = DiscrepancyFamilyPreimageV1 {
        schema_version: 1,
        profile: foreign_envelope.profile.clone(),
        scope: foreign,
        finding_type: foreign_envelope.finding_type,
        canonical_subject: foreign_envelope.canonical_subject.clone(),
        predicate: foreign_envelope.predicate.clone(),
        comparator_lineage_fingerprint: foreign_envelope.comparator_lineage_fingerprint,
        expectation_policy: foreign_envelope.expectation_policy.clone(),
        required_applicability_dimension_ids: foreign_envelope
            .required_applicability_dimension_ids
            .clone(),
        applicability: foreign_envelope.applicability.clone(),
        episode_policy_version: foreign_envelope.episode_policy.version,
    }
    .fingerprint()
    .unwrap();
    foreign_envelope.family_fingerprint = family;
    foreign_envelope.episode_fingerprint = DiscrepancyEpisodePreimageV1 {
        schema_version: 1,
        family_fingerprint: family,
        continuity_key: vec![applicability()[1].clone()],
        opening_transition_source_fact_id: foreign_envelope.opening_transition.source_fact_id,
        episode_policy_version: foreign_envelope.episode_policy.version,
    }
    .fingerprint()
    .unwrap();
    let foreign_episode = foreign_envelope.episode_fingerprint;

    assert!(
        repository
            .admit_envelope(&candidate(foreign_envelope))
            .await
            .is_err()
    );
    assert!(
        repository
            .read_projection(foreign_episode)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        repository
            .read_log(foreign_episode)
            .await
            .unwrap()
            .is_empty()
    );
}

// --- relations ---

#[tokio::test]
async fn live_a_superseding_relation_freezes_the_source_episode() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let repository = ledger(&pool, "supersede");
    let source = envelope('5');
    let replacement = envelope('6');
    assert_eq!(source.family_fingerprint, replacement.family_fingerprint);
    assert_ne!(source.episode_fingerprint, replacement.episode_fingerprint);

    repository
        .admit_envelope(&candidate(source.clone()))
        .await
        .unwrap();
    repository
        .admit_envelope(&candidate(replacement.clone()))
        .await
        .unwrap();

    let relation = DiscrepancyEpisodeRelationV1 {
        schema_version: 1,
        profile: source.profile.clone(),
        scope: source.scope.clone(),
        family_fingerprint: source.family_fingerprint,
        kind: EpisodeRelationKindV1::Superseded,
        from_episodes: vec![source.episode_fingerprint],
        to_episode: replacement.episode_fingerprint,
    };
    let outcome = repository.append_relation(&relation).await.unwrap();
    let DiscrepancyAppendOutcomeV1::Appended(transition) = &outcome else {
        panic!("a lawful relation must append");
    };
    assert_eq!(transition.log_seq, None);
    assert_eq!(transition.refreshed_episodes.len(), 2);

    // The SOURCE episode's projection is frozen as superseded...
    let frozen = repository
        .read_projection(source.episode_fingerprint)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(frozen.lifecycle_state, LifecycleState::Superseded);
    // ...the replacement stays open...
    let open = repository
        .read_projection(replacement.episode_fingerprint)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(open.lifecycle_state, LifecycleState::Open);
    // ...both rebuild identically from the durable log + relation store...
    assert_eq!(
        repository
            .rebuild_projection(source.episode_fingerprint)
            .await
            .unwrap(),
        frozen
    );
    assert_eq!(
        repository
            .rebuild_projection(replacement.episode_fingerprint)
            .await
            .unwrap(),
        open
    );
    // ...and a replayed relation append is idempotent.
    assert!(matches!(
        repository.append_relation(&relation).await.unwrap(),
        DiscrepancyAppendOutcomeV1::AlreadyRecorded { .. }
    ));
    assert_eq!(
        repository
            .read_relations(source.family_fingerprint)
            .await
            .unwrap(),
        vec![relation]
    );
}

#[tokio::test]
async fn live_a_relation_claiming_another_family_for_a_seeded_episode_is_refused() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let repository = ledger(&pool, "cross-family");
    let detection = envelope('5');
    repository
        .admit_envelope(&candidate(detection.clone()))
        .await
        .unwrap();

    // A relation minted with only public fingerprints, claiming a DIFFERENT
    // family while naming this scope's episode as its suppression source.
    let alien_family = DiscrepancyFamilyFingerprintV1::from_digest(digest(&"7".repeat(64)));
    let alien_target = DiscrepancyEpisodeFingerprintV1::from_digest(digest(&"8".repeat(64)));
    let relation = DiscrepancyEpisodeRelationV1 {
        schema_version: 1,
        profile: detection.profile.clone(),
        scope: detection.scope.clone(),
        family_fingerprint: alien_family,
        kind: EpisodeRelationKindV1::Superseded,
        from_episodes: vec![detection.episode_fingerprint],
        to_episode: alien_target,
    };
    assert!(repository.append_relation(&relation).await.is_err());
    // Nothing was stored, and the episode is untouched.
    assert!(
        repository
            .read_relations(alien_family)
            .await
            .unwrap()
            .is_empty()
    );
    let stored = repository
        .read_projection(detection.episode_fingerprint)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.lifecycle_state, LifecycleState::Open);
}
