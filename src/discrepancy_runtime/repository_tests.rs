use super::super::testbed::{
    acknowledge_event, digest, dismiss_event, envelope, other_scope, refingerprint,
    resolved_comparator_lineage, resolved_episode_policy, scope, unseeded_episode_fingerprint,
};
use super::*;
use crate::memory_contracts::canonical::{decode_strict, encode_canonical};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::discrepancy::{
    DiscrepancyEpisodeRelationV1, EpisodeRelationKindV1, LifecycleState, VerificationState,
};

fn binding() -> DiscrepancyRegistryBindingV1 {
    DiscrepancyRegistryBindingV1 {
        registry_package_digest: digest(&"2".repeat(64)),
        activation_policy_digest: digest(&"3".repeat(64)),
    }
}

fn candidate() -> DiscrepancyEnvelopeCandidateV1 {
    DiscrepancyEnvelopeCandidateV1 {
        envelope: envelope(),
        resolved_episode_policy: resolved_episode_policy(),
        resolved_comparator_lineage: resolved_comparator_lineage(),
    }
}

// --- envelope admission ---

#[test]
fn a_lawful_envelope_is_admitted_with_its_derived_identities() {
    let candidate = candidate();
    let admitted = admit_envelope(&candidate, &binding(), &scope()).unwrap();
    assert_eq!(
        admitted.family_fingerprint,
        candidate.envelope.family_fingerprint
    );
    assert_eq!(
        admitted.episode_fingerprint,
        candidate.envelope.episode_fingerprint
    );
    assert_eq!(
        admitted.envelope_id,
        candidate.envelope.envelope_id().unwrap()
    );
    assert_eq!(
        admitted.canonical_envelope,
        encode_canonical(&candidate.envelope).unwrap()
    );
}

/// SCOPE binds from the runtime, never the payload: an envelope minted for
/// another tenant/project is refused before anything touches storage.
#[test]
fn an_envelope_for_another_scope_is_refused() {
    let candidate = candidate();
    assert!(admit_envelope(&candidate, &binding(), &other_scope()).is_err());
}

/// The reverse direction: a well-scoped runtime refuses an envelope whose
/// own declared scope is foreign, even though its fingerprints self-verify.
#[test]
fn an_envelope_declaring_a_foreign_scope_is_refused() {
    let mut candidate = candidate();
    candidate.envelope.scope = other_scope();
    refingerprint(&mut candidate.envelope);
    assert!(admit_envelope(&candidate, &binding(), &scope()).is_err());
}

#[test]
fn a_stale_registry_head_is_refused() {
    let stale = DiscrepancyRegistryBindingV1 {
        registry_package_digest: digest(&"e".repeat(64)),
        activation_policy_digest: digest(&"3".repeat(64)),
    };
    assert!(matches!(
        admit_envelope(&candidate(), &stale, &scope()),
        Err(crate::memory_contracts::ContractError::StaleRegistryHead)
    ));
}

#[test]
fn a_zero_registry_binding_is_refused() {
    let unbound = DiscrepancyRegistryBindingV1 {
        registry_package_digest: Sha256Digest::ZERO,
        activation_policy_digest: digest(&"3".repeat(64)),
    };
    assert!(admit_envelope(&candidate(), &unbound, &scope()).is_err());
}

/// The payload cannot self-select episode identity: an envelope declaring
/// its own continuity-key set (here: empty) while citing the registered
/// policy is refused, even though its fingerprints self-verify.
#[test]
fn a_continuity_key_diverging_from_the_registered_policy_is_refused() {
    let mut candidate = candidate();
    candidate.envelope.continuity_key_dimension_ids = vec![];
    refingerprint(&mut candidate.envelope);
    assert!(admit_envelope(&candidate, &binding(), &scope()).is_err());
}

/// The payload cannot self-select its comparator: a lineage fingerprint that
/// does not equal the registered lineage's own is refused.
#[test]
fn a_comparator_fingerprint_diverging_from_the_registered_lineage_is_refused() {
    let mut candidate = candidate();
    candidate.envelope.comparator_lineage_fingerprint =
        crate::memory_contracts::discrepancy::ComparatorLineageFingerprint::from_digest(digest(
            &"f".repeat(64),
        ));
    refingerprint(&mut candidate.envelope);
    assert!(admit_envelope(&candidate, &binding(), &scope()).is_err());
}

/// A shape-invalid envelope (fingerprint fields disagreeing with the
/// envelope's own content) never reaches the policy/lineage checks.
#[test]
fn a_fingerprint_mismatch_is_refused() {
    let mut candidate = candidate();
    candidate.envelope.episode_fingerprint = unseeded_episode_fingerprint();
    assert!(admit_envelope(&candidate, &binding(), &scope()).is_err());
}

// --- lifecycle event admission ---

#[test]
fn a_lawful_lifecycle_event_is_admitted() {
    let sample = envelope();
    let event = acknowledge_event(&sample, "2026-08-15T05:00:00.000000000Z");
    let admitted = admit_lifecycle_event(&sample, &event, &scope()).unwrap();
    assert_eq!(admitted.episode_fingerprint, sample.episode_fingerprint);
    assert_eq!(admitted.event_id, event.lifecycle_event_id().unwrap());
    assert_eq!(admitted.canonical_event, encode_canonical(&event).unwrap());
}

#[test]
fn a_lifecycle_event_for_another_bound_scope_is_refused() {
    let sample = envelope();
    let event = acknowledge_event(&sample, "2026-08-15T05:00:00.000000000Z");
    assert!(admit_lifecycle_event(&sample, &event, &other_scope()).is_err());
}

#[test]
fn a_lifecycle_event_targeting_a_different_episode_is_refused() {
    let sample = envelope();
    let mut event = acknowledge_event(&sample, "2026-08-15T05:00:00.000000000Z");
    event.episode_fingerprint = unseeded_episode_fingerprint();
    assert!(admit_lifecycle_event(&sample, &event, &scope()).is_err());
}

/// AUTH-03 flows through the runtime boundary: an implicated actor cannot
/// dismiss their own discrepancy.
#[test]
fn a_self_implicated_dismissal_is_refused() {
    let sample = envelope();
    let event = dismiss_event(
        &sample,
        "2026-08-15T05:30:00.000000000Z",
        "principal.author_a",
    );
    assert!(admit_lifecycle_event(&sample, &event, &scope()).is_err());
}

// --- relation admission ---

fn relation_for(sample: &crate::memory_contracts::discrepancy::DiscrepancyEnvelopeV1) -> DiscrepancyEpisodeRelationV1 {
    DiscrepancyEpisodeRelationV1 {
        schema_version: 1,
        profile: sample.profile.clone(),
        scope: sample.scope.clone(),
        family_fingerprint: sample.family_fingerprint,
        kind: EpisodeRelationKindV1::Superseded,
        from_episodes: vec![sample.episode_fingerprint],
        to_episode: unseeded_episode_fingerprint(),
    }
}

#[test]
fn a_lawful_relation_is_admitted_with_a_deterministic_identity() {
    let sample = envelope();
    let relation = relation_for(&sample);
    let admitted = admit_relation(&relation, &scope()).unwrap();
    let again = admit_relation(&relation, &scope()).unwrap();
    assert_eq!(admitted, again);
    assert_eq!(admitted.family_fingerprint, sample.family_fingerprint);
    assert_eq!(
        admitted.canonical_relation,
        encode_canonical(&relation).unwrap()
    );
    assert_ne!(admitted.relation_id, Sha256Digest::ZERO);
}

#[test]
fn a_relation_for_another_scope_is_refused() {
    let sample = envelope();
    let relation = relation_for(&sample);
    assert!(admit_relation(&relation, &other_scope()).is_err());
}

#[test]
fn a_self_referential_relation_is_refused() {
    let sample = envelope();
    let mut relation = relation_for(&sample);
    relation.to_episode = sample.episode_fingerprint;
    assert!(admit_relation(&relation, &scope()).is_err());
}

// --- record shapes ---

#[test]
fn log_records_round_trip_canonically() {
    let sample = envelope();
    let event = acknowledge_event(&sample, "2026-08-15T05:00:00.000000000Z");

    let envelope_record = DiscrepancyLogRecordV1::Envelope {
        envelope: sample.clone(),
    };
    assert_eq!(envelope_record.record_kind(), "envelope");
    envelope_record.validate().unwrap();
    let bytes = encode_canonical(&envelope_record).unwrap();
    let decoded: DiscrepancyLogRecordV1 = decode_strict(&bytes).unwrap();
    assert_eq!(decoded, envelope_record);

    let lifecycle_record = DiscrepancyLogRecordV1::Lifecycle { event };
    assert_eq!(lifecycle_record.record_kind(), "lifecycle");
    lifecycle_record.validate().unwrap();
    let bytes = encode_canonical(&lifecycle_record).unwrap();
    let decoded: DiscrepancyLogRecordV1 = decode_strict(&bytes).unwrap();
    assert_eq!(decoded, lifecycle_record);
}

#[test]
fn state_columns_round_trip_and_fail_closed_on_drift() {
    for state in [
        LifecycleState::Open,
        LifecycleState::Acknowledged,
        LifecycleState::Resolved,
        LifecycleState::Waived,
        LifecycleState::Dismissed,
        LifecycleState::Superseded,
    ] {
        assert_eq!(
            lifecycle_state_from_str(lifecycle_state_str(state)).unwrap(),
            state
        );
    }
    for state in [
        VerificationState::Candidate,
        VerificationState::Verified,
        VerificationState::Refuted,
        VerificationState::Indeterminate,
    ] {
        assert_eq!(
            verification_state_from_str(verification_state_str(state)).unwrap(),
            state
        );
    }
    assert!(lifecycle_state_from_str("escalated").is_err());
    assert!(verification_state_from_str("probably").is_err());
}
