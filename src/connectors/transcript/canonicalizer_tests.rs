//! Unit tests for the canonicalizer: identity derivation and every fail-closed
//! rejection path.

use super::super::parser::{parse_transcript, transcript_parser_key_v1, transcript_parser_key_v2};
use super::super::test_fixture::{
    INSTALLATION_COORDINATE, active_package, binding, binding_without_coordinates,
    clean_transcript, clocks, line,
};
use super::*;
use crate::memory_contracts::evidence_v2::{
    derive_representation_key_v2, derive_source_fact_id_v2,
};

const SESSION: &str = "01931f2c-0000-7000-8000-000000000001";

fn first_turn(transcript: &str) -> crate::connectors::transcript::ParsedTurnV1 {
    parse_transcript("s", transcript.as_bytes(), 0, 0)
        .unwrap()
        .turns
        .swap_remove(0)
}

fn canonicalize(text: &str) -> CanonicalizedTurnV1 {
    let active = active_package();
    let transcript = clean_transcript(SESSION);
    let turn = first_turn(&transcript);
    let clocks = clocks();
    canonicalize_turn(
        &active,
        &binding(),
        &transcript_parser_key_v1(),
        &turn,
        text,
        &clocks.observed_at,
        &clocks.received_at,
    )
    .unwrap()
}

#[test]
fn a_canonicalized_turn_is_admissible_against_the_active_connector() {
    let active = active_package();
    let canonicalized = canonicalize("a clean body");
    canonicalized
        .candidate
        .validate_against_structural_connector(active.connector())
        .expect("the candidate must satisfy the active connector schema");
    assert_eq!(
        canonicalized.candidate.connector_schema,
        *active.connector().registry_reference()
    );
}

#[test]
fn the_candidate_scope_is_the_credential_scope_not_a_parameter() {
    let active = active_package();
    let canonicalized = canonicalize("a clean body");
    assert_eq!(canonicalized.candidate.scope, *active.scope());
    assert_eq!(canonicalized.candidate.source_fact.scope, *active.scope());
}

#[test]
fn the_stored_body_is_the_redacted_text_and_nothing_else() {
    let canonicalized = canonicalize("REDACTED BODY MARKER");
    let body: TranscriptTurnBodyV1 =
        crate::memory_contracts::canonical::decode_strict(&canonicalized.canonical_payload)
            .unwrap();
    assert_eq!(body.text, "REDACTED BODY MARKER");
    assert_eq!(body.role, "user");
    assert_eq!(body.session_id, SESSION);
    // The raw parsed text is NOT in the payload: the canonicalizer never reads
    // ParsedTurnV1::text, which is what makes redact-before-outbox structural.
    let payload = String::from_utf8(canonicalized.canonical_payload).unwrap();
    assert!(!payload.contains("please check the failing auth test"));
}

#[test]
fn the_declared_content_digest_and_length_match_the_payload_exactly() {
    let canonicalized = canonicalize("a clean body");
    let reference = &canonicalized.candidate.canonical_payload;
    assert_eq!(
        reference.content_digest,
        super::super::test_fixture::sha256(&canonicalized.canonical_payload)
    );
    assert_eq!(
        reference.byte_length.as_str(),
        canonicalized.canonical_payload.len().to_string()
    );
}

#[test]
fn the_immutable_revision_is_the_derived_revision_digest() {
    let canonicalized = canonicalize("a clean body");
    assert_eq!(
        canonicalized
            .candidate
            .source_fact
            .immutable_revision
            .as_bytes(),
        canonicalized.revision.as_bytes()
    );
}

#[test]
fn a_different_parser_key_is_a_different_representation() {
    // The property the brief names: the parser identity and configuration
    // digest are part of representation identity. Same bytes, same body, same
    // package -> a DIFFERENT parser key must not collide with the first.
    let active = active_package();
    let transcript = clean_transcript(SESSION);
    let turn = first_turn(&transcript);
    let clocks = clocks();
    let derive = |key: &crate::memory_contracts::chunk_identity::ParserKeyV1| {
        canonicalize_turn(
            &active,
            &binding(),
            key,
            &turn,
            "identical body",
            &clocks.observed_at,
            &clocks.received_at,
        )
        .unwrap()
    };
    let first = derive(&transcript_parser_key_v1());
    let second = derive(&transcript_parser_key_v2());

    assert_ne!(first.revision, second.revision);
    assert_ne!(
        first.candidate.source_fact.canonical_resource_id,
        second.candidate.source_fact.canonical_resource_id
    );
    assert_ne!(
        derive_source_fact_id_v2(&first.candidate.source_fact).unwrap(),
        derive_source_fact_id_v2(&second.candidate.source_fact).unwrap()
    );
}

#[test]
fn a_different_body_is_a_different_revision_under_the_same_parser() {
    let first = canonicalize("body one");
    let second = canonicalize("body two");
    assert_ne!(first.revision, second.revision);
    assert_ne!(
        first.candidate.canonical_payload.content_digest,
        second.candidate.canonical_payload.content_digest
    );
}

#[test]
fn canonicalizing_the_same_turn_twice_is_byte_identical() {
    let first = canonicalize("stable body");
    let second = canonicalize("stable body");
    assert_eq!(first.candidate, second.candidate);
    assert_eq!(first.canonical_payload, second.canonical_payload);
    assert_eq!(first.revision, second.revision);
}

#[test]
fn the_locator_carries_the_published_coordinates_verbatim() {
    // The admission seam re-checks every locator coordinate that names a
    // published source-fact field; a locator that hashed different bytes than
    // the envelope declares would be rejected there.
    let canonicalized = canonicalize("a clean body");
    let fact = &canonicalized.candidate.source_fact;
    for component in &canonicalized.locators.canonical_resource.components {
        let expected = match component.key.as_str() {
            "immutable_revision" => hex::encode(fact.immutable_revision.as_bytes()),
            "provider_object_id" => hex::encode(fact.provider_object_id.as_bytes()),
            other => panic!("unexpected published coordinate {other}"),
        };
        assert_eq!(component.value, expected);
    }
}

#[test]
fn the_provider_instance_locator_is_built_from_the_binding_not_the_transcript() {
    let canonicalized = canonicalize("a clean body");
    let components = &canonicalized.locators.provider_instance.components;
    assert_eq!(components.len(), 1);
    assert_eq!(components[0].key.as_str(), INSTALLATION_COORDINATE);
    assert_eq!(components[0].value, "4242");
}

#[test]
fn a_missing_instance_coordinate_is_a_closed_refusal_not_a_guess() {
    let active = active_package();
    let transcript = clean_transcript(SESSION);
    let turn = first_turn(&transcript);
    let clocks = clocks();
    let error = canonicalize_turn(
        &active,
        &binding_without_coordinates(),
        &transcript_parser_key_v1(),
        &turn,
        "body",
        &clocks.observed_at,
        &clocks.received_at,
    )
    .unwrap_err();
    assert!(matches!(
        error,
        TranscriptConnectorError::MissingLocatorCoordinate { ref key }
            if key == INSTALLATION_COORDINATE
    ));
}

#[test]
fn an_observed_clock_before_the_turn_clock_is_refused() {
    let active = active_package();
    let transcript = clean_transcript(SESSION);
    let turn = first_turn(&transcript);
    let error = canonicalize_turn(
        &active,
        &binding(),
        &transcript_parser_key_v1(),
        &turn,
        "body",
        &crate::memory_contracts::common::CanonicalTimestamp::parse(
            "2020-01-01T00:00:00.000000000Z",
        )
        .unwrap(),
        &clocks().received_at,
    )
    .unwrap_err();
    assert!(matches!(error, TranscriptConnectorError::ClockOrder));
}

#[test]
fn a_received_clock_before_the_observed_clock_is_refused() {
    let active = active_package();
    let transcript = clean_transcript(SESSION);
    let turn = first_turn(&transcript);
    let clocks = clocks();
    let error = canonicalize_turn(
        &active,
        &binding(),
        &transcript_parser_key_v1(),
        &turn,
        "body",
        &clocks.observed_at,
        &crate::memory_contracts::common::CanonicalTimestamp::parse(
            "2026-08-15T12:59:00.000000000Z",
        )
        .unwrap(),
    )
    .unwrap_err();
    assert!(matches!(error, TranscriptConnectorError::ClockOrder));
}

#[test]
fn a_clock_that_is_not_microsecond_aligned_is_refused() {
    let active = active_package();
    let transcript = clean_transcript(SESSION);
    let turn = first_turn(&transcript);
    let error = canonicalize_turn(
        &active,
        &binding(),
        &transcript_parser_key_v1(),
        &turn,
        "body",
        &crate::memory_contracts::common::CanonicalTimestamp::parse(
            "2026-08-15T13:00:00.000000001Z",
        )
        .unwrap(),
        &clocks().received_at,
    )
    .unwrap_err();
    assert!(matches!(error, TranscriptConnectorError::ClockOrder));
}

#[test]
fn turns_from_different_sessions_derive_different_resources() {
    let active = active_package();
    let clocks = clocks();
    let derive = |session: &str| {
        let transcript = format!(
            "{}\n",
            line(
                "user",
                session,
                "turn-1",
                "2026-08-15T12:30:00.000Z",
                "identical body text"
            )
        );
        let turn = first_turn(&transcript);
        canonicalize_turn(
            &active,
            &binding(),
            &transcript_parser_key_v1(),
            &turn,
            "identical body text",
            &clocks.observed_at,
            &clocks.received_at,
        )
        .unwrap()
    };
    let first = derive("session-a");
    let second = derive("session-b");
    assert_ne!(
        first.candidate.source_fact.provider_object_id,
        second.candidate.source_fact.provider_object_id
    );
    assert_ne!(
        first.candidate.source_fact.canonical_resource_id,
        second.candidate.source_fact.canonical_resource_id
    );
}

#[test]
fn the_revision_preimage_digest_is_stable_and_domain_separated() {
    let preimage = TranscriptTurnRevisionPreimageV1 {
        schema_version: TRANSCRIPT_SCHEMA_VERSION,
        parser_key_id: transcript_parser_key_v1().key_digest().unwrap(),
        session_id: SESSION.to_owned(),
        turn_uid: "turn-1".to_owned(),
        ordinal: 0,
        span: crate::memory_contracts::chunk_identity::SourceSpanV1 {
            schema_version: 1,
            byte_start: 0,
            byte_end: 10,
            span_digest: super::super::test_fixture::sha256(b"line"),
            ordinal: 0,
        },
        body_digest: super::super::test_fixture::sha256(b"body"),
    };
    let digest = preimage.revision_digest().unwrap();
    assert_eq!(digest, preimage.revision_digest().unwrap());
    // Not the bare canonical hash: the domain prefix must be in the preimage.
    let bare = super::super::test_fixture::sha256(
        &crate::memory_contracts::canonical::encode_canonical(&preimage).unwrap(),
    );
    assert_ne!(digest, bare);
}

#[test]
fn an_invalid_span_makes_the_revision_digest_fail_closed() {
    let preimage = TranscriptTurnRevisionPreimageV1 {
        schema_version: TRANSCRIPT_SCHEMA_VERSION,
        parser_key_id: transcript_parser_key_v1().key_digest().unwrap(),
        session_id: SESSION.to_owned(),
        turn_uid: "turn-1".to_owned(),
        ordinal: 0,
        span: crate::memory_contracts::chunk_identity::SourceSpanV1 {
            schema_version: 1,
            // Empty range: SourceSpanV1::validate refuses it.
            byte_start: 10,
            byte_end: 10,
            span_digest: super::super::test_fixture::sha256(b"line"),
            ordinal: 0,
        },
        body_digest: super::super::test_fixture::sha256(b"body"),
    };
    assert!(preimage.revision_digest().is_err());
}

#[test]
fn the_representation_key_changes_with_the_parser_key() {
    // Full end-to-end of the identity chain the module documents: parser key ->
    // revision -> canonical resource -> source fact -> representation key.
    let active = active_package();
    let transcript = clean_transcript(SESSION);
    let turn = first_turn(&transcript);
    let clocks = clocks();
    let key_for = |parser: &crate::memory_contracts::chunk_identity::ParserKeyV1| {
        let canonicalized = canonicalize_turn(
            &active,
            &binding(),
            parser,
            &turn,
            "identical body",
            &clocks.observed_at,
            &clocks.received_at,
        )
        .unwrap();
        let connector = active.connector();
        let representation = crate::memory_contracts::evidence_v2::RepresentationIdentityV2 {
            schema_version: 2,
            source_fact_id: derive_source_fact_id_v2(&canonicalized.candidate.source_fact).unwrap(),
            registry_head: active.head().clone(),
            connector_schema: connector.registry_reference().clone(),
            evidence_schema: connector.schema().evidence_schema.clone(),
            canonicalization_profile: active.profile().clone(),
            provider_instance_identity_recipe: connector
                .schema()
                .provider_instance_identity_recipe
                .clone(),
            canonical_resource_identity_recipe: connector
                .schema()
                .canonical_resource_identity_recipe
                .clone(),
            redaction_policy: connector.registry_reference().clone(),
            classifier_policy: connector.registry_reference().clone(),
            retention_policy: connector.registry_reference().clone(),
            publication_policy: connector.registry_reference().clone(),
            integrity_state:
                crate::memory_contracts::evidence::IntegrityState::TransportAuthenticated,
            visibility_class: crate::memory_contracts::evidence::VisibilityClass::Private,
            retention_class: crate::memory_contracts::evidence::RetentionClass::Governed,
            publication_class: crate::memory_contracts::evidence::PublicationClass::PrivateOnly,
            erasure_scopes: vec![crate::memory_contracts::evidence::ErasureScopeReferenceV1 {
                kind: crate::memory_contracts::evidence::ErasureScopeKind::SourceFact,
                target_digest: canonicalized.revision,
            }],
            lineage: crate::memory_contracts::evidence_v2::RepresentationLineageV2::Origin,
        };
        derive_representation_key_v2(&representation).unwrap()
    };
    assert_ne!(
        key_for(&transcript_parser_key_v1()),
        key_for(&transcript_parser_key_v2())
    );
}
