use std::collections::BTreeMap;

use super::*;
use crate::memory_contracts::canonical::decode_typed_canonical;
use crate::memory_contracts::normative::NormativePropositionV1;
use crate::spec_conformance::testkit::{expectation, label, proposal_for, reference, resource};

#[test]
fn a_proposal_minted_for_the_expectation_is_bound() {
    let expectation = expectation();
    expectation.validate().unwrap();
    expectation
        .require_bound_to(&proposal_for(&expectation))
        .unwrap();
}

#[test]
fn the_fingerprint_changes_with_every_field_that_carries_meaning() {
    let base = expectation();
    let fingerprint = base.fingerprint().unwrap();
    assert_eq!(fingerprint, expectation().fingerprint().unwrap());

    let variants = [
        RememberActionExpectationV1 {
            member: "Record".into(),
            ..expectation()
        },
        RememberActionExpectationV1 {
            enum_name: "RememberAction".into(),
            ..expectation()
        },
        RememberActionExpectationV1 {
            source_path: "src/other.rs".into(),
            ..expectation()
        },
        RememberActionExpectationV1 {
            expected: ExpectedMembershipV1::Present,
            ..expectation()
        },
        RememberActionExpectationV1 {
            severity: DiscrepancySeverityV1::Low,
            ..expectation()
        },
        RememberActionExpectationV1 {
            predicate: reference("mcp.remember.other"),
            ..expectation()
        },
    ];
    for variant in variants {
        assert_ne!(variant.fingerprint().unwrap(), fingerprint, "{variant:?}");
    }
}

#[test]
fn the_canonical_form_round_trips_and_refuses_unknown_fields() {
    let expectation = expectation();
    let bytes = expectation.canonical_bytes().unwrap();
    let decoded: RememberActionExpectationV1 = decode_typed_canonical(&bytes).unwrap();
    assert_eq!(decoded, expectation);

    let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    value["unexpected"] = serde_json::json!(true);
    let widened = crate::memory_contracts::canonical::encode_canonical(&value).unwrap();
    assert!(decode_typed_canonical::<RememberActionExpectationV1>(&widened).is_err());
}

#[test]
fn validate_refuses_malformed_names_paths_and_versions() {
    let refused = [
        RememberActionExpectationV1 {
            schema_version: 2,
            ..expectation()
        },
        RememberActionExpectationV1 {
            predicate: RegistryReferenceV1 {
                version: 0,
                ..reference("mcp.remember.allowed_actions")
            },
            ..expectation()
        },
        RememberActionExpectationV1 {
            member: String::new(),
            ..expectation()
        },
        RememberActionExpectationV1 {
            member: "9Forget".into(),
            ..expectation()
        },
        RememberActionExpectationV1 {
            member: "_Forget".into(),
            ..expectation()
        },
        RememberActionExpectationV1 {
            member: "r#Forget".into(),
            ..expectation()
        },
        RememberActionExpectationV1 {
            member: "F".repeat(MAX_RUST_IDENTIFIER_BYTES + 1),
            ..expectation()
        },
        RememberActionExpectationV1 {
            enum_name: String::new(),
            ..expectation()
        },
        RememberActionExpectationV1 {
            enum_name: "service::Action".into(),
            ..expectation()
        },
        RememberActionExpectationV1 {
            source_path: String::new(),
            ..expectation()
        },
        RememberActionExpectationV1 {
            source_path: "/src/service.rs".into(),
            ..expectation()
        },
        RememberActionExpectationV1 {
            source_path: "src/../service.rs".into(),
            ..expectation()
        },
        RememberActionExpectationV1 {
            source_path: "src/./service.rs".into(),
            ..expectation()
        },
        RememberActionExpectationV1 {
            source_path: "src//service.rs".into(),
            ..expectation()
        },
        RememberActionExpectationV1 {
            source_path: "src/".into(),
            ..expectation()
        },
        RememberActionExpectationV1 {
            source_path: "--output=x".into(),
            ..expectation()
        },
        RememberActionExpectationV1 {
            source_path: "src\\service.rs".into(),
            ..expectation()
        },
        RememberActionExpectationV1 {
            source_path: "src/serv\nice.rs".into(),
            ..expectation()
        },
        RememberActionExpectationV1 {
            source_path: "a".repeat(MAX_SOURCE_PATH_BYTES + 1),
            ..expectation()
        },
    ];
    for expectation in refused {
        assert!(expectation.validate().is_err(), "{expectation:?}");
        assert!(expectation.fingerprint().is_err(), "{expectation:?}");
    }
}

#[test]
fn require_bound_to_refuses_every_unbound_proposal() {
    let expectation = expectation();
    let fingerprint = expectation.fingerprint().unwrap();
    let bound = proposal_for(&expectation);

    let mut two_propositions = bound.clone();
    two_propositions.propositions.push(NormativePropositionV1 {
        predicate_schema: reference("zz.other.predicate"),
        proposition_fingerprint: fingerprint,
    });
    two_propositions.propositions.sort();

    let mut foreign_predicate = bound.clone();
    foreign_predicate.propositions[0].predicate_schema = reference("mcp.remember.other");

    let mut foreign_fingerprint = bound.clone();
    foreign_fingerprint.propositions[0].proposition_fingerprint = label("another expectation");

    let mut foreign_parser_configuration = bound.clone();
    foreign_parser_configuration.parser_configuration_digest = label("another configuration");

    let mut other_repository = bound.clone();
    other_repository.applicability_selector = CanonicalValue::Object(BTreeMap::from([(
        REPOSITORY_SELECTOR_KEY.to_owned(),
        CanonicalValue::String(resource("entity", "repository", "other").to_string()),
    )]));

    let mut wider_selector = bound.clone();
    let CanonicalValue::Object(mut selector) = repository_selector(&bound) else {
        unreachable!("the repository selector is an object");
    };
    selector.insert("environment".into(), CanonicalValue::String("prod".into()));
    wider_selector.applicability_selector = CanonicalValue::Object(selector);

    let mut other_subject = bound.clone();
    other_subject.repository_entity_id = resource("entity", "repository", "other");

    for (name, proposal) in [
        ("two propositions", two_propositions),
        ("a foreign predicate", foreign_predicate),
        ("a foreign proposition fingerprint", foreign_fingerprint),
        (
            "a foreign parser configuration digest",
            foreign_parser_configuration,
        ),
        ("a selector naming another repository", other_repository),
        ("a selector with another dimension", wider_selector),
        (
            "a selector that is not the proposal's subject",
            other_subject,
        ),
    ] {
        assert!(
            expectation.require_bound_to(&proposal).is_err(),
            "{name} must not bind"
        );
    }

    let another = RememberActionExpectationV1 {
        member: "Record".into(),
        ..expectation
    };
    assert!(
        another.require_bound_to(&bound).is_err(),
        "a proposal binds exactly one expectation"
    );
}

#[test]
fn membership_values_separate_conditions_and_name_boundaries() {
    let present = membership_value_digest("Action", "Forget", true);
    assert_eq!(present, membership_value_digest("Action", "Forget", true));
    assert_ne!(present, membership_value_digest("Action", "Forget", false));
    assert_ne!(present, membership_value_digest("Action", "Record", true));
    assert_ne!(
        membership_value_digest("Ab", "C", true),
        membership_value_digest("A", "bC", true)
    );
}
