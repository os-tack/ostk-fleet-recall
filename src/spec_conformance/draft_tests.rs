//! Unit tests for the pure parts of drafting a spec statement: the
//! genesis-derived predicate and evaluator, the repository subject, and span
//! selection. Drafting against a real witness and repository is proved in
//! `tests/spec_conformance_live.rs`.

use super::*;
use crate::memory_contracts::identity::IdentityForm;
use crate::registry_witness::{
    compiled_generation_two_package, compiled_genesis_package, compiled_stage4_package,
};
use crate::spec_conformance::testkit::scope;

fn other_scope() -> AuthenticatedProjectScopeV1 {
    AuthenticatedProjectScopeV1::from_trusted_context(
        ContractId::new("tenant.acme").unwrap(),
        ContractId::new("project.other").unwrap(),
    )
}

#[test]
fn the_spec_predicate_is_the_one_the_genesis_observer_is_admitted_for() {
    let genesis = compiled_genesis_package().unwrap();
    let predicate = spec_predicate(genesis).unwrap();
    assert_eq!(predicate.entry_id.as_str(), "mcp.remember.allowed_actions");
    assert!(
        genesis
            .entry(
                RegistryEntryKind::PredicateSchema,
                &predicate.entry_id,
                predicate.version
            )
            .is_some(),
        "the observer's predicate is a genesis entry"
    );
    let evaluator = spec_applicability_evaluator(genesis).unwrap();
    assert!(
        genesis
            .entry(
                RegistryEntryKind::ApplicabilityEvaluator,
                &evaluator.entry_id,
                evaluator.version
            )
            .is_some()
    );
}

#[test]
fn the_repository_subject_is_a_stable_entity_per_provider_id_and_scope() {
    let generation_one = compiled_stage4_package().unwrap();
    let generation_two = compiled_generation_two_package().unwrap();
    for package in [generation_one.successor_package(), &*generation_two] {
        let subject = repository_subject(package, &scope(), 908_172_635).unwrap();
        assert_eq!(subject.identity_form(), IdentityForm::Entity);
        assert_eq!(subject.resource_kind().as_str(), "repository");
        assert_eq!(
            subject,
            repository_subject(package, &scope(), 908_172_635).unwrap()
        );
        assert_ne!(
            subject,
            repository_subject(package, &scope(), 908_172_636).unwrap(),
            "another repository is another subject"
        );
        assert_ne!(
            subject,
            repository_subject(package, &other_scope(), 908_172_635).unwrap(),
            "the same repository in another project scope is another subject"
        );
    }
}

#[test]
fn spans_are_sorted_and_digest_exactly_the_bytes_they_select() {
    let document = b"# Spec\nForget must not be a remember action.\n";
    let spans = select_spans(document, &[7..13, 0..6]).unwrap();
    assert_eq!(
        spans
            .iter()
            .map(|span| (span.start, span.end))
            .collect::<Vec<_>>(),
        [(0, 6), (7, 13)]
    );
    assert_eq!(spans[0].selected_bytes_digest, spec_span_digest(b"# Spec"));
    assert_eq!(spans[1].selected_bytes_digest, spec_span_digest(b"Forget"));
    // Adjacent spans do not overlap.
    select_spans(document, &[0..7, 7..13]).unwrap();
}

#[test]
#[allow(clippy::single_range_in_vec_init)] // each case is a list of byte spans
fn spans_that_select_nothing_or_overlap_are_refused() {
    let document = b"Forget must not be a remember action.\n";
    let length = u64::try_from(document.len()).unwrap();
    for (spans, why) in [
        (vec![], "no span"),
        (vec![3..3], "an empty span"),
        (vec![Range { start: 9, end: 3 }], "a reversed span"),
        (vec![0..length + 1], "a span past the end"),
        (vec![0..10, 5..20], "overlapping spans"),
        (vec![0..6, 0..6], "a duplicated span"),
    ] {
        assert!(
            matches!(
                select_spans(document, &spans),
                Err(ContractError::Schema(_))
            ),
            "{why} must be refused"
        );
    }
}

#[test]
fn the_parser_artifact_is_one_occurrence_for_every_draft() {
    let artifact = spec_parser_artifact_id().unwrap();
    assert_eq!(artifact.identity_form(), IdentityForm::Occurrence);
    assert_eq!(artifact, spec_parser_artifact_id().unwrap());
}
