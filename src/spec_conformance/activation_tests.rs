//! Unit tests for the pure spec-statement gate activation runs before any
//! write. The approval, witnessed-head, and live activation paths are proved
//! in `normative_runtime` and `tests/spec_conformance_live.rs`.

use super::*;
use crate::memory_contracts::common::RegistryReferenceV1;
use crate::registry_witness::compiled_genesis_package;
use crate::spec_conformance::expectation::repository_selector;
use crate::spec_conformance::testkit::{expectation, proposal_for, reference};

/// A spec statement that names the genesis observer's predicate and the
/// genesis applicability evaluator, as `draft_statement` builds one.
fn genesis_bound(
    predicate: RegistryReferenceV1,
    evaluator: RegistryReferenceV1,
) -> (NormativeBindingProposalV2, RememberActionExpectationV1) {
    let expectation = RememberActionExpectationV1 {
        predicate,
        ..expectation()
    };
    let mut proposal = proposal_for(&expectation);
    proposal.applicability_evaluator = evaluator;
    proposal.applicability_selector = repository_selector(&proposal);
    (proposal, expectation)
}

#[test]
fn only_a_statement_the_genesis_observer_can_check_passes() {
    let genesis = compiled_genesis_package().unwrap();
    let predicate = spec_predicate(genesis).unwrap();
    let evaluator = spec_applicability_evaluator(genesis).unwrap();

    let (proposal, expectation) = genesis_bound(predicate.clone(), evaluator.clone());
    require_spec_statement(genesis, &proposal, &expectation).unwrap();

    let (foreign_predicate, its_expectation) =
        genesis_bound(reference("mcp.remember.allowed_actions"), evaluator);
    assert!(
        require_spec_statement(genesis, &foreign_predicate, &its_expectation).is_err(),
        "a predicate the genesis observer is not admitted for must be refused"
    );

    let (foreign_evaluator, its_expectation) =
        genesis_bound(predicate, reference("applicability.repository"));
    assert!(
        require_spec_statement(genesis, &foreign_evaluator, &its_expectation).is_err(),
        "an applicability evaluator other than the genesis package's must be refused"
    );

    let other_member = RememberActionExpectationV1 {
        member: "Record".into(),
        ..expectation
    };
    assert!(
        require_spec_statement(genesis, &proposal, &other_member).is_err(),
        "an expectation the proposal does not carry must be refused"
    );
}
