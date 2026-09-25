use super::*;
use crate::memory_contracts::common::ContractId;
use crate::spec_conformance::expectation::ExpectedMembershipV1;
use crate::spec_conformance::testkit::{
    expectation, label, nonconforming_check, proposal_for, scope,
};

fn stored_statement() -> StatementColumns {
    let expectation = expectation();
    let proposal = proposal_for(&expectation);
    StatementColumns {
        statement_id: proposal.statement_id().unwrap(),
        binding_family_id: proposal.binding_family_id.as_str().to_owned(),
        expectation_digest: expectation.fingerprint().unwrap(),
        canonical_proposal: encode_canonical(&proposal).unwrap(),
        canonical_expectation: expectation.canonical_bytes().unwrap(),
    }
}

fn stored_check() -> CheckColumns {
    let check = nonconforming_check(label("statement"));
    CheckColumns::from_record(
        check.check_id().unwrap(),
        &check,
        check.canonical_bytes().unwrap(),
    )
}

#[test]
fn an_untouched_statement_row_verifies() {
    let columns = stored_statement();
    let (proposal, expectation) =
        verify_statement_columns(Some(&scope()), columns.statement_id, &columns).unwrap();
    assert_eq!(expectation, super::super::testkit::expectation());
    assert_eq!(proposal, proposal_for(&expectation));
}

#[test]
fn a_statement_row_that_no_longer_derives_its_identity_is_refused() {
    let columns = stored_statement();
    let other_expectation = RememberActionExpectationV1 {
        member: "Record".into(),
        ..expectation()
    };
    let other_proposal = proposal_for(&other_expectation);

    let mut swapped_proposal = columns.clone();
    swapped_proposal.canonical_proposal = encode_canonical(&other_proposal).unwrap();

    let mut swapped_expectation = columns.clone();
    swapped_expectation.canonical_expectation = other_expectation.canonical_bytes().unwrap();
    swapped_expectation.expectation_digest = other_expectation.fingerprint().unwrap();

    let mut stale_digest = columns.clone();
    stale_digest.expectation_digest = label("stale");

    let mut other_family = columns.clone();
    other_family.binding_family_id = "spec.remember.other".into();

    let mut not_canonical = columns.clone();
    not_canonical.canonical_expectation.push(b' ');

    let mut wrong_row_id = columns.clone();
    wrong_row_id.statement_id = label("another statement");

    for (name, tampered) in [
        ("another proposal under the id", swapped_proposal),
        ("another bound expectation", swapped_expectation),
        ("a stale expectation digest", stale_digest),
        ("another binding family", other_family),
        ("non-canonical bytes", not_canonical),
        ("another row id", wrong_row_id),
    ] {
        for semantic_scope in [Some(&scope()), None] {
            assert!(
                verify_statement_columns(semantic_scope, columns.statement_id, &tampered).is_err(),
                "{name} must be refused"
            );
        }
    }

    let foreign_scope = AuthenticatedProjectScopeV1::from_trusted_context(
        ContractId::new("tenant.acme").unwrap(),
        ContractId::new("project.other").unwrap(),
    );
    assert!(
        verify_statement_columns(Some(&foreign_scope), columns.statement_id, &columns).is_err(),
        "a statement minted for another project scope must be refused"
    );
    // A reader bound only to the physical scope has no semantic scope to
    // hold the row to; everything else is still checked.
    assert!(verify_statement_columns(None, columns.statement_id, &columns).is_ok());
}

#[test]
fn a_check_row_whose_columns_left_its_record_is_refused() {
    let columns = stored_check();
    assert_eq!(
        verify_check_columns(&columns).unwrap(),
        nonconforming_check(label("statement"))
    );

    let mut verdict = columns.clone();
    verdict.verdict = "conforming".into();
    let mut commit = columns.clone();
    commit.commit_oid = "ab".repeat(20);
    let mut episode = columns.clone();
    episode.episode_fingerprint = None;
    let mut observer = columns.clone();
    observer.observer_event_id = label("another event");
    let mut identity = columns.clone();
    identity.check_id = label("another check");
    let mut bytes = columns;
    bytes.canonical_check.push(b' ');
    for (name, tampered) in [
        ("the verdict column", verdict),
        ("the commit column", commit),
        ("the episode column", episode),
        ("the observer event column", observer),
        ("the check id", identity),
        ("the canonical bytes", bytes),
    ] {
        assert!(
            verify_check_columns(&tampered).is_err(),
            "a changed {name} must be refused"
        );
    }
}

#[test]
fn a_check_must_judge_its_own_statements_expectation() {
    let expectation = expectation();
    let proposal = proposal_for(&expectation);
    let statement = RecordedSpecStatementV1 {
        statement_id: proposal.statement_id().unwrap(),
        proposal,
        expectation,
        recorded_at: DateTime::<Utc>::UNIX_EPOCH,
    };
    let check = nonconforming_check(statement.statement_id);
    require_check_matches_statement(&check, &statement).unwrap();

    let other_member = SpecCheckRecordV1 {
        member: "Record".into(),
        ..check.clone()
    };
    let other_expected = SpecCheckRecordV1 {
        expected: ExpectedMembershipV1::Present,
        verdict: crate::spec_conformance::SpecVerdictV1::Conforming,
        episode: None,
        ..check.clone()
    };
    let other_family = SpecCheckRecordV1 {
        binding_family_id: ContractId::new("spec.remember.other").unwrap(),
        ..check
    };
    for (name, check) in [
        ("another member", other_member),
        ("another expected membership", other_expected),
        ("another binding family", other_family),
    ] {
        assert!(
            require_check_matches_statement(&check, &statement).is_err(),
            "{name} must be refused"
        );
    }
}
