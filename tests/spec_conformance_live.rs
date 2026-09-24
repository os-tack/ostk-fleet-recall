//! Connected proof for the spec conformance store
//! (`ostk_fleet_recall::spec_conformance::CockroachSpecRepository`, migration
//! 31).
//!
//! Set `FLEET_RECALL_TEST_DATABASE_URL` to a disposable `CockroachDB` 26.2
//! database; every test here is inert otherwise. Each test writes into fresh
//! physical scopes.
//!
//! What it proves: a spec statement is stored under the identity its own
//! proposal derives, recording it again changes nothing, and a statement that
//! is out of scope or not bound to its expectation is refused before any
//! write; a row edited in place, in a column or in its canonical bytes, is
//! refused on read and blocks a re-record instead of being re-interpreted; a
//! spec check replays to the same identity without moving its first write, a
//! replay of an older check never makes it the newest again, and a check
//! that cites an unrecorded statement or another expectation is refused; and
//! two physical projects, even with one tenant, one semantic scope, and the
//! same statement, never see each other's statements or checks. The writes
//! run under a login holding only the runtime role's grants, which give
//! these tables `SELECT` and `INSERT` and nothing more.

mod common;

use std::future::Future;
use std::panic::AssertUnwindSafe;

use common::authority::{retry_policy, semantic_scope};
use common::runtime_role::RuntimeProbeRole;
use futures::FutureExt as _;
use ostk_fleet_recall::connectors::git::GitObjectId;
use ostk_fleet_recall::discrepancy_runtime::ComparisonIndeterminacyV1;
use ostk_fleet_recall::memory_contracts::canonical::CanonicalValue;
use ostk_fleet_recall::memory_contracts::common::{
    AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, HexBytes, RegistryReferenceV1,
    frozen_profile_reference_v1,
};
use ostk_fleet_recall::memory_contracts::digest::{
    DigestDomain, Sha256Digest, domain_separated_digest,
};
use ostk_fleet_recall::memory_contracts::discrepancy::{
    DiscrepancyEpisodeFingerprintV1, DiscrepancyFamilyFingerprintV1, DiscrepancySeverityV1,
};
use ostk_fleet_recall::memory_contracts::evidence::AcceptedEventId;
use ostk_fleet_recall::memory_contracts::evidence_v2::RegistryHeadBindingV1;
use ostk_fleet_recall::memory_contracts::identity::ResourceUri;
use ostk_fleet_recall::memory_contracts::normative::{NormativePropositionV1, SourceByteSpanV1};
use ostk_fleet_recall::memory_contracts::normative_v2::NormativeBindingProposalV2;
use ostk_fleet_recall::memory_contracts::observer::{EvaluatedConditionV1, VerificationOutcomeV1};
use ostk_fleet_recall::memory_contracts::registry::RegistryHeadV1;
use ostk_fleet_recall::spec_conformance::{
    CockroachSpecRepository, ExpectedMembershipV1, RememberActionExpectationV1, SpecCheckRecordV1,
    SpecRowWriteV1, SpecVerdictV1, repository_selector,
};
use ostk_fleet_recall::{FleetError, FleetScope, TrustedControlScope};
use ostk_recall_core::PrivacyTier;
use sqlx::PgPool;
use uuid::Uuid;

fn label(value: &str) -> Sha256Digest {
    domain_separated_digest(DigestDomain::RegistryEntry, value.as_bytes())
}

fn timestamp(value: &str) -> CanonicalTimestamp {
    CanonicalTimestamp::parse(value).expect("fixture timestamp must be canonical")
}

fn resource(form: &str, kind: &str, value: &str) -> ResourceUri {
    format!("urn:ostk:{form}:v1:{kind}:sha256:{}", label(value))
        .parse()
        .expect("fixture resource URI must be valid")
}

fn reference(id: &str) -> RegistryReferenceV1 {
    RegistryReferenceV1 {
        entry_id: ContractId::new(id).unwrap(),
        version: 1,
        entry_digest: label(id),
    }
}

fn commit(byte: &str) -> GitObjectId {
    GitObjectId::parse_hex(&byte.repeat(20)).unwrap()
}

/// "`Action` in `src/service.rs` must (or must not) declare `member`."
fn expectation(member: &str, expected: ExpectedMembershipV1) -> RememberActionExpectationV1 {
    RememberActionExpectationV1 {
        schema_version: 1,
        predicate: reference("mcp.remember.allowed_actions"),
        source_path: "src/service.rs".into(),
        enum_name: "Action".into(),
        member: member.into(),
        expected,
        severity: DiscrepancySeverityV1::High,
    }
}

/// A proposal in `scope` that carries exactly `expectation`, in a binding
/// family named after its member.
fn proposal_for(
    expectation: &RememberActionExpectationV1,
    scope: AuthenticatedProjectScopeV1,
) -> NormativeBindingProposalV2 {
    let fingerprint = expectation.fingerprint().unwrap();
    let mut proposal = NormativeBindingProposalV2 {
        schema_version: 2,
        profile: frozen_profile_reference_v1(),
        scope,
        binding_family_id: ContractId::new(format!(
            "spec.remember.{}",
            expectation.member.to_ascii_lowercase()
        ))
        .unwrap(),
        expected_active_binding_set_digest: None,
        repository_entity_id: resource("entity", "repository", "repo"),
        repository_version_id: resource("version", "git_blob", "spec"),
        blob_id: resource("occurrence", "git_blob", "spec"),
        exact_path_bytes: HexBytes::new(b"docs/spec.md".to_vec()).unwrap(),
        source_spans: vec![SourceByteSpanV1 {
            start: 0,
            end: 40,
            selected_bytes_digest: label("span"),
        }],
        parser_artifact_id: resource("occurrence", "artifact", "parser"),
        parser_configuration_digest: fingerprint,
        propositions: vec![NormativePropositionV1 {
            predicate_schema: expectation.predicate.clone(),
            proposition_fingerprint: fingerprint,
        }],
        applicability_evaluator: reference("applicability.repository"),
        applicability_selector: CanonicalValue::Null,
        effective_from: timestamp("2026-09-01T00:00:00.000000000Z"),
        effective_until: None,
        registry_head: RegistryHeadBindingV1 {
            head: RegistryHeadV1 {
                activation_id: label("activation"),
                package_digest: label("package"),
                activation_policy_digest: label("policy"),
            },
            effective_from: timestamp("2026-01-01T00:00:00.000000000Z"),
            effective_until: None,
        },
        explicitly_supersedes_statement_id: None,
        proposer_principal_id: ContractId::new("principal.dave").unwrap(),
        source_author_principal_id: ContractId::new("principal.carol").unwrap(),
    };
    proposal.applicability_selector = repository_selector(&proposal);
    proposal
}

/// A check of `statement_id`'s "`Forget` must be absent" expectation at
/// `commit`, where the observer verified `Forget` present.
fn nonconforming(statement_id: Sha256Digest, commit: &GitObjectId) -> SpecCheckRecordV1 {
    let at = commit.to_hex();
    SpecCheckRecordV1 {
        schema_version: 1,
        statement_id,
        binding_family_id: ContractId::new("spec.remember.forget").unwrap(),
        family_fingerprint: DiscrepancyFamilyFingerprintV1::from_digest(label("family")),
        commit_oid: commit.clone(),
        observed_revision_uri: resource("version", "git_blob", &format!("service {at}")),
        observer_event_id: AcceptedEventId::from_digest(label(&format!("observer {at}"))),
        blob_event_id: AcceptedEventId::from_digest(label(&format!("blob {at}"))),
        member: "Forget".into(),
        expected: ExpectedMembershipV1::Absent,
        observed_condition: EvaluatedConditionV1::Present,
        verification_outcome: VerificationOutcomeV1::VerifiedPositive,
        verdict: SpecVerdictV1::Nonconforming,
        reasons: Vec::new(),
        episode: Some(DiscrepancyEpisodeFingerprintV1::from_digest(label(
            "episode",
        ))),
        compared_at: timestamp("2026-09-02T00:00:00.000000000Z"),
    }
}

/// The same statement at `commit`, where the observer could not verify the
/// member either way.
fn unknown(statement_id: Sha256Digest, commit: &GitObjectId) -> SpecCheckRecordV1 {
    SpecCheckRecordV1 {
        observed_condition: EvaluatedConditionV1::Indeterminate,
        verification_outcome: VerificationOutcomeV1::Indeterminate,
        verdict: SpecVerdictV1::Unknown,
        reasons: vec![
            ComparisonIndeterminacyV1::ObservedUnmeasured,
            ComparisonIndeterminacyV1::ObservedUnknownCoverage,
        ],
        episode: None,
        ..nonconforming(statement_id, commit)
    }
}

fn spec_repository(pool: &PgPool, scope: &FleetScope) -> CockroachSpecRepository {
    CockroachSpecRepository::new(
        pool.clone(),
        TrustedControlScope::from_trusted_context(scope, semantic_scope()).unwrap(),
        retry_policy(),
    )
}

/// Require a refusal by the store's own checks (a contract or verification
/// error), not a database failure such as a missing privilege.
#[track_caller]
fn assert_refused<T: std::fmt::Debug>(result: ostk_fleet_recall::Result<T>, why: &str) {
    match result {
        Err(FleetError::Memory(_) | FleetError::ControlContract(_)) => {}
        other => panic!("{why}: {other:?}"),
    }
}

/// Run `body` with a pool authenticated as a login holding only the runtime
/// role's grants, and drop that login afterwards even when `body` fails.
async fn as_runtime_role<F, Fut>(owner: &PgPool, database_url: &str, body: F)
where
    F: FnOnce(PgPool) -> Fut,
    Fut: Future<Output = ()>,
{
    let role = RuntimeProbeRole::create_worker(owner, database_url, true).await;
    let outcome = AssertUnwindSafe(body(role.pool.clone()))
        .catch_unwind()
        .await;
    role.drop_role(owner).await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

/// A statement minted for another project scope, or whose expectation its
/// proposal does not carry, is refused and leaves no row.
async fn refuses_statements_it_cannot_bind(repository: &CockroachSpecRepository) {
    let forget_absent = expectation("Forget", ExpectedMembershipV1::Absent);
    let record_proposal = proposal_for(
        &expectation("Record", ExpectedMembershipV1::Present),
        semantic_scope(),
    );
    let foreign_scope = proposal_for(
        &forget_absent,
        AuthenticatedProjectScopeV1::from_trusted_context(
            ContractId::new("tenant.acme").unwrap(),
            ContractId::new("project.other").unwrap(),
        ),
    );
    assert_refused(
        repository
            .record_statement(&foreign_scope, &forget_absent)
            .await,
        "a proposal minted for another project scope must be refused",
    );
    assert_refused(
        repository
            .record_statement(&record_proposal, &forget_absent)
            .await,
        "an expectation the proposal does not carry must be refused",
    );
    for refused in [&foreign_scope, &record_proposal] {
        assert!(
            repository
                .read_statement(refused.statement_id().unwrap())
                .await
                .unwrap()
                .is_none(),
            "a refused statement must leave no row"
        );
    }
}

/// Statement rows edited in place by `owner`, in a column or in their
/// canonical bytes, are refused on read, and a re-record does not read the
/// diverged row as already recorded. `repository` has recorded the
/// "`Forget` must be absent" statement.
async fn refuses_statement_rows_edited_in_place(
    owner: &PgPool,
    repository: &CockroachSpecRepository,
    scope: &FleetScope,
) {
    let forget_absent = expectation("Forget", ExpectedMembershipV1::Absent);
    let forget_proposal = proposal_for(&forget_absent, semantic_scope());
    let forget_statement = forget_proposal.statement_id().unwrap();
    let record_present = expectation("Record", ExpectedMembershipV1::Present);
    let record_proposal = proposal_for(&record_present, semantic_scope());

    // A column edited in place: the stored family is no longer the
    // proposal's.
    sqlx::query(
        "UPDATE public.memory_normative_statements_v1 SET binding_family_id = $4 \
         WHERE tenant_id = $1 AND project = $2 AND statement_id = $3",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(forget_statement.as_bytes().as_slice())
    .bind("spec.remember.tampered")
    .execute(owner)
    .await
    .unwrap();
    assert_refused(
        repository.read_statement(forget_statement).await,
        "a statement row edited in place must be refused on read",
    );
    assert_refused(
        repository
            .record_statement(&forget_proposal, &forget_absent)
            .await,
        "a stored row whose bytes diverge must not read as already recorded",
    );

    // Canonical bytes swapped in place: another expectation, stored with its
    // own digest, so only the proposal's binding can tell.
    let record = repository
        .record_statement(&record_proposal, &record_present)
        .await
        .unwrap();
    assert_eq!(record.write, SpecRowWriteV1::Inserted);
    sqlx::query(
        "UPDATE public.memory_normative_statements_v1 \
         SET canonical_expectation = $4, expectation_digest = $5 \
         WHERE tenant_id = $1 AND project = $2 AND statement_id = $3",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(record.statement_id.as_bytes().as_slice())
    .bind(forget_absent.canonical_bytes().unwrap())
    .bind(forget_absent.fingerprint().unwrap().as_bytes().as_slice())
    .execute(owner)
    .await
    .unwrap();
    assert_refused(
        repository.read_statement(record.statement_id).await,
        "an expectation its proposal never approved must be refused on read",
    );
}

/// A check citing a statement the scope never recorded, or judging another
/// expectation than its statement's, is refused and leaves no row; a check
/// row edited in place by `owner` is refused on read and on replay.
/// `repository` has recorded `statement_id` ("`Forget` must be absent") and
/// its nonconforming check at commit `c0`, and nothing else nonconforming.
async fn refuses_foreign_and_edited_checks(
    owner: &PgPool,
    repository: &CockroachSpecRepository,
    scope: &FleetScope,
    statement_id: Sha256Digest,
) {
    let (c0, c1) = (commit("c0"), commit("c1"));
    assert_refused(
        repository
            .record_check(&nonconforming(label("never recorded"), &c0))
            .await,
        "a check of a statement this scope never recorded must be refused",
    );
    let other_member = SpecCheckRecordV1 {
        member: "Record".into(),
        ..nonconforming(statement_id, &c1)
    };
    assert_refused(
        repository.record_check(&other_member).await,
        "a check of another expectation than its statement's must be refused",
    );
    assert!(
        repository
            .nonconforming_check_for(statement_id, &c1)
            .await
            .unwrap()
            .is_none(),
        "a refused check must leave no row"
    );

    // An indexed column edited in place no longer matches its record.
    let judged = nonconforming(statement_id, &c0);
    sqlx::query(
        "UPDATE public.memory_spec_checks_v1 SET observer_event_id = $4 \
         WHERE tenant_id = $1 AND project = $2 AND check_id = $3",
    )
    .bind(scope.tenant_id)
    .bind(&scope.project)
    .bind(judged.check_id().unwrap().as_bytes().as_slice())
    .bind(label("another observer event").as_bytes().as_slice())
    .execute(owner)
    .await
    .unwrap();
    assert_refused(
        repository.nonconforming_check_for(statement_id, &c0).await,
        "a check row edited in place must be refused on read",
    );
    assert_refused(
        repository.record_check(&judged).await,
        "a stored check whose columns diverge must not read as already recorded",
    );
}

#[tokio::test]
async fn live_statement_rows_are_content_addressed_and_idempotent_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let owner = common::migrated_pool(&database_url).await;
    let scope = common::fresh_scope("spec-statements");
    let owner_ref = &owner;
    as_runtime_role(&owner, &database_url, |pool| async move {
        let repository = spec_repository(&pool, &scope);
        let forget_absent = expectation("Forget", ExpectedMembershipV1::Absent);
        let forget_proposal = proposal_for(&forget_absent, semantic_scope());

        let first = repository
            .record_statement(&forget_proposal, &forget_absent)
            .await
            .unwrap();
        assert_eq!(first.write, SpecRowWriteV1::Inserted);
        assert_eq!(first.statement_id, forget_proposal.statement_id().unwrap());
        let replay = repository
            .record_statement(&forget_proposal, &forget_absent)
            .await
            .unwrap();
        assert_eq!(replay.write, SpecRowWriteV1::AlreadyRecorded);
        assert_eq!(replay.statement_id, first.statement_id);

        let stored = repository
            .read_statement(first.statement_id)
            .await
            .unwrap()
            .expect("a recorded statement reads back");
        assert_eq!(stored.proposal, forget_proposal);
        assert_eq!(stored.expectation, forget_absent);
        assert!(
            repository
                .read_statement(label("never recorded"))
                .await
                .unwrap()
                .is_none()
        );

        refuses_statements_it_cannot_bind(&repository).await;
        refuses_statement_rows_edited_in_place(owner_ref, &repository, &scope).await;
    })
    .await;
}

#[tokio::test]
async fn live_check_records_replay_to_one_row_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let owner = common::migrated_pool(&database_url).await;
    let scope = common::fresh_scope("spec-checks");
    let owner_ref = &owner;
    as_runtime_role(&owner, &database_url, |pool| async move {
        let repository = spec_repository(&pool, &scope);
        let forget_absent = expectation("Forget", ExpectedMembershipV1::Absent);
        let proposal = proposal_for(&forget_absent, semantic_scope());
        let statement_id = repository
            .record_statement(&proposal, &forget_absent)
            .await
            .unwrap()
            .statement_id;
        let (c0, c1) = (commit("c0"), commit("c1"));

        let judged = nonconforming(statement_id, &c0);
        let first = repository.record_check(&judged).await.unwrap();
        assert_eq!(first.write, SpecRowWriteV1::Inserted);
        assert_eq!(first.check_id, judged.check_id().unwrap());
        let replay = repository.record_check(&judged).await.unwrap();
        assert_eq!(replay.write, SpecRowWriteV1::AlreadyRecorded);
        assert_eq!(replay.check_id, first.check_id);

        let stored = repository
            .nonconforming_check_for(statement_id, &c0)
            .await
            .unwrap()
            .expect("the commit was judged nonconforming");
        assert_eq!(stored.check_id, first.check_id);
        assert_eq!(stored.record, judged);
        let latest = repository.latest_checks(&[statement_id]).await.unwrap();
        assert_eq!(
            latest
                .iter()
                .map(|check| check.check_id)
                .collect::<Vec<_>>(),
            vec![first.check_id]
        );

        // A later check of another commit becomes the newest; replaying the
        // older one afterwards neither makes it newest again nor moves it.
        let later = unknown(statement_id, &c1);
        let later_write = repository.record_check(&later).await.unwrap();
        assert_eq!(later_write.write, SpecRowWriteV1::Inserted);
        assert_eq!(
            repository.record_check(&judged).await.unwrap().write,
            SpecRowWriteV1::AlreadyRecorded
        );
        let latest = repository
            .latest_checks(&[statement_id, statement_id, label("never checked")])
            .await
            .unwrap();
        assert_eq!(
            latest
                .iter()
                .map(|check| check.check_id)
                .collect::<Vec<_>>(),
            vec![later_write.check_id],
            "the newest check is the latest one written, and a never-checked statement is absent"
        );
        assert_eq!(latest[0].record, later);
        let after_replay = repository
            .nonconforming_check_for(statement_id, &c0)
            .await
            .unwrap()
            .expect("the judgment is still there");
        assert_eq!(after_replay.check_id, first.check_id);
        assert_eq!(
            after_replay.recorded_at, stored.recorded_at,
            "a replay must not move the first write"
        );
        assert!(
            repository
                .nonconforming_check_for(statement_id, &c1)
                .await
                .unwrap()
                .is_none(),
            "an unknown check is not a judgment"
        );

        refuses_foreign_and_edited_checks(owner_ref, &repository, &scope, statement_id).await;
    })
    .await;
}

#[tokio::test]
async fn live_two_projects_cannot_see_each_others_spec_rows_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let tenant = Uuid::now_v7();
    let physical = |tenant, project: &str| {
        FleetScope::new(
            tenant,
            project,
            common::LIVE_TEST_AGENT,
            None,
            PrivacyTier::T1Project,
        )
        .unwrap()
    };
    let alpha = spec_repository(&pool, &physical(tenant, "spec-alpha"));
    let beta = spec_repository(&pool, &physical(tenant, "spec-beta"));
    let alpha_elsewhere = spec_repository(&pool, &physical(Uuid::now_v7(), "spec-alpha"));

    let forget_absent = expectation("Forget", ExpectedMembershipV1::Absent);
    let proposal = proposal_for(&forget_absent, semantic_scope());
    let c0 = commit("c0");
    let statement_id = alpha
        .record_statement(&proposal, &forget_absent)
        .await
        .unwrap()
        .statement_id;
    let check = nonconforming(statement_id, &c0);
    let check_id = alpha.record_check(&check).await.unwrap().check_id;

    for (name, other) in [
        ("another project of the same tenant", &beta),
        (
            "the same project name under another tenant",
            &alpha_elsewhere,
        ),
    ] {
        assert!(
            other.read_statement(statement_id).await.unwrap().is_none(),
            "{name} must not read the statement"
        );
        assert!(
            other
                .latest_checks(&[statement_id])
                .await
                .unwrap()
                .is_empty(),
            "{name} must not read the checks"
        );
        assert!(
            other
                .nonconforming_check_for(statement_id, &c0)
                .await
                .unwrap()
                .is_none(),
            "{name} must not read the judgment"
        );
        assert_refused(
            other.record_check(&check).await,
            &format!("{name} must not record a check against a statement it does not hold"),
        );
    }

    // The same statement and check recorded in the other project are that
    // project's own rows, not replays of the first project's.
    assert_eq!(
        beta.record_statement(&proposal, &forget_absent)
            .await
            .unwrap()
            .write,
        SpecRowWriteV1::Inserted
    );
    let beta_check = beta.record_check(&check).await.unwrap();
    assert_eq!(beta_check.write, SpecRowWriteV1::Inserted);
    assert_eq!(beta_check.check_id, check_id);
    assert_eq!(
        alpha.record_check(&check).await.unwrap().write,
        SpecRowWriteV1::AlreadyRecorded
    );
    assert!(
        alpha_elsewhere
            .read_statement(statement_id)
            .await
            .unwrap()
            .is_none()
    );
}
