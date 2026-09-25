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
//!
//! It also proves `ostk-spec draft|approve|activate`'s library path over an
//! installed generation-2 writer authority and a scratch git repository: a
//! draft cites exactly the spec bytes it selects and names the repository its
//! provider id derives; a statement signed by the active policy's approvers
//! activates under the witnessed head, reads back, and activates again as
//! `already_active` with nothing appended; and a proposal drafted under
//! another head activates nothing.
//!
//! And it proves `recall(action="discrepancies")`'s read over seeded spec,
//! normative, and discrepancy rows: by default only the standing episodes of
//! specs in force, each with the statement it violates and the commit its
//! opening check observed, beside every spec's latest check, `unknown`
//! included; `include_resolved` adds closed episodes and episodes of specs
//! not in force; only specs in force at the database's time count as
//! active, and an expired spec's episodes are hidden by default while a
//! scheduled spec's are listed; an episode looked up by id carries its
//! lifecycle history; another project sees none of it; and the action is served, with
//! `recall(status)`'s block, exactly when the login may SELECT every table it
//! reads, while an unserved deployment keeps its tools and status as they
//! were.
//!
//! And it proves `ostk-spec check` and `ostk-spec episode resolve|dismiss`
//! over a memory worker's git source: a commit that declares a forbidden
//! member opens an episode, a commit that drops it checks as `unknown` and
//! leaves the episode standing, an operator resolves the episode citing that
//! later check's observer event by default (never the nonconformance itself
//! or a truncated re-read of the violating commit), after which
//! `recall(discrepancies)` lists it only with `include_resolved` and a
//! re-check of the offending commit joins it as already judged instead of
//! re-opening; a retried resolution answers with the recorded one and a
//! closed episode is not closed again; a dismissal without a rationale is
//! refused and appends nothing.
//!
//! And it proves the whole chain end to end, over the observer's checked-in
//! snapshot of `src/service.rs`, through only the entry points `ostk-spec`
//! and `serve` call: a memory-worker tick covers the repository; an operator
//! drafts "`Forget` must be absent", both approvers sign it, and it activates;
//! a check of the commit that declares `Forget` records a verified
//! nonconformance and opens one episode, and checking it again replays the
//! same check into that episode; an agent reads the episode, the expectation
//! it violates, the observed commit, and the spec's latest check over MCP,
//! whose `tools/list` advertises the action. A commit that drops `Forget`
//! checks as `unknown`, never `conforming`, and leaves the episode open,
//! while "`Record` must be present" checks as `conforming` and opens nothing.
//! And a login that holds no grant itself, only membership in a role holding
//! the runtime grants, as `fleet_writer` is a member of `fleet_runtime`, runs
//! the worker tick, the activation, the check, and the read.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::ops::Range;
use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use chrono::{DateTime, TimeDelta, Utc};
use common::authority::{InstalledAuthority, install_generation_two, retry_policy, semantic_scope};
use common::runtime_role::RuntimeProbeRole;
use common::worker::{
    FIRST_COMMIT_DATE, INSTALLATION_ID, RecordedCi, SECOND_COMMIT_DATE, ScratchRepository,
    StubEmbedder,
};
use futures::FutureExt as _;
use ostk_fleet_recall::connectors::git::GitObjectId;
use ostk_fleet_recall::discrepancy_runtime::{
    CockroachDiscrepancyLedgerRepository, ComparisonIndeterminacyV1, ComparisonVerdictV1,
    DiscrepancyLedgerRepository as _, DiscrepancyRegistryBindingV1,
};
use ostk_fleet_recall::evidence_ledger::ContentKeyEncryptionKey;
use ostk_fleet_recall::ledger::CockroachClaimLedger;
use ostk_fleet_recall::mcp::{McpServer, tool_list, tool_list_for_surfaces};
use ostk_fleet_recall::memory_contracts::ContractError;
use ostk_fleet_recall::memory_contracts::canonical::CanonicalValue;
use ostk_fleet_recall::memory_contracts::common::{
    AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, HexBytes, RegistryReferenceV1,
    frozen_profile_reference_v1,
};
use ostk_fleet_recall::memory_contracts::digest::{
    DigestDomain, Sha256Digest, domain_separated_digest,
};
use ostk_fleet_recall::memory_contracts::discrepancy::{
    DiscrepancyActorV1, DiscrepancyEnvelopeV1, DiscrepancyEpisodeFingerprintV1,
    DiscrepancyFamilyFingerprintV1, DiscrepancyLifecycleEventV1, DiscrepancySeverityV1,
    DismissalReasonKindV1, LifecycleState, LifecycleTransitionV1,
};
use ostk_fleet_recall::memory_contracts::evidence::{AcceptedEventId, SourceFactId};
use ostk_fleet_recall::memory_contracts::evidence_v2::RegistryHeadBindingV1;
use ostk_fleet_recall::memory_contracts::identity::ResourceUri;
use ostk_fleet_recall::memory_contracts::normative::{NormativePropositionV1, SourceByteSpanV1};
use ostk_fleet_recall::memory_contracts::normative_v2::{
    ApprovalAttestationV1, NormativeActivationReceiptV2, NormativeActivationSeparationOfDutyV2,
    NormativeBindingProposalV2,
};
use ostk_fleet_recall::memory_contracts::observer::{EvaluatedConditionV1, VerificationOutcomeV1};
use ostk_fleet_recall::memory_contracts::registry::{EligibleApprovalV1, RegistryHeadV1};
use ostk_fleet_recall::normative_runtime::{
    CockroachNormativeActivationRepository, NormativeActivationCandidateV1,
    NormativeActivationOutcomeV1, NormativeActivationRepository as _, NormativeRegistryBindingV1,
    NormativeResolutionV1, sign_normative_approval,
};
use ostk_fleet_recall::registry_witness::WriterAuthorityRuntime;
use ostk_fleet_recall::service::{
    FleetMemoryService, RecallAction, RecallRequest, RecallResult, ServiceError,
};
use ostk_fleet_recall::spec_conformance::{
    CockroachSpecRepository, DraftStatementRequestV1, ExpectedMembershipV1,
    RememberActionExpectationV1, SpecActivationOutcomeV1, SpecCheckOutcomeV1, SpecCheckRecordV1,
    SpecCheckRequestV1, SpecConformanceAnswerV1, SpecConformanceRead, SpecDetectionV1,
    SpecDiscrepancyActionV1, SpecEffectV1, SpecEpisodeTransitionV1, SpecRowWriteV1, SpecSummaryV1,
    SpecVerdictV1, activate_spec_statement, append_episode_lifecycle, build_spec_envelope,
    database_now, draft_spec_statement, normative_repository, repository_selector,
    repository_subject, require_spec_statement, run_spec_check, spec_predicate,
    spec_repository as runtime_spec_repository, spec_span_digest, start_spec_conformance,
};
use ostk_fleet_recall::store::cockroach::{
    CockroachStore, DatabaseCapabilities, SPEC_CONFORMANCE_SCHEMA_VERSION, probe_spec_conformance,
};
use ostk_fleet_recall::worker::{MemoryWorker, WorkerDeps, WorkerSourcesV1, parse_steps};
use ostk_fleet_recall::{CockroachMemoryService, FleetError, FleetScope, TrustedControlScope};
use ostk_recall_core::{ChunkEmbedder, PrivacyTier};
use serde_json::{Map, Value, json};
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
    as_role(owner, role, body).await;
}

/// Run `body` with `role`'s pool, and drop `role` afterwards even when `body`
/// fails.
async fn as_role<F, Fut>(owner: &PgPool, role: RuntimeProbeRole, body: F)
where
    F: FnOnce(PgPool) -> Fut,
    Fut: Future<Output = ()>,
{
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

// --- ostk-spec draft, approve, activate ---

/// The spec document the scratch repository carries at its first commit.
const SPEC_DOCUMENT: &[u8] =
    b"# Remember actions\n\nForget must not be a remember action.\n\nRecord stays.\n";
/// The sentence every drafted statement cites.
const SPEC_SENTENCE: &str = "Forget must not be a remember action.";
/// The same document revised at the second commit: the cited byte range now
/// selects other bytes.
const REVISED_SPEC_DOCUMENT: &[u8] =
    b"# Remember actions\n\nForget may never be a remember action.\n\nRecord stays.\n";
const SPEC_PATH: &str = "docs/spec.md";
const SERVICE_SOURCE: &[u8] = b"pub enum RememberAction {\n    Record,\n    Forget,\n}\n";
const SPEC_REPOSITORY_ID: &str = "git.repo.spec";
const PROVIDER_REPOSITORY_ID: u64 = 908_172_635;
const SPEC_FAMILY: &str = "spec.remember.no_forget";

/// The active activation policy's approvers and their public fixture seeds
/// (D4: nominal keys). Carol authors the spec and Dave proposes it, so
/// neither may approve.
const APPROVERS: [(&str, u8); 2] = [("principal.alice", 0x01), ("principal.bob", 0x02)];
const AUTHOR: &str = "principal.carol";
const PROPOSER: &str = "principal.dave";

fn id(value: &str) -> ContractId {
    ContractId::new(value).unwrap()
}

fn instant(at: DateTime<Utc>) -> CanonicalTimestamp {
    CanonicalTimestamp::from_datetime(&at).unwrap()
}

/// The half-open byte range `sentence` occupies in `document`.
fn span_of(document: &[u8], sentence: &str) -> Range<u64> {
    let start = document
        .windows(sentence.len())
        .position(|window| window == sentence.as_bytes())
        .expect("the sentence is in the document");
    u64::try_from(start).unwrap()..u64::try_from(start + sentence.len()).unwrap()
}

/// A scratch repository whose main has two commits: the spec document and
/// the service source, then the revised spec document. Returns both ids.
fn spec_repository_with_two_commits() -> (ScratchRepository, String, String) {
    let repository = ScratchRepository::empty();
    let first = repository.commit_files(
        None,
        &[
            (SPEC_PATH, SPEC_DOCUMENT),
            ("src/service.rs", SERVICE_SOURCE),
        ],
        "specify the remember actions",
        FIRST_COMMIT_DATE,
    );
    let second = repository.commit_files(
        Some(&first),
        &[
            (SPEC_PATH, REVISED_SPEC_DOCUMENT),
            ("src/service.rs", SERVICE_SOURCE),
        ],
        "revise the remember actions spec",
        SECOND_COMMIT_DATE,
    );
    (repository, first, second)
}

/// "`RememberAction` in `src/service.rs` must not declare `Forget`", citing
/// the spec sentence at `commit`.
fn draft_request(
    repository: &ScratchRepository,
    commit: &str,
    effective_from: CanonicalTimestamp,
) -> DraftStatementRequestV1 {
    DraftStatementRequestV1 {
        git_dir: repository.path().to_path_buf(),
        repository_id: id(SPEC_REPOSITORY_ID),
        installation_id: INSTALLATION_ID,
        provider_repository_id: PROVIDER_REPOSITORY_ID,
        commit: GitObjectId::parse_hex(commit).unwrap(),
        spec_path: SPEC_PATH.into(),
        spans: vec![span_of(SPEC_DOCUMENT, SPEC_SENTENCE)],
        binding_family_id: id(SPEC_FAMILY),
        source_path: "src/service.rs".into(),
        enum_name: "RememberAction".into(),
        member: "Forget".into(),
        expected: ExpectedMembershipV1::Absent,
        severity: DiscrepancySeverityV1::High,
        effective_from,
        effective_until: None,
        supersedes: None,
        proposer: id(PROPOSER),
        author: id(AUTHOR),
    }
}

/// Both approvers' signatures over `proposal`, made at `signed_at`.
fn approvals(
    proposal: &NormativeBindingProposalV2,
    signed_at: &CanonicalTimestamp,
) -> Vec<ApprovalAttestationV1> {
    APPROVERS
        .iter()
        .map(|(principal, seed)| {
            sign_normative_approval(proposal, id(principal), &[*seed; 32], signed_at.clone())
                .unwrap()
        })
        .collect()
}

/// Activate `proposal` with both approvals, accepted at the database's time
/// now.
async fn activate_signed(
    runtime: &WriterAuthorityRuntime,
    proposal: &NormativeBindingProposalV2,
    expectation: &RememberActionExpectationV1,
    signed_at: &CanonicalTimestamp,
) -> ostk_fleet_recall::Result<ostk_fleet_recall::spec_conformance::SpecActivationV1> {
    let accepted_at = instant(database_now(runtime.pool()).await.unwrap());
    activate_spec_statement(
        runtime,
        proposal,
        expectation,
        &approvals(proposal, signed_at),
        &accepted_at,
    )
    .await
}

#[tokio::test]
async fn live_a_signed_statement_activates_under_the_witnessed_head_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let owner = common::migrated_pool(&database_url).await;
    let installed = install_generation_two(&owner, "spec-activate").await;
    let (repository, first, _) = spec_repository_with_two_commits();
    let (installed, repository) = (&installed, &repository);
    as_runtime_role(&owner, &database_url, |pool| async move {
        let runtime = installed.runtime(&pool).await;
        let now = database_now(&pool).await.unwrap();
        // Activation must precede the statement's effect; 60 seconds is
        // ample for a slow runner.
        let effective_from = instant(now + TimeDelta::seconds(60));
        let request = draft_request(repository, &first, effective_from.clone());
        let (proposal, expectation) = draft_spec_statement(&runtime, &request).await.unwrap();
        let statement_id = proposal.statement_id().unwrap();
        let family = &proposal.binding_family_id;

        let activated = activate_signed(&runtime, &proposal, &expectation, &instant(now))
            .await
            .unwrap();
        assert!(
            matches!(activated.outcome, SpecActivationOutcomeV1::Installed { .. }),
            "{activated:?}"
        );
        assert_eq!(activated.statement_id, statement_id);
        assert_eq!(activated.statement_row, SpecRowWriteV1::Inserted);

        let verified = runtime.verify().await.unwrap();
        let normative = normative_repository(&runtime, verified.witness()).unwrap();
        let projection = normative
            .read_projection(family)
            .await
            .unwrap()
            .expect("an activated family has a projection");
        assert_eq!(
            projection.resolution,
            NormativeResolutionV1::Active { statement_id }
        );
        let stored = runtime_spec_repository(&runtime)
            .read_statement(statement_id)
            .await
            .unwrap()
            .expect("an activated statement is recorded");
        assert_eq!(stored.proposal, proposal);
        assert_eq!(stored.expectation, expectation);

        // Activating it again appends nothing and moves nothing.
        let log = normative.read_log(family).await.unwrap();
        let head = normative.read_head(family).await.unwrap();
        let again = activate_signed(&runtime, &proposal, &expectation, &instant(now))
            .await
            .unwrap();
        assert_eq!(again.outcome, SpecActivationOutcomeV1::AlreadyActive);
        assert_eq!(again.statement_row, SpecRowWriteV1::AlreadyRecorded);
        assert_eq!(normative.read_log(family).await.unwrap(), log);
        assert_eq!(normative.read_head(family).await.unwrap(), head);

        // A later draft in the family expects the binding set the
        // activation installed.
        let (next, _) = draft_spec_statement(&runtime, &request).await.unwrap();
        assert_eq!(
            next.expected_active_binding_set_digest,
            head.expect("an activated family has a head")
                .active_binding_set_digest
        );
    })
    .await;
}

#[tokio::test]
async fn live_a_stale_head_proposal_activates_nothing_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let owner = common::migrated_pool(&database_url).await;
    let installed = install_generation_two(&owner, "spec-stale-head").await;
    let (repository, first, _) = spec_repository_with_two_commits();
    let (installed, repository) = (&installed, &repository);
    as_runtime_role(&owner, &database_url, |pool| async move {
        let runtime = installed.runtime(&pool).await;
        let now = database_now(&pool).await.unwrap();
        let request = draft_request(repository, &first, instant(now + TimeDelta::seconds(60)));
        let (proposal, expectation) = draft_spec_statement(&runtime, &request).await.unwrap();

        // The same package and policy digests, which is all the normative
        // runtime's own admission compares: only the witnessed head's exact
        // activation and interval tell these apart.
        let mut earlier_activation = proposal.clone();
        earlier_activation.registry_head.head.activation_id = label("an earlier activation");
        let mut other_interval = proposal.clone();
        let head_from =
            DateTime::parse_from_rfc3339(proposal.registry_head.effective_from.as_str())
                .unwrap()
                .with_timezone(&Utc);
        other_interval.registry_head.effective_from = instant(head_from - TimeDelta::seconds(1));

        for (stale, why) in [
            (
                &earlier_activation,
                "another activation of the same package",
            ),
            (&other_interval, "another effective interval of the head"),
        ] {
            match activate_signed(&runtime, stale, &expectation, &instant(now)).await {
                Err(FleetError::ControlContract(ContractError::StaleRegistryHead)) => {}
                other => panic!("{why} must be a stale head: {other:?}"),
            }
            assert!(
                runtime_spec_repository(&runtime)
                    .read_statement(stale.statement_id().unwrap())
                    .await
                    .unwrap()
                    .is_none(),
                "{why}: a stale proposal must leave no statement row"
            );
        }
        let verified = runtime.verify().await.unwrap();
        let normative = normative_repository(&runtime, verified.witness()).unwrap();
        assert!(
            normative
                .read_head(&proposal.binding_family_id)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            normative
                .read_log(&proposal.binding_family_id)
                .await
                .unwrap()
                .is_empty()
        );
    })
    .await;
}

/// A span past the end of the spec document, a spec path the commit does not
/// have, and an author who proposes their own spec are refused.
async fn refuses_drafts_it_cannot_bind(
    runtime: &WriterAuthorityRuntime,
    request: &DraftStatementRequestV1,
) {
    let document_length = u64::try_from(SPEC_DOCUMENT.len()).unwrap();
    for (refused, why) in [
        (
            DraftStatementRequestV1 {
                spans: vec![Range {
                    start: 0,
                    end: document_length + 1,
                }],
                ..request.clone()
            },
            "a span past the end of the document",
        ),
        (
            DraftStatementRequestV1 {
                spec_path: "docs/absent.md".into(),
                ..request.clone()
            },
            "a spec path the commit does not have",
        ),
        (
            DraftStatementRequestV1 {
                proposer: id(AUTHOR),
                ..request.clone()
            },
            "an author who is also the proposer",
        ),
    ] {
        assert!(
            draft_spec_statement(runtime, &refused).await.is_err(),
            "{why} must be refused"
        );
    }
}

#[tokio::test]
async fn live_a_draft_binds_the_spec_span_and_the_repository_subject_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let owner = common::migrated_pool(&database_url).await;
    let installed = install_generation_two(&owner, "spec-draft").await;
    let (repository, first, second) = spec_repository_with_two_commits();
    let (installed, repository) = (&installed, &repository);
    as_runtime_role(&owner, &database_url, |pool| async move {
        let runtime = installed.runtime(&pool).await;
        let effective_from = instant(database_now(&pool).await.unwrap() + TimeDelta::seconds(60));
        let request = draft_request(repository, &first, effective_from);
        let (proposal, expectation) = draft_spec_statement(&runtime, &request).await.unwrap();
        let verified = runtime.verify().await.unwrap();
        let witness = verified.witness();

        // The cited span records exactly the bytes it selects.
        let [span] = proposal.source_spans.as_slice() else {
            panic!("one cited span");
        };
        assert_eq!(span.start..span.end, request.spans[0]);
        assert_eq!(
            span.selected_bytes_digest,
            spec_span_digest(SPEC_SENTENCE.as_bytes())
        );
        assert_eq!(proposal.exact_path_bytes.as_bytes(), SPEC_PATH.as_bytes());

        // It is a spec statement under the witnessed head and scope.
        assert_eq!(&proposal.registry_head, witness.head_binding());
        assert_eq!(&proposal.scope, runtime.semantic_scope());
        assert_eq!(proposal.expected_active_binding_set_digest, None);
        assert_eq!(
            expectation.predicate,
            spec_predicate(witness.genesis_package()).unwrap()
        );
        require_spec_statement(witness.genesis_package(), &proposal, &expectation).unwrap();

        // The subject is the repository the provider id names.
        assert_eq!(
            proposal.repository_entity_id,
            repository_subject(
                witness.package(),
                runtime.semantic_scope(),
                PROVIDER_REPOSITORY_ID
            )
            .unwrap()
        );
        let other_repository = DraftStatementRequestV1 {
            provider_repository_id: PROVIDER_REPOSITORY_ID + 1,
            ..request.clone()
        };
        let (elsewhere, _) = draft_spec_statement(&runtime, &other_repository)
            .await
            .unwrap();
        assert_ne!(
            elsewhere.repository_entity_id,
            proposal.repository_entity_id
        );

        // The same range at the revised commit is the same subject, but
        // another version of the document, another blob, and other bytes.
        let revised = DraftStatementRequestV1 {
            commit: GitObjectId::parse_hex(&second).unwrap(),
            ..request.clone()
        };
        let (at_revision, _) = draft_spec_statement(&runtime, &revised).await.unwrap();
        assert_eq!(
            at_revision.repository_entity_id,
            proposal.repository_entity_id
        );
        assert_ne!(
            at_revision.repository_version_id,
            proposal.repository_version_id
        );
        assert_ne!(at_revision.blob_id, proposal.blob_id);
        assert_ne!(
            at_revision.source_spans[0].selected_bytes_digest,
            span.selected_bytes_digest
        );

        // Drafting is deterministic.
        let (redrafted, _) = draft_spec_statement(&runtime, &request).await.unwrap();
        assert_eq!(
            redrafted.statement_id().unwrap(),
            proposal.statement_id().unwrap()
        );

        refuses_drafts_it_cannot_bind(&runtime, &request).await;
    })
    .await;
}

// --- recall(action="discrepancies") ---

/// One scope's spec store, normative runtime, and discrepancy ledger, the
/// last two bound to the labelled registry head `proposal_for` names.
struct SpecPlane {
    specs: CockroachSpecRepository,
    normative: CockroachNormativeActivationRepository,
    ledger: CockroachDiscrepancyLedgerRepository,
}

/// A statement "`Action` in `src/service.rs` must (not) declare `member`",
/// recorded as a spec.
struct SeededSpec {
    proposal: NormativeBindingProposalV2,
    expectation: RememberActionExpectationV1,
    statement_id: Sha256Digest,
}

impl SpecPlane {
    fn new(pool: &PgPool, scope: &FleetScope) -> Self {
        let trusted = TrustedControlScope::from_trusted_context(scope, semantic_scope()).unwrap();
        Self {
            specs: spec_repository(pool, scope),
            normative: CockroachNormativeActivationRepository::new(
                pool.clone(),
                trusted.clone(),
                NormativeRegistryBindingV1 {
                    registry_package_digest: label("package"),
                    activation_policy_digest: label("policy"),
                },
                retry_policy(),
            )
            .unwrap(),
            ledger: CockroachDiscrepancyLedgerRepository::new(
                pool.clone(),
                trusted,
                DiscrepancyRegistryBindingV1 {
                    registry_package_digest: label("package"),
                    activation_policy_digest: label("policy"),
                },
                retry_policy(),
            )
            .unwrap(),
        }
    }

    /// Record `member`'s statement as a spec, and make it normative when
    /// `live`.
    async fn statement(
        &self,
        member: &str,
        expected: ExpectedMembershipV1,
        live: bool,
    ) -> SeededSpec {
        let expectation = expectation(member, expected);
        let proposal = proposal_for(&expectation, semantic_scope());
        self.seed(proposal, expectation, live).await
    }

    /// Record "`member` must be absent" as a spec in effect over
    /// `[effective_from, effective_until)`, and make it normative.
    async fn statement_during(
        &self,
        member: &str,
        effective_from: CanonicalTimestamp,
        effective_until: Option<CanonicalTimestamp>,
    ) -> SeededSpec {
        let expectation = expectation(member, ExpectedMembershipV1::Absent);
        let proposal = NormativeBindingProposalV2 {
            effective_from,
            effective_until,
            ..proposal_for(&expectation, semantic_scope())
        };
        self.seed(proposal, expectation, true).await
    }

    async fn seed(
        &self,
        proposal: NormativeBindingProposalV2,
        expectation: RememberActionExpectationV1,
        live: bool,
    ) -> SeededSpec {
        let statement_id = self
            .specs
            .record_statement(&proposal, &expectation)
            .await
            .unwrap()
            .statement_id;
        if live {
            let outcome = self
                .normative
                .activate(&NormativeActivationCandidateV1 {
                    receipt: receipt_for(&proposal),
                    proposal: proposal.clone(),
                    retroactive_correction: None,
                })
                .await
                .unwrap();
            assert!(
                matches!(outcome, NormativeActivationOutcomeV1::Installed(_)),
                "{outcome:?}"
            );
        }
        SeededSpec {
            proposal,
            expectation,
            statement_id,
        }
    }

    /// A verified nonconformance of `spec` at `commit`, compared at `at`: its
    /// episode opened and its check recorded, as `ostk-spec check` leaves
    /// them.
    async fn nonconformance(
        &self,
        spec: &SeededSpec,
        commit: &GitObjectId,
        at: &str,
    ) -> DiscrepancyEnvelopeV1 {
        let name = format!("{} {}", spec.expectation.member, commit.to_hex());
        let observer = AcceptedEventId::from_digest(label(&format!("observer {name}")));
        let blob = AcceptedEventId::from_digest(label(&format!("blob {name}")));
        let compared_at = timestamp(at);
        let candidate = build_spec_envelope(&SpecDetectionV1 {
            registry: &spec.proposal.registry_head,
            statement_id: spec.statement_id,
            proposal: &spec.proposal,
            expectation: &spec.expectation,
            extractor: &reference("observer.rust_enum"),
            observer_event: observer,
            blob_event: blob,
            source_fact_id: SourceFactId::from_digest(label(&format!("source fact {name}"))),
            compared_at: &compared_at,
            verdict: &ComparisonVerdictV1::Discrepant,
        })
        .unwrap();
        self.ledger.admit_envelope(&candidate).await.unwrap();
        let envelope = candidate.envelope;
        self.specs
            .record_check(&SpecCheckRecordV1 {
                binding_family_id: spec.proposal.binding_family_id.clone(),
                family_fingerprint: envelope.family_fingerprint,
                observer_event_id: observer,
                blob_event_id: blob,
                member: spec.expectation.member.clone(),
                episode: Some(envelope.episode_fingerprint),
                compared_at,
                ..nonconforming(spec.statement_id, commit)
            })
            .await
            .unwrap();
        envelope
    }

    /// A check of `spec` at `commit` the observer could not settle.
    async fn unknown_check(&self, spec: &SeededSpec, commit: &GitObjectId) {
        self.specs
            .record_check(&SpecCheckRecordV1 {
                binding_family_id: spec.proposal.binding_family_id.clone(),
                member: spec.expectation.member.clone(),
                expected: spec.expectation.expected,
                ..unknown(spec.statement_id, commit)
            })
            .await
            .unwrap();
    }

    /// An operator acknowledging, then resolving, `envelope`'s episode.
    async fn close(
        &self,
        envelope: &DiscrepancyEnvelopeV1,
        acknowledged_at: &str,
        resolved_at: &str,
    ) {
        let actor = DiscrepancyActorV1 {
            principal_id: id("principal.on_call"),
        };
        let evidence = envelope.member_evidence_ids.clone();
        for (at, transition) in [
            (
                acknowledged_at,
                LifecycleTransitionV1::Acknowledge {
                    actor: actor.clone(),
                },
            ),
            (
                resolved_at,
                LifecycleTransitionV1::Resolve {
                    actor: actor.clone(),
                    resolution_evidence_ids: evidence.clone(),
                },
            ),
        ] {
            self.ledger
                .append_lifecycle_event(&DiscrepancyLifecycleEventV1 {
                    schema_version: 1,
                    event_kind: id("discrepancy.lifecycle.accepted"),
                    profile: envelope.profile.clone(),
                    scope: envelope.scope.clone(),
                    episode_fingerprint: envelope.episode_fingerprint,
                    effective_at: timestamp(at),
                    verification_update: None,
                    lifecycle_transition: Some(transition),
                    evidence_event_ids: evidence.clone(),
                })
                .await
                .unwrap();
        }
    }
}

/// Two approvers independent of the author and the proposer ratified
/// `proposal` before it takes effect.
fn receipt_for(proposal: &NormativeBindingProposalV2) -> NormativeActivationReceiptV2 {
    let mut eligible_approvals: Vec<EligibleApprovalV1> = APPROVERS
        .iter()
        .map(|(principal, _)| EligibleApprovalV1 {
            attestation_id: label(&format!("attestation {principal}")),
            principal_id: id(principal),
            signer_key_id: id(&format!("key.{principal}")),
        })
        .collect();
    eligible_approvals.sort();
    NormativeActivationReceiptV2 {
        schema_version: 2,
        statement_id: proposal.statement_id().unwrap(),
        source_author_principal_id: proposal.source_author_principal_id.clone(),
        eligible_approvals,
        required_threshold: 2,
        separation_of_duty:
            NormativeActivationSeparationOfDutyV2::IndependentApprovalFromSourceAuthor,
        separation_of_duty_satisfied: true,
        accepted_at: timestamp("2026-08-31T00:00:00.000000000Z"),
    }
}

async fn capabilities_of(pool: &PgPool, scope: &FleetScope) -> DatabaseCapabilities {
    CockroachStore::from_pool(pool.clone(), scope.clone())
        .unwrap()
        .capabilities()
        .await
        .unwrap()
}

/// The reader `serve` would build for `scope` over `pool`.
async fn spec_reader(pool: &PgPool, scope: &FleetScope) -> Arc<dyn SpecConformanceRead> {
    let capabilities = capabilities_of(pool, scope).await;
    start_spec_conformance(pool, &capabilities, scope)
        .await
        .expect("the schema owner may read every spec conformance table")
}

fn episode_ids(answer: &SpecConformanceAnswerV1) -> Vec<DiscrepancyEpisodeFingerprintV1> {
    answer
        .discrepancies
        .iter()
        .map(|discrepancy| discrepancy.episode_id)
        .collect()
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // one seeded scope read every way an agent can
async fn live_recall_discrepancies_reports_episodes_specs_and_unknowns_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let scope = common::fresh_scope("spec-recall");
    let plane = SpecPlane::new(&pool, &scope);
    // "Forget must be absent" and "Record must be present" are normative;
    // "Delete must be absent" was recorded but never activated.
    let forget = plane
        .statement("Forget", ExpectedMembershipV1::Absent, true)
        .await;
    let record = plane
        .statement("Record", ExpectedMembershipV1::Present, true)
        .await;
    let delete = plane
        .statement("Delete", ExpectedMembershipV1::Absent, false)
        .await;
    // Forget was found at c1 and an operator closed that episode; it was
    // found again at c2, and that episode stands. Delete's episode stands,
    // but Delete is not in force. Record could not be judged at c2.
    let (c1, c2) = (commit("c1"), commit("c2"));
    let closed = plane
        .nonconformance(&forget, &c1, "2026-09-02T00:00:00.000000000Z")
        .await;
    plane
        .close(
            &closed,
            "2026-09-03T00:00:00.000000000Z",
            "2026-09-03T12:00:00.000000000Z",
        )
        .await;
    let not_live = plane
        .nonconformance(&delete, &c1, "2026-09-04T00:00:00.000000000Z")
        .await;
    let standing = plane
        .nonconformance(&forget, &c2, "2026-09-05T00:00:00.000000000Z")
        .await;
    plane.unknown_check(&record, &c2).await;
    let reader = spec_reader(&pool, &scope).await;

    // By default: the standing episode of a spec in force, with what it
    // violates and what was observed, beside every spec's latest check.
    let listed = reader.list(false, 10).await.unwrap();
    assert!(listed.warnings.is_empty(), "{:?}", listed.warnings);
    assert_eq!(episode_ids(&listed), [standing.episode_fingerprint]);
    let episode = &listed.discrepancies[0];
    assert_eq!(episode.finding_type, "spec_nonconformance");
    assert_eq!(episode.lifecycle_state, LifecycleState::Open);
    assert!(episode.spec_live);
    assert_eq!(episode.subject, forget.proposal.repository_entity_id);
    let spec = episode.spec.as_ref().expect("the episode names its spec");
    assert_eq!(spec.statement_id, forget.statement_id);
    assert_eq!(spec.spec_path, "docs/spec.md");
    assert_eq!(spec.spans, forget.proposal.source_spans);
    assert_eq!(
        (spec.expectation.member.as_str(), spec.expectation.expected),
        ("Forget", ExpectedMembershipV1::Absent)
    );
    let observed = episode.observed.as_ref().expect("its opening check");
    assert_eq!(observed.commit, c2);
    assert_eq!(observed.condition, EvaluatedConditionV1::Present);
    assert_eq!(
        observed.verification_outcome,
        VerificationOutcomeV1::VerifiedPositive
    );
    assert_eq!(episode.evidence.member, standing.member_evidence_ids);
    assert!(episode.history.is_none());

    let specs: BTreeMap<Sha256Digest, &SpecSummaryV1> = listed
        .specs
        .iter()
        .map(|spec| (spec.statement_id, spec))
        .collect();
    assert_eq!(
        specs.keys().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([forget.statement_id, record.statement_id]),
        "a statement never made normative is not a spec"
    );
    let forget_check = specs[&forget.statement_id]
        .last_check
        .as_ref()
        .expect("Forget was checked");
    assert_eq!(forget_check.verdict, SpecVerdictV1::Nonconforming);
    assert_eq!(forget_check.commit, c2);
    assert_eq!(forget_check.episode_id, Some(standing.episode_fingerprint));
    let record_check = specs[&record.statement_id]
        .last_check
        .as_ref()
        .expect("Record was checked");
    assert_eq!(record_check.verdict, SpecVerdictV1::Unknown);
    assert!(!record_check.reasons.is_empty());
    assert_eq!(specs[&record.statement_id].resolution, "active");
    assert_eq!(listed.coverage.unknown_specs, 1);
    assert_eq!(listed.coverage.never_checked_specs, 0);
    assert!(!listed.coverage.episodes_truncated);

    // include_resolved adds the closed episode and the one whose spec is not
    // in force, most recently changed first.
    let everything = reader.list(true, 10).await.unwrap();
    assert_eq!(
        episode_ids(&everything),
        [
            standing.episode_fingerprint,
            not_live.episode_fingerprint,
            closed.episode_fingerprint
        ]
    );
    assert_eq!(
        everything.discrepancies[2].lifecycle_state,
        LifecycleState::Resolved
    );
    let hidden = &everything.discrepancies[1];
    assert_eq!(hidden.lifecycle_state, LifecycleState::Open);
    assert!(!hidden.spec_live);
    assert_eq!(
        hidden.spec.as_ref().map(|spec| spec.statement_id),
        Some(delete.statement_id)
    );
    let first = reader.list(true, 1).await.unwrap();
    assert_eq!(episode_ids(&first), [standing.episode_fingerprint]);
    assert!(first.coverage.episodes_truncated);

    // One episode by id, in any state, with its lifecycle history.
    let looked_up = reader.get(closed.episode_fingerprint).await.unwrap();
    let [episode] = looked_up.discrepancies.as_slice() else {
        panic!("one episode by id: {looked_up:?}");
    };
    assert_eq!(episode.lifecycle_state, LifecycleState::Resolved);
    assert_eq!(
        episode.observed.as_ref().map(|seen| &seen.commit),
        Some(&c1)
    );
    let history = episode.history.as_ref().expect("a lookup carries history");
    assert!(
        matches!(
            history
                .iter()
                .map(|event| event.lifecycle_transition.clone())
                .collect::<Vec<_>>()
                .as_slice(),
            [
                Some(LifecycleTransitionV1::Acknowledge { .. }),
                Some(LifecycleTransitionV1::Resolve { .. })
            ]
        ),
        "{history:?}"
    );
    assert_eq!(episode.history_truncated, Some(false));
    assert!(
        reader
            .get(DiscrepancyEpisodeFingerprintV1::from_digest(label(
                "no such episode"
            )))
            .await
            .unwrap()
            .discrepancies
            .is_empty()
    );

    // The status counts only the standing episode of a spec in force.
    let status = reader.status().await.unwrap();
    assert_eq!(
        (
            status.active_specs,
            status.open_discrepancies,
            status.unknown_specs,
            status.never_checked_specs
        ),
        (2, 1, 1, 0)
    );

    // Neither another project of the tenant nor the same project under
    // another tenant sees any of it.
    let sibling = FleetScope::new(
        scope.tenant_id,
        "spec-recall-sibling",
        common::LIVE_TEST_AGENT,
        None,
        PrivacyTier::T1Project,
    )
    .unwrap();
    for other in [sibling, common::fresh_scope("spec-recall")] {
        let other_reader = spec_reader(&pool, &other).await;
        let answer = other_reader.list(true, 100).await.unwrap();
        assert!(answer.discrepancies.is_empty(), "{other:?}");
        assert!(answer.specs.is_empty(), "{other:?}");
        assert!(
            other_reader
                .get(standing.episode_fingerprint)
                .await
                .unwrap()
                .discrepancies
                .is_empty()
        );
        assert_eq!(other_reader.status().await.unwrap().open_discrepancies, 0);
    }
}

#[tokio::test]
async fn live_recall_discrepancies_counts_only_specs_in_force_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let scope = common::fresh_scope("spec-effect");
    let plane = SpecPlane::new(&pool, &scope);
    let now = database_now(&pool).await.unwrap();
    // Forget's statement is in force; Delete's took effect and expired
    // before now; Purge's takes effect tomorrow. All three stay live in the
    // normative projection, which is not filtered by time.
    let in_force = plane
        .statement("Forget", ExpectedMembershipV1::Absent, true)
        .await;
    let expired = plane
        .statement_during(
            "Delete",
            timestamp("2026-09-01T00:00:00.000000000Z"),
            Some(timestamp("2026-09-02T00:00:00.000000000Z")),
        )
        .await;
    let scheduled_from = instant(now + TimeDelta::days(1));
    let scheduled = plane
        .statement_during("Purge", scheduled_from.clone(), None)
        .await;
    // Each was found violated, the scheduled one by a check evaluated
    // through its first instant.
    let c1 = commit("c1");
    let in_force_episode = plane
        .nonconformance(&in_force, &c1, "2026-09-03T00:00:00.000000000Z")
        .await;
    let expired_episode = plane
        .nonconformance(&expired, &c1, "2026-09-01T12:00:00.000000000Z")
        .await;
    let scheduled_episode = plane
        .nonconformance(&scheduled, &c1, scheduled_from.as_str())
        .await;
    let reader = spec_reader(&pool, &scope).await;

    // Only the spec in force is active; each spec says where it stands.
    let listed = reader.list(false, 10).await.unwrap();
    let effects: BTreeMap<Sha256Digest, SpecEffectV1> = listed
        .specs
        .iter()
        .map(|spec| (spec.statement_id, spec.effect))
        .collect();
    assert_eq!(
        effects,
        BTreeMap::from([
            (in_force.statement_id, SpecEffectV1::InForce),
            (expired.statement_id, SpecEffectV1::Expired),
            (scheduled.statement_id, SpecEffectV1::Scheduled),
        ])
    );
    assert_eq!(
        (
            listed.coverage.active_specs,
            listed.coverage.scheduled_specs,
            listed.coverage.expired_specs
        ),
        (1, 1, 1)
    );

    // By default the expired spec's episode is hidden like a retired one's;
    // the scheduled spec's verified nonconformance is listed.
    assert_eq!(
        episode_ids(&listed).into_iter().collect::<BTreeSet<_>>(),
        BTreeSet::from([
            in_force_episode.episode_fingerprint,
            scheduled_episode.episode_fingerprint
        ])
    );
    let everything = reader.list(true, 10).await.unwrap();
    let still_live: BTreeMap<DiscrepancyEpisodeFingerprintV1, bool> = everything
        .discrepancies
        .iter()
        .map(|episode| (episode.episode_id, episode.spec_live))
        .collect();
    assert_eq!(
        still_live,
        BTreeMap::from([
            (in_force_episode.episode_fingerprint, true),
            (expired_episode.episode_fingerprint, false),
            (scheduled_episode.episode_fingerprint, true),
        ])
    );

    let status = reader.status().await.unwrap();
    assert_eq!(
        (
            status.active_specs,
            status.scheduled_specs,
            status.expired_specs,
            status.open_discrepancies
        ),
        (1, 1, 1, 2)
    );
}

/// `serve`'s memory service for `scope`, record-only, with the spec
/// conformance reader attached when there is one.
fn serve_with(
    owner: &PgPool,
    scope: &FleetScope,
    reader: Option<Arc<dyn SpecConformanceRead>>,
) -> CockroachMemoryService {
    let embedder: Arc<dyn ChunkEmbedder> = Arc::new(StubEmbedder);
    let ledger = CockroachClaimLedger::new(
        owner.clone(),
        scope.clone(),
        embedder.clone(),
        retry_policy(),
    )
    .unwrap();
    let service = CockroachMemoryService::new(
        scope.clone(),
        Arc::new(CockroachStore::from_pool(owner.clone(), scope.clone()).unwrap()),
        Arc::new(ledger),
        embedder,
    )
    .unwrap();
    match reader {
        Some(reader) => service.with_spec_conformance(reader),
        None => service,
    }
}

async fn recall(
    service: &CockroachMemoryService,
    scope: &FleetScope,
    action: RecallAction,
) -> Result<RecallResult, ServiceError> {
    recall_with(service, scope, action, Map::new()).await
}

async fn recall_with(
    service: &CockroachMemoryService,
    scope: &FleetScope,
    action: RecallAction,
    arguments: Map<String, serde_json::Value>,
) -> Result<RecallResult, ServiceError> {
    FleetMemoryService::recall(
        service,
        scope.clone(),
        RecallRequest::new(action, arguments),
    )
    .await
}

#[tokio::test]
async fn live_the_probe_serves_discrepancies_only_with_select_grants_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let owner = common::migrated_pool(&database_url).await;
    let scope = common::fresh_scope("spec-recall-probe");
    let plane = SpecPlane::new(&owner, &scope);
    let forget = plane
        .statement("Forget", ExpectedMembershipV1::Absent, true)
        .await;
    let standing = plane
        .nonconformance(&forget, &commit("c1"), "2026-09-02T00:00:00.000000000Z")
        .await;
    let capabilities = capabilities_of(&owner, &scope).await;

    let mut older = capabilities.clone();
    older.schema_version = SPEC_CONFORMANCE_SCHEMA_VERSION - 1;
    assert!(
        probe_spec_conformance(&owner, &older)
            .await
            .unwrap()
            .is_none(),
        "a schema before migration 31 has no spec tables to read"
    );

    let role = RuntimeProbeRole::create_worker(&owner, &database_url, true).await;
    let outcome = AssertUnwindSafe(async {
        // The runtime grants cover every read the action makes.
        let reader = start_spec_conformance(&role.pool, &capabilities, &scope)
            .await
            .expect("the runtime grants serve recall(discrepancies)");
        let served = serve_with(&owner, &scope, Some(reader));
        let surface = FleetMemoryService::remember_surface(&served);
        let recall_surface = FleetMemoryService::recall_surface(&served);
        assert!(recall_surface.discrepancies);
        let tools = tool_list_for_surfaces(surface, recall_surface);
        assert!(
            tools[0]["inputSchema"]["properties"]["action"]["enum"]
                .as_array()
                .unwrap()
                .contains(&json!("discrepancies"))
        );
        let answer = recall(&served, &scope, RecallAction::Discrepancies)
            .await
            .unwrap();
        assert_eq!(
            answer.data["discrepancies"][0]["episode_id"],
            json!(standing.episode_fingerprint)
        );
        assert_eq!(
            answer.data["specs"][0]["last_check"]["verdict"],
            "nonconforming"
        );
        let status = recall(&served, &scope, RecallAction::Status).await.unwrap();
        assert_eq!(status.data["spec_conformance"]["served"], true);
        assert_eq!(status.data["spec_conformance"]["open_discrepancies"], 1);

        // A login without SELECT on the check history is not served, and
        // everything it serves stays as it was.
        sqlx::query(&format!(
            "REVOKE SELECT ON TABLE public.memory_spec_checks_v1 FROM {}",
            role.name()
        ))
        .execute(&owner)
        .await
        .expect("revoke the probe's check-history grant");
        assert!(
            probe_spec_conformance(&role.pool, &capabilities)
                .await
                .expect("a missing privilege is not an error")
                .is_none()
        );
        let reader = start_spec_conformance(&role.pool, &capabilities, &scope).await;
        assert!(reader.is_none());
        let unserved = serve_with(&owner, &scope, reader);
        assert!(!FleetMemoryService::recall_surface(&unserved).discrepancies);
        assert_eq!(
            tool_list_for_surfaces(
                FleetMemoryService::remember_surface(&unserved),
                FleetMemoryService::recall_surface(&unserved)
            ),
            tool_list()
        );
        let refused = recall(&unserved, &scope, RecallAction::Discrepancies)
            .await
            .unwrap_err();
        assert!(
            matches!(&refused, ServiceError::InvalidRequest(message) if message.contains("not served")),
            "{refused}"
        );
        let status = recall(&unserved, &scope, RecallAction::Status)
            .await
            .unwrap();
        assert!(status.data.get("spec_conformance").is_none(), "{status:?}");
    })
    .catch_unwind()
    .await;
    role.drop_role(&owner).await;
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

// --- ostk-spec check and ostk-spec episode resolve|dismiss ---

/// The service source once `Forget` is removed.
const FIXED_SERVICE_SOURCE: &[u8] = b"pub enum RememberAction {\n    Record,\n}\n";
/// The memory worker's git source over the spec repository.
const SPEC_GIT_SOURCE: &str = "connector.git.spec";
/// The operator who closes episodes; implicated in none.
const OPERATOR: &str = "principal.on_call";

/// A scratch repository whose main declares `Forget` at its first commit
/// (C0) and no longer at its second (C1); both carry the spec document.
/// Returns both ids.
fn spec_repository_fixing_forget() -> (ScratchRepository, String, String) {
    repository_dropping_forget(SERVICE_SOURCE, FIXED_SERVICE_SOURCE)
}

/// A scratch repository whose main carries the spec document and `declared`
/// as `src/service.rs` at its first commit (C0), then the spec document and
/// `fixed` at its second (C1). Returns both ids.
fn repository_dropping_forget(
    declared: &[u8],
    fixed: &[u8],
) -> (ScratchRepository, String, String) {
    let repository = ScratchRepository::empty();
    let c0 = repository.commit_files(
        None,
        &[(SPEC_PATH, SPEC_DOCUMENT), ("src/service.rs", declared)],
        "specify the remember actions",
        FIRST_COMMIT_DATE,
    );
    let c1 = repository.commit_files(
        Some(&c0),
        &[(SPEC_PATH, SPEC_DOCUMENT), ("src/service.rs", fixed)],
        "drop the forget action",
        SECOND_COMMIT_DATE,
    );
    (repository, c0, c1)
}

/// The memory worker's sources file over `repository`, as an operator writes
/// it for `ostk-spec check`: a git source naming the spec repository's
/// provider id, and the observer identity observer runs are appended under.
fn spec_sources(repository: &ScratchRepository) -> WorkerSourcesV1 {
    let sources = json!({
        "schema_version": 1,
        "coverage_since": "2025-01-01T00:00:00Z",
        "git": [{
            "connector_principal": "connector.git",
            "connector_instance": SPEC_GIT_SOURCE,
            "installation_id": INSTALLATION_ID,
            "repository_id": SPEC_REPOSITORY_ID,
            "git_dir": repository.path(),
            "ref_name": "refs/heads/main",
            "provider_repository_id": PROVIDER_REPOSITORY_ID
        }],
        "observer": {
            "connector_principal": "connector.observer",
            "connector_instance": "connector.observer.spec"
        }
    });
    WorkerSourcesV1::from_json_slice(&serde_json::to_vec(&sources).unwrap())
        .expect("the spec sources file is valid")
}

/// One memory-worker tick of the ingest step over `sources`, as `pool`: the
/// git source gets the coverage receipt a check binds.
async fn cover_git(installed: &InstalledAuthority, pool: &PgPool, sources: &WorkerSourcesV1) {
    let worker = MemoryWorker::new(
        WorkerDeps {
            pool: pool.clone(),
            scope: installed.scope.clone(),
            authority: Some(installed.runtime(pool).await),
            sources: sources.clone(),
            embedding: None,
            ci_providers: Arc::new(RecordedCi),
            retry: retry_policy(),
        },
        parse_steps("ingest").unwrap(),
        Some(installed.kek()),
        None,
    )
    .expect("the ingest step has its inputs");
    let tick = worker.run_tick().await;
    assert!(!tick.failed(), "{tick:#?}");
}

/// Draft "`Forget` must be absent" citing the spec at `commit`, sign it with
/// both approvers, and activate it, taking effect 60 seconds from the
/// database's time. Returns the proposal and the instant it takes effect.
async fn activate_no_forget(
    runtime: &WriterAuthorityRuntime,
    repository: &ScratchRepository,
    commit: &str,
) -> (NormativeBindingProposalV2, DateTime<Utc>) {
    // Activation must precede the statement's effect; 60 seconds is ample for
    // a slow runner.
    let effective_from = database_now(runtime.pool()).await.unwrap() + TimeDelta::seconds(60);
    let request = draft_request(repository, commit, instant(effective_from));
    (activate_draft(runtime, &request).await, effective_from)
}

/// Draft `request`, sign the draft with both approvers, as
/// `ostk-spec approve` does with their seeds, and activate it. Returns the
/// proposal.
async fn activate_draft(
    runtime: &WriterAuthorityRuntime,
    request: &DraftStatementRequestV1,
) -> NormativeBindingProposalV2 {
    let signed_at = instant(database_now(runtime.pool()).await.unwrap());
    let (proposal, expectation) = draft_spec_statement(runtime, request).await.unwrap();
    let activated = activate_signed(runtime, &proposal, &expectation, &signed_at)
        .await
        .unwrap();
    assert!(activated.is_live(), "{activated:?}");
    proposal
}

/// A check of `commit` against the no-`Forget` family, selecting the
/// statement in force at `evaluated_through`.
fn check_request(
    sources: &WorkerSourcesV1,
    commit: &str,
    evaluated_through: &CanonicalTimestamp,
) -> SpecCheckRequestV1 {
    SpecCheckRequestV1 {
        binding_family_id: id(SPEC_FAMILY),
        sources: sources.clone(),
        git_source: id(SPEC_GIT_SOURCE),
        commit: GitObjectId::parse_hex(commit).unwrap(),
        member_bound: 64,
        evaluated_through: Some(evaluated_through.clone()),
    }
}

/// Check one commit, as `ostk-spec check` does.
async fn check(
    runtime: &WriterAuthorityRuntime,
    kek: &ContentKeyEncryptionKey,
    request: &SpecCheckRequestV1,
) -> SpecCheckOutcomeV1 {
    Box::pin(run_spec_check(runtime, kek, request))
        .await
        .expect("the check runs")
}

/// The episode ids `recall(discrepancies)` answers with `arguments`.
async fn recalled_episodes(
    service: &CockroachMemoryService,
    scope: &FleetScope,
    arguments: &serde_json::Value,
) -> Vec<DiscrepancyEpisodeFingerprintV1> {
    let answer = recall_with(
        service,
        scope,
        RecallAction::Discrepancies,
        arguments.as_object().unwrap().clone(),
    )
    .await
    .unwrap();
    answer.data["discrepancies"]
        .as_array()
        .unwrap()
        .iter()
        .map(|episode| serde_json::from_value(episode["episode_id"].clone()).unwrap())
        .collect()
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // one episode's life, from opening to a replayed check
async fn live_an_operator_can_close_an_episode_and_recall_hides_it_by_default_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let owner = common::migrated_pool(&database_url).await;
    let installed = install_generation_two(&owner, "spec-episode").await;
    let (repository, c0, c1) = spec_repository_fixing_forget();
    let sources = spec_sources(&repository);
    let (installed, repository, sources, owner_pool) = (&installed, &repository, &sources, &owner);
    Box::pin(as_runtime_role(&owner, &database_url, |pool| async move {
        let runtime = installed.runtime(&pool).await;
        let kek = installed.kek();
        let scope = &installed.scope;
        cover_git(installed, &pool, sources).await;
        let (proposal, effective_from) = activate_no_forget(&runtime, repository, &c0).await;
        let statement_id = proposal.statement_id().unwrap();
        let through = instant(effective_from + TimeDelta::seconds(1));
        let operator = id(OPERATOR);
        let resolve = SpecEpisodeTransitionV1::Resolve {
            evidence: Vec::new(),
        };

        // C0 declares Forget: a verified nonconformance opens an episode.
        let opened = check(&runtime, &kek, &check_request(sources, &c0, &through)).await;
        let SpecDiscrepancyActionV1::Opened { episode } = opened.discrepancy else {
            panic!("C0 must open an episode: {opened:?}");
        };

        // Nothing shows a fix yet: the latest check is the nonconformance
        // itself, so a resolution has no evidence to cite by default.
        assert_refused(
            append_episode_lifecycle(&runtime, episode, &operator, &resolve).await,
            "a resolution citing the standing nonconformance",
        );

        // Re-reading C0 with too small a member bound cannot see Forget and
        // checks as unknown, but a re-read of the violating commit is not a
        // fix: a resolution still has nothing to cite by default.
        let truncated = check(
            &runtime,
            &kek,
            &SpecCheckRequestV1 {
                member_bound: 1,
                ..check_request(sources, &c0, &through)
            },
        )
        .await;
        assert_eq!(truncated.verdict, SpecVerdictV1::Unknown);
        assert_refused(
            append_episode_lifecycle(&runtime, episode, &operator, &resolve).await,
            "a resolution citing a truncated re-read of the violating commit",
        );

        // C1 no longer declares Forget. The observer cannot verify an
        // absence, so the check is unknown and the episode stands.
        let fixed = check(&runtime, &kek, &check_request(sources, &c1, &through)).await;
        assert_eq!(fixed.verdict, SpecVerdictV1::Unknown);
        assert_eq!(fixed.discrepancy, SpecDiscrepancyActionV1::NotOpened);
        let fix_evidence = fixed.observer_event.expect("C1 was observed");

        let served = serve_with(
            owner_pool,
            scope,
            Some(spec_reader(owner_pool, scope).await),
        );
        let by_default = json!({});
        let with_resolved = json!({"include_resolved": true});
        assert_eq!(
            recalled_episodes(&served, scope, &by_default).await,
            [episode]
        );

        // A dismissal needs a rationale; a refused one appends nothing.
        for blank in ["", " \n\t"] {
            assert_refused(
                append_episode_lifecycle(
                    &runtime,
                    episode,
                    &operator,
                    &SpecEpisodeTransitionV1::Dismiss {
                        reason: DismissalReasonKindV1::FalsePositive,
                        rationale: blank.into(),
                    },
                )
                .await,
                "a dismissal without a rationale",
            );
        }
        let looked_up = recall_with(
            &served,
            scope,
            RecallAction::Discrepancies,
            json!({"id": episode}).as_object().unwrap().clone(),
        )
        .await
        .unwrap();
        assert_eq!(looked_up.data["discrepancies"][0]["history"], json!([]));
        assert_eq!(
            looked_up.data["discrepancies"][0]["lifecycle_state"],
            "open"
        );

        // The operator resolves it. By default the resolution cites the
        // observer event of the later check, the one of the fixing commit.
        let resolved = append_episode_lifecycle(&runtime, episode, &operator, &resolve)
            .await
            .unwrap();
        assert_eq!(resolved.episode_id, episode);
        assert_eq!(resolved.statement_id, statement_id);
        assert_eq!(
            (resolved.previous_state, resolved.lifecycle_state),
            (LifecycleState::Open, LifecycleState::Resolved)
        );
        assert!(
            matches!(
                &resolved.transition,
                LifecycleTransitionV1::Resolve { actor, resolution_evidence_ids }
                    if actor.principal_id == operator
                        && resolution_evidence_ids == &[fix_evidence]
            ),
            "{resolved:?}"
        );
        assert!(resolved.appended);

        // Retrying the same resolution, as an operator does after a lost
        // connection, answers with the recorded closure and appends nothing;
        // closing the resolved episode another way is refused.
        let retried = append_episode_lifecycle(&runtime, episode, &operator, &resolve)
            .await
            .unwrap();
        assert!(!retried.appended, "{retried:?}");
        assert_eq!(
            (retried.event_id, retried.log_seq, &retried.effective_at),
            (resolved.event_id, resolved.log_seq, &resolved.effective_at)
        );
        assert_eq!(retried.lifecycle_state, LifecycleState::Resolved);
        assert_refused(
            append_episode_lifecycle(
                &runtime,
                episode,
                &operator,
                &SpecEpisodeTransitionV1::Dismiss {
                    reason: DismissalReasonKindV1::DuplicateOfOtherEpisode,
                    rationale: "closed twice".into(),
                },
            )
            .await,
            "a dismissal of a resolved episode",
        );

        // recall hides the closed episode by default and lists it, resolved,
        // with include_resolved; by id, its history shows who closed it and
        // on what evidence.
        assert!(
            recalled_episodes(&served, scope, &by_default)
                .await
                .is_empty()
        );
        assert_eq!(
            recalled_episodes(&served, scope, &with_resolved).await,
            [episode]
        );
        let looked_up = recall_with(
            &served,
            scope,
            RecallAction::Discrepancies,
            json!({"id": episode}).as_object().unwrap().clone(),
        )
        .await
        .unwrap();
        let closed = &looked_up.data["discrepancies"][0];
        assert_eq!(closed["lifecycle_state"], "resolved");
        let transition = &closed["history"][0]["lifecycle_transition"];
        assert_eq!(transition["transition"], "resolve");
        assert_eq!(transition["actor"]["principal_id"], OPERATOR);
        assert_eq!(transition["resolution_evidence_ids"], json!([fix_evidence]));
        assert!(closed["history"].get(1).is_none(), "{closed}");

        // Re-checking C0 replays its check into the closed episode as
        // already judged: the family opens nothing new.
        let rechecked = check(&runtime, &kek, &check_request(sources, &c0, &through)).await;
        assert_eq!(rechecked.verdict, SpecVerdictV1::Nonconforming);
        assert_eq!(
            rechecked.discrepancy,
            SpecDiscrepancyActionV1::AlreadyJudged { episode }
        );
        assert_eq!(rechecked.check_id, opened.check_id);
        assert!(
            recalled_episodes(&served, scope, &by_default)
                .await
                .is_empty()
        );
        assert_eq!(
            recalled_episodes(&served, scope, &with_resolved).await,
            [episode]
        );

        // An episode this project does not have cannot be closed.
        assert_refused(
            append_episode_lifecycle(
                &runtime,
                DiscrepancyEpisodeFingerprintV1::from_digest(label("no such episode")),
                &operator,
                &SpecEpisodeTransitionV1::Resolve {
                    evidence: vec![fix_evidence],
                },
            )
            .await,
            "an unknown episode",
        );
    }))
    .await;
}

// --- the chain end to end (ADR 0007) ---

/// The observer's checked-in snapshot of `src/service.rs`, whose
/// `RememberAction` declares both `Record` and `Forget`.
const OBSERVED_SERVICE_SOURCE: &[u8] =
    include_bytes!("../src/observer_runtime/fixtures/service.rs.txt");
/// The binding family of "`Record` must be present".
const RECORD_FAMILY: &str = "spec.remember.keep_record";
/// The spec sentence "`Record` must be present" cites.
const RECORD_SENTENCE: &str = "Record stays.";

/// A scratch repository whose main carries the spec document and the
/// observer's snapshot of `src/service.rs` at its first commit (C0), and the
/// same snapshot with `Forget` dropped from `RememberAction` at its second
/// (C1). Returns both ids.
fn observed_repository() -> (ScratchRepository, String, String) {
    let declared = std::str::from_utf8(OBSERVED_SERVICE_SOURCE).expect("the fixture is text");
    let fixed = declared.replacen("    Forget,\n", "", 1);
    assert_ne!(
        fixed, declared,
        "the fixture's RememberAction declares Forget"
    );
    repository_dropping_forget(OBSERVED_SERVICE_SOURCE, fixed.as_bytes())
}

/// "`RememberAction` in `src/service.rs` must declare `Record`", citing its
/// own sentence of the spec at `commit`, in its own binding family.
fn keep_record_request(
    repository: &ScratchRepository,
    commit: &str,
    effective_from: CanonicalTimestamp,
) -> DraftStatementRequestV1 {
    DraftStatementRequestV1 {
        spans: vec![span_of(SPEC_DOCUMENT, RECORD_SENTENCE)],
        binding_family_id: id(RECORD_FAMILY),
        member: "Record".into(),
        expected: ExpectedMembershipV1::Present,
        ..draft_request(repository, commit, effective_from)
    }
}

/// `serve`'s MCP server for `scope`: the record-only service with the spec
/// conformance reader `serve` builds for the owner attached.
async fn spec_mcp_server(owner: &PgPool, scope: &FleetScope) -> McpServer {
    let reader = spec_reader(owner, scope).await;
    McpServer::new(
        Arc::new(serve_with(owner, scope, Some(reader))),
        scope.clone(),
    )
    .expect("MCP server")
}

/// One JSON-RPC request to `server`, and its result.
async fn mcp_request(server: &McpServer, method: &str, params: Value) -> Value {
    let mut request = json!({ "jsonrpc": "2.0", "id": 1, "method": method });
    if !params.is_null() {
        request["params"] = params;
    }
    let response = server
        .handle_value(request)
        .await
        .expect("a request has a response");
    assert!(response.error.is_none(), "{method}: {:?}", response.error);
    response.result.expect("a successful request has a result")
}

/// `recall`'s structured content for `arguments`, over MCP.
async fn mcp_recall(server: &McpServer, arguments: Value) -> Value {
    let result = mcp_request(
        server,
        "tools/call",
        json!({ "name": "recall", "arguments": arguments }),
    )
    .await;
    assert_eq!(result["isError"], false, "{}", result["content"][0]["text"]);
    result["structuredContent"].clone()
}

/// The episode ids of one `recall(discrepancies)` answer over MCP.
fn answered_episodes(answer: &Value) -> Vec<DiscrepancyEpisodeFingerprintV1> {
    answer["data"]["discrepancies"]
        .as_array()
        .expect("an answer lists its episodes")
        .iter()
        .map(|episode| serde_json::from_value(episode["episode_id"].clone()).unwrap())
        .collect()
}

/// The spec of `statement_id` in one `recall(discrepancies)` answer over MCP.
fn answered_spec(answer: &Value, statement_id: Sha256Digest) -> Value {
    answer["data"]["specs"]
        .as_array()
        .expect("an answer lists its specs")
        .iter()
        .find(|spec| spec["statement_id"] == json!(statement_id))
        .unwrap_or_else(|| panic!("spec {statement_id} is listed: {answer}"))
        .clone()
}

/// The episode `recall(discrepancies)` reports for C0 over MCP names the
/// statement and expectation it violates and what the opening check
/// observed; the spec's latest check is that nonconformance.
fn assert_reports_the_nonconformance(
    answer: &Value,
    proposal: &NormativeBindingProposalV2,
    opened: &SpecCheckOutcomeV1,
    episode: DiscrepancyEpisodeFingerprintV1,
) {
    let statement_id = proposal.statement_id().unwrap();
    let observer_event = opened.observer_event.expect("C0 was observed");
    let discrepancy = &answer["data"]["discrepancies"][0];
    assert_eq!(discrepancy["episode_id"], json!(episode));
    assert_eq!(discrepancy["finding_type"], "spec_nonconformance");
    assert_eq!(discrepancy["lifecycle_state"], json!(LifecycleState::Open));
    assert_eq!(discrepancy["spec_live"], true);
    assert_eq!(discrepancy["subject"], json!(proposal.repository_entity_id));

    let spec = &discrepancy["spec"];
    assert_eq!(spec["statement_id"], json!(statement_id));
    assert_eq!(spec["binding_family_id"], SPEC_FAMILY);
    assert_eq!(spec["spec_path"], SPEC_PATH);
    assert_eq!(spec["spans"], json!(proposal.source_spans));
    let expectation = &spec["expectation"];
    assert_eq!(expectation["enum"], "RememberAction");
    assert_eq!(expectation["member"], "Forget");
    assert_eq!(expectation["expected"], json!(ExpectedMembershipV1::Absent));
    assert_eq!(expectation["source_path"], "src/service.rs");

    let observed = &discrepancy["observed"];
    assert_eq!(observed["commit"], json!(opened.commit));
    assert_eq!(observed["condition"], json!(EvaluatedConditionV1::Present));
    assert_eq!(
        observed["verification_outcome"],
        json!(VerificationOutcomeV1::VerifiedPositive)
    );
    assert_eq!(observed["observer_event_id"], json!(observer_event));
    assert_eq!(discrepancy["evidence"]["member"], json!([observer_event]));
    assert!(
        discrepancy["evidence"]["supporting"]
            .as_array()
            .unwrap()
            .contains(&json!(opened.blob_event.expect("C0's blob was cited"))),
        "{discrepancy}"
    );

    let last_check = &answered_spec(answer, statement_id)["last_check"];
    assert_eq!(last_check["verdict"], json!(SpecVerdictV1::Nonconforming));
    assert_eq!(last_check["commit"], json!(opened.commit));
    assert_eq!(last_check["episode_id"], json!(episode));
}

#[tokio::test]
async fn live_spec_chain_records_a_verified_nonconformance_and_recall_reports_it_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let owner = common::migrated_pool(&database_url).await;
    let installed = install_generation_two(&owner, "spec-chain").await;
    let scope = &installed.scope;
    let (repository, c0, _) = observed_repository();
    let sources = spec_sources(&repository);
    let runtime = installed.runtime(&owner).await;
    let kek = installed.kek();

    // The memory worker covers the repository; the spec is drafted against
    // it, signed by both approvers, and activated.
    cover_git(&installed, &owner, &sources).await;
    let (proposal, effective_from) = activate_no_forget(&runtime, &repository, &c0).await;
    let statement_id = proposal.statement_id().unwrap();
    let request = check_request(
        &sources,
        &c0,
        &instant(effective_from + TimeDelta::seconds(1)),
    );

    // C0 declares Forget: the observer verifies it present, which violates
    // the statement, and the check opens an episode.
    let opened = check(&runtime, &kek, &request).await;
    assert_eq!(opened.statement_id, Some(statement_id));
    assert_eq!(opened.verdict, SpecVerdictV1::Nonconforming);
    assert!(opened.reasons.is_empty(), "{:?}", opened.reasons);
    assert_eq!(
        (opened.observed_condition, opened.verification_outcome),
        (
            Some(EvaluatedConditionV1::Present),
            Some(VerificationOutcomeV1::VerifiedPositive)
        )
    );
    assert_eq!(opened.check_row, Some(SpecRowWriteV1::Inserted));
    let SpecDiscrepancyActionV1::Opened { episode } = opened.discrepancy else {
        panic!("C0 must open an episode: {opened:?}");
    };

    // Checking C0 again replays the same check into the same episode.
    let again = check(&runtime, &kek, &request).await;
    assert_eq!(again.verdict, SpecVerdictV1::Nonconforming);
    assert_eq!(
        again.discrepancy,
        SpecDiscrepancyActionV1::AlreadyJudged { episode }
    );
    assert_eq!(again.check_id, opened.check_id);
    assert_eq!(again.check_row, Some(SpecRowWriteV1::AlreadyRecorded));
    assert_eq!(
        (again.observer_event, again.blob_event),
        (opened.observer_event, opened.blob_event),
        "a replayed check appends no new evidence"
    );

    // An agent sees the action advertised, and a warning that an empty list
    // proves nothing.
    let server = spec_mcp_server(&owner, scope).await;
    let tools = mcp_request(&server, "tools/list", Value::Null).await["tools"].clone();
    let recall_tool = tools
        .as_array()
        .unwrap()
        .iter()
        .find(|tool| tool["name"] == "recall")
        .expect("recall is listed");
    assert!(
        recall_tool["inputSchema"]["properties"]["action"]["enum"]
            .as_array()
            .unwrap()
            .contains(&json!("discrepancies")),
        "{recall_tool}"
    );
    assert!(
        recall_tool["description"]
            .as_str()
            .unwrap()
            .contains("an empty list is not proof of conformance"),
        "{recall_tool}"
    );

    // It reads the one episode, whether or not closed episodes are asked for,
    // with the spec it violates, the observed commit, and the latest check.
    let answer = mcp_recall(&server, json!({ "action": "discrepancies" })).await;
    assert_eq!(answered_episodes(&answer), [episode]);
    assert_reports_the_nonconformance(&answer, &proposal, &opened, episode);
    let everything = mcp_recall(
        &server,
        json!({ "action": "discrepancies", "include_resolved": true }),
    )
    .await;
    assert_eq!(answered_episodes(&everything), [episode]);

    // By id, the episode carries its lifecycle history: nothing after the
    // detection yet.
    let looked_up = mcp_recall(&server, json!({ "action": "discrepancies", "id": episode })).await;
    assert_eq!(answered_episodes(&looked_up), [episode]);
    assert_eq!(looked_up["data"]["discrepancies"][0]["history"], json!([]));

    let status = mcp_recall(&server, json!({ "action": "status" })).await;
    let block = &status["data"]["spec_conformance"];
    assert_eq!(block["served"], true, "{status}");
    assert_eq!(block["open_discrepancies"], 1, "{status}");
}

#[tokio::test]
async fn live_an_unverifiable_absence_is_unknown_never_conforming_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let owner = common::migrated_pool(&database_url).await;
    let installed = install_generation_two(&owner, "spec-unknown").await;
    let (repository, c0, c1) = observed_repository();
    let sources = spec_sources(&repository);
    let runtime = installed.runtime(&owner).await;
    let kek = installed.kek();
    cover_git(&installed, &owner, &sources).await;

    // "Forget must be absent" and "Record must be present", both in force
    // from one instant.
    let effective_from = database_now(&owner).await.unwrap() + TimeDelta::seconds(60);
    let forget = activate_draft(
        &runtime,
        &draft_request(&repository, &c0, instant(effective_from)),
    )
    .await
    .statement_id()
    .unwrap();
    let record = activate_draft(
        &runtime,
        &keep_record_request(&repository, &c0, instant(effective_from)),
    )
    .await
    .statement_id()
    .unwrap();
    let through = instant(effective_from + TimeDelta::seconds(1));
    let record_at = |commit: &str| SpecCheckRequestV1 {
        binding_family_id: id(RECORD_FAMILY),
        ..check_request(&sources, commit, &through)
    };

    // C0 declares Forget: an episode opens.
    let opened = check(&runtime, &kek, &check_request(&sources, &c0, &through)).await;
    let SpecDiscrepancyActionV1::Opened { episode } = opened.discrepancy else {
        panic!("C0 must open an episode: {opened:?}");
    };

    // C1 no longer declares Forget, but the admitted observer verifies
    // presence only: the absence is unknown, never conforming, and the
    // check neither opens nor closes anything.
    let dropped = check(&runtime, &kek, &check_request(&sources, &c1, &through)).await;
    assert_eq!(dropped.statement_id, Some(forget));
    assert_eq!(dropped.verdict, SpecVerdictV1::Unknown);
    assert!(
        dropped
            .reasons
            .contains(&ComparisonIndeterminacyV1::ObservedUnmeasured),
        "{:?}",
        dropped.reasons
    );
    assert_ne!(
        dropped.verification_outcome,
        Some(VerificationOutcomeV1::VerifiedPositive)
    );
    assert_eq!(dropped.discrepancy, SpecDiscrepancyActionV1::NotOpened);
    assert!(dropped.check_id.is_some(), "an unknown check is recorded");

    // C0 declares Record, which its spec requires: conforming, no episode.
    let kept = check(&runtime, &kek, &record_at(&c0)).await;
    assert_eq!(kept.statement_id, Some(record));
    assert_eq!(kept.verdict, SpecVerdictV1::Conforming);
    assert!(kept.reasons.is_empty(), "{:?}", kept.reasons);
    assert_eq!(
        kept.verification_outcome,
        Some(VerificationOutcomeV1::VerifiedPositive)
    );
    assert_eq!(kept.discrepancy, SpecDiscrepancyActionV1::NotOpened);

    // The episode still stands and is the only one; each spec's latest check
    // says what the last check concluded.
    let reader = spec_reader(&owner, &installed.scope).await;
    for include_resolved in [false, true] {
        let answer = reader.list(include_resolved, 10).await.unwrap();
        assert_eq!(episode_ids(&answer), [episode], "{answer:?}");
    }
    let answer = reader.list(false, 10).await.unwrap();
    assert!(answer.warnings.is_empty(), "{:?}", answer.warnings);
    assert_eq!(
        answer.discrepancies[0].lifecycle_state,
        LifecycleState::Open
    );
    let specs: BTreeMap<Sha256Digest, &SpecSummaryV1> = answer
        .specs
        .iter()
        .map(|spec| (spec.statement_id, spec))
        .collect();
    let forget_check = specs[&forget]
        .last_check
        .as_ref()
        .expect("Forget was checked");
    assert_eq!(forget_check.verdict, SpecVerdictV1::Unknown);
    assert_eq!(forget_check.commit, GitObjectId::parse_hex(&c1).unwrap());
    assert_eq!(forget_check.reasons, dropped.reasons);
    assert_eq!(forget_check.episode_id, None);
    let record_check = specs[&record]
        .last_check
        .as_ref()
        .expect("Record was checked");
    assert_eq!(record_check.verdict, SpecVerdictV1::Conforming);
    assert_eq!(record_check.commit, GitObjectId::parse_hex(&c0).unwrap());
    assert_eq!(record_check.episode_id, None);
}

#[tokio::test]
async fn live_the_spec_plane_runs_under_a_runtime_member_role_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let owner = common::migrated_pool(&database_url).await;
    let installed = install_generation_two(&owner, "spec-member").await;
    let (repository, c0, _) = observed_repository();
    let sources = spec_sources(&repository);
    // `serve` reads its capabilities with the claim-plane grants, which this
    // login does not need for anything the spec plane does.
    let capabilities = capabilities_of(&owner, &installed.scope).await;
    let member = RuntimeProbeRole::create_worker_member(&owner, &database_url).await;
    let (installed, repository, sources, capabilities) =
        (&installed, &repository, &sources, &capabilities);
    Box::pin(as_role(&owner, member, |pool| async move {
        let runtime = installed.runtime(&pool).await;
        cover_git(installed, &pool, sources).await;
        let (proposal, effective_from) = activate_no_forget(&runtime, repository, &c0).await;
        let through = instant(effective_from + TimeDelta::seconds(1));
        let opened = check(
            &runtime,
            &installed.kek(),
            &check_request(sources, &c0, &through),
        )
        .await;
        let SpecDiscrepancyActionV1::Opened { episode } = opened.discrepancy else {
            panic!("C0 must open an episode: {opened:?}");
        };

        let reader = start_spec_conformance(&pool, capabilities, &installed.scope)
            .await
            .expect("a member of the runtime role may read every spec conformance table");
        let answer = reader.list(false, 10).await.unwrap();
        assert!(answer.warnings.is_empty(), "{:?}", answer.warnings);
        assert!(episode_ids(&answer).contains(&episode), "{answer:?}");
        let spec = answer
            .specs
            .iter()
            .find(|spec| spec.statement_id == proposal.statement_id().unwrap())
            .expect("the activated spec is listed");
        assert_eq!(
            spec.last_check.as_ref().map(|check| check.verdict),
            Some(SpecVerdictV1::Nonconforming)
        );
        let looked_up = reader.get(episode).await.unwrap();
        assert!(
            looked_up
                .discrepancies
                .iter()
                .any(|found| found.episode_id == episode && found.history.is_some()),
            "{looked_up:?}"
        );
        reader.status().await.unwrap();
    }))
    .await;
}
