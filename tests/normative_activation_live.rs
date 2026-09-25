//! Connected proof for the normative activation runtime (W3-NORM, Stage 6).
//!
//! Set `FLEET_RECALL_TEST_DATABASE_URL` to a disposable `CockroachDB` 26.2
//! database. Every test here is inert otherwise. Nothing in this file starts a
//! database process, invokes Docker, or targets a cloud service.
//!
//! These tests exercise the real runtime against migration 0024's three tables
//! and reproduce, at the DB level, exactly the definition of done:
//! * a lawful activation installs and is durable;
//! * a concurrent second activation against the same head loses the
//!   compare-and-set cleanly — no double-apply, no torn head/log/projection;
//! * a contested overlap projects `unknown`;
//! * an actor implicated in the change is refused closed;
//! * retirement and supersession append without erasing history;
//! * the projection rebuilds byte-identically from the event log;
//! * a family whose head names an older registry head refuses every
//!   activation until it is rebased (ADR 0007 D11), a rebase whose target does
//!   not carry an entry a live statement depends on writes nothing, and a
//!   lawful rebase appends one `rebase` row, moves only the head's registry
//!   digests, is idempotent, and lets a supersession in under the new head
//!   (ADR 0008 D3).
//!
//! The normative tables are keyed by the trusted `(tenant, project)` pair; a
//! fresh unique project per test isolates them. The semantic scope is decoded
//! from the frozen v1 bootstrap-receipt fixture — the normative runtime is a
//! standalone projector bound to scope and to an already-active registry head,
//! so no genesis/successor ceremony is needed here; the active head is handed
//! to the runtime at construction, which is precisely the seam this proof
//! exercises (a proposal naming a different head is refused).

use std::sync::Arc;
use std::time::Duration;

use ostk_fleet_recall::FleetError;
use ostk_fleet_recall::FleetScope;
use ostk_fleet_recall::control_log::TrustedControlScope;
use ostk_fleet_recall::memory_contracts::bootstrap::BootstrapReceiptV1;
use ostk_fleet_recall::memory_contracts::canonical::{CanonicalValue, decode_strict};
use ostk_fleet_recall::memory_contracts::common::{
    AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, HexBytes, ProfileReferenceV1,
    RegistryReferenceV1,
};
use ostk_fleet_recall::memory_contracts::digest::{
    DigestDomain, Sha256Digest, domain_separated_digest,
};
use ostk_fleet_recall::memory_contracts::evidence_v2::RegistryHeadBindingV1;
use ostk_fleet_recall::memory_contracts::identity::ResourceUri;
use ostk_fleet_recall::memory_contracts::normative::{NormativePropositionV1, SourceByteSpanV1};
use ostk_fleet_recall::memory_contracts::normative_v2::{
    ContestedBindingV1, NormativeActivationReceiptV2, NormativeActivationSeparationOfDutyV2,
    NormativeBindingProposalV2, NormativeContestReasonV1, NormativeLifecycleKindV1,
};
use ostk_fleet_recall::memory_contracts::registry::{EligibleApprovalV1, RegistryHeadV1};
use ostk_fleet_recall::normative_runtime::{
    CockroachNormativeActivationRepository, NormativeActivationCandidateV1,
    NormativeActivationOutcomeV1, NormativeActivationRepository, NormativeFaultInjection,
    NormativeLifecycleRequestV1, NormativeLogRecordV1, NormativeRebaseOutcomeV1,
    NormativeRebaseRequestV1, NormativeRebaseTargetV1, NormativeRegistryBindingV1,
    NormativeResolutionV1, active_binding_set_digest,
};
use ostk_fleet_recall::store::cockroach::{CockroachStore, PoolConfig, RetryPolicy};
use ostk_recall_core::PrivacyTier;
use sqlx::PgPool;
use std::collections::{BTreeMap, BTreeSet};
use tokio::sync::Mutex;
use uuid::Uuid;

const BOOTSTRAP_RECEIPT: &[u8] =
    include_bytes!("../contracts/dynamic-memory/v1/bootstrap-receipt.jsonl");

const ACCEPTED_AT: &str = "2026-08-15T09:00:00.000000000Z";
const EFFECTIVE_FROM: &str = "2026-08-20T00:00:00.000000000Z";

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

fn timestamp(value: &str) -> CanonicalTimestamp {
    CanonicalTimestamp::parse(value).expect("fixture timestamp must be canonical")
}

fn resource(form: &str, kind: &str, value: &str) -> ResourceUri {
    format!("urn:ostk:{form}:v1:{kind}:sha256:{}", label(value))
        .parse()
        .expect("constructed resource URI must be valid")
}

fn reference(id: &str) -> RegistryReferenceV1 {
    RegistryReferenceV1 {
        entry_id: ContractId::new(id).unwrap(),
        version: 1,
        entry_digest: label(id),
    }
}

fn profile() -> ProfileReferenceV1 {
    ostk_fleet_recall::memory_contracts::common::frozen_profile_reference_v1()
}

const fn retry_policy() -> RetryPolicy {
    RetryPolicy {
        max_attempts: 24,
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(60),
    }
}

fn semantic_scope() -> AuthenticatedProjectScopeV1 {
    let receipt: BootstrapReceiptV1 = decode_strict(record(BOOTSTRAP_RECEIPT)).unwrap();
    receipt.statement.scope
}

fn physical_scope(label: &str) -> FleetScope {
    FleetScope::new(
        Uuid::now_v7(),
        format!("normative-runtime-{label}-{}", Uuid::now_v7()),
        "normative-runtime-connected-test",
        None,
        PrivacyTier::T1Project,
    )
    .expect("connected-test scope must be valid")
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

fn registry_binding() -> NormativeRegistryBindingV1 {
    NormativeRegistryBindingV1 {
        registry_package_digest: label("registry-package"),
        activation_policy_digest: label("activation-policy"),
    }
}

fn registry_head() -> RegistryHeadBindingV1 {
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

/// One live normative runtime bound to a unique project.
struct NormativeScope {
    repository: Arc<CockroachNormativeActivationRepository>,
    scope: AuthenticatedProjectScopeV1,
    physical: FleetScope,
    family: ContractId,
}

fn normative_scope(pool: &PgPool, name: &str) -> NormativeScope {
    let physical = physical_scope(name);
    let semantic = semantic_scope();
    let trusted = TrustedControlScope::from_trusted_context(&physical, semantic.clone()).unwrap();
    // `physical` is retained so the raw-SQL assertions below can bind the same
    // trusted (tenant, project) pair the runtime binds; every test in this file
    // shares one binding family id, so an unscoped query would read a sibling.
    let repository = CockroachNormativeActivationRepository::new(
        pool.clone(),
        trusted,
        registry_binding(),
        retry_policy(),
    )
    .expect("bound registry head must be non-zero");
    NormativeScope {
        repository: Arc::new(repository),
        scope: semantic,
        physical,
        family: ContractId::new("slo.home.errors").unwrap(),
    }
}

fn proposal(
    scope: &NormativeScope,
    body: &str,
    effective_from: &str,
) -> NormativeBindingProposalV2 {
    NormativeBindingProposalV2 {
        schema_version: 2,
        profile: profile(),
        scope: scope.scope.clone(),
        binding_family_id: scope.family.clone(),
        expected_active_binding_set_digest: None,
        repository_entity_id: resource("entity", "repository", "repo"),
        repository_version_id: resource("version", "repository_version", body),
        blob_id: resource("occurrence", "git_blob", body),
        exact_path_bytes: HexBytes::new(b"docs/SLO.md".to_vec()).unwrap(),
        source_spans: vec![SourceByteSpanV1 {
            start: 10,
            end: 80,
            selected_bytes_digest: label(body),
        }],
        parser_artifact_id: resource("occurrence", "artifact", "parser"),
        parser_configuration_digest: label("parser-config"),
        propositions: vec![NormativePropositionV1 {
            predicate_schema: reference("slo.error_rate"),
            proposition_fingerprint: label(body),
        }],
        applicability_evaluator: reference("environment.selector"),
        applicability_selector: CanonicalValue::Object(BTreeMap::from([(
            "environment".into(),
            CanonicalValue::String("production".into()),
        )])),
        effective_from: timestamp(effective_from),
        effective_until: None,
        registry_head: registry_head(),
        explicitly_supersedes_statement_id: None,
        proposer_principal_id: ContractId::new("principal.agent").unwrap(),
        source_author_principal_id: ContractId::new("principal.author").unwrap(),
    }
}

fn receipt_for(
    proposal: &NormativeBindingProposalV2,
    approving_principals: &[&str],
) -> NormativeActivationReceiptV2 {
    let statement_id = proposal.statement_id().unwrap();
    let mut approvals: Vec<EligibleApprovalV1> = approving_principals
        .iter()
        .map(|principal| EligibleApprovalV1 {
            attestation_id: label(&format!("attestation.{principal}")),
            principal_id: ContractId::new(*principal).unwrap(),
            signer_key_id: ContractId::new(format!("key.{principal}")).unwrap(),
        })
        .collect();
    approvals.sort();
    let satisfied = approvals
        .iter()
        .any(|approval| approval.principal_id != proposal.source_author_principal_id);
    NormativeActivationReceiptV2 {
        schema_version: 2,
        statement_id,
        source_author_principal_id: proposal.source_author_principal_id.clone(),
        eligible_approvals: approvals,
        required_threshold: 1,
        separation_of_duty:
            NormativeActivationSeparationOfDutyV2::IndependentApprovalFromSourceAuthor,
        separation_of_duty_satisfied: satisfied,
        accepted_at: timestamp(ACCEPTED_AT),
    }
}

fn candidate(proposal: NormativeBindingProposalV2) -> NormativeActivationCandidateV1 {
    let receipt = receipt_for(&proposal, &["principal.author", "principal.reviewer"]);
    NormativeActivationCandidateV1 {
        proposal,
        receipt,
        retroactive_correction: None,
    }
}

/// Install one lawful activation and return its statement id.
async fn install_first(scope: &NormativeScope) -> Sha256Digest {
    let candidate = candidate(proposal(scope, "first", EFFECTIVE_FROM));
    let outcome = scope.repository.activate(&candidate).await.unwrap();
    let NormativeActivationOutcomeV1::Installed(transition) = outcome else {
        panic!("a lawful inaugural activation must install, got {outcome:?}");
    };
    assert_eq!(transition.head_revision, 1);
    assert_eq!(transition.log_seq, 1);
    candidate.proposal.statement_id().unwrap()
}

// --- a lawful activation installs and is durable ---

#[tokio::test]
async fn live_a_lawful_activation_installs_and_is_durable() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let scope = normative_scope(&pool, "lawful");
    let statement_id = install_first(&scope).await;

    let head = scope
        .repository
        .read_head(&scope.family)
        .await
        .unwrap()
        .expect("an installed activation must leave a durable head");
    assert_eq!(head.head_revision, 1);
    assert_eq!(head.log_seq, 1);
    assert_eq!(
        head.active_binding_set_digest,
        active_binding_set_digest(&scope.family, &[statement_id])
    );
    assert_eq!(
        head.registry_package_digest,
        registry_binding().registry_package_digest
    );

    let projection = scope
        .repository
        .read_projection(&scope.family)
        .await
        .unwrap()
        .expect("an installed activation must leave a durable projection");
    assert_eq!(projection.cursor_seq, 1);
    assert_eq!(
        projection.resolution,
        NormativeResolutionV1::Active { statement_id }
    );

    let log = scope.repository.read_log(&scope.family).await.unwrap();
    assert_eq!(log.len(), 1);
    let NormativeLogRecordV1::Lifecycle { event, .. } = &log[0].record else {
        panic!("expected a lifecycle record");
    };
    assert_eq!(event.kind, NormativeLifecycleKindV1::Activation);
    assert_eq!(event.statement_id, statement_id);
}

// --- concurrency: two activations against one head, exactly one winner ---

#[tokio::test]
async fn live_two_concurrent_activations_against_one_head_produce_exactly_one_winner() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let scope = normative_scope(&pool, "race");

    // Two distinct, independently lawful proposals, both expecting the SAME
    // (inaugural, empty) composite head.
    let first = candidate(proposal(&scope, "racer-a", EFFECTIVE_FROM));
    let second = candidate(proposal(&scope, "racer-b", EFFECTIVE_FROM));
    assert_ne!(
        first.proposal.statement_id().unwrap(),
        second.proposal.statement_id().unwrap()
    );

    let left = Arc::clone(&scope.repository);
    let right = Arc::clone(&scope.repository);
    let (one, two) = tokio::join!(
        tokio::spawn(async move { left.activate(&first).await }),
        tokio::spawn(async move { right.activate(&second).await }),
    );
    let outcomes = [one.unwrap().unwrap(), two.unwrap().unwrap()];

    let installed = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, NormativeActivationOutcomeV1::Installed(_)))
        .count();
    let lost = outcomes
        .iter()
        .filter(|outcome| matches!(outcome, NormativeActivationOutcomeV1::Lost { .. }))
        .count();
    assert_eq!(installed, 1, "exactly one activation may win: {outcomes:?}");
    assert_eq!(lost, 1, "the other must lose cleanly: {outcomes:?}");

    // No double-apply and no torn state: one head revision, one log row, one
    // projection entry, and the cursor exactly on the log tail.
    let head = scope
        .repository
        .read_head(&scope.family)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(head.head_revision, 1);
    assert_eq!(head.log_seq, 1);
    let log = scope.repository.read_log(&scope.family).await.unwrap();
    assert_eq!(log.len(), 1, "the loser must not have appended");
    let projection = scope
        .repository
        .read_projection(&scope.family)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(projection.cursor_seq, head.log_seq);
    assert_eq!(projection.live.len(), 1);
    assert!(matches!(
        projection.resolution,
        NormativeResolutionV1::Active { .. }
    ));
}

#[tokio::test]
async fn live_a_second_activation_against_a_stale_head_loses_cleanly() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let scope = normative_scope(&pool, "stale");
    let first_id = install_first(&scope).await;

    // Prepared against the empty head, submitted after the head moved.
    let stale = candidate(proposal(&scope, "second", "2026-08-30T00:00:00.000000000Z"));
    let outcome = scope.repository.activate(&stale).await.unwrap();
    let NormativeActivationOutcomeV1::Lost {
        observed_binding_set_digest,
        observed_head_revision,
    } = outcome
    else {
        panic!("a stale expected head must lose the compare-and-set, got {outcome:?}");
    };
    assert_eq!(observed_head_revision, 1);
    assert_eq!(
        observed_binding_set_digest,
        active_binding_set_digest(&scope.family, &[first_id])
    );
    assert_eq!(
        scope
            .repository
            .read_log(&scope.family)
            .await
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn live_a_crash_after_the_writes_leaves_nothing_durable() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let scope = normative_scope(&pool, "atomic");

    let candidate = candidate(proposal(&scope, "aborted", EFFECTIVE_FROM));
    let error = scope
        .repository
        .activate_with_fault_injection(&candidate, NormativeFaultInjection::AbortAfterWrites)
        .await
        .expect_err("the injected fault must fail the transaction");
    assert!(
        error.to_string().contains("abort after writes"),
        "unexpected error: {error}"
    );

    // The log append, the head advance and the projection advance are one unit:
    // none of the three survived. The head row itself was seeded, but at its
    // untouched inaugural values.
    assert!(
        scope
            .repository
            .read_log(&scope.family)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        scope
            .repository
            .read_projection(&scope.family)
            .await
            .unwrap()
            .is_none()
    );
    let head = scope.repository.read_head(&scope.family).await.unwrap();
    assert!(head.is_none_or(|head| head.head_revision == 0 && head.log_seq == 0));

    // And the same candidate installs cleanly afterwards: no torn state was left.
    let outcome = scope.repository.activate(&candidate).await.unwrap();
    assert!(matches!(
        outcome,
        NormativeActivationOutcomeV1::Installed(_)
    ));
}

// --- contested overlap projects unknown ---

#[tokio::test]
async fn live_a_contested_overlap_projects_unknown() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let scope = normative_scope(&pool, "contested");

    // Two lawfully accepted, non-overlapping statements for one family.
    let first_id = install_first(&scope).await;
    let mut second = proposal(&scope, "second-era", "2026-09-01T00:00:00.000000000Z");
    second.effective_until = None;
    let mut first_bounded = proposal(&scope, "first", EFFECTIVE_FROM);
    first_bounded.effective_until = Some(timestamp("2026-09-01T00:00:00.000000000Z"));
    // Retire the open-ended first statement and re-activate it bounded, so the
    // two eras are disjoint and both live.
    let retire = NormativeLifecycleRequestV1 {
        binding_family_id: scope.family.clone(),
        kind: NormativeLifecycleKindV1::Retirement,
        statement_id: first_id,
        registry_head: registry_head(),
        effective_at: timestamp("2026-08-31T00:00:00.000000000Z"),
        expected_active_binding_set_digest: active_binding_set_digest(&scope.family, &[first_id]),
        waiver_reference_digest: None,
    };
    assert!(matches!(
        scope.repository.retire(&retire).await.unwrap(),
        NormativeActivationOutcomeV1::Installed(_)
    ));

    let mut bounded = candidate(first_bounded);
    bounded.proposal.expected_active_binding_set_digest = None;
    bounded.receipt = receipt_for(
        &bounded.proposal,
        &["principal.author", "principal.reviewer"],
    );
    let bounded_id = bounded.proposal.statement_id().unwrap();
    assert!(matches!(
        scope.repository.activate(&bounded).await.unwrap(),
        NormativeActivationOutcomeV1::Installed(_)
    ));

    let mut later = candidate(second);
    later.proposal.expected_active_binding_set_digest =
        active_binding_set_digest(&scope.family, &[bounded_id]);
    later.receipt = receipt_for(&later.proposal, &["principal.author", "principal.reviewer"]);
    let later_id = later.proposal.statement_id().unwrap();
    assert!(matches!(
        scope.repository.activate(&later).await.unwrap(),
        NormativeActivationOutcomeV1::Installed(_)
    ));

    // A detector finds their precedence unestablishable.
    let mut contested_statement_ids = vec![bounded_id, later_id];
    contested_statement_ids.sort_unstable();
    let contest = ContestedBindingV1 {
        schema_version: 1,
        binding_family_id: scope.family.clone(),
        contested_statement_ids,
        reason: NormativeContestReasonV1::IndependentlyAcceptedUnestablishableOrdering,
        detected_at: timestamp("2026-09-05T00:00:00.000000000Z"),
        waiver_reference_digest: None,
    };
    let transition = scope.repository.record_contest(&contest).await.unwrap();
    assert_eq!(transition.statement_id, None);

    let projection = scope
        .repository
        .read_projection(&scope.family)
        .await
        .unwrap()
        .unwrap();
    let NormativeResolutionV1::Unknown {
        contested_statement_ids,
    } = &projection.resolution
    else {
        panic!("a contested overlap must project unknown, got {projection:?}");
    };
    assert!(contested_statement_ids.contains(&bounded_id));
    assert!(contested_statement_ids.contains(&later_id));

    // The stored denormalised column agrees: no winner was picked.
    let stored: (String, Option<Vec<u8>>) = sqlx::query_as(
        "SELECT resolution, active_statement_id FROM public.memory_normative_projections_v1 \
         WHERE tenant_id = $1 AND project = $2 AND binding_family_id = $3",
    )
    .bind(scope.physical.tenant_id)
    .bind(scope.physical.project.as_str())
    .bind(scope.family.as_str())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(stored.0, "unknown");
    assert_eq!(stored.1, None);
}

// --- separation of duty is fail-closed ---

#[tokio::test]
async fn live_an_implicated_actor_cannot_activate_the_change() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let scope = normative_scope(&pool, "sod");

    // The source author is the only ratifier: refused by the contract's own rule.
    let mut author_only = candidate(proposal(&scope, "author-only", EFFECTIVE_FROM));
    author_only.receipt = receipt_for(&author_only.proposal, &["principal.author"]);
    assert!(scope.repository.activate(&author_only).await.is_err());

    // Author plus proposer: passes the contract's "not the sole ratifier" rule,
    // but every ratifier is implicated in the change, so the runtime refuses it.
    let mut implicated = candidate(proposal(&scope, "implicated", EFFECTIVE_FROM));
    implicated.receipt = receipt_for(
        &implicated.proposal,
        &["principal.author", "principal.agent"],
    );
    implicated
        .receipt
        .validate()
        .expect("the contract layer accepts this receipt");
    assert!(scope.repository.activate(&implicated).await.is_err());

    // Nothing reached the database on either refusal.
    assert!(
        scope
            .repository
            .read_log(&scope.family)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        scope
            .repository
            .read_head(&scope.family)
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn live_a_proposal_bound_to_another_scope_or_registry_is_refused() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let scope = normative_scope(&pool, "binding");

    let mut foreign_scope = candidate(proposal(&scope, "foreign-scope", EFFECTIVE_FROM));
    foreign_scope.proposal.scope = AuthenticatedProjectScopeV1::from_trusted_context(
        ContractId::new("tenant.attacker").unwrap(),
        ContractId::new("project.attacker").unwrap(),
    );
    foreign_scope.receipt = receipt_for(
        &foreign_scope.proposal,
        &["principal.author", "principal.reviewer"],
    );
    assert!(scope.repository.activate(&foreign_scope).await.is_err());

    let mut foreign_registry = candidate(proposal(&scope, "foreign-registry", EFFECTIVE_FROM));
    foreign_registry.proposal.registry_head.head.package_digest = label("attacker-package");
    foreign_registry.receipt = receipt_for(
        &foreign_registry.proposal,
        &["principal.author", "principal.reviewer"],
    );
    assert!(scope.repository.activate(&foreign_registry).await.is_err());

    assert!(
        scope
            .repository
            .read_log(&scope.family)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn live_an_overlapping_activation_without_supersession_is_refused() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let scope = normative_scope(&pool, "overlap");
    let first_id = install_first(&scope).await;

    let mut overlapping = candidate(proposal(
        &scope,
        "overlapping",
        "2026-08-25T00:00:00.000000000Z",
    ));
    overlapping.proposal.expected_active_binding_set_digest =
        active_binding_set_digest(&scope.family, &[first_id]);
    overlapping.receipt = receipt_for(
        &overlapping.proposal,
        &["principal.author", "principal.reviewer"],
    );
    let error = scope
        .repository
        .activate(&overlapping)
        .await
        .expect_err("an overlap without explicit supersession must be refused");
    assert!(
        error.to_string().contains("supersession"),
        "unexpected error: {error}"
    );
    assert_eq!(
        scope
            .repository
            .read_log(&scope.family)
            .await
            .unwrap()
            .len(),
        1
    );
}

// --- retirement and supersession append; the projection rebuilds ---

#[tokio::test]
async fn live_supersession_and_retirement_append_without_erasing_history() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let scope = normative_scope(&pool, "lifecycle");
    let first_id = install_first(&scope).await;
    let first_log = scope.repository.read_log(&scope.family).await.unwrap();
    let first_bytes = first_log[0].record.clone();

    // A lawful supersession: it overlaps the first statement and names it.
    let mut superseding = candidate(proposal(
        &scope,
        "superseding",
        "2026-08-25T00:00:00.000000000Z",
    ));
    superseding.proposal.explicitly_supersedes_statement_id = Some(first_id);
    superseding.proposal.expected_active_binding_set_digest =
        active_binding_set_digest(&scope.family, &[first_id]);
    superseding.receipt = receipt_for(
        &superseding.proposal,
        &["principal.author", "principal.reviewer"],
    );
    let second_id = superseding.proposal.statement_id().unwrap();
    let NormativeActivationOutcomeV1::Installed(transition) =
        scope.repository.activate(&superseding).await.unwrap()
    else {
        panic!("a lawful supersession must install");
    };
    assert_eq!(transition.head_revision, 2);
    assert_eq!(transition.log_seq, 2);

    // The prior activation row is byte-identical to what was accepted.
    let log = scope.repository.read_log(&scope.family).await.unwrap();
    assert_eq!(log.len(), 2);
    assert_eq!(log[0].record, first_bytes, "history must not be rewritten");
    let NormativeLogRecordV1::Lifecycle { event, .. } = &log[1].record else {
        panic!("expected a lifecycle record");
    };
    assert_eq!(event.kind, NormativeLifecycleKindV1::Supersession);
    assert_eq!(event.supersedes_statement_id, Some(first_id));

    // Retire the survivor: the family goes retired, the log keeps growing.
    let retire = NormativeLifecycleRequestV1 {
        binding_family_id: scope.family.clone(),
        kind: NormativeLifecycleKindV1::Retirement,
        statement_id: second_id,
        registry_head: registry_head(),
        effective_at: timestamp("2026-09-10T00:00:00.000000000Z"),
        expected_active_binding_set_digest: active_binding_set_digest(&scope.family, &[second_id]),
        waiver_reference_digest: None,
    };
    let NormativeActivationOutcomeV1::Installed(transition) =
        scope.repository.retire(&retire).await.unwrap()
    else {
        panic!("a lawful retirement must install");
    };
    assert_eq!(transition.log_seq, 3);
    assert_eq!(transition.active_binding_set_digest, None);

    let log = scope.repository.read_log(&scope.family).await.unwrap();
    assert_eq!(log.len(), 3);
    assert_eq!(log[0].record, first_bytes);
    let projection = scope
        .repository
        .read_projection(&scope.family)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(projection.resolution, NormativeResolutionV1::Retired);

    // A retirement whose expected binding set is stale loses the CAS cleanly.
    let stale_retire = NormativeLifecycleRequestV1 {
        expected_active_binding_set_digest: active_binding_set_digest(&scope.family, &[first_id]),
        ..retire
    };
    assert!(matches!(
        scope.repository.retire(&stale_retire).await.unwrap(),
        NormativeActivationOutcomeV1::Lost { .. }
    ));
    assert_eq!(
        scope
            .repository
            .read_log(&scope.family)
            .await
            .unwrap()
            .len(),
        3
    );
}

#[tokio::test]
async fn live_the_projection_rebuilds_byte_identically_from_the_event_log() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let scope = normative_scope(&pool, "rebuild");
    let first_id = install_first(&scope).await;

    let mut superseding = candidate(proposal(
        &scope,
        "superseding",
        "2026-08-25T00:00:00.000000000Z",
    ));
    superseding.proposal.explicitly_supersedes_statement_id = Some(first_id);
    superseding.proposal.expected_active_binding_set_digest =
        active_binding_set_digest(&scope.family, &[first_id]);
    superseding.receipt = receipt_for(
        &superseding.proposal,
        &["principal.author", "principal.reviewer"],
    );
    let second_id = superseding.proposal.statement_id().unwrap();
    assert!(matches!(
        scope.repository.activate(&superseding).await.unwrap(),
        NormativeActivationOutcomeV1::Installed(_)
    ));

    let stored = scope
        .repository
        .read_projection(&scope.family)
        .await
        .unwrap()
        .unwrap();
    let rebuilt = scope
        .repository
        .rebuild_projection(&scope.family)
        .await
        .unwrap();
    assert_eq!(
        stored.canonical_bytes().unwrap(),
        rebuilt.canonical_bytes().unwrap(),
        "the projection must rebuild byte-identically from the durable log"
    );
    assert_eq!(
        rebuilt.resolution,
        NormativeResolutionV1::Active {
            statement_id: second_id
        }
    );

    // And the stored canonical bytes on disk are exactly those bytes.
    let on_disk: Vec<u8> = sqlx::query_scalar(
        "SELECT canonical_projection FROM public.memory_normative_projections_v1 \
         WHERE tenant_id = $1 AND project = $2 AND binding_family_id = $3",
    )
    .bind(scope.physical.tenant_id)
    .bind(scope.physical.project.as_str())
    .bind(scope.family.as_str())
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(on_disk, rebuilt.canonical_bytes().unwrap());
}

#[tokio::test]
async fn live_two_projects_cannot_see_each_others_normative_state() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let one = normative_scope(&pool, "tenant-one");
    let two = normative_scope(&pool, "tenant-two");
    install_first(&one).await;

    // Same binding family id, different trusted (tenant, project) pair: the
    // second runtime sees no head, no log, and no projection.
    assert!(
        two.repository
            .read_head(&two.family)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        two.repository
            .read_log(&two.family)
            .await
            .unwrap()
            .is_empty()
    );
    assert!(
        two.repository
            .read_projection(&two.family)
            .await
            .unwrap()
            .is_none()
    );

    // And an inaugural activation in the second scope wins its own CAS, proving
    // the first scope's head did not leak into its compare.
    assert!(matches!(
        two.repository
            .activate(&candidate(proposal(&two, "first", EFFECTIVE_FROM)))
            .await
            .unwrap(),
        NormativeActivationOutcomeV1::Installed(_)
    ));
}

// --- head rebase (ADR 0008 D3) ---

/// The registry head a scope moves to: another package under the same
/// activation policy, as generation 2 -> 3 is.
fn next_binding() -> NormativeRegistryBindingV1 {
    NormativeRegistryBindingV1 {
        registry_package_digest: label("registry-package-next"),
        activation_policy_digest: registry_binding().activation_policy_digest,
    }
}

fn next_head() -> RegistryHeadBindingV1 {
    RegistryHeadBindingV1 {
        head: RegistryHeadV1 {
            activation_id: label("activation-next"),
            package_digest: next_binding().registry_package_digest,
            activation_policy_digest: next_binding().activation_policy_digest,
        },
        effective_from: timestamp("2026-08-01T00:00:00.000000000Z"),
        effective_until: None,
    }
}

/// The runtime for `scope` bound to the next registry head, as a writer
/// verifying the moved head builds it.
fn rebound(pool: &PgPool, scope: &NormativeScope) -> CockroachNormativeActivationRepository {
    let trusted =
        TrustedControlScope::from_trusted_context(&scope.physical, scope.scope.clone()).unwrap();
    CockroachNormativeActivationRepository::new(
        pool.clone(),
        trusted,
        next_binding(),
        retry_policy(),
    )
    .unwrap()
}

/// The next head as a rebase target that carries `entries`.
fn next_target(entries: &[&str]) -> NormativeRebaseTargetV1 {
    NormativeRebaseTargetV1::new(
        next_binding(),
        next_head().head.activation_id,
        entries.iter().copied().map(reference),
    )
    .unwrap()
}

/// A rebase of `scope`'s family whose one live statement, `statement_id`,
/// depends on what [`proposal`] names, resolved at `head_revision`.
fn rebase_request(
    scope: &NormativeScope,
    statement_id: Sha256Digest,
    head_revision: u64,
) -> NormativeRebaseRequestV1 {
    NormativeRebaseRequestV1 {
        binding_family_id: scope.family.clone(),
        expected_head_revision: head_revision,
        live_statement_dependencies: BTreeMap::from([(
            statement_id,
            BTreeSet::from([
                reference("environment.selector"),
                reference("slo.error_rate"),
            ]),
        )]),
    }
}

/// A supersession of `superseded` drafted under the next head.
fn superseding_under_next_head(
    scope: &NormativeScope,
    superseded: Sha256Digest,
) -> NormativeActivationCandidateV1 {
    let mut proposal = proposal(scope, "superseding", "2026-08-25T00:00:00.000000000Z");
    proposal.registry_head = next_head();
    proposal.explicitly_supersedes_statement_id = Some(superseded);
    proposal.expected_active_binding_set_digest =
        active_binding_set_digest(&scope.family, &[superseded]);
    candidate(proposal)
}

async fn record_kinds(pool: &PgPool, scope: &NormativeScope) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT record_kind FROM public.memory_normative_log_v1 \
         WHERE tenant_id = $1 AND project = $2 AND binding_family_id = $3 ORDER BY seq",
    )
    .bind(scope.physical.tenant_id)
    .bind(scope.physical.project.as_str())
    .bind(scope.family.as_str())
    .fetch_all(pool)
    .await
    .unwrap()
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // one family's whole stranded -> refused -> rebased -> superseded path
async fn live_a_family_is_rebased_onto_a_new_registry_head_only_when_its_dependencies_carry_when_configured()
 {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let scope = normative_scope(&pool, "rebase");
    let first_id = install_first(&scope).await;
    let moved = rebound(&pool, &scope);
    let head_before = moved.read_head(&scope.family).await.unwrap().unwrap();

    // Before any rebase the family is stranded: a supersession drafted under
    // the new head loses the compare-and-set and writes nothing (ADR 0007 D11).
    let superseding = superseding_under_next_head(&scope, first_id);
    assert!(matches!(
        moved.activate(&superseding).await.unwrap(),
        NormativeActivationOutcomeV1::Lost { .. }
    ));

    // A target missing an entry the live statement depends on is refused, and
    // so is a target the runtime is not bound to; neither writes anything.
    let missing = moved
        .rebase_family(
            &next_target(&["environment.selector"]),
            &rebase_request(&scope, first_id, 1),
        )
        .await;
    assert!(
        matches!(missing, Err(FleetError::ControlContract(_))),
        "{missing:?}"
    );
    let carried = next_target(&["environment.selector", "slo.error_rate", "unrelated"]);
    assert!(
        scope
            .repository
            .rebase_family(&carried, &rebase_request(&scope, first_id, 1))
            .await
            .is_err(),
        "a runtime bound to the old head cannot rebase onto the new one"
    );
    // A request resolved at another head revision is stale, not rebased over.
    assert_eq!(
        moved
            .rebase_family(&carried, &rebase_request(&scope, first_id, 0))
            .await
            .unwrap(),
        NormativeRebaseOutcomeV1::Stale {
            observed_head_revision: 1
        }
    );
    assert_eq!(
        moved.read_head(&scope.family).await.unwrap().unwrap(),
        head_before
    );
    assert_eq!(record_kinds(&pool, &scope).await, ["lifecycle"]);

    // The lawful rebase: one `rebase` row, the head moved onto the new
    // registry digests with its binding set unchanged, the resolution intact.
    let NormativeRebaseOutcomeV1::Rebased { transition, rebase } = moved
        .rebase_family(&carried, &rebase_request(&scope, first_id, 1))
        .await
        .unwrap()
    else {
        panic!("a family whose dependencies carry must rebase");
    };
    assert_eq!(transition.head_revision, 2);
    assert_eq!(transition.log_seq, 2);
    assert_eq!(transition.statement_id, None);
    assert_eq!(
        transition.active_binding_set_digest,
        head_before.active_binding_set_digest
    );
    assert_eq!(
        rebase.from_registry_package_digest,
        registry_binding().registry_package_digest
    );
    assert_eq!(
        rebase.to_registry_package_digest,
        next_binding().registry_package_digest
    );
    assert_eq!(
        rebase.registry_activation_id,
        next_head().head.activation_id
    );
    assert_eq!(rebase.carried_entry_digests.len(), 2);
    let head = moved.read_head(&scope.family).await.unwrap().unwrap();
    assert_eq!(
        head.registry_package_digest,
        next_binding().registry_package_digest
    );
    assert_eq!(
        head.active_binding_set_digest,
        head_before.active_binding_set_digest
    );
    assert_eq!((head.head_revision, head.log_seq), (2, 2));
    assert_eq!(record_kinds(&pool, &scope).await, ["lifecycle", "rebase"]);
    let log = moved.read_log(&scope.family).await.unwrap();
    assert_eq!(log[1].record_id, transition.event_id);
    let stored = moved.read_projection(&scope.family).await.unwrap().unwrap();
    assert_eq!(stored.cursor_seq, 2);
    assert_eq!(
        stored.resolution,
        NormativeResolutionV1::Active {
            statement_id: first_id
        }
    );
    assert_eq!(
        moved
            .rebuild_projection(&scope.family)
            .await
            .unwrap()
            .canonical_bytes()
            .unwrap(),
        stored.canonical_bytes().unwrap(),
        "the rebased projection rebuilds byte-identically from the log"
    );

    // A re-run rebases nothing twice.
    assert_eq!(
        moved
            .rebase_family(&carried, &rebase_request(&scope, first_id, 2))
            .await
            .unwrap(),
        NormativeRebaseOutcomeV1::AlreadyCurrent { head_revision: 2 }
    );
    assert_eq!(moved.read_log(&scope.family).await.unwrap().len(), 2);

    // The family now takes activations under the new head, and only there.
    assert!(matches!(
        scope
            .repository
            .activate(&candidate(proposal(
                &scope,
                "old-head",
                "2026-08-25T00:00:00.000000000Z"
            )))
            .await
            .unwrap(),
        NormativeActivationOutcomeV1::Lost { .. }
    ));
    let second_id = superseding.proposal.statement_id().unwrap();
    let NormativeActivationOutcomeV1::Installed(transition) =
        moved.activate(&superseding).await.unwrap()
    else {
        panic!("a supersession under the new head must install once rebased");
    };
    assert_eq!((transition.head_revision, transition.log_seq), (3, 3));
    assert_eq!(
        moved
            .read_projection(&scope.family)
            .await
            .unwrap()
            .unwrap()
            .resolution,
        NormativeResolutionV1::Active {
            statement_id: second_id
        }
    );
}
