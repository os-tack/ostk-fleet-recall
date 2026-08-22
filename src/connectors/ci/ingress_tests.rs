//! Unit proofs for the CI ingress: Version-form or nothing, scope from the
//! witness, three ordered clocks.

use super::*;
use crate::connectors::ci::fact::{
    CI_FACT_SCHEMA_VERSION, CiCommitShaV1, CiJobV1, CiOutcomeV1, CiRepositoryIdV1, CiRunStatusV1,
    CiStepV1, CiTextV1, CiWorkflowRunFactV1,
};
use crate::evidence_ledger::{
    WriterAuthoritySnapshot, WriterAuthorityWitness, partition_algorithm_label,
};
use crate::memory_contracts::bootstrap::BootstrapReceiptV1;
use crate::memory_contracts::canonical::decode_strict;
use crate::memory_contracts::common::{CanonicalDecimal, frozen_profile_reference_v1};
use crate::memory_contracts::digest::{DigestDomain, domain_separated_digest};
use crate::memory_contracts::evidence_v2::RegistryHeadBindingV1;
use crate::memory_contracts::generation2_registry::{
    CI_CONNECTOR, GIT_CONNECTOR, generation_two_registry_package,
};
use crate::memory_contracts::registry::{ManifestVerifiedRegistryPackage, RegistryHeadV1};
use crate::memory_contracts::stage4_target_package::SemanticallyClosedStage4Package;
use crate::memory_contracts::successor_package::SemanticallyClosedSuccessorPackage;

const BOOTSTRAP_RECEIPT: &[u8] =
    include_bytes!("../../../contracts/dynamic-memory/v1/bootstrap-receipt.jsonl");
const GENERATION_ONE_PACKAGE: &[u8] =
    include_bytes!("../../../contracts/dynamic-memory/v2/stage4-successor/registry-package.jsonl");

const INSTALLATION_ID: u64 = 4242;

fn record(artifact: &'static [u8]) -> &'static [u8] {
    artifact
        .strip_suffix(b"\n")
        .expect("contract JSONL must have exactly one framing LF")
}

fn generation_one() -> ManifestVerifiedRegistryPackage {
    ManifestVerifiedRegistryPackage::decode(
        record(GENERATION_ONE_PACKAGE),
        &frozen_profile_reference_v1(),
    )
    .expect("the frozen generation-1 package must decode")
}

fn synthetic_head(
    package_digest: crate::memory_contracts::digest::Sha256Digest,
) -> RegistryHeadBindingV1 {
    RegistryHeadBindingV1 {
        head: RegistryHeadV1 {
            activation_id: domain_separated_digest(
                DigestDomain::RegistryActivationReceipt,
                b"w3-ciev-activation",
            ),
            package_digest,
            activation_policy_digest: domain_separated_digest(
                DigestDomain::RegistryActivationStatement,
                b"w3-ciev-activation-policy",
            ),
        },
        effective_from: CanonicalTimestamp::parse("2026-08-15T12:00:00.000000000Z").unwrap(),
        effective_until: None,
    }
}

fn witness_for(head: &RegistryHeadBindingV1) -> WriterAuthorityWitness {
    let receipt: BootstrapReceiptV1 = decode_strict(record(BOOTSTRAP_RECEIPT)).unwrap();
    let genesis_epoch = receipt.statement.genesis_epoch.clone();
    let scope = receipt.statement.scope;
    let recipe = genesis_epoch.partition_recipe.clone();
    WriterAuthorityWitness::from_authority_snapshot(WriterAuthoritySnapshot {
        head_state: "active".to_owned(),
        generation: 1,
        activation_id: head.head.activation_id,
        package_digest: head.head.package_digest,
        activation_policy_digest: head.head.activation_policy_digest,
        log_epoch_id: genesis_epoch.epoch_id().unwrap(),
        partition_recipe_id: recipe.recipe_id.as_str().to_owned(),
        partition_recipe_version: recipe.recipe_version,
        partition_algorithm: partition_algorithm_label(recipe.algorithm).to_owned(),
        partition_seed: recipe.seed,
        log_shard_count: recipe.shard_count,
        head_scope: scope.clone(),
        bootstrap_scope: scope,
        genesis_epoch,
    })
    .expect("the frozen bootstrap receipt must yield a consistent witness")
}

/// A generation-2 head bound to one named connector schema.
fn generation_two_active(connector_schema_id: &str) -> ActiveStage4Package {
    let package = SemanticallyClosedSuccessorPackage::from_manifest_verified(
        generation_two_registry_package(&generation_one())
            .expect("the generation-2 composition must close"),
    )
    .expect("the composed package must close semantically");
    let head = synthetic_head(package.package_digest());
    let witness = witness_for(&head);
    ActiveStage4Package::bind_connector(
        package,
        &ContractId::new(connector_schema_id).unwrap(),
        head,
        &witness,
    )
    .expect("the generation-2 package must bind to the head that activated it")
}

/// The frozen generation-1 head, whose only connector is occurrence-form.
fn generation_one_active() -> ActiveStage4Package {
    let package = SemanticallyClosedStage4Package::from_successor_package(
        SemanticallyClosedSuccessorPackage::from_manifest_verified(generation_one())
            .expect("the frozen package must close"),
    )
    .expect("the frozen package must narrow to the Stage-4 target");
    let head = synthetic_head(package.package_digest());
    let witness = witness_for(&head);
    ActiveStage4Package::bind(&package, head, &witness)
        .expect("the frozen package must bind to a head that activated it")
}

fn binding(active: &ActiveStage4Package) -> CiIngressResult<CiConnectorBindingV1> {
    CiConnectorBindingV1::resolve(
        active,
        ContractId::new("connector.ci").unwrap(),
        ContractId::new("connector.ci.instance-1").unwrap(),
        INSTALLATION_ID,
    )
}

fn stamp(value: &str) -> CanonicalTimestamp {
    CanonicalTimestamp::parse(value).unwrap()
}

fn clocks() -> CiIngressClocksV1 {
    CiIngressClocksV1 {
        observed_at: stamp("2026-08-22T12:00:00.000000000Z"),
        received_at: stamp("2026-08-22T12:00:01.000000000Z"),
    }
}

fn run_fact() -> CiFactV1 {
    CiFactV1::WorkflowRun(CiWorkflowRunFactV1 {
        schema_version: CI_FACT_SCHEMA_VERSION,
        repository: CiRepositoryIdV1::from_trusted_config(
            ContractId::new("ci.repo.aetia").unwrap(),
            INSTALLATION_ID,
        )
        .unwrap(),
        run_id: CanonicalDecimal::parse("31741164105").unwrap(),
        run_number: 5,
        run_attempt: 1,
        workflow: CiTextV1::render("ci.yml").unwrap(),
        event: CiTextV1::render("push").unwrap(),
        head_branch: CiTextV1::render("main").unwrap(),
        head_sha: CiCommitShaV1::parse("bf34dc1f48624221839c5b7b4ab8dfcd00bed73a").unwrap(),
        display_title: CiTextV1::render("ci add the acceptance demo").unwrap(),
        status: CiRunStatusV1::Completed,
        conclusion: CiOutcomeV1::Failure,
        run_started_at: stamp("2026-08-13T20:30:00.000000000Z"),
        settled_at: stamp("2026-08-13T20:45:00.000000000Z"),
        jobs: vec![CiJobV1 {
            job_id: CanonicalDecimal::parse("94584609140").unwrap(),
            name: CiTextV1::render("docs").unwrap(),
            status: CiRunStatusV1::Completed,
            conclusion: CiOutcomeV1::Failure,
            started_at: stamp("2026-08-13T20:30:06.000000000Z"),
            completed_at: stamp("2026-08-13T20:31:06.000000000Z"),
            steps: vec![CiStepV1 {
                number: 3,
                name: CiTextV1::render("Validate Mermaid diagrams").unwrap(),
                status: CiRunStatusV1::Completed,
                conclusion: CiOutcomeV1::Failure,
            }],
            failure_annotations: vec![
                CiTextV1::render(".github Process completed with exit code 1.").unwrap(),
            ],
        }],
    })
}

// ---------------------------------------------------------------------------
// The Version-form gate.
// ---------------------------------------------------------------------------

#[test]
fn a_generation_two_head_binds_the_ci_connector() {
    let active = generation_two_active(CI_CONNECTOR.connector_schema);
    let binding = binding(&active).expect("the CI connector must resolve under generation 2");
    let uri = binding
        .canonical_resource_uri(&run_fact())
        .expect("a settled run must address a canonical resource");
    assert_eq!(
        uri.identity_form(),
        IdentityForm::Version,
        "the body plane only chunks a version-form resource"
    );
}

#[test]
fn an_occurrence_form_head_is_refused_rather_than_admitted() {
    // THE regression this connector exists downstream of. Generation 1's only
    // connector names `identity.github.push`, whose form is `occurrence`.
    // Admitting under it produced 980 accepted events with 0 bodies and 0
    // lexical rows. Refusing to bind is strictly better than minting evidence
    // nothing can retrieve.
    let active = generation_one_active();
    let error = binding(&active).expect_err("an occurrence-form connector must not bind");
    match error {
        CiIngressError::CanonicalResourceNotVersionForm { recipe, form } => {
            assert_eq!(recipe, "identity.github.push");
            assert_eq!(form, IdentityForm::Occurrence);
        }
        other => panic!("expected a version-form refusal, got {other}"),
    }
}

#[test]
fn binding_a_connector_the_active_package_does_not_carry_is_refused() {
    let package = SemanticallyClosedSuccessorPackage::from_manifest_verified(
        generation_two_registry_package(&generation_one()).unwrap(),
    )
    .unwrap();
    let head = synthetic_head(package.package_digest());
    let witness = witness_for(&head);
    assert!(
        ActiveStage4Package::bind_connector(
            package,
            &ContractId::new("connector.ci.invented").unwrap(),
            head,
            &witness,
        )
        .is_err(),
        "a connector id selects an entry; it can never introduce one"
    );
}

// ---------------------------------------------------------------------------
// EVID-04: scope comes from the witness, never from the fact.
// ---------------------------------------------------------------------------

#[test]
fn every_candidate_carries_the_credential_bound_scope() {
    let active = generation_two_active(CI_CONNECTOR.connector_schema);
    let binding = binding(&active).unwrap();
    let ingress = binding.build_ingress(&run_fact(), &clocks(), 1).unwrap();
    assert_eq!(&ingress.candidate.scope, active.scope());
    assert_eq!(&ingress.candidate.source_fact.scope, active.scope());
    assert_eq!(binding.scope(), active.scope());
}

#[test]
fn the_ci_connector_and_the_git_connector_derive_different_resources() {
    // Two connectors under one head must not collide on one resource just
    // because their revision bytes could coincide.
    let ci = generation_two_active(CI_CONNECTOR.connector_schema);
    let git = generation_two_active(GIT_CONNECTOR.connector_schema);
    let ci_uri = binding(&ci)
        .unwrap()
        .canonical_resource_uri(&run_fact())
        .unwrap();
    let git_binding = crate::connectors::git::GitConnectorBindingV1::resolve(
        &git,
        ContractId::new("connector.git").unwrap(),
        ContractId::new("connector.git.instance-1").unwrap(),
        INSTALLATION_ID,
    )
    .unwrap();
    let git_uri = git_binding.provider_instance_uri().unwrap();
    assert_ne!(ci_uri.digest(), git_uri.digest());
    assert_ne!(ci_uri.resource_kind(), git_uri.resource_kind());
}

// ---------------------------------------------------------------------------
// EVID-03: three clocks, ordered, never rewritten.
// ---------------------------------------------------------------------------

#[test]
fn the_three_clocks_are_distinct_and_ordered() {
    let active = generation_two_active(CI_CONNECTOR.connector_schema);
    let ingress = binding(&active)
        .unwrap()
        .build_ingress(&run_fact(), &clocks(), 1)
        .unwrap();
    let candidate = &ingress.candidate;
    assert_eq!(
        candidate.occurred_at.as_str(),
        "2026-08-13T20:45:00.000000000Z",
        "occurred_at is the provider's settle instant"
    );
    assert_eq!(
        candidate.observed_at.as_str(),
        "2026-08-22T12:00:00.000000000Z",
        "observed_at is when this connector fetched the window"
    );
    assert_eq!(
        candidate.received_at.as_str(),
        "2026-08-22T12:00:01.000000000Z",
        "received_at is when the ingress accepted the reading"
    );
    assert!(candidate.occurred_at < candidate.observed_at);
    assert!(candidate.observed_at < candidate.received_at);
}

#[test]
fn a_provider_clock_ahead_of_the_reader_is_refused_not_back_dated() {
    let active = generation_two_active(CI_CONNECTOR.connector_schema);
    let binding = binding(&active).unwrap();
    let mut future = clocks();
    // The provider claims the run settled AFTER the fetch that saw it.
    future.observed_at = stamp("2026-08-13T20:00:00.000000000Z");
    future.received_at = stamp("2026-08-13T20:00:01.000000000Z");
    let error = binding
        .build_ingress(&run_fact(), &future, 1)
        .expect_err("a run cannot be observed before it settled");
    assert!(
        matches!(error, CiIngressError::ClockOrder(_)),
        "unexpected error: {error}"
    );
}

#[test]
fn a_received_clock_before_the_observation_is_refused() {
    let active = generation_two_active(CI_CONNECTOR.connector_schema);
    let binding = binding(&active).unwrap();
    let mut inverted = clocks();
    inverted.received_at = stamp("2026-08-22T11:59:00.000000000Z");
    assert!(matches!(
        binding.build_ingress(&run_fact(), &inverted, 1),
        Err(CiIngressError::ClockOrder(_))
    ));
}

#[test]
fn a_clock_that_is_not_microsecond_aligned_is_refused() {
    let active = generation_two_active(CI_CONNECTOR.connector_schema);
    let binding = binding(&active).unwrap();
    let mut misaligned = clocks();
    misaligned.observed_at = stamp("2026-08-22T12:00:00.000000001Z");
    assert!(matches!(
        binding.build_ingress(&run_fact(), &misaligned, 1),
        Err(CiIngressError::ClockOrder(_))
    ));
}

// ---------------------------------------------------------------------------
// Settledness and shape at the admission boundary.
// ---------------------------------------------------------------------------

#[test]
fn an_unsettled_run_is_refused_at_the_admission_boundary() {
    let active = generation_two_active(CI_CONNECTOR.connector_schema);
    let binding = binding(&active).unwrap();
    let CiFactV1::WorkflowRun(mut run) = run_fact() else {
        unreachable!("run_fact builds a workflow run")
    };
    run.status = CiRunStatusV1::InProgress;
    let error = binding
        .build_ingress(&CiFactV1::WorkflowRun(run), &clocks(), 1)
        .expect_err("an unsettled run has no immutable revision to address");
    assert!(
        matches!(
            error,
            CiIngressError::Fact(crate::connectors::ci::CiFactError::UnsettledRun {
                run_number: 5,
                ..
            })
        ),
        "unexpected error: {error}"
    );
}

#[test]
fn the_candidate_asserts_no_actor_and_no_private_artifact() {
    let active = generation_two_active(CI_CONNECTOR.connector_schema);
    let ingress = binding(&active)
        .unwrap()
        .build_ingress(&run_fact(), &clocks(), 1)
        .unwrap();
    assert!(
        ingress.candidate.provider_actor_id.is_none(),
        "AUTH-02: this connector cannot prove a provider actor"
    );
    assert!(
        ingress.candidate.private_raw_artifact.is_none(),
        "EVID-05: no raw artifact crosses to the private plane"
    );
    assert_eq!(
        ingress
            .candidate
            .canonical_payload
            .asserted_media_type
            .as_str(),
        CI_FACT_MEDIA_TYPE
    );
}

#[test]
fn the_body_is_word_searchable_json_not_hex() {
    let active = generation_two_active(CI_CONNECTOR.connector_schema);
    let ingress = binding(&active)
        .unwrap()
        .build_ingress(&run_fact(), &clocks(), 1)
        .unwrap();
    let body = String::from_utf8(ingress.canonical_payload).unwrap();
    // The words a reader actually types, present verbatim in the governed body.
    for word in ["docs", "Mermaid", "failure", "main", "ci.yml"] {
        assert!(
            body.contains(word),
            "the body must contain {word:?}: {body}"
        );
    }
}

#[test]
fn two_builds_of_one_fact_are_byte_identical() {
    let active = generation_two_active(CI_CONNECTOR.connector_schema);
    let binding = binding(&active).unwrap();
    let once = binding.build_ingress(&run_fact(), &clocks(), 1).unwrap();
    let twice = binding.build_ingress(&run_fact(), &clocks(), 1).unwrap();
    assert_eq!(once, twice, "EVENT-01: a re-drain is an exact replay");
}
