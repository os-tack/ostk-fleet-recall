//! Connected proof for the writer-authority installer
//! (`registry_activation::install`, `ostk-authority-install apply`).
//!
//! Set `FLEET_RECALL_TEST_DATABASE_URL` to a disposable `CockroachDB` 26.2
//! database; every test here is inert otherwise. Each test installs into a
//! fresh physical tenant through the shared `tests/common` fixture or the
//! installer directly, so nothing here depends on another test's rows.
//!
//! What it proves is behavior a writer depends on: the installer takes a
//! physical scope to generation 2 under contract namespaces other than the
//! frozen `tenant.fixture` ones, the strict witness accepts the result under
//! exactly the pins the installer prints, both a Wave-2 connector and the
//! generation-1 connector bind out of it, a re-run changes nothing, and a
//! physical scope already installed for other namespaces, or bootstrapped by
//! another receipt with no head yet, is refused intact.
//! It also proves the `WriterAuthorityRuntime` every appending process starts
//! from those pins: it starts and binds connectors under nothing but the
//! runtime role's grants, refuses pins the head does not honor, and re-reads
//! the head on every verification instead of trusting its startup read.
//!
//! And it proves generation 3 is opt-in and one-way (ADR 0008 D2): a fresh
//! scope reaches it in one run with `--target generation-3`, a generation-2
//! head that cannot bind a collected-item connector moves to it and then can,
//! a re-run changes nothing, and the default target leaves a generation-3
//! head where it is.

mod common;

use common::authority::{
    InstalledAuthority, install_generation_three, install_generation_two, retry_policy,
    semantic_scope,
};
use common::runtime_role::RuntimeProbeRole;
use ostk_fleet_recall::FleetError;
use ostk_fleet_recall::config::WriterAuthorityConfig;
use ostk_fleet_recall::control_log::{
    CockroachGenesisRepository, GenesisInspection, GenesisRepository as _, TrustedControlScope,
};
use ostk_fleet_recall::evidence_ledger::{ActiveStage4Package, EvidenceAdmissionError};
use ostk_fleet_recall::memory_contracts::bootstrap::{
    BootstrapPin, BootstrapReceiptDigest, verify_pinned_bootstrap,
};
use ostk_fleet_recall::memory_contracts::common::{
    AuthenticatedProjectScopeV1, ContractId, frozen_profile_reference_v1,
};
use ostk_fleet_recall::memory_contracts::digest::{
    DigestDomain, Sha256Digest, domain_separated_digest,
};
use ostk_fleet_recall::memory_contracts::generation2_registry::GIT_CONNECTOR;
use ostk_fleet_recall::memory_contracts::generation3_registry::COLLECTED_ITEM_FAMILY;
use ostk_fleet_recall::registry_activation::install::{
    AuthorityInstallRequestV1, InstallStepOutcomeV1, InstallStepV1, InstallTargetV1,
    install_writer_authority,
};
use ostk_fleet_recall::registry_witness::{
    KnownRegistryPackage, WriterAuthorityError, WriterAuthorityRejection, WriterAuthorityRuntime,
    WriterAuthorityStartError, WriterAuthorityWitness, compiled_genesis_package, load_and_verify,
};
use sqlx::PgPool;

/// The one connector the frozen generation-1 package carries, which
/// generation 2 carries forward.
const GITHUB_PUSH_CONNECTOR: &str = "connector.github.push";

/// The frozen Stage-1 bootstrap receipt, as a hand-run `ostk-control-bootstrap`
/// would apply it: `tenant.fixture`/`project.fixture`, public fixture keys.
const FROZEN_BOOTSTRAP_RECEIPT: &[u8] =
    include_bytes!("../contracts/dynamic-memory/v1/bootstrap-receipt.jsonl");

#[tokio::test]
async fn live_install_reaches_generation_two_and_the_strict_witness_accepts_it_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let physical = common::fresh_scope("authority-install");
    let semantic = semantic_scope();
    assert_ne!(
        semantic.tenant_namespace.as_str(),
        "tenant.fixture",
        "the install must exercise a re-scoped receipt and a rebuilt key bridge"
    );

    let report = install_writer_authority(
        &pool,
        &AuthorityInstallRequestV1 {
            physical_scope: physical.clone(),
            semantic_scope: semantic.clone(),
            target: InstallTargetV1::Generation2,
        },
        retry_policy(),
    )
    .await
    .expect("a fresh physical scope must install to generation 2");
    assert!(
        report
            .steps
            .iter()
            .all(|step| step.outcome == InstallStepOutcomeV1::Inserted),
        "a fresh physical scope must run every step: {:?}",
        report.steps
    );
    assert_eq!(report.package, KnownRegistryPackage::ConnectorGeneration2);
    assert_eq!(report.generation, 2);
    assert_eq!(report.pins.semantic_scope(), semantic);

    // A writer starts from the printed pins alone.
    let witness = load_and_verify(&pool, &physical, &report.pins.writer_authority_config())
        .await
        .expect("the strict witness must accept the installed head under the printed pins");
    assert_eq!(
        witness.active_package().known(),
        KnownRegistryPackage::ConnectorGeneration2
    );
    assert!(witness.stage4_package().is_none());
    assert_eq!(witness.activation_id(), report.activation_id);
    assert_eq!(witness.generation(), report.generation);
    assert_eq!(
        witness.contract_tenant_namespace(),
        &semantic.tenant_namespace
    );
    assert_eq!(
        witness.contract_project_namespace(),
        &semantic.project_namespace
    );
    assert!(witness.certifies_scope(&physical));

    let append_witness = witness
        .to_append_witness()
        .expect("the strict witness adapts to the append witness");
    for connector in [GIT_CONNECTOR.connector_schema, GITHUB_PUSH_CONNECTOR] {
        ActiveStage4Package::bind_connector(
            witness.package().clone(),
            &ContractId::new(connector).unwrap(),
            witness.head_binding().clone(),
            &append_witness,
        )
        .unwrap_or_else(|error| {
            panic!("the installed head must bind {connector} for admission: {error}")
        });
    }
}

#[tokio::test]
async fn live_install_is_idempotent_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let installed = install_generation_two(&pool, "authority-idempotent").await;
    assert!(
        installed
            .report
            .steps
            .iter()
            .all(|step| step.outcome == InstallStepOutcomeV1::Inserted)
    );

    let again = install_writer_authority(&pool, &installed.request(), retry_policy())
        .await
        .expect("a re-run over an installed physical scope must succeed");
    assert_eq!(
        again.steps.iter().map(|step| step.step).collect::<Vec<_>>(),
        installed
            .report
            .steps
            .iter()
            .map(|step| step.step)
            .collect::<Vec<_>>(),
        "a re-run walks the same steps"
    );
    assert!(
        again
            .steps
            .iter()
            .all(|step| step.outcome == InstallStepOutcomeV1::AlreadyPresent),
        "a re-run must write nothing: {:?}",
        again.steps
    );
    assert_eq!(again.pins, installed.report.pins);
    assert_eq!(again.activation_id, installed.report.activation_id);
    assert_eq!(again.generation, installed.report.generation);
    assert_eq!(again.package, installed.report.package);
}

#[tokio::test]
async fn live_install_refuses_a_physical_scope_installed_for_other_namespaces_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let installed = install_generation_two(&pool, "authority-refusal").await;

    let mut other = installed.request();
    other.semantic_scope = AuthenticatedProjectScopeV1::from_trusted_context(
        installed.semantic_scope.tenant_namespace.clone(),
        ContractId::new("project.other").unwrap(),
    );
    let refusal = install_writer_authority(&pool, &other, retry_policy())
        .await
        .expect_err("a physical scope installed for other namespaces must be refused");
    assert!(
        matches!(refusal, FleetError::Configuration(_)),
        "the refusal must be the installer's own verdict, not a failed write: {refusal}"
    );

    let witness = load_and_verify(&pool, &installed.scope, &installed.config)
        .await
        .expect("the refused run must leave the installed authority intact");
    assert_eq!(witness.activation_id(), installed.report.activation_id);
    assert_eq!(
        witness.active_package().known(),
        KnownRegistryPackage::ConnectorGeneration2
    );
}

#[tokio::test]
async fn live_install_refuses_a_physical_scope_bootstrapped_without_a_head_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let physical = common::fresh_scope("authority-foreign-bootstrap");

    // A control bootstrap no install wrote, with no registry head above it:
    // what a hand-run `ostk-control-bootstrap`, or an install for other
    // namespaces that stopped after its first step, leaves behind. The strict
    // witness cannot see it yet, because the view projects a head only once
    // `0 -> 1` has committed.
    let fixture_scope = AuthenticatedProjectScopeV1::from_trusted_context(
        ContractId::new("tenant.fixture").unwrap(),
        ContractId::new("project.fixture").unwrap(),
    );
    let genesis = compiled_genesis_package().expect("the compiled genesis package closes");
    let receipt = FROZEN_BOOTSTRAP_RECEIPT
        .strip_suffix(b"\n")
        .expect("contract JSONL ends in one framing LF");
    let bootstrap = verify_pinned_bootstrap(
        receipt,
        BootstrapPin::from_trusted_config(BootstrapReceiptDigest::from_digest(
            domain_separated_digest(DigestDomain::BootstrapReceipt, receipt),
        )),
        &frozen_profile_reference_v1(),
        &fixture_scope,
        genesis,
    )
    .expect("the frozen receipt verifies under its own digest");
    let control = CockroachGenesisRepository::new(
        pool.clone(),
        TrustedControlScope::from_trusted_context(&physical, fixture_scope.clone()).unwrap(),
        retry_policy(),
    );
    control
        .bootstrap_genesis(&bootstrap, genesis)
        .await
        .expect("the frozen receipt bootstraps a fresh physical scope");

    // The installer's own receipt under the same namespaces, and other
    // namespaces: neither is the authority this scope holds, and both are the
    // installer's refusal, exactly as they are once a head exists.
    for semantic in [fixture_scope.clone(), semantic_scope()] {
        let request = AuthorityInstallRequestV1 {
            physical_scope: physical.clone(),
            semantic_scope: semantic.clone(),
            target: InstallTargetV1::Generation2,
        };
        let refusal = install_writer_authority(&pool, &request, retry_policy())
            .await
            .expect_err("a physical scope bootstrapped by another receipt must be refused");
        assert!(
            matches!(refusal, FleetError::Configuration(_)),
            "the refusal for {} must be the installer's own verdict, not a failed write: {refusal}",
            semantic.tenant_namespace.as_str()
        );
    }

    // Nothing was written: the stored bootstrap is intact and still has no head.
    assert!(matches!(
        control
            .inspect_genesis(&bootstrap, genesis)
            .await
            .expect("the stored bootstrap must still audit"),
        GenesisInspection::Complete(_)
    ));
    let stored_pins = WriterAuthorityConfig::from_trusted_context(
        fixture_scope,
        bootstrap.receipt_digest(),
        None,
    );
    let head = load_and_verify(&pool, &physical, &stored_pins).await;
    assert!(
        matches!(
            head,
            Err(WriterAuthorityError::Rejected(
                WriterAuthorityRejection::Absent
            ))
        ),
        "a refused install must not activate anything: {:?}",
        head.map(|witness| witness.generation())
    );
}

#[tokio::test]
async fn live_runtime_bundle_starts_and_binds_connectors_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let installed = install_generation_two(&pool, "authority-runtime").await;
    let probe = RuntimeProbeRole::create(&pool, &database_url).await;

    // The runtime starts under nothing but the runtime role's grants.
    let (runtime, startup) = WriterAuthorityRuntime::start(
        probe.pool.clone(),
        installed.scope.clone(),
        installed.config.clone(),
        retry_policy(),
    )
    .await
    .expect("the runtime grants must suffice to start under the installed pins");
    assert_eq!(startup.package, KnownRegistryPackage::ConnectorGeneration2);
    assert_eq!(startup.generation, installed.report.generation);
    assert_eq!(startup.activation_id, installed.report.activation_id);
    assert_eq!(runtime.semantic_scope(), &installed.semantic_scope);
    assert_eq!(
        runtime.ledger().trusted_scope(),
        runtime.control_scope(),
        "the ledger appends into exactly the scope the witness certifies"
    );
    assert_eq!(
        runtime.control_scope().tenant_id(),
        installed.scope.tenant_id
    );
    assert_eq!(runtime.control_scope().project(), installed.scope.project);

    let authority = runtime
        .verify()
        .await
        .expect("a started runtime must verify the head again");
    assert_eq!(authority.witness().generation(), 2);
    assert_eq!(
        authority.witness().active_package().known(),
        KnownRegistryPackage::ConnectorGeneration2
    );
    assert!(authority.witness().certifies_scope(&installed.scope));
    assert_eq!(authority.head_binding(), authority.witness().head_binding());
    for connector in [GIT_CONNECTOR.connector_schema, GITHUB_PUSH_CONNECTOR] {
        authority
            .bind_connector(&ContractId::new(connector).unwrap())
            .unwrap_or_else(|error| {
                panic!("the runtime must bind {connector} for admission: {error}")
            });
    }

    // Pins the durable head does not honor stop a process at startup.
    let wrong_pin = WriterAuthorityConfig::from_trusted_context(
        installed.semantic_scope.clone(),
        BootstrapReceiptDigest::from_digest(Sha256Digest::from_bytes([0x5a; 32])),
        None,
    );
    let refusal = WriterAuthorityRuntime::start(
        probe.pool.clone(),
        installed.scope.clone(),
        wrong_pin,
        retry_policy(),
    )
    .await
    .expect_err("a receipt pin the head does not carry must not start");
    assert!(
        matches!(
            refusal,
            WriterAuthorityStartError::Rejected(WriterAuthorityRejection::BootstrapPin)
        ),
        "unexpected refusal: {refusal}"
    );

    // Nothing from startup is cached: once the login loses the authority
    // view, the very next verification fails.
    sqlx::query(&format!(
        "REVOKE SELECT ON TABLE public.memory_writer_authority_v1 FROM {}",
        probe.name()
    ))
    .execute(&pool)
    .await
    .expect("revoke the probe's view grant");
    let error = runtime
        .verify()
        .await
        .expect_err("a verification must re-read the authority view");
    let code = match &error {
        WriterAuthorityError::Database(error) => error
            .as_database_error()
            .and_then(sqlx::error::DatabaseError::code)
            .map(std::borrow::Cow::into_owned),
        _ => None,
    };
    assert_eq!(code.as_deref(), Some("42501"), "unexpected error: {error}");

    probe.drop_role(&pool).await;
}

// ---------------------------------------------------------------------------
// Generation 3 (ADR 0008 D2).
// ---------------------------------------------------------------------------

/// Bind `connector` for admission out of `witness`'s head.
fn bind(witness: &WriterAuthorityWitness, connector: &str) -> Result<(), EvidenceAdmissionError> {
    let append_witness = witness
        .to_append_witness()
        .expect("the strict witness adapts to the append witness");
    ActiveStage4Package::bind_connector(
        witness.package().clone(),
        &ContractId::new(connector).unwrap(),
        witness.head_binding().clone(),
        &append_witness,
    )
    .map(|_| ())
}

/// The strict witness under the pins `installed` printed.
async fn witness(pool: &PgPool, installed: &InstalledAuthority) -> WriterAuthorityWitness {
    load_and_verify(pool, &installed.scope, &installed.config)
        .await
        .expect("the strict witness must accept the installed head under the printed pins")
}

/// The steps a run reported, with their outcomes.
fn steps(
    report: &ostk_fleet_recall::registry_activation::install::AuthorityInstallReportV1,
) -> Vec<(InstallStepV1, InstallStepOutcomeV1)> {
    report
        .steps
        .iter()
        .map(|step| (step.step, step.outcome))
        .collect()
}

#[tokio::test]
async fn live_install_generation_three_reaches_it_in_one_run_on_a_fresh_scope_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let installed = install_generation_three(&pool, "authority-generation-three").await;
    assert_eq!(
        steps(&installed.report),
        [
            InstallStepV1::ControlBootstrap,
            InstallStepV1::GenesisActivation,
            InstallStepV1::FirstSuccessor,
            InstallStepV1::GenerationTwo,
            InstallStepV1::GenerationThree,
        ]
        .map(|step| (step, InstallStepOutcomeV1::Inserted)),
        "a fresh physical scope runs every step up to generation 3"
    );
    assert_eq!(
        installed.report.package,
        KnownRegistryPackage::CollectedItemsGeneration3
    );
    assert_eq!(installed.report.generation, 3);

    let witness = witness(&pool, &installed).await;
    assert_eq!(
        witness.active_package().known(),
        KnownRegistryPackage::CollectedItemsGeneration3
    );
    assert_eq!(witness.activation_id(), installed.report.activation_id);
    assert!(witness.certifies_scope(&installed.scope));
    // Every collected-item channel is admissible, and every connector
    // generation 2 served still is.
    for connector in COLLECTED_ITEM_FAMILY
        .connectors()
        .into_iter()
        .chain([GIT_CONNECTOR.connector_schema, GITHUB_PUSH_CONNECTOR])
    {
        bind(&witness, connector).unwrap_or_else(|error| {
            panic!("the generation-3 head must bind {connector} for admission: {error}")
        });
    }
}

#[tokio::test]
async fn live_install_generation_three_moves_a_generation_two_head_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let installed = install_generation_two(&pool, "authority-two-to-three").await;

    // Generation 2 is not opted in: a collected item has no connector to
    // admit it under.
    let before = witness(&pool, &installed).await;
    for connector in COLLECTED_ITEM_FAMILY.connectors() {
        assert!(
            matches!(
                bind(&before, connector),
                Err(EvidenceAdmissionError::ConnectorNotInActivePackage)
            ),
            "a generation-2 head must not bind {connector}"
        );
    }

    let mut request = installed.request();
    request.target = InstallTargetV1::Generation3;
    let moved = install_writer_authority(&pool, &request, retry_policy())
        .await
        .expect("a generation-2 head must move to generation 3");
    assert_eq!(
        steps(&moved),
        [
            (
                InstallStepV1::ControlBootstrap,
                InstallStepOutcomeV1::AlreadyPresent
            ),
            (
                InstallStepV1::GenesisActivation,
                InstallStepOutcomeV1::AlreadyPresent
            ),
            (
                InstallStepV1::FirstSuccessor,
                InstallStepOutcomeV1::AlreadyPresent
            ),
            (
                InstallStepV1::GenerationTwo,
                InstallStepOutcomeV1::AlreadyPresent
            ),
            (
                InstallStepV1::GenerationThree,
                InstallStepOutcomeV1::Inserted
            ),
        ]
    );
    assert_eq!(
        moved.package,
        KnownRegistryPackage::CollectedItemsGeneration3
    );
    assert_eq!(moved.generation, 3);
    assert_eq!(
        moved.pins, installed.report.pins,
        "a writer keeps its pins across the move; only the head changes"
    );
    assert_ne!(moved.activation_id, installed.report.activation_id);

    let after = witness(&pool, &installed).await;
    assert_eq!(after.activation_id(), moved.activation_id);
    for connector in COLLECTED_ITEM_FAMILY
        .connectors()
        .into_iter()
        .chain([GIT_CONNECTOR.connector_schema])
    {
        bind(&after, connector).unwrap_or_else(|error| {
            panic!("the moved head must bind {connector} for admission: {error}")
        });
    }
}

#[tokio::test]
async fn live_install_generation_three_rerun_is_already_present_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let installed = install_generation_three(&pool, "authority-three-rerun").await;

    let again = install_writer_authority(&pool, &installed.request(), retry_policy())
        .await
        .expect("a re-run over a generation-3 scope must succeed");
    assert_eq!(
        steps(&again),
        steps(&installed.report)
            .into_iter()
            .map(|(step, _)| (step, InstallStepOutcomeV1::AlreadyPresent))
            .collect::<Vec<_>>(),
        "a re-run walks the same steps and writes nothing"
    );
    assert_eq!(again.pins, installed.report.pins);
    assert_eq!(again.activation_id, installed.report.activation_id);
    assert_eq!(again.generation, 3);
    assert_eq!(
        again.package,
        KnownRegistryPackage::CollectedItemsGeneration3
    );
}

#[tokio::test]
async fn live_install_generation_three_is_not_downgraded_by_the_default_target_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let installed = install_generation_three(&pool, "authority-no-downgrade").await;

    let mut request = installed.request();
    request.target = InstallTargetV1::default();
    let report = install_writer_authority(&pool, &request, retry_policy())
        .await
        .expect("the default target over a generation-3 head must succeed");
    assert!(
        report
            .steps
            .iter()
            .all(|step| step.outcome == InstallStepOutcomeV1::AlreadyPresent),
        "the default target must write nothing over a generation-3 head: {:?}",
        report.steps
    );
    assert!(
        report
            .steps
            .iter()
            .any(|step| step.step == InstallStepV1::GenerationTwo),
        "generation 2 is reported present, because the head is past it"
    );
    assert_eq!(
        report.package,
        KnownRegistryPackage::CollectedItemsGeneration3
    );
    assert_eq!(report.generation, 3);
    assert_eq!(report.activation_id, installed.report.activation_id);

    let witness = witness(&pool, &installed).await;
    assert_eq!(witness.activation_id(), installed.report.activation_id);
    bind(&witness, COLLECTED_ITEM_FAMILY.pull_connector)
        .expect("the head still admits collected items");
}
