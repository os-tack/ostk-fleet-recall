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
//! physical scope already installed for other namespaces is refused intact.

mod common;

use common::authority::{install_generation_two, retry_policy, semantic_scope};
use ostk_fleet_recall::FleetError;
use ostk_fleet_recall::evidence_ledger::ActiveStage4Package;
use ostk_fleet_recall::memory_contracts::common::{AuthenticatedProjectScopeV1, ContractId};
use ostk_fleet_recall::memory_contracts::generation2_registry::GIT_CONNECTOR;
use ostk_fleet_recall::registry_activation::install::{
    AuthorityInstallRequestV1, InstallStepOutcomeV1, install_writer_authority,
};
use ostk_fleet_recall::registry_witness::{KnownRegistryPackage, load_and_verify};

/// The one connector the frozen generation-1 package carries, which
/// generation 2 carries forward.
const GITHUB_PUSH_CONNECTOR: &str = "connector.github.push";

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
