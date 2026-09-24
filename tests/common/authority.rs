//! A real generation-2 writer authority for a connected test, installed by the
//! production installer (`registry_activation::install`) rather than by a
//! ceremony copied into the test.

use std::time::Duration;

use ostk_fleet_recall::FleetScope;
use ostk_fleet_recall::config::WriterAuthorityConfig;
use ostk_fleet_recall::evidence_ledger::ContentKeyEncryptionKey;
use ostk_fleet_recall::memory_contracts::common::{AuthenticatedProjectScopeV1, ContractId};
use ostk_fleet_recall::registry_activation::install::{
    AuthorityInstallReportV1, AuthorityInstallRequestV1, install_writer_authority,
};
use ostk_fleet_recall::store::cockroach::RetryPolicy;
use ring::rand::{SecureRandom as _, SystemRandom};
use sqlx::PgPool;

use super::fresh_scope;

/// Contract namespaces every fixture install binds. Deliberately not the
/// frozen receipt's `tenant.fixture`/`project.fixture`, so every install
/// exercises the re-scoped receipt and the rebuilt genesis key bridge.
pub const SEMANTIC_TENANT_NAMESPACE: &str = "tenant.acme";
pub const SEMANTIC_PROJECT_NAMESPACE: &str = "project.recall";

/// One physical scope with an active generation-2 head.
pub struct InstalledAuthority {
    /// The physical scope: a fresh tenant, `project` = the caller's label.
    pub scope: FleetScope,
    pub semantic_scope: AuthenticatedProjectScopeV1,
    /// The writer-authority pin group the installer printed.
    pub config: WriterAuthorityConfig,
    /// What the install reported, pins and activation included.
    pub report: AuthorityInstallReportV1,
    /// A fresh content key for this install, as `FLEET_RECALL_CONTENT_KEK_HEX`
    /// would carry it.
    pub kek_hex: String,
}

impl InstalledAuthority {
    /// The content key. `ContentKeyEncryptionKey` is not `Clone`, so each call
    /// parses a fresh one.
    pub fn kek(&self) -> ContentKeyEncryptionKey {
        ContentKeyEncryptionKey::from_hex(&self.kek_hex).expect("the fixture key is valid hex")
    }

    /// The request that installed this authority, for a re-run.
    pub fn request(&self) -> AuthorityInstallRequestV1 {
        AuthorityInstallRequestV1 {
            physical_scope: self.scope.clone(),
            semantic_scope: self.semantic_scope.clone(),
        }
    }
}

/// Retry policy for connected tests, which contend on one shared cluster.
pub const fn retry_policy() -> RetryPolicy {
    RetryPolicy {
        max_attempts: 20,
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(50),
    }
}

/// The fixture semantic scope.
pub fn semantic_scope() -> AuthenticatedProjectScopeV1 {
    AuthenticatedProjectScopeV1::from_trusted_context(
        ContractId::new(SEMANTIC_TENANT_NAMESPACE).expect("fixture tenant namespace"),
        ContractId::new(SEMANTIC_PROJECT_NAMESPACE).expect("fixture project namespace"),
    )
}

/// Install a generation-2 writer authority into a fresh physical scope whose
/// project is `label`. `pool` must already be migrated.
pub async fn install_generation_two(pool: &PgPool, label: &str) -> InstalledAuthority {
    let scope = fresh_scope(label);
    let semantic_scope = semantic_scope();
    let report = install_writer_authority(
        pool,
        &AuthorityInstallRequestV1 {
            physical_scope: scope.clone(),
            semantic_scope: semantic_scope.clone(),
        },
        retry_policy(),
    )
    .await
    .expect("the installer must reach generation 2 on a fresh physical scope");
    InstalledAuthority {
        scope,
        semantic_scope,
        config: report.pins.writer_authority_config(),
        report,
        kek_hex: fresh_kek_hex(),
    }
}

fn fresh_kek_hex() -> String {
    let mut key = [0_u8; 32];
    SystemRandom::new()
        .fill(&mut key)
        .expect("the system random source must be available");
    hex::encode(key)
}
