//! Fixtures shared by the connected test binaries.
//!
//! Each `tests/*.rs` binary that declares `mod common;` compiles its own copy
//! of this module and uses only part of it, so unused items are expected.
#![allow(dead_code)]

pub mod authority;
pub mod runtime_role;

use ostk_fleet_recall::FleetScope;
use ostk_fleet_recall::store::cockroach::{CockroachStore, PoolConfig};
use ostk_recall_core::PrivacyTier;
use sqlx::PgPool;
use tokio::sync::Mutex;
use uuid::Uuid;

/// The one variable that makes a connected test run; without it every live
/// test returns immediately.
pub const TEST_DATABASE_URL_ENV: &str = "FLEET_RECALL_TEST_DATABASE_URL";

/// Agent recorded on every scope a connected test builds.
pub const LIVE_TEST_AGENT: &str = "fleet-recall-live-test";

/// A pool is bound to the Tokio runtime that created it, so each test builds
/// its own; the schema is shared, so migration runs once per test binary.
static MIGRATED: Mutex<bool> = Mutex::const_new(false);

/// The disposable database URL, or `None` to leave the test inert.
pub fn test_database_url() -> Option<String> {
    std::env::var(TEST_DATABASE_URL_ENV).ok()
}

/// A fresh physical scope: a new tenant, so nothing a test writes is visible
/// to another test or another run.
pub fn fresh_scope(project: &str) -> FleetScope {
    FleetScope::new(
        Uuid::now_v7(),
        project,
        LIVE_TEST_AGENT,
        None,
        PrivacyTier::T1Project,
    )
    .expect("a live-test scope must be valid")
}

/// Connect to the disposable database with the embedded migrations applied.
pub async fn migrated_pool(database_url: &str) -> PgPool {
    let store = CockroachStore::connect(
        database_url,
        fresh_scope("pool"),
        PoolConfig {
            max_connections: 10,
            ..PoolConfig::default()
        },
    )
    .await
    .expect("a connected test must reach the disposable database");
    {
        let mut migrated = MIGRATED.lock().await;
        if !*migrated {
            store
                .migrate()
                .await
                .expect("the migration prefix must apply");
            *migrated = true;
        }
    }
    store.pool().clone()
}
