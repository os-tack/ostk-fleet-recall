//! A disposable login that holds exactly the runtime role's evidence-plane
//! grants, so a connected test proves a writer path runs without the owner's
//! privileges.

use ostk_fleet_recall::store::cockroach::{CockroachStore, PoolConfig};
use sqlx::PgPool;
use url::Url;
use uuid::Uuid;

use super::fresh_scope;

/// The table privileges `deploy/cockroach/runtime-role-grants.sql` gives
/// `fleet_runtime` on the Stage-4 evidence plane (ADR 0002 D2). A probe role
/// receives these and nothing else: no privilege on any `memory_control_*` or
/// `memory_registry_*` base table. Keep this in step with that file.
pub const RUNTIME_EVIDENCE_GRANTS: [(&str, &str); 3] = [
    (
        "SELECT, INSERT",
        "public.memory_evidence_events, public.memory_evidence_quarantine, \
         public.memory_content_objects",
    ),
    (
        "SELECT, INSERT, UPDATE",
        "public.memory_evidence_shard_heads, public.memory_relation_projection_v1, \
         public.memory_relation_projection_watermarks_v1",
    ),
    ("SELECT", "public.memory_writer_authority_v1"),
];

/// A password login holding [`RUNTIME_EVIDENCE_GRANTS`], and a pool
/// authenticated as it. Call [`Self::drop_role`] at the end of the test: the
/// shared test database otherwise keeps the role and its grants.
pub struct RuntimeProbeRole {
    name: String,
    database: String,
    pub pool: PgPool,
}

impl RuntimeProbeRole {
    /// Create the role through `owner` and connect as it over the same TLS
    /// settings as `database_url`, without its client certificate.
    pub async fn create(owner: &PgPool, database_url: &str) -> Self {
        let name = format!("runtime_probe_{}", Uuid::now_v7().simple());
        let password = Uuid::now_v7().simple().to_string();
        let parsed = Url::parse(database_url).expect("the test database URL parses");
        let database = parsed.path().trim_start_matches('/').to_owned();
        let mut statements = vec![
            format!("CREATE ROLE {name} WITH LOGIN PASSWORD '{password}'"),
            format!("GRANT CONNECT ON DATABASE {database} TO {name}"),
            format!("GRANT USAGE ON SCHEMA public TO {name}"),
        ];
        statements.extend(
            RUNTIME_EVIDENCE_GRANTS
                .iter()
                .map(|(privileges, relations)| {
                    format!("GRANT {privileges} ON TABLE {relations} TO {name}")
                }),
        );
        for statement in statements {
            sqlx::query(&statement)
                .execute(owner)
                .await
                .unwrap_or_else(|error| panic!("{statement}: {error}"));
        }
        let pool = CockroachStore::connect(
            &probe_url(parsed, &name, &password),
            fresh_scope("runtime-probe"),
            PoolConfig {
                max_connections: 4,
                ..PoolConfig::default()
            },
        )
        .await
        .expect("the probe role must connect")
        .pool()
        .clone();
        Self {
            name,
            database,
            pool,
        }
    }

    /// The role name, for a test that changes its grants.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Close the pool, revoke every grant, and drop the role. `CockroachDB`
    /// refuses to drop a role that still holds a grant.
    pub async fn drop_role(self, owner: &PgPool) {
        self.pool.close().await;
        let name = &self.name;
        let mut statements = RUNTIME_EVIDENCE_GRANTS
            .iter()
            .map(|(_, relations)| format!("REVOKE ALL ON TABLE {relations} FROM {name}"))
            .collect::<Vec<_>>();
        statements.extend([
            format!("REVOKE ALL ON SCHEMA public FROM {name}"),
            format!("REVOKE ALL ON DATABASE {} FROM {name}", self.database),
            format!("DROP ROLE IF EXISTS {name}"),
        ]);
        for statement in statements {
            sqlx::query(&statement)
                .execute(owner)
                .await
                .unwrap_or_else(|error| panic!("{statement}: {error}"));
        }
    }
}

/// The owner URL rewritten to authenticate as the probe role by password:
/// the client certificate is dropped, TLS verification is kept.
fn probe_url(mut url: Url, role: &str, password: &str) -> String {
    let retained = url
        .query_pairs()
        .filter(|(name, _)| name == "sslmode" || name == "sslrootcert")
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    url.set_username(role).expect("probe username");
    url.set_password(Some(password)).expect("probe password");
    url.query_pairs_mut().clear();
    for (name, value) in retained {
        url.query_pairs_mut().append_pair(&name, &value);
    }
    url.into()
}
