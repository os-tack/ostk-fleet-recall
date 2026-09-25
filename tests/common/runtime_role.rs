//! A disposable login that holds exactly the runtime role's evidence-plane
//! grants, and optionally its claim-plane grants, so a connected test proves a
//! writer path runs without the owner's privileges; or exactly the publication
//! reader's grants, so it proves a public read runs with nothing more. The
//! grants are held directly by the login, or, as the deployment holds them, by
//! a group role the login is only a member of.

use ostk_fleet_recall::store::cockroach::{CockroachStore, PUBLICATION_READ_TABLES, PoolConfig};
use sqlx::PgPool;
use url::Url;
use uuid::Uuid;

use super::fresh_scope;

/// The table privileges `deploy/cockroach/runtime-role-grants.sql` gives
/// `fleet_runtime` on the Stage-4 evidence plane (ADR 0002 D2). A probe role
/// receives these and nothing else: no privilege on any `memory_control_*` or
/// `memory_registry_*` base table. UPDATE on `memory_content_objects` exists
/// only because `CockroachDB` requires it for the `SELECT ... FOR UPDATE` a
/// deduplicating governed-content append takes. Keep this in step with that
/// file.
pub const RUNTIME_EVIDENCE_GRANTS: [(&str, &str); 3] = [
    (
        "SELECT, INSERT",
        "public.memory_evidence_events, public.memory_evidence_quarantine",
    ),
    (
        "SELECT, INSERT, UPDATE",
        "public.memory_evidence_shard_heads, public.memory_relation_projection_v1, \
         public.memory_relation_projection_watermarks_v1, public.memory_content_objects",
    ),
    ("SELECT", "public.memory_writer_authority_v1"),
];

/// The table privileges `deploy/cockroach/runtime-role-grants.sql` gives
/// `fleet_runtime` on the legacy corpus and claim tables, which `record` and
/// the claim projection of `assert` write. The migration-29 lifecycle log and
/// the Stage-5/6 planes are left out: no claim write needs them. Keep this in
/// step with that file.
pub const RUNTIME_CLAIM_GRANTS: [(&str, &str); 4] = [
    (
        "SELECT",
        "public._sqlx_migrations, public.memory_corpus_models, public.memory_chunks, \
         public.memory_chunk_history, public.memory_claims, public.memory_claim_embeddings, \
         public.memory_claim_support, public.memory_conflict_members, public.memory_conflicts, \
         public.memory_claim_links, public.memory_mutation_receipts",
    ),
    (
        "INSERT",
        "public.memory_corpus_models, public.memory_chunks, public.memory_claims, \
         public.memory_claim_embeddings, public.memory_claim_support, \
         public.memory_claim_events, public.memory_conflict_members, public.memory_conflicts, \
         public.memory_mutation_receipts, public.memory_events",
    ),
    (
        "UPDATE",
        "public.memory_chunks, public.memory_claims, public.memory_conflicts, \
         public.memory_mutation_receipts",
    ),
    ("DELETE", "public.memory_chunk_history"),
];

/// The Stage-5/6 block of `deploy/cockroach/runtime-role-grants.sql`: the
/// body, coverage, recall, transcript, CI, normative, discrepancy, worker
/// status, and spec-conformance tables (migrations 19-24, 26, 27, 30, 31),
/// plus the UPDATE on `memory_content_objects` that `CockroachDB` requires for
/// the dedup path's `SELECT ... FOR UPDATE`. Keep this in step with that file.
pub const STAGE5_RUNTIME_GRANTS: [(&str, &str); 4] = [
    (
        "SELECT, INSERT",
        "public.memory_body_objects_v1, public.memory_chunk_occurrences_v1, \
         public.memory_chunk_occurrence_spans_v1, public.memory_parse_run_manifests_v1, \
         public.memory_source_commit_membership_v1, public.memory_coverage_receipts_v1, \
         public.memory_ci_measured_windows_v1, public.memory_normative_log_v1, \
         public.memory_discrepancy_log_v1, public.memory_normative_statements_v1, \
         public.memory_spec_checks_v1",
    ),
    (
        "SELECT, INSERT, UPDATE",
        "public.memory_generation_pointers_v1, public.memory_body_projection_watermarks_v1, \
         public.memory_body_visibility_v1, public.memory_coverage_cursors_v1, \
         public.memory_body_lexical_projection_v1, public.memory_body_dense_projection_v1, \
         public.memory_recall_projection_cursors_v1, public.memory_transcript_outbox_v1, \
         public.memory_transcript_cursors_v1, public.memory_normative_heads_v1, \
         public.memory_normative_projections_v1, public.memory_discrepancy_heads_v1, \
         public.memory_discrepancy_projections_v1, public.memory_worker_sources_v1",
    ),
    ("SELECT", "public.memory_discrepancy_relations_v1"),
    ("UPDATE", "public.memory_content_objects"),
];

/// The collected-item tables of the same block (migration 33, ADR 0008): the
/// item history, links, and dead letters are append-only; the outbox, heads,
/// collector status, cursors, and containers take `SELECT ... FOR UPDATE` and
/// compare-and-set upserts. The collect step also reads the schema version,
/// through the `SELECT` on `_sqlx_migrations` the policy's claim block gives.
/// Keep this in step with that file.
pub const COLLECTOR_RUNTIME_GRANTS: [(&str, &str); 3] = [
    ("SELECT", "public._sqlx_migrations"),
    (
        "SELECT, INSERT",
        "public.memory_collected_items_v1, public.memory_collected_item_links_v1, \
         public.memory_collector_dead_letters_v1",
    ),
    (
        "SELECT, INSERT, UPDATE",
        "public.memory_collector_outbox_v1, public.memory_collected_item_heads_v1, \
         public.memory_collector_sources_v1, public.memory_collector_cursors_v1, \
         public.memory_collector_containers_v1",
    ),
];

/// The sequences the same policy lets `fleet_runtime` draw claim, support,
/// and conflict IDs from.
pub const RUNTIME_SEQUENCES: &str = "public.memory_claim_id_seq, \
     public.memory_claim_support_id_seq, public.memory_conflict_id_seq";

/// A password login holding [`RUNTIME_EVIDENCE_GRANTS`] (and, for a claim
/// writer, [`RUNTIME_CLAIM_GRANTS`] and [`RUNTIME_SEQUENCES`]), and a pool
/// authenticated as it. Call [`Self::drop_role`] at the end of the test: the
/// shared test database otherwise keeps the role and its grants.
pub struct RuntimeProbeRole {
    name: String,
    /// The `NOLOGIN` role holding the grants when the login holds none
    /// itself, only its membership in this role.
    group: Option<String>,
    database: String,
    grants: Vec<(&'static str, String)>,
    sequences: bool,
    pub pool: PgPool,
}

impl RuntimeProbeRole {
    /// Create the role through `owner` and connect as it over the same TLS
    /// settings as `database_url`, without its client certificate.
    pub async fn create(owner: &PgPool, database_url: &str) -> Self {
        Self::create_with(
            owner,
            database_url,
            owned(&RUNTIME_EVIDENCE_GRANTS),
            false,
            false,
        )
        .await
    }

    /// A login holding only `SELECT` on the publication reader's exact
    /// tables (`deploy/cockroach/publication-reader-role-grants.sql`), as the
    /// public `demo` process reads with.
    pub async fn create_publication_reader(owner: &PgPool, database_url: &str) -> Self {
        let tables = PUBLICATION_READ_TABLES
            .iter()
            .map(|table| format!("public.{table}"))
            .collect::<Vec<_>>()
            .join(", ");
        Self::create_with(owner, database_url, vec![("SELECT", tables)], false, false).await
    }

    /// [`Self::create`], plus the runtime role's claim-plane table and
    /// sequence grants: what `remember` needs to write a claim and its
    /// accepted event.
    pub async fn create_claim_writer(owner: &PgPool, database_url: &str) -> Self {
        let mut grants = owned(&RUNTIME_EVIDENCE_GRANTS);
        grants.extend(owned(&RUNTIME_CLAIM_GRANTS));
        Self::create_with(owner, database_url, grants, true, false).await
    }

    /// [`Self::create`], plus [`STAGE5_RUNTIME_GRANTS`] and
    /// [`COLLECTOR_RUNTIME_GRANTS`] when `stage5` is set: what the memory
    /// worker runs with, or, without the Stage-5 block, a login that holds only
    /// the Stage-4 evidence grants.
    pub async fn create_worker(owner: &PgPool, database_url: &str, stage5: bool) -> Self {
        Self::create_worker_with(owner, database_url, stage5, stage5).await
    }

    /// [`Self::create`], plus [`STAGE5_RUNTIME_GRANTS`] when `stage5` is set and
    /// [`COLLECTOR_RUNTIME_GRANTS`] when `collectors` is set: a worker login
    /// that predates the collector grants, or one that holds only them.
    pub async fn create_worker_with(
        owner: &PgPool,
        database_url: &str,
        stage5: bool,
        collectors: bool,
    ) -> Self {
        let mut grants = owned(&RUNTIME_EVIDENCE_GRANTS);
        if stage5 {
            grants.extend(owned(&STAGE5_RUNTIME_GRANTS));
        }
        if collectors {
            grants.extend(owned(&COLLECTOR_RUNTIME_GRANTS));
        }
        Self::create_with(owner, database_url, grants, false, false).await
    }

    /// [`Self::create_worker`] with the Stage-5 and collector blocks, shaped as
    /// `deploy/cockroach/runtime-role-grants.sql` shapes the deployment: every
    /// grant goes to a `NOLOGIN` group role, as the policy gives them to
    /// `fleet_runtime`, and the login holds nothing but its membership in that
    /// group, as `fleet_writer` does.
    pub async fn create_worker_member(owner: &PgPool, database_url: &str) -> Self {
        let mut grants = owned(&RUNTIME_EVIDENCE_GRANTS);
        grants.extend(owned(&STAGE5_RUNTIME_GRANTS));
        grants.extend(owned(&COLLECTOR_RUNTIME_GRANTS));
        Self::create_with(owner, database_url, grants, false, true).await
    }

    async fn create_with(
        owner: &PgPool,
        database_url: &str,
        grants: Vec<(&'static str, String)>,
        sequences: bool,
        member: bool,
    ) -> Self {
        let name = format!("runtime_probe_{}", Uuid::now_v7().simple());
        let group = member.then(|| format!("runtime_group_{}", Uuid::now_v7().simple()));
        let grantee = group.as_deref().unwrap_or(&name);
        let password = Uuid::now_v7().simple().to_string();
        let parsed = Url::parse(database_url).expect("the test database URL parses");
        let database = parsed.path().trim_start_matches('/').to_owned();
        let mut statements = vec![format!(
            "CREATE ROLE {name} WITH LOGIN PASSWORD '{password}'"
        )];
        if let Some(group) = &group {
            statements.push(format!("CREATE ROLE {group} WITH NOLOGIN"));
        }
        statements.extend([
            format!("GRANT CONNECT ON DATABASE {database} TO {grantee}"),
            format!("GRANT USAGE ON SCHEMA public TO {grantee}"),
        ]);
        statements.extend(grants.iter().map(|(privileges, relations)| {
            format!("GRANT {privileges} ON TABLE {relations} TO {grantee}")
        }));
        if sequences {
            statements.push(format!(
                "GRANT USAGE ON SEQUENCE {RUNTIME_SEQUENCES} TO {grantee}"
            ));
        }
        if let Some(group) = &group {
            statements.push(format!("GRANT {group} TO {name}"));
        }
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
            group,
            database,
            grants,
            sequences,
            pool,
        }
    }

    /// The role name, for a test that changes its grants.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Close the pool, revoke every grant, and drop the role (and its group).
    /// `CockroachDB` refuses to drop a role that still holds a grant.
    pub async fn drop_role(self, owner: &PgPool) {
        self.pool.close().await;
        let name = &self.name;
        let grantee = self.group.as_deref().unwrap_or(name);
        let mut statements = self
            .grants
            .iter()
            .map(|(_, relations)| format!("REVOKE ALL ON TABLE {relations} FROM {grantee}"))
            .collect::<Vec<_>>();
        if self.sequences {
            statements.push(format!(
                "REVOKE ALL ON SEQUENCE {RUNTIME_SEQUENCES} FROM {grantee}"
            ));
        }
        statements.extend([
            format!("REVOKE ALL ON SCHEMA public FROM {grantee}"),
            format!("REVOKE ALL ON DATABASE {} FROM {grantee}", self.database),
        ]);
        if let Some(group) = &self.group {
            statements.push(format!("REVOKE {group} FROM {name}"));
        }
        statements.push(format!("DROP ROLE IF EXISTS {name}"));
        if let Some(group) = &self.group {
            statements.push(format!("DROP ROLE IF EXISTS {group}"));
        }
        for statement in statements {
            sqlx::query(&statement)
                .execute(owner)
                .await
                .unwrap_or_else(|error| panic!("{statement}: {error}"));
        }
    }
}

fn owned(grants: &[(&'static str, &'static str)]) -> Vec<(&'static str, String)> {
    grants
        .iter()
        .map(|(privileges, relations)| (*privileges, (*relations).to_owned()))
        .collect()
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
