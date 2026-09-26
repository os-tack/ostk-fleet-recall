//! The worker's privilege preflight.
//!
//! A worker that starts under a login missing one Stage-5 grant would run
//! every step up to the first statement that needs it and fail there, often
//! after appending evidence, so the tick would report a failure half-way
//! through a source. [`probe_worker_privileges`] instead checks, before the
//! first tick, every privilege the selected steps use, and names the first
//! missing one.
//!
//! Privileges are checked when a statement is planned, so each probe reads and
//! writes nothing: an `INSERT ... SELECT ... WHERE false` needs SELECT and
//! INSERT, and a `SELECT ... WHERE false FOR UPDATE` needs SELECT and UPDATE
//! (`CockroachDB` requires UPDATE for a locking read, and an upsert's
//! `DO UPDATE` or a compare-and-set advance needs it anyway). Every probe runs
//! in one transaction that is rolled back whatever happens, the same shape as
//! the conflict-lifecycle startup probe.

use std::collections::BTreeSet;

use sqlx::PgPool;

use crate::config::CollectedCaptureModeV1;
use crate::error::{FleetError, Result};
use crate::store::cockroach::{
    COLLECTED_ITEMS_SCHEMA_VERSION, COLLECTOR_INGRESS_SCHEMA_VERSION, DatabaseCapabilities,
    MEMORY_WORKER_SCHEMA_VERSION,
};

use super::WorkerStepV1;

const INSUFFICIENT_PRIVILEGE_SQLSTATE: &str = "42501";

/// The policy file that grants the runtime login what the worker needs.
pub const RUNTIME_GRANTS_POLICY: &str = "deploy/cockroach/runtime-role-grants.sql";

/// What one probe statement proves the login may do to one table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ProbeKind {
    /// SELECT.
    Read,
    /// SELECT and INSERT.
    Insert,
    /// SELECT and UPDATE, through a locking read.
    Lock,
}

impl ProbeKind {
    const fn privileges(self) -> &'static str {
        match self {
            Self::Read => "SELECT",
            Self::Insert => "SELECT and INSERT",
            Self::Lock => "SELECT and UPDATE (a locking read or an upsert)",
        }
    }
}

/// One probe: a table, what is needed on it, and, for a table with a computed
/// column, the columns an insert names (its primary key).
type Probe = (&'static str, ProbeKind, Option<&'static str>);

/// The evidence ledger, the governed content store, coverage, and worker
/// status: what every ingest step writes.
const INGEST_PROBES: &[Probe] = &[
    ("memory_writer_authority_v1", ProbeKind::Read, None),
    ("memory_evidence_events", ProbeKind::Insert, None),
    ("memory_evidence_quarantine", ProbeKind::Insert, None),
    ("memory_evidence_shard_heads", ProbeKind::Insert, None),
    ("memory_evidence_shard_heads", ProbeKind::Lock, None),
    ("memory_content_objects", ProbeKind::Insert, None),
    ("memory_content_objects", ProbeKind::Lock, None),
    ("memory_coverage_receipts_v1", ProbeKind::Insert, None),
    ("memory_coverage_cursors_v1", ProbeKind::Insert, None),
    ("memory_coverage_cursors_v1", ProbeKind::Lock, None),
    ("memory_worker_sources_v1", ProbeKind::Insert, None),
    ("memory_worker_sources_v1", ProbeKind::Lock, None),
];

const TRANSCRIPT_PROBES: &[Probe] = &[
    ("memory_transcript_outbox_v1", ProbeKind::Insert, None),
    ("memory_transcript_outbox_v1", ProbeKind::Lock, None),
    ("memory_transcript_cursors_v1", ProbeKind::Insert, None),
    ("memory_transcript_cursors_v1", ProbeKind::Lock, None),
];

const CI_PROBES: &[Probe] = &[("memory_ci_measured_windows_v1", ProbeKind::Insert, None)];

/// The collected-item sink (migrations 0033 and 0034): the schema version the
/// step reads at tick time, the outbox the drain settles, the item history,
/// heads, and links its projection writes, and the containers, item
/// withdrawals, status, cursors, and dead letters staging writes. Probed only
/// on a schema that has the tables.
const COLLECT_PROBES: &[Probe] = &[
    ("memory_collector_outbox_v1", ProbeKind::Insert, None),
    ("memory_collector_outbox_v1", ProbeKind::Lock, None),
    ("memory_collected_items_v1", ProbeKind::Insert, None),
    ("memory_collected_item_heads_v1", ProbeKind::Insert, None),
    ("memory_collected_item_heads_v1", ProbeKind::Lock, None),
    ("memory_collected_item_links_v1", ProbeKind::Insert, None),
    ("memory_collector_containers_v1", ProbeKind::Insert, None),
    ("memory_collector_containers_v1", ProbeKind::Lock, None),
    (
        "memory_collected_item_withdrawals_v1",
        ProbeKind::Insert,
        None,
    ),
    (
        "memory_collected_item_withdrawals_v1",
        ProbeKind::Lock,
        None,
    ),
    ("memory_collector_sources_v1", ProbeKind::Insert, None),
    ("memory_collector_sources_v1", ProbeKind::Lock, None),
    ("memory_collector_cursors_v1", ProbeKind::Insert, None),
    ("memory_collector_cursors_v1", ProbeKind::Lock, None),
    ("memory_collector_dead_letters_v1", ProbeKind::Insert, None),
    ("_sqlx_migrations", ProbeKind::Read, None),
];

/// The ingress's hint queue (migration 0036): the collect step reads each
/// instance's due hints and settles, backs off, or kills them with a locking
/// update. Probed only on a schema that has the queue.
const HINT_PROBES: &[Probe] = &[("memory_ingress_deliveries_v1", ProbeKind::Lock, None)];

const BODY_PROBES: &[Probe] = &[
    ("memory_evidence_events", ProbeKind::Read, None),
    ("memory_content_objects", ProbeKind::Read, None),
    ("memory_body_objects_v1", ProbeKind::Insert, None),
    ("memory_chunk_occurrences_v1", ProbeKind::Insert, None),
    ("memory_chunk_occurrence_spans_v1", ProbeKind::Insert, None),
    ("memory_parse_run_manifests_v1", ProbeKind::Insert, None),
    (
        "memory_source_commit_membership_v1",
        ProbeKind::Insert,
        None,
    ),
    ("memory_generation_pointers_v1", ProbeKind::Insert, None),
    ("memory_generation_pointers_v1", ProbeKind::Lock, None),
    (
        "memory_body_projection_watermarks_v1",
        ProbeKind::Insert,
        None,
    ),
    (
        "memory_body_projection_watermarks_v1",
        ProbeKind::Lock,
        None,
    ),
    ("memory_body_visibility_v1", ProbeKind::Insert, None),
    ("memory_body_visibility_v1", ProbeKind::Lock, None),
];

/// `search_document` is a computed column, so an insert names the key.
const LEXICAL_KEY: Option<&str> = Some("tenant_id, project, body_content_id");

const LEXICAL_PROBES: &[Probe] = &[
    ("memory_body_objects_v1", ProbeKind::Read, None),
    ("memory_body_visibility_v1", ProbeKind::Read, None),
    (
        "memory_body_lexical_projection_v1",
        ProbeKind::Insert,
        LEXICAL_KEY,
    ),
    ("memory_body_lexical_projection_v1", ProbeKind::Lock, None),
    (
        "memory_recall_projection_cursors_v1",
        ProbeKind::Insert,
        None,
    ),
    ("memory_recall_projection_cursors_v1", ProbeKind::Lock, None),
];

const DENSE_PROBES: &[Probe] = &[
    ("memory_body_lexical_projection_v1", ProbeKind::Read, None),
    ("memory_body_visibility_v1", ProbeKind::Read, None),
    ("memory_body_dense_projection_v1", ProbeKind::Insert, None),
    ("memory_body_dense_projection_v1", ProbeKind::Lock, None),
    (
        "memory_recall_projection_cursors_v1",
        ProbeKind::Insert,
        None,
    ),
    ("memory_recall_projection_cursors_v1", ProbeKind::Lock, None),
];

/// The idempotency receipts `remember(action="capture")` reserves, and
/// finalizes, its key in (ADR 0008 D10).
const RECEIPT_PROBES: &[Probe] = &[
    ("memory_mutation_receipts", ProbeKind::Insert, None),
    ("memory_mutation_receipts", ProbeKind::Lock, None),
];

/// Every probe of `groups`, each `(table, privilege)` once, in order.
fn unique_probes(groups: &[&[Probe]]) -> Vec<Probe> {
    let mut seen = BTreeSet::new();
    groups
        .iter()
        .copied()
        .flatten()
        .filter(|(table, kind, _)| seen.insert((*table, *kind)))
        .copied()
        .collect()
}

/// The probes `steps` need, each once, in step order.
fn probes_for(steps: &BTreeSet<WorkerStepV1>) -> Vec<Probe> {
    let mut groups: Vec<&[Probe]> = Vec::new();
    if steps.iter().any(|step| step.is_ingest()) {
        groups.push(INGEST_PROBES);
    }
    if steps.contains(&WorkerStepV1::Transcript) {
        groups.push(TRANSCRIPT_PROBES);
    }
    if steps.contains(&WorkerStepV1::Ci) {
        groups.push(CI_PROBES);
    }
    if steps.contains(&WorkerStepV1::Collect) {
        groups.push(COLLECT_PROBES);
    }
    if steps.contains(&WorkerStepV1::Bodies) {
        groups.push(BODY_PROBES);
    }
    if steps.contains(&WorkerStepV1::Lexical) {
        groups.push(LEXICAL_PROBES);
    }
    if steps.contains(&WorkerStepV1::Dense) {
        groups.push(DENSE_PROBES);
    }
    unique_probes(&groups)
}

/// What `remember(action="capture")` writes: the collect step's tables (it
/// stages through the same sink and, when enabled, drains through the same
/// append), the mutation receipts, and, when `enabled`, the three projection
/// tiers it runs over what it admitted (the bodies, lexical, and dense
/// steps' tables).
fn capture_probes(mode: CollectedCaptureModeV1) -> Vec<Probe> {
    match mode {
        CollectedCaptureModeV1::Enabled => unique_probes(&[
            INGEST_PROBES,
            COLLECT_PROBES,
            RECEIPT_PROBES,
            BODY_PROBES,
            LEXICAL_PROBES,
            DENSE_PROBES,
        ]),
        CollectedCaptureModeV1::Disabled | CollectedCaptureModeV1::StageOnly => {
            unique_probes(&[INGEST_PROBES, COLLECT_PROBES, RECEIPT_PROBES])
        }
    }
}

fn probe_statement((table, kind, columns): Probe) -> String {
    match (kind, columns) {
        (ProbeKind::Read, _) => format!("SELECT 1 FROM public.{table} WHERE false"),
        (ProbeKind::Insert, None) => {
            format!("INSERT INTO public.{table} SELECT * FROM public.{table} WHERE false")
        }
        (ProbeKind::Insert, Some(columns)) => format!(
            "INSERT INTO public.{table} ({columns}) SELECT {columns} FROM public.{table} WHERE false"
        ),
        (ProbeKind::Lock, _) => format!("SELECT 1 FROM public.{table} WHERE false FOR UPDATE"),
    }
}

/// Check, before the first tick, that the connected login holds every
/// privilege the selected steps use.
///
/// Requires the schema to have reached migration 30
/// ([`MEMORY_WORKER_SCHEMA_VERSION`]), which creates the worker status table.
/// The collect step's privileges are probed only from migration 34
/// ([`COLLECTED_ITEMS_SCHEMA_VERSION`]) on: before it the step has nothing to
/// drain and is skipped, so neither its probes nor the ingest probes it alone
/// would add are run. From migration 36
/// ([`COLLECTOR_INGRESS_SCHEMA_VERSION`]) on, the step also reads and settles
/// the ingress's hints.
///
/// # Errors
///
/// [`FleetError::Configuration`] for an older schema, or naming the first
/// table the login lacks a privilege on and the policy file that grants it;
/// any other database failure as itself.
pub async fn probe_worker_privileges(
    pool: &PgPool,
    capabilities: &DatabaseCapabilities,
    steps: &BTreeSet<WorkerStepV1>,
) -> Result<()> {
    if !capabilities.supports_schema_version(MEMORY_WORKER_SCHEMA_VERSION) {
        return Err(FleetError::Configuration(format!(
            "the memory worker needs the schema through migration {MEMORY_WORKER_SCHEMA_VERSION}, \
             but this database has reached {}; run `ostk-fleet-recall migrate`",
            capabilities.schema_version
        )));
    }
    let mut probes = if capabilities.supports_schema_version(COLLECTED_ITEMS_SCHEMA_VERSION) {
        probes_for(steps)
    } else {
        let mut older = steps.clone();
        older.remove(&WorkerStepV1::Collect);
        probes_for(&older)
    };
    if steps.contains(&WorkerStepV1::Collect)
        && capabilities.supports_schema_version(COLLECTOR_INGRESS_SCHEMA_VERSION)
    {
        probes.extend_from_slice(HINT_PROBES);
    }
    run_probes(pool, &probes, "the worker's database login", "the worker").await
}

/// Check that `serve`'s login holds every privilege agent capture uses in
/// `mode`.
///
/// That is the collect step's (capture stages through the same sink, and,
/// when enabled, drains through the same append) plus SELECT, INSERT, and
/// UPDATE on the mutation receipts; `enabled` adds the bodies, lexical, and
/// dense steps' tables, since it projects what it admits before answering.
/// `remember(action="capture")` is served only where this passes (ADR 0008
/// D10).
///
/// # Errors
///
/// [`FleetError::Configuration`] for a schema before migration 34
/// ([`COLLECTED_ITEMS_SCHEMA_VERSION`]), or naming the first table the login
/// lacks a privilege on and the policy file that grants it; any other
/// database failure as itself.
pub async fn probe_capture_privileges(
    pool: &PgPool,
    capabilities: &DatabaseCapabilities,
    mode: CollectedCaptureModeV1,
) -> Result<()> {
    if !capabilities.supports_schema_version(COLLECTED_ITEMS_SCHEMA_VERSION) {
        return Err(FleetError::Configuration(format!(
            "agent capture needs the schema through migration \
             {COLLECTED_ITEMS_SCHEMA_VERSION}, but this database has reached {}; run \
             `ostk-fleet-recall migrate`",
            capabilities.schema_version
        )));
    }
    run_probes(
        pool,
        &capture_probes(mode),
        "serve's database login",
        "serve",
    )
    .await
}

/// Run `probes` in one transaction that is rolled back whatever happens,
/// naming the first missing privilege of `login`, which `process` needs.
async fn run_probes(pool: &PgPool, probes: &[Probe], login: &str, process: &str) -> Result<()> {
    let mut transaction = pool.begin().await?;
    let mut outcome = Ok(());
    for probe in probes {
        match sqlx::query(&probe_statement(*probe))
            .execute(&mut *transaction)
            .await
        {
            Ok(_) => {}
            Err(sqlx::Error::Database(error))
                if error.code().as_deref() == Some(INSUFFICIENT_PRIVILEGE_SQLSTATE) =>
            {
                outcome = Err(FleetError::Configuration(format!(
                    "{login} lacks {} on public.{}; apply {RUNTIME_GRANTS_POLICY} after \
                     `migrate`, then restart {process}",
                    probe.1.privileges(),
                    probe.0
                )));
                break;
            }
            Err(error) => {
                outcome = Err(error.into());
                break;
            }
        }
    }
    // Every probe wrote nothing; roll back regardless of the outcome.
    transaction.rollback().await?;
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;

    fn steps(names: &[WorkerStepV1]) -> BTreeSet<WorkerStepV1> {
        names.iter().copied().collect()
    }

    #[test]
    fn a_projection_only_worker_probes_no_ingest_table() {
        let probes = probes_for(&steps(&[WorkerStepV1::Lexical, WorkerStepV1::Dense]));
        assert!(
            probes
                .iter()
                .all(|(table, _, _)| !table.starts_with("memory_evidence")
                    && !table.starts_with("memory_worker"))
        );
        assert!(
            probes
                .iter()
                .any(|(table, _, _)| *table == "memory_body_dense_projection_v1")
        );
    }

    #[test]
    fn every_ingest_step_probes_worker_status_and_the_content_lock() {
        for step in [
            WorkerStepV1::Transcript,
            WorkerStepV1::Git,
            WorkerStepV1::Ci,
        ] {
            let probes = probes_for(&steps(&[step]));
            assert!(probes.contains(&("memory_worker_sources_v1", ProbeKind::Lock, None)));
            assert!(probes.contains(&("memory_content_objects", ProbeKind::Lock, None)));
        }
    }

    #[test]
    fn the_collect_step_probes_the_ingest_tables_and_the_collector_tables() {
        let probes = probes_for(&steps(&[WorkerStepV1::Collect]));
        assert!(probes.contains(&("memory_content_objects", ProbeKind::Lock, None)));
        assert!(probes.contains(&("memory_collected_item_heads_v1", ProbeKind::Lock, None)));
        assert!(probes.contains(&("memory_collector_dead_letters_v1", ProbeKind::Insert, None)));
        // The ingest group alone never reaches a collector table.
        assert!(
            probes_for(&WorkerStepV1::INGEST.into_iter().collect())
                .iter()
                .all(|(table, _, _)| !table.starts_with("memory_collect"))
        );
    }

    #[test]
    fn capture_probes_the_collect_step_and_the_receipts() {
        let probes = capture_probes(CollectedCaptureModeV1::StageOnly);
        for step in probes_for(&steps(&[WorkerStepV1::Collect])) {
            assert!(probes.contains(&step), "{step:?}");
        }
        assert!(probes.contains(&("memory_mutation_receipts", ProbeKind::Insert, None)));
        assert!(probes.contains(&("memory_mutation_receipts", ProbeKind::Lock, None)));
        let unique: BTreeSet<_> = probes
            .iter()
            .map(|(table, kind, _)| (table, kind))
            .collect();
        assert_eq!(unique.len(), probes.len());
        // stage_only never touches a projection table: the worker projects.
        assert!(
            probes
                .iter()
                .all(|(table, _, _)| !table.starts_with("memory_body")
                    && !table.starts_with("memory_recall_projection"))
        );
    }

    #[test]
    fn an_enabled_capture_also_probes_every_projection_tier() {
        let probes = capture_probes(CollectedCaptureModeV1::Enabled);
        for step in probes_for(&steps(&[
            WorkerStepV1::Collect,
            WorkerStepV1::Bodies,
            WorkerStepV1::Lexical,
            WorkerStepV1::Dense,
        ])) {
            assert!(probes.contains(&step), "{step:?}");
        }
        assert!(probes.contains(&("memory_mutation_receipts", ProbeKind::Lock, None)));
        let unique: BTreeSet<_> = probes
            .iter()
            .map(|(table, kind, _)| (table, kind))
            .collect();
        assert_eq!(unique.len(), probes.len());
    }

    #[test]
    fn a_table_is_probed_once_per_privilege() {
        let probes = probes_for(&WorkerStepV1::ALL.into_iter().collect());
        let unique: BTreeSet<_> = probes
            .iter()
            .map(|(table, kind, _)| (table, kind))
            .collect();
        assert_eq!(unique.len(), probes.len());
    }
}
