//! Connected proof for the at-rest supersession pass
//! (`ostk_fleet_recall::evidence_supersession`, ADR 0006 D9 amendment).
//!
//! Set `FLEET_RECALL_TEST_DATABASE_URL` to a disposable `CockroachDB` 26.2
//! database; every test here is inert otherwise. Each test installs a real
//! generation-2 writer authority through the shared `tests/common` fixture
//! and admits one git fact RAW, by hand and without redaction, exactly as a
//! connector did before redaction profile 3.
//!
//! What it proves: the raw fact's body is plaintext at rest and its
//! re-presentation quarantines as a preimage disagreement; one pass appends
//! the redacted successor with a `supersedes` lineage naming the raw key,
//! removes the raw body plane and content object, and leaves the raw event
//! row byte-identical; the literal is then absent from every stored body and
//! lexical text; a second pass is idempotent; the next full walk replays the
//! fact instead of quarantining it; a full re-projection lets the erased raw
//! event pass; and `recall(status)` counts the disagreement as resolved. A
//! separate test proves a login without the policy's DELETEs fails closed at
//! its first erase and appends nothing (it needs a password login, so it is
//! environmental on an insecure-mode node).

mod common;

use std::sync::Arc;

use common::authority::retry_policy;
use common::runtime_role::RuntimeProbeRole;
use common::worker::{GIT_INSTANCE, INSTALLATION_ID, WorkerFixture as Fixture};
use ostk_fleet_recall::body_store::{
    BodyProjectionRepository as _, CockroachBodyProjectionRepository, GovernedContentResolver,
    reference_parser_key_v1,
};
use ostk_fleet_recall::connectors::git::{
    GitConnectorBindingV1, GitFactV1, GitIngressClocksV1, GitRepositoryReader, GitScanRequestV1,
    GitTreeScanModeV1,
};
use ostk_fleet_recall::evidence_ledger::{
    AcceptedEventRepository as _, AppendOutcome, EvidenceAdmissionRequestV1,
    GovernedContentProjection, admit_evidence, fetch_governed_content, quarantine_summary,
};
use ostk_fleet_recall::evidence_supersession::{
    SupersessionRequestV1, SupersessionStateV1, run_supersession,
};
use ostk_fleet_recall::memory_contracts::canonical::decode_strict;
use ostk_fleet_recall::memory_contracts::common::{CanonicalTimestamp, ContractId};
use ostk_fleet_recall::memory_contracts::digest::Sha256Digest;
use ostk_fleet_recall::memory_contracts::evidence::AcceptedEventId;
use ostk_fleet_recall::memory_contracts::evidence_v2::{
    EvidenceStatementV2, RepresentationLineageV2,
};
use ostk_fleet_recall::memory_contracts::generation2_registry::GIT_CONNECTOR;
use ostk_fleet_recall::registry_witness::WriterAuthorityRuntime;
use ostk_fleet_recall::worker::{WorkerStepStatusV1, WorkerStepV1, WorkerTickReportV1};
use sqlx::PgPool;

/// The literal provider token the raw commit quotes: a literal copy of the
/// Slack placeholder in `src/collectors/test_support.rs` (that module is
/// `cfg(test)` inside the crate), which proves it matches no push-protection
/// pattern.
const PLANTED_SLACK_TOKEN: &str = "xoxb-EXAMPLE-NOT-A-TOKEN";
/// Fixed instants after the fixture's second commit.
const THIRD_COMMIT_DATE: &str = "1755432000 +0000";
const FOURTH_COMMIT_DATE: &str = "1755518400 +0000";

fn counter(report: &WorkerTickReportV1, step: WorkerStepV1, key: &str) -> u64 {
    report.steps[&step].counters.get(key).copied().unwrap_or(0)
}

fn status(report: &WorkerTickReportV1, step: WorkerStepV1) -> WorkerStepStatusV1 {
    report.steps[&step].status
}

/// Every stored byte string of the scope's body and lexical planes.
async fn body_and_lexical_bytes(pool: &PgPool, fixture: &Fixture) -> Vec<Vec<u8>> {
    let mut stored = Vec::new();
    for sql in [
        "SELECT body_bytes FROM memory_body_objects_v1 WHERE tenant_id = $1 AND project = $2",
        "SELECT lexical_text::BYTES FROM memory_body_lexical_projection_v1 \
         WHERE tenant_id = $1 AND project = $2",
    ] {
        let rows: Vec<Vec<u8>> = sqlx::query_scalar(sql)
            .bind(fixture.installed.scope.tenant_id)
            .bind(&fixture.installed.scope.project)
            .fetch_all(pool)
            .await
            .unwrap_or_else(|error| panic!("{sql}: {error}"));
        stored.extend(rows);
    }
    stored
}

fn holds(stored: &[Vec<u8>], literal: &str) -> bool {
    [
        literal.as_bytes().to_vec(),
        hex::encode(literal).into_bytes(),
    ]
    .iter()
    .any(|needle| {
        stored
            .iter()
            .any(|bytes| bytes.windows(needle.len()).any(|window| window == needle))
    })
}

async fn scoped_count(pool: &PgPool, table: &str, fixture: &Fixture) -> i64 {
    sqlx::query_scalar(&format!(
        "SELECT count(*) FROM {table} WHERE tenant_id = $1 AND project = $2"
    ))
    .bind(fixture.installed.scope.tenant_id)
    .bind(&fixture.installed.scope.project)
    .fetch_one(pool)
    .await
    .unwrap()
}

/// Every column of one accepted event row, for the byte-identity check.
#[derive(Debug, PartialEq, Eq)]
struct EventRow {
    epoch_id: Vec<u8>,
    shard: i32,
    committed_offset: i64,
    event_schema_version: i32,
    event_kind: String,
    semantic_object_digest: Vec<u8>,
    consistency_family: String,
    consistency_key_digest: Vec<u8>,
    canonical_event: Vec<u8>,
    previous_chain_digest: Vec<u8>,
    chain_digest: Vec<u8>,
    accepted_at: chrono::DateTime<chrono::Utc>,
    predecessor_representation_key_digest: Option<Vec<u8>>,
}

async fn event_row(pool: &PgPool, fixture: &Fixture, event_id: AcceptedEventId) -> EventRow {
    use sqlx::Row as _;
    let row = sqlx::query(
        "SELECT epoch_id, shard, committed_offset, event_schema_version, event_kind, \
                semantic_object_digest, consistency_family, consistency_key_digest, \
                canonical_event, previous_chain_digest, chain_digest, accepted_at, \
                predecessor_representation_key_digest \
         FROM memory_evidence_events WHERE tenant_id = $1 AND project = $2 AND event_id = $3",
    )
    .bind(fixture.installed.scope.tenant_id)
    .bind(&fixture.installed.scope.project)
    .bind(event_id.digest().as_bytes().to_vec())
    .fetch_one(pool)
    .await
    .unwrap();
    EventRow {
        epoch_id: row.get("epoch_id"),
        shard: row.get("shard"),
        committed_offset: row.get("committed_offset"),
        event_schema_version: row.get("event_schema_version"),
        event_kind: row.get("event_kind"),
        semantic_object_digest: row.get("semantic_object_digest"),
        consistency_family: row.get("consistency_family"),
        consistency_key_digest: row.get("consistency_key_digest"),
        canonical_event: row.get("canonical_event"),
        previous_chain_digest: row.get("previous_chain_digest"),
        chain_digest: row.get("chain_digest"),
        accepted_at: row.get("accepted_at"),
        predecessor_representation_key_digest: row.get("predecessor_representation_key_digest"),
    }
}

/// The raw fact as a pre-profile-3 connector left it.
struct RawFact {
    statement: EvidenceStatementV2,
    event_id: AcceptedEventId,
    storage_identity: Sha256Digest,
}

/// Commit a message quoting the token on top of main and admit its commit
/// fact RAW: scanned, rendered, and appended by hand through the same seams
/// the git drain uses, with the redaction step left out, exactly as every
/// fact was admitted before redaction profile 3.
async fn admit_raw_commit(
    pool: &PgPool,
    fixture: &Fixture,
    runtime: &WriterAuthorityRuntime,
) -> RawFact {
    let head = fixture.repository.head();
    let raw_commit = fixture.repository.commit(
        Some(&head),
        &format!("ops: rotate {PLANTED_SLACK_TOKEN} before the release"),
        THIRD_COMMIT_DATE,
    );

    let verified = runtime.verify().await.unwrap();
    let active = verified
        .bind_connector(&ContractId::new(GIT_CONNECTOR.connector_schema).unwrap())
        .unwrap();
    let binding = GitConnectorBindingV1::resolve(
        &active,
        ContractId::new("connector.git").unwrap(),
        ContractId::new(GIT_INSTANCE).unwrap(),
        INSTALLATION_ID,
    )
    .unwrap();
    let sources = fixture.sources();
    let source = &sources.git[0];
    let reader =
        GitRepositoryReader::new(&source.git_dir, source.repository().unwrap(), None).unwrap();
    let scan = reader
        .scan(&GitScanRequestV1 {
            ref_name: source.ref_name().unwrap(),
            max_commits: source.max_commits,
            max_facts: source.max_facts,
            tree_mode: GitTreeScanModeV1::CommitsOnly,
        })
        .unwrap();
    let raw_fact = scan
        .facts
        .iter()
        .find(|fact| matches!(fact, GitFactV1::Commit(commit) if commit.commit_id.to_hex() == raw_commit))
        .expect("the planted commit is in the walk")
        .clone();

    let now: chrono::DateTime<chrono::Utc> =
        sqlx::query_scalar("SELECT pg_catalog.statement_timestamp()")
            .fetch_one(pool)
            .await
            .unwrap();
    let ingress = binding
        .build_ingress(
            &raw_fact,
            &GitIngressClocksV1 {
                received_at: CanonicalTimestamp::from_datetime(&now).unwrap(),
            },
            1,
        )
        .unwrap();
    let token_hex = hex::encode(PLANTED_SLACK_TOKEN);
    assert!(
        ingress
            .canonical_payload
            .windows(token_hex.len())
            .any(|window| window == token_hex.as_bytes()),
        "the raw payload carries the token as the hex a git fact stores"
    );
    let admitted = admit_evidence(
        &active,
        EvidenceAdmissionRequestV1 {
            candidate: &ingress.candidate,
            locators: &ingress.locators,
            canonical_payload: &ingress.canonical_payload,
            delivery: ingress.delivery.clone(),
            lineage: RepresentationLineageV2::Origin,
        },
    )
    .unwrap();
    let projection = GovernedContentProjection::new(
        runtime.control_scope(),
        admitted.content(),
        &fixture.installed.kek(),
    )
    .unwrap();
    let appendable = admitted.appendable(verified.append_witness()).unwrap();
    let outcome = runtime
        .ledger()
        .append(verified.append_witness(), &appendable, Arc::new(projection))
        .await
        .unwrap();
    assert!(
        matches!(outcome, AppendOutcome::Appended { .. }),
        "{outcome:?}"
    );
    RawFact {
        statement: admitted.statement().clone(),
        event_id: appendable.accepted_event_id(),
        storage_identity: ingress.candidate.canonical_payload.storage_identity,
    }
}

fn body_projector(pool: &PgPool, fixture: &Fixture) -> CockroachBodyProjectionRepository {
    CockroachBodyProjectionRepository::new(
        pool.clone(),
        fixture.installed.scope.tenant_id,
        fixture.installed.scope.project.clone(),
        reference_parser_key_v1(),
        Arc::new(GovernedContentResolver::new(
            pool.clone(),
            fixture.installed.scope.tenant_id,
            fixture.installed.scope.project.clone(),
            fixture.installed.semantic_scope.clone(),
            fixture.installed.kek(),
        )),
        retry_policy(),
    )
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // one linear proof: raw at rest, quarantine, pass, replay, status
async fn live_the_pass_supersedes_a_raw_git_fact_and_its_replay_stops_quarantining_when_configured()
{
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = Fixture::install(&pool, "supersession").await;
    let runtime = fixture.installed.runtime(&pool).await;
    let kek = fixture.installed.kek();
    let sources = fixture.sources();
    let raw = admit_raw_commit(&pool, &fixture, &runtime).await;
    let raw_row_before = event_row(&pool, &fixture, raw.event_id).await;

    // (1) Projected, the raw fact's body is plaintext at rest.
    let report = fixture
        .worker(&pool, "project,embed")
        .await
        .run_tick()
        .await;
    assert_eq!(
        status(&report, WorkerStepV1::Bodies),
        WorkerStepStatusV1::Ok
    );
    assert_eq!(
        counter(&report, WorkerStepV1::Bodies, "events_projected"),
        1
    );
    let stored = body_and_lexical_bytes(&pool, &fixture).await;
    assert!(
        holds(&stored, PLANTED_SLACK_TOKEN),
        "the raw body carries the token (as the hex a git fact stores)"
    );

    // (2) A full walk re-presents the fact redacted: quarantined, unresolved.
    // The same tick projects the fixture's own commits, so the body plane
    // holds more than the raw body from here on.
    let report = fixture
        .worker(&pool, "ingest,project,embed")
        .await
        .run_tick()
        .await;
    assert_eq!(status(&report, WorkerStepV1::Git), WorkerStepStatusV1::Ok);
    assert_eq!(counter(&report, WorkerStepV1::Git, "quarantined"), 1);
    assert_eq!(counter(&report, WorkerStepV1::Git, "facts_redacted"), 1);
    assert_eq!(
        status(&report, WorkerStepV1::Bodies),
        WorkerStepStatusV1::Ok
    );
    let summary = quarantine_summary(
        &pool,
        fixture.installed.scope.tenant_id,
        &fixture.installed.scope.project,
    )
    .await
    .unwrap();
    assert_eq!(summary.by_reason.get("preimage_disagreement"), Some(&1));
    assert_eq!(summary.resolved_preimage_disagreements, 0);
    assert_eq!(summary.preimage_disagreement_sample.len(), 1);
    assert_eq!(
        summary.preimage_disagreement_sample[0].source_fact_id,
        Some(raw.statement.source_fact_id.digest())
    );

    // (3) A dry run decides and writes nothing.
    let dry = run_supersession(
        &pool,
        &runtime,
        &kek,
        SupersessionRequestV1 {
            sources: &sources,
            dry_run: true,
        },
    )
    .await
    .unwrap();
    assert_eq!(dry.state, SupersessionStateV1::DryRun);
    assert_eq!(dry.superseded, 1, "{dry:?}");
    assert_eq!(dry.quarantined, 0);
    assert!(dry.rows_removed.is_empty());
    assert!(
        holds(
            &body_and_lexical_bytes(&pool, &fixture).await,
            PLANTED_SLACK_TOKEN
        ),
        "a dry run leaves the raw body in place"
    );

    // (4) The pass: one successor appended, the raw representation erased.
    let events_before = scoped_count(&pool, "memory_evidence_events", &fixture).await;
    let applied = run_supersession(
        &pool,
        &runtime,
        &kek,
        SupersessionRequestV1 {
            sources: &sources,
            dry_run: false,
        },
    )
    .await
    .unwrap();
    assert_eq!(applied.state, SupersessionStateV1::Applied);
    assert_eq!(applied.redaction_profile, 3);
    assert_eq!(applied.superseded, 1, "{applied:?}");
    assert_eq!(applied.skipped_with_successor, 0);
    assert_eq!(applied.quarantined, 0);
    assert_eq!(applied.source_unbound, 0);
    assert_eq!(applied.content_shared_skipped, 0);
    assert!(applied.unchanged_under_profile >= 2, "{applied:?}");
    assert!(applied.git_facts_scanned >= 3, "{applied:?}");
    assert_eq!(applied.transcript_turns_raw_at_rest, 0);
    assert!(applied.bodies_removed >= 1, "{applied:?}");
    for table in [
        "memory_body_objects_v1",
        "memory_chunk_occurrences_v1",
        "memory_chunk_occurrence_spans_v1",
        "memory_parse_run_manifests_v1",
        "memory_generation_pointers_v1",
        "memory_content_objects",
    ] {
        assert!(
            applied.rows_removed.get(table).copied().unwrap_or(0) >= 1,
            "{table} lost no row: {applied:?}"
        );
    }
    assert_eq!(
        scoped_count(&pool, "memory_evidence_events", &fixture).await,
        events_before + 1,
        "exactly the successor was appended"
    );

    // The successor names the raw representation and the raw source fact,
    // and the column the ledger seeks on is set.
    let successors: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT canonical_event FROM memory_evidence_events \
         WHERE tenant_id = $1 AND project = $2 AND predecessor_representation_key_digest = $3",
    )
    .bind(fixture.installed.scope.tenant_id)
    .bind(&fixture.installed.scope.project)
    .bind(
        raw.statement
            .representation_key
            .digest()
            .as_bytes()
            .to_vec(),
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(successors.len(), 1);
    let successor: EvidenceStatementV2 = decode_strict(&successors[0]).unwrap();
    assert_eq!(
        successor.representation.lineage,
        RepresentationLineageV2::Supersedes {
            predecessor_representation_key: raw.statement.representation_key,
        }
    );
    assert_eq!(successor.source_fact, raw.statement.source_fact);
    assert_ne!(
        successor.canonical_content.content_digest,
        raw.statement.canonical_content.content_digest
    );

    // The literal is gone from every body and lexical text, the dense tier
    // references no body that no longer exists, the raw content object is
    // gone, and the raw event row is byte-identical.
    let stored = body_and_lexical_bytes(&pool, &fixture).await;
    assert!(!stored.is_empty());
    assert!(
        !holds(&stored, PLANTED_SLACK_TOKEN),
        "the raw body survived"
    );
    let dangling_dense: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM memory_body_dense_projection_v1 AS dense \
         WHERE tenant_id = $1 AND project = $2 AND NOT EXISTS (\
           SELECT 1 FROM memory_body_objects_v1 AS body \
           WHERE body.tenant_id = dense.tenant_id AND body.project = dense.project \
             AND body.content_sha256 = dense.body_content_id)",
    )
    .bind(fixture.installed.scope.tenant_id)
    .bind(&fixture.installed.scope.project)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(dangling_dense, 0);
    assert!(
        fetch_governed_content(
            &pool,
            fixture.installed.scope.tenant_id,
            &fixture.installed.scope.project,
            &fixture.installed.semantic_scope,
            raw.storage_identity,
        )
        .await
        .unwrap()
        .is_none(),
        "the raw content object must be gone"
    );
    assert_eq!(
        event_row(&pool, &fixture, raw.event_id).await,
        raw_row_before,
        "the raw accepted event row is the tombstone and never changes"
    );

    // (5) A second run is idempotent: the successor is found, nothing new
    // is removed.
    let again = run_supersession(
        &pool,
        &runtime,
        &kek,
        SupersessionRequestV1 {
            sources: &sources,
            dry_run: false,
        },
    )
    .await
    .unwrap();
    assert_eq!(again.superseded, 0, "{again:?}");
    assert_eq!(again.skipped_with_successor, 1);
    assert_eq!(again.quarantined, 0);
    assert!(again.rows_removed.is_empty(), "{again:?}");
    assert_eq!(
        scoped_count(&pool, "memory_evidence_events", &fixture).await,
        events_before + 1
    );

    // (6) The next full walk (the ref moved) replays the fact through its
    // successor instead of quarantining it, and the body step is fine.
    let head = fixture.repository.head();
    fixture
        .repository
        .commit(Some(&head), "docs: note the rotation", FOURTH_COMMIT_DATE);
    let report = fixture
        .worker(&pool, "ingest,project,embed")
        .await
        .run_tick()
        .await;
    assert_eq!(status(&report, WorkerStepV1::Git), WorkerStepStatusV1::Ok);
    assert_eq!(counter(&report, WorkerStepV1::Git, "quarantined"), 0);
    assert_eq!(
        counter(&report, WorkerStepV1::Git, "replayed"),
        3,
        "the two fixture commits and the superseded one: {report:?}"
    );
    assert_eq!(
        status(&report, WorkerStepV1::Bodies),
        WorkerStepStatusV1::Ok
    );
    assert_eq!(
        status(&report, WorkerStepV1::Lexical),
        WorkerStepStatusV1::Ok
    );
    assert!(
        !holds(
            &body_and_lexical_bytes(&pool, &fixture).await,
            PLANTED_SLACK_TOKEN
        ),
        "the replay must not bring the raw body back"
    );
    assert_eq!(
        scoped_count(&pool, "memory_evidence_quarantine", &fixture).await,
        1,
        "the one earlier disagreement, and no new one"
    );

    // (7) A full re-projection lets the erased raw event pass, counted.
    let rebuilt = body_projector(&pool, &fixture)
        .reproject_all()
        .await
        .unwrap();
    assert_eq!(rebuilt.events_superseded_erased, 1, "{rebuilt:?}");
    assert!(rebuilt.events_projected >= 4, "{rebuilt:?}");
    assert!(
        !holds(
            &body_and_lexical_bytes(&pool, &fixture).await,
            PLANTED_SLACK_TOKEN
        ),
        "a full re-projection must not bring the raw body back"
    );

    // (8) The disagreement is resolved: counted, out of the sample, and so
    // (per the unit test on the status block) no longer a warning.
    let summary = quarantine_summary(
        &pool,
        fixture.installed.scope.tenant_id,
        &fixture.installed.scope.project,
    )
    .await
    .unwrap();
    assert_eq!(summary.by_reason.get("preimage_disagreement"), Some(&1));
    assert_eq!(summary.resolved_preimage_disagreements, 1);
    assert!(summary.preimage_disagreement_sample.is_empty());
}

/// A login holding the supersession policy's surface minus its DELETEs
/// fails closed at the first erase with SQLSTATE 42501, and, because the
/// append and the erase are one transaction, appends nothing.
#[tokio::test]
async fn live_a_login_without_delete_fails_closed_and_appends_nothing_when_configured() {
    let Some(database_url) = common::test_database_url() else {
        return;
    };
    let pool = common::migrated_pool(&database_url).await;
    let fixture = Fixture::install(&pool, "supersession-role").await;
    let owner_runtime = fixture.installed.runtime(&pool).await;
    let sources = fixture.sources();
    let raw = admit_raw_commit(&pool, &fixture, &owner_runtime).await;
    let report = fixture
        .worker(&pool, "project,embed")
        .await
        .run_tick()
        .await;
    assert_eq!(
        status(&report, WorkerStepV1::Bodies),
        WorkerStepStatusV1::Ok
    );
    let events_before = scoped_count(&pool, "memory_evidence_events", &fixture).await;
    let raw_row_before = event_row(&pool, &fixture, raw.event_id).await;

    let probe = RuntimeProbeRole::create_supersession_without_delete(&pool, &database_url).await;
    let probe_runtime = fixture.installed.runtime(&probe.pool).await;
    let refused = run_supersession(
        &probe.pool,
        &probe_runtime,
        &fixture.installed.kek(),
        SupersessionRequestV1 {
            sources: &sources,
            dry_run: false,
        },
    )
    .await
    .expect_err("a login without DELETE must be refused");
    assert!(
        refused.to_string().contains("42501"),
        "expected a privilege refusal, got {refused}"
    );
    probe.drop_role(&pool).await;

    assert_eq!(
        scoped_count(&pool, "memory_evidence_events", &fixture).await,
        events_before,
        "the refused pass appended nothing"
    );
    assert_eq!(
        event_row(&pool, &fixture, raw.event_id).await,
        raw_row_before
    );
    assert!(
        holds(
            &body_and_lexical_bytes(&pool, &fixture).await,
            PLANTED_SLACK_TOKEN
        ),
        "the raw body is untouched"
    );
    assert!(
        fetch_governed_content(
            &pool,
            fixture.installed.scope.tenant_id,
            &fixture.installed.scope.project,
            &fixture.installed.semantic_scope,
            raw.storage_identity,
        )
        .await
        .unwrap()
        .is_some()
    );
}
