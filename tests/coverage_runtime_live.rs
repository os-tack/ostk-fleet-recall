//! Connected proof for the coverage runtime (W2-COVER-RT, COVER-01..03).
//!
//! Set `FLEET_RECALL_TEST_DATABASE_URL` to a disposable `CockroachDB` 26.2
//! database. Every test here is inert otherwise. Nothing in this file starts a
//! database process, invokes Docker, or targets a cloud service.
//!
//! These tests exercise the real runtime against migration 0020's coverage
//! tables and reproduce, at the DB level:
//! * `complete` / `partial` / `unknown` from constructed observation sequences;
//! * that a cursor advance and its receipt row are one atomic unit (a fault
//!   injected after both writes but before commit leaves NEITHER durable);
//! * that re-observing an already-covered range is idempotent (no duplicate
//!   receipt, no cursor regression).
//!
//! The coverage cursor and receipts are keyed by the trusted `(tenant, project)`
//! pair; a fresh unique project per test isolates them. The semantic scope is
//! decoded from the frozen v1 bootstrap-receipt fixture (no genesis/successor
//! ceremony is needed: the coverage runtime is a standalone projector bound to
//! scope, not the evidence append path). Each receipt binds an accepted-event
//! id; the proof uses a constructed non-zero id, and the runtime rejects the
//! zero id closed exactly as the coverage contract does.

use std::str::FromStr as _;
use std::time::Duration;

use ostk_fleet_recall::FleetScope;
use ostk_fleet_recall::control_log::TrustedControlScope;
use ostk_fleet_recall::coverage_runtime::{
    CockroachCoverageRuntimeRepository, CoverageFaultInjection, CoverageObservationOutcome,
    CoverageObservationV1, CoverageRuntimeRepository, SequenceIntervalV1,
};
use ostk_fleet_recall::memory_contracts::bootstrap::BootstrapReceiptV1;
use ostk_fleet_recall::memory_contracts::canonical::decode_strict;
use ostk_fleet_recall::memory_contracts::common::{
    AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, HexBytes, RegistryReferenceV1,
};
use ostk_fleet_recall::memory_contracts::coverage::{
    CoverageCompletenessV1, CoverageFreshnessV1, CoverageProofBasisV1, CoverageProofMethodV1,
    CoverageScopeV1, CoverageWindowV1, FreshnessStateV1, ProducerIdentityV1, ProducerKindV1,
};
use ostk_fleet_recall::memory_contracts::digest::Sha256Digest;
use ostk_fleet_recall::memory_contracts::evidence::AcceptedEventId;
use ostk_fleet_recall::memory_contracts::identity::ResourceUri;
use ostk_fleet_recall::store::cockroach::{CockroachStore, PoolConfig, RetryPolicy};
use ostk_recall_core::PrivacyTier;
use sqlx::PgPool;
use tokio::sync::Mutex;
use uuid::Uuid;

const BOOTSTRAP_RECEIPT: &[u8] =
    include_bytes!("../contracts/dynamic-memory/v1/bootstrap-receipt.jsonl");

const SCOPE_URI: &str = "urn:ostk:entity:v1:repository:sha256:1111111111111111111111111111111111111111111111111111111111111111";
const REVISION_HEX: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const FRESHNESS_RULE_DIGEST: &str =
    "3333333333333333333333333333333333333333333333333333333333333333";
const PROOF_METHOD_DIGEST: &str =
    "4444444444444444444444444444444444444444444444444444444444444444";
const SOURCE_DIGEST: &str = "5555555555555555555555555555555555555555555555555555555555555555";
const EVIDENCE_ID_DIGEST: &str = "6666666666666666666666666666666666666666666666666666666666666666";

const WINDOW_START: &str = "2026-08-14T00:00:00.000000000Z";
const WINDOW_END: &str = "2026-08-15T00:00:00.000000000Z";

/// The schema is shared, so migration is serialized and runs once per process.
static MIGRATED: Mutex<bool> = Mutex::const_new(false);

fn record(artifact: &'static [u8]) -> &'static [u8] {
    artifact
        .strip_suffix(b"\n")
        .expect("contract JSONL must have exactly one framing LF")
}

fn digest(value: &str) -> Sha256Digest {
    Sha256Digest::from_str(value).expect("fixture digest must be lowercase SHA-256")
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
        format!("coverage-runtime-{label}-{}", Uuid::now_v7()),
        "coverage-runtime-connected-test",
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

/// One live coverage runtime bound to a unique project.
struct CoverageScope {
    repository: CockroachCoverageRuntimeRepository,
    connector_instance: ContractId,
}

fn coverage_scope(pool: &PgPool, label: &str) -> CoverageScope {
    let physical = physical_scope(label);
    let trusted = TrustedControlScope::from_trusted_context(&physical, semantic_scope()).unwrap();
    CoverageScope {
        repository: CockroachCoverageRuntimeRepository::new(pool.clone(), trusted, retry_policy()),
        connector_instance: ContractId::new(format!("connector.github.instance-{label}")).unwrap(),
    }
}

fn contract_scope() -> CoverageScopeV1 {
    CoverageScopeV1 {
        scope: ResourceUri::from_str(SCOPE_URI).unwrap(),
        revision: HexBytes::new(hex::decode(REVISION_HEX).unwrap()).unwrap(),
        window: CoverageWindowV1 {
            window_start: CanonicalTimestamp::parse(WINDOW_START).unwrap(),
            window_end: CanonicalTimestamp::parse(WINDOW_END).unwrap(),
        },
    }
}

fn reg_ref(id: &str, digest_hex: &str) -> RegistryReferenceV1 {
    RegistryReferenceV1 {
        entry_id: ContractId::new(id).unwrap(),
        version: 1,
        entry_digest: digest(digest_hex),
    }
}

fn interval(start: u64, end: u64) -> SequenceIntervalV1 {
    SequenceIntervalV1::new(start, end).unwrap()
}

/// A base observation over target `[0, 100)`, observing `observed`, with an
/// `observed_through` that reaches the window end (a valid receipt).
fn observation(
    scope: &CoverageScope,
    observed: SequenceIntervalV1,
    target: SequenceIntervalV1,
) -> CoverageObservationV1 {
    CoverageObservationV1 {
        connector_instance: scope.connector_instance.clone(),
        producer: ProducerIdentityV1 {
            schema_version: 1,
            kind: ProducerKindV1::Connector,
            producer_id: ContractId::new("connector.github").unwrap(),
            version: 1,
        },
        scope: contract_scope(),
        target,
        observed,
        freshness: CoverageFreshnessV1 {
            state: FreshnessStateV1::Current,
            freshness_rule: reg_ref("coverage.freshness.default_rule", FRESHNESS_RULE_DIGEST),
        },
        proof_basis: CoverageProofBasisV1 {
            method: CoverageProofMethodV1::ClosedProviderQuery,
            proof_method_registration: reg_ref(
                "coverage.proof.closed_provider_query",
                PROOF_METHOD_DIGEST,
            ),
        },
        source_digest: digest(SOURCE_DIGEST),
        source_count: 42,
        evidence_id: AcceptedEventId::from_digest(digest(EVIDENCE_ID_DIGEST)),
        observed_through: CanonicalTimestamp::parse(WINDOW_END).unwrap(),
    }
}

#[tokio::test]
async fn live_complete_coverage_is_recorded_at_the_db_level() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let scope = coverage_scope(&pool, "complete");
    let target = interval(0, 100);

    let outcome = scope
        .repository
        .observe(&observation(&scope, interval(0, 100), target))
        .await
        .unwrap();
    let CoverageObservationOutcome::Recorded {
        receipt_id,
        completeness,
        gap_detected,
        observation_seq,
    } = outcome
    else {
        panic!("a fresh full observation must record a receipt, got {outcome:?}");
    };
    assert_eq!(completeness, CoverageCompletenessV1::Complete);
    assert!(!gap_detected);
    assert_eq!(observation_seq, 1);

    let cursor = scope
        .repository
        .read_cursor(&scope.connector_instance, &contract_scope(), target)
        .await
        .unwrap()
        .expect("cursor must exist after a committed observation");
    assert_eq!(cursor.observation_seq, 1);
    assert_eq!(cursor.last_completeness, CoverageCompletenessV1::Complete);
    assert_eq!(cursor.last_receipt_id, Some(receipt_id));
    assert_eq!(cursor.observed.intervals(), &[interval(0, 100)]);

    let receipt = scope
        .repository
        .read_receipt(receipt_id)
        .await
        .unwrap()
        .expect("receipt row must exist after a committed observation");
    assert_eq!(receipt.completeness, CoverageCompletenessV1::Complete);
    assert_eq!(receipt.observation_seq, 1);
    assert_eq!(
        scope
            .repository
            .count_receipts_for_instance(&scope.connector_instance)
            .await
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn live_partial_coverage_from_a_gap_is_recorded() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let scope = coverage_scope(&pool, "partial");
    let target = interval(0, 100);

    // A clean prefix: partial, but no detected gap.
    let first = scope
        .repository
        .observe(&observation(&scope, interval(0, 40), target))
        .await
        .unwrap();
    let CoverageObservationOutcome::Recorded {
        completeness,
        gap_detected,
        observation_seq,
        ..
    } = first
    else {
        panic!("first partial observation must record, got {first:?}");
    };
    assert_eq!(completeness, CoverageCompletenessV1::Partial);
    assert!(!gap_detected);
    assert_eq!(observation_seq, 1);

    // A later disjoint piece leaves a hole [40,60): still partial, now with a
    // detected sequence gap (COVER-03).
    let second = scope
        .repository
        .observe(&observation(&scope, interval(60, 100), target))
        .await
        .unwrap();
    let CoverageObservationOutcome::Recorded {
        completeness,
        gap_detected,
        observation_seq,
        ..
    } = second
    else {
        panic!("second partial observation must record, got {second:?}");
    };
    assert_eq!(completeness, CoverageCompletenessV1::Partial);
    assert!(gap_detected);
    assert_eq!(observation_seq, 2);

    let cursor = scope
        .repository
        .read_cursor(&scope.connector_instance, &contract_scope(), target)
        .await
        .unwrap()
        .expect("cursor must exist");
    assert_eq!(cursor.observation_seq, 2);
    assert_eq!(cursor.last_completeness, CoverageCompletenessV1::Partial);
    assert_eq!(
        cursor.observed.intervals(),
        &[interval(0, 40), interval(60, 100)]
    );
    assert_eq!(
        scope
            .repository
            .count_receipts_for_instance(&scope.connector_instance)
            .await
            .unwrap(),
        2
    );
}

#[tokio::test]
async fn live_unknown_coverage_from_an_unobserved_region_is_recorded() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let scope = coverage_scope(&pool, "unknown");
    let target = interval(0, 100);

    // Observe entirely outside the target: nothing in [0,100) is observed.
    let outcome = scope
        .repository
        .observe(&observation(&scope, interval(200, 300), target))
        .await
        .unwrap();
    let CoverageObservationOutcome::Recorded {
        completeness,
        observation_seq,
        ..
    } = outcome
    else {
        panic!("an out-of-target observation must record unknown, got {outcome:?}");
    };
    assert_eq!(completeness, CoverageCompletenessV1::Unknown);
    assert_eq!(observation_seq, 1);

    let cursor = scope
        .repository
        .read_cursor(&scope.connector_instance, &contract_scope(), target)
        .await
        .unwrap()
        .expect("cursor must exist");
    assert_eq!(cursor.last_completeness, CoverageCompletenessV1::Unknown);
    assert_eq!(cursor.observed.intervals(), &[interval(200, 300)]);
}

#[tokio::test]
async fn live_cursor_advance_and_receipt_are_atomic() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let scope = coverage_scope(&pool, "atomic");
    let target = interval(0, 100);

    // A clean first advance: cursor at seq 1, one receipt.
    scope
        .repository
        .observe(&observation(&scope, interval(0, 40), target))
        .await
        .unwrap();

    // A second observation that WOULD advance the cursor and mint a receipt,
    // but the transaction is forced to fail after both writes and before
    // commit. Neither the cursor advance nor the receipt may survive.
    let faulted = scope
        .repository
        .observe_with_fault_injection(
            &observation(&scope, interval(60, 100), target),
            CoverageFaultInjection::AbortAfterWrites,
        )
        .await;
    assert!(
        faulted.is_err(),
        "the injected fault must abort the observe"
    );

    let cursor = scope
        .repository
        .read_cursor(&scope.connector_instance, &contract_scope(), target)
        .await
        .unwrap()
        .expect("the first committed cursor must remain");
    assert_eq!(
        cursor.observation_seq, 1,
        "the aborted advance left no trace"
    );
    assert_eq!(
        cursor.observed.intervals(),
        &[interval(0, 40)],
        "the aborted merge did not persist"
    );
    assert_eq!(
        scope
            .repository
            .count_receipts_for_instance(&scope.connector_instance)
            .await
            .unwrap(),
        1,
        "the aborted receipt was rolled back with the cursor advance"
    );

    // A retry WITHOUT the fault now succeeds and advances exactly once.
    let retried = scope
        .repository
        .observe(&observation(&scope, interval(60, 100), target))
        .await
        .unwrap();
    let CoverageObservationOutcome::Recorded {
        observation_seq, ..
    } = retried
    else {
        panic!("the clean retry must record, got {retried:?}");
    };
    assert_eq!(observation_seq, 2);
    assert_eq!(
        scope
            .repository
            .count_receipts_for_instance(&scope.connector_instance)
            .await
            .unwrap(),
        2
    );
}

#[tokio::test]
async fn live_re_observing_a_covered_range_is_idempotent() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let scope = coverage_scope(&pool, "idempotent");
    let target = interval(0, 100);

    let first = scope
        .repository
        .observe(&observation(&scope, interval(0, 100), target))
        .await
        .unwrap();
    let CoverageObservationOutcome::Recorded {
        receipt_id,
        observation_seq,
        ..
    } = first
    else {
        panic!("first observation must record, got {first:?}");
    };
    assert_eq!(observation_seq, 1);

    // Re-observing the identical range: no duplicate receipt, no cursor
    // advance.
    let replay = scope
        .repository
        .observe(&observation(&scope, interval(0, 100), target))
        .await
        .unwrap();
    assert_eq!(
        replay,
        CoverageObservationOutcome::AlreadyCovered { observation_seq: 1 }
    );

    // Re-observing a strict SUBSET of the covered range is equally idempotent.
    let subset = scope
        .repository
        .observe(&observation(&scope, interval(20, 80), target))
        .await
        .unwrap();
    assert_eq!(
        subset,
        CoverageObservationOutcome::AlreadyCovered { observation_seq: 1 }
    );

    let cursor = scope
        .repository
        .read_cursor(&scope.connector_instance, &contract_scope(), target)
        .await
        .unwrap()
        .expect("cursor must exist");
    assert_eq!(
        cursor.observation_seq, 1,
        "cursor must not regress or advance"
    );
    assert_eq!(cursor.last_receipt_id, Some(receipt_id));
    assert_eq!(cursor.observed.intervals(), &[interval(0, 100)]);
    assert_eq!(
        scope
            .repository
            .count_receipts_for_instance(&scope.connector_instance)
            .await
            .unwrap(),
        1,
        "no duplicate receipt was written"
    );
}

#[tokio::test]
async fn live_observed_through_short_of_window_end_fails_closed() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let scope = coverage_scope(&pool, "failclosed-window");
    let target = interval(0, 100);

    // A receipt whose observed_through does not reach the window end is invalid
    // (COVER-02); the runtime must reject it and write nothing.
    let mut bad = observation(&scope, interval(0, 100), target);
    bad.observed_through = CanonicalTimestamp::parse("2026-08-14T12:00:00.000000000Z").unwrap();
    assert!(scope.repository.observe(&bad).await.is_err());

    assert!(
        scope
            .repository
            .read_cursor(&scope.connector_instance, &contract_scope(), target)
            .await
            .unwrap()
            .is_none(),
        "a rejected observation leaves no cursor row"
    );
    assert_eq!(
        scope
            .repository
            .count_receipts_for_instance(&scope.connector_instance)
            .await
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn live_zero_evidence_id_fails_closed() {
    let Ok(database_url) = std::env::var("FLEET_RECALL_TEST_DATABASE_URL") else {
        return;
    };
    let pool = live_pool(&database_url).await;
    let scope = coverage_scope(&pool, "failclosed-evidence");
    let target = interval(0, 100);

    // A zero evidence id names no accepted event (COVER-03); reject closed.
    let mut bad = observation(&scope, interval(0, 100), target);
    bad.evidence_id = AcceptedEventId::from_digest(Sha256Digest::ZERO);
    assert!(scope.repository.observe(&bad).await.is_err());

    assert!(
        scope
            .repository
            .read_cursor(&scope.connector_instance, &contract_scope(), target)
            .await
            .unwrap()
            .is_none()
    );
}
