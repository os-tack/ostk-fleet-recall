//! `CockroachDB` implementation of the coverage runtime (COVER-01..03).
//!
//! Every statement here touches only the two migration-0020 coverage tables,
//! `memory_coverage_cursors_v1` and `memory_coverage_receipts_v1`, both keyed by
//! the trusted `(tenant_id, project)` pair bound at construction. Neither table
//! is a publication-reader table (PUBLIC-03/04): coverage cursors and receipts
//! are private-plane projection rows.
//!
//! [`CockroachCoverageRuntimeRepository::observe`] runs the whole cursor-lock →
//! merge → receipt-insert → cursor-advance sequence inside ONE serializable
//! transaction via [`with_serializable_retry`]. A cursor advance and its
//! receipt row therefore commit together or not at all (EVENT-03): a crash — or
//! the fault injected by [`CoverageFaultInjection::AbortAfterWrites`] — leaves
//! neither. Re-observing an already-covered range takes the
//! [`super::observed_range::InsertOutcome::Redundant`] branch, which writes
//! nothing: no duplicate receipt, no cursor regression.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sha2::{Digest as _, Sha256};
use sqlx::postgres::{PgPool, PgRow};
use sqlx::{Postgres, Row as _, Transaction};

use crate::Result;
use crate::control_log::TrustedControlScope;
use crate::error::FleetError;
use crate::memory_contracts::common::ContractId;
use crate::memory_contracts::coverage::{
    CoverageCompletenessV1, CoverageReceiptId, CoverageScopeV1, SequenceContinuityV1,
};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::evidence::AcceptedEventId;
use crate::store::cockroach::{RetryPolicy, with_serializable_retry};

use super::observed_range::{InsertOutcome, ObservedRangeV1, SequenceIntervalV1};
use super::repository::{
    CoverageCursorRowV1, CoverageObservationOutcome, CoverageObservationV1, CoverageReceiptRowV1,
    CoverageRuntimeRepository, build_receipt,
};

/// Domain separator for the per-cursor coverage-key digest. Length-frames every
/// variable field so no two distinct domains can collide on one key.
const COVERAGE_KEY_DOMAIN: &[u8] = b"ostk-coverage-cursor-key-v1\0";

const SEED_CURSOR_SQL: &str = "INSERT INTO public.memory_coverage_cursors_v1 (\
     tenant_id, project, coverage_key_digest, connector_instance_id, observed_ranges, \
     target_start, target_end, observation_seq, last_completeness, last_receipt_id, updated_at\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, 0, 'unknown', NULL, $8) \
     ON CONFLICT (tenant_id, project, coverage_key_digest) DO NOTHING";

const SELECT_CURSOR_FOR_UPDATE_SQL: &str = "SELECT observed_ranges, target_start, target_end, \
     observation_seq, last_completeness, last_receipt_id, updated_at \
     FROM public.memory_coverage_cursors_v1 \
     WHERE tenant_id = $1 AND project = $2 AND coverage_key_digest = $3 FOR UPDATE";

const SELECT_CURSOR_SQL: &str = "SELECT observed_ranges, target_start, target_end, \
     observation_seq, last_completeness, last_receipt_id, updated_at \
     FROM public.memory_coverage_cursors_v1 \
     WHERE tenant_id = $1 AND project = $2 AND coverage_key_digest = $3";

const ADVANCE_CURSOR_SQL: &str = "UPDATE public.memory_coverage_cursors_v1 SET \
     observed_ranges = $4, observation_seq = $5, last_completeness = $6, \
     last_receipt_id = $7, updated_at = $8 \
     WHERE tenant_id = $1 AND project = $2 AND coverage_key_digest = $3";

const INSERT_RECEIPT_SQL: &str = "INSERT INTO public.memory_coverage_receipts_v1 (\
     tenant_id, project, receipt_id, connector_instance_id, coverage_key_digest, completeness, \
     evidence_id, source_digest, source_count, observation_seq, canonical_receipt, created_at\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
     ON CONFLICT (tenant_id, project, receipt_id) DO NOTHING";

const SELECT_RECEIPT_SQL: &str = "SELECT completeness, evidence_id, source_count, observation_seq, \
     canonical_receipt, created_at FROM public.memory_coverage_receipts_v1 \
     WHERE tenant_id = $1 AND project = $2 AND receipt_id = $3";

const COUNT_RECEIPTS_SQL: &str = "SELECT count(*) FROM public.memory_coverage_receipts_v1 \
     WHERE tenant_id = $1 AND project = $2 AND connector_instance_id = $3";

/// Where, if anywhere, [`CockroachCoverageRuntimeRepository::observe_with_fault_injection`]
/// forces the transaction to fail — used only by the connected atomicity proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverageFaultInjection {
    /// Run normally.
    None,
    /// Return an error AFTER both the receipt insert and the cursor advance
    /// have executed but BEFORE the transaction commits, so the connected proof
    /// can observe that a crash there leaves neither durable (EVENT-03).
    AbortAfterWrites,
}

/// Coverage runtime bound once to physical and semantic scope, exactly like
/// [`crate::evidence_ledger::CockroachAcceptedEventRepository`].
#[derive(Clone)]
pub struct CockroachCoverageRuntimeRepository {
    pool: PgPool,
    trusted_scope: TrustedControlScope,
    retry_policy: RetryPolicy,
}

impl std::fmt::Debug for CockroachCoverageRuntimeRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CockroachCoverageRuntimeRepository")
            .field("trusted_scope", &self.trusted_scope)
            .finish_non_exhaustive()
    }
}

impl CockroachCoverageRuntimeRepository {
    /// Bind one pool, one physical/semantic scope, and one retry policy.
    #[must_use]
    pub const fn new(
        pool: PgPool,
        trusted_scope: TrustedControlScope,
        retry_policy: RetryPolicy,
    ) -> Self {
        Self {
            pool,
            trusted_scope,
            retry_policy,
        }
    }

    /// Apply one observation, optionally forcing a fault to prove atomicity.
    ///
    /// [`CoverageFaultInjection::None`] is the production path
    /// ([`CoverageRuntimeRepository::observe`] delegates here). The fault
    /// variant exists only so the connected proof can assert that a failure
    /// after the writes but before commit leaves neither the receipt nor the
    /// cursor advance durable.
    pub async fn observe_with_fault_injection(
        &self,
        observation: &CoverageObservationV1,
        fault: CoverageFaultInjection,
    ) -> Result<CoverageObservationOutcome> {
        // Reject an empty/inverted observed interval up front (fail closed).
        if observation.observed.end <= observation.observed.start {
            return Err(FleetError::Memory(format!(
                "coverage observation interval [{}, {}) is empty or inverted",
                observation.observed.start, observation.observed.end
            )));
        }
        if observation.target.end <= observation.target.start {
            return Err(FleetError::Memory(format!(
                "coverage target interval [{}, {}) is empty or inverted",
                observation.target.start, observation.target.end
            )));
        }

        let scope = self.trusted_scope.clone();
        let key = coverage_key_digest(
            &observation.connector_instance,
            &observation.scope,
            observation.target,
        );
        let observation = observation.clone();
        with_serializable_retry(&self.pool, self.retry_policy, move |transaction| {
            let scope = scope.clone();
            let observation = observation.clone();
            Box::pin(async move {
                observe_in_transaction(transaction, &scope, key, &observation, fault).await
            })
        })
        .await
    }
}

#[async_trait]
impl CoverageRuntimeRepository for CockroachCoverageRuntimeRepository {
    async fn observe(
        &self,
        observation: &CoverageObservationV1,
    ) -> Result<CoverageObservationOutcome> {
        self.observe_with_fault_injection(observation, CoverageFaultInjection::None)
            .await
    }

    async fn read_cursor(
        &self,
        connector_instance: &ContractId,
        scope: &CoverageScopeV1,
        target: SequenceIntervalV1,
    ) -> Result<Option<CoverageCursorRowV1>> {
        let key = coverage_key_digest(connector_instance, scope, target);
        let row: Option<PgRow> = sqlx::query(SELECT_CURSOR_SQL)
            .bind(self.trusted_scope.tenant_id())
            .bind(self.trusted_scope.project())
            .bind(key.to_vec())
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(decode_cursor_row).transpose()
    }

    async fn read_receipt(
        &self,
        receipt_id: CoverageReceiptId,
    ) -> Result<Option<CoverageReceiptRowV1>> {
        let row: Option<PgRow> = sqlx::query(SELECT_RECEIPT_SQL)
            .bind(self.trusted_scope.tenant_id())
            .bind(self.trusted_scope.project())
            .bind(receipt_id.digest().as_bytes().to_vec())
            .fetch_optional(&self.pool)
            .await?;
        row.map(|row| decode_receipt_row(receipt_id, &row))
            .transpose()
    }

    async fn count_receipts_for_instance(&self, connector_instance: &ContractId) -> Result<u64> {
        let count: i64 = sqlx::query_scalar(COUNT_RECEIPTS_SQL)
            .bind(self.trusted_scope.tenant_id())
            .bind(self.trusted_scope.project())
            .bind(connector_instance.as_str())
            .fetch_one(&self.pool)
            .await?;
        u64::try_from(count)
            .map_err(|_| FleetError::Memory("coverage receipt count is negative".into()))
    }
}

async fn observe_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    key: [u8; 32],
    observation: &CoverageObservationV1,
    fault: CoverageFaultInjection,
) -> Result<CoverageObservationOutcome> {
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT pg_catalog.statement_timestamp()")
        .fetch_one(&mut **transaction)
        .await?;

    // Lazy seed so the FOR UPDATE below always locks a row (mirrors the
    // evidence ledger's offset-zero head seed). An existing row is untouched.
    sqlx::query(SEED_CURSOR_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(key.to_vec())
        .bind(observation.connector_instance.as_str())
        .bind(serde_json::to_vec(&ObservedRangeV1::empty()).map_err(|error| json_error(&error))?)
        .bind(observation.target.start.to_be_bytes().to_vec())
        .bind(observation.target.end.to_be_bytes().to_vec())
        .bind(now)
        .execute(&mut **transaction)
        .await?;

    let locked: PgRow = sqlx::query(SELECT_CURSOR_FOR_UPDATE_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(key.to_vec())
        .fetch_one(&mut **transaction)
        .await?;

    let stored = decode_cursor_row(&locked)?;
    // Defensive: the key digest already binds the target, so a mismatch here is
    // a stored-row tamper, not a routine disagreement. Fail closed.
    if stored.target != observation.target {
        return Err(FleetError::Memory(
            "coverage cursor target does not match the observation target".into(),
        ));
    }

    let mut merged = stored.observed.clone();
    let insert_outcome = merged
        .insert(observation.observed)
        .map_err(|error| FleetError::Memory(error.to_string()))?;

    if insert_outcome == InsertOutcome::Redundant {
        // Idempotent re-observation: no receipt, no cursor advance.
        return Ok(CoverageObservationOutcome::AlreadyCovered {
            observation_seq: stored.observation_seq,
        });
    }

    // build_receipt derives completeness and continuity from the merged range
    // against the target and runs the receipt's own validate (COVER-02/03), so
    // a receipt whose observed_through falls short of the window end, or that
    // carries a zero source/evidence digest, fails closed here — rolling the
    // whole transaction back — rather than reaching the database.
    let (receipt, receipt_id) = build_receipt(observation, &merged)?;
    let completeness = receipt.completeness;
    let gap_detected = matches!(receipt.continuity, SequenceContinuityV1::GapDetected { .. });
    let canonical_receipt = crate::memory_contracts::canonical::encode_canonical(&receipt)?;
    let next_seq = stored
        .observation_seq
        .checked_add(1)
        .ok_or_else(|| FleetError::Memory("coverage cursor observation_seq overflow".into()))?;

    sqlx::query(INSERT_RECEIPT_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(receipt_id.digest().as_bytes().to_vec())
        .bind(observation.connector_instance.as_str())
        .bind(key.to_vec())
        .bind(completeness_str(completeness))
        .bind(observation.evidence_id.digest().as_bytes().to_vec())
        .bind(observation.source_digest.as_bytes().to_vec())
        .bind(i64::from(observation.source_count))
        .bind(i64_from_seq(next_seq)?)
        .bind(canonical_receipt)
        .bind(now)
        .execute(&mut **transaction)
        .await?;

    sqlx::query(ADVANCE_CURSOR_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(key.to_vec())
        .bind(serde_json::to_vec(&merged).map_err(|error| json_error(&error))?)
        .bind(i64_from_seq(next_seq)?)
        .bind(completeness_str(completeness))
        .bind(receipt_id.digest().as_bytes().to_vec())
        .bind(now)
        .execute(&mut **transaction)
        .await?;

    if fault == CoverageFaultInjection::AbortAfterWrites {
        // Non-retryable, so with_serializable_retry rolls the transaction back
        // and returns this error rather than replaying: proof that the receipt
        // insert and the cursor advance are one atomic unit (EVENT-03).
        return Err(FleetError::Memory(
            "coverage fault injection: abort after writes".into(),
        ));
    }

    Ok(CoverageObservationOutcome::Recorded {
        receipt_id,
        completeness,
        gap_detected,
        observation_seq: next_seq,
    })
}

/// `SHA-256(domain || framed(connector) || framed(uri) || framed(revision) ||
/// framed(window_start) || framed(window_end) || target_start || target_end)`.
fn coverage_key_digest(
    connector_instance: &ContractId,
    scope: &CoverageScopeV1,
    target: SequenceIntervalV1,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(COVERAGE_KEY_DOMAIN);
    frame(&mut hasher, connector_instance.as_str().as_bytes());
    frame(&mut hasher, scope.scope.to_string().as_bytes());
    frame(&mut hasher, scope.revision.as_bytes());
    frame(&mut hasher, scope.window.window_start.as_str().as_bytes());
    frame(&mut hasher, scope.window.window_end.as_str().as_bytes());
    hasher.update(target.start.to_be_bytes());
    hasher.update(target.end.to_be_bytes());
    hasher.finalize().into()
}

fn frame(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_be_bytes());
    hasher.update(bytes);
}

fn decode_cursor_row(row: &PgRow) -> Result<CoverageCursorRowV1> {
    let observed_bytes: Vec<u8> = row.try_get("observed_ranges")?;
    let observed: ObservedRangeV1 =
        serde_json::from_slice(&observed_bytes).map_err(|error| json_error(&error))?;
    observed
        .validate()
        .map_err(|error| FleetError::Memory(error.to_string()))?;
    let target_start = u64_from_be(row.try_get("target_start")?)?;
    let target_end = u64_from_be(row.try_get("target_end")?)?;
    let target = SequenceIntervalV1::new(target_start, target_end)
        .map_err(|error| FleetError::Memory(error.to_string()))?;
    let observation_seq = seq_from_i64(row.try_get("observation_seq")?)?;
    let last_completeness = parse_completeness(&row.try_get::<String, _>("last_completeness")?)?;
    let last_receipt_id: Option<Vec<u8>> = row.try_get("last_receipt_id")?;
    let last_receipt_id = last_receipt_id
        .map(|bytes| digest32(bytes).map(CoverageReceiptId::from_digest))
        .transpose()?;
    Ok(CoverageCursorRowV1 {
        observed,
        target,
        observation_seq,
        last_completeness,
        last_receipt_id,
        updated_at: row.try_get("updated_at")?,
    })
}

fn decode_receipt_row(receipt_id: CoverageReceiptId, row: &PgRow) -> Result<CoverageReceiptRowV1> {
    let completeness = parse_completeness(&row.try_get::<String, _>("completeness")?)?;
    let evidence_id = AcceptedEventId::from_digest(digest32(row.try_get("evidence_id")?)?);
    let source_count = u32::try_from(row.try_get::<i64, _>("source_count")?)
        .map_err(|_| FleetError::Memory("stored coverage source_count is out of range".into()))?;
    let observation_seq = seq_from_i64(row.try_get("observation_seq")?)?;
    Ok(CoverageReceiptRowV1 {
        receipt_id,
        completeness,
        evidence_id,
        source_count,
        observation_seq,
        canonical_receipt: row.try_get("canonical_receipt")?,
        created_at: row.try_get("created_at")?,
    })
}

const fn completeness_str(completeness: CoverageCompletenessV1) -> &'static str {
    match completeness {
        CoverageCompletenessV1::Complete => "complete",
        CoverageCompletenessV1::Partial => "partial",
        CoverageCompletenessV1::Unknown => "unknown",
    }
}

fn parse_completeness(value: &str) -> Result<CoverageCompletenessV1> {
    match value {
        "complete" => Ok(CoverageCompletenessV1::Complete),
        "partial" => Ok(CoverageCompletenessV1::Partial),
        "unknown" => Ok(CoverageCompletenessV1::Unknown),
        other => Err(FleetError::Memory(format!(
            "unrecognized stored coverage completeness {other}"
        ))),
    }
}

fn i64_from_seq(seq: u64) -> Result<i64> {
    i64::try_from(seq)
        .map_err(|_| FleetError::Memory("coverage observation_seq exceeds INT8".into()))
}

fn seq_from_i64(value: i64) -> Result<u64> {
    u64::try_from(value)
        .map_err(|_| FleetError::Memory("stored coverage observation_seq is negative".into()))
}

fn u64_from_be(bytes: Vec<u8>) -> Result<u64> {
    let bytes: [u8; 8] = bytes
        .try_into()
        .map_err(|_| FleetError::Memory("stored coverage sequence column is not 8 bytes".into()))?;
    Ok(u64::from_be_bytes(bytes))
}

fn digest32(value: Vec<u8>) -> Result<Sha256Digest> {
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| FleetError::Memory("stored coverage digest column is not 32 bytes".into()))?;
    Ok(Sha256Digest::from_bytes(bytes))
}

fn json_error(error: &serde_json::Error) -> FleetError {
    FleetError::Memory(format!("coverage observed-range JSON error: {error}"))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use super::*;
    use crate::memory_contracts::common::{CanonicalTimestamp, HexBytes};
    use crate::memory_contracts::coverage::CoverageWindowV1;
    use crate::memory_contracts::identity::ResourceUri;

    const SCOPE_URI: &str = "urn:ostk:entity:v1:repository:sha256:1111111111111111111111111111111111111111111111111111111111111111";

    fn scope(revision_byte: u8) -> CoverageScopeV1 {
        CoverageScopeV1 {
            scope: ResourceUri::from_str(SCOPE_URI).unwrap(),
            revision: HexBytes::new(vec![revision_byte; 32]).unwrap(),
            window: CoverageWindowV1 {
                window_start: CanonicalTimestamp::parse("2026-08-14T00:00:00.000000000Z").unwrap(),
                window_end: CanonicalTimestamp::parse("2026-08-15T00:00:00.000000000Z").unwrap(),
            },
        }
    }

    fn interval(start: u64, end: u64) -> SequenceIntervalV1 {
        SequenceIntervalV1::new(start, end).unwrap()
    }

    #[test]
    fn completeness_str_round_trips_every_closed_variant() {
        for value in [
            CoverageCompletenessV1::Complete,
            CoverageCompletenessV1::Partial,
            CoverageCompletenessV1::Unknown,
        ] {
            assert_eq!(parse_completeness(completeness_str(value)).unwrap(), value);
        }
    }

    #[test]
    fn parse_completeness_rejects_unrecognized_strings() {
        // Kills a mutant that widens the match to a catch-all: an unrecognized
        // stored string must fail closed, never decode as a default state.
        assert!(matches!(
            parse_completeness("bogus"),
            Err(FleetError::Memory(_))
        ));
    }

    #[test]
    fn coverage_key_is_stable_and_domain_sensitive() {
        let instance = ContractId::new("connector.github.instance-1").unwrap();
        let base = coverage_key_digest(&instance, &scope(0x22), interval(0, 100));
        // Stable for identical inputs.
        assert_eq!(
            base,
            coverage_key_digest(&instance, &scope(0x22), interval(0, 100))
        );
        // A different connector instance changes the key.
        let other_instance = ContractId::new("connector.github.instance-2").unwrap();
        assert_ne!(
            base,
            coverage_key_digest(&other_instance, &scope(0x22), interval(0, 100))
        );
        // A different revision changes the key.
        assert_ne!(
            base,
            coverage_key_digest(&instance, &scope(0x33), interval(0, 100))
        );
        // A different target changes the key.
        assert_ne!(
            base,
            coverage_key_digest(&instance, &scope(0x22), interval(0, 200))
        );
    }

    #[test]
    fn coverage_key_framing_prevents_field_boundary_collisions() {
        // Length-framing means moving a byte across the connector/uri boundary
        // must change the digest. Two ContractIds whose concatenation with the
        // URI would be ambiguous under naive concatenation stay distinct.
        let a = ContractId::new("ab").unwrap();
        let b = ContractId::new("a").unwrap();
        // Same scope/target; only the connector split differs.
        assert_ne!(
            coverage_key_digest(&a, &scope(0x22), interval(0, 100)),
            coverage_key_digest(&b, &scope(0x22), interval(0, 100))
        );
    }

    #[test]
    fn seq_conversions_fail_closed_on_out_of_range() {
        assert!(seq_from_i64(-1).is_err());
        assert_eq!(seq_from_i64(7).unwrap(), 7);
        assert_eq!(i64_from_seq(7).unwrap(), 7);
        assert!(i64_from_seq(u64::MAX).is_err());
    }

    #[test]
    fn u64_be_round_trips_full_range() {
        for value in [0_u64, 1, u64::from(u32::MAX) + 1, u64::MAX] {
            assert_eq!(u64_from_be(value.to_be_bytes().to_vec()).unwrap(), value);
        }
        assert!(u64_from_be(vec![0_u8; 4]).is_err());
    }
}
