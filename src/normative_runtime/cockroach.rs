//! `CockroachDB` implementation of the normative activation runtime (W3-NORM).
//!
//! Every statement here touches only migration 0024's three tables —
//! `memory_normative_heads_v1`, `memory_normative_log_v1`, and
//! `memory_normative_projections_v1` — all keyed by the trusted
//! `(tenant_id, project)` pair bound at construction. None is a publication
//! reader table (PUBLIC-03/04): all three are private-plane rows.
//!
//! # Compare-and-set discipline
//!
//! [`CockroachNormativeActivationRepository::activate`] runs the whole
//! seed → lock → compare → append → advance sequence inside ONE serializable
//! transaction via [`with_serializable_retry`], the same discipline
//! [`crate::registry_activation`] and [`crate::coverage_runtime`] use. The
//! compare is the doc's composite: the durable
//! `(active binding-set digest, registry package digest, activation-policy
//! digest)` triple must equal the proposal's expected composite exactly. Two
//! concurrent activations against the same head therefore cannot both win: the
//! loser re-reads the committed head on retry, finds a different binding-set
//! digest, and returns [`NormativeActivationOutcomeV1::Lost`] having written
//! nothing.
//!
//! The head advance, the log append, and the projection advance are one atomic
//! unit (EVENT-03), so the projection cursor can never sit ahead of or behind
//! the log it was folded from.
//!
//! # Nothing is ever rewritten
//!
//! Retirement and supersession APPEND. There is no `UPDATE` or `DELETE` against
//! `memory_normative_log_v1` anywhere in this file, so a superseded activation
//! stays exactly as it was recorded — which is what makes
//! [`CockroachNormativeActivationRepository::rebuild_projection`] a real
//! replay rather than a re-read.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::postgres::{PgPool, PgRow};
use sqlx::{Postgres, Row as _, Transaction};

use crate::Result;
use crate::control_log::TrustedControlScope;
use crate::error::FleetError;
use crate::memory_contracts::canonical::{decode_strict, encode_canonical};
use crate::memory_contracts::common::ContractId;
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::normative_v2::ContestedBindingV1;
use crate::store::cockroach::{RetryPolicy, with_serializable_retry};

use super::projection::{
    MAX_FAMILY_LOG_ENTRIES, NormativeFamilyProjectionV1, NormativeLogEntryV1, NormativeLogRecordV1,
    apply_entry, project_family,
};
use super::repository::{
    AdmittedNormativeActivationV1, NormativeActivationCandidateV1, NormativeActivationOutcomeV1,
    NormativeActivationRepository, NormativeHeadRowV1, NormativeLifecycleRequestV1,
    NormativeRegistryBindingV1, NormativeTransitionV1, active_binding_set_digest, admit_activation,
    admit_contest, admit_lifecycle, require_non_conflicting_against_live,
};

const SEED_HEAD_SQL: &str = "INSERT INTO public.memory_normative_heads_v1 (\
     tenant_id, project, binding_family_id, active_binding_set_digest, \
     registry_package_digest, activation_policy_digest, head_revision, log_seq, updated_at\
     ) VALUES ($1, $2, $3, NULL, $4, $5, 0, 0, $6) \
     ON CONFLICT (tenant_id, project, binding_family_id) DO NOTHING";

const LOCK_HEAD_SQL: &str = "SELECT active_binding_set_digest, registry_package_digest, \
     activation_policy_digest, head_revision, log_seq \
     FROM public.memory_normative_heads_v1 \
     WHERE tenant_id = $1 AND project = $2 AND binding_family_id = $3 FOR UPDATE";

const SELECT_HEAD_SQL: &str = "SELECT active_binding_set_digest, registry_package_digest, \
     activation_policy_digest, head_revision, log_seq \
     FROM public.memory_normative_heads_v1 \
     WHERE tenant_id = $1 AND project = $2 AND binding_family_id = $3";

/// The head advance is itself a compare-and-set on the exact revision and
/// binding-set digest observed under the lock, so even a lock-free replay of
/// this statement cannot double-apply.
const ADVANCE_HEAD_SQL: &str = "UPDATE public.memory_normative_heads_v1 SET \
     active_binding_set_digest = $4, registry_package_digest = $5, \
     activation_policy_digest = $6, head_revision = $7, log_seq = $8, updated_at = $9 \
     WHERE tenant_id = $1 AND project = $2 AND binding_family_id = $3 \
       AND head_revision = $10 \
       AND active_binding_set_digest IS NOT DISTINCT FROM $11 \
     RETURNING head_revision";

const APPEND_LOG_SQL: &str = "INSERT INTO public.memory_normative_log_v1 (\
     tenant_id, project, binding_family_id, seq, record_kind, record_id, \
     statement_id, supersedes_statement_id, canonical_record, created_at\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)";

const SELECT_LOG_SQL: &str = "SELECT seq, record_id, canonical_record \
     FROM public.memory_normative_log_v1 \
     WHERE tenant_id = $1 AND project = $2 AND binding_family_id = $3 ORDER BY seq";

const UPSERT_PROJECTION_SQL: &str = "INSERT INTO public.memory_normative_projections_v1 (\
     tenant_id, project, binding_family_id, cursor_seq, resolution, active_statement_id, \
     canonical_projection, updated_at\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) \
     ON CONFLICT (tenant_id, project, binding_family_id) DO UPDATE SET \
     cursor_seq = excluded.cursor_seq, resolution = excluded.resolution, \
     active_statement_id = excluded.active_statement_id, \
     canonical_projection = excluded.canonical_projection, updated_at = excluded.updated_at \
     WHERE public.memory_normative_projections_v1.cursor_seq < excluded.cursor_seq \
     RETURNING cursor_seq";

const SELECT_PROJECTION_SQL: &str = "SELECT canonical_projection \
     FROM public.memory_normative_projections_v1 \
     WHERE tenant_id = $1 AND project = $2 AND binding_family_id = $3";

/// Where, if anywhere, an activation forces its transaction to fail — used only
/// by the connected atomicity proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormativeFaultInjection {
    /// Run normally.
    None,
    /// Return a non-retryable error AFTER the log append, the head advance and
    /// the projection advance have all executed but BEFORE the transaction
    /// commits, so the connected proof can observe that a crash there leaves
    /// none of the three durable (EVENT-03).
    AbortAfterWrites,
}

/// Normative activation runtime bound once to physical scope, semantic scope,
/// and the active registry head.
#[derive(Clone)]
pub struct CockroachNormativeActivationRepository {
    pool: PgPool,
    trusted_scope: TrustedControlScope,
    registry_binding: NormativeRegistryBindingV1,
    retry_policy: RetryPolicy,
}

impl std::fmt::Debug for CockroachNormativeActivationRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CockroachNormativeActivationRepository")
            .field("trusted_scope", &self.trusted_scope)
            .field("registry_binding", &self.registry_binding)
            .finish_non_exhaustive()
    }
}

impl CockroachNormativeActivationRepository {
    /// Bind one pool, one physical/semantic scope, the active registry head, and
    /// one retry policy. The registry binding is rejected closed if it names a
    /// zero package or policy digest.
    pub fn new(
        pool: PgPool,
        trusted_scope: TrustedControlScope,
        registry_binding: NormativeRegistryBindingV1,
        retry_policy: RetryPolicy,
    ) -> Result<Self> {
        registry_binding.validate()?;
        Ok(Self {
            pool,
            trusted_scope,
            registry_binding,
            retry_policy,
        })
    }

    /// The active registry head this runtime judges every proposal against.
    #[must_use]
    pub const fn registry_binding(&self) -> NormativeRegistryBindingV1 {
        self.registry_binding
    }

    /// Apply one activation, optionally forcing a fault to prove atomicity.
    pub async fn activate_with_fault_injection(
        &self,
        candidate: &NormativeActivationCandidateV1,
        fault: NormativeFaultInjection,
    ) -> Result<NormativeActivationOutcomeV1> {
        // Every fail-closed check runs here, BEFORE a transaction opens: a
        // rejected activation never reaches the database at all.
        let admitted = admit_activation(
            candidate,
            &self.registry_binding,
            self.trusted_scope.semantic_scope(),
        )?;
        let family = candidate.proposal.binding_family_id.clone();
        let scope = self.trusted_scope.clone();
        let binding = self.registry_binding;
        let candidate = candidate.clone();

        with_serializable_retry(&self.pool, self.retry_policy, move |transaction| {
            let scope = scope.clone();
            let family = family.clone();
            let admitted = admitted.clone();
            let candidate = candidate.clone();
            Box::pin(async move {
                activate_in_transaction(
                    transaction,
                    &scope,
                    &binding,
                    &family,
                    &candidate,
                    &admitted,
                    fault,
                )
                .await
            })
        })
        .await
    }
}

#[async_trait]
impl NormativeActivationRepository for CockroachNormativeActivationRepository {
    async fn activate(
        &self,
        candidate: &NormativeActivationCandidateV1,
    ) -> Result<NormativeActivationOutcomeV1> {
        self.activate_with_fault_injection(candidate, NormativeFaultInjection::None)
            .await
    }

    async fn retire(
        &self,
        request: &NormativeLifecycleRequestV1,
    ) -> Result<NormativeActivationOutcomeV1> {
        let scope = self.trusted_scope.clone();
        let binding = self.registry_binding;
        let request = request.clone();
        with_serializable_retry(&self.pool, self.retry_policy, move |transaction| {
            let scope = scope.clone();
            let request = request.clone();
            Box::pin(
                async move { retire_in_transaction(transaction, &scope, &binding, &request).await },
            )
        })
        .await
    }

    async fn record_contest(&self, contest: &ContestedBindingV1) -> Result<NormativeTransitionV1> {
        let scope = self.trusted_scope.clone();
        let binding = self.registry_binding;
        let contest = contest.clone();
        with_serializable_retry(&self.pool, self.retry_policy, move |transaction| {
            let scope = scope.clone();
            let contest = contest.clone();
            Box::pin(async move {
                contest_in_transaction(transaction, &scope, &binding, &contest).await
            })
        })
        .await
    }

    async fn read_head(
        &self,
        binding_family_id: &ContractId,
    ) -> Result<Option<NormativeHeadRowV1>> {
        let row: Option<PgRow> = sqlx::query(SELECT_HEAD_SQL)
            .bind(self.trusted_scope.tenant_id())
            .bind(self.trusted_scope.project())
            .bind(binding_family_id.as_str())
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref()
            .map(|row| decode_head_row(binding_family_id, row))
            .transpose()
    }

    async fn read_projection(
        &self,
        binding_family_id: &ContractId,
    ) -> Result<Option<NormativeFamilyProjectionV1>> {
        let stored: Option<Vec<u8>> = sqlx::query_scalar(SELECT_PROJECTION_SQL)
            .bind(self.trusted_scope.tenant_id())
            .bind(self.trusted_scope.project())
            .bind(binding_family_id.as_str())
            .fetch_optional(&self.pool)
            .await?;
        stored
            .map(|bytes| decode_projection(binding_family_id, &bytes))
            .transpose()
    }

    async fn read_log(&self, binding_family_id: &ContractId) -> Result<Vec<NormativeLogEntryV1>> {
        let rows: Vec<PgRow> = sqlx::query(SELECT_LOG_SQL)
            .bind(self.trusted_scope.tenant_id())
            .bind(self.trusted_scope.project())
            .bind(binding_family_id.as_str())
            .fetch_all(&self.pool)
            .await?;
        decode_log_rows(&rows)
    }

    async fn rebuild_projection(
        &self,
        binding_family_id: &ContractId,
    ) -> Result<NormativeFamilyProjectionV1> {
        let entries = self.read_log(binding_family_id).await?;
        project_family(binding_family_id, &entries).map_err(FleetError::from)
    }
}

/// Seed (if absent) and lock this family's head row, returning it decoded.
async fn lock_head(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    binding: &NormativeRegistryBindingV1,
    binding_family_id: &ContractId,
    now: DateTime<Utc>,
) -> Result<NormativeHeadRowV1> {
    sqlx::query(SEED_HEAD_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(binding_family_id.as_str())
        .bind(binding.registry_package_digest.as_bytes().to_vec())
        .bind(binding.activation_policy_digest.as_bytes().to_vec())
        .bind(now)
        .execute(&mut **transaction)
        .await?;

    let row: PgRow = sqlx::query(LOCK_HEAD_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(binding_family_id.as_str())
        .fetch_one(&mut **transaction)
        .await?;
    decode_head_row(binding_family_id, &row)
}

/// Read this family's stored projection under the head lock, defaulting to the
/// empty projection when the family has no rows yet.
async fn load_projection(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    binding_family_id: &ContractId,
) -> Result<NormativeFamilyProjectionV1> {
    let stored: Option<Vec<u8>> = sqlx::query_scalar(SELECT_PROJECTION_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(binding_family_id.as_str())
        .fetch_optional(&mut **transaction)
        .await?;
    stored.map_or_else(
        || {
            Ok(NormativeFamilyProjectionV1::empty(
                binding_family_id.clone(),
            ))
        },
        |bytes| decode_projection(binding_family_id, &bytes),
    )
}

#[allow(clippy::too_many_arguments)] // one transaction body; splitting it would hide the ordering.
async fn activate_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    binding: &NormativeRegistryBindingV1,
    binding_family_id: &ContractId,
    candidate: &NormativeActivationCandidateV1,
    admitted: &AdmittedNormativeActivationV1,
    fault: NormativeFaultInjection,
) -> Result<NormativeActivationOutcomeV1> {
    let now = statement_timestamp(transaction).await?;
    let head = lock_head(transaction, scope, binding, binding_family_id, now).await?;

    // THE compare-and-set. The durable composite — binding-family revision
    // (as the binding-set digest), registry package digest, activation policy
    // digest — must equal the proposal's expected composite exactly. A
    // concurrent winner has already changed the binding-set digest, so the
    // loser lands here having written nothing.
    if head.composite_head() != admitted.expected_head {
        return Ok(NormativeActivationOutcomeV1::Lost {
            observed_binding_set_digest: head.active_binding_set_digest,
            observed_head_revision: head.head_revision,
        });
    }

    let projection = load_projection(transaction, scope, binding_family_id).await?;
    if projection.cursor_seq != head.log_seq {
        return Err(FleetError::Memory(
            "normative projection cursor disagrees with its head log sequence".into(),
        ));
    }
    // An incompatible overlap with a live statement this proposal does not
    // explicitly supersede fails closed here, inside the lock, against the
    // durable live set (never against a caller-supplied snapshot).
    require_non_conflicting_against_live(&candidate.proposal, &projection)?;

    let next = commit_record(
        transaction,
        scope,
        binding,
        &head,
        &projection,
        admitted.event_id,
        &admitted.record,
        now,
    )
    .await?;

    if fault == NormativeFaultInjection::AbortAfterWrites {
        // Non-retryable, so with_serializable_retry rolls the transaction back
        // and returns this error rather than replaying: proof that the log
        // append, the head advance and the projection advance are one unit.
        return Err(FleetError::Memory(
            "normative fault injection: abort after writes".into(),
        ));
    }
    Ok(NormativeActivationOutcomeV1::Installed(next))
}

async fn retire_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    binding: &NormativeRegistryBindingV1,
    request: &NormativeLifecycleRequestV1,
) -> Result<NormativeActivationOutcomeV1> {
    let now = statement_timestamp(transaction).await?;
    let head = lock_head(transaction, scope, binding, &request.binding_family_id, now).await?;
    if head.active_binding_set_digest != request.expected_active_binding_set_digest {
        return Ok(NormativeActivationOutcomeV1::Lost {
            observed_binding_set_digest: head.active_binding_set_digest,
            observed_head_revision: head.head_revision,
        });
    }
    let projection = load_projection(transaction, scope, &request.binding_family_id).await?;
    if projection.cursor_seq != head.log_seq {
        return Err(FleetError::Memory(
            "normative projection cursor disagrees with its head log sequence".into(),
        ));
    }
    let (event_id, record) = admit_lifecycle(request, binding, &projection)?;
    let next = commit_record(
        transaction,
        scope,
        binding,
        &head,
        &projection,
        event_id,
        &record,
        now,
    )
    .await?;
    Ok(NormativeActivationOutcomeV1::Installed(next))
}

async fn contest_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    binding: &NormativeRegistryBindingV1,
    contest: &ContestedBindingV1,
) -> Result<NormativeTransitionV1> {
    let now = statement_timestamp(transaction).await?;
    let head = lock_head(transaction, scope, binding, &contest.binding_family_id, now).await?;
    let projection = load_projection(transaction, scope, &contest.binding_family_id).await?;
    if projection.cursor_seq != head.log_seq {
        return Err(FleetError::Memory(
            "normative projection cursor disagrees with its head log sequence".into(),
        ));
    }
    // A contest deliberately does NOT compare-and-set against an expected
    // binding-set digest: a detector must never be unable to record an
    // ambiguity because the head moved while it was deciding. It still advances
    // the head revision and the cursor atomically with its log row.
    let (contested_id, record) = admit_contest(contest, &projection)?;
    commit_record(
        transaction,
        scope,
        binding,
        &head,
        &projection,
        contested_id,
        &record,
        now,
    )
    .await
}

/// Append one record and advance the head and the projection with it — the
/// atomic unit every write path funnels through.
#[allow(clippy::too_many_arguments)] // the whole point is that these move together.
async fn commit_record(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    binding: &NormativeRegistryBindingV1,
    head: &NormativeHeadRowV1,
    projection: &NormativeFamilyProjectionV1,
    record_id: Sha256Digest,
    record: &NormativeLogRecordV1,
    now: DateTime<Utc>,
) -> Result<NormativeTransitionV1> {
    let next_seq = head
        .log_seq
        .checked_add(1)
        .ok_or_else(|| FleetError::Memory("normative log sequence overflow".into()))?;
    if usize::try_from(next_seq).unwrap_or(usize::MAX) > MAX_FAMILY_LOG_ENTRIES {
        return Err(FleetError::Memory(
            "normative binding family log exceeds its bound".into(),
        ));
    }
    let next_revision = head
        .head_revision
        .checked_add(1)
        .ok_or_else(|| FleetError::Memory("normative head revision overflow".into()))?;

    let entry = NormativeLogEntryV1 {
        seq: next_seq,
        record_id,
        record: record.clone(),
    };
    // Fold BEFORE writing: an entry the projection would reject (a supersession
    // whose target is not live, a retirement of an already-retired statement)
    // fails closed here and rolls the whole transaction back.
    let advanced = apply_entry(projection, &entry)?;
    let canonical_projection = advanced.canonical_bytes()?;
    let canonical_record = encode_canonical(record)?;
    let (statement_id, supersedes) = match record {
        NormativeLogRecordV1::Lifecycle { event, .. } => (
            Some(event.statement_id.as_bytes().to_vec()),
            event
                .supersedes_statement_id
                .map(|id| id.as_bytes().to_vec()),
        ),
        NormativeLogRecordV1::Contest { .. } => (None, None),
    };

    sqlx::query(APPEND_LOG_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(advanced.binding_family_id.as_str())
        .bind(seq_as_i64(next_seq)?)
        .bind(record.record_kind())
        .bind(record_id.as_bytes().to_vec())
        .bind(statement_id)
        .bind(supersedes)
        .bind(canonical_record)
        .bind(now)
        .execute(&mut **transaction)
        .await?;

    let live = advanced.live_statement_ids();
    let next_binding_set = active_binding_set_digest(&advanced.binding_family_id, &live);
    let advanced_revision: Option<i64> = sqlx::query_scalar(ADVANCE_HEAD_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(advanced.binding_family_id.as_str())
        .bind(next_binding_set.map(|digest| digest.as_bytes().to_vec()))
        .bind(binding.registry_package_digest.as_bytes().to_vec())
        .bind(binding.activation_policy_digest.as_bytes().to_vec())
        .bind(seq_as_i64(next_revision)?)
        .bind(seq_as_i64(next_seq)?)
        .bind(now)
        .bind(seq_as_i64(head.head_revision)?)
        .bind(
            head.active_binding_set_digest
                .map(|digest| digest.as_bytes().to_vec()),
        )
        .fetch_optional(&mut **transaction)
        .await?;
    if advanced_revision != Some(seq_as_i64(next_revision)?) {
        return Err(FleetError::Memory(
            "exact normative composite-head compare-and-set failed".into(),
        ));
    }

    let cursor: Option<i64> = sqlx::query_scalar(UPSERT_PROJECTION_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(advanced.binding_family_id.as_str())
        .bind(seq_as_i64(next_seq)?)
        .bind(advanced.resolution.as_str())
        .bind(
            advanced
                .resolution
                .active_statement_id()
                .map(|digest| digest.as_bytes().to_vec()),
        )
        .bind(canonical_projection)
        .bind(now)
        .fetch_optional(&mut **transaction)
        .await?;
    if cursor != Some(seq_as_i64(next_seq)?) {
        return Err(FleetError::Memory(
            "normative projection cursor did not advance with its log append".into(),
        ));
    }

    Ok(NormativeTransitionV1 {
        event_id: record_id,
        statement_id: match record {
            NormativeLogRecordV1::Lifecycle { event, .. } => Some(event.statement_id),
            NormativeLogRecordV1::Contest { .. } => None,
        },
        head_revision: next_revision,
        log_seq: next_seq,
        active_binding_set_digest: next_binding_set,
    })
}

async fn statement_timestamp(transaction: &mut Transaction<'_, Postgres>) -> Result<DateTime<Utc>> {
    let now: DateTime<Utc> = sqlx::query_scalar("SELECT pg_catalog.statement_timestamp()")
        .fetch_one(&mut **transaction)
        .await?;
    Ok(now)
}

fn decode_head_row(binding_family_id: &ContractId, row: &PgRow) -> Result<NormativeHeadRowV1> {
    let active: Option<Vec<u8>> = row.try_get("active_binding_set_digest")?;
    let package: Vec<u8> = row.try_get("registry_package_digest")?;
    let policy: Vec<u8> = row.try_get("activation_policy_digest")?;
    let head_revision: i64 = row.try_get("head_revision")?;
    let log_seq: i64 = row.try_get("log_seq")?;
    Ok(NormativeHeadRowV1 {
        binding_family_id: binding_family_id.clone(),
        active_binding_set_digest: active.map(|bytes| digest_from(&bytes)).transpose()?,
        registry_package_digest: digest_from(&package)?,
        activation_policy_digest: digest_from(&policy)?,
        head_revision: seq_from_i64(head_revision)?,
        log_seq: seq_from_i64(log_seq)?,
    })
}

fn decode_log_rows(rows: &[PgRow]) -> Result<Vec<NormativeLogEntryV1>> {
    if rows.len() > MAX_FAMILY_LOG_ENTRIES {
        return Err(FleetError::Memory(
            "normative binding family log exceeds its bound".into(),
        ));
    }
    let mut entries = Vec::with_capacity(rows.len());
    for row in rows {
        let seq: i64 = row.try_get("seq")?;
        let record_id: Vec<u8> = row.try_get("record_id")?;
        let canonical: Vec<u8> = row.try_get("canonical_record")?;
        // decode_strict, not a lenient parse: a stored record whose bytes are
        // not already canonical is corruption and fails closed.
        let record: NormativeLogRecordV1 = decode_strict(&canonical)?;
        entries.push(NormativeLogEntryV1 {
            seq: seq_from_i64(seq)?,
            record_id: digest_from(&record_id)?,
            record,
        });
    }
    Ok(entries)
}

fn decode_projection(
    binding_family_id: &ContractId,
    bytes: &[u8],
) -> Result<NormativeFamilyProjectionV1> {
    let projection: NormativeFamilyProjectionV1 = decode_strict(bytes)?;
    if &projection.binding_family_id != binding_family_id {
        return Err(FleetError::Memory(
            "stored normative projection names a different binding family".into(),
        ));
    }
    Ok(projection)
}

fn digest_from(bytes: &[u8]) -> Result<Sha256Digest> {
    let exact: [u8; 32] = bytes
        .try_into()
        .map_err(|_| FleetError::Memory("stored normative digest is not 32 bytes".into()))?;
    Ok(Sha256Digest::from_bytes(exact))
}

fn seq_as_i64(value: u64) -> Result<i64> {
    i64::try_from(value)
        .map_err(|_| FleetError::Memory("normative sequence exceeds the INT8 column".into()))
}

fn seq_from_i64(value: i64) -> Result<u64> {
    u64::try_from(value)
        .map_err(|_| FleetError::Memory("stored normative sequence is negative".into()))
}

#[cfg(test)]
#[path = "cockroach_tests.rs"]
mod tests;
