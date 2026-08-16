//! `CockroachDB` implementation of the general accepted-event append seam.
//!
//! Every statement below touches only relations `fleet_runtime` holds a grant
//! on (ADR 0002 D2): `memory_evidence_events`, `memory_evidence_shard_heads`,
//! `memory_evidence_quarantine`, and the read-only view
//! `memory_writer_authority_v1`. There is no `memory_control_*` or
//! `memory_registry_*` base-table reference anywhere in this file, which is
//! what lets the runtime append without any privilege on the governance ledger.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::postgres::{PgPool, PgRow};
use sqlx::{Postgres, Row as _, Transaction};

use crate::control_log::TrustedControlScope;
use crate::memory_contracts::bootstrap::{
    AppendPositionV1, BootstrapReceiptDigest, BootstrapReceiptV1, CommittedOffsetV1, EpochId,
    partition_for_epoch,
};
use crate::memory_contracts::canonical::{decode_strict, encode_canonical};
use crate::memory_contracts::common::{
    AuthenticatedProjectScopeV1, CanonicalTimestamp, ContractId, FixedHex32,
};
use crate::memory_contracts::control::derive_append_chain_digest;
use crate::memory_contracts::digest::{
    DigestDomain, Sha256Digest, body_digest, domain_separated_digest,
};
use crate::memory_contracts::evidence::AcceptedEventId;
use crate::memory_contracts::quarantine::{
    BoundedDiagnosticV1, QuarantineReasonV1, QuarantineRecordId, QuarantineRecordV1,
};
use crate::store::cockroach::{RetryPolicy, with_serializable_retry};
use crate::{FleetError, Result};

use super::appendable::{AppendableAcceptedEvent, SemanticIdentityRuleV1};
use super::error::{
    AuthorityUnavailableKind, EvidenceAppendError, EvidenceAppendResult, WitnessMismatchKind,
    integrity,
};
use super::repository::{
    AcceptedEventRepository, AppendOutcome, AppendProjection, ProjectionContext, ShardChainAudit,
    ShardChainDivergence, ShardChainDivergenceKind,
};
use super::witness::{
    ACTIVE_HEAD_STATE, WriterAuthoritySnapshot, WriterAuthorityWitness,
    evidence_genesis_chain_digest, partition_algorithm_label,
};

/// Every authority column the per-transaction fence compares (ADR 0002 D4).
const SELECT_AUTHORITY_FENCE_SQL: &str = "SELECT head_state, generation, activation_id, \
     package_digest, activation_policy_digest, log_epoch_id, partition_recipe_id, \
     partition_recipe_version, partition_algorithm, partition_seed, log_shard_count, \
     contract_tenant_namespace, contract_project_namespace, \
     bootstrap_contract_tenant_namespace, bootstrap_contract_project_namespace \
     FROM public.memory_writer_authority_v1 \
     WHERE tenant_id = $1 AND project = $2 LIMIT 2";

/// The fence columns plus the canonical bootstrap receipt the genesis epoch is
/// decoded from. Used only when materializing a witness, never per append.
const SELECT_AUTHORITY_WITNESS_SQL: &str = "SELECT head_state, generation, activation_id, \
     package_digest, activation_policy_digest, log_epoch_id, partition_recipe_id, \
     partition_recipe_version, partition_algorithm, partition_seed, log_shard_count, \
     contract_tenant_namespace, contract_project_namespace, \
     bootstrap_contract_tenant_namespace, bootstrap_contract_project_namespace, \
     bootstrap_receipt_digest, bootstrap_canonical_receipt \
     FROM public.memory_writer_authority_v1 \
     WHERE tenant_id = $1 AND project = $2 LIMIT 2";

const SEED_SHARD_HEAD_SQL: &str = "INSERT INTO public.memory_evidence_shard_heads (\
     tenant_id, project, epoch_id, shard, shard_count, last_committed_offset, \
     chain_digest, advanced_at\
     ) VALUES ($1, $2, $3, $4, $5, 0, $6, $7) ON CONFLICT DO NOTHING";

const LOCK_SHARD_HEAD_SQL: &str = "SELECT shard_count, last_committed_offset, chain_digest \
     FROM public.memory_evidence_shard_heads \
     WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4 FOR UPDATE";

const READ_SHARD_HEAD_SQL: &str = "SELECT shard_count, last_committed_offset, chain_digest \
     FROM public.memory_evidence_shard_heads \
     WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4";

const SELECT_EVENT_BY_ID_SQL: &str = "SELECT epoch_id, shard, committed_offset, canonical_event \
     FROM public.memory_evidence_events \
     WHERE tenant_id = $1 AND project = $2 AND event_id = $3";

/// Bounded by the primary-key prefix `(tenant, project, epoch, shard)`, so this
/// is a single-shard scan rather than a table scan. A dedicated index on
/// `semantic_object_digest` belongs to the migration owner; see the handoff.
const SELECT_EVENT_BY_SEMANTIC_OBJECT_SQL: &str = "SELECT event_id \
     FROM public.memory_evidence_events \
     WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4 \
       AND semantic_object_digest = $5 AND event_kind = $6 LIMIT 2";

const INSERT_EVENT_SQL: &str = "INSERT INTO public.memory_evidence_events (\
     tenant_id, project, epoch_id, shard, committed_offset, event_id, event_schema_version, \
     event_kind, semantic_object_digest, consistency_family, consistency_key_digest, \
     canonical_event, previous_chain_digest, chain_digest, accepted_at\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)";

const ADVANCE_SHARD_HEAD_SQL: &str = "UPDATE public.memory_evidence_shard_heads \
     SET last_committed_offset = $5, chain_digest = $6, advanced_at = $7 \
     WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4 \
       AND last_committed_offset = $8 AND chain_digest = $9";

const INSERT_QUARANTINE_SQL: &str = "INSERT INTO public.memory_evidence_quarantine (\
     tenant_id, project, quarantine_id, connector_principal_id, connector_instance_id, \
     delivery_id, attempt_count, source_fact_id, representation_key_digest, \
     canonical_payload_digest, diagnostic, reason, received_at\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
     ON CONFLICT (tenant_id, project, quarantine_id) DO NOTHING";

const AUDIT_EVENT_PAGE_SQL: &str = "SELECT committed_offset, event_id, canonical_event, \
     previous_chain_digest, chain_digest FROM public.memory_evidence_events \
     WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4 \
       AND committed_offset > $5 ORDER BY committed_offset LIMIT 256";

const AUDIT_PAGE_ROWS: usize = 256;

/// Private evidence-ledger repository bound once to physical and semantic
/// scope, exactly like the control-log repositories.
#[derive(Clone)]
pub struct CockroachAcceptedEventRepository {
    pool: PgPool,
    trusted_scope: TrustedControlScope,
    retry_policy: RetryPolicy,
}

impl std::fmt::Debug for CockroachAcceptedEventRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CockroachAcceptedEventRepository")
            .field("trusted_scope", &self.trusted_scope)
            .field("retry_policy", &self.retry_policy)
            .finish_non_exhaustive()
    }
}

impl CockroachAcceptedEventRepository {
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

    /// The scope every statement in this repository is bound to.
    #[must_use]
    pub const fn trusted_scope(&self) -> &TrustedControlScope {
        &self.trusted_scope
    }

    /// Materialize a head witness from `memory_writer_authority_v1`.
    ///
    /// This is the interim producer of the [`WriterAuthorityWitness`] seam:
    /// it proves the authority row is internally consistent and that the stored
    /// canonical bootstrap receipt reproduces the row's own receipt digest, but
    /// it does NOT verify descent from the deployment-pinned bootstrap root and
    /// does not consult the `FleetConfig` namespace pins. `W1-HEAD` owns both,
    /// and will supersede this method. The append path never trusts the witness
    /// on its own: it re-reads the same view inside the append transaction.
    pub async fn read_writer_authority_witness(
        &self,
    ) -> EvidenceAppendResult<WriterAuthorityWitness> {
        let rows: Vec<PgRow> = sqlx::query(SELECT_AUTHORITY_WITNESS_SQL)
            .bind(self.trusted_scope.tenant_id())
            .bind(self.trusted_scope.project())
            .fetch_all(&self.pool)
            .await?;
        let row = exactly_one_authority_row(&rows)?;
        let canonical_receipt: Vec<u8> = row.try_get("bootstrap_canonical_receipt")?;
        let receipt_digest = BootstrapReceiptDigest::from_digest(digest32(
            row.try_get("bootstrap_receipt_digest")?,
        )?);
        let receipt: BootstrapReceiptV1 = decode_strict(&canonical_receipt)?;
        if encode_canonical(&receipt)? != canonical_receipt
            || BootstrapReceiptDigest::from_digest(domain_separated_digest(
                DigestDomain::BootstrapReceipt,
                &canonical_receipt,
            )) != receipt_digest
        {
            return Err(EvidenceAppendError::AuthorityUnavailable(
                AuthorityUnavailableKind::UndecodableRow,
            ));
        }
        let fence = decode_authority_fence(row)?;
        WriterAuthorityWitness::from_authority_snapshot(WriterAuthoritySnapshot {
            head_state: fence.head_state,
            generation: fence.generation,
            activation_id: fence.activation_id,
            package_digest: fence.package_digest,
            activation_policy_digest: fence.activation_policy_digest,
            log_epoch_id: fence.log_epoch_id,
            partition_recipe_id: fence.partition_recipe_id,
            partition_recipe_version: fence.partition_recipe_version,
            partition_algorithm: fence.partition_algorithm,
            partition_seed: fence.partition_seed,
            log_shard_count: fence.log_shard_count,
            head_scope: fence.head_scope,
            bootstrap_scope: fence.bootstrap_scope,
            genesis_epoch: receipt.statement.genesis_epoch,
        })
    }
}

/// One append attempt's result inside the retry loop.
///
/// `Rejected` is produced ONLY before any statement has mutated a row, so
/// committing an empty transaction is observationally identical to rolling it
/// back. Every failure after a write returns `Err` instead, which rolls back.
enum AppendAttempt {
    Outcome(AppendOutcome),
    Rejected(EvidenceAppendError),
}

/// Authority columns compared by the in-transaction fence.
struct AuthorityFence {
    head_state: String,
    generation: u64,
    activation_id: Sha256Digest,
    package_digest: Sha256Digest,
    activation_policy_digest: Sha256Digest,
    log_epoch_id: EpochId,
    partition_recipe_id: String,
    partition_recipe_version: u32,
    partition_algorithm: String,
    partition_seed: FixedHex32,
    log_shard_count: u16,
    head_scope: AuthenticatedProjectScopeV1,
    bootstrap_scope: AuthenticatedProjectScopeV1,
}

/// Locked head state for one evidence shard.
struct LockedHead {
    last_committed_offset: u64,
    chain_digest: Sha256Digest,
}

#[async_trait]
impl AcceptedEventRepository for CockroachAcceptedEventRepository {
    async fn append(
        &self,
        witness: &WriterAuthorityWitness,
        appendable: &AppendableAcceptedEvent,
        projection: Arc<dyn AppendProjection>,
    ) -> EvidenceAppendResult<AppendOutcome> {
        if appendable.scope() != self.trusted_scope.semantic_scope() {
            return Err(EvidenceAppendError::StatementAuthority(
                WitnessMismatchKind::ContractNamespaces,
            ));
        }
        if witness.semantic_scope() != self.trusted_scope.semantic_scope() {
            return Err(EvidenceAppendError::WitnessMismatch(
                WitnessMismatchKind::ContractNamespaces,
            ));
        }
        let scope = self.trusted_scope.clone();
        let witness = Arc::new(witness.clone());
        let appendable = Arc::new(appendable.clone());
        let attempt = with_serializable_retry(&self.pool, self.retry_policy, move |transaction| {
            let scope = scope.clone();
            let witness = Arc::clone(&witness);
            let appendable = Arc::clone(&appendable);
            let projection = Arc::clone(&projection);
            Box::pin(async move {
                append_in_transaction(transaction, &scope, &witness, &appendable, &*projection)
                    .await
            })
        })
        .await
        .map_err(storage_or_integrity)?;
        match attempt {
            AppendAttempt::Outcome(outcome) => Ok(outcome),
            AppendAttempt::Rejected(error) => Err(error),
        }
    }

    async fn audit_shard_chain(
        &self,
        epoch_id: EpochId,
        shard: u16,
    ) -> EvidenceAppendResult<ShardChainAudit> {
        let scope = self.trusted_scope.clone();
        with_serializable_retry(&self.pool, self.retry_policy, move |transaction| {
            let scope = scope.clone();
            Box::pin(
                async move { audit_in_transaction(transaction, &scope, epoch_id, shard).await },
            )
        })
        .await
        .map_err(storage_or_integrity)
    }
}

async fn append_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    witness: &WriterAuthorityWitness,
    appendable: &AppendableAcceptedEvent,
    projection: &dyn AppendProjection,
) -> Result<AppendAttempt> {
    // (a) The fence: a plain in-transaction SELECT of the authority view under
    // serializable isolation. There is no separate compare-and-swap and no
    // last-known-head fallback (ADR 0002 D4).
    let fence = match read_authority_fence(transaction, scope).await? {
        Ok(fence) => fence,
        Err(rejection) => return Ok(AppendAttempt::Rejected(rejection)),
    };
    if let Some(mismatch) = fence_mismatch(&fence, witness) {
        return Ok(AppendAttempt::Rejected(
            EvidenceAppendError::WitnessMismatch(mismatch),
        ));
    }

    // (b) Shard selection uses the same recipe the control ledger uses, over
    // (epoch id, canonical scope, consistency family, key digest).
    let epoch_id = witness.epoch_id();
    let shard = partition_for_epoch(witness.genesis_epoch(), appendable.consistency())
        .map_err(FleetError::ControlContract)?;
    let shard_count = witness.shard_count();

    let now: DateTime<Utc> = sqlx::query_scalar("SELECT pg_catalog.statement_timestamp()")
        .fetch_one(&mut **transaction)
        .await?;

    // (c) Lazy seed. A head row is fully determined by (epoch, shard), so this
    // grants no forgeable authority (ADR 0002 D1).
    seed_shard_head(transaction, scope, epoch_id, shard, shard_count, now).await?;

    // (d) Serialize this shard's appenders.
    let locked = lock_shard_head(transaction, scope, epoch_id, shard, shard_count).await?;

    // (e) Replay and integrity classification, strictly before any insert.
    match classify(transaction, scope, appendable, epoch_id, shard).await? {
        Classification::Replay(position) => {
            return Ok(AppendAttempt::Outcome(AppendOutcome::Replayed { position }));
        }
        Classification::Quarantine(reason, message) => {
            let quarantine_id =
                write_quarantine(transaction, scope, appendable, reason, &message, now).await?;
            return Ok(AppendAttempt::Outcome(AppendOutcome::Quarantined {
                quarantine_id,
                reason,
            }));
        }
        Classification::Fresh => {}
    }

    // (f) Append.
    let next_offset = locked
        .last_committed_offset
        .checked_add(1)
        .ok_or_else(|| corrupt("evidence shard offset overflowed INT8"))?;
    let position = AppendPositionV1 {
        epoch_id,
        shard,
        committed_offset: CommittedOffsetV1::new(next_offset).map_err(FleetError::from)?,
    };
    let chain_digest = derive_append_chain_digest(
        locked.chain_digest,
        appendable.accepted_event_id(),
        &position,
    )
    .map_err(FleetError::from)?;
    insert_event(
        transaction,
        scope,
        appendable,
        &position,
        locked.chain_digest,
        chain_digest,
        now,
    )
    .await?;

    // (g) The caller's projection, in this same transaction (EVENT-03).
    projection
        .project(
            transaction,
            ProjectionContext {
                kind: appendable.kind(),
                accepted_event_id: appendable.accepted_event_id(),
                position,
                chain_digest,
            },
        )
        .await
        .map_err(FleetError::from)?;

    // (h) Compare-and-swap the head against the exact locked values.
    advance_shard_head(
        transaction,
        scope,
        epoch_id,
        shard,
        next_offset,
        chain_digest,
        &locked,
        now,
    )
    .await?;

    Ok(AppendAttempt::Outcome(AppendOutcome::Appended {
        position,
        chain_digest,
    }))
}

enum Classification {
    Fresh,
    Replay(AppendPositionV1),
    Quarantine(QuarantineReasonV1, String),
}

async fn classify(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    appendable: &AppendableAcceptedEvent,
    epoch_id: EpochId,
    shard: u16,
) -> Result<Classification> {
    let accepted_event_id = appendable.accepted_event_id();
    let existing: Option<PgRow> = sqlx::query(SELECT_EVENT_BY_ID_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(bytes(accepted_event_id.digest()))
        .fetch_optional(&mut **transaction)
        .await?;
    if let Some(row) = existing {
        let stored_canonical: Vec<u8> = row.try_get("canonical_event")?;
        if stored_canonical == appendable.canonical_event() {
            // EVENT-01: exact replay is a no-op. The projection already
            // committed with the original append, so it is not re-run.
            return Ok(Classification::Replay(stored_position(&row)?));
        }
        // Two different byte strings under one accepted-event ID. The ID is a
        // digest of those very bytes, so this is a stored-ledger tamper or a
        // hash collision, never a legitimate delivery.
        return Ok(Classification::Quarantine(
            QuarantineReasonV1::IntegrityCollision,
            format!(
                "stored canonical event under accepted-event ID {accepted_event_id} \
                 differs from the admitted bytes"
            ),
        ));
    }

    if appendable.semantic_identity_rule() == SemanticIdentityRuleV1::UniquePreimage {
        let rows: Vec<PgRow> = sqlx::query(SELECT_EVENT_BY_SEMANTIC_OBJECT_SQL)
            .bind(scope.tenant_id())
            .bind(scope.project())
            .bind(bytes(epoch_id.digest()))
            .bind(i32::from(shard))
            .bind(bytes(appendable.semantic_object_digest()))
            .bind(appendable.event_kind().as_str())
            .fetch_all(&mut **transaction)
            .await?;
        if let Some(row) = rows.first() {
            let stored_event_id = digest32(row.try_get("event_id")?).map_err(FleetError::from)?;
            // A different accepted-event ID means different canonical bytes by
            // construction, so the same semantic object was asserted twice with
            // disagreeing preimages (EVENT-01).
            return Ok(Classification::Quarantine(
                QuarantineReasonV1::PreimageDisagreement,
                format!(
                    "semantic object {} is already accepted under event ID {stored_event_id}, \
                     which disagrees with admitted event ID {accepted_event_id}",
                    appendable.semantic_object_digest()
                ),
            ));
        }
    }
    Ok(Classification::Fresh)
}

fn stored_position(row: &PgRow) -> Result<AppendPositionV1> {
    let epoch_id =
        EpochId::from_digest(digest32(row.try_get("epoch_id")?).map_err(FleetError::from)?);
    let shard: i32 = row.try_get("shard")?;
    let committed_offset: i64 = row.try_get("committed_offset")?;
    Ok(AppendPositionV1 {
        epoch_id,
        shard: u16::try_from(shard).map_err(|_| corrupt("stored evidence shard exceeds u16"))?,
        committed_offset: CommittedOffsetV1::new(
            u64::try_from(committed_offset)
                .map_err(|_| corrupt("stored evidence offset is negative"))?,
        )
        .map_err(FleetError::from)?,
    })
}

async fn read_authority_fence(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
) -> Result<std::result::Result<AuthorityFence, EvidenceAppendError>> {
    let rows: Vec<PgRow> = sqlx::query(SELECT_AUTHORITY_FENCE_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .fetch_all(&mut **transaction)
        .await?;
    let row = match exactly_one_authority_row(&rows) {
        Ok(row) => row,
        Err(rejection) => return Ok(Err(rejection)),
    };
    match decode_authority_fence(row) {
        Ok(fence) => Ok(Ok(fence)),
        Err(rejection) => Ok(Err(rejection)),
    }
}

fn exactly_one_authority_row(rows: &[PgRow]) -> EvidenceAppendResult<&PgRow> {
    match rows {
        [] => Err(EvidenceAppendError::AuthorityUnavailable(
            AuthorityUnavailableKind::NoRow,
        )),
        [row] => Ok(row),
        _ => Err(EvidenceAppendError::AuthorityUnavailable(
            AuthorityUnavailableKind::AmbiguousRow,
        )),
    }
}

fn decode_authority_fence(row: &PgRow) -> EvidenceAppendResult<AuthorityFence> {
    let head_state: String = row.try_get("head_state")?;
    if head_state != ACTIVE_HEAD_STATE {
        return Err(EvidenceAppendError::AuthorityUnavailable(
            AuthorityUnavailableKind::NotActive,
        ));
    }
    let generation: i64 = row.try_get("generation")?;
    let recipe_version: i32 = row.try_get("partition_recipe_version")?;
    let shard_count: i32 = row.try_get("log_shard_count")?;
    let seed: Vec<u8> = row.try_get("partition_seed")?;
    let seed: [u8; 32] = seed.try_into().map_err(|_| {
        EvidenceAppendError::AuthorityUnavailable(AuthorityUnavailableKind::UndecodableRow)
    })?;
    Ok(AuthorityFence {
        head_state,
        generation: u64::try_from(generation).map_err(|_| {
            EvidenceAppendError::AuthorityUnavailable(AuthorityUnavailableKind::UndecodableRow)
        })?,
        activation_id: digest32(row.try_get("activation_id")?)?,
        package_digest: digest32(row.try_get("package_digest")?)?,
        activation_policy_digest: digest32(row.try_get("activation_policy_digest")?)?,
        log_epoch_id: EpochId::from_digest(digest32(row.try_get("log_epoch_id")?)?),
        partition_recipe_id: row.try_get("partition_recipe_id")?,
        partition_recipe_version: u32::try_from(recipe_version).map_err(|_| {
            EvidenceAppendError::AuthorityUnavailable(AuthorityUnavailableKind::UndecodableRow)
        })?,
        partition_algorithm: row.try_get("partition_algorithm")?,
        partition_seed: FixedHex32::from_bytes(seed),
        log_shard_count: u16::try_from(shard_count).map_err(|_| {
            EvidenceAppendError::AuthorityUnavailable(AuthorityUnavailableKind::UndecodableRow)
        })?,
        head_scope: namespaces(
            row,
            "contract_tenant_namespace",
            "contract_project_namespace",
        )?,
        bootstrap_scope: namespaces(
            row,
            "bootstrap_contract_tenant_namespace",
            "bootstrap_contract_project_namespace",
        )?,
    })
}

fn namespaces(
    row: &PgRow,
    tenant_column: &str,
    project_column: &str,
) -> EvidenceAppendResult<AuthenticatedProjectScopeV1> {
    let tenant: String = row.try_get(tenant_column)?;
    let project: String = row.try_get(project_column)?;
    Ok(AuthenticatedProjectScopeV1::from_trusted_context(
        ContractId::new(tenant)?,
        ContractId::new(project)?,
    ))
}

/// Compare every witnessed authority field against the in-transaction read.
fn fence_mismatch(
    fence: &AuthorityFence,
    witness: &WriterAuthorityWitness,
) -> Option<WitnessMismatchKind> {
    let recipe = witness.partition_recipe();
    if fence.activation_id != witness.head().activation_id {
        return Some(WitnessMismatchKind::ActivationId);
    }
    if fence.generation != witness.generation() {
        return Some(WitnessMismatchKind::Generation);
    }
    if fence.package_digest != witness.head().package_digest {
        return Some(WitnessMismatchKind::PackageDigest);
    }
    if fence.activation_policy_digest != witness.head().activation_policy_digest {
        return Some(WitnessMismatchKind::ActivationPolicyDigest);
    }
    if fence.log_epoch_id != witness.epoch_id() {
        return Some(WitnessMismatchKind::LogEpochId);
    }
    if fence.partition_recipe_id != recipe.recipe_id.as_str()
        || fence.partition_recipe_version != recipe.recipe_version
        || fence.partition_algorithm != partition_algorithm_label(recipe.algorithm)
        || fence.partition_seed != recipe.seed
        || fence.log_shard_count != recipe.shard_count
    {
        return Some(WitnessMismatchKind::PartitionRecipe);
    }
    if &fence.head_scope != witness.semantic_scope()
        || &fence.bootstrap_scope != witness.semantic_scope()
    {
        return Some(WitnessMismatchKind::ContractNamespaces);
    }
    None
}

async fn seed_shard_head(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    epoch_id: EpochId,
    shard: u16,
    shard_count: u16,
    now: DateTime<Utc>,
) -> Result<()> {
    sqlx::query(SEED_SHARD_HEAD_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(bytes(epoch_id.digest()))
        .bind(i32::from(shard))
        .bind(i32::from(shard_count))
        .bind(bytes(evidence_genesis_chain_digest(epoch_id, shard)))
        .bind(now)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn lock_shard_head(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    epoch_id: EpochId,
    shard: u16,
    shard_count: u16,
) -> Result<LockedHead> {
    let row: PgRow = sqlx::query(LOCK_SHARD_HEAD_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(bytes(epoch_id.digest()))
        .bind(i32::from(shard))
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or_else(|| corrupt("evidence shard head vanished after a successful lazy seed"))?;
    let stored_shard_count: i32 = row.try_get("shard_count")?;
    if stored_shard_count != i32::from(shard_count) {
        return Err(corrupt(
            "evidence shard head shard_count disagrees with the activated log epoch",
        ));
    }
    let last_committed_offset: i64 = row.try_get("last_committed_offset")?;
    Ok(LockedHead {
        last_committed_offset: u64::try_from(last_committed_offset)
            .map_err(|_| corrupt("evidence shard head offset is negative"))?,
        chain_digest: digest32(row.try_get("chain_digest")?).map_err(FleetError::from)?,
    })
}

#[allow(clippy::too_many_arguments)] // One physical row; grouping would hide it.
async fn insert_event(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    appendable: &AppendableAcceptedEvent,
    position: &AppendPositionV1,
    previous_chain_digest: Sha256Digest,
    chain_digest: Sha256Digest,
    accepted_at: DateTime<Utc>,
) -> Result<()> {
    let offset = i64::try_from(position.committed_offset.as_u64())
        .map_err(|_| corrupt("evidence offset exceeds INT8"))?;
    let schema_version = i32::try_from(appendable.event_schema_version())
        .map_err(|_| corrupt("accepted event schema version exceeds INT4"))?;
    let result = sqlx::query(INSERT_EVENT_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(bytes(position.epoch_id.digest()))
        .bind(i32::from(position.shard))
        .bind(offset)
        .bind(bytes(appendable.accepted_event_id().digest()))
        .bind(schema_version)
        .bind(appendable.event_kind().as_str())
        .bind(bytes(appendable.semantic_object_digest()))
        .bind(appendable.consistency().family.as_str())
        .bind(bytes(appendable.consistency().key_digest))
        .bind(appendable.canonical_event())
        .bind(bytes(previous_chain_digest))
        .bind(bytes(chain_digest))
        .bind(accepted_at)
        .execute(&mut **transaction)
        .await?;
    if result.rows_affected() != 1 {
        return Err(corrupt(
            "accepted event insert did not affect exactly one row",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)] // Mirrors the exact compare-and-swap row.
async fn advance_shard_head(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    epoch_id: EpochId,
    shard: u16,
    next_offset: u64,
    chain_digest: Sha256Digest,
    locked: &LockedHead,
    advanced_at: DateTime<Utc>,
) -> Result<()> {
    let next = i64::try_from(next_offset).map_err(|_| corrupt("evidence offset exceeds INT8"))?;
    let previous = i64::try_from(locked.last_committed_offset)
        .map_err(|_| corrupt("evidence offset exceeds INT8"))?;
    let result = sqlx::query(ADVANCE_SHARD_HEAD_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(bytes(epoch_id.digest()))
        .bind(i32::from(shard))
        .bind(next)
        .bind(bytes(chain_digest))
        .bind(advanced_at)
        .bind(previous)
        .bind(bytes(locked.chain_digest))
        .execute(&mut **transaction)
        .await?;
    if result.rows_affected() != 1 {
        return Err(corrupt("evidence shard head compare-and-swap failed"));
    }
    Ok(())
}

async fn write_quarantine(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    appendable: &AppendableAcceptedEvent,
    reason: QuarantineReasonV1,
    message: &str,
    received_at: DateTime<Utc>,
) -> Result<QuarantineRecordId> {
    let (Some(identity), Some(delivery)) = (appendable.evidence_identity(), appendable.delivery())
    else {
        // Both quarantine reasons this seam can produce require a source-fact
        // AND a representation identity (W0-QUAR). Only `evidence.accepted`
        // carries them, so a relation or claim divergence under one accepted
        // event ID is a stored-ledger tamper with no valid dead-letter shape:
        // fail closed rather than invent one.
        return Err(corrupt(format!(
            "{} event {} diverges from stored bytes and has no quarantine identity",
            appendable.event_kind(),
            appendable.accepted_event_id()
        )));
    };
    let record = QuarantineRecordV1 {
        schema_version: 1,
        scope: appendable.scope().clone(),
        connector_principal_id: delivery.connector_principal_id.clone(),
        connector_instance_id: delivery.connector_instance_id.clone(),
        transport_delivery_id: delivery.transport_delivery_id.clone(),
        attempt_count: delivery.attempt_count,
        source_fact_id: Some(identity.source_fact_id),
        representation_key: Some(identity.representation_key),
        // Digest-only: the rejected bytes never become a second, ungoverned
        // copy outside retention and erasure (EVID-05, EVID-08).
        canonical_payload_digest: body_digest(appendable.canonical_event()),
        reason,
        diagnostic: BoundedDiagnosticV1 {
            message: bounded_message(message),
            redaction_required: false,
        },
        received_at: CanonicalTimestamp::from_datetime(&received_at).map_err(FleetError::from)?,
    };
    let quarantine_id = record.quarantine_id().map_err(FleetError::from)?;
    let attempt_count = i32::try_from(record.attempt_count)
        .map_err(|_| corrupt("quarantine attempt count exceeds INT4"))?;
    let result = sqlx::query(INSERT_QUARANTINE_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(bytes(quarantine_id.digest()))
        .bind(record.connector_principal_id.as_str())
        .bind(record.connector_instance_id.as_str())
        .bind(hex::encode(record.transport_delivery_id.as_bytes()))
        .bind(attempt_count)
        .bind(record.source_fact_id.map(bytes))
        .bind(record.representation_key.map(bytes))
        .bind(bytes(record.canonical_payload_digest))
        .bind(encode_canonical(&record.diagnostic).map_err(FleetError::from)?)
        .bind(quarantine_reason_label(reason))
        .bind(received_at)
        .execute(&mut **transaction)
        .await?;
    if result.rows_affected() > 1 {
        return Err(corrupt("quarantine insert affected more than one row"));
    }
    Ok(quarantine_id)
}

/// Wire label of one quarantine reason, matching the contract's
/// `rename_all = "snake_case"` serialization. Exhaustive over the closed enum,
/// so a tenth reason is a compile error here.
const fn quarantine_reason_label(reason: QuarantineReasonV1) -> &'static str {
    match reason {
        QuarantineReasonV1::IntegrityCollision => "integrity_collision",
        QuarantineReasonV1::InvalidSignature => "invalid_signature",
        QuarantineReasonV1::UnauthorizedScope => "unauthorized_scope",
        QuarantineReasonV1::UnknownSchema => "unknown_schema",
        QuarantineReasonV1::Oversize => "oversize",
        QuarantineReasonV1::DuplicatePosition => "duplicate_position",
        QuarantineReasonV1::PreimageDisagreement => "preimage_disagreement",
        QuarantineReasonV1::RedactionFailure => "redaction_failure",
        QuarantineReasonV1::UnknownRepresentationVersion => "unknown_representation_version",
    }
}

/// Truncate on a character boundary so the bounded diagnostic stays canonical.
fn bounded_message(message: &str) -> String {
    const LIMIT: usize = 512;
    if message.len() <= LIMIT {
        return message.to_owned();
    }
    let mut end = LIMIT;
    while end > 0 && !message.is_char_boundary(end) {
        end -= 1;
    }
    message[..end].to_owned()
}

async fn audit_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    epoch_id: EpochId,
    shard: u16,
) -> Result<ShardChainAudit> {
    let genesis_chain_digest = evidence_genesis_chain_digest(epoch_id, shard);
    let head: Option<PgRow> = sqlx::query(READ_SHARD_HEAD_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(bytes(epoch_id.digest()))
        .bind(i32::from(shard))
        .fetch_optional(&mut **transaction)
        .await?;
    let Some(head) = head else {
        return Ok(ShardChainAudit {
            epoch_id,
            shard,
            head_offset: 0,
            head_chain_digest: genesis_chain_digest,
            genesis_chain_digest,
            verified_events: 0,
            divergence: Some(ShardChainDivergence {
                committed_offset: 0,
                kind: ShardChainDivergenceKind::MissingHead,
            }),
        });
    };
    let head_offset_raw: i64 = head.try_get("last_committed_offset")?;
    let head_offset = u64::try_from(head_offset_raw)
        .map_err(|_| corrupt("evidence shard head offset is negative"))?;
    let head_chain_digest = digest32(head.try_get("chain_digest")?).map_err(FleetError::from)?;

    let mut running = genesis_chain_digest;
    let mut expected_offset = 0_u64;
    let mut verified_events = 0_u64;
    let mut divergence = None;
    let mut cursor = 0_i64;
    'pages: loop {
        let rows: Vec<PgRow> = sqlx::query(AUDIT_EVENT_PAGE_SQL)
            .bind(scope.tenant_id())
            .bind(scope.project())
            .bind(bytes(epoch_id.digest()))
            .bind(i32::from(shard))
            .bind(cursor)
            .fetch_all(&mut **transaction)
            .await?;
        let page_len = rows.len();
        for row in rows {
            let offset_raw: i64 = row.try_get("committed_offset")?;
            cursor = offset_raw;
            let offset = u64::try_from(offset_raw)
                .map_err(|_| corrupt("evidence event offset is negative"))?;
            expected_offset += 1;
            if offset != expected_offset {
                divergence = Some(ShardChainDivergence {
                    committed_offset: offset,
                    kind: ShardChainDivergenceKind::OffsetGap,
                });
                break 'pages;
            }
            if let Some(kind) = audit_row(&row, running, epoch_id, shard, offset, &mut running)? {
                divergence = Some(ShardChainDivergence {
                    committed_offset: offset,
                    kind,
                });
                break 'pages;
            }
            verified_events += 1;
        }
        if page_len < AUDIT_PAGE_ROWS {
            break;
        }
    }

    if divergence.is_none() {
        if expected_offset != head_offset {
            divergence = Some(ShardChainDivergence {
                committed_offset: head_offset,
                kind: ShardChainDivergenceKind::HeadOffsetMismatch,
            });
        } else if running != head_chain_digest {
            divergence = Some(ShardChainDivergence {
                committed_offset: head_offset,
                kind: ShardChainDivergenceKind::HeadChainMismatch,
            });
        }
    }

    Ok(ShardChainAudit {
        epoch_id,
        shard,
        head_offset,
        head_chain_digest,
        genesis_chain_digest,
        verified_events,
        divergence,
    })
}

/// Re-derive one stored row. Returns the first divergence kind it finds and,
/// when the row reproduces, advances `running` to its chain digest.
fn audit_row(
    row: &PgRow,
    previous: Sha256Digest,
    epoch_id: EpochId,
    shard: u16,
    offset: u64,
    running: &mut Sha256Digest,
) -> Result<Option<ShardChainDivergenceKind>> {
    let stored_event_id =
        AcceptedEventId::from_digest(digest32(row.try_get("event_id")?).map_err(FleetError::from)?);
    let canonical_event: Vec<u8> = row.try_get("canonical_event")?;
    let stored_previous =
        digest32(row.try_get("previous_chain_digest")?).map_err(FleetError::from)?;
    let stored_chain = digest32(row.try_get("chain_digest")?).map_err(FleetError::from)?;

    // The accepted-event ID is a digest of the very bytes stored beside it.
    let derived_event_id = AcceptedEventId::from_digest(domain_separated_digest(
        DigestDomain::AcceptedEvent,
        &canonical_event,
    ));
    if derived_event_id != stored_event_id {
        return Ok(Some(ShardChainDivergenceKind::EventIdMismatch));
    }
    if stored_previous != previous {
        return Ok(Some(ShardChainDivergenceKind::PreviousChainMismatch));
    }
    let position = AppendPositionV1 {
        epoch_id,
        shard,
        committed_offset: CommittedOffsetV1::new(offset).map_err(FleetError::from)?,
    };
    let derived_chain = derive_append_chain_digest(previous, stored_event_id, &position)
        .map_err(FleetError::from)?;
    if derived_chain != stored_chain {
        return Ok(Some(ShardChainDivergenceKind::ChainDigestMismatch));
    }
    *running = derived_chain;
    Ok(None)
}

fn corrupt(message: impl Into<String>) -> FleetError {
    FleetError::ControlLogCorrupt(message.into())
}

fn storage_or_integrity(error: FleetError) -> EvidenceAppendError {
    match error {
        FleetError::ControlLogCorrupt(message) => integrity(message),
        other => EvidenceAppendError::Storage(other),
    }
}

fn bytes(digest: Sha256Digest) -> Vec<u8> {
    digest.as_bytes().to_vec()
}

fn digest32(value: Vec<u8>) -> EvidenceAppendResult<Sha256Digest> {
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| integrity("stored digest column is not 32 bytes"))?;
    Ok(Sha256Digest::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_statement_stays_inside_the_runtime_grant_boundary() {
        for statement in [
            SELECT_AUTHORITY_FENCE_SQL,
            SELECT_AUTHORITY_WITNESS_SQL,
            SEED_SHARD_HEAD_SQL,
            LOCK_SHARD_HEAD_SQL,
            READ_SHARD_HEAD_SQL,
            SELECT_EVENT_BY_ID_SQL,
            SELECT_EVENT_BY_SEMANTIC_OBJECT_SQL,
            INSERT_EVENT_SQL,
            ADVANCE_SHARD_HEAD_SQL,
            INSERT_QUARANTINE_SQL,
            AUDIT_EVENT_PAGE_SQL,
        ] {
            for forbidden in ["memory_control_", "memory_registry_"] {
                assert!(
                    !statement.contains(forbidden),
                    "evidence append SQL referenced a governance relation: {statement}"
                );
            }
        }
    }

    #[test]
    fn the_accepted_envelope_is_never_updated_or_deleted() {
        for statement in [
            SEED_SHARD_HEAD_SQL,
            LOCK_SHARD_HEAD_SQL,
            READ_SHARD_HEAD_SQL,
            SELECT_EVENT_BY_ID_SQL,
            SELECT_EVENT_BY_SEMANTIC_OBJECT_SQL,
            INSERT_EVENT_SQL,
            ADVANCE_SHARD_HEAD_SQL,
            INSERT_QUARANTINE_SQL,
            AUDIT_EVENT_PAGE_SQL,
        ] {
            assert!(!statement.contains("DELETE"));
        }
        assert!(!INSERT_EVENT_SQL.contains("UPDATE"));
        assert!(ADVANCE_SHARD_HEAD_SQL.contains("public.memory_evidence_shard_heads"));
        assert!(LOCK_SHARD_HEAD_SQL.contains("FOR UPDATE"));
        assert!(SELECT_AUTHORITY_FENCE_SQL.contains("LIMIT 2"));
        assert!(!SELECT_AUTHORITY_FENCE_SQL.contains("FOR UPDATE"));
        assert!(ADVANCE_SHARD_HEAD_SQL.contains("AND last_committed_offset = $8"));
        assert!(ADVANCE_SHARD_HEAD_SQL.contains("AND chain_digest = $9"));
    }

    #[test]
    fn quarantine_reason_labels_match_the_contract_wire_form() {
        for (reason, label) in [
            (
                QuarantineReasonV1::IntegrityCollision,
                "integrity_collision",
            ),
            (
                QuarantineReasonV1::PreimageDisagreement,
                "preimage_disagreement",
            ),
            (QuarantineReasonV1::RedactionFailure, "redaction_failure"),
        ] {
            assert_eq!(
                serde_json::to_string(&reason).unwrap(),
                format!("\"{label}\"")
            );
            assert_eq!(quarantine_reason_label(reason), label);
        }
    }

    #[test]
    fn bounded_message_truncates_on_a_character_boundary() {
        let long = "é".repeat(400);
        let bounded = bounded_message(&long);
        assert!(bounded.len() <= 512);
        assert!(long.starts_with(&bounded));
        assert_eq!(bounded_message("short"), "short");
    }
}
