//! `CockroachDB` acceptance of the single pinned genesis control event.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::postgres::{PgPool, PgRow};
use sqlx::{Postgres, QueryBuilder, Row, Transaction};

use super::{
    GenesisBootstrapInspection, GenesisBootstrapOutcome, GenesisInspection, GenesisRepository,
    TrustedControlScope,
};
use crate::memory_contracts::ContractResult;
use crate::memory_contracts::bootstrap::{
    AppendPositionV1, BootstrapReceiptV1, CommittedOffsetV1, IntegrityCheckedBootstrapReceipt,
    VerifiedBootstrapReceipt, audit_untrusted_bootstrap_integrity, derive_genesis_chain_digest,
    partition_for_epoch,
};
use crate::memory_contracts::canonical::{decode_strict, encode_canonical, require_canonical};
use crate::memory_contracts::common::{ContractId, frozen_profile_reference_v1};
use crate::memory_contracts::control::{
    GenesisBootstrapAppendV1, GenesisBootstrapEventV1, derive_append_chain_digest,
};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::genesis::SemanticallyClosedGenesisPackage;
use crate::memory_contracts::registry::ManifestVerifiedRegistryPackage;
use crate::store::cockroach::{RetryPolicy, with_serializable_retry};
use crate::{FleetError, Result};

const CONTROL_EVENT_SCHEMA_VERSION: i32 = 1;
const CONTROL_EVENT_KIND: &str = "control.bootstrap.accepted";
const CONTROL_CONSISTENCY_FAMILY: &str = "control.bootstrap";
const PARTITION_RECIPE_ID: &str = "ostk.partition.sha256_prefix64_modulo";
const PARTITION_RECIPE_VERSION: i32 = 1;
const PARTITION_ALGORITHM: &str = "sha256_prefix64_modulo";
const INSERT_BOOTSTRAP_RESERVATION_SQL: &str = "INSERT INTO memory_control_bootstraps (\
         tenant_id, project, contract_tenant_namespace, contract_project_namespace, \
         receipt_digest, statement_id, bootstrap_event_id, profile_id, profile_digest, \
         vector_manifest_digest, genesis_registry_package_digest, signer_policy_digest, \
         signer_count, approval_threshold, epoch_id, shard_count, bootstrap_shard, \
         bootstrap_offset, canonical_receipt, canonical_genesis_package, accepted_at\
     ) VALUES (\
         $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, \
         $15, $16, $17, 1, $18, $19, $20\
     ) ON CONFLICT (tenant_id, project) DO NOTHING RETURNING receipt_digest";
const ADVANCE_SELECTED_HEAD_SQL: &str = "UPDATE memory_control_shard_heads \
     SET last_committed_offset = 1, chain_digest = $5, advanced_at = $7 \
     WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4 \
       AND last_committed_offset = 0 AND chain_digest = $6";
const BOUNDED_HEAD_SET_SQL: &str = "SELECT shard, shard_count, last_committed_offset, chain_digest, advanced_at \
     FROM memory_control_shard_heads \
     WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 \
     ORDER BY shard LIMIT $4";

/// Private control repository bound once to physical and semantic scope.
#[derive(Clone)]
pub struct CockroachGenesisRepository {
    pool: PgPool,
    trusted_scope: TrustedControlScope,
    retry_policy: RetryPolicy,
}

impl std::fmt::Debug for CockroachGenesisRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CockroachGenesisRepository")
            .field("trusted_scope", &self.trusted_scope)
            .field("retry_policy", &self.retry_policy)
            .finish_non_exhaustive()
    }
}

impl CockroachGenesisRepository {
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
}

#[derive(Clone)]
struct PreparedGenesis {
    append: GenesisBootstrapAppendV1,
    canonical_receipt: Vec<u8>,
    canonical_package: Vec<u8>,
    canonical_epoch: Vec<u8>,
    canonical_event: Vec<u8>,
    genesis_heads: Vec<(i32, Sha256Digest)>,
    signer_count: i32,
    approval_threshold: i32,
    shard_count: i32,
    partition_seed: [u8; 32],
}

/// Integrity-checked persisted Stage-2 authority and its immutable append.
///
/// This proves only the bootstrap prefix. Later repository stages own the
/// validity of any suffix and may advance the current shard heads.
pub struct DurableGenesisWitness {
    prepared: PreparedGenesis,
    bootstrap: IntegrityCheckedBootstrapReceipt,
    package: SemanticallyClosedGenesisPackage,
    bootstrap_accepted_at: DateTime<Utc>,
}

impl DurableGenesisWitness {
    pub const fn bootstrap(&self) -> &IntegrityCheckedBootstrapReceipt {
        &self.bootstrap
    }

    pub const fn package(&self) -> &SemanticallyClosedGenesisPackage {
        &self.package
    }

    pub const fn bootstrap_append(&self) -> &GenesisBootstrapAppendV1 {
        &self.prepared.append
    }

    pub fn genesis_heads(&self) -> &[(i32, Sha256Digest)] {
        &self.prepared.genesis_heads
    }

    pub const fn bootstrap_accepted_at(&self) -> DateTime<Utc> {
        self.bootstrap_accepted_at
    }

    fn inspection(&self) -> Result<GenesisBootstrapInspection> {
        self.prepared.inspection()
    }

    fn ensure_exact_candidate(&self, candidate: &PreparedGenesis) -> Result<()> {
        if self.prepared.canonical_receipt != candidate.canonical_receipt
            || self.prepared.canonical_package != candidate.canonical_package
            || self.prepared.append != candidate.append
            || self.prepared.canonical_epoch != candidate.canonical_epoch
            || self.prepared.canonical_event != candidate.canonical_event
            || self.prepared.genesis_heads != candidate.genesis_heads
        {
            return Err(corrupt(
                "stored bootstrap digest matches but canonical authority bytes differ",
            ));
        }
        Ok(())
    }
}

impl PreparedGenesis {
    fn build(
        trusted_scope: &TrustedControlScope,
        bootstrap: &VerifiedBootstrapReceipt,
        package: &SemanticallyClosedGenesisPackage,
    ) -> Result<Self> {
        let statement = &bootstrap.receipt().statement;
        statement.profile.require_frozen_runtime_profile()?;
        if &statement.scope != trusted_scope.semantic_scope() {
            return Err(FleetError::InvalidScope(
                "bootstrap receipt scope does not match deployment-bound control scope".into(),
            ));
        }
        let append = GenesisBootstrapAppendV1::from_verified(bootstrap, package)?;
        let canonical_event = encode_canonical(&append.event)?;
        let epoch = &statement.genesis_epoch;
        let shard_count = i32::from(epoch.partition_recipe.shard_count);
        let signer_count = i32::try_from(statement.signer_policy.signers.len()).map_err(|_| {
            FleetError::ControlLogCorrupt("bootstrap signer count exceeds INT4".into())
        })?;
        let approval_threshold = i32::from(statement.signer_policy.threshold);
        let mut genesis_heads = Vec::with_capacity(usize::from(epoch.partition_recipe.shard_count));
        for shard in 0..epoch.partition_recipe.shard_count {
            genesis_heads.push((i32::from(shard), bootstrap.genesis_chain_digest(shard)?));
        }
        Ok(Self {
            append,
            canonical_receipt: bootstrap.canonical_bytes().to_vec(),
            canonical_package: package.canonical_bytes().to_vec(),
            canonical_epoch: encode_canonical(epoch)?,
            canonical_event,
            genesis_heads,
            signer_count,
            approval_threshold,
            shard_count,
            partition_seed: *epoch.partition_recipe.seed.as_bytes(),
        })
    }

    fn inspection(&self) -> Result<GenesisBootstrapInspection> {
        Ok(GenesisBootstrapInspection {
            receipt_digest: self.append.event.bootstrap_receipt_digest,
            epoch_id: self.append.append_position.epoch_id,
            accepted_event_id: self.append.accepted_event_id,
            shard_count: u16::try_from(self.shard_count).map_err(|_| {
                FleetError::ControlLogCorrupt("stored shard count exceeds u16".into())
            })?,
            head_count: u16::try_from(self.genesis_heads.len()).map_err(|_| {
                FleetError::ControlLogCorrupt("stored head count exceeds u16".into())
            })?,
            event_shard: self.append.append_position.shard,
            committed_offset: self.append.append_position.committed_offset,
        })
    }
}

fn corrupt(message: impl Into<String>) -> FleetError {
    FleetError::ControlLogCorrupt(message.into())
}

fn conflict(message: impl Into<String>) -> FleetError {
    FleetError::GenesisBootstrapConflict(message.into())
}

fn bytes(digest: Sha256Digest) -> Vec<u8> {
    digest.as_bytes().to_vec()
}

#[async_trait]
impl GenesisRepository for CockroachGenesisRepository {
    async fn bootstrap_genesis(
        &self,
        bootstrap: &VerifiedBootstrapReceipt,
        package: &SemanticallyClosedGenesisPackage,
    ) -> Result<GenesisBootstrapOutcome> {
        let prepared = Arc::new(PreparedGenesis::build(
            &self.trusted_scope,
            bootstrap,
            package,
        )?);
        let scope = self.trusted_scope.clone();
        let pool = self.pool.clone();
        let policy = self.retry_policy;

        with_serializable_retry(&pool, policy, move |transaction| {
            let scope = scope.clone();
            let prepared = Arc::clone(&prepared);
            Box::pin(async move {
                if let Some(inspection) =
                    inspect_in_transaction(transaction, &scope, &prepared).await?
                {
                    return Ok(GenesisBootstrapOutcome::ExactReplay(inspection));
                }

                let accepted_at: DateTime<Utc> = sqlx::query_scalar("SELECT statement_timestamp()")
                    .fetch_one(&mut **transaction)
                    .await?;

                let reservation =
                    insert_bootstrap_reservation(transaction, &scope, &prepared, accepted_at)
                        .await?;
                if !reservation {
                    let inspection = inspect_in_transaction(transaction, &scope, &prepared)
                        .await?
                        .ok_or_else(|| {
                            corrupt("bootstrap reservation was lost without a visible winner")
                        })?;
                    return Ok(GenesisBootstrapOutcome::ExactReplay(inspection));
                }

                insert_epoch(transaction, &scope, &prepared, accepted_at).await?;
                insert_genesis_heads(transaction, &scope, &prepared, accepted_at).await?;
                insert_bootstrap_event(transaction, &scope, &prepared, accepted_at).await?;
                advance_selected_head(transaction, &scope, &prepared, accepted_at).await?;

                Ok(GenesisBootstrapOutcome::Inserted(prepared.inspection()?))
            })
        })
        .await
    }

    async fn inspect_genesis(
        &self,
        bootstrap: &VerifiedBootstrapReceipt,
        package: &SemanticallyClosedGenesisPackage,
    ) -> Result<GenesisInspection> {
        let prepared = Arc::new(PreparedGenesis::build(
            &self.trusted_scope,
            bootstrap,
            package,
        )?);
        let scope = self.trusted_scope.clone();
        let pool = self.pool.clone();
        let policy = self.retry_policy;
        with_serializable_retry(&pool, policy, move |transaction| {
            let scope = scope.clone();
            let prepared = Arc::clone(&prepared);
            Box::pin(async move {
                Ok(inspect_in_transaction(transaction, &scope, &prepared)
                    .await?
                    .map_or(GenesisInspection::Absent, GenesisInspection::Complete))
            })
        })
        .await
    }
}

async fn insert_bootstrap_reservation(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    prepared: &PreparedGenesis,
    accepted_at: DateTime<Utc>,
) -> Result<bool> {
    let event = &prepared.append.event;
    let row = sqlx::query_scalar::<_, Vec<u8>>(INSERT_BOOTSTRAP_RESERVATION_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(scope.semantic_scope().tenant_namespace.as_str())
        .bind(scope.semantic_scope().project_namespace.as_str())
        .bind(bytes(event.bootstrap_receipt_digest.digest()))
        .bind(bytes(event.bootstrap_statement_id.digest()))
        .bind(bytes(prepared.append.accepted_event_id.digest()))
        .bind(event.profile.profile_id.as_str())
        .bind(bytes(event.profile.profile_digest))
        .bind(bytes(event.profile.vector_manifest_digest))
        .bind(bytes(event.genesis_registry_package_digest))
        .bind(bytes(event.signer_policy_digest))
        .bind(prepared.signer_count)
        .bind(prepared.approval_threshold)
        .bind(bytes(event.genesis_epoch_id.digest()))
        .bind(prepared.shard_count)
        .bind(i32::from(prepared.append.append_position.shard))
        .bind(&prepared.canonical_receipt)
        .bind(&prepared.canonical_package)
        .bind(accepted_at)
        .fetch_optional(&mut **transaction)
        .await?;
    Ok(row.is_some())
}

async fn insert_epoch(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    prepared: &PreparedGenesis,
    accepted_at: DateTime<Utc>,
) -> Result<()> {
    let event = &prepared.append.event;
    let result = sqlx::query(
        "INSERT INTO memory_control_log_epochs (\
             tenant_id, project, epoch_id, bootstrap_receipt_digest, canonical_epoch, \
             partition_recipe_id, partition_recipe_version, partition_algorithm, \
             partition_seed, shard_count, created_at\
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
    )
    .bind(scope.tenant_id())
    .bind(scope.project())
    .bind(bytes(event.genesis_epoch_id.digest()))
    .bind(bytes(event.bootstrap_receipt_digest.digest()))
    .bind(&prepared.canonical_epoch)
    .bind(PARTITION_RECIPE_ID)
    .bind(PARTITION_RECIPE_VERSION)
    .bind(PARTITION_ALGORITHM)
    .bind(prepared.partition_seed.to_vec())
    .bind(prepared.shard_count)
    .bind(accepted_at)
    .execute(&mut **transaction)
    .await?;
    if result.rows_affected() != 1 {
        return Err(corrupt(
            "genesis epoch insert did not affect exactly one row",
        ));
    }
    Ok(())
}

async fn insert_genesis_heads(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    prepared: &PreparedGenesis,
    accepted_at: DateTime<Utc>,
) -> Result<()> {
    let mut builder = QueryBuilder::<Postgres>::new(
        "INSERT INTO memory_control_shard_heads (\
             tenant_id, project, epoch_id, shard, shard_count, last_committed_offset, chain_digest, advanced_at\
         ) ",
    );
    builder.push_values(&prepared.genesis_heads, |mut row, (shard, digest)| {
        row.push_bind(scope.tenant_id())
            .push_bind(scope.project())
            .push_bind(bytes(prepared.append.event.genesis_epoch_id.digest()))
            .push_bind(*shard)
            .push_bind(prepared.shard_count)
            .push_bind(0_i64)
            .push_bind(bytes(*digest))
            .push_bind(accepted_at);
    });
    let result = builder.build().execute(&mut **transaction).await?;
    if result.rows_affected() != u64::try_from(prepared.genesis_heads.len()).unwrap_or(u64::MAX) {
        return Err(corrupt(
            "genesis head insert count does not match shard count",
        ));
    }
    Ok(())
}

async fn insert_bootstrap_event(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    prepared: &PreparedGenesis,
    accepted_at: DateTime<Utc>,
) -> Result<()> {
    let append = &prepared.append;
    let offset = i64::try_from(append.append_position.committed_offset.as_u64())
        .map_err(|_| corrupt("bootstrap offset exceeds INT8"))?;
    let result = sqlx::query(
        "INSERT INTO memory_control_events (\
             tenant_id, project, epoch_id, shard, committed_offset, event_id, \
             event_schema_version, event_kind, semantic_object_digest, consistency_family, \
             consistency_key_digest, canonical_event, previous_chain_digest, chain_digest, accepted_at\
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)",
    )
    .bind(scope.tenant_id())
    .bind(scope.project())
    .bind(bytes(append.append_position.epoch_id.digest()))
    .bind(i32::from(append.append_position.shard))
    .bind(offset)
    .bind(bytes(append.accepted_event_id.digest()))
    .bind(CONTROL_EVENT_SCHEMA_VERSION)
    .bind(CONTROL_EVENT_KIND)
    .bind(bytes(append.event.bootstrap_receipt_digest.digest()))
    .bind(CONTROL_CONSISTENCY_FAMILY)
    .bind(bytes(append.consistency_partition_key.key_digest))
    .bind(&prepared.canonical_event)
    .bind(bytes(append.previous_chain_digest))
    .bind(bytes(append.append_chain_digest))
    .bind(accepted_at)
    .execute(&mut **transaction)
    .await?;
    if result.rows_affected() != 1 {
        return Err(corrupt(
            "bootstrap event insert did not affect exactly one row",
        ));
    }
    Ok(())
}

async fn advance_selected_head(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    prepared: &PreparedGenesis,
    accepted_at: DateTime<Utc>,
) -> Result<()> {
    let append = &prepared.append;
    let result = sqlx::query(ADVANCE_SELECTED_HEAD_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(bytes(append.append_position.epoch_id.digest()))
        .bind(i32::from(append.append_position.shard))
        .bind(bytes(append.append_chain_digest))
        .bind(bytes(append.previous_chain_digest))
        .bind(accepted_at)
        .execute(&mut **transaction)
        .await?;
    if result.rows_affected() != 1 {
        return Err(corrupt("bootstrap head compare-and-swap failed"));
    }
    Ok(())
}

async fn inspect_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    prepared: &PreparedGenesis,
) -> Result<Option<GenesisBootstrapInspection>> {
    let Some(witness) = load_durable_genesis_witness(transaction, scope).await? else {
        return Ok(None);
    };

    if witness.prepared.append.event.bootstrap_receipt_digest
        != prepared.append.event.bootstrap_receipt_digest
    {
        return Err(conflict(
            "the physical tenant/project already has another complete, integrity-checked bootstrap artifact",
        ));
    }
    witness.ensure_exact_candidate(prepared)?;
    Ok(Some(witness.inspection()?))
}

/// Load and audit the exact durable Stage-2 prefix inside the caller's
/// transaction. This does not authenticate or interpret any later suffix.
pub async fn load_durable_genesis_witness(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
) -> Result<Option<DurableGenesisWitness>> {
    let bootstrap = sqlx::query(
        "SELECT contract_tenant_namespace, contract_project_namespace, receipt_digest, \
                statement_id, bootstrap_event_id, profile_id, profile_digest, \
                vector_manifest_digest, genesis_registry_package_digest, signer_policy_digest, \
                signer_count, approval_threshold, epoch_id, shard_count, bootstrap_shard, \
                bootstrap_offset, canonical_receipt, canonical_genesis_package, accepted_at \
         FROM memory_control_bootstraps WHERE tenant_id = $1 AND project = $2",
    )
    .bind(scope.tenant_id())
    .bind(scope.project())
    .fetch_optional(&mut **transaction)
    .await?;
    let Some(bootstrap) = bootstrap else {
        ensure_no_orphan_control_rows(transaction, scope).await?;
        return Ok(None);
    };

    let bootstrap_accepted_at: DateTime<Utc> = bootstrap.try_get("accepted_at")?;
    let witness = prepare_stored_genesis(&bootstrap, scope, bootstrap_accepted_at)?;
    ensure_complete_genesis_prefix(transaction, scope, &bootstrap, &witness).await?;
    Ok(Some(witness))
}

async fn ensure_no_orphan_control_rows(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
) -> Result<()> {
    let has_children: bool = sqlx::query_scalar(
        "SELECT \
             EXISTS (SELECT 1 FROM memory_control_log_epochs \
                     WHERE tenant_id = $1 AND project = $2) \
          OR EXISTS (SELECT 1 FROM memory_control_shard_heads \
                     WHERE tenant_id = $1 AND project = $2) \
          OR EXISTS (SELECT 1 FROM memory_control_events \
                     WHERE tenant_id = $1 AND project = $2)",
    )
    .bind(scope.tenant_id())
    .bind(scope.project())
    .fetch_one(&mut **transaction)
    .await?;
    if has_children {
        return Err(corrupt(
            "control-ledger rows exist without the bootstrap singleton",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // One bounded reconstruction audits every stored authority field.
fn prepare_stored_genesis(
    row: &PgRow,
    scope: &TrustedControlScope,
    bootstrap_accepted_at: DateTime<Utc>,
) -> Result<DurableGenesisWitness> {
    let canonical_receipt: Vec<u8> = row.try_get("canonical_receipt")?;
    let canonical_package: Vec<u8> = row.try_get("canonical_genesis_package")?;
    let receipt_digest = digest_from_stored_bytes(row.try_get("receipt_digest")?, "receipt")?;

    require_canonical(&canonical_receipt).map_err(|error| {
        corrupt(format!(
            "stored bootstrap receipt is not canonical: {error}"
        ))
    })?;
    let receipt: BootstrapReceiptV1 = decode_strict(&canonical_receipt)
        .map_err(|error| corrupt(format!("stored bootstrap receipt is invalid: {error}")))?;
    let profile = frozen_profile_reference_v1();
    if receipt.statement.profile != profile {
        return Err(corrupt(
            "stored bootstrap names a profile this binary does not implement",
        ));
    }
    let manifest = ManifestVerifiedRegistryPackage::decode(&canonical_package, &profile)
        .map_err(|error| corrupt(format!("stored genesis package is invalid: {error}")))?;
    let package = SemanticallyClosedGenesisPackage::from_manifest_verified(manifest)
        .map_err(|error| corrupt(format!("stored genesis package is not closed: {error}")))?;
    let checked = audit_untrusted_bootstrap_integrity(
        &canonical_receipt,
        &profile,
        scope.semantic_scope(),
        &package,
    )
    .map_err(|error| {
        corrupt(format!(
            "stored bootstrap integrity proof is invalid: {error}"
        ))
    })?;
    if checked.receipt_digest().digest() != receipt_digest {
        return Err(corrupt(
            "stored canonical receipt does not match its persisted digest",
        ));
    }

    let statement = &checked.receipt().statement;
    let event = GenesisBootstrapEventV1 {
        schema_version: 1,
        event_kind: stored_contract(ContractId::new(CONTROL_EVENT_KIND))?,
        profile: statement.profile.clone(),
        scope: statement.scope.clone(),
        genesis_registry_package_digest: package.package_digest(),
        bootstrap_statement_id: checked.statement_id(),
        bootstrap_receipt_digest: checked.receipt_digest(),
        signer_policy_digest: statement.signer_policy_digest,
        genesis_epoch_id: checked.epoch_id(),
    };
    let accepted_event_id = stored_contract(event.accepted_event_id())?;
    let consistency_partition_key = stored_contract(event.consistency_partition_key())?;
    let canonical_event = stored_contract(encode_canonical(&event))?;
    let epoch = &statement.genesis_epoch;
    let shard = stored_contract(partition_for_epoch(epoch, &consistency_partition_key))?;
    let append_position = AppendPositionV1 {
        epoch_id: checked.epoch_id(),
        shard,
        committed_offset: stored_contract(CommittedOffsetV1::new(1))?,
    };
    let previous_chain_digest = stored_contract(derive_genesis_chain_digest(
        checked.receipt_digest(),
        checked.epoch_id(),
        shard,
        epoch.partition_recipe.shard_count,
    ))?;
    let append_chain_digest = stored_contract(derive_append_chain_digest(
        previous_chain_digest,
        accepted_event_id,
        &append_position,
    ))?;
    let append = GenesisBootstrapAppendV1 {
        schema_version: 1,
        event,
        accepted_event_id,
        consistency_partition_key,
        append_position,
        previous_chain_digest,
        append_chain_digest,
    };
    let mut genesis_heads = Vec::with_capacity(usize::from(epoch.partition_recipe.shard_count));
    for head_shard in 0..epoch.partition_recipe.shard_count {
        let chain_digest = stored_contract(derive_genesis_chain_digest(
            checked.receipt_digest(),
            checked.epoch_id(),
            head_shard,
            epoch.partition_recipe.shard_count,
        ))?;
        genesis_heads.push((i32::from(head_shard), chain_digest));
    }
    let prepared = PreparedGenesis {
        append,
        canonical_receipt: checked.canonical_bytes().to_vec(),
        canonical_package: package.canonical_bytes().to_vec(),
        canonical_epoch: stored_contract(encode_canonical(epoch))?,
        canonical_event,
        genesis_heads,
        signer_count: i32::try_from(statement.signer_policy.signers.len())
            .map_err(|_| corrupt("stored signer count exceeds INT4"))?,
        approval_threshold: i32::from(statement.signer_policy.threshold),
        shard_count: i32::from(epoch.partition_recipe.shard_count),
        partition_seed: *epoch.partition_recipe.seed.as_bytes(),
    };
    Ok(DurableGenesisWitness {
        prepared,
        bootstrap: checked,
        package,
        bootstrap_accepted_at,
    })
}

fn stored_contract<T>(outcome: ContractResult<T>) -> Result<T> {
    outcome.map_err(|error| corrupt(format!("stored bootstrap contract mismatch: {error}")))
}

fn digest_from_stored_bytes(bytes: Vec<u8>, field: &str) -> Result<Sha256Digest> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| corrupt(format!("stored {field} digest has the wrong length")))?;
    Ok(Sha256Digest::from_bytes(bytes))
}

async fn ensure_complete_genesis_prefix(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    bootstrap: &PgRow,
    witness: &DurableGenesisWitness,
) -> Result<()> {
    let prepared = &witness.prepared;
    ensure_bootstrap_matches(bootstrap, scope, prepared)?;
    ensure_epoch_matches(transaction, scope, prepared, witness.bootstrap_accepted_at).await?;
    ensure_event_matches(transaction, scope, prepared, witness.bootstrap_accepted_at).await?;
    ensure_heads_cover_prefix(transaction, scope, prepared, witness.bootstrap_accepted_at).await
}

fn ensure_bootstrap_matches(
    row: &PgRow,
    scope: &TrustedControlScope,
    prepared: &PreparedGenesis,
) -> Result<()> {
    let event = &prepared.append.event;
    let stored_receipt: Vec<u8> = row.try_get("receipt_digest")?;
    let stored_canonical_receipt: Vec<u8> = row.try_get("canonical_receipt")?;
    let stored_package: Vec<u8> = row.try_get("canonical_genesis_package")?;
    if stored_receipt != bytes(event.bootstrap_receipt_digest.digest()) {
        return Err(corrupt(
            "stored receipt digest changed during genesis inspection",
        ));
    }
    if stored_canonical_receipt != prepared.canonical_receipt
        || stored_package != prepared.canonical_package
    {
        return Err(corrupt(
            "stored bootstrap digest matches but canonical authority bytes differ",
        ));
    }

    expect_text(
        row,
        "contract_tenant_namespace",
        scope.semantic_scope().tenant_namespace.as_str(),
    )?;
    expect_text(
        row,
        "contract_project_namespace",
        scope.semantic_scope().project_namespace.as_str(),
    )?;
    expect_bytes(row, "statement_id", event.bootstrap_statement_id.digest())?;
    expect_bytes(
        row,
        "bootstrap_event_id",
        prepared.append.accepted_event_id.digest(),
    )?;
    expect_text(row, "profile_id", event.profile.profile_id.as_str())?;
    expect_bytes(row, "profile_digest", event.profile.profile_digest)?;
    expect_bytes(
        row,
        "vector_manifest_digest",
        event.profile.vector_manifest_digest,
    )?;
    expect_bytes(
        row,
        "genesis_registry_package_digest",
        event.genesis_registry_package_digest,
    )?;
    expect_bytes(row, "signer_policy_digest", event.signer_policy_digest)?;
    expect_i32(row, "signer_count", prepared.signer_count)?;
    expect_i32(row, "approval_threshold", prepared.approval_threshold)?;
    expect_bytes(row, "epoch_id", event.genesis_epoch_id.digest())?;
    expect_i32(row, "shard_count", prepared.shard_count)?;
    expect_i32(
        row,
        "bootstrap_shard",
        i32::from(prepared.append.append_position.shard),
    )?;
    let offset = i64::try_from(prepared.append.append_position.committed_offset.as_u64())
        .map_err(|_| corrupt("bootstrap offset exceeds INT8"))?;
    expect_i64(row, "bootstrap_offset", offset)
}

async fn ensure_epoch_matches(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    prepared: &PreparedGenesis,
    bootstrap_accepted_at: DateTime<Utc>,
) -> Result<()> {
    let row = sqlx::query(
        "SELECT bootstrap_receipt_digest, canonical_epoch, partition_recipe_id, \
                partition_recipe_version, partition_algorithm, partition_seed, shard_count, \
                created_at \
         FROM memory_control_log_epochs \
         WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3",
    )
    .bind(scope.tenant_id())
    .bind(scope.project())
    .bind(bytes(prepared.append.event.genesis_epoch_id.digest()))
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| corrupt("genesis epoch row is missing"))?;

    expect_bytes(
        &row,
        "bootstrap_receipt_digest",
        prepared.append.event.bootstrap_receipt_digest.digest(),
    )?;
    let canonical_epoch: Vec<u8> = row.try_get("canonical_epoch")?;
    if canonical_epoch != prepared.canonical_epoch {
        return Err(corrupt("stored canonical genesis epoch does not match"));
    }
    expect_text(&row, "partition_recipe_id", PARTITION_RECIPE_ID)?;
    expect_i32(&row, "partition_recipe_version", PARTITION_RECIPE_VERSION)?;
    expect_text(&row, "partition_algorithm", PARTITION_ALGORITHM)?;
    let seed: Vec<u8> = row.try_get("partition_seed")?;
    if seed != prepared.partition_seed {
        return Err(corrupt("stored partition seed does not match"));
    }
    expect_i32(&row, "shard_count", prepared.shard_count)?;
    let created_at: DateTime<Utc> = row.try_get("created_at")?;
    if created_at != bootstrap_accepted_at {
        return Err(corrupt(
            "genesis epoch timestamp differs from bootstrap acceptance",
        ));
    }
    Ok(())
}

async fn ensure_event_matches(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    prepared: &PreparedGenesis,
    bootstrap_accepted_at: DateTime<Utc>,
) -> Result<()> {
    let append = &prepared.append;
    let offset = i64::try_from(append.append_position.committed_offset.as_u64())
        .map_err(|_| corrupt("bootstrap offset exceeds INT8"))?;
    let row = sqlx::query(
        "SELECT event_id, event_schema_version, event_kind, semantic_object_digest, \
                consistency_family, consistency_key_digest, canonical_event, \
                previous_chain_digest, chain_digest, accepted_at \
         FROM memory_control_events \
         WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 \
           AND shard = $4 AND committed_offset = $5",
    )
    .bind(scope.tenant_id())
    .bind(scope.project())
    .bind(bytes(append.append_position.epoch_id.digest()))
    .bind(i32::from(append.append_position.shard))
    .bind(offset)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| corrupt("bootstrap control event is missing"))?;

    let event_accepted_at: DateTime<Utc> = row.try_get("accepted_at")?;
    if event_accepted_at != bootstrap_accepted_at {
        return Err(corrupt(
            "bootstrap singleton and accepted control event timestamps differ",
        ));
    }

    expect_bytes(&row, "event_id", append.accepted_event_id.digest())?;
    expect_i32(&row, "event_schema_version", CONTROL_EVENT_SCHEMA_VERSION)?;
    expect_text(&row, "event_kind", CONTROL_EVENT_KIND)?;
    expect_bytes(
        &row,
        "semantic_object_digest",
        append.event.bootstrap_receipt_digest.digest(),
    )?;
    expect_text(&row, "consistency_family", CONTROL_CONSISTENCY_FAMILY)?;
    expect_bytes(
        &row,
        "consistency_key_digest",
        append.consistency_partition_key.key_digest,
    )?;
    let canonical_event: Vec<u8> = row.try_get("canonical_event")?;
    if canonical_event != prepared.canonical_event {
        return Err(corrupt("stored canonical bootstrap event does not match"));
    }
    expect_bytes(&row, "previous_chain_digest", append.previous_chain_digest)?;
    expect_bytes(&row, "chain_digest", append.append_chain_digest)
}

async fn ensure_heads_cover_prefix(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    prepared: &PreparedGenesis,
    bootstrap_accepted_at: DateTime<Utc>,
) -> Result<()> {
    let row_limit = i64::from(prepared.shard_count)
        .checked_add(1)
        .ok_or_else(|| corrupt("stored shard-head audit limit overflowed INT8"))?;
    let rows = sqlx::query(BOUNDED_HEAD_SET_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(bytes(prepared.append.event.genesis_epoch_id.digest()))
        .bind(row_limit)
        .fetch_all(&mut **transaction)
        .await?;
    if rows.len() != prepared.genesis_heads.len() {
        return Err(corrupt("genesis shard-head set is incomplete"));
    }
    let selected = usize::from(prepared.append.append_position.shard);
    let bootstrap_offset = i64::try_from(prepared.append.append_position.committed_offset.as_u64())
        .map_err(|_| corrupt("bootstrap offset exceeds INT8"))?;
    for (expected_shard, row) in rows.iter().enumerate() {
        expect_i32(
            row,
            "shard",
            i32::try_from(expected_shard).map_err(|_| corrupt("stored shard exceeds INT4"))?,
        )?;
        expect_i32(row, "shard_count", prepared.shard_count)?;
        let prefix_offset = if expected_shard == selected {
            bootstrap_offset
        } else {
            0
        };
        let current_offset: i64 = row.try_get("last_committed_offset")?;
        if current_offset < prefix_offset {
            return Err(corrupt(format!(
                "stored shard {expected_shard} head precedes the durable bootstrap prefix"
            )));
        }
        if current_offset == prefix_offset {
            let prefix_chain = if expected_shard == selected {
                prepared.append.append_chain_digest
            } else {
                prepared.genesis_heads[expected_shard].1
            };
            expect_bytes(row, "chain_digest", prefix_chain)?;
            let advanced_at: DateTime<Utc> = row.try_get("advanced_at")?;
            if advanced_at != bootstrap_accepted_at {
                return Err(corrupt(format!(
                    "stored shard {expected_shard} prefix timestamp does not match bootstrap acceptance"
                )));
            }
        } else {
            digest_from_stored_bytes(row.try_get("chain_digest")?, "advanced head chain")?;
        }
    }
    Ok(())
}

fn expect_bytes(row: &PgRow, column: &str, expected: Sha256Digest) -> Result<()> {
    let actual: Vec<u8> = row.try_get(column)?;
    if actual != expected.as_bytes() {
        return Err(corrupt(format!("stored {column} does not match")));
    }
    Ok(())
}

fn expect_text(row: &PgRow, column: &str, expected: &str) -> Result<()> {
    let actual: String = row.try_get(column)?;
    if actual != expected {
        return Err(corrupt(format!("stored {column} does not match")));
    }
    Ok(())
}

fn expect_i32(row: &PgRow, column: &str, expected: i32) -> Result<()> {
    let actual: i32 = row.try_get(column)?;
    if actual != expected {
        return Err(corrupt(format!("stored {column} does not match")));
    }
    Ok(())
}

fn expect_i64(row: &PgRow, column: &str, expected: i64) -> Result<()> {
    let actual: i64 = row.try_get(column)?;
    if actual != expected {
        return Err(corrupt(format!("stored {column} does not match")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_reservation_is_insert_only_and_head_advance_is_cas_bounded() {
        assert!(INSERT_BOOTSTRAP_RESERVATION_SQL.contains("ON CONFLICT"));
        assert!(INSERT_BOOTSTRAP_RESERVATION_SQL.contains("DO NOTHING"));
        assert!(!INSERT_BOOTSTRAP_RESERVATION_SQL.contains("DO UPDATE"));
        assert!(INSERT_BOOTSTRAP_RESERVATION_SQL.contains("$20"));
        assert!(!INSERT_BOOTSTRAP_RESERVATION_SQL.contains("$21"));

        assert!(ADVANCE_SELECTED_HEAD_SQL.starts_with("UPDATE memory_control_shard_heads"));
        assert!(ADVANCE_SELECTED_HEAD_SQL.contains("last_committed_offset = 0"));
        assert!(ADVANCE_SELECTED_HEAD_SQL.contains("chain_digest = $6"));
        assert!(ADVANCE_SELECTED_HEAD_SQL.contains("advanced_at = $7"));
        assert!(!ADVANCE_SELECTED_HEAD_SQL.contains("now()"));
        assert!(!ADVANCE_SELECTED_HEAD_SQL.contains("memory_control_events"));
    }

    #[test]
    fn durable_prefix_head_probe_is_bounded_by_the_persisted_shard_count() {
        assert!(BOUNDED_HEAD_SET_SQL.contains("LIMIT $4"));
        assert!(!BOUNDED_HEAD_SET_SQL.contains("count("));
    }
}
