//! `CockroachDB` acceptance of the first active registry head.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::postgres::{PgPool, PgRow};
use sqlx::{Postgres, Row, Transaction};

use super::genesis_audit::{self, AuditedGenesisRoot};
use super::{
    AcceptedGenesisActivation, GenesisActivationInspection, GenesisActivationOutcome,
    GenesisActivationRepository, PinnedInactiveGenesis,
};
use crate::control_log::{
    DurableGenesisWitness, TrustedControlScope, load_durable_genesis_witness,
};
use crate::error::{GenesisActivationConflictKind, GenesisActivationTimingKind};
use crate::memory_contracts::ContractResult;
use crate::memory_contracts::bootstrap::{
    AppendPositionV1, CommittedOffsetV1, EpochId, VerifiedBootstrapReceipt,
};
use crate::memory_contracts::canonical::{decode_strict, encode_canonical, require_canonical};
use crate::memory_contracts::common::{CanonicalTimestamp, frozen_profile_reference_v1};
use crate::memory_contracts::control::{GenesisBootstrapAppendV1, derive_append_chain_digest};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::evidence_v2::RegistryHeadBindingV1;
use crate::memory_contracts::genesis::SemanticallyClosedGenesisPackage;
use crate::memory_contracts::genesis_activation::{
    GenesisActivationPrincipalBinding, GenesisRegistryActivatedEventV1,
    GenesisRegistryActivationId, GenesisRegistryActivationReceiptV1,
    GenesisRegistryActivationStatementId, VerifiedGenesisRegistryActivationRequest,
    VerifiedRegistryTestResult, registry_activation_consistency_partition_key,
    verify_genesis_registry_activation,
};
use crate::memory_contracts::registry::{RegistryEntryKind, RegistryHeadV1};
use crate::store::cockroach::{RetryPolicy, with_serializable_retry};
use crate::{FleetError, Result};

const ACTIVATION_EVENT_SCHEMA_VERSION: i32 = 1;
const ACTIVATION_EVENT_KIND: &str = "registry.genesis.activated";
const ACTIVATION_CONSISTENCY_FAMILY: &str = "registry.activation";
const ACTIVE_HEAD_STATE: &str = "active";
const REQUIRE_ACTIVATION_SCHEMA_SQL: &str = "SELECT count(*) = 9 \
     AND COALESCE(bool_and(success), false) \
     FROM _sqlx_migrations WHERE version BETWEEN 1 AND 9";
const SELECT_REGISTRY_STREAM_PREFIX_SQL: &str = "SELECT event_id, shard, committed_offset \
     FROM memory_control_events \
     WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 \
       AND consistency_family = $4 AND consistency_key_digest = $5 \
     ORDER BY shard, committed_offset LIMIT 2";
const SELECT_REGISTRY_STREAM_TIP_SQL: &str = "SELECT event_id, shard, committed_offset \
     FROM memory_control_events \
     WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 \
       AND consistency_family = $4 AND consistency_key_digest = $5 \
     ORDER BY shard DESC, committed_offset DESC LIMIT 2";
const SELECT_ACTIVATION_IDS_SQL: &str = "SELECT activation_id FROM memory_registry_activations \
     WHERE tenant_id = $1 AND project = $2 ORDER BY activation_id LIMIT 2";
const SELECT_EVENT_AHEAD_OF_HEAD_SQL: &str = "SELECT event_id FROM memory_control_events \
     WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4 \
       AND committed_offset > $5 ORDER BY committed_offset LIMIT 1";

const SELECT_STATEMENT_SQL: &str = "SELECT activation_id, statement_id, \
     bootstrap_statement_id, bootstrap_receipt_digest, bootstrap_event_id, genesis_epoch_id, \
     genesis_package_digest, bootstrap_signer_policy_digest, profile_id, profile_digest, \
     vector_manifest_digest, contract_tenant_namespace, contract_project_namespace, \
     activated_package_digest, activated_policy_digest, test_result_digest, \
     proposer_principal_id, package_author_principal_id, approval_ids_packed, approval_count, \
     required_threshold, separation_of_duty_satisfied, bootstrap_accepted_at, effective_from, \
     effective_until, accepted_at, accepted_event_id, control_epoch_id, control_shard, \
     control_committed_offset, canonical_statement, canonical_approval_set, \
     canonical_test_result, canonical_receipt, canonical_event \
     FROM memory_registry_activations \
     WHERE tenant_id = $1 AND project = $2 AND statement_id = $3";

const SELECT_ACTIVATION_ID_SQL: &str = "SELECT activation_id, statement_id, \
     bootstrap_statement_id, bootstrap_receipt_digest, bootstrap_event_id, genesis_epoch_id, \
     genesis_package_digest, bootstrap_signer_policy_digest, profile_id, profile_digest, \
     vector_manifest_digest, contract_tenant_namespace, contract_project_namespace, \
     activated_package_digest, activated_policy_digest, test_result_digest, \
     proposer_principal_id, package_author_principal_id, approval_ids_packed, approval_count, \
     required_threshold, separation_of_duty_satisfied, bootstrap_accepted_at, effective_from, \
     effective_until, accepted_at, accepted_event_id, control_epoch_id, control_shard, \
     control_committed_offset, canonical_statement, canonical_approval_set, \
     canonical_test_result, canonical_receipt, canonical_event \
     FROM memory_registry_activations \
     WHERE tenant_id = $1 AND project = $2 AND activation_id = $3";

const LOCK_CONTROL_HEAD_SQL: &str = "SELECT shard_count, last_committed_offset, chain_digest, advanced_at \
     FROM memory_control_shard_heads \
     WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4 FOR UPDATE";

const INSERT_CONTROL_EVENT_SQL: &str = "INSERT INTO memory_control_events (\
     tenant_id, project, epoch_id, shard, committed_offset, event_id, event_schema_version, \
     event_kind, semantic_object_digest, consistency_family, consistency_key_digest, \
     canonical_event, previous_chain_digest, chain_digest, accepted_at\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) \
     ON CONFLICT DO NOTHING RETURNING event_id";

const INSERT_ACTIVATION_SQL: &str = "INSERT INTO memory_registry_activations (\
     tenant_id, project, activation_id, statement_id, bootstrap_statement_id, \
     bootstrap_receipt_digest, bootstrap_event_id, genesis_epoch_id, genesis_package_digest, \
     bootstrap_signer_policy_digest, profile_id, profile_digest, vector_manifest_digest, \
     contract_tenant_namespace, contract_project_namespace, activated_package_digest, \
     activated_policy_digest, test_result_digest, proposer_principal_id, \
     package_author_principal_id, approval_ids_packed, approval_count, required_threshold, \
     separation_of_duty_satisfied, bootstrap_accepted_at, effective_from, effective_until, \
     accepted_at, accepted_event_id, control_epoch_id, control_shard, control_committed_offset, \
     canonical_statement, canonical_approval_set, canonical_test_result, canonical_receipt, \
     canonical_event\
     ) VALUES (\
     $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, \
     $18, $19, $20, $21, $22, $23, true, $24, $25, NULL, $26, $27, $28, $29, $30, \
     $31, $32, $33, $34, $35\
     ) ON CONFLICT DO NOTHING RETURNING activation_id";

const INSERT_REGISTRY_HEAD_SQL: &str = "INSERT INTO memory_registry_heads (\
     tenant_id, project, head_state, activation_id, package_digest, activation_policy_digest, \
     source_event_id, source_epoch_id, source_shard, source_committed_offset, activated_at, \
     canonical_head\
     ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) \
     ON CONFLICT DO NOTHING RETURNING activation_id";

const ADVANCE_CONTROL_HEAD_SQL: &str = "UPDATE memory_control_shard_heads \
     SET last_committed_offset = $5, chain_digest = $6, advanced_at = $7 \
     WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4 \
       AND last_committed_offset = $8 AND chain_digest = $9 \
     RETURNING last_committed_offset, chain_digest";

/// Private activation repository bound to one deployment and authority set.
#[derive(Clone)]
pub struct CockroachGenesisActivationRepository {
    pool: PgPool,
    trusted_scope: TrustedControlScope,
    retry_policy: RetryPolicy,
    authority: Arc<BoundActivationAuthority>,
}

impl std::fmt::Debug for CockroachGenesisActivationRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CockroachGenesisActivationRepository")
            .field("trusted_scope", &self.trusted_scope)
            .field("retry_policy", &self.retry_policy)
            .finish_non_exhaustive()
    }
}

pub(super) struct BoundActivationAuthority {
    pub(super) bootstrap: VerifiedBootstrapReceipt,
    pub(super) package: SemanticallyClosedGenesisPackage,
    pub(super) test_result: VerifiedRegistryTestResult,
    pub(super) principal_binding: GenesisActivationPrincipalBinding,
    pub(super) bootstrap_append: GenesisBootstrapAppendV1,
}

impl BoundActivationAuthority {
    pub(super) fn from_trusted_config(
        trusted_scope: &TrustedControlScope,
        bootstrap: VerifiedBootstrapReceipt,
        package: SemanticallyClosedGenesisPackage,
        test_result: VerifiedRegistryTestResult,
        principal_binding: GenesisActivationPrincipalBinding,
    ) -> Result<Self> {
        let statement = &bootstrap.receipt().statement;
        let frozen_profile = frozen_profile_reference_v1();
        statement.profile.require_frozen_runtime_profile()?;
        if &statement.scope != trusted_scope.semantic_scope() {
            return Err(FleetError::InvalidScope(
                "bootstrap authority scope does not match the repository scope".into(),
            ));
        }
        let bootstrap_append = GenesisBootstrapAppendV1::from_verified(&bootstrap, &package)?;
        if statement.profile != frozen_profile
            || package.manifest_verified_package().package().profile != frozen_profile
            || test_result.result().profile != frozen_profile
            || test_result.result().package_digest != package.package_digest()
        {
            return Err(FleetError::GenesisActivationConflict(
                GenesisActivationConflictKind::BoundAuthority,
            ));
        }
        Ok(Self {
            bootstrap,
            package,
            test_result,
            principal_binding,
            bootstrap_append,
        })
    }
}

impl CockroachGenesisActivationRepository {
    pub fn new(
        pool: PgPool,
        trusted_scope: TrustedControlScope,
        retry_policy: RetryPolicy,
        bootstrap: VerifiedBootstrapReceipt,
        package: SemanticallyClosedGenesisPackage,
        test_result: VerifiedRegistryTestResult,
        principal_binding: GenesisActivationPrincipalBinding,
    ) -> Result<Self> {
        let authority = BoundActivationAuthority::from_trusted_config(
            &trusted_scope,
            bootstrap,
            package,
            test_result,
            principal_binding,
        )?;
        Ok(Self {
            pool,
            trusted_scope,
            retry_policy,
            authority: Arc::new(authority),
        })
    }

    fn prepare_request(
        &self,
        request: &VerifiedGenesisRegistryActivationRequest,
    ) -> Result<PreparedActivation> {
        if &request.statement().scope != self.trusted_scope.semantic_scope() {
            return Err(FleetError::InvalidScope(
                "activation request scope does not match the repository scope".into(),
            ));
        }
        request
            .statement()
            .profile
            .require_frozen_runtime_profile()?;
        request
            .test_result()
            .result()
            .profile
            .require_frozen_runtime_profile()?;
        let verified = verify_genesis_registry_activation(
            request.canonical_statement(),
            request.canonical_approval_set(),
            &self.authority.bootstrap,
            &self.authority.package,
            &self.authority.test_result,
            &self.authority.principal_binding,
        )
        .map_err(|_| {
            FleetError::GenesisActivationConflict(GenesisActivationConflictKind::BoundAuthority)
        })?;
        if verified.statement() != request.statement()
            || verified.approval_set() != request.approval_set()
            || verified.eligible_approvals() != request.eligible_approvals()
            || verified.required_threshold() != request.required_threshold()
            || verified.test_result().canonical_bytes() != request.test_result().canonical_bytes()
        {
            return Err(FleetError::GenesisActivationConflict(
                GenesisActivationConflictKind::BoundAuthority,
            ));
        }
        PreparedActivation::new(verified)
    }
}

#[derive(Clone)]
struct PreparedActivation {
    verified: VerifiedGenesisRegistryActivationRequest,
    statement_id: GenesisRegistryActivationStatementId,
    approval_ids_packed: Vec<u8>,
    approval_count: i32,
    required_threshold: i32,
}

impl PreparedActivation {
    fn new(verified: VerifiedGenesisRegistryActivationRequest) -> Result<Self> {
        let statement_id = verified.statement().statement_id()?;
        let approval_count = i32::try_from(verified.eligible_approvals().len())
            .map_err(|_| corrupt("eligible approval count exceeds INT4"))?;
        let required_threshold = i32::from(verified.required_threshold());
        let mut approval_ids_packed =
            Vec::with_capacity(verified.eligible_approvals().len().saturating_mul(32));
        for approval in verified.eligible_approvals() {
            approval_ids_packed.extend_from_slice(approval.attestation_id.as_bytes());
        }
        Ok(Self {
            verified,
            statement_id,
            approval_ids_packed,
            approval_count,
            required_threshold,
        })
    }
}

struct LockedControlHead {
    shard: u16,
    committed_offset: i64,
    chain_digest: Sha256Digest,
    advanced_at: DateTime<Utc>,
}

struct AcceptedActivation {
    receipt: GenesisRegistryActivationReceiptV1,
    event: GenesisRegistryActivatedEventV1,
    registry_head: RegistryHeadV1,
    activation_id: GenesisRegistryActivationId,
    accepted_event_id: crate::memory_contracts::evidence::AcceptedEventId,
    append_position: AppendPositionV1,
    previous_chain_digest: Sha256Digest,
    append_chain_digest: Sha256Digest,
    canonical_receipt: Vec<u8>,
    canonical_event: Vec<u8>,
    canonical_head: Vec<u8>,
    accepted_at_database: DateTime<Utc>,
    effective_from_database: DateTime<Utc>,
}

impl AcceptedActivation {
    fn inspection(&self) -> AcceptedGenesisActivation {
        AcceptedGenesisActivation {
            statement_id: self.receipt.statement_id,
            activation_id: self.activation_id,
            accepted_event_id: self.accepted_event_id,
            registry_head: self.registry_head.clone(),
            append_position: self.append_position,
            bootstrap_receipt_digest: self.receipt.expected_anchor.bootstrap_receipt_digest,
            effective_from: self.event.effective_from.clone(),
            accepted_at: self.receipt.accepted_at.clone(),
        }
    }
}

fn corrupt(message: impl Into<String>) -> FleetError {
    FleetError::RegistryActivationCorrupt(message.into())
}

fn stored_contract<T>(outcome: ContractResult<T>) -> Result<T> {
    outcome.map_err(|error| corrupt(format!("stored activation contract mismatch: {error}")))
}

fn require_genesis_only_head(
    current_activation_id: Sha256Digest,
    genesis_activation_id: GenesisRegistryActivationId,
) -> Result<()> {
    if current_activation_id != genesis_activation_id.digest() {
        return Err(corrupt(
            "genesis-only schema has a different current registry activation",
        ));
    }
    Ok(())
}

fn bytes(digest: Sha256Digest) -> Vec<u8> {
    digest.as_bytes().to_vec()
}

#[async_trait]
impl GenesisActivationRepository for CockroachGenesisActivationRepository {
    async fn activate_genesis(
        &self,
        request: &VerifiedGenesisRegistryActivationRequest,
    ) -> Result<GenesisActivationOutcome> {
        let prepared = Arc::new(self.prepare_request(request)?);
        let scope = self.trusted_scope.clone();
        let authority = Arc::clone(&self.authority);
        let pool = self.pool.clone();
        let policy = self.retry_policy;
        with_serializable_retry(&pool, policy, move |transaction| {
            let prepared = Arc::clone(&prepared);
            let scope = scope.clone();
            let authority = Arc::clone(&authority);
            Box::pin(async move {
                activate_in_transaction(transaction, &scope, &authority, &prepared).await
            })
        })
        .await
    }

    async fn inspect_genesis_activation(
        &self,
        request: &VerifiedGenesisRegistryActivationRequest,
    ) -> Result<GenesisActivationInspection> {
        let prepared = Arc::new(self.prepare_request(request)?);
        let scope = self.trusted_scope.clone();
        let authority = Arc::clone(&self.authority);
        let pool = self.pool.clone();
        let policy = self.retry_policy;
        with_serializable_retry(&pool, policy, move |transaction| {
            let prepared = Arc::clone(&prepared);
            let scope = scope.clone();
            let authority = Arc::clone(&authority);
            Box::pin(async move {
                inspect_in_transaction(transaction, &scope, &authority, &prepared).await
            })
        })
        .await
    }
}

async fn activate_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    authority: &BoundActivationAuthority,
    prepared: &PreparedActivation,
) -> Result<GenesisActivationOutcome> {
    require_activation_schema(transaction).await?;
    if let Some(row) = select_by_statement(transaction, scope, prepared.statement_id).await? {
        let witness = require_bound_witness(transaction, scope, authority).await?;
        let stored = audit_stored_activation(transaction, scope, authority, &witness, &row).await?;
        return classify_same_statement(prepared, stored)
            .map(GenesisActivationOutcome::ExactReplay);
    }

    let witness = require_bound_witness(transaction, scope, authority).await?;
    require_not_before_bootstrap(prepared, &witness)?;
    let consistency_key = registry_activation_consistency_partition_key(scope.semantic_scope())?;
    let shard = authority.bootstrap.partition_for(&consistency_key)?;
    let locked = lock_control_head(transaction, scope, authority, shard).await?;

    // The stable scope-local stream lock serializes both identical requests and
    // distinct proposals before any accepted timestamp is chosen.
    if let Some(row) = select_by_statement(transaction, scope, prepared.statement_id).await? {
        let stored = audit_stored_activation(transaction, scope, authority, &witness, &row).await?;
        return classify_same_statement(prepared, stored)
            .map(GenesisActivationOutcome::ExactReplay);
    }
    if let Some(head) = select_registry_head(transaction, scope).await? {
        let stored =
            load_and_audit_head_activation(transaction, scope, authority, &witness, &head).await?;
        if stored.inspection.statement_id == prepared.statement_id {
            return classify_same_statement(prepared, stored)
                .map(GenesisActivationOutcome::ExactReplay);
        }
        return Err(FleetError::GenesisActivationStale);
    }

    require_pinned_inactive_tail(transaction, scope, &witness, &locked).await?;
    let accepted_at_database: DateTime<Utc> = sqlx::query_scalar("SELECT statement_timestamp()")
        .fetch_one(&mut **transaction)
        .await?;
    if accepted_at_database < locked.advanced_at {
        return Err(corrupt(
            "registry activation acceptance time precedes the locked control tail",
        ));
    }
    let accepted = materialize_accepted(prepared, &witness, &locked, accepted_at_database)?;

    insert_control_event(transaction, scope, &accepted).await?;
    insert_activation(transaction, scope, prepared, &witness, &accepted).await?;
    insert_registry_head(transaction, scope, &accepted).await?;
    advance_control_head(transaction, scope, &locked, &accepted).await?;

    Ok(GenesisActivationOutcome::Inserted(accepted.inspection()))
}

async fn inspect_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    authority: &BoundActivationAuthority,
    prepared: &PreparedActivation,
) -> Result<GenesisActivationInspection> {
    require_activation_schema(transaction).await?;
    if let Some(row) = select_by_statement(transaction, scope, prepared.statement_id).await? {
        let witness = require_bound_witness(transaction, scope, authority).await?;
        let stored = audit_stored_activation(transaction, scope, authority, &witness, &row).await?;
        return classify_same_statement(prepared, stored)
            .map(GenesisActivationInspection::Accepted);
    }

    let witness = require_bound_witness(transaction, scope, authority).await?;
    require_not_before_bootstrap(prepared, &witness)?;
    if let Some(head) = select_registry_head(transaction, scope).await? {
        let stored =
            load_and_audit_head_activation(transaction, scope, authority, &witness, &head).await?;
        if stored.inspection.statement_id == prepared.statement_id {
            return classify_same_statement(prepared, stored)
                .map(GenesisActivationInspection::Accepted);
        }
        return Err(FleetError::GenesisActivationStale);
    }

    let consistency_key = registry_activation_consistency_partition_key(scope.semantic_scope())?;
    let shard = authority.bootstrap.partition_for(&consistency_key)?;
    let current = read_control_head(transaction, scope, authority, shard, false).await?;
    require_pinned_inactive_tail(transaction, scope, &witness, &current).await?;
    Ok(GenesisActivationInspection::PinnedInactive(
        pinned_inspection(&witness)?,
    ))
}

async fn require_activation_schema(transaction: &mut Transaction<'_, Postgres>) -> Result<()> {
    let available: bool = sqlx::query_scalar(REQUIRE_ACTIVATION_SCHEMA_SQL)
        .fetch_one(&mut **transaction)
        .await?;
    if !available {
        return Err(FleetError::GenesisActivationSchemaUnavailable);
    }
    Ok(())
}

fn classify_same_statement(
    prepared: &PreparedActivation,
    stored: AuditedGenesisRoot,
) -> Result<AcceptedGenesisActivation> {
    if stored.canonical_statement != prepared.verified.canonical_statement() {
        return Err(corrupt(
            "one statement digest maps to different canonical statement bytes",
        ));
    }
    if stored.canonical_approval_set != prepared.verified.canonical_approval_set() {
        return Err(FleetError::GenesisActivationConflict(
            GenesisActivationConflictKind::ApprovalSet,
        ));
    }
    Ok(stored.inspection)
}

fn pinned_inspection(witness: &DurableGenesisWitness) -> Result<PinnedInactiveGenesis> {
    Ok(PinnedInactiveGenesis {
        bootstrap_receipt_digest: witness.bootstrap().receipt_digest(),
        bootstrap_event_id: witness.bootstrap_append().accepted_event_id,
        epoch_id: witness.bootstrap().epoch_id(),
        bootstrap_accepted_at: stored_contract(CanonicalTimestamp::from_datetime(
            &witness.bootstrap_accepted_at(),
        ))?,
    })
}

async fn require_bound_witness(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    authority: &BoundActivationAuthority,
) -> Result<DurableGenesisWitness> {
    let Some(witness) = load_durable_genesis_witness(transaction, scope).await? else {
        let stage_three_visible: bool = sqlx::query_scalar(
            "SELECT \
                 EXISTS (SELECT 1 FROM memory_registry_activations \
                         WHERE tenant_id = $1 AND project = $2 LIMIT 1) \
              OR EXISTS (SELECT 1 FROM memory_registry_heads \
                         WHERE tenant_id = $1 AND project = $2 LIMIT 1)",
        )
        .bind(scope.tenant_id())
        .bind(scope.project())
        .fetch_one(&mut **transaction)
        .await?;
        return if stage_three_visible {
            Err(corrupt(
                "registry activation state exists without a durable bootstrap",
            ))
        } else {
            Err(FleetError::GenesisActivationNotReady)
        };
    };
    if witness.bootstrap().receipt_digest() != authority.bootstrap.receipt_digest() {
        return Err(FleetError::GenesisActivationConflict(
            GenesisActivationConflictKind::BootstrapAnchor,
        ));
    }
    if witness.bootstrap().canonical_bytes() != authority.bootstrap.canonical_bytes()
        || witness.package().canonical_bytes() != authority.package.canonical_bytes()
        || witness.bootstrap_append() != &authority.bootstrap_append
    {
        return Err(corrupt(
            "durable bootstrap identity matches but authority bytes differ",
        ));
    }
    Ok(witness)
}

fn require_not_before_bootstrap(
    prepared: &PreparedActivation,
    witness: &DurableGenesisWitness,
) -> Result<()> {
    let bootstrap_accepted_at =
        CanonicalTimestamp::from_datetime(&witness.bootstrap_accepted_at())?;
    if prepared.verified.statement().effective_from < bootstrap_accepted_at {
        return Err(FleetError::GenesisActivationTiming(
            GenesisActivationTimingKind::BeforeBootstrap,
        ));
    }
    Ok(())
}

async fn select_by_statement(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    statement_id: GenesisRegistryActivationStatementId,
) -> Result<Option<PgRow>> {
    Ok(sqlx::query(SELECT_STATEMENT_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(bytes(statement_id.digest()))
        .fetch_optional(&mut **transaction)
        .await?)
}

async fn select_by_activation_id(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    activation_id: GenesisRegistryActivationId,
) -> Result<Option<PgRow>> {
    Ok(sqlx::query(SELECT_ACTIVATION_ID_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(bytes(activation_id.digest()))
        .fetch_optional(&mut **transaction)
        .await?)
}

async fn select_registry_head(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
) -> Result<Option<PgRow>> {
    Ok(sqlx::query(
        "SELECT head_state, activation_id, package_digest, activation_policy_digest, \
                source_event_id, source_epoch_id, source_shard, source_committed_offset, \
                activated_at, canonical_head \
         FROM memory_registry_heads WHERE tenant_id = $1 AND project = $2",
    )
    .bind(scope.tenant_id())
    .bind(scope.project())
    .fetch_optional(&mut **transaction)
    .await?)
}

async fn lock_control_head(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    authority: &BoundActivationAuthority,
    shard: u16,
) -> Result<LockedControlHead> {
    read_control_head(transaction, scope, authority, shard, true).await
}

async fn read_control_head(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    authority: &BoundActivationAuthority,
    shard: u16,
    for_update: bool,
) -> Result<LockedControlHead> {
    let row = if for_update {
        sqlx::query(LOCK_CONTROL_HEAD_SQL)
            .bind(scope.tenant_id())
            .bind(scope.project())
            .bind(bytes(authority.bootstrap.epoch_id().digest()))
            .bind(i32::from(shard))
            .fetch_optional(&mut **transaction)
            .await?
    } else {
        sqlx::query(
            "SELECT shard_count, last_committed_offset, chain_digest, advanced_at \
             FROM memory_control_shard_heads \
             WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4",
        )
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(bytes(authority.bootstrap.epoch_id().digest()))
        .bind(i32::from(shard))
        .fetch_optional(&mut **transaction)
        .await?
    }
    .ok_or_else(|| corrupt("registry stream control head is missing"))?;
    let shard_count: i32 = row.try_get("shard_count")?;
    if shard_count
        != i32::from(
            authority
                .bootstrap
                .receipt()
                .statement
                .genesis_epoch
                .partition_recipe
                .shard_count,
        )
    {
        return Err(corrupt("registry stream control head changed shard count"));
    }
    Ok(LockedControlHead {
        shard,
        committed_offset: row.try_get("last_committed_offset")?,
        chain_digest: digest_from_row(&row, "chain_digest")?,
        advanced_at: row.try_get("advanced_at")?,
    })
}

async fn require_pinned_inactive_tail(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    witness: &DurableGenesisWitness,
    selected_head: &LockedControlHead,
) -> Result<()> {
    let activation_ids: Vec<Vec<u8>> = sqlx::query_scalar(SELECT_ACTIVATION_IDS_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .fetch_all(&mut **transaction)
        .await?;
    if !activation_ids.is_empty() {
        return Err(corrupt(
            "activation rows exist without the singleton registry head",
        ));
    }

    let consistency_key = registry_activation_consistency_partition_key(scope.semantic_scope())?;
    let registry_events: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT event_id FROM memory_control_events \
         WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 \
           AND consistency_family = $4 AND consistency_key_digest = $5 \
         ORDER BY shard, committed_offset LIMIT 2",
    )
    .bind(scope.tenant_id())
    .bind(scope.project())
    .bind(bytes(witness.bootstrap().epoch_id().digest()))
    .bind(ACTIVATION_CONSISTENCY_FAMILY)
    .bind(bytes(consistency_key.key_digest))
    .fetch_all(&mut **transaction)
    .await?;
    if !registry_events.is_empty() {
        return Err(corrupt(
            "registry activation stream events exist without an activation projection",
        ));
    }

    let bootstrap_append = witness.bootstrap_append();
    let is_bootstrap_shard = selected_head.shard == bootstrap_append.append_position.shard;
    let prefix_offset = i64::from(is_bootstrap_shard);
    let prefix_chain = if is_bootstrap_shard {
        bootstrap_append.append_chain_digest
    } else {
        witness.genesis_heads()[usize::from(selected_head.shard)].1
    };
    audit_control_head_tip(
        transaction,
        scope,
        witness.bootstrap().epoch_id(),
        selected_head,
        prefix_offset,
        prefix_chain,
        witness.bootstrap_accepted_at(),
    )
    .await
}

fn materialize_accepted(
    prepared: &PreparedActivation,
    witness: &DurableGenesisWitness,
    locked: &LockedControlHead,
    accepted_at_database: DateTime<Utc>,
) -> Result<AcceptedActivation> {
    let bootstrap_accepted_at = stored_contract(CanonicalTimestamp::from_datetime(
        &witness.bootstrap_accepted_at(),
    ))?;
    let accepted_at = stored_contract(CanonicalTimestamp::from_datetime(&accepted_at_database))?;
    if prepared.verified.statement().effective_from > accepted_at {
        return Err(FleetError::GenesisActivationTiming(
            GenesisActivationTimingKind::FutureEffective,
        ));
    }
    let receipt = prepared
        .verified
        .receipt_at(&bootstrap_accepted_at, accepted_at)?;
    let event = GenesisRegistryActivatedEventV1::from_verified(&prepared.verified, &receipt)?;
    let activation_id = receipt.activation_id()?;
    let accepted_event_id = event.accepted_event_id()?;
    let consistency_key = event.consistency_partition_key()?;
    if consistency_key.family.as_str() != ACTIVATION_CONSISTENCY_FAMILY {
        return Err(corrupt("registry activation consistency family changed"));
    }
    let next_offset = locked
        .committed_offset
        .checked_add(1)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| corrupt("registry activation control offset overflowed INT8"))?;
    let append_position = AppendPositionV1 {
        epoch_id: witness.bootstrap().epoch_id(),
        shard: locked.shard,
        committed_offset: stored_contract(CommittedOffsetV1::new(next_offset))?,
    };
    let append_chain_digest =
        derive_append_chain_digest(locked.chain_digest, accepted_event_id, &append_position)?;
    let registry_head = prepared.verified.registry_head(&receipt)?;
    let canonical_receipt = encode_canonical(&receipt)?;
    let canonical_event = encode_canonical(&event)?;
    let canonical_head = encode_canonical(&registry_head)?;
    let effective_from_database = canonical_timestamp_to_database(&event.effective_from)?;
    Ok(AcceptedActivation {
        receipt,
        event,
        registry_head,
        activation_id,
        accepted_event_id,
        append_position,
        previous_chain_digest: locked.chain_digest,
        append_chain_digest,
        canonical_receipt,
        canonical_event,
        canonical_head,
        accepted_at_database,
        effective_from_database,
    })
}

async fn insert_control_event(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    accepted: &AcceptedActivation,
) -> Result<()> {
    let position = &accepted.append_position;
    let offset = offset_as_i64(position.committed_offset)?;
    let inserted = sqlx::query_scalar::<_, Vec<u8>>(INSERT_CONTROL_EVENT_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(bytes(position.epoch_id.digest()))
        .bind(i32::from(position.shard))
        .bind(offset)
        .bind(bytes(accepted.accepted_event_id.digest()))
        .bind(ACTIVATION_EVENT_SCHEMA_VERSION)
        .bind(ACTIVATION_EVENT_KIND)
        .bind(bytes(accepted.activation_id.digest()))
        .bind(ACTIVATION_CONSISTENCY_FAMILY)
        .bind(bytes(
            accepted.event.consistency_partition_key()?.key_digest,
        ))
        .bind(&accepted.canonical_event)
        .bind(bytes(accepted.previous_chain_digest))
        .bind(bytes(accepted.append_chain_digest))
        .bind(accepted.accepted_at_database)
        .fetch_optional(&mut **transaction)
        .await?;
    if inserted.is_none() {
        let collision_visible: bool = sqlx::query_scalar(
            "SELECT \
                 EXISTS (SELECT 1 FROM memory_control_events \
                         WHERE tenant_id = $1 AND project = $2 AND event_id = $3) \
                 OR EXISTS (SELECT 1 FROM memory_control_events \
                         WHERE tenant_id = $1 AND project = $2 AND epoch_id = $4 \
                           AND shard = $5 AND committed_offset = $6)",
        )
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(bytes(accepted.accepted_event_id.digest()))
        .bind(bytes(position.epoch_id.digest()))
        .bind(i32::from(position.shard))
        .bind(offset)
        .fetch_one(&mut **transaction)
        .await?;
        return Err(corrupt(format!(
            "registry activation event insert collided after the stream lock (visible={collision_visible})"
        )));
    }
    Ok(())
}

async fn insert_activation(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    prepared: &PreparedActivation,
    witness: &DurableGenesisWitness,
    accepted: &AcceptedActivation,
) -> Result<()> {
    let statement = prepared.verified.statement();
    let anchor = &statement.expected_anchor;
    let profile = &statement.profile;
    let position = &accepted.append_position;
    let inserted = sqlx::query_scalar::<_, Vec<u8>>(INSERT_ACTIVATION_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(bytes(accepted.activation_id.digest()))
        .bind(bytes(prepared.statement_id.digest()))
        .bind(bytes(anchor.bootstrap_statement_id.digest()))
        .bind(bytes(anchor.bootstrap_receipt_digest.digest()))
        .bind(bytes(anchor.bootstrap_event_id.digest()))
        .bind(bytes(anchor.genesis_epoch_id.digest()))
        .bind(bytes(anchor.genesis_package_digest))
        .bind(bytes(anchor.bootstrap_signer_policy_digest))
        .bind(profile.profile_id.as_str())
        .bind(bytes(profile.profile_digest))
        .bind(bytes(profile.vector_manifest_digest))
        .bind(statement.scope.tenant_namespace.as_str())
        .bind(statement.scope.project_namespace.as_str())
        .bind(bytes(statement.package_digest))
        .bind(bytes(statement.resulting_activation_policy_digest))
        .bind(bytes(statement.test_vector_result_digest.digest()))
        .bind(statement.proposer_principal_id.as_str())
        .bind(statement.package_author_principal_id.as_str())
        .bind(&prepared.approval_ids_packed)
        .bind(prepared.approval_count)
        .bind(prepared.required_threshold)
        .bind(witness.bootstrap_accepted_at())
        .bind(accepted.effective_from_database)
        .bind(accepted.accepted_at_database)
        .bind(bytes(accepted.accepted_event_id.digest()))
        .bind(bytes(position.epoch_id.digest()))
        .bind(i32::from(position.shard))
        .bind(offset_as_i64(position.committed_offset)?)
        .bind(prepared.verified.canonical_statement())
        .bind(prepared.verified.canonical_approval_set())
        .bind(prepared.verified.test_result().canonical_bytes())
        .bind(&accepted.canonical_receipt)
        .bind(&accepted.canonical_event)
        .fetch_optional(&mut **transaction)
        .await?;
    if inserted.is_none() {
        let statement_visible = select_by_statement(transaction, scope, prepared.statement_id)
            .await?
            .is_some();
        return Err(corrupt(format!(
            "activation insert collided after the stream lock (statement_visible={statement_visible})"
        )));
    }
    Ok(())
}

async fn insert_registry_head(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    accepted: &AcceptedActivation,
) -> Result<()> {
    let position = &accepted.append_position;
    let inserted = sqlx::query_scalar::<_, Vec<u8>>(INSERT_REGISTRY_HEAD_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(ACTIVE_HEAD_STATE)
        .bind(bytes(accepted.activation_id.digest()))
        .bind(bytes(accepted.registry_head.package_digest))
        .bind(bytes(accepted.registry_head.activation_policy_digest))
        .bind(bytes(accepted.accepted_event_id.digest()))
        .bind(bytes(position.epoch_id.digest()))
        .bind(i32::from(position.shard))
        .bind(offset_as_i64(position.committed_offset)?)
        .bind(accepted.accepted_at_database)
        .bind(&accepted.canonical_head)
        .fetch_optional(&mut **transaction)
        .await?;
    if inserted.is_none() {
        let head = select_registry_head(transaction, scope).await?;
        return Err(corrupt(format!(
            "registry head insert collided after local writes (head_visible={})",
            head.is_some()
        )));
    }
    Ok(())
}

async fn advance_control_head(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    locked: &LockedControlHead,
    accepted: &AcceptedActivation,
) -> Result<()> {
    let next_offset = offset_as_i64(accepted.append_position.committed_offset)?;
    let row = sqlx::query(ADVANCE_CONTROL_HEAD_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(bytes(accepted.append_position.epoch_id.digest()))
        .bind(i32::from(locked.shard))
        .bind(next_offset)
        .bind(bytes(accepted.append_chain_digest))
        .bind(accepted.accepted_at_database)
        .bind(locked.committed_offset)
        .bind(bytes(locked.chain_digest))
        .fetch_optional(&mut **transaction)
        .await?;
    let Some(row) = row else {
        let current = sqlx::query(
            "SELECT last_committed_offset, chain_digest FROM memory_control_shard_heads \
             WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4",
        )
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(bytes(accepted.append_position.epoch_id.digest()))
        .bind(i32::from(locked.shard))
        .fetch_optional(&mut **transaction)
        .await?;
        return Err(corrupt(format!(
            "locked registry stream CAS failed (head_visible={})",
            current.is_some()
        )));
    };
    expect_i64(&row, "last_committed_offset", next_offset)?;
    expect_digest(&row, "chain_digest", accepted.append_chain_digest)
}

async fn load_and_audit_head_activation(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    authority: &BoundActivationAuthority,
    witness: &DurableGenesisWitness,
    _head: &PgRow,
) -> Result<AuditedGenesisRoot> {
    let stored = genesis_audit::audit_immutable_genesis_root(transaction, scope, authority).await?;
    audit_genesis_only_current_state(transaction, scope, authority, witness, &stored.inspection)
        .await?;
    Ok(stored)
}

/// Implementation behind the shared immutable-root audit boundary.
///
/// It deliberately does not assert that the genesis event is still the stream
/// tip. The Stage-3 path adds that mutable-state assertion separately, while
/// successor replay needs this same immutable proof after generation one is
/// present.
pub(super) async fn audit_immutable_genesis_root_impl(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    authority: &BoundActivationAuthority,
) -> Result<AuditedGenesisRoot> {
    let witness = require_bound_witness(transaction, scope, authority).await?;
    let prefix = select_registry_stream_prefix(transaction, scope, authority)
        .await?
        .ok_or_else(|| corrupt("registry root has no genesis activation prefix"))?;
    let prefix_position = stream_endpoint_position(&prefix, authority.bootstrap.epoch_id())?;
    let prefix_source = select_control_event(transaction, scope, &prefix_position)
        .await?
        .ok_or_else(|| corrupt("genesis registry stream prefix event is missing"))?;
    expect_text(&prefix_source, "event_kind", ACTIVATION_EVENT_KIND)?;
    let activation_id = GenesisRegistryActivationId::from_digest(digest_from_row(
        &prefix_source,
        "semantic_object_digest",
    )?);
    let row = select_by_activation_id(transaction, scope, activation_id)
        .await?
        .ok_or_else(|| corrupt("genesis registry event has no activation projection"))?;
    let stored =
        audit_genesis_activation_prefix(transaction, scope, authority, &witness, &row).await?;
    audit_genesis_activation_cardinality(transaction, scope, stored.inspection.activation_id)
        .await?;
    let head = select_registry_head(transaction, scope)
        .await?
        .ok_or_else(|| corrupt("accepted genesis activation has no legacy registry head"))?;
    audit_legacy_genesis_head_root(transaction, scope, &witness, &head, &stored.inspection).await?;
    Ok(stored)
}

async fn select_registry_stream_prefix(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    authority: &BoundActivationAuthority,
) -> Result<Option<PgRow>> {
    let consistency_key = registry_activation_consistency_partition_key(scope.semantic_scope())?;
    let rows = sqlx::query(SELECT_REGISTRY_STREAM_PREFIX_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(bytes(authority.bootstrap.epoch_id().digest()))
        .bind(ACTIVATION_CONSISTENCY_FAMILY)
        .bind(bytes(consistency_key.key_digest))
        .fetch_all(&mut **transaction)
        .await?;
    Ok(rows.into_iter().next())
}

async fn select_registry_stream_tip(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    authority: &BoundActivationAuthority,
) -> Result<Option<PgRow>> {
    let consistency_key = registry_activation_consistency_partition_key(scope.semantic_scope())?;
    let rows = sqlx::query(SELECT_REGISTRY_STREAM_TIP_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(bytes(authority.bootstrap.epoch_id().digest()))
        .bind(ACTIVATION_CONSISTENCY_FAMILY)
        .bind(bytes(consistency_key.key_digest))
        .fetch_all(&mut **transaction)
        .await?;
    Ok(rows.into_iter().next())
}

#[allow(clippy::too_many_lines)] // Reconstruct every immutable projection field from authority.
async fn audit_stored_activation(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    authority: &BoundActivationAuthority,
    witness: &DurableGenesisWitness,
    row: &PgRow,
) -> Result<AuditedGenesisRoot> {
    let stored = genesis_audit::audit_immutable_genesis_root(transaction, scope, authority).await?;
    expect_digest(
        row,
        "activation_id",
        stored.inspection.activation_id.digest(),
    )?;
    audit_genesis_only_current_state(transaction, scope, authority, witness, &stored.inspection)
        .await?;
    Ok(stored)
}

async fn audit_genesis_activation_cardinality(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    expected_activation_id: GenesisRegistryActivationId,
) -> Result<()> {
    let activation_ids: Vec<Vec<u8>> = sqlx::query_scalar(SELECT_ACTIVATION_IDS_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .fetch_all(&mut **transaction)
        .await?;
    if activation_ids.len() != 1
        || activation_ids[0].as_slice() != expected_activation_id.digest().as_bytes()
    {
        return Err(corrupt(
            "genesis-only schema requires exactly one accepted activation projection",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // Reconstruct every immutable projection field from authority.
async fn audit_genesis_activation_prefix(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    authority: &BoundActivationAuthority,
    witness: &DurableGenesisWitness,
    row: &PgRow,
) -> Result<AuditedGenesisRoot> {
    let canonical_statement: Vec<u8> = row.try_get("canonical_statement")?;
    let canonical_approval_set: Vec<u8> = row.try_get("canonical_approval_set")?;
    let canonical_test_result: Vec<u8> = row.try_get("canonical_test_result")?;
    let canonical_receipt: Vec<u8> = row.try_get("canonical_receipt")?;
    let canonical_event: Vec<u8> = row.try_get("canonical_event")?;
    for (name, canonical) in [
        ("statement", canonical_statement.as_slice()),
        ("approval set", canonical_approval_set.as_slice()),
        ("test result", canonical_test_result.as_slice()),
        ("receipt", canonical_receipt.as_slice()),
        ("event", canonical_event.as_slice()),
    ] {
        require_canonical(canonical).map_err(|error| {
            corrupt(format!(
                "stored activation {name} is not canonical: {error}"
            ))
        })?;
    }
    if canonical_test_result != authority.test_result.canonical_bytes() {
        return Err(corrupt(
            "stored activation test result differs from construction-bound authority",
        ));
    }

    let verified = verify_genesis_registry_activation(
        &canonical_statement,
        &canonical_approval_set,
        &authority.bootstrap,
        &authority.package,
        &authority.test_result,
        &authority.principal_binding,
    )
    .map_err(|error| corrupt(format!("stored activation authority is invalid: {error}")))?;
    verified
        .statement()
        .profile
        .require_frozen_runtime_profile()
        .map_err(|error| {
            corrupt(format!(
                "stored activation profile is not implemented: {error}"
            ))
        })?;
    let bootstrap_accepted_at = stored_contract(CanonicalTimestamp::from_datetime(
        &witness.bootstrap_accepted_at(),
    ))?;
    if verified.statement().effective_from < bootstrap_accepted_at {
        return Err(corrupt(
            "stored activation became effective before durable bootstrap acceptance",
        ));
    }
    let receipt: GenesisRegistryActivationReceiptV1 = decode_strict(&canonical_receipt)
        .map_err(|error| corrupt(format!("stored activation receipt is invalid: {error}")))?;
    stored_contract(receipt.validate_against(&verified))?;
    let event: GenesisRegistryActivatedEventV1 = decode_strict(&canonical_event)
        .map_err(|error| corrupt(format!("stored activation event is invalid: {error}")))?;
    stored_contract(event.validate_against(&verified, &receipt))?;
    if stored_contract(encode_canonical(&receipt))? != canonical_receipt
        || stored_contract(encode_canonical(&event))? != canonical_event
    {
        return Err(corrupt(
            "stored activation receipt or event changed during reconstruction",
        ));
    }

    let statement_id = stored_contract(verified.statement().statement_id())?;
    let activation_id = stored_contract(receipt.activation_id())?;
    let accepted_event_id = stored_contract(event.accepted_event_id())?;
    let append_position = stored_append_position(row)?;
    if append_position.epoch_id != witness.bootstrap().epoch_id() {
        return Err(corrupt(
            "stored activation references a different control epoch",
        ));
    }
    let expected_shard = stored_contract(
        authority
            .bootstrap
            .partition_for(&stored_contract(event.consistency_partition_key())?),
    )?;
    if append_position.shard != expected_shard {
        return Err(corrupt(
            "stored activation event is on the wrong stable registry shard",
        ));
    }
    let stream_prefix = select_registry_stream_prefix(transaction, scope, authority)
        .await?
        .ok_or_else(|| corrupt("accepted genesis activation has no registry stream event"))?;
    expect_digest(&stream_prefix, "event_id", accepted_event_id.digest())?;
    expect_i32(&stream_prefix, "shard", i32::from(append_position.shard))?;
    expect_i64(
        &stream_prefix,
        "committed_offset",
        offset_as_i64(append_position.committed_offset)?,
    )?;
    let accepted_at_database = canonical_timestamp_to_database(&receipt.accepted_at)?;
    let previous_chain_digest = audit_activation_source_event(
        transaction,
        scope,
        witness,
        activation_id,
        accepted_event_id,
        &event,
        &canonical_event,
        &append_position,
        accepted_at_database,
    )
    .await?;
    audit_predecessor_chain(
        transaction,
        scope,
        witness,
        &append_position,
        previous_chain_digest,
        accepted_at_database,
    )
    .await?;
    audit_activation_columns(
        row,
        scope,
        witness,
        &verified,
        &receipt,
        &event,
        statement_id,
        activation_id,
        accepted_event_id,
        &append_position,
    )?;
    let registry_head = stored_contract(verified.registry_head(&receipt))?;
    let inspection = AcceptedGenesisActivation {
        statement_id,
        activation_id,
        accepted_event_id,
        registry_head,
        append_position,
        bootstrap_receipt_digest: receipt.expected_anchor.bootstrap_receipt_digest,
        effective_from: event.effective_from.clone(),
        accepted_at: receipt.accepted_at.clone(),
    };
    let current = read_control_head(
        transaction,
        scope,
        authority,
        inspection.append_position.shard,
        false,
    )
    .await?;
    if current.committed_offset < offset_as_i64(inspection.append_position.committed_offset)? {
        return Err(corrupt(
            "registry stream control head precedes the activation event",
        ));
    }
    let (floor_offset, floor_chain) = durable_shard_floor(witness, current.shard)?;
    audit_control_head_tip(
        transaction,
        scope,
        witness.bootstrap().epoch_id(),
        &current,
        floor_offset,
        floor_chain,
        witness.bootstrap_accepted_at(),
    )
    .await?;

    let head_binding = RegistryHeadBindingV1 {
        head: inspection.registry_head.clone(),
        effective_from: inspection.effective_from.clone(),
        effective_until: None,
    };
    stored_contract(head_binding.validate_shape())?;
    let canonical_head_binding = stored_contract(encode_canonical(&head_binding))?;
    let mut policy_entries = authority
        .package
        .manifest_verified_package()
        .package()
        .entries
        .iter()
        .filter(|entry| entry.kind == RegistryEntryKind::ActivationPolicy);
    let policy_entry = policy_entries
        .next()
        .ok_or_else(|| corrupt("audited genesis package has no activation policy"))?;
    if policy_entries.next().is_some() {
        return Err(corrupt(
            "audited genesis package has multiple activation policies",
        ));
    }
    let current_v1_activation_policy = crate::memory_contracts::common::RegistryReferenceV1 {
        entry_id: policy_entry.entry_id.clone(),
        version: policy_entry.version,
        entry_digest: stored_contract(policy_entry.digest())?,
    };
    if current_v1_activation_policy.entry_digest
        != inspection.registry_head.activation_policy_digest
    {
        return Err(corrupt(
            "audited genesis policy reference differs from the durable head",
        ));
    }
    let eligible_v1_principal_ids = authority
        .package
        .activation_policy()
        .eligible_principal_ids()
        .to_vec();
    let required_v1_threshold = authority.package.activation_policy().approval_threshold();

    Ok(AuditedGenesisRoot {
        inspection,
        verified,
        receipt,
        current_v1_activation_policy,
        eligible_v1_principal_ids,
        required_v1_threshold,
        canonical_statement,
        canonical_approval_set,
        canonical_receipt,
        canonical_event,
        canonical_head_binding,
    })
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn audit_activation_columns(
    row: &PgRow,
    scope: &TrustedControlScope,
    witness: &DurableGenesisWitness,
    verified: &VerifiedGenesisRegistryActivationRequest,
    receipt: &GenesisRegistryActivationReceiptV1,
    event: &GenesisRegistryActivatedEventV1,
    statement_id: GenesisRegistryActivationStatementId,
    activation_id: GenesisRegistryActivationId,
    accepted_event_id: crate::memory_contracts::evidence::AcceptedEventId,
    position: &AppendPositionV1,
) -> Result<()> {
    let statement = verified.statement();
    let anchor = &statement.expected_anchor;
    let profile = &statement.profile;
    expect_digest(row, "activation_id", activation_id.digest())?;
    expect_digest(row, "statement_id", statement_id.digest())?;
    expect_digest(
        row,
        "bootstrap_statement_id",
        anchor.bootstrap_statement_id.digest(),
    )?;
    expect_digest(
        row,
        "bootstrap_receipt_digest",
        anchor.bootstrap_receipt_digest.digest(),
    )?;
    expect_digest(
        row,
        "bootstrap_event_id",
        anchor.bootstrap_event_id.digest(),
    )?;
    expect_digest(row, "genesis_epoch_id", anchor.genesis_epoch_id.digest())?;
    expect_digest(row, "genesis_package_digest", anchor.genesis_package_digest)?;
    expect_digest(
        row,
        "bootstrap_signer_policy_digest",
        anchor.bootstrap_signer_policy_digest,
    )?;
    expect_text(row, "profile_id", profile.profile_id.as_str())?;
    expect_digest(row, "profile_digest", profile.profile_digest)?;
    expect_digest(
        row,
        "vector_manifest_digest",
        profile.vector_manifest_digest,
    )?;
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
    expect_digest(row, "activated_package_digest", statement.package_digest)?;
    expect_digest(
        row,
        "activated_policy_digest",
        statement.resulting_activation_policy_digest,
    )?;
    expect_digest(
        row,
        "test_result_digest",
        statement.test_vector_result_digest.digest(),
    )?;
    expect_text(
        row,
        "proposer_principal_id",
        statement.proposer_principal_id.as_str(),
    )?;
    expect_text(
        row,
        "package_author_principal_id",
        statement.package_author_principal_id.as_str(),
    )?;
    let mut approval_ids = Vec::with_capacity(receipt.eligible_approvals.len() * 32);
    for approval in &receipt.eligible_approvals {
        approval_ids.extend_from_slice(approval.attestation_id.as_bytes());
    }
    expect_raw_bytes(row, "approval_ids_packed", &approval_ids)?;
    expect_i32(
        row,
        "approval_count",
        i32::try_from(receipt.eligible_approvals.len())
            .map_err(|_| corrupt("stored approval count exceeds INT4"))?,
    )?;
    expect_i32(
        row,
        "required_threshold",
        i32::from(receipt.required_threshold),
    )?;
    expect_bool(
        row,
        "separation_of_duty_satisfied",
        receipt.separation_of_duty_satisfied,
    )?;
    expect_timestamp(
        row,
        "bootstrap_accepted_at",
        witness.bootstrap_accepted_at(),
    )?;
    expect_timestamp(
        row,
        "effective_from",
        canonical_timestamp_to_database(&event.effective_from)?,
    )?;
    let effective_until: Option<DateTime<Utc>> = row.try_get("effective_until")?;
    if effective_until.is_some() {
        return Err(corrupt("stored genesis activation unexpectedly expires"));
    }
    expect_timestamp(
        row,
        "accepted_at",
        canonical_timestamp_to_database(&receipt.accepted_at)?,
    )?;
    expect_digest(row, "accepted_event_id", accepted_event_id.digest())?;
    expect_digest(row, "control_epoch_id", position.epoch_id.digest())?;
    expect_i32(row, "control_shard", i32::from(position.shard))?;
    expect_i64(
        row,
        "control_committed_offset",
        offset_as_i64(position.committed_offset)?,
    )
}

#[allow(clippy::too_many_arguments)]
async fn audit_activation_source_event(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    witness: &DurableGenesisWitness,
    activation_id: GenesisRegistryActivationId,
    accepted_event_id: crate::memory_contracts::evidence::AcceptedEventId,
    event: &GenesisRegistryActivatedEventV1,
    canonical_event: &[u8],
    position: &AppendPositionV1,
    accepted_at: DateTime<Utc>,
) -> Result<Sha256Digest> {
    let row = select_control_event(transaction, scope, position)
        .await?
        .ok_or_else(|| corrupt("registry activation control event is missing"))?;
    expect_digest(&row, "event_id", accepted_event_id.digest())?;
    expect_i32(
        &row,
        "event_schema_version",
        ACTIVATION_EVENT_SCHEMA_VERSION,
    )?;
    expect_text(&row, "event_kind", ACTIVATION_EVENT_KIND)?;
    expect_digest(&row, "semantic_object_digest", activation_id.digest())?;
    let consistency_key = stored_contract(event.consistency_partition_key())?;
    expect_text(&row, "consistency_family", ACTIVATION_CONSISTENCY_FAMILY)?;
    expect_digest(&row, "consistency_key_digest", consistency_key.key_digest)?;
    expect_raw_bytes(&row, "canonical_event", canonical_event)?;
    expect_timestamp(&row, "accepted_at", accepted_at)?;
    if position.epoch_id != witness.bootstrap().epoch_id() {
        return Err(corrupt(
            "activation event escaped the durable genesis epoch",
        ));
    }
    let previous = digest_from_row(&row, "previous_chain_digest")?;
    let expected_chain = stored_contract(derive_append_chain_digest(
        previous,
        accepted_event_id,
        position,
    ))?;
    expect_digest(&row, "chain_digest", expected_chain)?;
    Ok(previous)
}

async fn select_control_event(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    position: &AppendPositionV1,
) -> Result<Option<PgRow>> {
    Ok(sqlx::query(
        "SELECT event_id, event_schema_version, event_kind, semantic_object_digest, \
                consistency_family, consistency_key_digest, canonical_event, \
                previous_chain_digest, chain_digest, accepted_at \
         FROM memory_control_events \
         WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 \
           AND shard = $4 AND committed_offset = $5",
    )
    .bind(scope.tenant_id())
    .bind(scope.project())
    .bind(bytes(position.epoch_id.digest()))
    .bind(i32::from(position.shard))
    .bind(offset_as_i64(position.committed_offset)?)
    .fetch_optional(&mut **transaction)
    .await?)
}

async fn audit_predecessor_chain(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    witness: &DurableGenesisWitness,
    position: &AppendPositionV1,
    previous_chain: Sha256Digest,
    successor_accepted_at: DateTime<Utc>,
) -> Result<()> {
    let (floor_offset, floor_chain) = durable_shard_floor(witness, position.shard)?;
    let offset = offset_as_i64(position.committed_offset)?;
    let predecessor_offset = offset
        .checked_sub(1)
        .ok_or_else(|| corrupt("activation control offset underflowed"))?;
    if predecessor_offset < floor_offset {
        return Err(corrupt(
            "activation event precedes the durable bootstrap prefix",
        ));
    }
    if predecessor_offset == floor_offset {
        if previous_chain != floor_chain {
            return Err(corrupt(
                "activation event does not extend the durable bootstrap prefix",
            ));
        }
        return Ok(());
    }
    audit_event_at_offset(
        transaction,
        scope,
        position.epoch_id,
        position.shard,
        predecessor_offset,
        previous_chain,
        floor_offset,
        floor_chain,
        witness.bootstrap_accepted_at(),
        Some(successor_accepted_at),
    )
    .await
}

async fn audit_control_head_tip(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    epoch_id: EpochId,
    head: &LockedControlHead,
    floor_offset: i64,
    floor_chain: Sha256Digest,
    floor_accepted_at: DateTime<Utc>,
) -> Result<()> {
    require_no_event_ahead_of_head(transaction, scope, epoch_id, head).await?;
    if head.committed_offset < floor_offset {
        return Err(corrupt("selected control head precedes the durable prefix"));
    }
    if head.committed_offset == floor_offset {
        return if head.chain_digest == floor_chain && head.advanced_at == floor_accepted_at {
            Ok(())
        } else {
            Err(corrupt(
                "selected control head changed the durable prefix state",
            ))
        };
    }
    audit_event_at_offset(
        transaction,
        scope,
        epoch_id,
        head.shard,
        head.committed_offset,
        head.chain_digest,
        floor_offset,
        floor_chain,
        floor_accepted_at,
        None,
    )
    .await?;
    let position = AppendPositionV1 {
        epoch_id,
        shard: head.shard,
        committed_offset: stored_contract(CommittedOffsetV1::new(
            u64::try_from(head.committed_offset)
                .map_err(|_| corrupt("negative control head offset"))?,
        ))?,
    };
    let tip = select_control_event(transaction, scope, &position)
        .await?
        .ok_or_else(|| corrupt("selected control head tip disappeared during audit"))?;
    expect_timestamp(&tip, "accepted_at", head.advanced_at)
}

async fn require_no_event_ahead_of_head(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    epoch_id: EpochId,
    head: &LockedControlHead,
) -> Result<()> {
    let event_id: Option<Vec<u8>> = sqlx::query_scalar(SELECT_EVENT_AHEAD_OF_HEAD_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(bytes(epoch_id.digest()))
        .bind(i32::from(head.shard))
        .bind(head.committed_offset)
        .fetch_optional(&mut **transaction)
        .await?;
    if event_id.is_some() {
        return Err(corrupt(
            "selected control shard contains an event beyond its authoritative head",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn audit_event_at_offset(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    epoch_id: EpochId,
    shard: u16,
    offset: i64,
    expected_chain: Sha256Digest,
    floor_offset: i64,
    floor_chain: Sha256Digest,
    floor_accepted_at: DateTime<Utc>,
    ceiling_accepted_at: Option<DateTime<Utc>>,
) -> Result<()> {
    let position = AppendPositionV1 {
        epoch_id,
        shard,
        committed_offset: stored_contract(CommittedOffsetV1::new(
            u64::try_from(offset).map_err(|_| corrupt("negative control event offset"))?,
        ))?,
    };
    let row = select_control_event(transaction, scope, &position)
        .await?
        .ok_or_else(|| corrupt("selected control head has no event at its exact tip"))?;
    let event_id = crate::memory_contracts::evidence::AcceptedEventId::from_digest(
        digest_from_row(&row, "event_id")?,
    );
    let previous_chain = digest_from_row(&row, "previous_chain_digest")?;
    let derived = stored_contract(derive_append_chain_digest(
        previous_chain,
        event_id,
        &position,
    ))?;
    if derived != expected_chain || digest_from_row(&row, "chain_digest")? != expected_chain {
        return Err(corrupt("selected control tail chain is invalid"));
    }
    let accepted_at: DateTime<Utc> = row.try_get("accepted_at")?;
    if accepted_at < floor_accepted_at {
        return Err(corrupt(
            "selected control tail predates durable bootstrap acceptance",
        ));
    }
    if ceiling_accepted_at.is_some_and(|ceiling| accepted_at > ceiling) {
        return Err(corrupt(
            "selected control tail is later than its accepted successor",
        ));
    }

    let predecessor_offset = offset
        .checked_sub(1)
        .ok_or_else(|| corrupt("selected control tail offset underflowed"))?;
    match predecessor_offset.cmp(&floor_offset) {
        std::cmp::Ordering::Equal => {
            if previous_chain != floor_chain {
                return Err(corrupt("selected control tail is detached from its prefix"));
            }
        }
        std::cmp::Ordering::Greater => {
            audit_immediate_predecessor(
                transaction,
                scope,
                &position,
                predecessor_offset,
                previous_chain,
                floor_offset,
                floor_chain,
                floor_accepted_at,
                accepted_at,
            )
            .await?;
        }
        std::cmp::Ordering::Less => {
            return Err(corrupt("selected control tail precedes its durable prefix"));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn audit_immediate_predecessor(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    position: &AppendPositionV1,
    predecessor_offset: i64,
    expected_chain: Sha256Digest,
    floor_offset: i64,
    floor_chain: Sha256Digest,
    floor_accepted_at: DateTime<Utc>,
    successor_accepted_at: DateTime<Utc>,
) -> Result<()> {
    let predecessor_position = AppendPositionV1 {
        epoch_id: position.epoch_id,
        shard: position.shard,
        committed_offset: stored_contract(CommittedOffsetV1::new(
            u64::try_from(predecessor_offset)
                .map_err(|_| corrupt("negative predecessor offset"))?,
        ))?,
    };
    let predecessor = select_control_event(transaction, scope, &predecessor_position)
        .await?
        .ok_or_else(|| corrupt("selected control tail predecessor is missing"))?;
    let predecessor_event = crate::memory_contracts::evidence::AcceptedEventId::from_digest(
        digest_from_row(&predecessor, "event_id")?,
    );
    let predecessor_previous = digest_from_row(&predecessor, "previous_chain_digest")?;
    let predecessor_chain = stored_contract(derive_append_chain_digest(
        predecessor_previous,
        predecessor_event,
        &predecessor_position,
    ))?;
    if predecessor_chain != expected_chain
        || digest_from_row(&predecessor, "chain_digest")? != expected_chain
    {
        return Err(corrupt(
            "selected control tail predecessor chain is invalid",
        ));
    }
    let predecessor_accepted_at: DateTime<Utc> = predecessor.try_get("accepted_at")?;
    if predecessor_accepted_at < floor_accepted_at
        || predecessor_accepted_at > successor_accepted_at
    {
        return Err(corrupt(
            "selected control tail predecessor acceptance time is out of order",
        ));
    }
    if predecessor_offset == floor_offset + 1 && predecessor_previous != floor_chain {
        return Err(corrupt(
            "selected control tail predecessor is detached from its prefix",
        ));
    }
    Ok(())
}

fn durable_shard_floor(witness: &DurableGenesisWitness, shard: u16) -> Result<(i64, Sha256Digest)> {
    let bootstrap = witness.bootstrap_append();
    if shard == bootstrap.append_position.shard {
        return Ok((
            offset_as_i64(bootstrap.append_position.committed_offset)?,
            bootstrap.append_chain_digest,
        ));
    }
    let chain = witness
        .genesis_heads()
        .get(usize::from(shard))
        .filter(|(stored_shard, _)| *stored_shard == i32::from(shard))
        .map(|(_, chain)| *chain)
        .ok_or_else(|| corrupt("selected shard is outside the durable genesis head set"))?;
    Ok((0, chain))
}

fn stored_append_position(row: &PgRow) -> Result<AppendPositionV1> {
    let shard = u16::try_from(row.try_get::<i32, _>("control_shard")?)
        .map_err(|_| corrupt("stored control shard is outside UINT16"))?;
    let offset = u64::try_from(row.try_get::<i64, _>("control_committed_offset")?)
        .map_err(|_| corrupt("stored control offset is negative"))?;
    Ok(AppendPositionV1 {
        epoch_id: EpochId::from_digest(digest_from_row(row, "control_epoch_id")?),
        shard,
        committed_offset: stored_contract(CommittedOffsetV1::new(offset))?,
    })
}

fn stream_endpoint_position(row: &PgRow, epoch_id: EpochId) -> Result<AppendPositionV1> {
    let shard = u16::try_from(row.try_get::<i32, _>("shard")?)
        .map_err(|_| corrupt("registry stream endpoint shard is outside UINT16"))?;
    let offset = u64::try_from(row.try_get::<i64, _>("committed_offset")?)
        .map_err(|_| corrupt("registry stream endpoint offset is negative"))?;
    Ok(AppendPositionV1 {
        epoch_id,
        shard,
        committed_offset: stored_contract(CommittedOffsetV1::new(offset))?,
    })
}

fn audit_registry_head_row(
    head: &PgRow,
    inspection: &AcceptedGenesisActivation,
    activation_row: &PgRow,
) -> Result<()> {
    expect_text(head, "head_state", ACTIVE_HEAD_STATE)?;
    expect_digest(head, "activation_id", inspection.activation_id.digest())?;
    expect_digest(
        head,
        "package_digest",
        inspection.registry_head.package_digest,
    )?;
    expect_digest(
        head,
        "activation_policy_digest",
        inspection.registry_head.activation_policy_digest,
    )?;
    expect_digest(
        head,
        "source_event_id",
        inspection.accepted_event_id.digest(),
    )?;
    expect_digest(
        head,
        "source_epoch_id",
        inspection.append_position.epoch_id.digest(),
    )?;
    expect_i32(
        head,
        "source_shard",
        i32::from(inspection.append_position.shard),
    )?;
    expect_i64(
        head,
        "source_committed_offset",
        offset_as_i64(inspection.append_position.committed_offset)?,
    )?;
    expect_timestamp(
        head,
        "activated_at",
        canonical_timestamp_to_database(&inspection.accepted_at)?,
    )?;
    let expected = encode_canonical(&inspection.registry_head)?;
    expect_raw_bytes(head, "canonical_head", &expected)?;
    let accepted_at: DateTime<Utc> = activation_row.try_get("accepted_at")?;
    expect_timestamp(head, "activated_at", accepted_at)
}

#[allow(clippy::too_many_lines)]
async fn audit_legacy_genesis_head_root(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    witness: &DurableGenesisWitness,
    head: &PgRow,
    genesis: &AcceptedGenesisActivation,
) -> Result<()> {
    expect_text(head, "head_state", ACTIVE_HEAD_STATE)?;
    let canonical_head: Vec<u8> = head.try_get("canonical_head")?;
    require_canonical(&canonical_head)
        .map_err(|error| corrupt(format!("current registry head is not canonical: {error}")))?;
    let decoded: RegistryHeadV1 = decode_strict(&canonical_head)
        .map_err(|error| corrupt(format!("current registry head is invalid: {error}")))?;
    if encode_canonical(&decoded)? != canonical_head {
        return Err(corrupt(
            "current registry head changed during canonical reconstruction",
        ));
    }
    require_genesis_only_head(decoded.activation_id, genesis.activation_id)?;
    expect_digest(head, "activation_id", decoded.activation_id)?;
    expect_digest(head, "package_digest", decoded.package_digest)?;
    expect_digest(
        head,
        "activation_policy_digest",
        decoded.activation_policy_digest,
    )?;

    let activation_id = GenesisRegistryActivationId::from_digest(decoded.activation_id);
    let activation = select_by_activation_id(transaction, scope, activation_id)
        .await?
        .ok_or_else(|| corrupt("current registry head points to a missing activation"))?;
    audit_registry_head_row(head, genesis, &activation)?;
    expect_digest(&activation, "activation_id", decoded.activation_id)?;
    expect_digest(
        &activation,
        "activated_package_digest",
        decoded.package_digest,
    )?;
    expect_digest(
        &activation,
        "activated_policy_digest",
        decoded.activation_policy_digest,
    )?;
    let source_position = AppendPositionV1 {
        epoch_id: EpochId::from_digest(digest_from_row(head, "source_epoch_id")?),
        shard: u16::try_from(head.try_get::<i32, _>("source_shard")?)
            .map_err(|_| corrupt("current registry source shard is outside UINT16"))?,
        committed_offset: stored_contract(CommittedOffsetV1::new(
            u64::try_from(head.try_get::<i64, _>("source_committed_offset")?)
                .map_err(|_| corrupt("current registry source offset is negative"))?,
        ))?,
    };
    if source_position != genesis.append_position {
        return Err(corrupt(
            "genesis-only registry head moved away from its exact source position",
        ));
    }
    let source_offset = offset_as_i64(source_position.committed_offset)?;

    let source_event_id = crate::memory_contracts::evidence::AcceptedEventId::from_digest(
        digest_from_row(head, "source_event_id")?,
    );
    if source_event_id != genesis.accepted_event_id {
        return Err(corrupt(
            "genesis-only registry head moved to a different source event",
        ));
    }
    expect_digest(&activation, "accepted_event_id", source_event_id.digest())?;
    expect_digest(
        &activation,
        "control_epoch_id",
        source_position.epoch_id.digest(),
    )?;
    expect_i32(
        &activation,
        "control_shard",
        i32::from(source_position.shard),
    )?;
    expect_i64(&activation, "control_committed_offset", source_offset)?;
    let activated_at: DateTime<Utc> = head.try_get("activated_at")?;
    expect_timestamp(
        head,
        "activated_at",
        canonical_timestamp_to_database(&genesis.accepted_at)?,
    )?;
    expect_timestamp(&activation, "accepted_at", activated_at)?;

    let source = select_control_event(transaction, scope, &source_position)
        .await?
        .ok_or_else(|| corrupt("current registry source event is missing"))?;
    expect_digest(&source, "event_id", source_event_id.digest())?;
    expect_digest(&source, "semantic_object_digest", decoded.activation_id)?;
    let consistency_key = registry_activation_consistency_partition_key(scope.semantic_scope())?;
    expect_text(&source, "consistency_family", ACTIVATION_CONSISTENCY_FAMILY)?;
    expect_digest(
        &source,
        "consistency_key_digest",
        consistency_key.key_digest,
    )?;
    expect_timestamp(&source, "accepted_at", activated_at)?;
    let previous_chain = digest_from_row(&source, "previous_chain_digest")?;
    let source_chain = stored_contract(derive_append_chain_digest(
        previous_chain,
        source_event_id,
        &source_position,
    ))?;
    expect_digest(&source, "chain_digest", source_chain)?;
    audit_predecessor_chain(
        transaction,
        scope,
        witness,
        &source_position,
        previous_chain,
        activated_at,
    )
    .await
}

async fn audit_genesis_only_current_state(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    authority: &BoundActivationAuthority,
    witness: &DurableGenesisWitness,
    genesis: &AcceptedGenesisActivation,
) -> Result<()> {
    let source_position = genesis.append_position;
    let source_offset = offset_as_i64(source_position.committed_offset)?;
    let source_event_id = genesis.accepted_event_id;
    let source = select_control_event(transaction, scope, &source_position)
        .await?
        .ok_or_else(|| corrupt("current registry source event is missing"))?;
    let previous_chain = digest_from_row(&source, "previous_chain_digest")?;
    let source_chain = stored_contract(derive_append_chain_digest(
        previous_chain,
        source_event_id,
        &source_position,
    ))?;
    let activated_at = canonical_timestamp_to_database(&genesis.accepted_at)?;
    let stream_tip = select_registry_stream_tip(transaction, scope, authority)
        .await?
        .ok_or_else(|| corrupt("current registry stream has no tip"))?;
    expect_digest(&stream_tip, "event_id", source_event_id.digest())?;
    expect_i32(&stream_tip, "shard", i32::from(source_position.shard))?;
    expect_i64(&stream_tip, "committed_offset", source_offset)?;

    let control_head =
        read_control_head(transaction, scope, authority, source_position.shard, false).await?;
    if control_head.committed_offset < source_offset
        || control_head.advanced_at < activated_at
        || (control_head.committed_offset == source_offset
            && (control_head.chain_digest != source_chain
                || control_head.advanced_at != activated_at))
    {
        return Err(corrupt(
            "current control head does not cover the registry source event",
        ));
    }
    let (floor_offset, floor_chain) = durable_shard_floor(witness, control_head.shard)?;
    audit_control_head_tip(
        transaction,
        scope,
        witness.bootstrap().epoch_id(),
        &control_head,
        floor_offset,
        floor_chain,
        witness.bootstrap_accepted_at(),
    )
    .await
}

fn canonical_timestamp_to_database(timestamp: &CanonicalTimestamp) -> Result<DateTime<Utc>> {
    if !timestamp.is_microsecond_aligned() {
        return Err(crate::memory_contracts::ContractError::Schema(
            "timestamp is not CockroachDB microsecond aligned".into(),
        )
        .into());
    }
    DateTime::parse_from_rfc3339(timestamp.as_str())
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| {
            crate::memory_contracts::ContractError::Schema(
                "timestamp cannot be represented as TIMESTAMPTZ".into(),
            )
            .into()
        })
}

fn offset_as_i64(offset: CommittedOffsetV1) -> Result<i64> {
    i64::try_from(offset.as_u64()).map_err(|_| corrupt("control offset exceeds INT8"))
}

fn digest_from_row(row: &PgRow, column: &str) -> Result<Sha256Digest> {
    let raw: Vec<u8> = row.try_get(column)?;
    let raw: [u8; 32] = raw
        .try_into()
        .map_err(|_| corrupt(format!("stored {column} digest has the wrong length")))?;
    Ok(Sha256Digest::from_bytes(raw))
}

fn expect_digest(row: &PgRow, column: &str, expected: Sha256Digest) -> Result<()> {
    if digest_from_row(row, column)? != expected {
        return Err(corrupt(format!("stored {column} does not match")));
    }
    Ok(())
}

fn expect_raw_bytes(row: &PgRow, column: &str, expected: &[u8]) -> Result<()> {
    let actual: Vec<u8> = row.try_get(column)?;
    if actual != expected {
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

fn expect_bool(row: &PgRow, column: &str, expected: bool) -> Result<()> {
    let actual: bool = row.try_get(column)?;
    if actual != expected {
        return Err(corrupt(format!("stored {column} does not match")));
    }
    Ok(())
}

fn expect_timestamp(row: &PgRow, column: &str, expected: DateTime<Utc>) -> Result<()> {
    let actual: DateTime<Utc> = row.try_get(column)?;
    if actual != expected {
        return Err(corrupt(format!("stored {column} does not match")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_preflight_requires_exact_successful_migration_nine() {
        assert!(REQUIRE_ACTIVATION_SCHEMA_SQL.contains("count(*) = 9"));
        assert!(REQUIRE_ACTIVATION_SCHEMA_SQL.contains("bool_and(success)"));
        assert!(REQUIRE_ACTIVATION_SCHEMA_SQL.contains("version BETWEEN 1 AND 9"));
        assert!(!REQUIRE_ACTIVATION_SCHEMA_SQL.contains("EXISTS"));
        assert!(!REQUIRE_ACTIVATION_SCHEMA_SQL.contains("MAX"));
    }

    #[test]
    fn registry_stream_endpoint_probes_are_bounded_and_cross_shard_visible() {
        for query in [
            SELECT_REGISTRY_STREAM_PREFIX_SQL,
            SELECT_REGISTRY_STREAM_TIP_SQL,
        ] {
            assert!(query.contains("consistency_family = $4"));
            assert!(query.contains("consistency_key_digest = $5"));
            assert!(query.contains("LIMIT 2"));
            assert!(!query.contains("shard ="));
            assert!(!query.to_ascii_lowercase().contains("count("));
            assert!(!query.contains("event_kind"));
            assert!(!query.contains("semantic_object_digest"));
        }
        assert!(SELECT_REGISTRY_STREAM_PREFIX_SQL.contains("ORDER BY shard, committed_offset"));
        assert!(
            SELECT_REGISTRY_STREAM_TIP_SQL.contains("ORDER BY shard DESC, committed_offset DESC")
        );
    }

    #[test]
    fn genesis_only_projection_probe_and_writer_constants_are_bound() {
        assert!(SELECT_ACTIVATION_IDS_SQL.starts_with("SELECT activation_id"));
        assert!(SELECT_ACTIVATION_IDS_SQL.contains("tenant_id = $1 AND project = $2"));
        assert!(SELECT_ACTIVATION_IDS_SQL.contains("LIMIT 2"));
        assert!(INSERT_CONTROL_EVENT_SQL.contains("$7"));
        assert!(!INSERT_CONTROL_EVENT_SQL.contains("VALUES ($1, $2, $3, $4, $5, $6, 1"));
        assert!(INSERT_REGISTRY_HEAD_SQL.contains("VALUES ($1, $2, $3"));
        assert!(!INSERT_REGISTRY_HEAD_SQL.contains("'active'"));
    }

    #[test]
    fn unsupported_successor_head_fails_closed_under_genesis_only_schema() {
        let genesis = GenesisRegistryActivationId::from_digest(Sha256Digest::from_bytes([1; 32]));
        assert!(require_genesis_only_head(genesis.digest(), genesis).is_ok());
        assert!(matches!(
            require_genesis_only_head(Sha256Digest::from_bytes([2; 32]), genesis),
            Err(FleetError::RegistryActivationCorrupt(_))
        ));
    }

    #[test]
    fn append_lock_and_head_advance_are_exact_cas_operations() {
        assert!(LOCK_CONTROL_HEAD_SQL.contains("advanced_at"));
        assert!(LOCK_CONTROL_HEAD_SQL.ends_with("FOR UPDATE"));
        assert!(ADVANCE_CONTROL_HEAD_SQL.starts_with("UPDATE memory_control_shard_heads"));
        assert!(ADVANCE_CONTROL_HEAD_SQL.contains("last_committed_offset = $8"));
        assert!(ADVANCE_CONTROL_HEAD_SQL.contains("chain_digest = $9"));
        assert!(ADVANCE_CONTROL_HEAD_SQL.contains("RETURNING"));
    }

    #[test]
    fn event_ahead_of_head_probe_is_a_bounded_primary_key_range() {
        assert!(SELECT_EVENT_AHEAD_OF_HEAD_SQL.starts_with("SELECT event_id"));
        assert!(SELECT_EVENT_AHEAD_OF_HEAD_SQL.contains("tenant_id = $1 AND project = $2"));
        assert!(SELECT_EVENT_AHEAD_OF_HEAD_SQL.contains("epoch_id = $3 AND shard = $4"));
        assert!(SELECT_EVENT_AHEAD_OF_HEAD_SQL.contains("committed_offset > $5"));
        assert!(SELECT_EVENT_AHEAD_OF_HEAD_SQL.contains("ORDER BY committed_offset LIMIT 1"));
        assert!(
            !SELECT_EVENT_AHEAD_OF_HEAD_SQL
                .to_ascii_lowercase()
                .contains("count(")
        );
    }
}
