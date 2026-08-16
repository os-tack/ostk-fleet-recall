//! `CockroachDB` acceptance of the one-time first successor registry head.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::postgres::{PgPool, PgRow};
use sqlx::{Postgres, Row, Transaction, ValueRef};

use super::cockroach::BoundActivationAuthority;
use super::genesis_audit::{AuditedGenesisRoot, audit_immutable_genesis_root};
use super::{
    AcceptedSuccessorActivation, ReadySuccessorActivation, SuccessorActivationCandidate,
    SuccessorActivationInspection, SuccessorActivationOutcome, SuccessorActivationRepository,
};
use crate::control_log::{TrustedControlScope, load_durable_genesis_witness};
use crate::error::{SuccessorActivationConflictKind, SuccessorActivationTimingKind};
use crate::memory_contracts::ContractResult;
use crate::memory_contracts::bootstrap::{
    AppendPositionV1, CommittedOffsetV1, VerifiedBootstrapReceipt,
};
use crate::memory_contracts::canonical::{decode_strict, encode_canonical, require_canonical};
use crate::memory_contracts::common::{CanonicalTimestamp, frozen_profile_reference_v1};
use crate::memory_contracts::control::derive_append_chain_digest;
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::evidence::AcceptedEventId;
use crate::memory_contracts::evidence_v2::RegistryHeadBindingV1;
use crate::memory_contracts::genesis::SemanticallyClosedGenesisPackage;
use crate::memory_contracts::genesis_activation::{
    GenesisActivationPrincipalBinding, VerifiedRegistryTestResult,
    registry_activation_consistency_partition_key,
};
use crate::memory_contracts::registry::EligibleApprovalV1;
use crate::memory_contracts::stage4_target_package::SemanticallyClosedStage4Package;
use crate::memory_contracts::successor_activation::{
    SuccessorActivationPrincipalBinding, SuccessorRegistryActivatedEventV1,
    SuccessorRegistryActivationId, SuccessorRegistryActivationReceiptV1,
    SuccessorRegistryActivationStatementId, SuccessorRegistryTestRunnerPin,
    VerifiedSuccessorRegistryActivationRequest, VerifiedSuccessorRegistryTestResult,
    verify_successor_registry_activation, verify_successor_registry_test_result,
};
use crate::memory_contracts::successor_policy::{
    GenesisSuccessorKeyBridgePin, PinnedGenesisSuccessorKeyBridge,
    require_fresh_genesis_successor_insert, verify_pinned_genesis_successor_key_bridge,
};
use crate::store::cockroach::{RetryPolicy, with_serializable_retry};
use crate::{FleetError, Result};

const ACTIVATION_CONSISTENCY_FAMILY: &str = "registry.activation";
const ACTIVE_HEAD_STATE: &str = "active";
const MAX_BOUND_ARTIFACT_BYTES: usize = 1_048_576;

const REQUIRE_SUCCESSOR_SCHEMA_SQL: &str = "SELECT pg_catalog.current_database() = 'fleet_recall' \
     AND count(*) = 14 \
     AND COALESCE(bool_and(success), false) \
     FROM public._sqlx_migrations WHERE version BETWEEN 1 AND 14";

const LOCK_CONTROL_HEAD_SQL: &str = "SELECT shard_count, last_committed_offset, \
     chain_digest, advanced_at FROM public.memory_control_shard_heads \
     WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4 FOR UPDATE";

const SELECT_TRANSITIONS_SQL: &str = "SELECT generation, activation_id, statement_id, \
     package_digest, activation_policy_digest, test_result_digest, profile_id, profile_digest, \
     vector_manifest_digest, contract_tenant_namespace, contract_project_namespace, \
     effective_from, accepted_at, source_event_id, source_epoch_id, source_shard, \
     source_committed_offset, proposer_principal_id, package_author_principal_id, \
     approval_ids_packed, approval_count, required_threshold, separation_of_duty_satisfied, \
     root_activation_id, root_package_digest, root_activation_policy_digest, root_profile_id, \
     root_profile_digest, root_vector_manifest_digest, root_contract_tenant_namespace, \
     root_contract_project_namespace, root_effective_from, root_accepted_at, \
     root_source_event_id, root_source_epoch_id, root_source_shard, root_source_committed_offset, \
     predecessor_generation, predecessor_activation_id, predecessor_package_digest, \
     predecessor_activation_policy_digest, predecessor_profile_id, predecessor_profile_digest, \
     predecessor_vector_manifest_digest, predecessor_contract_tenant_namespace, \
     predecessor_contract_project_namespace, predecessor_effective_from, \
     predecessor_accepted_at, predecessor_source_event_id, predecessor_source_epoch_id, \
     predecessor_source_shard, predecessor_source_committed_offset, canonical_package, \
     canonical_statement, canonical_approval_set, canonical_test_result, canonical_receipt, \
     canonical_event, canonical_head FROM public.memory_registry_transitions \
     WHERE tenant_id = $1 AND project = $2 ORDER BY generation LIMIT 3";

const SELECT_BRIDGES_SQL: &str = "SELECT bridge_digest, from_generation, genesis_activation_id, \
     genesis_package_digest, genesis_activation_policy_digest, genesis_profile_id, \
     genesis_profile_digest, genesis_vector_manifest_digest, \
     genesis_contract_tenant_namespace, genesis_contract_project_namespace, \
     genesis_effective_from, genesis_accepted_at, genesis_source_event_id, \
     genesis_source_epoch_id, genesis_source_shard, genesis_source_committed_offset, \
     to_generation, successor_activation_id, successor_package_digest, \
     successor_activation_policy_digest, successor_profile_id, successor_profile_digest, \
     successor_vector_manifest_digest, successor_contract_tenant_namespace, \
     successor_contract_project_namespace, successor_effective_from, successor_accepted_at, \
     successor_source_event_id, successor_source_epoch_id, successor_source_shard, \
     successor_source_committed_offset, canonical_bridge, consumed_at \
     FROM public.memory_registry_genesis_bridge_consumptions \
     WHERE tenant_id = $1 AND project = $2 LIMIT 2";

const SELECT_CURRENT_HEADS_SQL: &str = "SELECT head_state, generation, activation_id, \
     package_digest, activation_policy_digest, profile_id, profile_digest, \
     vector_manifest_digest, contract_tenant_namespace, contract_project_namespace, \
     effective_from, accepted_at, source_event_id, source_epoch_id, source_shard, \
     source_committed_offset, canonical_head FROM public.memory_registry_current_heads_v2 \
     WHERE tenant_id = $1 AND project = $2 LIMIT 2";

const INSERT_GENESIS_TRANSITION_SQL: &str = "INSERT INTO public.memory_registry_transitions (\
     tenant_id, project, generation, activation_id, statement_id, package_digest, \
     activation_policy_digest, test_result_digest, profile_id, profile_digest, \
     vector_manifest_digest, contract_tenant_namespace, contract_project_namespace, \
     effective_from, accepted_at, source_event_id, source_epoch_id, source_shard, \
     source_committed_offset, proposer_principal_id, package_author_principal_id, \
     approval_ids_packed, approval_count, required_threshold, separation_of_duty_satisfied, \
     root_activation_id, root_package_digest, root_activation_policy_digest, root_profile_id, \
     root_profile_digest, root_vector_manifest_digest, root_contract_tenant_namespace, \
     root_contract_project_namespace, root_effective_from, root_accepted_at, \
     root_source_event_id, root_source_epoch_id, root_source_shard, root_source_committed_offset, \
     predecessor_generation, predecessor_activation_id, predecessor_package_digest, \
     predecessor_activation_policy_digest, predecessor_profile_id, predecessor_profile_digest, \
     predecessor_vector_manifest_digest, predecessor_contract_tenant_namespace, \
     predecessor_contract_project_namespace, predecessor_effective_from, \
     predecessor_accepted_at, predecessor_source_event_id, predecessor_source_epoch_id, \
     predecessor_source_shard, predecessor_source_committed_offset, canonical_package, \
     canonical_statement, canonical_approval_set, canonical_test_result, canonical_receipt, \
     canonical_event, canonical_head) \
     SELECT a.tenant_id, a.project, 0, a.activation_id, a.statement_id, \
     a.activated_package_digest, a.activated_policy_digest, a.test_result_digest, a.profile_id, \
     a.profile_digest, a.vector_manifest_digest, a.contract_tenant_namespace, \
     a.contract_project_namespace, a.effective_from, a.accepted_at, a.accepted_event_id, \
     a.control_epoch_id, a.control_shard, a.control_committed_offset, a.proposer_principal_id, \
     a.package_author_principal_id, a.approval_ids_packed, a.approval_count, \
     a.required_threshold, a.separation_of_duty_satisfied, a.activation_id, \
     a.activated_package_digest, a.activated_policy_digest, a.profile_id, a.profile_digest, \
     a.vector_manifest_digest, a.contract_tenant_namespace, a.contract_project_namespace, \
     a.effective_from, a.accepted_at, a.accepted_event_id, a.control_epoch_id, a.control_shard, \
     a.control_committed_offset, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, \
     NULL, NULL, NULL, NULL, NULL, $4, a.canonical_statement, a.canonical_approval_set, \
     a.canonical_test_result, a.canonical_receipt, a.canonical_event, $5 \
     FROM public.memory_registry_activations AS a JOIN public.memory_registry_heads AS h \
       ON h.tenant_id = a.tenant_id AND h.project = a.project \
      AND h.activation_id = a.activation_id AND h.package_digest = a.activated_package_digest \
      AND h.activation_policy_digest = a.activated_policy_digest \
      AND h.source_event_id = a.accepted_event_id AND h.source_epoch_id = a.control_epoch_id \
      AND h.source_shard = a.control_shard \
      AND h.source_committed_offset = a.control_committed_offset \
      AND h.activated_at = a.accepted_at \
     WHERE a.tenant_id = $1 AND a.project = $2 AND a.activation_id = $3 \
     ON CONFLICT DO NOTHING RETURNING generation";

const INSERT_GENESIS_CURRENT_HEAD_SQL: &str = "INSERT INTO public.memory_registry_current_heads_v2 (\
     tenant_id, project, head_state, generation, activation_id, package_digest, \
     activation_policy_digest, profile_id, profile_digest, vector_manifest_digest, \
     contract_tenant_namespace, contract_project_namespace, effective_from, accepted_at, \
     source_event_id, source_epoch_id, source_shard, source_committed_offset, canonical_head) \
     SELECT tenant_id, project, $4, generation, activation_id, package_digest, \
     activation_policy_digest, profile_id, profile_digest, vector_manifest_digest, \
     contract_tenant_namespace, contract_project_namespace, effective_from, accepted_at, \
     source_event_id, source_epoch_id, source_shard, source_committed_offset, canonical_head \
     FROM public.memory_registry_transitions WHERE tenant_id = $1 AND project = $2 \
     AND generation = 0 AND activation_id = $3 ON CONFLICT DO NOTHING RETURNING generation";

const INSERT_CONTROL_EVENT_SQL: &str = "INSERT INTO public.memory_control_events (\
     tenant_id, project, epoch_id, shard, committed_offset, event_id, event_schema_version, \
     event_kind, semantic_object_digest, consistency_family, consistency_key_digest, \
     canonical_event, previous_chain_digest, chain_digest, accepted_at) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) \
     ON CONFLICT DO NOTHING RETURNING event_id";

const INSERT_SUCCESSOR_TRANSITION_SQL: &str = "INSERT INTO public.memory_registry_transitions (\
     tenant_id, project, generation, activation_id, statement_id, package_digest, \
     activation_policy_digest, test_result_digest, profile_id, profile_digest, \
     vector_manifest_digest, contract_tenant_namespace, contract_project_namespace, \
     effective_from, accepted_at, source_event_id, source_epoch_id, source_shard, \
     source_committed_offset, proposer_principal_id, package_author_principal_id, \
     approval_ids_packed, approval_count, required_threshold, separation_of_duty_satisfied, \
     root_activation_id, root_package_digest, root_activation_policy_digest, root_profile_id, \
     root_profile_digest, root_vector_manifest_digest, root_contract_tenant_namespace, \
     root_contract_project_namespace, root_effective_from, root_accepted_at, \
     root_source_event_id, root_source_epoch_id, root_source_shard, root_source_committed_offset, \
     predecessor_generation, predecessor_activation_id, predecessor_package_digest, \
     predecessor_activation_policy_digest, predecessor_profile_id, predecessor_profile_digest, \
     predecessor_vector_manifest_digest, predecessor_contract_tenant_namespace, \
     predecessor_contract_project_namespace, predecessor_effective_from, \
     predecessor_accepted_at, predecessor_source_event_id, predecessor_source_epoch_id, \
     predecessor_source_shard, predecessor_source_committed_offset, canonical_package, \
     canonical_statement, canonical_approval_set, canonical_test_result, canonical_receipt, \
     canonical_event, canonical_head) \
     SELECT g.tenant_id, g.project, 1, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, \
     $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, true, g.root_activation_id, \
     g.root_package_digest, g.root_activation_policy_digest, g.root_profile_id, \
     g.root_profile_digest, g.root_vector_manifest_digest, g.root_contract_tenant_namespace, \
     g.root_contract_project_namespace, g.root_effective_from, g.root_accepted_at, \
     g.root_source_event_id, g.root_source_epoch_id, g.root_source_shard, \
     g.root_source_committed_offset, g.generation, g.activation_id, g.package_digest, \
     g.activation_policy_digest, g.profile_id, g.profile_digest, g.vector_manifest_digest, \
     g.contract_tenant_namespace, g.contract_project_namespace, g.effective_from, g.accepted_at, \
     g.source_event_id, g.source_epoch_id, g.source_shard, g.source_committed_offset, $25, $26, \
     $27, $28, $29, $30, $31 FROM public.memory_registry_transitions AS g \
     WHERE g.tenant_id = $1 AND g.project = $2 AND g.generation = 0 \
       AND g.activation_id = $3 ON CONFLICT DO NOTHING RETURNING generation";

const INSERT_BRIDGE_CONSUMPTION_SQL: &str = "INSERT INTO \
     public.memory_registry_genesis_bridge_consumptions (tenant_id, project, bridge_digest, \
     from_generation, genesis_activation_id, genesis_package_digest, \
     genesis_activation_policy_digest, genesis_profile_id, genesis_profile_digest, \
     genesis_vector_manifest_digest, genesis_contract_tenant_namespace, \
     genesis_contract_project_namespace, genesis_effective_from, genesis_accepted_at, \
     genesis_source_event_id, genesis_source_epoch_id, genesis_source_shard, \
     genesis_source_committed_offset, to_generation, successor_activation_id, \
     successor_package_digest, successor_activation_policy_digest, successor_profile_id, \
     successor_profile_digest, successor_vector_manifest_digest, \
     successor_contract_tenant_namespace, successor_contract_project_namespace, \
     successor_effective_from, successor_accepted_at, successor_source_event_id, \
     successor_source_epoch_id, successor_source_shard, successor_source_committed_offset, \
     canonical_bridge, consumed_at) SELECT g.tenant_id, g.project, $3, g.generation, \
     g.activation_id, g.package_digest, g.activation_policy_digest, g.profile_id, \
     g.profile_digest, g.vector_manifest_digest, g.contract_tenant_namespace, \
     g.contract_project_namespace, g.effective_from, g.accepted_at, g.source_event_id, \
     g.source_epoch_id, g.source_shard, g.source_committed_offset, s.generation, s.activation_id, \
     s.package_digest, s.activation_policy_digest, s.profile_id, s.profile_digest, \
     s.vector_manifest_digest, s.contract_tenant_namespace, s.contract_project_namespace, \
     s.effective_from, s.accepted_at, s.source_event_id, s.source_epoch_id, s.source_shard, \
     s.source_committed_offset, $4, $5 FROM public.memory_registry_transitions AS g \
     JOIN public.memory_registry_transitions AS s ON s.tenant_id = g.tenant_id \
       AND s.project = g.project AND s.generation = 1 \
     WHERE g.tenant_id = $1 AND g.project = $2 AND g.generation = 0 \
     ON CONFLICT DO NOTHING RETURNING bridge_digest";

const ADVANCE_CURRENT_HEAD_SQL: &str = "UPDATE public.memory_registry_current_heads_v2 AS h SET \
     generation = s.generation, activation_id = s.activation_id, \
     package_digest = s.package_digest, activation_policy_digest = s.activation_policy_digest, \
     profile_id = s.profile_id, profile_digest = s.profile_digest, \
     vector_manifest_digest = s.vector_manifest_digest, \
     contract_tenant_namespace = s.contract_tenant_namespace, \
     contract_project_namespace = s.contract_project_namespace, effective_from = s.effective_from, \
     accepted_at = s.accepted_at, source_event_id = s.source_event_id, \
     source_epoch_id = s.source_epoch_id, source_shard = s.source_shard, \
     source_committed_offset = s.source_committed_offset, canonical_head = s.canonical_head \
     FROM public.memory_registry_transitions AS g, public.memory_registry_transitions AS s \
     WHERE h.tenant_id = $1 AND h.project = $2 AND h.head_state = $3 \
       AND g.tenant_id = h.tenant_id AND g.project = h.project AND g.generation = 0 \
       AND s.tenant_id = h.tenant_id AND s.project = h.project AND s.generation = 1 \
       AND h.generation = g.generation AND h.activation_id = g.activation_id \
       AND h.package_digest = g.package_digest \
       AND h.activation_policy_digest = g.activation_policy_digest \
       AND h.profile_id = g.profile_id AND h.profile_digest = g.profile_digest \
       AND h.vector_manifest_digest = g.vector_manifest_digest \
       AND h.contract_tenant_namespace = g.contract_tenant_namespace \
       AND h.contract_project_namespace = g.contract_project_namespace \
       AND h.effective_from = g.effective_from AND h.accepted_at = g.accepted_at \
       AND h.source_event_id = g.source_event_id AND h.source_epoch_id = g.source_epoch_id \
       AND h.source_shard = g.source_shard \
       AND h.source_committed_offset = g.source_committed_offset \
       AND h.canonical_head = g.canonical_head RETURNING h.generation";

const ADVANCE_CONTROL_HEAD_SQL: &str = "UPDATE public.memory_control_shard_heads SET \
     last_committed_offset = $5, chain_digest = $6, advanced_at = $7 \
     WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4 \
       AND last_committed_offset = $8 AND chain_digest = $9 \
     RETURNING last_committed_offset, chain_digest";

/// Private first-successor repository bound to one immutable authority set.
#[derive(Clone)]
pub struct CockroachSuccessorActivationRepository {
    pool: PgPool,
    trusted_scope: TrustedControlScope,
    retry_policy: RetryPolicy,
    authority: Arc<BoundSuccessorAuthority>,
}

impl std::fmt::Debug for CockroachSuccessorActivationRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CockroachSuccessorActivationRepository")
            .field("trusted_scope", &self.trusted_scope)
            .field("retry_policy", &self.retry_policy)
            .finish_non_exhaustive()
    }
}

struct BoundSuccessorAuthority {
    genesis: BoundActivationAuthority,
    target: SemanticallyClosedStage4Package,
    test_result: VerifiedSuccessorRegistryTestResult,
    bridge_bytes: Vec<u8>,
    bridge_pin: GenesisSuccessorKeyBridgePin,
    principal_binding: SuccessorActivationPrincipalBinding,
}

impl CockroachSuccessorActivationRepository {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool: PgPool,
        trusted_scope: TrustedControlScope,
        retry_policy: RetryPolicy,
        bootstrap: VerifiedBootstrapReceipt,
        genesis_package: SemanticallyClosedGenesisPackage,
        genesis_test_result: VerifiedRegistryTestResult,
        genesis_principal_binding: GenesisActivationPrincipalBinding,
        target: SemanticallyClosedStage4Package,
        canonical_successor_test_result: &[u8],
        successor_test_runner_pin: SuccessorRegistryTestRunnerPin,
        canonical_bridge: Vec<u8>,
        bridge_pin: GenesisSuccessorKeyBridgePin,
        principal_binding: SuccessorActivationPrincipalBinding,
    ) -> Result<Self> {
        require_bound_artifact("successor test result", canonical_successor_test_result)?;
        require_bound_artifact("genesis successor bridge", &canonical_bridge)?;
        let genesis = BoundActivationAuthority::from_trusted_config(
            &trusted_scope,
            bootstrap,
            genesis_package,
            genesis_test_result,
            genesis_principal_binding,
        )?;
        let frozen_profile = frozen_profile_reference_v1();
        if target
            .successor_package()
            .manifest_verified_package()
            .package()
            .profile
            != frozen_profile
        {
            return Err(FleetError::SuccessorActivationConflict(
                SuccessorActivationConflictKind::BoundAuthority,
            ));
        }
        let test_result = verify_successor_registry_test_result(
            canonical_successor_test_result,
            successor_test_runner_pin,
            &target,
        )
        .map_err(|_| {
            FleetError::SuccessorActivationConflict(SuccessorActivationConflictKind::BoundAuthority)
        })?;
        Ok(Self {
            pool,
            trusted_scope,
            retry_policy,
            authority: Arc::new(BoundSuccessorAuthority {
                genesis,
                target,
                test_result,
                bridge_bytes: canonical_bridge,
                bridge_pin,
                principal_binding,
            }),
        })
    }
}

fn require_bound_artifact(name: &str, bytes: &[u8]) -> Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_BOUND_ARTIFACT_BYTES {
        return Err(FleetError::Configuration(format!(
            "{name} must contain between 1 and {MAX_BOUND_ARTIFACT_BYTES} bytes"
        )));
    }
    Ok(())
}

struct LockedControlHead {
    shard: u16,
    committed_offset: i64,
    chain_digest: Sha256Digest,
    advanced_at: DateTime<Utc>,
}

struct PreparedSuccessor {
    verified: VerifiedSuccessorRegistryActivationRequest,
    statement_id: SuccessorRegistryActivationStatementId,
    approval_ids_packed: Vec<u8>,
    approval_count: i32,
    required_threshold: i32,
}

impl PreparedSuccessor {
    fn new(verified: VerifiedSuccessorRegistryActivationRequest) -> Result<Self> {
        let statement_id = verified.statement().statement_id()?;
        let approval_count = i32::try_from(verified.eligible_approvals().len())
            .map_err(|_| successor_corrupt("eligible approval count exceeds INT4"))?;
        let required_threshold = i32::from(verified.required_v1_threshold());
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

struct MaterializedSuccessor {
    receipt: SuccessorRegistryActivationReceiptV1,
    event: SuccessorRegistryActivatedEventV1,
    head: RegistryHeadBindingV1,
    activation_id: SuccessorRegistryActivationId,
    accepted_event_id: AcceptedEventId,
    append_position: AppendPositionV1,
    previous_chain_digest: Sha256Digest,
    append_chain_digest: Sha256Digest,
    canonical_receipt: Vec<u8>,
    canonical_event: Vec<u8>,
    canonical_head: Vec<u8>,
    accepted_at_database: DateTime<Utc>,
    effective_from_database: DateTime<Utc>,
}

impl MaterializedSuccessor {
    fn inspection(&self) -> AcceptedSuccessorActivation {
        AcceptedSuccessorActivation {
            statement_id: self.receipt.statement_id,
            activation_id: self.activation_id,
            accepted_event_id: self.accepted_event_id,
            registry_head: self.head.clone(),
            append_position: self.append_position,
            bridge_digest: self.receipt.genesis_successor_key_bridge_digest,
            accepted_at: self.receipt.accepted_at.clone(),
        }
    }
}

enum ClassifiedState {
    Ready,
    Accepted {
        genesis: Box<PgRow>,
        successor: Box<PgRow>,
        bridge: Box<PgRow>,
        current: Box<PgRow>,
    },
}

#[async_trait]
impl SuccessorActivationRepository for CockroachSuccessorActivationRepository {
    async fn activate_first_successor(
        &self,
        candidate: &SuccessorActivationCandidate,
    ) -> Result<SuccessorActivationOutcome> {
        let candidate = Arc::new(candidate.clone());
        let scope = self.trusted_scope.clone();
        let authority = Arc::clone(&self.authority);
        let pool = self.pool.clone();
        let policy = self.retry_policy;
        with_serializable_retry(&pool, policy, move |transaction| {
            let candidate = Arc::clone(&candidate);
            let scope = scope.clone();
            let authority = Arc::clone(&authority);
            Box::pin(async move {
                activate_in_transaction(transaction, &scope, &authority, &candidate).await
            })
        })
        .await
    }

    async fn inspect_first_successor(
        &self,
        candidate: &SuccessorActivationCandidate,
    ) -> Result<SuccessorActivationInspection> {
        let candidate = Arc::new(candidate.clone());
        let scope = self.trusted_scope.clone();
        let authority = Arc::clone(&self.authority);
        let pool = self.pool.clone();
        let policy = self.retry_policy;
        with_serializable_retry(&pool, policy, move |transaction| {
            let candidate = Arc::clone(&candidate);
            let scope = scope.clone();
            let authority = Arc::clone(&authority);
            Box::pin(async move {
                inspect_in_transaction(transaction, &scope, &authority, &candidate).await
            })
        })
        .await
    }
}

async fn activate_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    authority: &BoundSuccessorAuthority,
    candidate: &SuccessorActivationCandidate,
) -> Result<SuccessorActivationOutcome> {
    require_successor_schema(transaction).await?;
    require_bound_bootstrap_before_lock(transaction, scope, authority).await?;
    let locked = lock_registry_control_head(transaction, scope, authority).await?;
    require_genesis_projection_present(transaction, scope).await?;
    let genesis = audit_immutable_genesis_root(transaction, scope, &authority.genesis)
        .await
        .map_err(map_genesis_audit_error)?;
    let bridge = verify_bound_bridge(&genesis, authority)?;
    let prepared = prepare_candidate(candidate, scope, authority, &bridge)?;
    match classify_state(transaction, scope).await? {
        ClassifiedState::Accepted {
            genesis: genesis_row,
            successor,
            bridge: bridge_row,
            current,
        } => {
            let accepted = audit_accepted_state(
                transaction,
                scope,
                authority,
                &genesis,
                &bridge,
                &locked,
                &genesis_row,
                &successor,
                &bridge_row,
                &current,
            )
            .await?;
            classify_replay(&prepared, accepted).map(SuccessorActivationOutcome::ExactReplay)
        }
        ClassifiedState::Ready => {
            audit_ready_state(transaction, scope, authority, &genesis, &locked).await?;
            require_fresh_genesis_successor_insert(0, false).map_err(|error| {
                successor_corrupt(format!("fresh successor insertion point rejected: {error}"))
            })?;
            let accepted_at_database: DateTime<Utc> =
                sqlx::query_scalar("SELECT pg_catalog.statement_timestamp()")
                    .fetch_one(&mut **transaction)
                    .await?;
            if accepted_at_database < locked.advanced_at {
                return Err(successor_corrupt(
                    "successor acceptance time precedes the locked control tail",
                ));
            }
            let materialized = materialize_successor(
                scope,
                authority,
                &genesis,
                &prepared,
                &locked,
                accepted_at_database,
            )?;
            insert_genesis_transition(transaction, scope, authority, &genesis).await?;
            insert_genesis_current_head(transaction, scope, &genesis).await?;
            insert_control_event(transaction, scope, &materialized).await?;
            insert_successor_transition(
                transaction,
                scope,
                authority,
                &genesis,
                &prepared,
                &materialized,
            )
            .await?;
            insert_bridge_consumption(transaction, scope, &bridge, &materialized).await?;
            advance_current_head(transaction, scope).await?;
            advance_control_head(transaction, scope, &locked, &materialized).await?;
            Ok(SuccessorActivationOutcome::Inserted(
                materialized.inspection(),
            ))
        }
    }
}

async fn inspect_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    authority: &BoundSuccessorAuthority,
    candidate: &SuccessorActivationCandidate,
) -> Result<SuccessorActivationInspection> {
    require_successor_schema(transaction).await?;
    require_bound_bootstrap_before_lock(transaction, scope, authority).await?;
    let locked = lock_registry_control_head(transaction, scope, authority).await?;
    require_genesis_projection_present(transaction, scope).await?;
    let genesis = audit_immutable_genesis_root(transaction, scope, &authority.genesis)
        .await
        .map_err(map_genesis_audit_error)?;
    let bridge = verify_bound_bridge(&genesis, authority)?;
    let prepared = prepare_candidate(candidate, scope, authority, &bridge)?;
    match classify_state(transaction, scope).await? {
        ClassifiedState::Ready => {
            audit_ready_state(transaction, scope, authority, &genesis, &locked).await?;
            Ok(SuccessorActivationInspection::Ready(
                ReadySuccessorActivation {
                    genesis_head: genesis.head_binding()?,
                    bridge_digest: bridge.bridge_digest(),
                },
            ))
        }
        ClassifiedState::Accepted {
            genesis: genesis_row,
            successor,
            bridge: bridge_row,
            current,
        } => {
            let accepted = audit_accepted_state(
                transaction,
                scope,
                authority,
                &genesis,
                &bridge,
                &locked,
                &genesis_row,
                &successor,
                &bridge_row,
                &current,
            )
            .await?;
            classify_replay(&prepared, accepted).map(SuccessorActivationInspection::Accepted)
        }
    }
}

async fn require_successor_schema(transaction: &mut Transaction<'_, Postgres>) -> Result<()> {
    let available: bool = sqlx::query_scalar(REQUIRE_SUCCESSOR_SCHEMA_SQL)
        .fetch_one(&mut **transaction)
        .await?;
    if !available {
        return Err(FleetError::SuccessorActivationSchemaUnavailable);
    }
    Ok(())
}

async fn require_bound_bootstrap_before_lock(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    authority: &BoundSuccessorAuthority,
) -> Result<()> {
    let Some(witness) = load_durable_genesis_witness(transaction, scope).await? else {
        return Err(FleetError::SuccessorActivationNotReady);
    };
    if witness.bootstrap().receipt_digest() != authority.genesis.bootstrap.receipt_digest() {
        return Err(FleetError::SuccessorActivationConflict(
            SuccessorActivationConflictKind::BoundAuthority,
        ));
    }
    if witness.bootstrap().canonical_bytes() != authority.genesis.bootstrap.canonical_bytes()
        || witness.package().canonical_bytes() != authority.genesis.package.canonical_bytes()
        || witness.bootstrap_append() != &authority.genesis.bootstrap_append
    {
        return Err(successor_corrupt(
            "durable bootstrap identity matches but bound authority bytes differ",
        ));
    }
    Ok(())
}

async fn lock_registry_control_head(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    authority: &BoundSuccessorAuthority,
) -> Result<LockedControlHead> {
    let consistency_key = registry_activation_consistency_partition_key(scope.semantic_scope())?;
    let shard = authority
        .genesis
        .bootstrap
        .partition_for(&consistency_key)?;
    let row = sqlx::query(LOCK_CONTROL_HEAD_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(bytes(authority.genesis.bootstrap.epoch_id().digest()))
        .bind(i32::from(shard))
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or_else(|| successor_corrupt("stable registry control head is missing"))?;
    let shard_count: i32 = row.try_get("shard_count")?;
    if shard_count
        != i32::from(
            authority
                .genesis
                .bootstrap
                .receipt()
                .statement
                .genesis_epoch
                .partition_recipe
                .shard_count,
        )
    {
        return Err(successor_corrupt(
            "stable registry control head changed shard count",
        ));
    }
    Ok(LockedControlHead {
        shard,
        committed_offset: row.try_get("last_committed_offset")?,
        chain_digest: digest_from_row(&row, "chain_digest")?,
        advanced_at: row.try_get("advanced_at")?,
    })
}

async fn require_genesis_projection_present(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
) -> Result<()> {
    let activation_ids: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT activation_id FROM public.memory_registry_activations \
         WHERE tenant_id = $1 AND project = $2 ORDER BY activation_id LIMIT 2",
    )
    .bind(scope.tenant_id())
    .bind(scope.project())
    .fetch_all(&mut **transaction)
    .await?;
    let head_ids: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT activation_id FROM public.memory_registry_heads \
         WHERE tenant_id = $1 AND project = $2 LIMIT 2",
    )
    .bind(scope.tenant_id())
    .bind(scope.project())
    .fetch_all(&mut **transaction)
    .await?;
    match (activation_ids.len(), head_ids.len()) {
        (0, 0) => Err(FleetError::SuccessorActivationNotReady),
        (1, 1) => Ok(()),
        _ => Err(successor_corrupt(
            "legacy genesis activation and head cardinality is partial",
        )),
    }
}

fn verify_bound_bridge(
    genesis: &AuditedGenesisRoot,
    authority: &BoundSuccessorAuthority,
) -> Result<PinnedGenesisSuccessorKeyBridge> {
    let witness = genesis.immutable_successor_witness()?;
    verify_pinned_genesis_successor_key_bridge(
        &authority.bridge_bytes,
        authority.bridge_pin,
        &witness,
    )
    .map_err(|_| {
        FleetError::SuccessorActivationConflict(SuccessorActivationConflictKind::BoundAuthority)
    })
}

fn prepare_candidate(
    candidate: &SuccessorActivationCandidate,
    scope: &TrustedControlScope,
    authority: &BoundSuccessorAuthority,
    bridge: &PinnedGenesisSuccessorKeyBridge,
) -> Result<PreparedSuccessor> {
    let verified = verify_successor_registry_activation(
        candidate.canonical_statement(),
        candidate.canonical_approval_set(),
        &authority.target,
        &authority.test_result,
        bridge,
        &authority.principal_binding,
    )?;
    if &verified.statement().scope != scope.semantic_scope() {
        return Err(FleetError::InvalidScope(
            "successor activation scope does not match repository scope".into(),
        ));
    }
    PreparedSuccessor::new(verified)
}

async fn classify_state(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
) -> Result<ClassifiedState> {
    let transitions = sqlx::query(SELECT_TRANSITIONS_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .fetch_all(&mut **transaction)
        .await?;
    let bridges = sqlx::query(SELECT_BRIDGES_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .fetch_all(&mut **transaction)
        .await?;
    let currents = sqlx::query(SELECT_CURRENT_HEADS_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .fetch_all(&mut **transaction)
        .await?;
    match (transitions.len(), bridges.len(), currents.len()) {
        (0, 0, 0) => Ok(ClassifiedState::Ready),
        (2, 1, 1) => {
            let mut transitions = transitions.into_iter();
            let genesis = transitions.next().expect("length checked");
            let successor = transitions.next().expect("length checked");
            if genesis.try_get::<i64, _>("generation")? != 0
                || successor.try_get::<i64, _>("generation")? != 1
            {
                return Err(successor_corrupt(
                    "transition history is not the exact generation zero/one prefix",
                ));
            }
            Ok(ClassifiedState::Accepted {
                genesis: Box::new(genesis),
                successor: Box::new(successor),
                bridge: Box::new(bridges.into_iter().next().expect("length checked")),
                current: Box::new(currents.into_iter().next().expect("length checked")),
            })
        }
        _ => Err(successor_corrupt(
            "successor transition, bridge, and current-head state is partial or cross-wired",
        )),
    }
}

async fn audit_ready_state(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    authority: &BoundSuccessorAuthority,
    genesis: &AuditedGenesisRoot,
    locked: &LockedControlHead,
) -> Result<()> {
    let consistency_key = registry_activation_consistency_partition_key(scope.semantic_scope())?;
    let rows = sqlx::query(
        "SELECT event_id, shard, committed_offset FROM public.memory_control_events \
         WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 \
           AND consistency_family = $4 AND consistency_key_digest = $5 \
         ORDER BY shard, committed_offset LIMIT 3",
    )
    .bind(scope.tenant_id())
    .bind(scope.project())
    .bind(bytes(authority.genesis.bootstrap.epoch_id().digest()))
    .bind(ACTIVATION_CONSISTENCY_FAMILY)
    .bind(bytes(consistency_key.key_digest))
    .fetch_all(&mut **transaction)
    .await?;
    if rows.len() != 1 {
        return Err(successor_corrupt(
            "ready state requires exactly the audited genesis registry event",
        ));
    }
    let row = &rows[0];
    expect_digest(
        row,
        "event_id",
        genesis.inspection.accepted_event_id.digest(),
    )?;
    expect_i32(
        row,
        "shard",
        i32::from(genesis.inspection.append_position.shard),
    )?;
    expect_i64(
        row,
        "committed_offset",
        offset_as_i64(genesis.inspection.append_position.committed_offset)?,
    )?;
    let ahead: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT event_id FROM public.memory_control_events WHERE tenant_id = $1 AND project = $2 \
         AND epoch_id = $3 AND shard = $4 AND committed_offset > $5 \
         ORDER BY committed_offset LIMIT 1",
    )
    .bind(scope.tenant_id())
    .bind(scope.project())
    .bind(bytes(authority.genesis.bootstrap.epoch_id().digest()))
    .bind(i32::from(locked.shard))
    .bind(locked.committed_offset)
    .fetch_optional(&mut **transaction)
    .await?;
    if ahead.is_some() {
        return Err(successor_corrupt(
            "stable registry shard contains an event ahead of its locked head",
        ));
    }
    Ok(())
}

fn materialize_successor(
    scope: &TrustedControlScope,
    authority: &BoundSuccessorAuthority,
    genesis: &AuditedGenesisRoot,
    prepared: &PreparedSuccessor,
    locked: &LockedControlHead,
    accepted_at_database: DateTime<Utc>,
) -> Result<MaterializedSuccessor> {
    let predecessor_accepted_at = genesis.inspection.accepted_at.clone();
    let accepted_at = stored_contract(CanonicalTimestamp::from_datetime(&accepted_at_database))?;
    if prepared.verified.statement().effective_from < predecessor_accepted_at {
        return Err(FleetError::SuccessorActivationTiming(
            SuccessorActivationTimingKind::BeforePredecessorAcceptance,
        ));
    }
    if prepared.verified.statement().effective_from > accepted_at {
        return Err(FleetError::SuccessorActivationTiming(
            SuccessorActivationTimingKind::FutureEffective,
        ));
    }
    let receipt = prepared
        .verified
        .receipt_at(&genesis.inspection.accepted_at, accepted_at)?;
    let event = SuccessorRegistryActivatedEventV1::from_verified(&prepared.verified, &receipt)?;
    let head = prepared.verified.resulting_registry_head(&receipt)?;
    let activation_id = receipt.activation_id()?;
    let accepted_event_id = event.accepted_event_id()?;
    let consistency_key = event.consistency_partition_key()?;
    let expected_consistency_key =
        registry_activation_consistency_partition_key(scope.semantic_scope())?;
    if consistency_key != expected_consistency_key
        || consistency_key.family.as_str() != ACTIVATION_CONSISTENCY_FAMILY
    {
        return Err(successor_corrupt(
            "successor consistency family changed from registry.activation",
        ));
    }
    let next_offset = locked
        .committed_offset
        .checked_add(1)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| successor_corrupt("successor control offset overflowed INT8"))?;
    let append_position = AppendPositionV1 {
        epoch_id: authority.genesis.bootstrap.epoch_id(),
        shard: locked.shard,
        committed_offset: stored_contract(CommittedOffsetV1::new(next_offset))?,
    };
    let append_chain_digest =
        derive_append_chain_digest(locked.chain_digest, accepted_event_id, &append_position)?;
    let canonical_receipt = encode_canonical(&receipt)?;
    let canonical_event = encode_canonical(&event)?;
    let canonical_head = encode_canonical(&head)?;
    let effective_from_database =
        canonical_timestamp_to_database(&prepared.verified.statement().effective_from)?;
    Ok(MaterializedSuccessor {
        receipt,
        event,
        head,
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

async fn insert_genesis_transition(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    authority: &BoundSuccessorAuthority,
    genesis: &AuditedGenesisRoot,
) -> Result<()> {
    let generation: Option<i64> = sqlx::query_scalar(INSERT_GENESIS_TRANSITION_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(bytes(genesis.inspection.activation_id.digest()))
        .bind(authority.genesis.package.canonical_bytes())
        .bind(&genesis.canonical_head_binding)
        .fetch_optional(&mut **transaction)
        .await?;
    if generation != Some(0) {
        return Err(successor_corrupt(
            "lazy genesis transition insert returned the wrong generation",
        ));
    }
    Ok(())
}

async fn insert_genesis_current_head(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    genesis: &AuditedGenesisRoot,
) -> Result<()> {
    let generation: Option<i64> = sqlx::query_scalar(INSERT_GENESIS_CURRENT_HEAD_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(bytes(genesis.inspection.activation_id.digest()))
        .bind(ACTIVE_HEAD_STATE)
        .fetch_optional(&mut **transaction)
        .await?;
    if generation != Some(0) {
        return Err(successor_corrupt(
            "lazy current-head insert returned the wrong generation",
        ));
    }
    Ok(())
}

async fn insert_control_event(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    accepted: &MaterializedSuccessor,
) -> Result<()> {
    let consistency_key = accepted.event.consistency_partition_key()?;
    let event_id: Option<Vec<u8>> = sqlx::query_scalar(INSERT_CONTROL_EVENT_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(bytes(accepted.append_position.epoch_id.digest()))
        .bind(i32::from(accepted.append_position.shard))
        .bind(offset_as_i64(accepted.append_position.committed_offset)?)
        .bind(bytes(accepted.accepted_event_id.digest()))
        .bind(
            i32::try_from(accepted.event.schema_version)
                .map_err(|_| successor_corrupt("successor event schema version exceeds INT4"))?,
        )
        .bind(accepted.event.event_kind.as_str())
        .bind(bytes(accepted.activation_id.digest()))
        .bind(ACTIVATION_CONSISTENCY_FAMILY)
        .bind(bytes(consistency_key.key_digest))
        .bind(&accepted.canonical_event)
        .bind(bytes(accepted.previous_chain_digest))
        .bind(bytes(accepted.append_chain_digest))
        .bind(accepted.accepted_at_database)
        .fetch_optional(&mut **transaction)
        .await?;
    if event_id.as_deref() != Some(accepted.accepted_event_id.digest().as_bytes()) {
        return Err(successor_corrupt(
            "successor event insert returned a different event id",
        ));
    }
    Ok(())
}

async fn insert_successor_transition(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    authority: &BoundSuccessorAuthority,
    genesis: &AuditedGenesisRoot,
    prepared: &PreparedSuccessor,
    accepted: &MaterializedSuccessor,
) -> Result<()> {
    let statement = prepared.verified.statement();
    let profile = &statement.profile;
    let generation: Option<i64> = sqlx::query_scalar(INSERT_SUCCESSOR_TRANSITION_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(bytes(genesis.inspection.activation_id.digest()))
        .bind(bytes(accepted.activation_id.digest()))
        .bind(bytes(prepared.statement_id.digest()))
        .bind(bytes(statement.target_package_digest))
        .bind(bytes(statement.target_activation_policy.entry_digest))
        .bind(bytes(statement.test_vector_result_digest.digest()))
        .bind(profile.profile_id.as_str())
        .bind(bytes(profile.profile_digest))
        .bind(bytes(profile.vector_manifest_digest))
        .bind(scope.semantic_scope().tenant_namespace.as_str())
        .bind(scope.semantic_scope().project_namespace.as_str())
        .bind(accepted.effective_from_database)
        .bind(accepted.accepted_at_database)
        .bind(bytes(accepted.accepted_event_id.digest()))
        .bind(bytes(accepted.append_position.epoch_id.digest()))
        .bind(i32::from(accepted.append_position.shard))
        .bind(offset_as_i64(accepted.append_position.committed_offset)?)
        .bind(statement.proposer_principal_id.as_str())
        .bind(statement.package_author_principal_id.as_str())
        .bind(&prepared.approval_ids_packed)
        .bind(prepared.approval_count)
        .bind(prepared.required_threshold)
        .bind(authority.target.canonical_bytes())
        .bind(prepared.verified.canonical_statement())
        .bind(prepared.verified.canonical_approval_set())
        .bind(authority.test_result.canonical_bytes())
        .bind(&accepted.canonical_receipt)
        .bind(&accepted.canonical_event)
        .bind(&accepted.canonical_head)
        .fetch_optional(&mut **transaction)
        .await?;
    if generation != Some(1) {
        return Err(successor_corrupt(
            "successor transition insert returned the wrong generation",
        ));
    }
    Ok(())
}

async fn insert_bridge_consumption(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    bridge: &PinnedGenesisSuccessorKeyBridge,
    accepted: &MaterializedSuccessor,
) -> Result<()> {
    let bridge_digest: Option<Vec<u8>> = sqlx::query_scalar(INSERT_BRIDGE_CONSUMPTION_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(bytes(bridge.bridge_digest().digest()))
        .bind(bridge.canonical_bytes())
        .bind(accepted.accepted_at_database)
        .fetch_optional(&mut **transaction)
        .await?;
    if bridge_digest.as_deref() != Some(bridge.bridge_digest().digest().as_bytes()) {
        return Err(successor_corrupt(
            "bridge consumption insert returned a different digest",
        ));
    }
    Ok(())
}

async fn advance_current_head(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
) -> Result<()> {
    let generation: Option<i64> = sqlx::query_scalar(ADVANCE_CURRENT_HEAD_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(ACTIVE_HEAD_STATE)
        .fetch_optional(&mut **transaction)
        .await?;
    if generation != Some(1) {
        return Err(successor_corrupt(
            "exact generation-zero current-head CAS failed",
        ));
    }
    Ok(())
}

async fn advance_control_head(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    locked: &LockedControlHead,
    accepted: &MaterializedSuccessor,
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
        return Err(successor_corrupt(
            "exact stable registry control-head CAS failed",
        ));
    };
    expect_i64(&row, "last_committed_offset", next_offset)?;
    expect_digest(&row, "chain_digest", accepted.append_chain_digest)
}

struct AuditedAcceptedSuccessor {
    inspection: AcceptedSuccessorActivation,
    canonical_statement: Vec<u8>,
    canonical_approval_set: Vec<u8>,
}

fn classify_replay(
    prepared: &PreparedSuccessor,
    stored: AuditedAcceptedSuccessor,
) -> Result<AcceptedSuccessorActivation> {
    classify_replay_identity(
        prepared.statement_id,
        prepared.verified.canonical_statement(),
        prepared.verified.canonical_approval_set(),
        stored.inspection.statement_id,
        &stored.canonical_statement,
        &stored.canonical_approval_set,
    )?;
    Ok(stored.inspection)
}

fn classify_replay_identity(
    candidate_statement_id: SuccessorRegistryActivationStatementId,
    candidate_statement: &[u8],
    candidate_approval_set: &[u8],
    stored_statement_id: SuccessorRegistryActivationStatementId,
    stored_statement: &[u8],
    stored_approval_set: &[u8],
) -> Result<()> {
    if stored_statement_id != candidate_statement_id {
        return Err(FleetError::SuccessorActivationStale);
    }
    if stored_statement != candidate_statement {
        return Err(successor_corrupt(
            "one successor statement digest maps to different canonical bytes",
        ));
    }
    if stored_approval_set != candidate_approval_set {
        return Err(FleetError::SuccessorActivationConflict(
            SuccessorActivationConflictKind::ApprovalSet,
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // exhaustive durable graph audit
async fn audit_accepted_state(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    authority: &BoundSuccessorAuthority,
    genesis: &AuditedGenesisRoot,
    bridge: &PinnedGenesisSuccessorKeyBridge,
    locked: &LockedControlHead,
    genesis_row: &PgRow,
    successor_row: &PgRow,
    bridge_row: &PgRow,
    current_row: &PgRow,
) -> Result<AuditedAcceptedSuccessor> {
    audit_genesis_transition_row(scope, authority, genesis, genesis_row)?;
    let canonical_statement: Vec<u8> = successor_row.try_get("canonical_statement")?;
    let canonical_approval_set: Vec<u8> = successor_row.try_get("canonical_approval_set")?;
    let canonical_package: Vec<u8> = successor_row.try_get("canonical_package")?;
    let canonical_test_result: Vec<u8> = successor_row.try_get("canonical_test_result")?;
    let canonical_receipt: Vec<u8> = successor_row.try_get("canonical_receipt")?;
    let canonical_event: Vec<u8> = successor_row.try_get("canonical_event")?;
    let canonical_head: Vec<u8> = successor_row.try_get("canonical_head")?;
    for (name, canonical) in [
        ("package", canonical_package.as_slice()),
        ("statement", canonical_statement.as_slice()),
        ("approval set", canonical_approval_set.as_slice()),
        ("test result", canonical_test_result.as_slice()),
        ("receipt", canonical_receipt.as_slice()),
        ("event", canonical_event.as_slice()),
        ("head", canonical_head.as_slice()),
    ] {
        require_canonical(canonical).map_err(|error| {
            successor_corrupt(format!("stored successor {name} is not canonical: {error}"))
        })?;
    }
    if canonical_package != authority.target.canonical_bytes()
        || canonical_test_result != authority.test_result.canonical_bytes()
    {
        return Err(successor_corrupt(
            "stored successor package or test result differs from bound authority",
        ));
    }
    let verified = verify_successor_registry_activation(
        &canonical_statement,
        &canonical_approval_set,
        &authority.target,
        &authority.test_result,
        bridge,
        &authority.principal_binding,
    )
    .map_err(|error| {
        successor_corrupt(format!("stored successor authority is invalid: {error}"))
    })?;
    if verified.statement().effective_from < genesis.inspection.accepted_at {
        return Err(successor_corrupt(
            "stored successor became effective before genesis acceptance",
        ));
    }
    let receipt: SuccessorRegistryActivationReceiptV1 = decode_strict(&canonical_receipt)
        .map_err(|error| successor_corrupt(format!("stored receipt is invalid: {error}")))?;
    stored_contract(receipt.validate_against(&verified))?;
    let event: SuccessorRegistryActivatedEventV1 = decode_strict(&canonical_event)
        .map_err(|error| successor_corrupt(format!("stored event is invalid: {error}")))?;
    stored_contract(event.validate_against(&verified, &receipt))?;
    let head: RegistryHeadBindingV1 = decode_strict(&canonical_head)
        .map_err(|error| successor_corrupt(format!("stored head is invalid: {error}")))?;
    stored_contract(head.validate_shape())?;
    if stored_contract(encode_canonical(&receipt))? != canonical_receipt
        || stored_contract(encode_canonical(&event))? != canonical_event
        || stored_contract(encode_canonical(&head))? != canonical_head
        || stored_contract(verified.resulting_registry_head(&receipt))? != head
    {
        return Err(successor_corrupt(
            "stored successor receipt, event, or head changed during reconstruction",
        ));
    }
    let statement_id = stored_contract(verified.statement().statement_id())?;
    let activation_id = stored_contract(receipt.activation_id())?;
    let accepted_event_id = stored_contract(event.accepted_event_id())?;
    let append_position = stored_successor_position(successor_row)?;
    audit_successor_transition_row(
        scope,
        authority,
        genesis,
        &verified,
        &receipt,
        &event,
        &head,
        statement_id,
        activation_id,
        accepted_event_id,
        &append_position,
        successor_row,
    )?;
    audit_bridge_row(
        scope,
        genesis,
        bridge,
        activation_id,
        accepted_event_id,
        &head,
        &append_position,
        &receipt,
        bridge_row,
    )?;
    audit_current_head_row(
        scope,
        activation_id,
        accepted_event_id,
        &head,
        &append_position,
        &receipt,
        &verified.statement().profile,
        &canonical_head,
        current_row,
    )?;
    audit_successor_control_event(
        transaction,
        scope,
        authority,
        genesis,
        locked,
        activation_id,
        accepted_event_id,
        &event,
        &append_position,
        &canonical_event,
        &receipt,
    )
    .await?;
    audit_registry_stream_pair(
        transaction,
        scope,
        authority,
        genesis,
        accepted_event_id,
        &append_position,
    )
    .await?;
    Ok(AuditedAcceptedSuccessor {
        inspection: AcceptedSuccessorActivation {
            statement_id,
            activation_id,
            accepted_event_id,
            registry_head: head,
            append_position,
            bridge_digest: bridge.bridge_digest(),
            accepted_at: receipt.accepted_at,
        },
        canonical_statement,
        canonical_approval_set,
    })
}

#[allow(clippy::too_many_lines)] // every generation-zero projection column is reconstructed
fn audit_genesis_transition_row(
    scope: &TrustedControlScope,
    authority: &BoundSuccessorAuthority,
    genesis: &AuditedGenesisRoot,
    row: &PgRow,
) -> Result<()> {
    let statement = genesis.verified.statement();
    let receipt = &genesis.receipt;
    expect_i64(row, "generation", 0)?;
    expect_digest(
        row,
        "activation_id",
        genesis.inspection.activation_id.digest(),
    )?;
    expect_digest(
        row,
        "statement_id",
        genesis.inspection.statement_id.digest(),
    )?;
    expect_digest(
        row,
        "package_digest",
        genesis.inspection.registry_head.package_digest,
    )?;
    expect_digest(
        row,
        "activation_policy_digest",
        genesis.inspection.registry_head.activation_policy_digest,
    )?;
    expect_digest(
        row,
        "test_result_digest",
        statement.test_vector_result_digest.digest(),
    )?;
    audit_profile_scope_columns(row, scope, &statement.profile)?;
    expect_timestamp(
        row,
        "effective_from",
        canonical_timestamp_to_database(&genesis.inspection.effective_from)?,
    )?;
    expect_timestamp(
        row,
        "accepted_at",
        canonical_timestamp_to_database(&genesis.inspection.accepted_at)?,
    )?;
    expect_digest(
        row,
        "source_event_id",
        genesis.inspection.accepted_event_id.digest(),
    )?;
    expect_digest(
        row,
        "source_epoch_id",
        genesis.inspection.append_position.epoch_id.digest(),
    )?;
    expect_i32(
        row,
        "source_shard",
        i32::from(genesis.inspection.append_position.shard),
    )?;
    expect_i64(
        row,
        "source_committed_offset",
        offset_as_i64(genesis.inspection.append_position.committed_offset)?,
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
    audit_approval_columns(
        row,
        &packed_approval_ids(&receipt.eligible_approvals),
        receipt.eligible_approvals.len(),
        receipt.required_threshold,
    )?;
    for (column, expected) in [
        (
            "root_activation_id",
            genesis.inspection.activation_id.digest(),
        ),
        (
            "root_package_digest",
            genesis.inspection.registry_head.package_digest,
        ),
        (
            "root_activation_policy_digest",
            genesis.inspection.registry_head.activation_policy_digest,
        ),
        ("root_profile_digest", statement.profile.profile_digest),
        (
            "root_vector_manifest_digest",
            statement.profile.vector_manifest_digest,
        ),
        (
            "root_source_event_id",
            genesis.inspection.accepted_event_id.digest(),
        ),
        (
            "root_source_epoch_id",
            genesis.inspection.append_position.epoch_id.digest(),
        ),
    ] {
        expect_digest(row, column, expected)?;
    }
    expect_text(
        row,
        "root_profile_id",
        statement.profile.profile_id.as_str(),
    )?;
    expect_text(
        row,
        "root_contract_tenant_namespace",
        scope.semantic_scope().tenant_namespace.as_str(),
    )?;
    expect_text(
        row,
        "root_contract_project_namespace",
        scope.semantic_scope().project_namespace.as_str(),
    )?;
    expect_timestamp(
        row,
        "root_effective_from",
        canonical_timestamp_to_database(&genesis.inspection.effective_from)?,
    )?;
    expect_timestamp(
        row,
        "root_accepted_at",
        canonical_timestamp_to_database(&genesis.inspection.accepted_at)?,
    )?;
    expect_i32(
        row,
        "root_source_shard",
        i32::from(genesis.inspection.append_position.shard),
    )?;
    expect_i64(
        row,
        "root_source_committed_offset",
        offset_as_i64(genesis.inspection.append_position.committed_offset)?,
    )?;
    for column in [
        "predecessor_generation",
        "predecessor_activation_id",
        "predecessor_package_digest",
        "predecessor_activation_policy_digest",
        "predecessor_profile_id",
        "predecessor_profile_digest",
        "predecessor_vector_manifest_digest",
        "predecessor_contract_tenant_namespace",
        "predecessor_contract_project_namespace",
        "predecessor_effective_from",
        "predecessor_accepted_at",
        "predecessor_source_event_id",
        "predecessor_source_epoch_id",
        "predecessor_source_shard",
        "predecessor_source_committed_offset",
    ] {
        if !row.try_get_raw(column)?.is_null() {
            return Err(successor_corrupt(format!(
                "generation-zero predecessor column {column} is not null"
            )));
        }
    }
    expect_raw_bytes(
        row,
        "canonical_package",
        authority.genesis.package.canonical_bytes(),
    )?;
    expect_raw_bytes(row, "canonical_statement", &genesis.canonical_statement)?;
    expect_raw_bytes(
        row,
        "canonical_approval_set",
        &genesis.canonical_approval_set,
    )?;
    expect_raw_bytes(
        row,
        "canonical_test_result",
        authority.genesis.test_result.canonical_bytes(),
    )?;
    expect_raw_bytes(row, "canonical_receipt", &genesis.canonical_receipt)?;
    expect_raw_bytes(row, "canonical_event", &genesis.canonical_event)?;
    expect_raw_bytes(row, "canonical_head", &genesis.canonical_head_binding)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn audit_successor_transition_row(
    scope: &TrustedControlScope,
    authority: &BoundSuccessorAuthority,
    genesis: &AuditedGenesisRoot,
    verified: &VerifiedSuccessorRegistryActivationRequest,
    receipt: &SuccessorRegistryActivationReceiptV1,
    event: &SuccessorRegistryActivatedEventV1,
    head: &RegistryHeadBindingV1,
    statement_id: SuccessorRegistryActivationStatementId,
    activation_id: SuccessorRegistryActivationId,
    accepted_event_id: AcceptedEventId,
    position: &AppendPositionV1,
    row: &PgRow,
) -> Result<()> {
    let statement = verified.statement();
    expect_i64(row, "generation", 1)?;
    expect_digest(row, "activation_id", activation_id.digest())?;
    expect_digest(row, "statement_id", statement_id.digest())?;
    expect_digest(row, "package_digest", statement.target_package_digest)?;
    expect_digest(
        row,
        "activation_policy_digest",
        statement.target_activation_policy.entry_digest,
    )?;
    expect_digest(
        row,
        "test_result_digest",
        statement.test_vector_result_digest.digest(),
    )?;
    audit_profile_scope_columns(row, scope, &statement.profile)?;
    expect_timestamp(
        row,
        "effective_from",
        canonical_timestamp_to_database(&statement.effective_from)?,
    )?;
    expect_timestamp(
        row,
        "accepted_at",
        canonical_timestamp_to_database(&receipt.accepted_at)?,
    )?;
    expect_digest(row, "source_event_id", accepted_event_id.digest())?;
    expect_digest(row, "source_epoch_id", position.epoch_id.digest())?;
    expect_i32(row, "source_shard", i32::from(position.shard))?;
    expect_i64(
        row,
        "source_committed_offset",
        offset_as_i64(position.committed_offset)?,
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
    audit_approval_columns(
        row,
        &packed_approval_ids(&receipt.eligible_approvals),
        receipt.eligible_approvals.len(),
        receipt.required_v1_threshold,
    )?;
    let root_statement = genesis.verified.statement();
    for (column, expected) in [
        (
            "root_activation_id",
            genesis.inspection.activation_id.digest(),
        ),
        (
            "root_package_digest",
            genesis.inspection.registry_head.package_digest,
        ),
        (
            "root_activation_policy_digest",
            genesis.inspection.registry_head.activation_policy_digest,
        ),
        ("root_profile_digest", root_statement.profile.profile_digest),
        (
            "root_vector_manifest_digest",
            root_statement.profile.vector_manifest_digest,
        ),
        (
            "root_source_event_id",
            genesis.inspection.accepted_event_id.digest(),
        ),
        (
            "root_source_epoch_id",
            genesis.inspection.append_position.epoch_id.digest(),
        ),
        (
            "predecessor_activation_id",
            genesis.inspection.activation_id.digest(),
        ),
        (
            "predecessor_package_digest",
            genesis.inspection.registry_head.package_digest,
        ),
        (
            "predecessor_activation_policy_digest",
            genesis.inspection.registry_head.activation_policy_digest,
        ),
        (
            "predecessor_profile_digest",
            root_statement.profile.profile_digest,
        ),
        (
            "predecessor_vector_manifest_digest",
            root_statement.profile.vector_manifest_digest,
        ),
        (
            "predecessor_source_event_id",
            genesis.inspection.accepted_event_id.digest(),
        ),
        (
            "predecessor_source_epoch_id",
            genesis.inspection.append_position.epoch_id.digest(),
        ),
    ] {
        expect_digest(row, column, expected)?;
    }
    expect_text(
        row,
        "root_profile_id",
        root_statement.profile.profile_id.as_str(),
    )?;
    expect_text(
        row,
        "predecessor_profile_id",
        root_statement.profile.profile_id.as_str(),
    )?;
    for column in [
        "root_contract_tenant_namespace",
        "predecessor_contract_tenant_namespace",
    ] {
        expect_text(
            row,
            column,
            scope.semantic_scope().tenant_namespace.as_str(),
        )?;
    }
    for column in [
        "root_contract_project_namespace",
        "predecessor_contract_project_namespace",
    ] {
        expect_text(
            row,
            column,
            scope.semantic_scope().project_namespace.as_str(),
        )?;
    }
    for column in ["root_effective_from", "predecessor_effective_from"] {
        expect_timestamp(
            row,
            column,
            canonical_timestamp_to_database(&genesis.inspection.effective_from)?,
        )?;
    }
    for column in ["root_accepted_at", "predecessor_accepted_at"] {
        expect_timestamp(
            row,
            column,
            canonical_timestamp_to_database(&genesis.inspection.accepted_at)?,
        )?;
    }
    for column in ["root_source_shard", "predecessor_source_shard"] {
        expect_i32(
            row,
            column,
            i32::from(genesis.inspection.append_position.shard),
        )?;
    }
    for column in [
        "root_source_committed_offset",
        "predecessor_source_committed_offset",
    ] {
        expect_i64(
            row,
            column,
            offset_as_i64(genesis.inspection.append_position.committed_offset)?,
        )?;
    }
    expect_i64(row, "predecessor_generation", 0)?;
    expect_raw_bytes(row, "canonical_package", authority.target.canonical_bytes())?;
    expect_raw_bytes(row, "canonical_statement", verified.canonical_statement())?;
    expect_raw_bytes(
        row,
        "canonical_approval_set",
        verified.canonical_approval_set(),
    )?;
    expect_raw_bytes(
        row,
        "canonical_test_result",
        authority.test_result.canonical_bytes(),
    )?;
    expect_raw_bytes(row, "canonical_receipt", &encode_canonical(receipt)?)?;
    expect_raw_bytes(row, "canonical_event", &encode_canonical(event)?)?;
    expect_raw_bytes(row, "canonical_head", &encode_canonical(head)?)
}

#[allow(clippy::too_many_arguments)]
fn audit_bridge_row(
    scope: &TrustedControlScope,
    genesis: &AuditedGenesisRoot,
    bridge: &PinnedGenesisSuccessorKeyBridge,
    activation_id: SuccessorRegistryActivationId,
    accepted_event_id: AcceptedEventId,
    head: &RegistryHeadBindingV1,
    position: &AppendPositionV1,
    receipt: &SuccessorRegistryActivationReceiptV1,
    row: &PgRow,
) -> Result<()> {
    expect_digest(row, "bridge_digest", bridge.bridge_digest().digest())?;
    expect_i64(row, "from_generation", 0)?;
    expect_i64(row, "to_generation", 1)?;
    expect_digest(
        row,
        "genesis_activation_id",
        genesis.inspection.activation_id.digest(),
    )?;
    expect_digest(
        row,
        "genesis_package_digest",
        genesis.inspection.registry_head.package_digest,
    )?;
    expect_digest(
        row,
        "genesis_activation_policy_digest",
        genesis.inspection.registry_head.activation_policy_digest,
    )?;
    audit_endpoint_profile_scope(row, scope, "genesis", &bridge.bridge().profile)?;
    expect_timestamp(
        row,
        "genesis_effective_from",
        canonical_timestamp_to_database(&genesis.inspection.effective_from)?,
    )?;
    expect_timestamp(
        row,
        "genesis_accepted_at",
        canonical_timestamp_to_database(&genesis.inspection.accepted_at)?,
    )?;
    expect_digest(
        row,
        "genesis_source_event_id",
        genesis.inspection.accepted_event_id.digest(),
    )?;
    expect_digest(
        row,
        "genesis_source_epoch_id",
        genesis.inspection.append_position.epoch_id.digest(),
    )?;
    expect_i32(
        row,
        "genesis_source_shard",
        i32::from(genesis.inspection.append_position.shard),
    )?;
    expect_i64(
        row,
        "genesis_source_committed_offset",
        offset_as_i64(genesis.inspection.append_position.committed_offset)?,
    )?;
    expect_digest(row, "successor_activation_id", activation_id.digest())?;
    expect_digest(row, "successor_package_digest", head.head.package_digest)?;
    expect_digest(
        row,
        "successor_activation_policy_digest",
        head.head.activation_policy_digest,
    )?;
    audit_endpoint_profile_scope(row, scope, "successor", &bridge.bridge().profile)?;
    expect_timestamp(
        row,
        "successor_effective_from",
        canonical_timestamp_to_database(&head.effective_from)?,
    )?;
    expect_timestamp(
        row,
        "successor_accepted_at",
        canonical_timestamp_to_database(&receipt.accepted_at)?,
    )?;
    expect_digest(row, "successor_source_event_id", accepted_event_id.digest())?;
    expect_digest(row, "successor_source_epoch_id", position.epoch_id.digest())?;
    expect_i32(row, "successor_source_shard", i32::from(position.shard))?;
    expect_i64(
        row,
        "successor_source_committed_offset",
        offset_as_i64(position.committed_offset)?,
    )?;
    expect_raw_bytes(row, "canonical_bridge", bridge.canonical_bytes())?;
    expect_timestamp(
        row,
        "consumed_at",
        canonical_timestamp_to_database(&receipt.accepted_at)?,
    )
}

#[allow(clippy::too_many_arguments)]
fn audit_current_head_row(
    scope: &TrustedControlScope,
    activation_id: SuccessorRegistryActivationId,
    accepted_event_id: AcceptedEventId,
    head: &RegistryHeadBindingV1,
    position: &AppendPositionV1,
    receipt: &SuccessorRegistryActivationReceiptV1,
    profile: &crate::memory_contracts::common::ProfileReferenceV1,
    canonical_head: &[u8],
    row: &PgRow,
) -> Result<()> {
    expect_text(row, "head_state", ACTIVE_HEAD_STATE)?;
    expect_i64(row, "generation", 1)?;
    expect_digest(row, "activation_id", activation_id.digest())?;
    expect_digest(row, "package_digest", head.head.package_digest)?;
    expect_digest(
        row,
        "activation_policy_digest",
        head.head.activation_policy_digest,
    )?;
    audit_profile_scope_columns(row, scope, profile)?;
    expect_timestamp(
        row,
        "effective_from",
        canonical_timestamp_to_database(&head.effective_from)?,
    )?;
    expect_timestamp(
        row,
        "accepted_at",
        canonical_timestamp_to_database(&receipt.accepted_at)?,
    )?;
    expect_digest(row, "source_event_id", accepted_event_id.digest())?;
    expect_digest(row, "source_epoch_id", position.epoch_id.digest())?;
    expect_i32(row, "source_shard", i32::from(position.shard))?;
    expect_i64(
        row,
        "source_committed_offset",
        offset_as_i64(position.committed_offset)?,
    )?;
    expect_raw_bytes(row, "canonical_head", canonical_head)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)] // bounded ledger proof is explicit
async fn audit_successor_control_event(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    authority: &BoundSuccessorAuthority,
    genesis: &AuditedGenesisRoot,
    locked: &LockedControlHead,
    activation_id: SuccessorRegistryActivationId,
    accepted_event_id: AcceptedEventId,
    event: &SuccessorRegistryActivatedEventV1,
    position: &AppendPositionV1,
    canonical_event: &[u8],
    receipt: &SuccessorRegistryActivationReceiptV1,
) -> Result<()> {
    let consistency_key = event.consistency_partition_key()?;
    let expected_shard = authority
        .genesis
        .bootstrap
        .partition_for(&consistency_key)?;
    if position.epoch_id != authority.genesis.bootstrap.epoch_id()
        || position.shard != expected_shard
        || position.shard != locked.shard
    {
        return Err(successor_corrupt(
            "successor source event escaped the authority-derived stable shard",
        ));
    }
    let row = sqlx::query(
        "SELECT event_id, event_schema_version, event_kind, semantic_object_digest, \
                consistency_family, consistency_key_digest, canonical_event, \
                previous_chain_digest, chain_digest, accepted_at \
         FROM public.memory_control_events WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 \
           AND shard = $4 AND committed_offset = $5",
    )
    .bind(scope.tenant_id())
    .bind(scope.project())
    .bind(bytes(position.epoch_id.digest()))
    .bind(i32::from(position.shard))
    .bind(offset_as_i64(position.committed_offset)?)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| successor_corrupt("successor control event is missing"))?;
    expect_digest(&row, "event_id", accepted_event_id.digest())?;
    expect_i32(
        &row,
        "event_schema_version",
        i32::try_from(event.schema_version)
            .map_err(|_| successor_corrupt("stored event schema version exceeds INT4"))?,
    )?;
    expect_text(&row, "event_kind", event.event_kind.as_str())?;
    expect_digest(&row, "semantic_object_digest", activation_id.digest())?;
    expect_text(&row, "consistency_family", ACTIVATION_CONSISTENCY_FAMILY)?;
    expect_digest(&row, "consistency_key_digest", consistency_key.key_digest)?;
    expect_raw_bytes(&row, "canonical_event", canonical_event)?;
    expect_timestamp(
        &row,
        "accepted_at",
        canonical_timestamp_to_database(&receipt.accepted_at)?,
    )?;
    let previous_chain = digest_from_row(&row, "previous_chain_digest")?;
    let chain = derive_append_chain_digest(previous_chain, accepted_event_id, position)?;
    expect_digest(&row, "chain_digest", chain)?;
    let source_offset = offset_as_i64(position.committed_offset)?;
    let successor_accepted_at: DateTime<Utc> = row.try_get("accepted_at")?;
    if locked.committed_offset < source_offset || locked.advanced_at < successor_accepted_at {
        return Err(successor_corrupt(
            "locked control head does not cover the successor source event",
        ));
    }
    if locked.committed_offset == source_offset
        && (locked.chain_digest != chain || locked.advanced_at != successor_accepted_at)
    {
        return Err(successor_corrupt(
            "locked control head changed the successor source tip",
        ));
    }
    let predecessor_offset = source_offset
        .checked_sub(1)
        .ok_or_else(|| successor_corrupt("successor source offset underflowed"))?;
    let predecessor = sqlx::query(
        "SELECT event_id, previous_chain_digest, chain_digest, accepted_at \
         FROM public.memory_control_events \
         WHERE tenant_id = $1 AND project = $2 \
         AND epoch_id = $3 AND shard = $4 AND committed_offset = $5",
    )
    .bind(scope.tenant_id())
    .bind(scope.project())
    .bind(bytes(position.epoch_id.digest()))
    .bind(i32::from(position.shard))
    .bind(predecessor_offset)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| successor_corrupt("successor source predecessor is missing"))?;
    let predecessor_position = AppendPositionV1 {
        epoch_id: position.epoch_id,
        shard: position.shard,
        committed_offset: stored_contract(CommittedOffsetV1::new(
            u64::try_from(predecessor_offset)
                .map_err(|_| successor_corrupt("negative successor predecessor offset"))?,
        ))?,
    };
    let predecessor_event_id =
        AcceptedEventId::from_digest(digest_from_row(&predecessor, "event_id")?);
    let predecessor_previous = digest_from_row(&predecessor, "previous_chain_digest")?;
    let predecessor_derived = derive_append_chain_digest(
        predecessor_previous,
        predecessor_event_id,
        &predecessor_position,
    )?;
    expect_digest(&predecessor, "chain_digest", predecessor_derived)?;
    if predecessor_derived != previous_chain {
        return Err(successor_corrupt(
            "successor source event is detached from its immediate predecessor",
        ));
    }
    let predecessor_accepted_at: DateTime<Utc> = predecessor.try_get("accepted_at")?;
    let genesis_accepted_at = canonical_timestamp_to_database(&genesis.inspection.accepted_at)?;
    if predecessor_accepted_at < genesis_accepted_at
        || predecessor_accepted_at > successor_accepted_at
    {
        return Err(successor_corrupt(
            "successor source predecessor acceptance time is out of order",
        ));
    }
    let ahead: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT event_id FROM public.memory_control_events WHERE tenant_id = $1 AND project = $2 \
         AND epoch_id = $3 AND shard = $4 AND committed_offset > $5 \
         ORDER BY committed_offset LIMIT 1",
    )
    .bind(scope.tenant_id())
    .bind(scope.project())
    .bind(bytes(position.epoch_id.digest()))
    .bind(i32::from(locked.shard))
    .bind(locked.committed_offset)
    .fetch_optional(&mut **transaction)
    .await?;
    if ahead.is_some() {
        return Err(successor_corrupt(
            "stable registry shard contains an event ahead of its locked head",
        ));
    }
    Ok(())
}

async fn audit_registry_stream_pair(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    authority: &BoundSuccessorAuthority,
    genesis: &AuditedGenesisRoot,
    successor_event_id: AcceptedEventId,
    successor_position: &AppendPositionV1,
) -> Result<()> {
    let consistency_key = registry_activation_consistency_partition_key(scope.semantic_scope())?;
    let rows = sqlx::query(
        "SELECT event_id, shard, committed_offset FROM public.memory_control_events \
         WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 \
           AND consistency_family = $4 AND consistency_key_digest = $5 \
         ORDER BY shard, committed_offset LIMIT 3",
    )
    .bind(scope.tenant_id())
    .bind(scope.project())
    .bind(bytes(authority.genesis.bootstrap.epoch_id().digest()))
    .bind(ACTIVATION_CONSISTENCY_FAMILY)
    .bind(bytes(consistency_key.key_digest))
    .fetch_all(&mut **transaction)
    .await?;
    if rows.len() != 2 {
        return Err(successor_corrupt(
            "accepted state requires exactly genesis and successor registry events",
        ));
    }
    for (row, event_id, position) in [
        (
            &rows[0],
            genesis.inspection.accepted_event_id,
            &genesis.inspection.append_position,
        ),
        (&rows[1], successor_event_id, successor_position),
    ] {
        expect_digest(row, "event_id", event_id.digest())?;
        expect_i32(row, "shard", i32::from(position.shard))?;
        expect_i64(
            row,
            "committed_offset",
            offset_as_i64(position.committed_offset)?,
        )?;
    }
    Ok(())
}

fn audit_profile_scope_columns(
    row: &PgRow,
    scope: &TrustedControlScope,
    profile: &crate::memory_contracts::common::ProfileReferenceV1,
) -> Result<()> {
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
    )
}

fn audit_endpoint_profile_scope(
    row: &PgRow,
    scope: &TrustedControlScope,
    prefix: &str,
    profile: &crate::memory_contracts::common::ProfileReferenceV1,
) -> Result<()> {
    expect_text(
        row,
        &format!("{prefix}_profile_id"),
        profile.profile_id.as_str(),
    )?;
    expect_digest(
        row,
        &format!("{prefix}_profile_digest"),
        profile.profile_digest,
    )?;
    expect_digest(
        row,
        &format!("{prefix}_vector_manifest_digest"),
        profile.vector_manifest_digest,
    )?;
    expect_text(
        row,
        &format!("{prefix}_contract_tenant_namespace"),
        scope.semantic_scope().tenant_namespace.as_str(),
    )?;
    expect_text(
        row,
        &format!("{prefix}_contract_project_namespace"),
        scope.semantic_scope().project_namespace.as_str(),
    )
}

fn audit_approval_columns(
    row: &PgRow,
    approval_ids_packed: &[u8],
    approval_count: usize,
    required_threshold: u16,
) -> Result<()> {
    expect_raw_bytes(row, "approval_ids_packed", approval_ids_packed)?;
    expect_i32(
        row,
        "approval_count",
        i32::try_from(approval_count)
            .map_err(|_| successor_corrupt("stored approval count exceeds INT4"))?,
    )?;
    expect_i32(row, "required_threshold", i32::from(required_threshold))?;
    expect_bool(row, "separation_of_duty_satisfied", true)
}

fn packed_approval_ids(approvals: &[EligibleApprovalV1]) -> Vec<u8> {
    let mut packed = Vec::with_capacity(approvals.len().saturating_mul(32));
    for approval in approvals {
        packed.extend_from_slice(approval.attestation_id.as_bytes());
    }
    packed
}

fn stored_successor_position(row: &PgRow) -> Result<AppendPositionV1> {
    let shard = u16::try_from(row.try_get::<i32, _>("source_shard")?)
        .map_err(|_| successor_corrupt("stored successor shard is outside UINT16"))?;
    let offset = u64::try_from(row.try_get::<i64, _>("source_committed_offset")?)
        .map_err(|_| successor_corrupt("stored successor offset is negative"))?;
    Ok(AppendPositionV1 {
        epoch_id: crate::memory_contracts::bootstrap::EpochId::from_digest(digest_from_row(
            row,
            "source_epoch_id",
        )?),
        shard,
        committed_offset: stored_contract(CommittedOffsetV1::new(offset))?,
    })
}

fn map_genesis_audit_error(error: FleetError) -> FleetError {
    match error {
        FleetError::Database(error) => FleetError::Database(error),
        FleetError::Migration(error) => FleetError::Migration(error),
        FleetError::GenesisActivationNotReady => FleetError::SuccessorActivationNotReady,
        FleetError::GenesisActivationConflict(_) => {
            FleetError::SuccessorActivationConflict(SuccessorActivationConflictKind::BoundAuthority)
        }
        FleetError::RegistryActivationCorrupt(message) | FleetError::ControlLogCorrupt(message) => {
            FleetError::SuccessorActivationCorrupt(message)
        }
        other => FleetError::SuccessorActivationCorrupt(format!(
            "immutable genesis audit failed: {other}"
        )),
    }
}

fn successor_corrupt(message: impl Into<String>) -> FleetError {
    FleetError::SuccessorActivationCorrupt(message.into())
}

fn stored_contract<T>(outcome: ContractResult<T>) -> Result<T> {
    outcome.map_err(|error| successor_corrupt(format!("stored contract mismatch: {error}")))
}

fn canonical_timestamp_to_database(timestamp: &CanonicalTimestamp) -> Result<DateTime<Utc>> {
    if !timestamp.is_microsecond_aligned() {
        return Err(successor_corrupt(
            "canonical timestamp is not CockroachDB microsecond aligned",
        ));
    }
    DateTime::parse_from_rfc3339(timestamp.as_str())
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| successor_corrupt("canonical timestamp cannot be represented as TIMESTAMPTZ"))
}

fn offset_as_i64(offset: CommittedOffsetV1) -> Result<i64> {
    i64::try_from(offset.as_u64()).map_err(|_| successor_corrupt("control offset exceeds INT8"))
}

fn bytes(digest: Sha256Digest) -> Vec<u8> {
    digest.as_bytes().to_vec()
}

fn digest_from_row(row: &PgRow, column: &str) -> Result<Sha256Digest> {
    let raw: Vec<u8> = row.try_get(column)?;
    let raw: [u8; 32] = raw
        .try_into()
        .map_err(|_| successor_corrupt(format!("stored {column} digest has the wrong length")))?;
    Ok(Sha256Digest::from_bytes(raw))
}

fn expect_digest(row: &PgRow, column: &str, expected: Sha256Digest) -> Result<()> {
    if digest_from_row(row, column)? != expected {
        return Err(successor_corrupt(format!("stored {column} does not match")));
    }
    Ok(())
}

fn expect_raw_bytes(row: &PgRow, column: &str, expected: &[u8]) -> Result<()> {
    let actual: Vec<u8> = row.try_get(column)?;
    if actual != expected {
        return Err(successor_corrupt(format!("stored {column} does not match")));
    }
    Ok(())
}

fn expect_text(row: &PgRow, column: &str, expected: &str) -> Result<()> {
    let actual: String = row.try_get(column)?;
    if actual != expected {
        return Err(successor_corrupt(format!("stored {column} does not match")));
    }
    Ok(())
}

fn expect_i32(row: &PgRow, column: &str, expected: i32) -> Result<()> {
    let actual: i32 = row.try_get(column)?;
    if actual != expected {
        return Err(successor_corrupt(format!("stored {column} does not match")));
    }
    Ok(())
}

fn expect_i64(row: &PgRow, column: &str, expected: i64) -> Result<()> {
    let actual: i64 = row.try_get(column)?;
    if actual != expected {
        return Err(successor_corrupt(format!("stored {column} does not match")));
    }
    Ok(())
}

fn expect_bool(row: &PgRow, column: &str, expected: bool) -> Result<()> {
    let actual: bool = row.try_get(column)?;
    if actual != expected {
        return Err(successor_corrupt(format!("stored {column} does not match")));
    }
    Ok(())
}

fn expect_timestamp(row: &PgRow, column: &str, expected: DateTime<Utc>) -> Result<()> {
    let actual: DateTime<Utc> = row.try_get(column)?;
    if actual != expected {
        return Err(successor_corrupt(format!("stored {column} does not match")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::memory_contracts::digest::{DigestDomain, domain_separated_digest};

    const CONTROL_LOG_SOURCE: &str = include_str!("../control_log/cockroach.rs");
    const GENESIS_COCKROACH_SOURCE: &str = include_str!("cockroach.rs");
    const GENESIS_AUDIT_SOURCE: &str = include_str!("genesis_audit.rs");
    const SUCCESSOR_SOURCE: &str = include_str!("successor_cockroach.rs");
    const AUTHORITY_RELATIONS: [&str; 10] = [
        "_sqlx_migrations",
        "memory_control_bootstraps",
        "memory_control_log_epochs",
        "memory_control_shard_heads",
        "memory_control_events",
        "memory_registry_activations",
        "memory_registry_heads",
        "memory_registry_transitions",
        "memory_registry_genesis_bridge_consumptions",
        "memory_registry_current_heads_v2",
    ];

    fn production_prefix(source: &'static str) -> &'static str {
        source
            .split_once("#[cfg(test)]")
            .map_or(source, |(code, _)| code)
    }

    fn successor_authority_source() -> String {
        [
            production_prefix(SUCCESSOR_SOURCE),
            production_prefix(GENESIS_AUDIT_SOURCE),
            production_prefix(GENESIS_COCKROACH_SOURCE),
            production_prefix(CONTROL_LOG_SOURCE),
        ]
        .join("\n")
    }

    #[test]
    fn schema_preflight_requires_the_exact_successful_prefix_through_fourteen() {
        assert!(
            REQUIRE_SUCCESSOR_SCHEMA_SQL
                .starts_with("SELECT pg_catalog.current_database() = 'fleet_recall'")
        );
        assert!(REQUIRE_SUCCESSOR_SCHEMA_SQL.contains("count(*) = 14"));
        assert!(REQUIRE_SUCCESSOR_SCHEMA_SQL.contains("bool_and(success)"));
        assert!(REQUIRE_SUCCESSOR_SCHEMA_SQL.contains("FROM public._sqlx_migrations"));
        assert!(REQUIRE_SUCCESSOR_SCHEMA_SQL.contains("version BETWEEN 1 AND 14"));
        assert!(!REQUIRE_SUCCESSOR_SCHEMA_SQL.contains("MAX"));
        assert!(!REQUIRE_SUCCESSOR_SCHEMA_SQL.contains("EXISTS"));
    }

    #[test]
    fn apply_and_inspect_share_the_database_and_schema_first_statement() {
        for (start, end) in [
            (
                "async fn activate_in_transaction(",
                "\nasync fn inspect_in_transaction(",
            ),
            (
                "async fn inspect_in_transaction(",
                "\nasync fn require_successor_schema(",
            ),
        ] {
            let start = SUCCESSOR_SOURCE.find(start).expect("transaction function");
            let end = SUCCESSOR_SOURCE[start..]
                .find(end)
                .map(|offset| start + offset)
                .expect("transaction function boundary");
            let body = &SUCCESSOR_SOURCE[start..end];
            let identity_and_schema = body
                .find("require_successor_schema(transaction).await?")
                .expect("database/schema preflight");
            let next_database_use = body
                .find("require_bound_bootstrap_before_lock(")
                .expect("durable bootstrap read");
            assert!(identity_and_schema < next_database_use);
        }
    }

    #[test]
    fn search_path_and_temporary_shadows_cannot_redirect_successor_authority_sql() {
        let source = successor_authority_source();
        let mut found = BTreeSet::new();

        for token in source.split(|character: char| {
            !(character.is_ascii_alphanumeric() || matches!(character, '_' | '.'))
        }) {
            let relation = token.strip_prefix("public.").unwrap_or(token);
            let is_authority_relation = relation == "_sqlx_migrations"
                || relation.starts_with("memory_control_")
                || relation.starts_with("memory_registry_");
            if !is_authority_relation {
                continue;
            }
            assert!(
                token.starts_with("public."),
                "unqualified successor authority relation can follow search_path: {token}"
            );
            assert!(
                AUTHORITY_RELATIONS.contains(&relation),
                "unreviewed successor authority relation: {relation}"
            );
            found.insert(relation);
        }

        assert_eq!(
            found,
            AUTHORITY_RELATIONS.into_iter().collect(),
            "reachable relation inventory changed"
        );
        assert!(!source.contains("public.public."));
        assert!(!source.contains("pg_temp."));
        assert!(!source.contains("attacker."));

        for function in ["current_database()", "statement_timestamp()"] {
            for (offset, _) in source.match_indices(function) {
                assert!(
                    source[..offset].ends_with("pg_catalog."),
                    "{function} can follow an attacker-controlled search_path"
                );
            }
        }
        for sequence_function in ["nextval(", "currval(", "setval("] {
            assert!(
                !source.contains(sequence_function),
                "successor authority unexpectedly consumes a sequence via {sequence_function}"
            );
        }
    }

    #[test]
    fn stable_stream_lock_and_bounded_classification_are_explicit() {
        assert!(LOCK_CONTROL_HEAD_SQL.contains("FOR UPDATE"));
        assert!(SELECT_TRANSITIONS_SQL.contains("ORDER BY generation LIMIT 3"));
        assert!(SELECT_BRIDGES_SQL.contains("LIMIT 2"));
        assert!(SELECT_CURRENT_HEADS_SQL.contains("LIMIT 2"));
    }

    #[test]
    fn every_insert_is_conflict_observing_and_both_heads_use_exact_cas() {
        for query in [
            INSERT_GENESIS_TRANSITION_SQL,
            INSERT_GENESIS_CURRENT_HEAD_SQL,
            INSERT_CONTROL_EVENT_SQL,
            INSERT_SUCCESSOR_TRANSITION_SQL,
            INSERT_BRIDGE_CONSUMPTION_SQL,
        ] {
            assert!(query.contains("ON CONFLICT DO NOTHING RETURNING"));
        }
        assert!(ADVANCE_CURRENT_HEAD_SQL.contains("h.canonical_head = g.canonical_head"));
        assert!(ADVANCE_CONTROL_HEAD_SQL.contains("last_committed_offset = $8"));
        assert!(ADVANCE_CONTROL_HEAD_SQL.contains("chain_digest = $9"));
    }

    #[test]
    fn source_uses_one_server_timestamp_and_no_database_default() {
        assert_eq!(
            production_prefix(SUCCESSOR_SOURCE)
                .matches("query_scalar(\"SELECT pg_catalog.statement_timestamp()\")")
                .count(),
            1
        );
        assert!(!INSERT_CONTROL_EVENT_SQL.contains("now()"));
        assert!(!INSERT_SUCCESSOR_TRANSITION_SQL.contains("now()"));
        assert!(!INSERT_BRIDGE_CONSUMPTION_SQL.contains("now()"));
    }

    #[test]
    fn future_multi_ceremony_policy_keeps_approval_set_conflict_closed() {
        let statement_id = SuccessorRegistryActivationStatementId::from_digest(
            domain_separated_digest(DigestDomain::Body, b"fixed-successor-statement"),
        );
        let error = classify_replay_identity(
            statement_id,
            b"same canonical statement",
            b"candidate valid approval ceremony",
            statement_id,
            b"same canonical statement",
            b"stored valid approval ceremony",
        )
        .unwrap_err();
        assert!(matches!(
            error,
            FleetError::SuccessorActivationConflict(SuccessorActivationConflictKind::ApprovalSet)
        ));
    }
}
