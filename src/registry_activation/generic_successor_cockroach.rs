//! `CockroachDB` acceptance of the repeatable generation `N -> N+1` registry
//! head (`N >= 1`).
//!
//! The frozen one-time `0 -> 1` ceremony lives in
//! [`super::successor_cockroach`] and is not touched here. It borrows
//! verification keys from a deployment-pinned genesis key bridge because
//! generation zero installs no activation-policy v2. Every later generation is
//! governed by the policy the **currently active** package already installed,
//! so this repository has no bridge, consumes no bridge row, and never audits
//! the immutable genesis root as an authority: it rebuilds
//! [`InstalledSuccessorPolicyV2`] from the durable generation-`N` transition's
//! own canonical package bytes, under the registry control-shard head lock.
//!
//! # Transaction discipline
//!
//! One `SERIALIZABLE` transaction, in this exact order:
//!
//! 1. pin the database identity and the complete successful migration prefix;
//! 2. read the durable bootstrap singleton and require its receipt digest to
//!    equal the deployment pin (the epoch and partition recipe come from it,
//!    never from the request);
//! 3. lock the `registry.activation` control shard head `FOR UPDATE`;
//! 4. load the singleton current head (`LIMIT 2`, exactly one row,
//!    `head_state = 'active'`) and the generation-`N` transition it projects;
//! 5. rebuild the installed activation policy from the **current** head's
//!    package and verify the candidate under it, including
//!    [`VerifiedGenericSuccessorActivation::require_expected_head`] against the
//!    exact durable [`RegistryHeadBindingV1`] — activation ID included, so an
//!    `A -> B -> A` package sequence cannot revive a stale proposal;
//! 6. append the `registry.successor.activated.v2` event to the **control**
//!    ledger, insert the generation-`N+1` transition, compare-and-swap the
//!    current head from `N` to `N+1`, and compare-and-swap the control shard
//!    head.
//!
//! # Deliberately out of scope
//!
//! Contested-set recording and contested-set resolution are **not** implemented
//! here and must not be inferred from this module. No durable table for a
//! contested set exists yet, so the runtime fails closed whenever the head is
//! absent, duplicated, or not `active`, and it never selects between rival
//! successors. The pure contracts for that ceremony
//! (`AuditedContestedSetV1`, `verify_contested_set_resolution`) stay unused
//! until their storage lands.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::postgres::{PgPool, PgRow};
use sqlx::{Postgres, Row, Transaction};

use super::{
    AcceptedGenericSuccessorActivation, GenericSuccessorActivationCandidate,
    GenericSuccessorActivationInspection, GenericSuccessorActivationOutcome,
    GenericSuccessorRepository, ReadyGenericSuccessor,
};
use crate::control_log::{TrustedControlScope, load_durable_genesis_witness};
use crate::error::{SuccessorActivationConflictKind, SuccessorActivationTimingKind};
use crate::memory_contracts::bootstrap::{
    AppendPositionV1, BootstrapReceiptDigest, CommittedOffsetV1, EpochId, GenesisLogEpochV1,
    partition_for_epoch,
};
use crate::memory_contracts::canonical::{decode_strict, encode_canonical, require_canonical};
use crate::memory_contracts::common::{
    CanonicalTimestamp, ProfileReferenceV1, frozen_profile_reference_v1,
};
use crate::memory_contracts::control::derive_append_chain_digest;
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::evidence::AcceptedEventId;
use crate::memory_contracts::evidence_v2::RegistryHeadBindingV1;
use crate::memory_contracts::genesis_activation::registry_activation_consistency_partition_key;
use crate::memory_contracts::registry::{EligibleApprovalV1, ManifestVerifiedRegistryPackage};
use crate::memory_contracts::successor_generic::{
    GenericSuccessorActivatedEventV2, GenericSuccessorActivationId,
    GenericSuccessorActivationReceiptV2, GenericSuccessorActivationStatementId,
    GenericSuccessorActivationStatementV2, GenericSuccessorPrincipalBinding,
    GenericSuccessorReplayClassV2, GenericSuccessorTestRunnerPin, InstalledSuccessorPolicyV2,
    StructurallyClosedSuccessorTargetV2, VerifiedGenericSuccessorActivation,
    VerifiedGenericSuccessorTestResult, classify_generic_successor_replay,
    verify_generic_successor_activation, verify_generic_successor_test_result,
};
use crate::memory_contracts::{ContractError, ContractResult};
use crate::store::cockroach::{RetryPolicy, with_serializable_retry};
use crate::{FleetError, Result};

const ACTIVATION_CONSISTENCY_FAMILY: &str = "registry.activation";
const ACTIVE_HEAD_STATE: &str = "active";
const MAX_BOUND_ARTIFACT_BYTES: usize = 1_048_576;
/// Lowest generation this repository may succeed; `0 -> 1` stays frozen.
const MIN_PREDECESSOR_GENERATION: u32 = 1;

/// The complete successful migration prefix this runtime requires.
///
/// This is a *prefix* gate, exactly like the frozen `0 -> 1` constant it
/// mirrors: later migration rows are compatible and are deliberately not
/// required, because nothing in this transaction reads a relation introduced
/// after 0017.
const REQUIRE_GENERIC_SUCCESSOR_SCHEMA_SQL: &str = "SELECT pg_catalog.current_database() = 'fleet_recall' \
     AND count(*) = 17 \
     AND COALESCE(bool_and(success), false) \
     FROM public._sqlx_migrations WHERE version BETWEEN 1 AND 17";

const LOCK_CONTROL_HEAD_SQL: &str = "SELECT shard_count, last_committed_offset, \
     chain_digest, advanced_at FROM public.memory_control_shard_heads \
     WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4 FOR UPDATE";

const SELECT_CURRENT_HEADS_SQL: &str = "SELECT head_state, generation, activation_id, \
     package_digest, activation_policy_digest, profile_id, profile_digest, \
     vector_manifest_digest, contract_tenant_namespace, contract_project_namespace, \
     effective_from, accepted_at, source_event_id, source_epoch_id, source_shard, \
     source_committed_offset, canonical_head FROM public.memory_registry_current_heads_v2 \
     WHERE tenant_id = $1 AND project = $2 LIMIT 2";

const SELECT_TRANSITION_SQL: &str = "SELECT generation, activation_id, statement_id, \
     package_digest, activation_policy_digest, test_result_digest, profile_id, profile_digest, \
     vector_manifest_digest, contract_tenant_namespace, contract_project_namespace, \
     effective_from, accepted_at, source_event_id, source_epoch_id, source_shard, \
     source_committed_offset, proposer_principal_id, package_author_principal_id, \
     approval_ids_packed, approval_count, required_threshold, separation_of_duty_satisfied, \
     predecessor_generation, canonical_package, canonical_statement, canonical_approval_set, \
     canonical_test_result, canonical_receipt, canonical_event, canonical_head \
     FROM public.memory_registry_transitions \
     WHERE tenant_id = $1 AND project = $2 AND generation = $3 LIMIT 2";

const SELECT_REGISTRY_STREAM_TIP_SQL: &str = "SELECT event_id, shard, committed_offset \
     FROM public.memory_control_events WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 \
       AND consistency_family = $4 AND consistency_key_digest = $5 \
     ORDER BY shard DESC, committed_offset DESC LIMIT 1";

const SELECT_EVENT_AHEAD_SQL: &str = "SELECT event_id FROM public.memory_control_events \
     WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4 \
       AND committed_offset > $5 ORDER BY committed_offset LIMIT 1";

const SELECT_CONTROL_EVENT_SQL: &str = "SELECT event_id, event_schema_version, event_kind, \
     semantic_object_digest, consistency_family, consistency_key_digest, canonical_event, \
     previous_chain_digest, chain_digest, accepted_at FROM public.memory_control_events \
     WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4 \
       AND committed_offset = $5";

const INSERT_CONTROL_EVENT_SQL: &str = "INSERT INTO public.memory_control_events (\
     tenant_id, project, epoch_id, shard, committed_offset, event_id, event_schema_version, \
     event_kind, semantic_object_digest, consistency_family, consistency_key_digest, \
     canonical_event, previous_chain_digest, chain_digest, accepted_at) \
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) \
     ON CONFLICT DO NOTHING RETURNING event_id";

const INSERT_GENERIC_TRANSITION_SQL: &str = "INSERT INTO public.memory_registry_transitions (\
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
     SELECT p.tenant_id, p.project, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, \
     $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, true, p.root_activation_id, \
     p.root_package_digest, p.root_activation_policy_digest, p.root_profile_id, \
     p.root_profile_digest, p.root_vector_manifest_digest, p.root_contract_tenant_namespace, \
     p.root_contract_project_namespace, p.root_effective_from, p.root_accepted_at, \
     p.root_source_event_id, p.root_source_epoch_id, p.root_source_shard, \
     p.root_source_committed_offset, p.generation, p.activation_id, p.package_digest, \
     p.activation_policy_digest, p.profile_id, p.profile_digest, p.vector_manifest_digest, \
     p.contract_tenant_namespace, p.contract_project_namespace, p.effective_from, \
     p.accepted_at, p.source_event_id, p.source_epoch_id, p.source_shard, \
     p.source_committed_offset, $27, $28, $29, $30, $31, $32, $33 \
     FROM public.memory_registry_transitions AS p \
     WHERE p.tenant_id = $1 AND p.project = $2 AND p.generation = $3 \
       AND p.activation_id = $4 ON CONFLICT DO NOTHING RETURNING generation";

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
     FROM public.memory_registry_transitions AS p, public.memory_registry_transitions AS s \
     WHERE h.tenant_id = $1 AND h.project = $2 AND h.head_state = $3 \
       AND h.generation = $4 AND h.activation_id = $5 \
       AND p.tenant_id = h.tenant_id AND p.project = h.project AND p.generation = $4 \
       AND s.tenant_id = h.tenant_id AND s.project = h.project AND s.generation = $6 \
       AND s.activation_id = $7 AND s.predecessor_generation = $4 \
       AND h.activation_id = p.activation_id AND h.package_digest = p.package_digest \
       AND h.activation_policy_digest = p.activation_policy_digest \
       AND h.profile_id = p.profile_id AND h.profile_digest = p.profile_digest \
       AND h.vector_manifest_digest = p.vector_manifest_digest \
       AND h.contract_tenant_namespace = p.contract_tenant_namespace \
       AND h.contract_project_namespace = p.contract_project_namespace \
       AND h.effective_from = p.effective_from AND h.accepted_at = p.accepted_at \
       AND h.source_event_id = p.source_event_id AND h.source_epoch_id = p.source_epoch_id \
       AND h.source_shard = p.source_shard \
       AND h.source_committed_offset = p.source_committed_offset \
       AND h.canonical_head = p.canonical_head RETURNING h.generation";

const ADVANCE_CONTROL_HEAD_SQL: &str = "UPDATE public.memory_control_shard_heads SET \
     last_committed_offset = $5, chain_digest = $6, advanced_at = $7 \
     WHERE tenant_id = $1 AND project = $2 AND epoch_id = $3 AND shard = $4 \
       AND last_committed_offset = $8 AND chain_digest = $9 \
     RETURNING last_committed_offset, chain_digest";

/// Private generic-successor repository bound to one immutable authority set.
#[derive(Clone)]
pub struct CockroachGenericSuccessorRepository {
    pool: PgPool,
    trusted_scope: TrustedControlScope,
    retry_policy: RetryPolicy,
    authority: Arc<BoundGenericSuccessorAuthority>,
}

impl std::fmt::Debug for CockroachGenericSuccessorRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CockroachGenericSuccessorRepository")
            .field("trusted_scope", &self.trusted_scope)
            .field("retry_policy", &self.retry_policy)
            .finish_non_exhaustive()
    }
}

struct BoundGenericSuccessorAuthority {
    bootstrap_receipt_digest: BootstrapReceiptDigest,
    profile: ProfileReferenceV1,
    target: StructurallyClosedSuccessorTargetV2,
    canonical_target_package: Vec<u8>,
    test_result: VerifiedGenericSuccessorTestResult,
    principal_binding: GenericSuccessorPrincipalBinding,
    expected_head: RegistryHeadBindingV1,
}

impl CockroachGenericSuccessorRepository {
    /// Bind one ceremony's offline-verified authority to one physical scope.
    ///
    /// Every argument is deployment-pinned or offline-verified before any
    /// database work: the bootstrap receipt digest and the runner pin come from
    /// trusted configuration, and the target package plus conformance result are
    /// re-derived from their canonical bytes here.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool: PgPool,
        trusted_scope: TrustedControlScope,
        retry_policy: RetryPolicy,
        bootstrap_receipt_digest: BootstrapReceiptDigest,
        canonical_target_package: Vec<u8>,
        canonical_target_test_result: &[u8],
        test_runner_pin: GenericSuccessorTestRunnerPin,
        principal_binding: GenericSuccessorPrincipalBinding,
        expected_head: RegistryHeadBindingV1,
    ) -> Result<Self> {
        require_bound_artifact(
            "generic successor target package",
            &canonical_target_package,
        )?;
        require_bound_artifact(
            "generic successor test result",
            canonical_target_test_result,
        )?;
        let profile = frozen_profile_reference_v1();
        let manifest =
            ManifestVerifiedRegistryPackage::decode(&canonical_target_package, &profile)?;
        let target = StructurallyClosedSuccessorTargetV2::from_manifest_verified(&manifest)?;
        let test_result = verify_generic_successor_test_result(
            canonical_target_test_result,
            test_runner_pin,
            &target,
        )
        .map_err(|_| {
            FleetError::SuccessorActivationConflict(SuccessorActivationConflictKind::BoundAuthority)
        })?;
        expected_head.validate_shape()?;
        if expected_head.effective_until.is_some() {
            return Err(FleetError::SuccessorActivationConflict(
                SuccessorActivationConflictKind::BoundAuthority,
            ));
        }
        Ok(Self {
            pool,
            trusted_scope,
            retry_policy,
            authority: Arc::new(BoundGenericSuccessorAuthority {
                bootstrap_receipt_digest,
                profile,
                target,
                canonical_target_package,
                test_result,
                principal_binding,
                expected_head,
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
    epoch_id: EpochId,
    shard: u16,
    committed_offset: i64,
    chain_digest: Sha256Digest,
    advanced_at: DateTime<Utc>,
}

/// The durable open head and the transition row that projects it.
struct AuditedOpenHead {
    generation: u32,
    activation_id: Sha256Digest,
    head: RegistryHeadBindingV1,
    canonical_head: Vec<u8>,
    accepted_at: CanonicalTimestamp,
    installed_policy: InstalledSuccessorPolicyV2,
}

struct PreparedGenericSuccessor {
    verified: VerifiedGenericSuccessorActivation,
    statement_id: GenericSuccessorActivationStatementId,
    approval_ids_packed: Vec<u8>,
    approval_count: i32,
    required_threshold: i32,
}

impl PreparedGenericSuccessor {
    fn new(verified: VerifiedGenericSuccessorActivation) -> Result<Self> {
        let statement_id = verified.statement_id()?;
        let approval_count = i32::try_from(verified.eligible_approvals().len())
            .map_err(|_| generic_corrupt("eligible approval count exceeds INT4"))?;
        let required_threshold = i32::from(verified.required_threshold());
        Ok(Self {
            approval_ids_packed: packed_approval_ids(verified.eligible_approvals()),
            verified,
            statement_id,
            approval_count,
            required_threshold,
        })
    }
}

struct MaterializedGenericSuccessor {
    receipt: GenericSuccessorActivationReceiptV2,
    event: GenericSuccessorActivatedEventV2,
    head: RegistryHeadBindingV1,
    activation_id: GenericSuccessorActivationId,
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

#[async_trait]
impl GenericSuccessorRepository for CockroachGenericSuccessorRepository {
    async fn activate_generic_successor(
        &self,
        candidate: &GenericSuccessorActivationCandidate,
    ) -> Result<GenericSuccessorActivationOutcome> {
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

    async fn inspect_generic_successor(
        &self,
        generation: u32,
    ) -> Result<GenericSuccessorActivationInspection> {
        let scope = self.trusted_scope.clone();
        let authority = Arc::clone(&self.authority);
        let pool = self.pool.clone();
        let policy = self.retry_policy;
        with_serializable_retry(&pool, policy, move |transaction| {
            let scope = scope.clone();
            let authority = Arc::clone(&authority);
            Box::pin(async move {
                inspect_in_transaction(transaction, &scope, &authority, generation).await
            })
        })
        .await
    }
}

async fn activate_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    authority: &BoundGenericSuccessorAuthority,
    candidate: &GenericSuccessorActivationCandidate,
) -> Result<GenericSuccessorActivationOutcome> {
    require_generic_successor_schema(transaction).await?;
    let epoch = require_pinned_bootstrap_before_lock(transaction, scope, authority).await?;
    let locked = lock_registry_control_head(transaction, scope, &epoch).await?;
    let peeked = peek_candidate_statement(scope, candidate)?;
    let (current_row, current_generation) = load_current_head_row(transaction, scope).await?;
    require_registry_stream_tip(transaction, scope, &epoch, &locked, &current_row).await?;
    require_no_event_ahead_of_head(transaction, scope, &epoch, &locked).await?;

    if current_generation == peeked.to_generation {
        return replay_in_transaction(transaction, scope, authority, candidate, &peeked)
            .await
            .map(|accepted| GenericSuccessorActivationOutcome::ExactReplay(Box::new(accepted)));
    }
    if current_generation != peeked.from_generation {
        return Err(FleetError::SuccessorActivationStale);
    }

    let predecessor_row = load_transition_row(transaction, scope, current_generation).await?;
    let audited = audit_open_head_against_transition(
        scope,
        authority,
        &current_row,
        &predecessor_row,
        current_generation,
    )?;
    require_absent_transition(transaction, scope, peeked.to_generation).await?;

    let prepared = prepare_candidate(candidate, authority, &audited)?;
    let accepted_at_database: DateTime<Utc> =
        sqlx::query_scalar("SELECT pg_catalog.statement_timestamp()")
            .fetch_one(&mut **transaction)
            .await?;
    if accepted_at_database < locked.advanced_at {
        return Err(generic_corrupt(
            "generic successor acceptance time precedes the locked control tail",
        ));
    }
    let materialized =
        materialize_generic_successor(scope, &audited, &prepared, &locked, accepted_at_database)?;
    insert_control_event(transaction, scope, &materialized).await?;
    insert_generic_transition(
        transaction,
        scope,
        authority,
        &audited,
        &prepared,
        &materialized,
    )
    .await?;
    advance_current_head(transaction, scope, &audited, &materialized).await?;
    advance_control_head(transaction, scope, &locked, &materialized).await?;
    Ok(GenericSuccessorActivationOutcome::Inserted(Box::new(
        accepted_from_materialized(&prepared, &audited, &materialized),
    )))
}

async fn inspect_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    authority: &BoundGenericSuccessorAuthority,
    generation: u32,
) -> Result<GenericSuccessorActivationInspection> {
    require_generic_successor_schema(transaction).await?;
    let epoch = require_pinned_bootstrap_before_lock(transaction, scope, authority).await?;
    let locked = lock_registry_control_head(transaction, scope, &epoch).await?;
    let (current_row, current_generation) = load_current_head_row(transaction, scope).await?;
    require_registry_stream_tip(transaction, scope, &epoch, &locked, &current_row).await?;
    require_no_event_ahead_of_head(transaction, scope, &epoch, &locked).await?;
    let predecessor_generation = generation
        .checked_sub(1)
        .ok_or(FleetError::SuccessorActivationStale)?;
    if predecessor_generation < MIN_PREDECESSOR_GENERATION {
        return Err(FleetError::SuccessorActivationStale);
    }

    if current_generation == predecessor_generation {
        let predecessor_row = load_transition_row(transaction, scope, current_generation).await?;
        let audited = audit_open_head_against_transition(
            scope,
            authority,
            &current_row,
            &predecessor_row,
            current_generation,
        )?;
        require_absent_transition(transaction, scope, generation).await?;
        return Ok(GenericSuccessorActivationInspection::Ready(Box::new(
            ReadyGenericSuccessor {
                current_generation,
                next_generation: generation,
                current_activation_policy: audited.installed_policy.policy_reference().clone(),
                current_head: audited.head,
            },
        )));
    }
    if current_generation < generation {
        return Err(FleetError::SuccessorActivationStale);
    }

    let predecessor_row = load_transition_row(transaction, scope, predecessor_generation).await?;
    let stored_row = load_transition_row(transaction, scope, generation).await?;
    let audited = audit_installed_policy_from_transition(
        scope,
        authority,
        &predecessor_row,
        predecessor_generation,
    )?;
    let accepted =
        audit_accepted_transition(transaction, scope, authority, &audited, &stored_row).await?;
    Ok(GenericSuccessorActivationInspection::Accepted(Box::new(
        accepted,
    )))
}

/// Replay path: the head is already at the candidate's target generation.
async fn replay_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    authority: &BoundGenericSuccessorAuthority,
    candidate: &GenericSuccessorActivationCandidate,
    peeked: &PeekedStatement,
) -> Result<AcceptedGenericSuccessorActivation> {
    let predecessor_row = load_transition_row(transaction, scope, peeked.from_generation).await?;
    let stored_row = load_transition_row(transaction, scope, peeked.to_generation).await?;
    let audited = audit_installed_policy_from_transition(
        scope,
        authority,
        &predecessor_row,
        peeked.from_generation,
    )?;
    let prepared = prepare_candidate(candidate, authority, &audited)?;
    let stored_statement_id = GenericSuccessorActivationStatementId::from_digest(digest_from_row(
        &stored_row,
        "statement_id",
    )?);
    let stored_statement: Vec<u8> = stored_row.try_get("canonical_statement")?;
    let stored_approval_set: Vec<u8> = stored_row.try_get("canonical_approval_set")?;
    match classify_generic_successor_replay(
        &prepared.verified,
        stored_statement_id,
        &stored_statement,
        &stored_approval_set,
    )? {
        GenericSuccessorReplayClassV2::StaleStatement => Err(FleetError::SuccessorActivationStale),
        GenericSuccessorReplayClassV2::IntegrityCollision => Err(generic_corrupt(
            "one generic successor statement digest maps to different canonical bytes",
        )),
        GenericSuccessorReplayClassV2::ApprovalSetConflict => Err(
            FleetError::SuccessorActivationConflict(SuccessorActivationConflictKind::ApprovalSet),
        ),
        GenericSuccessorReplayClassV2::ExactReplay => {
            audit_accepted_transition(transaction, scope, authority, &audited, &stored_row).await
        }
    }
}

async fn require_generic_successor_schema(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<()> {
    let available: bool = sqlx::query_scalar(REQUIRE_GENERIC_SUCCESSOR_SCHEMA_SQL)
        .fetch_one(&mut **transaction)
        .await?;
    if !available {
        return Err(generic_corrupt(
            "generic successor activation requires the complete successful schema prefix \
             through 17 in fleet_recall",
        ));
    }
    Ok(())
}

/// Read the durable bootstrap singleton and require the deployment pin.
///
/// The epoch identity and partition recipe come only from that authenticated
/// row, never from the request. Nothing here re-audits the genesis registry
/// root: at generation `N >= 1` the governing authority is the current head's
/// own installed policy.
async fn require_pinned_bootstrap_before_lock(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    authority: &BoundGenericSuccessorAuthority,
) -> Result<GenesisLogEpochV1> {
    let Some(witness) = load_durable_genesis_witness(transaction, scope).await? else {
        return Err(FleetError::SuccessorActivationNotReady);
    };
    if witness.bootstrap().receipt_digest() != authority.bootstrap_receipt_digest {
        return Err(FleetError::SuccessorActivationConflict(
            SuccessorActivationConflictKind::BoundAuthority,
        ));
    }
    let epoch = witness
        .bootstrap()
        .receipt()
        .statement
        .genesis_epoch
        .clone();
    if epoch.epoch_id()? != witness.bootstrap().epoch_id() {
        return Err(generic_corrupt(
            "durable bootstrap epoch identity does not reproduce",
        ));
    }
    Ok(epoch)
}

async fn lock_registry_control_head(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    epoch: &GenesisLogEpochV1,
) -> Result<LockedControlHead> {
    let consistency_key = registry_activation_consistency_partition_key(scope.semantic_scope())?;
    let shard = partition_for_epoch(epoch, &consistency_key)?;
    let epoch_id = epoch.epoch_id()?;
    let row = sqlx::query(LOCK_CONTROL_HEAD_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(bytes(epoch_id.digest()))
        .bind(i32::from(shard))
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or_else(|| generic_corrupt("stable registry control head is missing"))?;
    let shard_count: i32 = row.try_get("shard_count")?;
    if shard_count != i32::from(epoch.partition_recipe.shard_count) {
        return Err(generic_corrupt(
            "stable registry control head changed shard count",
        ));
    }
    Ok(LockedControlHead {
        epoch_id,
        shard,
        committed_offset: row.try_get("last_committed_offset")?,
        chain_digest: digest_from_row(&row, "chain_digest")?,
        advanced_at: row.try_get("advanced_at")?,
    })
}

/// Bounded, validated view of the untrusted candidate statement.
///
/// Only the generation pair is read here, and only to choose which durable
/// generation to audit. Every authority decision below is taken against the
/// durable head bytes, never against these fields.
struct PeekedStatement {
    from_generation: u32,
    to_generation: u32,
}

fn peek_candidate_statement(
    scope: &TrustedControlScope,
    candidate: &GenericSuccessorActivationCandidate,
) -> Result<PeekedStatement> {
    let canonical = candidate.canonical_statement();
    require_canonical(canonical)?;
    let statement: GenericSuccessorActivationStatementV2 = decode_strict(canonical)?;
    statement.validate_shape()?;
    if encode_canonical(&statement)? != canonical {
        return Err(FleetError::ControlContract(ContractError::NotCanonical));
    }
    if &statement.scope != scope.semantic_scope() {
        return Err(FleetError::InvalidScope(
            "generic successor activation scope does not match repository scope".into(),
        ));
    }
    if statement.from_generation < MIN_PREDECESSOR_GENERATION {
        return Err(FleetError::SuccessorActivationStale);
    }
    Ok(PeekedStatement {
        from_generation: statement.from_generation,
        to_generation: statement.to_generation,
    })
}

async fn load_current_head_row(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
) -> Result<(PgRow, u32)> {
    let rows = sqlx::query(SELECT_CURRENT_HEADS_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .fetch_all(&mut **transaction)
        .await?;
    if rows.len() != 1 {
        return Err(FleetError::SuccessorActivationNotReady);
    }
    let row = rows.into_iter().next().expect("length checked");
    let head_state: String = row.try_get("head_state")?;
    if head_state != ACTIVE_HEAD_STATE {
        return Err(generic_corrupt(
            "current registry head is not in the active state",
        ));
    }
    let generation = generation_from_row(&row, "generation")?;
    Ok((row, generation))
}

async fn load_transition_row(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    generation: u32,
) -> Result<PgRow> {
    let rows = sqlx::query(SELECT_TRANSITION_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(i64::from(generation))
        .fetch_all(&mut **transaction)
        .await?;
    if rows.len() != 1 {
        return Err(generic_corrupt(format!(
            "generation {generation} does not have exactly one transition row"
        )));
    }
    Ok(rows.into_iter().next().expect("length checked"))
}

async fn require_absent_transition(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    generation: u32,
) -> Result<()> {
    let rows = sqlx::query(SELECT_TRANSITION_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(i64::from(generation))
        .fetch_all(&mut **transaction)
        .await?;
    if rows.is_empty() {
        return Ok(());
    }
    Err(generic_corrupt(format!(
        "generation {generation} already exists while the current head trails it"
    )))
}

/// Rebuild the installed activation policy from one durable transition row.
fn audit_installed_policy_from_transition(
    scope: &TrustedControlScope,
    authority: &BoundGenericSuccessorAuthority,
    row: &PgRow,
    generation: u32,
) -> Result<AuditedOpenHead> {
    if generation < MIN_PREDECESSOR_GENERATION {
        return Err(FleetError::SuccessorActivationStale);
    }
    expect_i64(row, "generation", i64::from(generation))?;
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
    let canonical_head: Vec<u8> = row.try_get("canonical_head")?;
    require_canonical(&canonical_head).map_err(|error| {
        generic_corrupt(format!("stored generic head is not canonical: {error}"))
    })?;
    let head: RegistryHeadBindingV1 = decode_strict(&canonical_head)
        .map_err(|error| generic_corrupt(format!("stored generic head is invalid: {error}")))?;
    stored_contract(head.validate_shape())?;
    if stored_contract(encode_canonical(&head))? != canonical_head {
        return Err(generic_corrupt(
            "stored generic head changed during reconstruction",
        ));
    }
    let activation_id = digest_from_row(row, "activation_id")?;
    if head.head.activation_id != activation_id
        || head.head.package_digest != digest_from_row(row, "package_digest")?
        || head.head.activation_policy_digest != digest_from_row(row, "activation_policy_digest")?
        || head.effective_until.is_some()
    {
        return Err(generic_corrupt(
            "stored head binding disagrees with its own transition row",
        ));
    }
    let canonical_package: Vec<u8> = row.try_get("canonical_package")?;
    let manifest = ManifestVerifiedRegistryPackage::decode(&canonical_package, &authority.profile)
        .map_err(|error| {
            generic_corrupt(format!("stored installed package is invalid: {error}"))
        })?;
    let installed_package = stored_contract(
        StructurallyClosedSuccessorTargetV2::from_manifest_verified(&manifest),
    )?;
    let installed_policy = stored_contract(InstalledSuccessorPolicyV2::from_durable_audit(
        authority.profile.clone(),
        scope.semantic_scope().clone(),
        generation,
        head.clone(),
        &installed_package,
    ))?;
    let accepted_at = timestamp_from_row(row, "accepted_at")?;
    Ok(AuditedOpenHead {
        generation,
        activation_id,
        head,
        canonical_head,
        accepted_at,
        installed_policy,
    })
}

/// Prove that the singleton current head is exactly the generation-`N`
/// transition it claims to project, then rebuild the installed policy.
fn audit_open_head_against_transition(
    scope: &TrustedControlScope,
    authority: &BoundGenericSuccessorAuthority,
    head_row: &PgRow,
    transition_row: &PgRow,
    generation: u32,
) -> Result<AuditedOpenHead> {
    let audited =
        audit_installed_policy_from_transition(scope, authority, transition_row, generation)?;
    expect_i64(head_row, "generation", i64::from(generation))?;
    for column in [
        "activation_id",
        "package_digest",
        "activation_policy_digest",
        "profile_digest",
        "vector_manifest_digest",
        "source_event_id",
        "source_epoch_id",
    ] {
        expect_digest(head_row, column, digest_from_row(transition_row, column)?)?;
    }
    for column in [
        "profile_id",
        "contract_tenant_namespace",
        "contract_project_namespace",
    ] {
        let expected: String = transition_row.try_get(column)?;
        expect_text(head_row, column, &expected)?;
    }
    for column in ["effective_from", "accepted_at"] {
        let expected: DateTime<Utc> = transition_row.try_get(column)?;
        expect_timestamp(head_row, column, expected)?;
    }
    expect_i32(
        head_row,
        "source_shard",
        transition_row.try_get::<i32, _>("source_shard")?,
    )?;
    expect_i64(
        head_row,
        "source_committed_offset",
        transition_row.try_get::<i64, _>("source_committed_offset")?,
    )?;
    expect_raw_bytes(head_row, "canonical_head", &audited.canonical_head)?;
    Ok(audited)
}

fn prepare_candidate(
    candidate: &GenericSuccessorActivationCandidate,
    authority: &BoundGenericSuccessorAuthority,
    audited: &AuditedOpenHead,
) -> Result<PreparedGenericSuccessor> {
    let verified = verify_generic_successor_activation(
        candidate.canonical_statement(),
        candidate.canonical_approval_set(),
        &audited.installed_policy,
        &authority.target,
        &authority.test_result,
        &authority.principal_binding,
    )
    .map_err(map_stale_head)?;
    // The compare-and-swap precondition, restated explicitly against the durable
    // head bytes: package-digest equality is never enough, because `A -> B -> A`
    // returns the same package digest under a new activation ID.
    verified
        .require_expected_head(&audited.head)
        .map_err(map_stale_head)?;
    // The operator's out-of-band expectation must also be the durable head, so a
    // ceremony prepared for one head cannot silently apply to another.
    if audited.head != authority.expected_head {
        return Err(FleetError::SuccessorActivationStale);
    }
    PreparedGenericSuccessor::new(verified)
}

fn materialize_generic_successor(
    scope: &TrustedControlScope,
    audited: &AuditedOpenHead,
    prepared: &PreparedGenericSuccessor,
    locked: &LockedControlHead,
    accepted_at_database: DateTime<Utc>,
) -> Result<MaterializedGenericSuccessor> {
    let accepted_at = stored_contract(CanonicalTimestamp::from_datetime(&accepted_at_database))?;
    let statement = prepared.verified.statement();
    if statement.effective_from < audited.accepted_at {
        return Err(FleetError::SuccessorActivationTiming(
            SuccessorActivationTimingKind::BeforePredecessorAcceptance,
        ));
    }
    if statement.effective_from > accepted_at {
        return Err(FleetError::SuccessorActivationTiming(
            SuccessorActivationTimingKind::FutureEffective,
        ));
    }
    let receipt = prepared.verified.receipt_at(
        &audited.installed_policy,
        &audited.accepted_at,
        accepted_at,
    )?;
    let event = GenericSuccessorActivatedEventV2::from_verified(&prepared.verified, &receipt)?;
    let head = prepared.verified.resulting_registry_head(&receipt)?;
    let activation_id = receipt.activation_id()?;
    let accepted_event_id = event.accepted_event_id()?;
    let consistency_key = event.consistency_partition_key()?;
    let expected_consistency_key =
        registry_activation_consistency_partition_key(scope.semantic_scope())?;
    if consistency_key != expected_consistency_key
        || consistency_key.family.as_str() != ACTIVATION_CONSISTENCY_FAMILY
    {
        return Err(generic_corrupt(
            "generic successor consistency family changed from registry.activation",
        ));
    }
    let next_offset = locked
        .committed_offset
        .checked_add(1)
        .and_then(|value| u64::try_from(value).ok())
        .ok_or_else(|| generic_corrupt("generic successor control offset overflowed INT8"))?;
    let append_position = AppendPositionV1 {
        epoch_id: locked.epoch_id,
        shard: locked.shard,
        committed_offset: stored_contract(CommittedOffsetV1::new(next_offset))?,
    };
    let append_chain_digest =
        derive_append_chain_digest(locked.chain_digest, accepted_event_id, &append_position)?;
    let canonical_receipt = encode_canonical(&receipt)?;
    let canonical_event = encode_canonical(&event)?;
    let canonical_head = encode_canonical(&head)?;
    let effective_from_database = canonical_timestamp_to_database(&statement.effective_from)?;
    Ok(MaterializedGenericSuccessor {
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

async fn insert_control_event(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    accepted: &MaterializedGenericSuccessor,
) -> Result<()> {
    let consistency_key = accepted.event.consistency_partition_key()?;
    let event_id: Option<Vec<u8>> =
        sqlx::query_scalar(INSERT_CONTROL_EVENT_SQL)
            .bind(scope.tenant_id())
            .bind(scope.project())
            .bind(bytes(accepted.append_position.epoch_id.digest()))
            .bind(i32::from(accepted.append_position.shard))
            .bind(offset_as_i64(accepted.append_position.committed_offset)?)
            .bind(bytes(accepted.accepted_event_id.digest()))
            .bind(i32::try_from(accepted.event.schema_version).map_err(|_| {
                generic_corrupt("generic successor event schema version exceeds INT4")
            })?)
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
        return Err(generic_corrupt(
            "generic successor event insert returned a different event id",
        ));
    }
    Ok(())
}

async fn insert_generic_transition(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    authority: &BoundGenericSuccessorAuthority,
    audited: &AuditedOpenHead,
    prepared: &PreparedGenericSuccessor,
    accepted: &MaterializedGenericSuccessor,
) -> Result<()> {
    let statement = prepared.verified.statement();
    let profile = &statement.profile;
    let generation: Option<i64> = sqlx::query_scalar(INSERT_GENERIC_TRANSITION_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(i64::from(audited.generation))
        .bind(bytes(audited.activation_id))
        .bind(i64::from(statement.to_generation))
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
        .bind(&authority.canonical_target_package)
        .bind(prepared.verified.canonical_statement())
        .bind(prepared.verified.canonical_approval_set())
        .bind(authority.test_result.canonical_bytes())
        .bind(&accepted.canonical_receipt)
        .bind(&accepted.canonical_event)
        .bind(&accepted.canonical_head)
        .fetch_optional(&mut **transaction)
        .await?;
    if generation != Some(i64::from(statement.to_generation)) {
        return Err(generic_corrupt(
            "generic successor transition insert returned the wrong generation",
        ));
    }
    Ok(())
}

async fn advance_current_head(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    audited: &AuditedOpenHead,
    accepted: &MaterializedGenericSuccessor,
) -> Result<()> {
    let to_generation = i64::from(accepted.event.to_generation);
    let generation: Option<i64> = sqlx::query_scalar(ADVANCE_CURRENT_HEAD_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(ACTIVE_HEAD_STATE)
        .bind(i64::from(audited.generation))
        .bind(bytes(audited.activation_id))
        .bind(to_generation)
        .bind(bytes(accepted.activation_id.digest()))
        .fetch_optional(&mut **transaction)
        .await?;
    if generation != Some(to_generation) {
        return Err(generic_corrupt(
            "exact generic successor current-head CAS failed",
        ));
    }
    Ok(())
}

async fn advance_control_head(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    locked: &LockedControlHead,
    accepted: &MaterializedGenericSuccessor,
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
        return Err(generic_corrupt(
            "exact stable registry control-head CAS failed",
        ));
    };
    expect_i64(&row, "last_committed_offset", next_offset)?;
    expect_digest(&row, "chain_digest", accepted.append_chain_digest)
}

/// The current open head must be projected by the newest `registry.activation`
/// event, on the locked shard, at or below the locked control tail.
async fn require_registry_stream_tip(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    epoch: &GenesisLogEpochV1,
    locked: &LockedControlHead,
    head_row: &PgRow,
) -> Result<()> {
    let consistency_key = registry_activation_consistency_partition_key(scope.semantic_scope())?;
    let row = sqlx::query(SELECT_REGISTRY_STREAM_TIP_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(bytes(epoch.epoch_id()?.digest()))
        .bind(ACTIVATION_CONSISTENCY_FAMILY)
        .bind(bytes(consistency_key.key_digest))
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or_else(|| generic_corrupt("registry activation stream is empty under an open head"))?;
    let tip_shard: i32 = row.try_get("shard")?;
    let tip_offset: i64 = row.try_get("committed_offset")?;
    let tip_event = digest_from_row(&row, "event_id")?;
    expect_digest(head_row, "source_event_id", tip_event)?;
    expect_i32(head_row, "source_shard", tip_shard)?;
    expect_i64(head_row, "source_committed_offset", tip_offset)?;
    expect_digest(head_row, "source_epoch_id", epoch.epoch_id()?.digest())?;
    if u16::try_from(tip_shard).map_err(|_| generic_corrupt("stream shard exceeds UINT16"))?
        != locked.shard
        || tip_offset > locked.committed_offset
    {
        return Err(generic_corrupt(
            "registry activation stream tip escaped the locked control head",
        ));
    }
    Ok(())
}

async fn require_no_event_ahead_of_head(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    epoch: &GenesisLogEpochV1,
    locked: &LockedControlHead,
) -> Result<()> {
    let ahead: Option<Vec<u8>> = sqlx::query_scalar(SELECT_EVENT_AHEAD_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(bytes(epoch.epoch_id()?.digest()))
        .bind(i32::from(locked.shard))
        .bind(locked.committed_offset)
        .fetch_optional(&mut **transaction)
        .await?;
    if ahead.is_some() {
        return Err(generic_corrupt(
            "stable registry shard contains an event ahead of its locked head",
        ));
    }
    Ok(())
}

/// Re-derive one accepted generic transition from its stored canonical bytes.
async fn audit_accepted_transition(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    authority: &BoundGenericSuccessorAuthority,
    predecessor: &AuditedOpenHead,
    row: &PgRow,
) -> Result<AcceptedGenericSuccessorActivation> {
    let canonical_statement: Vec<u8> = row.try_get("canonical_statement")?;
    let canonical_approval_set: Vec<u8> = row.try_get("canonical_approval_set")?;
    let canonical_package: Vec<u8> = row.try_get("canonical_package")?;
    let canonical_test_result: Vec<u8> = row.try_get("canonical_test_result")?;
    let canonical_receipt: Vec<u8> = row.try_get("canonical_receipt")?;
    let canonical_event: Vec<u8> = row.try_get("canonical_event")?;
    let canonical_head: Vec<u8> = row.try_get("canonical_head")?;
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
            generic_corrupt(format!(
                "stored generic successor {name} is not canonical: {error}"
            ))
        })?;
    }
    if canonical_package != authority.canonical_target_package
        || canonical_test_result != authority.test_result.canonical_bytes()
    {
        return Err(generic_corrupt(
            "stored generic package or test result differs from bound authority",
        ));
    }
    let verified = verify_generic_successor_activation(
        &canonical_statement,
        &canonical_approval_set,
        &predecessor.installed_policy,
        &authority.target,
        &authority.test_result,
        &authority.principal_binding,
    )
    .map_err(|error| {
        generic_corrupt(format!(
            "stored generic successor authority is invalid: {error}"
        ))
    })?;
    let receipt: GenericSuccessorActivationReceiptV2 = decode_strict(&canonical_receipt)
        .map_err(|error| generic_corrupt(format!("stored generic receipt is invalid: {error}")))?;
    stored_contract(receipt.validate_against(&verified))?;
    let event: GenericSuccessorActivatedEventV2 = decode_strict(&canonical_event)
        .map_err(|error| generic_corrupt(format!("stored generic event is invalid: {error}")))?;
    stored_contract(event.validate_against(&verified, &receipt))?;
    let head: RegistryHeadBindingV1 = decode_strict(&canonical_head)
        .map_err(|error| generic_corrupt(format!("stored generic head is invalid: {error}")))?;
    stored_contract(head.validate_shape())?;
    if stored_contract(encode_canonical(&receipt))? != canonical_receipt
        || stored_contract(encode_canonical(&event))? != canonical_event
        || stored_contract(encode_canonical(&head))? != canonical_head
        || stored_contract(verified.resulting_registry_head(&receipt))? != head
    {
        return Err(generic_corrupt(
            "stored generic receipt, event, or head changed during reconstruction",
        ));
    }
    let statement_id = stored_contract(verified.statement_id())?;
    let activation_id = stored_contract(receipt.activation_id())?;
    let accepted_event_id = stored_contract(event.accepted_event_id())?;
    let position = stored_position(row)?;
    audit_generic_transition_row(
        scope,
        &verified,
        &receipt,
        &head,
        statement_id,
        activation_id,
        accepted_event_id,
        &position,
        predecessor,
        row,
    )?;
    audit_generic_control_event(
        transaction,
        scope,
        activation_id,
        accepted_event_id,
        &event,
        &position,
        &canonical_event,
        &receipt,
    )
    .await?;
    Ok(AcceptedGenericSuccessorActivation {
        statement_id,
        activation_id,
        accepted_event_id,
        from_generation: verified.statement().from_generation,
        to_generation: verified.statement().to_generation,
        predecessor_head: predecessor.head.clone(),
        registry_head: head,
        append_position: position,
        accepted_at: receipt.accepted_at,
    })
}

#[allow(clippy::too_many_arguments)]
fn audit_generic_transition_row(
    scope: &TrustedControlScope,
    verified: &VerifiedGenericSuccessorActivation,
    receipt: &GenericSuccessorActivationReceiptV2,
    head: &RegistryHeadBindingV1,
    statement_id: GenericSuccessorActivationStatementId,
    activation_id: GenericSuccessorActivationId,
    accepted_event_id: AcceptedEventId,
    position: &AppendPositionV1,
    predecessor: &AuditedOpenHead,
    row: &PgRow,
) -> Result<()> {
    let statement = verified.statement();
    expect_i64(row, "generation", i64::from(statement.to_generation))?;
    expect_i64(
        row,
        "predecessor_generation",
        i64::from(predecessor.generation),
    )?;
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
    expect_text(row, "profile_id", statement.profile.profile_id.as_str())?;
    expect_digest(row, "profile_digest", statement.profile.profile_digest)?;
    expect_digest(
        row,
        "vector_manifest_digest",
        statement.profile.vector_manifest_digest,
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
    expect_raw_bytes(
        row,
        "approval_ids_packed",
        &packed_approval_ids(&receipt.eligible_approvals),
    )?;
    expect_i32(
        row,
        "approval_count",
        i32::try_from(receipt.eligible_approvals.len())
            .map_err(|_| generic_corrupt("stored approval count exceeds INT4"))?,
    )?;
    expect_i32(
        row,
        "required_threshold",
        i32::from(receipt.required_threshold),
    )?;
    expect_bool(row, "separation_of_duty_satisfied", true)?;
    if head.head.package_digest == predecessor.head.head.package_digest
        && head.head.activation_id == predecessor.head.head.activation_id
    {
        return Err(generic_corrupt(
            "stored generic successor head repeats its predecessor identity",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn audit_generic_control_event(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    activation_id: GenericSuccessorActivationId,
    accepted_event_id: AcceptedEventId,
    event: &GenericSuccessorActivatedEventV2,
    position: &AppendPositionV1,
    canonical_event: &[u8],
    receipt: &GenericSuccessorActivationReceiptV2,
) -> Result<()> {
    let consistency_key = event.consistency_partition_key()?;
    let row = sqlx::query(SELECT_CONTROL_EVENT_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(bytes(position.epoch_id.digest()))
        .bind(i32::from(position.shard))
        .bind(offset_as_i64(position.committed_offset)?)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or_else(|| generic_corrupt("generic successor control event is missing"))?;
    expect_digest(&row, "event_id", accepted_event_id.digest())?;
    expect_i32(
        &row,
        "event_schema_version",
        i32::try_from(event.schema_version)
            .map_err(|_| generic_corrupt("stored event schema version exceeds INT4"))?,
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

    let predecessor_offset = offset_as_i64(position.committed_offset)?
        .checked_sub(1)
        .ok_or_else(|| generic_corrupt("generic successor source offset underflowed"))?;
    let predecessor = sqlx::query(SELECT_CONTROL_EVENT_SQL)
        .bind(scope.tenant_id())
        .bind(scope.project())
        .bind(bytes(position.epoch_id.digest()))
        .bind(i32::from(position.shard))
        .bind(predecessor_offset)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or_else(|| generic_corrupt("generic successor source predecessor is missing"))?;
    let predecessor_position = AppendPositionV1 {
        epoch_id: position.epoch_id,
        shard: position.shard,
        committed_offset: stored_contract(CommittedOffsetV1::new(
            u64::try_from(predecessor_offset)
                .map_err(|_| generic_corrupt("negative generic predecessor offset"))?,
        ))?,
    };
    let predecessor_event_id =
        AcceptedEventId::from_digest(digest_from_row(&predecessor, "event_id")?);
    let predecessor_derived = derive_append_chain_digest(
        digest_from_row(&predecessor, "previous_chain_digest")?,
        predecessor_event_id,
        &predecessor_position,
    )?;
    expect_digest(&predecessor, "chain_digest", predecessor_derived)?;
    if predecessor_derived != previous_chain {
        return Err(generic_corrupt(
            "generic successor source event is detached from its immediate predecessor",
        ));
    }
    Ok(())
}

fn accepted_from_materialized(
    prepared: &PreparedGenericSuccessor,
    audited: &AuditedOpenHead,
    accepted: &MaterializedGenericSuccessor,
) -> AcceptedGenericSuccessorActivation {
    AcceptedGenericSuccessorActivation {
        statement_id: prepared.statement_id,
        activation_id: accepted.activation_id,
        accepted_event_id: accepted.accepted_event_id,
        from_generation: accepted.event.from_generation,
        to_generation: accepted.event.to_generation,
        predecessor_head: audited.head.clone(),
        registry_head: accepted.head.clone(),
        append_position: accepted.append_position,
        accepted_at: accepted.receipt.accepted_at.clone(),
    }
}

fn packed_approval_ids(approvals: &[EligibleApprovalV1]) -> Vec<u8> {
    let mut packed = Vec::with_capacity(approvals.len().saturating_mul(32));
    for approval in approvals {
        packed.extend_from_slice(approval.attestation_id.as_bytes());
    }
    packed
}

fn stored_position(row: &PgRow) -> Result<AppendPositionV1> {
    let shard = u16::try_from(row.try_get::<i32, _>("source_shard")?)
        .map_err(|_| generic_corrupt("stored generic shard is outside UINT16"))?;
    let offset = u64::try_from(row.try_get::<i64, _>("source_committed_offset")?)
        .map_err(|_| generic_corrupt("stored generic offset is negative"))?;
    Ok(AppendPositionV1 {
        epoch_id: EpochId::from_digest(digest_from_row(row, "source_epoch_id")?),
        shard,
        committed_offset: stored_contract(CommittedOffsetV1::new(offset))?,
    })
}

/// A head mismatch is the one closed staleness outcome, not a generic contract
/// failure: it is exactly the `A -> B -> A` and moved-head case.
fn map_stale_head(error: ContractError) -> FleetError {
    match error {
        ContractError::StaleRegistryHead => FleetError::SuccessorActivationStale,
        other => FleetError::ControlContract(other),
    }
}

fn generic_corrupt(message: impl Into<String>) -> FleetError {
    FleetError::SuccessorActivationCorrupt(message.into())
}

fn stored_contract<T>(outcome: ContractResult<T>) -> Result<T> {
    outcome.map_err(|error| generic_corrupt(format!("stored contract mismatch: {error}")))
}

fn canonical_timestamp_to_database(timestamp: &CanonicalTimestamp) -> Result<DateTime<Utc>> {
    if !timestamp.is_microsecond_aligned() {
        return Err(generic_corrupt(
            "canonical timestamp is not CockroachDB microsecond aligned",
        ));
    }
    DateTime::parse_from_rfc3339(timestamp.as_str())
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| generic_corrupt("canonical timestamp cannot be represented as TIMESTAMPTZ"))
}

fn timestamp_from_row(row: &PgRow, column: &str) -> Result<CanonicalTimestamp> {
    let value: DateTime<Utc> = row.try_get(column)?;
    stored_contract(CanonicalTimestamp::from_datetime(&value))
}

fn generation_from_row(row: &PgRow, column: &str) -> Result<u32> {
    u32::try_from(row.try_get::<i64, _>(column)?)
        .map_err(|_| generic_corrupt(format!("stored {column} is outside UINT32")))
}

fn offset_as_i64(offset: CommittedOffsetV1) -> Result<i64> {
    i64::try_from(offset.as_u64()).map_err(|_| generic_corrupt("control offset exceeds INT8"))
}

fn bytes(digest: Sha256Digest) -> Vec<u8> {
    digest.as_bytes().to_vec()
}

fn digest_from_row(row: &PgRow, column: &str) -> Result<Sha256Digest> {
    let raw: Vec<u8> = row.try_get(column)?;
    let raw: [u8; 32] = raw
        .try_into()
        .map_err(|_| generic_corrupt(format!("stored {column} digest has the wrong length")))?;
    Ok(Sha256Digest::from_bytes(raw))
}

fn expect_digest(row: &PgRow, column: &str, expected: Sha256Digest) -> Result<()> {
    if digest_from_row(row, column)? != expected {
        return Err(generic_corrupt(format!("stored {column} does not match")));
    }
    Ok(())
}

fn expect_raw_bytes(row: &PgRow, column: &str, expected: &[u8]) -> Result<()> {
    let actual: Vec<u8> = row.try_get(column)?;
    if actual != expected {
        return Err(generic_corrupt(format!("stored {column} does not match")));
    }
    Ok(())
}

fn expect_text(row: &PgRow, column: &str, expected: &str) -> Result<()> {
    let actual: String = row.try_get(column)?;
    if actual != expected {
        return Err(generic_corrupt(format!("stored {column} does not match")));
    }
    Ok(())
}

fn expect_i32(row: &PgRow, column: &str, expected: i32) -> Result<()> {
    let actual: i32 = row.try_get(column)?;
    if actual != expected {
        return Err(generic_corrupt(format!("stored {column} does not match")));
    }
    Ok(())
}

fn expect_i64(row: &PgRow, column: &str, expected: i64) -> Result<()> {
    let actual: i64 = row.try_get(column)?;
    if actual != expected {
        return Err(generic_corrupt(format!("stored {column} does not match")));
    }
    Ok(())
}

fn expect_bool(row: &PgRow, column: &str, expected: bool) -> Result<()> {
    let actual: bool = row.try_get(column)?;
    if actual != expected {
        return Err(generic_corrupt(format!("stored {column} does not match")));
    }
    Ok(())
}

fn expect_timestamp(row: &PgRow, column: &str, expected: DateTime<Utc>) -> Result<()> {
    let actual: DateTime<Utc> = row.try_get(column)?;
    if actual != expected {
        return Err(generic_corrupt(format!("stored {column} does not match")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    const GENERIC_SOURCE: &str = include_str!("generic_successor_cockroach.rs");
    const AUTHORITY_RELATIONS: [&str; 4] = [
        "_sqlx_migrations",
        "memory_control_shard_heads",
        "memory_control_events",
        "memory_registry_transitions",
    ];
    const CURRENT_HEAD_RELATION: &str = "memory_registry_current_heads_v2";

    fn production_prefix(source: &'static str) -> &'static str {
        source
            .split_once("#[cfg(test)]")
            .map_or(source, |(code, _)| code)
    }

    /// Production source with every comment line removed, so a prose mention
    /// of a name can never satisfy or violate a reachability assertion.
    fn production_code(source: &'static str) -> String {
        production_prefix(source)
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn generic_schema_preflight_pins_the_exact_successful_prefix_through_seventeen() {
        assert!(
            REQUIRE_GENERIC_SUCCESSOR_SCHEMA_SQL
                .starts_with("SELECT pg_catalog.current_database() = 'fleet_recall'")
        );
        assert!(REQUIRE_GENERIC_SUCCESSOR_SCHEMA_SQL.contains("count(*) = 17"));
        assert!(REQUIRE_GENERIC_SUCCESSOR_SCHEMA_SQL.contains("bool_and(success)"));
        assert!(REQUIRE_GENERIC_SUCCESSOR_SCHEMA_SQL.contains("FROM public._sqlx_migrations"));
        assert!(REQUIRE_GENERIC_SUCCESSOR_SCHEMA_SQL.contains("version BETWEEN 1 AND 17"));
        assert!(!REQUIRE_GENERIC_SUCCESSOR_SCHEMA_SQL.contains("MAX"));
        assert!(!REQUIRE_GENERIC_SUCCESSOR_SCHEMA_SQL.contains("EXISTS"));
    }

    #[test]
    fn generic_apply_and_inspect_share_the_database_and_schema_first_statement() {
        for (start, end) in [
            (
                "async fn activate_in_transaction(",
                "\nasync fn inspect_in_transaction(",
            ),
            ("async fn inspect_in_transaction(", "\n/// Replay path:"),
        ] {
            let start = GENERIC_SOURCE.find(start).expect("transaction function");
            let end = GENERIC_SOURCE[start..]
                .find(end)
                .map(|offset| start + offset)
                .expect("transaction function boundary");
            let body = &GENERIC_SOURCE[start..end];
            let schema = body
                .find("require_generic_successor_schema(transaction).await?")
                .expect("database/schema preflight");
            let bootstrap = body
                .find("require_pinned_bootstrap_before_lock(")
                .expect("durable bootstrap read");
            let lock = body
                .find("lock_registry_control_head(")
                .expect("control head lock");
            assert!(schema < bootstrap && bootstrap < lock);
        }
    }

    #[test]
    fn generic_stream_lock_and_bounded_state_reads_are_explicit() {
        assert!(LOCK_CONTROL_HEAD_SQL.contains("FOR UPDATE"));
        assert!(SELECT_CURRENT_HEADS_SQL.contains("LIMIT 2"));
        assert!(SELECT_TRANSITION_SQL.contains("LIMIT 2"));
        assert!(SELECT_REGISTRY_STREAM_TIP_SQL.contains("LIMIT 1"));
        assert!(SELECT_EVENT_AHEAD_SQL.contains("LIMIT 1"));
    }

    #[test]
    fn generic_inserts_are_conflict_observing_and_both_heads_use_exact_cas() {
        for query in [INSERT_CONTROL_EVENT_SQL, INSERT_GENERIC_TRANSITION_SQL] {
            assert!(query.contains("ON CONFLICT DO NOTHING RETURNING"));
        }
        // The activation-ID binding is the ABA-safe half of the head CAS.
        assert!(ADVANCE_CURRENT_HEAD_SQL.contains("h.generation = $4 AND h.activation_id = $5"));
        assert!(ADVANCE_CURRENT_HEAD_SQL.contains("s.predecessor_generation = $4"));
        assert!(ADVANCE_CURRENT_HEAD_SQL.contains("h.canonical_head = p.canonical_head"));
        assert!(ADVANCE_CONTROL_HEAD_SQL.contains("last_committed_offset = $8"));
        assert!(ADVANCE_CONTROL_HEAD_SQL.contains("chain_digest = $9"));
    }

    #[test]
    fn generic_source_uses_one_server_timestamp_and_no_database_default() {
        assert_eq!(
            production_code(GENERIC_SOURCE)
                .matches("query_scalar(\"SELECT pg_catalog.statement_timestamp()\")")
                .count(),
            1
        );
        for query in [INSERT_CONTROL_EVENT_SQL, INSERT_GENERIC_TRANSITION_SQL] {
            assert!(!query.contains("now()"));
        }
    }

    #[test]
    fn search_path_and_temporary_shadows_cannot_redirect_generic_authority_sql() {
        let source = production_code(GENERIC_SOURCE);
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
                "unqualified generic authority relation can follow search_path: {token}"
            );
            assert!(
                AUTHORITY_RELATIONS.contains(&relation) || relation == CURRENT_HEAD_RELATION,
                "unreviewed generic authority relation: {relation}"
            );
            found.insert(relation);
        }
        let mut expected: BTreeSet<&str> = AUTHORITY_RELATIONS.into_iter().collect();
        expected.insert(CURRENT_HEAD_RELATION);
        assert_eq!(found, expected, "reachable relation inventory changed");
        assert!(!source.contains("public.public."));
        assert!(!source.contains("pg_temp."));
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
                "generic authority unexpectedly consumes a sequence via {sequence_function}"
            );
        }
    }

    #[test]
    fn contested_resolution_runtime_is_deliberately_absent() {
        let source = production_code(GENERIC_SOURCE);
        for absent in [
            "verify_contested_set_resolution",
            "AuditedContestedSetV1",
            "AuditedContenderActivationV2",
            "ContestedSetResolutionReceiptV1",
            "memory_registry_contested",
        ] {
            assert!(
                !source.contains(absent),
                "contested-set resolution runtime leaked into this cycle: {absent}"
            );
        }
        assert!(source.contains("head_state != ACTIVE_HEAD_STATE"));
        assert!(source.contains("return Err(FleetError::SuccessorActivationNotReady)"));
    }
}
