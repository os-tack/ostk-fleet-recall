//! Writer-side active registry head witness (ADR 0002 D4).
//!
//! The Stage-4 writer never reads a control or registry base table. Inside the
//! same serializable transaction that appends an accepted event it SELECTs the
//! read-only view `memory_writer_authority_v1`, requires exactly one active
//! row, and re-derives every authority fact it needs from the pinned bootstrap
//! receipt that row carries. The witness this module mints is the only token
//! that says "this exact activation is the current head"; it has private
//! fields and no public constructor, so no caller can fabricate one without
//! going through [`load_and_verify`] or [`verify_within`].
//!
//! Invariants enforced here:
//!
//! - **AUTH-04** — normativity is designated. Nothing is treated as an active
//!   registry unless the deployment-pinned bootstrap receipt, the durable log
//!   epoch, and the active head all agree, and the head's package digest
//!   materializes to a compiled-in semantically closed package.
//! - **ABA safety** — the comparison is on the exact `activation_id`, never on
//!   the package or policy digest, so an A -> B -> A rollback that restores a
//!   previous package cannot be mistaken for the head the caller observed.
//! - **D4** — no last-known-head fallback and no caching of authority state:
//!   zero rows, two rows, a non-active head, a decode failure, or any mismatch
//!   fails the call closed, and every call re-reads the view. Serializable
//!   isolation is the fence; this module never issues a separate CAS.
//! - **REPLAY-01 / EVENT-03** — the witness carries the epoch, partition
//!   recipe, and closed package a replayed append must reuse, so a rebuild
//!   under the same head yields the same append coordinates and the same
//!   semantic identities.
//!
//! What this module deliberately does NOT verify, because the runtime role has
//! zero privilege on the control and registry base tables (ADR 0002 D2): the
//! full transition chain from generation 0 to the current generation, the
//! approval ceremony behind each transition, and the canonical package bytes
//! of a head whose digest is not compiled in. The composite view join already
//! guarantees that the projected head and its transition row agree on all
//! seventeen foreign-key columns (migration 0014), so what remains unverified
//! here is verified by the activation ceremonies themselves and audited by the
//! registry-activation binaries, which run as separate identities.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

use chrono::{DateTime, Utc};
use sqlx::postgres::PgPool;
use sqlx::{Executor, Postgres, Row, Transaction};

use crate::config::WriterAuthorityConfig;
use crate::context::FleetScope;
use crate::error::FleetError;
use crate::memory_contracts::bootstrap::{
    EpochId, PartitionAlgorithm, VerifiedBootstrapReceipt, verify_pinned_bootstrap,
};
use crate::memory_contracts::canonical::{decode_strict, encode_canonical, require_canonical};
use crate::memory_contracts::common::{
    CanonicalTimestamp, ContractId, frozen_profile_reference_v1,
};
use crate::memory_contracts::digest::Sha256Digest;
use crate::memory_contracts::evidence_v2::RegistryHeadBindingV1;
use crate::memory_contracts::genesis::SemanticallyClosedGenesisPackage;
use crate::memory_contracts::genesis_activation::genesis_activation_policy_digest;
use crate::memory_contracts::registry::ManifestVerifiedRegistryPackage;
use crate::memory_contracts::stage4_target_package::SemanticallyClosedStage4Package;
use crate::memory_contracts::successor_package::SemanticallyClosedSuccessorPackage;
use crate::memory_contracts::{ContractError, ContractResult};

/// Exact canonical bytes of the frozen genesis registry package. The pinned
/// bootstrap receipt binds this package digest, so the receipt cannot be
/// verified without it.
const GENESIS_PACKAGE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v1/genesis-registry-package.jsonl");

/// Exact canonical bytes of the frozen first Stage-4 successor package. This
/// is the only package a generation-1 head may activate.
const STAGE4_PACKAGE: &[u8] =
    include_bytes!("../../contracts/dynamic-memory/v2/stage4-successor/registry-package.jsonl");

/// Only head state the projection admits; migration 0014 also CHECKs it.
const ACTIVE_HEAD_STATE: &str = "active";

/// The head witness reads exactly one relation, fully qualified so a session
/// `search_path` or a temporary shadow cannot redirect it.
const SELECT_WRITER_AUTHORITY_SQL: &str = "SELECT bootstrap_receipt_digest, \
     bootstrap_canonical_receipt, bootstrap_epoch_id, bootstrap_shard_count, \
     bootstrap_contract_tenant_namespace, bootstrap_contract_project_namespace, log_epoch_id, \
     partition_recipe_id, partition_recipe_version, partition_algorithm, partition_seed, \
     log_shard_count, head_state, generation, activation_id, package_digest, \
     activation_policy_digest, contract_tenant_namespace, contract_project_namespace, \
     effective_from, canonical_head, root_activation_id, root_package_digest, \
     root_activation_policy_digest, predecessor_generation, predecessor_activation_id, \
     predecessor_package_digest, predecessor_activation_policy_digest \
     FROM public.memory_writer_authority_v1 \
     WHERE tenant_id = $1 AND project = $2 LIMIT 2";

/// Upper bound on the decode cache. The key is the exact canonical head, so a
/// live deployment holds one entry per activation it has observed; the bound
/// keeps a pathological sequence of forged heads from growing the process.
const DECODE_CACHE_CAPACITY: usize = 16;

/// Closed reasons the durable state cannot mint writer authority.
///
/// Every variant is a fail-closed verdict, never a downgrade: the caller has
/// no usable head and must abort its append.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WriterAuthorityRejection {
    #[error("no writer authority row exists for the configured scope")]
    Absent,
    #[error("the writer authority view returned more than one row for the configured scope")]
    Ambiguous,
    #[error("the projected registry head is not active")]
    HeadNotActive,
    #[error("the durable bootstrap receipt does not match the deployment pin")]
    BootstrapPin,
    #[error("the durable contract namespaces do not match the deployment pins")]
    ContractNamespace,
    #[error("the durable log epoch does not match the pinned bootstrap genesis epoch")]
    LogEpoch,
    #[error("the head generation is below the first activated generation")]
    Generation,
    #[error("the head does not descend from the pinned bootstrap genesis root")]
    Descent,
    #[error("the canonical head does not bind the projected head columns")]
    HeadBinding,
    #[error("the active package digest is not a compiled-in known package")]
    UnknownActivePackage,
    #[error("the active activation ID does not match the break-glass pin")]
    ExpectedActivationId,
    #[error("the writer authority row is not representable in the contract types")]
    Unrepresentable,
}

/// Failure of one writer-authority verification attempt.
#[derive(Debug, thiserror::Error)]
pub enum WriterAuthorityError {
    #[error("writer authority is unusable: {0}")]
    Rejected(#[from] WriterAuthorityRejection),
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("writer authority contract validation failed: {0}")]
    Contract(#[from] ContractError),
}

impl From<WriterAuthorityError> for FleetError {
    fn from(error: WriterAuthorityError) -> Self {
        match error {
            WriterAuthorityError::Rejected(rejection) => {
                Self::Memory(format!("writer authority is unusable: {rejection}"))
            }
            WriterAuthorityError::Database(error) => Self::Database(error),
            WriterAuthorityError::Contract(error) => Self::ControlContract(error),
        }
    }
}

pub type WitnessResult<T> = std::result::Result<T, WriterAuthorityError>;

/// Proof that one exact registry activation is the current active head.
///
/// The fields are private and there is no public constructor: the only way to
/// hold one is to have run [`load_and_verify`] or [`verify_within`] against a
/// live view row under the deployment pins. A witness is a snapshot of one
/// read; it is never cached and never outlives the transaction that must act
/// on it (D4).
#[derive(Debug, Clone)]
pub struct WriterAuthorityWitness {
    activation_id: Sha256Digest,
    generation: u64,
    package_digest: Sha256Digest,
    activation_policy_digest: Sha256Digest,
    log_epoch_id: EpochId,
    partition_recipe_id: ContractId,
    partition_recipe_version: u32,
    partition_algorithm: PartitionAlgorithm,
    partition_seed: [u8; 32],
    shard_count: u16,
    contract_tenant_namespace: ContractId,
    contract_project_namespace: ContractId,
    canonical_head: Arc<Vec<u8>>,
    head_binding: Arc<RegistryHeadBindingV1>,
    bootstrap: Arc<VerifiedBootstrapReceipt>,
    package: Arc<SemanticallyClosedStage4Package>,
}

impl WriterAuthorityWitness {
    /// Exact activation identity of the active head. This, never the package
    /// digest, is the value a caller compares across reads (ABA safety).
    #[must_use]
    pub const fn activation_id(&self) -> Sha256Digest {
        self.activation_id
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn package_digest(&self) -> Sha256Digest {
        self.package_digest
    }

    #[must_use]
    pub const fn activation_policy_digest(&self) -> Sha256Digest {
        self.activation_policy_digest
    }

    #[must_use]
    pub const fn log_epoch_id(&self) -> EpochId {
        self.log_epoch_id
    }

    #[must_use]
    pub const fn partition_recipe_id(&self) -> &ContractId {
        &self.partition_recipe_id
    }

    #[must_use]
    pub const fn partition_recipe_version(&self) -> u32 {
        self.partition_recipe_version
    }

    #[must_use]
    pub const fn partition_algorithm(&self) -> PartitionAlgorithm {
        self.partition_algorithm
    }

    #[must_use]
    pub const fn partition_seed(&self) -> &[u8; 32] {
        &self.partition_seed
    }

    #[must_use]
    pub const fn shard_count(&self) -> u16 {
        self.shard_count
    }

    #[must_use]
    pub const fn contract_tenant_namespace(&self) -> &ContractId {
        &self.contract_tenant_namespace
    }

    #[must_use]
    pub const fn contract_project_namespace(&self) -> &ContractId {
        &self.contract_project_namespace
    }

    /// The exact canonical `RegistryHeadBindingV1` bytes the durable head
    /// carries. An appended statement must bind these exact bytes; comparing
    /// the bytes is strictly stronger than comparing a digest of them, and it
    /// needs no new `DigestDomain` variant (those belong to W0-REG).
    #[must_use]
    pub fn canonical_head(&self) -> &[u8] {
        &self.canonical_head
    }

    #[must_use]
    pub fn head_binding(&self) -> &RegistryHeadBindingV1 {
        &self.head_binding
    }

    /// The verified bootstrap receipt this head descends from. Callers derive
    /// their shard from it so the evidence ledger and the control ledger share
    /// one genesis epoch (ADR 0002 D1).
    #[must_use]
    pub fn bootstrap(&self) -> &VerifiedBootstrapReceipt {
        &self.bootstrap
    }

    /// The compiled-in, semantically closed package the active head activates.
    #[must_use]
    pub fn package(&self) -> &SemanticallyClosedStage4Package {
        &self.package
    }
}

/// Read and verify the active writer authority on a pool connection.
///
/// Startup and any out-of-transaction check use this. An append must use
/// [`verify_within`] instead so the read is fenced by the same serializable
/// transaction that writes.
pub async fn load_and_verify(
    pool: &PgPool,
    scope: &FleetScope,
    config: &WriterAuthorityConfig,
) -> WitnessResult<WriterAuthorityWitness> {
    verify_with_executor(pool, scope, config).await
}

/// Re-read and re-verify the active writer authority inside an open
/// transaction.
///
/// This is the D4 per-transaction witness: it runs exactly the same code path
/// as [`load_and_verify`], and serializable isolation — not a separate CAS —
/// is what makes a concurrent activation abort the append.
pub async fn verify_within(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &FleetScope,
    config: &WriterAuthorityConfig,
) -> WitnessResult<WriterAuthorityWitness> {
    verify_with_executor(&mut **transaction, scope, config).await
}

async fn verify_with_executor<'executor, E>(
    executor: E,
    scope: &FleetScope,
    config: &WriterAuthorityConfig,
) -> WitnessResult<WriterAuthorityWitness>
where
    E: Executor<'executor, Database = Postgres>,
{
    let rows = sqlx::query(SELECT_WRITER_AUTHORITY_SQL)
        .bind(scope.tenant_id)
        .bind(&scope.project)
        .fetch_all(executor)
        .await?;
    let mut rows = rows.into_iter();
    let row = rows.next().ok_or(WriterAuthorityRejection::Absent)?;
    if rows.next().is_some() {
        return Err(WriterAuthorityRejection::Ambiguous.into());
    }
    verify_row(&AuthorityRow::read(&row)?, config)
}

/// Exactly the columns the witness consumes, decoded once into contract types.
///
/// `Clone` exists only under `cfg(test)`, where the offline negative vectors
/// mutate one field of an otherwise valid row to prove that each verification
/// step is load bearing.
#[cfg_attr(test, derive(Clone))]
struct AuthorityRow {
    bootstrap_receipt_digest: Sha256Digest,
    bootstrap_canonical_receipt: Vec<u8>,
    bootstrap_epoch_id: Sha256Digest,
    bootstrap_shard_count: i32,
    bootstrap_contract_tenant_namespace: String,
    bootstrap_contract_project_namespace: String,
    log_epoch_id: Sha256Digest,
    partition_recipe_id: String,
    partition_recipe_version: i32,
    partition_algorithm: String,
    partition_seed: Vec<u8>,
    log_shard_count: i32,
    head_state: String,
    generation: i64,
    activation_id: Sha256Digest,
    package_digest: Sha256Digest,
    activation_policy_digest: Sha256Digest,
    contract_tenant_namespace: String,
    contract_project_namespace: String,
    effective_from: DateTime<Utc>,
    canonical_head: Vec<u8>,
    root_activation_id: Sha256Digest,
    root_package_digest: Sha256Digest,
    root_activation_policy_digest: Sha256Digest,
    predecessor_generation: Option<i64>,
    predecessor_activation_id: Option<Sha256Digest>,
    predecessor_package_digest: Option<Sha256Digest>,
    predecessor_activation_policy_digest: Option<Sha256Digest>,
}

impl AuthorityRow {
    fn read(row: &sqlx::postgres::PgRow) -> WitnessResult<Self> {
        Ok(Self {
            bootstrap_receipt_digest: digest_column(row, "bootstrap_receipt_digest")?,
            bootstrap_canonical_receipt: row.try_get("bootstrap_canonical_receipt")?,
            bootstrap_epoch_id: digest_column(row, "bootstrap_epoch_id")?,
            bootstrap_shard_count: row.try_get("bootstrap_shard_count")?,
            bootstrap_contract_tenant_namespace: row
                .try_get("bootstrap_contract_tenant_namespace")?,
            bootstrap_contract_project_namespace: row
                .try_get("bootstrap_contract_project_namespace")?,
            log_epoch_id: digest_column(row, "log_epoch_id")?,
            partition_recipe_id: row.try_get("partition_recipe_id")?,
            partition_recipe_version: row.try_get("partition_recipe_version")?,
            partition_algorithm: row.try_get("partition_algorithm")?,
            partition_seed: row.try_get("partition_seed")?,
            log_shard_count: row.try_get("log_shard_count")?,
            head_state: row.try_get("head_state")?,
            generation: row.try_get("generation")?,
            activation_id: digest_column(row, "activation_id")?,
            package_digest: digest_column(row, "package_digest")?,
            activation_policy_digest: digest_column(row, "activation_policy_digest")?,
            contract_tenant_namespace: row.try_get("contract_tenant_namespace")?,
            contract_project_namespace: row.try_get("contract_project_namespace")?,
            effective_from: row.try_get("effective_from")?,
            canonical_head: row.try_get("canonical_head")?,
            root_activation_id: digest_column(row, "root_activation_id")?,
            root_package_digest: digest_column(row, "root_package_digest")?,
            root_activation_policy_digest: digest_column(row, "root_activation_policy_digest")?,
            predecessor_generation: row.try_get("predecessor_generation")?,
            predecessor_activation_id: optional_digest_column(row, "predecessor_activation_id")?,
            predecessor_package_digest: optional_digest_column(row, "predecessor_package_digest")?,
            predecessor_activation_policy_digest: optional_digest_column(
                row,
                "predecessor_activation_policy_digest",
            )?,
        })
    }
}

fn verify_row(
    row: &AuthorityRow,
    config: &WriterAuthorityConfig,
) -> WitnessResult<WriterAuthorityWitness> {
    if row.head_state != ACTIVE_HEAD_STATE {
        return Err(WriterAuthorityRejection::HeadNotActive.into());
    }
    if row.bootstrap_receipt_digest != config.bootstrap_receipt_digest().digest() {
        return Err(WriterAuthorityRejection::BootstrapPin.into());
    }
    let pinned_scope = config.semantic_scope();
    if row.bootstrap_contract_tenant_namespace != pinned_scope.tenant_namespace.as_str()
        || row.bootstrap_contract_project_namespace != pinned_scope.project_namespace.as_str()
        || row.contract_tenant_namespace != pinned_scope.tenant_namespace.as_str()
        || row.contract_project_namespace != pinned_scope.project_namespace.as_str()
    {
        return Err(WriterAuthorityRejection::ContractNamespace.into());
    }

    // Re-verify the durable receipt from its own bytes: canonical form, exact
    // deployment pin, exact profile and semantic scope, exact genesis package
    // digest, signer threshold, and every signature. Nothing about this head
    // is trusted because the view returned it.
    let bootstrap = verify_pinned_bootstrap(
        &row.bootstrap_canonical_receipt,
        config.receipt_pin(),
        &frozen_profile_reference_v1(),
        pinned_scope,
        genesis_package()?,
    )?;
    verify_epoch(row, &bootstrap)?;

    let generation =
        u64::try_from(row.generation).map_err(|_| WriterAuthorityRejection::Unrepresentable)?;
    if generation < 1 {
        return Err(WriterAuthorityRejection::Generation.into());
    }
    verify_descent(row, generation)?;

    let head_binding = decode_canonical_head(&row.canonical_head)?;
    verify_head_binding(row, &head_binding)?;

    if config
        .expected_activation_id()
        .is_some_and(|expected| expected != row.activation_id)
    {
        return Err(WriterAuthorityRejection::ExpectedActivationId.into());
    }

    let package = materialize_active_package(row.package_digest)?;
    let recipe = &bootstrap.receipt().statement.genesis_epoch.partition_recipe;
    Ok(WriterAuthorityWitness {
        activation_id: row.activation_id,
        generation,
        package_digest: row.package_digest,
        activation_policy_digest: row.activation_policy_digest,
        log_epoch_id: bootstrap.epoch_id(),
        partition_recipe_id: recipe.recipe_id.clone(),
        partition_recipe_version: recipe.recipe_version,
        partition_algorithm: recipe.algorithm,
        partition_seed: *recipe.seed.as_bytes(),
        shard_count: recipe.shard_count,
        contract_tenant_namespace: pinned_scope.tenant_namespace.clone(),
        contract_project_namespace: pinned_scope.project_namespace.clone(),
        canonical_head: Arc::new(row.canonical_head.clone()),
        head_binding,
        bootstrap: Arc::new(bootstrap),
        package,
    })
}

/// The durable log epoch must be exactly the receipt's genesis epoch. The
/// evidence ledger binds its head rows to this epoch inside the append
/// transaction, which is what replaces the foreign key ADR 0002 D1 forbids.
fn verify_epoch(row: &AuthorityRow, bootstrap: &VerifiedBootstrapReceipt) -> WitnessResult<()> {
    let recipe = &bootstrap.receipt().statement.genesis_epoch.partition_recipe;
    let epoch_id = bootstrap.epoch_id().digest();
    let shard_count = i32::from(recipe.shard_count);
    let recipe_version =
        i32::try_from(recipe.recipe_version).map_err(|_| WriterAuthorityRejection::LogEpoch)?;
    if row.log_epoch_id != epoch_id
        || row.bootstrap_epoch_id != epoch_id
        || row.log_shard_count != shard_count
        || row.bootstrap_shard_count != shard_count
        || row.partition_recipe_id != recipe.recipe_id.as_str()
        || row.partition_recipe_version != recipe_version
        || row.partition_algorithm != partition_algorithm_column(recipe.algorithm)
        || row.partition_seed != recipe.seed.as_bytes()
    {
        return Err(WriterAuthorityRejection::LogEpoch.into());
    }
    Ok(())
}

/// Descent facts a reader can establish without any base-table privilege.
///
/// `root_package_digest` must be the genesis package the pinned receipt names,
/// and `root_activation_policy_digest` must be the policy digest that package
/// determines, so the transition the view joined descends from the pinned
/// bootstrap root rather than from some other genesis. The predecessor columns
/// must be present and ordinally correct for every post-genesis generation,
/// and at generation 1 they must be the root itself.
///
/// `root_activation_id` cannot be recomputed here: a genesis activation ID is
/// a function of the activation statement (effective interval, proposer and
/// author principals, test-result digest), none of which the view exposes and
/// none of which the runtime role may read. It is checked for shape only; the
/// activation ceremonies and their audits establish it.
fn verify_descent(row: &AuthorityRow, generation: u64) -> WitnessResult<()> {
    let genesis_package = genesis_package()?;
    let expected_root_policy = genesis_activation_policy_digest(genesis_package)?;
    if row.root_package_digest != genesis_package.package_digest()
        || row.root_activation_policy_digest != expected_root_policy
        || row.root_activation_id == Sha256Digest::ZERO
    {
        return Err(WriterAuthorityRejection::Descent.into());
    }
    let (Some(predecessor_generation), Some(predecessor_activation_id)) =
        (row.predecessor_generation, row.predecessor_activation_id)
    else {
        return Err(WriterAuthorityRejection::Descent.into());
    };
    let expected_predecessor_generation =
        i64::try_from(generation - 1).map_err(|_| WriterAuthorityRejection::Unrepresentable)?;
    if predecessor_generation != expected_predecessor_generation
        || row.predecessor_package_digest.is_none()
        || row.predecessor_activation_policy_digest.is_none()
    {
        return Err(WriterAuthorityRejection::Descent.into());
    }
    if generation == 1
        && (predecessor_activation_id != row.root_activation_id
            || row.predecessor_package_digest != Some(row.root_package_digest)
            || row.predecessor_activation_policy_digest != Some(row.root_activation_policy_digest))
    {
        return Err(WriterAuthorityRejection::Descent.into());
    }
    if row.activation_id == predecessor_activation_id {
        return Err(WriterAuthorityRejection::Descent.into());
    }
    Ok(())
}

/// The canonical head bytes must bind exactly the projected head columns.
///
/// `RegistryHeadBindingV1::validate_shape` admits `Some(effective_until)`, and
/// `memory_registry_current_heads_v2` has no `effective_until` column to
/// contradict it, so an active head whose own canonical bytes declare
/// themselves already expired would otherwise be accepted. No supported write
/// path can produce one (every activation ceremony rejects a bounded interval
/// on both the predecessor and the activated head), which is exactly why this
/// is asserted here rather than assumed: an open interval is what the
/// projection means, so a closed one is not a head this writer may act under.
fn verify_head_binding(
    row: &AuthorityRow,
    head_binding: &RegistryHeadBindingV1,
) -> WitnessResult<()> {
    let effective_from = canonical_timestamp_to_database(&head_binding.effective_from)?;
    if head_binding.head.activation_id != row.activation_id
        || head_binding.head.package_digest != row.package_digest
        || head_binding.head.activation_policy_digest != row.activation_policy_digest
        || effective_from != row.effective_from
        || head_binding.effective_until.is_some()
    {
        return Err(WriterAuthorityRejection::HeadBinding.into());
    }
    Ok(())
}

/// Map the head's package digest to a compiled-in semantically closed package.
///
/// Generation 1 activates exactly the frozen first Stage-4 package. Any other
/// digest fails closed: the view deliberately exposes no `canonical_package`
/// column, so a later generation needs either its own compiled-in bytes here
/// or an additive migration that exposes the canonical package through
/// `memory_writer_authority_v1`. Guessing is not an option — the writer would
/// otherwise run admission rules it has never verified.
pub fn materialize_active_package(
    package_digest: Sha256Digest,
) -> WitnessResult<Arc<SemanticallyClosedStage4Package>> {
    let package = stage4_package()?;
    if package.package_digest() != package_digest {
        return Err(WriterAuthorityRejection::UnknownActivePackage.into());
    }
    Ok(package)
}

/// Decode cache keyed ONLY by the exact canonical head bytes (D4). Nothing
/// else in the authority path is cached: every call re-reads the view, and a
/// cache hit still re-verifies the decoded value against that fresh row.
fn decode_canonical_head(canonical_head: &[u8]) -> WitnessResult<Arc<RegistryHeadBindingV1>> {
    let cache = decode_cache();
    if let Ok(guard) = cache.lock()
        && let Some(cached) = guard.get(canonical_head)
    {
        return Ok(Arc::clone(cached));
    }
    require_canonical(canonical_head)?;
    let head_binding: RegistryHeadBindingV1 = decode_strict(canonical_head)?;
    head_binding.validate_shape()?;
    if encode_canonical(&head_binding)? != canonical_head {
        return Err(ContractError::NotCanonical.into());
    }
    let head_binding = Arc::new(head_binding);
    if let Ok(mut guard) = cache.lock() {
        if guard.len() >= DECODE_CACHE_CAPACITY {
            guard.clear();
        }
        guard.insert(canonical_head.to_vec(), Arc::clone(&head_binding));
    }
    Ok(head_binding)
}

fn decode_cache() -> &'static Mutex<HashMap<Vec<u8>, Arc<RegistryHeadBindingV1>>> {
    static CACHE: OnceLock<Mutex<HashMap<Vec<u8>, Arc<RegistryHeadBindingV1>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Compiled-in genesis package closure. These bytes are a build input, not
/// database state, so memoizing the closure caches no authority.
fn genesis_package() -> WitnessResult<&'static SemanticallyClosedGenesisPackage> {
    static PACKAGE: OnceLock<Option<SemanticallyClosedGenesisPackage>> = OnceLock::new();
    PACKAGE
        .get_or_init(|| closed_genesis_package().ok())
        .as_ref()
        .ok_or_else(|| {
            WriterAuthorityError::Contract(ContractError::Schema(
                "the compiled-in genesis registry package is not semantically closed".into(),
            ))
        })
}

fn closed_genesis_package() -> ContractResult<SemanticallyClosedGenesisPackage> {
    let profile = frozen_profile_reference_v1();
    let manifest =
        ManifestVerifiedRegistryPackage::decode(framed_record(GENESIS_PACKAGE)?, &profile)?;
    SemanticallyClosedGenesisPackage::from_manifest_verified(manifest)
}

/// Compiled-in Stage-4 package closure, memoized for the same reason.
fn stage4_package() -> WitnessResult<Arc<SemanticallyClosedStage4Package>> {
    static PACKAGE: OnceLock<Option<Arc<SemanticallyClosedStage4Package>>> = OnceLock::new();
    PACKAGE
        .get_or_init(|| closed_stage4_package().ok().map(Arc::new))
        .clone()
        .ok_or_else(|| {
            WriterAuthorityError::Contract(ContractError::Schema(
                "the compiled-in Stage-4 successor package is not semantically closed".into(),
            ))
        })
}

fn closed_stage4_package() -> ContractResult<SemanticallyClosedStage4Package> {
    let profile = frozen_profile_reference_v1();
    let manifest =
        ManifestVerifiedRegistryPackage::decode(framed_record(STAGE4_PACKAGE)?, &profile)?;
    let successor = SemanticallyClosedSuccessorPackage::from_manifest_verified(manifest)?;
    SemanticallyClosedStage4Package::from_successor_package(successor)
}

/// Frozen contract artifacts carry exactly one trailing LF frame.
fn framed_record(artifact: &'static [u8]) -> ContractResult<&'static [u8]> {
    let body = artifact
        .strip_suffix(b"\n")
        .ok_or_else(|| ContractError::Schema("contract artifact is not LF framed".into()))?;
    if body.ends_with(b"\n") || body.contains(&b'\r') {
        return Err(ContractError::Schema(
            "contract artifact framing is not exact".into(),
        ));
    }
    Ok(body)
}

const fn partition_algorithm_column(algorithm: PartitionAlgorithm) -> &'static str {
    match algorithm {
        PartitionAlgorithm::Sha256Prefix64Modulo => "sha256_prefix64_modulo",
    }
}

fn canonical_timestamp_to_database(timestamp: &CanonicalTimestamp) -> WitnessResult<DateTime<Utc>> {
    Ok(DateTime::parse_from_rfc3339(timestamp.as_str())
        .map_err(|_| WriterAuthorityRejection::HeadBinding)?
        .with_timezone(&Utc))
}

fn digest_column(row: &sqlx::postgres::PgRow, column: &str) -> WitnessResult<Sha256Digest> {
    let bytes: Vec<u8> = row.try_get(column)?;
    fixed_digest(bytes)
}

fn optional_digest_column(
    row: &sqlx::postgres::PgRow,
    column: &str,
) -> WitnessResult<Option<Sha256Digest>> {
    let bytes: Option<Vec<u8>> = row.try_get(column)?;
    bytes.map(fixed_digest).transpose()
}

fn fixed_digest(bytes: Vec<u8>) -> WitnessResult<Sha256Digest> {
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| WriterAuthorityRejection::Unrepresentable)?;
    Ok(Sha256Digest::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::memory_contracts::bootstrap::{
        BootstrapAttestationV1, BootstrapPin, BootstrapReceiptDigest, BootstrapReceiptV1,
    };
    use crate::memory_contracts::common::{FixedHex32, FixedHex64};
    use crate::memory_contracts::digest::{DigestDomain, domain_separated_digest};
    use crate::memory_contracts::registry::RegistryHeadV1;
    use ring::signature::Ed25519KeyPair;

    /// Exact canonical bytes of the frozen bootstrap receipt. The offline
    /// vectors below re-sign a copy of it, which is what lets a complete
    /// authority row exist without a database: every negative vector here runs
    /// the same [`verify_row`] the connected proof runs, so weakening any
    /// verification step fails `cargo test` even with no `CockroachDB` in
    /// reach.
    const BOOTSTRAP_RECEIPT: &[u8] =
        include_bytes!("../../contracts/dynamic-memory/v1/bootstrap-receipt.jsonl");

    /// Head interval start used by the offline row. Microsecond aligned, so
    /// `RegistryHeadBindingV1::validate_shape` admits it.
    const EFFECTIVE_FROM: &str = "2026-08-16T00:00:00.000000000Z";

    /// One negative vector: a single-field edit of an otherwise valid row.
    type RowMutation = fn(&mut AuthorityRow);

    /// A digest no compiled-in artifact and no fixture column carries.
    const FOREIGN_DIGEST: [u8; 32] = [0x66; 32];

    /// One fully consistent authority row, the receipt it descends from, and
    /// the pins that accept it.
    struct AuthorityFixture {
        bootstrap: VerifiedBootstrapReceipt,
        config: WriterAuthorityConfig,
        head_binding: RegistryHeadBindingV1,
        row: AuthorityRow,
    }

    /// Re-sign the frozen receipt over a caller-chosen partition seed so each
    /// vector gets a distinct but genuinely verifiable genesis epoch.
    fn signed_bootstrap(seed_byte: u8) -> VerifiedBootstrapReceipt {
        let mut receipt: BootstrapReceiptV1 =
            decode_strict(framed_record(BOOTSTRAP_RECEIPT).expect("receipt framing"))
                .expect("bootstrap fixture decodes");
        receipt.statement.genesis_epoch.partition_recipe.seed =
            FixedHex32::from_bytes([seed_byte; 32]);
        let statement_id = receipt.statement.statement_id().expect("statement id");
        let mut message = b"ostk-bootstrap-approval-v1\0".to_vec();
        message.extend_from_slice(statement_id.digest().as_bytes());
        receipt.attestations = [1_u8, 2]
            .into_iter()
            .enumerate()
            .map(|(index, signer_seed)| BootstrapAttestationV1 {
                schema_version: 1,
                statement_id,
                signer_principal_id: ContractId::new(format!("principal.{}", index + 1))
                    .expect("principal"),
                signature: FixedHex64::from_bytes(
                    Ed25519KeyPair::from_seed_unchecked(&[signer_seed; 32])
                        .expect("signing key")
                        .sign(&message)
                        .as_ref()
                        .try_into()
                        .expect("signature width"),
                ),
            })
            .collect();
        let canonical = encode_canonical(&receipt).expect("canonical receipt");
        let receipt_digest = BootstrapReceiptDigest::from_digest(domain_separated_digest(
            DigestDomain::BootstrapReceipt,
            &canonical,
        ));
        verify_pinned_bootstrap(
            &canonical,
            BootstrapPin::from_trusted_config(receipt_digest),
            &frozen_profile_reference_v1(),
            &receipt.statement.scope,
            genesis_package().expect("genesis package"),
        )
        .expect("the re-signed receipt must verify against its own digest")
    }

    /// Build the exact row shape `memory_writer_authority_v1` projects for a
    /// generation-1 head that activated the frozen Stage-4 package.
    fn authority_fixture(seed_byte: u8) -> AuthorityFixture {
        let bootstrap = signed_bootstrap(seed_byte);
        let semantic_scope = bootstrap.receipt().statement.scope.clone();
        let config = WriterAuthorityConfig::from_trusted_context(
            semantic_scope.clone(),
            bootstrap.receipt_digest(),
            None,
        );
        let genesis = genesis_package().expect("genesis package");
        let stage4 = stage4_package().expect("Stage-4 package");
        let root_activation_id = Sha256Digest::from_bytes([0x11; 32]);
        let root_policy = genesis_activation_policy_digest(genesis).expect("genesis policy digest");
        let activation_id = Sha256Digest::from_bytes([0x22; 32]);
        let activation_policy_digest = Sha256Digest::from_bytes([0x33; 32]);
        let head_binding = RegistryHeadBindingV1 {
            head: RegistryHeadV1 {
                activation_id,
                package_digest: stage4.package_digest(),
                activation_policy_digest,
            },
            effective_from: CanonicalTimestamp::parse(EFFECTIVE_FROM).expect("canonical time"),
            effective_until: None,
        };
        let recipe = &bootstrap.receipt().statement.genesis_epoch.partition_recipe;
        let shard_count = i32::from(recipe.shard_count);
        let row = AuthorityRow {
            bootstrap_receipt_digest: bootstrap.receipt_digest().digest(),
            bootstrap_canonical_receipt: bootstrap.canonical_bytes().to_vec(),
            bootstrap_epoch_id: bootstrap.epoch_id().digest(),
            bootstrap_shard_count: shard_count,
            bootstrap_contract_tenant_namespace: semantic_scope
                .tenant_namespace
                .as_str()
                .to_owned(),
            bootstrap_contract_project_namespace: semantic_scope
                .project_namespace
                .as_str()
                .to_owned(),
            log_epoch_id: bootstrap.epoch_id().digest(),
            partition_recipe_id: recipe.recipe_id.as_str().to_owned(),
            partition_recipe_version: i32::try_from(recipe.recipe_version).expect("recipe version"),
            partition_algorithm: partition_algorithm_column(recipe.algorithm).to_owned(),
            partition_seed: recipe.seed.as_bytes().to_vec(),
            log_shard_count: shard_count,
            head_state: ACTIVE_HEAD_STATE.to_owned(),
            generation: 1,
            activation_id,
            package_digest: stage4.package_digest(),
            activation_policy_digest,
            contract_tenant_namespace: semantic_scope.tenant_namespace.as_str().to_owned(),
            contract_project_namespace: semantic_scope.project_namespace.as_str().to_owned(),
            effective_from: DateTime::parse_from_rfc3339(EFFECTIVE_FROM)
                .expect("rfc3339 head interval start")
                .with_timezone(&Utc),
            canonical_head: encode_canonical(&head_binding).expect("canonical head"),
            root_activation_id,
            root_package_digest: genesis.package_digest(),
            root_activation_policy_digest: root_policy,
            predecessor_generation: Some(0),
            predecessor_activation_id: Some(root_activation_id),
            predecessor_package_digest: Some(genesis.package_digest()),
            predecessor_activation_policy_digest: Some(root_policy),
        };
        AuthorityFixture {
            bootstrap,
            config,
            head_binding,
            row,
        }
    }

    /// Mutate one field of an otherwise valid row and require the exact
    /// fail-closed verdict from the whole verification path.
    fn expect_rejection(
        fixture: &AuthorityFixture,
        label: &str,
        mutate: impl FnOnce(&mut AuthorityRow),
        expected: WriterAuthorityRejection,
    ) {
        let mut row = fixture.row.clone();
        mutate(&mut row);
        match verify_row(&row, &fixture.config) {
            Err(WriterAuthorityError::Rejected(actual)) => {
                assert_eq!(actual, expected, "{label}: wrong rejection");
            }
            Err(other) => panic!("{label}: expected {expected:?}, got {other}"),
            Ok(_) => panic!("{label}: a tampered authority row minted a witness"),
        }
    }

    /// Replace only the canonical head bytes and require a contract-level
    /// failure: a canonicality verdict is never a rejection verdict.
    fn expect_contract_error(fixture: &AuthorityFixture, label: &str, canonical_head: Vec<u8>) {
        let mut row = fixture.row.clone();
        row.canonical_head = canonical_head;
        match verify_row(&row, &fixture.config) {
            Err(WriterAuthorityError::Contract(_)) => {}
            Err(other) => panic!("{label}: expected a contract error, got {other}"),
            Ok(_) => panic!("{label}: non-canonical head bytes minted a witness"),
        }
    }

    /// Re-encode the head binding after mutating it, leaving every projected
    /// column untouched.
    fn head_bytes(
        fixture: &AuthorityFixture,
        mutate: impl FnOnce(&mut RegistryHeadBindingV1),
    ) -> Vec<u8> {
        let mut binding = fixture.head_binding.clone();
        mutate(&mut binding);
        encode_canonical(&binding).expect("canonical head")
    }

    #[test]
    fn compiled_in_packages_are_semantically_closed() {
        let genesis = genesis_package().expect("genesis package closure");
        let stage4 = stage4_package().expect("Stage-4 package closure");
        assert_ne!(genesis.package_digest(), stage4.package_digest());
    }

    #[test]
    fn materialization_admits_only_the_compiled_in_stage4_package() {
        let stage4 = stage4_package().expect("Stage-4 package closure");
        assert_eq!(
            materialize_active_package(stage4.package_digest())
                .expect("Stage-4 digest materializes")
                .package_digest(),
            stage4.package_digest()
        );

        let genesis = genesis_package().expect("genesis package closure");
        for unknown in [
            Sha256Digest::ZERO,
            genesis.package_digest(),
            Sha256Digest::from_bytes([0x5a; 32]),
        ] {
            assert!(
                matches!(
                    materialize_active_package(unknown),
                    Err(WriterAuthorityError::Rejected(
                        WriterAuthorityRejection::UnknownActivePackage
                    ))
                ),
                "materialized an unknown active package digest {unknown}"
            );
        }
    }

    #[test]
    fn the_authority_query_reads_exactly_one_fully_qualified_relation() {
        assert!(SELECT_WRITER_AUTHORITY_SQL.contains("public.memory_writer_authority_v1"));
        assert!(SELECT_WRITER_AUTHORITY_SQL.contains("LIMIT 2"));
        assert!(!SELECT_WRITER_AUTHORITY_SQL.contains("FOR UPDATE"));
        for forbidden in [
            "memory_control_",
            "memory_registry_",
            "memory_evidence_",
            "JOIN",
            "UNION",
        ] {
            assert!(
                !SELECT_WRITER_AUTHORITY_SQL.contains(forbidden),
                "the head witness must not reference {forbidden}"
            );
        }
    }

    #[test]
    fn the_decode_cache_is_keyed_by_exact_canonical_bytes_and_is_bounded() {
        let first = decode_cache().lock().expect("cache").len();
        assert!(first <= DECODE_CACHE_CAPACITY);
        assert!(decode_canonical_head(b"{}").is_err());
        assert!(decode_canonical_head(b"not json").is_err());
        assert_eq!(
            decode_cache().lock().expect("cache").len(),
            first,
            "a rejected head must never enter the decode cache"
        );
    }

    #[test]
    fn a_consistent_authority_row_mints_a_witness() {
        let fixture = authority_fixture(0x51);
        let witness = verify_row(&fixture.row, &fixture.config).expect("witness");
        assert_eq!(witness.generation(), 1);
        assert_eq!(witness.activation_id(), fixture.row.activation_id);
        assert_eq!(witness.partition_seed(), &[0x51_u8; 32]);
        assert_eq!(witness.canonical_head(), fixture.row.canonical_head);
        assert_eq!(
            witness.package().package_digest(),
            stage4_package().expect("Stage-4 package").package_digest()
        );
    }

    /// REPLAY-01. `verify_epoch` is the only thing binding the durable log
    /// epoch, partition recipe, seed, and shard count to the verified receipt,
    /// so every field it compares gets a negative vector. On a live database
    /// only `partition_seed` is reachable — migration 0014's
    /// `memory_control_head_epoch_fk` holds `shard_count` and a CHECK holds
    /// `partition_recipe_version` — so the connected proof attacks that one and
    /// the remaining seven are established here.
    #[test]
    fn epoch_verification_binds_every_field_of_the_receipts_genesis_epoch() {
        let fixture = authority_fixture(0x52);
        verify_epoch(&fixture.row, &fixture.bootstrap).expect("the fixture epoch must verify");
        let mutations: [(&str, RowMutation); 8] = [
            ("partition_seed", |row| row.partition_seed = vec![0x40; 32]),
            ("log_epoch_id", |row| {
                row.log_epoch_id = Sha256Digest::from_bytes(FOREIGN_DIGEST);
            }),
            ("bootstrap_epoch_id", |row| {
                row.bootstrap_epoch_id = Sha256Digest::from_bytes(FOREIGN_DIGEST);
            }),
            ("log_shard_count", |row| row.log_shard_count = 8),
            ("bootstrap_shard_count", |row| row.bootstrap_shard_count = 8),
            ("partition_recipe_id", |row| {
                row.partition_recipe_id = "ostk.partition.other".to_owned();
            }),
            ("partition_recipe_version", |row| {
                row.partition_recipe_version = 2;
            }),
            ("partition_algorithm", |row| {
                row.partition_algorithm = "sha256_prefix64_modulo_v2".to_owned();
            }),
        ];
        for (label, mutate) in mutations {
            expect_rejection(&fixture, label, mutate, WriterAuthorityRejection::LogEpoch);
        }
    }

    /// AUTH-04 descent. A root UPDATE cannot reach these columns on a live
    /// database: `memory_registry_transitions` holds every root column under
    /// `memory_registry_transition_genesis_head_fk` and
    /// `memory_registry_transition_genesis_activation_fk` (migration 0012), and
    /// `memory_registry_current_head_transition_fk` (migration 0014) holds the
    /// projected columns, so the connected proof asserts that refusal and the
    /// negative vectors for `verify_descent` live here, over a hand-built row.
    #[test]
    fn descent_verification_requires_the_pinned_genesis_root() {
        let fixture = authority_fixture(0x53);
        verify_descent(&fixture.row, 1).expect("the fixture descent must verify");
        let mutations: [(&str, RowMutation); 11] = [
            ("root_package_digest", |row| {
                row.root_package_digest = Sha256Digest::from_bytes(FOREIGN_DIGEST);
            }),
            ("root_activation_policy_digest", |row| {
                row.root_activation_policy_digest = Sha256Digest::from_bytes(FOREIGN_DIGEST);
            }),
            ("zero root_activation_id", |row| {
                row.root_activation_id = Sha256Digest::ZERO;
                row.predecessor_activation_id = Some(Sha256Digest::ZERO);
            }),
            ("absent predecessor_generation", |row| {
                row.predecessor_generation = None;
            }),
            ("misordered predecessor_generation", |row| {
                row.predecessor_generation = Some(1);
            }),
            ("absent predecessor_package_digest", |row| {
                row.predecessor_package_digest = None;
            }),
            ("absent predecessor_activation_policy_digest", |row| {
                row.predecessor_activation_policy_digest = None;
            }),
            ("generation-1 predecessor is not the root", |row| {
                row.predecessor_activation_id = Some(Sha256Digest::from_bytes(FOREIGN_DIGEST));
            }),
            ("generation-1 predecessor package is not the root", |row| {
                row.predecessor_package_digest = Some(Sha256Digest::from_bytes(FOREIGN_DIGEST));
            }),
            ("generation-1 predecessor policy is not the root", |row| {
                row.predecessor_activation_policy_digest =
                    Some(Sha256Digest::from_bytes(FOREIGN_DIGEST));
            }),
            ("ABA: the head is its own predecessor", |row| {
                row.activation_id = row.root_activation_id;
            }),
        ];
        for (label, mutate) in mutations {
            expect_rejection(&fixture, label, mutate, WriterAuthorityRejection::Descent);
        }
    }

    /// D4. The canonical head must bind the projected columns exactly. Each
    /// column the binding carries gets a vector, plus the closed-interval case
    /// the projection has no column to contradict.
    #[test]
    fn head_binding_verification_requires_every_projected_column() {
        let fixture = authority_fixture(0x54);
        verify_head_binding(&fixture.row, &fixture.head_binding)
            .expect("the fixture head binding must verify");

        for (label, canonical_head) in [
            (
                "activation_id",
                head_bytes(&fixture, |binding| {
                    binding.head.activation_id = Sha256Digest::from_bytes(FOREIGN_DIGEST);
                }),
            ),
            (
                "package_digest",
                head_bytes(&fixture, |binding| {
                    binding.head.package_digest = Sha256Digest::from_bytes(FOREIGN_DIGEST);
                }),
            ),
            (
                "activation_policy_digest",
                head_bytes(&fixture, |binding| {
                    binding.head.activation_policy_digest =
                        Sha256Digest::from_bytes(FOREIGN_DIGEST);
                }),
            ),
            (
                "effective_from",
                head_bytes(&fixture, |binding| {
                    binding.effective_from =
                        CanonicalTimestamp::parse("2026-08-17T00:00:00.000000000Z")
                            .expect("canonical time");
                }),
            ),
            (
                "effective_until",
                head_bytes(&fixture, |binding| {
                    binding.effective_until = Some(
                        CanonicalTimestamp::parse("2026-08-17T00:00:00.000000000Z")
                            .expect("canonical time"),
                    );
                }),
            ),
        ] {
            expect_rejection(
                &fixture,
                label,
                |row| row.canonical_head = canonical_head,
                WriterAuthorityRejection::HeadBinding,
            );
        }
    }

    /// D4. The stored head must already be in canonical byte form. Whitespace
    /// is caught by `require_canonical`; a dropped `effective_until` member is
    /// valid canonical JSON that decodes cleanly and is caught only by the
    /// re-encode comparison, so both gates are load bearing.
    #[test]
    fn canonical_head_bytes_must_already_be_canonical() {
        let fixture = authority_fixture(0x55);
        let canonical = fixture.row.canonical_head.clone();

        let value: serde_json::Value =
            serde_json::from_slice(&canonical).expect("the fixture head is JSON");
        let pretty = serde_json::to_vec_pretty(&value).expect("pretty printed head");
        assert_ne!(pretty, canonical);
        expect_contract_error(&fixture, "pretty printed head", pretty);

        let text = String::from_utf8(canonical).expect("canonical JSON is UTF-8");
        let trimmed = text.replace("\"effective_until\":null,", "");
        assert_ne!(
            trimmed, text,
            "the canonical head must carry effective_until"
        );
        assert!(
            require_canonical(trimmed.as_bytes()).is_ok(),
            "the trimmed head must still be canonical JSON, so only the \
             re-encode comparison can catch it"
        );
        assert!(
            decode_strict::<RegistryHeadBindingV1>(trimmed.as_bytes()).is_ok(),
            "the trimmed head must still decode, so only the re-encode \
             comparison can catch it"
        );
        expect_contract_error(
            &fixture,
            "dropped effective_until member",
            trimmed.into_bytes(),
        );
    }

    /// AUTH-04. The break-glass pin and the head-state and namespace gates are
    /// asserted live; these two are asserted here as well because they are the
    /// cheapest to weaken and the hardest to notice.
    #[test]
    fn the_break_glass_pin_and_head_state_are_load_bearing() {
        let fixture = authority_fixture(0x56);
        let pinned = WriterAuthorityConfig::from_trusted_context(
            fixture.config.semantic_scope().clone(),
            fixture.config.bootstrap_receipt_digest(),
            Some(Sha256Digest::from_bytes(FOREIGN_DIGEST)),
        );
        match verify_row(&fixture.row, &pinned) {
            Err(WriterAuthorityError::Rejected(WriterAuthorityRejection::ExpectedActivationId)) => {
            }
            other => panic!("a break-glass mismatch must fail closed, got {other:?}"),
        }

        expect_rejection(
            &fixture,
            "head_state",
            |row| row.head_state = "retired".to_owned(),
            WriterAuthorityRejection::HeadNotActive,
        );
        expect_rejection(
            &fixture,
            "generation 0",
            |row| row.generation = 0,
            WriterAuthorityRejection::Generation,
        );
    }
}
