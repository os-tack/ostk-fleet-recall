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
fn verify_head_binding(
    row: &AuthorityRow,
    head_binding: &RegistryHeadBindingV1,
) -> WitnessResult<()> {
    let effective_from = canonical_timestamp_to_database(&head_binding.effective_from)?;
    if head_binding.head.activation_id != row.activation_id
        || head_binding.head.package_digest != row.package_digest
        || head_binding.head.activation_policy_digest != row.activation_policy_digest
        || effective_from != row.effective_from
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
}
