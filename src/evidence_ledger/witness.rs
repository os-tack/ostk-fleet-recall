//! The minimal head-witness seam consumed by the accepted-event appender.
//!
//! # Ownership
//!
//! `W1-HEAD` owns the *production* of a [`WriterAuthorityWitness`]: reading
//! `memory_writer_authority_v1`, verifying descent from the pinned bootstrap
//! root, caching that verdict per exact activation ID, and enforcing the
//! `FleetConfig` namespace pins (ADR 0002 D4). `W1-APPEND` owns only what the
//! append transaction must compare against, so this seam is deliberately a
//! plain value object with:
//!
//! * the exact ABA-safe `activation_id`, `generation`, `package_digest`, and
//!   `activation_policy_digest` of the active head,
//! * the genesis log-epoch ID and its full [`PartitionRecipeV1`],
//! * the credential-bound [`AuthenticatedProjectScopeV1`] namespaces, and
//! * the decoded [`GenesisLogEpochV1`] the shard mapping is computed from.
//!
//! # Why a public constructor is safe
//!
//! [`WriterAuthorityWitness::from_authority_snapshot`] is public because the
//! witness is *not* authority. It is a claim about what the head was when the
//! statement was admitted. ADR 0002 D4 makes the in-transaction plain `SELECT`
//! of `memory_writer_authority_v1` the fence: the appender re-reads the view
//! inside the same serializable transaction and refuses the append unless every
//! witnessed field is byte-equal to what the view reports. A forged witness
//! therefore cannot append anything; it can only fail closed with
//! [`crate::evidence_ledger::EvidenceAppendError::WitnessMismatch`].
//!
//! What *is* unforgeable is the accepted-event side: an
//! [`crate::evidence_ledger::AppendableAcceptedEvent`] can only be built from a
//! contract-validated admitted statement whose own registry-head binding equals
//! this witness.

use crate::memory_contracts::bootstrap::{
    EpochId, GenesisLogEpochV1, PartitionAlgorithm, PartitionRecipeV1,
};
use crate::memory_contracts::common::{AuthenticatedProjectScopeV1, FixedHex32};
use crate::memory_contracts::digest::{DigestDomain, Sha256Digest, framed_digest};
use crate::memory_contracts::registry::RegistryHeadV1;

use super::error::{AuthorityUnavailableKind, EvidenceAppendError, EvidenceAppendResult};

/// The `head_state` value the append fence admits. ADR 0002 D4.
pub const ACTIVE_HEAD_STATE: &str = "active";

/// One decoded `memory_writer_authority_v1` row.
///
/// Every field is copied verbatim from the view. Nothing here is trusted until
/// [`WriterAuthorityWitness::from_authority_snapshot`] proves the row is
/// internally consistent: the decoded genesis epoch must rederive the view's
/// `log_epoch_id`, must carry the view's partition-recipe columns, and must be
/// scoped to the view's contract namespaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriterAuthoritySnapshot {
    /// `head_state`; only [`ACTIVE_HEAD_STATE`] is admitted.
    pub head_state: String,
    /// `generation` of the active registry head.
    pub generation: u64,
    /// `activation_id` of the active registry head.
    pub activation_id: Sha256Digest,
    /// `package_digest` of the active registry head.
    pub package_digest: Sha256Digest,
    /// `activation_policy_digest` of the active registry head.
    pub activation_policy_digest: Sha256Digest,
    /// `log_epoch_id` of the single genesis log epoch.
    pub log_epoch_id: EpochId,
    /// `partition_recipe_id`.
    pub partition_recipe_id: String,
    /// `partition_recipe_version`.
    pub partition_recipe_version: u32,
    /// `partition_algorithm`.
    pub partition_algorithm: String,
    /// `partition_seed`.
    pub partition_seed: FixedHex32,
    /// `log_shard_count`.
    pub log_shard_count: u16,
    /// `contract_tenant_namespace` / `contract_project_namespace` of the head.
    pub head_scope: AuthenticatedProjectScopeV1,
    /// `bootstrap_contract_tenant_namespace` / `..._project_namespace`.
    pub bootstrap_scope: AuthenticatedProjectScopeV1,
    /// The genesis epoch decoded from `bootstrap_canonical_receipt`.
    pub genesis_epoch: GenesisLogEpochV1,
}

/// Per-transaction head witness token (ADR 0002 D4).
///
/// Construct through [`Self::from_authority_snapshot`]. Every field is private
/// so a caller cannot mutate one after the internal-consistency proof ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriterAuthorityWitness {
    head: RegistryHeadV1,
    generation: u64,
    epoch_id: EpochId,
    partition_recipe: PartitionRecipeV1,
    semantic_scope: AuthenticatedProjectScopeV1,
    genesis_epoch: GenesisLogEpochV1,
}

impl WriterAuthorityWitness {
    /// Prove one authority row is internally consistent and freeze it.
    ///
    /// This checks only what the row can prove about itself. It does NOT prove
    /// descent from the pinned bootstrap root, and it is not a substitute for
    /// the in-transaction fence — see the module documentation.
    pub fn from_authority_snapshot(
        snapshot: WriterAuthoritySnapshot,
    ) -> EvidenceAppendResult<Self> {
        if snapshot.head_state != ACTIVE_HEAD_STATE {
            return Err(EvidenceAppendError::AuthorityUnavailable(
                AuthorityUnavailableKind::NotActive,
            ));
        }
        let WriterAuthoritySnapshot {
            generation,
            activation_id,
            package_digest,
            activation_policy_digest,
            log_epoch_id,
            partition_recipe_id,
            partition_recipe_version,
            partition_algorithm,
            partition_seed,
            log_shard_count,
            head_scope,
            bootstrap_scope,
            genesis_epoch,
            ..
        } = snapshot;

        genesis_epoch.validate()?;
        let recipe = &genesis_epoch.partition_recipe;
        let algorithm_label = partition_algorithm_label(recipe.algorithm);
        // The view's denormalized recipe columns and its epoch ID must both be
        // exactly what the signed bootstrap receipt says, or the shard mapping
        // the appender computes would not be the activated one.
        if genesis_epoch.epoch_id()? != log_epoch_id
            || recipe.recipe_id.as_str() != partition_recipe_id
            || recipe.recipe_version != partition_recipe_version
            || algorithm_label != partition_algorithm
            || recipe.seed != partition_seed
            || recipe.shard_count != log_shard_count
        {
            return Err(EvidenceAppendError::AuthorityUnavailable(
                AuthorityUnavailableKind::UndecodableRow,
            ));
        }
        // One semantic scope across bootstrap, epoch, and head. EVID-04: the
        // append never derives scope from a payload field.
        if genesis_epoch.scope != head_scope || bootstrap_scope != head_scope {
            return Err(EvidenceAppendError::AuthorityUnavailable(
                AuthorityUnavailableKind::UndecodableRow,
            ));
        }

        Ok(Self {
            head: RegistryHeadV1 {
                activation_id,
                package_digest,
                activation_policy_digest,
            },
            generation,
            epoch_id: log_epoch_id,
            partition_recipe: recipe.clone(),
            semantic_scope: head_scope,
            genesis_epoch,
        })
    }

    /// Active registry head as the accepted-event contracts spell it.
    #[must_use]
    pub const fn head(&self) -> &RegistryHeadV1 {
        &self.head
    }

    /// Registry generation of the active head.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Genesis log-epoch ID every append position is bound to.
    #[must_use]
    pub const fn epoch_id(&self) -> EpochId {
        self.epoch_id
    }

    /// Activated partition recipe (seed, shard count, algorithm).
    #[must_use]
    pub const fn partition_recipe(&self) -> &PartitionRecipeV1 {
        &self.partition_recipe
    }

    /// Credential-bound semantic scope namespaces.
    #[must_use]
    pub const fn semantic_scope(&self) -> &AuthenticatedProjectScopeV1 {
        &self.semantic_scope
    }

    /// The epoch the shard mapping is computed over.
    #[must_use]
    pub const fn genesis_epoch(&self) -> &GenesisLogEpochV1 {
        &self.genesis_epoch
    }

    /// Number of shards in the activated epoch.
    #[must_use]
    pub const fn shard_count(&self) -> u16 {
        self.partition_recipe.shard_count
    }
}

/// Wire label of one partition algorithm, matching the contract's
/// `rename_all = "snake_case"` serialization and the `partition_algorithm`
/// column migration 0006 writes.
pub const fn partition_algorithm_label(algorithm: PartitionAlgorithm) -> &'static str {
    match algorithm {
        PartitionAlgorithm::Sha256Prefix64Modulo => "sha256_prefix64_modulo",
    }
}

/// Offset-zero chain digest of one lazily seeded evidence shard head.
///
/// `H0 = framed(ostk-evidence-genesis-chain-v1, [epoch_id_bytes,
/// shard_as_u32_big_endian])`.
///
/// The framing is length-prefixed by [`framed_digest`], so the 32-byte epoch ID
/// and the 4-byte shard number can never be re-split. `shard` is framed as a
/// big-endian `u32` even though shard numbers are bounded by 4096: the width is
/// part of the frozen preimage, and the control ledger's `GenesisChain` domain
/// deliberately uses a different domain, a different part list (it also frames
/// the bootstrap receipt digest), and a `u16` shard, so no evidence offset-zero
/// digest can ever be replayed as a control one (ADR 0002 D1).
///
/// A head row is fully determined by `(epoch, shard)`, which is why lazy
/// seeding by the appender grants no forgeable authority.
#[must_use]
pub fn evidence_genesis_chain_digest(epoch_id: EpochId, shard: u16) -> Sha256Digest {
    framed_digest(
        DigestDomain::EvidenceGenesisChainV1,
        &[
            epoch_id.digest().as_bytes(),
            &u32::from(shard).to_be_bytes(),
        ],
    )
}

#[cfg(test)]
mod tests {
    use std::str::FromStr as _;

    use super::*;

    fn epoch(byte: u8) -> EpochId {
        EpochId::from_digest(Sha256Digest::from_bytes([byte; 32]))
    }

    #[test]
    fn evidence_genesis_chain_digest_matches_its_frozen_vector() {
        // Vectored so a later refactor of the framing changes a visible
        // constant rather than silently reseeding every evidence shard head.
        assert_eq!(
            evidence_genesis_chain_digest(epoch(0), 0).to_hex(),
            "d25b08b2d454d8acee3d7395321955cb51d70f7527a14b7de38b55a05713b0a3"
        );
    }

    #[test]
    fn evidence_genesis_chain_domain_and_parts_are_not_interchangeable() {
        let epoch_id = epoch(7);
        assert_ne!(
            evidence_genesis_chain_digest(epoch_id, 1),
            evidence_genesis_chain_digest(epoch_id, 2)
        );
        assert_ne!(
            evidence_genesis_chain_digest(epoch_id, 1),
            evidence_genesis_chain_digest(epoch(8), 1)
        );
        // The control ledger's genesis chain frames three parts under a
        // different domain, so the two ledgers can never collide at offset 0.
        assert_ne!(
            evidence_genesis_chain_digest(epoch_id, 1),
            framed_digest(
                DigestDomain::GenesisChain,
                &[
                    epoch_id.digest().as_bytes(),
                    epoch_id.digest().as_bytes(),
                    &1_u16.to_be_bytes(),
                ],
            )
        );
        assert_eq!(
            DigestDomain::EvidenceGenesisChainV1.prefix(),
            "ostk-evidence-genesis-chain-v1"
        );
    }

    #[test]
    fn shard_number_width_is_part_of_the_frozen_preimage() {
        let epoch_id = epoch(3);
        assert_ne!(
            evidence_genesis_chain_digest(epoch_id, 5),
            framed_digest(
                DigestDomain::EvidenceGenesisChainV1,
                &[epoch_id.digest().as_bytes(), &5_u16.to_be_bytes()],
            )
        );
        assert!(
            Sha256Digest::from_str(&evidence_genesis_chain_digest(epoch_id, 5).to_hex()).is_ok()
        );
    }
}
