//! Shared, full audit boundary for the immutable Stage-3 genesis root.
//!
//! The Stage-3 repository adds a separate assertion that genesis is still the
//! registry-stream tip. The first-successor repository deliberately does not:
//! after a successful `0 -> 1` transition, the same immutable genesis root must
//! remain re-auditable during exact replay.

use sqlx::{Postgres, Transaction};

use super::AcceptedGenesisActivation;
use super::cockroach::{BoundActivationAuthority, audit_immutable_genesis_root_impl};
use crate::Result;
use crate::control_log::TrustedControlScope;
use crate::memory_contracts::canonical::encode_canonical;
use crate::memory_contracts::common::{ContractId, RegistryReferenceV1};
use crate::memory_contracts::evidence_v2::RegistryHeadBindingV1;
use crate::memory_contracts::genesis_activation::{
    GenesisRegistryActivationReceiptV1, VerifiedGenesisRegistryActivationRequest,
};
use crate::memory_contracts::successor_policy::{
    GenesisTransitionSeparationOfDutyV1, ImmutableGenesisSuccessorWitness,
};

/// Fully reconstructed immutable genesis authority and all of its canonical
/// durable preimages.
pub(super) struct AuditedGenesisRoot {
    pub(super) inspection: AcceptedGenesisActivation,
    pub(super) verified: VerifiedGenesisRegistryActivationRequest,
    pub(super) receipt: GenesisRegistryActivationReceiptV1,
    pub(super) current_v1_activation_policy: RegistryReferenceV1,
    pub(super) eligible_v1_principal_ids: Vec<ContractId>,
    pub(super) required_v1_threshold: u16,
    pub(super) canonical_statement: Vec<u8>,
    pub(super) canonical_approval_set: Vec<u8>,
    pub(super) canonical_receipt: Vec<u8>,
    pub(super) canonical_event: Vec<u8>,
    pub(super) canonical_head_binding: Vec<u8>,
}

impl AuditedGenesisRoot {
    pub(super) fn head_binding(&self) -> Result<RegistryHeadBindingV1> {
        let binding = RegistryHeadBindingV1 {
            head: self.inspection.registry_head.clone(),
            effective_from: self.inspection.effective_from.clone(),
            effective_until: None,
        };
        binding.validate_shape()?;
        if encode_canonical(&binding)? != self.canonical_head_binding {
            return Err(crate::FleetError::RegistryActivationCorrupt(
                "audited genesis head binding changed during reconstruction".into(),
            ));
        }
        Ok(binding)
    }

    /// Mint the bridge verifier's opaque witness only after the durable root
    /// has passed the shared full audit.
    pub(super) fn immutable_successor_witness(&self) -> Result<ImmutableGenesisSuccessorWitness> {
        Ok(ImmutableGenesisSuccessorWitness::from_durable_audit(
            self.verified.statement().profile.clone(),
            self.verified.statement().scope.clone(),
            self.head_binding()?,
            self.current_v1_activation_policy.clone(),
            self.eligible_v1_principal_ids.clone(),
            self.required_v1_threshold,
            GenesisTransitionSeparationOfDutyV1::IndependentApprovalFromPackageAuthor,
        )?)
    }
}

/// The only shared entry point for reconstructing the immutable genesis root.
pub(super) async fn audit_immutable_genesis_root(
    transaction: &mut Transaction<'_, Postgres>,
    scope: &TrustedControlScope,
    authority: &BoundActivationAuthority,
) -> Result<AuditedGenesisRoot> {
    audit_immutable_genesis_root_impl(transaction, scope, authority).await
}
