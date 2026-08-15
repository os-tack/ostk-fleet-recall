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
    GenesisRegistryActivatedEventV1, GenesisRegistryActivationReceiptV1,
    VerifiedGenesisRegistryActivationRequest,
};
use crate::memory_contracts::successor_policy::{
    GenesisTransitionSeparationOfDutyV1, ImmutableGenesisSuccessorWitness,
};

/// Fully reconstructed immutable genesis authority and all of its canonical
/// durable preimages.
#[allow(dead_code)] // successor-only fields are consumed by the repository SQL slice
pub(super) struct AuditedGenesisRoot {
    pub(super) inspection: AcceptedGenesisActivation,
    pub(super) verified: VerifiedGenesisRegistryActivationRequest,
    pub(super) receipt: GenesisRegistryActivationReceiptV1,
    pub(super) event: GenesisRegistryActivatedEventV1,
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
    #[allow(dead_code)] // consumed by the repository SQL slice
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
    #[allow(dead_code)] // consumed by the repository SQL slice
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

#[cfg(test)]
mod tests {
    const COCKROACH_SOURCE: &str = include_str!("cockroach.rs");

    #[test]
    fn accepted_genesis_paths_share_one_immutable_root_boundary() {
        let calls = COCKROACH_SOURCE
            .matches("genesis_audit::audit_immutable_genesis_root(")
            .count();
        assert_eq!(calls, 2, "both accepted-state paths must share the audit");
        assert!(
            COCKROACH_SOURCE.contains("pub(super) async fn audit_immutable_genesis_root_impl(")
        );
    }

    #[test]
    fn immutable_root_does_not_assume_genesis_is_still_the_stream_tip() {
        let start = COCKROACH_SOURCE
            .find("pub(super) async fn audit_immutable_genesis_root_impl(")
            .unwrap();
        let end = COCKROACH_SOURCE[start..]
            .find("\nasync fn select_registry_stream_prefix(")
            .map(|offset| start + offset)
            .unwrap();
        let boundary = &COCKROACH_SOURCE[start..end];
        assert!(!boundary.contains("select_registry_stream_tip("));
        assert!(!boundary.contains("audit_genesis_only_current_state("));
        assert!(boundary.contains("audit_legacy_genesis_head_root("));
    }

    #[test]
    fn genesis_only_state_retains_the_full_mutable_control_tip_audit() {
        let start = COCKROACH_SOURCE
            .find("async fn audit_genesis_only_current_state(")
            .unwrap();
        let end = COCKROACH_SOURCE[start..]
            .find("\nfn canonical_timestamp_to_database(")
            .map(|offset| start + offset)
            .unwrap();
        let boundary = &COCKROACH_SOURCE[start..end];
        assert!(boundary.contains("durable_shard_floor("));
        assert!(boundary.contains("audit_control_head_tip("));
        assert!(COCKROACH_SOURCE.contains("async fn require_no_event_ahead_of_head("));
    }
}
