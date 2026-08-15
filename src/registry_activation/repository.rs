//! Narrow repository contract for the first registry activation.

use async_trait::async_trait;

use crate::Result;
use crate::memory_contracts::bootstrap::{AppendPositionV1, BootstrapReceiptDigest, EpochId};
use crate::memory_contracts::common::CanonicalTimestamp;
use crate::memory_contracts::evidence::AcceptedEventId;
use crate::memory_contracts::genesis_activation::{
    GenesisRegistryActivationId, GenesisRegistryActivationStatementId,
    VerifiedGenesisRegistryActivationRequest,
};
use crate::memory_contracts::registry::RegistryHeadV1;

/// Exact persisted Stage-2 predecessor before the registry is active.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedInactiveGenesis {
    pub bootstrap_receipt_digest: BootstrapReceiptDigest,
    pub bootstrap_event_id: AcceptedEventId,
    pub epoch_id: EpochId,
    pub bootstrap_accepted_at: CanonicalTimestamp,
}

/// Bounded receipt for the immutable genesis-activation prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedGenesisActivation {
    pub statement_id: GenesisRegistryActivationStatementId,
    pub activation_id: GenesisRegistryActivationId,
    pub accepted_event_id: AcceptedEventId,
    pub registry_head: RegistryHeadV1,
    pub append_position: AppendPositionV1,
    pub bootstrap_receipt_digest: BootstrapReceiptDigest,
    pub effective_from: CanonicalTimestamp,
    pub accepted_at: CanonicalTimestamp,
}

/// Read-only state of the one genesis activation against supplied authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenesisActivationInspection {
    PinnedInactive(PinnedInactiveGenesis),
    Accepted(AcceptedGenesisActivation),
}

/// A first commit is distinguished from an exact historical replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenesisActivationOutcome {
    Inserted(AcceptedGenesisActivation),
    ExactReplay(AcceptedGenesisActivation),
}

/// The private repository accepts only cryptographically verified requests.
#[async_trait]
pub trait GenesisActivationRepository: Send + Sync {
    async fn activate_genesis(
        &self,
        request: &VerifiedGenesisRegistryActivationRequest,
    ) -> Result<GenesisActivationOutcome>;

    async fn inspect_genesis_activation(
        &self,
        request: &VerifiedGenesisRegistryActivationRequest,
    ) -> Result<GenesisActivationInspection>;
}
