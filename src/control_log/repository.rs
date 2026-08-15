//! Narrow repository contract for accepting the one genesis control event.

use async_trait::async_trait;

use crate::Result;
use crate::memory_contracts::bootstrap::{
    BootstrapReceiptDigest, CommittedOffsetV1, EpochId, VerifiedBootstrapReceipt,
};
use crate::memory_contracts::evidence::AcceptedEventId;
use crate::memory_contracts::genesis::SemanticallyClosedGenesisPackage;

/// Bounded proof that the complete genesis database shape matches one exact
/// verified receipt and package. Canonical artifacts remain out of the result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisBootstrapInspection {
    pub receipt_digest: BootstrapReceiptDigest,
    pub epoch_id: EpochId,
    pub accepted_event_id: AcceptedEventId,
    pub shard_count: u16,
    pub head_count: u16,
    pub event_shard: u16,
    pub committed_offset: CommittedOffsetV1,
}

/// Result of inspecting the singleton genesis slot against supplied authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenesisInspection {
    Absent,
    Complete(GenesisBootstrapInspection),
}

/// A successful first acceptance is distinguished from a byte-exact replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenesisBootstrapOutcome {
    Inserted(GenesisBootstrapInspection),
    ExactReplay(GenesisBootstrapInspection),
}

/// The control repository intentionally has no generic append or caller scope.
#[async_trait]
pub trait GenesisRepository: Send + Sync {
    async fn bootstrap_genesis(
        &self,
        bootstrap: &VerifiedBootstrapReceipt,
        package: &SemanticallyClosedGenesisPackage,
    ) -> Result<GenesisBootstrapOutcome>;

    async fn inspect_genesis(
        &self,
        bootstrap: &VerifiedBootstrapReceipt,
        package: &SemanticallyClosedGenesisPackage,
    ) -> Result<GenesisInspection>;
}
