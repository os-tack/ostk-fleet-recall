//! Narrow repository contract for the one-time generation `0 -> 1` transition.

use async_trait::async_trait;

use crate::Result;
use crate::memory_contracts::bootstrap::AppendPositionV1;
use crate::memory_contracts::common::CanonicalTimestamp;
use crate::memory_contracts::evidence::AcceptedEventId;
use crate::memory_contracts::evidence_v2::RegistryHeadBindingV1;
use crate::memory_contracts::successor_activation::{
    SuccessorRegistryActivationId, SuccessorRegistryActivationStatementId,
};
use crate::memory_contracts::successor_policy::GenesisSuccessorKeyBridgeDigest;

const MAX_CANONICAL_CANDIDATE_BYTES: usize = 1_048_576;

/// Bounded, still-untrusted canonical candidates.
///
/// Construction proves only transport bounds. Canonical decoding, signature
/// verification, durable bridge binding, and freshness all occur inside the
/// repository transaction.
#[derive(Clone, PartialEq, Eq)]
pub struct SuccessorActivationCandidate {
    canonical_statement: Vec<u8>,
    canonical_approval_set: Vec<u8>,
}

impl std::fmt::Debug for SuccessorActivationCandidate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SuccessorActivationCandidate")
            .field("canonical_statement_bytes", &self.canonical_statement.len())
            .field(
                "canonical_approval_set_bytes",
                &self.canonical_approval_set.len(),
            )
            .finish_non_exhaustive()
    }
}

impl SuccessorActivationCandidate {
    pub fn from_bounded_canonical_bytes(
        canonical_statement: Vec<u8>,
        canonical_approval_set: Vec<u8>,
    ) -> Result<Self> {
        for (name, bytes) in [
            ("successor statement", canonical_statement.as_slice()),
            ("successor approval set", canonical_approval_set.as_slice()),
        ] {
            if bytes.is_empty() || bytes.len() > MAX_CANONICAL_CANDIDATE_BYTES {
                return Err(crate::FleetError::Protocol(format!(
                    "{name} must contain between 1 and {MAX_CANONICAL_CANDIDATE_BYTES} bytes"
                )));
            }
        }
        Ok(Self {
            canonical_statement,
            canonical_approval_set,
        })
    }

    pub fn canonical_statement(&self) -> &[u8] {
        &self.canonical_statement
    }

    pub fn canonical_approval_set(&self) -> &[u8] {
        &self.canonical_approval_set
    }
}

/// Bounded proof that the audited legacy root is ready for its one successor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadySuccessorActivation {
    pub genesis_head: RegistryHeadBindingV1,
    pub bridge_digest: GenesisSuccessorKeyBridgeDigest,
}

/// Bounded receipt for the accepted first-successor transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedSuccessorActivation {
    pub statement_id: SuccessorRegistryActivationStatementId,
    pub activation_id: SuccessorRegistryActivationId,
    pub accepted_event_id: AcceptedEventId,
    pub registry_head: RegistryHeadBindingV1,
    pub append_position: AppendPositionV1,
    pub bridge_digest: GenesisSuccessorKeyBridgeDigest,
    pub accepted_at: CanonicalTimestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuccessorActivationInspection {
    Ready(ReadySuccessorActivation),
    Accepted(AcceptedSuccessorActivation),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuccessorActivationOutcome {
    Inserted(AcceptedSuccessorActivation),
    ExactReplay(AcceptedSuccessorActivation),
}

/// The private repository accepts candidates, then authenticates them against
/// construction-bound authority and durable state inside one transaction.
#[async_trait]
pub trait SuccessorActivationRepository: Send + Sync {
    async fn activate_first_successor(
        &self,
        candidate: &SuccessorActivationCandidate,
    ) -> Result<SuccessorActivationOutcome>;

    async fn inspect_first_successor(
        &self,
        candidate: &SuccessorActivationCandidate,
    ) -> Result<SuccessorActivationInspection>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_debug_redacts_canonical_bytes_and_bounds_both_inputs() {
        let candidate = SuccessorActivationCandidate::from_bounded_canonical_bytes(
            b"statement-secret".to_vec(),
            b"approval-secret".to_vec(),
        )
        .unwrap();
        let debug = format!("{candidate:?}");
        assert!(!debug.contains("statement-secret"));
        assert!(!debug.contains("approval-secret"));
        assert!(
            SuccessorActivationCandidate::from_bounded_canonical_bytes(Vec::new(), vec![1],)
                .is_err()
        );
        assert!(
            SuccessorActivationCandidate::from_bounded_canonical_bytes(
                vec![1],
                vec![0; MAX_CANONICAL_CANDIDATE_BYTES + 1],
            )
            .is_err()
        );
    }
}
