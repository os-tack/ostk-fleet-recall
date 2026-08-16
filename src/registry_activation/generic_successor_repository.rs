//! Narrow repository contract for the repeatable generation `N -> N+1`
//! registry transition (`N >= 1`).
//!
//! The one-time `0 -> 1` ceremony keeps its own frozen contract in
//! [`super::successor_repository`]; nothing here widens or replaces it.

use async_trait::async_trait;

use crate::Result;
use crate::memory_contracts::bootstrap::AppendPositionV1;
use crate::memory_contracts::common::{CanonicalTimestamp, RegistryReferenceV1};
use crate::memory_contracts::evidence::AcceptedEventId;
use crate::memory_contracts::evidence_v2::RegistryHeadBindingV1;
use crate::memory_contracts::successor_generic::{
    GenericSuccessorActivationId, GenericSuccessorActivationStatementId,
};

const MAX_CANONICAL_CANDIDATE_BYTES: usize = 1_048_576;

/// Bounded, still-untrusted canonical generic-successor candidate.
///
/// Construction proves only transport bounds. Canonical decoding, signature
/// verification under the *installed* predecessor policy, freshness, and the
/// head compare-and-swap all occur inside the repository transaction.
#[derive(Clone, PartialEq, Eq)]
pub struct GenericSuccessorActivationCandidate {
    canonical_statement: Vec<u8>,
    canonical_approval_set: Vec<u8>,
}

impl std::fmt::Debug for GenericSuccessorActivationCandidate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GenericSuccessorActivationCandidate")
            .field("canonical_statement_bytes", &self.canonical_statement.len())
            .field(
                "canonical_approval_set_bytes",
                &self.canonical_approval_set.len(),
            )
            .finish_non_exhaustive()
    }
}

impl GenericSuccessorActivationCandidate {
    pub fn from_bounded_canonical_bytes(
        canonical_statement: Vec<u8>,
        canonical_approval_set: Vec<u8>,
    ) -> Result<Self> {
        for (name, bytes) in [
            (
                "generic successor statement",
                canonical_statement.as_slice(),
            ),
            (
                "generic successor approval set",
                canonical_approval_set.as_slice(),
            ),
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

/// Bounded proof that the audited open head is ready to receive one exact
/// successor generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyGenericSuccessor {
    pub current_generation: u32,
    pub next_generation: u32,
    pub current_head: RegistryHeadBindingV1,
    pub current_activation_policy: RegistryReferenceV1,
}

/// Bounded receipt for one accepted generation `N -> N+1` transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedGenericSuccessorActivation {
    pub statement_id: GenericSuccessorActivationStatementId,
    pub activation_id: GenericSuccessorActivationId,
    pub accepted_event_id: AcceptedEventId,
    pub from_generation: u32,
    pub to_generation: u32,
    pub predecessor_head: RegistryHeadBindingV1,
    pub registry_head: RegistryHeadBindingV1,
    pub append_position: AppendPositionV1,
    pub accepted_at: CanonicalTimestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenericSuccessorActivationInspection {
    Ready(Box<ReadyGenericSuccessor>),
    Accepted(Box<AcceptedGenericSuccessorActivation>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenericSuccessorActivationOutcome {
    Inserted(Box<AcceptedGenericSuccessorActivation>),
    ExactReplay(Box<AcceptedGenericSuccessorActivation>),
}

/// The private repository accepts candidates, then authenticates them against
/// construction-bound authority and the durable open head inside one
/// serializable transaction.
#[async_trait]
pub trait GenericSuccessorRepository: Send + Sync {
    /// Audit the durable open head and atomically install its successor.
    async fn activate_generic_successor(
        &self,
        candidate: &GenericSuccessorActivationCandidate,
    ) -> Result<GenericSuccessorActivationOutcome>;

    /// Report whether `generation` is the next open slot or is already durable.
    ///
    /// `generation` is the *target* generation of the transition being
    /// inspected, so `2` asks about the `1 -> 2` step.
    async fn inspect_generic_successor(
        &self,
        generation: u32,
    ) -> Result<GenericSuccessorActivationInspection>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generic_candidate_debug_redacts_canonical_bytes_and_bounds_both_inputs() {
        let candidate = GenericSuccessorActivationCandidate::from_bounded_canonical_bytes(
            b"generic-statement-secret".to_vec(),
            b"generic-approval-secret".to_vec(),
        )
        .unwrap();
        let debug = format!("{candidate:?}");
        assert!(!debug.contains("generic-statement-secret"));
        assert!(!debug.contains("generic-approval-secret"));
        assert!(
            GenericSuccessorActivationCandidate::from_bounded_canonical_bytes(Vec::new(), vec![1],)
                .is_err()
        );
        assert!(
            GenericSuccessorActivationCandidate::from_bounded_canonical_bytes(
                vec![1],
                vec![0; MAX_CANONICAL_CANDIDATE_BYTES + 1],
            )
            .is_err()
        );
    }
}
