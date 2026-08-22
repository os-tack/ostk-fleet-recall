//! Connectors: the runtimes that turn provider-side material into accepted
//! evidence through the W1-EVID admission seam.
//!
//! A connector in this crate is deliberately *not* an appender. It reads
//! provider truth, parses/redacts/classifies it, canonicalizes the result into
//! [`crate::memory_contracts::evidence_v2::EvidenceIngressCandidateV2`] values,
//! and (where the connector is outbox-backed) stages them durably. Only
//! [`crate::evidence_ledger::admit_evidence`] resolves a connector schema,
//! rederives resource identities, reads governance out of the activated
//! policies, and binds scope to the writer credential, and only an admitted
//! statement reaches
//! [`crate::evidence_ledger::AcceptedEventRepository::append`]. A connector
//! therefore cannot widen what is admissible: the worst a mis-implemented one
//! can do is produce candidates that admission rejects.

pub mod git;
pub mod transcript;
