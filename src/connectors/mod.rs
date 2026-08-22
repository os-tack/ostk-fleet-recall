//! Provider connectors that read a source of record and produce evidence
//! ingress candidates for the W1-EVID admission seam.
//!
//! A connector in this crate is deliberately *not* an appender. It reads
//! provider truth, renders it as canonical bytes, and hands
//! [`crate::memory_contracts::evidence_v2::EvidenceIngressCandidateV2`] values
//! to [`crate::evidence_ledger::admit_evidence`], which is the only place that
//! resolves a connector schema, rederives resource identities, reads governance
//! out of the activated policies, and binds scope to the writer credential. A
//! connector therefore cannot widen what is admissible: the worst a
//! mis-implemented one can do is produce candidates that admission rejects.

pub mod git;
