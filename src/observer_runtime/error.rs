//! Closed refusal taxonomy for the observer runtime (W3-OBSRT).
//!
//! Every variant here is a refusal, never a degraded result. The distinction
//! this module keeps sharp is the one the whole workstream turns on:
//!
//! * An **error** means the run could not honestly happen at all — the source
//!   the caller pinned is not the source the object store has, the admission
//!   is not one an activated registry granted, the enum the predicate is about
//!   is not uniquely locatable. Nothing is written.
//! * A **non-exhaustive enumeration** is not an error. It is a successful run
//!   whose verdict is `indeterminate`, carried through
//!   [`crate::memory_contracts::observer::ObserverRunReceiptV1`]'s unsupported
//!   input tally and coverage witness. It is written, and it says "I do not
//!   know" out loud.
//!
//! Collapsing those two would be the bug: a refused run that silently became
//! "absent", or an unknown that an operator retries until it passes, are the
//! two ways a partial read turns into a false negative.

use crate::memory_contracts::ContractError;
use crate::memory_contracts::digest::Sha256Digest;

/// Result alias for the observer runtime.
pub type ObserverRuntimeResult<T> = Result<T, ObserverRuntimeError>;

/// Why an observer run was refused.
#[derive(Debug, thiserror::Error)]
pub enum ObserverRuntimeError {
    /// A memory contract refused an input or a derived value.
    #[error("observer runtime contract failure: {0}")]
    Contract(#[from] ContractError),

    /// Reading the local git object store failed.
    #[error("observer source read failed: {0}")]
    Scan(#[from] crate::connectors::git::GitScanError),

    /// A git provider fact the runtime rendered is inadmissible.
    #[error("observer source fact is inadmissible: {0}")]
    Fact(#[from] crate::connectors::git::GitFactError),

    /// Building the evidence ingress candidate failed.
    #[error("observer ingress failed: {0}")]
    Ingress(#[from] crate::connectors::git::GitIngressError),

    /// The W1-EVID admission seam refused the candidate.
    #[error("observer result admission failed: {0}")]
    Admission(#[from] crate::evidence_ledger::EvidenceAdmissionError),

    /// The accepted-event append failed, or the governed run record could not
    /// be sealed for the same transaction.
    #[error("observer result append failed: {0}")]
    Append(#[from] crate::evidence_ledger::EvidenceAppendError),

    /// The genesis registry package supplied is not the one the
    /// deployment-pinned bootstrap receipt names.
    ///
    /// This is the anchor for the whole admission chain: without it a caller
    /// could hand the runtime any package it liked and have its own observer
    /// "admitted" by it (AUTH-03, AUTH-04).
    #[error("supplied registry package is not the pinned genesis registry package")]
    RegistryPackageNotPinned,

    /// No activated registry entry admits an observer under this id and
    /// version, or more than one does.
    #[error("no unique activated observer admission for {observer_id} v{version}")]
    ObserverNotAdmitted {
        /// The admission id the runtime was configured with.
        observer_id: String,
        /// The admission version the runtime was configured with.
        version: u32,
    },

    /// The runtime's declared admission disagrees with the activated entry on
    /// a field governance actually decided.
    #[error("declared observer admission disagrees with the activated entry on {0}")]
    AdmissionDisagreement(&'static str),

    /// The commit and path resolve to a different blob than the caller pinned.
    ///
    /// The adversarial case: the same claimed commit, a different blob.
    #[error("commit resolves the path to blob {found}, but {expected} was pinned")]
    BlobIdMismatch {
        /// The blob the pin named.
        expected: String,
        /// The blob the object store actually has at that commit and path.
        found: String,
    },

    /// The bytes read back do not hash to the object id they were read under.
    #[error("blob {blob_id} does not hash to the bytes the object store returned")]
    BlobObjectIntegrity {
        /// The object id that was asked for.
        blob_id: String,
    },

    /// The bytes read back do not reproduce the pinned content digest.
    #[error("observed source content digest {found} does not match the pinned {expected}")]
    ContentDigestMismatch {
        /// The digest the pin named.
        expected: Sha256Digest,
        /// The digest the bytes actually produce.
        found: Sha256Digest,
    },

    /// The source blob is not valid UTF-8, so no Rust item can be located in
    /// it. Refused rather than lossily decoded: a replacement character in the
    /// middle of an identifier would silently rename a variant.
    #[error("observed source blob is not UTF-8")]
    SourceNotUtf8,

    /// The blob is larger than the runtime's configured bound.
    #[error("observed source blob is {actual} bytes, over the {bound}-byte bound")]
    SourceTooLarge {
        /// Actual blob size.
        actual: usize,
        /// The configured bound.
        bound: usize,
    },

    /// The enum the predicate is about does not occur exactly once at module
    /// level in the observed blob.
    ///
    /// Zero occurrences and two occurrences are the same refusal on purpose:
    /// "I could not find it" must never become "it is not there", and "I found
    /// two" must never become "I picked one".
    #[error("enum {name} does not occur exactly once at module level ({found} found)")]
    EnumNotUnique {
        /// The enum the predicate names.
        name: String,
        /// How many module-level declarations were found.
        found: usize,
    },

    /// The enum body is not terminated inside the observed blob.
    #[error("enum {0} body is not terminated")]
    EnumBodyUnterminated(String),

    /// The enum declares the same variant name twice.
    #[error("enum {enum_name} declares variant {member} more than once")]
    DuplicateMember {
        /// The enum.
        enum_name: String,
        /// The repeated variant.
        member: String,
    },

    /// The member bound a caller configured is not usable.
    #[error("observer enumeration member bound is invalid")]
    InvalidMemberBound,

    /// The active package's remember admission rule would let a run flip the
    /// remember basis to `registered_observer`.
    ///
    /// The basis may move only through a package change (an activation). A run
    /// that could move it is refused before it writes anything.
    #[error(
        "active package enables registered-observer remember appends, so a run could change the \
         remember basis"
    )]
    RunWouldChangeRememberBasis,

    /// The active head moved while the run was in flight.
    #[error("the active registry head changed during the run")]
    ActiveHeadMoved,
}
