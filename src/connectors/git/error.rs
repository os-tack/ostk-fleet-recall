//! Closed rejection taxonomies for the git history connector (W2-GIT).
//!
//! Every variant here is a refusal. Nothing in this connector degrades to a
//! weaker fact when an input does not check out: a malformed object, an
//! unreadable ref, a clock that runs backwards, and a locator coordinate the
//! activated recipe does not name are each an error, never a default.

use crate::memory_contracts::ContractError;
use crate::memory_contracts::identity::LocatorEncoding;

/// Result alias for the provider-truth model.
pub type GitFactResult<T> = Result<T, GitFactError>;

/// Why a git provider fact was refused.
#[derive(Debug, thiserror::Error)]
pub enum GitFactError {
    /// A memory contract refused an input or a derived value.
    #[error("git fact contract failure: {0}")]
    Contract(#[from] ContractError),
    /// A value is not a lowercase 40- or 64-character git object id.
    #[error("not a git object id: {0}")]
    ObjectId(String),
    /// A value is not an admissible fully qualified ref name.
    #[error("not an admissible git ref name: {0}")]
    RefName(String),
    /// A tree entry mode names something other than blob content.
    #[error("tree entry mode {0} does not name blob content")]
    FileMode(String),
    /// A structural rule of one fact family was violated.
    #[error("invalid git fact: {0}")]
    Schema(&'static str),
    /// A new ref observation was taken before the previous one.
    #[error("ref observation clock moved backwards")]
    ObservationClockRegression,
}

/// Result alias for the repository scanner.
pub type GitScanResult<T> = Result<T, GitScanError>;

/// Why reading the local object store failed.
#[derive(Debug, thiserror::Error)]
pub enum GitScanError {
    /// A fact the scan produced is not structurally valid.
    #[error("git scan produced an inadmissible fact: {0}")]
    Fact(#[from] GitFactError),
    /// The `git` process could not be started.
    #[error("could not run git: {0}")]
    Spawn(String),
    /// The `git` process exited non-zero.
    #[error("git {command} failed with status {status}: {stderr}")]
    Command {
        /// The plumbing subcommand that failed.
        command: &'static str,
        /// Exit status text.
        status: String,
        /// Bounded standard-error text.
        stderr: String,
    },
    /// `git` produced output this reader cannot parse.
    #[error("git {command} produced unparseable output: {detail}")]
    Output {
        /// The plumbing subcommand whose output was unparseable.
        command: &'static str,
        /// What did not parse.
        detail: &'static str,
    },
    /// A commit records a timestamp outside the representable range.
    #[error("commit timestamp is not representable")]
    Timestamp,
    /// The scan would exceed its configured bound.
    #[error("git scan exceeded its configured bound of {0} facts")]
    ScanTooLarge(usize),
}

/// Result alias for ingress construction.
pub type GitIngressResult<T> = Result<T, GitIngressError>;

/// Why an evidence ingress candidate could not be built.
#[derive(Debug, thiserror::Error)]
pub enum GitIngressError {
    /// A memory contract refused an input or a derived value.
    #[error("git ingress contract failure: {0}")]
    Contract(#[from] ContractError),
    /// A fact this ingress was asked to render is not valid.
    #[error("git ingress fact failure: {0}")]
    Fact(#[from] GitFactError),
    /// An identity recipe the active connector names is not resolvable from the
    /// active package.
    #[error("active package does not resolve the {0} identity recipe")]
    RecipeNotInActivePackage(&'static str),
    /// The activated recipe names a locator coordinate this connector does not
    /// know how to produce. Guessing a value would be exactly the self-asserted
    /// identity admission exists to prevent, so this fails closed.
    #[error(
        "activated identity recipe names locator component {0}, which the git connector cannot supply"
    )]
    UnsupportedLocatorComponent(String),
    /// The activated recipe demands a different wire encoding for a coordinate
    /// this connector does know.
    #[error(
        "activated identity recipe demands {demanded:?} for locator component {key}, not {supplied:?}"
    )]
    LocatorEncodingMismatch {
        /// The coordinate whose encoding disagreed.
        key: String,
        /// What the recipe demands.
        demanded: LocatorEncoding,
        /// What this connector produces for that coordinate.
        supplied: LocatorEncoding,
    },
    /// The three ingress clocks are not ordered `occurred <= observed <=
    /// received`, or one is not microsecond-aligned.
    #[error("git ingress clocks are not ordered: {0}")]
    ClockOrder(&'static str),
}

/// Result alias for the drain.
pub type GitDrainResult<T> = Result<T, GitDrainError>;

/// Why draining a git scan into the evidence ledger failed.
#[derive(Debug, thiserror::Error)]
pub enum GitDrainError {
    /// An ingress candidate could not be built.
    #[error("git drain ingress failure: {0}")]
    Ingress(#[from] GitIngressError),
    /// A fact handed to the drain is not structurally valid.
    #[error("git drain fact failure: {0}")]
    Fact(#[from] GitFactError),
    /// Admission refused the candidate.
    #[error("git drain admission failure: {0}")]
    Admission(#[from] crate::evidence_ledger::EvidenceAdmissionError),
    /// The append transaction refused or failed.
    #[error("git drain append failure: {0}")]
    Append(#[from] crate::evidence_ledger::EvidenceAppendError),
    /// A memory contract refused a derived coverage value.
    #[error("git drain contract failure: {0}")]
    Contract(#[from] ContractError),
    /// No ref observation was drained, so there is no accepted event for a
    /// coverage receipt to bind (COVER-03 rejects a zero evidence id).
    #[error("git drain produced no ref observation to anchor a coverage receipt")]
    NoRefObservation,
    /// The ledger refused this scan's ref observation into quarantine, so no
    /// event row backs the newest view of the ref. A quarantine writes a
    /// dead-letter receipt and NO event, so the accepted-event id the drain
    /// computed names nothing in `memory_evidence_events`; anchoring a coverage
    /// receipt on it -- or falling back to an older observation that survived
    /// -- would claim coverage of a range whose newest evidence the ledger
    /// declined (COVER-03).
    #[error(
        "git drain ref observation was quarantined, so no accepted event backs a coverage receipt"
    )]
    RefObservationQuarantined,
}
