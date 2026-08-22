//! Closed rejection taxonomies for the CI-evidence connector (W3-CIEV).
//!
//! Every variant here is a refusal. Nothing in this connector degrades to a
//! weaker fact when an input does not check out: a run the provider has not
//! settled, a conclusion this connector does not model, provider text that
//! cannot be rendered canonically, a clock that runs backwards, and a locator
//! coordinate the activated recipe does not name are each an error, never a
//! default.

use crate::memory_contracts::ContractError;
use crate::memory_contracts::identity::LocatorEncoding;

/// Result alias for the provider-truth model.
pub type CiFactResult<T> = Result<T, CiFactError>;

/// Why a CI provider fact was refused.
#[derive(Debug, thiserror::Error)]
pub enum CiFactError {
    /// A memory contract refused an input or a derived value.
    #[error("ci fact contract failure: {0}")]
    Contract(#[from] ContractError),
    /// The run has not settled, so it is not an immutable object and has no
    /// Version-form canonical resource. Queued, waiting, requested, pending,
    /// and in-progress runs land here, as does a run cancelled before its work
    /// concluded.
    #[error("ci run {run_number} is not settled: status {status}, conclusion {conclusion}")]
    UnsettledRun {
        /// The provider's run number.
        run_number: u64,
        /// The provider's `status` value, verbatim.
        status: String,
        /// The provider's `conclusion` value, verbatim (empty when absent).
        conclusion: String,
    },
    /// A `status` value this connector does not model.
    #[error("not a workflow-run status this connector models: {0}")]
    Status(String),
    /// A `conclusion` value this connector does not model.
    #[error("not a workflow-run conclusion this connector models: {0}")]
    Conclusion(String),
    /// Provider text could not be rendered as one canonical string.
    #[error("provider text is not renderable as a canonical string: {0}")]
    Text(&'static str),
    /// A value is not a lowercase 40-character commit sha.
    #[error("not a commit sha: {0}")]
    CommitSha(String),
    /// A structural rule of one fact family was violated.
    #[error("invalid ci fact: {0}")]
    Schema(&'static str),
    /// A window observation was taken before the previous one.
    #[error("ci window observation clock moved backwards")]
    ObservationClockRegression,
    /// A run fact was measured against a window that does not contain it, or
    /// that names a different repository, workflow, or branch.
    #[error("ci run {run_number} does not belong to the window under measurement")]
    RunOutsideWindow {
        /// The run number that fell outside.
        run_number: u64,
    },
}

/// Result alias for the provider reader.
pub type CiScanResult<T> = Result<T, CiScanError>;

/// Why reading the CI provider failed.
#[derive(Debug, thiserror::Error)]
pub enum CiScanError {
    /// A fact the scan produced is not structurally valid.
    #[error("ci scan produced an inadmissible fact: {0}")]
    Fact(#[from] CiFactError),
    /// The provider process could not be started.
    #[error("could not run the ci provider command: {0}")]
    Spawn(String),
    /// The provider process exited non-zero.
    #[error("ci provider command {command} failed with status {status}: {stderr}")]
    Command {
        /// The provider subcommand that failed.
        command: &'static str,
        /// Exit status text.
        status: String,
        /// Bounded standard-error text.
        stderr: String,
    },
    /// The provider produced a payload this reader cannot parse.
    #[error("ci provider payload is unparseable: {detail}")]
    Payload {
        /// What did not parse.
        detail: &'static str,
    },
    /// The provider payload omits a field the scan requires.
    #[error("ci provider payload omits the required field {0}")]
    MissingField(&'static str),
    /// A recorded provider payload has no entry for a run the listing names.
    #[error("the recorded provider has no job payload for run {0}")]
    RecordedRunMissing(u64),
    /// The provider handed back a run outside the requested window.
    #[error("ci provider returned run {run_number}, which is outside the requested window")]
    RunOutsideRequest {
        /// The offending run number.
        run_number: u64,
    },
    /// A provider timestamp is outside the representable range.
    #[error("ci provider timestamp {0} is not representable")]
    Timestamp(String),
    /// The scan would exceed its configured bound.
    #[error("ci scan exceeded its configured bound of {0} runs")]
    ScanTooLarge(usize),
    /// The requested window is empty or inverted.
    #[error("ci scan request names an empty window")]
    EmptyWindow,
}

/// Result alias for ingress construction.
pub type CiIngressResult<T> = Result<T, CiIngressError>;

/// Why an evidence ingress candidate could not be built.
#[derive(Debug, thiserror::Error)]
pub enum CiIngressError {
    /// A memory contract refused an input or a derived value.
    #[error("ci ingress contract failure: {0}")]
    Contract(#[from] ContractError),
    /// A fact this ingress was asked to render is not valid — most often an
    /// unsettled run, which has no immutable revision to address.
    #[error("ci ingress fact failure: {0}")]
    Fact(#[from] CiFactError),
    /// An identity recipe the active connector names is not resolvable from the
    /// active package.
    #[error("active package does not resolve the {0} identity recipe")]
    RecipeNotInActivePackage(&'static str),
    /// The activated canonical-resource recipe is not Version-form.
    ///
    /// A CI run that has settled is an immutable object, and the body plane
    /// only chunks a Version-form canonical resource
    /// (`ChunkOccurrencePreimageV1`). Admitting under an occurrence-form recipe
    /// is what left 980 accepted events with 0 bodies and 0 lexical rows before
    /// W3-CHAIN, so this connector refuses to build the candidate at all rather
    /// than mint evidence nothing can retrieve.
    #[error(
        "activated canonical-resource recipe {recipe} is {form:?}-form; the CI connector only \
         admits under a version-form recipe"
    )]
    CanonicalResourceNotVersionForm {
        /// The recipe that was resolved.
        recipe: String,
        /// The identity form it declares.
        form: crate::memory_contracts::identity::IdentityForm,
    },
    /// The activated recipe names a locator coordinate this connector does not
    /// know how to produce. Guessing a value would be exactly the self-asserted
    /// identity admission exists to prevent, so this fails closed.
    #[error(
        "activated identity recipe names locator component {0}, which the ci connector cannot \
         supply"
    )]
    UnsupportedLocatorComponent(String),
    /// The activated recipe demands a different wire encoding for a coordinate
    /// this connector does know.
    #[error(
        "activated identity recipe demands {demanded:?} for locator component {key}, not \
         {supplied:?}"
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
    /// received`, or one is not microsecond-aligned (EVID-03).
    #[error("ci ingress clocks are not ordered: {0}")]
    ClockOrder(&'static str),
}

/// Result alias for the drain.
pub type CiDrainResult<T> = Result<T, CiDrainError>;

/// Why draining a CI scan into the evidence ledger failed.
#[derive(Debug, thiserror::Error)]
pub enum CiDrainError {
    /// An ingress candidate could not be built.
    #[error("ci drain ingress failure: {0}")]
    Ingress(#[from] CiIngressError),
    /// A fact handed to the drain is not structurally valid.
    #[error("ci drain fact failure: {0}")]
    Fact(#[from] CiFactError),
    /// Admission refused the candidate.
    #[error("ci drain admission failure: {0}")]
    Admission(#[from] crate::evidence_ledger::EvidenceAdmissionError),
    /// The append transaction refused or failed.
    #[error("ci drain append failure: {0}")]
    Append(#[from] crate::evidence_ledger::EvidenceAppendError),
    /// A memory contract refused a derived coverage value.
    #[error("ci drain contract failure: {0}")]
    Contract(#[from] ContractError),
    /// The durable window record could not be written or read.
    #[error("ci window store failure: {0}")]
    Storage(#[from] crate::FleetError),
    /// No window observation was drained, so there is no accepted event for a
    /// coverage receipt to bind (COVER-03 rejects a zero evidence id).
    #[error("ci drain produced no window observation to anchor a coverage receipt")]
    NoWindowObservation,
    /// The ledger refused this scan's window observation into quarantine. A
    /// quarantine writes a dead-letter receipt and NO event row, so the
    /// accepted-event id the drain computed names nothing in
    /// `memory_evidence_events`; anchoring a coverage receipt on it — or
    /// falling back to an older window that survived — would claim coverage of
    /// a range whose defining evidence the ledger declined (COVER-03).
    #[error("ci drain window observation was quarantined, so no accepted event backs a receipt")]
    WindowObservationQuarantined,
}
