//! Provider-truth model for the CI-evidence connector (W3-CIEV).
//!
//! # Why the text here is canonical strings, not `HexBytes`
//!
//! The git connector carries every provider byte string as
//! [`crate::memory_contracts::common::HexBytes`], because a git object field is
//! an undeclared byte string that may legitimately contain newlines. That is
//! right for git and wrong here. A CI provider hands back *JSON*, so every
//! string it gives is already Unicode text with a declared encoding, and the
//! consequence of hexing it is severe: a body reading `{"name":"<hex>"}` is not
//! word-searchable, so "which job failed?" cannot be answered from the lexical
//! tier at all.
//!
//! So a workflow name, a job name, a step name, a conclusion label, a head
//! branch, and a commit subject are each carried as a [`CiTextV1`] — one
//! canonical NFC string with exactly one admissible spelling. Provider text
//! that the canonical-JSON profile would refuse (a control scalar, a
//! noncharacter, a private-use scalar) is *rendered*, not rejected and not
//! smuggled: [`CiTextV1::render`] folds each such scalar to a space and
//! collapses the run. That is lossy, and it is recorded as lossy — the value is
//! a rendering of provider text, never a claim to be the provider's exact
//! bytes. Nothing about a run's *identity* depends on it: identity closes over
//! the run id, the attempt, the conclusion label, and the settle instant, all
//! of which are already canonical.
//!
//! # Settled or refused: there is no third state
//!
//! A workflow run becomes an immutable object exactly when the provider settles
//! it. Before that its conclusion is `null`, its jobs are still moving, and its
//! `updated_at` advances on every heartbeat — there is no revision to address.
//! [`CiWorkflowRunFactV1::validate`] therefore refuses any run whose status is
//! not `completed` or whose conclusion is not settled, with
//! [`CiFactError::UnsettledRun`], and it does so *before* any identity is
//! derived. A cancelled run is refused for the same reason and not as an
//! oversight: cancellation interrupts the work, so the run reports no settled
//! outcome for what the code did, and the provider can re-run it under the same
//! run id.
//!
//! A re-run is not a rewrite. It mints a new *attempt*, and
//! [`CiFactV1::immutable_revision`] closes over the attempt number, the
//! conclusion label, and the settle instant, so the second attempt is a new
//! immutable revision of the same provider object rather than a mutation of the
//! first (EVENT-01).
//!
//! # A window is a fact, and it is the only thing that bounds an absence
//!
//! This connector reads a FINITE range of run numbers on one workflow and one
//! branch. That range is itself evidence: [`CiWindowObservationFactV1`] is an
//! append-only observation of "these runs, on this workflow and branch, read at
//! this instant", and it is what a coverage receipt binds. Because the window
//! is durable and addressable, a reader can state exactly what was measured —
//! and [`answer_first_failure`] refuses to answer a question whose subject lies
//! outside it. Absence of a failure inside a window is never evidence of
//! absence outside it (COVER-01..03).

use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error as _};
use unicode_normalization::UnicodeNormalization as _;

use crate::memory_contracts::canonical::encode_canonical;
use crate::memory_contracts::common::{CanonicalDecimal, CanonicalTimestamp, ContractId, HexBytes};
use crate::memory_contracts::digest::{DigestDomain, framed_digest};

use super::error::{CiFactError, CiFactResult};

/// Schema version every fact in this module carries.
pub const CI_FACT_SCHEMA_VERSION: u32 = 1;
/// Largest rendered provider string this connector stores, in bytes.
pub const MAX_CI_TEXT_BYTES: usize = 4_096;
/// Largest job count on one workflow-run fact.
pub const MAX_CI_JOBS: usize = 64;
/// Largest step count on one job.
pub const MAX_CI_STEPS: usize = 256;
/// Largest failure-annotation count on one job.
pub const MAX_CI_ANNOTATIONS: usize = 32;
/// Largest run count one window may name.
pub const MAX_CI_WINDOW_RUNS: usize = 512;
/// Largest window observation sequence, inside the canonical-JSON safe integer
/// range so the number survives the profile unchanged.
pub const MAX_CI_OBSERVATION_SEQ: u64 = (1_u64 << 53) - 1;

/// One rendered provider string.
///
/// The canonical form is: NFC, no scalar the canonical-JSON profile forbids, no
/// leading or trailing space, no doubled space, non-empty, and at most
/// [`MAX_CI_TEXT_BYTES`] bytes. There is exactly one admissible spelling per
/// value, so two renderings of the same provider text are byte-identical and a
/// re-scan replays rather than colliding.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CiTextV1(String);

/// Scalars the canonical-JSON profile refuses inside a string.
///
/// Mirrors `canonical::is_forbidden_scalar`, which is private to that module.
/// Kept conservative on purpose: a scalar this predicate wrongly calls
/// forbidden is folded to a space, which is lossy but admissible, while one it
/// wrongly admits would make `encode_canonical` refuse the whole fact.
fn is_forbidden_scalar(value: char) -> bool {
    let code = u32::from(value);
    value.is_control()
        || (0xfdd0..=0xfdef).contains(&code)
        || code & 0xffff >= 0xfffe
        || (0xe000..=0xf8ff).contains(&code)
        || (0xf0000..=0xffffd).contains(&code)
        || (0x0010_0000..=0x0010_fffd).contains(&code)
}

impl CiTextV1 {
    /// Render arbitrary provider text into the one canonical spelling.
    ///
    /// Lossy where it must be: a scalar the canonical profile forbids becomes a
    /// space, and a run of whitespace collapses to one. Provider text that
    /// renders to nothing is refused rather than stored as an empty string,
    /// because an empty name is not a name.
    pub fn render(value: &str) -> CiFactResult<Self> {
        let folded: String = value
            .nfc()
            .map(|scalar| {
                if scalar.is_whitespace() || is_forbidden_scalar(scalar) {
                    ' '
                } else {
                    scalar
                }
            })
            .collect();
        let rendered = folded.split_whitespace().collect::<Vec<_>>().join(" ");
        if rendered.is_empty() {
            return Err(CiFactError::Text("provider text renders to nothing"));
        }
        if rendered.len() > MAX_CI_TEXT_BYTES {
            return Err(CiFactError::Text("provider text exceeds the render bound"));
        }
        Ok(Self(rendered))
    }

    /// Accept a value that is already in canonical form.
    ///
    /// Deliberately strict rather than re-rendering: the wire form of a stored
    /// fact must have exactly one spelling, so a value that would *become*
    /// canonical under [`Self::render`] is still refused here.
    pub fn parse(value: &str) -> CiFactResult<Self> {
        let rendered = Self::render(value)?;
        if rendered.0 != value {
            return Err(CiFactError::Text("provider text is not in canonical form"));
        }
        Ok(rendered)
    }

    /// The exact stored text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for CiTextV1 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CiTextV1 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(D::Error::custom)
    }
}

/// A 40-character lowercase commit sha, stored as the plain text a reader
/// searches for.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CiCommitShaV1(String);

impl CiCommitShaV1 {
    /// Accept one lowercase 40-character hex sha.
    pub fn parse(value: &str) -> CiFactResult<Self> {
        let shaped = value.len() == 40
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if !shaped {
            return Err(CiFactError::CommitSha(value.to_owned()));
        }
        Ok(Self(value.to_owned()))
    }

    /// The exact sha text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for CiCommitShaV1 {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CiCommitShaV1 {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value).map_err(D::Error::custom)
    }
}

/// Deployment identity of one scanned repository's CI.
///
/// `installation_id` is the provider-instance coordinate the activated identity
/// recipe hashes; it is operator configuration, never a payload field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CiRepositoryIdV1 {
    /// Schema version, always [`CI_FACT_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Stable operator-declared identifier of the repository.
    pub repository_id: ContractId,
    /// Provider-instance installation coordinate, as a canonical decimal.
    pub installation_id: CanonicalDecimal,
}

impl CiRepositoryIdV1 {
    /// Build one repository identity from trusted deployment configuration.
    pub fn from_trusted_config(
        repository_id: ContractId,
        installation_id: u64,
    ) -> CiFactResult<Self> {
        Ok(Self {
            schema_version: CI_FACT_SCHEMA_VERSION,
            repository_id,
            installation_id: CanonicalDecimal::parse(installation_id.to_string())?,
        })
    }

    /// Reject anything that is not this exact schema version, or an
    /// installation coordinate that is not a `u64`.
    pub fn validate(&self) -> CiFactResult<()> {
        if self.schema_version != CI_FACT_SCHEMA_VERSION
            || self.installation_id.as_str().parse::<u64>().is_err()
        {
            return Err(CiFactError::Schema("invalid ci repository identity"));
        }
        Ok(())
    }
}

/// Lifecycle state the provider reports for a run, job, or step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CiRunStatusV1 {
    /// Accepted, not yet scheduled.
    Queued,
    /// Waiting on a deployment gate or a concurrency group.
    Waiting,
    /// Requested but not yet accepted by a runner.
    Requested,
    /// Accepted and pending.
    Pending,
    /// Running now.
    InProgress,
    /// Finished. The only status under which a run may be admitted.
    Completed,
}

impl CiRunStatusV1 {
    /// Parse one provider `status` value.
    pub fn parse(value: &str) -> CiFactResult<Self> {
        match value {
            "queued" => Ok(Self::Queued),
            "waiting" => Ok(Self::Waiting),
            "requested" => Ok(Self::Requested),
            "pending" => Ok(Self::Pending),
            "in_progress" => Ok(Self::InProgress),
            "completed" => Ok(Self::Completed),
            other => Err(CiFactError::Status(other.to_owned())),
        }
    }

    /// Stable label used inside identity preimages and rendered bodies.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Waiting => "waiting",
            Self::Requested => "requested",
            Self::Pending => "pending",
            Self::InProgress => "in_progress",
            Self::Completed => "completed",
        }
    }
}

/// Outcome label the provider reports once a run, job, or step finishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CiOutcomeV1 {
    /// Everything the unit ran passed.
    Success,
    /// The unit ran and failed.
    Failure,
    /// The unit was cancelled before its work concluded.
    Cancelled,
    /// The unit exceeded its time budget.
    TimedOut,
    /// The unit halted awaiting a human decision.
    ActionRequired,
    /// The unit finished without asserting pass or fail.
    Neutral,
    /// The unit did not run because its condition was false.
    Skipped,
    /// The workflow file itself could not start.
    StartupFailure,
}

impl CiOutcomeV1 {
    /// Parse one provider `conclusion` value.
    ///
    /// The provider spells an absent conclusion as the empty string, which is
    /// refused here rather than mapped onto a neutral outcome: "the run has not
    /// concluded" and "the run concluded neutrally" are different facts.
    pub fn parse(value: &str) -> CiFactResult<Self> {
        match value {
            "success" => Ok(Self::Success),
            "failure" => Ok(Self::Failure),
            "cancelled" => Ok(Self::Cancelled),
            "timed_out" => Ok(Self::TimedOut),
            "action_required" => Ok(Self::ActionRequired),
            "neutral" => Ok(Self::Neutral),
            "skipped" => Ok(Self::Skipped),
            "startup_failure" => Ok(Self::StartupFailure),
            other => Err(CiFactError::Conclusion(other.to_owned())),
        }
    }

    /// Stable label used inside identity preimages and rendered bodies.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
            Self::ActionRequired => "action_required",
            Self::Neutral => "neutral",
            Self::Skipped => "skipped",
            Self::StartupFailure => "startup_failure",
        }
    }

    /// Whether this outcome settles a RUN into an immutable object.
    ///
    /// Every outcome except cancellation does. A cancelled run's work was
    /// interrupted, so it reports no settled outcome about the code, and the
    /// provider may re-run it under the same run id — exactly the mutability
    /// that a Version-form canonical resource must not have.
    #[must_use]
    pub const fn settles_a_run(self) -> bool {
        !matches!(self, Self::Cancelled)
    }

    /// Whether this outcome is a CI failure for the purposes of
    /// [`answer_first_failure`].
    ///
    /// `neutral` and `skipped` are not failures, and `cancelled` is not one
    /// either — it is an absence of an outcome, and a run carrying it never
    /// reaches this connector's ledger in the first place.
    #[must_use]
    pub const fn is_failure(self) -> bool {
        matches!(
            self,
            Self::Failure | Self::TimedOut | Self::ActionRequired | Self::StartupFailure
        )
    }
}

/// One step inside one job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CiStepV1 {
    /// Provider-assigned step number inside its job.
    pub number: u32,
    /// Rendered step name — the words a reader searches for.
    pub name: CiTextV1,
    /// Lifecycle state the provider reported.
    pub status: CiRunStatusV1,
    /// Outcome the provider reported.
    pub conclusion: CiOutcomeV1,
}

/// One job inside one workflow run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CiJobV1 {
    /// Provider-assigned job id, as a canonical decimal.
    pub job_id: CanonicalDecimal,
    /// Rendered job name — the words a reader searches for.
    pub name: CiTextV1,
    /// Lifecycle state the provider reported.
    pub status: CiRunStatusV1,
    /// Outcome the provider reported.
    pub conclusion: CiOutcomeV1,
    /// When the job started.
    pub started_at: CanonicalTimestamp,
    /// When the job finished.
    pub completed_at: CanonicalTimestamp,
    /// Steps, in the provider's own order.
    pub steps: Vec<CiStepV1>,
    /// Rendered failure-annotation text the provider attached to this job.
    pub failure_annotations: Vec<CiTextV1>,
}

impl CiJobV1 {
    fn validate(&self) -> CiFactResult<()> {
        let steps_ordered = self
            .steps
            .windows(2)
            .all(|pair| pair[0].number < pair[1].number);
        if self.job_id.as_str().parse::<u64>().is_err()
            || self.steps.len() > MAX_CI_STEPS
            || !steps_ordered
            || self.failure_annotations.len() > MAX_CI_ANNOTATIONS
            || !self.started_at.is_microsecond_aligned()
            || !self.completed_at.is_microsecond_aligned()
            || self.completed_at < self.started_at
        {
            return Err(CiFactError::Schema("invalid ci job"));
        }
        Ok(())
    }

    /// Whether this job reports a CI failure.
    #[must_use]
    pub const fn failed(&self) -> bool {
        self.conclusion.is_failure()
    }
}

/// The finite range of runs one scan actually read.
///
/// This is the whole of what the connector may claim to have measured. It names
/// one repository, one workflow, one branch, an inclusive run-number range, and
/// the instant the range was read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CiCoverageWindowV1 {
    /// Schema version, always [`CI_FACT_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Repository whose CI was read.
    pub repository: CiRepositoryIdV1,
    /// Rendered workflow identifier (the workflow file or its name).
    pub workflow: CiTextV1,
    /// Rendered branch the runs were filtered to.
    pub branch: CiTextV1,
    /// First run number read, inclusive.
    pub first_run_number: u64,
    /// Last run number read, inclusive.
    pub last_run_number: u64,
    /// When the range was read from the provider.
    pub fetched_at: CanonicalTimestamp,
}

fn max_window_runs() -> u64 {
    u64::try_from(MAX_CI_WINDOW_RUNS).unwrap_or(u64::MAX)
}

impl CiCoverageWindowV1 {
    /// Reject an empty, inverted, or zero-based window.
    ///
    /// Provider run numbers start at one, so `first_run_number == 0` would name
    /// a run that cannot exist and would silently widen every containment
    /// answer below it.
    pub fn validate(&self) -> CiFactResult<()> {
        self.repository.validate()?;
        let span = self
            .last_run_number
            .checked_sub(self.first_run_number)
            .and_then(|span| span.checked_add(1));
        if self.schema_version != CI_FACT_SCHEMA_VERSION
            || self.first_run_number == 0
            || self.last_run_number < self.first_run_number
            || !self.fetched_at.is_microsecond_aligned()
            || span.is_none_or(|span| span > max_window_runs())
        {
            return Err(CiFactError::Schema("invalid ci coverage window"));
        }
        Ok(())
    }

    /// Whether this window measured `run_number`.
    #[must_use]
    pub const fn covers(&self, run_number: u64) -> bool {
        self.first_run_number <= run_number && run_number <= self.last_run_number
    }

    /// Whether this window measured the whole inclusive range `[first, last]`.
    ///
    /// The containment is total on purpose. A question whose range only
    /// *overlaps* the window is a question this connector cannot answer, and
    /// answering the overlap while staying silent about the remainder is the
    /// false-completeness COVER-01..03 forbid.
    #[must_use]
    pub const fn covers_range(&self, first: u64, last: u64) -> bool {
        first <= last && self.first_run_number <= first && last <= self.last_run_number
    }

    /// Whether this window is left-closed at the workflow's own origin.
    ///
    /// Only a window starting at run number one can support "the first failure
    /// ever"; any other window can support at most "the first failure inside
    /// this range".
    #[must_use]
    pub const fn starts_at_origin(&self) -> bool {
        self.first_run_number == 1
    }

    /// Whether `run` belongs to this window's repository, workflow, and branch.
    fn admits(&self, run: &CiWorkflowRunFactV1) -> bool {
        let same_domain = self.repository == run.repository && self.workflow == run.workflow;
        let same_branch = self.branch == run.head_branch;
        same_domain && same_branch && self.covers(run.run_number)
    }

    /// Content-addressed identity of this exact window.
    pub fn window_id(&self) -> CiFactResult<crate::memory_contracts::digest::Sha256Digest> {
        self.validate()?;
        Ok(framed_digest(
            DigestDomain::CiCoverageWindowV1,
            &[
                self.repository.repository_id.as_str().as_bytes(),
                self.workflow.as_str().as_bytes(),
                self.branch.as_str().as_bytes(),
                &self.first_run_number.to_be_bytes(),
                &self.last_run_number.to_be_bytes(),
                self.fetched_at.as_str().as_bytes(),
            ],
        ))
    }
}

/// One settled workflow run, as the provider reported it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CiWorkflowRunFactV1 {
    /// Schema version, always [`CI_FACT_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Repository the run belongs to.
    pub repository: CiRepositoryIdV1,
    /// Provider-assigned run id, as a canonical decimal.
    pub run_id: CanonicalDecimal,
    /// Provider-assigned run number inside its workflow.
    pub run_number: u64,
    /// Attempt number. A re-run mints a new attempt and therefore a new
    /// immutable revision of the same run.
    pub run_attempt: u32,
    /// Rendered workflow identifier.
    pub workflow: CiTextV1,
    /// Rendered triggering event.
    pub event: CiTextV1,
    /// Rendered head branch.
    pub head_branch: CiTextV1,
    /// Head commit the run built.
    pub head_sha: CiCommitShaV1,
    /// Rendered commit subject the provider displayed for this run.
    pub display_title: CiTextV1,
    /// Lifecycle state. Must be [`CiRunStatusV1::Completed`].
    pub status: CiRunStatusV1,
    /// Settled outcome. Must satisfy [`CiOutcomeV1::settles_a_run`].
    pub conclusion: CiOutcomeV1,
    /// When the run started.
    pub run_started_at: CanonicalTimestamp,
    /// When the run settled — the instant the outcome became a fact.
    pub settled_at: CanonicalTimestamp,
    /// Jobs, in the provider's own order.
    pub jobs: Vec<CiJobV1>,
}

impl CiWorkflowRunFactV1 {
    /// Reject a structurally invalid or unsettled run before any identity is
    /// derived.
    pub fn validate(&self) -> CiFactResult<()> {
        self.repository.validate()?;
        if self.status != CiRunStatusV1::Completed || !self.conclusion.settles_a_run() {
            return Err(CiFactError::UnsettledRun {
                run_number: self.run_number,
                status: self.status.as_str().to_owned(),
                conclusion: self.conclusion.as_str().to_owned(),
            });
        }
        if self.schema_version != CI_FACT_SCHEMA_VERSION
            || self.run_number == 0
            || self.run_attempt == 0
            || self.run_id.as_str().parse::<u64>().is_err()
            || self.jobs.len() > MAX_CI_JOBS
            || !self.run_started_at.is_microsecond_aligned()
            || !self.settled_at.is_microsecond_aligned()
            || self.settled_at < self.run_started_at
        {
            return Err(CiFactError::Schema("invalid ci workflow run fact"));
        }
        for job in &self.jobs {
            job.validate()?;
        }
        Ok(())
    }

    /// Whether this run reports a CI failure.
    #[must_use]
    pub const fn failed(&self) -> bool {
        self.conclusion.is_failure()
    }

    /// The jobs that failed, in provider order.
    pub fn failed_jobs(&self) -> impl Iterator<Item = &CiJobV1> {
        self.jobs.iter().filter(|job| job.failed())
    }
}

/// An inclusive range of provider run numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CiRunRangeV1 {
    /// First run number, inclusive.
    pub first_run_number: u64,
    /// Last run number, inclusive.
    pub last_run_number: u64,
}

/// One observation of the finite window a scan read.
///
/// Append-only, exactly like the git connector's ref observation: a second scan
/// over a different range mints a NEW observation naming the previous range,
/// and every earlier observation keeps its bytes and its identity. The
/// observation sequence and instant are inside the observation's immutable
/// revision, so two observations of the same range at different instants are
/// still distinct source facts (EVENT-01).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CiWindowObservationFactV1 {
    /// Schema version, always [`CI_FACT_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// The window this observation measured.
    pub window: CiCoverageWindowV1,
    /// Strictly increasing observation counter for this coverage domain.
    pub observation_seq: u64,
    /// Number of settled runs the scan admitted inside the window.
    pub admitted_run_count: u32,
    /// Number of runs inside the window that reported a failure.
    pub failed_run_count: u32,
    /// Range of the immediately preceding observation, if any.
    pub previous_range: Option<CiRunRangeV1>,
    /// Identity of the connector instance that took the reading.
    pub observer: ContractId,
}

impl CiWindowObservationFactV1 {
    fn validate(&self) -> CiFactResult<()> {
        self.window.validate()?;
        if self.schema_version != CI_FACT_SCHEMA_VERSION
            || self.observation_seq == 0
            || self.observation_seq > MAX_CI_OBSERVATION_SEQ
            || self.failed_run_count > self.admitted_run_count
            || self.previous_range.as_ref().is_some_and(|range| {
                range.first_run_number == 0 || range.last_run_number < range.first_run_number
            })
        {
            return Err(CiFactError::Schema("invalid ci window observation fact"));
        }
        Ok(())
    }
}

/// Which of the two CI fact families a value is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CiFactKindV1 {
    /// One settled workflow run.
    WorkflowRun,
    /// One observation of the window a scan read.
    WindowObservation,
}

impl CiFactKindV1 {
    /// Stable label used inside identity preimages.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::WorkflowRun => "workflow_run",
            Self::WindowObservation => "window_observation",
        }
    }
}

/// One provider fact this connector renders.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CiFactV1 {
    /// One settled workflow run.
    WorkflowRun(CiWorkflowRunFactV1),
    /// One observation of the window a scan read.
    WindowObservation(CiWindowObservationFactV1),
}

impl CiFactV1 {
    /// Which family this fact belongs to.
    #[must_use]
    pub const fn kind(&self) -> CiFactKindV1 {
        match self {
            Self::WorkflowRun(_) => CiFactKindV1::WorkflowRun,
            Self::WindowObservation(_) => CiFactKindV1::WindowObservation,
        }
    }

    /// Repository the fact was read from.
    #[must_use]
    pub const fn repository(&self) -> &CiRepositoryIdV1 {
        match self {
            Self::WorkflowRun(fact) => &fact.repository,
            Self::WindowObservation(fact) => &fact.window.repository,
        }
    }

    /// Reject a structurally invalid or unsettled fact before any identity is
    /// derived.
    pub fn validate(&self) -> CiFactResult<()> {
        match self {
            Self::WorkflowRun(fact) => fact.validate(),
            Self::WindowObservation(fact) => fact.validate(),
        }
    }

    /// The clock at which the underlying provider fact occurred.
    ///
    /// For a run it is the instant the provider settled the outcome — the
    /// moment the failure became a fact — not the instant the run was queued.
    /// For a window observation it is the instant the range was read.
    #[must_use]
    pub const fn occurred_at(&self) -> &CanonicalTimestamp {
        match self {
            Self::WorkflowRun(fact) => &fact.settled_at,
            Self::WindowObservation(fact) => &fact.window.fetched_at,
        }
    }

    /// Stable identity of the provider object this fact is about.
    ///
    /// A run's object is the run, not the attempt: two attempts are two
    /// revisions of one object. A window observation's object is the coverage
    /// domain — repository, workflow, branch — so every observation of that
    /// domain shares an object while differing in revision.
    pub fn provider_object_id(&self) -> CiFactResult<HexBytes> {
        let digest = match self {
            Self::WorkflowRun(fact) => framed_digest(
                DigestDomain::CiProviderFactV1,
                &[
                    b"workflow_run",
                    fact.repository.repository_id.as_str().as_bytes(),
                    fact.workflow.as_str().as_bytes(),
                    fact.run_id.as_str().as_bytes(),
                ],
            ),
            Self::WindowObservation(fact) => framed_digest(
                DigestDomain::CiProviderFactV1,
                &[
                    b"coverage_domain",
                    fact.window.repository.repository_id.as_str().as_bytes(),
                    fact.window.workflow.as_str().as_bytes(),
                    fact.window.branch.as_str().as_bytes(),
                ],
            ),
        };
        Ok(HexBytes::new(digest.as_bytes().to_vec())?)
    }

    /// The immutable revision of this fact.
    ///
    /// For a run it closes over the attempt, the settled conclusion, and the
    /// settle instant, so a re-run under the same run id is a NEW revision
    /// rather than a rewrite of the old one. For a window observation it is the
    /// observation itself — range, sequence, and instant.
    pub fn immutable_revision(&self) -> CiFactResult<HexBytes> {
        let digest = match self {
            Self::WorkflowRun(fact) => framed_digest(
                DigestDomain::CiProviderFactV1,
                &[
                    b"workflow_run_attempt",
                    fact.repository.repository_id.as_str().as_bytes(),
                    fact.run_id.as_str().as_bytes(),
                    &fact.run_attempt.to_be_bytes(),
                    fact.conclusion.as_str().as_bytes(),
                    fact.settled_at.as_str().as_bytes(),
                ],
            ),
            Self::WindowObservation(fact) => framed_digest(
                DigestDomain::CiProviderFactV1,
                &[
                    b"window_observation",
                    fact.window.repository.repository_id.as_str().as_bytes(),
                    fact.window.workflow.as_str().as_bytes(),
                    fact.window.branch.as_str().as_bytes(),
                    &fact.window.first_run_number.to_be_bytes(),
                    &fact.window.last_run_number.to_be_bytes(),
                    &fact.observation_seq.to_be_bytes(),
                    fact.window.fetched_at.as_str().as_bytes(),
                ],
            ),
        };
        Ok(HexBytes::new(digest.as_bytes().to_vec())?)
    }

    /// Connector-local event key: the fact family plus both identities.
    pub fn logical_event_key(&self) -> CiFactResult<HexBytes> {
        let object = self.provider_object_id()?;
        let revision = self.immutable_revision()?;
        let digest = framed_digest(
            DigestDomain::CiProviderFactV1,
            &[
                b"logical_event_key",
                self.kind().as_str().as_bytes(),
                self.repository().repository_id.as_str().as_bytes(),
                object.as_bytes(),
                revision.as_bytes(),
            ],
        );
        Ok(HexBytes::new(digest.as_bytes().to_vec())?)
    }

    /// The exact canonical bytes admission will hash and govern.
    pub fn canonical_payload(&self) -> CiFactResult<Vec<u8>> {
        self.validate()?;
        Ok(encode_canonical(self)?)
    }
}

/// Append-only observation log for one CI coverage domain.
///
/// The log is the only way this connector mints a window observation, and it
/// can only append: [`Self::observe`] hands back a reference into the log and
/// [`Self::observations`] is a read-only slice, so no earlier observation can
/// be edited through this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiWindowObservationLogV1 {
    observer: ContractId,
    observations: Vec<CiWindowObservationFactV1>,
}

impl CiWindowObservationLogV1 {
    /// Open an empty log for one connector instance.
    #[must_use]
    pub const fn new(observer: ContractId) -> Self {
        Self {
            observer,
            observations: Vec::new(),
        }
    }

    /// Record one new window observation.
    ///
    /// Fails closed when the observation clock moves backwards: a reading taken
    /// before the previous one cannot be the newer view of what was measured,
    /// and accepting it would let a stale scan narrow the recorded coverage.
    pub fn observe(
        &mut self,
        window: CiCoverageWindowV1,
        admitted_run_count: u32,
        failed_run_count: u32,
        max_observations: usize,
    ) -> CiFactResult<&CiWindowObservationFactV1> {
        window.validate()?;
        if self
            .observations
            .last()
            .is_some_and(|previous| window.fetched_at < previous.window.fetched_at)
        {
            return Err(CiFactError::ObservationClockRegression);
        }
        if self.observations.len() >= max_observations {
            return Err(CiFactError::Schema("ci window observation log is full"));
        }
        let observation_seq = u64::try_from(self.observations.len())
            .map_err(|_| CiFactError::Schema("ci window observation log is full"))?
            + 1;
        let fact = CiWindowObservationFactV1 {
            schema_version: CI_FACT_SCHEMA_VERSION,
            window,
            observation_seq,
            admitted_run_count,
            failed_run_count,
            previous_range: self.observations.last().map(|last| CiRunRangeV1 {
                first_run_number: last.window.first_run_number,
                last_run_number: last.window.last_run_number,
            }),
            observer: self.observer.clone(),
        };
        fact.validate()?;
        self.observations.push(fact);
        self.observations
            .last()
            .ok_or(CiFactError::Schema("ci window observation log is empty"))
    }

    /// Every observation, oldest first. Read-only by construction.
    #[must_use]
    pub fn observations(&self) -> &[CiWindowObservationFactV1] {
        &self.observations
    }

    /// The newest observation, or `None` before any window was read.
    #[must_use]
    pub fn view(&self) -> Option<&CiWindowObservationFactV1> {
        self.observations.last()
    }
}

/// The run range a question is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CiFailureQuestionV1 {
    /// First run number the question covers, inclusive.
    pub first_run_number: u64,
    /// Last run number the question covers, inclusive.
    pub last_run_number: u64,
}

impl CiFailureQuestionV1 {
    /// "When did CI first fail, ever?" — the question that motivated this
    /// connector. It reaches back to run number one, so only a window that is
    /// left-closed at the origin can answer it.
    #[must_use]
    pub const fn since_the_beginning(last_run_number: u64) -> Self {
        Self {
            first_run_number: 1,
            last_run_number,
        }
    }
}

/// Why a CI question could not be answered from what was measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CiUnknownReasonV1 {
    /// The question reaches below the window's first run.
    QuestionStartsBeforeWindow,
    /// The question reaches above the window's last run.
    QuestionEndsAfterWindow,
    /// The question's own range is empty or inverted.
    QuestionRangeIsEmpty,
}

/// What this memory can honestly say about "when did CI first fail?".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CiFirstFailureAnswerV1 {
    /// A failing run was found, and the whole question range was measured.
    FirstFailure {
        /// The failing run's number.
        run_number: u64,
        /// The instant the provider settled the failure.
        occurred_at: CanonicalTimestamp,
        /// The settled conclusion label.
        conclusion: CiOutcomeV1,
        /// The window the answer was measured against.
        window: CiCoverageWindowV1,
    },
    /// Every run in the question range was measured, and none failed. This is a
    /// verified negative, and it is only reachable when the window contains the
    /// whole question.
    NoFailureInWindow {
        /// The window the answer was measured against.
        window: CiCoverageWindowV1,
    },
    /// The question's subject is not inside what was measured.
    ///
    /// This is NOT "no failure occurred". Absence of a failure inside a bounded
    /// window is not evidence of absence outside it (COVER-01..03).
    Unknown {
        /// The window that WAS measured, so a reader can state the bound.
        window: CiCoverageWindowV1,
        /// Why the question fell outside it.
        reason: CiUnknownReasonV1,
    },
}

impl CiFirstFailureAnswerV1 {
    /// Whether this answer is a verified negative.
    ///
    /// Deliberately false for [`Self::Unknown`]: an unmeasured range must never
    /// read as "nothing failed".
    #[must_use]
    pub const fn is_verified_negative(&self) -> bool {
        matches!(self, Self::NoFailureInWindow { .. })
    }

    /// The window every answer, including an unknown one, reports.
    #[must_use]
    pub const fn measured_window(&self) -> &CiCoverageWindowV1 {
        match self {
            Self::FirstFailure { window, .. }
            | Self::NoFailureInWindow { window }
            | Self::Unknown { window, .. } => window,
        }
    }
}

/// Answer "when did CI first fail?" against exactly what was measured.
///
/// The containment check runs FIRST and is total: a question that reaches
/// outside the window resolves to [`CiFirstFailureAnswerV1::Unknown`] before
/// any run is examined, so a failing run inside an overlapping window can never
/// be presented as "the first failure" of a wider range, and an empty window
/// can never be presented as "no failure occurred".
///
/// `runs` must all belong to `window`; a run that does not is a caller error
/// and fails closed rather than being filtered out silently, because silently
/// dropping a run would shrink the measured set without shrinking the claim.
pub fn answer_first_failure(
    window: &CiCoverageWindowV1,
    runs: &[CiWorkflowRunFactV1],
    question: CiFailureQuestionV1,
) -> CiFactResult<CiFirstFailureAnswerV1> {
    window.validate()?;
    for run in runs {
        run.validate()?;
        if !window.admits(run) {
            return Err(CiFactError::RunOutsideWindow {
                run_number: run.run_number,
            });
        }
    }
    if question.last_run_number < question.first_run_number || question.first_run_number == 0 {
        return Ok(CiFirstFailureAnswerV1::Unknown {
            window: window.clone(),
            reason: CiUnknownReasonV1::QuestionRangeIsEmpty,
        });
    }
    if question.first_run_number < window.first_run_number {
        return Ok(CiFirstFailureAnswerV1::Unknown {
            window: window.clone(),
            reason: CiUnknownReasonV1::QuestionStartsBeforeWindow,
        });
    }
    if question.last_run_number > window.last_run_number {
        return Ok(CiFirstFailureAnswerV1::Unknown {
            window: window.clone(),
            reason: CiUnknownReasonV1::QuestionEndsAfterWindow,
        });
    }
    let earliest = runs
        .iter()
        .filter(|run| {
            run.failed()
                && question.first_run_number <= run.run_number
                && run.run_number <= question.last_run_number
        })
        .min_by_key(|run| run.run_number);
    Ok(earliest.map_or_else(
        || CiFirstFailureAnswerV1::NoFailureInWindow {
            window: window.clone(),
        },
        |run| CiFirstFailureAnswerV1::FirstFailure {
            run_number: run.run_number,
            occurred_at: run.settled_at.clone(),
            conclusion: run.conclusion,
            window: window.clone(),
        },
    ))
}

#[cfg(test)]
#[path = "fact_tests.rs"]
mod tests;
