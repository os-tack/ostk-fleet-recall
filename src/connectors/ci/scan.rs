//! Reading a CI provider, behind a seam no test crosses (W3-CIEV).
//!
//! # The provider is a trait, and tests only ever see the recorded side
//!
//! [`CiRunProvider`] has exactly two implementations. [`GhCliRunProvider`]
//! shells out to `gh` for real use and inherits whatever ambient credential the
//! operator's environment already holds — this crate never reads, stores, or
//! transports a token, and there is none in any fixture.
//! [`RecordedRunProvider`] replays payloads recorded VERBATIM from that same
//! `gh` for this repository. Every test in this crate and in
//! `tests/ci_connector_live.rs` uses the recorded side, so no test opens a
//! socket.
//!
//! The fixtures under `fixtures/` are real bytes, not plausible-looking ones.
//! Hand-written JSON would have missed what the real payloads actually contain
//! — an empty-string `conclusion` where a null was expected, `0001-01-01`
//! timestamps on jobs that never started, annotation objects with an empty
//! `title` and the whole message in `message`.
//!
//! # A window that contains an unsettled run is not a window
//!
//! [`scan_runs`] fails the WHOLE scan closed when any run inside the requested
//! range has not settled. It does not skip the run, it does not shrink the
//! window silently, and it does not coerce the run into a neutral outcome: the
//! caller must narrow the request to a range the provider has finished. A
//! window is a claim about immutable objects, and a range containing a moving
//! one is not that claim.

use std::collections::BTreeMap;
use std::process::Command;

use chrono::{DateTime, Utc};
use serde::Deserialize;

use crate::memory_contracts::common::{CanonicalDecimal, CanonicalTimestamp, ContractId};

use super::error::{CiScanError, CiScanResult};
use super::fact::{CI_FACT_SCHEMA_VERSION, CiCommitShaV1};
use super::fact::{
    CiCoverageWindowV1, CiJobV1, CiOutcomeV1, CiRepositoryIdV1, CiRunStatusV1, CiStepV1, CiTextV1,
    CiWorkflowRunFactV1, MAX_CI_ANNOTATIONS, MAX_CI_JOBS, MAX_CI_STEPS, MAX_CI_WINDOW_RUNS,
};

/// Exact `--json` field list the run listing must be requested with.
///
/// Named as a constant because the recorded fixtures were produced with it: a
/// reader can reproduce them by running `gh run list` with this exact list.
pub const GH_RUN_LIST_FIELDS: &str = "databaseId,number,name,workflowName,displayTitle,\
headBranch,headSha,event,status,conclusion,createdAt,startedAt,updatedAt,attempt,url";

/// Largest provider payload this reader will parse, in bytes.
pub const MAX_PROVIDER_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;

/// What one scan asks the provider for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiScanRequestV1 {
    /// Deployment identity of the repository being read.
    pub repository: CiRepositoryIdV1,
    /// `owner/name` coordinate the provider command is pointed at.
    pub provider_repository: String,
    /// Workflow file the runs are filtered to, e.g. `ci.yml`.
    pub workflow_file: String,
    /// Branch the runs are filtered to.
    pub branch: String,
    /// First run number to read, inclusive.
    pub first_run_number: u64,
    /// Last run number to read, inclusive.
    pub last_run_number: u64,
}

/// Conservative `owner/name` check: keeps a hostile coordinate out of argv and
/// out of the window's identity preimage.
fn admissible_repository_coordinate(value: &str) -> bool {
    let mut parts = value.split('/');
    let (Some(owner), Some(name), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let admissible = |segment: &str| {
        !segment.is_empty()
            && segment.len() <= 100
            && segment.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.'
            })
            && !segment.starts_with('.')
    };
    admissible(owner) && admissible(name)
}

/// Conservative workflow-file / branch check, for the same reason.
fn admissible_provider_argument(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_./".contains(&byte))
        && !value.starts_with('-')
        && !value.contains("..")
}

impl CiScanRequestV1 {
    /// Reject a request this reader will not send.
    pub fn validate(&self) -> CiScanResult<()> {
        self.repository.validate()?;
        if !admissible_repository_coordinate(&self.provider_repository)
            || !admissible_provider_argument(&self.workflow_file)
            || !admissible_provider_argument(&self.branch)
        {
            return Err(CiScanError::Payload {
                detail: "scan request names an inadmissible provider coordinate",
            });
        }
        if self.first_run_number == 0 || self.last_run_number < self.first_run_number {
            return Err(CiScanError::EmptyWindow);
        }
        let span = self.last_run_number - self.first_run_number + 1;
        if span > u64::try_from(MAX_CI_WINDOW_RUNS).unwrap_or(u64::MAX) {
            return Err(CiScanError::ScanTooLarge(MAX_CI_WINDOW_RUNS));
        }
        Ok(())
    }

    /// How many runs `gh run list` must be asked for to reach
    /// [`Self::first_run_number`].
    ///
    /// The provider lists newest first with no run-number filter, so the limit
    /// must reach back far enough to include the oldest run in the window.
    /// Bounded by the provider's own maximum.
    #[must_use]
    pub const fn provider_limit(&self, newest_run_number: u64) -> u64 {
        let reach = newest_run_number.saturating_sub(self.first_run_number) + 1;
        if reach > 1_000 { 1_000 } else { reach }
    }
}

/// The provider seam: raw payloads in, nothing interpreted.
///
/// Deliberately byte-oriented. Parsing lives in this module so that the real
/// and the recorded implementation cannot disagree about how a payload is
/// read — they only differ in where the bytes come from.
pub trait CiRunProvider: Send + Sync {
    /// The `gh run list` payload for `request`: a JSON array of run objects.
    fn list_runs(&self, request: &CiScanRequestV1) -> CiScanResult<Vec<u8>>;

    /// The `gh run view <run_id> --json jobs` payload for one run.
    fn view_run_jobs(&self, run_id: u64) -> CiScanResult<Vec<u8>>;

    /// The check-run annotations payload for one job.
    ///
    /// Only ever called for a job that failed: an annotation set is bounded
    /// evidence about a failure, and fetching one per successful job would be
    /// a per-job round trip that buys nothing.
    fn job_annotations(&self, job_id: u64) -> CiScanResult<Vec<u8>>;
}

/// The real provider: `gh`, with the operator's ambient credential.
///
/// No token is read, stored, or passed by this type. `gh` resolves its own
/// authentication from the environment the operator already logged in with, so
/// there is nothing here for a repository, a fixture, or a test to leak.
#[derive(Debug, Clone)]
pub struct GhCliRunProvider {
    repository: String,
    newest_run_number: u64,
}

impl GhCliRunProvider {
    /// Bind the reader to one `owner/name` repository.
    ///
    /// `newest_run_number` is how far back the listing must reach; it is
    /// operator configuration, read once from the provider by whatever schedules
    /// the scan.
    pub fn new(repository: impl Into<String>, newest_run_number: u64) -> CiScanResult<Self> {
        let repository = repository.into();
        if !admissible_repository_coordinate(&repository) {
            return Err(CiScanError::Payload {
                detail: "provider repository coordinate is inadmissible",
            });
        }
        Ok(Self {
            repository,
            newest_run_number,
        })
    }

    fn run(command: &'static str, args: &[&str]) -> CiScanResult<Vec<u8>> {
        let output = Command::new("gh")
            .args(args)
            .output()
            .map_err(|error| CiScanError::Spawn(error.to_string()))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(CiScanError::Command {
                command,
                status: output.status.to_string(),
                stderr: stderr.chars().take(512).collect(),
            });
        }
        if output.stdout.len() > MAX_PROVIDER_PAYLOAD_BYTES {
            return Err(CiScanError::ScanTooLarge(MAX_PROVIDER_PAYLOAD_BYTES));
        }
        Ok(output.stdout)
    }
}

impl CiRunProvider for GhCliRunProvider {
    fn list_runs(&self, request: &CiScanRequestV1) -> CiScanResult<Vec<u8>> {
        request.validate()?;
        let limit = request.provider_limit(self.newest_run_number).to_string();
        Self::run(
            "run list",
            &[
                "run",
                "list",
                "--repo",
                &self.repository,
                "--workflow",
                &request.workflow_file,
                "--branch",
                &request.branch,
                "--limit",
                &limit,
                "--json",
                GH_RUN_LIST_FIELDS,
            ],
        )
    }

    fn view_run_jobs(&self, run_id: u64) -> CiScanResult<Vec<u8>> {
        let run_id = run_id.to_string();
        Self::run(
            "run view",
            &[
                "run",
                "view",
                &run_id,
                "--repo",
                &self.repository,
                "--json",
                "jobs",
            ],
        )
    }

    fn job_annotations(&self, job_id: u64) -> CiScanResult<Vec<u8>> {
        let path = format!("repos/{}/check-runs/{job_id}/annotations", self.repository);
        Self::run("api check-runs annotations", &["api", &path])
    }
}

/// The recorded provider: exact bytes captured from `gh`, replayed offline.
#[derive(Debug, Clone, Default)]
pub struct RecordedRunProvider {
    runs: Vec<u8>,
    jobs: BTreeMap<u64, Vec<u8>>,
    annotations: BTreeMap<u64, Vec<u8>>,
}

impl RecordedRunProvider {
    /// Build one recorded provider from a captured `gh run list` payload.
    #[must_use]
    pub fn new(runs: &[u8]) -> Self {
        Self {
            runs: runs.to_vec(),
            jobs: BTreeMap::new(),
            annotations: BTreeMap::new(),
        }
    }

    /// Record the captured `gh run view --json jobs` payload for one run.
    #[must_use]
    pub fn with_jobs(mut self, run_id: u64, payload: &[u8]) -> Self {
        self.jobs.insert(run_id, payload.to_vec());
        self
    }

    /// Record the captured annotations payload for one job.
    #[must_use]
    pub fn with_annotations(mut self, job_id: u64, payload: &[u8]) -> Self {
        self.annotations.insert(job_id, payload.to_vec());
        self
    }

    /// Replace the recorded listing bytes.
    ///
    /// Used by tests that need a provider state the real repository does not
    /// currently have — an in-flight run, for instance — by editing the REAL
    /// recorded bytes rather than inventing a payload.
    #[must_use]
    pub fn with_runs(mut self, runs: &[u8]) -> Self {
        self.runs = runs.to_vec();
        self
    }
}

impl CiRunProvider for RecordedRunProvider {
    fn list_runs(&self, request: &CiScanRequestV1) -> CiScanResult<Vec<u8>> {
        request.validate()?;
        Ok(self.runs.clone())
    }

    fn view_run_jobs(&self, run_id: u64) -> CiScanResult<Vec<u8>> {
        self.jobs
            .get(&run_id)
            .cloned()
            .ok_or(CiScanError::RecordedRunMissing(run_id))
    }

    fn job_annotations(&self, job_id: u64) -> CiScanResult<Vec<u8>> {
        self.annotations
            .get(&job_id)
            .cloned()
            .ok_or(CiScanError::RecordedRunMissing(job_id))
    }
}

// ---------------------------------------------------------------------------
// Wire shapes. Provider payloads, not contracts: unknown fields are ignored
// because the provider owns its own schema, while every field this reader
// depends on is required and typed.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GhRunListItem {
    database_id: u64,
    number: u64,
    attempt: u32,
    workflow_name: String,
    display_title: String,
    head_branch: String,
    head_sha: String,
    event: String,
    status: String,
    conclusion: String,
    started_at: String,
    updated_at: String,
}

#[derive(Debug, Deserialize)]
struct GhJobsPayload {
    jobs: Vec<GhJob>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GhJob {
    database_id: u64,
    name: String,
    status: String,
    conclusion: String,
    started_at: String,
    completed_at: String,
    steps: Vec<GhStep>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GhStep {
    number: u32,
    name: String,
    status: String,
    conclusion: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
struct GhAnnotation {
    path: String,
    annotation_level: String,
    title: String,
    message: String,
}

/// One provider instant, converted to the exact contract wire form.
fn provider_time(value: &str) -> CiScanResult<CanonicalTimestamp> {
    let parsed: DateTime<Utc> = DateTime::parse_from_rfc3339(value)
        .map_err(|_| CiScanError::Timestamp(value.to_owned()))?
        .with_timezone(&Utc);
    CanonicalTimestamp::from_datetime(&parsed).map_err(|_| CiScanError::Timestamp(value.to_owned()))
}

/// What one scan read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CiScanV1 {
    /// The finite range this scan actually read.
    pub window: CiCoverageWindowV1,
    /// Settled runs inside the window, ordered by run number.
    pub runs: Vec<CiWorkflowRunFactV1>,
}

impl CiScanV1 {
    /// How many runs inside the window reported a failure.
    #[must_use]
    pub fn failed_run_count(&self) -> u32 {
        u32::try_from(self.runs.iter().filter(|run| run.failed()).count()).unwrap_or(u32::MAX)
    }

    /// How many settled runs the scan admitted.
    #[must_use]
    pub fn admitted_run_count(&self) -> u32 {
        u32::try_from(self.runs.len()).unwrap_or(u32::MAX)
    }
}

/// Read one finite window of settled runs from the provider.
///
/// `fetched_at` is the connector's own observation clock and is recorded in the
/// window; it is the value every run fact's `observed_at` takes, and it is
/// distinct from each run's `settled_at` (EVID-03).
pub fn scan_runs(
    provider: &dyn CiRunProvider,
    request: &CiScanRequestV1,
    fetched_at: &CanonicalTimestamp,
) -> CiScanResult<CiScanV1> {
    request.validate()?;
    let listing = provider.list_runs(request)?;
    if listing.len() > MAX_PROVIDER_PAYLOAD_BYTES {
        return Err(CiScanError::ScanTooLarge(MAX_PROVIDER_PAYLOAD_BYTES));
    }
    let items: Vec<GhRunListItem> =
        serde_json::from_slice(&listing).map_err(|_| CiScanError::Payload {
            detail: "run listing is not the expected JSON array of run objects",
        })?;

    let mut runs = Vec::new();
    for item in items {
        if item.number < request.first_run_number || item.number > request.last_run_number {
            continue;
        }
        runs.push(build_run(provider, request, &item)?);
    }
    runs.sort_by_key(|run| run.run_number);
    if runs
        .windows(2)
        .any(|pair| pair[0].run_number == pair[1].run_number)
    {
        return Err(CiScanError::Payload {
            detail: "run listing names one run number twice",
        });
    }
    if runs.len() > MAX_CI_WINDOW_RUNS {
        return Err(CiScanError::ScanTooLarge(MAX_CI_WINDOW_RUNS));
    }

    let window = CiCoverageWindowV1 {
        schema_version: CI_FACT_SCHEMA_VERSION,
        repository: request.repository.clone(),
        workflow: CiTextV1::render(&request.workflow_file)?,
        branch: CiTextV1::render(&request.branch)?,
        first_run_number: request.first_run_number,
        last_run_number: request.last_run_number,
        fetched_at: fetched_at.clone(),
    };
    window.validate()?;
    for run in &runs {
        let same_workflow = run.workflow == window.workflow;
        let same_branch = run.head_branch == window.branch;
        if !same_workflow || !same_branch {
            return Err(CiScanError::RunOutsideRequest {
                run_number: run.run_number,
            });
        }
    }
    Ok(CiScanV1 { window, runs })
}

/// Build one settled run fact, refusing an unsettled one closed.
fn build_run(
    provider: &dyn CiRunProvider,
    request: &CiScanRequestV1,
    item: &GhRunListItem,
) -> CiScanResult<CiWorkflowRunFactV1> {
    let status = CiRunStatusV1::parse(&item.status)?;
    // The provider spells an absent conclusion as the empty string. Parsing it
    // as an outcome is what refuses an in-flight run here rather than letting
    // it reach identity derivation with a fabricated outcome.
    let conclusion = if item.conclusion.is_empty() {
        return Err(CiScanError::Fact(super::error::CiFactError::UnsettledRun {
            run_number: item.number,
            status: item.status.clone(),
            conclusion: String::new(),
        }));
    } else {
        CiOutcomeV1::parse(&item.conclusion)?
    };

    let fact = CiWorkflowRunFactV1 {
        schema_version: CI_FACT_SCHEMA_VERSION,
        repository: request.repository.clone(),
        run_id: CanonicalDecimal::parse(item.database_id.to_string())
            .map_err(super::error::CiFactError::Contract)?,
        run_number: item.number,
        run_attempt: item.attempt,
        // The window filters on the workflow FILE, so the fact records the file
        // as its workflow identifier and keeps the provider's display name as
        // searchable text on the run instead.
        workflow: CiTextV1::render(&request.workflow_file)?,
        event: CiTextV1::render(&item.event)?,
        head_branch: CiTextV1::render(&item.head_branch)?,
        head_sha: CiCommitShaV1::parse(&item.head_sha)?,
        display_title: CiTextV1::render(&format!("{} {}", item.workflow_name, item.display_title))?,
        status,
        conclusion,
        run_started_at: provider_time(&item.started_at)?,
        settled_at: provider_time(&item.updated_at)?,
        jobs: build_jobs(provider, item.database_id)?,
    };
    fact.validate()?;
    Ok(fact)
}

fn build_jobs(provider: &dyn CiRunProvider, run_id: u64) -> CiScanResult<Vec<CiJobV1>> {
    let payload = provider.view_run_jobs(run_id)?;
    let parsed: GhJobsPayload =
        serde_json::from_slice(&payload).map_err(|_| CiScanError::Payload {
            detail: "job payload is not the expected {\"jobs\":[...]} object",
        })?;
    if parsed.jobs.len() > MAX_CI_JOBS {
        return Err(CiScanError::ScanTooLarge(MAX_CI_JOBS));
    }
    let mut jobs = Vec::with_capacity(parsed.jobs.len());
    for job in parsed.jobs {
        if job.steps.len() > MAX_CI_STEPS {
            return Err(CiScanError::ScanTooLarge(MAX_CI_STEPS));
        }
        let conclusion = CiOutcomeV1::parse(&job.conclusion)?;
        let mut steps = Vec::with_capacity(job.steps.len());
        for step in &job.steps {
            steps.push(CiStepV1 {
                number: step.number,
                name: CiTextV1::render(&step.name)?,
                status: CiRunStatusV1::parse(&step.status)?,
                conclusion: CiOutcomeV1::parse(&step.conclusion)?,
            });
        }
        steps.sort_by_key(|step| step.number);
        let failure_annotations = if conclusion.is_failure() {
            build_annotations(provider, job.database_id)?
        } else {
            Vec::new()
        };
        let built = CiJobV1 {
            job_id: CanonicalDecimal::parse(job.database_id.to_string())
                .map_err(super::error::CiFactError::Contract)?,
            name: CiTextV1::render(&job.name)?,
            status: CiRunStatusV1::parse(&job.status)?,
            conclusion,
            started_at: provider_time(&job.started_at)?,
            completed_at: provider_time(&job.completed_at)?,
            steps,
            failure_annotations,
        };
        jobs.push(built);
    }
    Ok(jobs)
}

/// Render a failed job's annotations as searchable text.
///
/// Only `failure`-level annotations are kept: a warning is not evidence about
/// why the job failed, and carrying every deprecation notice would bury the one
/// line that is.
fn build_annotations(provider: &dyn CiRunProvider, job_id: u64) -> CiScanResult<Vec<CiTextV1>> {
    let payload = provider.job_annotations(job_id)?;
    let parsed: Vec<GhAnnotation> =
        serde_json::from_slice(&payload).map_err(|_| CiScanError::Payload {
            detail: "annotation payload is not the expected JSON array",
        })?;
    let mut rendered = Vec::new();
    for annotation in parsed {
        if annotation.annotation_level != "failure" {
            continue;
        }
        if rendered.len() >= MAX_CI_ANNOTATIONS {
            break;
        }
        let text = if annotation.title.is_empty() {
            format!("{} {}", annotation.path, annotation.message)
        } else {
            format!(
                "{} {} {}",
                annotation.path, annotation.title, annotation.message
            )
        };
        rendered.push(CiTextV1::render(&text)?);
    }
    Ok(rendered)
}

// ---------------------------------------------------------------------------
// The recorded corpus.
// ---------------------------------------------------------------------------

/// `owner/name` of the repository the recorded corpus was captured from.
pub const RECORDED_REPOSITORY: &str = "os-tack/ostk-fleet-recall";
/// Workflow file the recorded corpus covers.
pub const RECORDED_WORKFLOW: &str = "ci.yml";
/// Branch the recorded corpus covers.
pub const RECORDED_BRANCH: &str = "main";
/// First run number in the recorded corpus.
///
/// It is one, so this window is left-closed at the workflow's own origin and
/// can therefore support "the first failure ever" rather than only "the first
/// failure in this range".
pub const RECORDED_FIRST_RUN: u64 = 1;
/// Last run number in the recorded corpus.
pub const RECORDED_LAST_RUN: u64 = 8;
/// Run number of this repository's first CI failure, as recorded.
pub const RECORDED_FIRST_FAILING_RUN: u64 = 5;

/// Verbatim `gh run list` output for runs 1..8 of `ci.yml` on `main`, captured
/// with [`GH_RUN_LIST_FIELDS`].
pub const RECORDED_RUN_LIST: &[u8] = include_bytes!("fixtures/gh-run-list-main-1-8.json");

/// Verbatim `gh run view <id> --json jobs` output, one per recorded run.
pub const RECORDED_JOB_PAYLOADS: [(u64, &[u8]); 8] = [
    (
        31_726_670_433,
        include_bytes!("fixtures/gh-run-view-jobs-31726670433.json"),
    ),
    (
        31_726_892_136,
        include_bytes!("fixtures/gh-run-view-jobs-31726892136.json"),
    ),
    (
        31_733_339_111,
        include_bytes!("fixtures/gh-run-view-jobs-31733339111.json"),
    ),
    (
        31_733_689_665,
        include_bytes!("fixtures/gh-run-view-jobs-31733689665.json"),
    ),
    (
        31_741_164_105,
        include_bytes!("fixtures/gh-run-view-jobs-31741164105.json"),
    ),
    (
        31_741_319_725,
        include_bytes!("fixtures/gh-run-view-jobs-31741319725.json"),
    ),
    (
        31_742_555_817,
        include_bytes!("fixtures/gh-run-view-jobs-31742555817.json"),
    ),
    (
        31_760_381_799,
        include_bytes!("fixtures/gh-run-view-jobs-31760381799.json"),
    ),
];

/// Verbatim check-run annotation output for the two jobs that failed inside the
/// recorded window.
pub const RECORDED_ANNOTATION_PAYLOADS: [(u64, &[u8]); 2] = [
    (
        94_584_609_140,
        include_bytes!("fixtures/gh-api-annotations-94584609140.json"),
    ),
    (
        94_645_273_278,
        include_bytes!("fixtures/gh-api-annotations-94645273278.json"),
    ),
];

/// A provider replaying the recorded corpus.
///
/// Shipped in the library rather than duplicated per test file so the unit
/// tests and the connected proof read the SAME real bytes; a fixture that
/// drifted between the two would let one of them pass on a payload the other
/// never sees.
#[must_use]
pub fn recorded_provider() -> RecordedRunProvider {
    let mut provider = RecordedRunProvider::new(RECORDED_RUN_LIST);
    for (run_id, payload) in RECORDED_JOB_PAYLOADS {
        provider = provider.with_jobs(run_id, payload);
    }
    for (job_id, payload) in RECORDED_ANNOTATION_PAYLOADS {
        provider = provider.with_annotations(job_id, payload);
    }
    provider
}

/// The scan request that reads the whole recorded corpus.
pub fn recorded_request(repository: CiRepositoryIdV1) -> CiScanRequestV1 {
    CiScanRequestV1 {
        repository,
        provider_repository: RECORDED_REPOSITORY.to_owned(),
        workflow_file: RECORDED_WORKFLOW.to_owned(),
        branch: RECORDED_BRANCH.to_owned(),
        first_run_number: RECORDED_FIRST_RUN,
        last_run_number: RECORDED_LAST_RUN,
    }
}

/// Deployment identity helper: the connector instance that observed a scan.
///
/// Present so a caller names the observer once and passes a validated value
/// around rather than re-parsing a string at each use site.
pub fn observer_id(value: &str) -> CiScanResult<ContractId> {
    ContractId::new(value).map_err(|error| CiScanError::Fact(error.into()))
}

#[cfg(test)]
#[path = "scan_tests.rs"]
mod tests;
