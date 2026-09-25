//! Workstation-only spec statement CLI (Stage 6).
//!
//! A spec statement says what one Rust enum in the repository must or must
//! not declare, bound to exact byte spans of a spec document at one commit.
//! It becomes normative in three steps, each a subcommand:
//!
//! 1. `ostk-spec draft` reads the active registry head and the binding
//!    family's head, binds the spec document at `--commit`, and writes
//!    `proposal.jsonl` and `expectation.jsonl` (each its canonical bytes plus
//!    one LF) to `--out`. It prints the statement id, the expectation
//!    fingerprint, the exact message an approver signs, and both documents.
//! 2. `ostk-spec approve` signs a drafted proposal offline with one Ed25519
//!    seed and writes the approval. It reads no environment and no database.
//! 3. `ostk-spec activate` verifies the proposal against a freshly read
//!    strict witness (the exact registry head), verifies the approvals under
//!    the active activation policy with `accepted_at` taken from the
//!    database clock, records the statement, and compare-and-sets it into its
//!    binding family. It exits 1 when the compare-and-set lost and the
//!    statement is not live.
//!
//! Once a statement is in force, `ostk-spec check` judges one commit against
//! it: it reads the source file the expectation names at `--commit` through
//! the memory worker's git source `--git-source` (from the worker's sources
//! file `--sources`, whose `provider_repository_id` must derive the
//! statement's repository and whose latest coverage receipt the observer
//! binds), runs the genesis-admitted observer over the enum, appends the blob
//! fact and the observer result, and compares. A verified nonconformance
//! opens (or joins) a `spec_nonconformance` discrepancy episode; every
//! comparison records one spec check. It prints the check (statement,
//! commit, verdict and reasons, both appended events, the discrepancy action
//! and episode, and the check id) and exits 0 for every verdict: `unknown` is
//! an answer, not a failure. Run it after the worker's git step has covered
//! the commit.
//!
//! No check ever closes an episode: under the observer's positive-only
//! admission a fixing commit checks as `unknown`. An operator closes one with
//! `ostk-spec episode resolve --episode HEX --actor ID [--evidence HEX...]`,
//! which cites the given accepted events, or by default the observer event of
//! the latest check of the violated statement (refused when there is none,
//! or that check is nonconforming, truncated by its member bound, of a
//! commit already judged nonconforming, or not later than the check that
//! opened the episode), or with
//! `ostk-spec episode dismiss --episode HEX --actor ID --reason REASON
//! --rationale TEXT`. Either appends one lifecycle event to the episode's
//! log, effective at the database's time, and prints the episode's state
//! before and after. `recall(action="discrepancies")` then lists the episode
//! only with `include_resolved`, and re-checking a commit already judged
//! nonconforming never re-opens it.
//!
//! See `ostk_fleet_recall::spec_conformance` for what each step checks.
//!
//! Environment for `draft`, `activate`, `check`, and `episode` (nothing else,
//! and no CLI authority override):
//!
//! - `FLEET_RECALL_DATABASE_URL` as the private writer login (`fleet_writer`,
//!   a member of `fleet_runtime`), with the
//!   `FLEET_RECALL_ALLOW_INSECURE_LOCAL_DATABASE=1` loopback escape;
//! - `FLEET_RECALL_TENANT_ID` and `FLEET_RECALL_PROJECT`: the physical scope;
//! - the writer-authority pin group `ostk-authority-install apply` prints
//!   (`FLEET_RECALL_CONTRACT_TENANT_NAMESPACE`,
//!   `FLEET_RECALL_CONTRACT_PROJECT_NAMESPACE`,
//!   `FLEET_RECALL_BOOTSTRAP_RECEIPT_DIGEST`, and optionally
//!   `FLEET_RECALL_EXPECTED_ACTIVATION_ID`), which is required;
//! - for `check` only, `FLEET_RECALL_CONTENT_KEK_HEX`: the blob fact and the
//!   observer run record are governed content.
//!
//! Every command prints one JSON document. Like the other operator CLIs, this
//! binary is not in the production image.

use std::fs;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr as _;

use anyhow::{Context as _, anyhow, bail};
use chrono::{DateTime, TimeDelta, Utc};
use clap::{Args, Parser, Subcommand, ValueEnum};
use ostk_fleet_recall::config::WriterProcessConfig;
use ostk_fleet_recall::connectors::git::GitObjectId;
use ostk_fleet_recall::evidence_ledger::{CONTENT_KEY_ENCRYPTION_KEY_ENV, content_kek_from_env};
use ostk_fleet_recall::memory_contracts::canonical::{decode_typed_canonical, encode_canonical};
use ostk_fleet_recall::memory_contracts::common::{CanonicalTimestamp, ContractId};
use ostk_fleet_recall::memory_contracts::digest::Sha256Digest;
use ostk_fleet_recall::memory_contracts::discrepancy::{
    DiscrepancyEpisodeFingerprintV1, DiscrepancySeverityV1, DismissalReasonKindV1,
};
use ostk_fleet_recall::memory_contracts::evidence::AcceptedEventId;
use ostk_fleet_recall::memory_contracts::normative_v2::{
    ApprovalAttestationV1, NormativeBindingProposalV2,
};
use ostk_fleet_recall::normative_runtime::{normative_approval_message, sign_normative_approval};
use ostk_fleet_recall::registry_witness::WriterAuthorityRuntime;
use ostk_fleet_recall::spec_conformance::{
    DEFAULT_SPEC_MEMBER_BOUND, DraftStatementRequestV1, ExpectedMembershipV1,
    RememberActionExpectationV1, SpecCheckRequestV1, SpecEpisodeTransitionV1,
    activate_spec_statement, append_episode_lifecycle, database_now, draft_spec_statement,
    run_spec_check,
};
use ostk_fleet_recall::store::cockroach::{CockroachStore, PoolConfig, RetryPolicy};
use ostk_fleet_recall::worker::WorkerSourcesV1;
use serde::Serialize;
use serde::de::DeserializeOwned;

const APPLICATION_NAME: &str = "ostk-spec";
const MAX_CONNECTIONS: u32 = 2;
/// Each write is one serializable transaction; retry only its 40001 aborts.
const RETRY: RetryPolicy = RetryPolicy {
    max_attempts: 10,
    initial_backoff: std::time::Duration::from_millis(10),
    max_backoff: std::time::Duration::from_millis(500),
};
const PROPOSAL_FILE: &str = "proposal.jsonl";
const EXPECTATION_FILE: &str = "expectation.jsonl";

#[derive(Debug, Parser)]
#[command(
    name = "ostk-spec",
    version,
    about = "Private, workstation-only spec statement CLI: draft, approve, activate, check, episode"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Draft a spec statement under the active registry head and write its
    /// proposal and expectation.
    Draft(Box<DraftArgs>),
    /// Sign a drafted proposal offline with one approver's Ed25519 seed.
    Approve(ApproveArgs),
    /// Verify approvals and activate a drafted statement.
    Activate(ActivateArgs),
    /// Check one commit against the statement in force in a binding family.
    Check(CheckArgs),
    /// Close a spec nonconformance episode as an operator.
    #[command(subcommand)]
    Episode(EpisodeCommand),
}

#[derive(Debug, Subcommand)]
enum EpisodeCommand {
    /// Resolve an episode: the nonconformance is fixed.
    Resolve(ResolveArgs),
    /// Dismiss an episode: it should not stand.
    Dismiss(DismissArgs),
}

#[derive(Debug, Args)]
struct DraftArgs {
    /// The repository's git directory (a bare repository or a `.git`).
    #[arg(long)]
    git_dir: PathBuf,
    /// Operator-declared repository identity, as the worker's git source
    /// names it.
    #[arg(long, value_parser = parse_contract_id)]
    repository_id: ContractId,
    /// Provider-installation coordinate, as the worker's git source names it.
    #[arg(long)]
    installation_id: u64,
    /// The provider's numeric repository id; the statement's subject.
    #[arg(long)]
    provider_repository_id: u64,
    /// The exact commit (full object id) the spec document is read at.
    #[arg(long, value_parser = parse_commit)]
    commit: GitObjectId,
    /// Repository-relative path of the spec document.
    #[arg(long)]
    spec_path: String,
    /// A cited byte range of the spec document, `START..END` (half-open).
    /// Repeat for several.
    #[arg(long = "span", value_parser = parse_span, required = true)]
    spans: Vec<Range<u64>>,
    /// The binding family this statement belongs to.
    #[arg(long = "family", value_parser = parse_contract_id)]
    binding_family_id: ContractId,
    /// The Rust enum the expectation is about.
    #[arg(long = "enum", default_value = "RememberAction")]
    enum_name: String,
    /// The enum member the expectation is about.
    #[arg(long)]
    member: String,
    /// Whether the enum must declare the member.
    #[arg(long, value_enum)]
    expected: Expected,
    /// Repository-relative path of the Rust source that declares the enum.
    #[arg(long, default_value = "src/service.rs")]
    source_path: String,
    /// Severity of a discrepancy episode this statement opens.
    #[arg(long, value_enum, default_value_t = Severity::Medium)]
    severity: Severity,
    /// When the statement takes effect (RFC 3339). Must not precede its
    /// activation.
    #[arg(
        long,
        value_parser = parse_timestamp,
        required_unless_present = "effective_in_seconds",
        conflicts_with = "effective_in_seconds"
    )]
    effective_from: Option<CanonicalTimestamp>,
    /// Take effect this many seconds after the database's current time.
    #[arg(long)]
    effective_in_seconds: Option<u32>,
    /// When the statement stops taking effect (RFC 3339).
    #[arg(long, value_parser = parse_timestamp)]
    effective_until: Option<CanonicalTimestamp>,
    /// The live statement (64 hex) this one explicitly supersedes.
    #[arg(long, value_parser = parse_digest)]
    supersedes: Option<Sha256Digest>,
    /// The principal proposing the statement. May not approve it.
    #[arg(long, value_parser = parse_contract_id)]
    proposer: ContractId,
    /// The spec document's author. Must differ from the proposer and may not
    /// approve.
    #[arg(long, value_parser = parse_contract_id)]
    author: ContractId,
    /// Directory to write `proposal.jsonl` and `expectation.jsonl` into.
    #[arg(long)]
    out: PathBuf,
}

#[derive(Debug, Args)]
struct ApproveArgs {
    /// A drafted `proposal.jsonl`.
    #[arg(long)]
    proposal: PathBuf,
    /// The approving principal, as the active activation policy lists it.
    #[arg(long, value_parser = parse_contract_id)]
    principal: ContractId,
    /// A file holding the approver's 32-byte Ed25519 seed, raw or as 64 hex
    /// characters.
    #[arg(long)]
    seed_file: PathBuf,
    /// When the approval is signed (RFC 3339); defaults to now. Must not be
    /// later than the activation's server time.
    #[arg(long, value_parser = parse_timestamp)]
    signed_at: Option<CanonicalTimestamp>,
    /// Where to write the approval.
    #[arg(long)]
    out: PathBuf,
}

#[derive(Debug, Args)]
struct ActivateArgs {
    /// A drafted `proposal.jsonl`.
    #[arg(long)]
    proposal: PathBuf,
    /// The `expectation.jsonl` drafted with it.
    #[arg(long)]
    expectation: PathBuf,
    /// An approval written by `approve`. Repeat for each approver.
    #[arg(long = "approval", required = true)]
    approvals: Vec<PathBuf>,
}

#[derive(Debug, Args)]
struct CheckArgs {
    /// The binding family whose statement in force the commit is judged
    /// against.
    #[arg(long = "family", value_parser = parse_contract_id)]
    binding_family_id: ContractId,
    /// The memory worker's sources file: the git source to read and the
    /// observer identity to append under.
    #[arg(long)]
    sources: PathBuf,
    /// The connector instance of the git source in `--sources` that reads the
    /// statement's repository.
    #[arg(long, value_parser = parse_contract_id)]
    git_source: ContractId,
    /// The exact commit (full object id) to check.
    #[arg(long, value_parser = parse_commit)]
    commit: GitObjectId,
    /// Hard cap on enumerated enum members. Reaching it makes the read
    /// non-exhaustive, so a missing member stays unknown.
    #[arg(long, default_value_t = DEFAULT_SPEC_MEMBER_BOUND)]
    member_bound: usize,
}

#[derive(Debug, Args)]
struct ResolveArgs {
    /// The episode (64 hex), as `recall(action="discrepancies")` lists it.
    #[arg(long, value_parser = parse_episode)]
    episode: DiscrepancyEpisodeFingerprintV1,
    /// The principal resolving it. May not be implicated in the finding.
    #[arg(long, value_parser = parse_contract_id)]
    actor: ContractId,
    /// An accepted event (64 hex) that shows the fix. Repeat for several.
    /// Defaults to the observer event of the latest check of the statement
    /// the episode violates, which must be an exhaustive, not nonconforming
    /// check of a commit never judged nonconforming, recorded after the
    /// check that opened the episode.
    #[arg(long = "evidence", value_parser = parse_event)]
    evidence: Vec<AcceptedEventId>,
}

#[derive(Debug, Args)]
struct DismissArgs {
    /// The episode (64 hex), as `recall(action="discrepancies")` lists it.
    #[arg(long, value_parser = parse_episode)]
    episode: DiscrepancyEpisodeFingerprintV1,
    /// The principal dismissing it. May not be implicated in the finding.
    #[arg(long, value_parser = parse_contract_id)]
    actor: ContractId,
    /// Why the episode should not stand.
    #[arg(long, value_enum)]
    reason: DismissReason,
    /// The justification, recorded in the episode's history. Must not be
    /// blank.
    #[arg(long)]
    rationale: String,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
#[value(rename_all = "snake_case")]
enum DismissReason {
    FalsePositive,
    DuplicateOfOtherEpisode,
    OutOfScope,
    NotReproducible,
}

impl From<DismissReason> for DismissalReasonKindV1 {
    fn from(value: DismissReason) -> Self {
        match value {
            DismissReason::FalsePositive => Self::FalsePositive,
            DismissReason::DuplicateOfOtherEpisode => Self::DuplicateOfOtherEpisode,
            DismissReason::OutOfScope => Self::OutOfScope,
            DismissReason::NotReproducible => Self::NotReproducible,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Expected {
    Present,
    Absent,
}

impl From<Expected> for ExpectedMembershipV1 {
    fn from(value: Expected) -> Self {
        match value {
            Expected::Present => Self::Present,
            Expected::Absent => Self::Absent,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl From<Severity> for DiscrepancySeverityV1 {
    fn from(value: Severity) -> Self {
        match value {
            Severity::Info => Self::Info,
            Severity::Low => Self::Low,
            Severity::Medium => Self::Medium,
            Severity::High => Self::High,
            Severity::Critical => Self::Critical,
        }
    }
}

/// What `draft` prints: everything an approver checks before signing.
#[derive(Debug, Serialize)]
struct DraftReport<'a> {
    statement_id: Sha256Digest,
    binding_family_id: &'a ContractId,
    expectation_fingerprint: Sha256Digest,
    /// The exact bytes an approver signs, hex-encoded.
    signing_message_hex: String,
    proposal_file: &'a Path,
    expectation_file: &'a Path,
    proposal: &'a NormativeBindingProposalV2,
    expectation: &'a RememberActionExpectationV1,
}

/// What `approve` prints.
#[derive(Debug, Serialize)]
struct ApproveReport<'a> {
    statement_id: Sha256Digest,
    principal_id: &'a ContractId,
    signer_key_id: &'a ContractId,
    signed_at: &'a CanonicalTimestamp,
    approval_file: &'a Path,
}

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    match Cli::parse().command {
        Command::Draft(args) => draft(*args).await.map(|()| ExitCode::SUCCESS),
        Command::Approve(args) => approve(&args).map(|()| ExitCode::SUCCESS),
        Command::Activate(args) => activate(args).await,
        Command::Check(args) => check(args).await.map(|()| ExitCode::SUCCESS),
        Command::Episode(command) => episode(command).await.map(|()| ExitCode::SUCCESS),
    }
}

async fn draft(args: DraftArgs) -> anyhow::Result<()> {
    let runtime = connect_runtime().await?;
    let effective_from = match (args.effective_from, args.effective_in_seconds) {
        (Some(at), None) => at,
        (None, Some(seconds)) => {
            let now = database_now(runtime.pool()).await?;
            CanonicalTimestamp::from_datetime(&(now + TimeDelta::seconds(i64::from(seconds))))?
        }
        _ => bail!("exactly one of --effective-from and --effective-in-seconds is required"),
    };
    let request = DraftStatementRequestV1 {
        git_dir: args.git_dir,
        repository_id: args.repository_id,
        installation_id: args.installation_id,
        provider_repository_id: args.provider_repository_id,
        commit: args.commit,
        spec_path: args.spec_path,
        spans: args.spans,
        binding_family_id: args.binding_family_id,
        source_path: args.source_path,
        enum_name: args.enum_name,
        member: args.member,
        expected: args.expected.into(),
        severity: args.severity.into(),
        effective_from,
        effective_until: args.effective_until,
        supersedes: args.supersedes,
        proposer: args.proposer,
        author: args.author,
    };
    let (proposal, expectation) = draft_spec_statement(&runtime, &request).await?;
    let statement_id = proposal.statement_id()?;

    fs::create_dir_all(&args.out)
        .with_context(|| format!("cannot create {}", args.out.display()))?;
    let proposal_file = args.out.join(PROPOSAL_FILE);
    let expectation_file = args.out.join(EXPECTATION_FILE);
    write_canonical(&proposal_file, &proposal)?;
    write_canonical(&expectation_file, &expectation)?;
    print_json(&DraftReport {
        statement_id,
        binding_family_id: &proposal.binding_family_id,
        expectation_fingerprint: expectation.fingerprint()?,
        signing_message_hex: hex::encode(normative_approval_message(statement_id)),
        proposal_file: &proposal_file,
        expectation_file: &expectation_file,
        proposal: &proposal,
        expectation: &expectation,
    })
}

fn approve(args: &ApproveArgs) -> anyhow::Result<()> {
    let proposal: NormativeBindingProposalV2 = read_canonical(&args.proposal)?;
    let seed = read_seed(&args.seed_file)?;
    let signed_at = match &args.signed_at {
        Some(at) => at.clone(),
        None => CanonicalTimestamp::from_datetime(&Utc::now())?,
    };
    let approval = sign_normative_approval(&proposal, args.principal.clone(), &seed, signed_at)?;
    write_canonical(&args.out, &approval)?;
    print_json(&ApproveReport {
        statement_id: approval.statement_id,
        principal_id: &approval.principal_id,
        signer_key_id: &approval.signer_key_id,
        signed_at: &approval.signed_at,
        approval_file: &args.out,
    })
}

async fn activate(args: ActivateArgs) -> anyhow::Result<ExitCode> {
    let proposal: NormativeBindingProposalV2 = read_canonical(&args.proposal)?;
    let expectation: RememberActionExpectationV1 = read_canonical(&args.expectation)?;
    let approvals = args
        .approvals
        .iter()
        .map(|path| read_canonical::<ApprovalAttestationV1>(path))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let runtime = connect_runtime().await?;
    let accepted_at = CanonicalTimestamp::from_datetime(&database_now(runtime.pool()).await?)?;
    let report =
        activate_spec_statement(&runtime, &proposal, &expectation, &approvals, &accepted_at)
            .await?;
    print_json(&report)?;
    Ok(if report.is_live() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

async fn check(args: CheckArgs) -> anyhow::Result<()> {
    let sources = WorkerSourcesV1::load(&args.sources)?;
    let kek = content_kek_from_env()?.ok_or_else(|| {
        anyhow!("{CONTENT_KEY_ENCRYPTION_KEY_ENV} must carry the governed-content key")
    })?;
    let runtime = connect_runtime().await?;
    let request = SpecCheckRequestV1 {
        binding_family_id: args.binding_family_id,
        sources,
        git_source: args.git_source,
        commit: args.commit,
        member_bound: args.member_bound,
        evaluated_through: None,
    };
    let outcome = Box::pin(run_spec_check(&runtime, &kek, &request)).await?;
    print_json(&outcome)
}

async fn episode(command: EpisodeCommand) -> anyhow::Result<()> {
    let (episode, actor, transition) = match command {
        EpisodeCommand::Resolve(args) => (
            args.episode,
            args.actor,
            SpecEpisodeTransitionV1::Resolve {
                evidence: args.evidence,
            },
        ),
        EpisodeCommand::Dismiss(args) => (
            args.episode,
            args.actor,
            SpecEpisodeTransitionV1::Dismiss {
                reason: args.reason.into(),
                rationale: args.rationale,
            },
        ),
    };
    let runtime = connect_runtime().await?;
    let report = append_episode_lifecycle(&runtime, episode, &actor, &transition).await?;
    print_json(&report)
}

/// Connect as the writer login and verify the pinned head once.
async fn connect_runtime() -> anyhow::Result<WriterAuthorityRuntime> {
    let process = WriterProcessConfig::from_env(APPLICATION_NAME)?;
    let store = CockroachStore::connect_writer(
        process.database_url(),
        process.database_ssl_policy(),
        process.physical_scope().clone(),
        PoolConfig {
            max_connections: MAX_CONNECTIONS,
            ..PoolConfig::default()
        },
    )
    .await?;
    let (runtime, _startup) = WriterAuthorityRuntime::from_env(
        store.pool().clone(),
        process.physical_scope().clone(),
        RETRY,
    )
    .await?
    .ok_or_else(|| {
        anyhow!(
            "ostk-spec needs the writer-authority pin group that `ostk-authority-install apply` prints"
        )
    })?;
    Ok(runtime)
}

/// Write `value` as its canonical bytes plus one LF.
fn write_canonical<T: Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    let mut bytes = encode_canonical(value)?;
    bytes.push(b'\n');
    fs::write(path, bytes).with_context(|| format!("cannot write {}", path.display()))
}

/// Read a document `write_canonical` wrote: exactly its canonical bytes,
/// optionally followed by one LF.
fn read_canonical<T: DeserializeOwned + Serialize>(path: &Path) -> anyhow::Result<T> {
    let bytes = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    let body = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
    decode_typed_canonical(body)
        .with_context(|| format!("{} is not one canonical document", path.display()))
}

/// A 32-byte Ed25519 seed, stored raw or as 64 hex characters.
fn read_seed(path: &Path) -> anyhow::Result<[u8; 32]> {
    let bytes = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    parse_seed(&bytes).with_context(|| format!("{} holds no Ed25519 seed", path.display()))
}

fn parse_seed(bytes: &[u8]) -> anyhow::Result<[u8; 32]> {
    let text = std::str::from_utf8(bytes)
        .map(str::trim)
        .unwrap_or_default();
    if text.len() == 64 {
        let mut seed = [0_u8; 32];
        hex::decode_to_slice(text, &mut seed)?;
        return Ok(seed);
    }
    bytes
        .try_into()
        .map_err(|_| anyhow!("a seed is 32 raw bytes or 64 hex characters"))
}

fn print_json<T: Serialize>(value: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn parse_contract_id(value: &str) -> Result<ContractId, String> {
    ContractId::new(value).map_err(|error| error.to_string())
}

fn parse_commit(value: &str) -> Result<GitObjectId, String> {
    GitObjectId::parse_hex(value).map_err(|error| error.to_string())
}

fn parse_digest(value: &str) -> Result<Sha256Digest, String> {
    Sha256Digest::from_str(value).map_err(|error| error.to_string())
}

fn parse_episode(value: &str) -> Result<DiscrepancyEpisodeFingerprintV1, String> {
    parse_digest(value).map(DiscrepancyEpisodeFingerprintV1::from_digest)
}

fn parse_event(value: &str) -> Result<AcceptedEventId, String> {
    parse_digest(value).map(AcceptedEventId::from_digest)
}

fn parse_timestamp(value: &str) -> Result<CanonicalTimestamp, String> {
    let parsed = DateTime::parse_from_rfc3339(value).map_err(|error| error.to_string())?;
    CanonicalTimestamp::from_datetime(&parsed.with_timezone(&Utc))
        .map_err(|error| error.to_string())
}

fn parse_span(value: &str) -> Result<Range<u64>, String> {
    let (start, end) = value
        .split_once("..")
        .ok_or_else(|| "a span is START..END".to_owned())?;
    let start = start.parse::<u64>().map_err(|error| error.to_string())?;
    let end = end.parse::<u64>().map_err(|error| error.to_string())?;
    if start >= end {
        return Err("a span must select at least one byte (START < END)".into());
    }
    Ok(start..end)
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory as _;

    use super::*;

    #[test]
    fn the_command_line_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn spans_timestamps_and_seeds_parse_as_documented() {
        assert_eq!(parse_span("7..13").unwrap(), 7..13);
        for refused in ["7", "13..7", "7..7", "a..b", "-1..3"] {
            assert!(parse_span(refused).is_err(), "{refused}");
        }
        assert_eq!(
            parse_timestamp("2026-09-24T12:00:00+02:00").unwrap(),
            CanonicalTimestamp::parse("2026-09-24T10:00:00.000000000Z").unwrap()
        );
        assert!(parse_timestamp("yesterday").is_err());

        let hex_seed = format!("{}\n", "01".repeat(32));
        assert_eq!(parse_seed(hex_seed.as_bytes()).unwrap(), [0x01; 32]);
        assert_eq!(parse_seed(&[0x02; 32]).unwrap(), [0x02; 32]);
        assert!(parse_seed(b"0101").is_err());
        assert!(parse_seed(&[0x02; 31]).is_err());
    }

    #[test]
    fn an_episode_is_resolved_with_evidence_or_dismissed_with_a_rationale() {
        let episode = "ab".repeat(32);
        let evidence = ["01".repeat(32), "02".repeat(32)];
        let episode_args = |subcommand: &'static str, extra: &[&str]| {
            let mut args = vec![
                "ostk-spec",
                "episode",
                subcommand,
                "--episode",
                &episode,
                "--actor",
                "principal.on_call",
            ];
            args.extend_from_slice(extra);
            Cli::try_parse_from(args).map(|cli| cli.command)
        };

        let Ok(Command::Episode(EpisodeCommand::Resolve(defaulted))) = episode_args("resolve", &[])
        else {
            panic!("a resolve command");
        };
        assert!(defaulted.evidence.is_empty());
        let Ok(Command::Episode(EpisodeCommand::Resolve(cited))) = episode_args(
            "resolve",
            &["--evidence", &evidence[0], "--evidence", &evidence[1]],
        ) else {
            panic!("a resolve command");
        };
        assert_eq!(
            cited.evidence,
            evidence
                .iter()
                .map(|hex| parse_event(hex).unwrap())
                .collect::<Vec<_>>()
        );
        assert!(episode_args("resolve", &["--evidence", "not-hex"]).is_err());

        let Ok(Command::Episode(EpisodeCommand::Dismiss(dismissed))) = episode_args(
            "dismiss",
            &[
                "--reason",
                "duplicate_of_other_episode",
                "--rationale",
                "the same finding as another episode",
            ],
        ) else {
            panic!("a dismiss command");
        };
        assert_eq!(
            DismissalReasonKindV1::from(dismissed.reason),
            DismissalReasonKindV1::DuplicateOfOtherEpisode
        );
        assert!(
            episode_args("dismiss", &["--reason", "false_positive"]).is_err(),
            "a dismissal without a rationale"
        );
        assert!(
            episode_args("dismiss", &["--reason", "wont_fix", "--rationale", "later"]).is_err(),
            "a reason outside the contract's taxonomy"
        );
    }
}
