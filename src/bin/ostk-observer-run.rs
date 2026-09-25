//! The exhaustive observer worker (W3-OBSRT, Stage 6).
//!
//! A private executable. It has no public server route, no HTTP surface, and
//! nothing in the MCP tool namespace: an observation is a governed write, and
//! exposing it to the request path would make "run the observer" something a
//! caller could ask for rather than something an operator does.
//!
//! # What it does
//!
//! Evaluates `mcp.remember.allowed_actions` over one Rust enum at ONE exact
//! commit and blob, and emits a run receipt plus a typed observer result
//! through the W1-EVID admission seam.
//!
//! * `inspect` reads the repository, resolves the admission, builds the whole
//!   record, and prints it. It never opens a database connection, so it is
//!   safe to run anywhere and is the way to see what a run WOULD claim.
//! * `apply` does all of that and then appends, with the run receipt sealed
//!   into the same serializable transaction as the accepted event.
//!
//! # What is configuration and what is not
//!
//! Every value governance decided — the observer id and version, the
//! executable artifact digest, the dependency closure digest, the
//! configuration context digest, the admission mode, the predicate reference —
//! is a CLI argument, and every one of them is checked against the activated
//! `observer_admission` entry before the run is admitted. Supplying the wrong
//! one is refused, not accepted under a different admission.
//!
//! Values that describe THIS BINARY rather than the deployment — the
//! enumeration algorithm, its registered diagnostics, the closed input
//! boundary, the toolchain identifiers, and the conformance vector digests —
//! are compiled in, as the `observer_runtime` constants `ostk-spec check` also
//! runs under. An operator flag for them would let a deployment claim more
//! exhaustiveness than the code can deliver.
//!
//! # The source is pinned, not discovered
//!
//! `--commit` takes an object id, never a revision expression, and `--blob`
//! and `--content-digest` must both hold. A repository that resolves the path
//! to a different object, or a store that answers with different bytes, is
//! refused before anything is written.

use std::path::PathBuf;

use anyhow::{Context as _, anyhow};
use clap::{Args, Parser, Subcommand, ValueEnum};
use ostk_fleet_recall::FleetScope;
use ostk_fleet_recall::connectors::git::{GitObjectId, GitRepositoryIdV1, GitRepositoryReader};
use ostk_fleet_recall::evidence_ledger::{CONTENT_KEY_ENCRYPTION_KEY_ENV, content_kek_from_env};
use ostk_fleet_recall::memory_contracts::canonical::decode_strict;
use ostk_fleet_recall::memory_contracts::common::{
    CanonicalTimestamp, ContractId, ProfileReferenceV1, RegistryReferenceV1,
    frozen_profile_reference_v1,
};
use ostk_fleet_recall::memory_contracts::digest::Sha256Digest;
use ostk_fleet_recall::memory_contracts::evidence::AcceptedEventId;
use ostk_fleet_recall::memory_contracts::genesis::SemanticallyClosedGenesisPackage;
use ostk_fleet_recall::memory_contracts::observer::{
    ObserverAdmissionModeV1, ObserverCoverageContinuityV1,
};
use ostk_fleet_recall::memory_contracts::registry::ManifestVerifiedRegistryPackage;
use ostk_fleet_recall::memory_contracts::relation::ConcreteApplicabilityDimensionV1;
use ostk_fleet_recall::observer_runtime::{
    ADVERSARIAL_VECTOR_DIGEST, MAX_OBSERVED_SOURCE_BYTES, MUTATION_VECTOR_DIGEST,
    NEGATIVE_VECTOR_DIGEST, OBSERVER_CONNECTOR_SCHEMA, OBSERVER_KIND, ObserverAdmissionBindingV1,
    ObserverConnectorBindingV1, ObserverDrainContextV1, ObserverIngressClocksV1,
    ObserverQuestionV1, ObserverRunPlanV1, ObserverRunRecordV1, ObserverRuntimeDeclarationV1,
    ObserverSourcePinV1, POSITIVE_VECTOR_DIGEST, REQUIRED_APPLICABILITY_DIMENSION,
    bind_observed_source, build_observer_run, drain_observer_run, enumerate_rust_enum,
    observer_input_domain, observer_toolchain_versions,
};
use ostk_fleet_recall::private_postgres::{
    PrivatePostgresSslPolicy, private_postgres_connect_options,
};
use ostk_fleet_recall::registry_witness::WriterAuthorityRuntime;
use ostk_fleet_recall::store::cockroach::RetryPolicy;
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

const APPLICATION_NAME: &str = "ostk-observer-run";
const MAX_CONNECTIONS: u32 = 2;
const DATABASE_URL_ENV: &str = "FLEET_RECALL_OBSERVER_DATABASE_URL";

#[derive(Debug, Parser)]
#[command(
    name = "ostk-observer-run",
    version,
    about = "Private exhaustive observer for mcp.remember.allowed_actions"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Build the run receipt and result and print them. Touches no database.
    Inspect(InspectArgs),
    /// Build the run and append it, receipt and event in one transaction.
    Apply(ApplyArgs),
}

#[derive(Debug, Args)]
struct InspectArgs {
    #[command(flatten)]
    source: SourceArgs,
    #[command(flatten)]
    question: QuestionArgs,
    #[command(flatten)]
    admission: AdmissionArgs,
    /// Canonical genesis registry package plus one LF.
    #[arg(long, value_name = "PATH")]
    genesis_package: PathBuf,
    /// Canonical bootstrap receipt plus one LF.
    #[arg(long, value_name = "PATH")]
    bootstrap_receipt: PathBuf,
    /// The deployment's out-of-band bootstrap receipt digest pin.
    #[arg(long, value_name = "HEX")]
    bootstrap_pin: String,
    /// Digest of the coverage receipt this run's coverage witness binds.
    #[arg(long, value_name = "HEX")]
    coverage_receipt_digest: String,
    /// Accepted-event identity of the git blob-source fact for the exact
    /// object this run reads, as a W2-GIT drain reported it.
    #[arg(long, value_name = "HEX")]
    evidence_event: String,
}

#[derive(Debug, Args)]
struct ApplyArgs {
    #[command(flatten)]
    inspect: InspectArgs,
    /// Physical tenant this run writes into.
    #[arg(long, value_name = "UUID")]
    tenant_id: Uuid,
    /// Physical project this run writes into.
    #[arg(long, value_name = "TEXT")]
    project: String,
    /// Authenticated connector principal the record is delivered as.
    #[arg(long, value_name = "ID")]
    connector_principal: String,
    /// Connector instance the record is delivered as.
    #[arg(long, value_name = "ID")]
    connector_instance: String,
}

#[derive(Debug, Args)]
struct SourceArgs {
    /// The repository's `--git-dir`.
    #[arg(long, value_name = "PATH")]
    git_dir: PathBuf,
    /// Operator-declared repository identifier.
    #[arg(long, value_name = "ID")]
    repository_id: String,
    /// Provider-instance installation coordinate.
    #[arg(long, value_name = "N")]
    installation_id: u64,
    /// The exact commit OBJECT ID. Not a revision expression.
    #[arg(long, value_name = "HEX")]
    commit: String,
    /// The exact path inside that commit's tree.
    #[arg(long, value_name = "PATH")]
    path: String,
    /// The exact blob object the path must resolve to.
    #[arg(long, value_name = "HEX")]
    blob: String,
    /// The exact `ostk-observer-source-blob-v1` digest of the blob's bytes.
    #[arg(long, value_name = "HEX")]
    content_digest: String,
}

#[derive(Debug, Args)]
struct QuestionArgs {
    /// The enum the predicate is about.
    #[arg(long, value_name = "NAME", default_value = "RememberAction")]
    enum_name: String,
    /// Ask whether one named variant is in the set. Omit for an exact-set
    /// question.
    #[arg(long, value_name = "NAME")]
    member: Option<String>,
    /// Hard cap on enumerated members. Reaching it makes the read
    /// non-exhaustive rather than shorter.
    #[arg(long, value_name = "N", default_value_t = 64)]
    member_bound: usize,
}

#[derive(Debug, Args)]
struct AdmissionArgs {
    /// The activated observer admission id.
    #[arg(long, value_name = "ID")]
    observer_id: String,
    /// The activated observer admission version.
    #[arg(long, value_name = "N")]
    observer_version: u32,
    /// The observer kind.
    #[arg(long, value_name = "ID", default_value = OBSERVER_KIND)]
    observer_kind: String,
    /// The executable artifact digest governance pinned.
    #[arg(long, value_name = "HEX")]
    executable_digest: String,
    /// The dependency closure digest governance pinned.
    #[arg(long, value_name = "HEX")]
    dependency_closure_digest: String,
    /// The configuration context digest governance pinned.
    #[arg(long, value_name = "HEX")]
    configuration_digest: String,
    /// The admission mode governance granted.
    #[arg(long, value_enum)]
    mode: AdmissionMode,
    /// Predicate entry id, version, and entry digest.
    #[arg(long, value_name = "ID")]
    predicate_entry: String,
    /// Predicate entry version.
    #[arg(long, value_name = "N")]
    predicate_version: u32,
    /// Predicate entry digest.
    #[arg(long, value_name = "HEX")]
    predicate_digest: String,
    /// Coverage-receipt recipe entry id.
    #[arg(long, value_name = "ID")]
    coverage_recipe_entry: String,
    /// Coverage-receipt recipe version.
    #[arg(long, value_name = "N")]
    coverage_recipe_version: u32,
    /// Coverage-receipt recipe entry digest.
    #[arg(long, value_name = "HEX")]
    coverage_recipe_digest: String,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum AdmissionMode {
    CandidateOnly,
    PositiveVerified,
    ClosedWorldVerified,
}

impl AdmissionMode {
    const fn to_contract(self) -> ObserverAdmissionModeV1 {
        match self {
            Self::CandidateOnly => ObserverAdmissionModeV1::CandidateOnly,
            Self::PositiveVerified => ObserverAdmissionModeV1::PositiveVerified,
            Self::ClosedWorldVerified => ObserverAdmissionModeV1::ClosedWorldVerified,
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    match Cli::parse().command {
        Command::Inspect(args) => {
            let record = build(&args)?;
            println!("{}", serde_json::to_string_pretty(&report(&record, None)?)?);
            Ok(())
        }
        Command::Apply(args) => apply(args).await,
    }
}

/// Build the run record offline: repository, admission, enumeration, receipt.
fn build(args: &InspectArgs) -> anyhow::Result<ObserverRunRecordV1> {
    let profile = frozen_profile_reference_v1();
    let genesis = read_genesis_package(&args.genesis_package, &profile)?;
    let bootstrap = read_bootstrap(args, &profile, &genesis)?;

    let declaration = declaration(&args.admission)?;
    let binding =
        ObserverAdmissionBindingV1::resolve(&bootstrap, &genesis, declaration.to_admission()?)
            .map_err(|error| anyhow!("observer admission refused: {error}"))?;

    let reader = GitRepositoryReader::new(
        &args.source.git_dir,
        GitRepositoryIdV1::from_trusted_config(
            ContractId::new(args.source.repository_id.clone())?,
            args.source.installation_id,
        )?,
        None,
    )?;
    let pin = ObserverSourcePinV1 {
        commit_id: GitObjectId::parse_hex(&args.source.commit)?,
        path: args.source.path.clone().into_bytes(),
        blob_id: GitObjectId::parse_hex(&args.source.blob)?,
        content_digest: parse_digest(&args.source.content_digest, "--content-digest")?,
    };
    let source = bind_observed_source(&reader, &pin, MAX_OBSERVED_SOURCE_BYTES)
        .map_err(|error| anyhow!("pinned source refused: {error}"))?;
    let enumeration = enumerate_rust_enum(
        source.source_text()?,
        &args.question.enum_name,
        args.question.member_bound,
    )
    .map_err(|error| anyhow!("enumeration refused: {error}"))?;

    let revision = source.observed_revision_uri()?;
    let plan = ObserverRunPlanV1 {
        enum_name: args.question.enum_name.clone(),
        question: args
            .question
            .member
            .clone()
            .map_or(ObserverQuestionV1::ExactSet, |member| {
                ObserverQuestionV1::Membership { member }
            }),
        member_bound: args.question.member_bound,
        applicability: vec![ConcreteApplicabilityDimensionV1 {
            dimension_id: ContractId::new(REQUIRED_APPLICABILITY_DIMENSION)?,
            resource: revision.clone(),
        }],
        // The run cites the accepted event of the git blob-source fact for
        // the exact object it read. That event is the LEDGER's record of the
        // blob, minted by a W2-GIT drain; this worker names it rather than
        // asserting the blob itself, so the receipt's evidence is something
        // already durable and independently checkable.
        evidence_event_ids: vec![AcceptedEventId::from_digest(parse_digest(
            &args.evidence_event,
            "--evidence-event",
        )?)],
        coverage_receipt_digest: parse_digest(
            &args.coverage_receipt_digest,
            "--coverage-receipt-digest",
        )?,
        // One immutable blob has no sequencing dimension to be contiguous in.
        coverage_continuity: ObserverCoverageContinuityV1::NotApplicable,
        profile,
        scope: bootstrap.receipt().statement.scope.clone(),
    };
    let record = build_observer_run(&binding, &source, &enumeration, &plan, revision)
        .map_err(|error| anyhow!("run refused: {error}"))?;
    Ok(record)
}

async fn apply(args: ApplyArgs) -> anyhow::Result<()> {
    let record = build(&args.inspect)?;

    let database_url = std::env::var(DATABASE_URL_ENV)
        .with_context(|| format!("{DATABASE_URL_ENV} must name the target database"))?;
    let options = private_postgres_connect_options(
        &database_url,
        APPLICATION_NAME,
        PrivatePostgresSslPolicy::VerifyFull,
    )?;
    let pool = PgPoolOptions::new()
        .max_connections(MAX_CONNECTIONS)
        .connect_with(options)
        .await?;

    let scope = FleetScope::new(
        args.tenant_id,
        args.project.clone(),
        APPLICATION_NAME,
        None,
        ostk_recall_core::PrivacyTier::T1Project,
    )?;
    // An observer append is event-first by definition, so an absent or
    // partial pin group, or pins the durable head does not honor, stops the
    // run before it appends anything (D5).
    let (runtime, _startup) = WriterAuthorityRuntime::from_env(pool, scope, RetryPolicy::default())
        .await?
        .ok_or_else(|| {
            anyhow!("the writer-authority pin group must be configured for an observer append")
        })?;
    let authority = runtime.verify().await?;
    let active = authority.bind_connector(&ContractId::new(OBSERVER_CONNECTOR_SCHEMA)?)?;
    let kek = content_kek_from_env()?.ok_or_else(|| {
        anyhow!("{CONTENT_KEY_ENCRYPTION_KEY_ENV} must carry the governed-content key")
    })?;
    let connector = ObserverConnectorBindingV1::resolve(
        &active,
        ContractId::new(args.connector_principal.clone())?,
        ContractId::new(args.connector_instance.clone())?,
        args.inspect.source.installation_id,
    )?;
    let received_at = CanonicalTimestamp::from_datetime(&chrono::Utc::now())?;
    let outcome = drain_observer_run(
        &ObserverDrainContextV1 {
            binding: &connector,
            active: &active,
            witness: authority.append_witness(),
            ledger: runtime.ledger().as_ref(),
            control_scope: runtime.control_scope(),
            kek: &kek,
            clocks: &ObserverIngressClocksV1 { received_at },
        },
        &record,
    )
    .await
    .map_err(|error| anyhow!("observer append refused: {error}"))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&report(&record, Some(&outcome))?)?
    );
    Ok(())
}

/// What the worker prints. Deliberately includes the exhaustiveness verdict
/// and every diagnostic beside the outcome: a reader must be able to see why
/// an `indeterminate` is indeterminate without opening the ledger.
fn report(
    record: &ObserverRunRecordV1,
    outcome: Option<&ostk_fleet_recall::observer_runtime::ObserverRunOutcomeV1>,
) -> anyhow::Result<Value> {
    Ok(json!({
        "enum": record.enum_name.as_str(),
        "exhaustive": record.exhaustive,
        "members": record.members,
        "diagnostics": record
            .diagnostics
            .iter()
            .map(|id| id.as_str().to_owned())
            .collect::<Vec<_>>(),
        "run_outcome": format!("{:?}", record.receipt.outcome),
        "verification_outcome": format!("{:?}", record.verification_outcome()),
        "source_version": record.receipt.source_version.to_string(),
        "input_digest": record.receipt.input_digest.to_string(),
        "output_digest": record.receipt.output_digest.to_string(),
        "run_receipt_digest": record.receipt.digest()?.to_string(),
        "admission_digest": record.result.admission_digest.to_string(),
        "result_fingerprint": record.result.result_fingerprint()?.to_string(),
        "accepted_event": outcome
            .and_then(|outcome| outcome.accepted_event)
            .map(|event| event.to_string()),
        "disposition": outcome.map(|outcome| format!("{:?}", outcome.disposition)),
    }))
}

fn declaration(args: &AdmissionArgs) -> anyhow::Result<ObserverRuntimeDeclarationV1> {
    Ok(ObserverRuntimeDeclarationV1 {
        admission_id: ContractId::new(args.observer_id.clone())?,
        version: args.observer_version,
        observer_kind: ContractId::new(args.observer_kind.clone())?,
        executable_digest: parse_digest(&args.executable_digest, "--executable-digest")?,
        dependency_closure_pin: parse_digest(
            &args.dependency_closure_digest,
            "--dependency-closure-digest",
        )?,
        configuration_context_digest: parse_digest(
            &args.configuration_digest,
            "--configuration-digest",
        )?,
        mode: args.mode.to_contract(),
        predicate: RegistryReferenceV1 {
            entry_id: ContractId::new(args.predicate_entry.clone())?,
            version: args.predicate_version,
            entry_digest: parse_digest(&args.predicate_digest, "--predicate-digest")?,
        },
        input_domain: observer_input_domain()?,
        toolchain_versions: observer_toolchain_versions()?,
        coverage_receipt_recipe: RegistryReferenceV1 {
            entry_id: ContractId::new(args.coverage_recipe_entry.clone())?,
            version: args.coverage_recipe_version,
            entry_digest: parse_digest(&args.coverage_recipe_digest, "--coverage-recipe-digest")?,
        },
        positive_vector_digest: Sha256Digest::from_bytes(POSITIVE_VECTOR_DIGEST),
        negative_vector_digest: Sha256Digest::from_bytes(NEGATIVE_VECTOR_DIGEST),
        mutation_vector_digest: Sha256Digest::from_bytes(MUTATION_VECTOR_DIGEST),
        adversarial_vector_digest: Sha256Digest::from_bytes(ADVERSARIAL_VECTOR_DIGEST),
    })
}

fn read_genesis_package(
    path: &PathBuf,
    profile: &ProfileReferenceV1,
) -> anyhow::Result<SemanticallyClosedGenesisPackage> {
    let bytes = read_framed(path)?;
    let manifest = ManifestVerifiedRegistryPackage::decode(&bytes, profile)?;
    Ok(SemanticallyClosedGenesisPackage::from_manifest_verified(
        manifest,
    )?)
}

fn read_bootstrap(
    args: &InspectArgs,
    profile: &ProfileReferenceV1,
    genesis: &SemanticallyClosedGenesisPackage,
) -> anyhow::Result<ostk_fleet_recall::memory_contracts::bootstrap::VerifiedBootstrapReceipt> {
    use ostk_fleet_recall::memory_contracts::bootstrap::{
        BootstrapPin, BootstrapReceiptDigest, BootstrapReceiptV1, verify_pinned_bootstrap,
    };
    let bytes = read_framed(&args.bootstrap_receipt)?;
    // Decoded only to read its scope; the pin below is what makes it trusted.
    let receipt: BootstrapReceiptV1 = decode_strict(&bytes)?;
    let pin = BootstrapPin::from_trusted_config(BootstrapReceiptDigest::from_digest(parse_digest(
        &args.bootstrap_pin,
        "--bootstrap-pin",
    )?));
    Ok(verify_pinned_bootstrap(
        &bytes,
        pin,
        profile,
        &receipt.statement.scope,
        genesis,
    )?)
}

/// Read one canonical JSONL artifact and strip its single framing LF.
fn read_framed(path: &PathBuf) -> anyhow::Result<Vec<u8>> {
    let bytes =
        std::fs::read(path).with_context(|| format!("could not read {}", path.display()))?;
    let body = bytes
        .strip_suffix(b"\n")
        .ok_or_else(|| anyhow!("{} must end with exactly one LF", path.display()))?;
    if body.ends_with(b"\n") || body.contains(&b'\r') {
        return Err(anyhow!("{} is not canonical JSONL", path.display()));
    }
    Ok(body.to_vec())
}

fn parse_digest(value: &str, flag: &'static str) -> anyhow::Result<Sha256Digest> {
    value
        .parse()
        .map_err(|_| anyhow!("{flag} must be lowercase 64-character hex"))
}
