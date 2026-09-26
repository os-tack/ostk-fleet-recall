//! The worker's sources file: which connector instances one scope runs.
//!
//! `WorkerSourcesV1` is operator configuration, read once when the worker
//! starts. It names every source the worker ingests, one connector instance
//! per source, so each source owns its own coverage domains, its own resume
//! cursor, and its own row in `memory_worker_sources_v1`:
//!
//! * **git** — one instance per `(repository, ref)`. Commit facts only
//!   (`GitTreeScanModeV1::CommitsOnly`); blob-source facts are not rendered.
//! * **transcripts** — one group per directory set. Every `*.jsonl` file
//!   directly inside a listed directory (not recursively) is one source and one
//!   instance, `<instance_prefix>.<sanitized file stem>`
//!   ([`transcript_instance_id`]).
//! * **ci** — one instance per `(provider repository, workflow, branch)`.
//! * **collectors** — one instance per provider scope (a Slack workspace, a
//!   Linear organization, a documents root): the provider, the pinned scope,
//!   the audience the operator declares, and the provider's own settings
//!   (ADR 0008). The provider's adapter ([`crate::collectors::ADAPTERS`])
//!   validates its settings, which are closed, and the audience policy it
//!   needs, when the file is loaded; the worker's `collect` step runs each
//!   collector's pass. A provider this build has no adapter for is accepted
//!   here and reported as a failed source at tick time. Settings name
//!   credentials by environment variable, never inline: a secret-shaped
//!   value, or an inline value under a credential-named key, is refused.
//! * **observer** — the identity `ostk-spec check` appends observer runs under.
//!   The worker does not read it.
//!
//! Relative paths resolve against the worker's working directory.
//!
//! Nothing here is authority. Admission still resolves every connector schema,
//! identity recipe, and governance decision from the active package; a sources
//! file can only choose which provider material is offered to it.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::collectors::audience::AudiencePolicyV1;
use crate::collectors::redaction::scan_collected_secrets;
use crate::connectors::ci::{CiRepositoryIdV1, CiScanRequestV1};
use crate::connectors::git::{GitRefName, GitRepositoryIdV1};
use crate::connectors::transcript::MAX_TRANSCRIPT_BYTES;
use crate::error::{FleetError, Result};
use crate::memory_contracts::collected_item::{BoundedTextV1, MAX_SCOPE_ID_BYTES, ProviderKindV1};
use crate::memory_contracts::common::{CanonicalTimestamp, ContractId};

/// The only `schema_version` a sources file may declare.
pub const WORKER_SOURCES_SCHEMA_VERSION: u32 = 1;

/// Start of every coverage window the worker opens, unless the file says
/// otherwise.
pub const DEFAULT_COVERAGE_SINCE: &str = "2026-01-01T00:00:00Z";

/// How long a completed check stays current, unless the file or the source
/// says otherwise (one day).
pub const DEFAULT_STALE_AFTER_SECONDS: u64 = 86_400;

/// Bounds migration 0030 puts on `stale_after_seconds`: one minute to one
/// year.
pub const MIN_STALE_AFTER_SECONDS: u64 = 60;
pub const MAX_STALE_AFTER_SECONDS: u64 = 31_536_000;

/// Instance-id prefix of a transcript group that names none.
pub const DEFAULT_TRANSCRIPT_INSTANCE_PREFIX: &str = "connector.transcript";

/// Bytes of one transcript file collected per window (4 MiB).
pub const DEFAULT_TRANSCRIPT_WINDOW_BYTES: usize = 4 * 1024 * 1024;

/// Bounds of one git scan: commits walked and facts rendered.
pub const DEFAULT_GIT_MAX_COMMITS: usize = 5_000;
pub const DEFAULT_GIT_MAX_FACTS: usize = 20_000;

/// Longest connector instance id a coverage cursor or status row accepts.
const MAX_INSTANCE_ID_BYTES: usize = 128;

/// Hex characters of the file-name digest a too-long transcript instance id
/// falls back to.
const INSTANCE_DIGEST_HEX_CHARS: usize = 16;

/// Longest instance prefix that still leaves room for the digest fallback
/// (`<prefix>.<16 hex>`).
const MAX_INSTANCE_PREFIX_BYTES: usize = MAX_INSTANCE_ID_BYTES - 1 - INSTANCE_DIGEST_HEX_CHARS;

fn default_coverage_since() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(DEFAULT_COVERAGE_SINCE)
        .map(|value| value.with_timezone(&Utc))
        .unwrap_or_default()
}

const fn default_stale_after_seconds() -> u64 {
    DEFAULT_STALE_AFTER_SECONDS
}

fn default_transcript_instance_prefix() -> ContractId {
    ContractId::new(DEFAULT_TRANSCRIPT_INSTANCE_PREFIX)
        .unwrap_or_else(|_| unreachable!("the default transcript prefix is a contract id"))
}

const fn default_transcript_window_bytes() -> usize {
    DEFAULT_TRANSCRIPT_WINDOW_BYTES
}

const fn default_git_max_commits() -> usize {
    DEFAULT_GIT_MAX_COMMITS
}

const fn default_git_max_facts() -> usize {
    DEFAULT_GIT_MAX_FACTS
}

const fn default_first_run_number() -> u64 {
    1
}

/// Every source one worker runs for one `(tenant_id, project)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerSourcesV1 {
    /// Always [`WORKER_SOURCES_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Start of every coverage window this worker opens. A receipt covers
    /// `[coverage_since, tick time)`.
    #[serde(default = "default_coverage_since")]
    pub coverage_since: DateTime<Utc>,
    /// Default staleness bound for every source that names none.
    #[serde(default = "default_stale_after_seconds")]
    pub stale_after_seconds: u64,
    #[serde(default)]
    pub git: Vec<GitSourceV1>,
    #[serde(default)]
    pub transcripts: Vec<TranscriptSourceGroupV1>,
    #[serde(default)]
    pub ci: Vec<CiSourceV1>,
    /// Collector instances (ADR 0008).
    #[serde(default)]
    pub collectors: Vec<CollectorSourceV1>,
    /// Read by `ostk-spec check`, never by the worker.
    #[serde(default)]
    pub observer: Option<ObserverSourceV1>,
}

/// One git repository and ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GitSourceV1 {
    /// Authenticated ingress principal the facts are delivered as.
    pub connector_principal: ContractId,
    /// This source's connector instance: its coverage domains and status row.
    pub connector_instance: ContractId,
    /// Provider-installation coordinate the identity recipes hash.
    pub installation_id: u64,
    /// Operator-declared repository identity every fact carries.
    pub repository_id: ContractId,
    /// The repository's git directory (a bare repository or a `.git`).
    pub git_dir: PathBuf,
    /// The fully qualified ref to observe, e.g. `refs/heads/main`.
    pub ref_name: String,
    #[serde(default = "default_git_max_commits")]
    pub max_commits: usize,
    #[serde(default = "default_git_max_facts")]
    pub max_facts: usize,
    /// The provider's numeric repository id, for `ostk-spec`. The worker does
    /// not read it.
    #[serde(default)]
    pub provider_repository_id: Option<u64>,
    #[serde(default)]
    pub stale_after_seconds: Option<u64>,
}

/// A set of transcript directories sharing one principal and prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptSourceGroupV1 {
    pub connector_principal: ContractId,
    /// Every file's instance id is `<instance_prefix>.<sanitized stem>`.
    #[serde(default = "default_transcript_instance_prefix")]
    pub instance_prefix: ContractId,
    pub installation_id: u64,
    /// Directories whose `*.jsonl` files are sources. Not recursive.
    pub dirs: Vec<PathBuf>,
    /// Bytes collected per window of one file.
    #[serde(default = "default_transcript_window_bytes")]
    pub window_bytes: usize,
    #[serde(default)]
    pub stale_after_seconds: Option<u64>,
}

/// One CI workflow on one branch of one provider repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CiSourceV1 {
    pub connector_principal: ContractId,
    pub connector_instance: ContractId,
    pub installation_id: u64,
    /// Operator-declared repository identity every fact carries.
    pub repository_id: ContractId,
    /// `owner/name`, as `gh --repo` takes it.
    pub provider_repository: String,
    /// Workflow file name, e.g. `ci.yml`.
    pub workflow: String,
    pub branch: String,
    /// The first run number this source ever reads.
    #[serde(default = "default_first_run_number")]
    pub first_run_number: u64,
    #[serde(default)]
    pub stale_after_seconds: Option<u64>,
}

/// One collector instance: one provider scope, read by one provider adapter
/// (ADR 0008).
///
/// The provider is data (`docs`, `slack`, `linear`, `granola`, and any later
/// one), so a new provider needs no registry change. `settings` belong to the
/// provider's adapter, which validates them; this file only refuses a
/// credential written inline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorSourceV1 {
    /// The provider kind.
    pub provider: ProviderKindV1,
    /// Authenticated ingress principal the items are delivered as.
    pub connector_principal: ContractId,
    /// This collector's instance: its outbox rows, cursors, status row, and
    /// coverage domains.
    pub connector_instance: ContractId,
    /// The operator-pinned provider scope: a Slack `team_id`, a Linear
    /// organization id, a Granola workspace pin, a documents root id.
    pub provider_scope_id: BoundedTextV1<MAX_SCOPE_ID_BYTES>,
    /// What the operator declares visible to the whole project.
    #[serde(default)]
    pub audience: AudiencePolicyV1,
    /// The provider adapter's settings.
    #[serde(default)]
    pub settings: serde_json::Map<String, serde_json::Value>,
    #[serde(default)]
    pub stale_after_seconds: Option<u64>,
}

/// Settings keys that name a credential; their value must be the name of an
/// environment variable, under a key ending in `_env`.
const CREDENTIAL_KEY_SUFFIXES: [&str; 6] = [
    "token",
    "secret",
    "password",
    "api_key",
    "apikey",
    "credential",
];

impl CollectorSourceV1 {
    fn validate(&self) -> Result<()> {
        let instance = &self.connector_instance;
        if !scan_collected_secrets(self.provider_scope_id.as_str()).is_empty() {
            return Err(invalid(&format!(
                "collector {instance}: provider_scope_id holds a secret shape"
            )));
        }
        for container in &self.audience.private_containers {
            if container.is_empty() || !scan_collected_secrets(container).is_empty() {
                return Err(invalid(&format!(
                    "collector {instance}: a private container id is empty or secret-shaped"
                )));
            }
        }
        refuse_inline_credentials(instance, "settings", &self.settings)?;
        if let Some(adapter) = crate::collectors::adapter(self.provider.as_str()) {
            adapter
                .validate(self)
                .map_err(|message| invalid(&format!("collector {instance}: {message}")))?;
        }
        validate_stale_after(
            &format!("collector {instance} stale_after_seconds"),
            self.stale_after_seconds
                .unwrap_or(DEFAULT_STALE_AFTER_SECONDS),
        )
    }
}

/// Refuse a credential written into the sources file: any secret-shaped
/// string, and any inline string under a credential-named key.
fn refuse_inline_credentials(
    instance: &ContractId,
    path: &str,
    settings: &serde_json::Map<String, serde_json::Value>,
) -> Result<()> {
    for (key, value) in settings {
        let field = format!("{path}.{key}");
        let lowered = key.to_ascii_lowercase();
        if value.is_string()
            && !lowered.ends_with("_env")
            && CREDENTIAL_KEY_SUFFIXES
                .iter()
                .any(|suffix| lowered.ends_with(suffix))
        {
            return Err(invalid(&format!(
                "collector {instance}: {field} holds a credential inline; name an environment \
                 variable under {key}_env instead"
            )));
        }
        refuse_secret_values(instance, &field, value)?;
    }
    Ok(())
}

fn refuse_secret_values(
    instance: &ContractId,
    field: &str,
    value: &serde_json::Value,
) -> Result<()> {
    match value {
        serde_json::Value::String(text) if !scan_collected_secrets(text).is_empty() => {
            Err(invalid(&format!(
                "collector {instance}: {field} holds a secret-shaped value"
            )))
        }
        serde_json::Value::Array(values) => values
            .iter()
            .try_for_each(|value| refuse_secret_values(instance, field, value)),
        serde_json::Value::Object(map) => refuse_inline_credentials(instance, field, map),
        _ => Ok(()),
    }
}

/// The identity observer runs are appended under (`ostk-spec check`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObserverSourceV1 {
    pub connector_principal: ContractId,
    pub connector_instance: ContractId,
}

impl WorkerSourcesV1 {
    /// Parse and validate one sources file's bytes.
    ///
    /// # Errors
    ///
    /// [`FleetError::Configuration`] for malformed JSON, an unknown field, or
    /// anything [`Self::validate`] refuses.
    pub fn from_json_slice(bytes: &[u8]) -> Result<Self> {
        let sources: Self = serde_json::from_slice(bytes).map_err(|error| {
            FleetError::Configuration(format!("worker sources file is invalid: {error}"))
        })?;
        sources.validate()?;
        Ok(sources)
    }

    /// Read, parse, and validate the sources file at `path`.
    ///
    /// # Errors
    ///
    /// [`FleetError::Configuration`] when the file cannot be read, or as
    /// [`Self::from_json_slice`].
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).map_err(|error| {
            FleetError::Configuration(format!(
                "worker sources file {} cannot be read: {error}",
                path.display()
            ))
        })?;
        Self::from_json_slice(&bytes)
    }

    /// Refuse a file the worker could not run exactly as written.
    ///
    /// Contract ids are already validated by deserialization. This checks the
    /// schema version, the coverage start, every staleness bound, every scan
    /// bound, every git ref and CI coordinate, and that no two configured
    /// sources share a connector instance (a transcript prefix counts as the
    /// instances it can derive, and collectors count), and that no collector
    /// writes a credential inline. Transcript file names are only known at tick
    /// time, so a collision between two files is refused then, per file.
    ///
    /// # Errors
    ///
    /// [`FleetError::Configuration`] naming the first offending value.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != WORKER_SOURCES_SCHEMA_VERSION {
            return Err(invalid(&format!(
                "schema_version must be {WORKER_SOURCES_SCHEMA_VERSION}, not {}",
                self.schema_version
            )));
        }
        self.coverage_since_timestamp()?;
        validate_stale_after("stale_after_seconds", self.stale_after_seconds)?;
        let mut instances = BTreeSet::new();
        let mut claim = |instance: &ContractId, owner: &str| {
            if instances.insert(instance.as_str().to_owned()) {
                Ok(())
            } else {
                Err(invalid(&format!(
                    "connector instance {instance} is configured twice ({owner})"
                )))
            }
        };
        for source in &self.git {
            source.validate()?;
            claim(&source.connector_instance, "git")?;
        }
        for source in &self.ci {
            source.validate()?;
            claim(&source.connector_instance, "ci")?;
        }
        let mut scopes = BTreeSet::new();
        for source in &self.collectors {
            source.validate()?;
            if let Some(every) = crate::collectors::adapter(source.provider.as_str())
                .and_then(|adapter| adapter.reconcile_every_seconds(source))
            {
                let stale_after = self.stale_after(source.stale_after_seconds);
                if stale_after < every {
                    return Err(invalid(&format!(
                        "collector {}: stale_after_seconds ({stale_after}) is shorter than its \
                         reconcile interval ({every} s), so it would read as stale between \
                         reconciliations",
                        source.connector_instance
                    )));
                }
            }
            claim(&source.connector_instance, "collector")?;
            // One instance per provider scope: two would each see the other's
            // items as missing from their own reads.
            if !scopes.insert((source.provider.as_str(), source.provider_scope_id.as_str())) {
                return Err(invalid(&format!(
                    "collector {}: another collector already reads {} scope {}",
                    source.connector_instance, source.provider, source.provider_scope_id
                )));
            }
        }
        if let Some(observer) = &self.observer {
            claim(&observer.connector_instance, "observer")?;
        }
        let mut dirs = BTreeSet::new();
        for group in &self.transcripts {
            group.validate()?;
            for dir in &group.dirs {
                if !dirs.insert(dir.clone()) {
                    return Err(invalid(&format!(
                        "transcript directory {} is listed twice",
                        dir.display()
                    )));
                }
            }
        }
        for instance in &instances {
            for group in &self.transcripts {
                if instance
                    .strip_prefix(group.instance_prefix.as_str())
                    .is_some_and(|rest| rest.starts_with('.'))
                {
                    return Err(invalid(&format!(
                        "connector instance {instance} lies under the transcript prefix {}",
                        group.instance_prefix
                    )));
                }
            }
        }
        Ok(())
    }

    /// [`Self::coverage_since`] in contract wire form.
    ///
    /// # Errors
    ///
    /// [`FleetError::Configuration`] for an instant `CockroachDB` cannot store
    /// exactly (finer than a microsecond).
    pub fn coverage_since_timestamp(&self) -> Result<CanonicalTimestamp> {
        let timestamp = CanonicalTimestamp::parse(
            self.coverage_since
                .to_rfc3339_opts(SecondsFormat::Nanos, true),
        )
        .map_err(|error| invalid(&format!("coverage_since is not a UTC instant: {error}")))?;
        if !timestamp.is_microsecond_aligned() {
            return Err(invalid(
                "coverage_since must be a whole number of microseconds",
            ));
        }
        Ok(timestamp)
    }

    /// Every configured connector instance that is not a transcript file:
    /// git, then CI.
    pub fn static_instances(&self) -> impl Iterator<Item = &ContractId> {
        self.git
            .iter()
            .map(|source| &source.connector_instance)
            .chain(self.ci.iter().map(|source| &source.connector_instance))
    }

    /// The staleness bound of a source that names `own`.
    #[must_use]
    pub fn stale_after(&self, own: Option<u64>) -> u64 {
        own.unwrap_or(self.stale_after_seconds)
    }
}

impl GitSourceV1 {
    /// The repository identity every fact of this source carries.
    ///
    /// # Errors
    ///
    /// [`FleetError::Configuration`] when the identity does not validate.
    pub fn repository(&self) -> Result<GitRepositoryIdV1> {
        GitRepositoryIdV1::from_trusted_config(self.repository_id.clone(), self.installation_id)
            .map_err(|error| invalid(&format!("git source {}: {error}", self.connector_instance)))
    }

    /// The configured ref.
    ///
    /// # Errors
    ///
    /// [`FleetError::Configuration`] for a ref that is not fully qualified.
    pub fn ref_name(&self) -> Result<GitRefName> {
        GitRefName::parse(&self.ref_name).map_err(|error| {
            invalid(&format!(
                "git source {}: ref_name {:?}: {error}",
                self.connector_instance, self.ref_name
            ))
        })
    }

    fn validate(&self) -> Result<()> {
        self.repository()?;
        self.ref_name()?;
        if self.max_commits == 0 || self.max_facts == 0 {
            return Err(invalid(&format!(
                "git source {}: max_commits and max_facts must be positive",
                self.connector_instance
            )));
        }
        if self.git_dir.as_os_str().is_empty() {
            return Err(invalid(&format!(
                "git source {}: git_dir is empty",
                self.connector_instance
            )));
        }
        validate_stale_after(
            &format!("git source {} stale_after_seconds", self.connector_instance),
            self.stale_after_seconds
                .unwrap_or(DEFAULT_STALE_AFTER_SECONDS),
        )
    }
}

impl TranscriptSourceGroupV1 {
    fn validate(&self) -> Result<()> {
        let prefix = self.instance_prefix.as_str();
        if prefix.len() > MAX_INSTANCE_PREFIX_BYTES {
            return Err(invalid(&format!(
                "transcript instance_prefix {prefix} is longer than {MAX_INSTANCE_PREFIX_BYTES} bytes"
            )));
        }
        if self.dirs.is_empty() {
            return Err(invalid(&format!(
                "transcript group {prefix} lists no directory"
            )));
        }
        if self.window_bytes == 0 || self.window_bytes > MAX_TRANSCRIPT_BYTES {
            return Err(invalid(&format!(
                "transcript group {prefix}: window_bytes must be between 1 and {MAX_TRANSCRIPT_BYTES}"
            )));
        }
        validate_stale_after(
            &format!("transcript group {prefix} stale_after_seconds"),
            self.stale_after_seconds
                .unwrap_or(DEFAULT_STALE_AFTER_SECONDS),
        )
    }
}

impl CiSourceV1 {
    /// The repository identity every fact of this source carries.
    ///
    /// # Errors
    ///
    /// [`FleetError::Configuration`] when the identity does not validate.
    pub fn repository(&self) -> Result<CiRepositoryIdV1> {
        CiRepositoryIdV1::from_trusted_config(self.repository_id.clone(), self.installation_id)
            .map_err(|error| invalid(&format!("ci source {}: {error}", self.connector_instance)))
    }

    /// The scan request for runs `first..=last` of this source.
    ///
    /// # Errors
    ///
    /// [`FleetError::Configuration`] for an identity that does not validate.
    pub fn scan_request(&self, first: u64, last: u64) -> Result<CiScanRequestV1> {
        Ok(CiScanRequestV1 {
            repository: self.repository()?,
            provider_repository: self.provider_repository.clone(),
            workflow_file: self.workflow.clone(),
            branch: self.branch.clone(),
            first_run_number: first,
            last_run_number: last,
        })
    }

    fn validate(&self) -> Result<()> {
        if self.first_run_number == 0 {
            return Err(invalid(&format!(
                "ci source {}: first_run_number must be positive",
                self.connector_instance
            )));
        }
        // The scan request's own checks keep a hostile coordinate out of argv.
        self.scan_request(self.first_run_number, self.first_run_number)?
            .validate()
            .map_err(|error| invalid(&format!("ci source {}: {error}", self.connector_instance)))?;
        validate_stale_after(
            &format!("ci source {} stale_after_seconds", self.connector_instance),
            self.stale_after_seconds
                .unwrap_or(DEFAULT_STALE_AFTER_SECONDS),
        )
    }
}

/// The connector instance of one transcript file.
///
/// `<prefix>.<stem>`, where the stem is the file name without its `.jsonl`
/// extension, lowercased, with every character a contract id does not allow
/// replaced by `-`. When that is longer than 128 bytes, or the stem is empty,
/// it is `<prefix>.<first 16 hex characters of sha256(file name)>` instead.
///
/// # Errors
///
/// [`FleetError::Configuration`] when even the fallback is not a contract id,
/// which [`WorkerSourcesV1::validate`] rules out for a validated prefix.
pub fn transcript_instance_id(prefix: &ContractId, file_name: &str) -> Result<ContractId> {
    let stem = file_name.strip_suffix(".jsonl").unwrap_or(file_name);
    let sanitized: String = stem
        .chars()
        .map(|character| {
            let lowered = character.to_ascii_lowercase();
            if lowered.is_ascii_lowercase()
                || lowered.is_ascii_digit()
                || matches!(lowered, '_' | '-' | '.')
            {
                lowered
            } else {
                '-'
            }
        })
        .collect();
    let direct = format!("{prefix}.{sanitized}");
    if !sanitized.is_empty()
        && direct.len() <= MAX_INSTANCE_ID_BYTES
        && let Ok(instance) = ContractId::new(direct)
    {
        return Ok(instance);
    }
    let digest = hex::encode(Sha256::digest(file_name.as_bytes()));
    ContractId::new(format!("{prefix}.{}", &digest[..INSTANCE_DIGEST_HEX_CHARS]))
        .map_err(|error| invalid(&format!("transcript instance for {file_name:?}: {error}")))
}

fn validate_stale_after(field: &str, value: u64) -> Result<()> {
    if (MIN_STALE_AFTER_SECONDS..=MAX_STALE_AFTER_SECONDS).contains(&value) {
        Ok(())
    } else {
        Err(invalid(&format!(
            "{field} must be between {MIN_STALE_AFTER_SECONDS} and {MAX_STALE_AFTER_SECONDS}, not {value}"
        )))
    }
}

fn invalid(message: &str) -> FleetError {
    FleetError::Configuration(format!("worker sources: {message}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal() -> serde_json::Value {
        serde_json::json!({
            "schema_version": 1,
            "git": [{
                "connector_principal": "connector.git",
                "connector_instance": "connector.git.main",
                "installation_id": 4242,
                "repository_id": "git.repo.main",
                "git_dir": "/srv/repo.git",
                "ref_name": "refs/heads/main"
            }],
            "transcripts": [{
                "connector_principal": "connector.transcript",
                "installation_id": 4242,
                "dirs": ["/srv/transcripts"]
            }],
            "ci": [{
                "connector_principal": "connector.ci",
                "connector_instance": "connector.ci.main",
                "installation_id": 4242,
                "repository_id": "ci.repo.main",
                "provider_repository": "owner/name",
                "workflow": "ci.yml",
                "branch": "main"
            }]
        })
    }

    fn parse(value: &serde_json::Value) -> Result<WorkerSourcesV1> {
        WorkerSourcesV1::from_json_slice(&serde_json::to_vec(value).unwrap())
    }

    fn refusal(value: &serde_json::Value) -> String {
        match parse(value) {
            Err(FleetError::Configuration(message)) => message,
            other => panic!("expected a configuration refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_minimal_file_takes_every_default() {
        let sources = parse(&minimal()).expect("the minimal file is valid");
        assert_eq!(
            sources.coverage_since_timestamp().unwrap().as_str(),
            "2026-01-01T00:00:00.000000000Z"
        );
        assert_eq!(sources.stale_after_seconds, DEFAULT_STALE_AFTER_SECONDS);
        assert_eq!(sources.git[0].max_commits, DEFAULT_GIT_MAX_COMMITS);
        assert_eq!(sources.git[0].max_facts, DEFAULT_GIT_MAX_FACTS);
        assert_eq!(sources.git[0].provider_repository_id, None);
        assert_eq!(
            sources.transcripts[0].instance_prefix.as_str(),
            DEFAULT_TRANSCRIPT_INSTANCE_PREFIX
        );
        assert_eq!(
            sources.transcripts[0].window_bytes,
            DEFAULT_TRANSCRIPT_WINDOW_BYTES
        );
        assert_eq!(sources.ci[0].first_run_number, 1);
        assert_eq!(sources.observer, None);
        assert_eq!(sources.stale_after(None), DEFAULT_STALE_AFTER_SECONDS);
        assert_eq!(sources.stale_after(Some(120)), 120);
    }

    #[test]
    fn an_unknown_field_or_schema_version_is_refused() {
        let mut value = minimal();
        value["retries"] = serde_json::json!(3);
        assert!(refusal(&value).contains("retries"));

        let mut value = minimal();
        value["git"][0]["tree_mode"] = serde_json::json!("changed_paths");
        assert!(refusal(&value).contains("tree_mode"));

        let mut value = minimal();
        value["schema_version"] = serde_json::json!(2);
        assert!(refusal(&value).contains("schema_version"));
    }

    #[test]
    fn a_bad_contract_id_ref_or_coordinate_is_refused() {
        let mut value = minimal();
        value["git"][0]["connector_instance"] = serde_json::json!("Connector.Git");
        assert!(refusal(&value).contains("Connector.Git"));

        let mut value = minimal();
        value["git"][0]["ref_name"] = serde_json::json!("main");
        assert!(refusal(&value).contains("ref_name"));

        let mut value = minimal();
        value["ci"][0]["provider_repository"] = serde_json::json!("--repo=evil");
        assert!(refusal(&value).contains("connector.ci.main"));

        let mut value = minimal();
        value["ci"][0]["first_run_number"] = serde_json::json!(0);
        assert!(refusal(&value).contains("first_run_number"));

        let mut value = minimal();
        value["git"][0]["max_commits"] = serde_json::json!(0);
        assert!(refusal(&value).contains("max_commits"));

        let mut value = minimal();
        value["transcripts"][0]["window_bytes"] = serde_json::json!(0);
        assert!(refusal(&value).contains("window_bytes"));

        let mut value = minimal();
        value["transcripts"][0]["dirs"] = serde_json::json!([]);
        assert!(refusal(&value).contains("no directory"));
    }

    #[test]
    fn a_staleness_bound_outside_the_table_check_is_refused() {
        let mut value = minimal();
        value["stale_after_seconds"] = serde_json::json!(59);
        assert!(refusal(&value).contains("stale_after_seconds"));

        let mut value = minimal();
        value["ci"][0]["stale_after_seconds"] = serde_json::json!(MAX_STALE_AFTER_SECONDS + 1);
        assert!(refusal(&value).contains("connector.ci.main"));
    }

    #[test]
    fn a_duplicate_instance_or_directory_is_refused() {
        let mut value = minimal();
        value["ci"][0]["connector_instance"] = serde_json::json!("connector.git.main");
        assert!(refusal(&value).contains("configured twice"));

        let mut value = minimal();
        value["observer"] = serde_json::json!({
            "connector_principal": "connector.observer",
            "connector_instance": "connector.ci.main"
        });
        assert!(refusal(&value).contains("configured twice"));

        let mut value = minimal();
        let group = value["transcripts"][0].clone();
        value["transcripts"].as_array_mut().unwrap().push(group);
        assert!(refusal(&value).contains("listed twice"));

        let mut value = minimal();
        value["git"][0]["connector_instance"] = serde_json::json!("connector.transcript.main");
        assert!(refusal(&value).contains("transcript prefix"));
    }

    #[test]
    fn a_sub_microsecond_coverage_start_is_refused() {
        let mut value = minimal();
        value["coverage_since"] = serde_json::json!("2026-01-01T00:00:00.000000001Z");
        assert!(refusal(&value).contains("microseconds"));

        let mut value = minimal();
        value["coverage_since"] = serde_json::json!("2026-03-01T12:00:00+02:00");
        assert_eq!(
            parse(&value)
                .unwrap()
                .coverage_since_timestamp()
                .unwrap()
                .as_str(),
            "2026-03-01T10:00:00.000000000Z"
        );
    }

    #[test]
    fn a_transcript_instance_is_the_sanitized_stem_under_the_prefix() {
        let prefix = ContractId::new("connector.transcript").unwrap();
        assert_eq!(
            transcript_instance_id(&prefix, "0f3a-Session_1.jsonl")
                .unwrap()
                .as_str(),
            "connector.transcript.0f3a-session_1"
        );
        assert_eq!(
            transcript_instance_id(&prefix, "notes from Monday!.jsonl")
                .unwrap()
                .as_str(),
            "connector.transcript.notes-from-monday-"
        );
    }

    #[test]
    fn a_too_long_or_empty_stem_falls_back_to_the_file_name_digest() {
        let prefix = ContractId::new("connector.transcript").unwrap();
        let long = format!("{}.jsonl", "a".repeat(200));
        let instance = transcript_instance_id(&prefix, &long).unwrap();
        let digest = hex::encode(Sha256::digest(long.as_bytes()));
        assert_eq!(
            instance.as_str(),
            format!("connector.transcript.{}", &digest[..16])
        );
        assert_ne!(
            transcript_instance_id(&prefix, &format!("{}.jsonl", "b".repeat(200))).unwrap(),
            instance,
            "the fallback still separates two files"
        );

        let empty = transcript_instance_id(&prefix, ".jsonl").unwrap();
        let digest = hex::encode(Sha256::digest(b".jsonl"));
        assert_eq!(
            empty.as_str(),
            format!("connector.transcript.{}", &digest[..16])
        );

        let longest_prefix = ContractId::new("p".repeat(MAX_INSTANCE_PREFIX_BYTES)).unwrap();
        let fallback = transcript_instance_id(&longest_prefix, &long).unwrap();
        assert_eq!(fallback.as_str().len(), MAX_INSTANCE_ID_BYTES);
    }

    fn with_collector(settings: &serde_json::Value) -> serde_json::Value {
        let mut value = minimal();
        value["collectors"] = serde_json::json!([{
            "provider": "slack",
            "connector_principal": "principal.slack",
            "connector_instance": "slack.acme",
            "provider_scope_id": "T07ACME0001",
            "audience": {"operator_declared": false, "private_containers": ["C07PRIVATE1"]},
            "settings": settings.clone()
        }]);
        value
    }

    /// Settings the Slack adapter accepts.
    fn slack() -> serde_json::Value {
        serde_json::json!({
            "token_env": "FLEET_RECALL_SLACK_BOT_TOKEN",
            "channels": ["C07PLATENG1", "C07PRIVATE1"]
        })
    }

    #[test]
    fn a_collector_parses_with_its_provider_scope_and_settings() {
        let sources = parse(&with_collector(&serde_json::json!({
            "token_env": "FLEET_RECALL_SLACK_BOT_TOKEN",
            "channels": ["C07PLATENG1"],
            "api_base": "https://slack.com/api"
        })))
        .expect("a collector with an env-named token is valid");
        let collector = &sources.collectors[0];
        assert_eq!(collector.provider.as_str(), "slack");
        assert_eq!(collector.provider_scope_id.as_str(), "T07ACME0001");
        assert_eq!(collector.audience.private_containers, ["C07PRIVATE1"]);
        assert_eq!(collector.settings["channels"][0], "C07PLATENG1");
        // A file with no collectors keeps parsing exactly as before.
        assert!(parse(&minimal()).unwrap().collectors.is_empty());
    }

    #[test]
    fn a_collector_credential_written_inline_is_refused() {
        let token = "xoxb-EXAMPLE-NOT-A-TOKEN";
        let message = refusal(&with_collector(&serde_json::json!({ "token": token })));
        assert!(message.contains("token_env"), "{message}");

        let message = refusal(&with_collector(&serde_json::json!({
            "headers": {"x-extra": token}
        })));
        assert!(message.contains("secret-shaped"), "{message}");
        assert!(
            !message.contains(token),
            "the refusal never repeats the value"
        );

        let message = refusal(&with_collector(&serde_json::json!({
            "channels": ["C07PLATENG1", token]
        })));
        assert!(message.contains("settings.channels"), "{message}");

        let message = refusal(&with_collector(
            &serde_json::json!({ "signing_secret": "hunter2" }),
        ));
        assert!(message.contains("signing_secret_env"), "{message}");
    }

    #[test]
    fn a_collector_instance_is_unique_across_every_connector() {
        let mut value = with_collector(&slack());
        value["collectors"][0]["connector_instance"] = serde_json::json!("connector.ci.main");
        assert!(refusal(&value).contains("configured twice"));

        let mut value = with_collector(&slack());
        value["collectors"][0]["connector_instance"] =
            serde_json::json!("connector.transcript.slack");
        assert!(refusal(&value).contains("transcript prefix"));

        let mut value = with_collector(&slack());
        value["collectors"][0]["provider"] = serde_json::json!("Slack");
        assert!(refusal(&value).contains("provider"));

        let mut value = with_collector(&slack());
        value["collectors"][0]["stale_after_seconds"] = serde_json::json!(30);
        assert!(refusal(&value).contains("slack.acme"));
    }

    #[test]
    fn one_provider_scope_has_one_collector() {
        let mut value = with_collector(&slack());
        let mut second = value["collectors"][0].clone();
        second["connector_instance"] = serde_json::json!("slack.acme.second");
        value["collectors"]
            .as_array_mut()
            .unwrap()
            .push(second.clone());
        assert!(refusal(&value).contains("already reads slack scope T07ACME0001"));

        second["provider_scope_id"] = serde_json::json!("T07OTHER001");
        value["collectors"][1] = second;
        assert_eq!(parse(&value).unwrap().collectors.len(), 2);
    }

    #[test]
    fn a_collector_is_never_stale_between_its_reconciliations() {
        let mut value = with_collector(&serde_json::json!({
            "token_env": "FLEET_RECALL_SLACK_BOT_TOKEN",
            "channels": ["C07PLATENG1"],
            "reconcile_every_seconds": 172_800
        }));
        let message = refusal(&value);
        assert!(message.contains("reconcile interval"), "{message}");
        value["collectors"][0]["stale_after_seconds"] = serde_json::json!(172_800);
        assert!(parse(&value).is_ok());
        value["collectors"][0]["settings"]["api_base"] =
            serde_json::json!("http://slack.example.com/api");
        assert!(refusal(&value).contains("not loopback"));
    }

    #[test]
    fn a_docs_collector_is_validated_by_its_adapter() {
        let docs = |settings: serde_json::Value, declared: bool| {
            let mut value = minimal();
            value["collectors"] = serde_json::json!([{
                "provider": "docs",
                "connector_principal": "principal.docs",
                "connector_instance": "docs.specs",
                "provider_scope_id": "specs",
                "audience": {"operator_declared": declared},
                "settings": settings
            }]);
            value
        };
        let sources = parse(&docs(
            serde_json::json!({"root": "/work/specs", "extensions": ["md"],
                               "max_file_bytes": 1_048_576, "max_files": 5_000}),
            true,
        ))
        .expect("a declared root with closed settings is valid");
        assert_eq!(sources.collectors[0].provider.as_str(), "docs");

        let message = refusal(&docs(serde_json::json!({"root": "/work/specs"}), false));
        assert!(message.contains("docs.specs"), "{message}");
        assert!(message.contains("operator_declared"), "{message}");
        let message = refusal(&docs(
            serde_json::json!({"root": "/work/specs", "recurse": false}),
            true,
        ));
        assert!(message.contains("recurse"), "{message}");
        let message = refusal(&docs(serde_json::json!({}), true));
        assert!(message.contains("root"), "{message}");
    }

    #[test]
    fn a_prefix_with_no_room_for_the_fallback_is_refused() {
        let mut value = minimal();
        value["transcripts"][0]["instance_prefix"] =
            serde_json::json!("p".repeat(MAX_INSTANCE_PREFIX_BYTES + 1));
        assert!(refusal(&value).contains("instance_prefix"));
    }
}
