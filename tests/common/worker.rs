//! A memory-worker scope for a connected test: an installed generation-2
//! writer authority, a scratch git repository, a scratch transcript
//! directory, the recorded CI corpus, and a deterministic stub embedder, so a
//! real `MemoryWorker` tick can ingest, project, and embed all three
//! connectors.

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;

use ostk_fleet_recall::connectors::ci::scan::{
    RECORDED_BRANCH, RECORDED_REPOSITORY, RECORDED_WORKFLOW, recorded_provider,
};
use ostk_fleet_recall::connectors::ci::{CiRunProvider, CiScanResult};
use ostk_fleet_recall::control_log::TrustedControlScope;
use ostk_fleet_recall::coverage_runtime::CockroachCoverageRuntimeRepository;
use ostk_fleet_recall::memory_contracts::digest::Sha256Digest;
use ostk_fleet_recall::projectors::{ChunkEmbedderProvider, CockroachRecallReader};
use ostk_fleet_recall::store::cockroach::RetryPolicy;
use ostk_fleet_recall::worker::{
    CiProviderFactory, CiSourceV1, MemoryWorker, WorkerDeps, WorkerSourcesV1, parse_steps,
};
use ostk_recall_core::ChunkEmbedder;
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;

use super::authority::{InstalledAuthority, install_generation_two, retry_policy};

/// The provider-installation coordinate every source is configured with.
pub const INSTALLATION_ID: u64 = 4242;

pub const GIT_INSTANCE: &str = "connector.git.worker";
pub const CI_INSTANCE: &str = "connector.ci.worker";
pub const TRANSCRIPT_PREFIX: &str = "connector.transcript";

/// A word that occurs only in the scratch repository's second commit.
pub const COMMIT_WORD: &str = "zephyrine";
/// A word that occurs only in the scratch transcript's first turn.
pub const TRANSCRIPT_WORD: &str = "quillback";
/// The step that failed in the recorded CI corpus.
pub const FAILING_STEP_WORD: &str = "Mermaid";

/// Fixed past commit instants, so every scan of the scratch repository
/// renders byte-identical commit facts.
pub const FIRST_COMMIT_DATE: &str = "1755259200 +0000";
pub const SECOND_COMMIT_DATE: &str = "1755345600 +0000";

/// The model digest the stub embedder's dense rows record.
pub const STUB_MODEL_DIGEST: [u8; 32] = [0x5a; 32];

/// A bare scratch repository whose `refs/heads/main` has two commits.
pub struct ScratchRepository {
    directory: tempfile::TempDir,
}

impl ScratchRepository {
    pub fn with_two_commits() -> Self {
        let directory = tempfile::tempdir().expect("scratch repository directory");
        let status = Command::new("git")
            .args(["init", "--bare", "--quiet"])
            .arg(directory.path())
            .status()
            .expect("git must be on PATH for the memory worker proof");
        assert!(status.success(), "git init --bare must succeed");
        let repository = Self { directory };
        let first = repository.commit(None, "seed the worker fixture", FIRST_COMMIT_DATE);
        repository.commit(
            Some(&first),
            &format!("document the {COMMIT_WORD} cache eviction"),
            SECOND_COMMIT_DATE,
        );
        repository
    }

    pub fn path(&self) -> &Path {
        self.directory.path()
    }

    /// Commit `message` on top of `refs/heads/main` (or as a root commit when
    /// `parent` is `None` and main does not exist yet) at `date`, move main to
    /// it, and return its id.
    pub fn commit(&self, parent: Option<&str>, message: &str, date: &str) -> String {
        let readme = self.git(&["hash-object", "-w", "--stdin"], Some(b"worker\n"), None);
        let tree = self.git(
            &["mktree"],
            Some(format!("100644 blob {readme}\tREADME.md\n").as_bytes()),
            None,
        );
        let mut args = vec!["commit-tree", tree.as_str(), "-m", message];
        if let Some(parent) = parent {
            args.extend(["-p", parent]);
        }
        let commit = self.git(&args, None, Some(date));
        self.git(&["update-ref", "refs/heads/main", &commit], None, None);
        commit
    }

    /// The commit `refs/heads/main` names.
    pub fn head(&self) -> String {
        self.git(&["rev-parse", "refs/heads/main"], None, None)
    }

    pub fn git(&self, args: &[&str], stdin: Option<&[u8]>, date: Option<&str>) -> String {
        let date = date.unwrap_or(FIRST_COMMIT_DATE);
        let mut child = Command::new("git")
            .arg(format!("--git-dir={}", self.directory.path().display()))
            .args(args)
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_SYSTEM", "/dev/null")
            .env("GIT_AUTHOR_NAME", "Worker Fixture")
            .env("GIT_AUTHOR_EMAIL", "worker@example.invalid")
            .env("GIT_AUTHOR_DATE", date)
            .env("GIT_COMMITTER_NAME", "Worker Fixture")
            .env("GIT_COMMITTER_EMAIL", "worker@example.invalid")
            .env("GIT_COMMITTER_DATE", date)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("git must spawn");
        if let Some(bytes) = stdin {
            child
                .stdin
                .as_mut()
                .expect("piped stdin")
                .write_all(bytes)
                .expect("git stdin");
        }
        let output = child.wait_with_output().expect("git must finish");
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("plumbing output is ASCII")
            .trim()
            .to_owned()
    }
}

const SESSION: &str = "0f3a8c5e-worker-session";

/// One transcript JSONL line.
pub fn line(kind: &str, uid: &str, timestamp: &str, text: &str) -> String {
    format!(
        r#"{{"type":"{kind}","sessionId":"{SESSION}","uuid":"{uid}","timestamp":"{timestamp}","message":{{"role":"{kind}","content":[{{"type":"text","text":{}}}]}}}}"#,
        serde_json::to_string(text).unwrap()
    )
}

pub fn first_turn_text() -> String {
    format!("why does the {TRANSCRIPT_WORD} importer drop rows")
}

/// A transcript line of a record type the parser refuses.
pub const BROKEN_TRANSCRIPT_LINE: &str = r#"{"type":"telemetry-burst","sessionId":"s","uuid":"u","timestamp":"2026-08-15T12:30:00.000Z"}"#;

/// A scratch transcript directory.
///
/// `session.jsonl` holds two turns. `session-resumed.jsonl` repeats the first
/// turn exactly as a resumed session file does, but with its own timestamp:
/// the line differs, so the turn is a second source fact, while its redacted
/// body is byte-identical, so its append deduplicates onto the governed
/// content object the first file already wrote.
pub fn transcript_directory() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("transcript directory");
    let first = line(
        "user",
        "turn-1",
        "2026-08-15T12:30:00.000Z",
        &first_turn_text(),
    );
    std::fs::write(
        directory.path().join("session.jsonl"),
        format!(
            "{first}\n{}\n",
            line(
                "assistant",
                "turn-2",
                "2026-08-15T12:30:01.000Z",
                "the importer skips rows whose checksum collides"
            )
        ),
    )
    .unwrap();
    std::fs::write(
        directory.path().join("session-resumed.jsonl"),
        format!(
            "{}\n",
            line(
                "user",
                "turn-1",
                "2026-08-16T09:00:00.000Z",
                &first_turn_text()
            )
        ),
    )
    .unwrap();
    directory
}

/// The recorded CI corpus, settled through run 8.
pub struct RecordedCi;

impl CiProviderFactory for RecordedCi {
    fn provider(
        &self,
        _source: &CiSourceV1,
    ) -> CiScanResult<Option<(Box<dyn CiRunProvider>, u64)>> {
        Ok(Some((Box::new(recorded_provider()), 8)))
    }
}

/// A deterministic 512-component embedder with no zero component.
pub struct StubEmbedder;

impl ChunkEmbedder for StubEmbedder {
    fn dim(&self) -> usize {
        512
    }

    fn model_id(&self) -> &'static str {
        "stub-model2vec-512"
    }

    fn encode_batch(&self, texts: &[&str]) -> Vec<Vec<f32>> {
        texts
            .iter()
            .map(|text| {
                let seed = Sha256::digest(text.as_bytes());
                (0..512)
                    .map(|index| f32::from(seed[index % seed.len()]) - 127.5)
                    .collect()
            })
            .collect()
    }
}

/// One installed scope and the sources a worker runs for it.
pub struct WorkerFixture {
    pub installed: InstalledAuthority,
    pub repository: ScratchRepository,
    pub transcripts: tempfile::TempDir,
}

impl WorkerFixture {
    pub async fn install(pool: &PgPool, label: &str) -> Self {
        Self {
            installed: install_generation_two(pool, label).await,
            repository: ScratchRepository::with_two_commits(),
            transcripts: transcript_directory(),
        }
    }

    pub fn sources(&self) -> WorkerSourcesV1 {
        WorkerSourcesV1::from_json_slice(&serde_json::to_vec(&self.sources_json()).unwrap())
            .expect("the fixture sources file is valid")
    }

    /// The sources file, as an operator would write it.
    pub fn sources_json(&self) -> serde_json::Value {
        serde_json::json!({
                "schema_version": 1,
                "coverage_since": "2026-08-01T00:00:00Z",
                "git": [{
                    "connector_principal": "connector.git",
                    "connector_instance": GIT_INSTANCE,
                    "installation_id": INSTALLATION_ID,
                    "repository_id": "git.repo.worker",
                    "git_dir": self.repository.path(),
                    "ref_name": "refs/heads/main"
                }],
                "transcripts": [{
                    "connector_principal": "connector.transcript",
                    "instance_prefix": TRANSCRIPT_PREFIX,
                    "installation_id": INSTALLATION_ID,
                    "dirs": [self.transcripts.path()]
                }],
                "ci": [{
                    "connector_principal": "connector.ci",
                    "connector_instance": CI_INSTANCE,
                    "installation_id": INSTALLATION_ID,
                    "repository_id": "ci.repo.worker",
                    "provider_repository": RECORDED_REPOSITORY,
                    "workflow": RECORDED_WORKFLOW,
                    "branch": RECORDED_BRANCH
                }]
        })
    }

    /// A worker running `steps` over `pool` (the owner, or a probe login).
    pub async fn worker(&self, pool: &PgPool, steps: &str) -> MemoryWorker {
        let embedding = ChunkEmbedderProvider::new(
            Arc::new(StubEmbedder),
            Sha256Digest::from_bytes(STUB_MODEL_DIGEST),
        )
        .expect("the stub embedder is 512 wide");
        MemoryWorker::new(
            WorkerDeps {
                pool: pool.clone(),
                scope: self.installed.scope.clone(),
                authority: Some(self.installed.runtime(pool).await),
                sources: self.sources(),
                embedding: Some(Arc::new(embedding)),
                ci_providers: Arc::new(RecordedCi),
                retry: retry_policy(),
            },
            parse_steps(steps).unwrap(),
            Some(self.installed.kek()),
            Some(self.installed.kek()),
        )
        .expect("every selected step has its inputs")
    }

    pub fn coverage(&self, pool: &PgPool) -> CockroachCoverageRuntimeRepository {
        CockroachCoverageRuntimeRepository::new(
            pool.clone(),
            TrustedControlScope::from_trusted_context(
                &self.installed.scope,
                self.installed.semantic_scope.clone(),
            )
            .unwrap(),
            RetryPolicy::default(),
        )
    }

    pub fn reader(&self, pool: &PgPool) -> CockroachRecallReader {
        CockroachRecallReader::new(
            pool.clone(),
            self.installed.scope.tenant_id,
            self.installed.scope.project.clone(),
        )
    }
}
