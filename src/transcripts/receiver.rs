use crate::connectors::transcript::TranscriptFormat;
use rustix::fs::{self, Dir, FlockOperation, Mode, OFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::os::unix::fs::MetadataExt as _;
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
    sync::Arc,
};
use uuid::Uuid;

pub const MAX_WINDOW_BYTES: usize = 4 * 1024 * 1024;
const MAX_FILES: usize = 1024;

#[derive(Debug, thiserror::Error)]
pub enum TranscriptError {
    #[error("invalid_transcript_request")]
    Invalid,
    #[error("transcript_offset_conflict")]
    Conflict(u64),
    #[error("transcript_quota_exceeded")]
    Quota,
    #[error("transcript_spool_unavailable")]
    Io(#[from] std::io::Error),
}

impl From<rustix::io::Errno> for TranscriptError {
    fn from(error: rustix::io::Errno) -> Self {
        Self::Io(error.into())
    }
}

/// Constructed only after the remote backend verifies a sandbox-bound shipper grant.
#[derive(Debug, Clone)]
pub struct TranscriptAuthorization {
    pub tenant_id: Uuid,
    pub project: String,
    pub principal_id: Uuid,
    pub agent: String,
    pub sandbox_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptUpload {
    pub instance: String,
    pub file: String,
    pub source: String,
    pub format: TranscriptFormat,
    pub first_line_sha256: String,
    pub offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TranscriptProgress {
    pub length: u64,
    pub replayed: bool,
}

#[derive(Debug, Clone)]
pub struct TranscriptReceiverConfig {
    pub root: PathBuf,
    pub window_bytes: usize,
    pub max_file_bytes: u64,
    pub max_scope_bytes: u64,
}
impl TranscriptReceiverConfig {
    #[must_use]
    pub const fn new(root: PathBuf) -> Self {
        Self {
            root,
            window_bytes: MAX_WINDOW_BYTES,
            max_file_bytes: 64 * 1024 * 1024,
            max_scope_bytes: 1024 * 1024 * 1024,
        }
    }
}

pub struct TranscriptReceiver {
    config: TranscriptReceiverConfig,
    root: File,
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    tenant_id: Uuid,
    project: String,
    principal_id: Uuid,
    agent: String,
    sandbox_id: String,
    source: String,
    format: TranscriptFormat,
    first_line_sha256: String,
}

fn component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

pub(super) fn valid_source(source: &str) -> bool {
    !source.is_empty()
        && source.len() <= 1024
        && !source.contains('\\')
        && !source.chars().any(char::is_control)
        && Path::new(source)
            .components()
            .all(|part| matches!(part, Component::Normal(_)))
        && !source
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        && Path::new(source)
            .extension()
            .is_some_and(|extension| extension == "jsonl")
}

pub fn scope_spool_dir(
    root: &Path,
    tenant: Uuid,
    project: &str,
) -> Result<PathBuf, TranscriptError> {
    if !component(project) {
        return Err(TranscriptError::Invalid);
    }
    Ok(root.join(tenant.to_string()).join(project))
}

#[must_use]
pub fn stable_file_name(
    instance: &str,
    format: TranscriptFormat,
    source: &str,
    first_line: &str,
) -> String {
    let mut digest = Sha256::new();
    for value in [
        "transcript-spool-v1",
        instance,
        format.as_str(),
        source,
        first_line,
    ] {
        digest.update(value.as_bytes());
        digest.update([0]);
    }
    format!("{}.jsonl", hex::encode(digest.finalize()))
}

fn directory(parent: &File, name: &str) -> Result<File, TranscriptError> {
    match fs::mkdirat(parent, name, Mode::RUSR | Mode::WUSR | Mode::XUSR) {
        Ok(()) => parent.sync_all()?,
        Err(rustix::io::Errno::EXIST) => {}
        Err(error) => return Err(error.into()),
    }
    Ok(File::from(fs::openat(
        parent,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )?))
}

fn regular(parent: &File, name: &str, flags: OFlags) -> Result<File, TranscriptError> {
    let file = File::from(fs::openat(
        parent,
        name,
        flags | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::RUSR | Mode::WUSR,
    )?);
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(TranscriptError::Invalid);
    }
    Ok(file)
}

impl TranscriptReceiver {
    pub fn new(config: TranscriptReceiverConfig) -> Result<Self, TranscriptError> {
        if !(1..=MAX_WINDOW_BYTES).contains(&config.window_bytes)
            || config.max_file_bytes < config.window_bytes as u64
            || config.max_scope_bytes < config.max_file_bytes
        {
            return Err(TranscriptError::Invalid);
        }
        std::fs::create_dir_all(&config.root)?;
        // Ancestor directories are operator-owned configuration; the configured
        // leaf itself and every untrusted descendant must never be a symlink.
        let root = File::from(fs::open(
            &config.root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )?);
        // Fixed operational categories only: no scope, source, path or error text.
        // Initialize before traffic so a first failure has a scrape baseline.
        for unit in ["quota_rejected", "io_errors"] {
            crate::telemetry::add_units("transcript", "receive", unit, 0);
        }
        Ok(Self { config, root })
    }

    pub const fn window_bytes(&self) -> usize {
        self.config.window_bytes
    }

    /// Prepare a credential-bound worker scope using the receiver's no-follow
    /// traversal, before the worker discovers either format directory.
    pub fn prepare_scope(&self, tenant: Uuid, project: &str) -> Result<PathBuf, TranscriptError> {
        let path = scope_spool_dir(&self.config.root, tenant, project)?;
        let tenant = directory(&self.root, &tenant.to_string())?;
        let scope = directory(&tenant, project)?;
        directory(&scope, TranscriptFormat::ClaudeCode.as_str())?;
        directory(&scope, TranscriptFormat::Codex.as_str())?;
        Ok(path)
    }

    pub async fn receive(
        self: &Arc<Self>,
        auth: TranscriptAuthorization,
        upload: TranscriptUpload,
        body: Option<Vec<u8>>,
    ) -> Result<TranscriptProgress, TranscriptError> {
        let receiver = self.clone();
        tokio::task::spawn_blocking(move || {
            let result = receiver.receive_sync(&auth, &upload, body.as_deref());
            // Observe inside the blocking task: cancellation of the HTTP waiter
            // must not hide a completed spool failure or count it twice.
            match &result {
                Err(TranscriptError::Quota) => {
                    crate::telemetry::add_units("transcript", "receive", "quota_rejected", 1);
                }
                Err(TranscriptError::Io(_)) => {
                    crate::telemetry::add_units("transcript", "receive", "io_errors", 1);
                }
                _ => {}
            }
            result
        })
        .await
        .map_err(|_| {
            crate::telemetry::add_units("transcript", "receive", "io_errors", 1);
            TranscriptError::Io(std::io::Error::other("transcript task failed"))
        })?
    }

    #[allow(clippy::too_many_lines)] // The authorization, lock, replay and commit order is one invariant.
    fn receive_sync(
        &self,
        auth: &TranscriptAuthorization,
        upload: &TranscriptUpload,
        body: Option<&[u8]>,
    ) -> Result<TranscriptProgress, TranscriptError> {
        if !component(&upload.instance)
            || upload.instance != auth.sandbox_id
            || !component(&auth.project)
            || !valid_source(&upload.source)
            || upload.first_line_sha256.len() != 64
            || !upload
                .first_line_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
            || upload.file
                != stable_file_name(
                    &upload.instance,
                    upload.format,
                    &upload.source,
                    &upload.first_line_sha256,
                )
            || body.is_some_and(|b| {
                b.is_empty() || b.len() > self.config.window_bytes || b.last() != Some(&b'\n')
            })
        {
            return Err(TranscriptError::Invalid);
        }
        let tenant = directory(&self.root, &auth.tenant_id.to_string())?;
        let scope = directory(&tenant, &auth.project)?;
        let lock = regular(&scope, ".lock", OFlags::RDWR | OFlags::CREATE)?;
        fs::flock(&lock, FlockOperation::NonBlockingLockExclusive)?;
        let dir = directory(&scope, upload.format.as_str())?;
        let expected = Manifest {
            version: 1,
            tenant_id: auth.tenant_id,
            project: auth.project.clone(),
            principal_id: auth.principal_id,
            agent: auth.agent.clone(),
            sandbox_id: auth.sandbox_id.clone(),
            source: upload.source.clone(),
            format: upload.format,
            first_line_sha256: upload.first_line_sha256.clone(),
        };
        let manifest_name = format!("{}.meta", upload.file);
        let existing = match regular(&dir, &upload.file, OFlags::RDONLY) {
            Ok(file) => Some(file),
            Err(TranscriptError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        };
        let length = existing
            .as_ref()
            .map_or(Ok(0), |f| f.metadata().map(|m| m.len()))?;
        if existing.is_some() {
            let mut manifest = regular(&dir, &manifest_name, OFlags::RDONLY)?;
            let mut bytes = Vec::new();
            Read::by_ref(&mut manifest)
                .take(8193)
                .read_to_end(&mut bytes)?;
            let prior: Manifest =
                serde_json::from_slice(&bytes).map_err(|_| TranscriptError::Invalid)?;
            if prior != expected {
                return Err(TranscriptError::Invalid);
            }
        }
        let Some(body) = body else {
            return Ok(TranscriptProgress {
                length,
                replayed: false,
            });
        };
        let end = upload
            .offset
            .checked_add(body.len() as u64)
            .ok_or(TranscriptError::Invalid)?;
        if upload.offset < length && end <= length {
            let mut file = existing
                .as_ref()
                .ok_or(TranscriptError::Invalid)?
                .try_clone()?;
            file.seek(SeekFrom::Start(upload.offset))?;
            let mut prior = vec![0; body.len()];
            file.read_exact(&mut prior)?;
            if Sha256::digest(&prior) == Sha256::digest(body) {
                return Ok(TranscriptProgress {
                    length,
                    replayed: true,
                });
            }
        }
        if upload.offset != length {
            return Err(TranscriptError::Conflict(length));
        }
        if end > self.config.max_file_bytes {
            return Err(TranscriptError::Quota);
        }
        if length == 0 {
            let first = body
                .split_inclusive(|b| *b == b'\n')
                .next()
                .ok_or(TranscriptError::Invalid)?;
            if hex::encode(Sha256::digest(first)) != upload.first_line_sha256 {
                return Err(TranscriptError::Invalid);
            }
        }
        let (files, total) = scope_usage(&scope)?;
        if (length == 0 && files >= MAX_FILES)
            || total.saturating_add(body.len() as u64) > self.config.max_scope_bytes
        {
            return Err(TranscriptError::Quota);
        }
        let metadata = serde_json::to_vec(&expected).map_err(|_| TranscriptError::Invalid)?;
        atomic_write(&dir, &manifest_name, None, &metadata)?;
        // Copy + rename keeps every worker-visible file an entire committed
        // prefix. A killed receiver leaves only an ignored .next file.
        atomic_write(&dir, &upload.file, existing, body)?;
        Ok(TranscriptProgress {
            length: end,
            replayed: false,
        })
    }
}

fn atomic_write(
    dir: &File,
    name: &str,
    prefix: Option<File>,
    bytes: &[u8],
) -> Result<(), TranscriptError> {
    let next = format!("{name}.next");
    let mut file = regular(dir, &next, OFlags::WRONLY | OFlags::CREATE)?;
    file.set_len(0)?;
    if let Some(mut prefix) = prefix {
        std::io::copy(&mut prefix, &mut file)?;
    }
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::renameat(dir, &next, dir, name)?;
    dir.sync_all()?;
    Ok(())
}

fn scope_usage(scope: &File) -> Result<(usize, u64), TranscriptError> {
    let mut files = 0;
    let mut bytes = 0_u64;
    for format in [TranscriptFormat::ClaudeCode, TranscriptFormat::Codex] {
        let dir = directory(scope, format.as_str())?;
        for entry in Dir::read_from(&dir)? {
            let entry = entry?;
            if !entry.file_name().to_bytes().ends_with(b".jsonl") {
                continue;
            }
            let file = regular(
                &dir,
                entry
                    .file_name()
                    .to_str()
                    .map_err(|_| TranscriptError::Invalid)?,
                OFlags::RDONLY,
            )?;
            files += 1;
            bytes = bytes.saturating_add(file.metadata()?.len());
            if files > MAX_FILES {
                return Err(TranscriptError::Quota);
            }
        }
    }
    Ok((files, bytes))
}
