//! Private state contains IDs and recovery instructions; credentials are separate.
use std::{
    fs::{File, OpenOptions},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
};

use anyhow::{Context as _, ensure};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{AnchorArgs, BackendKind, LaunchUpV1, SandboxHandle, validate_name};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct GrantState {
    pub id: Uuid,
    pub revoked: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct LaunchState {
    pub version: u32,
    pub backend: BackendKind,
    pub anchor: AnchorArgs,
    pub url: String,
    pub resource: String,
    #[serde(default)]
    pub ca_path: Option<PathBuf>,
    #[serde(default)]
    pub allow_http: Option<bool>,
    pub handle: SandboxHandle,
    pub grants: Vec<GrantState>,
    pub runtime_started: bool,
    pub runtime_stopped: bool,
    pub phase: String,
}

pub(super) struct StateFile {
    path: PathBuf,
    directory: PathBuf,
}

impl StateFile {
    pub fn create(
        args: &LaunchUpV1,
        name: &str,
        resource: String,
        ca_bundle: Option<&[u8]>,
    ) -> anyhow::Result<(Self, LaunchState)> {
        private_directory(&args.state_dir)?;
        let directory = args.state_dir.canonicalize()?.join(name);
        ensure!(!directory.try_exists()?, "launch directory already exists");
        private_directory(&directory)?;
        let file = Self {
            path: directory.join("launch-state.json"),
            directory,
        };
        let ca_path = ca_bundle
            .map(|bytes| {
                let path = file.directory.join("recall-ca.pem");
                write_private_new(&path, bytes)?;
                // The bundle contains public certificates only. Docker's UID 10001
                // must be able to read its bind mount; the parent stays mode 0700.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt as _;
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o444))?;
                }
                anyhow::Ok(path)
            })
            .transpose()?;
        let state = LaunchState {
            version: 1,
            backend: args.backend,
            anchor: args.anchor.clone(),
            url: args.url.clone(),
            resource,
            ca_path,
            allow_http: Some(args.allow_http),
            handle: SandboxHandle {
                name: name.into(),
                namespace: args.namespace.clone(),
                transcript_volume: format!("{name}-transcripts"),
            },
            grants: Vec::new(),
            runtime_started: false,
            runtime_stopped: false,
            phase: "preparing".into(),
        };
        file.save(&state)?;
        Ok((file, state))
    }

    pub fn load(path: &Path) -> anyhow::Result<(Self, LaunchState)> {
        let directory = path
            .parent()
            .context("state path needs a parent directory")?
            .canonicalize()?;
        check_private(&directory, true)?;
        ensure!(
            path.file_name().is_some_and(|n| n == "launch-state.json"),
            "expected launch-state.json"
        );
        let state: LaunchState = serde_json::from_slice(&read_bounded(path, 65_536, true)?)
            .context("invalid launch state")?;
        ensure!(
            state.version == 1 && state.grants.len() <= 2,
            "unsupported launch state"
        );
        validate_name(&state.handle.name)?;
        validate_name(&state.handle.namespace)?;
        ensure!(
            state.handle.name.starts_with("recall-")
                && state.handle.transcript_volume == format!("{}-transcripts", state.handle.name),
            "invalid launch resource identity"
        );
        ensure!(
            directory
                .file_name()
                .is_some_and(|n| n == state.handle.name.as_str()),
            "launch directory does not match resource identity"
        );
        let path = directory.join("launch-state.json");
        ensure!(
            state
                .ca_path
                .as_ref()
                .is_none_or(|ca| ca == &directory.join("recall-ca.pem")),
            "state CA path must identify the retained launch bundle"
        );
        Ok((Self { path, directory }, state))
    }

    pub fn save(&self, state: &LaunchState) -> anyhow::Result<()> {
        // Retain each fsynced snapshot for audit and crash recovery. Rename the
        // latest copy atomically so a kill cannot truncate the recovery file.
        let next = self
            .directory
            .join(format!("state-{}.json", Uuid::now_v7()));
        let bytes = serde_json::to_vec_pretty(state)?;
        write_private_new(&next, &bytes)?;
        let staging = self
            .directory
            .join(format!("latest-{}.json", Uuid::now_v7()));
        write_private_new(&staging, &bytes)?;
        std::fs::rename(staging, &self.path).context("cannot persist launch state")?;
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }

    pub fn clear_credentials(&self) -> anyhow::Result<()> {
        for name in ["agent.env", "shipper.env"] {
            let path = self.directory.join(name);
            if path.try_exists()? {
                check_private(&path, false)?;
                let file = OpenOptions::new().write(true).truncate(true).open(path)?;
                file.sync_all()?;
            }
        }
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
    pub fn directory(&self) -> &Path {
        &self.directory
    }
}

pub(super) fn private_directory(path: &Path) -> anyhow::Result<()> {
    if !path.try_exists()? {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt as _;
            builder.mode(0o700);
        }
        builder
            .create(path)
            .context("cannot create private launch directory")?;
    }
    check_private(path, true)
}

fn check_private(path: &Path, directory: bool) -> anyhow::Result<()> {
    let metadata = std::fs::symlink_metadata(path).context("cannot inspect protected file")?;
    ensure!(
        !metadata.file_type().is_symlink()
            && metadata.is_dir() == directory
            && (directory || metadata.is_file()),
        "protected path must be a regular file or directory, not a symlink"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        ensure!(
            metadata.permissions().mode().trailing_zeros() >= 6,
            "protected path must not grant group or other access"
        );
    }
    Ok(())
}

pub(super) fn read_bounded(path: &Path, limit: usize, private: bool) -> anyhow::Result<Vec<u8>> {
    if private {
        check_private(path, false)?;
    }
    let file = File::open(path).context("cannot open credential or state file")?;
    ensure!(
        file.metadata()?.is_file(),
        "expected regular credential or state file"
    );
    let mut bytes = Vec::new();
    file.take(u64::try_from(limit)? + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= limit,
        "credential or state file exceeds size limit"
    );
    Ok(bytes)
}

pub(super) fn write_private_new(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .context("cannot create private credential or state file")?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

pub(super) fn write_environment(
    path: &Path,
    env: &std::collections::BTreeMap<String, String>,
) -> anyhow::Result<()> {
    let mut bytes = Vec::new();
    for (name, value) in env {
        ensure!(
            !name.is_empty()
                && name
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
                && !value.contains(['\r', '\n', '\0']),
            "invalid container environment"
        );
        writeln!(bytes, "{name}={value}")?;
    }
    write_private_new(path, &bytes)
}
