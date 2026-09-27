//! Docker adapter: named volume, two containers, separate private env files.
use std::path::PathBuf;

use anyhow::ensure;
use async_trait::async_trait;

use super::{SandboxBackend, SandboxHandle, SandboxSpecV1, process, state};

pub struct DockerBackend {
    pub(crate) program: PathBuf,
}
impl Default for DockerBackend {
    fn default() -> Self {
        Self {
            program: "docker".into(),
        }
    }
}

fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| (*s).into()).collect()
}

fn container_args(spec: &SandboxSpecV1, agent: bool) -> anyhow::Result<Vec<String>> {
    let name = if agent {
        spec.name.clone()
    } else {
        format!("{}-shipper", spec.name)
    };
    let env = spec
        .state_dir
        .join(if agent { "agent.env" } else { "shipper.env" });
    let env = env
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("launch state path must be UTF-8"))?;
    let volume = format!(
        "type=volume,src={},dst=/transcripts{}",
        spec.transcript_volume,
        if agent { "" } else { ",readonly" }
    );
    let mut args = strings(&[
        "run",
        "--detach",
        "--name",
        &name,
        "--label",
        "fleet-recall.launch=true",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "256",
        "--memory",
        "1g",
        "--cpus",
        "2",
        "--user",
        "10001:10001",
        "--tmpfs",
        "/tmp:rw,nosuid,nodev,size=64m,mode=1777",
        "--tmpfs",
        "/home/sandbox:rw,nosuid,nodev,size=256m,uid=10001,gid=10001,mode=0700",
        "--env-file",
        env,
        "--mount",
        &volume,
    ]);
    if agent {
        args.push(spec.image.clone());
    } else {
        args.extend(strings(&[
            "--entrypoint",
            "/usr/local/bin/ostk-fleet-recall",
        ]));
        args.push(spec.shipper_image.clone());
        args.extend(spec.shipper_args.clone());
    }
    Ok(args)
}

#[async_trait]
impl SandboxBackend for DockerBackend {
    async fn create(&self, spec: &SandboxSpecV1) -> anyhow::Result<SandboxHandle> {
        spec.validate()?;
        state::write_environment(&spec.state_dir.join("agent.env"), &spec.env)?;
        state::write_environment(&spec.state_dir.join("shipper.env"), &spec.shipper_env)?;
        process::checked(
            &self.program,
            &strings(&[
                "volume",
                "create",
                "--label",
                "fleet-recall.launch=true",
                &spec.transcript_volume,
            ]),
            None,
        )
        .await?;
        // The sandbox image owns /transcripts as uid 10001. Docker initializes
        // the named volume from that directory before applying the read-only
        // shipper mount. Start the agent first for that initialization.
        process::checked(&self.program, &container_args(spec, true)?, None).await?;
        process::checked(&self.program, &container_args(spec, false)?, None).await?;
        Ok(SandboxHandle {
            name: spec.name.clone(),
            namespace: spec.namespace.clone(),
            transcript_volume: spec.transcript_volume.clone(),
        })
    }

    async fn destroy(&self, handle: &SandboxHandle) -> anyhow::Result<()> {
        handle.validate()?;
        let mut complete = true;
        for (name, grace) in [
            (&handle.name, "30"),
            (&format!("{}-shipper", handle.name), "150"),
        ] {
            // Stop agent first; then SIGTERM lets the shipper flush the final LF.
            let stopped = process::run(
                &self.program,
                &strings(&["stop", "--time", grace, name]),
                None,
            )
            .await;
            if !accepted_missing(stopped) {
                complete = false;
            }
            let removed =
                process::run(&self.program, &strings(&["rm", "--force", name]), None).await;
            if !accepted_missing(removed) {
                complete = false;
            }
        }
        // Deliberately retain the transcript volume for audit/recovery.
        ensure!(complete, "could not stop all launch containers");
        Ok(())
    }
}

fn accepted_missing(output: anyhow::Result<process::Output>) -> bool {
    output.is_ok_and(|out| {
        out.success || String::from_utf8_lossy(&out.stderr).contains("No such container")
    })
}

#[cfg(test)]
pub(super) fn command_arguments(spec: &SandboxSpecV1, agent: bool) -> anyhow::Result<Vec<String>> {
    container_args(spec, agent)
}
