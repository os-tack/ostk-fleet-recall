//! Bound external runtime commands; never render argv, stdin, or stderr in errors.
use std::{path::Path, process::Stdio, time::Duration};

use anyhow::{Context as _, ensure};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};

pub(super) struct Output {
    pub success: bool,
    pub stderr: Vec<u8>,
}

pub(super) async fn run(
    program: &Path,
    arguments: &[String],
    input: Option<Vec<u8>>,
) -> anyhow::Result<Output> {
    let mut command = tokio::process::Command::new(program);
    command
        .args(arguments)
        .env_clear()
        .kill_on_drop(true)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Runtime connection settings are trusted operator input; application,
    // provider, SQL, cloud and grant credentials are not inherited.
    for name in [
        "PATH",
        "HOME",
        "DOCKER_HOST",
        "DOCKER_CONTEXT",
        "DOCKER_CONFIG",
        "KUBECONFIG",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let mut child = command
        .spawn()
        .context("cannot start container runtime CLI")?;
    let stdout = child.stdout.take().context("missing runtime stdout")?;
    let stderr = child.stderr.take().context("missing runtime stderr")?;
    let stdin = child.stdin.take();
    tokio::time::timeout(Duration::from_secs(240), async {
        let write = async {
            if let (Some(mut stdin), Some(input)) = (stdin, input) {
                stdin.write_all(&input).await?;
                stdin.shutdown().await?;
            }
            anyhow::Ok(())
        };
        let (status, (), _, stderr) = tokio::try_join!(
            async { child.wait().await.map_err(anyhow::Error::from) },
            write,
            bounded(stdout),
            bounded(stderr)
        )?;
        Ok(Output {
            success: status.success(),
            stderr,
        })
    })
    .await
    .context("container runtime command exceeded 240 seconds")?
}

async fn bounded(mut reader: impl AsyncRead + Unpin) -> anyhow::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    (&mut reader)
        .take(1_048_577)
        .read_to_end(&mut bytes)
        .await?;
    ensure!(
        bytes.len() <= 1_048_576,
        "container runtime output exceeded 1 MiB"
    );
    Ok(bytes)
}

pub(super) async fn checked(
    program: &Path,
    args: &[String],
    input: Option<Vec<u8>>,
) -> anyhow::Result<()> {
    ensure!(
        run(program, args, input).await?.success,
        "container runtime command failed (details suppressed to protect credentials)"
    );
    Ok(())
}
