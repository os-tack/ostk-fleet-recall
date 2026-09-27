//! Process logging, an optional private scrape listener, and atomic snapshots
//! for short-lived jobs (Prometheus node-exporter textfile collector).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, ensure};
use axum::{
    Router,
    http::{StatusCode, header},
    response::IntoResponse as _,
    routing::get,
};
use tokio::{sync::oneshot, task::JoinHandle};

#[derive(Debug, Default)]
pub struct Config {
    pub listen: Option<SocketAddr>,
    pub textfile: Option<PathBuf>,
}

impl Config {
    pub fn from_env() -> anyhow::Result<Self> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> anyhow::Result<Self> {
        let listen = lookup("FLEET_RECALL_METRICS_LISTEN")
            .map(|value| {
                value
                    .parse::<SocketAddr>()
                    .context("FLEET_RECALL_METRICS_LISTEN must be an IP address and port")
            })
            .transpose()?;
        let allow_non_loopback = match lookup("FLEET_RECALL_METRICS_ALLOW_NON_LOOPBACK").as_deref()
        {
            None | Some("false") => false,
            Some("true") => true,
            Some(_) => {
                anyhow::bail!("FLEET_RECALL_METRICS_ALLOW_NON_LOOPBACK must be true or false")
            }
        };
        if let Some(address) = listen {
            ensure!(
                address.ip().is_loopback() || allow_non_loopback,
                "non-loopback metrics listener requires FLEET_RECALL_METRICS_ALLOW_NON_LOOPBACK=true and a private network boundary"
            );
        }
        let textfile = lookup("FLEET_RECALL_METRICS_TEXTFILE").map(PathBuf::from);
        if let Some(path) = &textfile {
            ensure!(
                path.extension()
                    .is_some_and(|extension| extension == "prom")
                    && path.file_stem().is_some_and(|stem| !stem.is_empty()),
                "FLEET_RECALL_METRICS_TEXTFILE must name a .prom file"
            );
        }
        Ok(Self { listen, textfile })
    }
}

/// JSON is the default. Text is useful at a terminal. Both write exclusively
/// to stderr, leaving stdout available for MCP and CLI result documents.
pub fn init_logging() -> anyhow::Result<()> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "ostk_fleet_recall=info".into());
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(false);
    let result = match std::env::var("FLEET_RECALL_LOG_FORMAT").as_deref() {
        Err(std::env::VarError::NotPresent) | Ok("json") => subscriber.json().try_init(),
        Ok("text") => subscriber.try_init(),
        _ => anyhow::bail!("FLEET_RECALL_LOG_FORMAT must be json or text"),
    };
    result.map_err(|_| anyhow::anyhow!("could not initialize telemetry logging"))
}

pub struct Runtime {
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<std::io::Result<()>>>,
    textfile: Option<PathBuf>,
}

impl Runtime {
    pub async fn start(config: Config) -> anyhow::Result<Self> {
        // Initialize counters at process startup, before the first request.
        let _ = super::render()?;
        let mut runtime = Self {
            stop: None,
            task: None,
            textfile: config.textfile,
        };
        if let Some(address) = config.listen {
            let listener = tokio::net::TcpListener::bind(address)
                .await
                .context("bind private metrics listener")?;
            let (stop, stopped) = oneshot::channel();
            runtime.stop = Some(stop);
            runtime.task = Some(tokio::spawn(async move {
                let result = axum::serve(listener, router())
                    .with_graceful_shutdown(async {
                        let _ = stopped.await;
                    })
                    .await;
                if result.is_err() {
                    tracing::error!(
                        event = "telemetry.exporter.failed",
                        event_version = 1_u64,
                        "metrics listener failed"
                    );
                }
                result
            }));
            tracing::info!(
                event = "telemetry.exporter.started",
                event_version = 1_u64,
                "private metrics listener started"
            );
        }
        Ok(runtime)
    }

    /// Snapshot after the command's terminal event, including error exits.
    pub async fn finish(mut self) -> anyhow::Result<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let snapshot = self.textfile.as_deref().map(write_snapshot).transpose();
        if let Some(task) = self.task.as_mut() {
            if let Ok(result) =
                tokio::time::timeout(std::time::Duration::from_secs(2), &mut *task).await
            {
                result
                    .context("join metrics listener")?
                    .context("serve metrics")?;
            } else {
                task.abort();
                let _ = task.await;
            }
        }
        self.task.take();
        snapshot?;
        Ok(())
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

pub fn router() -> Router {
    Router::new().route(
        "/metrics",
        get(|| async {
            super::render().map_or_else(
                |_| (StatusCode::INTERNAL_SERVER_ERROR, "metrics unavailable").into_response(),
                |body| {
                    (
                        [
                            (header::CONTENT_TYPE, prometheus::TEXT_FORMAT),
                            (header::CACHE_CONTROL, "no-store"),
                        ],
                        body,
                    )
                        .into_response()
                },
            )
        }),
    )
}

fn write_snapshot(path: &Path) -> anyhow::Result<()> {
    use std::io::Write as _;
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let temporary = parent.join(format!(".fleet-metrics-{}.tmp", uuid::Uuid::now_v7()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .context("create metrics snapshot in its destination directory")?;
    let metrics = super::render()?;
    file.write_all(metrics.as_bytes())
        .context("write metrics snapshot")?;
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();
    writeln!(
        file,
        "# HELP fleet_recall_snapshot_time_seconds Time this job snapshot was written.\n# TYPE fleet_recall_snapshot_time_seconds gauge\nfleet_recall_snapshot_time_seconds {timestamp}"
    )?;
    file.sync_all().context("sync metrics snapshot")?;
    std::fs::rename(&temporary, path).context("publish metrics snapshot")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt as _;

    #[test]
    fn configuration_requires_explicit_network_exposure_and_valid_values() {
        let config = |listen: &str, allow: Option<&str>| {
            Config::from_lookup(|key| match key {
                "FLEET_RECALL_METRICS_LISTEN" => Some(listen.to_owned()),
                "FLEET_RECALL_METRICS_ALLOW_NON_LOOPBACK" => allow.map(str::to_owned),
                _ => None,
            })
        };
        assert!(Config::from_lookup(|_| None).unwrap().listen.is_none());
        assert!(config("127.0.0.1:9091", None).is_ok());
        assert!(config("[::1]:9091", None).is_ok());
        assert!(config("0.0.0.0:9091", None).is_err());
        assert!(config("0.0.0.0:9091", Some("true")).is_ok());
        assert!(config("invalid", None).is_err());
        assert!(config("127.0.0.1:9091", Some("yes")).is_err());
    }

    #[tokio::test]
    async fn scrape_surface_is_only_metrics_and_has_the_correct_content_type() {
        let response = router()
            .oneshot(Request::get("/metrics").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            prometheus::TEXT_FORMAT
        );
        let body = axum::body::to_bytes(response.into_body(), 4 * 1024 * 1024)
            .await
            .unwrap();
        assert!(
            std::str::from_utf8(&body)
                .unwrap()
                .contains("fleet_recall_build_info")
        );
        let response = router()
            .oneshot(Request::get("/mcp").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn snapshots_replace_atomically_and_include_freshness() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("worker.prom");
        std::fs::write(&path, "old").unwrap();
        write_snapshot(&path).unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("fleet_recall_snapshot_time_seconds"));
        assert!(contents.contains("fleet_recall_build_info"));
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn cancelling_shutdown_aborts_the_exporter_task() {
        let task = tokio::spawn(std::future::pending::<std::io::Result<()>>());
        let handle = task.abort_handle();
        let runtime = Runtime {
            stop: None,
            task: Some(task),
            textfile: None,
        };
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(1), runtime.finish())
                .await
                .is_err()
        );
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            while !handle.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropping shutdown must abort the outstanding task");
    }
}
