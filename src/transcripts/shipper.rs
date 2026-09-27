use super::{MAX_WINDOW_BYTES, TranscriptProgress, stable_file_name};
use crate::connectors::transcript::TranscriptFormat;
use crate::encoding::base64;
use crate::{FleetError, Result};
use rustix::fs::{self, Dir, Mode, OFlags};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::PathBuf,
    time::Duration,
};

/// Deliberately not Debug: it owns a delegated shipper credential.
pub struct ShipperConfig {
    pub dir: PathBuf,
    pub url: String,
    pub instance: String,
    pub format: TranscriptFormat,
    pub token: String,
    pub ca_path: Option<PathBuf>,
    pub once: bool,
}

#[derive(Debug, Default, Serialize)]
pub struct ShipReport {
    pub files: usize,
    pub windows: u64,
    pub bytes: u64,
}

fn invalid(message: &str) -> FleetError {
    FleetError::Configuration(message.into())
}

struct Client {
    http: reqwest::Client,
    base: reqwest::Url,
    root: File,
}
impl Client {
    fn new(config: &ShipperConfig) -> Result<Self> {
        let mut base =
            reqwest::Url::parse(&config.url).map_err(|_| invalid("invalid transcript URL"))?;
        if !matches!(base.scheme(), "https" | "http")
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
            || base.fragment().is_some()
            || base.path() != "/mcp"
            || config.token.is_empty()
            || config.token.len() > 32768
            || config.token.chars().any(char::is_whitespace)
            || uuid::Uuid::parse_str(&config.instance).is_err()
        {
            return Err(invalid("invalid transcript shipper configuration"));
        }
        base.set_path("/");
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(40));
        if let Some(path) = &config.ca_path {
            let bytes = std::fs::read(path).map_err(|_| invalid("cannot read transcript CA"))?;
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_pem(&bytes)
                    .map_err(|_| invalid("invalid transcript CA"))?,
            );
        }
        let http = builder
            .build()
            .map_err(|_| invalid("cannot build transcript client"))?;
        let root = File::from(
            fs::open(
                &config.dir,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| invalid("cannot open transcript directory"))?,
        );
        Ok(Self { http, base, root })
    }
}

/// One pass includes only complete LF-terminated windows.
///
/// Replaying from byte
/// zero after process restart verifies every previously shipped prefix before
/// trusting the receiver's length, so a replaced file cannot rewrite history.
pub async fn ship_once(config: &ShipperConfig) -> Result<ShipReport> {
    let client = Client::new(config)?;
    pass(config, &client, &mut BTreeMap::new()).await
}

pub async fn ship_transcripts(config: ShipperConfig) -> Result<ShipReport> {
    let client = Client::new(&config)?;
    let mut offsets = BTreeMap::new();
    let mut total = ShipReport::default();
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|_| invalid("cannot install shipper shutdown handler"))?;
    loop {
        let result = tokio::select! {
            result=pass(&config,&client,&mut offsets)=>result,
            _=tokio::signal::ctrl_c()=>break,
            _=terminate.recv()=>break,
        };
        match result {
            Ok(report) => {
                total.files = report.files;
                total.windows += report.windows;
                total.bytes += report.bytes;
            }
            Err(error) if config.once => return Err(error),
            Err(_) => tracing::warn!("transcript pass failed; retaining offsets and retrying"),
        }
        if config.once {
            return Ok(total);
        }
        tokio::select! {
            ()=tokio::time::sleep(Duration::from_secs(2))=>{},
            _=tokio::signal::ctrl_c()=>break,
            _=terminate.recv()=>break,
        }
    }
    let report = pass(&config, &client, &mut offsets).await?;
    total.files = report.files;
    total.windows += report.windows;
    total.bytes += report.bytes;
    Ok(total)
}

struct Source {
    relative: String,
    file: File,
}
fn discover(dir: &File, prefix: &str, depth: usize, files: &mut Vec<Source>) -> Result<()> {
    if depth > 16 {
        return Err(invalid("transcript directory nesting exceeds limit"));
    }
    for entry in Dir::read_from(dir).map_err(|_| invalid("cannot list transcripts"))? {
        let entry = entry.map_err(|_| invalid("cannot list transcripts"))?;
        let Some(name) = entry
            .file_name()
            .to_str()
            .ok()
            .filter(|s| *s != "." && *s != "..")
        else {
            continue;
        };
        let relative = if prefix.is_empty() {
            name.into()
        } else {
            format!("{prefix}/{name}")
        };
        if relative.len() > 1024 {
            return Err(invalid("transcript path exceeds limit"));
        }
        // O_NOFOLLOW applies independently at every level; a sandbox-owned
        // symlink cannot make the sidecar read any credential outside the mount.
        let fd = match fs::openat(
            dir,
            name,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(rustix::io::Errno::LOOP | rustix::io::Errno::NOENT) => continue,
            Err(_) => return Err(invalid("cannot open transcript entry")),
        };
        let file = File::from(fd);
        let meta = file
            .metadata()
            .map_err(|_| invalid("cannot inspect transcript entry"))?;
        if meta.is_dir() {
            discover(&file, &relative, depth + 1, files)?;
        } else if meta.is_file()
            && std::path::Path::new(name)
                .extension()
                .is_some_and(|extension| extension == "jsonl")
        {
            use std::os::unix::fs::MetadataExt as _;
            if meta.nlink() != 1 || !super::receiver::valid_source(&relative) {
                return Err(invalid("unsafe transcript source"));
            }
            if files.len() >= 1024 {
                return Err(invalid("transcript file count exceeds limit"));
            }
            files.push(Source { relative, file });
        }
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // Keep receiver prefix verification and local offset advancement adjacent.
async fn pass(
    config: &ShipperConfig,
    client: &Client,
    offsets: &mut BTreeMap<String, u64>,
) -> Result<ShipReport> {
    let mut files = Vec::new();
    discover(&client.root, "", 0, &mut files)?;
    files.sort_by(|a, b| a.relative.cmp(&b.relative));
    let mut report = ShipReport {
        files: files.len(),
        ..ShipReport::default()
    };
    for mut source in files {
        let mut first = Vec::new();
        Read::by_ref(&mut source.file)
            .take(MAX_WINDOW_BYTES as u64)
            .read_to_end(&mut first)
            .map_err(|_| invalid("cannot read transcript"))?;
        let Some(lf) = first.iter().position(|b| *b == b'\n') else {
            if first.len() == MAX_WINDOW_BYTES {
                return Err(invalid("transcript line exceeds window limit"));
            }
            continue;
        };
        let first_digest = hex::encode(Sha256::digest(&first[..=lf]));
        let name = stable_file_name(
            &config.instance,
            config.format,
            &source.relative,
            &first_digest,
        );
        let mut offset = offsets.get(&name).copied().unwrap_or(0);
        let length = source
            .file
            .metadata()
            .map_err(|_| invalid("cannot inspect transcript"))?
            .len();
        if length < offset {
            return Err(invalid("transcript was truncated after shipping"));
        }
        let mut endpoint = client.base.clone();
        endpoint
            .path_segments_mut()
            .map_err(|()| invalid("invalid transcript base URL"))?
            .extend(["v1", "transcripts", &config.instance, &name]);
        let remote = send_window(
            client,
            config,
            &source.relative,
            &first_digest,
            endpoint.clone(),
            None,
        )
        .await?
        .length;
        if remote > length {
            return Err(invalid("local transcript is shorter than receiver history"));
        }
        if remote < offset {
            offset = 0;
        }
        while offset < length {
            source
                .file
                .seek(SeekFrom::Start(offset))
                .map_err(|_| invalid("cannot seek transcript"))?;
            let mut window = Vec::new();
            let limit = if offset < remote {
                (remote - offset).min(MAX_WINDOW_BYTES as u64)
            } else {
                MAX_WINDOW_BYTES as u64
            };
            Read::by_ref(&mut source.file)
                .take(limit)
                .read_to_end(&mut window)
                .map_err(|_| invalid("cannot read transcript"))?;
            let Some(last) = window.iter().rposition(|b| *b == b'\n') else {
                if window.len() == MAX_WINDOW_BYTES {
                    return Err(invalid("transcript line exceeds window limit"));
                }
                break;
            };
            window.truncate(last + 1);
            let mut url = endpoint.clone();
            url.query_pairs_mut()
                .append_pair("offset", &offset.to_string());
            let progress = send_window(
                client,
                config,
                &source.relative,
                &first_digest,
                url,
                Some(window.clone()),
            )
            .await?;
            let next = offset + window.len() as u64;
            if progress.length < next {
                return Err(invalid(
                    "receiver acknowledged an incomplete transcript window",
                ));
            }
            // On replay the receiver can be farther ahead. Still compare each
            // local window instead of skipping unverified bytes after restart.
            offset = next;
            if offsets.len() >= 1024 && !offsets.contains_key(&name) {
                offsets.clear();
            }
            offsets.insert(name.clone(), offset);
            report.windows += 1;
            report.bytes += window.len() as u64;
        }
    }
    Ok(report)
}

async fn send_window(
    client: &Client,
    config: &ShipperConfig,
    source: &str,
    first: &str,
    url: reqwest::Url,
    window: Option<Vec<u8>>,
) -> Result<TranscriptProgress> {
    for attempt in 0..3 {
        let result = client
            .http
            .request(
                if window.is_some() {
                    reqwest::Method::PUT
                } else {
                    reqwest::Method::GET
                },
                url.clone(),
            )
            .bearer_auth(&config.token)
            .header("content-type", "application/octet-stream")
            .header("x-transcript-source", base64::encode_url(source.as_bytes()))
            .header("x-transcript-format", config.format.as_str())
            .header("x-transcript-first-line-sha256", first)
            .body(window.clone().unwrap_or_default())
            .send()
            .await;
        match result {
            Ok(mut response) if response.status().is_success() => {
                if response.content_length().is_some_and(|n| n > 4096) {
                    return Err(invalid("invalid transcript receiver response"));
                }
                let mut bytes = Vec::new();
                while let Some(chunk) = response
                    .chunk()
                    .await
                    .map_err(|_| invalid("cannot read transcript acknowledgement"))?
                {
                    if bytes.len().saturating_add(chunk.len()) > 4096 {
                        return Err(invalid("invalid transcript receiver response"));
                    }
                    bytes.extend_from_slice(&chunk);
                }
                return serde_json::from_slice(&bytes)
                    .map_err(|_| invalid("invalid transcript acknowledgement"));
            }
            Ok(response) if !response.status().is_server_error() => {
                return Err(invalid("transcript receiver refused upload"));
            }
            _ if attempt < 2 => {
                tokio::time::sleep(Duration::from_millis(250 * (1 << attempt))).await;
            }
            _ => return Err(invalid("transcript receiver is unavailable")),
        }
    }
    Err(invalid("transcript upload failed"))
}
