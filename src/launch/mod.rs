//! Workstation launcher. Only per-run grants cross the sandbox boundary.
pub mod docker;
pub mod kubernetes;
mod process;
mod state;

use std::{collections::BTreeMap, path::PathBuf, time::Duration};

use anyhow::{Context as _, bail, ensure};
use async_trait::async_trait;
use clap::{Args, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::auth::{grant::SessionGrant, jose::Ed25519Signer};
use state::{LaunchState, StateFile};

#[derive(Debug, Subcommand)]
pub enum LaunchCommandV1 {
    /// Mint scoped grants and start an isolated agent plus transcript shipper.
    Up(Box<LaunchUpV1>),
    /// Stop a launch and revoke both grants, preserving audit state.
    Down(LaunchDownV1),
}

#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BackendKind {
    Docker,
    Kubernetes,
}

#[derive(Debug, Clone, Copy, ValueEnum, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AnchorKind {
    LocalKey,
    Kubernetes,
}

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum Harness {
    Synthetic,
    Codex,
    Claude,
}

impl Harness {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Synthetic => "synthetic",
            Self::Codex => "codex",
            Self::Claude => "claude",
        }
    }
}

#[derive(Debug, Clone, Args, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorArgs {
    #[arg(long, value_enum, default_value = "local-key")]
    pub anchor: AnchorKind,
    /// Enrolled local-key subject; seed is read only from `FLEET_RECALL_LAUNCHER_KEY_HEX`.
    #[arg(long, default_value = "launcher")]
    pub key_id: String,
    /// Projected token with audience equal to --resource-url.
    #[arg(long, default_value = "/var/run/secrets/tokens/recall")]
    pub service_account_token_file: PathBuf,
}

#[derive(Debug, Args)]
pub struct LaunchUpV1 {
    #[arg(long, value_enum)]
    pub backend: BackendKind,
    #[command(flatten)]
    pub anchor: AnchorArgs,
    /// Expected grant scope, `TENANT_UUID/PROJECT`. Server enrollment is authoritative.
    #[arg(long)]
    pub scope: String,
    #[arg(long)]
    pub agent: String,
    #[arg(long)]
    pub image: String,
    /// Defaults to the sandbox image, which includes the shipper binary.
    #[arg(long)]
    pub shipper_image: Option<String>,
    /// MCP URL reachable from this launcher.
    #[arg(long, env = "FLEET_RECALL_URL")]
    pub url: String,
    /// MCP audience; defaults to --url, even when --sandbox-url uses another route.
    #[arg(long)]
    pub resource_url: Option<String>,
    /// MCP URL reachable from containers; defaults to --url.
    #[arg(long)]
    pub sandbox_url: Option<String>,
    #[arg(long, value_enum, default_value = "synthetic")]
    pub harness: Harness,
    #[arg(
        long,
        default_value = "Use recall to check status, then remember one brief note about this sandbox run."
    )]
    pub task: String,
    #[arg(long)]
    pub model: Option<String>,
    /// Hard execution deadline for the sandbox harness.
    #[arg(long, default_value_t = 300)]
    pub timeout_seconds: u64,
    #[arg(long, default_value_t = 3600)]
    pub ttl_seconds: u64,
    /// Parent for private, unique per-launch directories. Existing broad permissions are refused.
    #[arg(long, default_value = ".fleet-launch")]
    pub state_dir: PathBuf,
    #[arg(long, default_value = "default")]
    pub namespace: String,
    #[arg(long)]
    pub runtime_class: Option<String>,
    /// Explicitly copy this Codex login cache into only the agent container.
    #[arg(long)]
    pub codex_auth_file: Option<PathBuf>,
    /// Explicitly forward `CODEX_API_KEY` or `ANTHROPIC_API_KEY` for the selected harness.
    #[arg(long)]
    pub provider_key: bool,
}

#[derive(Debug, Args)]
pub struct LaunchDownV1 {
    /// Private launch-state.json path printed by launch up.
    #[arg(long)]
    pub state: PathBuf,
}

/// Secret values deliberately do not implement Debug or Serialize.
pub struct SandboxSpecV1 {
    pub name: String,
    pub image: String,
    pub shipper_image: String,
    pub env: BTreeMap<String, String>,
    pub shipper_env: BTreeMap<String, String>,
    pub transcript_volume: String,
    pub runtime_class: Option<String>,
    pub namespace: String,
    pub state_dir: PathBuf,
    pub shipper_args: Vec<String>,
}

impl SandboxSpecV1 {
    fn validate(&self) -> anyhow::Result<()> {
        validate_name(&self.name)?;
        validate_name(&self.namespace)?;
        validate_name(&self.transcript_volume)?;
        validate_image(&self.image)?;
        validate_image(&self.shipper_image)?;
        if let Some(class) = &self.runtime_class {
            validate_name(class)?;
        }
        ensure!(
            self.transcript_volume == format!("{}-transcripts", self.name),
            "transcript volume does not match launch name"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxHandle {
    pub name: String,
    pub namespace: String,
    pub transcript_volume: String,
}

impl SandboxHandle {
    fn validate(&self) -> anyhow::Result<()> {
        validate_name(&self.name)?;
        validate_name(&self.namespace)?;
        ensure!(
            self.name.starts_with("recall-")
                && self.transcript_volume == format!("{}-transcripts", self.name),
            "invalid runtime handle"
        );
        Ok(())
    }
}

#[async_trait]
pub trait SandboxBackend: Send + Sync {
    async fn create(&self, spec: &SandboxSpecV1) -> anyhow::Result<SandboxHandle>;
    /// Attempts every owned resource even if a preceding cleanup fails.
    async fn destroy(&self, handle: &SandboxHandle) -> anyhow::Result<()>;
}

pub async fn run_launch_command(command: LaunchCommandV1) -> anyhow::Result<()> {
    match command {
        LaunchCommandV1::Up(args) => launch_up(*args).await,
        LaunchCommandV1::Down(args) => launch_down(args).await,
    }
}

fn backend(kind: BackendKind) -> Box<dyn SandboxBackend> {
    match kind {
        BackendKind::Docker => Box::new(docker::DockerBackend::default()),
        BackendKind::Kubernetes => Box::new(kubernetes::KubernetesBackend::default()),
    }
}

fn validate_up(args: &LaunchUpV1) -> anyhow::Result<(Uuid, String)> {
    let (tenant, project) = args
        .scope
        .split_once('/')
        .context("scope must be TENANT_UUID/PROJECT")?;
    let tenant = tenant
        .parse::<Uuid>()
        .context("scope tenant must be a UUID")?;
    crate::FleetScope::new(
        tenant,
        project,
        &args.agent,
        None,
        ostk_recall_core::PrivacyTier::T1Project,
    )?;
    crate::memory_contracts::common::ContractId::new(&args.agent)?;
    validate_image(&args.image)?;
    if let Some(image) = &args.shipper_image {
        validate_image(image)?;
    }
    validate_name(&args.namespace)?;
    if let Some(class) = &args.runtime_class {
        validate_name(class)?;
    }
    ensure!(
        args.backend == BackendKind::Kubernetes || args.runtime_class.is_none(),
        "runtime-class requires Kubernetes"
    );
    validate_url(&args.url)?;
    validate_url(args.resource_url.as_deref().unwrap_or(&args.url))?;
    validate_url(args.sandbox_url.as_deref().unwrap_or(&args.url))?;
    ensure!(
        (1..=3600).contains(&args.timeout_seconds),
        "timeout must be 1..3600 seconds"
    );
    ensure!(
        (1..=86400).contains(&args.ttl_seconds),
        "grant TTL must be 1..86400 seconds"
    );
    ensure!(
        args.task.len() <= 32_768 && !args.task.contains('\0'),
        "task exceeds 32 KiB or contains NUL"
    );
    if let Some(model) = &args.model {
        ensure!(
            !model.is_empty() && model.len() <= 128 && !model.chars().any(char::is_control),
            "invalid model"
        );
    }
    ensure!(
        args.codex_auth_file.is_none() || args.harness == Harness::Codex,
        "codex-auth-file requires Codex"
    );
    ensure!(
        !args.provider_key || args.harness != Harness::Synthetic,
        "synthetic harness requires no provider credentials"
    );
    ensure!(
        !(args.provider_key && args.codex_auth_file.is_some()),
        "choose provider-key or codex-auth-file"
    );
    ensure!(
        args.harness != Harness::Codex || args.provider_key || args.codex_auth_file.is_some(),
        "Codex requires --codex-auth-file or --provider-key"
    );
    ensure!(
        args.harness != Harness::Claude || args.provider_key,
        "Claude requires --provider-key"
    );
    Ok((tenant, project.into()))
}

fn validate_image(image: &str) -> anyhow::Result<()> {
    ensure!(
        !image.is_empty()
            && image.len() <= 512
            && !image.starts_with('-')
            && image
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/._:@-".contains(&b)),
        "invalid container image"
    );
    Ok(())
}

pub(crate) fn validate_name(name: &str) -> anyhow::Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 63
            && name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && name.as_bytes()[0].is_ascii_alphanumeric()
            && name.as_bytes()[name.len() - 1].is_ascii_alphanumeric(),
        "invalid runtime resource name"
    );
    Ok(())
}

fn validate_url(value: &str) -> anyhow::Result<url::Url> {
    let url = url::Url::parse(value).context("invalid MCP URL")?;
    ensure!(
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/mcp",
        "MCP URL must be http(s), end in /mcp, and contain no credentials, query, or fragment"
    );
    Ok(url)
}

fn anchor_token(args: &AnchorArgs, resource: &str) -> anyhow::Result<String> {
    match args.anchor {
        AnchorKind::LocalKey => {
            let mut seed = std::env::var("FLEET_RECALL_LAUNCHER_KEY_HEX")
                .context("FLEET_RECALL_LAUNCHER_KEY_HEX is required")?;
            let signer = Ed25519Signer::from_seed_hex(&args.key_id, &seed);
            seed.clear();
            let signer = signer.context("invalid launcher key or key ID")?;
            let now = chrono::Utc::now().timestamp();
            signer.sign(&json!({"iss":"fleet-recall-local-key","sub":args.key_id,"aud":resource,"jti":Uuid::now_v7(),"iat":now,"exp":now+240})).context("cannot sign launcher assertion")
        }
        AnchorKind::Kubernetes => {
            // Kubernetes projected volumes use a symlink by design. They are read
            // only here and never copied into a sandbox or persisted in state.
            let bytes = state::read_bounded(&args.service_account_token_file, 16_384, false)?;
            let token =
                String::from_utf8(bytes).context("invalid service account token encoding")?;
            let token = token.trim();
            ensure!(
                !token.is_empty() && !token.chars().any(char::is_whitespace),
                "invalid service account token"
            );
            Ok(token.into())
        }
    }
}

struct GrantClient {
    client: reqwest::Client,
    url: url::Url,
    resource: String,
    anchor: AnchorArgs,
}

impl GrantClient {
    fn new(url: &str, resource: String, anchor: AnchorArgs) -> anyhow::Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(Duration::from_secs(30))
                .build()?,
            url: validate_url(url)?,
            resource,
            anchor,
        })
    }
    async fn issue(
        &self,
        kind: &str,
        args: &LaunchUpV1,
        sandbox: &str,
    ) -> anyhow::Result<GrantResponse> {
        let response = self.client.post(self.url.join("/v1/grants")?).bearer_auth(anchor_token(&self.anchor, &self.resource)?).json(&json!({"kind":kind,"agent":args.agent,"sandbox_id":sandbox,"ttl_seconds":args.ttl_seconds})).send().await.context("grant request failed")?;
        ensure!(
            response.status() == reqwest::StatusCode::CREATED,
            "grant request returned HTTP {}",
            response.status().as_u16()
        );
        let bytes = bounded_response(response).await?;
        serde_json::from_slice(&bytes).context("invalid grant response")
    }
    async fn revoke(&self, id: Uuid) -> anyhow::Result<()> {
        let response = self
            .client
            .delete(self.url.join(&format!("/v1/grants/{id}"))?)
            .bearer_auth(anchor_token(&self.anchor, &self.resource)?)
            .send()
            .await
            .context("grant revocation failed")?;
        ensure!(
            response.status() == reqwest::StatusCode::NO_CONTENT,
            "grant revocation returned HTTP {}",
            response.status().as_u16()
        );
        Ok(())
    }
}

async fn bounded_response(mut response: reqwest::Response) -> anyhow::Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .context("cannot read grant response")?
    {
        ensure!(
            body.len() + chunk.len() <= 65_536,
            "grant response exceeds 64 KiB"
        );
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantResponse {
    token: String,
    grant: SessionGrant,
}

fn validate_grant(
    response: &GrantResponse,
    kind: &str,
    args: &LaunchUpV1,
    tenant: Uuid,
    project: &str,
    sandbox: &str,
) -> anyhow::Result<()> {
    let grant = &response.grant;
    ensure!(
        grant.kind.as_str() == kind
            && !grant.jti.is_nil()
            && !grant.principal_id.is_nil()
            && grant.principal_revision > 0
            && grant.tenant_id == tenant
            && grant.project == project
            && grant.agent == args.agent
            && grant.sandbox_id.as_deref() == Some(sandbox),
        "server returned a grant for a different identity or scope"
    );
    ensure!(
        valid_grant_lifetime(grant, args.ttl_seconds, chrono::Utc::now()),
        "server returned an invalid grant lifetime"
    );
    ensure!(
        !response.token.is_empty()
            && response.token.len() <= 16_384
            && response.token.bytes().all(|byte| byte.is_ascii_graphic()),
        "server returned an invalid grant token"
    );
    Ok(())
}

fn valid_grant_lifetime(
    grant: &SessionGrant,
    ttl_seconds: u64,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    let lifetime = grant.expires_at - grant.issued_at;
    // Match the verifier's bounded clock leeway. VM and host clocks can
    // differ by milliseconds even while showing the same wall-clock second.
    grant.expires_at > now
        && grant.issued_at <= now + chrono::Duration::seconds(60)
        && lifetime > chrono::Duration::zero()
        && lifetime <= chrono::Duration::seconds(i64::try_from(ttl_seconds).unwrap_or_default())
}

async fn launch_up(args: LaunchUpV1) -> anyhow::Result<()> {
    let runtime = backend(args.backend);
    launch_up_with_backend(args, runtime.as_ref()).await
}

async fn launch_up_with_backend(
    args: LaunchUpV1,
    runtime: &dyn SandboxBackend,
) -> anyhow::Result<()> {
    let (tenant, project) = validate_up(&args)?;
    let instance = Uuid::now_v7().to_string();
    let name = format!("recall-{instance}");
    let resource = args
        .resource_url
        .clone()
        .unwrap_or_else(|| args.url.clone());
    let client = GrantClient::new(&args.url, resource.clone(), args.anchor.clone())?;
    // Check anchor and provider inputs before any grant is created.
    let _ = anchor_token(&args.anchor, &resource)?;
    let env = agent_environment(&args, &instance)?;
    let (file, mut state) = StateFile::create(&args, &name, resource)?;
    let result = async {
        let mut tokens = Vec::new();
        let mut principal = None;
        for kind in ["agent", "shipper"] {
            let response = client.issue(kind, &args, &instance).await?;
            // Record the ID before validation so an unexpected returned scope
            // is still revoked; never hand a mismatched token to a sandbox.
            state.grants.push(state::GrantState {
                id: response.grant.jti,
                revoked: false,
            });
            file.save(&state)?;
            validate_grant(&response, kind, &args, tenant, &project, &instance)?;
            let identity = (
                response.grant.principal_id,
                response.grant.principal_revision,
            );
            ensure!(
                principal.is_none_or(|previous| previous == identity),
                "launcher identity changed while issuing grants"
            );
            principal = Some(identity);
            tokens.push(response.token);
        }
        let mut env = env;
        env.insert("FLEET_RECALL_TOKEN".into(), tokens[0].clone());
        let shipper_env = BTreeMap::from([("FLEET_RECALL_TOKEN".into(), tokens[1].clone())]);
        let spec = SandboxSpecV1 {
            name: name.clone(),
            image: args.image.clone(),
            shipper_image: args
                .shipper_image
                .clone()
                .unwrap_or_else(|| args.image.clone()),
            env,
            shipper_env,
            transcript_volume: state.handle.transcript_volume.clone(),
            runtime_class: args.runtime_class.clone(),
            namespace: args.namespace.clone(),
            state_dir: file.directory().to_path_buf(),
            shipper_args: vec![
                "ship".into(),
                "transcripts".into(),
                "--dir".into(),
                "/transcripts".into(),
                "--url".into(),
                args.sandbox_url.clone().unwrap_or_else(|| args.url.clone()),
                "--instance".into(),
                instance,
                "--format".into(),
                if args.harness == Harness::Codex {
                    "codex"
                } else {
                    "claude-code"
                }
                .into(),
            ],
        };
        state.runtime_started = true; // Covers a partially completed create.
        file.save(&state)?;
        runtime.create(&spec).await?;
        state.phase = "running".into();
        file.save(&state)?;
        anyhow::Ok(())
    }
    .await;
    if let Err(error) = result {
        let cleanup = cleanup(&mut state, &file, runtime, &client).await;
        bail!(
            "launch failed: {error}; cleanup {}; retry with launch down --state {}",
            if cleanup.is_ok() {
                "complete"
            } else {
                "incomplete"
            },
            file.path().display()
        );
    }
    println!("Launch running: {name}\nState: {}", file.path().display());
    Ok(())
}

fn agent_environment(
    args: &LaunchUpV1,
    instance: &str,
) -> anyhow::Result<BTreeMap<String, String>> {
    let mut env = BTreeMap::from([
        (
            "FLEET_RECALL_URL".into(),
            args.sandbox_url.clone().unwrap_or_else(|| args.url.clone()),
        ),
        ("FLEET_SANDBOX_HARNESS".into(), args.harness.as_str().into()),
        ("FLEET_SANDBOX_INSTANCE".into(), instance.into()),
        (
            "FLEET_SANDBOX_TASK_B64".into(),
            crate::encoding::base64::encode(args.task.as_bytes()),
        ),
        (
            "FLEET_SANDBOX_TIMEOUT_SECONDS".into(),
            args.timeout_seconds.to_string(),
        ),
    ]);
    if let Some(model) = &args.model {
        env.insert("FLEET_SANDBOX_MODEL".into(), model.clone());
    }
    if let Some(path) = &args.codex_auth_file {
        let bytes = state::read_bounded(path, 65_536, true)?;
        let value: Value =
            serde_json::from_slice(&bytes).context("Codex auth file must be JSON")?;
        ensure!(value.is_object(), "Codex auth file must contain an object");
        env.insert(
            "FLEET_SANDBOX_CODEX_AUTH_B64".into(),
            crate::encoding::base64::encode(&bytes),
        );
    }
    if args.provider_key {
        let key = if args.harness == Harness::Codex {
            "CODEX_API_KEY"
        } else {
            "ANTHROPIC_API_KEY"
        };
        let value =
            std::env::var(key).with_context(|| format!("{key} is required with --provider-key"))?;
        ensure!(
            !value.is_empty() && value.len() <= 16_384 && !value.chars().any(char::is_control),
            "provider key is empty or invalid"
        );
        env.insert(key.into(), value);
    }
    Ok(env)
}

async fn launch_down(args: LaunchDownV1) -> anyhow::Result<()> {
    let (file, mut state) = StateFile::load(&args.state)?;
    let client = GrantClient::new(&state.url, state.resource.clone(), state.anchor.clone())?;
    let runtime = backend(state.backend);
    cleanup(&mut state, &file, runtime.as_ref(), &client).await?;
    println!(
        "Launch stopped; both grants revoked. State: {}",
        file.path().display()
    );
    Ok(())
}

async fn cleanup(
    state: &mut LaunchState,
    file: &StateFile,
    runtime: &dyn SandboxBackend,
    client: &GrantClient,
) -> anyhow::Result<()> {
    let mut failures = Vec::new();
    if state.runtime_started && !state.runtime_stopped {
        match runtime.destroy(&state.handle).await {
            Ok(()) => state.runtime_stopped = true,
            Err(_) => failures.push("runtime cleanup"),
        }
    }
    for grant in &mut state.grants {
        if !grant.revoked {
            match client.revoke(grant.id).await {
                Ok(()) => grant.revoked = true,
                Err(_) => failures.push("grant revocation"),
            }
        }
    }
    state.phase = if failures.is_empty() {
        "stopped"
    } else {
        "cleanup-pending"
    }
    .into();
    // Keep the IDs even after successful revocation so a retry remains safe.
    file.save(state)?;
    file.clear_credentials()?;
    ensure!(
        failures.is_empty(),
        "cleanup incomplete ({}); retry launch down --state {}",
        failures.join(", "),
        file.path().display()
    );
    Ok(())
}

#[cfg(test)]
mod tests;
