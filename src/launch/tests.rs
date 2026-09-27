use super::*;
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    routing::{delete, post},
};
use std::{
    path::Path,
    sync::{Arc, Mutex},
};

fn args(directory: &Path) -> LaunchUpV1 {
    LaunchUpV1 {
        backend: BackendKind::Docker,
        anchor: AnchorArgs {
            anchor: AnchorKind::Kubernetes,
            key_id: "launcher".into(),
            service_account_token_file: directory.join("sa-token"),
        },
        scope: "0198a849-f6ae-7d61-9800-000000000001/local-k0s".into(),
        agent: "sandbox-one".into(),
        image: "sandbox:local".into(),
        shipper_image: None,
        url: "http://localhost:8080/mcp".into(),
        ca_path: None,
        allow_http: true,
        resource_url: None,
        sandbox_url: Some("http://host.docker.internal:8080/mcp".into()),
        harness: Harness::Synthetic,
        task: "a task\nwith two lines".into(),
        model: None,
        timeout_seconds: 300,
        ttl_seconds: 3600,
        state_dir: directory.join("private"),
        namespace: "default".into(),
        runtime_class: None,
        codex_auth_file: None,
        provider_key: false,
    }
}

fn spec(directory: &Path) -> SandboxSpecV1 {
    SandboxSpecV1 {
        name: "recall-test".into(),
        image: "sandbox:test".into(),
        shipper_image: "shipper:test".into(),
        env: BTreeMap::from([
            ("FLEET_RECALL_TOKEN".into(), "agent-secret".into()),
            ("CODEX_API_KEY".into(), "provider-secret".into()),
        ]),
        shipper_env: BTreeMap::from([("FLEET_RECALL_TOKEN".into(), "shipper-secret".into())]),
        transcript_volume: "recall-test-transcripts".into(),
        runtime_class: Some("kata-qemu-runtime-rs".into()),
        namespace: "sandbox".into(),
        state_dir: directory.into(),
        ca_path: None,
        shipper_args: vec![
            "ship".into(),
            "transcripts".into(),
            "--dir".into(),
            "/transcripts".into(),
        ],
    }
}

#[test]
fn launch_validates_identity_and_cli_boundaries_before_effects() {
    let directory = tempfile::tempdir().unwrap();
    let mut value = args(directory.path());
    assert!(validate_up(&value).is_ok());
    for invalid in [
        "--privileged",
        "image name",
        "image; touch /tmp/x",
        "$(whoami)",
    ] {
        value.image = invalid.into();
        assert!(validate_up(&value).is_err());
    }
    value.image = "sandbox:test".into();
    value.namespace = "--all".into();
    assert!(validate_up(&value).is_err());
    value.namespace = "default".into();
    value.url = "http://user:password@example.test/mcp".into();
    assert!(validate_up(&value).is_err());
    value.url = "http://localhost:8080/mcp".into();
    value.runtime_class = Some("kata".into());
    assert!(validate_up(&value).is_err());
}

#[test]
fn docker_argv_contains_paths_and_no_secret_values() {
    let directory = tempfile::tempdir().unwrap();
    let value = spec(directory.path());
    for agent in [true, false] {
        let args = docker::command_arguments(&value, agent).unwrap();
        let joined = args.join(" ");
        assert!(!joined.contains("secret"));
        assert!(joined.contains("--cap-drop ALL"));
        assert!(joined.contains("--read-only"));
        assert!(joined.contains("no-new-privileges"));
        assert!(!joined.contains("docker.sock"));
        assert_eq!(joined.contains("readonly"), !agent);
    }
}

#[test]
fn kubernetes_separates_secrets_and_finishes_agent_before_shipper() {
    let directory = tempfile::tempdir().unwrap();
    let value = kubernetes::manifest(&spec(directory.path())).unwrap();
    let agent_secret = &value["items"][0];
    let shipper_secret = &value["items"][1];
    assert!(agent_secret["data"].get("CODEX_API_KEY").is_some());
    assert!(shipper_secret["data"].get("CODEX_API_KEY").is_none());
    assert_ne!(
        agent_secret["data"]["FLEET_RECALL_TOKEN"],
        shipper_secret["data"]["FLEET_RECALL_TOKEN"]
    );
    let pod = &value["items"][2]["spec"];
    assert_eq!(pod["automountServiceAccountToken"], false);
    assert_eq!(pod["enableServiceLinks"], false);
    assert_eq!(pod["runtimeClassName"], "kata-qemu-runtime-rs");
    assert_eq!(pod["initContainers"][0]["restartPolicy"], "Always");
    assert_eq!(
        pod["initContainers"][0]["volumeMounts"][0]["readOnly"],
        true
    );
    assert_eq!(pod["containers"].as_array().unwrap().len(), 1);
    assert!(!value.to_string().contains("hostPath"));
    assert!(!pod.to_string().contains("secret-token"));
}

#[test]
fn retained_ca_is_read_only_in_both_runtimes_and_separate_from_credentials() {
    use std::os::unix::fs::PermissionsExt as _;
    let directory = tempfile::tempdir().unwrap();
    let value = args(directory.path());
    let pem = include_bytes!("../../tests/fixtures/tls/ca-first.pem");
    let (file, state) =
        StateFile::create(&value, "recall-test", value.url.clone(), Some(pem)).unwrap();
    let path = state.ca_path.unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), pem);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o444
    );
    assert_eq!(
        std::fs::metadata(file.directory())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    let mut value = spec(file.directory());
    value.ca_path = Some(path.clone());
    value.validate().unwrap();
    for agent in [true, false] {
        let args = docker::command_arguments(&value, agent).unwrap();
        let expected = format!(
            "type=bind,src={},dst={SANDBOX_CA_PATH},readonly",
            path.display()
        );
        assert!(
            args.windows(2)
                .any(|pair| pair[0] == "--mount" && pair[1] == expected)
        );
        assert!(!args.join(" ").contains("BEGIN CERTIFICATE"));
    }
    let manifest = kubernetes::manifest(&value).unwrap();
    assert_eq!(manifest["items"][2]["kind"], "ConfigMap");
    assert_eq!(manifest["items"][2]["immutable"], true);
    assert_eq!(
        manifest["items"][2]["binaryData"]["ca.pem"],
        crate::encoding::base64::encode(pem)
    );
    let pod = &manifest["items"][3]["spec"];
    for container in ["containers", "initContainers"] {
        assert!(
            pod[container][0]["volumeMounts"]
                .as_array()
                .unwrap()
                .iter()
                .any(|mount| mount["name"] == "recall-ca"
                    && mount["readOnly"] == true
                    && mount["mountPath"] == "/etc/fleet-recall")
        );
    }
    assert!(!manifest["items"][0].to_string().contains("ca.pem"));
    assert!(!manifest["items"][1].to_string().contains("ca.pem"));
}

#[test]
fn ca_mount_rejects_path_injection_and_symlink_substitution_before_effects() {
    use std::os::unix::fs::symlink;
    let directory = tempfile::tempdir().unwrap();
    let mut value = spec(directory.path());
    value.ca_path = Some(directory.path().join("../other-ca.pem"));
    assert!(value.validate().is_err());
    let cert = directory.path().join("certificate.pem");
    std::fs::write(
        &cert,
        include_bytes!("../../tests/fixtures/tls/ca-first.pem"),
    )
    .unwrap();
    let link = directory.path().join("recall-ca.pem");
    symlink(cert, &link).unwrap();
    value.ca_path = Some(link);
    assert!(value.validate().is_err());
    value.state_dir = directory.path().join("state,readonly=false");
    value.ca_path = Some(value.state_dir.join("recall-ca.pem"));
    assert!(value.validate().is_err());
}

#[test]
fn protected_state_refuses_broad_modes_and_symlinks() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    let directory = tempfile::tempdir().unwrap();
    let value = args(directory.path());
    std::fs::create_dir(&value.state_dir).unwrap();
    std::fs::set_permissions(&value.state_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(
        StateFile::create(
            &value,
            "recall-test",
            "http://localhost:8080/mcp".into(),
            None
        )
        .is_err()
    );
    std::fs::set_permissions(&value.state_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let (file, state) = StateFile::create(
        &value,
        "recall-test",
        "http://localhost:8080/mcp".into(),
        None,
    )
    .unwrap();
    assert_eq!(
        std::fs::metadata(file.path()).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(StateFile::load(file.path()).is_ok());
    let link = directory.path().join("linked-auth");
    symlink(file.path(), &link).unwrap();
    assert!(state::read_bounded(&link, 65_536, true).is_err());
    assert!(serde_json::to_string(&state).unwrap().contains("preparing"));
}

#[test]
fn provider_inputs_are_opt_in_and_never_shared_with_shipper() {
    let directory = tempfile::tempdir().unwrap();
    let mut value = args(directory.path());
    let env = agent_environment(&value, "instance").unwrap();
    assert!(!env.contains_key("CODEX_API_KEY"));
    assert!(!env.contains_key("ANTHROPIC_API_KEY"));
    assert!(!env.contains_key("PGPASSWORD"));
    value.harness = Harness::Codex;
    let path = directory.path().join("auth.json");
    state::write_private_new(&path, b"{\"tokens\":{\"access_token\":\"test-only\"}}").unwrap();
    value.codex_auth_file = Some(path);
    let env = agent_environment(&value, "instance").unwrap();
    assert!(env.contains_key("FLEET_SANDBOX_CODEX_AUTH_B64"));
    assert!(!env.contains_key("CODEX_HOME"));
}

#[test]
fn https_and_http_permission_apply_to_every_launcher_url() {
    let directory = tempfile::tempdir().unwrap();
    let mut value = args(directory.path());
    value.allow_http = false;
    assert!(validate_up(&value).is_err());
    value.url = "https://recall.example/mcp".into();
    value.sandbox_url = None;
    assert!(validate_up(&value).is_ok());
    for http in [
        "http://localhost/mcp",
        "http://127.0.0.1/mcp",
        "http://[::1]/mcp",
        "http://recall/mcp",
    ] {
        value.sandbox_url = Some(http.into());
        assert!(validate_up(&value).is_err());
        value.allow_http = true;
        assert!(validate_up(&value).is_ok());
        assert_eq!(
            agent_environment(&value, "instance").unwrap()["FLEET_RECALL_ALLOW_HTTP"],
            "true"
        );
        value.allow_http = false;
    }
    value.sandbox_url = None;
    value.resource_url = Some("http://localhost/mcp".into());
    assert!(validate_up(&value).is_err());
    value.resource_url = None;
    assert!(
        !agent_environment(&value, "instance")
            .unwrap()
            .contains_key("FLEET_RECALL_ALLOW_HTTP")
    );
}

#[test]
fn ttl_covers_startup_execution_and_final_flush_before_effects() {
    let directory = tempfile::tempdir().unwrap();
    let mut value = args(directory.path());
    value.ttl_seconds = required_remaining_seconds(value.timeout_seconds) + ISSUANCE_MARGIN_SECONDS;
    assert!(validate_up(&value).is_ok());
    value.ttl_seconds -= 1;
    assert!(validate_up(&value).is_err());
    value.timeout_seconds = 3600;
    value.ttl_seconds = 3600;
    assert!(validate_up(&value).is_err());
    value.ttl_seconds = 86400;
    assert!(validate_up(&value).is_ok());
}

#[test]
fn grant_lifetime_allows_bounded_clock_skew_but_not_expiry_or_extended_ttl() {
    let now = chrono::Utc::now();
    let mut grant = SessionGrant {
        jti: Uuid::now_v7(),
        kind: crate::auth::grant::GrantKind::Agent,
        principal_id: Uuid::now_v7(),
        principal_revision: 1,
        tenant_id: Uuid::now_v7(),
        project: "local-k0s".into(),
        agent: "sandbox-test".into(),
        ceiling: crate::auth::registry::Ceiling::Project,
        sandbox_id: Some(Uuid::now_v7().to_string()),
        issued_at: now + chrono::Duration::milliseconds(100),
        expires_at: now + chrono::Duration::seconds(3600) + chrono::Duration::milliseconds(100),
    };
    assert!(valid_grant_lifetime(&grant, 3600, now));
    grant.issued_at = now + chrono::Duration::seconds(60);
    grant.expires_at = grant.issued_at + chrono::Duration::seconds(3600);
    assert!(valid_grant_lifetime(&grant, 3600, now));
    grant.issued_at += chrono::Duration::milliseconds(1);
    assert!(!valid_grant_lifetime(&grant, 3600, now));
    grant.issued_at = now;
    grant.expires_at = now + chrono::Duration::seconds(3600) + chrono::Duration::milliseconds(1);
    assert!(!valid_grant_lifetime(&grant, 3600, now));
    grant.expires_at = now;
    assert!(!valid_grant_lifetime(&grant, 3600, now));
    grant.issued_at = now + chrono::Duration::seconds(1);
    assert!(!valid_grant_lifetime(&grant, 3600, now));
}

#[test]
fn remaining_lifetime_boundary_rechecks_the_first_grant_after_second_issuance() {
    let now = chrono::Utc::now();
    let duration =
        chrono::Duration::seconds(i64::try_from(required_remaining_seconds(300)).unwrap());
    let grant = SessionGrant {
        jti: Uuid::now_v7(),
        kind: crate::auth::grant::GrantKind::Agent,
        principal_id: Uuid::now_v7(),
        principal_revision: 1,
        tenant_id: Uuid::now_v7(),
        project: "local-k0s".into(),
        agent: "sandbox-test".into(),
        ceiling: crate::auth::registry::Ceiling::Project,
        sandbox_id: Some(Uuid::now_v7().to_string()),
        issued_at: now,
        expires_at: now + duration,
    };
    let mut grants = vec![
        GrantResponse {
            token: "agent".into(),
            grant: grant.clone(),
        },
        GrantResponse {
            token: "shipper".into(),
            grant,
        },
    ];
    assert!(sufficient_remaining_lifetime(&grants, 300, now));
    assert_eq!(
        sandbox_start_before(&grants, 300),
        now.timestamp() + i64::try_from(STARTUP_MARGIN_SECONDS).unwrap()
    );
    grants[1].grant.expires_at += chrono::Duration::seconds(30);
    assert_eq!(
        sandbox_start_before(&grants, 300),
        now.timestamp() + i64::try_from(STARTUP_MARGIN_SECONDS).unwrap()
    );
    assert!(!sufficient_remaining_lifetime(
        &grants,
        300,
        now + chrono::Duration::milliseconds(1)
    ));
    grants[0].grant.expires_at += chrono::Duration::seconds(30);
    assert!(sufficient_remaining_lifetime(
        &grants,
        300,
        now + chrono::Duration::seconds(30)
    ));
    assert!(!sufficient_remaining_lifetime(
        &grants,
        300,
        now + chrono::Duration::seconds(31)
    ));
}

fn fake_program(directory: &Path, name: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt as _;
    let program = directory.join(name);
    let log = serde_json::to_string(&directory.join(format!("{name}.jsonl"))).unwrap();
    let script = format!(
        "#!/usr/bin/python3\nimport json, os, sys\nwith open({log}, 'a') as f: f.write(json.dumps({{'argv':sys.argv[1:],'env':dict(os.environ),'input':sys.stdin.read()}})+'\\n')\n"
    );
    std::fs::write(&program, script).unwrap();
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700)).unwrap();
    program
}

fn recorded(directory: &Path, name: &str) -> Vec<Value> {
    std::fs::read_to_string(directory.join(format!("{name}.jsonl")))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[tokio::test]
async fn fake_docker_records_safe_argv_and_revocable_resources() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = docker::DockerBackend {
        program: fake_program(directory.path(), "docker"),
    };
    let value = spec(directory.path());
    let handle = runtime.create(&value).await.unwrap();
    runtime.destroy(&handle).await.unwrap();
    let calls = recorded(directory.path(), "docker");
    assert_eq!(calls.len(), 7);
    for call in &calls {
        assert!(!call["argv"].to_string().contains("secret"));
        for key in call["env"].as_object().unwrap().keys() {
            assert!(
                !key.starts_with("FLEET_") && !key.starts_with("PG") && !key.contains("API_KEY")
            );
        }
    }
    assert_eq!(calls[3]["argv"][3], "recall-test");
    assert_eq!(calls[5]["argv"][3], "recall-test-shipper");
    assert!(
        std::fs::read_to_string(directory.path().join("agent.env"))
            .unwrap()
            .contains("provider-secret")
    );
    assert!(
        !std::fs::read_to_string(directory.path().join("shipper.env"))
            .unwrap()
            .contains("provider-secret")
    );
}

#[tokio::test]
async fn fake_kubectl_receives_credentials_only_via_stdin() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = kubernetes::KubernetesBackend {
        program: fake_program(directory.path(), "kubectl"),
    };
    let handle = runtime.create(&spec(directory.path())).await.unwrap();
    runtime.destroy(&handle).await.unwrap();
    let calls = recorded(directory.path(), "kubectl");
    assert_eq!(calls.len(), 4);
    assert!(
        calls[0]["argv"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "--server-side")
    );
    assert!(!calls[0]["argv"].to_string().contains("secret"));
    let input: Value = serde_json::from_str(calls[0]["input"].as_str().unwrap()).unwrap();
    assert_eq!(input["items"][0]["kind"], "Secret");
    assert_eq!(calls[1]["argv"][1], "pod");
    assert_eq!(calls[2]["argv"][1], "secret");
    assert_eq!(calls[3]["argv"][1], "configmap");
}

#[derive(Default)]
struct FakeBackend {
    fail_create: bool,
    fail_destroy: bool,
    expect_tls: bool,
    events: Mutex<Vec<&'static str>>,
}
#[async_trait]
impl SandboxBackend for FakeBackend {
    async fn create(&self, spec: &SandboxSpecV1) -> anyhow::Result<SandboxHandle> {
        self.events.lock().unwrap().push("create");
        if self.expect_tls {
            spec.validate()?;
            assert_eq!(spec.env["FLEET_RECALL_CA_PATH"], SANDBOX_CA_PATH);
            assert!(
                spec.shipper_args
                    .windows(2)
                    .any(|pair| pair == ["--ca-path", SANDBOX_CA_PATH])
            );
            assert!(
                !spec
                    .shipper_args
                    .iter()
                    .any(|argument| argument == "--allow-http")
            );
            assert!(!spec.env.contains_key("FLEET_RECALL_ALLOW_HTTP"));
            assert!(!spec.env.contains_key("SSL_CERT_FILE"));
            assert!(!spec.env.contains_key("CODEX_CA_CERTIFICATE"));
            assert_eq!(spec.shipper_env.len(), 1);
            assert!(spec.env.contains_key("FLEET_SANDBOX_START_BEFORE_UNIX"));
            assert_ne!(
                spec.shipper_env["FLEET_RECALL_TOKEN"],
                spec.env["FLEET_RECALL_TOKEN"]
            );
        }
        ensure!(!self.fail_create, "injected create failure");
        Ok(SandboxHandle {
            name: spec.name.clone(),
            namespace: spec.namespace.clone(),
            transcript_volume: spec.transcript_volume.clone(),
        })
    }
    async fn destroy(&self, _: &SandboxHandle) -> anyhow::Result<()> {
        self.events.lock().unwrap().push("destroy");
        ensure!(!self.fail_destroy, "injected destroy failure");
        Ok(())
    }
}

#[derive(Default)]
struct GrantFixture {
    events: Mutex<Vec<String>>,
    fail_second: bool,
    mismatched_scope: bool,
    fail_revoke: bool,
    short_grant: Option<&'static str>,
}

async fn issue(
    State(state): State<Arc<GrantFixture>>,
    Json(request): Json<Value>,
) -> (StatusCode, Json<Value>) {
    let kind = request["kind"].as_str().unwrap();
    state.events.lock().unwrap().push(format!("issue-{kind}"));
    if state.fail_second && kind == "shipper" {
        return (StatusCode::FORBIDDEN, Json(json!({})));
    }
    let now = chrono::Utc::now();
    let ttl = if state.short_grant == Some(kind) {
        30
    } else {
        request["ttl_seconds"].as_i64().unwrap()
    };
    (
        StatusCode::CREATED,
        Json(
            json!({"token":format!("token-{kind}"),"grant":{"jti":Uuid::now_v7(),"kind":kind,"principal_id":"0198a849-f6ae-7d61-9800-000000000101","principal_revision":1,"tenant_id":"0198a849-f6ae-7d61-9800-000000000001","project":if state.mismatched_scope {"other"} else {"local-k0s"},"agent":request["agent"],"ceiling":"project","sandbox_id":request["sandbox_id"],"issued_at":now,"expires_at":now+chrono::Duration::seconds(ttl)}}),
        ),
    )
}
async fn revoke(State(state): State<Arc<GrantFixture>>) -> StatusCode {
    state.events.lock().unwrap().push("revoke".into());
    if state.fail_revoke {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::NO_CONTENT
    }
}

async fn fixture(state: Arc<GrantFixture>) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/mcp", listener.local_addr().unwrap());
    let router = Router::new()
        .route("/v1/grants", post(issue))
        .route("/v1/grants/{id}", delete(revoke))
        .with_state(state);
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (url, task)
}

fn load_only_state(parent: &Path) -> LaunchState {
    let directory = std::fs::read_dir(parent)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    StateFile::load(&directory.join("launch-state.json"))
        .unwrap()
        .1
}

#[tokio::test]
async fn creation_failure_revokes_both_grants_and_retains_retry_state() {
    let directory = tempfile::tempdir().unwrap();
    let mut value = args(directory.path());
    state::write_private_new(&value.anchor.service_account_token_file, b"test-sa-token").unwrap();
    let grants = Arc::new(GrantFixture::default());
    let (url, task) = fixture(grants.clone()).await;
    value.url = url;
    let state_dir = value.state_dir.clone();
    let runtime = FakeBackend {
        fail_create: true,
        fail_destroy: true,
        ..Default::default()
    };
    assert!(launch_up_with_backend(value, &runtime).await.is_err());
    assert_eq!(*runtime.events.lock().unwrap(), vec!["create", "destroy"]);
    assert_eq!(
        *grants.events.lock().unwrap(),
        vec!["issue-agent", "issue-shipper", "revoke", "revoke"]
    );
    let state = load_only_state(&state_dir);
    assert_eq!(state.phase, "cleanup-pending");
    assert!(state.grants.iter().all(|g| g.revoked));
    assert!(!state.runtime_stopped);
    task.abort();
}

#[tokio::test]
async fn second_grant_failure_revokes_first_and_never_starts_runtime() {
    let directory = tempfile::tempdir().unwrap();
    let mut value = args(directory.path());
    state::write_private_new(&value.anchor.service_account_token_file, b"test-sa-token").unwrap();
    let grants = Arc::new(GrantFixture {
        fail_second: true,
        ..Default::default()
    });
    let (url, task) = fixture(grants.clone()).await;
    value.url = url;
    let runtime = FakeBackend::default();
    assert!(launch_up_with_backend(value, &runtime).await.is_err());
    assert!(runtime.events.lock().unwrap().is_empty());
    assert_eq!(
        *grants.events.lock().unwrap(),
        vec!["issue-agent", "issue-shipper", "revoke"]
    );
    task.abort();
}

#[tokio::test]
async fn mismatched_grant_is_revoked_and_failed_revocation_stays_pending() {
    let directory = tempfile::tempdir().unwrap();
    let mut value = args(directory.path());
    state::write_private_new(&value.anchor.service_account_token_file, b"test-sa-token").unwrap();
    let grants = Arc::new(GrantFixture {
        mismatched_scope: true,
        fail_revoke: true,
        ..Default::default()
    });
    let (url, task) = fixture(grants.clone()).await;
    value.url = url;
    let state_dir = value.state_dir.clone();
    let runtime = FakeBackend::default();
    assert!(launch_up_with_backend(value, &runtime).await.is_err());
    assert!(runtime.events.lock().unwrap().is_empty());
    let state = load_only_state(&state_dir);
    assert_eq!(state.phase, "cleanup-pending");
    assert!(!state.grants[0].revoked);
    assert_eq!(
        *grants.events.lock().unwrap(),
        vec!["issue-agent", "revoke"]
    );
    task.abort();
}

#[tokio::test]
async fn insufficient_remaining_lifetime_revokes_both_before_runtime_creation() {
    for short_grant in ["agent", "shipper"] {
        let directory = tempfile::tempdir().unwrap();
        let mut value = args(directory.path());
        state::write_private_new(&value.anchor.service_account_token_file, b"test-sa-token")
            .unwrap();
        let grants = Arc::new(GrantFixture {
            short_grant: Some(short_grant),
            ..Default::default()
        });
        let (url, task) = fixture(grants.clone()).await;
        value.url = url;
        let state_dir = value.state_dir.clone();
        let runtime = FakeBackend::default();
        assert!(launch_up_with_backend(value, &runtime).await.is_err());
        assert!(runtime.events.lock().unwrap().is_empty());
        assert_eq!(
            *grants.events.lock().unwrap(),
            vec!["issue-agent", "issue-shipper", "revoke", "revoke"]
        );
        let state = load_only_state(&state_dir);
        assert_eq!(state.phase, "stopped");
        assert!(!state.runtime_started);
        assert!(state.grants.iter().all(|grant| grant.revoked));
        task.abort();
    }
}

#[tokio::test]
async fn invalid_ca_fails_before_grants_or_runtime_or_state() {
    let directory = tempfile::tempdir().unwrap();
    let mut value = args(directory.path());
    let ca_path = directory.path().join("not-ca.pem");
    std::fs::write(
        &ca_path,
        b"-----BEGIN PRIVATE KEY-----\nnot a certificate\n",
    )
    .unwrap();
    value.ca_path = Some(ca_path);
    let state_dir = value.state_dir.clone();
    let runtime = FakeBackend::default();
    assert!(launch_up_with_backend(value, &runtime).await.is_err());
    assert!(runtime.events.lock().unwrap().is_empty());
    assert!(!state_dir.exists());
}

#[tokio::test]
async fn legacy_state_can_revoke_http_grants_without_new_launch_permission() {
    let directory = tempfile::tempdir().unwrap();
    let mut value = args(directory.path());
    state::write_private_new(&value.anchor.service_account_token_file, b"test-sa-token").unwrap();
    let grants = Arc::new(GrantFixture::default());
    let (url, task) = fixture(grants.clone()).await;
    value.url = url.clone();
    let (file, mut state) = StateFile::create(&value, "recall-legacy", url, None).unwrap();
    state.runtime_started = true;
    state.grants.push(state::GrantState {
        id: Uuid::now_v7(),
        revoked: false,
    });
    let mut legacy = serde_json::to_value(state).unwrap();
    legacy.as_object_mut().unwrap().remove("ca_path");
    legacy.as_object_mut().unwrap().remove("allow_http");
    std::fs::write(file.path(), serde_json::to_vec(&legacy).unwrap()).unwrap();
    let (file, mut state) = StateFile::load(file.path()).unwrap();
    assert!(state.allow_http.is_none());
    let runtime = FakeBackend::default();
    launch_down_with_backend(&file, &mut state, &runtime)
        .await
        .unwrap();
    assert_eq!(*runtime.events.lock().unwrap(), vec!["destroy"]);
    assert_eq!(*grants.events.lock().unwrap(), vec!["revoke"]);
    assert_eq!(state.phase, "stopped");
    task.abort();
}

#[tokio::test]
async fn missing_retained_ca_still_stops_runtime_and_keeps_revocations_pending() {
    let directory = tempfile::tempdir().unwrap();
    let value = args(directory.path());
    let (file, mut state) = StateFile::create(
        &value,
        "recall-missing-ca",
        "https://recall.example/mcp".into(),
        None,
    )
    .unwrap();
    state.ca_path = Some(file.directory().join("recall-ca.pem"));
    state.runtime_started = true;
    state.grants.push(state::GrantState {
        id: Uuid::now_v7(),
        revoked: false,
    });
    file.save(&state).unwrap();
    let runtime = FakeBackend::default();
    assert!(
        launch_down_with_backend(&file, &mut state, &runtime)
            .await
            .is_err()
    );
    assert_eq!(*runtime.events.lock().unwrap(), vec!["destroy"]);
    assert!(state.runtime_stopped);
    assert_eq!(state.phase, "cleanup-pending");
    assert!(!state.grants[0].revoked);
}

#[tokio::test]
async fn custom_ca_launch_and_down_keep_original_trust_after_source_bundle_changes() {
    use crate::client_tls::tests::{CA_FIRST, CA_SECOND, KEY_FIRST, SERVER_FIRST, serve_tls};
    let directory = tempfile::tempdir().unwrap();
    let mut value = args(directory.path());
    value.allow_http = false;
    value.sandbox_url = None;
    state::write_private_new(&value.anchor.service_account_token_file, b"test-sa-token").unwrap();
    let source = directory.path().join("operator-ca.pem");
    std::fs::write(&source, CA_FIRST).unwrap();
    let grants = Arc::new(GrantFixture::default());
    let router = Router::new()
        .route("/v1/grants", post(issue))
        .route("/v1/grants/{id}", delete(revoke))
        .with_state(grants.clone());
    let (base, task) = serve_tls(router, SERVER_FIRST, KEY_FIRST).await;
    value.url = format!("{base}/mcp");
    let untrusted = GrantClient::new(
        &value.url,
        value.url.clone(),
        value.anchor.clone(),
        None,
        false,
    )
    .unwrap();
    assert!(untrusted.issue("agent", &value, "test").await.is_err());
    assert!(grants.events.lock().unwrap().is_empty());
    value.ca_path = Some(source.clone());
    let state_dir = value.state_dir.clone();
    let runtime = FakeBackend {
        expect_tls: true,
        ..Default::default()
    };
    launch_up_with_backend(value, &runtime).await.unwrap();
    let state = load_only_state(&state_dir);
    assert_eq!(state.allow_http, Some(false));
    assert_ne!(state.ca_path.as_ref().unwrap(), &source);
    let path = state_dir.join(&state.handle.name).join("launch-state.json");
    std::fs::write(source, CA_SECOND).unwrap();
    let (file, mut state) = StateFile::load(&path).unwrap();
    launch_down_with_backend(&file, &mut state, &runtime)
        .await
        .unwrap();
    assert_eq!(
        *grants.events.lock().unwrap(),
        vec!["issue-agent", "issue-shipper", "revoke", "revoke"]
    );
    assert_eq!(*runtime.events.lock().unwrap(), vec!["create", "destroy"]);
    assert_eq!(state.phase, "stopped");
    task.abort();
}
