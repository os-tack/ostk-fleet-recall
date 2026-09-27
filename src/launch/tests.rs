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
    let value = kubernetes::manifest(&spec(directory.path()));
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
fn protected_state_refuses_broad_modes_and_symlinks() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    let directory = tempfile::tempdir().unwrap();
    let value = args(directory.path());
    std::fs::create_dir(&value.state_dir).unwrap();
    std::fs::set_permissions(&value.state_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(StateFile::create(&value, "recall-test", "http://localhost:8080/mcp".into()).is_err());
    std::fs::set_permissions(&value.state_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let (file, state) =
        StateFile::create(&value, "recall-test", "http://localhost:8080/mcp".into()).unwrap();
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
    assert_eq!(calls.len(), 3);
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
}

#[derive(Default)]
struct FakeBackend {
    fail_create: bool,
    fail_destroy: bool,
    events: Mutex<Vec<&'static str>>,
}
#[async_trait]
impl SandboxBackend for FakeBackend {
    async fn create(&self, spec: &SandboxSpecV1) -> anyhow::Result<SandboxHandle> {
        self.events.lock().unwrap().push("create");
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
    (
        StatusCode::CREATED,
        Json(
            json!({"token":format!("token-{kind}"),"grant":{"jti":Uuid::now_v7(),"kind":kind,"principal_id":"0198a849-f6ae-7d61-9800-000000000101","principal_revision":1,"tenant_id":"0198a849-f6ae-7d61-9800-000000000001","project":if state.mismatched_scope {"other"} else {"local-k0s"},"agent":request["agent"],"ceiling":"project","sandbox_id":request["sandbox_id"],"issued_at":now,"expires_at":now+chrono::Duration::seconds(3600)}}),
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
