use super::*;
use crate::connectors::transcript::{TranscriptFormat, parse_codex_transcript};
use crate::mcp::{
    McpServer,
    http::{HttpBackend, HttpConfig, HttpError, router},
};
use async_trait::async_trait;
use axum::http::StatusCode;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::{io::Write as _, sync::Arc};
use uuid::Uuid;

fn auth() -> TranscriptAuthorization {
    TranscriptAuthorization {
        tenant_id: Uuid::now_v7(),
        project: "sandbox-test".into(),
        principal_id: Uuid::now_v7(),
        agent: "sandbox-agent".into(),
        sandbox_id: Uuid::now_v7().to_string(),
    }
}
fn upload(auth: &TranscriptAuthorization, first: &[u8]) -> TranscriptUpload {
    let digest = hex::encode(Sha256::digest(first));
    let source = "sessions/nested/session.jsonl";
    TranscriptUpload {
        instance: auth.sandbox_id.clone(),
        file: stable_file_name(&auth.sandbox_id, TranscriptFormat::Codex, source, &digest),
        source: source.into(),
        format: TranscriptFormat::Codex,
        first_line_sha256: digest,
        offset: 0,
    }
}

#[test]
fn worker_spool_groups_are_scoped_and_choose_the_native_parser() {
    let root = tempfile::tempdir().unwrap();
    let scope = crate::FleetScope::new(
        Uuid::now_v7(),
        "sandbox-test",
        "worker",
        None,
        ostk_recall_core::PrivacyTier::T1Project,
    )
    .unwrap();
    let mut sources =
        crate::worker::WorkerSourcesV1::from_json_slice(br#"{"schema_version":1}"#).unwrap();
    sources.add_transcript_spool(root.path(), &scope).unwrap();
    assert_eq!(sources.transcripts.len(), 2);
    for group in &sources.transcripts {
        assert_eq!(
            group.connector_principal.as_str(),
            "connector.transcript.sandbox"
        );
        assert!(
            group.dirs[0].starts_with(
                scope_spool_dir(root.path(), scope.tenant_id, &scope.project).unwrap()
            )
        );
        assert_eq!(group.dirs[0].file_name().unwrap(), group.format.as_str());
    }
    assert_ne!(
        sources.transcripts[0].format.parser_key(),
        sources.transcripts[1].format.parser_key()
    );
    assert!(sources.add_transcript_spool(root.path(), &scope).is_err());
    let mut malicious = scope;
    malicious.project = "../outside".into();
    assert!(
        sources
            .add_transcript_spool(root.path(), &malicious)
            .is_err()
    );
}

#[tokio::test]
async fn append_replay_offset_binding_and_scope_isolation() {
    let dir = tempfile::tempdir().unwrap();
    let receiver = Arc::new(
        TranscriptReceiver::new(TranscriptReceiverConfig::new(dir.path().into())).unwrap(),
    );
    let auth = auth();
    let first = b"{\"first\":1}\n";
    let mut request = upload(&auth, first);
    assert_eq!(
        receiver
            .receive(auth.clone(), request.clone(), None)
            .await
            .unwrap()
            .length,
        0
    );
    assert!(
        !receiver
            .receive(auth.clone(), request.clone(), Some(first.to_vec()))
            .await
            .unwrap()
            .replayed
    );
    assert!(
        receiver
            .receive(auth.clone(), request.clone(), Some(first.to_vec()))
            .await
            .unwrap()
            .replayed
    );
    let altered = b"{\"first\":2}\n";
    assert!(matches!(
        receiver
            .receive(auth.clone(), request.clone(), Some(altered.to_vec()))
            .await,
        Err(TranscriptError::Conflict(_))
    ));
    request.offset = first.len() as u64 + 1;
    assert!(matches!(
        receiver
            .receive(auth.clone(), request.clone(), Some(b"next\n".to_vec()))
            .await,
        Err(TranscriptError::Conflict(_))
    ));
    request.offset = first.len() as u64;
    assert_eq!(
        receiver
            .receive(auth.clone(), request.clone(), Some(b"next\n".to_vec()))
            .await
            .unwrap()
            .length,
        first.len() as u64 + 5
    );
    let mut foreign = auth.clone();
    foreign.principal_id = Uuid::now_v7();
    assert!(matches!(
        receiver.receive(foreign, request.clone(), None).await,
        Err(TranscriptError::Invalid)
    ));
    let mut foreign = auth.clone();
    foreign.sandbox_id = Uuid::now_v7().to_string();
    assert!(matches!(
        receiver.receive(foreign, request.clone(), None).await,
        Err(TranscriptError::Invalid)
    ));
    let mut other_scope = auth;
    other_scope.tenant_id = Uuid::now_v7();
    assert_eq!(
        receiver
            .receive(other_scope, request, None)
            .await
            .unwrap()
            .length,
        0
    );
}

#[tokio::test]
async fn traversal_symlink_partial_and_quota_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let target = tempfile::NamedTempFile::new().unwrap();
    let config = TranscriptReceiverConfig {
        root: dir.path().into(),
        window_bytes: 16,
        max_file_bytes: 16,
        max_scope_bytes: 16,
    };
    let receiver = Arc::new(TranscriptReceiver::new(config).unwrap());
    let auth = auth();
    let first = b"12345678\n";
    let mut request = upload(&auth, first);
    let scope = receiver
        .prepare_scope(auth.tenant_id, &auth.project)
        .unwrap();
    std::os::unix::fs::symlink(target.path(), scope.join("codex").join(&request.file)).unwrap();
    assert!(
        receiver
            .receive(auth.clone(), request.clone(), Some(first.to_vec()))
            .await
            .is_err()
    );
    request.source = "../private.jsonl".into();
    assert!(matches!(
        receiver
            .receive(auth.clone(), request.clone(), Some(first.to_vec()))
            .await,
        Err(TranscriptError::Invalid)
    ));
    let mut request = upload(&auth, b"other\n");
    assert!(matches!(
        receiver
            .receive(auth.clone(), request.clone(), Some(b"partial".to_vec()))
            .await,
        Err(TranscriptError::Invalid)
    ));
    // A new scope avoids the deliberately planted symlink quota scan.
    let mut auth = auth;
    auth.tenant_id = Uuid::now_v7();
    receiver
        .receive(auth.clone(), request.clone(), Some(b"other\n".to_vec()))
        .await
        .unwrap();
    request.offset = 6;
    assert!(matches!(
        receiver
            .receive(auth, request, Some(b"12345678901\n".to_vec()))
            .await,
        Err(TranscriptError::Quota)
    ));
    assert_eq!(std::fs::metadata(target.path()).unwrap().len(), 0);
}

struct Backend {
    receiver: Arc<TranscriptReceiver>,
    auth: TranscriptAuthorization,
}
#[async_trait]
impl HttpBackend for Backend {
    async fn authenticate(&self, _: &str) -> Result<Arc<McpServer>, HttpError> {
        Err(HttpError::Forbidden)
    }
    async fn issue_grant(&self, _: &str, _: Value) -> Result<Value, HttpError> {
        Err(HttpError::Forbidden)
    }
    async fn revoke_grant(&self, _: &str, _: &str) -> Result<(), HttpError> {
        Err(HttpError::Forbidden)
    }
    async fn exchange_aws(&self, _: Value) -> Result<Value, HttpError> {
        Err(HttpError::Forbidden)
    }
    async fn transcript_receiver(
        &self,
        bearer: &str,
        instance: &str,
    ) -> Result<(Arc<TranscriptReceiver>, TranscriptAuthorization), HttpError> {
        if bearer != "shipper" {
            return Err(HttpError::Unauthorized);
        }
        if instance != self.auth.sandbox_id {
            return Err(HttpError::Forbidden);
        }
        Ok((self.receiver.clone(), self.auth.clone()))
    }
}

#[tokio::test]
async fn shipper_http_restart_partial_line_and_codex_provenance() {
    let spool = tempfile::tempdir().unwrap();
    let source = tempfile::tempdir().unwrap();
    std::fs::create_dir(source.path().join("nested")).unwrap();
    let path = source.path().join("nested/rollout.jsonl");
    let first=b"{\"timestamp\":\"2026-09-27T18:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"codex-session\",\"cli_version\":\"0.118.0\"}}\n";
    let turn=b"{\"timestamp\":\"2026-09-27T18:00:01Z\",\"type\":\"response_item\",\"payload\":{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"sandbox marker\"}]}}\n";
    let mut bytes = first.to_vec();
    bytes.extend_from_slice(&turn[..turn.len() - 1]);
    std::fs::write(&path, &bytes).unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    std::os::unix::fs::symlink(outside.path(), source.path().join("escape.jsonl")).unwrap();
    let auth = auth();
    let receiver = Arc::new(
        TranscriptReceiver::new(TranscriptReceiverConfig::new(spool.path().into())).unwrap(),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let url = format!("http://{address}/mcp");
    let app = router(
        HttpConfig::new(url.clone(), vec![]),
        Arc::new(Backend {
            receiver,
            auth: auth.clone(),
        }),
    )
    .unwrap();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let config = ShipperConfig {
        dir: source.path().into(),
        url,
        instance: auth.sandbox_id.clone(),
        format: TranscriptFormat::Codex,
        token: "shipper".into(),
        ca_path: None,
        once: true,
    };
    assert_eq!(ship_once(&config).await.unwrap().files, 1);
    let name = stable_file_name(
        &auth.sandbox_id,
        TranscriptFormat::Codex,
        "nested/rollout.jsonl",
        &hex::encode(Sha256::digest(first)),
    );
    let saved = scope_spool_dir(spool.path(), auth.tenant_id, &auth.project)
        .unwrap()
        .join("codex")
        .join(name);
    assert_eq!(std::fs::read(&saved).unwrap(), first);
    std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .unwrap()
        .write_all(b"\n")
        .unwrap();
    ship_once(&config).await.unwrap(); // fresh state replays the acknowledged prefix
    let stored = std::fs::read(&saved).unwrap();
    assert_eq!(stored, std::fs::read(&path).unwrap());
    let parsed = parse_codex_transcript("rollout", &stored, 0, 0).unwrap();
    assert_eq!(parsed.turns[0].session_id, "codex-session");
    assert_eq!(parsed.turns[0].text, "sandbox marker");
    let response = reqwest::Client::new()
        .put(format!(
            "http://{address}/v1/transcripts/{}/file.jsonl",
            auth.sandbox_id
        ))
        .body("untrusted")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    server.abort();
}
