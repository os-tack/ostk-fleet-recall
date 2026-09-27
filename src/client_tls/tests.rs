use super::*;
use std::{net::SocketAddr, sync::Arc};

use axum::{Router, routing::get};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject as _},
    },
    server::TlsStream,
};

pub const CA_FIRST: &[u8] = include_bytes!("../../tests/fixtures/tls/ca-first.pem");
pub const CA_SECOND: &[u8] = include_bytes!("../../tests/fixtures/tls/ca-second.pem");
pub const SERVER_FIRST: &[u8] = include_bytes!("../../tests/fixtures/tls/server-first.pem");
pub const KEY_FIRST: &[u8] = include_bytes!("../../tests/fixtures/tls/server-first-key.pem");
const SERVER_SECOND: &[u8] = include_bytes!("../../tests/fixtures/tls/server-second.pem");
const KEY_SECOND: &[u8] = include_bytes!("../../tests/fixtures/tls/server-second-key.pem");
const SERVER_EXPIRED: &[u8] = include_bytes!("../../tests/fixtures/tls/server-expired.pem");

struct TlsListener {
    tcp: TcpListener,
    acceptor: TlsAcceptor,
}

impl axum::serve::Listener for TlsListener {
    type Io = TlsStream<TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let (stream, address) = self.tcp.accept().await.unwrap();
            if let Ok(Ok(stream)) = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                self.acceptor.accept(stream),
            )
            .await
            {
                return (stream, address);
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.tcp.local_addr()
    }
}

/// Real TLS endpoint for transport tests; invalid handshakes never reach Router.
pub async fn serve_tls(
    router: Router,
    certificate: &[u8],
    key: &[u8],
) -> (String, tokio::task::JoinHandle<()>) {
    let certificates = CertificateDer::pem_slice_iter(certificate)
        .collect::<std::result::Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(key).unwrap();
    let config = ServerConfig::builder_with_provider(Arc::new(
        tokio_rustls::rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certificates, key)
    .unwrap();
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = tcp.local_addr().unwrap().port();
    let listener = TlsListener {
        tcp,
        acceptor: TlsAcceptor::from(Arc::new(config)),
    };
    let task = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    (format!("https://localhost:{port}"), task)
}

#[test]
fn ca_files_are_bounded_regular_and_certificates_only() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("ca.pem");
    for bytes in [
        Vec::new(),
        b"not a certificate".to_vec(),
        b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n".to_vec(),
        [CA_FIRST, b"trailing garbage"].concat(),
        [CA_FIRST, b"-----BEGIN CERTIFICATE-----\n"].concat(),
        [CA_FIRST, KEY_FIRST].concat(),
        vec![b'x'; MAX_CA_BYTES + 1],
    ] {
        std::fs::write(&path, bytes).unwrap();
        assert!(read_ca_bundle(&path).is_err());
    }
    assert!(read_ca_bundle(directory.path()).is_err());
    assert!(read_ca_bundle(&directory.path().join("missing")).is_err());
    let fifo = directory.path().join("fifo");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    assert!(read_ca_bundle(&fifo).is_err());
    let bundle = [CA_FIRST, CA_SECOND].concat();
    std::fs::write(&path, &bundle).unwrap();
    let link = directory.path().join("projected-ca.pem");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert_eq!(read_ca_bundle(&link).unwrap(), bundle);
}

#[tokio::test]
async fn tls_trust_rotation_and_certificate_failures_use_real_handshakes() {
    let app = Router::new().route("/", get(|| async { "trusted" }));
    let (first, task_first) = serve_tls(app.clone(), SERVER_FIRST, KEY_FIRST).await;
    let (second, task_second) = serve_tls(app.clone(), SERVER_SECOND, KEY_SECOND).await;
    let (expired, task_expired) = serve_tls(app, SERVER_EXPIRED, KEY_FIRST).await;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("ca.pem");
    let client = |path| {
        with_ca_bundle(
            Client::builder()
                .no_proxy()
                .timeout(std::time::Duration::from_secs(3)),
            path,
        )
        .unwrap()
        .build()
        .unwrap()
    };
    assert!(client(None).get(&first).send().await.is_err());
    std::fs::write(&path, CA_FIRST).unwrap();
    let old = client(Some(path.as_path()));
    assert_eq!(
        old.get(&first).send().await.unwrap().text().await.unwrap(),
        "trusted"
    );
    assert!(
        old.get(first.replace("localhost", "127.0.0.1"))
            .send()
            .await
            .is_err()
    );
    assert!(old.get(&expired).send().await.is_err());
    assert!(old.get(&second).send().await.is_err());
    std::fs::write(&path, [CA_FIRST, CA_SECOND].concat()).unwrap();
    let overlap = client(Some(path.as_path()));
    assert!(
        overlap
            .get(&first)
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
    );
    assert!(
        overlap
            .get(&second)
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
    );
    std::fs::write(&path, CA_SECOND).unwrap();
    let rotated = client(Some(path.as_path()));
    assert!(rotated.get(&first).send().await.is_err());
    assert!(
        rotated
            .get(&second)
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
    );
    task_first.abort();
    task_second.abort();
    task_expired.abort();
}
