//! A fake provider API for connected tests: an axum server on
//! `127.0.0.1:0` that answers every request through a responder the test
//! supplies (fixture pages keyed by cursor), with scripted one-shot replies
//! (a 429 on page 2, a 5xx) and a record of every request, so a test can
//! prove the credential travels in the `Authorization` header and nowhere
//! else. No test reaches a real provider.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, Method, Response, StatusCode, Uri};

/// One request the fake received.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeRequest {
    pub method: String,
    pub path: String,
    /// The raw query string.
    pub raw_query: String,
    /// The decoded query parameters.
    pub query: BTreeMap<String, String>,
    /// Every header, lowercased name first.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl FakeRequest {
    /// One query parameter.
    pub fn param(&self, name: &str) -> Option<&str> {
        self.query.get(name).map(String::as_str)
    }

    /// One header.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

/// One reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FakeReply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl FakeReply {
    /// `200` with a JSON body.
    pub fn json(value: &serde_json::Value) -> Self {
        Self {
            status: 200,
            headers: vec![("content-type".into(), "application/json".into())],
            body: serde_json::to_vec(value).unwrap(),
        }
    }

    /// A bare status with a text body.
    pub fn status(status: u16, body: &str) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.as_bytes().to_vec(),
        }
    }

    /// `429` with `Retry-After`.
    pub fn rate_limited(retry_after_seconds: u64) -> Self {
        Self {
            status: 429,
            headers: vec![("retry-after".into(), retry_after_seconds.to_string())],
            body: b"rate limited".to_vec(),
        }
    }
}

type Responder = dyn Fn(&FakeRequest) -> FakeReply + Send + Sync;
type Matcher = Box<dyn Fn(&FakeRequest) -> bool + Send + Sync>;

struct FakeState {
    responder: Box<Responder>,
    scripted: VecDeque<(Matcher, FakeReply)>,
    requests: Vec<FakeRequest>,
}

/// The fake provider; stopped when dropped.
pub struct FakeProvider {
    /// `http://127.0.0.1:<port>`.
    pub base: String,
    state: Arc<Mutex<FakeState>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for FakeProvider {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn answer(
    State(state): State<Arc<Mutex<FakeState>>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Body> {
    let raw_query = uri.query().unwrap_or_default().to_owned();
    let request = FakeRequest {
        method: method.to_string(),
        path: uri.path().to_owned(),
        query: url::form_urlencoded::parse(raw_query.as_bytes())
            .into_owned()
            .collect(),
        raw_query,
        headers: headers
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect(),
        body: body.to_vec(),
    };
    let reply = {
        let mut state = state.lock().unwrap();
        state.requests.push(request.clone());
        let scripted = state
            .scripted
            .iter()
            .position(|(matches, _)| matches(&request));
        match scripted.and_then(|index| state.scripted.remove(index)) {
            Some((_, reply)) => reply,
            None => (state.responder)(&request),
        }
    };
    let mut response = Response::builder()
        .status(StatusCode::from_u16(reply.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR));
    for (name, value) in &reply.headers {
        response = response.header(name, value);
    }
    response.body(Body::from(reply.body)).unwrap()
}

impl FakeProvider {
    /// Serve `responder` on a fresh loopback port.
    pub async fn start(
        responder: impl Fn(&FakeRequest) -> FakeReply + Send + Sync + 'static,
    ) -> Self {
        let state = Arc::new(Mutex::new(FakeState {
            responder: Box::new(responder),
            scripted: VecDeque::new(),
            requests: Vec::new(),
        }));
        let router = Router::new()
            .fallback(answer)
            .with_state(Arc::clone(&state));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        Self {
            base: format!("http://{address}"),
            state,
            task,
        }
    }

    /// Answer the first later request `matches` accepts with `reply`, once.
    pub fn script(
        &self,
        matches: impl Fn(&FakeRequest) -> bool + Send + Sync + 'static,
        reply: FakeReply,
    ) {
        self.state
            .lock()
            .unwrap()
            .scripted
            .push_back((Box::new(matches), reply));
    }

    /// Every request so far, in order.
    pub fn requests(&self) -> Vec<FakeRequest> {
        self.state.lock().unwrap().requests.clone()
    }

    /// Forget the requests so far.
    pub fn clear_requests(&self) {
        self.state.lock().unwrap().requests.clear();
    }

    /// Every request carried exactly `authorization` in its `Authorization`
    /// header, and `secret` appears nowhere else in any request: not in a
    /// path, a query, another header, or a body.
    pub fn assert_credential_confined(&self, authorization: &str, secret: &str) {
        let requests = self.requests();
        assert!(!requests.is_empty(), "the fake provider was called");
        for request in &requests {
            assert_eq!(
                request.header("authorization"),
                Some(authorization),
                "{} {} carries the credential in its Authorization header",
                request.method,
                request.path
            );
            assert!(!request.path.contains(secret), "{}", request.path);
            assert!(!request.raw_query.contains(secret), "{}", request.path);
            assert!(
                !String::from_utf8_lossy(&request.body).contains(secret),
                "{}",
                request.path
            );
            for (name, value) in &request.headers {
                assert!(
                    name == "authorization" || !value.contains(secret),
                    "the credential leaked into the {name} header of {}",
                    request.path
                );
            }
        }
    }
}
