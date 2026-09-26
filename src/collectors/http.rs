//! The provider HTTP seam: the one way a collector talks to a provider's API
//! (ADR 0008 D8).
//!
//! [`ProviderHttpV1`] is a small client over one API base, with the
//! discipline every provider collector shares:
//!
//! * **Bounded.** Every request has a 30 second deadline
//!   ([`PROVIDER_HTTP_TIMEOUT`]) and every response body is read up to 8 MiB
//!   ([`MAX_PROVIDER_RESPONSE_BYTES`]); a longer one is an error, never a
//!   truncated page.
//! * **GraphQL errors are answers.** [`ProviderHttpV1::post_graphql`] returns a
//!   `4xx` other than `429` as a response, since a GraphQL API reports a
//!   refused credential or a rate limit in the body of a `400` or `401`; the
//!   collector reads the error codes and nothing else from it.
//! * **Rate limits are an answer, not a failure.** A `429` is returned as
//!   [`ProviderHttpErrorV1::RateLimited`] with its `Retry-After`, so a
//!   collector ends its pass partial with its cursor held rather than
//!   retrying in a loop.
//! * **TLS, except on loopback.** The base must be `https`; plain `http` is
//!   accepted only when the host is loopback (a local fake provider, a relay
//!   on the same host). A base with credentials, a query, or a fragment is
//!   refused ([`validate_api_base`]). Redirects are never followed, so the
//!   credential is never replayed to another origin. Proxies come from the
//!   environment (`HTTPS_PROXY`, `NO_PROXY`), except that a loopback base is
//!   always reached directly.
//! * **The credential stays in its header.** The token is read from the
//!   environment variable the collector's settings name
//!   ([`ProviderTokenV1::from_environment`]); it is only ever an
//!   `Authorization` header marked sensitive, and neither the token type nor
//!   the client prints it.
//! * **The sources file cannot redirect a credential.** The variable must be
//!   in the provider's own namespace, `FLEET_RECALL_<PROVIDER>_...`
//!   ([`validate_token_variable`]), so a sources file cannot name the
//!   worker's content key or a database URL; and a collector's API base must
//!   be its provider's own host, or loopback
//!   ([`validate_provider_api_base`]), so it cannot send a token anywhere
//!   else. A refused base is described by its origin, never echoed.
//! * **Errors are scrubbed.** An error never carries a response body, and its
//!   text is passed through the collector redactor's scan
//!   ([`scrub_diagnostic`]) before anything records it, so a provider that
//!   echoes a credential cannot write it into a status row.

use std::time::Duration;

use reqwest::header::{AUTHORIZATION, HeaderMap, HeaderValue};

use crate::redaction::REDACTION_PLACEHOLDER;

use super::redaction::scan_collected_secrets;

/// How long one provider request may take, connection included.
pub const PROVIDER_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// How long connecting may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The largest response body a collector reads: 8 MiB.
pub const MAX_PROVIDER_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Response headers a collector may read back: rate-limit accounting only.
const KEPT_HEADER_PREFIXES: [&str; 2] = ["x-ratelimit-", "retry-after"];

/// Longest diagnostic an error carries.
const MAX_DIAGNOSTIC_BYTES: usize = 512;

/// How the credential is presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthSchemeV1 {
    /// `Authorization: Bearer <token>` (Slack, Granola, Linear OAuth).
    Bearer,
    /// `Authorization: <token>` (a Linear personal API key).
    Plain,
}

/// Why a provider request did not give a usable response. Never carries a
/// response body or a credential.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProviderHttpErrorV1 {
    /// The environment variable the settings name is unset or empty.
    #[error("environment variable {variable} is not set; it holds the provider credential")]
    MissingToken {
        /// The variable.
        variable: String,
    },
    /// The token cannot be sent as a header value.
    #[error("the provider credential in {variable} is not a valid header value")]
    InvalidToken {
        /// The variable.
        variable: String,
    },
    /// The API base or a request path is refused.
    #[error("{0}")]
    InvalidBase(String),
    /// The provider asked the collector to slow down.
    #[error("the provider rate-limited the request{}", retry_after_text(*.retry_after_seconds))]
    RateLimited {
        /// Its `Retry-After`, in seconds, when it gave one.
        retry_after_seconds: Option<u64>,
    },
    /// Any other status outside `2xx`.
    #[error("the provider answered HTTP {status}")]
    Status {
        /// The status.
        status: u16,
    },
    /// The body is larger than [`MAX_PROVIDER_RESPONSE_BYTES`].
    #[error("the provider's response is larger than {MAX_PROVIDER_RESPONSE_BYTES} bytes")]
    TooLarge,
    /// The request did not finish within [`PROVIDER_HTTP_TIMEOUT`].
    #[error("the provider request timed out")]
    Timeout,
    /// The request failed below HTTP; a scrubbed diagnostic.
    #[error("the provider request failed: {0}")]
    Transport(String),
}

fn retry_after_text(seconds: Option<u64>) -> String {
    seconds.map_or_else(String::new, |seconds| format!(" (retry after {seconds} s)"))
}

/// Replace every secret shape in `text` with the redaction placeholder: what
/// an error may say before a status row records it. A text whose scrubbed
/// form still holds a secret shape is withheld whole.
#[must_use]
pub fn scrub_diagnostic(text: &str) -> String {
    let mut scrubbed = String::with_capacity(text.len());
    let mut cursor = 0;
    for finding in scan_collected_secrets(text) {
        let (Some(prefix), true) = (
            text.get(cursor..finding.byte_start),
            text.is_char_boundary(finding.byte_end),
        ) else {
            // A range that is not on a char boundary cannot be cut safely:
            // drop the rest rather than keep part of a secret.
            scrubbed.push_str(REDACTION_PLACEHOLDER);
            cursor = text.len();
            break;
        };
        scrubbed.push_str(prefix);
        scrubbed.push_str(REDACTION_PLACEHOLDER);
        cursor = finding.byte_end;
    }
    if let Some(tail) = text.get(cursor..) {
        scrubbed.push_str(tail);
    }
    if scan_collected_secrets(&scrubbed).is_empty() {
        scrubbed
    } else {
        "the diagnostic was withheld: it held a secret shape".to_owned()
    }
}

/// [`scrub_diagnostic`], bounded to what one error carries.
fn bounded_diagnostic(text: &str) -> String {
    super::text::truncate_on_char_boundary(scrub_diagnostic(text), MAX_DIAGNOSTIC_BYTES)
}

/// A provider credential, read from the environment. It prints as
/// `<redacted>`.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderTokenV1 {
    variable: String,
    value: String,
}

impl std::fmt::Debug for ProviderTokenV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderTokenV1")
            .field("variable", &self.variable)
            .field("value", &"<redacted>")
            .finish()
    }
}

impl ProviderTokenV1 {
    /// Read the credential from `variable` through `lookup` (the process
    /// environment in production).
    ///
    /// # Errors
    ///
    /// [`ProviderHttpErrorV1::MissingToken`] when the variable is unset or
    /// holds only whitespace.
    pub fn from_environment(
        variable: &str,
        lookup: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Self, ProviderHttpErrorV1> {
        let value = lookup(variable)
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| ProviderHttpErrorV1::MissingToken {
                variable: variable.to_owned(),
            })?;
        Ok(Self {
            variable: variable.to_owned(),
            value,
        })
    }

    /// The variable the credential was read from.
    #[must_use]
    pub fn variable(&self) -> &str {
        &self.variable
    }

    /// The credential itself: for a comparison, never for a message.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.value
    }
}

/// Whether `value` can name the environment variable a collector's
/// credential is read from: `[A-Z_][A-Z0-9_]*`, at most 128 bytes.
#[must_use]
pub fn is_variable_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && !value.starts_with(|scalar: char| scalar.is_ascii_digit())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

/// The prefix of every variable a `provider` collector may read its
/// credential from: `FLEET_RECALL_<PROVIDER>_` (`FLEET_RECALL_SLACK_`).
#[must_use]
pub fn token_variable_prefix(provider: &str) -> String {
    format!(
        "FLEET_RECALL_{}_",
        provider.to_ascii_uppercase().replace(['-', '.'], "_")
    )
}

/// Check the variable a `provider` collector's settings name for its
/// credential (`settings.token_env`).
///
/// The sources file is less trusted than the environment: it may never
/// hold a credential, and it may not point a collector at one the worker
/// holds for itself. A collector reads only a variable in its provider's own
/// namespace ([`token_variable_prefix`]), so no edit of the sources file can
/// send the content key, a database URL, or another provider's token to an
/// API as an `Authorization` header.
///
/// # Errors
///
/// A message naming the refused setting and the namespace.
pub fn validate_token_variable(provider: &str, name: &str) -> Result<(), String> {
    if !is_variable_name(name) {
        return Err(
            "settings.token_env must name an environment variable ([A-Z_][A-Z0-9_]*)".to_owned(),
        );
    }
    let prefix = token_variable_prefix(provider);
    let reserved = name.ends_with("DATABASE_URL") || name.contains("_KEK");
    if !name.starts_with(&prefix) || name.len() == prefix.len() || reserved {
        return Err(format!(
            "settings.token_env must name a variable in the collector's own namespace, \
             {prefix}... (such as {prefix}API_TOKEN): a collector never reads a variable the \
             worker holds for itself"
        ));
    }
    Ok(())
}

/// Whether a URL's host is loopback: `localhost`, `127.0.0.0/8`, or `::1`.
#[must_use]
pub fn is_loopback(url: &url::Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

/// A URL's origin for a message: scheme, host, and port, never its
/// credentials, path, or query.
fn origin(url: &url::Url) -> String {
    let host = url.host_str().unwrap_or("no host");
    url.port().map_or_else(
        || format!("{}://{host}", url.scheme()),
        |port| format!("{}://{host}:{port}", url.scheme()),
    )
}

/// Parse and check an API base: `https`, or `http` on a loopback host; no
/// credentials, query, or fragment. The returned base ends in `/`, so a
/// method path joins under it.
///
/// # Errors
///
/// A message naming what is refused. It names at most the base's scheme,
/// host, and port: never the raw value, which may hold a password.
pub fn validate_api_base(raw: &str) -> Result<url::Url, String> {
    let mut url =
        url::Url::parse(raw).map_err(|error| format!("the api base is not a URL ({error})"))?;
    if url.host().is_none() {
        return Err("the api base names no host".to_owned());
    }
    let shown = origin(&url);
    match url.scheme() {
        "https" => {}
        "http" if is_loopback(&url) => {}
        "http" => {
            return Err(format!(
                "api base {shown} is plain http to a host that is not loopback; use https"
            ));
        }
        other => return Err(format!("api base {shown} has scheme {other}; use https")),
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!(
            "api base {shown} carries credentials; a credential is only ever named by token_env"
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(format!("api base {shown} carries a query or a fragment"));
    }
    if !url.path().ends_with('/') {
        let path = format!("{}/", url.path());
        url.set_path(&path);
    }
    Ok(url)
}

/// [`validate_api_base`] for a collector: the host must be its provider's.
///
/// The base's host must be `pinned_host`, the provider's own API host,
/// unless it is loopback (a local fake provider, a relay on the same host): a
/// collector's credential is only ever sent to the provider that issued it.
///
/// # Errors
///
/// What [`validate_api_base`] refuses, and any other host.
pub fn validate_provider_api_base(raw: &str, pinned_host: &str) -> Result<url::Url, String> {
    let url = validate_api_base(raw)?;
    let pinned = url
        .host_str()
        .is_some_and(|host| host.eq_ignore_ascii_case(pinned_host));
    if !pinned && !is_loopback(&url) {
        return Err(format!(
            "api base {} is not the provider's own API host {pinned_host}; the credential is \
             only ever sent there, or to a loopback host",
            origin(&url)
        ));
    }
    Ok(url)
}

/// One response: its status, the rate-limit headers, and the body.
#[derive(Clone, PartialEq, Eq)]
pub struct ProviderResponseV1 {
    /// The HTTP status: `2xx`, or, from [`ProviderHttpV1::post_graphql`], a
    /// `4xx` other than `429`.
    pub status: u16,
    /// `x-ratelimit-*` and `retry-after`, lowercased.
    pub headers: Vec<(String, String)>,
    /// The body, at most [`MAX_PROVIDER_RESPONSE_BYTES`].
    pub body: Vec<u8>,
}

/// Lengths only: a body is provider content.
impl std::fmt::Debug for ProviderResponseV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderResponseV1")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

impl ProviderResponseV1 {
    /// One kept header, by lowercase name.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

/// A client over one provider API base. See the module documentation.
#[derive(Clone)]
pub struct ProviderHttpV1 {
    client: reqwest::Client,
    base: url::Url,
    authorization: HeaderValue,
}

impl std::fmt::Debug for ProviderHttpV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProviderHttpV1")
            .field("base", &self.base.as_str())
            .finish_non_exhaustive()
    }
}

impl ProviderHttpV1 {
    /// A client for `api_base`, presenting `token` under `scheme`.
    ///
    /// # Errors
    ///
    /// [`ProviderHttpErrorV1::InvalidBase`] for a base [`validate_api_base`]
    /// refuses; [`ProviderHttpErrorV1::InvalidToken`] for a token that is not
    /// a header value; [`ProviderHttpErrorV1::Transport`] when the TLS client
    /// cannot be built.
    pub fn new(
        api_base: &str,
        token: &ProviderTokenV1,
        scheme: AuthSchemeV1,
    ) -> Result<Self, ProviderHttpErrorV1> {
        let base = validate_api_base(api_base).map_err(ProviderHttpErrorV1::InvalidBase)?;
        let loopback = is_loopback(&base);
        let value = match scheme {
            AuthSchemeV1::Bearer => format!("Bearer {}", token.expose()),
            AuthSchemeV1::Plain => token.expose().to_owned(),
        };
        let mut authorization =
            HeaderValue::from_str(&value).map_err(|_| ProviderHttpErrorV1::InvalidToken {
                variable: token.variable().to_owned(),
            })?;
        authorization.set_sensitive(true);
        let mut builder = reqwest::Client::builder()
            .timeout(PROVIDER_HTTP_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .https_only(!loopback)
            .user_agent(concat!("ostk-fleet-recall/", env!("CARGO_PKG_VERSION")));
        if loopback {
            builder = builder.no_proxy();
        }
        let client = builder
            .build()
            .map_err(|error| ProviderHttpErrorV1::Transport(describe(&error)))?;
        Ok(Self {
            client,
            base,
            authorization,
        })
    }

    /// The API base, ending in `/`.
    #[must_use]
    pub const fn base(&self) -> &url::Url {
        &self.base
    }

    fn url(&self, path: &str) -> Result<url::Url, ProviderHttpErrorV1> {
        if path.is_empty()
            || path.starts_with('/')
            || path.contains("..")
            || path.contains("://")
            || path.contains(['?', '#'])
        {
            return Err(ProviderHttpErrorV1::InvalidBase(format!(
                "request path {path:?} is not a relative method path"
            )));
        }
        self.base
            .join(path)
            .map_err(|error| ProviderHttpErrorV1::InvalidBase(format!("{path:?}: {error}")))
    }

    /// `GET <base><path>?<query>`.
    ///
    /// # Errors
    ///
    /// Every [`ProviderHttpErrorV1`] but the construction ones.
    pub async fn get(
        &self,
        path: &str,
        query: &[(&str, &str)],
    ) -> Result<ProviderResponseV1, ProviderHttpErrorV1> {
        let request = self
            .client
            .get(self.url(path)?)
            .header(AUTHORIZATION, self.authorization.clone())
            .query(query);
        read(request, AnswerV1::Success).await
    }

    /// `POST <base><path>` with a JSON body.
    ///
    /// # Errors
    ///
    /// Every [`ProviderHttpErrorV1`] but the construction ones.
    pub async fn post_json(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<ProviderResponseV1, ProviderHttpErrorV1> {
        let request = self
            .client
            .post(self.url(path)?)
            .header(AUTHORIZATION, self.authorization.clone())
            .json(body);
        read(request, AnswerV1::Success).await
    }

    /// `POST <base><path>` with a JSON body, to a GraphQL endpoint. A GraphQL
    /// API answers its errors (a refused credential, a rate limit, a field
    /// the key may not read) in the body of a `400` or `401` as often as in a
    /// `200`, so a `4xx` other than `429` is returned as a response, read
    /// within the same bound, for the collector to read its `errors`. A `429`
    /// is still [`ProviderHttpErrorV1::RateLimited`], and anything else
    /// outside `2xx` and `4xx` is still an error.
    ///
    /// # Errors
    ///
    /// Every [`ProviderHttpErrorV1`] but the construction ones.
    pub async fn post_graphql(
        &self,
        path: &str,
        body: &serde_json::Value,
    ) -> Result<ProviderResponseV1, ProviderHttpErrorV1> {
        let request = self
            .client
            .post(self.url(path)?)
            .header(AUTHORIZATION, self.authorization.clone())
            .json(body);
        read(request, AnswerV1::ClientErrorsToo).await
    }
}

/// Which statuses a request reads as an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnswerV1 {
    /// `2xx` only.
    Success,
    /// `2xx`, and `4xx` other than `429`: a GraphQL API's errors.
    ClientErrorsToo,
}

/// A transport error's text, without its URL, scrubbed.
fn describe(error: &reqwest::Error) -> String {
    let mut current: Option<&dyn std::error::Error> = Some(error);
    let mut parts = Vec::new();
    while let Some(source) = current {
        parts.push(source.to_string());
        current = source.source();
    }
    bounded_diagnostic(&parts.join(": "))
}

fn transport(error: reqwest::Error) -> ProviderHttpErrorV1 {
    if error.is_timeout() {
        return ProviderHttpErrorV1::Timeout;
    }
    ProviderHttpErrorV1::Transport(describe(&error.without_url()))
}

fn kept_headers(headers: &HeaderMap) -> Vec<(String, String)> {
    let mut kept: Vec<(String, String)> = headers
        .iter()
        .filter(|(name, _)| {
            KEPT_HEADER_PREFIXES
                .iter()
                .any(|prefix| name.as_str().starts_with(prefix))
        })
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), bounded_diagnostic(value)))
        })
        .collect();
    kept.sort();
    kept
}

/// Send `request` and read its answer within the bounds.
async fn read(
    request: reqwest::RequestBuilder,
    answer: AnswerV1,
) -> Result<ProviderResponseV1, ProviderHttpErrorV1> {
    let mut response = request.send().await.map_err(transport)?;
    let status = response.status();
    let headers = kept_headers(response.headers());
    if status.as_u16() == 429 {
        let retry_after_seconds = headers
            .iter()
            .find(|(name, _)| name == "retry-after")
            .and_then(|(_, value)| value.trim().parse::<u64>().ok());
        return Err(ProviderHttpErrorV1::RateLimited {
            retry_after_seconds,
        });
    }
    let answered =
        status.is_success() || (answer == AnswerV1::ClientErrorsToo && status.is_client_error());
    if !answered {
        return Err(ProviderHttpErrorV1::Status {
            status: status.as_u16(),
        });
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_PROVIDER_RESPONSE_BYTES as u64)
    {
        return Err(ProviderHttpErrorV1::TooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(transport)? {
        if body.len() + chunk.len() > MAX_PROVIDER_RESPONSE_BYTES {
            return Err(ProviderHttpErrorV1::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(ProviderResponseV1 {
        status: status.as_u16(),
        headers,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup(pairs: &[(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        let pairs = pairs.to_vec();
        move |name: &str| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| (*value).to_owned())
        }
    }

    #[test]
    fn an_api_base_is_https_or_loopback_http_and_carries_nothing_else() {
        for good in [
            "https://slack.com/api",
            "https://slack.com/api/",
            "http://127.0.0.1:8080",
            "http://localhost:9/api",
            "http://[::1]:7/",
        ] {
            let url = validate_api_base(good).unwrap_or_else(|error| panic!("{good}: {error}"));
            assert!(url.path().ends_with('/'), "{url}");
        }
        for (bad, needle) in [
            ("http://slack.com/api", "not loopback"),
            ("http://10.0.0.1/api", "not loopback"),
            ("ftp://slack.com/api", "scheme ftp"),
            ("https://user:pw@slack.com/api", "credentials"),
            ("https://svc:Pa55word@relay.internal/api", "credentials"),
            ("https://slack.com/api?token=x", "query"),
            ("https://slack.com/api#x", "fragment"),
            ("not a url", "api base"),
        ] {
            let message = validate_api_base(bad).unwrap_err();
            assert!(message.contains(needle), "{bad}: {message}");
            for part in ["pw@", "Pa55word", "token=x", "#x"] {
                assert!(!message.contains(part), "{bad}: the message echoes {part}");
            }
        }
    }

    #[test]
    fn a_provider_base_is_the_providers_own_host_or_loopback() {
        for good in [
            "https://slack.com/api",
            "https://SLACK.com/api/",
            "http://127.0.0.1:8080/api",
            "https://localhost:9/api",
        ] {
            validate_provider_api_base(good, "slack.com")
                .unwrap_or_else(|error| panic!("{good}: {error}"));
        }
        for bad in [
            "https://kek-sink.example/api",
            "https://slack.com.evil.example/api",
            "https://api.linear.app/graphql",
        ] {
            let message = validate_provider_api_base(bad, "slack.com").unwrap_err();
            assert!(message.contains("slack.com"), "{bad}: {message}");
        }
    }

    #[test]
    fn a_credential_variable_is_in_its_providers_own_namespace() {
        for good in [
            ("slack", "FLEET_RECALL_SLACK_BOT_TOKEN"),
            ("linear", "FLEET_RECALL_LINEAR_API_KEY"),
            ("granola", "FLEET_RECALL_GRANOLA_API_KEY"),
        ] {
            validate_token_variable(good.0, good.1).unwrap_or_else(|error| panic!("{error}"));
        }
        for (provider, bad) in [
            ("slack", "FLEET_RECALL_CONTENT_KEK_HEX"),
            ("slack", "FLEET_RECALL_DATABASE_URL"),
            ("linear", "FLEET_RECALL_SLACK_BOT_TOKEN"),
            ("granola", "GITHUB_TOKEN"),
            ("slack", "FLEET_RECALL_SLACK_"),
            ("slack", "FLEET_RECALL_SLACK_CONTROL_DATABASE_URL"),
            ("slack", "FLEET_RECALL_SLACK_KEK_COPY"),
            ("slack", "lower"),
        ] {
            let message = validate_token_variable(provider, bad).unwrap_err();
            assert!(message.contains("settings.token_env"), "{bad}: {message}");
        }
        // No variable the worker reads for itself is in any collector's
        // namespace.
        for provider in ["slack", "linear", "granola", "docs"] {
            for reserved in [
                "FLEET_RECALL_CONTENT_KEK_HEX",
                "FLEET_RECALL_DATABASE_URL",
                "FLEET_RECALL_CONTROL_DATABASE_URL",
                "FLEET_RECALL_PUBLICATION_DATABASE_URL",
            ] {
                assert!(validate_token_variable(provider, reserved).is_err());
            }
        }
    }

    #[test]
    fn a_token_comes_from_its_variable_and_never_prints() {
        let secret = "xoxb-EXAMPLE-NOT-A-TOKEN".to_owned();
        let pairs = [("SLACK_TOKEN", "placeholder")];
        let token = ProviderTokenV1::from_environment("SLACK_TOKEN", &lookup(&pairs)).unwrap();
        assert_eq!(token.expose(), "placeholder");
        let owned = secret.clone();
        let token = ProviderTokenV1::from_environment("SLACK_TOKEN", &move |_: &str| {
            Some(format!(" {owned}\n"))
        })
        .unwrap();
        assert_eq!(token.expose(), secret);
        assert!(!format!("{token:?}").contains(&secret));
        for missing in [lookup(&[]), lookup(&[("SLACK_TOKEN", "  ")])] {
            let error = ProviderTokenV1::from_environment("SLACK_TOKEN", &missing).unwrap_err();
            assert_eq!(
                error,
                ProviderHttpErrorV1::MissingToken {
                    variable: "SLACK_TOKEN".into()
                }
            );
            assert!(error.to_string().contains("SLACK_TOKEN"));
        }
        let client = ProviderHttpV1::new("http://127.0.0.1:1/api", &token, AuthSchemeV1::Bearer)
            .expect("a loopback client");
        assert!(!format!("{client:?}").contains(&secret));
        let refused =
            ProviderHttpV1::new("http://example.com/api", &token, AuthSchemeV1::Plain).unwrap_err();
        assert!(matches!(refused, ProviderHttpErrorV1::InvalidBase(_)));
    }

    #[test]
    fn a_diagnostic_is_scrubbed_of_every_secret_shape_and_a_transport_one_bounded() {
        let secret = "xoxb-EXAMPLE-NOT-A-TOKEN";
        let scrubbed = scrub_diagnostic(&format!("upstream said {secret} was bad"));
        assert!(!scrubbed.contains(secret), "{scrubbed}");
        assert!(scrubbed.contains(REDACTION_PLACEHOLDER));
        assert!(scrubbed.starts_with("upstream said "));
        assert_eq!(scrub_diagnostic("plain"), "plain");
        assert_eq!(scrub_diagnostic(&"é".repeat(1_000)).len(), 2_000);
        assert!(bounded_diagnostic(&"é".repeat(1_000)).len() <= MAX_DIAGNOSTIC_BYTES);
    }

    /// A loopback server that answers by path and echoes what it was sent.
    async fn serve() -> String {
        use axum::http::{HeaderMap as Headers, StatusCode};
        use axum::response::IntoResponse as _;
        async fn answer(uri: axum::http::Uri, headers: Headers) -> axum::response::Response {
            let authorization = headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned();
            match uri.path() {
                "/api/ok" => (
                    [("x-ratelimit-remaining", "41"), ("set-cookie", "kept=no")],
                    format!(
                        "{{\"authorization\":\"{authorization}\",\"query\":\"{}\"}}",
                        uri.query().unwrap_or_default()
                    ),
                )
                    .into_response(),
                "/api/slow-down" => (
                    StatusCode::TOO_MANY_REQUESTS,
                    [("retry-after", "30")],
                    "later",
                )
                    .into_response(),
                "/api/broken" => (StatusCode::BAD_GATEWAY, authorization).into_response(),
                "/api/refused" => (
                    StatusCode::BAD_REQUEST,
                    [("x-ratelimit-requests-remaining", "7")],
                    r#"{"errors":[{"extensions":{"code":"INPUT_ERROR"}}]}"#,
                )
                    .into_response(),
                "/api/huge" => vec![b'x'; MAX_PROVIDER_RESPONSE_BYTES + 1].into_response(),
                "/api/moved" => (
                    StatusCode::FOUND,
                    [("location", "https://elsewhere.example/")],
                )
                    .into_response(),
                _ => StatusCode::NOT_FOUND.into_response(),
            }
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, axum::Router::new().fallback(answer))
                .await
                .unwrap();
        });
        format!("http://{address}/api")
    }

    #[tokio::test]
    async fn a_response_is_bounded_and_a_rate_limit_or_a_status_is_an_answer() {
        let base = serve().await;
        let token =
            ProviderTokenV1::from_environment("T", &|_: &str| Some("s3cr3t".into())).unwrap();
        let client = ProviderHttpV1::new(&base, &token, AuthSchemeV1::Bearer).unwrap();
        let ok = client.get("ok", &[("channel", "C1")]).await.unwrap();
        assert_eq!(ok.status, 200);
        let body: serde_json::Value = serde_json::from_slice(&ok.body).unwrap();
        assert_eq!(body["authorization"], "Bearer s3cr3t");
        assert_eq!(body["query"], "channel=C1");
        assert_eq!(ok.header("x-ratelimit-remaining"), Some("41"));
        assert_eq!(
            ok.header("set-cookie"),
            None,
            "only rate-limit headers are kept"
        );
        assert_eq!(
            client.get("slow-down", &[]).await.unwrap_err(),
            ProviderHttpErrorV1::RateLimited {
                retry_after_seconds: Some(30)
            }
        );
        let broken = client.get("broken", &[]).await.unwrap_err();
        assert_eq!(broken, ProviderHttpErrorV1::Status { status: 502 });
        assert!(
            !broken.to_string().contains("s3cr3t"),
            "no body in an error"
        );
        assert_eq!(
            client.get("huge", &[]).await.unwrap_err(),
            ProviderHttpErrorV1::TooLarge
        );
        assert_eq!(
            client.get("moved", &[]).await.unwrap_err(),
            ProviderHttpErrorV1::Status { status: 302 },
            "a redirect is never followed"
        );
        let plain = ProviderHttpV1::new(&base, &token, AuthSchemeV1::Plain).unwrap();
        let query = serde_json::json!({"query": "{ viewer { id } }"});
        let posted = plain.post_json("ok", &query).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&posted.body).unwrap();
        assert_eq!(body["authorization"], "s3cr3t");
        let refused = ProviderHttpV1::new("http://127.0.0.1:1/api", &token, AuthSchemeV1::Bearer)
            .unwrap()
            .get("ok", &[])
            .await
            .unwrap_err();
        assert!(
            matches!(refused, ProviderHttpErrorV1::Transport(_)),
            "{refused:?}"
        );
    }

    #[tokio::test]
    async fn a_graphql_post_reads_a_client_error_as_an_answer_and_nothing_else() {
        let base = serve().await;
        let token =
            ProviderTokenV1::from_environment("T", &|_: &str| Some("s3cr3t".into())).unwrap();
        let client = ProviderHttpV1::new(&base, &token, AuthSchemeV1::Plain).unwrap();
        let query = serde_json::json!({"query": "{ organization { id } }"});
        assert_eq!(
            client.post_json("refused", &query).await.unwrap_err(),
            ProviderHttpErrorV1::Status { status: 400 },
            "a plain post keeps a 400 an error"
        );
        let refused = client.post_graphql("refused", &query).await.unwrap();
        assert_eq!(refused.status, 400);
        assert_eq!(refused.header("x-ratelimit-requests-remaining"), Some("7"));
        let body: serde_json::Value = serde_json::from_slice(&refused.body).unwrap();
        assert_eq!(body["errors"][0]["extensions"]["code"], "INPUT_ERROR");
        assert_eq!(client.post_graphql("ok", &query).await.unwrap().status, 200);
        assert_eq!(
            client.post_graphql("slow-down", &query).await.unwrap_err(),
            ProviderHttpErrorV1::RateLimited {
                retry_after_seconds: Some(30)
            }
        );
        assert_eq!(
            client.post_graphql("broken", &query).await.unwrap_err(),
            ProviderHttpErrorV1::Status { status: 502 }
        );
        assert_eq!(
            client.post_graphql("huge", &query).await.unwrap_err(),
            ProviderHttpErrorV1::TooLarge
        );
    }

    #[test]
    fn a_request_path_is_a_relative_method_path() {
        let token = ProviderTokenV1::from_environment("T", &|_: &str| Some("t".into())).unwrap();
        let client =
            ProviderHttpV1::new("https://slack.com/api", &token, AuthSchemeV1::Bearer).unwrap();
        assert_eq!(
            client.url("conversations.history").unwrap().as_str(),
            "https://slack.com/api/conversations.history"
        );
        for bad in ["", "/abs", "../up", "https://evil.example/x", "a?b", "a#b"] {
            assert!(client.url(bad).is_err(), "{bad}");
        }
        assert_eq!(
            ProviderHttpErrorV1::RateLimited {
                retry_after_seconds: Some(30)
            }
            .to_string(),
            "the provider rate-limited the request (retry after 30 s)"
        );
    }
}
