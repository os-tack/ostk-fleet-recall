//! AWS IAM signed-request forwarding. STS verifies `SigV4`; this module pins
//! the destination, operation, signed server binding and allowed accounts.

use chrono::NaiveDateTime;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use url::Url;

use super::super::{AuthError, VerifiedIdentity, jose};
use super::{bounded_body, endpoint, http_client};
use crate::encoding::base64;

const ACTION: &str = "Action=GetCallerIdentity&Version=2011-06-15";
const BODY_LIMIT: usize = 65_536;
const SERVER_HEADER: &str = "x-fleet-recall-server-id";

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AwsIamRequest {
    pub iam_http_request_method: String,
    /// Canonical standard-padded base64 of the complete configured STS URL.
    pub iam_request_url: String,
    /// Canonical standard-padded base64 of the `GetCallerIdentity` action.
    pub iam_request_body: String,
    pub iam_request_headers: BTreeMap<String, Vec<String>>,
}

pub struct AwsIamConfig {
    pub anchor_id: String,
    pub sts_endpoint: String,
    pub server_id: String,
    pub allowed_accounts: BTreeSet<String>,
    pub allow_http: bool,
}

pub struct AwsIamAnchor {
    anchor_id: String,
    endpoint: Url,
    server_id: String,
    allowed_accounts: BTreeSet<String>,
    client: reqwest::Client,
}

impl AwsIamAnchor {
    pub fn new(config: AwsIamConfig) -> Result<Self, AuthError> {
        if !jose::valid_identifier(&config.anchor_id, 128)
            || !jose::valid_identifier(&config.server_id, 2048)
            || config.allowed_accounts.is_empty()
            || config.allowed_accounts.len() > 1000
            || config
                .allowed_accounts
                .iter()
                .any(|account| !account_id(account))
        {
            return Err(AuthError::Configuration);
        }
        Ok(Self {
            anchor_id: config.anchor_id,
            endpoint: endpoint(&config.sts_endpoint, config.allow_http)?,
            server_id: config.server_id,
            allowed_accounts: config.allowed_accounts,
            client: http_client(None)?,
        })
    }

    pub async fn verify_request(
        &self,
        request: &AwsIamRequest,
        now: i64,
    ) -> Result<VerifiedIdentity, AuthError> {
        let headers = self.validate(request, now)?;
        let response = self
            .client
            .post(self.endpoint.clone())
            .headers(headers)
            .body(ACTION)
            .send()
            .await
            .map_err(|_| AuthError::ProviderUnavailable)?;
        if response.status().is_client_error() {
            return Err(AuthError::InvalidToken);
        }
        let body = bounded_body(response, BODY_LIMIT).await?;
        let identity = parse_identity(&body)?;
        if !self.allowed_accounts.contains(&identity.account) {
            return Err(AuthError::InvalidToken);
        }
        Ok(VerifiedIdentity {
            anchor_id: self.anchor_id.clone(),
            subject: canonical_arn(&identity.arn, &identity.account)?,
        })
    }

    fn validate(&self, request: &AwsIamRequest, now: i64) -> Result<HeaderMap, AuthError> {
        if request.iam_http_request_method != "POST"
            || request.iam_request_url.len() > 4096
            || request.iam_request_body.len() > 128
            || request.iam_request_headers.len() > 10
        {
            return Err(AuthError::InvalidToken);
        }
        let url = base64::decode(&request.iam_request_url).ok_or(AuthError::InvalidToken)?;
        let url = Url::parse(std::str::from_utf8(&url).map_err(|_| AuthError::InvalidToken)?)
            .map_err(|_| AuthError::InvalidToken)?;
        if url != self.endpoint
            || base64::decode(&request.iam_request_body).as_deref() != Some(ACTION.as_bytes())
        {
            return Err(AuthError::InvalidToken);
        }
        let mut headers = HeaderMap::new();
        let mut size = 0;
        for (name, values) in &request.iam_request_headers {
            let name =
                HeaderName::from_bytes(name.as_bytes()).map_err(|_| AuthError::InvalidToken)?;
            if !matches!(
                name.as_str(),
                "authorization"
                    | "host"
                    | "accept"
                    | "content-type"
                    | "x-amz-date"
                    | "x-amz-security-token"
                    | "x-amz-content-sha256"
                    | SERVER_HEADER
            ) || values.len() != 1
                || headers.contains_key(&name)
            {
                return Err(AuthError::InvalidToken);
            }
            size += values[0].len();
            if size > 16_384 || values[0].is_empty() || values[0].trim() != values[0] {
                return Err(AuthError::InvalidToken);
            }
            let value = HeaderValue::from_str(&values[0]).map_err(|_| AuthError::InvalidToken)?;
            headers.insert(name, value);
        }
        let get = |name: &str| {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .ok_or(AuthError::InvalidToken)
        };
        let expected_host = &self.endpoint[url::Position::BeforeHost..url::Position::AfterPort];
        if get("host")? != expected_host
            || get("accept")? != "application/json"
            || get("content-type")? != "application/x-www-form-urlencoded"
            || get(SERVER_HEADER)? != self.server_id
        {
            return Err(AuthError::InvalidToken);
        }
        let date = get("x-amz-date")?;
        let signed_at = NaiveDateTime::parse_from_str(date, "%Y%m%dT%H%M%SZ")
            .map_err(|_| AuthError::InvalidToken)?
            .and_utc()
            .timestamp();
        if now.abs_diff(signed_at) > 300 {
            return Err(AuthError::InvalidTime);
        }
        validate_authorization(get("authorization")?, &headers, date)?;
        Ok(headers)
    }
}

fn validate_authorization(auth: &str, headers: &HeaderMap, date: &str) -> Result<(), AuthError> {
    let value = auth
        .strip_prefix("AWS4-HMAC-SHA256 ")
        .ok_or(AuthError::InvalidToken)?;
    let mut fields = BTreeMap::new();
    for item in value.split(',') {
        let (key, value) = item.trim().split_once('=').ok_or(AuthError::InvalidToken)?;
        if fields.insert(key, value).is_some() {
            return Err(AuthError::InvalidToken);
        }
    }
    if fields.len() != 3 {
        return Err(AuthError::InvalidToken);
    }
    let credential = fields.get("Credential").ok_or(AuthError::InvalidToken)?;
    let parts: Vec<_> = credential.split('/').collect();
    if parts.len() != 5
        || parts[0].is_empty()
        || parts[1] != date.get(..8).ok_or(AuthError::InvalidToken)?
        || parts[2].is_empty()
        || parts[3] != "sts"
        || parts[4] != "aws4_request"
    {
        return Err(AuthError::InvalidToken);
    }
    let signature = fields.get("Signature").ok_or(AuthError::InvalidToken)?;
    if signature.len() != 64 || !signature.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AuthError::InvalidToken);
    }
    let names: Vec<_> = fields
        .get("SignedHeaders")
        .ok_or(AuthError::InvalidToken)?
        .split(';')
        .collect();
    if names.windows(2).any(|pair| pair[0] >= pair[1])
        || names.iter().any(|name| {
            !headers.contains_key(*name) || name.bytes().any(|b| b.is_ascii_uppercase())
        })
        || headers
            .keys()
            .any(|name| name != "authorization" && !names.contains(&name.as_str()))
    {
        return Err(AuthError::InvalidToken);
    }
    Ok(())
}

#[derive(Deserialize)]
struct StsIdentity {
    #[serde(rename = "Account")]
    account: String,
    #[serde(rename = "Arn")]
    arn: String,
}

fn parse_identity(bytes: &[u8]) -> Result<StsIdentity, AuthError> {
    if bytes.iter().find(|byte| !byte.is_ascii_whitespace()) == Some(&b'{') {
        let value: serde_json::Value =
            jose::strict_json(bytes).map_err(|_| AuthError::ProviderUnavailable)?;
        let result = value
            .get("GetCallerIdentityResponse")
            .and_then(|v| v.get("GetCallerIdentityResult"))
            .or_else(|| value.get("GetCallerIdentityResult"))
            .unwrap_or(&value);
        return serde_json::from_value(result.clone()).map_err(|_| AuthError::ProviderUnavailable);
    }
    parse_xml_identity(bytes)
}

fn account_id(value: &str) -> bool {
    value.len() == 12 && value.bytes().all(|byte| byte.is_ascii_digit())
}

/// STS role session ARNs lose only the final session segment; the registry
/// binds the stable role ARN, never an attacker-selected session name.
fn canonical_arn(arn: &str, account: &str) -> Result<String, AuthError> {
    if !account_id(account) || !jose::valid_identifier(arn, 2048) || !arn.is_ascii() {
        return Err(AuthError::InvalidToken);
    }
    let parts: Vec<_> = arn.splitn(6, ':').collect();
    if parts.len() != 6
        || parts[0] != "arn"
        || !matches!(parts[1], "aws" | "aws-cn" | "aws-us-gov")
        || !parts[3].is_empty()
        || parts[4] != account
    {
        return Err(AuthError::InvalidToken);
    }
    match parts[2] {
        "iam"
            if parts[5] == "root"
                || parts[5]
                    .strip_prefix("user/")
                    .is_some_and(|name| !name.is_empty()) =>
        {
            Ok(arn.to_owned())
        }
        "sts" => {
            let role = parts[5]
                .strip_prefix("assumed-role/")
                .ok_or(AuthError::InvalidToken)?;
            let (role, session) = role.rsplit_once('/').ok_or(AuthError::InvalidToken)?;
            if role.is_empty() || session.is_empty() || role.split('/').any(str::is_empty) {
                return Err(AuthError::InvalidToken);
            }
            Ok(format!("arn:{}:iam::{account}:role/{role}", parts[1]))
        }
        _ => Err(AuthError::InvalidToken),
    }
}

fn parse_xml_identity(bytes: &[u8]) -> Result<StsIdentity, AuthError> {
    use quick_xml::{Reader, events::Event};
    let mut reader = Reader::from_reader(bytes);
    reader.config_mut().trim_text(true);
    let mut stack: Vec<Vec<u8>> = Vec::new();
    let mut seen = BTreeSet::new();
    let mut root_seen = false;
    let mut account = None;
    let mut arn = None;
    loop {
        match reader
            .read_event()
            .map_err(|_| AuthError::ProviderUnavailable)?
        {
            Event::Start(tag) => {
                let name = tag.name().as_ref().as_bytes().to_vec();
                let allowed = match stack.as_slice() {
                    [] => !root_seen && name == b"GetCallerIdentityResponse",
                    [root] if root == b"GetCallerIdentityResponse" => matches!(
                        name.as_slice(),
                        b"GetCallerIdentityResult" | b"ResponseMetadata"
                    ),
                    [_, result] if result == b"GetCallerIdentityResult" => {
                        matches!(name.as_slice(), b"Account" | b"Arn" | b"UserId")
                    }
                    [_, metadata] if metadata == b"ResponseMetadata" => name == b"RequestId",
                    _ => false,
                };
                if !allowed || !seen.insert(name.clone()) {
                    return Err(AuthError::ProviderUnavailable);
                }
                if stack.is_empty() {
                    root_seen = true;
                }
                stack.push(name);
            }
            Event::End(_) => {
                stack.pop().ok_or(AuthError::ProviderUnavailable)?;
            }
            Event::Text(text) => {
                let value = text.as_ref();
                match stack.last().map(Vec::as_slice) {
                    Some(b"Account") if account.is_none() => account = Some(value.to_owned()),
                    Some(b"Arn") if arn.is_none() => arn = Some(value.to_owned()),
                    Some(b"UserId" | b"RequestId") => {}
                    _ if value.trim().is_empty() => {}
                    _ => return Err(AuthError::ProviderUnavailable),
                }
            }
            Event::Decl(_) if !root_seen => {}
            Event::Comment(_) => {}
            Event::Eof if root_seen && stack.is_empty() => break,
            // DTDs, entity references, CDATA, processing instructions and
            // unexpected empty/nested elements are outside this response.
            _ => return Err(AuthError::ProviderUnavailable),
        }
    }
    Ok(StsIdentity {
        account: account.ok_or(AuthError::ProviderUnavailable)?,
        arn: arn.ok_or(AuthError::ProviderUnavailable)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, routing::post};
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    const ACCOUNT: &str = "123456789012";
    const ARN: &str = "arn:aws:sts::123456789012:assumed-role/Launcher/session";
    const NOW: i64 = 1_790_553_600;

    fn request(url: &str) -> AwsIamRequest {
        let parsed = Url::parse(url).unwrap();
        let date = chrono::DateTime::from_timestamp(NOW, 0)
            .unwrap()
            .format("%Y%m%dT%H%M%SZ")
            .to_string();
        let mut headers = BTreeMap::from([
            (
                "host".into(),
                vec![parsed[url::Position::BeforeHost..url::Position::AfterPort].to_owned()],
            ),
            ("accept".into(), vec!["application/json".into()]),
            (
                "content-type".into(),
                vec!["application/x-www-form-urlencoded".into()],
            ),
            ("x-amz-date".into(), vec![date.clone()]),
            (SERVER_HEADER.into(), vec!["https://recall/mcp".into()]),
        ]);
        headers.insert("authorization".into(),vec![format!("AWS4-HMAC-SHA256 Credential=EXAMPLE/{}/us-east-1/sts/aws4_request, SignedHeaders=accept;content-type;host;x-amz-date;x-fleet-recall-server-id, Signature={}",&date[..8],"ab".repeat(32))]);
        AwsIamRequest {
            iam_http_request_method: "POST".into(),
            iam_request_url: base64::encode(url.as_bytes()),
            iam_request_body: base64::encode(ACTION.as_bytes()),
            iam_request_headers: headers,
        }
    }

    fn anchor(url: &str) -> AwsIamAnchor {
        AwsIamAnchor::new(AwsIamConfig {
            anchor_id: "aws".into(),
            sts_endpoint: url.into(),
            server_id: "https://recall/mcp".into(),
            allowed_accounts: BTreeSet::from([ACCOUNT.into()]),
            allow_http: true,
        })
        .unwrap()
    }

    #[test]
    fn xml_and_json_have_the_same_identity_and_reject_ambiguity() {
        let xml = format!(
            "<GetCallerIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\"><GetCallerIdentityResult><Arn>{ARN}</Arn><UserId>AIDA:session</UserId><Account>{ACCOUNT}</Account></GetCallerIdentityResult><ResponseMetadata><RequestId>request</RequestId></ResponseMetadata></GetCallerIdentityResponse>"
        );
        for bytes in [xml.as_bytes(), br#"{"GetCallerIdentityResponse":{"GetCallerIdentityResult":{"Arn":"arn:aws:sts::123456789012:assumed-role/Launcher/session","Account":"123456789012"}}}"#] {
            let identity=parse_identity(bytes).unwrap();
            assert_eq!(canonical_arn(&identity.arn,&identity.account).unwrap(),"arn:aws:iam::123456789012:role/Launcher");
        }
        let duplicate = xml.replace("</Account>", "</Account><Account>000000000000</Account>");
        assert!(parse_identity(duplicate.as_bytes()).is_err());
        assert!(parse_identity(b"<!DOCTYPE x [<!ENTITY a SYSTEM 'file:///etc/passwd'>]><GetCallerIdentityResponse>&a;</GetCallerIdentityResponse>").is_err());
        assert!(canonical_arn(ARN, "000000000000").is_err());
        assert!(canonical_arn("arn:aws:sts::123456789012:federated-user/name", ACCOUNT).is_err());
    }

    #[tokio::test]
    async fn forwarding_is_pinned_and_rejects_unsigned_binding_before_network() {
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = calls.clone();
        let app = Router::new().route(
            "/",
            post(move |headers: HeaderMap, body: String| {
                seen.fetch_add(1, Ordering::SeqCst);
                assert_eq!(headers["accept"], "application/json");
                assert_eq!(headers[SERVER_HEADER], "https://recall/mcp");
                assert_eq!(body, ACTION);
                async { axum::Json(serde_json::json!({"Account":ACCOUNT,"Arn":ARN})) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let anchor = anchor(&url);
        let request = request(&url);
        assert_eq!(
            anchor.verify_request(&request, NOW).await.unwrap().subject,
            "arn:aws:iam::123456789012:role/Launcher"
        );
        for variant in 0..6 {
            let mut bad = request.clone();
            match variant {
                0 => bad.iam_request_url = base64::encode(b"http://169.254.169.254/"),
                1 => bad.iam_request_body = base64::encode(b"Action=AssumeRole&Version=2011-06-15"),
                2 => {
                    bad.iam_request_headers.get_mut("authorization").unwrap()[0] = bad
                        .iam_request_headers["authorization"][0]
                        .replace(";x-fleet-recall-server-id", "");
                }
                3 => {
                    bad.iam_request_headers.insert(
                        SERVER_HEADER.into(),
                        vec!["https://another-server/mcp".into()],
                    );
                }
                4 => {
                    bad.iam_request_headers.insert(
                        "X-Fleet-Recall-Server-Id".into(),
                        vec!["https://recall/mcp".into()],
                    );
                }
                _ => {
                    bad.iam_request_headers
                        .insert("host".into(), vec!["attacker.example".into()]);
                }
            }
            assert!(anchor.verify_request(&bad, NOW).await.is_err());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            anchor
                .verify_request(&request, NOW + 301)
                .await
                .unwrap_err(),
            AuthError::InvalidTime
        );
        task.abort();
    }
}
