//! `ostk-fleet-recall ingress`: the private-plane webhook receiver (ADR 0008
//! D12).
//!
//! One route, `POST /v1/hooks/{connector_instance}`, for every collector of
//! the sources file that configures a webhook (`push.signing_secret_env`).
//! For each request, in order:
//!
//! 1. An instance the sources file does not configure for webhooks is `404`
//!    and a log line; nothing is written, so an unauthenticated caller cannot
//!    fill the dead letters of an instance that does not exist.
//! 2. The body limit ([`super::DEFAULT_INGRESS_MAX_BODY_BYTES`] unless the
//!    operator sets `FLEET_RECALL_INGRESS_MAX_BODY_BYTES`): a longer body is
//!    `413` and an `oversize` dead letter.
//! 3. The provider's signature over the exact bytes received, under the
//!    injected clock ([`super::PushVerifierV1`]): `401` and an
//!    `invalid_signature` or `stale_signature` dead letter.
//! 4. The signed body is parsed (`400`, `parse_failed`) and its scope checked
//!    against the instance's pin (`403`, `unauthorized_scope`).
//! 5. It maps to a hint (ids only), to nothing the collectors read, or to a
//!    Slack challenge, and is inserted once
//!    ([`super::deliveries::IngressStoreV1::record_delivery`]): a replay adds
//!    no row.
//! 6. `200` once the row is committed (a challenge's body is the challenge);
//!    `503` when the database failed, so the provider retries.
//!
//! A rejection's dead letter is at most one row per instance, reason, and
//! minute, and holds only the digest of what was refused. The receiver binds
//! loopback unless `--allow-non-loopback` says otherwise: providers reach it
//! through an operator's relay, and it is never mounted on the demo's public
//! router.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header as http_header};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use chrono::{DateTime, Utc};
use sha2::{Digest as _, Sha256};

use crate::collectors::{CollectorAdapterV1, adapter};
use crate::error::{FleetError, Result};
use crate::memory_contracts::collected_item::ProviderKindV1;
use crate::memory_contracts::common::ContractId;
use crate::memory_contracts::digest::Sha256Digest;
use crate::worker::WorkerSourcesV1;

use super::super::cockroach::framed_sha256;
use super::super::sink::DeadLetterReasonV1;
use super::deliveries::{DeliveryRecordV1, IngressStoreV1, RejectionRecordV1};
use super::{
    DEFAULT_INGRESS_MAX_BODY_BYTES, DeliveryMappingV1, INGRESS_ROUTE, MAX_INGRESS_MAX_BODY_BYTES,
    PushRequestV1, PushVerifierV1, SigningKeyV1,
};

/// The receiver's clock: read once per request.
pub type IngressClockV1 = Arc<dyn Fn() -> DateTime<Utc> + Send + Sync>;

/// The wall clock.
#[must_use]
pub fn system_clock() -> IngressClockV1 {
    Arc::new(Utc::now)
}

/// One collector instance the receiver accepts deliveries for.
pub struct IngressInstanceV1 {
    instance: ContractId,
    provider: ProviderKindV1,
    provider_scope_id: String,
    verifier: &'static dyn PushVerifierV1,
    key: SigningKeyV1,
}

impl std::fmt::Debug for IngressInstanceV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IngressInstanceV1")
            .field("instance", &self.instance)
            .field("provider", &self.provider)
            .field("provider_scope_id", &self.provider_scope_id)
            .finish_non_exhaustive()
    }
}

/// Every instance the receiver accepts, by instance id.
#[derive(Debug, Default)]
pub struct IngressInstancesV1 {
    instances: BTreeMap<String, IngressInstanceV1>,
}

impl IngressInstancesV1 {
    /// Every collector of `sources` that configures a webhook, with its
    /// signing key read from the variable its `push.signing_secret_env`
    /// names. `environment` is the process environment in production.
    ///
    /// The receiver holds no provider credential: it fails closed when any
    /// variable a collector's settings name for its API credential (a
    /// `settings.*_env` key, such as `token_env`) is set, since the sources
    /// file it shares with the worker names them. A compromised receiver then
    /// has no read access to the providers' content.
    ///
    /// # Errors
    ///
    /// [`FleetError::Configuration`] when a provider credential is set, no
    /// collector configures a webhook, a provider has no webhook this build
    /// receives, or a secret is missing or gives no key. The error names the
    /// variable, never its value.
    pub fn from_sources(
        sources: &WorkerSourcesV1,
        environment: &dyn Fn(&str) -> Option<String>,
    ) -> Result<Self> {
        refuse_provider_credentials(sources, environment)?;
        let mut instances = BTreeMap::new();
        for source in &sources.collectors {
            let Some(push) = &source.push else {
                continue;
            };
            let instance = &source.connector_instance;
            let verifier = adapter(source.provider.as_str())
                .and_then(CollectorAdapterV1::push)
                .ok_or_else(|| {
                    FleetError::Configuration(format!(
                        "collector {instance}: provider {} has no webhook this build receives",
                        source.provider
                    ))
                })?;
            let secret = environment(&push.signing_secret_env)
                .filter(|secret| !secret.is_empty())
                .ok_or_else(|| {
                    FleetError::Configuration(format!(
                        "collector {instance}: {} is not set; the ingress needs the webhook's \
                         signing secret",
                        push.signing_secret_env
                    ))
                })?;
            let key = verifier.signing_key(&secret).map_err(|message| {
                FleetError::Configuration(format!(
                    "collector {instance}: {}: {message}",
                    push.signing_secret_env
                ))
            })?;
            instances.insert(
                instance.as_str().to_owned(),
                IngressInstanceV1 {
                    instance: instance.clone(),
                    provider: source.provider.clone(),
                    provider_scope_id: source.provider_scope_id.as_str().to_owned(),
                    verifier,
                    key,
                },
            );
        }
        if instances.is_empty() {
            return Err(FleetError::Configuration(
                "no collector in the sources file configures a webhook (push.signing_secret_env)"
                    .to_owned(),
            ));
        }
        Ok(Self { instances })
    }

    /// The instances, by id.
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.instances.keys().map(String::as_str)
    }

    fn get(&self, instance: &str) -> Option<&IngressInstanceV1> {
        self.instances.get(instance)
    }
}

/// Fail closed when a variable any collector's settings name for a provider
/// credential (`settings.<key>_env`) is set, unless it is also a webhook's
/// signing secret variable. The error names the variable, never its value.
fn refuse_provider_credentials(
    sources: &WorkerSourcesV1,
    environment: &dyn Fn(&str) -> Option<String>,
) -> Result<()> {
    let secrets: Vec<&str> = sources
        .collectors
        .iter()
        .filter_map(|source| source.push.as_ref())
        .map(|push| push.signing_secret_env.as_str())
        .collect();
    for source in &sources.collectors {
        for (key, value) in &source.settings {
            let Some(variable) = value.as_str() else {
                continue;
            };
            if key.ends_with("_env")
                && !secrets.contains(&variable)
                && environment(variable).is_some()
            {
                return Err(FleetError::Configuration(format!(
                    "the ingress forbids {variable} (collector {}'s settings.{key}): the \
                     receiver never holds a provider API credential; unset it in the \
                     ingress's environment; value is redacted",
                    source.connector_instance
                )));
            }
        }
    }
    Ok(())
}

/// Refuse a listen address that is not loopback unless the operator allows
/// it: providers reach the receiver through a relay the operator runs.
///
/// # Errors
///
/// [`FleetError::Configuration`].
pub fn validate_listen(listen: SocketAddr, allow_non_loopback: bool) -> Result<SocketAddr> {
    if listen.ip().is_loopback() || allow_non_loopback {
        Ok(listen)
    } else {
        Err(FleetError::Configuration(format!(
            "the ingress listens on loopback only; {listen} is not loopback (pass \
             --allow-non-loopback to listen there, behind a relay you run)"
        )))
    }
}

/// The body limit `FLEET_RECALL_INGRESS_MAX_BODY_BYTES` sets, or the
/// default.
///
/// # Errors
///
/// [`FleetError::Configuration`] for a value that is not 1 to 16 MiB.
pub fn max_body_bytes(value: Option<&str>) -> Result<usize> {
    let Some(value) = value else {
        return Ok(DEFAULT_INGRESS_MAX_BODY_BYTES);
    };
    value
        .parse::<usize>()
        .ok()
        .filter(|bytes| (1..=MAX_INGRESS_MAX_BODY_BYTES).contains(bytes))
        .ok_or_else(|| {
            FleetError::Configuration(format!(
                "FLEET_RECALL_INGRESS_MAX_BODY_BYTES must be an integer from 1 to \
                 {MAX_INGRESS_MAX_BODY_BYTES}"
            ))
        })
}

/// Everything the receiver's handler shares.
struct IngressStateV1 {
    store: IngressStoreV1,
    instances: IngressInstancesV1,
    clock: IngressClockV1,
}

/// The receiver's router: the one route, the body limit, and the state.
pub fn router(
    store: IngressStoreV1,
    instances: IngressInstancesV1,
    clock: IngressClockV1,
    body_limit: usize,
) -> Router {
    Router::new()
        .route(INGRESS_ROUTE, post(receive))
        .layer(DefaultBodyLimit::max(body_limit))
        .with_state(Arc::new(IngressStateV1 {
            store,
            instances,
            clock,
        }))
}

/// Serve `router` on `listener` until `shutdown` completes.
///
/// # Errors
///
/// [`FleetError::Configuration`] when the server fails.
pub async fn serve(
    listener: tokio::net::TcpListener,
    router: Router,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(|error| FleetError::Configuration(format!("the ingress server failed: {error}")))
}

/// An instance id a caller sent, cut to what an id holds, for a log line.
fn shown_instance(instance: &str) -> String {
    instance
        .chars()
        .filter(|scalar| scalar.is_ascii_alphanumeric() || matches!(scalar, '.' | '_' | '-'))
        .take(64)
        .collect()
}

async fn reject(
    state: &IngressStateV1,
    target: &IngressInstanceV1,
    reason: DeadLetterReasonV1,
    payload_digest: &Sha256Digest,
    diagnostic: &str,
    now: DateTime<Utc>,
) {
    let recorded = state
        .store
        .record_rejection(&RejectionRecordV1 {
            instance: target.instance.as_str(),
            provider: target.provider.as_str(),
            reason,
            payload_digest,
            diagnostic,
            now,
        })
        .await;
    if let Err(error) = recorded {
        tracing::warn!(
            instance = %target.instance,
            reason = reason.as_str(),
            %error,
            "an ingress rejection was not recorded"
        );
    }
}

fn status(code: u16) -> Response {
    StatusCode::from_u16(code)
        .unwrap_or(StatusCode::BAD_REQUEST)
        .into_response()
}

async fn receive(
    State(state): State<Arc<IngressStateV1>>,
    Path(instance): Path<String>,
    headers: HeaderMap,
    body: std::result::Result<Bytes, BytesRejection>,
) -> Response {
    let Some(target) = state.instances.get(&instance) else {
        tracing::warn!(
            instance = %shown_instance(&instance),
            "an ingress delivery named an instance that takes no webhook"
        );
        return StatusCode::NOT_FOUND.into_response();
    };
    let now = (state.clock)();
    let body = match body {
        Ok(body) => body,
        Err(rejection) => {
            if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
                let declared = headers
                    .get(http_header::CONTENT_LENGTH)
                    .map_or(&b""[..], HeaderValue::as_bytes);
                reject(
                    &state,
                    target,
                    DeadLetterReasonV1::Oversize,
                    &framed_sha256(
                        "ostk-ingress-oversize-v1",
                        &[target.instance.as_str().as_bytes(), declared],
                    ),
                    "a webhook delivery is larger than the ingress body limit",
                    now,
                )
                .await;
            }
            return rejection.into_response();
        }
    };
    let raw_body_sha256 = Sha256Digest::from_bytes(Sha256::digest(&body).into());
    let delivery = match target.verifier.accept(&PushRequestV1 {
        headers: &headers,
        body: &body,
        provider_scope_id: &target.provider_scope_id,
        key: &target.key,
        now,
    }) {
        Ok(delivery) => delivery,
        Err(refusal) => {
            reject(
                &state,
                target,
                refusal.reason(),
                &raw_body_sha256,
                refusal.diagnostic(),
                now,
            )
            .await;
            return status(refusal.status());
        }
    };
    let recorded = state
        .store
        .record_delivery(&DeliveryRecordV1 {
            instance: target.instance.as_str(),
            provider: target.provider.as_str(),
            delivery: &delivery,
            raw_body_sha256: &raw_body_sha256,
            raw_body_bytes: body.len(),
        })
        .await;
    match recorded {
        Ok(_) => match delivery.mapping {
            DeliveryMappingV1::Challenge(challenge) => (
                StatusCode::OK,
                [(http_header::CONTENT_TYPE, "text/plain; charset=utf-8")],
                challenge,
            )
                .into_response(),
            DeliveryMappingV1::Hint(_) | DeliveryMappingV1::Ignored => {
                StatusCode::OK.into_response()
            }
        },
        Err(error) => {
            tracing::warn!(
                instance = %target.instance,
                %error,
                "an ingress delivery was not recorded; answering 503 so the provider retries"
            );
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_non_loopback_listen_needs_the_operator_to_allow_it() {
        let loopback: SocketAddr = "127.0.0.1:8787".parse().unwrap();
        let v6: SocketAddr = "[::1]:8787".parse().unwrap();
        let open: SocketAddr = "0.0.0.0:8787".parse().unwrap();
        assert_eq!(validate_listen(loopback, false).unwrap(), loopback);
        assert_eq!(validate_listen(v6, false).unwrap(), v6);
        let refused = validate_listen(open, false).unwrap_err().to_string();
        assert!(refused.contains("--allow-non-loopback"), "{refused}");
        assert_eq!(validate_listen(open, true).unwrap(), open);
    }

    #[test]
    fn the_body_limit_is_bounded() {
        assert_eq!(
            max_body_bytes(None).unwrap(),
            DEFAULT_INGRESS_MAX_BODY_BYTES
        );
        assert_eq!(max_body_bytes(Some("4096")).unwrap(), 4096);
        for bad in ["0", "-1", "lots", "17000000"] {
            assert!(max_body_bytes(Some(bad)).is_err(), "{bad}");
        }
    }

    fn sources(push: &serde_json::Value) -> WorkerSourcesV1 {
        WorkerSourcesV1::from_json_slice(
            &serde_json::to_vec(&serde_json::json!({
                "schema_version": 1,
                "collectors": [{
                    "provider": "slack",
                    "connector_principal": "principal.slack",
                    "connector_instance": "slack.acme",
                    "provider_scope_id": "T07ACME0001",
                    "settings": {"token_env": "FLEET_RECALL_SLACK_BOT_TOKEN",
                                 "channels": ["C07PLATENG1"]},
                    "push": push
                }]
            }))
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn instances_read_their_secret_from_the_variable_the_sources_file_names() {
        let configured = sources(
            &serde_json::json!({"signing_secret_env": "FLEET_RECALL_SLACK_SIGNING_SECRET"}),
        );
        let environment = |name: &str| {
            (name == "FLEET_RECALL_SLACK_SIGNING_SECRET")
                .then(|| "EXAMPLE-NOT-A-SIGNING-SECRET".to_owned())
        };
        let instances = IngressInstancesV1::from_sources(&configured, &environment).unwrap();
        assert_eq!(instances.ids().collect::<Vec<_>>(), ["slack.acme"]);
        assert!(!format!("{instances:?}").contains("EXAMPLE-NOT-A-SIGNING-SECRET"));
        let missing = IngressInstancesV1::from_sources(&configured, &|_: &str| None)
            .unwrap_err()
            .to_string();
        assert!(
            missing.contains("FLEET_RECALL_SLACK_SIGNING_SECRET"),
            "{missing}"
        );
    }

    #[test]
    fn the_receiver_refuses_to_start_beside_a_provider_api_credential() {
        let configured = sources(
            &serde_json::json!({"signing_secret_env": "FLEET_RECALL_SLACK_SIGNING_SECRET"}),
        );
        let environment = |name: &str| match name {
            "FLEET_RECALL_SLACK_SIGNING_SECRET" => Some("EXAMPLE-NOT-A-SIGNING-SECRET".to_owned()),
            "FLEET_RECALL_SLACK_BOT_TOKEN" => Some("xoxb-EXAMPLE-NOT-A-TOKEN".to_owned()),
            _ => None,
        };
        let refused = IngressInstancesV1::from_sources(&configured, &environment)
            .unwrap_err()
            .to_string();
        assert!(
            refused.contains("FLEET_RECALL_SLACK_BOT_TOKEN"),
            "{refused}"
        );
        assert!(refused.contains("settings.token_env"), "{refused}");
        assert!(!refused.contains("xoxb-"), "{refused}");
        assert!(!refused.contains("  "), "{refused}");
    }
}
