//! Content-free HTTP measurements. Only code-owned route categories escape.

use axum::Router;
use axum::extract::{MatchedPath, Request, State};
use axum::middleware::{self, Next};
use axum::response::Response;
use tracing::Instrument as _;

use super::{Outcome, add_units, start};

/// Install outside authentication, limits, and routing so rejected requests
/// are measured too. The component must be a fixed server role.
pub fn instrument(router: Router, component: &'static str) -> Router {
    router.layer(middleware::from_fn_with_state(component, observe))
}

async fn observe(State(component): State<&'static str>, request: Request, next: Next) -> Response {
    let operation = route(
        request
            .extensions()
            .get::<MatchedPath>()
            .map(MatchedPath::as_str),
    );
    let guard = start(component, operation);
    let response = next.run(request).instrument(guard.span()).await;
    let status = response.status();
    // Status class is finite; raw method, URI, headers and bodies never enter telemetry.
    let class = match status.as_u16() {
        100..=199 => "responses_1xx",
        200..=299 => "responses_2xx",
        300..=399 => "responses_3xx",
        400..=499 => "responses_4xx",
        _ => "responses_5xx",
    };
    add_units(component, operation, class, 1);
    guard.finish(match status.as_u16() {
        401 | 403 | 429 => Outcome::Refused,
        408 | 504 => Outcome::Timeout,
        400..=499 => Outcome::Invalid,
        500..=599 => Outcome::Error,
        _ => Outcome::Success,
    });
    response
}

fn route(path: Option<&str>) -> &'static str {
    match path {
        Some("/") => "index",
        Some("/healthz" | "/readyz") => "health",
        Some("/api/status") => "status",
        Some("/api/recall") => "recall",
        Some("/mcp") => "mcp",
        Some("/v1/embed") => "embed",
        Some("/v1/descriptor") => "descriptor",
        Some("/v1/model") => "model",
        Some(
            "/.well-known/oauth-protected-resource" | "/.well-known/oauth-protected-resource/mcp",
        ) => "resource_metadata",
        Some("/.well-known/jwks.json") => "jwks",
        Some("/v1/grants") => "grant",
        Some("/v1/grants/{jti}") => "revoke",
        Some("/v1/auth/aws") => "auth_aws",
        Some("/v1/transcripts/{instance}/{file}") => "transcript",
        Some("/v1/hooks/{connector_instance}") => "ingress",
        _ => "other",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        routing::{delete, get},
    };
    use tower::ServiceExt as _;

    #[test]
    fn unknown_paths_never_become_labels() {
        assert_eq!(
            route(Some(crate::collectors::ingress::INGRESS_ROUTE)),
            "ingress"
        );
        assert_eq!(route(Some("/tenant/customer-secret?token=secret")), "other");
        assert_eq!(route(None), "other");
        assert_eq!(
            route(Some("/v1/transcripts/{instance}/{file}")),
            "transcript"
        );
        for (path, expected) in [
            ("/mcp", "mcp"),
            ("/v1/embed", "embed"),
            ("/v1/descriptor", "descriptor"),
            ("/.well-known/oauth-protected-resource", "resource_metadata"),
            (
                "/.well-known/oauth-protected-resource/mcp",
                "resource_metadata",
            ),
            ("/v1/grants", "grant"),
            ("/v1/grants/{jti}", "revoke"),
            ("/v1/auth/aws", "auth_aws"),
            ("/v1/grants/private-grant-id", "other"),
            ("/v1/auth/private-anchor", "other"),
        ] {
            assert_eq!(route(Some(path)), expected, "{path}");
        }
    }

    #[tokio::test]
    async fn matched_remote_route_excludes_grant_id_and_query() {
        let router = instrument(
            Router::new().route(
                "/v1/grants/{jti}",
                delete(|| async { StatusCode::FORBIDDEN }),
            ),
            "http_remote_route_test",
        );
        let response = router
            .oneshot(
                Request::delete("/v1/grants/private-grant-id?token=private-query-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let metrics = super::super::render().unwrap();
        assert!(metrics.contains(
            "fleet_recall_operations_total{component=\"http_remote_route_test\",operation=\"revoke\",outcome=\"refused\"} 1"
        ));
        assert!(!metrics.contains("private-grant-id"));
        assert!(!metrics.contains("private-query-token"));
    }

    #[tokio::test]
    async fn instrumentation_preserves_http_errors_and_bodies() {
        let router = instrument(
            Router::new().route("/mcp", get(|| async { (StatusCode::UNAUTHORIZED, "no") })),
            "http_test",
        );
        let response = router
            .clone()
            .oneshot(Request::get("/mcp").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            axum::body::to_bytes(response.into_body(), 8).await.unwrap(),
            "no"
        );
        let missing = router
            .oneshot(Request::get("/private-secret").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        assert!(!super::super::render().unwrap().contains("private-secret"));
    }
}
