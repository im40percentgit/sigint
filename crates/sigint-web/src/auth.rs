//! Bearer-token authentication middleware for the SIGINT web server.
//!
//! This module provides [`auth_middleware`], an Axum middleware that enforces a
//! shared Bearer secret on every request except `GET /api/health`.
//!
//! # Key resolution order
//!
//! 1. `config.web.api_key` (from `[web]` in config.toml)
//! 2. `SIGINT_API_KEY_AUTH` environment variable
//! 3. Key persisted at `~/.config/sigint/.api_key` (written on first boot, mode 0600)
//! 4. Auto-generate a 32-byte URL-safe random token; persist to the file above
//!    and print once to stderr with a "Save this" warning.
//!
//! # Exempt paths
//!
//! `GET /api/health` is always allowed (liveness probe). Every other path
//! requires a valid `Authorization: Bearer <token>` header.
//!
//! # WebSocket auth
//!
//! Browsers cannot set arbitrary headers on `new WebSocket()`. The middleware
//! therefore also accepts the token via:
//! - `?token=<token>` query parameter on `/ws/events` only
//! - `Sec-WebSocket-Protocol: bearer.<token>` subprotocol header
//!
//! @decision DEC-WEB-AUTH-001
//! @title Bearer token + shared secret (vs OAuth/JWT/mTLS)
//! @status accepted
//! @rationale SIGINT is a single-operator pentest tool. A shared Bearer secret
//! is the simplest defensible posture: no token-rotation infra, no IDP, no
//! key distribution ceremony. The auto-generate-on-first-boot default
//! (DEC-WEB-AUTH-002) means default installs are secure out of the box.
//!
//! @decision DEC-WEB-AUTH-002
//! @title Auto-generate and persist API key on first boot
//! @status accepted
//! @rationale If no key is configured the server generates a 32-byte URL-safe
//! random token, prints it once to stderr, and persists it to
//! ~/.config/sigint/.api_key (mode 0600). Subsequent restarts load the
//! persisted key so the operator is never locked out. This beats both
//! "ship with no auth" (insecure) and "refuse to start without a key"
//! (bad UX that causes operators to disable auth entirely).
//!
//! @decision DEC-WEB-AUTH-003
//! @title WS auth via Authorization header OR ?token= query param OR
//!         Sec-WebSocket-Protocol: bearer.<token>
//! @status accepted
//! @rationale Browsers cannot set arbitrary headers on the `new WebSocket()`
//! constructor — the spec prohibits it. The query-param path (simplest) and
//! the Sec-WebSocket-Protocol subprotocol path (more spec-compliant) are both
//! accepted so callers have flexibility. The TUI and CLI use the header path;
//! the embedded web UI uses ?token=. All paths use the same constant-time
//! comparison to prevent timing oracle attacks.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;

use axum::{
    body::Body,
    extract::Request,
    http::{header, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use rand::Rng;
use serde_json::json;
use subtle::ConstantTimeEq;

use sigint_core::Config;

// ── Key resolution ────────────────────────────────────────────────────────────

/// Resolve the effective API key from the priority chain described in the
/// module doc. Generates and persists a random key if none is configured.
///
/// This is called once at server startup; the resolved key is stored in
/// `AppState` for lifetime of the process.
pub fn resolve_api_key(config: &Config) -> String {
    // 1. Config file
    if let Some(key) = &config.web.api_key {
        if !key.is_empty() {
            tracing::info!("web auth: using API key from config.toml [web] section");
            return key.clone();
        }
    }

    // 2. Environment variable (separate from SIGINT_API_KEY which is the LLM key)
    if let Ok(key) = std::env::var("SIGINT_API_KEY_AUTH") {
        if !key.is_empty() {
            tracing::info!("web auth: using API key from SIGINT_API_KEY_AUTH env var");
            return key;
        }
    }

    // 3. Persisted key file
    let key_path = api_key_path();
    if key_path.exists() {
        match std::fs::read_to_string(&key_path) {
            Ok(key) => {
                let key = key.trim().to_string();
                if !key.is_empty() {
                    tracing::info!("web auth: loaded persisted API key from {:?}", key_path);
                    return key;
                }
            }
            Err(e) => {
                tracing::warn!("web auth: cannot read key file {:?}: {}", key_path, e);
            }
        }
    }

    // 4. Generate a new random key, persist it, and print to stderr
    let key = generate_random_key();
    if let Err(e) = persist_key(&key, &key_path) {
        tracing::warn!(
            "web auth: cannot persist generated key to {:?}: {}",
            key_path,
            e
        );
    }

    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════╗");
    eprintln!("║          SIGINT — API KEY GENERATED                      ║");
    eprintln!("║                                                          ║");
    eprintln!("║  A random API key was generated for this server.         ║");
    eprintln!("║  Save it — every API call requires this token:           ║");
    eprintln!("║                                                          ║");
    eprintln!("║  {:<56}  ║", &key);
    eprintln!("║                                                          ║");
    eprintln!("║  Usage:  Authorization: Bearer <key>                     ║");
    eprintln!("║  WebSocket: ?token=<key>                                 ║");
    eprintln!("║                                                          ║");
    eprintln!("║  Key persisted to: {:?}", key_path);
    eprintln!("║  To set permanently, add to ~/.config/sigint/config.toml:║");
    eprintln!("║    [web]                                                  ║");
    eprintln!("║    api_key = \"<key>\"                                    ║");
    eprintln!("╚══════════════════════════════════════════════════════════╝");
    eprintln!();

    key
}

/// Generate a 32-byte URL-safe base64 random token.
fn generate_random_key() -> String {
    let bytes: Vec<u8> = (0..32).map(|_| rand::thread_rng().gen::<u8>()).collect();
    // URL-safe base64 without padding
    use std::fmt::Write;
    let mut out = String::with_capacity(44);
    for b in &bytes {
        write!(out, "{:02x}", b).unwrap();
    }
    out
}

/// Persist the key to `~/.config/sigint/.api_key` with mode 0600.
fn persist_key(key: &str, path: &PathBuf) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, key)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// Return the path to the persisted API key file.
fn api_key_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home)
        .join(".config")
        .join("sigint")
        .join(".api_key")
}

// ── Middleware ────────────────────────────────────────────────────────────────

/// Axum middleware that enforces Bearer-token authentication.
///
/// Exempt paths: `GET /api/health` (liveness probe).
///
/// Token is accepted via:
/// - `Authorization: Bearer <token>` header (preferred)
/// - `?token=<token>` query parameter (WebSocket JS clients, `/ws/events` only)
/// - `Sec-WebSocket-Protocol: bearer.<token>` subprotocol header (WS)
pub async fn auth_middleware(
    State(api_key): axum::extract::State<Arc<String>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    // Health endpoint is always exempt
    if req.uri().path() == "/api/health" && req.method() == axum::http::Method::GET {
        return next.run(req).await;
    }

    // Extract token from the request using all supported methods
    let token = extract_token(&req);

    match token {
        None => (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "authentication required"})),
        )
            .into_response(),
        Some(provided) => {
            if constant_time_eq(provided.as_bytes(), api_key.as_bytes()) {
                next.run(req).await
            } else {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "unauthorized"})),
                )
                    .into_response()
            }
        }
    }
}

/// Extract the Bearer token from the request using all supported paths.
///
/// Priority:
/// 1. `Authorization: Bearer <token>` header
/// 2. `?token=<value>` query parameter
/// 3. `Sec-WebSocket-Protocol: bearer.<token>` subprotocol
fn extract_token(req: &Request<Body>) -> Option<String> {
    // 1. Authorization header
    if let Some(auth_header) = req.headers().get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth_header.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                return Some(token.to_string());
            }
        }
    }

    // 2. ?token= query parameter (primary WS path for browser JS clients).
    // Restrict this to the WebSocket endpoint so REST tokens are not accepted
    // through URLs, which are more likely to be logged or copied around.
    if req.uri().path() == "/ws/events" {
        if let Some(token) = extract_query_token(req.uri().query()) {
            return Some(token);
        }
    }

    // 3. Sec-WebSocket-Protocol: bearer.<token>
    if let Some(proto_header) = req.headers().get("Sec-WebSocket-Protocol") {
        if let Ok(proto_str) = proto_header.to_str() {
            for proto in proto_str.split(',') {
                let proto = proto.trim();
                if let Some(token) = proto.strip_prefix("bearer.") {
                    if !token.is_empty() {
                        return Some(token.to_string());
                    }
                }
            }
        }
    }

    None
}

fn extract_query_token(query: Option<&str>) -> Option<String> {
    if let Some(query) = query {
        for pair in query.split('&') {
            if let Some(val) = pair.strip_prefix("token=") {
                if !val.is_empty() {
                    return Some(val.to_string());
                }
            }
        }
    }
    None
}

/// Constant-time byte comparison to prevent timing oracle attacks.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        // Lengths differ — still do a dummy comparison to avoid length-based timing leak,
        // then return false.
        let _ = a.ct_eq(a);
        return false;
    }
    a.ct_eq(b).into()
}

// Re-export State for use in middleware wiring
use axum::extract::State;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build the `Authorization: Bearer <token>` header value for use in tests.
pub fn bearer_header(token: &str) -> HeaderValue {
    HeaderValue::from_str(&format!("Bearer {}", token)).unwrap()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        middleware,
        routing::get,
        Router,
    };
    use tower::ServiceExt;

    const TEST_TOKEN: &str = "test-secret-token-abc123";

    /// Build a minimal test router with auth middleware wired in.
    fn test_router() -> Router {
        let api_key = Arc::new(TEST_TOKEN.to_string());
        Router::new()
            .route("/api/health", get(|| async { "ok" }))
            .route("/api/sessions", get(|| async { "sessions" }))
            .route("/ws/events", get(|| async { "ws" }))
            .layer(middleware::from_fn_with_state(api_key, auth_middleware))
    }

    #[tokio::test]
    async fn auth_missing_header_returns_401() {
        let app = test_router();
        let req = Request::builder()
            .uri("/api/sessions")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "authentication required");
    }

    #[tokio::test]
    async fn auth_wrong_token_returns_401() {
        let app = test_router();
        let req = Request::builder()
            .uri("/api/sessions")
            .header("Authorization", "Bearer wrong-token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let body = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "unauthorized");
    }

    #[tokio::test]
    async fn auth_correct_token_returns_200() {
        let app = test_router();
        let req = Request::builder()
            .uri("/api/sessions")
            .header("Authorization", format!("Bearer {}", TEST_TOKEN))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn auth_health_endpoint_skips_auth() {
        let app = test_router();
        let req = Request::builder()
            .uri("/api/health")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // Health endpoint must return 200 without any token
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn auth_token_via_query_param() {
        let app = test_router();
        let req = Request::builder()
            .uri(format!("/ws/events?token={}", TEST_TOKEN))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn auth_token_via_query_param_rejected_for_rest() {
        let app = test_router();
        let req = Request::builder()
            .uri(format!("/api/sessions?token={}", TEST_TOKEN))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_token_via_websocket_protocol_header() {
        let app = test_router();
        let req = Request::builder()
            .uri("/ws/events")
            .header("Sec-WebSocket-Protocol", format!("bearer.{}", TEST_TOKEN))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn auth_wrong_query_token_returns_401() {
        let app = test_router();
        let req = Request::builder()
            .uri("/ws/events?token=wrong-token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn constant_time_eq_same_returns_true() {
        assert!(constant_time_eq(b"hello", b"hello"));
    }

    #[test]
    fn constant_time_eq_diff_returns_false() {
        assert!(!constant_time_eq(b"hello", b"world"));
    }

    #[test]
    fn constant_time_eq_diff_lengths_returns_false() {
        assert!(!constant_time_eq(b"short", b"much-longer-value"));
    }

    #[test]
    fn generate_random_key_is_64_chars() {
        let key = generate_random_key();
        assert_eq!(key.len(), 64, "32 bytes hex-encoded = 64 chars");
    }

    #[test]
    fn generate_random_key_is_unique() {
        let k1 = generate_random_key();
        let k2 = generate_random_key();
        assert_ne!(k1, k2);
    }
}
