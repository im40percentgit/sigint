//! sigint-web — Axum-based REST API and WebSocket server for SIGINT.
//!
//! # Architecture
//!
//! - [`create_router`] assembles the full Axum `Router` with CORS middleware and
//!   all REST + WebSocket routes mounted. Useful for testing with `oneshot`.
//! - [`serve`] binds a TCP listener and runs the server until shutdown.
//! - [`serve_with_shutdown`] is the same but accepts a caller-supplied shutdown
//!   future for graceful termination (used by the `serve` CLI subcommand).
//!
//! # Route map
//!
//! | Method | Path | Handler |
//! |--------|------|---------|
//! | GET | `/api/health` | [`routes::health`] |
//! | GET | `/api/sessions` | [`routes::list_sessions`] |
//! | GET | `/api/sessions/{id}` | [`routes::get_session`] |
//! | DELETE | `/api/sessions/{id}` | [`routes::delete_session`] |
//! | GET | `/api/sessions/{id}/assets` | [`routes::session_assets`] |
//! | GET | `/api/sessions/{id}/findings` | [`routes::session_findings`] |
//! | GET | `/api/report/{id}` | [`routes::get_report`] |
//! | POST | `/api/scan` | [`routes::start_scan`] |
//! | GET | `/api/scan/{id}/status` | [`routes::scan_status`] |
//! | DELETE | `/api/scan/{id}` | [`routes::cancel_scan`] |
//! | GET | `/api/scans` | [`routes::list_scans`] |
//! | GET | `/api/diff/{scan_a}/{scan_b}` | [`routes::diff_scans`] |
//! | GET | `/api/models` | [`routes::list_models`] |
//! | POST | `/api/train/harvest/{id}` | [`routes::harvest_session`] |
//! | POST | `/api/train/unharvest/{id}` | [`routes::unharvest_session`] |
//! | GET | `/api/train/stats` | [`routes::train_stats`] |
//! | POST | `/api/train/export` | [`routes::train_export`] |
//! | POST | `/api/train/finetune` | [`routes::train_finetune`] |
//! | GET | `/api/train/jobs` | [`routes::train_list_jobs`] |
//! | GET | `/api/train/jobs/{id}` | [`routes::train_get_job`] |
//! | POST | `/api/train/evaluate` | [`routes::train_run_eval`] |
//! | GET | `/api/train/evaluations/last` | [`routes::train_last_eval`] |
//! | POST | `/api/model/promote` | [`routes::model_promote`] |
//! | POST | `/api/model/rollback` | [`routes::model_rollback`] |
//! | GET | `/api/model/promotions` | [`routes::model_promotions`] |
//! | GET | `/ws/events` | [`ws::ws_events`] |
//!
//! @decision DEC-WEB-001
//! @title Axum 0.8 with tower-http CORS as the web framework
//! @status accepted
//! @rationale Axum is the de-facto async Rust web framework (backed by the
//! Tokio team), with ergonomic extractors, first-class WebSocket support, and
//! native integration with tower middleware.
//!
//! @decision DEC-WEB-AUTH-001
//! @title Bearer token + shared secret for all REST and WebSocket endpoints
//! @status accepted
//! @rationale See auth.rs for full rationale. Middleware is wired BEFORE the
//! CORS layer so that CORS wraps auth — preflight OPTIONS requests still reach
//! the CORS layer without being blocked by auth (browsers send OPTIONS without
//! Authorization headers). The auth middleware exempts GET /api/health for
//! liveness probes. All other paths require a valid Bearer token.

pub mod auth;
pub mod routes;
pub mod state;
pub mod static_files;
pub mod ws;

use std::sync::Arc;

use axum::{
    http::{HeaderValue, Method},
    middleware,
    routing::{delete, get, post},
    Router,
};
use tokio::sync::Semaphore;
use tower_http::cors::{AllowOrigin, CorsLayer};

use sigint_agents::ScanService;
use sigint_core::{event::EventBus, ApprovalRegistry, Config};
use sigint_llm::factory::create_provider;
use sigint_store::Database;

pub use state::{AppState, ProviderFactory};

/// Build the semaphore permit count from `max_concurrent_jobs`.
///
/// 0 → `usize::MAX` (disabled); otherwise the configured value.
fn semaphore_permits(max_concurrent_jobs: usize) -> usize {
    if max_concurrent_jobs == 0 {
        usize::MAX
    } else {
        max_concurrent_jobs
    }
}

/// Assemble the full Axum `Router` with auth and CORS middleware injected.
///
/// Layer order matters in Axum: layers are applied from innermost (closest to
/// the handler) outward. We want:
///
///   request → CORS → auth → handler
///
/// which means CORS wraps auth so OPTIONS preflight reaches the CORS layer
/// before being blocked by auth. In Axum's `.layer()` chain, the last
/// `.layer()` call is the outermost layer. So we add CORS last.
///
/// The `api_key` is resolved once at startup (see [`auth::resolve_api_key`])
/// and stored as `Arc<String>` in the middleware state.
pub fn create_router(state: AppState) -> Router {
    let api_key = Arc::new(state.api_key.clone());

    // Build restricted CORS layer from configured origins.
    let cors = build_cors_layer(&state.config);

    Router::new()
        // Health (exempt from auth — liveness probe)
        .route("/api/health", get(routes::health))
        // Sessions CRUD
        .route("/api/sessions", get(routes::list_sessions))
        .route(
            "/api/sessions/{id}",
            get(routes::get_session).delete(routes::delete_session),
        )
        // Assets and findings
        .route("/api/sessions/{id}/assets", get(routes::session_assets))
        .route("/api/sessions/{id}/findings", get(routes::session_findings))
        // Report generation
        .route("/api/report/{id}", get(routes::get_report))
        // Scan diff
        .route("/api/diff/{scan_a}/{scan_b}", get(routes::diff_scans))
        // Models
        .route("/api/models", get(routes::list_models))
        // Scan lifecycle
        .route("/api/scan", post(routes::start_scan))
        .route("/api/scan/{id}/status", get(routes::scan_status))
        .route("/api/scan/{id}", delete(routes::cancel_scan))
        .route("/api/scans", get(routes::list_scans))
        // Training routes (Phase 26 T1 — all behind Bearer auth)
        .route("/api/train/harvest/{id}", post(routes::harvest_session))
        .route("/api/train/unharvest/{id}", post(routes::unharvest_session))
        .route("/api/train/stats", get(routes::train_stats))
        .route("/api/train/export", post(routes::train_export))
        .route("/api/train/finetune", post(routes::train_finetune))
        .route("/api/train/jobs", get(routes::train_list_jobs))
        .route("/api/train/jobs/{id}", get(routes::train_get_job))
        // Evaluate routes (Phase 26 T3)
        .route("/api/train/evaluate", post(routes::train_run_eval))
        .route("/api/train/evaluations/last", get(routes::train_last_eval))
        // Model swap routes (Phase 26 T3)
        .route("/api/model/promote", post(routes::model_promote))
        .route("/api/model/rollback", post(routes::model_rollback))
        .route("/api/model/promotions", get(routes::model_promotions))
        // WebSocket event bridge
        .route("/ws/events", get(ws::ws_events))
        // Auth middleware (innermost — applied before CORS)
        .layer(middleware::from_fn_with_state(
            api_key,
            auth::auth_middleware,
        ))
        // CORS layer (outermost — wraps auth so OPTIONS preflight is not blocked)
        .layer(cors)
        .with_state(state)
        // SPA fallback: all unmatched paths serve the embedded frontend
        .fallback(static_files::serve_static)
}

/// Build a restricted `CorsLayer` from `config.web.cors_origins`.
///
/// Defaults to `["http://localhost:8080", "http://127.0.0.1:8080"]` when
/// the origin list is empty. Allows standard methods (GET, POST, DELETE,
/// OPTIONS) and the `Authorization` + `Content-Type` headers. No credentials
/// (we use Bearer tokens, not cookies).
fn build_cors_layer(config: &Config) -> CorsLayer {
    let origins: Vec<HeaderValue> = config
        .web
        .effective_cors_origins()
        .into_iter()
        .filter_map(|o| HeaderValue::from_str(&o).ok())
        .collect();

    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers([
            axum::http::header::AUTHORIZATION,
            axum::http::header::CONTENT_TYPE,
        ])
}

/// Bind a TCP listener and run the SIGINT web server.
///
/// This function runs until the process is killed or an unrecoverable error
/// occurs. The event bus is subscribed to by WebSocket clients on demand.
///
/// For graceful shutdown support, use [`serve_with_shutdown`] instead.
pub async fn serve(
    db: Database,
    event_bus: EventBus,
    config: Arc<Config>,
    approval_registry: Arc<ApprovalRegistry>,
    addr: std::net::SocketAddr,
) -> Result<(), sigint_core::Error> {
    serve_with_shutdown(
        db,
        event_bus,
        config,
        approval_registry,
        addr,
        std::future::pending::<()>(),
    )
    .await
}

/// Bind a TCP listener and run the SIGINT web server with a custom shutdown signal.
///
/// The `shutdown` future is awaited concurrently with the server; when it
/// resolves the server stops accepting new connections and drains in-flight
/// requests before returning.  Pass `std::future::pending()` (or call
/// [`serve`]) for a server that only exits on process termination.
///
/// @decision DEC-WEB-007
/// @title serve_with_shutdown accepts generic Future<Output=()> for axum graceful shutdown
/// @status accepted
/// @rationale Axum's `.with_graceful_shutdown` is the idiomatic path for clean
/// server teardown. Wrapping it in a separate exported function keeps the
/// existing `serve` signature stable (no breaking change for existing callers)
/// while giving `sigint-cli`'s serve subcommand clean Ctrl-C support.
/// `serve` delegates here with `std::future::pending()` so its behaviour is
/// unchanged for callers that do not need shutdown control.
pub async fn serve_with_shutdown(
    db: Database,
    event_bus: EventBus,
    config: Arc<Config>,
    approval_registry: Arc<ApprovalRegistry>,
    addr: std::net::SocketAddr,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), sigint_core::Error> {
    let scan_service = Arc::new(ScanService::new(
        config.clone(),
        event_bus.clone(),
        approval_registry.clone(),
    ));

    // Resolve API key once at startup using the priority chain in auth.rs
    let api_key = auth::resolve_api_key(&config);

    // Build training job semaphore from web.train.max_concurrent_jobs.
    // 0 → usize::MAX (disabled cap); otherwise the configured value.
    let permits = semaphore_permits(config.web.train.max_concurrent_jobs);
    let training_job_semaphore = Arc::new(Semaphore::new(permits));

    let state = AppState {
        db: Arc::new(db),
        event_bus,
        config,
        approval_registry,
        scan_service,
        api_key,
        training_job_semaphore,
        provider_factory: std::sync::Arc::new(create_provider),
    };
    let app = create_router(state);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| sigint_core::Error::Other(format!("Cannot bind to {}: {}", addr, e)))?;
    tracing::info!("SIGINT web server listening on {}", addr);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(|e| sigint_core::Error::Other(format!("Web server error: {}", e)))?;
    Ok(())
}

// ── Integration tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use sigint_core::{event::EventBus, ApprovalRegistry, Config};
    use sigint_store::Database;
    use std::sync::Arc;
    use std::time::Duration;
    use tower::ServiceExt;

    const TEST_TOKEN: &str = "integration-test-token-xyz";

    fn test_state() -> AppState {
        let db = Database::open_in_memory().expect("in-memory db");
        let event_bus = EventBus::new();
        let config = Arc::new(Config::default());
        let approval_registry = Arc::new(ApprovalRegistry::new(Duration::from_secs(30)));
        let scan_service = Arc::new(ScanService::new(
            config.clone(),
            event_bus.clone(),
            approval_registry.clone(),
        ));
        let permits = semaphore_permits(config.web.train.max_concurrent_jobs);
        AppState {
            db: Arc::new(db),
            event_bus,
            config,
            approval_registry,
            scan_service,
            api_key: TEST_TOKEN.to_string(),
            training_job_semaphore: Arc::new(Semaphore::new(permits)),
            provider_factory: std::sync::Arc::new(|_cfg| {
                Ok(Box::new(sigint_llm::MockProvider::new()) as Box<dyn sigint_llm::LlmProvider>)
            }),
        }
    }

    #[tokio::test]
    async fn cors_allowed_origin_returns_acao() {
        // Default config allows localhost:8080
        let app = create_router(test_state());
        let req = Request::builder()
            .method("OPTIONS")
            .uri("/api/health")
            .header("Origin", "http://localhost:8080")
            .header("Access-Control-Request-Method", "GET")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // CORS preflight on health (exempt from auth) should return ACAO
        let acao = resp.headers().get("access-control-allow-origin");
        assert!(
            acao.is_some(),
            "expected Access-Control-Allow-Origin header for allowed origin, got headers: {:?}",
            resp.headers()
        );
    }

    #[tokio::test]
    async fn cors_disallowed_origin_no_acao() {
        let app = create_router(test_state());
        let req = Request::builder()
            .method("OPTIONS")
            .uri("/api/health")
            .header("Origin", "https://evil.example.com")
            .header("Access-Control-Request-Method", "GET")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let acao = resp
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        // Either no header at all, or empty — evil origin must not be reflected
        assert!(
            acao.is_empty() || acao == "null",
            "disallowed origin must not get ACAO header, got: {:?}",
            acao
        );
    }

    #[tokio::test]
    async fn ws_upgrade_without_token_returns_401() {
        let app = create_router(test_state());
        // Auth middleware runs before WS upgrade handler
        let req = Request::builder()
            .uri("/ws/events")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("Sec-WebSocket-Version", "13")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "WS upgrade without token must be rejected at auth layer"
        );
    }

    #[tokio::test]
    async fn ws_upgrade_with_query_token_succeeds() {
        let app = create_router(test_state());
        // Auth middleware accepts ?token= before WS upgrade runs.
        // The WS handler returns a non-101 (likely 400) because we're using
        // oneshot (not a real TCP connection) — but it must NOT be 401.
        let req = Request::builder()
            .uri(format!("/ws/events?token={}", TEST_TOKEN))
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("Sec-WebSocket-Version", "13")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "WS upgrade with valid ?token= must pass auth middleware"
        );
    }
}
