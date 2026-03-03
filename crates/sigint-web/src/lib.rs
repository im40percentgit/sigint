//! sigint-web — Axum-based REST API and WebSocket server for SIGINT.
//!
//! # Architecture
//!
//! - [`create_router`] assembles the full Axum `Router` with CORS middleware and
//!   all REST + WebSocket routes mounted. Useful for testing with `oneshot`.
//! - [`serve`] binds a TCP listener and runs the server until shutdown.
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
//! | GET | `/ws/events` | [`ws::ws_events`] |
//!
//! @decision DEC-WEB-001
//! @title Axum 0.8 with tower-http CORS as the web framework
//! @status accepted
//! @rationale Axum is the de-facto async Rust web framework (backed by the
//! Tokio team), with ergonomic extractors, first-class WebSocket support, and
//! native integration with tower middleware. CORS is permissive during
//! development; production deployments should restrict origins via config.

pub mod routes;
pub mod state;
pub mod static_files;
pub mod ws;

use std::sync::Arc;

use axum::{
    routing::{delete, get, post},
    Router,
};
use tower_http::cors::CorsLayer;

use sigint_agents::ScanService;
use sigint_core::{event::EventBus, ApprovalRegistry, Config};
use sigint_store::Database;

pub use state::AppState;

/// Assemble the full Axum `Router` with state injected.
///
/// This function is separated from `serve` so tests can call `create_router`
/// and use `tower::ServiceExt::oneshot` without binding a real socket.
pub fn create_router(state: AppState) -> Router {
    Router::new()
        // Health
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
        // Scan lifecycle
        .route("/api/scan", post(routes::start_scan))
        .route("/api/scan/{id}/status", get(routes::scan_status))
        .route("/api/scan/{id}", delete(routes::cancel_scan))
        .route("/api/scans", get(routes::list_scans))
        // WebSocket event bridge
        .route("/ws/events", get(ws::ws_events))
        // Permissive CORS for local development
        .layer(CorsLayer::permissive())
        .with_state(state)
        // SPA fallback: all unmatched paths serve the embedded frontend
        .fallback(static_files::serve_static)
}

/// Bind a TCP listener and run the SIGINT web server.
///
/// This function runs until the process is killed or an unrecoverable error
/// occurs. The event bus is subscribed to by WebSocket clients on demand.
pub async fn serve(
    db: Database,
    event_bus: EventBus,
    config: Arc<Config>,
    approval_registry: Arc<ApprovalRegistry>,
    addr: std::net::SocketAddr,
) -> Result<(), sigint_core::Error> {
    let scan_service = Arc::new(ScanService::new(
        config.clone(),
        event_bus.clone(),
        approval_registry.clone(),
    ));
    let state = AppState {
        db: Arc::new(db),
        event_bus,
        config,
        approval_registry,
        scan_service,
    };
    let app = create_router(state);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| sigint_core::Error::Other(format!("Cannot bind to {}: {}", addr, e)))?;
    tracing::info!("SIGINT web server listening on {}", addr);
    axum::serve(listener, app)
        .await
        .map_err(|e| sigint_core::Error::Other(format!("Web server error: {}", e)))?;
    Ok(())
}
