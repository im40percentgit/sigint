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
    Router,
    routing::get,
};
use tower_http::cors::CorsLayer;

use sigint_core::event::EventBus;
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
    addr: std::net::SocketAddr,
) -> Result<(), sigint_core::Error> {
    let state = AppState {
        db: Arc::new(db),
        event_bus,
    };
    let app = create_router(state);
    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| {
        sigint_core::Error::Other(format!("Cannot bind to {}: {}", addr, e))
    })?;
    tracing::info!("SIGINT web server listening on {}", addr);
    axum::serve(listener, app).await.map_err(|e| {
        sigint_core::Error::Other(format!("Web server error: {}", e))
    })?;
    Ok(())
}
