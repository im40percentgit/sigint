//! E2E test helpers — shared server bootstrap and HTTP client utilities.
//!
//! This crate provides utilities for spinning up a real Axum server on a
//! random port for integration tests. Each test gets its own isolated server
//! instance backed by an in-memory SQLite database.
//!
//! @decision DEC-E2E-001
//! @title E2E tests use real Axum server on random port with in-memory SQLite
//! @status accepted
//! @rationale Testing against a real running server catches integration issues
//! (routing, middleware, serialization) that unit tests miss. In-memory SQLite
//! provides test isolation without filesystem cleanup. Random port assignment
//! via TcpListener::bind("127.0.0.1:0") eliminates port conflicts when tests
//! run in parallel. This mirrors the production code path exactly — same
//! router, same state construction, same middleware stack.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use sigint_agents::ScanService;
use sigint_core::{ApprovalRegistry, Config, event::EventBus};
use sigint_store::Database;
use sigint_web::AppState;

/// Start a real Axum server on a random port. Returns the bound address.
///
/// Creates a fresh in-memory SQLite database for test isolation. The server
/// runs in a background tokio task and is dropped when the test completes.
pub async fn start_server() -> SocketAddr {
    let db = Database::open_in_memory().expect("in-memory db");
    let event_bus = EventBus::new();
    let config = Arc::new(Config::default());
    let approval_registry = Arc::new(ApprovalRegistry::new(Duration::from_secs(30)));
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

    let app = sigint_web::create_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind to random port");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    addr
}

/// Build a base URL from a socket address.
pub fn base_url(addr: SocketAddr) -> String {
    format!("http://{}", addr)
}
