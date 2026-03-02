//! Shared Axum application state injected into every route handler.
//!
//! `AppState` is cheap to clone — the `Database` is behind an `Arc`,
//! `EventBus` is a thin wrapper around a `broadcast::Sender` (also cheap
//! to clone), and `Config` / `ApprovalRegistry` / `ScanService` are behind
//! `Arc` so the underlying data is shared rather than copied.
//!
//! @decision DEC-WEB-003
//! @title AppState carries config, approval_registry, and scan_service for web-initiated scans
//! @status accepted
//! @rationale The web layer needs to read config (e.g. default model, timeouts)
//! when constructing scan sessions, and must be able to route approve/deny
//! WebSocket messages to the agent loop via ApprovalRegistry. ScanService is
//! the single point of truth for scan lifecycle — all handlers delegate to it
//! rather than spawning tasks directly. Carrying all three in AppState keeps
//! the dependency injection explicit and avoids global state.

use sigint_agents::ScanService;
use sigint_core::{event::EventBus, ApprovalRegistry, Config};
use sigint_store::Database;
use std::sync::Arc;

/// Axum application state shared across all request handlers.
///
/// `Clone` is required by Axum so the state can be extracted into handlers
/// via `axum::extract::State<AppState>`.
#[derive(Clone)]
pub struct AppState {
    /// Thread-safe handle to the SQLite connection pool.
    pub db: Arc<Database>,
    /// Broadcast event bus — call `.subscribe()` to receive future events.
    pub event_bus: EventBus,
    /// Runtime configuration (LLM provider, approval timeouts, etc.).
    pub config: Arc<Config>,
    /// Registry of pending tool-approval requests from the agent loop.
    pub approval_registry: Arc<ApprovalRegistry>,
    /// Manages concurrent scan pipelines (start, status, cancel, list).
    pub scan_service: Arc<ScanService>,
}
