//! Shared Axum application state injected into every route handler.
//!
//! `AppState` is cheap to clone — the `Database` is behind an `Arc`,
//! `EventBus` is a thin wrapper around a `broadcast::Sender` (also cheap
//! to clone), and `Config` / `ApprovalRegistry` are behind `Arc` so the
//! underlying data is shared rather than copied.
//!
//! @decision DEC-WEB-003
//! @title AppState carries config and approval_registry for web-initiated scans
//! @status accepted
//! @rationale The web layer needs to read config (e.g. default model, timeouts)
//! when constructing scan sessions, and must be able to route approve/deny
//! WebSocket messages to the agent loop via ApprovalRegistry. Carrying both
//! in AppState keeps the dependency injection explicit and avoids global state.

use sigint_core::{ApprovalRegistry, Config, event::EventBus};
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
}
