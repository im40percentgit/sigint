//! Shared Axum application state injected into every route handler.
//!
//! `AppState` is cheap to clone — the `Database` is behind an `Arc` and
//! `EventBus` is already a thin wrapper around a `broadcast::Sender` (also
//! cheap to clone).

use sigint_core::event::EventBus;
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
}
