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
use tokio::sync::Semaphore;

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
    /// Resolved Bearer API key for this server instance.
    ///
    /// Set once at startup by [`crate::auth::resolve_api_key`] and used by
    /// [`crate::auth::auth_middleware`] on every authenticated request.
    pub api_key: String,

    /// Concurrency gate for fine-tuning jobs.
    ///
    /// `POST /api/train/finetune` calls `try_acquire_owned()` before spawning.
    /// Returns `429` when the cap (`config.web.train.max_concurrent_jobs`)
    /// is reached. The owned permit is moved into the spawned task and dropped
    /// when the task completes, releasing the slot automatically via RAII.
    ///
    /// Initialized with `max_concurrent_jobs` permits. When `max_concurrent_jobs`
    /// is 0 the semaphore is created with `usize::MAX` permits, disabling the cap.
    ///
    /// @decision DEC-P26-008
    /// @title Fine-tune job concurrency capped via tokio Semaphore (matches DEC-WEB-RATELIMIT-002 scan pattern)
    /// @status accepted
    /// @rationale The handler returns 202 Accepted immediately; the actual
    /// training command runs in a spawned tokio task. A semaphore with
    /// try_acquire_owned() (non-blocking) is the same atomic pattern used by
    /// the scan rate-limiter (DEC-WEB-RATELIMIT-002). Owned permits are held
    /// by the spawned task across await points; RAII drop ensures the permit
    /// is released on completion or panic. Default cap = 1 (single-operator
    /// GPU avoids contention). Addresses: REQ-P26-NOGO-004.
    pub training_job_semaphore: Arc<Semaphore>,
}
