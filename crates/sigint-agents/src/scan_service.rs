//! ScanService — lifecycle management for concurrent scan pipelines.
//!
//! Wraps Orchestrator creation, spawn, and tracking. Both CLI and web
//! handlers use this to start scans and monitor their progress.
//!
//! @decision DEC-AGENT-012
//! @title ScanService owns scan lifecycle; callers get session_id back immediately
//! @status accepted
//! @rationale Centralising Orchestrator creation in one place eliminates
//! duplication between CLI and web handlers. The spawned task updates
//! ScanHandle status on completion/failure, and the EventBus provides
//! real-time progress to all subscribers. AbortHandle (not JoinHandle) is
//! stored so ScanHandle itself need not be Send + Sync — we grab the abort
//! handle before inserting into the map.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::Mutex;
use tokio::task::AbortHandle;
use uuid::Uuid;

use sigint_core::{event::EventBus, ApprovalRegistry, Config, Error};
use sigint_llm::factory::create_provider;
use sigint_memory::MemoryService;
use sigint_store::{Database, ScanRecord};
use tracing::{info, warn};

use crate::{Orchestrator, ToolRegistry};

// ── Types ─────────────────────────────────────────────────────────────────────

/// Status of a running or completed scan.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    Running,
    Completed,
    Failed(String),
    Cancelled,
}

/// Internal tracking handle for a spawned scan task.
///
/// Stores an `AbortHandle` (not `JoinHandle`) so the struct itself does not
/// need to be `Send + Sync` — the spawned future already satisfies those
/// bounds independently.
pub struct ScanHandle {
    pub session_id: Uuid,
    pub target: String,
    pub status: ScanStatus,
    pub abort_handle: AbortHandle,
    pub started_at: DateTime<Utc>,
}

/// Summary info returned by `list()`.
#[derive(Debug, Clone, Serialize)]
pub struct ScanInfo {
    pub session_id: Uuid,
    pub target: String,
    pub status: ScanStatus,
    pub started_at: DateTime<Utc>,
}

// ── ScanService ───────────────────────────────────────────────────────────────

/// Manages concurrent scan pipelines.
///
/// Create one `ScanService` per application and share it via `Arc<ScanService>`.
/// Callers call `start()` to launch a scan and receive a session UUID back
/// immediately. Progress arrives via the EventBus; final status is queryable
/// via `status()`. Active scans can be cancelled with `cancel()`.
pub struct ScanService {
    config: Arc<Config>,
    event_bus: EventBus,
    approval_registry: Arc<ApprovalRegistry>,
    scans: Arc<Mutex<HashMap<Uuid, ScanHandle>>>,
}

impl ScanService {
    /// Create a new `ScanService`.
    pub fn new(
        config: Arc<Config>,
        event_bus: EventBus,
        approval_registry: Arc<ApprovalRegistry>,
    ) -> Self {
        Self {
            config,
            event_bus,
            approval_registry,
            scans: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    // ── start() ───────────────────────────────────────────────────────────────

    /// Start a new scan against `target`.
    ///
    /// Creates a DB session, builds the Orchestrator pipeline, and spawns the
    /// scan as a background tokio task. Returns the session UUID immediately —
    /// callers monitor progress via EventBus or `status()`.
    ///
    /// # Errors
    /// Returns `Error` if session creation or LLM provider construction fails.
    /// Tool or agent failures inside the spawned task do not propagate — they
    /// update the `ScanHandle` status to `Failed`.
    pub async fn start(
        &self,
        db: &Arc<Database>,
        target: &str,
        model: Option<String>,
    ) -> Result<Uuid, Error> {
        let model = model.unwrap_or_else(|| self.config.llm.model.clone());
        let context_window = if self.config.llm.context_window > 0 {
            self.config.llm.context_window
        } else {
            8192
        };

        // Create a session record so the scan is visible in the DB immediately.
        let session = sigint_core::types::Session::new(format!(
            "scan-{}-{}",
            target.replace(['.', '/', ':'], "-"),
            chrono::Utc::now().format("%Y%m%d-%H%M%S")
        ))
        .with_target(target);
        db.create_session(&session)
            .map_err(|e| Error::Other(format!("Failed to create session: {}", e)))?;

        let session_id = session.id;

        // Build the LLM provider from config.
        let provider = create_provider(&self.config.llm)?;
        let provider = Arc::from(provider);

        // Populate tool registry with all executor tools.
        let mut registry = ToolRegistry::new();
        for tool in sigint_tools::all_executor_tools_with_config(&self.config.tools) {
            registry.register(tool);
        }

        // Optional memory service (best-effort: skip on DB open failure).
        let memory_service = {
            let db_path = self.config.resolved_db_path();
            Database::open(&db_path)
                .ok()
                .map(|mem_db| MemoryService::new_without_embeddings(mem_db, context_window / 5))
        };

        let mut orchestrator = Orchestrator::new(
            provider,
            registry,
            self.event_bus.clone(),
            context_window,
            model,
        )
        .with_max_iterations(10)
        .with_approval_registry(self.approval_registry.clone())
        // Web-initiated scans auto-approve only Low-risk (info-gathering) tools.
        // Medium and High risk tools require explicit operator approval via WebSocket.
        .with_auto_approve("low");

        if let Some(memory) = memory_service {
            orchestrator = orchestrator.with_memory(memory);
        }

        // Emit a start event so WebSocket clients see activity immediately.
        self.event_bus
            .emit(sigint_core::event::Event::Status(format!(
                "Scan started for target: {}",
                target
            )));

        // Clone everything the spawned task needs to own.
        let scans = self.scans.clone();
        let event_bus = self.event_bus.clone();
        let target_owned = target.to_string();
        let db_clone = db.clone();
        let config = self.config.clone();

        let join_handle = tokio::spawn(async move {
            let result = orchestrator.run_scan(&target_owned).await;

            match result {
                Ok(report) => {
                    info!(session_id = %session_id, "scan completed successfully");
                    event_bus.emit(sigint_core::event::Event::Status(format!(
                        "Scan completed for {}",
                        target_owned
                    )));

                    // Persist a summary record (best-effort).
                    let record = ScanRecord::new(
                        session_id,
                        "pipeline",
                        serde_json::json!({"target": target_owned}).to_string(),
                    );
                    if let Err(e) = db_clone.create_scan_record(&record) {
                        warn!("Failed to persist scan record: {}", e);
                    }

                    // Store episodic memory for future scans of same target (best-effort).
                    let db_path = config.resolved_db_path();
                    if let Ok(mem_db) = Database::open(&db_path) {
                        let svc = MemoryService::new_without_embeddings(mem_db, 1600);
                        if let Err(e) = svc.store_episode(session_id, &report.summary) {
                            warn!("Failed to store episode: {}", e);
                        }
                    }

                    let mut scans = scans.lock().await;
                    if let Some(handle) = scans.get_mut(&session_id) {
                        handle.status = ScanStatus::Completed;
                    }
                }
                Err(e) => {
                    let msg = e.to_string();
                    warn!(session_id = %session_id, error = %msg, "scan failed");
                    event_bus.emit(sigint_core::event::Event::Status(format!(
                        "Scan failed for {}: {}",
                        target_owned, msg
                    )));
                    let mut scans = scans.lock().await;
                    if let Some(handle) = scans.get_mut(&session_id) {
                        handle.status = ScanStatus::Failed(msg);
                    }
                }
            }
        });

        // Grab the abort handle before moving join_handle; insert the tracking entry.
        let abort_handle = join_handle.abort_handle();
        let handle = ScanHandle {
            session_id,
            target: target.to_string(),
            status: ScanStatus::Running,
            abort_handle,
            started_at: Utc::now(),
        };
        self.scans.lock().await.insert(session_id, handle);

        Ok(session_id)
    }

    // ── status() ──────────────────────────────────────────────────────────────

    /// Query the status of a scan by session_id.
    ///
    /// Returns `None` if no scan with that ID is tracked (unknown or expired).
    pub async fn status(&self, session_id: Uuid) -> Option<ScanStatus> {
        self.scans
            .lock()
            .await
            .get(&session_id)
            .map(|h| h.status.clone())
    }

    // ── cancel() ──────────────────────────────────────────────────────────────

    /// Cancel a running scan.
    ///
    /// Aborts the spawned tokio task and marks the handle `Cancelled`.
    /// Returns `true` if the scan was found in `Running` state and aborted,
    /// `false` if the scan is unknown or already completed/cancelled.
    pub async fn cancel(&self, session_id: Uuid) -> bool {
        let mut scans = self.scans.lock().await;
        if let Some(handle) = scans.get_mut(&session_id) {
            if matches!(handle.status, ScanStatus::Running) {
                handle.abort_handle.abort();
                handle.status = ScanStatus::Cancelled;
                return true;
            }
        }
        false
    }

    // ── list() ────────────────────────────────────────────────────────────────

    /// List all tracked scans (active and completed).
    ///
    /// Returns a snapshot of `ScanInfo` for every scan registered since this
    /// `ScanService` was created. Completed and cancelled scans remain in the
    /// map until the service is dropped.
    pub async fn list(&self) -> Vec<ScanInfo> {
        self.scans
            .lock()
            .await
            .values()
            .map(|h| ScanInfo {
                session_id: h.session_id,
                target: h.target.clone(),
                status: h.status.clone(),
                started_at: h.started_at,
            })
            .collect()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn test_service() -> ScanService {
        let config = Arc::new(Config::default());
        let event_bus = EventBus::new();
        let approval = Arc::new(ApprovalRegistry::new(Duration::from_secs(60)));
        ScanService::new(config, event_bus, approval)
    }

    #[tokio::test]
    async fn status_unknown_session_returns_none() {
        let svc = test_service();
        assert!(svc.status(Uuid::new_v4()).await.is_none());
    }

    #[tokio::test]
    async fn cancel_unknown_session_returns_false() {
        let svc = test_service();
        assert!(!svc.cancel(Uuid::new_v4()).await);
    }

    #[tokio::test]
    async fn list_empty_returns_empty_vec() {
        let svc = test_service();
        assert!(svc.list().await.is_empty());
    }

    #[tokio::test]
    async fn scan_status_running_serializes() {
        let status = ScanStatus::Running;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, r#""running""#);
    }

    #[tokio::test]
    async fn scan_status_completed_serializes() {
        let status = ScanStatus::Completed;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, r#""completed""#);
    }

    #[tokio::test]
    async fn scan_status_cancelled_serializes() {
        let status = ScanStatus::Cancelled;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, r#""cancelled""#);
    }

    #[tokio::test]
    async fn scan_status_failed_serializes() {
        let status = ScanStatus::Failed("timeout".into());
        let json = serde_json::to_string(&status).unwrap();
        // serde rename_all = "lowercase" applies to the variant name "failed";
        // the inner String is preserved as the nested value.
        assert!(json.contains("failed"), "expected 'failed' in: {}", json);
        assert!(json.contains("timeout"), "expected 'timeout' in: {}", json);
    }
}
