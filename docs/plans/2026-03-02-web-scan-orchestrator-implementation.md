# Web Scan Orchestrator Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Wire the full Orchestrator pipeline into `POST /api/scan` via a reusable `ScanService` with start/status/cancel/list lifecycle management.

**Architecture:** `ScanService` in `sigint-agents` wraps Orchestrator creation and spawn. Web handler delegates to ScanService. Active scans tracked in `HashMap<Uuid, ScanHandle>` with abort support. Events stream to WebSocket clients via the existing EventBus.

**Tech Stack:** Rust, tokio::spawn, tokio::task::AbortHandle, sigint-agents Orchestrator, sigint-llm factory, sigint-tools all_executor_tools()

---

### Task 1: Add ScanStatus and ScanHandle types

**Files:**
- Create: `crates/sigint-agents/src/scan_service.rs`
- Modify: `crates/sigint-agents/src/lib.rs`

**Step 1: Create scan_service.rs with types and stubs**

```rust
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
//! real-time progress to all subscribers.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::Mutex;
use tokio::task::AbortHandle;
use uuid::Uuid;

use sigint_core::{ApprovalRegistry, Config, Error, event::EventBus};
use sigint_store::Database;

/// Status of a running or completed scan.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    Running,
    Completed,
    Failed(String),
    Cancelled,
}

/// Tracking handle for a spawned scan task.
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

/// Manages concurrent scan pipelines.
pub struct ScanService {
    config: Arc<Config>,
    event_bus: EventBus,
    approval_registry: Arc<ApprovalRegistry>,
    scans: Arc<Mutex<HashMap<Uuid, ScanHandle>>>,
}

impl ScanService {
    /// Create a new ScanService.
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
}
```

**Step 2: Register module in lib.rs**

Add to `crates/sigint-agents/src/lib.rs` after the existing modules:

```rust
pub mod scan_service;
```

And add a re-export:

```rust
pub use scan_service::ScanService;
```

**Step 3: Verify it compiles**

Run: `cargo check -p sigint-agents`
Expected: OK (types only, no logic yet)

**Step 4: Commit**

```bash
git add crates/sigint-agents/src/scan_service.rs crates/sigint-agents/src/lib.rs
git commit -m "feat(agents): add ScanService types — ScanStatus, ScanHandle, ScanInfo"
```

---

### Task 2: Implement ScanService::start()

**Files:**
- Modify: `crates/sigint-agents/src/scan_service.rs`
- Modify: `crates/sigint-agents/Cargo.toml` (add `chrono` dep if not present)

**Step 1: Add start() method**

Add these imports at the top of `scan_service.rs`:

```rust
use sigint_llm::factory::create_provider;
use sigint_memory::MemoryService;
use tracing::{info, warn};

use crate::{Orchestrator, ToolRegistry};
```

Then add to the `impl ScanService` block:

```rust
    /// Start a new scan against `target`.
    ///
    /// Creates a DB session, builds the Orchestrator pipeline, and spawns
    /// the scan as a background tokio task. Returns the session UUID
    /// immediately — callers monitor progress via EventBus or `status()`.
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

        // Create session in DB.
        let session = sigint_core::types::Session::new(
            &format!("scan-{}-{}", target.replace(['.', '/'], "-"),
                chrono::Utc::now().format("%Y%m%d-%H%M%S"))
        ).with_target(target);
        db.create_session(&session).map_err(|e| {
            Error::Other(format!("Failed to create session: {}", e))
        })?;

        let session_id = session.id;

        // Build pipeline components.
        let provider = create_provider(&self.config.llm)?;
        let provider = Arc::from(provider);

        let mut registry = ToolRegistry::new();
        for tool in sigint_tools::all_executor_tools() {
            registry.register(tool);
        }

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
        ).with_max_iterations(10);

        if let Some(memory) = memory_service {
            orchestrator = orchestrator.with_memory(memory);
        }

        // Emit start event.
        self.event_bus.emit(sigint_core::event::Event::Status(
            format!("Scan started for target: {}", target)
        ));

        // Spawn the scan task.
        let scans = self.scans.clone();
        let event_bus = self.event_bus.clone();
        let target_owned = target.to_string();
        let db_clone = db.clone();
        let config = self.config.clone();

        let join_handle = tokio::spawn(async move {
            let result = orchestrator.run_scan(&target_owned).await;

            match &result {
                Ok(report) => {
                    info!(session_id = %session_id, "scan completed successfully");
                    event_bus.emit(sigint_core::event::Event::Status(
                        format!("Scan completed for {}", target_owned)
                    ));

                    // Persist report summary (best-effort).
                    let record = sigint_store::ScanRecord::new(
                        session_id, "pipeline",
                        serde_json::json!({"target": target_owned}).to_string(),
                    );
                    if let Err(e) = db_clone.create_scan_record(&record) {
                        warn!("Failed to persist scan record: {}", e);
                    }

                    // Store episodic memory (best-effort).
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
                    event_bus.emit(sigint_core::event::Event::Status(
                        format!("Scan failed for {}: {}", target_owned, msg)
                    ));
                    let mut scans = scans.lock().await;
                    if let Some(handle) = scans.get_mut(&session_id) {
                        handle.status = ScanStatus::Failed(msg);
                    }
                }
            }
        });

        // Track the scan.
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
```

**Step 2: Verify it compiles**

Run: `cargo check -p sigint-agents`
Expected: OK

**Step 3: Commit**

```bash
git add crates/sigint-agents/src/scan_service.rs crates/sigint-agents/Cargo.toml
git commit -m "feat(agents): implement ScanService::start() with Orchestrator spawn"
```

---

### Task 3: Implement status(), cancel(), list()

**Files:**
- Modify: `crates/sigint-agents/src/scan_service.rs`

**Step 1: Add remaining methods to impl ScanService**

```rust
    /// Query the status of a scan by session_id.
    pub async fn status(&self, session_id: Uuid) -> Option<ScanStatus> {
        self.scans.lock().await.get(&session_id).map(|h| h.status.clone())
    }

    /// Cancel a running scan. Returns true if the scan was found and aborted.
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

    /// List all tracked scans (active and completed).
    pub async fn list(&self) -> Vec<ScanInfo> {
        self.scans.lock().await.values().map(|h| ScanInfo {
            session_id: h.session_id,
            target: h.target.clone(),
            status: h.status.clone(),
            started_at: h.started_at,
        }).collect()
    }
```

**Step 2: Add tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn test_config() -> Arc<Config> {
        Arc::new(Config::default())
    }

    fn test_service() -> ScanService {
        let config = test_config();
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
    async fn scan_status_serializes() {
        let status = ScanStatus::Failed("timeout".into());
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("failed"));
    }
}
```

**Step 3: Run tests**

Run: `cargo test -p sigint-agents`
Expected: All pass

**Step 4: Commit**

```bash
git add crates/sigint-agents/src/scan_service.rs
git commit -m "feat(agents): add ScanService status/cancel/list + tests"
```

---

### Task 4: Add ScanService to web AppState

**Files:**
- Modify: `crates/sigint-web/src/state.rs`
- Modify: `crates/sigint-web/src/lib.rs`
- Modify: `crates/sigint-web/Cargo.toml`

**Step 1: Add sigint-agents dep to sigint-web/Cargo.toml**

Add under `[dependencies]`:
```toml
sigint-agents = { workspace = true }
```

**Step 2: Expand AppState**

In `crates/sigint-web/src/state.rs`, add:
```rust
use sigint_agents::ScanService;
```

Add to `AppState`:
```rust
pub struct AppState {
    pub db: Arc<Database>,
    pub event_bus: EventBus,
    pub config: Arc<Config>,
    pub approval_registry: Arc<ApprovalRegistry>,
    pub scan_service: Arc<ScanService>,
}
```

**Step 3: Update serve() in lib.rs**

In `crates/sigint-web/src/lib.rs`, update `serve()` to construct and inject `ScanService`:

```rust
use sigint_agents::ScanService;
```

In the `serve` function body, before creating `AppState`:
```rust
let scan_service = Arc::new(ScanService::new(
    config.clone(),
    event_bus.clone(),
    approval_registry.clone(),
));
```

And add it to the AppState constructor.

**Step 4: Update all test_state() helpers**

In `crates/sigint-web/src/routes.rs` tests, update `test_state()`:
```rust
use sigint_agents::ScanService;
```

```rust
fn test_state() -> AppState {
    let db = Database::open_in_memory().expect("in-memory db");
    let event_bus = EventBus::new();
    let config = Arc::new(Config::default());
    let approval_registry = Arc::new(ApprovalRegistry::new(Duration::from_secs(300)));
    let scan_service = Arc::new(ScanService::new(
        config.clone(), event_bus.clone(), approval_registry.clone(),
    ));
    AppState { db: Arc::new(db), event_bus, config, approval_registry, scan_service }
}
```

Do the same for any other `test_state()` in `static_files.rs` if it exists.

**Step 5: Verify**

Run: `cargo test -p sigint-web`
Expected: All existing tests pass

**Step 6: Commit**

```bash
git add crates/sigint-web/
git commit -m "feat(web): add ScanService to AppState"
```

---

### Task 5: Wire start_scan handler to ScanService

**Files:**
- Modify: `crates/sigint-web/src/routes.rs`

**Step 1: Update start_scan to use ScanService**

Replace the existing `start_scan` handler body with:

```rust
pub async fn start_scan(
    State(state): State<AppState>,
    Json(body): Json<ScanRequest>,
) -> ApiResult<impl IntoResponse> {
    if body.target.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "target is required".into()));
    }

    let session_id = state.scan_service
        .start(&state.db, &body.target, body.model.clone())
        .await
        .map_err(internal)?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "session_id": session_id })),
    ))
}
```

**Step 2: Verify**

Run: `cargo test -p sigint-web`
Expected: `start_scan_returns_201_with_session_id` still passes (ScanService::start will fail internally because Ollama isn't running, but the test only checks the HTTP response shape — need to verify this. If it fails because start() returns Error, adjust the test or make start() handle provider errors gracefully.)

Note: The test may need adjustment. If `create_provider` fails with the default config (provider="ollama" and no running Ollama), the handler will return 500. In that case, either:
- Make the test set up a config that doesn't fail, OR
- Accept that the existing test needs to change from checking 201 to checking that the handler runs without panicking

The simplest fix: the test sends a request and verifies the response code. Since create_provider("ollama") succeeds (it just creates the struct, doesn't connect), the test should still pass — the scan will be spawned and fail async later.

**Step 3: Commit**

```bash
git add crates/sigint-web/src/routes.rs
git commit -m "feat(web): wire start_scan handler to ScanService::start()"
```

---

### Task 6: Add status, cancel, and list scan endpoints

**Files:**
- Modify: `crates/sigint-web/src/routes.rs`
- Modify: `crates/sigint-web/src/lib.rs`

**Step 1: Add handlers in routes.rs**

```rust
/// `GET /api/scan/{id}/status` — query scan status.
pub async fn scan_status(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let uuid = parse_uuid(&id)?;
    match state.scan_service.status(uuid).await {
        Some(status) => Ok(Json(serde_json::json!({ "session_id": uuid, "status": status }))),
        None => Err(not_found(format!("scan '{}' not found", id))),
    }
}

/// `DELETE /api/scan/{id}` — cancel a running scan.
pub async fn cancel_scan(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let uuid = parse_uuid(&id)?;
    if state.scan_service.cancel(uuid).await {
        Ok(Json(serde_json::json!({ "cancelled": true })))
    } else {
        Err(not_found(format!("scan '{}' not found or not running", id)))
    }
}

/// `GET /api/scans` — list all tracked scans.
pub async fn list_scans(
    State(state): State<AppState>,
) -> impl IntoResponse {
    let scans = state.scan_service.list().await;
    Json(scans)
}
```

**Step 2: Register routes in lib.rs**

Add to `create_router`:
```rust
.route("/api/scan/{id}/status", get(routes::scan_status))
.route("/api/scan/{id}", axum::routing::delete(routes::cancel_scan))
.route("/api/scans", get(routes::list_scans))
```

**Step 3: Add tests**

```rust
#[tokio::test]
async fn scan_status_unknown_returns_404() {
    let app = create_router(test_state());
    let req = Request::builder()
        .uri("/api/scan/00000000-0000-0000-0000-000000000000/status")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn cancel_unknown_scan_returns_404() {
    let app = create_router(test_state());
    let req = Request::builder()
        .method("DELETE")
        .uri("/api/scan/00000000-0000-0000-0000-000000000000")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn list_scans_returns_array() {
    let app = create_router(test_state());
    let req = Request::builder()
        .uri("/api/scans")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp.into_body()).await;
    let v: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(v.is_array());
}
```

**Step 4: Run tests**

Run: `cargo test -p sigint-web`
Expected: All pass

**Step 5: Commit**

```bash
git add crates/sigint-web/
git commit -m "feat(web): add scan status/cancel/list endpoints"
```

---

### Task 7: Update MASTER_PLAN.md + full workspace test

**Files:**
- Modify: `MASTER_PLAN.md`

**Step 1: Run full workspace tests**

Run: `cargo test --workspace`
Expected: All pass (except pre-existing sigint-sandbox failures)

**Step 2: Update MASTER_PLAN.md**

Update "Current Phase" and "Active Work" to reflect Phase 6 completion and this web scan feature.

**Step 3: Commit**

```bash
git add MASTER_PLAN.md
git commit -m "docs: update MASTER_PLAN.md with Phase 6 completion and web scan orchestrator"
```

---

## Implementation Order

```
Task 1 (types) → Task 2 (start) → Task 3 (status/cancel/list) → Task 4 (AppState) → Task 5 (wire handler) → Task 6 (new endpoints) → Task 7 (MASTER_PLAN)
```

Each task builds on the previous. Tasks 1-3 are pure `sigint-agents`. Tasks 4-6 are `sigint-web`. Task 7 is docs.
