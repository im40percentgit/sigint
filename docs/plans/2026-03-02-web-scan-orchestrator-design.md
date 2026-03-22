# Web Scan Orchestrator — Design Document

**Date:** 2026-03-02
**Status:** approved
**Approach:** ScanService abstraction in sigint-agents

## Context

Phase 6 added `POST /api/scan` but it only creates a session — the Orchestrator pipeline is not spawned. The CLI's `scan::run` already wires together LLM provider, ToolRegistry, and Orchestrator. This design extracts that wiring into a reusable `ScanService` that both web and CLI can use, with scan lifecycle management (start, status, cancel, list).

## Design Decisions

- **ScanService location:** `sigint-agents` (owns Orchestrator already)
- **Concurrency:** Multiple scans can run simultaneously, each as a `tokio::spawn` task
- **Lifecycle tracking:** `HashMap<Uuid, ScanHandle>` with status, abort handle, timestamps
- **Provider creation:** Uses `sigint_llm::factory::create_provider(&config.llm)` (supports Ollama + OpenAI)
- **Error handling:** LLM errors caught in spawned task, status updated to Failed, error event emitted

## ScanService

New file: `sigint-agents/src/scan_service.rs`

```rust
pub struct ScanService {
    config: Arc<Config>,
    event_bus: EventBus,
    approval_registry: Arc<ApprovalRegistry>,
    active_scans: Arc<Mutex<HashMap<Uuid, ScanHandle>>>,
}

pub struct ScanHandle {
    pub session_id: Uuid,
    pub target: String,
    pub status: ScanStatus,
    pub abort_handle: AbortHandle,
    pub started_at: DateTime<Utc>,
}

#[derive(Clone, Serialize)]
pub enum ScanStatus {
    Running,
    Completed,
    Failed(String),
    Cancelled,
}
```

**Methods:**
- `new(config, event_bus, approval_registry)` — constructor
- `start(db, target, model) -> Result<Uuid>` — create session, build pipeline, spawn task
- `status(session_id) -> Option<ScanStatus>` — query
- `cancel(session_id) -> bool` — abort via JoinHandle
- `list() -> Vec<ScanInfo>` — all tracked scans

The `start` method:
1. Creates `Session` in DB
2. Calls `factory::create_provider(&config.llm)` for LLM
3. Builds `ToolRegistry` via `sigint_tools::all_executor_tools()`
4. Creates `Orchestrator` with event_bus, approval_registry, memory
5. `tokio::spawn`s `orchestrator.run_scan(target)`
6. Stores `ScanHandle` with abort handle
7. Returns session_id

Spawned task on completion:
- Updates status to `Completed` or `Failed(msg)`
- Persists scan results to DB (best-effort)
- Stores episodic memory summary

## Web Integration

**AppState expansion:**
```rust
pub struct AppState {
    pub db: Arc<Database>,
    pub event_bus: EventBus,
    pub config: Arc<Config>,
    pub approval_registry: Arc<ApprovalRegistry>,
    pub scan_service: Arc<ScanService>,
}
```

**New endpoints:**

| Method | Path | Returns |
|--------|------|---------|
| POST | `/api/scan` | `201 { session_id }` |
| GET | `/api/scan/{id}/status` | `200 { status, target, started_at }` |
| DELETE | `/api/scan/{id}` | `200` or `404` |
| GET | `/api/scans` | `200 [{ session_id, target, status, started_at }]` |

**New deps for sigint-web:** `sigint-agents`, `sigint-llm`, `sigint-tools`, `sigint-memory`

## Testing

- ScanService lifecycle: start → status Running → cancel → status Cancelled
- ScanService with unknown session returns None
- HTTP endpoints: 201 for POST, 200 for status, 404 for unknown
- Integration (#[ignore]): full pipeline against scanme.nmap.org
