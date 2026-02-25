# Phase 3 Design: TUI + Memory + Embeddings

**Date:** 2026-02-25
**Status:** Approved
**Phase:** 3 of 5
**Depends on:** Phase 2 (Agent System + Sandboxing) — completed

---

## Decisions

| ID | Decision | Rationale |
|----|----------|-----------|
| DEC-P3-001 | New `sigint-memory` crate for memory system | Clean boundary: store owns persistence + embeddings, memory owns retrieval strategy + prompt injection |
| DEC-P3-002 | fastembed always-on (no feature gate) | Pentest tool audience has beefy machines; 20MB extra is irrelevant; feature-gating adds conditional compilation complexity. Gate later if needed. |
| DEC-P3-003 | TUI auto-detect via `isatty`, `--tui`/`--no-tui` overrides | Follows cargo/git convention; respects both interactive and scripted use cases |
| DEC-P3-004 | Episodic summaries from Reporter output (no dedicated summarizer) | Reporter already summarizes; zero new code. Add compression step later if context quality suffers. |
| DEC-P3-005 | Fork-join execution: 3B parallel 3D after 3A, 3C joins both | Exploits natural dependency graph parallelism; 3B and 3D touch completely different crates |

## Execution Strategy

Fork-join: Store DAL first, then Embeddings and TUI in parallel, then Memory joins both.

```
3A (Store DAL + Pool)
    |-- 3B (FTS5 + Embeddings)   <- parallel worktree
    \-- 3D (Ratatui TUI)         <- parallel worktree
         \-- merge both --> 3C (Memory) --> 3E (Integration + Polish)
```

---

## Sub-Phase 3A: Store DAL + Connection Pool

**Crate:** `sigint-store`
**Branch:** `feature/phase-3a-store-dal`

### Connection Pool

Replace `Mutex<Connection>` with `r2d2::Pool<SqliteConnectionManager>`:

```rust
pub struct Database {
    pool: r2d2::Pool<SqliteConnectionManager>,
}

impl Database {
    pub fn with_conn<F, T>(&self, f: F) -> Result<T>        // read path
    pub fn with_write_conn<F, T>(&self, f: F) -> Result<T>  // write path (same pool, WAL handles concurrency)
}
```

Existing `with_conn` callers keep working — the API change is internal. Pool size: 4 connections (configurable). WAL mode already enabled.

### Typed Query Builders

Replace raw SQL strings with composable builders. Not an ORM — just ergonomic wrappers over rusqlite:

```rust
// Before (current):
store.with_conn(|conn| {
    conn.query_row("SELECT * FROM findings WHERE session_id = ?1 AND severity = ?2", ...)
})

// After:
store.findings()
    .by_session(session_id)
    .severity(Severity::High)
    .limit(20)
    .offset(40)
    .list()
```

One builder per table: `FindingQuery`, `MessageQuery`, `ScanQuery`, `SessionQuery`, `AssetQuery`. Each supports:
- Filtering (by session, by date range, by severity, by target)
- Pagination (`limit` + `offset`)
- Ordering (`order_by` + direction)
- Count (`count()` instead of `list()`)
- Batch insert for `scan_history` and `messages`

### Migration 2: FTS5 Tables

Add FTS5 virtual tables as external-content tables (no data duplication):

```sql
-- FTS5 for messages
CREATE VIRTUAL TABLE messages_fts USING fts5(content, content=messages, content_rowid=id);
-- Sync triggers
CREATE TRIGGER messages_ai AFTER INSERT ON messages BEGIN
    INSERT INTO messages_fts(rowid, content) VALUES (new.id, new.content);
END;
-- (+ UPDATE and DELETE triggers)

-- FTS5 for findings
CREATE VIRTUAL TABLE findings_fts USING fts5(title, description, content=findings, content_rowid=id);

-- FTS5 for scan_history
CREATE VIRTUAL TABLE scan_history_fts USING fts5(output, content=scan_history, content_rowid=id);
```

### Search API

```rust
pub struct SearchResult {
    pub source_type: String,    // "message", "finding", "scan"
    pub source_id: i64,
    pub snippet: String,        // FTS5 snippet() with highlights
    pub rank: f64,              // BM25 rank
}

impl Database {
    pub fn search(&self, query: &str) -> Result<Vec<SearchResult>>
    pub fn search_messages(&self, query: &str) -> Result<Vec<SearchResult>>
    pub fn search_findings(&self, query: &str) -> Result<Vec<SearchResult>>
}
```

### Tests
- Pool: 4 concurrent reads + 1 write don't deadlock
- Query builders: filter, paginate, count for each table
- FTS5: insert -> search -> ranked results with snippets
- Migration: v1 -> v2 runs cleanly, existing data indexed
- Backward compat: all existing tests pass unchanged

---

## Sub-Phase 3B: Embeddings + Semantic Search

**Crate:** `sigint-store` (embedding storage + UDF) + workspace dep `fastembed`
**Branch:** `feature/phase-3b-embeddings` (parallel with 3D, after 3A merges)

### fastembed Integration

```rust
// sigint-store/src/embeddings.rs
pub struct EmbeddingService {
    model: TextEmbedding,  // fastembed model handle
}

impl EmbeddingService {
    pub fn new() -> Result<Self>                                    // loads all-MiniLM-L6-v2
    pub fn embed(&self, text: &str) -> Result<Vec<f32>>             // single doc -> 384-dim
    pub fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>>  // batch
}
```

Model cache dir: `~/.cache/sigint/models/` (configurable via `StoreConfig`).

### Embedding CRUD

```rust
impl Database {
    pub fn store_embedding(&self, source_type: &str, source_id: i64, model: &str, vector: &[f32]) -> Result<()>
    pub fn get_embedding(&self, source_type: &str, source_id: i64) -> Result<Option<Vec<f32>>>
    pub fn has_embedding(&self, source_type: &str, source_id: i64) -> Result<bool>
    pub fn unembedded(&self, source_type: &str, limit: usize) -> Result<Vec<i64>>
}
```

Vectors stored as raw `f32` byte arrays in BLOB columns (`bytemuck::cast_slice`).

### Cosine Similarity UDF

Registered on each connection via `create_scalar_function` during pool initialization:

```rust
fn register_cosine_similarity(conn: &Connection) {
    conn.create_scalar_function("cosine_similarity", 2, |ctx| {
        let a: &[u8] = ctx.get_raw(0);
        let b: &[u8] = ctx.get_raw(1);
        Ok(cosine_sim(a, b))
    });
}
```

### Semantic Search API

```rust
pub struct SemanticResult {
    pub source_type: String,
    pub source_id: i64,
    pub similarity: f64,
}

impl Database {
    pub fn semantic_search(&self, query_vector: &[f32], top_k: usize) -> Result<Vec<SemanticResult>>
    pub fn semantic_search_typed(&self, query_vector: &[f32], source_type: &str, top_k: usize) -> Result<Vec<SemanticResult>>
}
```

Brute-force scan. HNSW deferred to P2.

### Background Embedding Worker

```rust
pub async fn embedding_worker(db: Database, service: EmbeddingService, event_bus: EventBus) {
    loop {
        for source_type in ["message", "finding", "scan"] {
            let ids = db.unembedded(source_type, 32)?;
            if ids.is_empty() { continue; }
            let texts = db.get_texts_for_embedding(source_type, &ids)?;
            let vectors = tokio::task::spawn_blocking(|| service.embed_batch(&texts)).await?;
            for (id, vec) in ids.iter().zip(vectors) {
                db.store_embedding(source_type, *id, "all-MiniLM-L6-v2", &vec)?;
            }
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}
```

### Tests
- `EmbeddingService::embed` returns 384-dim vector
- `embed_batch` with 10 docs returns 10 vectors
- Store/retrieve embedding round-trip (byte-level fidelity)
- Cosine similarity: identical vectors -> 1.0, orthogonal -> 0.0
- Semantic search ranking correctness
- `unembedded()` returns only IDs without embeddings
- Background worker: insert findings -> wait -> all have embeddings

---

## Sub-Phase 3D: Ratatui TUI

**Crate:** `sigint-tui`
**Branch:** `feature/phase-3d-tui` (parallel with 3B, after 3A merges)
**New deps:** `ratatui`, `crossterm`

### Architecture

TUI runs in its own tokio task, subscribing to EventBus. Never calls agents directly — observes events and renders.

### Core Structs

```rust
pub struct TuiApp {
    state: AppState,
    event_rx: broadcast::Receiver<Event>,
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

pub struct AppState {
    active_agent: Option<(AgentRole, Instant)>,
    iteration: usize,
    messages: Vec<DisplayMessage>,
    streaming_buffer: String,
    tool_log: Vec<ToolEntry>,
    findings: Vec<Finding>,
    focused_panel: Panel,
    scroll_offsets: HashMap<Panel, usize>,
    auto_scroll: HashMap<Panel, bool>,
    input: String,
    mode: Mode,
}

pub enum Panel { Chat, ToolOutput, Findings, Input }
pub enum Mode { Normal, Search(String), Command(String) }
```

### Layout (5 panels)

```
+--------------------------------------------------+
| [Researcher] * iteration 3/10 | 12.4s elapsed   |  <- Agent Status Bar (1 row)
+--------------------------+-----------------------+
|                          |                       |
|  Chat Panel (60%)        |  Tool Output (40%)    |
|                          |                       |
|  [User] scan example.com |  > nmap_scan          |
|  [Researcher] I'll run   |    -sV example.com    |
|  an nmap service scan... |    exit: 0 (4.2s)     |
|                          |                       |
+--------------------------+-----------------------+
| SEV  | TITLE                    | ASSET          |  <- Findings (3-5 rows)
| HIGH | SSH weak cipher suite    | example.com    |
+--------------------------+-----------------------+
| > scan example.com                               |  <- Input Bar (1 row)
+--------------------------------------------------+
```

Panel proportions adapt on resize. Minimum terminal: 80x24.

### Event -> State Mapping

| Event | State Update |
|-------|-------------|
| `Status("Agent: Researcher started")` | `active_agent = Some(Researcher, now())` |
| `ToolStarted { name, args }` | Push to `tool_log`, increment `iteration` |
| `ToolOutput { name, output }` | Update last `tool_log` entry with output |
| `ToolCompleted { name, exit_code }` | Mark tool entry complete with duration |
| `TokenReceived(token)` | Append to `streaming_buffer` |
| `StreamCompleted` | Flush `streaming_buffer` into `messages` |
| `FindingCreated(finding)` | Push to `findings` |
| `MessageCreated(msg)` | Push to `messages` |
| `Shutdown` | Exit TUI cleanly, restore terminal |

### Render Loop

~30fps tick with event polling. TUI must not block the agent pipeline.

### Input Handling

| Key | Mode | Action |
|-----|------|--------|
| `q` | Normal | Quit |
| `Tab` | Normal | Cycle focused panel |
| `j/k` or arrows | Normal | Scroll focused panel |
| `G` | Normal | Jump to bottom (re-enable auto-scroll) |
| `/` | Normal | Enter Search mode |
| `:` | Normal | Enter Command mode |
| `Enter` | Input focused | Send message |
| `Esc` | Search/Command | Return to Normal |

### isatty Auto-Detection (DEC-P3-003)

```rust
if args.tui.unwrap_or_else(|| std::io::stdout().is_terminal()) {
    let tui = TuiApp::new(event_bus.subscribe(), terminal)?;
    tokio::spawn(tui.run());
} else {
    tokio::spawn(print_events(event_bus.subscribe()));
}
```

### Terminal Lifecycle

Setup: enable raw mode, enter alternate screen, install panic hook to restore terminal on crash.
Teardown: restore terminal on clean exit or panic.

### Tests
- `AppState::apply(event)` updates correct state fields
- Layout renders without panic at various sizes
- Scroll: manual scroll-up pauses auto-scroll; `G` re-enables
- Input: typing appends to buffer, Enter clears
- Mode transitions work correctly

---

## Sub-Phase 3C: Memory System

**New crate:** `sigint-memory`
**Branch:** `feature/phase-3c-memory` (after 3A + 3B merged)
**Depends on:** `sigint-store`, `sigint-core`

### Three-Layer Architecture

1. **Working Memory:** Current session's ConversationState. Persisted to SQLite on each turn. Reconstructable on resume.
2. **Episodic Memory:** Session summaries (Reporter output, <500 tokens) indexed by target + date. Top 3 most recent for a target injected into agent prompts.
3. **Semantic Memory:** Vector-indexed findings/scans/messages. Queried via cosine similarity for relevant context.

### Core Types

```rust
pub struct MemoryFragment {
    pub source: MemorySource,
    pub content: String,
    pub relevance: f64,
    pub token_estimate: usize,
}

pub enum MemorySource {
    Episodic { session_id: Uuid, target: String, date: DateTime<Utc> },
    Semantic { source_type: String, source_id: i64 },
    Working,
}

pub struct SessionSummary {
    pub session_id: Uuid,
    pub target: String,
    pub date: DateTime<Utc>,
    pub summary: String,
    pub finding_count: usize,
    pub key_findings: Vec<String>,
}
```

### MemoryService

```rust
pub struct MemoryService {
    store: Database,
    embeddings: EmbeddingService,
    context_budget: usize,  // 20% of context_window
}

impl MemoryService {
    /// Retrieve relevant context: episodic + semantic, fits within budget
    pub async fn recall(&self, target: &str, query: &str) -> Result<Vec<MemoryFragment>>
    /// Format fragments for prompt injection
    pub fn format_context(&self, fragments: &[MemoryFragment]) -> String
    /// Persist episodic summary at session end
    pub fn store_episode(&self, session_id: Uuid, reporter_output: &str) -> Result<()>
    /// Reconstruct ConversationState from stored messages
    pub fn restore_working_memory(&self, session_id: Uuid, context_window: usize) -> Result<ConversationState>
}
```

### Orchestrator Integration

Before each agent dispatch, `recall()` injects relevant memory into the agent's system prompt. Budget-capped at 20% of context window. Graceful degradation: no prior data = no injection = Phase 2 behavior.

### Tests
- `recall()` with no prior data -> empty vec
- `recall()` with 3 prior sessions -> returns up to 3 episodic summaries
- Budget enforcement: doesn't overshoot 20%
- `store_episode()` + `recall()` round-trip
- `restore_working_memory()` reconstructs messages in order
- Graceful degradation on first-ever run

---

## Sub-Phase 3E: Integration + Polish

**Branch:** `feature/phase-3e-integration` (after 3C merges)
**Touches:** `sigint-cli`, `sigint-tui`, `sigint-agents`, `sigint-store`

### Session Management CLI

```rust
#[derive(Subcommand)]
enum Sessions {
    List { target: Option<String>, limit: usize },
    Resume { id: Uuid, model: Option<String> },
    Export { id: Uuid, format: ExportFormat, output: Option<PathBuf> },
    Delete { id: Uuid },
}
```

### TUI Keyboard Navigation (P1)

- `Tab` cycles panels with visual focus indicator
- `j/k` scrolls, `/` opens inline FTS5-backed search
- `?` renders help overlay, `t` toggles Task Queue panel

### Embedding Worker + Episode Persistence Wiring

- Spawn embedding worker on scan/tui startup
- Persist Reporter output as episodic memory after each scan

### End-to-End Flow

```
sigint scan example.com
  |-- isatty? -> TUI or stdout
  |-- spawn embedding_worker
  |-- MemoryService::recall() -> inject prior intel
  |-- Orchestrator::run_scan() with real-time TUI events
  |-- store_episode() on completion
  \-- embedding_worker picks up new content in background
```

### Tests
- `sigint sessions list` with data -> formatted table
- `sigint sessions export` -> valid JSON
- `sigint sessions resume` -> ConversationState restored
- E2E: scan -> TUI events -> session resumable
