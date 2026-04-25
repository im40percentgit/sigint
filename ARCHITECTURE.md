# SIGINT Architecture

Technical reference for contributors. Describes how the 12-crate workspace fits
together, the agent pipeline, the tool system, data model, and key architectural
decisions.

---

## System Overview

SIGINT is a Cargo workspace of 12 crates that compiles to a **single binary**
(`sigint`). The binary hosts two mutually exclusive interfaces — a Ratatui TUI
and an Axum web UI — on top of a shared `AppCore` backend. There is no
container daemon, no cloud dependency, and no external database: everything
runs locally via Ollama.

```
single binary: sigint
  interfaces:  TUI (ratatui)  |  Web UI (Axum + embedded SPA)
  backend:     AppCore (config + event bus + SQLite)
  agents:      6-role LLM pipeline (Ollama / OpenAI)
  tools:       29 sandboxed tool wrappers
  store:       SQLite with FTS5 and vector embeddings
```

---

## Crate Dependency Graph

```
sigint-cli  (binary entry point)
├── sigint-tui      (Ratatui terminal interface)
├── sigint-web      (Axum REST + WebSocket + embedded SPA)
├── sigint-agents   (6-role agent system + Orchestrator)
│   ├── sigint-llm      (LlmProvider trait + Ollama + OpenAI)
│   ├── sigint-tools    (29 tool wrappers + Tool trait)
│   │   └── sigint-sandbox  (hakoniwa namespace isolation)
│   └── sigint-memory   (episodic + semantic recall)
├── sigint-store    (SQLite + FTS5 + vector embeddings)
├── sigint-recon    (attack surface mapping, change detection)
├── sigint-report   (Markdown / HTML report generation)
└── sigint-core     (Config, domain types, EventBus)
```

`sigint-core` is the leaf dependency that everything else imports. It contains
no I/O — only types, config structs, and the event bus. This prevents circular
dependencies and keeps unit tests fast.

---

## Agent Pipeline

The `Orchestrator` in `sigint-agents` drives the full pipeline for each scan
engagement. The sequence is:

```
Orchestrator::run_scan(target)
 │
 ├─ 1. Create TaskContext (holds accumulated findings, messages, asset map)
 │
 ├─ 2. [optional] ReconEngine pre-step (--recon flag)
 │      DNS, port, web, cert, OSINT modules → assets stored in DB
 │
 ├─ 3. [optional] RfRecon agent (if HackRF / akaei tools detected)
 │      Surveys radio spectrum; output feeds Strategist prompt
 │
 ├─ 4. Researcher agent
 │      OSINT + service enumeration via tool calls
 │      Injects episodic memory context (--memory flag)
 │
 ├─ 5. Convergence loop  [repeats 1..max_cycles]
 │   │
 │   ├─ 5a. Strategist agent
 │   │       Produces structured MITRE ATT&CK-aligned attack plan
 │   │       via CreateAttackPlanTool; emits EscalationTier recommendations
 │   │
 │   ├─ 5b. [optional] Escalation gate (--approval-gates)
 │   │       Pauses if Strategist recommends exploitation / post-exploitation;
 │   │       waits for operator Y/N before Executor proceeds
 │   │
 │   ├─ 5c. Executor agent
 │   │       Executes tools from the attack plan inside Linux namespace sandboxes
 │   │       Each tool call: emit ToolApprovalRequested → wait → execute → emit ToolOutput
 │   │
 │   ├─ 5d. Analyst agent
 │   │       Extracts structured findings via CreateFindingTool
 │   │       Checks convergence: any new finding matching --goal? → stop
 │   │
 │   └─ 5e. [if cycle N+1 finds nothing new] → converged, exit loop
 │
 └─ 6. Reporter agent
        Synthesises all findings into the session ScanReport
        Stored to DB; emitted as Status events
```

**Convergence logic:** `max_cycles=1` (default) runs the loop exactly once,
preserving the original linear pipeline behaviour. Values `> 1` enable
iterative refinement. The loop exits early when either (a) no new findings
are produced in a cycle or (b) any finding title/description matches the
`--goal` keyword.

**Tool-call loop:** Each agent runs inside `run_tool_loop()` (loop_engine.rs),
which calls `chat_stream()`, accumulates tool calls from stream chunks, executes
each tool, appends results as `tool`-role messages, and repeats until the model
produces a plain-text final response or `max_iterations` is reached.

---

## Tool System

### Tool trait

Every sandboxed tool implements the `Tool` trait (async, object-safe via
`async_trait`):

```rust
pub trait Tool: Send + Sync {
    fn name(&self) -> &str;
    fn definition(&self) -> ToolDefinition;  // JSON schema for the LLM tools array
    async fn execute(&self, args: Value) -> Result<ToolResult>;
}
```

`ToolDefinition` is what the LLM sees as its `tools` array entry. `ToolResult`
carries `stdout`, `stderr`, `exit_code`, `duration`, `status` (Ok / Timeout /
SandboxError), and optional `TruncationInfo` when output exceeded the cap.

### Sandbox profiles

Each tool executes inside a Linux namespace sandbox via `hakoniwa`. Five named
profiles encode per-tool-class defaults:

| Profile | Network | Timeout | Used by |
|---------|---------|---------|---------|
| `Nmap` | pasta | 300s | nmap |
| `Bruteforce` | pasta | 300s | gobuster, feroxbuster, hydra, ffuf |
| `WebScanner` | pasta | 600s | nikto, nuclei, sqlmap, whatweb, wpscan, testssl |
| `Recon` | pasta | 60s | whois, dig, curl |
| `Offline` | none | 60s | hashcat, offline analysis |

`pasta` is a user-space network stack (`passt`) that provides full TCP/UDP/DNS
to sandboxed processes without root or TAP devices.

### Tool catalog (29 tools)

| Category | Tools |
|----------|-------|
| Network | nmap, masscan |
| Web discovery | gobuster, feroxbuster, ffuf, whatweb, nikto, nuclei, wpscan |
| Exploitation | sqlmap, hydra, msfconsole |
| Cryptography | hashcat, testssl |
| Post-exploitation | linpeas, enum4linux |
| Network analysis | tshark, responder |
| Cloud / container | trivy, scout_suite, cloudsploit |
| SDR (akaei / HackRF) | akaei_sweep, akaei_scan, akaei_decode, akaei_analyze, akaei_audit, akaei_fingerprint, akaei_freqdb |
| Shell | shell (general-purpose) |

Tool registration is centralised in `all_executor_tools_with_config()` in
`sigint-tools/src/lib.rs` so CLI and web always expose the same catalog.

### Output cap system

Every tool has a configurable byte cap on its combined stdout+stderr. When
output exceeds the cap it is truncated and a `TruncationInfo` struct records
how many bytes were dropped. This prevents context-window overflow when noisy
tools (e.g., nuclei running 1000+ templates) dump megabytes of output.

Caps are configured globally or per-tool in `config.toml` under
`[tools]` / `[tools.overrides.TOOLNAME]`. Default: 1 MB.

---

## Data Model

All persistence is in a single SQLite file (default: `~/.local/share/sigint/sigint.db`).
The schema is migrated at startup via 9 embedded migrations.

### Core tables

| Table | Purpose |
|-------|---------|
| `sessions` | One row per scan engagement; links to target, campaign, parent session |
| `messages` | LLM conversation turns (system / user / assistant / tool roles) |
| `findings` | Structured security findings with severity, CVSS score, evidence, remediation, chain |
| `assets` | Discovered hosts/services; links to `asset_services` and `asset_changes` |
| `scan_history` | Per-tool execution records with args, output, exit code, agent role |
| `campaigns` | Multi-target batch campaigns |
| `embeddings` | Float32 vectors for semantic similarity search |
| `schema_version` | Migration tracking |

### Full-text search

FTS5 virtual tables (`messages_fts`, `findings_fts`, `scan_history_fts`) are
kept in sync via SQLite triggers. Porter stemmer tokenisation enables
prefix/phrase search across conversation history and findings.

### Vector embeddings

`fastembed` computes embedding vectors asynchronously via a background worker.
Cosine similarity search is used by the memory system for semantic recall of
prior findings relevant to the current target.

---

## Event System

`EventBus` (in `sigint-core/src/event.rs`) is a `tokio::broadcast` channel with
a 256-event buffer.

```
EventBus::emit(event)
    │
    ├─ TUI subscriber  (broadcast::Receiver in TuiApp)
    └─ Web subscriber  (broadcast::Receiver per WebSocket connection)
```

Every subscriber receives an independent copy of every event. A slow subscriber
cannot block event delivery to others.

### Key event types

| Event | Emitted by | Consumed by |
|-------|------------|-------------|
| `ToolStarted / ToolOutput / ToolCompleted` | loop_engine | TUI tool panel, Web event log |
| `FindingCreated` | Analyst via CreateFindingTool | TUI findings table, Web findings view |
| `AgentThinking / AgentThinkingDone` | loop_engine (streaming tokens) | TUI chat panel live buffer |
| `ToolApprovalRequested` | loop_engine approval gate | TUI approval prompt, Web approval UI |
| `CycleCompleted` | Orchestrator convergence loop | TUI / Web cycle progress |
| `EscalationRequested / Approved / Denied` | Orchestrator | TUI / Web escalation gate |
| `ReconStarted / ReconCompleted / AssetDiscovered` | ReconEngine | TUI / Web asset map |
| `Shutdown` | main() Ctrl-C handler | TUI, Web axum graceful shutdown |

---

## Web Architecture

### Axum router

`sigint-web::create_router` assembles the full Axum `Router`:

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/health` | Liveness probe |
| GET | `/api/sessions` | List scan sessions |
| GET | `/api/sessions/{id}` | Session details |
| DELETE | `/api/sessions/{id}` | Delete session |
| GET | `/api/sessions/{id}/assets` | Session assets |
| GET | `/api/sessions/{id}/findings` | Session findings |
| GET | `/api/report/{id}` | Generate report (Markdown/HTML) |
| POST | `/api/scan` | Start a new scan |
| GET | `/api/scan/{id}/status` | Live scan status |
| DELETE | `/api/scan/{id}` | Cancel running scan |
| GET | `/api/scans` | List scan records |
| GET | `/api/diff/{scan_a}/{scan_b}` | Compare two scan sessions |
| GET | `/ws/events` | WebSocket event stream |
| GET | `/*` | SPA fallback (embedded frontend) |

### WebSocket bridge

`/ws/events` subscribes to `EventBus` and fans each event as JSON to connected
browser clients. Clients can send JSON messages back (e.g., approval
`Y`/`N` responses) which are forwarded to `ApprovalRegistry`.

### Frontend

The Preact + TypeScript SPA is compiled at build time and embedded into the
binary via `rust-embed`. No separate file server or CDN is required. The SPA
opens a WebSocket on load and renders the live event stream.

---

## LLM Provider Abstraction

`sigint-llm` defines the `LlmProvider` trait:

```rust
pub trait LlmProvider: Send + Sync {
    async fn chat(&self, req: ChatRequest) -> Result<ChatResponse>;
    async fn chat_stream(&self, req: ChatRequest) -> Result<Box<dyn Stream<...>>>;
}
```

Implementations:
- `OllamaProvider` — local Ollama via `/api/chat` (default)
- `OpenAiProvider` — OpenAI-compatible API (OpenAI, Anthropic via proxy, etc.)

The factory (`create_provider`) reads `config.llm.provider` and constructs the
appropriate implementation. `Arc<dyn LlmProvider>` is threaded through
Orchestrator to all agent turns.

---

## Memory System

`sigint-memory` provides three memory layers:

| Layer | Storage | Retrieval |
|-------|---------|-----------|
| Working | `ConversationState` in current session | Direct (current turn context) |
| Episodic | Session summaries in `sessions` table | Target + date lookup |
| Semantic | `embeddings` table (vector BLOB) | Cosine similarity top-K |

The `MemoryService` is an optional field on `Orchestrator`. When `--memory` is
active, relevant prior findings are injected into the Researcher and Strategist
prompts before those agents run.

---

## Key Architectural Decisions

| Decision ID | Component | Summary |
|-------------|-----------|---------|
| DEC-ARCH-001 | sigint-cli | Single binary via clap derive; subcommands in separate modules |
| DEC-ARCH-002 | sigint-core | `tokio::broadcast` event bus decouples TUI and Web from core |
| DEC-AGENT-001 | sigint-agents | Six-role pipeline: RfRecon(opt) → Researcher → Strategist → Executor → Analyst → Reporter |
| DEC-AGENT-002 | sigint-agents | `Tool` trait is object-safe; tools are `Box<dyn Tool>` to allow heterogeneous sets |
| DEC-AGENT-009 | loop_engine | Unknown tool name feeds error message back to LLM for graceful recovery |
| DEC-AGENT-010 | loop_engine | Approval gate blocks on oneshot channel; timeout denies and feeds error back |
| DEC-AGENT-013 | orchestrator | Agents instantiated locally in `run_scan`, not stored as fields (zero-cost) |
| DEC-AGENT-017 | orchestrator | Convergence loop defaults to `max_cycles=1` for backward compatibility |
| DEC-LLM-001 | sigint-llm | Ollama-first with `LlmProvider` trait for swappable cloud backends |
| DEC-LLM-007 | loop_engine | Accumulate tool calls from all stream chunks (not just `done=true`) |
| DEC-SAND-001 | sigint-sandbox | hakoniwa chosen over Docker: no daemon, unprivileged namespaces, zero overhead |
| DEC-SAND-002 | sigint-sandbox | `SandboxedCommand` is synchronous; callers use `spawn_blocking` |
| DEC-SAND-004 | sigint-sandbox | Named profiles encode tool-class defaults (nmap, bruteforce, web_scanner, recon, offline) |
| DEC-STORE-001 | sigint-store | SQLite + rusqlite bundled; WAL mode; embedded migrations; zero external dependencies |
| DEC-TOOL-003 | sigint-tools | `Tool` trait is the uniform interface for all sandboxed wrappers |
| DEC-TOOL-004 | sigint-tools | `all_executor_tools_with_config()` is the canonical catalog; CLI and Web share it |
| DEC-WEB-001 | sigint-web | Axum 0.8 with tower-http CORS; WebSocket bridge fans EventBus to browsers |
| DEC-RECON-008 | sigint-recon | ReconEngine runs modules sequentially; a failing module logs and continues |
| DEC-P3-001 | orchestrator | `MemoryService` is `Option<>` on Orchestrator; `None` = no-op, no backward breaks |

---

## Fine-tuning Closed Loop

`sigint-train` implements an optional pipeline for adapting the LLM to
engagement-specific tool-calling patterns. All steps are explicit opt-in:
no data leaves the local machine without a user-initiated command.

```
sigint train harvest <session_id>   # mark session trainable=1 in SQLite
sigint train export                 # extract JSONL, 80/20 split
sigint train finetune --base <tag> --output <name>  # shell-out to trainer
sigint train evaluate --base <tag> --candidate <tag> # live A/B comparison
sigint model promote <tag>          # atomic config rewrite + promotion.log
sigint model rollback               # revert via promotion.log last entry
```

### Crate responsibilities

| Crate | Responsibility |
|-------|---------------|
| `sigint-train` | extract, format, split, finetune, evaluate, modelfile, assess |
| `sigint-cli::train` | CLI dispatch for harvest/export/finetune/evaluate |
| `sigint-cli::model` | CLI dispatch for promote/rollback; atomic config rewrite |
| `sigint-core::TrainConfig` | `[train]` config section: finetune_command, min_eval_examples, job_dir |

### Key decisions

- **DEC-P24-001** — Fine-tune backend is an external shell-out command. The
  command receives training data via env vars (`SIGINT_TRAIN_JSONL`,
  `SIGINT_TEST_JSONL`, `SIGINT_BASE_MODEL`, `SIGINT_OUTPUT_PATH`). This keeps
  sigint toolchain-agnostic (unsloth / axolotl / MLX).

- **DEC-P24-002** — Harvest is explicit opt-in (`trainable=1`). Production
  `extract_all` filters to harvested sessions only; `extract_all_unfiltered`
  is available for tests and back-compat.

- **DEC-P24-003** — Evaluation runs live inference on both base and candidate
  providers against the held-out test set (20%). This is the only methodology
  that detects real quality regressions introduced by fine-tuning.

- **DEC-P24-004** — Promotion atomically rewrites `config.toml` via
  `.tmp` + `rename()`. A `.bak` backup is created before every promotion.
  An append-only `promotion.log` (JSONL) enables rollback.

- **DEC-P24-007** — Modelfile `ADAPTER` directive is emitted only when a real
  LoRA adapter binary path is provided (`Some`). Supersedes DEC-TRAIN-005.

### P1 promotion gate

`sigint model promote` refuses unless `last_eval.json` contains
`total_examples >= config.train.min_eval_examples` (default: 50). Use
`--force` to override. This prevents promoting models evaluated on too few
examples to be statistically meaningful.

### Web UI closed loop (Phase 26)

Phase 26 adds a browser-based workbench that exposes the same fine-tuning
pipeline via REST + WebSocket. The CLI and web UI share all training state
through the filesystem — there is no synchronisation layer.

```
Browser                  Axum routes             sigint-train / sigint-core
──────                   ───────────             ──────────────────────────
/sessions toggle     →   POST /api/train/harvest/<id>  →  db.set_trainable()
/train Export        →   POST /api/train/export         →  extract_all() + split
/train Fine-tune     →   POST /api/train/finetune        →  run_finetune()
/train/evaluate      →   POST /api/train/evaluate        →  run_evaluation()
/models Promote      →   POST /api/model/promote         →  promote_model()
/models Rollback     →   POST /api/model/rollback        →  rollback_model()
```

**Shared filesystem state** — identical files read and written by both paths:

| File | Location |
|------|---------|
| `jobs.json` | `~/.local/share/sigint/training/jobs.json` |
| `train.jsonl` / `test.jsonl` | `~/.local/share/sigint/training/` |
| `last_eval.json` | `~/.local/share/sigint/training/last_eval.json` |
| `config.toml` | `~/.config/sigint/config.toml` |
| `promotion.log` | `~/.config/sigint/promotion.log` |

**Job state in jobs.json, not SQLite** (DEC-P26-002): the web routes read
`jobs.json` directly. Migrating to SQLite would require CLI-side changes with
no benefit at single-operator scale; the file is append-only and crash-safe.

**WebSocket progress events**: `TrainingJobStarted`, `TrainingJobProgress`
(deferred — issue #21), `TrainingJobCompleted`, `TrainingJobFailed`,
`EvaluationStarted`, `EvaluationProgress`, `EvaluationCompleted`,
`ModelPromoted`, `ModelRolledBack` — all fanned via the `EventBus` broadcast
channel to subscribed browser clients (DEC-P26-001).

**Auth**: all `/api/train/*` and `/api/model/*` routes sit behind the Phase 25
Bearer middleware. No new auth surface is introduced (DEC-P26-007).

---

## Adding a New Tool

1. Create `crates/sigint-tools/src/<toolname>.rs` implementing `Tool`.
2. Register it in `all_executor_tools_with_config()` in `sigint-tools/src/lib.rs`.
3. Choose the appropriate `SandboxProfile` in `execute()`.
4. Update the `all_executor_tools_returns_N_tools` test count.
5. Add an install entry to `doctor.rs` so `sigint doctor` reports it.

## Adding a New Migration

Append an entry to the `MIGRATIONS` slice in `sigint-store/src/migrations.rs`
with a consecutive version number. Migrations run automatically at startup and
are idempotent (already-applied versions are skipped).
