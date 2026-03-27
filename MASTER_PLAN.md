# MASTER_PLAN.md — SIGINT: AI-Powered Penetration Testing Tool

## Project Overview

**Type:** CLI / security tool
**Languages:** Rust (100%)
**Root:** /home/j/sigint

**SIGINT** is a single-binary AI-powered penetration testing tool built in Rust. It replaces overengineered multi-container pentest orchestrators (like PentAGI) with a local-first design: embedded SQLite, local LLM via Ollama, native Linux sandboxing via hakoniwa, and continuous attack surface mapping.

**Architecture:** Cargo workspace with 12 crates, shared `AppCore` backend, dual interface (TUI + Web), 6-role agent system with Orchestrator dispatch (5 core + optional RfRecon).

**Current Phase:** Phase 13 in progress — Live Target Hardening

### Architecture

```
sigint/
  crates/
    sigint-core/       # Config, domain types, AppCore, event bus
    sigint-llm/        # LLM provider trait + Ollama (tool calling support)
    sigint-agents/     # Agent trait, Orchestrator, 5 roles, tool-call loop
    sigint-sandbox/    # Linux namespaces + seccomp via hakoniwa
    sigint-store/      # SQLite + FTS5 + embeddings
    sigint-tools/      # Tool trait, nmap/gobuster/shell wrappers, registry
    sigint-recon/      # Attack surface mapping, change detection
    sigint-tui/        # Ratatui terminal interface
    sigint-web/        # Axum embedded web UI + REST API + WebSocket
    sigint-report/     # Report generation (Markdown, HTML)
    sigint-cli/        # Binary entry point
    sigint-memory/     # Episodic + semantic memory
```

**Interfaces:** TUI (default), Web (`sigint serve`), dual (`sigint --web`), headless (`sigint run <task>`)

**Shared backend:** Both TUI and Web connect to `AppCore` via `tokio::broadcast` event bus.

### Active Work

- Phase 1 completed (commit 862f9e1)
- Phase 2 completed (commits d8e5c4a–031276b, 4 hotfix rounds)
- Phase 3 completed (commits 8bcf354–0fee08c) — TUI, memory, embeddings, session CLI, integration wiring
- Phase 4 completed (commits 65588ba–a1b59d2) — ASM store, discovery, tools, TUI+CLI
- Phase 5 completed (commits 654eaa2–ec9ccf0) — Doctor, OpenAI provider, reports, REST API, SPA frontend
- Phase 6 completed (commits b17839e–333a002) — nmap/nuclei parsers, approval gates, bidirectional WebSocket, web scan orchestrator with ScanService
- Phase 7 completed — scan diff engine (7A), E2E integration tests (7B), graceful shutdown (7C)
- Phase 8 completed — streaming reasoning (8A), interactive TUI sessions (8B), per-chunk streaming timeout
- Phase 9 completed — session resume with auto-diff (9A), multi-target campaign mode (9B), report polish with executive summary + SVG chart (9C)
- Phase 12 completed — iterative convergence loop, enriched findings, evidence linking, approval-gated escalation

---

## Original Intent

Build a single-binary AI-powered penetration testing tool in Rust that replaces overengineered multi-container solutions like PentAGI (7+ Docker containers: Go, React, PostgreSQL, Redis, Neo4j, MinIO, Langfuse, ClickHouse, Grafana). The vision: no Docker, no external databases, local-first with Ollama, native Linux sandboxing, and continuous attack surface mapping — all in one `sigint` binary. A tool that a pentester can download and run immediately, with AI agents orchestrating reconnaissance, strategy, execution, analysis, and reporting.

## Agent System

5 roles with role-based tool access, coordinated by an Orchestrator:

- **Orchestrator** — Receives user goals, decomposes into tasks, dispatches to specialist agents, manages task queue
- **Researcher** — OSINT, recon, information gathering (tools: nmap, gobuster, shell)
- **Strategist** — Attack planning, methodology selection (tools: none — LLM reasoning only)
- **Executor** — Tool execution in sandboxed environments (tools: nmap, gobuster, shell, all future tools)
- **Analyst** — Result analysis, finding correlation, vulnerability assessment (tools: shell for parsing)
- **Reporter** — Report generation, evidence compilation (tools: none — LLM generation only)

## Key Crates

| Component | Crate |
|-----------|-------|
| Runtime | `tokio` |
| HTTP | `reqwest` (stream), `axum` (REST + WS) |
| SSE | `eventsource-stream` (OpenAI streaming) |
| CLI | `clap` |
| TUI | `ratatui` + `crossterm` |
| DB | `rusqlite` (bundled) |
| Embeddings | `fastembed` |
| Sandbox | `hakoniwa` |
| Logging | `tracing` |
| Reports | `pulldown-cmark` (Markdown→HTML) |
| Frontend | Preact + HTM + esbuild, `rust-embed` |
| Serialization | `serde`, `serde_json`, `toml` |

## Phases

### Phase 1: Foundation
**Status:** completed

- [x] Project bootstrap (git, MASTER_PLAN.md)
- [x] Cargo workspace with all crate stubs
- [x] sigint-core: Config (TOML), error types, domain types, event bus
- [x] sigint-llm: Ollama provider with streaming JSON-lines
- [x] sigint-cli: `sigint chat` interactive command
- [x] sigint-store: SQLite schema + migrations + basic CRUD
- [x] sigint-sandbox: hakoniwa namespace isolation with SandboxedCommand builder

---

### Phase 2: Agent System + Sandboxing
**Status:** completed
**Decision IDs:** DEC-AGENT-001, DEC-AGENT-002, DEC-AGENT-003, DEC-AGENT-004, DEC-AGENT-005, DEC-AGENT-006
**Requirements:** REQ-P0-001, REQ-P0-002, REQ-P0-003, REQ-P0-004, REQ-P0-005, REQ-P0-006, REQ-P0-007, REQ-P0-008
**Issues:** Inline (no GitHub remote)
**Definition of Done:**
- REQ-P0-005 satisfied: `sigint scan scanme.nmap.org` runs nmap in sandbox, Orchestrator routes through agents, LLM analyzes results, displays summary
- REQ-P0-001 satisfied: Adding a new tool = one struct implementing Tool trait + one sandbox profile
- REQ-P0-004 satisfied: Conversations exceeding context_window are trimmed without losing system prompt
- REQ-P0-006 satisfied: Role-based ACL prevents agents from using tools outside their allowed set
- REQ-P0-008 satisfied: Orchestrator dispatches tasks to Researcher/Strategist/Executor/Analyst/Reporter based on task type
- All non-integration tests pass without Ollama running
- scan_history table populated in SQLite after a scan

**Known Gaps (deferred):**
- GobusterTool not implemented (was P1/optional, deferred to Phase 4)
- `--ports` CLI flag parsed but not plumbed to NmapTool
- Only aggregate scan_history rows persisted, not per-tool-invocation records

## Problem Statement

SIGINT Phase 1 delivered a streaming chat REPL backed by Ollama. The user types, the LLM responds. But a penetration testing tool needs the LLM to *act*: invoke nmap, parse results, decide next steps, and chain tool executions toward a goal. Without an agent system, SIGINT is a chatbot, not a pentest tool.

Phase 2 transforms SIGINT from a passive chat interface into an autonomous multi-agent system where specialized agents collaborate — the Researcher gathers intel, the Strategist plans attacks, the Executor runs tools in sandboxes, the Analyst correlates findings, and the Reporter summarizes results.

## Goals & Non-Goals

### Goals
- REQ-GOAL-001: LLM agents can autonomously invoke security tools (nmap, gobuster, shell) via a structured tool-call loop
- REQ-GOAL-002: All tool execution happens inside hakoniwa sandboxes with per-tool security profiles
- REQ-GOAL-003: `sigint scan <target>` performs end-to-end reconnaissance with multi-agent coordination
- REQ-GOAL-004: Agent and tool systems are extensible — adding a new tool or agent role requires minimal boilerplate
- REQ-GOAL-005: Context window is managed to prevent conversation from exceeding model limits

### Non-Goals
- REQ-NOGO-001: TUI integration — Phase 2 outputs to stdout via CLI; TUI is Phase 3
- REQ-NOGO-002: Memory/persistence of agent reasoning — tool outputs persist in scan_history; episodic memory is Phase 3
- REQ-NOGO-003: Cloud LLM providers — Phase 2 is Ollama-only per DEC-LLM-001
- REQ-NOGO-004: Concurrent/parallel tool execution — tools run sequentially in Phase 2
- REQ-NOGO-005: Tool approval mechanism (user confirms before execution) — all tools run automatically in Phase 2

## Requirements

### Must-Have (P0)

- REQ-P0-001: Tool trait with name, description, parameters (JSON Schema), and execute method
  Acceptance: Given a Tool impl, When its definition() is serialized, Then it produces valid Ollama tools JSON matching the OpenAI-compatible schema format
- REQ-P0-002: Nmap tool wrapper that builds SandboxedCommand from arguments, executes in hakoniwa sandbox, returns structured output
  Acceptance: Given NmapTool with target "scanme.nmap.org", When executed, Then returns ToolResult with stdout containing port/service data and exit_code 0
- REQ-P0-003: Tool-call loop: send messages+tools to Ollama -> parse tool_calls -> execute -> send results back -> repeat until text response
  Acceptance: Given a user message "scan 192.168.1.1", When the agent loop runs, Then it invokes nmap via tool_calls, feeds results back, and the LLM produces analysis text
- REQ-P0-004: ConversationState holds message history, tool schemas, and manages context window budget
  Acceptance: Given a conversation exceeding context_window tokens, When a new turn starts, Then oldest non-system messages are trimmed while preserving the system prompt
- REQ-P0-005: `sigint scan <target>` CLI command that creates a session, runs the Orchestrator, and displays results
  Acceptance: Given `sigint scan scanme.nmap.org`, When executed, Then Orchestrator dispatches to agents, nmap runs in sandbox, analysis is printed to stdout
- REQ-P0-006: Role-based tool ACL — each agent role declares allowed tools; ToolRegistry enforces access
  Acceptance: Given an agent with role Strategist (no tools), When the LLM produces a tool_call, Then it is denied and the agent continues with text-only reasoning
- REQ-P0-007: sigint-llm types extended with tool_calls support (ToolDefinition, ToolCall, tool role messages)
  Acceptance: Given ChatMessage with tool_calls, When serialized for Ollama /api/chat, Then the JSON matches Ollama's expected format including the tools array
- REQ-P0-008: Orchestrator coordinates 5 agent roles (Researcher, Strategist, Executor, Analyst, Reporter)
  Acceptance: Given a scan task, When the Orchestrator runs, Then it dispatches reconnaissance to Researcher, planning to Strategist, tool execution to Executor, analysis to Analyst, summary to Reporter

### Nice-to-Have (P1)

- REQ-P1-001: Gobuster tool wrapper with directory/vhost bruteforce modes
- REQ-P1-002: Tool execution events emitted on EventBus (ToolStarted, ToolOutput, ToolCompleted)
- REQ-P1-003: Streaming display of LLM reasoning between tool calls (not just final response)
- REQ-P1-004: Max-iterations guard on the tool-call loop (prevent infinite loops, default 10)

### Future Consideration (P2)

- REQ-P2-001: Tool approval mechanism (user confirms before dangerous tool execution)
- REQ-P2-002: Parallel tool execution within a single agent turn
- REQ-P2-003: Agent-to-agent direct communication (bypass Orchestrator for efficiency)

### Planned Decisions

- DEC-AGENT-001: Use Ollama native tool calling via /api/chat `tools` parameter — Ollama supports OpenAI-compatible JSON Schema format; internal parser handles malformed output and falls back to JSON detection for models without explicit tool support; 8B models achieve ~89% accuracy which is acceptable (failures are recoverable). Research: `.claude/research/DeepResearch_Ollama_Tool_Calling_API_2026-02-23/report.md` — Addresses: REQ-P0-003, REQ-P0-007
- DEC-AGENT-002: Full 5-role multi-agent Orchestrator — Orchestrator receives user goals, decomposes into tasks, dispatches to specialist agents (Researcher, Strategist, Executor, Analyst, Reporter) in sequence; each agent has its own system prompt, allowed tools, and ConversationState; Orchestrator passes context between agents via a shared TaskContext — Addresses: REQ-P0-008, REQ-GOAL-003, REQ-GOAL-004
- DEC-AGENT-003: Tool trait with JSON Schema definition — each tool declares capabilities via `definition() -> ToolDefinition` (name, description, parameters as serde_json::Value conforming to JSON Schema); passed directly to Ollama's tools parameter; `execute(args: Value) -> Result<ToolResult>` runs the tool — Addresses: REQ-P0-001, REQ-GOAL-004
- DEC-AGENT-004: Synchronous tool execution via spawn_blocking — consistent with DEC-SAND-002; hakoniwa fork(2) is incompatible with multi-threaded tokio; agent loop awaits the blocking task — Addresses: REQ-P0-002, REQ-GOAL-002
- DEC-AGENT-005: Context window management via token counting heuristic — track cumulative tokens from Ollama response usage stats; 4 chars ~= 1 token estimation; trim oldest non-system messages when approaching context_window limit — Addresses: REQ-P0-004, REQ-GOAL-005
- DEC-AGENT-006: Non-streaming for tool-call iterations, streaming for final text — use `stream: false` during tool-call loop (tool_calls are complete JSON); switch to streaming only for the final text response; standard Ollama pattern per docs — Addresses: REQ-P0-003

### Decision Log
<!-- Guardian appends here after phase completion -->

| ID | Date | Decision | Context |
|----|------|----------|---------|
| DEC-HOTFIX-001 | 2026-02-25 | Resolve bare command paths via `which` before sandbox exec | Sandbox requires absolute paths; tools like `nmap` need runtime resolution. Commit ad36d0d |
| DEC-HOTFIX-002 | 2026-02-25 | DNS via /etc/resolv.conf bind-mount in Pasta networking | Pasta network namespaces lack DNS by default; bind-mounting resolv.conf from host restores resolution. Commit ad36d0d |
| DEC-HOTFIX-003 | 2026-02-25 | Fix Nmap ACL name mismatch "nmap" vs "nmap_scan" | Tool registered as "nmap_scan" but agent ACL listed "nmap"; dispatcher couldn't find tool. Standardized on "nmap_scan". Commit 2b6317b |
| DEC-HOTFIX-004 | 2026-02-25 | Add /dev mount for Pasta sandbox profile | Nmap requires /dev/null and /dev/urandom; missing mount caused runtime failures. Commit 031276b |
| DEC-HOTFIX-005 | 2026-02-25 | ShellTool combined-command string splitting | ShellTool received combined command strings (e.g. "grep foo \| sort"); added shell-style splitting to handle pipes and redirections. Commit 031276b |
| DEC-SAND-001 | 2026-02-25 | hakoniwa chosen over Docker for native Linux namespaces | Eliminates container daemon dependency, zero-overhead fork/exec, unprivileged user namespaces only — no setuid binaries required. |
| DEC-SAND-002 | 2026-02-25 | SandboxedCommand is synchronous; callers use spawn_blocking | hakoniwa's fork(2) is incompatible with multi-threaded tokio runtimes. Blocking in a dedicated OS thread (via spawn_blocking) is the safe bridge. |
| DEC-SAND-003 | 2026-02-25 | Capability detection via /proc and PATH walk at runtime | Probing at runtime lets the binary surface actionable error messages without failing to compile on misconfigured hosts. |
| DEC-SAND-004 | 2026-02-25 | Named profiles encode tool-class defaults (nmap, offline) | Callers should not need to know nmap requires pasta networking and a 5-minute timeout — that knowledge lives in the profile. |
| DEC-SAND-005 | 2026-02-25 | Integration tests run against real namespaces, no mocks | Sandbox correctness cannot be verified by mocking OS primitives; tests fork real child processes inside real namespaces. |
| DEC-SAND-006 | 2026-02-25 | Resolve bare commands to absolute paths before execve | hakoniwa uses raw execve() (not execvp()); bare command names like "grep" fail with ENOENT. Resolved at build time, PATH injected into sandbox env. |
| DEC-TOOL-001 | 2026-02-25 | Crate-local ToolError for tool-specific failure modes | Mirrors SandboxError pattern; lets sigint-tools express domain-specific failures without coupling to workspace-wide error types. |
| DEC-TOOL-002 | 2026-02-25 | ToolResult mirrors SandboxOutput with optional structured data | Wraps stdout/stderr/exit_code/duration from sandbox layer; adds structured_data field for tools that parse their own output into JSON. |
| DEC-TOOL-003 | 2026-02-25 | async_trait for object-safe async Tool methods | Rust RPITIT does not produce object-safe traits; async_trait rewrites async fn into Pin<Box<dyn Future>> enabling dyn Tool and dynamic dispatch at the agent layer. |
| DEC-TOOL-004 | 2026-02-25 | NmapTool uses SandboxProfile::nmap() for pasta networking | nmap requires real network access; Pasta user-mode networking gives network access while remaining isolated from host filesystem and process tree. |
| DEC-TOOL-005 | 2026-02-25 | ShellTool uses a static allowlist and offline sandbox profile | Static allowlist of read-only/analysis commands prevents LLM from running arbitrary binaries; offline sandbox prevents network egress. |
| DEC-AGENT-007 | 2026-02-25 | ResearcherAgent system prompt focuses on OSINT/recon with nmap+shell tools | Agent specialization via system prompt and tool ACL; tools: nmap_scan, shell. |
| DEC-AGENT-008 | 2026-02-25 | StrategistAgent is LLM-only (no tools) — reasoning-only role | Attack planning requires no tool execution; tool list is empty to prevent accidental tool calls during reasoning phases. |
| DEC-AGENT-009 | 2026-02-25 | ExecutorAgent has access to all tools for hands-on exploitation | Executor role requires broadest tool access; tool ACL: nmap_scan, shell. |
| DEC-AGENT-010 | 2026-02-25 | AnalystAgent uses shell-only tools for result parsing | Analysis requires parsing tool output; only shell (grep, awk, jq, etc.) is needed — no network tools. |
| DEC-AGENT-011 | 2026-02-25 | ReporterAgent is LLM-only — report generation via text synthesis | Report generation requires no external tools; tool list is empty. ToolRegistry.for_role(Reporter) returns empty. |
| DEC-AGENT-012 | 2026-02-25 | ScanReport carries context + summary string for Display rendering | Reporter's text output is the primary human-readable artifact; TaskContext provides structured data for programmatic access. |
| DEC-AGENT-013 | 2026-02-25 | Agents instantiated locally inside run_scan, not as Orchestrator fields | Agent structs are stateless identity objects; local instantiation is zero-cost (stack allocation) and makes pipeline order explicit. |
| DEC-AGENT-014 | 2026-02-25 | Orchestrator holds Arc<dyn LlmProvider> for cheap Clone across agent turns | Arc avoids lifetime parameters on Orchestrator struct and enables future parallel agent dispatch without copying the provider. |
| DEC-STORE-001 | 2026-02-25 | SQLite with rusqlite bundled — no external database | Zero-config deployment; database is a single file. bundled feature compiles SQLite into the binary eliminating system libsqlite3 dependency. WAL mode enables concurrent reads. |
| DEC-STORE-002 | 2026-02-25 | ScanRecord stored as denormalized row — one row per tool invocation | Enables per-tool queries, filtering by exit_code, and future diffing across scans without a separate arguments table. |
| DEC-STORE-003 | 2026-02-25 | Findings stored with severity TEXT and optional asset/evidence columns | Severity as TEXT CHECK constraint matches message role pattern; asset and evidence are nullable TEXT. CASCADE DELETE on session_id. |
| DEC-STORE-FTS | 2026-02-25 | Standalone FTS5 with UUID source_id — not external-content tables | FTS5 content_rowid requires INTEGER; UUID is TEXT. Standalone FTS table synced via triggers maintains FTS without rowid aliasing issues. |
| DEC-P3-002 | 2026-02-25 | fastembed always-on with all-MiniLM-L6-v2 | Semantic search requires local embedding model; fastembed wraps ONNX Runtime for CPU inference. 384-dim vectors stored as raw f32 bytes via bytemuck::cast_slice. |
| DEC-P3-003 | 2026-02-25 | TUI auto-detected via isatty(stdout); --tui/--no-tui override | When stdout is a TTY the user is interactive — show TUI. When piped or in CI, fall back to stdout event printer. Flags override the heuristic. |
| DEC-P3-POOL | 2026-02-25 | r2d2 connection pool replaces Mutex<Connection> | WAL mode + r2d2 pool enables concurrent reads from TUI and agents without mutex contention. In-memory DBs use max_size(1) to share a single SQLite :memory: database. |
| DEC-P3-QUERY | 2026-02-25 | Typed query builders replace ad-hoc SQL string construction | Builder pattern makes filters, pagination, and ordering composable and discoverable; bound parameters prevent SQL injection; builders borrow Database to ensure pool outlives query. |
| DEC-P3-TUI-001 | 2026-02-25 | AppState as pure event-driven state machine | Separating state from rendering (ui.rs) and I/O (app.rs) lets every state transition be exercised by a unit test. Mirrors Elm architecture. |
| DEC-P3-TUI-002 | 2026-02-25 | render() is a pure function of AppState with no side effects | Pure render function enables full layout testing via ratatui TestBackend without a real terminal. No mutable global state, no I/O in ui.rs. |
| DEC-P3-TUI-003 | 2026-02-25 | TuiApp separates terminal I/O from state; state lives in AppState | Terminal setup/teardown and event loop are inherently impure; isolating them in app.rs lets state.rs and ui.rs remain pure and fully unit-testable. |
| DEC-CLI-003 | 2026-02-25 | sessions subcommand uses best-effort database access, same as scan | Consistency with scan command's error handling; database errors reported with clear message and non-zero exit without panicking. --confirm flag on delete guards against accidental data loss. |
| DEC-WEB-002 | 2026-03-01 | Bidirectional WebSocket using tokio::select! over broadcast::Receiver and StreamExt | Replace send-only WS loop with select! so client messages (approval, scan requests) flow back to the event bus. Phase 6C. |
| DEC-WEB-003 | 2026-03-01 | AppState carries config, approval_registry, and scan_service for web-initiated scans | Web layer needs all three for browser-initiated scans; config for model/timeouts, approval_registry for y/n routing, scan_service for lifecycle management. Phase 6C. |
| DEC-WEB-005 | 2026-03-01 | start_scan delegates fully to ScanService::start() | Centralised scan lifecycle in ScanService eliminates duplicated session/event logic between web and CLI paths. Phase 6 Web Scan Orchestrator. |
| DEC-WEB-010 | 2026-03-01 | rust-embed for compile-time asset embedding with mime_guess content-types | Single binary with no external file dependencies; mime_guess maps extension to Content-Type. Phase 5E. |
| DEC-APPROVE-001 | 2026-03-01 | std::sync::Mutex + tokio::sync::oneshot for the approval registry | oneshot channels are the Tokio primitive for single-response request/reply; Mutex<HashMap> is sufficient for infrequent approval lookups. Phase 6B. |
| DEC-AGENT-015 | 2026-03-01 | Per-tool scan record persistence opt-in via Option<&Database> in ToolLoopOptions | Tool loop tests and non-CLI callers don't always have a DB; Option keeps the loop backward-compatible. Phase 6 Web Scan Orchestrator. |
| DEC-AGENT-016 | 2026-03-01 | Orchestrator holds Option<Arc<Database>> + session_id for per-tool persistence | Optional DB avoids lifetime parameters and keeps web scan path (no DB session yet) working. Phase 6 Web Scan Orchestrator. |
| DEC-P6-APPROVAL-002 | 2026-03-01 | Approval bar occupies a conditional 1-row slot at the bottom of the TUI layout | Must be unmissable; disappears when no approval pending to avoid wasted space. Phase 6D. |
| DEC-LLM-004 | 2026-03-01 | OpenAI-compatible provider with manual SSE parsing | /v1/chat/completions is the de-facto standard for hosted LLMs; manual SSE avoids adding an eventsource crate. Phase 5B. |
| DEC-LLM-006 | 2026-03-01 | Centralised provider factory maps Config to LLM backend | Single create_provider eliminates duplicate construction logic; callers pass &Config and get Arc<dyn LlmProvider>. Phase 5B. |
| DEC-ASM-001 | 2026-03-01 | Asset store uses SELECT-then-INSERT for upsert | No UNIQUE constraint on (session_id, kind, value); INSERT OR REPLACE risks silent duplicates on schema drift. Phase 4A. |
| DEC-DIFF-001 | 2026-03-02 | Match findings by (title.to_lowercase(), asset) as cross-session key | Finding IDs are per-session UUIDs; (title, asset) is the stable logical identity for change tracking. Phase 7A. |
| DEC-CLI-DIFF-001 | 2026-03-02 | sigint diff uses direct DB access, not HTTP API | CLI has sigint-store as a dep; direct DB avoids requiring a running server and keeps diff offline-capable. Phase 7A. |
| DEC-CLI-005 | 2026-03-01 | report command accepts UUID prefix for session_id | Full UUIDs are 36 chars; prefix matching (≥4 chars) is comfortable for interactive use. Phase 5C. |
| DEC-WEB-007 | 2026-03-13 | serve_with_shutdown accepts generic Future<Output=()> for axum graceful shutdown | Axum's with_graceful_shutdown is the idiomatic path; separate function keeps serve signature stable. Phase 7C. |
| DEC-CLI-006 | 2026-03-13 | serve subcommand uses serve_with_shutdown for clean Ctrl-C teardown | axum drain on Ctrl-C prevents dropped requests; Event::Shutdown emitted so WebSocket clients clean up. Phase 7C. |
| DEC-4D-RECON-002 | 2026-03-14 | ReconEngine borrows &Database and &EventBus — both live for the scope of run() | Borrowed references avoid Arc overhead and make the lifetime constraint explicit at the call site (CLI holds both for the session). Phase 4D. |
| DEC-P6-APPROVAL-001 | 2026-03-14 | PendingApproval held in AppState; approval responses emitted by app.rs | AppState remains a pure data structure (no channel handles). apply() records pending approvals; app.rs reads and emits responses, then clears pending_approval. Phase 6D. |
| DEC-AGENT-007-REV | 2026-03-14 | Tool loop switched from chat() to chat_stream() for all iterations (Phase 8A) | Streaming every iteration enables AgentThinking event emission for real-time reasoning visibility. Tool calls still arrive on the done=true chunk per DEC-LLM-003. Phase 8A. |

### Implementation Issues (Inline — No GitHub Remote)

Issues are ordered by dependency tier. Tier 1 issues have no dependencies and can be parallelized. Tier 2 depends on Tier 1. Tier 3 depends on both.

#### Tier 1 — Foundation Types (parallelizable)

**Issue P2-1: Extend sigint-llm Types for Tool Calling**
Complexity: Medium
Crate: sigint-llm

Add tool-calling types and extend OllamaProvider:

1. New types in `sigint-llm/src/types.rs`:
   - `ToolDefinition` { type_: "function", function: FunctionDef { name, description, parameters: Value } }
   - `ToolCall` { function: FunctionCall { name: String, arguments: Value } }
   - Extend `ChatMessage` with optional `tool_calls: Option<Vec<ToolCall>>`
   - Add `ChatMessage::tool(content: impl Into<String>)` constructor for role="tool" messages

2. Extend `sigint-llm/src/ollama.rs`:
   - `OllamaRequest` gains optional `tools: Option<&[ToolDefinition]>`
   - `OllamaStreamLine.message` gains optional `tool_calls`
   - `ChatResponse` gains `tool_calls: Vec<ToolCall>`
   - Non-streaming `chat()` returns tool_calls when present
   - `chat()` passes tools to Ollama when provided — new method or extend ChatRequest

3. Extend `ChatRequest`:
   - Add `tools: Vec<ToolDefinition>` field (default empty vec)
   - Add `with_tools(tools: Vec<ToolDefinition>)` builder method

4. Tests:
   - ToolDefinition serialization matches Ollama's expected format
   - ChatMessage::tool() produces role="tool" messages
   - ChatRequest with tools serializes correctly
   - Parse sample Ollama response JSON containing tool_calls
   - Parse sample Ollama response JSON without tool_calls (backward compat)

**Issue P2-2: Tool Trait + Nmap/Shell Wrappers**
Complexity: Medium
Crate: sigint-tools

1. Define `Tool` trait:
   ```rust
   #[async_trait]
   pub trait Tool: Send + Sync {
       fn name(&self) -> &str;
       fn description(&self) -> &str;
       fn definition(&self) -> ToolDefinition;
       async fn execute(&self, args: Value) -> Result<ToolResult, Error>;
   }
   ```

2. `ToolResult` struct:
   - stdout: String, stderr: String, exit_code: i32
   - duration: Duration
   - structured_data: Option<Value> (for parsed output)

3. `NmapTool`:
   - definition(): target (required string), ports (optional string), scan_type (optional enum: "quick"/"full"/"service")
   - execute(): builds SandboxedCommand via SandboxProfile::nmap(), runs in spawn_blocking
   - Parses nmap XML output when -oX is used (or raw text otherwise)
   - New SandboxProfile variant if needed

4. `ShellTool`:
   - definition(): command (required string), args (optional array of strings)
   - execute(): builds SandboxedCommand with SandboxProfile::offline() (no network)
   - Returns raw stdout/stderr
   - Safety: command allowlist (grep, awk, sed, cat, head, tail, sort, uniq, wc, jq, curl) — no arbitrary binaries

5. `GobusterTool` (P1):
   - definition(): url (required), wordlist (optional, default /usr/share/wordlists/...), mode (dir/vhost)
   - execute(): SandboxProfile with Pasta networking, 300s timeout
   - New SandboxProfile::Gobuster variant

6. Tests:
   - NmapTool::definition() produces valid ToolDefinition
   - ShellTool command allowlist enforcement
   - ToolResult construction
   - Each tool's argument validation (missing required args -> error)

#### Tier 2 — Agent System (depends on Tier 1)

**Issue P2-3: Agent Trait + ConversationState + 5 Roles**
Complexity: High
Crate: sigint-agents
Depends on: P2-1

1. `AgentRole` enum: Researcher, Strategist, Executor, Analyst, Reporter

2. `Agent` trait:
   ```rust
   #[async_trait]
   pub trait Agent: Send + Sync {
       fn name(&self) -> &str;
       fn role(&self) -> AgentRole;
       fn system_prompt(&self) -> &str;
       fn allowed_tools(&self) -> &[String];
   }
   ```

3. `ConversationState`:
   - messages: Vec<ChatMessage>
   - token_count: usize (estimated)
   - context_window: usize (from config)
   - `add_message(msg: ChatMessage)` — adds and updates token estimate
   - `trim_to_budget()` — removes oldest non-system messages until under budget
   - `to_chat_messages() -> Vec<ChatMessage>` — returns messages for LLM request
   - `estimate_tokens(text: &str) -> usize` — heuristic: text.len() / 4

4. Concrete agent implementations:
   - `ResearcherAgent` — system prompt focused on OSINT/recon, allowed: [nmap, gobuster, shell]
   - `StrategistAgent` — system prompt for attack planning, allowed: [] (no tools, LLM reasoning only)
   - `ExecutorAgent` — system prompt for tool execution, allowed: [nmap, gobuster, shell] (all tools)
   - `AnalystAgent` — system prompt for result analysis, allowed: [shell] (for parsing)
   - `ReporterAgent` — system prompt for report generation, allowed: [] (no tools, LLM text generation)

5. `TaskContext` — shared state passed between agents by the Orchestrator:
   - target: String
   - findings: Vec<Finding>
   - scan_results: Vec<ToolResult>
   - agent_outputs: HashMap<AgentRole, String> (each agent's text output)
   - Serializable to inject into the next agent's conversation as context

6. Tests:
   - ConversationState trimming preserves system prompt
   - ConversationState token estimation
   - Each agent's system_prompt is non-empty
   - Each agent's allowed_tools matches expected set
   - TaskContext serialization round-trip

**Issue P2-4: Tool-Call Loop Engine**
Complexity: High
Crate: sigint-agents
Depends on: P2-1, P2-2

1. Core loop function:
   ```rust
   pub async fn run_tool_loop(
       provider: &dyn LlmProvider,
       state: &mut ConversationState,
       tools: &[&dyn Tool],
       tool_defs: &[ToolDefinition],
       max_iterations: usize,  // default 10
       event_bus: &EventBus,
   ) -> Result<String, Error>
   ```

2. Loop logic:
   - Build ChatRequest from state.to_chat_messages() + tool_defs
   - Send with `stream: false` (DEC-AGENT-006)
   - If response contains tool_calls:
     a. For each tool_call, find matching tool by name
     b. Emit ToolStarted event
     c. Execute tool via spawn_blocking
     d. Emit ToolOutput + ToolCompleted events
     e. Append assistant message (with tool_calls) + tool result messages to state
     f. Continue loop
   - If response contains text (no tool_calls): return text
   - If max_iterations exceeded: return accumulated text + warning

3. Error handling:
   - Tool execution failure -> append error as tool-role message, let LLM retry/adapt
   - Tool not found -> append "tool not available" message
   - LLM returns invalid tool_calls -> log warning, treat as text response
   - Ollama connection failure -> propagate error up

4. EventBus integration:
   - Emit Event::ToolStarted { name, args } before each tool execution
   - Emit Event::ToolOutput { name, output } with stdout
   - Emit Event::ToolCompleted { name, exit_code } after completion
   - Emit Event::Status for loop progress ("Iteration 3/10: executing nmap...")

5. Tests (with mock LlmProvider):
   - Single tool call -> execute -> text response (2-iteration loop)
   - Multiple sequential tool calls (3+ iterations)
   - Max iterations exceeded -> returns with warning
   - Tool execution failure -> error fed back to LLM
   - No tool_calls in first response -> immediate text return
   - Unknown tool name -> error message to LLM

**Issue P2-5: Orchestrator + Role-Based ACL**
Complexity: High
Crate: sigint-agents
Depends on: P2-3, P2-4

1. `ToolRegistry`:
   - `register(tool: Box<dyn Tool>)` — stores tool by name
   - `get(name: &str) -> Option<&dyn Tool>` — lookup
   - `definitions() -> Vec<ToolDefinition>` — all tool definitions
   - `for_role(role: AgentRole) -> (Vec<&dyn Tool>, Vec<ToolDefinition>)` — filtered by role's allowed tools

2. Role-based ACL:
   - Each Agent declares `allowed_tools() -> &[String]`
   - ToolRegistry.for_role() intersects agent's allowed_tools with registered tools
   - If agent's tool list is empty, no tools parameter sent to Ollama (text-only agent)

3. `Orchestrator`:
   ```rust
   pub struct Orchestrator {
       provider: Arc<dyn LlmProvider>,
       registry: ToolRegistry,
       event_bus: EventBus,
       context_window: usize,
   }

   impl Orchestrator {
       pub async fn run_scan(&self, target: &str) -> Result<ScanReport, Error> {
           let mut ctx = TaskContext::new(target);

           // Phase 1: Researcher gathers intel
           let recon_output = self.run_agent(ResearcherAgent, &mut ctx).await?;
           ctx.agent_outputs.insert(AgentRole::Researcher, recon_output);

           // Phase 2: Strategist plans attack based on recon
           let strategy = self.run_agent(StrategistAgent, &mut ctx).await?;
           ctx.agent_outputs.insert(AgentRole::Strategist, strategy);

           // Phase 3: Executor runs tools per strategy
           let exec_output = self.run_agent(ExecutorAgent, &mut ctx).await?;
           ctx.agent_outputs.insert(AgentRole::Executor, exec_output);

           // Phase 4: Analyst correlates findings
           let analysis = self.run_agent(AnalystAgent, &mut ctx).await?;
           ctx.agent_outputs.insert(AgentRole::Analyst, analysis);

           // Phase 5: Reporter compiles final report
           let report = self.run_agent(ReporterAgent, &mut ctx).await?;

           Ok(ScanReport { context: ctx, summary: report })
       }

       async fn run_agent(&self, agent: impl Agent, ctx: &mut TaskContext) -> Result<String, Error> {
           let mut state = ConversationState::new(self.context_window);
           state.add_message(ChatMessage::system(agent.system_prompt()));
           state.add_message(ChatMessage::user(&ctx.to_agent_prompt(&agent)));

           let (tools, defs) = self.registry.for_role(agent.role());
           run_tool_loop(&*self.provider, &mut state, &tools, &defs, 10, &self.event_bus).await
       }
   }
   ```

4. `ScanReport` struct:
   - context: TaskContext (all accumulated data)
   - summary: String (Reporter's output)
   - findings: Vec<Finding>
   - Display impl for stdout rendering

5. Tests:
   - ToolRegistry.for_role(Executor) returns all tools
   - ToolRegistry.for_role(Strategist) returns empty
   - Orchestrator with mock provider: verify agent dispatch order
   - Orchestrator passes context between agents

#### Tier 3 — CLI Integration (depends on Tier 1 + 2)

**Issue P2-6: `sigint scan <target>` CLI Command**
Complexity: Medium
Crate: sigint-cli
Depends on: P2-5

1. New `scan` subcommand in sigint-cli:
   ```rust
   /// Run a multi-agent penetration scan against a target.
   Scan(scan::ScanArgs)
   ```

2. `ScanArgs`:
   - target: String (positional, required)
   - `--ports` / `-p`: Optional port specification (passed to nmap)
   - `--model` / `-m`: Model override
   - `--max-iterations`: Max tool-call iterations per agent (default 10)

3. `scan::run()`:
   - Create Session with target
   - Initialize OllamaProvider from config
   - Initialize ToolRegistry, register NmapTool + ShellTool (+ GobusterTool if P1)
   - Create Orchestrator
   - Subscribe to EventBus, spawn task to print tool events to stdout
   - Run Orchestrator.run_scan(target)
   - Persist scan_history records for each tool execution
   - Print ScanReport to stdout
   - Stream final Reporter output for real-time display

4. scan_history persistence:
   - After each tool execution, insert into scan_history table
   - Fields: session_id, tool name, args (JSON), output, exit_code, started_at, finished_at

5. Tests:
   - ScanArgs parsing (clap derive)
   - Integration test (requires Ollama + sandbox): `#[ignore]` annotated
   - scan_history records created after mock scan

---

### Phase 3: TUI + Memory + Embeddings
**Status:** completed
**Sub-phases:** 3A (Store DAL) → 3B (Embeddings) + 3D (TUI) parallel → 3C (Memory) → 3E (Integration)
**Plan:** `docs/plans/2026-02-25-phase-3-implementation.md`
**Decisions:** DEC-P3-POOL, DEC-P3-QUERY, DEC-P3-TUI-001, DEC-P3-TUI-002, DEC-P3-TUI-003, DEC-P3-003, DEC-P3-001, DEC-P3-002, DEC-CLI-003

- [x] Sub-Phase 3A: Store DAL — r2d2 connection pool, FTS5 search, typed query builders, findings CRUD
- [x] Sub-Phase 3D: Ratatui TUI — AppState, 5-panel layout, event loop, isatty auto-detection
- [x] Sub-Phase 3B: Embeddings — EmbeddingService, vector CRUD, cosine UDF, semantic search, background worker
- [x] Sub-Phase 3C: Memory — MemoryService (episodic + semantic recall), token budget, orchestrator wiring
- [x] Sub-Phase 3E: Integration — sessions CLI (list/export/delete), memory+embedding wiring in scan, TUI help overlay

### Phase 4: Attack Surface Mapping
**Status:** completed
**Sub-phases:** 4A (Store) → 4B (Discovery) → 4C (Tools) → 4D (TUI+CLI)
**Plan:** `docs/plans/2026-03-01-phase5-web-ui-polish-design.md` (Phase 5 design includes Phase 4 context)
**Decisions:** DEC-ASM-001, DEC-RECON-001–008, DEC-TOOL-005–008, DEC-4D-STATE-001, DEC-4D-UI-001, DEC-4D-RECON-001–002

- [x] Sub-Phase 4A: Store layer — Asset/AssetService/AssetChange CRUD, 4 ASM events
- [x] Sub-Phase 4B: Discovery modules — DNS, port, web, cert, OSINT + correlator + change detector
- [x] Sub-Phase 4C: Offensive tools — gobuster, nikto, nuclei, feroxbuster + WebScanner/Bruteforce sandbox profiles
- [x] Sub-Phase 4D: TUI + CLI — Assets panel, `sigint recon <target>` subcommand

### Phase 5: Web UI + Polish
**Status:** completed
**Sub-phases:** 5A (Doctor) → 5B (OpenAI Provider) → 5C (Reports) → 5D (REST API) → 5E (SPA)
**Design:** `docs/plans/2026-03-01-phase5-web-ui-polish-design.md`
**Plan:** `docs/plans/2026-03-01-phase5-implementation.md`
**Decisions:** DEC-P5-DOCTOR, DEC-P5-OPENAI, DEC-LLM-005, DEC-P5-REPORT, DEC-REPORT-001, DEC-WEB-001–010

- [x] Sub-Phase 5A: `sigint doctor` — 6 health checks (config, Ollama, model, tools, sandbox, DB)
- [x] Sub-Phase 5B: OpenAI-compatible LLM provider + factory + SSE streaming
- [x] Sub-Phase 5C: Report generation (Markdown, HTML) with 3 templates + CLI command
- [x] Sub-Phase 5D: Axum REST API (8 routes) + WebSocket event bridge + `sigint serve`
- [x] Sub-Phase 5E: Embedded SPA frontend (Preact + HTM + rust-embed)

### Phase 6: Parsers, Approval Gates, Web Scan
**Status:** completed
**Sub-phases:** 6A (Parsers) → 6B (Approval) → 6C (Web Layer) → 6D (TUI + Frontend) → Web Scan Orchestrator
**Design:** `docs/plans/2026-03-01-phase6-hybrid-design.md`
**Plan:** `docs/plans/2026-03-01-phase6-implementation.md`
**Decisions:** DEC-TOOL-004, DEC-TOOL-007, DEC-AGENT-012, DEC-WEB-003, DEC-WEB-004, DEC-WEB-005, DEC-WEB-010, DEC-APPROVE-001, DEC-AGENT-015, DEC-AGENT-016, DEC-P6-APPROVAL-002, DEC-LLM-004, DEC-LLM-006

- [x] Sub-Phase 6A: nmap XML parser (quick-xml), nuclei JSONL parser → structured_data
- [x] Sub-Phase 6B: ToolRisk enum, ApprovalRegistry (oneshot channels), approval gate in loop engine
- [x] Sub-Phase 6C: Expanded AppState, bidirectional WebSocket (select!), POST /api/scan
- [x] Sub-Phase 6D: TUI approval prompt (y/n keys), Dashboard scan button, ScanView approval modal
- [x] Web Scan Orchestrator: ScanService with start/status/cancel/list, wired into web endpoints

### Phase 7: Scan Diff, Graceful Shutdown, E2E Testing
**Status:** completed
**Sub-phases:** 7A (Scan Diff) → 7B (E2E Integration Tests) → 7C (Graceful Shutdown)
**Design:** `docs/plans/2026-03-02-scan-diff-design.md`, `docs/plans/2026-03-02-e2e-integration-testing-design.md`
**Plan:** `docs/plans/2026-03-02-scan-diff-implementation.md`, `docs/plans/2026-03-02-e2e-integration-testing-implementation.md`
**Decisions:** DEC-DIFF-001, DEC-CLI-DIFF-001, DEC-WEB-002, DEC-CLI-005, DEC-WEB-007

- [x] Sub-Phase 7A: Scan diff engine (DiffResult/DiffEntry), GET /api/diff/{a}/{b}, `sigint diff` CLI subcommand
- [x] Sub-Phase 7B: E2E integration tests for diff endpoint, session lifecycle, health check
- [x] Sub-Phase 7C: Graceful shutdown — Ctrl-C emits Event::Shutdown; axum serve_with_shutdown

### Phase 8: Streaming Reasoning + Interactive TUI Sessions
**Status:** completed
**Decisions:** DEC-AGENT-007-REV, DEC-AGENT-018

- [x] Sub-Phase 8A: Streaming reasoning — AgentThinking/AgentThinkingDone events, chat_stream in tool loop, TUI live reasoning buffer
- [x] Sub-Phase 8B: Interactive TUI sessions — InteractiveSession struct, parse_command, UserInput routing to Orchestrator

### Phase 9: Session Intelligence & Campaign Mode
**Status:** completed
**Decision IDs:** DEC-RESUME-001, DEC-RESUME-002, DEC-CAMPAIGN-001, DEC-CAMPAIGN-002, DEC-DIFF-UI-001, DEC-REPORT-003
**Requirements:** REQ-P0-001 through REQ-P0-007 (see design doc)
**Design:** `docs/plans/2026-03-21-phase9-design.md`
**Definition of Done:**
- REQ-P0-001 satisfied: `sigint resume <prefix>` re-scans target and prints diff summary
- REQ-P0-004 satisfied: TUI Findings panel shows green/dim+strikethrough/default diff colors
- REQ-P0-005 satisfied: `sigint campaign run --file targets.json` scans all targets sequentially with aggregated output
- REQ-P0-007 satisfied: Profile templates adjust tools and agent prompts without code changes

### Planned Decisions
- DEC-RESUME-001: Resume creates new session with parent_session_id FK, auto-diffs after scan — Addresses: REQ-P0-001, REQ-P0-002
- DEC-RESUME-002: UUID prefix matching via client-side filter on list_sessions() — Addresses: REQ-P0-002
- DEC-CAMPAIGN-001: Campaign file is flat JSON with named profiles and target references — Addresses: REQ-P0-005, REQ-P0-006, REQ-P0-007
- DEC-CAMPAIGN-002: Campaign state stored via campaigns table with campaign_id FK on sessions — Addresses: REQ-P0-005, REQ-P1-001
- DEC-DIFF-UI-001: Diff results emitted as Event::ScanDiffCompleted for TUI/Web rendering — Addresses: REQ-P0-004
- DEC-REPORT-003: Campaign report reuses ReportData with cross-target aggregation wrapper — Addresses: REQ-P1-001

Sub-phases:
- [x] Sub-Phase 9A: Session Resume + Diff UI — resume CLI, UUID prefix match, parent_session_id, TUI diff colors, ScanDiffCompleted event
- [x] Sub-Phase 9B: Multi-Target Campaign Mode — campaign CLI, JSON file parsing, profile templates, sequential execution, campaign DB table
- [x] Sub-Phase 9C: Report Polish + Risk Scoring — executive summary, cvss_score field, campaign aggregated reports, HTML SVG pie chart

### Decision Log
<!-- Guardian appends here after phase completion -->

## Architectural Decisions

| ID | Decision | Status | Rationale |
|----|----------|--------|-----------|
| DEC-ARCH-001 | Single Rust binary | accepted | Eliminates Docker dependency, simplifies deployment |
| DEC-ARCH-002 | Cargo workspace with 10 crates | accepted | Clean separation of concerns, parallel compilation |
| DEC-STORE-001 | SQLite bundled (not external DB) | accepted | Zero-config, single file, portable |
| DEC-SAND-001 | hakoniwa for sandboxing | accepted | Native Linux namespaces, no Docker overhead |
| DEC-LLM-001 | Ollama-first, cloud fallback | accepted | Local-first privacy, cloud for capability |
| DEC-EMBED-001 | fastembed with all-MiniLM-L6-v2 | deprecated | Superseded by DEC-P3-002 which is annotated in sigint-memory |
| DEC-SAND-002 | Generic SandboxedCommand builder | accepted | Consuming builder over hakoniwa's &mut self API; tool-agnostic, profiles specialize |
| DEC-SAND-003 | Runtime capability detection via /proc | accepted | Probes namespaces + AppArmor + PATH at runtime for actionable error messages |
| DEC-SAND-004 | Per-tool sandbox profiles | accepted | Nmap (Pasta + 300s) and Offline (None + 60s) presets; extensible for future tools |
| DEC-SAND-005 | Integration tests against real namespaces | accepted | No mocking OS primitives; nmap test #[ignore] for CI without passt/network |
| DEC-AGENT-001 | Ollama native tool calling | accepted | /api/chat tools parameter with OpenAI-compatible JSON Schema; internal parser handles malformed output; 8B ~89% accuracy |
| DEC-AGENT-002 | Full 5-role multi-agent Orchestrator | accepted | Orchestrator dispatches to Researcher/Strategist/Executor/Analyst/Reporter in sequence; TaskContext carries state between agents |
| DEC-AGENT-003 | Tool trait with JSON Schema definition | accepted | Tools declare definition() -> ToolDefinition passed to Ollama; execute(Value) -> ToolResult |
| DEC-AGENT-004 | spawn_blocking for tool execution | accepted | hakoniwa fork(2) incompatible with tokio; consistent with DEC-SAND-002 |
| DEC-AGENT-005 | Context window mgmt via token heuristic | accepted | 4 chars ~= 1 token; calibrated by Ollama response counts; trim oldest non-system messages |
| DEC-AGENT-006 | Non-streaming tool loop, streaming final text | accepted | stream:false during tool iterations; streaming for final user-facing response |
| DEC-HOTFIX-001 | Bare command path resolution via `which` | deprecated | Operational fix documented in commit history; absorbed into DEC-SAND-006 which is annotated in sandbox/command.rs |
| DEC-HOTFIX-002 | DNS via /etc/resolv.conf bind-mount | deprecated | Operational fix documented in commit history; absorbed into DEC-SAND-004 profile annotations |
| DEC-HOTFIX-003 | Nmap ACL name standardization | deprecated | Operational fix documented in commit history; resolved in tool registry |
| DEC-HOTFIX-004 | /dev mount for Pasta sandbox | deprecated | Operational fix documented in commit history; absorbed into DEC-SAND-004 profile annotations |
| DEC-HOTFIX-005 | ShellTool combined-command splitting | deprecated | Operational fix documented in commit history; absorbed into DEC-TOOL-005 ShellTool annotations |
| DEC-LLM-002 | Tool-calling types use OpenAI-compatible JSON Schema | accepted | Ollama tool API is OpenAI-compatible; same ToolDefinition/ToolCall shapes work with any OpenAI-compatible provider added later without conversion |
| DEC-LLM-003 | Tool calls threaded through OllamaMessage, accumulated in streaming | accepted | Ollama embeds tool_calls in the message object; for streaming they appear only on the final done=true chunk, propagated via StreamChunk.tool_calls |
| DEC-STORE-002 | ScanRecord as denormalized row — one row per tool invocation | accepted | Per-tool rows enable per-tool queries, exit_code filtering, and future diff across scans; args as JSON for readability without a separate table |
| DEC-STORE-003 | Findings with severity TEXT and optional asset/evidence columns | accepted | Severity stored as TEXT matching the CHECK constraint pattern; asset and evidence are nullable TEXT; CASCADE DELETE on session_id |
| DEC-STORE-FTS | Standalone FTS5 with UUID source_id instead of external-content tables | accepted | FTS5 content_rowid requires INTEGER; UUIDs are TEXT so external-content was infeasible; standalone FTS5 with UNINDEXED source_id column used instead |
| DEC-P3-POOL | r2d2 connection pool replaces Mutex<Connection> | accepted | WAL mode + pool enables concurrent reads from TUI and agents without mutex contention; in-memory DBs use max_size(1) to avoid N independent schemas |
| DEC-P3-QUERY | Typed query builders replace ad-hoc SQL string construction | accepted | Builder pattern makes filters, pagination, and ordering composable without exposing raw SQL; builders borrow Database to ensure pool outlives query |
| DEC-P3-002 | fastembed always-on with all-MiniLM-L6-v2 (384-dim) | accepted | Local CPU inference via ONNX Runtime; vectors stored as raw f32 bytes via bytemuck::cast_slice — zero-copy with no schema overhead |
| DEC-AGENT-007 | Non-streaming chat() for all tool-loop iterations | accepted | Tool calls require complete JSON; streaming adds latency and complexity with no user-visible benefit during intermediate iterations |
| DEC-AGENT-008 | Event emission is best-effort; errors silently discarded | accepted | EventBus::emit already silences send errors; tool execution is the critical path, event delivery is observability-only |
| DEC-AGENT-009 | Unknown tool name feeds error message back to LLM | accepted | Silently skipping hallucinated tool names leaves the model in inconsistent state; explicit error as tool-role turn lets model recover gracefully |
| DEC-AGENT-010 | Analyst allowed tools: shell only | accepted | Analyst post-processes tool output via shell (grep, jq, awk); no network or scan tools needed in analysis phase |
| DEC-AGENT-011 | ToolRegistry owns Box<dyn Tool>; for_agent returns borrowed slices | accepted | Boxed ownership means tools outlive any agent turn; borrowed references avoid Arc overhead on the hot path (tool lookup per loop iteration) |
| DEC-AGENT-012 | ScanReport is plain data struct with Display; no builder pattern | accepted | Always constructed in one step at end of run_scan; plain struct avoids builder complexity tax; fmt::Display serves CLI stdout primary path |
| DEC-AGENT-013 | Agents instantiated locally in run_scan, not stored as fields | accepted | Agent structs are stateless identity objects; local instantiation is zero-cost (stack), keeps Orchestrator lean, makes pipeline order explicit |
| DEC-AGENT-014 | Orchestrator holds Arc<dyn LlmProvider> for cheap Clone across agent turns | accepted | Arc avoids lifetime parameters on Orchestrator struct; enables future parallel agent dispatch via fan-out |
| DEC-SAND-006 | Resolve bare commands to absolute paths before execve | accepted | hakoniwa uses raw execve() not execvp(); bare names fail with ENOENT; resolved at build time via SANDBOX_PATH search |
| DEC-TOOL-001 | Crate-local ToolError for tool-specific failure modes | accepted | Isolates tool errors from sigint-core Error type |
| DEC-TOOL-002 | ToolResult mirrors SandboxOutput with optional structured data | accepted | Consistent with SandboxOutput; structured_data for parsed output |
| DEC-TOOL-003 | async_trait for object-safe async Tool methods | accepted | async fn in traits requires async-trait for dyn dispatch |
| DEC-TOOL-004 | NmapTool uses SandboxProfile::nmap() for pasta networking | accepted | Nmap needs network; pasta provides isolated network namespace |
| DEC-TOOL-005 | ShellTool uses static allowlist and offline sandbox profile | accepted | Static allowlist of read-only commands prevents LLM from issuing destructive shell commands; offline sandbox prevents network egress |
| DEC-CLI-001 | scan command uses best-effort database persistence | accepted | Scan against live target must not fail due to DB unavailability; all db.* calls wrapped in if-let or warned; stdout output always printed |
| DEC-CLI-002 | Event display runs in detached tokio task; scan does not block on it | accepted | EventBus receiver loop must not block orchestrator.run_scan; tokio::spawn creates concurrent reader; task exits naturally when broadcast channel closes |
| DEC-P3-TUI-001 | AppState as single source of truth for TUI rendering | accepted | All mutable TUI state lives in AppState; event loop receives Events from broadcast bus and applies pure state transitions; render() reads AppState without mutation |
| DEC-P3-TUI-002 | render() is a pure function of AppState with no side effects | accepted | Pure render function (AppState -> Frame writes) enables full layout testing via ratatui TestBackend without a real terminal; 5-panel layout uses Constraint::Percentage + Constraint::Length for deterministic sizing |
| DEC-P3-TUI-003 | TuiApp separates terminal I/O from state; state lives in AppState | accepted | Terminal setup/teardown and event loop are inherently impure (raw mode, alternate screen, panic hooks); isolating in app.rs lets state.rs and ui.rs remain pure and fully unit-testable |
| DEC-P3-003 | TUI auto-detected via isatty(stdout); --tui/--no-tui override | accepted | When stdout is a TTY the user is interactive — show TUI; when piped or in CI fall back to stdout event printer; flags override heuristic for scripting and testing |
| DEC-P3-001 | sigint-memory as separate crate | accepted | Memory subsystem (retrieval + prompt injection) is independently testable without LLM provider; avoids circular dependency agents → memory → store; sigint-agents gains soft dep at Orchestrator level only |
| DEC-WEB-002 | Bidirectional WebSocket using tokio::select! | accepted | Original send-only loop replaced with select! over broadcast::Receiver and StreamExt; client messages (approval y/n, scan requests) flow back through event bus |
| DEC-WEB-003 | AppState carries config, approval_registry, and scan_service | accepted | Web layer needs config for default model/timeouts, approval_registry to route y/n responses, and scan_service to start/cancel scans initiated from the browser |
| DEC-WEB-005 | start_scan delegates fully to ScanService::start() | accepted | Previously start_scan created its own session and emitted events directly; centralised in ScanService to share logic with TUI and CLI paths |
| DEC-WEB-010 | rust-embed for compile-time asset embedding with mime_guess | accepted | Embedding static assets at compile time produces a single binary with no external file dependencies; mime_guess maps extension to Content-Type without a lookup table |
| DEC-APPROVE-001 | std::sync::Mutex + tokio::sync::oneshot for approval registry | accepted | oneshot channels are the idiomatic Tokio primitive for single-response request/reply; Mutex<HashMap> is sufficient since approval lookups are infrequent |
| DEC-AGENT-015 | Per-tool scan record persistence is opt-in via Option<&Database> | accepted | Tool loop tests and non-CLI callers don't always have a database; Option keeps the loop backward-compatible without requiring a dummy DB |
| DEC-AGENT-016 | Orchestrator holds Option<Arc<Database>> + session_id for per-tool persistence | accepted | Database is optional because not all callers (tests, web scan service) provide one; Arc avoids lifetime parameters on Orchestrator struct |
| DEC-P6-APPROVAL-002 | Approval bar occupies a conditional 1-row slot at the very bottom of the TUI | accepted | Must be impossible to miss; placed below all content panels; disappears when no approval is pending to avoid wasted screen space |
| DEC-LLM-004 | OpenAI-compatible provider with manual SSE parsing | accepted | OpenAI /v1/chat/completions is the de-facto standard for hosted LLMs; manual SSE parsing avoids adding an eventsource crate dependency |
| DEC-LLM-006 | Centralised provider factory for all LLM backends | accepted | Single create_provider function maps Config fields to the correct provider; eliminates duplicate construction logic across CLI and web callers |
| DEC-ASM-001 | Asset store uses SELECT-then-INSERT for upsert, no UPSERT SQL | accepted | assets table has no UNIQUE constraint; INSERT OR REPLACE would silently create duplicates on schema drift; explicit SELECT-then-INSERT is safe and auditable |
| DEC-DIFF-001 | Match findings by (title.to_lowercase(), asset) as cross-session key | accepted | Finding IDs are per-session UUIDs and cannot be compared across sessions; (title, asset) is a stable logical identity; severity/description changes are tracked as mutations |
| DEC-CLI-DIFF-001 | CLI diff uses direct DB access, not HTTP API | accepted | CLI binary already has sigint-store as a dependency; direct DB access avoids requiring a running server and keeps diff fast and offline-capable |
| DEC-CLI-005 | report command accepts UUID prefix for session_id | accepted | Full UUIDs are 36 characters and hard to type; prefix matching (≥4 chars) makes interactive use comfortable without risk of collision in practice |
| DEC-CLI-006 | serve subcommand uses serve_with_shutdown for clean Ctrl-C teardown | accepted | Without a shutdown signal axum keeps accepting connections until the OS kills the process; serve_with_shutdown + ctrl_c() lets axum drain open connections and emits Event::Shutdown to all bus subscribers |
| DEC-WEB-007 | serve_with_shutdown accepts a generic Future<Output=()> for axum graceful shutdown | accepted | Axum's with_graceful_shutdown takes a caller-supplied future; wrapping in a separate function keeps the existing serve signature stable while enabling clean Ctrl-C support |
| DEC-DOCTOR-001 | Synchronous checks for PATH/config, async HTTP for Ollama | accepted | Config, PATH, and DB checks are all local and synchronous; only Ollama reachability requires an HTTP call via reqwest |
| DEC-RECON-002 | Port module uses nmap via SandboxProfile::nmap() (pasta networking) | accepted | nmap requires real network connectivity; SandboxProfile::Nmap provides isolated network namespace via pasta |
| DEC-RECON-003 | Web module uses curl -sI (HEAD) via sandbox for HTTP fingerprinting | accepted | curl HEAD requests capture response headers without downloading body; sandboxed to prevent host filesystem access |
| DEC-RECON-004 | Cert module uses reqwest to query crt.sh JSON API | accepted | crt.sh is a TLS-protected JSON API; reqwest avoids sandbox overhead for outbound HTTPS calls |
| DEC-RECON-005 | OSINT module uses whois via SandboxProfile::recon() with key parsing | accepted | whois provides registrant info and nameservers; sandbox prevents abuse of the process |
| DEC-RECON-006 | Correlator deduplicates by (kind, value) and enriches metadata with relationships | accepted | Multiple discovery modules may return the same asset; deduplication by (kind, value) is the minimal correct key |
| DEC-RECON-007 | Change detector compares metadata JSON blobs as strings | accepted | Full JSON diffing would require recursive tree walking; string comparison is sufficient for change detection at this scale |
| DEC-RECON-008 | ReconEngine orchestrates modules sequentially with best-effort error handling | accepted | Sequential execution simplifies backpressure and timeout tracking; individual module errors are logged but do not abort the run |
| DEC-REPORT-002 | pulldown-cmark for Markdown-to-HTML rendering | accepted | de-facto Rust Markdown parser; CommonMark-compliant, handles tables and fenced code blocks needed for scan reports |
| DEC-TOOL-006 | NiktoTool uses SandboxProfile::web_scanner() for pasta networking | accepted | nikto is a comprehensive web scanner requiring network access; web_scanner profile provides pasta networking with appropriate timeout |
| DEC-TOOL-008 | FeroxbusterTool uses SandboxProfile::bruteforce() for pasta networking | accepted | feroxbuster is a Rust-native recursive content-discovery tool; bruteforce sandbox profile provides pasta networking |
| DEC-TOOL-007 | NucleiTool uses SandboxProfile::web_scanner() for pasta networking | accepted | nuclei runs community-authored YAML templates against targets; web_scanner sandbox profile provides pasta networking with appropriate timeout |
| DEC-4D-RECON-001 | recon command uses best-effort persistence matching scan.rs pattern | accepted | Consistent with DEC-CLI-001: recon run must not fail because DB is unavailable; all DB calls wrapped best-effort; output always shown |
| DEC-4D-STATE-001 | Assets panel added as fifth panel in the TUI Tab cycle | accepted | Phase 4D ASM assets need a dedicated panel; placed between Findings and Input in Tab cycle to keep asset data visually separate from findings |
| DEC-4D-UI-001 | Findings and Assets share the bottom row as a 50/50 horizontal split | accepted | Both panels have comparable data density at MVP scale; 50/50 split avoids privileging one over the other and can be adjusted later |
| DEC-LLM-005 | OpenAI arguments field deserialized as String then re-parsed | accepted | OpenAI sends tool call arguments as a JSON-encoded string, not a nested object; deserialize as String then from_str to Value avoids double-nesting |
| DEC-RECON-001 | DNS module uses dig via SandboxProfile::recon() with spawn_blocking | accepted | dig is a fast, reliable DNS resolver; recon sandbox profile provides pasta networking so dig reaches real DNS servers while remaining isolated |
| DEC-REPORT-001 | Report builder is pure Rust with no template engine dependency | accepted | Plain Rust string formatting avoids pulling in Tera/Handlebars which would add compile time and contributor friction; output quality is equal for structured reports |
| DEC-WEB-001 | REST handlers are thin wrappers over store CRUD with no business logic | accepted | Web layer is a presentation concern only; all persistence and domain logic lives in sigint-store and sigint-core; keeps handlers testable via tower oneshot |
| DEC-AGENT-018 | InteractiveSession as EventBus consumer for TUI input routing | accepted | Orchestrator stays unchanged — run_scan() still takes a target string; InteractiveSession bridges the event-driven TUI world to the Orchestrator's imperative API; parse_command extracted as pure function for unit testing without a live provider |
| DEC-RESUME-001 | Resume creates new session with parent_session_id FK, auto-diffs | accepted | New session preserves temporal record; parent link enables chain-of-scans visualization; diff engine reused from Phase 7A |
| DEC-RESUME-002 | UUID prefix matching via client-side filter on list_sessions() | accepted | Reuses existing list_sessions(); session count is small enough for client-side filter; matches pattern from DEC-CLI-005 |
| DEC-CAMPAIGN-001 | Campaign file is flat JSON with named profiles and target references | accepted | Self-contained JSON is easy to version-control and validate; profiles extensible via serde(default) without code changes |
| DEC-CAMPAIGN-002 | Campaign state stored via campaigns table with campaign_id FK | accepted | Enables aggregated reporting and status queries; nullable FK preserves non-campaign sessions |
| DEC-DIFF-UI-001 | Diff results emitted as Event::ScanDiffCompleted variant | accepted | Consistent with event-driven architecture; ScanDiff already derives Serialize; TUI and Web both receive via EventBus |
| DEC-REPORT-003 | Campaign report reuses ReportData with cross-target aggregation wrapper | accepted | Reuses all existing report infrastructure; overview section aggregates severity counts; per-target detail rendered by existing builder |
| DEC-E2E-001 | E2E tests use real Axum server on random port with in-memory SQLite | accepted | Testing against a real running server catches integration issues (routing, middleware, serialization) that unit tests miss; in-memory SQLite keeps tests hermetic |
| DEC-E2E-002 | Session CRUD E2E tests cover empty list, 404 on missing, and bad UUID | accepted | Full HTTP stack verification for session endpoints: routing, UUID parsing, database queries, and JSON serialization |
| DEC-E2E-003 | Scan lifecycle E2E tests cover start, status, list, cancel, and session creation | accepted | Full HTTP stack verification for scan endpoints: POST /api/scan returns 201, GET /api/scan/{id}/status returns scan state |
| DEC-E2E-004 | Diff E2E tests use start_server_with_db() to seed findings before HTTP calls | accepted | Diff endpoint requires pre-existing findings in two sessions; start_server_with_db() helper retains DB handle so test can insert seed data before HTTP calls |
| DEC-AKAEI-001 | akaei tools bypass sandbox — use tokio::process::Command with timeout | accepted | USB device access (HackRF via libusb) breaks Linux user namespace isolation; direct tokio process is the safe path for hardware-touching tools |
| DEC-AKAEI-002 | Per-command output parsers — JSON-lines, text, tab-separated | accepted | akaei subcommands emit heterogeneous formats; per-tool parsers are simpler and independently testable than a universal discriminated union |
| DEC-AKAEI-003 | RfRecon agent runs optionally before Researcher — feature-detected via registry | accepted | When no akaei tools are registered (no HackRF) the RF phase is silently skipped; pipeline degrades gracefully to existing 5-role flow |
| DEC-TUI-002 | Redirect tracing output to log file when TUI is active | accepted | ratatui occupies the alternate screen buffer on stderr; tracing lines written to stderr corrupt TUI rendering; redirect to ~/.local/share/sigint/sigint.log when TUI detected |
| DEC-TUI-BUG-001 | TerminalGuard drop-guard ensures terminal is restored on all exit paths | accepted | Explicit restore_terminal() handles normal returns; panic hook handles panics; TerminalGuard adds a third layer via Drop for future code paths that bypass both |
| DEC-TUI-BUG-002 | Resize events consumed and redrawn immediately via the normal render cycle | accepted | crossterm emits CEvent::Resize(w,h); ratatui's Terminal::draw() queries current area on each call so no explicit size update needed; consuming the event prevents spurious state changes |
| DEC-TUI-BUG3-001 | TUI lifecycle fix — terminal restored before tokio runtime exits | accepted | Terminal raw mode must be disabled before the process exits regardless of scan outcome; TerminalGuard ensures this even when run() returns an error |
| DEC-P6-APPROVAL-001 | PendingApproval held in AppState; approval responses emitted by app.rs | accepted | AppState remains a pure data structure with no channel handles; apply() records pending approvals; app.rs reads and emits responses then clears pending_approval |
| DEC-RESUME-002 | UUID prefix matching via client-side filter on list_sessions() | accepted | Reuses existing list_sessions(); session count is small enough for client-side filter; matches pattern from DEC-CLI-005 |
| DEC-DIFF-UI-001 | Diff results emitted as Event::ScanDiffCompleted variant | accepted | Consistent with event-driven architecture; ScanDiff already derives Serialize; TUI and Web both receive via EventBus |
| DEC-REPORT-003 | Campaign report reuses ReportData with cross-target aggregation wrapper | accepted | Reuses all existing report infrastructure; overview section aggregates severity counts; per-target detail rendered by existing builder |
| DEC-FINDING-001 | Use create_finding tool call (not text parsing) to extract structured findings | accepted | Text parsing is brittle against model drift and provides no validation at generation time; a tool call validates severity enum immediately, gives the LLM correctable feedback, and uses a shared Arc<Mutex<Vec<Value>>> collector drained by the orchestrator after the Analyst agent completes |
| DEC-LLM-007 | Accumulate tool_calls from all stream chunks, not just done=true | accepted | Ollama sends tool_calls on the content chunk (done=false), not the final metadata chunk (done=true); extending rather than replacing the accumulator collects tool calls from any chunk position |
| DEC-AGENT-007-REV | Streaming (chat_stream()) for all tool-loop iterations (Phase 8A) | accepted | Switched from non-streaming chat() to chat_stream() so incremental tokens emit AgentThinking events; tool calls still accumulate across all chunks per DEC-LLM-007 |
| DEC-LOG-001 | sigint log renders chronological audit trail from scan_history with agent attribution | accepted | Operators need a timestamped audit trail showing which agent invoked which tool with what args and output; chronological rendering from scan_history ordered by started_at; agent_role column (migration 7) attributes each tool call to a role without denormalizing the data model |
| DEC-LOOP-001 | Researcher runs once; loop wraps Strategist/Executor/Analyst | accepted | Recon results don't change between iterations; re-running wastes tokens. Phase 12C. |
| DEC-LOOP-002 | Convergence = no new findings OR goal keyword match (heuristic) | accepted | LLM-judged convergence adds latency and cost; heuristic sufficient for v1. Phase 12C. |
| DEC-LOOP-003 | max_cycles defaults to 1 for backward compatibility | accepted | Existing tests and workflows unaffected; --max-cycles N opts into iterative mode. Phase 12C. |
| DEC-LOOP-004 | Escalation detected via string marker in Strategist output | accepted | Strategist is tool-free (DEC-AGENT-008); adding a tool would violate that design; string markers are parsed by the orchestrator. Phase 12A/12E. |
| DEC-LOOP-005 | Evidence linking via post-processing DB query after Executor | accepted | Analyst needs all Executor records, not just the latest; DB query is cleaner than plumbing IDs through the tool loop. Phase 12D. |
| DEC-LOOP-006 | Per-cycle agent_output clearing for Strategist/Executor/Analyst; Researcher preserved | accepted | Prevents stale context from polluting re-planning; Researcher output is stable across cycles. Phase 12C. |
| DEC-FINDING-002 | Phase 12B enrichment fields are optional in both schema and execute() | accepted | All five new fields (remediation, exploitability, impact, cvss_score, evidence_ref) are optional so existing calls without them continue to work; CVSS score is the only field with a validation constraint (0.0–10.0) because out-of-range values indicate a model error worth surfacing immediately. Phase 12B. |
| DEC-AGENT-017 | Convergence loop uses max_cycles=1 default to preserve backward compatibility | accepted | The iterative Strategist→Executor→Analyst loop must not change behavior for existing callers; max_cycles=1 preserves single-pass behavior; iterative mode opt-in via --max-cycles N. Phase 12C. |
| DEC-P13-001 | Three-state scan status (Complete/TimedOut/Partial) provides tool-agnostic completion metadata | accepted | Agents can reason about coverage gaps without tool-specific logic; TimedOut preserves partial output; Partial carries human-readable reason; default Complete requires no change at existing construction sites. Phase 13D-prereq. |
| DEC-P13-002 | 1MB default output cap prevents OOM from unbounded tool output while preserving enough data for meaningful analysis | accepted | Sandbox-level cap applied after capture; TruncationInfo records original_bytes and kept_bytes so the agent knows how much was dropped; 1MB chosen as sufficient for most tool output while bounding memory use. Phase 13D-prereq. |

### Phase 10: akaei SDR Integration
**Status:** completed
**Sub-phases:** 10A (Tool Wrappers) → 10B (RfRecon Agent)
**Plan:** `~/.claude/plans/quiet-fluttering-perlis.md`
**Decision IDs:** DEC-AKAEI-001, DEC-AKAEI-002, DEC-AKAEI-003

- [x] Sub-Phase 10A: 7 akaei tool wrappers (sweep, decode, analyze, audit, fingerprint, scan, freqdb) + doctor entry
- [x] Sub-Phase 10B: RfRecon agent role, context threading, optional orchestrator RF phase

---

### Phase 12: Iterative Convergence + Finding Intelligence
**Status:** completed
**Sub-phases:** 12A (Finding Model) → 12B (CreateFindingTool) → 12C (Convergence Loop) → 12D (Evidence Linking) → 12E (Escalation Gates)
**Plan:** `~/.claude/plans/bright-hopping-matsumoto.md`
**Decision IDs:** DEC-LOOP-001, DEC-LOOP-002, DEC-LOOP-003, DEC-LOOP-004, DEC-LOOP-005, DEC-LOOP-006, DEC-FINDING-002
**Definition of Done:**
- Linear pipeline transformed into goal-driven convergence loop
- `--max-cycles` and `--goal` CLI flags control iteration behavior
- Finding model enriched with remediation, exploitability, impact, evidence_ref, CVSS score, attack chain grouping
- CreateFindingTool schema extended with all enrichment fields + CVSS validation
- Evidence linking: Analyst context includes scan_history record references for proof traceability
- `--approval-gates` flag enables escalation tier detection and user approval at tier transitions
- All non-integration tests pass

- [x] Sub-Phase 12A: Enhanced Finding model + Migration 8 — 6 new fields on Finding, EscalationTier enum, migration 8 (6 ALTER TABLE columns)
- [x] Sub-Phase 12B: Enhanced CreateFindingTool — 5 optional enrichment properties, CVSS range validation, Analyst prompt enrichment
- [x] Sub-Phase 12C: Convergence Loop — run_inner_cycle extraction, is_converged heuristic, CycleCompleted events, --max-cycles/--goal CLI
- [x] Sub-Phase 12D: Evidence Linking — get_scan_records_by_role query, scan_record_refs in Analyst context, evidence_ref validation
- [x] Sub-Phase 12E: Approval-Gated Escalation — detect_tier parsing, approval_gates toggle, EscalationRequested/Approved/Denied events, --approval-gates CLI

---

### Phase 11: Findings Extraction + Engagement Log
**Status:** completed
**Sub-phases:** 11A (CreateFindingTool) → 11B (Orchestrator wiring) → 11C (Persistence) → 11D (sigint log command)
**Decision IDs:** DEC-FINDING-001, DEC-STORE-003, DEC-LOG-001
**Definition of Done:**
- `create_finding` tool registered in the tool catalog and accessible to the Analyst
- Analyst system prompt instructs the LLM to call `create_finding` for each vulnerability
- Orchestrator drains the finding collector into `ctx.findings` after the Analyst completes
- `FindingCreated` events emitted via the event bus for each finding
- `persist_scan()` in sigint-cli persists findings to the database findings table
- `sigint log <session-id>` renders chronological audit trail with agent attribution
- All non-integration tests pass

- [x] Sub-Phase 11A: `CreateFindingTool` in `sigint-tools/src/finding.rs` — in-memory tool with `FindingCollector` (Arc<Mutex<Vec<Value>>>), severity validation, structured output
- [x] Sub-Phase 11B: Analyst agent updated (allowed_tools + system prompt); Orchestrator wires collector into `run_scan`, drains findings into `ctx.findings`, emits `FindingCreated` events
- [x] Sub-Phase 11C: `persist_scan()` in sigint-cli persists `ctx.findings` to the database
- [x] Sub-Phase 11D: `sigint log <session-id>` command — migration 7 adds `agent_role` to scan_history; CLI renders chronological engagement log (Markdown/HTML) with per-agent tool attribution and findings summary

---

### Phase 13: Live Target Hardening
**Status:** in-progress
**Sub-phases:** 13D-prereq (Foundation Types) → 13A (nmap) → 13B (gobuster) → 13C (other tools)
**Decision IDs:** DEC-P13-001, DEC-P13-002
**Definition of Done:**
- `ScanStatus` enum (Complete/TimedOut/Partial) added to `sigint-tools`
- `TruncationInfo` struct added to `sigint-tools`
- `ToolResult` carries `status` and `truncation` fields with backward-compatible defaults
- Sandbox output cap (`max_output_bytes`) wired through `SandboxedCommand` → `SandboxOutput` → `ToolResult.truncation`
- All existing tests pass; new unit tests cover each status variant and truncation path
- Tool-specific hardening (timeout recovery, real-target robustness) addressed in subsequent sub-phases

- [ ] Sub-Phase 13D-prereq: Foundation types — ScanStatus, TruncationInfo, ToolResult new fields, sandbox output cap, timeout investigation

---

## References

- Ollama /api/chat docs: https://github.com/ollama/ollama/blob/main/docs/api.md
- Ollama tool calling: https://docs.ollama.com/capabilities/tool-calling
- Ollama streaming tool calls: https://ollama.com/blog/streaming-tool
- hakoniwa crate: https://docs.rs/hakoniwa
- Research report: `.claude/research/DeepResearch_Ollama_Tool_Calling_API_2026-02-23/report.md`
- Research log: `.claude/research-log.md`

## Risks

1. **Ollama tool calling reliability** — Local 8B models achieve ~89% accuracy on tool calls; complex multi-tool scenarios may fail. Mitigation: error messages fed back to LLM for retry; max-iterations guard. (high risk)
2. **Sandbox reliability** — hakoniwa isolating nmap with network restrictions. Mitigated by Phase 1 integration tests. (medium risk, reduced from Phase 1)
3. **Multi-agent context accumulation** — 5 agents each consuming context window budget. Mitigation: each agent gets fresh ConversationState; TaskContext is a compact summary, not full history. (medium risk)
4. **Binary size** — fastembed ONNX runtime may push binary past 100MB. Mitigation: feature flags. (medium risk, deferred to Phase 3)

## Worktree Strategy

Main is sacred. Phase 2 implementation happens in a feature worktree:
- Branch: `feature/phase-2-agents`
- Worktree: `.claude/worktrees/phase-2-agents`
- Merge to main only after all Phase 2 tests pass
