# MASTER_PLAN.md — SIGINT: AI-Powered Penetration Testing Tool

## Project Overview

**Type:** CLI / security tool
**Languages:** Rust (100%)
**Root:** /home/j/sigint

**SIGINT** is a single-binary AI-powered penetration testing tool built in Rust. It replaces overengineered multi-container pentest orchestrators (like PentAGI) with a local-first design: embedded SQLite, local LLM via Ollama, native Linux sandboxing via hakoniwa, and continuous attack surface mapping.

**Architecture:** Cargo workspace with 12 crates, shared `AppCore` backend, dual interface (TUI + Web), 6-role agent system with Orchestrator dispatch (5 core + optional RfRecon).

**Current Phase:** Phase 23 completed — Model fine-tuning pipeline (sigint-train crate: dataset extraction, format conversion, train/val split, Modelfile generation, assessment). Phase 24 planned — close the fine-tune loop (harvest opt-in → train shell-out → live A/B evaluate → promote/rollback).

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
- Phase 13 completed — live target hardening: ScanStatus/TruncationInfo foundation types, sandbox output cap, nmap/gobuster/feroxbuster/nikto/nuclei/shell hardening
- Phase 14 completed — agent intelligence: memory wiring, Strategist overhaul with MITRE ATT&CK, recon integration, asset-finding linking, configurable output caps
- Phase 15A completed — tool expansion: sqlmap (SQL injection), ffuf (web fuzzing), whatweb (tech fingerprinting)
- Phase 15B completed — auth/exploitation tools: hydra (brute-force), wpscan (WordPress), testssl (TLS analysis), hashcat (hash cracking)
- Phase 15C completed — network/infrastructure tools: masscan (fast port scanning), tshark (packet capture), responder (LLMNR/NBT-NS credential capture)
- Phase 15D completed — post-exploitation tools: msfconsole (Metasploit Framework), linpeas (privilege escalation enumeration), enum4linux-ng (SMB enumeration)
- Phase 15E completed — cloud/container security tools: trivy (vulnerability scanning), ScoutSuite (cloud auditing), CloudSploit (cloud misconfigurations)
- Phase 16 completed — Web UI rebuild: Preact + TypeScript + esbuild, 9 pages, 8 components, 62KB JS + 5KB CSS bundle
- Phase 17 completed — E2E validation infrastructure: MockProvider extraction to sigint-llm, provider injection via ScanService::with_provider(), 4 new E2E scan pipeline tests
- Phase 18 completed — User readiness: README.md, ARCHITECTURE.md, USER_GUIDE.md, config.example.toml, LICENSE (MIT), crates/sigint-web/build.rs (frontend bundling)
- Phase 19 completed — Embedded LLM infrastructure: GGUF reader, EmbeddedProvider stub, Model CLI (list/pull/info), GET /api/models, web UI model selector, doctor checks
- Phase 19B completed — Real llama-cpp-2 inference wiring: EmbeddedProvider generates tokens, threads + flash_attention config, tool-calling support via grammar-constrained JSON
- Phase 20 completed — Ship readiness: CI/CD with frontend build + security audit, multi-stage Dockerfile, docker-compose with Ollama sidecar, Makefile, CONTAINER.md
- Phase 21 completed — TUI polish: tab-based multi-view architecture (commits 81c07c5, 2ecf9cb, 3a6a53b)
- Phase 22 completed — Compile-time plugin system: sigint-plugin crate, PluginsConfig, Orchestrator wiring, CLI plugin subcommand (commits 7691267, a9c6916, 93026e3)
- Phase 23 completed — Model fine-tuning pipeline: sigint-train crate with dataset extraction, format conversion, train/val split, Modelfile generation, quality assessment (commits 272d2a7, c97cad0)

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
| DEC-P17-001 | 2026-04-02 | MockProvider extracted as public sigint-llm module (mock.rs) | MockProvider was defined locally in orchestrator.rs tests; extracting to sigint-llm makes it reusable by E2E tests without circular crate dependencies. Phase 17. |
| DEC-P17-002 | 2026-04-02 | ScanService::with_provider() builder for test-time LLM injection | Provider injection via builder method lets E2E tests supply a MockProvider to ScanService without changing production code paths. Phase 17. |
| DEC-P19-001 | 2026-04-04 | llama-cpp-2 crate for embedded inference | Safe Rust bindings to llama.cpp with GPU acceleration support; chosen over candle/burn for GGUF ecosystem compatibility and quantised model support. Phase 19. |
| DEC-P19-002 | 2026-04-04 | Feature flag gating (embedded-llm) | llama-cpp-2 requires C/C++ toolchain and takes minutes to compile; feature flag keeps default builds fast; factory returns descriptive error when feature absent. Phase 19. |
| DEC-P19-003 | 2026-04-04 | spawn_blocking for inference calls | llama-cpp-2 inference is synchronous/CPU-bound; spawn_blocking prevents async runtime blocking, consistent with DEC-SAND-002 pattern. Phase 19. |
| DEC-P19-004 | 2026-04-04 | HuggingFace as model source | De facto hub for GGUF model distribution; model pull resolves repo IDs to download URLs; reqwest streaming with byte-counter progress. Phase 19. |
| DEC-P19-005 | 2026-04-04 | Compile-time GPU flags via Cargo features | GPU acceleration (CUDA, Metal, Vulkan) requires compile-time vendor SDK linking; Cargo features map to llama-cpp-2 build config; default is CPU-only. Phase 19. |
| DEC-P19-006 | 2026-04-04 | Standalone GGUF reader (no llama-cpp dependency) | Model discovery needs only header metadata, not multi-GB weights; pure-Rust reader avoids C dependencies for list/info path. Phase 19. |
| DEC-P19-EMBEDDED-001 | 2026-04-04 | EmbeddedProvider gated behind embedded-llm Cargo feature flag | llama-cpp-2 compilation requires a C toolchain and takes several minutes; feature flag keeps default builds fast and dependency-free. Factory returns a descriptive error (mentioning the feature flag) when provider=embedded is requested without the flag. Phase 19B. |
| DEC-P19-EMBEDDED-002 | 2026-04-04 | Load model fresh inside spawn_blocking rather than storing in struct | LlamaModel is not Send+Sync (raw C pointers). Loading fresh per call avoids unsafe Send impls while keeping the async executor happy. Model weights stay in the OS page cache so re-opens are fast. Phase 19B. |
| DEC-P19-EMBEDDED-003 | 2026-04-04 | threads + flash_attention config fields for embedded inference | Maps to llama.cpp -t and -fa flags; threads=0 means auto-detect (llama.cpp default); flash_attention defaults to false; wired through LlamaContextParams in EmbeddedProvider. Phase 19B. |
| DEC-P19-GGUF-001 | 2026-04-04 | Pure-Rust GGUF header reader, no weight loading | Model discovery only needs architecture/quantisation metadata, not the multi-GB weight tensors. A bespoke reader keeps the dependency surface minimal and avoids linking llama-cpp-2 for the listing path. Phase 19. |
| DEC-P19-MODEL-CLI-001 | 2026-04-04 | Model CLI commands (list/pull/info) in sigint-cli | Model management commands added to the CLI binary for offline model workflow; list reads GGUF headers, pull downloads from HuggingFace, info shows metadata. Phase 19. |

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
**Decisions:** DEC-P5-DOCTOR, DEC-P5-OPENAI, DEC-LLM-005, DEC-P5-REPORT, DEC-REPORT-001, DEC-WEB-001, DEC-WEB-002, DEC-WEB-003, DEC-WEB-004, DEC-WEB-005, DEC-WEB-006, DEC-WEB-007, DEC-WEB-008, DEC-WEB-009, DEC-WEB-010, DEC-WEB-011, DEC-WEB-012

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
| DEC-P14-001 | MemoryService gated by --memory flag and config.memory.enabled | accepted | Memory retrieval adds latency and token cost; opt-in prevents regression for users who don't need episodic context; flag and config are independent toggles. Phase 14A. |
| DEC-P14-002 | Strategist uses CreateAttackPlanTool with MITRE ATT&CK-enriched system prompt | accepted | Structured tool call captures attack plans as machine-parseable JSON via Arc<Mutex<Vec>> collector; MITRE ATT&CK framework provides standardized tactic/technique vocabulary for the LLM. Phase 14B. |
| DEC-P14-003 | ReconEngine pre-step injects asset context into Orchestrator TaskContext | accepted | Running recon before the agent loop provides up-to-date asset inventory; injecting into TaskContext makes asset data available to all downstream agents without coupling them to ReconEngine. Phase 14C. |
| DEC-P14-004 | Migration 9 adds asset_id FK to findings table with FindingQuery::by_asset_id | accepted | Foreign key links findings to discovered assets; nullable column preserves backward compatibility for findings without asset association; query method enables per-asset finding retrieval for reports and analysis. Phase 14D. |
| DEC-P14-005 | ToolsConfig with per-tool max_output overrides for all 6 tools | accepted | Global default (1MB from DEC-P13-002) may be too large or small for specific tools; per-tool config in sigint.toml [tools.<name>] allows operators to tune output caps without code changes. Phase 14E. |
| DEC-P15-001 | sqlmap runs with --batch flag for non-interactive automated execution | accepted | sqlmap prompts interactively by default which blocks the agent tool loop; --batch selects safe defaults automatically; combined with --forms and risk/level params for coverage control. Phase 15A. |
| DEC-P15-002 | ffuf uses -json flag for structured JSON output parsing | accepted | ffuf's default output is human-readable text; -json emits one JSON object per result line enabling reliable structured parsing without fragile regex; results array built from line-delimited JSON. Phase 15A. |
| DEC-P15-003 | whatweb uses --log-json with Recon aggression profile | accepted | Recon profile (aggression level 1) is passive and safe for authorized testing; --log-json produces machine-parseable output; higher aggression levels available via parameter override. Phase 15A. |
| DEC-P15-004 | HydraTool uses SandboxProfile::bruteforce() for credential brute-forcing | accepted | bruteforce profile provides pasta networking with 300s timeout; -l/-L flags for single username or list; -P for password wordlist; target as service://host; -o /dev/stdout captures found credentials; Risk High because successful attacks yield direct auth access. Phase 15B. |
| DEC-P15-005 | WpscanTool uses JSON output format for reliable structured parsing | accepted | wpscan --format json provides stable machine-readable output; --no-banner --random-user-agent suppress noise and avoid WAF detection; plugin vulnerabilities counted from array length; users extracted by slug field. Phase 15B. |
| DEC-P15-006 | TestsslTool uses SandboxProfile::recon() for passive TLS analysis | accepted | recon profile provides 60s timeout sufficient for single-host TLS checks; --jsonfile /dev/stdout emits JSON array; --quiet --color 0 suppress banner/ANSI; OK findings filtered out; protocol entries separated into protocols map. Phase 15B. |
| DEC-P15-007 | HashcatTool uses SandboxProfile::offline() — no network, 60s timeout | accepted | hash cracking requires no network access; offline profile enforces no-network constraint; --force bypasses hardware warnings; --outfile-format=2 outputs plaintext-only for line parsing; -o /dev/stdout captures cracked pairs inline. Phase 15B. |
| DEC-P15-008 | MasscanTool uses SandboxProfile::nmap() for pasta networking | accepted | masscan needs raw socket access like nmap; nmap profile provides pasta networking with 120s timeout; --rate parameter controls scan speed; -oJ /dev/stdout for JSON output; banners parsed from service array. Phase 15C. |
| DEC-P15-009 | TsharkTool uses SandboxProfile::nmap() for raw network access; JSON output for structured analysis | accepted | tshark requires raw network access for packet capture; nmap profile provides pasta networking; -T json for structured output; -c packet count limit prevents unbounded capture; protocol hierarchy and conversation stats parsed from JSON layers. Phase 15C. |
| DEC-P15-010 | Responder defaults to analyze-only mode (passive) for safety; active poisoning requires explicit opt-in | accepted | LLMNR/NBT-NS poisoning is high-impact; --analyze flag makes passive the default; active mode requires explicit poison=true parameter; SandboxProfile::nmap() for raw network; captured credentials parsed from Responder-Session.log format. Phase 15C. |
| DEC-P15-011 | MsfconsoleTool uses inline -x commands and web_scanner profile | accepted | msfconsole is invoked with inline resource commands via -x rather than RPC/REST (msfrpcd). Simpler to sandbox: no daemon process, no auth tokens, no TCP ports inside the namespace. web_scanner profile provides pasta networking (needed for reverse shells) and 600s timeout (exploits can take several minutes). Risk is High. Phase 15D. |
| DEC-P15-012 | LinpeasTool uses offline profile; runs in sandbox for enumeration of local system or parses pre-captured output | accepted | linpeas is a local privilege escalation enumeration script requiring no network access; offline profile enforces no-network constraint and provides 60s timeout. Supports two modes: run linpeas.sh directly or parse existing output file. Risk is Medium. Phase 15D. |
| DEC-P13-003 | Regex-based text fallback parser when nmap XML is truncated or unclosed | accepted | When nmap is killed mid-scan the XML is often unclosed; the event parser hits EOF and stops. A regex fallback over nmap's human-readable text output extracts port/state/service tuples — less structured than XML but better than discarding all data. ASCII character classes used to avoid PCRE Unicode issues. Phase 13A. |
| DEC-P13-004 | Detect systemd-resolved stub (127.0.0.53) and resolve to upstream nameservers | accepted | On systemd-resolved systems /etc/resolv.conf points to 127.0.0.53 which does not exist inside a new network namespace (Pasta mode); resolve_dns_content() detects the stub and substitutes real upstream nameservers from /run/systemd/resolve/resolv.conf or falls back to 8.8.8.8. Phase 13A. |
| DEC-P13-005 | Best-effort structured parsing of gobuster quiet-mode output | accepted | Extracts path/status/size from gobuster -q lines matching the format "[STATUS] /path (Size: N)"; lines that don't match are silently skipped; returns None on empty output. Phase 13B. |
| DEC-P13-006 | Best-effort structured parsing of feroxbuster quiet-mode output | accepted | Feroxbuster -q --no-state emits one result per line in the format "STATUS METHOD LINES WORDS CHARS URL"; parser extracts these fields and builds a structured findings list with total count and status code aggregates. Phase 13B. |
| DEC-P13-007 | Best-effort structured parsing of nikto findings from text output | accepted | Nikto text lines beginning with "+" are findings; parser extracts finding text and OSVDB references (e.g. OSVDB-3092) into a structured list; lines not matching the pattern are silently skipped. Phase 13B. |
| DEC-P14-TOOLS-001 | Per-tool output caps in ToolsConfig with output_cap_for() lookup | accepted | Allows noisy tools (e.g. nuclei, feroxbuster) to have larger caps while keeping the global default tight; output_cap_for() returns the tool-specific override when configured, falling back to the global default. Phase 14E. |
| DEC-P15-013 | enum4linux-ng (Python rewrite) preferred over original enum4linux; JSON output via -oJ | accepted | enum4linux-ng is the maintained Python rewrite of the original Perl tool; -oJ /dev/stdout emits structured JSON covering shares/users/groups/policies; bruteforce profile provides pasta networking for SMB access with 300s timeout. Risk is Medium. Phase 15D. |
| DEC-P15-014 | TrivyTool uses SandboxProfile::recon() — pasta networking, 60s timeout, Risk Low | accepted | trivy scans container images, filesystems, and repos for CVEs; image scans need network for registry pulls (pasta); read-only scan never modifies target so Risk Low; --format json --quiet provides structured output; parse_trivy_output extracts per-target vulns, severity counts, and total. Phase 15E. |
| DEC-P15-015 | ScoutSuiteTool uses SandboxProfile::web_scanner() — pasta networking, 600s timeout, Risk Medium | accepted | ScoutSuite calls cloud provider APIs which are slow (up to 10 min for large accounts); web_scanner profile provides 600s timeout; --report-format json --no-browser for headless structured output; findings extracted from JSON report by service/rule/severity/item count. Phase 15E. |
| DEC-P15-016 | CloudsploitTool uses SandboxProfile::web_scanner() — pasta networking, 600s timeout, Risk Medium | accepted | CloudSploit calls cloud provider APIs; web_scanner profile provides 600s timeout; --json for structured output; findings extracted as plugin/category/status/message tuples with PASS/FAIL/WARN aggregates. Phase 15E. |
| DEC-WEB-020 | GitHub Dark palette as the canonical SIGINT color system | accepted | Pentest tooling is used in darkened environments; GitHub Dark provides a well-tested accessible palette that security practitioners already trust; JetBrains Mono with monospace fallbacks keeps the terminal aesthetic. Phase 16A. |
| DEC-WEB-021 | Discriminated union for WebSocket events using `type` literal field | accepted | A discriminated union on `type` lets TypeScript narrow the event payload with a switch statement, producing fully type-safe handlers without runtime casting. Phase 16A. |
| DEC-WEB-022 | Hash-based SPA routing via window.location.hash and hashchange event | accepted | Hash routing requires no server-side route configuration — the static file server's SPA fallback (serve index.html for unknown paths) already handles all routes; hashchange + useState provides a clean reactive routing model in Preact. Phase 16B. |
| DEC-WEB-023 | WebSocketManager singleton with auto-reconnect and subscribe/unsubscribe pattern | accepted | A singleton prevents multiple WS connections from different components; subscribe returns an unsubscribe function matching Preact's useEffect cleanup convention; 3s reconnect delay avoids reconnect storms. Phase 16A. |
| DEC-WEB-024 | esbuild CSS import creates sibling app.css alongside app.js — matches index.html expectations | accepted | esbuild automatically extracts CSS imports to a sibling file when outfile (not outdir) is configured; the existing index.html loads both /assets/app.js and /assets/app.css so this produces the correct output without manual file management. Phase 16A. |
| DEC-WEB-025 | Sidebar uses CSS hover expansion (48px → 200px) with no JS state | accepted | Pure CSS transition on width avoids a useState toggle and re-render on every hover; the inner container is fixed at 200px so text is always laid out correctly and simply clipped by the overflow:hidden parent during collapse. Phase 16B. |
| DEC-WEB-026 | TopBar carries WebSocket status badge and live scan indicator | accepted | Persistent top-of-screen visibility ensures operators always know connection state and whether a scan is active; avoids burying status in a sidebar or modal. Phase 16B. |
| DEC-WEB-027 | App shell uses hash router with useState + hashchange listener | accepted | Hash routing requires no server configuration; a single hashchange listener + useState(location.hash) is the minimal correct Preact implementation; cleanup via removeEventListener in useEffect return prevents listener accumulation. Phase 16B. |
| DEC-WEB-028 | DataTable generic over T with Column render prop for cell customisation | accepted | Generic table avoids duplicating sort/click logic across all list views; Column.render? allows per-cell JSX overrides (badges, links) while defaulting to String(value) for simple cases. Phase 16C. |
| DEC-WEB-030 | Dashboard uses parallel useEffect fetches for sessions and scans | accepted | Two independent API calls fired in a single useEffect to minimise time-to-paint; they update independent state slices so partial failure still renders available data; loading and error states tracked independently. Phase 16D. |
| DEC-WEB-031 | ReportViewer uses srcdoc iframe with sandbox="allow-same-origin" | accepted | srcdoc injects arbitrary HTML safely — sandbox prevents script execution from report body while allow-same-origin lets the iframe inherit CSS custom properties for themed rendering; Blob URL download avoids a second network round-trip. Phase 16E. |
| DEC-WEB-032 | PipelineStatus uses CSS keyframes pulse animation on the active stage icon | accepted | CSS animation on the icon avoids JS setInterval for visual feedback; the pulse keyframe is defined in theme.css for consistency with the existing status-dot animation. Phase 16D. |
| DEC-WEB-033 | EventLog auto-scroll uses a sentinel div + scrollIntoView | accepted | Zero-height sentinel div at bottom combined with scrollIntoView({ behavior: "smooth" }) is the idiomatic Preact pattern; avoids manual scrollTop arithmetic and handles dynamic item heights correctly. Phase 16D. |
| DEC-WEB-034 | ApprovalModal is a pure presentational component — parent owns WS send | accepted | Keeping the modal free of WebSocket knowledge makes it testable in isolation and reusable; parent (ScanLive) constructs approval payload and calls wsManager.send(); modal fires onApprove/onDeny callbacks. Phase 16D. |
| DEC-WEB-035 | Settings page is read-only, sourced from /api/health + hardcoded defaults | accepted | No /api/config endpoint exists; health check provides server status; hardcoding known defaults is preferable to omitting the section or adding a new endpoint solely for display; read-only avoids accidental misconfiguration from UI. Phase 16F. |
| DEC-P19-001 | llama-cpp-2 crate for embedded inference | accepted | llama-cpp-2 provides safe Rust bindings to llama.cpp with GPU acceleration support; chosen over alternatives (candle, burn) for compatibility with the GGUF ecosystem and quantised model support. Phase 19. |
| DEC-P19-002 | Feature flag gating (embedded-llm) | accepted | llama-cpp-2 compilation requires a C/C++ toolchain and takes several minutes; feature flag keeps default builds fast and dependency-free; factory returns a descriptive error when provider="embedded" is configured but the feature is absent. Phase 19. |
| DEC-P19-003 | spawn_blocking for inference calls | accepted | llama-cpp-2 inference is synchronous and CPU/GPU-bound; wrapping in tokio::task::spawn_blocking prevents blocking the async runtime, consistent with DEC-SAND-002 pattern for synchronous operations. Phase 19. |
| DEC-P19-004 | HuggingFace as model source for pull | accepted | HuggingFace is the de facto hub for GGUF model distribution; model pull resolves repo IDs to direct download URLs; reqwest streaming with byte-counter progress avoids adding the indicatif crate. Phase 19. |
| DEC-P19-005 | Compile-time GPU flags via Cargo features | accepted | GPU acceleration (CUDA, Metal, Vulkan) requires compile-time linking of vendor SDKs; Cargo feature flags (cuda, metal, vulkan) map cleanly to llama-cpp-2's build configuration; default build is CPU-only for maximum portability. Phase 19. |
| DEC-P19-006 | Standalone GGUF reader (no llama-cpp dependency) | accepted | Model discovery only needs architecture/quantisation metadata, not multi-GB weight tensors; a pure-Rust GGUF v3 header reader keeps the listing/info path free of C dependencies and compiles in the default build without the embedded-llm feature. Phase 19. |
| DEC-P19-EMBEDDED-003 | threads + flash_attention config fields | accepted | Maps to llama.cpp -t (CPU threads) and -fa (flash attention) flags; threads=0 means auto-detect; flash_attention defaults to false; wired through LlamaContextParams in EmbeddedProvider. Phase 19B. |
| DEC-P20-001 | Multi-stage Dockerfile with Debian slim runtime | accepted | Builder stage compiles Rust + frontend; slim runtime keeps image small while including essential pentest tools (nmap, gobuster, nikto); two-stage build avoids shipping compiler toolchain. Phase 20. |
| DEC-P20-002 | CI frontend build before Rust test/clippy jobs | accepted | sigint-web's build.rs expects pre-built frontend assets; CI must run npm ci + npm run build before cargo test/clippy to avoid build failures on the frontend embedding step. Phase 20. |
| DEC-P20-003 | docker-compose with Ollama sidecar on bridge network | accepted | Ollama runs as a separate container so sigint can reach it at http://ollama:11434; bridge network isolates services; persistent volumes for model weights and sigint data survive container restarts. Phase 20. |

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
**Status:** completed
**Sub-phases:** 13D-prereq (Foundation Types) → 13A (nmap) → 13B (gobuster) → 13C (other tools)
**Decision IDs:** DEC-P13-001, DEC-P13-002
**Definition of Done:**
- `ScanStatus` enum (Complete/TimedOut/Partial) added to `sigint-tools`
- `TruncationInfo` struct added to `sigint-tools`
- `ToolResult` carries `status` and `truncation` fields with backward-compatible defaults
- Sandbox output cap (`max_output_bytes`) wired through `SandboxedCommand` → `SandboxOutput` → `ToolResult.truncation`
- All existing tests pass; new unit tests cover each status variant and truncation path
- Tool-specific hardening (timeout recovery, real-target robustness) addressed in subsequent sub-phases

- [x] Sub-Phase 13D-prereq: Foundation types — ScanStatus, TruncationInfo, ToolResult new fields, sandbox output cap, timeout investigation
- [x] Sub-Phase 13A: nmap hardening — DNS resolution fix, text fallback parser, ASCII regex classes, agent prompt tuning
- [x] Sub-Phase 13B: Web scanner hardening — feroxbuster/gobuster/nikto parser integration, merge conflict resolution
- [x] Sub-Phase 13C: Remaining tools — 1MB max_output cap added to nuclei and shell

---

### Phase 14: Agent Intelligence
**Status:** completed
**Sub-phases:** 14A (Memory Wiring) → 14B (Strategist Overhaul) → 14C (Recon Integration) → 14D (Asset-Finding Linking) → 14E (Configurable Output Caps)
**Decision IDs:** DEC-P14-001, DEC-P14-002, DEC-P14-003, DEC-P14-004, DEC-P14-005, DEC-AGENT-019

> Anchored retroactively (2026-04-27): DEC-AGENT-019 — KNOWN_OUTPUT_TOOLS const in `sigint-agents/src/registry.rs` lets `for_agent()` suppress the "unregistered tool" warning for `create_attack_plan` (DEC-P14-001) and `create_finding` (DEC-FINDING-001) since both are output channels, not executable tools. Introduced as a clean-up alongside Phase 14B's CreateAttackPlanTool when the second output tool joined the first.
**Definition of Done:**
- `--memory` flag and `config.memory.enabled` gate MemoryService injection into agent context
- Strategist uses CreateAttackPlanTool with MITRE ATT&CK-enriched system prompt; plans collected via Arc<Mutex<Vec>>
- `--recon` flag triggers ReconEngine pre-step; asset context injected into Orchestrator TaskContext
- Migration 9 adds `asset_id` FK to findings table; `FindingQuery::by_asset_id` enables per-asset finding queries
- ToolsConfig with per-tool `max_output` overrides wired through all 6 tools (nmap, gobuster, feroxbuster, nikto, nuclei, shell)
- 874 tests pass, 0 failures

- [x] Sub-Phase 14A: Memory wiring — --memory flag, config toggle, MemoryService gating
- [x] Sub-Phase 14B: Strategist overhaul — CreateAttackPlanTool, MITRE ATT&CK prompt, plan collector
- [x] Sub-Phase 14C: Recon integration — --recon flag, ReconEngine pre-step, asset context injection
- [x] Sub-Phase 14D: Asset-finding linking — migration 9 (asset_id FK), FindingQuery::by_asset_id
- [x] Sub-Phase 14E: Configurable output caps — ToolsConfig, per-tool overrides, all 6 tools updated

---

### Phase 15A: Tool Expansion
**Status:** completed
**Sub-phases:** sqlmap_scan → ffuf_scan → whatweb_scan
**Decision IDs:** DEC-P15-001, DEC-P15-002, DEC-P15-003
**Definition of Done:**
- 3 new tools (sqlmap_scan, ffuf_scan, whatweb_scan) with structured JSON parsers
- All tools registered in sigint-tools/src/lib.rs with sandbox profiles
- Agent ACLs updated: Executor and Researcher have access to new tools
- Doctor checks added for sqlmap, ffuf, whatweb binaries
- 214 tool-crate tests pass (899+ total), 0 failures

- [x] Sub-Phase sqlmap_scan: sqlmap wrapper with --batch mode, SQL injection parameter support, structured finding parser
- [x] Sub-Phase ffuf_scan: ffuf wrapper with -json output, wordlist/URL/method params, result parser
- [x] Sub-Phase whatweb_scan: whatweb wrapper with --log-json, Recon aggression profile, technology fingerprint parser

---

### Phase 15B: Auth/Exploitation Tool Expansion
**Status:** completed
**Branch:** feature/phase15b-auth-tools
**Decision IDs:** DEC-P15-004, DEC-P15-005, DEC-P15-006, DEC-P15-007
**Definition of Done:**
- 4 new tools (hydra_scan, wpscan_scan, testssl_scan, hashcat_crack) with structured parsers
- All tools registered in sigint-tools/src/lib.rs with sandbox profiles
- Agent ACLs updated: Executor has all 4; Researcher gets testssl_scan
- Doctor checks added for hydra, wpscan, testssl, hashcat binaries
- All sigint-tools and sigint-agents tests pass, cargo check clean

- [x] hydra_scan: online credential brute-forcer, SandboxProfile::bruteforce(), credential line parser
- [x] wpscan_scan: WordPress enumeration, SandboxProfile::web_scanner(), JSON output parser
- [x] testssl_scan: TLS/SSL analysis, SandboxProfile::recon(), JSON array findings parser
- [x] hashcat_crack: offline hash cracking, SandboxProfile::offline(), cracked line parser

---

### Phase 15C: Network/Infrastructure Tool Expansion
**Status:** completed
**Branch:** feature/phase15c-network-tools
**Decision IDs:** DEC-P15-008, DEC-P15-009, DEC-P15-010
**Definition of Done:**
- 3 new tools (masscan_scan, tshark_capture, responder_poison) with structured parsers
- All tools registered in sigint-tools/src/lib.rs with sandbox profiles
- Agent ACLs updated: Executor has all 3 (16 total); Researcher gets masscan + tshark (8 total), responder excluded
- Doctor checks added for masscan, tshark, responder binaries
- 276 tool tests + 161 agent tests pass, cargo check clean

- [x] masscan_scan: fast large-scale port scanner, SandboxProfile::nmap(), JSON output parser with banner extraction
- [x] tshark_capture: packet capture and traffic analysis, SandboxProfile::nmap(), JSON layer parser with protocol hierarchy
- [x] responder_poison: LLMNR/NBT-NS credential capture, SandboxProfile::nmap(), passive by default (--analyze), session log parser

---

### Phase 15D: Post-Exploitation Tool Expansion
**Status:** completed
**Branch:** feature/phase15d-postexploit
**Decision IDs:** DEC-P15-011, DEC-P15-012, DEC-P15-013
**Definition of Done:**
- 3 new tools (msf_exploit, linpeas_enum, enum4linux_scan) with structured parsers
- All tools registered in sigint-tools/src/lib.rs with sandbox profiles
- Agent ACLs updated: Executor has all 3 (19 total); Researcher gets enum4linux_scan (9 total)
- Doctor checks added for msfconsole, linpeas.sh, enum4linux-ng binaries
- All sigint-tools and sigint-agents tests pass, cargo check clean

- [x] msf_exploit: Metasploit Framework wrapper, SandboxProfile::web_scanner(), inline -x command execution, session/marker parser
- [x] linpeas_enum: linpeas privilege escalation enumeration, SandboxProfile::offline(), section/high-priority finding parser
- [x] enum4linux_scan: SMB enumeration via enum4linux-ng, SandboxProfile::bruteforce(), JSON output parser with shares/users/groups

---

### Phase 15E: Cloud/Container Security Tool Expansion
**Status:** completed
**Branch:** feature/phase15e-cloud-tools
**Decision IDs:** DEC-P15-014, DEC-P15-015, DEC-P15-016
**Definition of Done:**
- 3 new tools (trivy_scan, scout_suite_scan, cloudsploit_scan) with structured JSON parsers
- All tools registered in sigint-tools/src/lib.rs with sandbox profiles
- Agent ACLs updated: Executor has all 3 (22 total); Researcher gets trivy_scan (10 total)
- Doctor checks added for trivy, scout, cloudsploit binaries
- All sigint-tools and sigint-agents tests pass, cargo check clean

- [x] trivy_scan: container image/filesystem/repo vulnerability scanner, SandboxProfile::recon(), JSON Results parser with per-target CVE list
- [x] scout_suite_scan: cloud infrastructure auditor (AWS/Azure/GCP), SandboxProfile::web_scanner(), JSON report parser with service/rule/severity findings
- [x] cloudsploit_scan: cloud misconfiguration detector, SandboxProfile::web_scanner(), JSON findings parser with PASS/FAIL/WARN aggregates

---

### Phase 16: Web UI Rebuild — Preact + TypeScript + esbuild
**Status:** completed
**Branch:** feature/phase16-web-ui (merged)
**Sub-phases:** 16A (Build System + Infrastructure) → 16B (Shell + Layout) → 16C (Shared Components) → 16D (Dashboard + Scan pages) → 16E (Sessions + Reports) → 16F (Diff + Settings)
**Decision IDs:** DEC-WEB-020..028, DEC-WEB-030..035
**Definition of Done:**
- `crates/sigint-web/frontend/` with esbuild build system producing `static/assets/app.js` + `app.css`
- Preact + TypeScript SPA with hash-based routing, Sidebar, TopBar, shared components
- All existing `cargo test -p sigint-web` tests pass (static files still servable)
- `npm run build` completes without errors
- Dashboard, NewScan, ScanLive, SessionDetail, ReportViewer, AttackPlanView, ScanDiff, Settings pages implemented

- [x] Sub-Phase 16A (Tasks 1-3): Build system — package.json, tsconfig.json, esbuild.config.mjs; infrastructure — theme.css, types.ts, api.ts, ws.ts
- [x] Sub-Phase 16B (Task 4): Shell — Sidebar.tsx, TopBar.tsx, app.tsx, index.tsx
- [x] Sub-Phase 16C (Task 5): Shared components — StatCard.tsx, SeverityBadge.tsx, DataTable.tsx
- [x] Sub-Phase 16D: Dashboard.tsx (stat cards, session list, recent findings), NewScan.tsx (form), ScanLive.tsx (live log + approval)
- [x] Sub-Phase 16E: SessionDetail.tsx, ReportViewer.tsx, FindingsDetail.tsx, AttackPlanView.tsx
- [x] Sub-Phase 16F: ScanDiff.tsx, Settings.tsx

---

### Phase 17: E2E Validation Infrastructure
**Status:** completed
**Branch:** feature/phase17-e2e (merged)
**Decision IDs:** DEC-P17-001, DEC-P17-002
**Definition of Done:**
- MockProvider extracted from orchestrator.rs into `crates/sigint-llm/src/mock.rs` as a public module
- ScanService gains `with_provider()` builder for test-time LLM injection
- 4 new E2E tests in `tests/e2e/tests/scan_e2e.rs` exercise full scan pipeline (start -> agents -> DB -> query)
- All tests pass (sigint-llm 45, sigint-agents 162, sigint-e2e 20)

- [x] Extract MockProvider + MockResponse (Text/ToolCall variants) into sigint-llm/src/mock.rs
- [x] Remove local MockProvider from orchestrator.rs, import from sigint_llm::mock
- [x] Add provider_override field + with_provider() builder to ScanService
- [x] Write start_server_with_mock() E2E helper
- [x] 4 E2E scan pipeline tests: start scan, verify agents dispatched, check DB state, query findings

---

### Phase 18: User Readiness — Docs, Config, License, Build Automation
**Status:** completed
**Branch:** feature/phase18-user-readiness (merged)
**Definition of Done:**
- README.md with quickstart, features, CLI reference, tool catalog, architecture overview
- ARCHITECTURE.md with 12-crate system design, agent pipeline, tool system, data model
- USER_GUIDE.md with operator guide — TUI, Web UI, CLI workflows, troubleshooting
- config.example.toml with documented configuration template
- LICENSE (MIT)
- crates/sigint-web/build.rs for automated frontend bundling with graceful degradation

- [x] README.md: project overview, quickstart, feature list, CLI reference, 26-tool catalog, architecture
- [x] ARCHITECTURE.md: crate dependency graph, agent pipeline, tool system, sandbox model, data model
- [x] USER_GUIDE.md: installation, configuration, TUI guide, Web UI guide, CLI workflows, troubleshooting
- [x] config.example.toml: annotated configuration template with all sections
- [x] LICENSE: MIT license
- [x] crates/sigint-web/build.rs: build script for frontend asset bundling (esbuild + Preact)

---

### Phase 19: Embedded LLM — GGUF Reader, EmbeddedProvider, Config Extensions
**Status:** completed (all sub-phases)
**Branch:** feature/phase19-embedded-llm (merged), feature/phase19b-inference (merged)
**Decision IDs:** DEC-P19-001 through DEC-P19-006, DEC-P19-EMBEDDED-001, DEC-P19-EMBEDDED-002, DEC-P19-EMBEDDED-003
**Sub-phases:**
- 19A: EmbeddedProvider stub + GGUF reader (foundation) — completed
- 19B: Real llama-cpp-2 inference wiring, threads/flash_attention config, tool-calling via grammar-constrained JSON — completed
- 19C: Web UI model selector (future — deferred)
**Definition of Done:**
- `GgufMetadata::read(path)` parses GGUF v3 headers without loading weights
- `EmbeddedProvider` gated behind `--features embedded-llm` feature flag
- `sigint model list/pull/info` CLI subcommands for local model management
- `GET /api/models` endpoint returning JSON array of available GGUF models
- `sigint doctor` checks for embedded provider config (models_dir + model file)
- `config.example.toml` includes commented embedded provider example
- `README.md` documents embedded LLM workflow
- All `cargo test -p sigint-cli` and `cargo test -p sigint-web` tests pass

- [x] Task 1: `GgufMetadata::read()` pure-Rust GGUF v3 header reader (sigint-llm/src/gguf.rs)
- [x] Task 2: `EmbeddedProvider` behind `embedded-llm` feature flag (sigint-llm/src/embedded.rs)
- [x] Task 3: `resolved_models_dir()` config helper + `gpu_layers` field (sigint-core/src/config.rs)
- [x] Task 4: `sigint model list/pull/info` CLI subcommands (sigint-cli/src/model.rs)
- [x] Task 5: `GET /api/models` web endpoint (sigint-web/src/routes.rs)
- [x] Task 6: Doctor embedded check + config.example.toml + README.md

---

### Phase 20: Ship Readiness — CI/CD, Docker, Makefile
**Status:** completed
**Branch:** feature/phase20-ship-ready (merged)
**Decision IDs:** DEC-P20-001, DEC-P20-002, DEC-P20-003
**Definition of Done:**
- CI workflow builds frontend before Rust tests/clippy (Node.js 20 + npm ci + npm run build)
- Security audit job via cargo-audit in CI pipeline
- Multi-stage Dockerfile: Rust builder + Debian slim runtime with pentest tools
- docker-compose.yml with sigint + Ollama sidecar on shared bridge network
- Makefile with build/test/lint/fmt/docker/up/clean targets
- CONTAINER.md documenting Docker usage

- [x] CI/CD: frontend build step before test + clippy, cargo cache, security audit job
- [x] Dockerfile: multi-stage (rust:1.82-bookworm builder, debian:bookworm-slim runtime), Node.js for frontend, nmap/gobuster/nikto/curl/dnsutils/whois in runtime
- [x] docker-compose.yml: sigint service + Ollama sidecar, persistent volumes, bridge network
- [x] Makefile: build, frontend, test, lint, fmt, docker, up, clean targets
- [x] CONTAINER.md: Docker quickstart and docker-compose usage docs
- [x] config.example.toml: added Docker Ollama URL comment
- [x] .dockerignore: target, node_modules, .git, .claude exclusions

---

### Phase 21: TUI Polish — Tab-Based Multi-View Architecture
**Status:** completed (commits 81c07c5, 2ecf9cb, 3a6a53b)
**Decision IDs:** (none requiring formal anchoring)

Refactored the ratatui TUI from a single-pane scroll view into a tabbed multi-view layout (Sessions / Engagement Log / Findings / Help). No code-level @decision annotations were introduced; the change was structural-only. Listed here for traceability since it occupies the Phase 21 slot referenced by issue numbering.

---

### Phase 22: Compile-Time Plugin System
**Status:** completed (commits 7691267, a9c6916, 93026e3)
**Decision IDs:** DEC-PLUGIN-001, DEC-PLUGIN-002, DEC-PLUGIN-003

> Anchored retroactively (2026-04-27): this section captures decisions originally made during the Phase 22 work that landed before MASTER_PLAN.md adopted the structured Phase format for new phases. The decisions are live in code.

#### Scope
Introduced a compile-time plugin system: external crates implement `sigint_tools::Tool`, register via `register_tool!()`, and the main binary calls `collect_plugin_tools()` at startup. Added a `sigint plugin` CLI subcommand (`list`, `new`) that scaffolds workspace-member plugin crates so plugins are linked in on the next `cargo build`.

#### Definition of Done
- `sigint-plugin` crate exists with `register_tool!()`, `collect_plugin_tools()`, `find_prompt_pack()` APIs
- `sigint plugin list` shows built-in tools + plugin tools side-by-side
- `sigint plugin new <name>` scaffolds a new workspace-member crate with a working example tool
- Orchestrator accepts a prompt-override fn pointer for per-pack system-prompt customization
- No circular crate dependency between `sigint-agents` and `sigint-plugin`

### Planned Decisions
- DEC-PLUGIN-001: `inventory` crate for zero-boilerplate link-time tool registration — Platform-specific linker sections collect static submissions at link time; no runtime reflection, no manual wiring per plugin. — Source: `crates/sigint-plugin/src/lib.rs`
- DEC-PLUGIN-002: `sigint plugin new` generates workspace-member crates — Workspace members are linked automatically on `cargo build`; scaffolding writes Cargo.toml + lib.rs + example tool so authors only replace the example. — Source: `crates/sigint-cli/src/plugin.rs`
- DEC-PLUGIN-003: PromptPack defined in sigint-plugin; Orchestrator uses fn-pointer bridge — `inventory::collect!(T)` requires T to be defined in the calling crate. To break a would-be circular dependency between `sigint-plugin` and `sigint-agents`, the override is a bare `fn(AgentRole) -> Option<&'static str>` defined in `sigint-agents`; the CLI bridges between PromptPack and that fn pointer. — Source: `crates/sigint-plugin/src/lib.rs`, `crates/sigint-agents/src/prompt_pack.rs`

### Decision Log
<!-- Backfill: anchored retroactively 2026-04-27, no live work in progress -->

---

### Phase 23: Model Fine-Tuning Pipeline (sigint-train crate)
**Status:** completed (commits 272d2a7, c97cad0)
**Decision IDs:** DEC-TRAIN-001, DEC-TRAIN-002, DEC-TRAIN-003, DEC-TRAIN-004, DEC-TRAIN-006, DEC-TRAIN-007
**Superseded:** DEC-TRAIN-005 superseded by DEC-P24-007 (Modelfile ADAPTER semantics — see Phase 24)

> Anchored retroactively (2026-04-27): this section captures decisions originally made during the Phase 23 work that landed before MASTER_PLAN.md adopted the structured Phase format for new phases. The decisions are live in code. Phase 24 ("Close the Fine-Tune Loop") consumes these primitives end-to-end.

#### Scope
Introduced `sigint-train` crate: extracts tool-calling training data from scan history, formats as OpenAI-compatible JSONL, generates Ollama Modelfiles, and provides an accuracy assessment harness. CLI exposes the workflow as `sigint train export | create | stats | assess`. Phase 24 then closed the loop with harvest opt-in, async finetune runner, evaluation, promote/rollback.

#### Definition of Done
- `sigint train export` produces `train.jsonl`, `test.jsonl`, `Modelfile` from scan history
- 80/20 deterministic split based on session_id hash (no leakage between splits)
- JSONL files conform to OpenAI chat-completion schema (portable to Axolotl, Ollama, etc.)
- Output goes to `~/.local/share/sigint/training/` (XDG data home)
- `sigint train assess` returns tool-selection accuracy, argument exact-match rate, per-tool precision/recall

### Planned Decisions
- DEC-TRAIN-001: OpenAI chat-completion format for training JSONL — De-facto standard accepted by Ollama, Axolotl, and other local fine-tuning toolchains; data portable across toolchains without conversion. — Source: `crates/sigint-train/src/lib.rs`
- DEC-TRAIN-002: One TrainingExample per successful ScanRecord tool call — Each successful invocation is a discrete supervisory signal; failed calls (exit_code != 0) are noise, not ground truth. Includes up to 5 prior message turns so the model learns sequencing. — Source: `crates/sigint-train/src/extract.rs`
- DEC-TRAIN-003: One JSON object per line with `session_id` not serialized — JSONL with `#[serde(skip_serializing)]` on session_id keeps output strictly OpenAI-compatible. — Source: `crates/sigint-train/src/format.rs`
- DEC-TRAIN-004: Session-based 80/20 split using session_id hash, not example index — Index-based splits leak context from the same scan into both train and test; session-based hashing prevents cross-contamination and is deterministic. — Source: `crates/sigint-train/src/split.rs`
- DEC-TRAIN-006: Argument comparison uses exact string match on normalized JSON — Tool wrappers already serialize args deterministically, so exact string match is sufficient for first-pass assessment without re-parsing every invocation. — Source: `crates/sigint-train/src/assess.rs`
- DEC-TRAIN-007: Training output goes to `~/.local/share/sigint/training/` (XDG data home) — Follows XDG Base Directory spec; matches the existing sigint data-dir convention (sigint.db, sigint.log); keeps training artifacts out of the project directory. — Source: `crates/sigint-cli/src/train.rs`

### Decision Log
<!-- Backfill: anchored retroactively 2026-04-27, no live work in progress -->

---

### Phase 24: Close the Fine-Tune Loop — Harvest → Train → Evaluate → Promote → Rollback
**Status:** completed
**Branch:** feature/phase24-finetune-loop
**Decision IDs:** DEC-P24-001, DEC-P24-002, DEC-P24-003, DEC-P24-004, DEC-P24-005, DEC-P24-006, DEC-P24-007, DEC-P24-008
**Requirements:** REQ-P24-P0-001 through REQ-P24-P0-005, REQ-P24-P1-001, REQ-P24-P2-001
**Depends on:** Phase 19/19B (EmbeddedProvider + sigint model CLI), Phase 23 (sigint-train crate)

#### Problem Statement

Phase 23 shipped `crates/sigint-train/` — a dataset extraction and Modelfile-generation pipeline — but produced artifacts that no downstream sigint code consumes. A user today can run `sigint train export` and receive `train.jsonl` / `test.jsonl` / `Modelfile`, but nothing connects those artifacts back to the runtime: no trainer is invoked, no adapter is registered with `EmbeddedProvider` or Ollama, and `config.llm.model` is still edited by hand. The loop is half-built. Phase 24 closes it end-to-end so a pentester can improve sigint's tool-calling accuracy on their own corpus with a single `sigint` command chain.

Evidence: reading `sigint-train/src/lib.rs`, `extract.rs`, `modelfile.rs`, `assess.rs`, and `sigint-cli/src/train.rs` confirms (a) no trainer invocation, (b) `assess::run_assess` is a placeholder that feeds ground-truth as predictions (self-evaluation), and (c) `modelfile::generate_modelfile` incorrectly points ADAPTER at training JSONL rather than a LoRA adapter binary.

#### Goals

- **REQ-P24-GOAL-001** — A pentester can opt an engagement into training, run a fine-tune, evaluate it against a held-out set, and promote it — all via `sigint` CLI commands — without manually editing config.toml.
- **REQ-P24-GOAL-002** — Base vs fine-tuned models are compared with real inference numbers (tool-selection accuracy, argument-match rate), not ground-truth self-evaluation.
- **REQ-P24-GOAL-003** — A failed promotion is recoverable via a single `sigint model rollback` command.

#### Non-Goals

- **REQ-P24-NOGO-001** — No GPU requirement. CPU-only baseline; any GPU path is the user's toolchain problem.
- **REQ-P24-NOGO-002** — No built-in trainer. We do not bundle unsloth / axolotl / HF PEFT; we shell out to a user-configured command.
- **REQ-P24-NOGO-003** — No web UI for this phase. CLI only. Web integration is Phase 25+ if the user wants.
- **REQ-P24-NOGO-004** — No role-specific fine-tuning for v1 (flagged as P2). Whole-orchestrator model swap only.
- **REQ-P24-NOGO-005** — No automatic promotion or live-session A/B. All transitions are user-initiated.
- **REQ-P24-NOGO-006** — No changes to `sigint-core` Agent trait or Orchestrator. Integration happens at provider-factory and CLI layers.

#### Requirements

**Must-Have (P0)**

- **REQ-P24-P0-001** — Training-data harvest is opt-in per engagement.
  Acceptance: `sigint train harvest <session_id>` sets `sessions.trainable=1`. `sigint train export` filters to `WHERE trainable=1`. Default for new sessions is `trainable=0`.
- **REQ-P24-P0-002** — A user can invoke fine-tuning through sigint.
  Acceptance: `sigint train finetune --base <model> --output <name>` shells out to `config.train.finetune_command` with env vars `SIGINT_TRAIN_JSONL`, `SIGINT_TEST_JSONL`, `SIGINT_BASE_MODEL`, `SIGINT_OUTPUT_PATH`. Job record written to `~/.local/share/sigint/training/jobs.json`. Exit code propagated.
- **REQ-P24-P0-003** — Evaluation runs real inference against both base and fine-tuned models.
  Acceptance: `sigint train evaluate --base <tag> --candidate <tag>` loads `test.jsonl`, invokes both providers via the existing LlmProvider trait, runs `assess::assess` on each, prints a side-by-side diff with Δ tool-accuracy and Δ argument-match.
- **REQ-P24-P0-004** — A fine-tuned model can be promoted to active with a single command.
  Acceptance: `sigint model promote <tag>` detects output kind (GGUF path → embedded provider; Ollama tag → ollama provider), atomically rewrites `config.llm.model` (and `config.llm.provider` if needed), writes backup of prior config to `config.toml.bak`, appends an entry to `~/.local/share/sigint/promotion.log`.
- **REQ-P24-P0-005** — Promotion is reversible.
  Acceptance: `sigint model rollback` reads the last entry in promotion.log and reverses config to the prior model. Handles missing log with actionable error.

**Nice-to-Have (P1)**

- **REQ-P24-P1-001** — Promotion refuses to proceed if eval sample size below a threshold unless `--force` is supplied.
  Acceptance: `sigint model promote` reads last eval result from a state file; if `total_examples < config.train.min_eval_examples` (default 50), exit 1 with actionable error.

**Future Consideration (P2)**

- **REQ-P24-P2-001** — Role-specific fine-tuning: `config.agents.<role>.model` overrides the global model for that agent role only. Deferred; data model (`agent_role` on ScanRecord and TrainingExample) already supports slicing by role.

#### Definition of Done

- **REQ-P24-GOAL-001 satisfied**: Running `sigint train harvest <id> → sigint train export → sigint train finetune → sigint train evaluate → sigint model promote` on a fixture corpus produces a successful end-to-end run (smoke test with mocked finetune command).
- **REQ-P24-GOAL-002 satisfied**: `sigint train evaluate` invokes the LLM provider for each test example, collects predictions, and prints diffs (e.g., "Δ tool-accuracy: +4.2pp"). No ground-truth self-evaluation remains.
- **REQ-P24-GOAL-003 satisfied**: `sigint model rollback` restores the prior `config.llm.model` value; round-trip (promote→rollback→promote) is idempotent.
- Doctor checks for `config.train.finetune_command` presence, models_dir writability, and `ollama` CLI presence when needed.
- `config.example.toml` documents the `[train]` section with an example `finetune_command` (unsloth/axolotl placeholder).
- README adds a "Fine-tuning workflow" section with the full command chain.
- All `cargo test -p sigint-train`, `-p sigint-cli`, `-p sigint-store` pass.
- `DEC-TRAIN-005` superseded by `DEC-P24-007` (noted in DECISIONS.md); Phase 23's `modelfile::generate_modelfile` signature updated to take an optional `adapter_path: Option<&Path>` instead of conflating training data with adapter binary.

### Planned Decisions

- **DEC-P24-001**: Fine-tune backend is an external shell-out command, not a built-in trainer — user configures `config.train.finetune_command`, sigint passes env vars and polls for output. Chosen over `ollama create` (which only packages, doesn't train) and llama.cpp finetune (deprecated upstream). — Addresses: REQ-P24-P0-002, REQ-P24-NOGO-002
- **DEC-P24-002**: Training-data gating via per-engagement opt-in (`sessions.trainable` column + `sigint train harvest <id>` command). Chosen over opt-out-with-redaction because engagement logs contain customer PII and the conservative default must be explicit consent. — Addresses: REQ-P24-P0-001
- **DEC-P24-003**: Evaluation methodology combines existing 80/20 holdout split with live inference of BOTH base and candidate models against the test set. Chosen over offline-only (doesn't close the loop) and live-session A/B (needs Phase 25 telemetry). — Addresses: REQ-P24-P0-003, REQ-P24-GOAL-002
- **DEC-P24-004**: Promotion rewrites `config.llm.model` atomically via a CLI command, appending to a promotion log. Chosen over config flag (no audit trail) and background watcher (premature, non-deterministic). — Addresses: REQ-P24-P0-004
- **DEC-P24-005**: Rollback is manual only (`sigint model rollback`). No auto-rollback on eval-regression threshold. Chosen to keep the user in control and avoid model-swap thrashing. — Addresses: REQ-P24-P0-005
- **DEC-P24-006**: Fine-tune scope is whole-orchestrator for v1; role-specific support flagged P2. Chosen to avoid Phase 24 touching `sigint-core` agent-config schema. — Addresses: REQ-P24-P2-001, REQ-P24-NOGO-004
- **DEC-P24-007**: Correct Modelfile ADAPTER semantics — supersedes DEC-TRAIN-005. `generate_modelfile` takes `adapter_path: Option<&Path>`; emits ADAPTER only when a real LoRA adapter binary exists. Rationale: Phase 23 incorrectly pointed ADAPTER at training JSONL; Ollama expects a pre-trained adapter (GGUF or safetensors), not training data. This is the single required change to pre-existing Phase 23 code. — Addresses: REQ-P24-P0-002
- **DEC-P24-008**: Fine-tune output format is detected, not prescribed. If `$SIGINT_OUTPUT_PATH` resolves to an existing `.gguf` file, the result is treated as embedded-provider input; if the path doesn't exist but the basename appears in `ollama list`, it's treated as an Ollama tag. Rationale: respects user toolchain diversity without forcing one output kind. — Addresses: REQ-P24-P0-004

### Decision Log

| ID | Date | Decision | Context |
|----|------|----------|---------|
| DEC-P24-001 | 2026-04-22 | Fine-tune backend is an external shell-out command | User configures `config.train.finetune_command`; sigint passes env vars (SIGINT_TRAIN_JSONL, SIGINT_OUTPUT_PATH, …). Chosen over built-in trainer and `ollama create`. Phase 24 Task 2. |
| DEC-P24-002 | 2026-04-22 | Per-engagement opt-in harvest (`sessions.trainable` column) | Customer PII in engagement logs requires explicit consent; default `trainable=0`; `sigint train harvest <id>` sets to 1; export filters `WHERE trainable=1`. Phase 24 Task 1. |
| DEC-P24-003 | 2026-04-22 | Evaluation runs live inference on BOTH base and candidate | 80/20 holdout + `LlmProvider` against both models via `sigint-train/src/evaluate.rs`; replaces Phase 23's ground-truth self-evaluation. Phase 24 Task 3. |
| DEC-P24-004 | 2026-04-22 | Atomic config rewrite via `sigint model promote <tag>` | Writes `config.toml.tmp` then rename; backs up to `config.toml.bak`; appends JSONL entry to `~/.local/share/sigint/promotion.log`. Chosen over background watcher and config flag. Phase 24 Task 4. |
| DEC-P24-005 | 2026-04-22 | Rollback is manual only — `sigint model rollback` | Reads last promotion.log entry and reverses. No auto-rollback on eval regression; keeps the user in control and avoids model-swap thrashing. Phase 24 Task 4. |
| DEC-P24-006 | 2026-04-22 | Fine-tune scope is whole-orchestrator for v1 | Role-specific fine-tune (`config.agents.<role>.model`) flagged P2; avoids Phase 24 touching sigint-core agent-config schema. Phase 24. |
| DEC-P24-007 | 2026-04-22 | Correct Modelfile ADAPTER semantics (supersedes DEC-TRAIN-005) | `generate_modelfile` takes `adapter_path: Option<&Path>`; emits ADAPTER only when a real LoRA adapter binary exists. Phase 23 incorrectly pointed ADAPTER at training JSONL. Phase 24 Task 1. |
| DEC-P24-008 | 2026-04-22 | Fine-tune output format is detected, not prescribed | Existing `.gguf` at `$SIGINT_OUTPUT_PATH` → embedded provider; basename appearing in `ollama list` → Ollama tag. Respects user toolchain diversity. Phase 24 Task 4. |

### Task Breakdown (6 discrete tasks)

- [ ] **Task 1 — Harvest gating + Modelfile fix** (sigint-store migration, sigint-train, sigint-cli)
  - Add `trainable INTEGER NOT NULL DEFAULT 0` column to `sessions` table via new migration.
  - Add `Database::set_session_trainable(id, bool)` + `list_trainable_sessions()` methods.
  - Update `extract::extract_all` to filter `WHERE trainable=1` (add second function `extract_all_unfiltered` for tests and back-compat).
  - Update `modelfile::generate_modelfile` signature: `(base_model, adapter_path: Option<&Path>, system_prompt_override: Option<&str>, output_path) -> Result<()>`. Emit `ADAPTER` line only when `Some`.
  - Add `sigint train harvest <session_id>` CLI subcommand.
  - Acceptance: unit tests cover (a) migration adds column with default 0, (b) `extract_all` with no trainable sessions returns empty, (c) `modelfile` output contains ADAPTER iff `Some`, (d) harvest command toggles column.

- [ ] **Task 2 — Fine-tune shell-out runner** (sigint-train, sigint-cli, sigint-core config)
  - Add `TrainConfig { finetune_command: String, min_eval_examples: usize, job_dir: PathBuf }` to `sigint-core/src/config.rs`.
  - Add `sigint-train/src/finetune.rs` module with `run_finetune(cfg, base, output) -> Result<JobRecord>`. Executes the configured command with env vars; records JobRecord (id, command, start/end, exit_code, output_path) to `job_dir/jobs.json`.
  - Add `sigint train finetune --base <tag> --output <name>` CLI handler.
  - Add `sigint train jobs` to list job history.
  - Acceptance: integration test uses a mock finetune_command that `cat $SIGINT_TRAIN_JSONL > $SIGINT_OUTPUT_PATH` (fake training); verifies JobRecord persisted, exit code propagated, output file exists.

- [ ] **Task 3 — Live A/B evaluation** (sigint-train, sigint-cli)
  - Add `sigint-train/src/evaluate.rs`: `run_evaluation(provider_a, provider_b, test_examples) -> Result<ComparisonReport>`. Iterates test set, calls each provider's `chat()` with system + context from example, parses tool_calls from response, produces two prediction vectors, runs `assess::assess` on each, diffs results.
  - Add `sigint train evaluate --base <tag> --candidate <tag>` CLI handler. Uses `factory::create_provider` twice with mutated configs.
  - Persist last eval result to `~/.local/share/sigint/training/last_eval.json` for REQ-P24-P1-001.
  - Acceptance: integration test with MockProvider (from Phase 17) returns canned predictions; diff shows expected Δ values.

- [ ] **Task 4 — Promote + rollback** (sigint-cli, sigint-core)
  - Add `sigint-cli/src/model.rs` subcommands `run_promote(tag)` and `run_rollback()`.
  - Detect output kind per DEC-P24-008: check `models_dir/<tag>` (GGUF) then `ollama list` (Ollama tag).
  - Atomic config rewrite: write to `config.toml.tmp` then `rename`. Backup to `config.toml.bak` before rewrite.
  - Promotion log at `~/.local/share/sigint/promotion.log` (JSONL, append-only): `{ts, action, old_provider, old_model, new_provider, new_model, eval_result_ref}`.
  - Rollback reads last promotion entry, reverses fields.
  - P1 gate: refuse if `last_eval.json` shows `total_examples < config.train.min_eval_examples`, override with `--force`.
  - Acceptance: round-trip test (promote → rollback → promote); atomic-write test (simulate crash between tmp and rename, verify original config intact); P1 refusal test.

- [ ] **Task 5 — Doctor + config.example + README** (sigint-cli, repo root)
  - Extend `sigint doctor` with checks: `config.train.finetune_command` exists and is executable (if set); `models_dir` writable; `ollama` CLI on PATH when any Ollama-tagged promotion exists in log.
  - Add `[train]` section to `config.example.toml` with commented examples for unsloth/axolotl/MLX finetune_command.
  - Add "Fine-tuning Workflow" section to README.md (or USER_GUIDE.md): harvest → export → finetune → evaluate → promote → rollback, with one code block per step.
  - Add warning banner to `sigint train harvest` output: "Training data may contain sensitive engagement data. Review before sharing."
  - Acceptance: `sigint doctor` passes cleanly on default config without `[train]` section (feature is optional); passes with valid `[train]`; flags bad finetune_command.

- [ ] **Task 6 — End-to-end smoke test + supersedes-doc** (sigint-train integration tests, DECISIONS.md)
  - Integration test `tests/finetune_loop.rs` that runs the full chain against an in-memory DB: seed sessions with scan records, harvest, export, finetune (mock command), evaluate (MockProvider), promote, rollback. Assert every config-state transition.
  - Update DECISIONS.md: note that DEC-TRAIN-005 is superseded by DEC-P24-007 (Modelfile ADAPTER semantics corrected).
  - Update `@decision` annotations in `modelfile.rs` to cite DEC-P24-007 alongside the corrected rationale.
  - Update ARCHITECTURE.md "Fine-tuning" subsection (if one doesn't exist, add it) describing the closed loop.
  - Acceptance: smoke test runs end-to-end in CI within 30s (mocked trainer); coverage report shows no regression in sigint-train test coverage.

### Risks

1. **Ollama tooling availability at runtime** — If a user promotes to an Ollama-tagged model but the Ollama daemon isn't running (or the tag was created by `ollama create` that failed silently), the next scan will fail. Mitigation: doctor check for `ollama list` before promotion; promote command probes `ollama list | grep <tag>` and refuses if missing. Risk level: medium.
2. **Training data sensitivity (engagement logs contain customer PII)** — Opt-in harvest (DEC-P24-002) is the primary defense, but JSONL may still include IP addresses, hostnames, and tool output containing credentials. Mitigation: warning banner; documentation explicitly calls out responsibility to review before sharing; future Phase 25+ can add redaction pass as optional transform. Risk level: high (compliance-grade).
3. **Eval-regression false negatives** — An 80/20 split from a small engagement may produce a test set of only 10-20 examples, insufficient to detect real quality regressions. Mitigation: `min_eval_examples` threshold (default 50); `sigint model promote` refuses below threshold unless `--force`; doctor warns when test.jsonl has fewer than threshold examples. Risk level: medium.
4. **Shell-out security (user-configured finetune_command)** — The configured command runs outside any sandbox and inherits sigint's env. Mitigation: documented as a user-trust boundary (same category as `config.tools.shell.command` which is already trusted); command string echoed to stdout before execution; audit-logged. Risk level: medium — user configuration, not attacker-controllable.
5. **Long-running training processes** — Fine-tuning can take hours. Mitigation: `sigint train finetune` runs synchronously by default (user keeps terminal open) with `--detach` flag for nohup-style detach; `sigint train jobs` and `sigint train status <job_id>` for polling. Risk level: low.
6. **Config-rewrite corruption** — A crash during `config.toml` rewrite could brick the install. Mitigation: atomic write (temp + rename); backup to `config.toml.bak` before every promotion. Risk level: low.

### Worktree Strategy

- Branch: `feature/phase24-finetune-loop`
- Worktree: `.claude/worktrees/phase24-finetune-loop`
- Implementer sequence: Task 1 → Task 2 → Task 3 → Task 4 → (Task 5 ∥ Task 6 in parallel sub-branches optional)
- Merge to main only after all six tasks pass integration tests and the end-to-end smoke test in Task 6 is green.

### Phase 25: Security Hardening Pass (P0→P5)
**Status:** completed
**Branches merged:** security/p0-web-auth-bundle, fix/doctor-cli-test-build, security/p1-input-validators, security/p2-hardening, security/p3a-redaction, security/p3b-tool-acl, security/p4-prompt-injection, security/p5-cleanup
**Decision IDs:** DEC-WEB-AUTH-001, DEC-WEB-AUTH-002, DEC-RECON-SSRF-001, DEC-TOOL-NUCLEI-001, DEC-TOOL-NUCLEI-002, DEC-WEB-ERROR-001, DEC-WEB-RATELIMIT-001, DEC-DOCKER-001, DEC-CORE-REDACT-001, DEC-AGENT-PERSIST-REDACT-001, DEC-TRAIN-EXTRACT-REDACT-001, DEC-AGENT-TOOL-ACL-001, DEC-TOOL-SHELL-CANON-001, DEC-AGENT-PROMPT-SAFETY-001, DEC-WEB-RATELIMIT-002, DEC-CORE-REDACT-002, DEC-TOOL-NUCLEI-003, DEC-AGENT-PROMPT-SAFETY-002
**Depends on:** Phase 24 complete

#### Problem Statement

A CSO-mode security audit between Phase 24 and this pass flagged (a) an unauthenticated web control plane, (b) SSRF via recon against arbitrary targets, (c) container running as root, (d) credential leakage at persistence boundaries, (e) symlink-evading shell allowlist, (f) tool output reaching agent context without prompt-injection scrubbing, and (g) TOCTOU + case-sensitivity gaps surfaced during P3a–P4 finishing review. The pass closes them in six batches.

#### Tasks (all merged to main)

- **P0 — Web auth bundle** (`50d7894` merge `48d287e`) — Bearer middleware in `crates/sigint-web/src/auth.rs`, constant-time compare via `subtle`, WS token via query or `bearer.<token>` subprotocol, key resolution chain (config → env → persisted → auto-generate), CORS allowlist via `[web].cors_origins`.
- **P1 — Recon SSRF guard + nuclei allowlist** (`2ead3d5` merge `5f6cb9d`) — `crates/sigint-core/src/validate.rs` (target allowlist), `crates/sigint-recon/src/validate.rs`, `crates/sigint-tools/src/nuclei.rs` template/target validation.
- **P2 — Docker non-root, generic errors, scan rate limit** (`40af5f1` merge `64dae5a`) — Dockerfile UID change; `routes.rs` scrubs internal error details; per-operator scan rate-limit config.
- **P3a — Credential redaction at persistence** (`762fe0d` merge `22963a9`) — `crates/sigint-core/src/redact.rs` (OpenAI, Anthropic, AWS, GitHub PAT, Slack, Bearer/Basic, kv pairs, PEM); applied in `loop_engine` (agent persistence) and `sigint-train/extract.rs` (training corpus).
- **P3b — Tool risk-level ACL + shell symlink canonicalization** (`5038fc8` merge `c92b429`) — `crates/sigint-agents/src/tool_acl.rs` risk levels; `sigint-tools/src/shell.rs` canonicalizes paths before allowlist check (symlink `/tmp/grep -> /bin/bash` no longer bypasses).
- **P4 — Prompt-injection mitigation for tool output** (`0ac83b8` merge `f51ac17`) — `crates/sigint-agents/src/prompt_safety.rs`; `INJECTION_WARNING` appended to all 5 role prompts at orchestrator assembly; strips `</tool_output>`, `<|im_start|>`, fake BEGIN markers; 64 KiB cap.
- **P5 — TOCTOU + redactor/nuclei/prompt-safety hardening** (`fc05425` merge `df53fc0`) — rate-limit bug fix (max=0 inverted comparison); case-insensitive prompt-safety scrub via lowercased scratch; Nuclei template path TOCTOU fix; redactor tightening.

#### Decision Log

| ID | Date | Decision | Context |
|----|------|----------|---------|
| DEC-WEB-AUTH-001 | 2026-04-22 | Bearer + shared secret over OAuth/JWT/mTLS | Single-operator local/VPN tool; constant-time compare via `subtle` crate. P0. |
| DEC-WEB-AUTH-002 | 2026-04-22 | Auto-generate + persist API key on first boot | Beats "ship with no auth" and "refuse to start"; 32-byte URL-safe token persisted mode 0600. P0. |
| DEC-WEB-ERROR-001 | 2026-04-22 | Scrub internal error details from HTTP responses | Returns generic error codes; detailed errors only in server logs. P2. |
| DEC-WEB-RATELIMIT-001 | 2026-04-22 | Concurrent scan cap per operator (superseded by -002) | Initial implementation capped concurrent scans; superseded in P5 after max=0 inversion bug found by finisher. P2 → P5. |
| DEC-WEB-RATELIMIT-002 | 2026-04-24 | Rate-limit cap uses correct comparison + JSON 429 body | Supersedes DEC-WEB-RATELIMIT-001; fixes max=0 inverted comparison that rejected all scans. P5. |
| DEC-DOCKER-001 | 2026-04-22 | Container runs as non-root UID | Dockerfile USER directive; docker-compose updated. P2. |
| DEC-CORE-REDACT-001 | 2026-04-22 | Centralised redactor in sigint-core, applied at persistence boundaries | `crates/sigint-core/src/redact.rs`; OnceLock-cached regex set; zero new deps. P3a. |
| DEC-CORE-REDACT-002 | 2026-04-24 | Redactor patterns tightened after P5 review | Additional patterns + false-positive pruning; case-insensitivity audited. P5. |
| DEC-AGENT-PERSIST-REDACT-001 | 2026-04-22 | Loop engine redacts before scan_history write | Prevents tool output containing credentials from persisting into the engagement DB. P3a. |
| DEC-TRAIN-EXTRACT-REDACT-001 | 2026-04-22 | Training-corpus extract redacts at export time | Training JSONL cannot contain raw credentials; applied in `sigint-train/src/extract.rs`. P3a. |
| DEC-AGENT-TOOL-ACL-001 | 2026-04-22 | Tool allowlist is risk-level tiered | Low/Medium/High risk per tool; role ACL composes with risk gate. P3b. |
| DEC-TOOL-SHELL-CANON-001 | 2026-04-22 | Shell allowlist canonicalizes paths before check | `fs::canonicalize` before allowlist match; defeats symlink-based bypass; falls back to basename if path absent (preserves bare-name `$PATH` lookup). P3b. |
| DEC-AGENT-PROMPT-SAFETY-001 | 2026-04-22 | Tool output scrubbed before agent ingestion | Strips injection markers, caps at 64 KiB; INJECTION_WARNING appended to all 5 role prompts. Partial defense; classifier pass out of scope. P4. |
| DEC-AGENT-PROMPT-SAFETY-002 | 2026-04-24 | Prompt-safety scrub is case-insensitive | Lowercased scratch + range replace_range; UTF-8 safe because `to_ascii_lowercase` preserves byte lengths for ASCII. P5. |
| DEC-TOOL-NUCLEI-001 | 2026-04-22 | Nuclei template allowlist | Restricts user-supplied templates to a curated set. P1. |
| DEC-TOOL-NUCLEI-002 | 2026-04-22 | Nuclei target allowlist | Restricts scan targets to allowlisted ranges. P1. |
| DEC-TOOL-NUCLEI-003 | 2026-04-24 | Nuclei template TOCTOU fix | Path resolved and validated atomically; cannot swap template between check and use. P5. |
| DEC-RECON-SSRF-001 | 2026-04-22 | Recon target validation in `sigint-core/validate.rs` | Blocks internal IP ranges, link-local, loopback unless explicitly allowlisted. P1. |

#### Verification

- P0: User confirmed live — 401 without Bearer, 200 with, WS rejected without token.
- P2: Unit test `rate_limit_returns_429_when_cap_reached` (also caught the max=0 bug fixed in P5).
- P3a: 13 new tests; 328 total pass across sigint-core, sigint-agents, sigint-train.
- P3b: 9 new tests (6 tool_acl unit + 1 loop_engine integration + 3 shell symlink); 609 total pass.
- P4: 12 new tests (9 unit in prompt_safety + 2 integration in loop_engine + 1 orchestrator).
- P5: 692 tests pass; clippy `-D warnings` clean; fmt clean.

#### Not Done (follow-ups flagged)

- Content-classifier pass before LLM ingestion (P4 is a barrier-raiser, not comprehensive).
- Live container verification (no Docker daemon available at P2 merge time; Dockerfile + compose changes verified by static read).

### Phase 26: Fine-Tune Web UI
**Status:** completed
**Branch:** feature/phase26-finetune-ui
**Decision IDs:** DEC-P26-001, DEC-P26-002, DEC-P26-003, DEC-P26-004, DEC-P26-005, DEC-P26-006, DEC-P26-007, DEC-P26-008
**Requirements:** REQ-P26-P0-001 through REQ-P26-P0-007, REQ-P26-P1-001, REQ-P26-P1-002, REQ-P26-P2-001, REQ-P26-P2-002
**Issues:** #11 (T1), #12 (T2), #13 (T3), #14 (T4), #15 (T5), #16 (T6), #17 (T7), #18 (T8)
**Depends on:** Phase 24 (fine-tune loop), Phase 25 P0 (web auth + Bearer middleware), Phase 16 (web UI infrastructure — Axum + Preact + WebSocket bus), Phase 18 (ApprovalModal pattern)

#### Problem Statement

Phase 24 closed the CLI fine-tune loop: a pentester can run `sigint train harvest → export → finetune → evaluate` and `sigint model promote/rollback` to improve the orchestrator's tool-calling accuracy on their own engagement corpus. But every step is terminal-only. The product audience is pentesters who already prefer the browser for scan monitoring, finding triage, and report generation (Phases 16–18 shipped the web UI explicitly for that reason). Forcing them into a terminal just for the training loop creates a cliff in the UX and hides the capability — an operator who is already in the browser reviewing session findings has to switch contexts to improve the model that would have caught those findings better next time.

Evidence from reading `crates/sigint-cli/src/train.rs` and `model.rs`: every CLI subcommand (`harvest`, `export`, `finetune`, `jobs`, `evaluate`, `promote`, `rollback`) is a thin wrapper over a `sigint-train` or helper function. These can be reused verbatim from Axum handlers — the plumbing already exists. What's missing is (a) REST routes, (b) WebSocket event variants for long-running job progress, (c) the Preact surfaces. The Phase 16 web architecture (thin REST handlers + broadcast event bus + discriminated TS union) is exactly the shape this needs.

Product value: one-click harvest from the session list, visual progress for fine-tune jobs that can run for hours, side-by-side evaluation where Δ-tool-accuracy and Δ-argument-match are visible at a glance, and promotion/rollback gated behind the same `ApprovalModal` the operator already uses for tool approvals. The browser becomes the full control plane.

#### Goals

- **REQ-P26-GOAL-001** — A pentester can complete the full fine-tune loop (harvest → export → finetune → evaluate → promote) from the browser without opening a terminal or editing any file.
- **REQ-P26-GOAL-002** — Fine-tune job progress (a process that can run minutes to hours) is visible in real time; closing and re-opening the browser does not lose job state.
- **REQ-P26-GOAL-003** — Evaluation results are presented side-by-side with Δ-metrics prominent so the operator can promote with confidence — or reject and re-train.
- **REQ-P26-GOAL-004** — Every model swap (promote, rollback) requires an explicit browser confirmation, reusing the existing tool-approval pattern so there is no new UX primitive to learn.
- **REQ-P26-GOAL-005** — The CLI and web surface share a single source of truth (same `jobs.json`, same `promotion.log`, same `last_eval.json`) so mixed CLI+web workflows never drift.

#### Non-Goals

- **REQ-P26-NOGO-001** — No automatic training triggers (timer-based, scan-count-based, or event-driven). All fine-tune runs remain user-initiated per the spirit of DEC-P24-005.
- **REQ-P26-NOGO-002** — No real-time training-loss visualization beyond a heartbeat progress bar. Loss curves require trainer-specific stdout parsing that's out of scope for v1.
- **REQ-P26-NOGO-003** — No cross-engagement training aggregation UI. Users harvest specific sessions; there is no "train on everything" or auto-assemble wizard.
- **REQ-P26-NOGO-004** — No multi-user training queue. SIGINT is single-operator; concurrent fine-tunes serialize via a semaphore (see DEC-P26-008).
- **REQ-P26-NOGO-005** — No mobile-responsive training pages. The Phase 16 UI targets desktop; fine-tune UIs match that surface area.
- **REQ-P26-NOGO-006** — No trainer management UI (install unsloth, configure conda envs, GPU selection). The `finetune_command` in config remains a user-trust boundary per DEC-P24-001.
- **REQ-P26-NOGO-007** — No background promotion (e.g., "auto-promote if Δ > 3pp"). Every promotion is an explicit modal confirmation.

#### Requirements

**Must-Have (P0)**

- **REQ-P26-P0-001** — Harvest toggle on the sessions list.
  Acceptance: Given the sessions page, When the operator clicks the Harvest toggle on a row, Then `POST /api/train/harvest/:id` is called, the row's `trainable` flag flips in the UI immediately (optimistic update with rollback on error), and a tooltip warns about PII per the Phase 24 banner text.
- **REQ-P26-P0-002** — Train workbench page at `/train` that exposes stats, export, finetune, and evaluate steps.
  Acceptance: Given a user with at least one harvested session, When they navigate to `/train`, Then the page shows (a) training stats (example count, role breakdown, trainable session count) from `GET /api/train/stats`, (b) an Export button that triggers `POST /api/train/export` and reports the sample counts, (c) a fine-tune form (base model, output name) that starts the job, (d) a link to the evaluate page. Each step visually indicates ready/running/done/error state.
- **REQ-P26-P0-003** — Fine-tune job progress streams via WebSocket; job history persists across reloads.
  Acceptance: Given a running fine-tune job, When the operator reloads the page, Then the job appears in the Jobs table with the correct status (running/completed/failed), duration, and the latest progress heartbeat; the same info is reachable via `GET /api/train/jobs` and `GET /api/train/jobs/:id`. WebSocket events `TrainingJobStarted`, `TrainingJobProgress`, `TrainingJobCompleted`, `TrainingJobFailed` arrive in-band with scan events.
- **REQ-P26-P0-004** — Evaluation page renders base vs candidate side-by-side with Δ-metrics.
  Acceptance: Given a completed fine-tune output, When the operator selects a candidate + base and clicks Evaluate, Then the page streams progress per example, presents tool-accuracy and argument-match for both models, highlights Δ with color coding (green ≥ 0, red < 0), and persists the result to `last_eval.json` via the existing `sigint-train::evaluate::persist_last_eval` helper.
- **REQ-P26-P0-005** — Promote action opens the existing `ApprovalModal`, blocking the swap until the operator confirms.
  Acceptance: Given a candidate tag, When the operator clicks Promote, Then an `ApprovalModal` appears showing `old_provider/old_model → new_provider/new_model`, the most recent eval Δ (if present), and a confirm/cancel choice. Confirm calls `POST /api/model/promote` and the config rewrite occurs server-side exactly as the CLI path does. Cancel closes the modal with no side effect. The P1 gate from DEC-P24 (min_eval_examples) surfaces as a warning in the modal; an explicit `force` checkbox forwards the flag.
- **REQ-P26-P0-006** — Rollback is one click and is discoverable on the same screen as promotion history.
  Acceptance: Given at least one prior promotion, When the operator clicks Rollback on the most recent promotion entry, Then the same `ApprovalModal` confirms the reversal, calls `POST /api/model/rollback`, and the promotion-history table refreshes to show the new rollback entry appended.
- **REQ-P26-P0-007** — All new routes authenticate via the Phase 25 Bearer middleware; WebSocket training events use the same token/subprotocol mechanism as existing events.
  Acceptance: Given an unauthenticated request to any `/api/train/*` or `/api/model/(promote|rollback|promotions)` route, Then the server returns `401`. Given a WebSocket connected without the Bearer query/subprotocol, Then training events are not delivered.

**Nice-to-Have (P1)**

- **REQ-P26-P1-001** — Job detail drawer with stdout tail.
  Acceptance: Clicking a job row opens a drawer showing the last 2 KiB of stdout (capped server-side), exit code, env-var summary, and duration. Refreshes live while the job is running.
- **REQ-P26-P1-002** — Bulk-harvest action on the sessions page.
  Acceptance: Selecting multiple session rows and clicking "Harvest selected" calls harvest once per ID (or a single batch endpoint if cheap to add). Rollback-on-error per row.

**Future Consideration (P2)**

- **REQ-P26-P2-001** — Trainer stdout parser plug-ins that extract loss/step from known trainers (unsloth, axolotl) into structured progress events. Data model already supports arbitrary progress heartbeat JSON; the parser is the missing piece. Deferred.
- **REQ-P26-P2-002** — Per-role evaluation view showing Δ broken down by agent role (recon/attack/exploit/report). `agent_role` is already on training examples from Phase 24; UI deferred until role-specific fine-tuning (REQ-P24-P2-001) lands.

#### Definition of Done

- **REQ-P26-GOAL-001 satisfied**: A browser-only end-to-end demo (toggle harvest → export → finetune with mock trainer → evaluate with MockProvider → promote → rollback) completes without the operator touching a terminal. Captured as an e2e test using `/browse` against the running server.
- **REQ-P26-GOAL-002 satisfied**: Restarting the browser during a running fine-tune job restores job state from `jobs.json` via `GET /api/train/jobs`; the new WebSocket subscription picks up subsequent progress events.
- **REQ-P26-GOAL-003 satisfied**: The evaluation page renders the same numbers as the CLI's `sigint train evaluate` output for the same inputs; Δ-metrics are visually distinct (color + sign) for positive/negative deltas.
- **REQ-P26-GOAL-004 satisfied**: Promote and rollback both route through `ApprovalModal`; no code path swaps the model without a browser confirmation.
- **REQ-P26-GOAL-005 satisfied**: A mixed workflow (CLI harvest + web evaluate + CLI promote, or any permutation) produces consistent state — the same `jobs.json`, `last_eval.json`, and `promotion.log` files are read and appended by both surfaces.
- All `cargo test -p sigint-web`, `cargo test -p sigint-train`, `cargo test -p sigint-cli` pass.
- Frontend builds cleanly (`cd crates/sigint-web/frontend && npm run build`).
- README / USER_GUIDE gains a "Fine-tuning from the Web UI" section with screenshots and the `/train` route documented.
- `sigint doctor` is unchanged; Phase 24's checks cover the shared state.

### Planned Decisions

- **DEC-P26-001**: Long-running job transport = existing WebSocket event bus with new `TrainingJob*` / `Evaluation*` / `Model*` variants. Chosen over SSE (would require a second transport surface; the frontend already consumes a discriminated union), and over polling (masks failures, higher latency, higher request volume). Cost: ~20 lines of Rust enum variants + matching TS union members. — Addresses: REQ-P26-P0-003, REQ-P26-P0-004
- **DEC-P26-002**: Job state persistence stays in `~/.local/share/sigint/training/jobs.json` (JSONL). Not migrated to SQLite. Chosen because the CLI (Phase 24) already reads/writes this file, a schema migration forces a CLI-side change with no corresponding benefit, the file is append-only and crash-safe, and single-operator scale never exceeds a few dozen rows. SQLite would make sense if we later needed cross-query or multi-user views — that's a future phase. — Addresses: REQ-P26-GOAL-005, REQ-P26-P0-003
- **DEC-P26-003**: Evaluation UI is a dedicated page (`/train/evaluate` or `/train/jobs/:id/evaluate`) with a diff table, not a modal or inline-in-jobs-list component. Chosen because the evaluation view is the go/no-go decision point — it deserves space, scroll, and revisit behavior. Modal rejected (cramped for comparison tables); inline rejected (hides the Δ signal in a busy list). — Addresses: REQ-P26-P0-004, REQ-P26-GOAL-003
- **DEC-P26-004**: Promote and rollback reuse the existing `ApprovalModal` / `ApprovalRegistry` infrastructure from Phase 17. The browser operator confirms via the same UX they already use for tool-call approvals. Chosen over a custom confirm dialog (adds a second approval primitive, splits user mental model) and over a "just a red button" direct action (violates Sacred Practice #8 — approval gates for destructive model swaps). — Addresses: REQ-P26-P0-005, REQ-P26-P0-006, REQ-P26-GOAL-004
- **DEC-P26-005**: Config additions are scoped to `[web.train]` for UI-only knobs (`stdout_tail_bytes` default 2048, `jobs_page_size` default 20, `max_concurrent_jobs` default 1). The existing `[train]` section stays unchanged. Chosen to keep CLI-relevant config separate from presentation-layer config so CLI users don't see `[web.train]` noise and the `finetune_command` definition isn't duplicated. — Addresses: REQ-P26-P1-001, REQ-P26-NOGO-004
- **DEC-P26-006**: Promotion history is inlined on the `/models` (extended) or `/train/promote` page, not a separate settings screen. Chosen because discoverability matters — the operator browsing models is the exact audience for "here's what you last switched to, one-click rollback." A separate `/settings/promotions` page would bury the capability. — Addresses: REQ-P26-P0-006, REQ-P26-GOAL-004
- **DEC-P26-007**: WebSocket auth for training events reuses Phase 25 P0 Bearer-subprotocol resolution (`bearer.<token>` or `?token=` query). No new auth code. The same middleware gates `/api/train/*` REST routes. Chosen to avoid a second auth surface; P0 security stays uniform. — Addresses: REQ-P26-P0-007
- **DEC-P26-008**: Fine-tune job execution runs in-process on the web server via `tokio::process::Command`, streaming stdout to the event bus as `TrainingJobProgress` heartbeats. Concurrency is capped via a semaphore (`[web.train].max_concurrent_jobs`, default 1). Chosen over a separate trainer daemon (premature; no multi-host deployment), and over in-request blocking (would hang the axum handler for hours). The handler returns `202 Accepted` with the job ID immediately; the task runs to completion on the tokio runtime. A concurrent-job cap reuses the DEC-WEB-RATELIMIT-002 pattern (atomic semaphore try_reserve). — Addresses: REQ-P26-P0-003, REQ-P26-NOGO-004

### Decision Log

| ID | Date | Decision | Context |
|----|------|----------|---------|
| DEC-P26-001 | 2026-04-24 | Long-running job transport = WebSocket event variants | Existing broadcast bus extended with `TrainingJob*`, `Evaluation*`, `Model*` variants. Chosen over SSE (second transport surface) and polling (latency, masks failures). T2 PR #20. |
| DEC-P26-002 | 2026-04-24 | Job state persistence stays in `~/.local/share/sigint/training/jobs.json` (JSONL) | Not migrated to SQLite. CLI already reads/writes this file (Phase 24); single-operator scale never exceeds a few dozen rows. T1 PR #22. |
| DEC-P26-003 | 2026-04-24 | Evaluation UI is a dedicated page (`/train/evaluate`), not a modal | Eval is the go/no-go decision point — deserves space, scroll, revisit behavior. T7 PR #27. |
| DEC-P26-004 | 2026-04-24 | Promote and rollback reuse the existing `ApprovalModal` from Phase 17 | Same UX primitive as tool-call approvals. Extended with backward-compatible optional `warning` + `extraField` props for the force-promote-below-threshold flow. T7 PR #27. |
| DEC-P26-005 | 2026-04-24 | Config additions scoped to `[web.train]` | UI-only knobs (`max_concurrent_jobs`, `stdout_tail_bytes`, `jobs_page_size`). Existing `[train]` stays single-sourced for CLI. T1 PR #22. |
| DEC-P26-006 | 2026-04-24 | Promotion history inlined on `/models` | Discoverability — operator browsing models is the audience for "here's what you last switched to." Separate `/settings/promotions` would bury the capability. T7 PR #27. |
| DEC-P26-007 | 2026-04-24 | WebSocket auth reuses Phase 25 P0 Bearer-subprotocol | No new auth surface. Same middleware gates `/api/train/*` and `/api/model/*` REST routes. T1 PR #22, T3 PR #23. |
| DEC-P26-008 | 2026-04-24 | Fine-tune jobs run in-process via `tokio::process::Command` | Spawned task with semaphore cap (`[web.train].max_concurrent_jobs`, default 1). Handler returns 202 + job_id immediately. Mirrors DEC-WEB-RATELIMIT-002 semaphore pattern. T1 PR #22. |
| DEC-P26-T1B-001 | 2026-04-27 | Streaming runner is a separate async fn (`run_finetune_streaming`); sync `run_finetune` unchanged | CLI path has no progress consumer; forcing tokio there adds unnecessary surface area. Shared persist + audit helpers avoid duplication. Closes issue #21. |
| DEC-P26-T1B-002 | 2026-04-27 | Progress events rate-limited to ≤1/sec; tail bounded by `stdout_tail_bytes` (default 2048) | Plan Risk #2: line-rate trainer output would flood the broadcast bus. ≤1/sec is fast enough for human UX, safe for bus health. Implemented as `last_emitted: Instant` guard inside `run_finetune_streaming`. |
| DEC-P26-T1B-003 | 2026-04-27 | `job_id` plumbed in by caller; not generated inside `run_finetune` / `run_finetune_streaming` | Previously each function called `Uuid::new_v4()` internally, so the UUID returned in the 202 body never matched the persisted `JobRecord`. `GET /api/train/jobs/<id>` always 404'd for web clients. Caller (web handler or CLI) now passes its own `job_id` string, closing issue #35. |
| DEC-P26-T8-001 | 2026-04-27 | Provider construction plumbed via `AppState.provider_factory`; `full_loop.rs` evaluate step re-enabled | `train_run_eval` previously hardcoded `OllamaProvider::from_config`, preventing MockProvider injection from tests. `ProviderFactory` type alias (`Arc<dyn Fn(&LlmConfig) -> Result<Box<dyn LlmProvider>, Error> + Send + Sync>`) added to `AppState`. Production binds `sigint_llm::factory::create_provider`; tests inject a closure returning `MockProvider::new()`. Closed the architectural gap noted in the original Phase 26 T8 retrospective. All 4 CI gates pass. |

#### Follow-Ups (tracked as open issues)

- **Issue #21** — CLOSED. TrainingJobProgress streaming implemented in T1b: `run_finetune_streaming` async function added to `sigint-train::finetune`, web handler wired to call it. DEC-P26-T1B-001 and DEC-P26-T1B-002 record the design choices.
- **DEC-P26-T6-002** — P1 job-detail drawer in the workbench page. Backend `JobRecord.stdout_tail` field doesn't exist; adding it is a small follow-up.
- **DEC-P26-T8-001** — CLOSED. Provider factory threaded through `AppState`; `full_loop.rs` evaluate step re-enabled end-to-end. `ProviderFactory` type alias added to `state.rs`; production binds `create_provider`, tests inject `MockProvider`. Decision recorded in decision log above.
- **REQ-P26-P1-002** — Bulk-harvest selection bar on the sessions page. DataTable lacks row-selection primitive. Tracked as follow-up against #15.

### Task Breakdown (8 discrete tasks)

- [ ] **Task 1 — Backend REST routes for harvest/stats/export/finetune/jobs** (sigint-web, sigint-agents glue)
  - Add `POST /api/train/harvest/:id` → `Database::set_session_trainable(id, true)`.
  - Add `POST /api/train/unharvest/:id` → `Database::set_session_trainable(id, false)`.
  - Add `GET /api/train/stats` → `extract::extract_all` without file writes, return counts.
  - Add `POST /api/train/export` → wraps `train::run_export` logic; returns `{train_count, test_count, train_path, test_path}`.
  - Add `POST /api/train/finetune` → kicks off a background `tokio::spawn` wrapping `finetune::run_finetune`; returns `202 Accepted` with `job_id` immediately. Streams stdout/stderr to the event bus per DEC-P26-001.
  - Add `GET /api/train/jobs` and `GET /api/train/jobs/:id` → reads `jobs.json` (DEC-P26-002).
  - Add semaphore `training_job_semaphore` to `AppState` with cap from `[web.train].max_concurrent_jobs` (DEC-P26-008).
  - Acceptance: Unit tests for each route (200/201/401/404/409 paths); integration test with mock `finetune_command` returns a completed job within 5s.

- [ ] **Task 2 — Event bus additions for training lifecycle** (sigint-core events, sigint-web ws.rs passthrough, sigint-web frontend types)
  - Add `Event::TrainingJobStarted { job_id, base_model, output_path }`.
  - Add `Event::TrainingJobProgress { job_id, heartbeat_at, stdout_tail }`.
  - Add `Event::TrainingJobCompleted { job_id, exit_code, duration_secs }`.
  - Add `Event::TrainingJobFailed { job_id, error }`.
  - Add `Event::EvaluationStarted { eval_id, base_tag, candidate_tag, total_examples }`.
  - Add `Event::EvaluationProgress { eval_id, examples_done }`.
  - Add `Event::EvaluationCompleted { eval_id, report_path }`.
  - Add `Event::ModelPromoted { old_provider, old_model, new_provider, new_model }`.
  - Add `Event::ModelRolledBack { old_provider, old_model, new_provider, new_model }`.
  - Mirror in `crates/sigint-web/frontend/src/types.ts` discriminated union.
  - Acceptance: Events round-trip through WebSocket and land in the TS union with no `unknown` narrowing.

- [ ] **Task 3 — Backend routes for evaluate + promote + rollback + promotions** (sigint-web routes.rs, shared promotion helper)
  - Add `POST /api/train/evaluate { base, candidate }` → spawns `evaluate::run_comparison`, streams progress events, persists `last_eval.json`, returns eval handle.
  - Add `GET /api/train/evaluations/last` → reads `last_eval.json`.
  - Extract the `atomic_config_rewrite` + `append_promotion_log` helpers from `sigint-cli/src/model.rs` into a shared module (suggested: `sigint-train/src/promotion.rs` or `sigint-core/src/promotion.rs`) so both CLI and web call the same code path (single source of truth per REQ-P26-GOAL-005).
  - Add `POST /api/model/promote { tag, force }` → calls shared promote helper; emits `ModelPromoted` event; returns new config state.
  - Add `POST /api/model/rollback` → calls shared rollback helper; emits `ModelRolledBack`.
  - Add `GET /api/model/promotions` → reads `promotion.log` and returns JSON array.
  - Acceptance: round-trip test (promote → list promotions → rollback → list) against in-memory DB and temp config path; P1 gate test with `force=false` returns 409, with `force=true` succeeds.

- [ ] **Task 4 — Frontend types + api.ts client** (sigint-web/frontend/src)
  - Add `TrainStats`, `ExportResult`, `TrainingJob`, `EvaluationReport`, `PromotionEntry`, `ModelState` types to `types.ts`.
  - Add the new WS event variants to the `WsEvent` discriminated union.
  - Add `api.train.*` namespace (`harvest`, `unharvest`, `stats`, `export`, `finetune`, `jobs`, `job`, `evaluate`, `lastEvaluation`) and `api.model.*` additions (`promote`, `rollback`, `promotions`).
  - Acceptance: `npm run typecheck` passes; new calls compile against the route shapes defined in Task 1/3.

- [ ] **Task 5 — Sessions harvest toggle** (sigint-web/frontend/src/components, pages/sessions.tsx)
  - Add a `trainable` column to the sessions table with a toggle component.
  - Optimistic UI update with rollback on fetch error.
  - Tooltip: "Enables this session's scan history for fine-tune export. Data may contain PII — review before sharing." (matches the Phase 24 CLI banner.)
  - P1: Add selection checkboxes + "Harvest selected" action bar if Task 5 has budget; otherwise defer to follow-up issue.
  - Acceptance: Visual QA via `/browse` — click toggle, see flag persist after reload; backend sees `trainable=1` in DB.

- [ ] **Task 6 — Train workbench page** (sigint-web/frontend/src/pages/train.tsx)
  - New route `/train`. Hash router entry.
  - Four sequential cards: Stats → Export → Fine-tune → Evaluate (link to `/train/evaluate`).
  - Stats card renders counts from `GET /api/train/stats` with a "Refresh" button.
  - Export card has an "Export now" button and reports counts.
  - Fine-tune card: form (base model dropdown from `/api/models`, output-name text, optional advanced JSON), Start button; shows live status via WS events; surfaces errors inline. Disables while another job is running (DEC-P26-008).
  - Jobs mini-table at the bottom showing the last 5 jobs with status + duration; click-through to `/train/jobs/:id`.
  - Acceptance: Visual QA end-to-end with mock `finetune_command`; progress bar updates on WS heartbeat; completed job flips card to "Done" with output path.

- [ ] **Task 7 — Evaluation diff page + promotion + rollback UI** (sigint-web/frontend/src/pages/evaluate.tsx, pages/models.tsx)
  - New route `/train/evaluate?base=&candidate=`. Selectors pre-populated when navigated from a completed job.
  - Renders base/candidate header row; per-metric row (tool_accuracy, argument_match); Δ column with green/red coloring and explicit + or – sign.
  - "Promote candidate" button opens `ApprovalModal` showing old→new, eval summary, optional `force` checkbox for the min_eval_examples gate. On confirm, calls `api.model.promote`. On rollback-history row: "Rollback" button opens `ApprovalModal` with reversed direction.
  - Extend `/models` page (or add `/train/promote`) to show the current active model prominently and a promotion-history table (DEC-P26-006).
  - Acceptance: Visual QA — evaluate + promote + rollback round-trip via browser; the same `ApprovalModal` shell used for tool approvals renders here; denied promote has no side effect.

- [ ] **Task 8 — User docs + e2e test + shared-helper landing** (README/USER_GUIDE, tests, DECISIONS.md)
  - Add "Fine-tuning from the Web UI" section to USER_GUIDE.md with the four screenshots (harvest, workbench, evaluate, promote modal).
  - Add `crates/sigint-web/tests/train_flow.rs` integration test: harvest → export → mock-finetune → evaluate with MockProvider → promote → rollback, all via `oneshot` HTTP requests. Asserts terminal state matches CLI round-trip.
  - Add a `/browse`-driven e2e that exercises the same flow visually (runs against a spawned server).
  - Append DEC-P26-* entries to DECISIONS.md with cross-references to the CLI-side DEC-P24-004/005/008 they wrap.
  - Update `@decision` annotations in `sigint-web/src/routes.rs`, frontend pages, and any new shared `promotion.rs` module.
  - Acceptance: integration test green in CI; USER_GUIDE section renders correctly; DECISIONS.md reflects the new decisions.

### Risks

1. **Long-running job leaks if the web server restarts mid-fine-tune.** The spawned `tokio::process::Command` is tied to the server's lifetime — a server restart orphans the child process. Mitigation: on startup, reconcile `jobs.json` entries that are `running` but whose PID is absent, mark them `failed` with an explanatory note; surface in the UI. Document restart behavior in USER_GUIDE. Severity: medium.
2. **Stdout flooding overwhelms the WebSocket bus.** Chatty trainers (unsloth) can emit hundreds of lines per second; forwarding all of that as `TrainingJobProgress` can starve scan events. Mitigation: per-job rate-limit the heartbeat (default 1/sec or every N KB); store the full stdout to a file (`jobs/<id>.stdout`) for the drawer; the WS only carries the tail. Severity: medium.
3. **Config rewrite races between CLI and web.** If the CLI calls `sigint model promote` while the web UI also posts to `POST /api/model/promote`, two processes could contend on `config.toml`. Mitigation: advisory file lock (`fs2::FileExt::try_lock_exclusive`) around the atomic rewrite; second caller receives `409 Conflict` or waits. The shared helper (Task 3) is the single place to add this. Severity: low-medium.
4. **Browser operator force-promotes below eval threshold without reading the warning.** Destructive UX risk — the modal's `force` checkbox could be clicked reflexively. Mitigation: warning banner inside the modal with exact number ("Only 12 evaluation examples — below the 50-sample threshold. Model quality is not guaranteed."); `force` defaults unchecked; requires two distinct clicks (check, then Promote). Severity: medium.
5. **WebSocket lag during concurrent scan + training.** With the broadcast bus shared, heavy scan activity could delay training progress events and vice versa. Mitigation: confirm the bus capacity (currently broadcast channel; audit during Task 2); if insufficient, either bump capacity or split into two channels. Severity: low.
6. **PII leakage via `stdout_tail` on the jobs drawer.** The trainer might echo redacted-but-still-identifying strings (IP blocks, hostnames). Mitigation: pipe trainer stdout through `sigint-core::redact::scrub` (Phase 25 P3a) before storing or sending to the browser. Severity: medium — regulatory if not addressed.
7. **Trainer command injection via output-name parameter.** If the frontend lets the user pass `output_name` that gets interpolated into `SIGINT_OUTPUT_PATH`, a crafted value could escape the path. Mitigation: server-side validation — `output_name` must match `[a-zA-Z0-9_.-]{1,64}`; rejected names return 400. Severity: medium — attacker-controllable if the web UI is exposed.
8. **Evaluation runs blocking the event loop.** `run_comparison` loops over the test set doing LLM calls; if spawned on the main handler's task, the response hangs. Mitigation: same pattern as Task 1 — return `202` with eval_id immediately, run on a spawned task with progress events. Severity: low — well-understood pattern.

### Worktree Strategy

- Branch: `feature/phase26-finetune-ui`
- Worktree: `.claude/worktrees/phase26-finetune-ui`
- Implementer sequence:
  - Wave 1 (backend foundations, parallel): Task 1 (REST routes) and Task 2 (events) — independent enough to share a single worktree, commit atomically, or split into sub-branches.
  - Wave 2 (backend extension): Task 3 (evaluate + promote + rollback, depends on shared promotion helper from Task 1).
  - Wave 3 (frontend wiring, parallel): Task 4 (types/api.ts) gates Tasks 5–7; Tasks 5, 6, 7 can be parallelized as sub-worktrees once Task 4 lands.
  - Wave 4: Task 8 (docs + e2e + DECISIONS) — serialized last to capture the final state.
- Merge to main only after all eight tasks pass cargo tests, `npm run build` is clean, and the `/browse` e2e demonstrates the full loop. Guardian PRs the phase plan update (this section) as a separate doc-only commit before implementation begins.

---

### Phase 27: Plugin Packaging + Local Install
**Status:** planned
**Branch:** feature/phase-27-plugin-pack (created at implementation time)
**Decision IDs:** DEC-P27-001, DEC-P27-002, DEC-P27-003, DEC-P27-004, DEC-P27-005, DEC-P27-006, DEC-P27-007, DEC-P27-008
**Requirements:** REQ-P27-GOAL-001 through REQ-P27-GOAL-004, REQ-P27-NOGO-001 through REQ-P27-NOGO-006, REQ-P27-P0-001 through REQ-P27-P0-010, REQ-P27-P1-001 through REQ-P27-P1-003, REQ-P27-P2-001 through REQ-P27-P2-004
**Issues:** TBD (orchestrator opens after docs PR merges)
**Depends on:** Phase 22 (compile-time plugin system, `sigint-plugin` crate, `Tool` trait, `inventory`-based registration), Phase 25 (security pass — applies to install-path validation)

#### Problem Statement

Phase 22 shipped a compile-time plugin system: external crates implement `sigint_tools::Tool`, register via `register_tool!()`, and `collect_plugin_tools()` discovers them via the `inventory` crate at link time. The model works for in-tree plugins, but it caps sigint's reach: every external contributor must fork the workspace, add their crate as a member, and rebuild the binary from source. A pentester who writes a custom recon tool cannot share it without their consumers running `cargo build --release` from source — that is not a distribution model, it is a build instruction.

Evidence from reading `crates/sigint-plugin/src/lib.rs`: `inventory::collect!` is fundamentally a link-time mechanism. It cannot pick up crates that were not present when `cargo build` ran. There is no runtime hook to add a `ToolFactory` after the binary started. This means the existing plugin surface is closed at compile time by design. Without a runtime loading path, "plugin system" is a misnomer — it is really a "first-party tool extension scaffold".

Phase 27 closes the local-install gap and only the local-install gap. It defines a `.sgnt-pack` package format, ships CLI commands to pack / install / list / uninstall plugins, and adds a runtime loader that surfaces installed plugins in the registry alongside compile-time ones. The format and loader decisions calcify once external developers consume them, so they must be pinned now even though the trust model (signing, sandbox) is deferred.

Trusted-local and unsandboxed by design: an operator-asserted trust boundary at install time. The user runs `sigint plugin install ./my-plugin.sgnt-pack` against a binary they trust, with a plugin file they trust. Phase 28 will harden against untrusted plugins via signing, a remote registry, and sandboxed execution. Phase 27 must lay seams that Phase 28 can extend without rewriting Phase 27 surfaces.

#### Goals

- **REQ-P27-GOAL-001** — A plugin author packages their crate into a single `.sgnt-pack` artifact via `sigint plugin pack <crate-path>`, and a consumer installs it via `sigint plugin install <path>` without modifying the consumer's source tree or rebuilding the sigint binary.
- **REQ-P27-GOAL-002** — Installed plugins appear in `sigint plugin list` alongside compile-time plugins and are loaded at startup so their tools are visible to agents in the same way compile-time tools are.
- **REQ-P27-GOAL-003** — The existing `Plugin` / `Tool` trait surface and the `inventory`-based compile-time registration path remain unchanged; runtime loading is additive only.
- **REQ-P27-GOAL-004** — Phase 28 (signing, registry, sandbox) drops into well-defined seams identified explicitly in this phase — no rework of Phase 27 surfaces.

#### Non-Goals

- **REQ-P27-NOGO-001** — No signing, signature verification, or trust roots. Trust is operator-asserted at install time.
- **REQ-P27-NOGO-002** — No remote registry, discovery, or `plugin search` command. Install accepts a local file path only.
- **REQ-P27-NOGO-003** — No runtime sandbox for plugin code. Loaded plugins run in the host process with full host privileges.
- **REQ-P27-NOGO-004** — No cross-platform binary compatibility. Pack format is host-platform-specific (target-triple-pinned). A pack built on `x86_64-unknown-linux-gnu` is not installable on macOS.
- **REQ-P27-NOGO-005** — No automatic update or version management. Installing an updated version requires explicit `sigint plugin uninstall` + `sigint plugin install`.
- **REQ-P27-NOGO-006** — No hot reload. A plugin uninstalled at runtime takes effect on the next process start; a newly installed plugin is not loaded into the running process.

#### Requirements

**Must-Have (P0)**

- **REQ-P27-P0-001** — `.sgnt-pack` is a deterministic archive containing a manifest, a single dynamic library, and optional auxiliary files.
  Acceptance: Given any plugin crate that builds a `cdylib`, When `sigint plugin pack <crate-path>` runs, Then the output is a single `.sgnt-pack` file whose contents (when extracted) include `manifest.json`, the platform-appropriate dynamic library (`.so` / `.dylib` / `.dll`), and optionally `README.md` and `LICENSE`. The pack format is locked in DEC-P27-001.
- **REQ-P27-P0-002** — Manifest schema is explicit and machine-validated.
  Acceptance: Given a `.sgnt-pack` install attempt, When the manifest is missing required fields or contains unknown required fields, Then install fails with a structured error and writes nothing to the install dir. Required fields: `id` (semver-stable identifier), `version` (semver), `target_triple`, `entry_symbol`, `manifest_version`. Optional: `display_name`, `description`, `author`, `homepage`, `license`. Schema locked in DEC-P27-002.
- **REQ-P27-P0-003** — Runtime loader uses `libloading` to `dlopen` the dynamic library and call the entry symbol.
  Acceptance: Given an installed plugin matching the host target triple, When `AppCore::init()` runs, Then the loader (a) opens the library with `libloading::Library::new`, (b) resolves the manifest's `entry_symbol` via `Library::get`, (c) invokes the C-ABI entry function which returns a list of `Box<dyn Tool>` factories, (d) registers them in the same registry consulted by agents. The `Plugin` trait + entry-symbol C ABI is locked in DEC-P27-003.
- **REQ-P27-P0-004** — Install location is namespaced by id+version under the platform user-data directory.
  Acceptance: Given `sigint plugin install <path>`, When the manifest declares `id=foo` and `version=1.2.3`, Then the install dir is `${XDG_DATA_HOME:-~/.local/share}/sigint/plugins/foo-1.2.3/` (Linux), `~/Library/Application Support/sigint/plugins/foo-1.2.3/` (macOS), or `%APPDATA%/sigint/plugins/foo-1.2.3/` (Windows). The path layout is locked in DEC-P27-004.
- **REQ-P27-P0-005** — Startup discovery scans the install dir and registers each valid plugin.
  Acceptance: Given any number of installed plugins, When `sigint` starts, Then the loader walks the install dir, validates each manifest, attempts to load each library, and registers tools from successful loads in the runtime tool registry alongside `inventory`-collected compile-time tools. Discovery mechanism locked in DEC-P27-005.
- **REQ-P27-P0-006** — A failing plugin logs a warning and is skipped — never crashes the binary.
  Acceptance: Given a plugin with any failure mode (manifest invalid, target triple mismatch, library missing, `dlopen` error, missing entry symbol, panic in entry function, schema version too new), When the binary starts, Then a structured `tracing::warn!` is emitted with `plugin_id`, `plugin_path`, `failure_reason`, and the binary continues startup with that plugin skipped. Compile-time plugins and other runtime plugins still load. Failure-handling contract locked in DEC-P27-006.
- **REQ-P27-P0-007** — `sigint plugin pack <crate-path>` produces a valid pack from a plugin crate.
  Acceptance: Given a plugin crate that builds a `cdylib` and exports the C-ABI entry symbol, When `sigint plugin pack <crate-path>` runs, Then it (a) invokes `cargo build --release --target <host-triple>`, (b) reads the crate's `Cargo.toml` for plugin metadata under a `[package.metadata.sigint-plugin]` table, (c) writes `manifest.json`, (d) bundles the resulting dynamic library, (e) emits `<id>-<version>-<target-triple>.sgnt-pack` to the current directory or `--output <path>`. CLI surface locked in DEC-P27-008.
- **REQ-P27-P0-008** — `sigint plugin install <path>`, `uninstall <id>`, `list`, `info <id>` cover the full lifecycle.
  Acceptance: Given the four commands, When invoked, Then `install` validates and unpacks; `uninstall` removes the install dir for `<id>` (any version, or `--version <ver>` to disambiguate); `list` shows compile-time + installed plugins with id, version, source (`builtin` / `installed`), and load status (`loaded` / `failed: <reason>`); `info <id>` prints the full manifest plus install path. CLI surface locked in DEC-P27-008.
- **REQ-P27-P0-009** — Closed-loop end-to-end test verifies the pack→install→use loop.
  Acceptance: Given the test suite, When CI runs, Then a test in `tests/e2e/` or `crates/sigint-plugin/tests/` (a) writes a minimal example plugin to a temp dir, (b) runs `sigint plugin pack`, (c) runs `sigint plugin install` with `--prefix <tempdir>` to redirect the install dir, (d) starts a sigint subprocess with `SIGINT_PLUGIN_DIR=<tempdir>`, (e) verifies the plugin's tool appears in `sigint plugin list` output and that an agent can invoke it.
- **REQ-P27-P0-010** — User docs cover plugin authoring.
  Acceptance: Given USER_GUIDE.md, When the operator reads the plugin section, Then they find (a) a quickstart that pack→install→runs a hello-world tool from the `examples/` plugin, (b) the manifest schema reference, (c) the C-ABI entry-symbol contract, (d) the install-dir layout, (e) the failure modes and how to diagnose them, (f) an explicit "trust model: operator-asserted, no signing yet" disclaimer pointing at Phase 28.

**Nice-to-Have (P1)**

- **REQ-P27-P1-001** — Pack format includes a SHA-256 checksum of the dynamic library inside `manifest.json`, validated on install. Phase 28 will extend this to a signed checksum; the bare hash is a P1 hardening step that does not commit to a key infrastructure.
- **REQ-P27-P1-002** — `--prefix` flag on install/uninstall/list to override the install dir for testing and per-engagement isolation. Drives REQ-P27-P0-009.
- **REQ-P27-P1-003** — Example external plugin in `examples/sigint-plugin-hello/` with its own `Cargo.toml`, `lib.rs`, and `[package.metadata.sigint-plugin]` table — used by both the closed-loop test and the USER_GUIDE quickstart.

**Future Consideration (P2)**

- **REQ-P27-P2-001** — Multi-target packs (a single `.sgnt-pack` containing libraries for multiple target triples). Pack format is forward-compatible — `manifest.json` could grow a `targets: [{triple, library}]` array. Designed but not built.
- **REQ-P27-P2-002** — WASM as an alternative loader. Lighter sandboxing pre-Phase-28; lower performance. Pack format leaves room for `library_kind: "native" | "wasm"` in the manifest. Designed but not built.
- **REQ-P27-P2-003** — Signature field in manifest (`signature: <base64>`, `signed_by: <key-id>`). Phase 28 will populate this; Phase 27 reserves the schema slot.
- **REQ-P27-P2-004** — Plugin-management web UI. Phase 28 territory; pack/install commands today are CLI-only.

#### Architectural Decisions

- **DEC-P27-001 — Pack format: tar+gzip archive.**
  Options considered: (a) `.tar.gz` with a fixed internal layout, (b) `.zip`, (c) a custom binary format, (d) a directory (no archive). Trade-offs: `.tar.gz` is universal, streamable, and the Rust ecosystem has strong support (`tar` crate); `.zip` adds random access at the cost of a less-Rusty toolchain; custom format is gratuitous; raw directory loses the single-artifact distribution property. Chosen: `.tar.gz`, internal layout `manifest.json` at the root, `lib/<library-filename>` for the dynamic library, optional `README.md` and `LICENSE` at the root. Addresses: REQ-P27-P0-001. Evidence basis: well-trodden territory, no research needed.

- **DEC-P27-002 — Manifest schema.**
  Options considered: (a) JSON with a `manifest_version` discriminator, (b) TOML, (c) YAML, (d) embedded in the dynamic library as a metadata symbol. Trade-offs: JSON is the lingua franca for tool/SDK manifests, machine-validated easily, version-discriminated cleanly. TOML is more readable but the rest of sigint's runtime data is JSON. YAML invites parser drift. Embedding-as-symbol couples the manifest to the binary in a way that breaks `pack inspect` for an unloadable library. Chosen: JSON with `manifest_version: 1`. Required fields: `manifest_version`, `id`, `version`, `target_triple`, `entry_symbol`. Optional: `display_name`, `description`, `author`, `homepage`, `license`, `library_filename` (defaults to platform-derived `lib<id>.so` / `<id>.dylib` / `<id>.dll`). Schema is open for additive fields; unknown optional fields are ignored, unknown required fields fail validation. Addresses: REQ-P27-P0-002. Evidence basis: standard practice (cargo, npm, pip wheel METADATA).

- **DEC-P27-003 — Loader: `libloading` + C-ABI entry symbol.**
  Options considered: (a) `libloading` with a C-ABI entry function, (b) WASM via `wasmtime`, (c) subprocess + IPC, (d) custom dlopen wrapper. Trade-offs: `libloading` is the standard Rust dynamic-loading crate, in-process, zero-overhead, and matches the unsandboxed-trust model Phase 27 commits to. WASM brings sandboxing prematurely (Phase 28's job) and constrains plugin authors to a WASM-compatible ABI. Subprocess + IPC adds a serialization tax on every tool call. Custom dlopen wrapper reinvents `libloading`. Chosen: `libloading` for Phase 27. Entry symbol is a `extern "C" fn` named in the manifest (default `sigint_plugin_entry`) that returns a `*const PluginEntrypoint` C struct describing the plugin's tools. The full C-ABI shape lives in `crates/sigint-plugin/src/abi.rs` and is documented in USER_GUIDE.md. Addresses: REQ-P27-P0-003, REQ-P27-GOAL-003. Evidence basis: brief explicitly recommends `libloading`; alternatives (WASM) deferred to REQ-P27-P2-002. **Phase 28 seam:** swap `libloading::Library::new` for a sandboxed-loader call without changing the entry symbol contract.

- **DEC-P27-004 — Install location: platform user-data dir, namespaced by id+version.**
  Options considered: (a) flat archive stored as `<id>.sgnt-pack` in install dir, (b) unpacked to `<id>-<version>/` subdirs, (c) global system-wide install path (`/usr/local/lib/sigint/plugins/`). Trade-offs: flat archive forces re-extraction on every load; subdirs allow inspection/debugging and let multiple versions coexist; system-wide path requires root and conflicts with single-user trust model. Chosen: unpacked subdir under platform user-data dir. Linux: `${XDG_DATA_HOME:-~/.local/share}/sigint/plugins/<id>-<version>/`. macOS: `~/Library/Application Support/sigint/plugins/<id>-<version>/`. Windows: `%APPDATA%/sigint/plugins/<id>-<version>/`. The `directories` crate (already in tree via dependents) provides cross-platform paths. Addresses: REQ-P27-P0-004. Evidence basis: matches XDG and Apple platform conventions.

- **DEC-P27-005 — Discovery mechanism: filesystem scan at startup, register into shared registry.**
  Options considered: (a) scan install dir, validate each, register into the same `inventory`-backed registry compile-time plugins use, (b) build a separate runtime-plugin registry tier, (c) lazy-load on first tool invocation. Trade-offs: a single registry keeps the agent-side tool-lookup code unchanged (REQ-P27-GOAL-003); separate tiers double the lookup surface; lazy load saves startup time but defers errors and complicates `plugin list`. Chosen: shared registry, populated at startup. Implementation: `inventory` itself stays compile-time; runtime tools land in a `RuntimeToolRegistry` that the existing `collect_plugin_tools()` path is extended to consult (one merged Vec returned). The merge happens in `sigint-plugin` so callers (`AppCore::init`, agent dispatch) see one list. Addresses: REQ-P27-P0-005, REQ-P27-GOAL-003. **Phase 28 seam:** the registry-merge function is the natural insertion point for the signature-verification step.

- **DEC-P27-006 — Failure mode: log-and-skip, never crash.**
  Options considered: (a) abort startup on any plugin failure, (b) log warning and skip, (c) fail-on-startup but allow `--ignore-plugin-errors` flag. Trade-offs: aborting is safer in a security-critical model (Phase 28) but actively hostile in Phase 27's trust-the-operator model — a single broken plugin blocks the entire tool. Skipping with a structured log is the principle of least surprise for an unsandboxed local-install system. Chosen: log-and-skip with `tracing::warn!` carrying `plugin_id`, `plugin_path`, `failure_reason`. Failure categories defined: `manifest_invalid`, `target_mismatch`, `library_missing`, `dlopen_failed`, `entry_symbol_missing`, `entry_panicked`, `manifest_version_too_new`. Each has a documented diagnosis path in USER_GUIDE.md. Addresses: REQ-P27-P0-006. **Phase 28 seam:** the failure-category enum is exactly where Phase 28 adds `signature_invalid`, `signature_unknown_signer`, `sandbox_setup_failed`.

- **DEC-P27-007 — Plugin metadata source-of-truth: `[package.metadata.sigint-plugin]` in `Cargo.toml`.**
  Options considered: (a) standalone `sigint-plugin.toml` in the crate root, (b) `[package.metadata.sigint-plugin]` table in `Cargo.toml`, (c) inline attributes in `lib.rs`. Trade-offs: `Cargo.toml` metadata is the cargo-standard extension point and lets `cargo metadata` surface plugin info without a custom parser; standalone file duplicates package identity (name, version) that already lives in `Cargo.toml`; inline attributes require a proc-macro and obscure the metadata. Chosen: `[package.metadata.sigint-plugin]` table. `pack` reads `Cargo.toml`, derives the manifest from `name`+`version`+the metadata table, fills in `target_triple` from the build target, and writes `manifest.json` into the pack. Addresses: REQ-P27-P0-007. Evidence basis: cargo-deny, cargo-about, cargo-dist all use this pattern.

- **DEC-P27-008 — CLI surface: `sigint plugin pack | install | uninstall | list | info`.**
  Options considered: (a) keep all plugin commands under the existing `sigint plugin` subcommand from Phase 22, (b) split installable plugins into a separate `sigint pack` top-level command, (c) integrate into the web UI (P2). Trade-offs: keeping under `sigint plugin` is the principle of least surprise — Phase 22's `list` and `new` already live there. Adding `pack` (build a pack), `install` (consume a pack), `uninstall`, `info` extends the set without renaming. The Phase 22 `new` command (scaffold a workspace-member plugin) becomes the recommended starting point for plugin authors who'll then `pack` their crate. Each subcommand emits structured `--help` per clap idioms, matching the rest of the sigint CLI. Addresses: REQ-P27-P0-007, REQ-P27-P0-008.

#### Phase 28 Seams (explicit, do-not-rework list)

These are the surfaces Phase 27 deliberately leaves room for so Phase 28 (signing, registry, sandbox) can extend without rewriting:

1. **Manifest schema reservation** — `signature`, `signed_by`, `signature_algorithm`, `library_kind` are reserved optional fields. Phase 27 ignores them. Phase 28 populates them.
2. **Manifest version discriminator** — `manifest_version: 1` for Phase 27. Phase 28 introduces `manifest_version: 2` (signed) without breaking v1 packs.
3. **Loader insertion point** — the call site of `libloading::Library::new` in the runtime loader is the single natural seam for inserting a sandbox-setup step. Phase 27 calls `Library::new` directly; Phase 28 wraps it in a `SandboxedLibrary::new` that performs `seccomp` / WASM init.
4. **Registry-merge function** — the function that merges `inventory`-collected and runtime-loaded tools into one list is the insertion point for the signature-verification gate. Phase 27 merges unconditionally; Phase 28 inserts a verifier before merge.
5. **Failure-category enum** — extensible enum for skip reasons. Phase 28 adds `signature_invalid`, `signature_unknown_signer`, `sandbox_setup_failed`.
6. **Install command argument shape** — `sigint plugin install <path>` accepts a path. Phase 28 will accept `sigint plugin install <id>@<version>` from a registry; the command is the same, the argument parser dispatches on prefix.
7. **Install-dir layout** — `<id>-<version>/` subdirs are stable. Phase 28 may add a sibling `<id>-<version>.sig` file or extend the manifest, never restructure the layout.
8. **C-ABI entry symbol** — the entry symbol contract (`extern "C" fn` returning a `*const PluginEntrypoint`) is locked in Phase 27. Phase 28 sandboxing wraps the call site, never the contract.

#### Definition of Done

- REQ-P27-GOAL-001 satisfied: a plugin author runs `sigint plugin pack examples/sigint-plugin-hello/`, gets `sigint-plugin-hello-0.1.0-x86_64-unknown-linux-gnu.sgnt-pack`, ships it; consumer runs `sigint plugin install sigint-plugin-hello-0.1.0-x86_64-unknown-linux-gnu.sgnt-pack`, sees it in `sigint plugin list`, and an agent invokes its tool successfully.
- REQ-P27-GOAL-002 satisfied: `sigint plugin list` shows both compile-time and installed plugins; tools from both are reachable by agents.
- REQ-P27-GOAL-003 satisfied: `crates/sigint-plugin/src/lib.rs` Phase 22 surface (`Tool` trait, `register_tool!`, `collect_plugin_tools`) is unchanged; runtime loading is purely additive.
- REQ-P27-GOAL-004 satisfied: the eight Phase 28 seams above are documented in this section and reserved in code comments at each seam point.
- All P0 acceptance criteria pass.
- Closed-loop e2e test (REQ-P27-P0-009) green in CI.
- USER_GUIDE.md plugin chapter merged (REQ-P27-P0-010).
- README plugin section updated to reference USER_GUIDE.md.
- `cargo check --workspace`, `cargo clippy --all-targets -D warnings`, `cargo fmt --all -- --check`, `cargo test --workspace`, `cargo audit` all clean.
- MASTER_PLAN.md Decision Log populated by Guardian after merge.

#### Tasks (target: 5–7 PR-sized chunks; orchestrator opens issues after this docs PR merges)

- **T1 — Manifest schema + pack format library (no CLI yet).**
  Files: `crates/sigint-plugin/src/manifest.rs` (new), `crates/sigint-plugin/src/pack.rs` (new), `crates/sigint-plugin/src/abi.rs` (new — C-ABI entry-symbol contract), `crates/sigint-plugin/src/lib.rs` (re-exports).
  Adds: `Manifest` struct + `serde` impls, `manifest_version=1` discriminator, schema validation, `Pack::read(path)` and `Pack::write(manifest, library_path, output)` helpers (tar+gzip), `PluginEntrypoint` C struct + entry-symbol typedef.
  Acceptance: unit tests for manifest round-trip, unknown-required-field rejection, target-triple parsing, pack archive round-trip. No CLI surface in this task. Anchors DEC-P27-001, DEC-P27-002, DEC-P27-003 (entry-symbol shape only).
  Depends on: nothing.

- **T2 — `sigint plugin pack <crate-path>` CLI.**
  Files: `crates/sigint-cli/src/plugin.rs` (extend), `crates/sigint-cli/src/main.rs` (subcommand wiring).
  Adds: `pack` subcommand that runs `cargo build --release --target <host-triple>`, reads `[package.metadata.sigint-plugin]`, writes `manifest.json`, bundles the cdylib, emits `<id>-<version>-<triple>.sgnt-pack` to cwd or `--output`.
  Acceptance: integration test packs the example plugin from T7 and verifies the resulting archive's manifest + library are byte-identical to expectations. Anchors DEC-P27-007, DEC-P27-008 (`pack` only).
  Depends on: T1 (manifest + pack lib), T7 (example plugin to pack).

- **T3 — Runtime loader + startup discovery.**
  Files: `crates/sigint-plugin/src/loader.rs` (new), `crates/sigint-plugin/src/registry.rs` (new), `crates/sigint-plugin/src/lib.rs` (extend `collect_plugin_tools` to merge runtime + compile-time), `crates/sigint-core/src/app.rs` (call loader at `AppCore::init`).
  Adds: `RuntimeToolRegistry`, install-dir scan, `libloading`-based dlopen, entry-symbol resolution, failure-category enum, `tracing::warn!` skip path, merged registry returned by `collect_plugin_tools`.
  Acceptance: unit tests for each failure mode (manifest invalid, target mismatch, dlopen fail, missing symbol, panicking entry, wrong manifest_version). Integration test loads a fixture plugin from a temp dir. Anchors DEC-P27-003, DEC-P27-005, DEC-P27-006.
  Depends on: T1.

- **T4 — `sigint plugin install` + `uninstall` CLI.**
  Files: `crates/sigint-cli/src/plugin.rs` (extend), `crates/sigint-cli/src/main.rs` (subcommand wiring).
  Adds: `install` subcommand that validates the pack, resolves install dir via the `directories` crate, unpacks into `<install-dir>/<id>-<version>/`, supports `--prefix <path>` for testing; `uninstall <id>` removes the install dir, supports `--version <ver>` for disambiguation. Refuses to install over an existing version unless `--force`.
  Acceptance: integration tests for happy path, target-triple mismatch (error), bad manifest (error), `--prefix` redirection, uninstall, uninstall of non-existent (error). Anchors DEC-P27-004, DEC-P27-008 (install/uninstall only).
  Depends on: T1.

- **T5 — `sigint plugin list` + `info <id>` CLI.**
  Files: `crates/sigint-cli/src/plugin.rs` (extend the existing Phase 22 `list`), `crates/sigint-cli/src/main.rs` (`info` wiring).
  Adds: `list` extended to show compile-time plugins (`source: builtin`) + installed plugins (`source: installed`, with `loaded` / `failed: <reason>` status); `info <id>` prints full manifest + install path + load status.
  Acceptance: integration tests for list with mixed-source plugins, info on installed and missing ids, `--prefix` support. Anchors DEC-P27-008 (list/info only).
  Depends on: T3 (load status comes from the runtime loader), T4 (install dir resolution).

- **T6 — Documentation: USER_GUIDE plugin chapter + README plugin section.**
  Files: `USER_GUIDE.md` (new chapter), `README.md` (plugin section update), `crates/sigint-plugin/src/lib.rs` (top-level rustdoc with quickstart link).
  Adds: pack→install→use quickstart referencing T7's example, manifest schema reference, C-ABI entry-symbol contract, install-dir layout, failure modes + diagnosis, "trust model: operator-asserted, no signing yet — see Phase 28" disclaimer.
  Acceptance: a fresh reader follows the quickstart end-to-end against the T7 example without consulting the source. Anchors REQ-P27-P0-010.
  Depends on: T2, T3, T4, T5, T7.

- **T7 — Example external plugin: `examples/sigint-plugin-hello/`.**
  Files: `examples/sigint-plugin-hello/Cargo.toml`, `examples/sigint-plugin-hello/src/lib.rs`, `examples/sigint-plugin-hello/README.md`.
  Adds: minimal plugin crate (`crate-type = ["cdylib"]`), `[package.metadata.sigint-plugin]` table, one tool (e.g., `HelloEcho`), the C-ABI entry symbol exporting it, README describing what it does.
  Acceptance: builds standalone (`cd examples/sigint-plugin-hello && cargo build --release`); used by T2's integration test, T3's loader test, and T6's quickstart. Anchors REQ-P27-P1-003.
  Depends on: T1 (entry-symbol contract).

- **T8 — Closed-loop e2e + CI gates.**
  Files: `tests/e2e/tests/plugin_pack_install.rs` (new) or `crates/sigint-plugin/tests/e2e.rs` (new — single-crate test if no external bins needed).
  Adds: e2e test that drives the full pack→install→list→agent-invoke loop end-to-end against the T7 example, using a tempdir + `--prefix` + `SIGINT_PLUGIN_DIR` env override.
  Acceptance: green in CI. Phase DoD line REQ-P27-P0-009 is this test.
  Depends on: T2, T3, T4, T5, T7.

Parallelization: T1 and T7 can land first (T7 stubs out the entry symbol against a placeholder if needed). T2, T3 are parallel after T1. T4, T5 run after T3. T6, T8 run last after the runtime stack is in.

Effort estimate: ~2 weeks for the full eight tasks at the project's existing PR cadence.

### Planned Decisions

- DEC-P27-001: Pack format is `.tar.gz` with fixed internal layout (`manifest.json` at root, `lib/<library>`, optional `README.md`/`LICENSE`) — universal, streamable, strong Rust toolchain support — Addresses: REQ-P27-P0-001
- DEC-P27-002: Manifest schema is JSON with `manifest_version: 1` discriminator and required `id`/`version`/`target_triple`/`entry_symbol` fields — JSON is the lingua franca for SDK manifests, schema-evolvable, machine-validated easily — Addresses: REQ-P27-P0-002
- DEC-P27-003: Loader uses `libloading` + a C-ABI entry symbol (`extern "C" fn` returning `*const PluginEntrypoint`) — standard Rust dynamic-loading crate, in-process zero-overhead, matches unsandboxed-trust model; WASM deferred to REQ-P27-P2-002 — Addresses: REQ-P27-P0-003, REQ-P27-GOAL-003
- DEC-P27-004: Install dir is platform user-data dir (`directories` crate) namespaced `<install-dir>/<id>-<version>/` — XDG/Apple/Windows conventions, single-user trust, multiple versions coexist for inspection — Addresses: REQ-P27-P0-004
- DEC-P27-005: Discovery is filesystem scan at startup, runtime tools merged into the same list `collect_plugin_tools` returns — single registry preserves agent-side tool-lookup contract; Phase 28 inserts the signature gate at the merge function — Addresses: REQ-P27-P0-005, REQ-P27-GOAL-003
- DEC-P27-006: Failure mode is log-and-skip via `tracing::warn!` with structured `failure_reason` enum — principle of least surprise for unsandboxed local-install; Phase 28 extends the enum with signature/sandbox failure categories — Addresses: REQ-P27-P0-006
- DEC-P27-007: Plugin metadata lives in `[package.metadata.sigint-plugin]` of the crate's `Cargo.toml` — cargo-standard extension point, no duplicate package identity, surfaceable via `cargo metadata` — Addresses: REQ-P27-P0-007
- DEC-P27-008: CLI surface extends Phase 22's `sigint plugin` with `pack`, `install`, `uninstall`, `info`; existing `list` and `new` retained — principle of least surprise, single command tree for all plugin operations — Addresses: REQ-P27-P0-007, REQ-P27-P0-008

### Decision Log
<!-- Guardian appends here after Phase 27 completes -->

---

## Backlog: Future Phase Themes

> Carryover from the Phase 27 candidate-themes planning notes. The user picked Theme A (split into Phase 27 + Phase 28 above). The remaining themes are preserved here so the analysis isn't lost — each is a problem statement + product value + rough effort, not a design. Pick one when scoping the next phase.

### Theme B — Continuous Evaluation & Model Drift Detection
**Problem.** Phase 24-26 turned fine-tuning into an interactive, web-driven workflow — a user can promote a model and roll back if it underperforms. But once a model is promoted, it stays promoted. There's no scheduled re-evaluation, no regression alarm if the model's accuracy on new corpora drifts, and no longitudinal tracking of which model version produced which findings. Operators learn about drift through field surprises, not telemetry.

**Product value.** Continuous evaluation closes the observability loop on the fine-tune work that just shipped. Schedule nightly assessments against the most recent harvested sessions, alert on accuracy regression beyond a threshold, dashboard the trend, and keep enough history to attribute findings to model versions. This makes promoted models trustworthy over time, not just at promotion-day.

**Rough effort.** Medium (2-3 weeks). Mostly built on top of existing primitives (`evaluate.rs`, training stats, event bus). New surface: a scheduler, a metrics-history table, and a web dashboard tab. No new crates likely.

### Theme C — Closed-Loop Scan Automation (Continuous Surface Reassessment)
**Problem.** Phases 11-12 built finding intelligence and Phase 4 added attack-surface mapping, but every scan today is operator-initiated. A real engagement involves baselining a target, checking back periodically for new exposures, and re-running narrow scans against changed assets. Today this requires the operator to remember, decide, and re-launch — there's no "watch this target and tell me when something changes" mode.

**Product value.** A continuous-surface mode would turn sigint from a point-in-time tool into a persistent surveillance asset for engagement. Schedule recurring recon, diff against the last baseline, automatically queue narrow follow-up scans for changed assets, and surface only the deltas to the operator. Bridges sigint into the "exposure management" category that Wiz/Censys occupy commercially.

**Rough effort.** Medium-Large (3-4 weeks). Builds on Phase 7's diff infrastructure and Phase 9's resume mode. New surface: a scheduling layer, automated triggers, a "watching" status concept, and notification channels (event bus → email/Slack/webhook).

### Other themes worth naming (not fully scoped here)
- **Multi-engagement / multi-tenant** — separate engagements isolated, role-based access, shared model artifacts. Architecturally invasive. Probably premature without paying customers.
- **Mobile / responsive web UI** — Phase 26 explicitly declined this. Worth revisiting if remote/field operators turn out to be a real audience.
- **Cloud-native / Kubernetes deployment** — helm chart, k8s manifests, multi-host operation. Phase 20 shipped Docker; this is the next deployment-maturity step.
- **Report generation V2** — interactive HTML reports with embedded evidence, redaction controls, client-deliverable polish.

### Small follow-ups (not phase-worthy)
These are housekeeping items that can each be a one-shot ticket without a full phase:
- Issue **#39** — `train_run_eval` factory error emits wrong event variant (P1 bug).
- **DEC-P26-T6-002** — P1 job-detail drawer (needs `JobRecord.stdout_tail` field).
- **REQ-P26-P1-002** — bulk-harvest selection bar (needs DataTable row-selection primitive).

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
