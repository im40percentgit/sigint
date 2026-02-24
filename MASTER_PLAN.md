# MASTER_PLAN.md — SIGINT: AI-Powered Penetration Testing Tool

## Original Intent

Build a single-binary AI-powered penetration testing tool in Rust that replaces overengineered multi-container solutions like PentAGI (7+ Docker containers: Go, React, PostgreSQL, Redis, Neo4j, MinIO, Langfuse, ClickHouse, Grafana). The vision: no Docker, no external databases, local-first with Ollama, native Linux sandboxing, and continuous attack surface mapping — all in one `sigint` binary. A tool that a pentester can download and run immediately, with AI agents orchestrating reconnaissance, strategy, execution, analysis, and reporting.

## Project Overview

**SIGINT** is a single-binary AI-powered penetration testing tool built in Rust. It replaces overengineered multi-container pentest orchestrators (like PentAGI) with a local-first design: embedded SQLite, local LLM via Ollama, native Linux sandboxing via hakoniwa, and continuous attack surface mapping.

**Architecture:** Cargo workspace with 10 crates, shared `AppCore` backend, dual interface (TUI + Web), 5-role agent system.

**Current Phase:** Phase 1 — Foundation

## Architecture

```
sigint/
  crates/
    sigint-core/       # Config, domain types, AppCore, event bus
    sigint-llm/        # LLM provider trait + Ollama/OpenAI/Anthropic
    sigint-agents/     # Agent system, orchestrator, tool registry
    sigint-sandbox/    # Linux namespaces + seccomp via hakoniwa
    sigint-store/      # SQLite + FTS5 + embeddings
    sigint-tools/      # Pentest tool wrappers (nmap, sqlmap, etc.)
    sigint-recon/      # Attack surface mapping, change detection
    sigint-tui/        # Ratatui terminal interface
    sigint-web/        # Axum embedded web UI
    sigint-cli/        # Binary entry point
```

**Interfaces:** TUI (default), Web (`sigint serve`), dual (`sigint --web`), headless (`sigint run <task>`)

**Shared backend:** Both TUI and Web connect to `AppCore` via `tokio::broadcast` event bus.

## Agent System

5 roles with role-based tool access:
- **Researcher** — OSINT, recon, information gathering
- **Strategist** — Attack planning, methodology selection
- **Executor** — Tool execution in sandboxed containers
- **Analyst** — Result analysis, finding correlation
- **Reporter** — Report generation, evidence compilation

## Key Crates

| Component | Crate |
|-----------|-------|
| Runtime | `tokio` |
| HTTP | `reqwest` (stream), `axum` |
| SSE | `eventsource-stream` |
| CLI | `clap` |
| TUI | `ratatui` + `crossterm` |
| DB | `rusqlite` (bundled) |
| Embeddings | `fastembed` |
| Sandbox | `hakoniwa` |
| Logging | `tracing` |
| Serialization | `serde`, `serde_json`, `toml` |

## Phases

### Phase 1: Foundation ← ACTIVE
- [x] Project bootstrap (git, MASTER_PLAN.md)
- [ ] Cargo workspace with all crate stubs
- [ ] sigint-core: Config (TOML), error types, domain types, event bus
- [ ] sigint-llm: Ollama provider with SSE streaming
- [ ] sigint-cli: `sigint chat` interactive command
- [ ] sigint-store: SQLite schema + migrations + basic CRUD
- [ ] Prototype: sandbox harness (nmap in hakoniwa)

### Phase 2: Agent System + Sandboxing
- [ ] Agent trait, Orchestrator, ConversationState with tool-call loop
- [ ] Tool trait, nmap/gobuster/shell wrappers
- [ ] hakoniwa sandbox integration with per-tool profiles
- [ ] Role-based tool ACL
- [ ] Context window management
- [ ] `sigint scan <target>` end-to-end

### Phase 3: TUI + Memory + Embeddings
- [ ] Ratatui interface (agent chat, tool output, findings, task queue)
- [ ] Real-time LLM streaming to TUI
- [ ] FTS5 search, fastembed embeddings, cosine similarity UDF
- [ ] Memory system: episodic + semantic + working
- [ ] Session save/restore, finding export

### Phase 4: Attack Surface Mapping
- [ ] Discovery modules (DNS, port scan, web, cert, OSINT)
- [ ] Asset correlator + change detector
- [ ] Recon scheduler
- [ ] TUI ASM dashboard
- [ ] Additional tools: nikto, sqlmap, feroxbuster, nuclei

### Phase 5: Web UI + Polish
- [ ] Axum server + embedded SPA
- [ ] REST API + WebSocket
- [ ] Report generation (HTML, Markdown, PDF)
- [ ] Additional LLM providers
- [ ] `sigint doctor`

## Decision Log

| ID | Decision | Status | Rationale |
|----|----------|--------|-----------|
| DEC-ARCH-001 | Single Rust binary | accepted | Eliminates Docker dependency, simplifies deployment |
| DEC-ARCH-002 | Cargo workspace with 10 crates | accepted | Clean separation of concerns, parallel compilation |
| DEC-STORE-001 | SQLite bundled (not external DB) | accepted | Zero-config, single file, portable |
| DEC-SAND-001 | hakoniwa for sandboxing | accepted | Native Linux namespaces, no Docker overhead |
| DEC-LLM-001 | Ollama-first, cloud fallback | accepted | Local-first privacy, cloud for capability |
| DEC-EMBED-001 | fastembed with all-MiniLM-L6-v2 | accepted | Local embeddings, no API calls, ONNX runtime |

## Risks

1. **Sandbox reliability** — hakoniwa isolating nmap with network restrictions (highest risk)
2. **Ollama tool calling** — local models producing valid tool-call JSON (high risk)
3. **Binary size** — fastembed ONNX runtime may push binary past 100MB (medium, feature flags mitigate)
