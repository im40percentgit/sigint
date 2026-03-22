# Phase 5: Web UI + Polish — Design Document

**Date:** 2026-03-01
**Status:** approved
**Approach:** Vertical slices (5 independent sub-phases)

## Context

Phases 1-4 complete: foundation, agent system, TUI/memory/embeddings, attack surface mapping. SIGINT is a fully functional CLI/TUI pentest tool with 199 passing tests across 11 crates. Phase 5 adds web UI, report generation, environment diagnostics, and cloud LLM support.

## Design Decisions

- **Single binary:** SPA embedded via `rust-embed`, no runtime Node/npm dependency
- **Frontend:** Preact + HTM (lightweight, minimal build step)
- **LLM providers:** OpenAI-compatible API (covers OpenAI, Groq, Together, OpenRouter, vLLM)
- **PDF reports:** Pure Rust (`genpdf` or `printpdf`), no external tooling
- **Auth:** None initially (localhost-only), optional API key later

## Sub-Phase 5A: `sigint doctor`

**Scope:** Environment diagnostic command.
**Crate:** `sigint-cli` (no new crate)
**File:** `sigint-cli/src/doctor.rs` (already wired as `Commands::Doctor`)

### Checks

1. **Config** — Load and validate `~/.config/sigint/config.toml`
2. **Ollama reachability** — HTTP GET `base_url/api/tags`
3. **Model availability** — Check configured model is in Ollama's model list
4. **Tool availability** — PATH check for: nmap, gobuster, nikto, nuclei, feroxbuster, dig, whois, curl
5. **Sandbox prerequisites** — Check for `newuidmap` (uidmap) and `pasta` (passt)
6. **Database** — Open configured DB path, verify schema version

### Output Format

```
SIGINT Doctor
  ✓ Config loaded (~/.config/sigint/config.toml)
  ✓ Ollama reachable (http://localhost:11434)
  ✓ Model available (llama3.2)
  ✗ nmap not found — install: sudo apt install nmap
  ✓ Sandbox: newuidmap found
  ✗ Sandbox: pasta not found — install: sudo apt install passt
  ✓ Database OK (v2, ~/.local/share/sigint/sigint.db)

5/7 checks passed, 2 issues found
```

### Tests

- Mock HTTP for Ollama check
- Real PATH checks for tools
- In-memory DB for schema verification

---

## Sub-Phase 5B: OpenAI-Compatible LLM Provider

**Scope:** Support any OpenAI-compatible API endpoint.
**Crate:** `sigint-llm`
**File:** `sigint-llm/src/openai.rs` (new)

### Provider Design

- `OpenAiProvider` implements existing `LlmProvider` trait
- `POST /v1/chat/completions` with `stream: true/false`
- Bearer token auth via `api_key` (config or `SIGINT_API_KEY` env var)
- SSE streaming for token-by-token output
- Tool calling reuses existing `ToolDefinition`/`ToolCall` types (already OpenAI-compatible)

### Config Extension

```toml
[llm]
provider = "openai"  # or "ollama" (default)
model = "gpt-4o"
base_url = "https://api.openai.com"
api_key = "sk-..."   # or SIGINT_API_KEY env var
```

### Provider Factory

Factory function in `sigint-llm` dispatches based on `provider` config string. All CLI commands (scan, recon, chat) use whichever provider is configured.

### Tests

- Request serialization matches OpenAI format
- Response parsing (with/without tool_calls)
- Streaming SSE chunk parsing
- API key from env var fallback
- Error handling (401, 429 rate limit, 500)

---

## Sub-Phase 5C: Report Generation

**Scope:** Export scan results as HTML, Markdown, and PDF.
**Crate:** `sigint-report` (new)
**CLI:** `sigint report <session-id> --format html --output report.html`

### Architecture

```rust
ReportBuilder::new(scan_report, findings, assets)
    .format(ReportFormat::Html)  // Markdown, Html, Pdf
    .template(ReportTemplate::Executive | Detailed | Technical)
    .build() -> Result<Vec<u8>>
```

### Formats

- **Markdown** — canonical format, native Rust string templating
- **HTML** — Markdown rendered via `pulldown-cmark`, wrapped with embedded CSS
- **PDF** — HTML rendered via `genpdf` or `printpdf` (pure Rust, no external deps)

### Templates

3 embedded templates:
- **Executive** — high-level summary, risk score, top findings
- **Detailed** — full findings with evidence, asset inventory, timeline
- **Technical** — raw tool output, service banners, change history

### CLI Integration

New `Commands::Report` variant in main.rs. Loads session data from DB, builds report, writes to file or stdout.

---

## Sub-Phase 5D: Axum REST API + WebSocket

**Scope:** HTTP API backend for web UI and programmatic access.
**Crate:** `sigint-web` (existing stub)
**CLI:** `sigint serve` subcommand

### API Routes

```
GET    /api/sessions              — list sessions
GET    /api/sessions/:id          — session details
DELETE /api/sessions/:id          — delete session
GET    /api/sessions/:id/assets   — assets for session
GET    /api/sessions/:id/findings — findings for session
POST   /api/scan                  — start scan (returns session_id)
POST   /api/recon                 — start recon (returns session_id)
GET    /api/health                — health check (doctor-lite)
GET    /api/report/:id            — generate report (format query param)
WS     /ws/events                 — live event streaming via WebSocket
```

### WebSocket

Bridges `tokio::broadcast` EventBus to WebSocket clients. Events stream as JSON. Clients see tool executions, findings, assets in real-time — same events the TUI consumes.

### State Management

Axum `State` holds `AppCore` + `Database`. Routes are thin wrappers over existing store CRUD functions from `sigint-store`.

### Auth

None initially (binds to `127.0.0.1` only). Future: optional `--api-key` flag or config for remote access.

---

## Sub-Phase 5E: Embedded SPA Frontend

**Scope:** Browser-based UI served from the binary.
**Location:** `web/` directory at project root, embedded via `rust-embed`

### Technology

- **Preact** (~3KB gzipped) + **HTM** (tagged templates, no JSX build step)
- Minimal esbuild for bundling
- Embedded into binary via `rust-embed` pointing at `crates/sigint-web/static/`

### UI Panels

- **Dashboard** — active scans, recent sessions, quick stats
- **Scan View** — live event stream (mirrors TUI Chat + Tools), findings, assets
- **Sessions** — list/search/delete, view past results
- **Assets** — ASM dashboard (grouped by kind, services, changes)
- **Reports** — generate/download reports for any session

### Build Process

1. `web/` contains package.json, src/, esbuild config
2. `npm run build` outputs to `crates/sigint-web/static/`
3. `rust-embed` includes `static/` at compile time
4. Pre-built static files can be committed for cargo-only builds
5. Fallback: missing static files → `GET /` returns JSON pointing to API

### Serving

- `GET /` → `index.html` (embedded)
- `GET /assets/*` → JS/CSS bundles (embedded)
- `GET /api/*` → REST API routes (5D)
- `WS /ws/*` → WebSocket (5D)

---

## Implementation Order

```
5A (Doctor)  →  5B (OpenAI Provider)  →  5C (Reports)  →  5D (REST API)  →  5E (SPA)
  small win       enables cloud          CLI export       API backend       capstone
```

Each sub-phase gets its own worktree branch, tests, and merge to main.

## Dependencies

| Sub-Phase | New Crates/Deps | Depends On |
|-----------|----------------|------------|
| 5A | reqwest (existing) | — |
| 5B | reqwest (existing), eventsource-stream (existing) | — |
| 5C | pulldown-cmark, genpdf (new) | — |
| 5D | axum (existing in Cargo.toml), tower, tower-http | 5C (for report endpoint) |
| 5E | rust-embed (new), preact/htm (npm) | 5D |
