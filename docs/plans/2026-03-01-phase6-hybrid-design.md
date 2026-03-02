# Phase 6: Hybrid — Parsers, Approval Gates, Web Scan — Design Document

**Date:** 2026-03-01
**Status:** approved
**Approach:** Event-driven approval (Approach 1) with 4 sub-phases

## Context

Phases 1-5 complete: foundation, agent system, TUI/memory/embeddings, attack surface mapping, web UI + polish. SIGINT is a fully functional CLI/TUI/web pentest tool with 12 crates and 250+ tests. Phase 6 adds structured tool output, human-in-the-loop approval gates, and web-triggered scans.

## Design Decisions

- **Approval mechanism:** oneshot channels keyed by request UUID, not the broadcast EventBus. EventBus signals the request; a separate `ApprovalRegistry` routes responses.
- **Risk classification:** Per-tool static risk level via `Tool::risk_level()`. Configurable auto-approve threshold.
- **Tool parsers:** nmap XML (`-oX -`) and nuclei JSONL (`-jsonl`). Raw stdout preserved for LLM; structured_data populated for asset/finding correlation.
- **Web scan:** POST /api/scan spawns a tokio task. Returns session_id immediately. Client subscribes to WebSocket for progress.
- **Bidirectional WebSocket:** select! loop reads commands + writes events. Approval responses route through ApprovalRegistry.

## Sub-Phase 6A: Tool Output Parsers

**Scope:** Structured parsing for nmap and nuclei output.
**Crate:** `sigint-tools`
**New dep:** `quick-xml` (lightweight SAX-style XML parser)

### nmap Parser

Current: `nmap -oN - <target>` (human-readable text to stdout). `structured_data: None`.

New: `nmap -oX - <target>` (XML to stdout). Parse XML into:
```json
{
  "hosts": [
    {
      "address": "93.184.216.34",
      "hostnames": ["example.com"],
      "status": "up",
      "ports": [
        {
          "port": 80,
          "protocol": "tcp",
          "state": "open",
          "service": "http",
          "version": "nginx 1.25.3",
          "banner": "..."
        }
      ]
    }
  ],
  "scan_info": { "type": "syn", "services": "1-1000" }
}
```

Raw XML preserved in `stdout` for LLM context. `structured_data` populated with parsed JSON.

### nuclei Parser

Current: `nuclei -silent -nc -u <target>` (text to stdout). `structured_data: None`.

New: add `-jsonl` flag. Each output line is a JSON object:
```json
{
  "template-id": "cve-2021-44228",
  "info": { "name": "Log4Shell", "severity": "critical" },
  "matched-at": "http://example.com/api",
  "extracted-results": ["..."],
  "type": "http"
}
```

Parse into:
```json
{
  "findings": [
    {
      "template_id": "cve-2021-44228",
      "name": "Log4Shell",
      "severity": "critical",
      "matched_at": "http://example.com/api",
      "type": "http"
    }
  ],
  "total": 3,
  "by_severity": { "critical": 1, "high": 1, "medium": 1 }
}
```

Raw JSONL preserved in `stdout`. `structured_data` populated with aggregated JSON.

### Tests

- Parse fixture nmap XML (scanme.nmap.org-style output) into structured hosts/ports
- Parse fixture nuclei JSONL into structured findings
- Gracefully handle malformed XML/JSON (fall back to None)
- Verify `stdout` still contains raw output for LLM

---

## Sub-Phase 6B: Tool Approval Gate

**Scope:** Risk classification, approval registry, loop engine integration.
**Crates:** `sigint-core` (types + registry), `sigint-agents` (loop engine hook)

### Risk Classification

New enum in `sigint-core/src/types.rs`:
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ToolRisk {
    Low,     // info-gathering: nmap, dig, whois, curl
    Medium,  // active scanning: gobuster, feroxbuster, nuclei
    High,    // exploitation: nikto, shell
}
```

`Tool` trait gains: `fn risk_level(&self) -> ToolRisk` with default `ToolRisk::Low`.

Each tool in `sigint-tools` implements `risk_level()`:
- **Low:** NmapTool, (future: dig, whois, curl)
- **Medium:** GobusterTool, FeroxbusterTool, NucleiTool
- **High:** NiktoTool, ShellTool

### ApprovalRegistry

New file `sigint-core/src/approval.rs`:
```rust
pub struct ApprovalRegistry {
    pending: Mutex<HashMap<Uuid, oneshot::Sender<bool>>>,
    timeout: Duration,
}

impl ApprovalRegistry {
    pub fn new(timeout: Duration) -> Self;
    pub fn request(&self, request_id: Uuid) -> oneshot::Receiver<bool>;
    pub fn respond(&self, request_id: Uuid, approved: bool) -> Result<()>;
    pub fn pending_count(&self) -> usize;
}
```

### Event Variants

Add to `Event` enum:
```rust
ToolApprovalRequested {
    request_id: Uuid,
    session_id: Uuid,
    tool_name: String,
    args: serde_json::Value,
    risk_level: ToolRisk,
},
ToolApprovalGranted { request_id: Uuid },
ToolApprovalDenied { request_id: Uuid, reason: Option<String> },
```

### Loop Engine Integration

In `sigint-agents/src/loop_engine.rs`, before `tool.execute(args)`:
1. Check `tool.risk_level()` against `config.agent.auto_approve` threshold
2. If auto-approved → execute immediately
3. If needs approval:
   a. Generate `request_id`
   b. Call `approval_registry.request(request_id)` to get receiver
   c. Emit `ToolApprovalRequested` event
   d. `tokio::time::timeout(registry.timeout, receiver.await)`
   e. On approved → execute. On denied → return "Tool execution denied by operator" to LLM. On timeout → return "Approval timed out" to LLM.

### Config Extension

```toml
[agent]
auto_approve = "low"  # auto-approve Low risk, prompt for Medium+
# Options: "none" (prompt for all), "low", "medium", "all" (no prompts)
approval_timeout = 300  # seconds
```

### Tests

- ApprovalRegistry: request + respond cycle
- ApprovalRegistry: timeout behavior
- ApprovalRegistry: respond to unknown request_id
- Loop engine: auto-approve Low tool (no block)
- Loop engine: Medium tool blocks until approval
- Loop engine: denied tool returns error message
- Risk level assignment per tool

---

## Sub-Phase 6C: Bidirectional WebSocket + Web Scan

**Scope:** Make WebSocket read/write, add POST /api/scan, expand AppState.
**Crate:** `sigint-web`

### Bidirectional WebSocket

Replace current send-only `handle_socket` with:
```rust
async fn handle_socket(mut socket: WebSocket, state: AppState) {
    let mut rx = state.event_bus.subscribe();
    loop {
        tokio::select! {
            Ok(event) = rx.recv() => {
                let json = serde_json::to_string(&event).unwrap();
                if socket.send(Message::Text(json)).await.is_err() { break; }
            }
            Some(Ok(msg)) = socket.recv() => {
                handle_client_message(msg, &state).await;
            }
            else => break,
        }
    }
}
```

Client commands (JSON):
- `{"type": "approve", "request_id": "uuid"}` → `state.approval_registry.respond(id, true)`
- `{"type": "deny", "request_id": "uuid", "reason": "..."}` → `state.approval_registry.respond(id, false)`

Unknown message types are logged and ignored.

### POST /api/scan

```
POST /api/scan
Body: { "target": "example.com", "model": "llama3.2" (optional) }
Response: 201 Created { "session_id": "uuid" }
```

Handler:
1. Create session in DB
2. Build ToolRegistry with all 6 executor tools
3. Create LLM provider via `factory::create_provider(&config.llm)`
4. Build Orchestrator
5. `tokio::spawn` the scan task (passing event_bus for real-time streaming)
6. Return session_id immediately

### AppState Expansion

```rust
pub struct AppState {
    pub db: Arc<Database>,
    pub event_bus: EventBus,
    pub config: Arc<SigintConfig>,
    pub approval_registry: Arc<ApprovalRegistry>,
}
```

### Tool Registration Fix

Extract tool registration into a shared function in `sigint-tools`:
```rust
pub fn register_all_executor_tools(registry: &mut ToolRegistry) {
    registry.register(NmapTool::new());
    registry.register(ShellTool::new());
    registry.register(GobusterTool::new());
    registry.register(NiktoTool::new());
    registry.register(NucleiTool::new());
    registry.register(FeroxbusterTool::new());
}
```

Used by both `sigint-cli/src/scan.rs` and the web scan handler.

### Tests

- POST /api/scan returns 201 with valid session_id
- POST /api/scan with missing target returns 400
- WebSocket receives events after scan starts
- WebSocket approval command routes to ApprovalRegistry
- WebSocket invalid command is ignored (no crash)

---

## Sub-Phase 6D: TUI Approval + Frontend Update

**Scope:** TUI approval prompt, web frontend approval modal + scan button.
**Crates:** `sigint-tui`, `web/`

### TUI Approval

In `sigint-tui/src/state.rs` + `ui.rs`:
- New state: `pending_approval: Option<(Uuid, String, String)>` (request_id, tool_name, args_summary)
- When `Event::ToolApprovalRequested` received → set pending_approval, render prompt bar
- Prompt: `"[APPROVAL] Run nuclei_scan on example.com? [y/n]"`
- On `y` → emit ToolApprovalGranted, clear pending
- On `n` → emit ToolApprovalDenied, clear pending

### Web Frontend

**Dashboard** (`web/src/components/Dashboard.js`):
- "New Scan" button with target input field
- Calls `POST /api/scan`, navigates to ScanView for that session

**ScanView** (`web/src/components/ScanView.js`):
- Approval modal: when `ToolApprovalRequested` event arrives via WebSocket, show a modal with tool name, args, risk level badge
- "Approve" / "Deny" buttons send WS command
- Risk level color coding: Low=green, Medium=yellow, High=red

### Tests

- TUI: ToolApprovalRequested sets pending_approval state
- TUI: y keypress emits ToolApprovalGranted
- Frontend: manual verification (browser)

---

## Implementation Order

```
6A (Parsers)  ──┐
                 ├──→  6C (Web Scan + WS)  ──→  6D (TUI + Frontend)
6B (Approval)  ──┘
```

6A and 6B are independent and can be implemented in parallel. 6C depends on 6B (needs ApprovalRegistry in AppState). 6D depends on 6B (needs approval events) and 6C (needs POST /api/scan for frontend).

## Dependencies

| Sub-Phase | New Deps | Depends On |
|-----------|----------|------------|
| 6A | quick-xml (new) | — |
| 6B | — (uses existing tokio::sync) | — |
| 6C | — | 6B |
| 6D | — | 6B, 6C |
