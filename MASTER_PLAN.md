# MASTER_PLAN.md — SIGINT: AI-Powered Penetration Testing Tool

## Project Overview

**Type:** CLI / security tool
**Languages:** Rust (100%)
**Root:** /home/j/sigint

**SIGINT** is a single-binary AI-powered penetration testing tool built in Rust. It replaces overengineered multi-container pentest orchestrators (like PentAGI) with a local-first design: embedded SQLite, local LLM via Ollama, native Linux sandboxing via hakoniwa, and continuous attack surface mapping.

**Architecture:** Cargo workspace with 10 crates, shared `AppCore` backend, dual interface (TUI + Web), 5-role agent system with Orchestrator dispatch.

**Current Phase:** Phase 3 — TUI + Memory + Embeddings

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
    sigint-web/        # Axum embedded web UI
    sigint-cli/        # Binary entry point
```

**Interfaces:** TUI (default), Web (`sigint serve`), dual (`sigint --web`), headless (`sigint run <task>`)

**Shared backend:** Both TUI and Web connect to `AppCore` via `tokio::broadcast` event bus.

### Active Work

- Phase 1 completed (commit 862f9e1)
- Phase 2 completed (commits d8e5c4a–031276b, 4 hotfix rounds)
- Phase 3 planning not yet started
- Stale worktree: `fix/sandbox-fixes` needs cleanup

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
**Status:** planning
**Note:** Full PRD to be developed next session. All three sub-systems (Store DAL, Memory + Embeddings, Ratatui TUI) confirmed in scope.
- [ ] Ratatui interface (agent chat, tool output, findings, task queue)
- [ ] Real-time LLM streaming to TUI
- [ ] FTS5 search, fastembed embeddings, cosine similarity UDF
- [ ] Memory system: episodic + semantic + working
- [ ] Session save/restore, finding export

### Phase 4: Attack Surface Mapping
**Status:** planned
- [ ] Discovery modules (DNS, port scan, web, cert, OSINT)
- [ ] Asset correlator + change detector
- [ ] Recon scheduler
- [ ] TUI ASM dashboard
- [ ] Additional tools: nikto, sqlmap, feroxbuster, nuclei

### Phase 5: Web UI + Polish
**Status:** planned
- [ ] Axum server + embedded SPA
- [ ] REST API + WebSocket
- [ ] Report generation (HTML, Markdown, PDF)
- [ ] Additional LLM providers
- [ ] `sigint doctor`

## Architectural Decisions

| ID | Decision | Status | Rationale |
|----|----------|--------|-----------|
| DEC-ARCH-001 | Single Rust binary | accepted | Eliminates Docker dependency, simplifies deployment |
| DEC-ARCH-002 | Cargo workspace with 10 crates | accepted | Clean separation of concerns, parallel compilation |
| DEC-STORE-001 | SQLite bundled (not external DB) | accepted | Zero-config, single file, portable |
| DEC-SAND-001 | hakoniwa for sandboxing | accepted | Native Linux namespaces, no Docker overhead |
| DEC-LLM-001 | Ollama-first, cloud fallback | accepted | Local-first privacy, cloud for capability |
| DEC-EMBED-001 | fastembed with all-MiniLM-L6-v2 | accepted | Local embeddings, no API calls, ONNX runtime |
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
| DEC-HOTFIX-001 | Bare command path resolution via `which` | accepted | Sandbox requires absolute paths; runtime `which` lookup before exec |
| DEC-HOTFIX-002 | DNS via /etc/resolv.conf bind-mount | accepted | Pasta namespaces lack DNS; bind-mount host resolv.conf |
| DEC-HOTFIX-003 | Nmap ACL name standardization | accepted | Tool name "nmap_scan" must match ACL entries; was "nmap" vs "nmap_scan" |
| DEC-HOTFIX-004 | /dev mount for Pasta sandbox | accepted | Nmap needs /dev/null, /dev/urandom; added /dev bind-mount |
| DEC-HOTFIX-005 | ShellTool combined-command splitting | accepted | Handle piped/redirected commands via shell-style string splitting |

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
