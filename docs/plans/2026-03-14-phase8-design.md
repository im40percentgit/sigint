# Phase 8 Design: Interactive Sessions & Streaming Reasoning

**Date:** 2026-03-14
**Status:** proposed
**Complexity:** Tier 2 (Standard)
**Crates touched:** sigint-core, sigint-llm, sigint-agents, sigint-tui, sigint-cli, sigint-web

---

## Problem Statement

SIGINT's TUI accepts user text input and publishes `Event::UserInput` on the EventBus, but no
component consumes these events. Users who type in the TUI see their message echoed in the chat
panel, but nothing happens -- no agent responds. The TUI is read-only during scans and inert
outside of them.

Separately, the agent pipeline uses non-streaming `chat()` for all tool-loop iterations
(DEC-AGENT-007). While correct for tool-call rounds, users see zero output between tool calls.
The LLM's reasoning is invisible until the final text response. During multi-minute scans this
creates a silent black box that erodes user trust and makes debugging difficult.

## Goals

- REQ-GOAL-001: Users can type commands in the TUI and receive agent responses interactively
- REQ-GOAL-002: LLM reasoning between tool calls is visible in real-time via streaming tokens
- REQ-GOAL-003: Both TUI and Web interfaces show live agent thinking during scan pipelines
- REQ-GOAL-004: Interactive sessions persist to SQLite for recall and session management

## Non-Goals

- REQ-NOGO-001: Multi-turn conversational agent -- Phase 8 connects input to the existing 5-agent
  pipeline; a general-purpose chat agent is a separate initiative
- REQ-NOGO-002: Parallel agent execution -- agents still run sequentially
- REQ-NOGO-003: Custom scan profiles or agent selection from TUI -- future feature
- REQ-NOGO-004: Web UI interactive chat -- Phase 8 focuses on TUI and CLI; web already has
  scan triggering via POST /api/scan

## Requirements

### Must-Have (P0)

- REQ-P0-001: `run_tool_loop` uses `chat_stream()` instead of `chat()` for all iterations,
  emitting reasoning tokens via the EventBus as they arrive
  - Acceptance: Given a scan with tool calls, When the LLM reasons between tool invocations,
    Then `Event::AgentThinking` events are emitted with streaming tokens visible in the TUI
    Chat panel before the tool executes

- REQ-P0-002: `chat_stream()` in the tool loop correctly accumulates `tool_calls` from the
  final `StreamChunk` and enters tool execution when present
  - Acceptance: Given a tool-loop iteration, When the streamed response's final chunk contains
    `tool_calls`, Then the loop executes those tools exactly as it does today with `chat()`;
    When the final chunk has no `tool_calls`, Then the loop returns the accumulated text

- REQ-P0-003: TUI input routed to an `InteractiveSession` that dispatches to the Orchestrator
  - Acceptance: Given the TUI is running, When the user types "scan example.com" and presses
    Enter, Then an Orchestrator scan pipeline runs against example.com with progress visible
    in the TUI panels

- REQ-P0-004: `Event::AgentThinking` variant added to the event bus for streaming reasoning
  - Acceptance: Given the Event enum, When `AgentThinking { agent_role, token }` is emitted,
    Then the TUI displays reasoning tokens distinctly from final output (e.g., dimmed text)

- REQ-P0-005: TUI `AppState.apply()` handles `AgentThinking` events by appending to a
  dedicated reasoning buffer, displayed in the Chat panel
  - Acceptance: Given AgentThinking events arriving, When the TUI renders, Then reasoning
    text appears in the Chat panel with visual distinction from user/assistant messages

### Nice-to-Have (P1)

- REQ-P1-001: TUI input prefix routing -- "scan X" triggers a scan, "help" shows commands,
  bare text warns "unknown command"
- REQ-P1-002: Interactive session persists to SQLite (session + messages) for later recall
- REQ-P1-003: Web WebSocket forwards `AgentThinking` events to browser clients for live
  thinking display (no UI changes -- events already bridge via the existing ws handler)
- REQ-P1-004: Report crate test expansion (additional edge cases, empty findings, template variants)

### Future Consideration (P2)

- REQ-P2-001: Multi-turn chat with the agent (conversational mode, not just scan dispatch)
- REQ-P2-002: Streaming reasoning during `sigint chat` CLI REPL (currently already streams final output)
- REQ-P2-003: TUI command history (up-arrow recall)

---

## Architectural Decisions

### DEC-AGENT-017: Streaming reasoning via chat_stream() with tool_calls accumulation

**Problem:** The tool loop uses `chat()` for all iterations. Between tool calls, the LLM's
reasoning is invisible -- the user sees nothing until the final text response.

**Options considered:**
1. `chat_stream()` only for non-tool-call iterations (prediction-based) -- rejected: cannot
   predict when the model will call tools vs produce text
2. `chat_stream()` for ALL iterations, accumulate tool_calls from final chunk -- **selected**
3. Keep `chat()` but emit reasoning as batch events after response -- rejected: not streaming

**Decision:** Always use `chat_stream()` in the tool loop. Stream delta tokens as they arrive,
emitting `Event::AgentThinking` events. On the final (`done=true`) chunk, check `tool_calls`:
if present, enter tool execution; if absent, the loop is done.

**Rationale:** `StreamChunk` already carries `tool_calls` on the `done=true` chunk (DEC-LLM-003).
This approach requires no prediction and emits tokens in real-time during ALL iterations. The
Ollama provider already handles streaming tool calls correctly in `newline_json_stream()`.

**Risk:** Streaming adds latency per iteration (must buffer until `done=true` to know if tool
calls are present). In practice, Ollama streams tool calls on the very last chunk, so the
accumulated text before that chunk is genuine reasoning that should be displayed.

**Addresses:** REQ-P0-001, REQ-P0-002, REQ-GOAL-002, REQ-GOAL-003

### DEC-AGENT-018: InteractiveSession as EventBus consumer for TUI input routing

**Problem:** `Event::UserInput` is emitted by the TUI but no component consumes it.

**Options considered:**
1. New `InteractiveSession` struct in sigint-agents -- **selected**
2. Modify Orchestrator to listen for EventBus inputs -- rejected: violates stateless design
   (DEC-AGENT-013)

**Decision:** Create `InteractiveSession` in sigint-agents that subscribes to the EventBus,
listens for `Event::UserInput`, parses commands, and dispatches to the Orchestrator. It manages
its own session lifecycle (session_id, DB persistence).

**Rationale:** The Orchestrator stays unchanged -- `run_scan()` still takes a target string.
`InteractiveSession` is the bridge between the event-driven TUI world and the Orchestrator's
imperative API. Can be spawned by both `sigint scan --tui` and a future `sigint interactive`.

**Addresses:** REQ-P0-003, REQ-GOAL-001, REQ-GOAL-004

### DEC-AGENT-019: New Event::AgentThinking variant for streaming reasoning

**Problem:** Need to distinguish inter-tool reasoning tokens from final streaming output.

**Options considered:**
1. Reuse `Event::TokenReceived` -- rejected: conflates reasoning with final output
2. New `Event::AgentThinking { agent_role, token }` -- **selected**

**Decision:** Add `Event::AgentThinking` to the Event enum. The tool loop emits this for each
streaming delta during tool-call iterations. `AppState` accumulates these in a
`reasoning_buffer` field, displayed with visual distinction in the Chat panel.

**Rationale:** Clear semantic separation. `TokenReceived` remains for final-output streaming
(used by `sigint chat`). `AgentThinking` is for the ephemeral inter-tool reasoning that helps
users understand what the agent is doing without polluting the final message history.

**Addresses:** REQ-P0-004, REQ-P0-005, REQ-GOAL-002

### DEC-TUI-001: Input panel prefix routing for command dispatch

**Problem:** TUI input bar exists but user input has no structured handler.

**Decision:** Lines starting with `scan ` trigger `orchestrator.run_scan()`. `help` shows
available commands. Everything else warns "unknown command -- type 'help' for available
commands". Future phases can add `chat ` prefix for conversational mode.

**Rationale:** Simple and discoverable. No new UI elements needed. The input bar already exists
and emits `UserInput` events.

**Addresses:** REQ-P1-001

---

## Implementation Plan

### Sub-Phase 8A: Streaming Reasoning in Tool Loop (Independent)

**Files modified:**
- `crates/sigint-core/src/event.rs` -- add `Event::AgentThinking` variant
- `crates/sigint-agents/src/loop_engine.rs` -- replace `provider.chat()` with `provider.chat_stream()`,
  accumulate tokens + emit `AgentThinking` events, extract `tool_calls` from final chunk
- `crates/sigint-tui/src/state.rs` -- add `reasoning_buffer` field, handle `AgentThinking` in `apply()`
- `crates/sigint-tui/src/ui.rs` -- render reasoning buffer in Chat panel with dimmed style

**Specific changes to `loop_engine.rs`:**

Replace the current block (lines 178-195):
```rust
// Build the request from current conversation state.
let request = ChatRequest::new(model, state.to_chat_messages().to_vec())
    .with_tools(tool_defs.to_vec());

let response = provider.chat(request).await?;

// Update our last-seen text content (may be empty during tool rounds).
if !response.content.is_empty() {
    last_text = response.content.clone();
}

if !response.has_tool_calls() {
    // Model produced a plain-text response -- loop is done.
    debug!(iteration, "tool loop: text response received, exiting");
    return Ok(last_text);
}
```

With streaming equivalent:
```rust
let request = ChatRequest::new(model, state.to_chat_messages().to_vec())
    .with_tools(tool_defs.to_vec());

let mut stream = provider.chat_stream(request).await?;
let mut accumulated_text = String::new();
let mut final_tool_calls = Vec::new();

while let Some(chunk_result) = stream.next().await {
    let chunk = chunk_result?;

    if !chunk.delta.is_empty() {
        accumulated_text.push_str(&chunk.delta);
        // Emit reasoning token for live display.
        event_bus.emit(Event::AgentThinking {
            agent_role: agent_role.clone(),
            token: chunk.delta.clone(),
        });
    }

    if chunk.done {
        final_tool_calls = chunk.tool_calls;
        break;
    }
}

if !accumulated_text.is_empty() {
    last_text = accumulated_text.clone();
}

if final_tool_calls.is_empty() {
    debug!(iteration, "tool loop: text response received, exiting");
    // Emit stream completion so TUI flushes reasoning buffer.
    event_bus.emit(Event::AgentThinkingDone {
        agent_role: agent_role.clone(),
    });
    return Ok(last_text);
}
```

**Note on `ToolLoopOptions`:** Add an `agent_role: String` field (or pass it separately) so the
tool loop knows which agent's reasoning is being streamed. This enables the TUI to display
"Researcher is thinking..." vs "Executor is thinking...".

**Specific changes to `event.rs`:**

Add two new variants:
```rust
/// Streaming reasoning token from an agent between tool calls.
AgentThinking {
    agent_role: String,
    token: String,
},
/// Agent finished a reasoning segment (tool loop iteration complete).
AgentThinkingDone {
    agent_role: String,
},
```

**Specific changes to `state.rs`:**

Add field:
```rust
/// Accumulator for in-progress agent reasoning (between tool calls).
pub reasoning_buffer: String,
/// Which agent is currently thinking (for display label).
pub thinking_agent: Option<String>,
```

Handle in `apply()`:
```rust
Event::AgentThinking { agent_role, token } => {
    self.thinking_agent = Some(agent_role);
    self.reasoning_buffer.push_str(&token);
}
Event::AgentThinkingDone { agent_role: _ } => {
    if !self.reasoning_buffer.is_empty() {
        self.messages.push(DisplayMessage {
            role: "thinking".to_string(),
            content: std::mem::take(&mut self.reasoning_buffer),
        });
    }
    self.thinking_agent = None;
}
```

**Specific changes to `ui.rs`:**

In the Chat panel rendering, add rendering for the `reasoning_buffer` when non-empty:
- Show as a dimmed/italic block below the last message
- Prefix with the agent name: "[Researcher thinking] ..."
- Also render messages with `role == "thinking"` in a dimmed style

**Tests for 8A:**

1. `loop_engine.rs`: New test `streaming_tool_call_then_text` -- mock provider's `chat_stream()`
   returns a stream with tool calls on the final chunk, verify tools execute and text is returned
2. `loop_engine.rs`: New test `streaming_no_tool_calls_returns_text` -- verify streaming path
   returns accumulated text when no tool calls appear
3. `loop_engine.rs`: New test `streaming_emits_agent_thinking_events` -- subscribe to EventBus,
   verify `AgentThinking` events are emitted during streaming
4. `state.rs`: New test `agent_thinking_accumulates_in_buffer` -- verify `apply(AgentThinking)`
   accumulates tokens
5. `state.rs`: New test `agent_thinking_done_flushes_to_messages` -- verify buffer flush
6. `event.rs`: New test `agent_thinking_serializes` -- verify JSON roundtrip

**Estimated complexity:** Medium-high. The core change (chat -> chat_stream in loop_engine) is
conceptually simple but touches the critical path. Extensive testing needed.

**Mock provider changes:** The `MockProvider` in loop_engine tests currently returns
`stream::empty()` from `chat_stream`. This must be updated to return a realistic stream of
`StreamChunk` items. Create a helper: `fn mock_stream(chunks: Vec<StreamChunk>) -> ChunkStream`.

---

### Sub-Phase 8B: Interactive Session (Depends on 8A for reasoning display)

**Files modified:**
- `crates/sigint-agents/src/interactive.rs` -- NEW: `InteractiveSession` struct
- `crates/sigint-agents/src/lib.rs` -- export `InteractiveSession`
- `crates/sigint-cli/src/scan.rs` -- spawn `InteractiveSession` when TUI is active
- `crates/sigint-tui/src/app.rs` -- no changes needed (UserInput already emitted)

**`InteractiveSession` design:**

```rust
/// Bridges TUI input events to the Orchestrator scan pipeline.
///
/// Subscribes to the EventBus, listens for `Event::UserInput` events, parses
/// the input as a command, and dispatches accordingly. Runs as a long-lived
/// tokio task alongside the TUI event loop.
pub struct InteractiveSession {
    orchestrator: Orchestrator,
    event_rx: broadcast::Receiver<Event>,
    db: Option<Arc<Database>>,
    session_id: Uuid,
}

impl InteractiveSession {
    pub fn new(
        orchestrator: Orchestrator,
        event_rx: broadcast::Receiver<Event>,
        db: Option<Arc<Database>>,
    ) -> Self { ... }

    /// Run the session loop. Listens for UserInput events and dispatches commands.
    /// Returns when Event::Shutdown is received or the channel closes.
    pub async fn run(mut self) -> Result<(), Error> {
        loop {
            match self.event_rx.recv().await {
                Ok(Event::UserInput { session_id: _, text }) => {
                    self.handle_input(&text).await;
                }
                Ok(Event::Shutdown) => break,
                Ok(_) => continue,
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!("interactive session: lagged {} events", n);
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
        Ok(())
    }

    async fn handle_input(&self, text: &str) {
        let text = text.trim();
        if text.is_empty() {
            return;
        }

        if let Some(target) = text.strip_prefix("scan ") {
            let target = target.trim();
            if target.is_empty() {
                self.emit_status("Usage: scan <target>");
                return;
            }
            self.emit_status(&format!("Starting scan of {target}..."));
            match self.orchestrator.run_scan(target).await {
                Ok(report) => {
                    self.emit_display_message("assistant", &report.summary);
                }
                Err(e) => {
                    self.emit_status(&format!("Scan failed: {e}"));
                }
            }
        } else if text == "help" {
            self.emit_status("Available commands: scan <target>, help");
        } else {
            self.emit_status(&format!(
                "Unknown command: '{text}'. Type 'help' for available commands."
            ));
        }
    }
}
```

**Integration in `scan.rs`:**

When TUI mode is active, instead of (or in addition to) spawning the orchestrator directly,
spawn an `InteractiveSession` that listens for user input:

```rust
// After building orchestrator and TUI...
let session = InteractiveSession::new(
    orchestrator,
    core.events.subscribe(),
    db.map(Arc::new),
);
tokio::spawn(async move {
    if let Err(e) = session.run().await {
        tracing::error!("Interactive session error: {e}");
    }
});
```

The initial scan (from `sigint scan <target>`) can still run as a direct `orchestrator.run_scan()`
call, with the `InteractiveSession` handling subsequent TUI inputs.

**Alternative approach (simpler):** Instead of a full `InteractiveSession` struct, add a small
event consumer loop directly in `scan.rs` that listens for `UserInput` events and dispatches
to the orchestrator. This avoids a new module but couples the logic to the CLI crate.

**Recommended:** Start with the simpler approach (event consumer in scan.rs) and extract to
`InteractiveSession` if it grows complex.

**Tests for 8B:**

1. `interactive.rs`: Test `handle_input_scan_dispatches` -- mock provider, verify run_scan called
2. `interactive.rs`: Test `handle_input_help_emits_status` -- verify help text emitted
3. `interactive.rs`: Test `handle_input_unknown_warns` -- verify unknown command warning
4. `interactive.rs`: Test `shutdown_event_exits_loop` -- verify clean shutdown
5. Integration: TUI input -> UserInput event -> InteractiveSession -> orchestrator (manual test)

**Estimated complexity:** Medium. The InteractiveSession itself is straightforward; the
complexity is in wiring it into the existing scan.rs lifecycle without breaking the direct-scan
path.

---

### Sub-Phase 8C: Report Test Expansion (Independent, Low Priority)

**Files modified:**
- `crates/sigint-report/src/builder.rs` -- add test cases
- `crates/sigint-report/src/format.rs` -- add test cases

**Tests to add:**

1. `builder.rs`: Test empty findings list produces valid output
2. `builder.rs`: Test all three templates (executive, detailed, technical) produce non-empty output
3. `builder.rs`: Test HTML format includes proper HTML structure tags
4. `format.rs`: Test markdown-to-HTML conversion preserves headings and lists
5. `builder.rs`: Test findings with nil UUIDs don't panic
6. `builder.rs`: Test very long finding descriptions are handled (no truncation bugs)

**Estimated complexity:** Low. Pure test additions, no production code changes.

---

### Sub-Phase 8D: Production Hardening (Independent)

Additional improvements identified during architecture review:

**8D-1: Session ID propagation in TUI UserInput events**

Currently `session_id: uuid::Uuid::nil()` is hardcoded in the TUI input handler (app.rs line 204).
Once InteractiveSession exists, the session_id should be set to the active session's UUID.

**Files:** `crates/sigint-tui/src/app.rs`, `crates/sigint-tui/src/state.rs`
**Change:** Add `active_session_id: Option<Uuid>` to `AppState`. When InteractiveSession starts,
emit an event that sets it. TUI uses this when constructing `UserInput` events.

**8D-2: Streaming timeout protection**

The streaming path in the tool loop could hang indefinitely if Ollama stops sending chunks.
Add a `tokio::time::timeout` around the stream consumption loop (e.g., 120s per iteration).

**Files:** `crates/sigint-agents/src/loop_engine.rs`
**Change:** Wrap the stream consumption in `tokio::time::timeout(Duration::from_secs(120), ...)`.
On timeout, feed a timeout error message back to the LLM (same pattern as tool execution errors).

**8D-3: Conversation state token accounting for streaming**

The current `ConversationState::trim_to_budget()` relies on `ChatResponse.usage` for token
counts. With streaming, `TokenUsage` only arrives on the final chunk. Ensure the accumulated
text is properly accounted for in the conversation state trim logic.

**Files:** `crates/sigint-agents/src/state.rs`
**Change:** After streaming completes, add the assistant message with accumulated text to
conversation state (same as the current `chat()` path -- just ensure the message is added
before `trim_to_budget()` is called).

---

## Dependency Graph

```
8A (Streaming Reasoning)  ─────────────┐
                                        ├──> 8B (Interactive Session)
8C (Report Tests)       [independent]   │
8D (Production Hardening) [independent] │
```

- **8A** is the foundation -- the streaming tool loop is needed before InteractiveSession can
  show live reasoning to TUI users
- **8B** depends on 8A: without streaming, TUI-initiated scans would still show no reasoning
- **8C** and **8D** are independent and can run in parallel with 8A or 8B

## Implementation Order

1. **Phase 8A** (first) -- Streaming reasoning in tool loop. This is the highest-risk,
   highest-value change. Needs careful testing against the existing tool-call flow.
2. **Phase 8D** (parallel with 8A) -- Production hardening items are small and independent.
3. **Phase 8B** (after 8A) -- Interactive session. Lower risk, builds on 8A's streaming.
4. **Phase 8C** (anytime) -- Report tests. No dependencies, low priority.

## Definition of Done

- [ ] REQ-P0-001: Tool loop uses `chat_stream()` and emits `AgentThinking` events
- [ ] REQ-P0-002: Streaming tool loop correctly handles tool_calls from final chunk
- [ ] REQ-P0-003: TUI "scan X" input triggers orchestrator pipeline with progress
- [ ] REQ-P0-004: `Event::AgentThinking` variant exists and serializes correctly
- [ ] REQ-P0-005: TUI renders reasoning buffer with visual distinction
- [ ] All existing 474+ tests still pass (no regressions)
- [ ] New tests added for streaming tool loop (minimum 6 tests)
- [ ] New tests added for InteractiveSession (minimum 4 tests)
- [ ] Manual verification: `sigint scan scanme.nmap.org --tui` shows streaming reasoning

## Risk Assessment

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Streaming tool loop introduces latency regression | High | Low | Benchmark before/after; Ollama streams at wire speed |
| StreamChunk.tool_calls empty on Ollama but populated on OpenAI (or vice versa) | High | Medium | Test both providers; fallback to chat() if stream lacks tool_calls |
| EventBus backpressure from rapid AgentThinking events | Medium | Low | Bus capacity is 256; reasoning tokens are word-sized, not byte-sized |
| Mock provider chat_stream() in tests doesn't match real behavior | Medium | Medium | Create realistic mock streams with proper done/tool_calls semantics |

## Files Summary

| File | Sub-Phase | Change Type |
|------|-----------|-------------|
| `crates/sigint-core/src/event.rs` | 8A | Add `AgentThinking`, `AgentThinkingDone` variants |
| `crates/sigint-agents/src/loop_engine.rs` | 8A | Replace `chat()` with `chat_stream()`, emit events |
| `crates/sigint-agents/src/loop_engine.rs` (ToolLoopOptions) | 8A | Add `agent_role` field |
| `crates/sigint-agents/src/orchestrator.rs` | 8A | Pass agent role to ToolLoopOptions |
| `crates/sigint-tui/src/state.rs` | 8A | Add reasoning_buffer, thinking_agent, handle events |
| `crates/sigint-tui/src/ui.rs` | 8A | Render reasoning with dimmed style |
| `crates/sigint-agents/src/interactive.rs` | 8B | NEW: InteractiveSession |
| `crates/sigint-agents/src/lib.rs` | 8B | Export InteractiveSession |
| `crates/sigint-cli/src/scan.rs` | 8B | Spawn InteractiveSession when TUI active |
| `crates/sigint-tui/src/app.rs` | 8D | Active session_id propagation |
| `crates/sigint-tui/src/state.rs` | 8D | Add active_session_id field |
| `crates/sigint-report/src/builder.rs` | 8C | Add tests |
| `crates/sigint-report/src/format.rs` | 8C | Add tests |
