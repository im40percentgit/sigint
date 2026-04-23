//! Tool-call loop engine — drives the LLM ↔ tool execution cycle.
//!
//! The loop sends a `ChatRequest` to the provider via `chat_stream()`. If the
//! model responds with tool calls, the engine executes them, appends results to
//! the conversation state, and repeats. The loop terminates when the model
//! produces a plain-text response or `max_iterations` is exceeded.
//!
//! Streaming is used for every iteration so incremental tokens can be emitted
//! as `AgentThinking` events, giving users real-time visibility into reasoning.
//! Tool calls are accumulated across ALL stream chunks (see DEC-LLM-007).
//!
//! @decision DEC-AGENT-007-REV
//! @title Streaming (`chat_stream()`) for all tool-loop iterations (Phase 8A)
//! @status accepted
//! @rationale Originally non-streaming (`chat()`) was used because tool calls
//! require complete, structured JSON that only arrives on the final chunk.
//! Phase 8A switches to `chat_stream()` for ALL iterations so incremental
//! tokens can be emitted as `AgentThinking` events, giving users real-time
//! visibility into the model's reasoning between tool calls. Tool calls are
//! accumulated from every chunk position (see DEC-LLM-007).
//!
//! @decision DEC-LLM-007
//! @title Accumulate tool_calls from all stream chunks, not just done=true
//! @status accepted
//! @rationale Ollama sends tool_calls on the content chunk (done=false),
//! not the final metadata chunk (done=true). The done chunk carries only
//! token counts. Replacing the assignment with extend() collects tool calls
//! from any chunk position, which is correct for both Ollama and OpenAI
//! streaming formats.
//!
//! @decision DEC-AGENT-008
//! @title Event emission is best-effort; errors are silently discarded
//! @status accepted
//! @rationale `EventBus::emit` already silences send errors (no receivers).
//! The loop must not fail because a TUI subscriber is slow or absent. Tool
//! execution is the critical path; event delivery is observability-only.
//!
//! @decision DEC-AGENT-009
//! @title Unknown tool name feeds an error message back to the LLM
//! @status accepted
//! @rationale When the model hallucrinates a tool name, silently skipping it
//! leaves the model in an inconsistent state (it expects a result). Returning
//! an explicit error message as a `tool`-role turn lets the model recover
//! gracefully — it can acknowledge the error and either try a different tool
//! or respond with text. This matches OpenAI's recommended error-handling
//! pattern for function calling.
//!
//! @decision DEC-AGENT-010
//! @title Approval gate checks tool risk before execution; blocks on oneshot channel
//! @status accepted
//! @rationale Medium/High risk tools require human approval. The gate uses
//! `ApprovalRegistry::request()` to obtain a oneshot receiver, emits
//! `ToolApprovalRequested`, then races against a timeout. On deny/timeout the
//! gate feeds an error message back to the LLM (same recovery path as unknown
//! tool) rather than propagating an error. On approve it emits
//! `ToolApprovalGranted` and proceeds to execution. When `approval_registry`
//! is `None` the gate is completely bypassed — no performance overhead for
//! callers that don't need it. `auto_approve` controls which risk levels skip
//! the gate: "all"/"medium"/"low"/"none".
//!
//! @decision DEC-AGENT-015
//! @title Per-tool scan record persistence is opt-in via `Option<&Database>`
//! @status accepted
//! @rationale Tool loop tests and non-CLI callers don't always have a database.
//! Making `db` an `Option` in `ToolLoopOptions` keeps the loop backward-compatible
//! — `None` disables persistence with zero overhead. All DB operations are
//! best-effort (warn on `Err`, never propagate), so a transient SQLite error
//! cannot abort a live scan. Records are created before execution (so a record
//! exists even if the process dies mid-run) and updated after (output + exit code).
//!
//! @decision DEC-AGENT-016
//! @title Per-chunk 30-second timeout guards against stalled LLM streams (Phase 8D)
//! @status accepted
//! @rationale A stalled Ollama process (OOM-killed, network drop, hung generate
//! goroutine) never closes the HTTP response body — `StreamExt::next()` pends
//! forever, hanging the agent loop indefinitely. A per-chunk timeout (30s) fires
//! only when no new token arrives for 30 seconds, so legitimate long-running
//! generations (slow hardware, large outputs) are unaffected. On timeout the loop
//! breaks and any text accumulated so far is returned as partial output; the loop
//!
//! @decision DEC-AGENT-TOOL-ACL-001
//! @title Approval gate uses effective_risk(name, self_reported) not bare risk_level()
//! @status accepted
//! @rationale `Tool::risk_level()` is self-reported. A plugin can declare Low
//! while doing destructive things, bypassing the gate with auto_approve="low".
//! `tool_acl::effective_risk` takes the max of the static ACL floor and the
//! self-reported value, so the ACL table in tool_acl.rs is the binding policy.
//! Unknown tools (not in the ACL) default to High — fail-secure.
//! treats the stalled stream as a text-only response (no tool calls) and terminates
//! the current iteration gracefully — no error is propagated, no panic occurs.

use std::time::Instant;

use futures_util::StreamExt;
use tracing::{debug, warn};
use uuid::Uuid;

use sigint_core::types::ToolRisk;
use sigint_core::{
    event::{Event, EventBus},
    ApprovalRegistry, Error,
};
use sigint_llm::{
    provider::{ChunkStream, LlmProvider},
    types::{ChatMessage, ChatRequest, ToolDefinition},
};
use sigint_tools::tool::Tool;

/// Configuration options for [`run_tool_loop`].
///
/// Bundles the execution-policy parameters to keep the function signature
/// within clippy's `too_many_arguments` limit (≤7).
///
/// @decision DEC-AGENT-015
/// @title Per-tool scan record persistence is opt-in via `Option<&Database>`
/// @status accepted
/// @rationale Tool loop tests and non-CLI callers (e.g. the web scan service)
/// don't always have a database. Making `db` an `Option` keeps the loop
/// backward-compatible — `None` disables persistence with zero overhead.
/// All DB operations are best-effort (warn on `Err`, never propagate), so a
/// transient SQLite error cannot abort a live scan. The `session_id` field is
/// ignored when `db` is `None`, so callers that don't supply a database don't
/// need to generate a meaningful UUID.
pub struct ToolLoopOptions<'a> {
    /// Hard cap on tool-call rounds before the loop gives up.
    pub max_iterations: usize,
    /// Model identifier string passed to the provider (e.g. `"llama3.2"`).
    pub model: &'a str,
    /// Best-effort event bus for observability; errors are silently discarded.
    pub event_bus: &'a EventBus,
    /// Optional approval gate. When `Some`, tools whose risk exceeds
    /// `auto_approve` will block for human approval.
    pub approval_registry: Option<&'a ApprovalRegistry>,
    /// Auto-approval threshold: `"all"`, `"medium"`, `"low"`, or `"none"`.
    pub auto_approve: &'a str,
    /// Optional database for persisting per-tool scan records.
    ///
    /// When `Some`, each tool invocation creates a `ScanRecord` before
    /// execution and updates it with output and exit code after completion.
    /// Operations are best-effort — failures are logged as warnings, not
    /// propagated. When `None`, no persistence occurs.
    pub db: Option<&'a sigint_store::Database>,
    /// Session ID for scan record attribution. Only used when `db` is `Some`.
    pub session_id: uuid::Uuid,
    /// Agent role label for `AgentThinking` events (e.g. `"researcher"`).
    ///
    /// Passed through to every `AgentThinking` / `AgentThinkingDone` event
    /// emitted during this loop run so the TUI can display which agent is
    /// currently reasoning.
    pub agent_role: &'a str,
}

/// Returns `true` if `risk` is within the auto-approval threshold.
///
/// - `"all"`    — every tool runs without approval
/// - `"medium"` — Low and Medium auto-approve; High requires approval
/// - `"low"`    — only Low tools auto-approve
/// - `"none"`   — every tool requires approval
/// - any other value is treated as `"low"` (safe default)
fn is_auto_approved(risk: ToolRisk, threshold: &str) -> bool {
    match threshold {
        "all" => true,
        "none" => false,
        "medium" => risk <= ToolRisk::Medium,
        "low" => risk <= ToolRisk::Low,
        _ => risk <= ToolRisk::Low,
    }
}

/// Run the tool-call loop for an agent.
///
/// Sends `state.to_chat_messages()` to the provider with the given tool
/// definitions. If the model responds with tool calls, executes them via the
/// `tools` slice and appends results back to `state`. Repeats until the model
/// returns plain text or `max_iterations` is exhausted.
///
/// # Arguments
/// * `provider`           — LLM backend (Ollama, mock, etc.)
/// * `state`              — Mutable conversation history; updated in-place.
/// * `tools`              — Available tool implementations; matched by name.
/// * `tool_defs`          — Tool schemas passed to the LLM in each request.
/// * `max_iterations`     — Hard cap on tool-call rounds before giving up.
/// * `model`              — Model identifier string (e.g. `"llama3.2"`).
/// * `event_bus`          — Best-effort event emission for observability.
/// * `approval_registry`  — Optional approval gate. When `Some`, tools whose
///   risk level exceeds `auto_approve` will block for human approval. When
///   `None`, all tools run immediately regardless of risk.
/// * `auto_approve`       — Auto-approval threshold: `"all"`, `"medium"`,
///   `"low"`, or `"none"`. See [`is_auto_approved`] for semantics.
///
/// # Returns
/// The model's final text response, or the last partial response with a
/// warning suffix when `max_iterations` is hit.
///
/// # Errors
/// Returns `Error` when the provider call itself fails. Tool execution errors
/// are fed back to the model as error messages rather than propagated.
pub async fn run_tool_loop(
    provider: &dyn LlmProvider,
    state: &mut crate::state::ConversationState,
    tools: &[&dyn Tool],
    tool_defs: &[ToolDefinition],
    opts: ToolLoopOptions<'_>,
) -> Result<String, Error> {
    let ToolLoopOptions {
        max_iterations,
        model,
        event_bus,
        approval_registry,
        auto_approve,
        db,
        session_id,
        agent_role,
    } = opts;

    let mut last_text = String::new();

    for iteration in 0..max_iterations {
        debug!(iteration, "tool loop: sending request to provider");

        // Build the request from current conversation state.
        let request = ChatRequest::new(model, state.to_chat_messages().to_vec())
            .with_tools(tool_defs.to_vec());

        // Stream the response, emitting AgentThinking events as tokens arrive.
        // Tool calls arrive atomically on the done=true chunk (DEC-LLM-003).
        let mut stream: ChunkStream = provider.chat_stream(request).await?;
        let mut accumulated_text = String::new();
        let mut final_tool_calls: Vec<sigint_llm::types::ToolCall> = Vec::new();

        // Per-chunk timeout: if no token arrives within 30 seconds the stream is
        // considered stalled and we break out with whatever text we have so far.
        // This guards against Ollama hanging indefinitely (DEC-AGENT-016).
        const CHUNK_TIMEOUT_SECS: u64 = 30;
        loop {
            let maybe_chunk = tokio::time::timeout(
                std::time::Duration::from_secs(CHUNK_TIMEOUT_SECS),
                StreamExt::next(&mut stream),
            )
            .await;

            match maybe_chunk {
                Ok(Some(chunk_result)) => {
                    let chunk = chunk_result?;

                    if !chunk.delta.is_empty() {
                        accumulated_text.push_str(&chunk.delta);
                        event_bus.emit(Event::AgentThinking {
                            agent_role: agent_role.to_string(),
                            token: chunk.delta.clone(),
                        });
                    }

                    // Accumulate tool calls from every chunk — Ollama sends them
                    // on the content chunk (done=false), not the metadata chunk
                    // (done=true). Using extend() works for both Ollama and
                    // OpenAI streaming formats. (DEC-LLM-007)
                    if !chunk.tool_calls.is_empty() {
                        final_tool_calls.extend(chunk.tool_calls);
                    }
                    if chunk.done {
                        break;
                    }
                }
                Ok(None) => {
                    // Stream ended without a done=true chunk — treat as text response.
                    break;
                }
                Err(_elapsed) => {
                    // Per-chunk timeout: LLM stalled for 30 seconds.
                    warn!(
                        iteration,
                        timeout_secs = CHUNK_TIMEOUT_SECS,
                        "tool loop: LLM stream stalled, breaking with partial output"
                    );
                    break;
                }
            }
        }

        // Update our last-seen text content.
        if !accumulated_text.is_empty() {
            last_text = accumulated_text.clone();
        }

        if final_tool_calls.is_empty() {
            // Model produced a plain-text response — loop is done.
            debug!(iteration, "tool loop: text response received, exiting");
            event_bus.emit(Event::AgentThinkingDone {
                agent_role: agent_role.to_string(),
            });
            return Ok(last_text);
        }

        // Emit AgentThinkingDone before the tool execution phase begins.
        event_bus.emit(Event::AgentThinkingDone {
            agent_role: agent_role.to_string(),
        });

        // ── Tool-call round ──────────────────────────────────────────────────
        debug!(
            iteration,
            tool_call_count = final_tool_calls.len(),
            "tool loop: processing tool calls"
        );

        // Append the assistant turn (with tool_calls) to state.
        let assistant_msg = ChatMessage {
            role: "assistant".into(),
            content: accumulated_text,
            tool_calls: Some(final_tool_calls.clone()),
        };
        state.add_message(assistant_msg);

        // Execute each requested tool and append a tool-role result message.
        for tool_call in &final_tool_calls {
            let name = &tool_call.function.name;
            let args = &tool_call.function.arguments;

            // Find matching tool by name.
            let maybe_tool = tools.iter().find(|t| t.name() == name);

            match maybe_tool {
                None => {
                    warn!(tool_name = %name, "tool loop: unknown tool requested");
                    event_bus.emit(Event::Status(format!("Unknown tool requested: {name}")));
                    let error_msg = format!("Tool '{name}' is not available.");
                    state.add_message(ChatMessage::tool(error_msg));
                }
                Some(tool) => {
                    // ── Approval gate ─────────────────────────────────────────
                    // Check risk level against the auto_approve threshold. If
                    // approval is needed and a registry is configured, emit
                    // ToolApprovalRequested and block until approved, denied,
                    // or timed out. A missing registry skips the gate entirely.
                    // Use effective_risk: max(ACL-required minimum, self-reported).
                    // This prevents a Low-declaring plugin from bypassing the gate
                    // for tools the policy requires to be High (finding #10).
                    let risk = crate::tool_acl::effective_risk(name.as_str(), tool.risk_level());
                    if !is_auto_approved(risk, auto_approve) {
                        if let Some(registry) = approval_registry {
                            let request_id = Uuid::new_v4();
                            let rx = registry.request(request_id);
                            event_bus.emit(Event::ToolApprovalRequested {
                                request_id,
                                session_id: Uuid::nil(),
                                tool_name: name.clone(),
                                args: args.clone(),
                                risk_level: risk,
                            });
                            let timeout_dur = registry.timeout();
                            match tokio::time::timeout(timeout_dur, rx).await {
                                Ok(Ok(true)) => {
                                    event_bus.emit(Event::ToolApprovalGranted { request_id });
                                }
                                Ok(Ok(false)) => {
                                    event_bus.emit(Event::ToolApprovalDenied {
                                        request_id,
                                        reason: None,
                                    });
                                    state.add_message(ChatMessage::tool(format!(
                                        "Tool '{}' execution denied by operator.",
                                        name
                                    )));
                                    continue;
                                }
                                Ok(Err(_)) => {
                                    // Sender dropped — approval channel cancelled.
                                    state.add_message(ChatMessage::tool(format!(
                                        "Tool '{}' approval cancelled.",
                                        name
                                    )));
                                    continue;
                                }
                                Err(_) => {
                                    // tokio::time::timeout elapsed.
                                    state.add_message(ChatMessage::tool(format!(
                                        "Tool '{}' approval timed out after {}s.",
                                        name,
                                        timeout_dur.as_secs()
                                    )));
                                    continue;
                                }
                            }
                        }
                    }

                    // ── Scan record persistence (best-effort) ─────────────────
                    // Create a ScanRecord before execution so the record exists
                    // even if the tool panics or the process dies mid-run.
                    //
                    // @decision DEC-AGENT-PERSIST-REDACT-001
                    // @title Redact credentials from tool-call args at persistence boundary
                    // @status accepted
                    // @rationale Defense-in-depth: even if a tool receives a
                    // credential (e.g. an Authorization header passed as an arg),
                    // it must not reach the scan-record store in plaintext.
                    // Redaction happens here — after approval but before the DB
                    // write — so approval logs and event-bus payloads are
                    // unaffected while the durable store stays clean.
                    let record_id: Option<Uuid> = if let Some(db) = db {
                        let (redacted_args, n_redactions) = sigint_core::redact_json(args);
                        if n_redactions > 0 {
                            debug!(
                                tool_name = %name,
                                n_redactions,
                                "scan record: redacted credentials in args"
                            );
                        }
                        let mut record = sigint_store::ScanRecord::new(
                            session_id,
                            name.as_str(),
                            redacted_args.to_string(),
                        );
                        // Attribute this tool call to the invoking agent role.
                        record.agent_role = Some(agent_role.to_string());
                        let rid = record.id;
                        if let Err(e) = db.create_scan_record(&record) {
                            warn!(tool_name = %name, error = %e, "scan record create failed");
                        }
                        Some(rid)
                    } else {
                        None
                    };

                    // Emit ToolStarted before execution.
                    event_bus.emit(Event::ToolStarted {
                        name: name.clone(),
                        args: args.clone(),
                    });

                    let started = Instant::now();

                    match tool.execute(args.clone()).await {
                        Ok(result) => {
                            let elapsed_ms = started.elapsed().as_millis() as u64;
                            let exit_code = result.exit_code;
                            let output_preview = if result.stdout.len() > 200 {
                                format!("{}…", &result.stdout[..200])
                            } else {
                                result.stdout.clone()
                            };

                            event_bus.emit(Event::ToolOutput {
                                name: name.clone(),
                                output: output_preview,
                            });
                            event_bus.emit(Event::ToolCompleted {
                                name: name.clone(),
                                exit_code,
                            });

                            debug!(
                                tool_name = %name,
                                exit_code,
                                elapsed_ms,
                                "tool loop: tool completed"
                            );

                            // Update the scan record with output and exit code.
                            if let (Some(db), Some(rid)) = (db, record_id) {
                                let finished = chrono::Utc::now().to_rfc3339();
                                if let Err(e) = db.update_scan_record(
                                    rid,
                                    Some(result.stdout.as_str()),
                                    exit_code,
                                    &finished,
                                ) {
                                    warn!(tool_name = %name, error = %e, "scan record update failed");
                                }
                            }

                            // Feed full result (with Display formatting) back to model.
                            state.add_message(ChatMessage::tool(result.to_string()));
                        }
                        Err(e) => {
                            warn!(tool_name = %name, error = %e, "tool loop: tool execution error");
                            event_bus.emit(Event::ToolCompleted {
                                name: name.clone(),
                                exit_code: -1,
                            });

                            // Update the scan record with the error as output.
                            if let (Some(db), Some(rid)) = (db, record_id) {
                                let finished = chrono::Utc::now().to_rfc3339();
                                let err_str = e.to_string();
                                if let Err(ue) = db.update_scan_record(
                                    rid,
                                    Some(err_str.as_str()),
                                    -1,
                                    &finished,
                                ) {
                                    warn!(tool_name = %name, error = %ue, "scan record update failed");
                                }
                            }

                            let error_msg = format!("Tool '{name}' failed: {e}");
                            state.add_message(ChatMessage::tool(error_msg));
                        }
                    }
                }
            }
        }

        // Trim conversation to stay within token budget.
        state.trim_to_budget();
    }

    // max_iterations exhausted — return whatever text we have with a warning.
    warn!(max_iterations, "tool loop: maximum iterations reached");
    Ok(format!(
        "{last_text}\n\n[Warning: maximum tool iterations reached]"
    ))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use serde_json::{json, Value};
    use std::sync::Mutex;
    use std::time::Duration;

    use sigint_core::{event::EventBus, ApprovalRegistry, Error};
    use sigint_llm::{
        provider::{ChunkStream, LlmProvider},
        types::{ChatResponse, FunctionCall, StreamChunk, ToolCall},
    };
    use sigint_tools::{error::ToolError, result::ToolResult, tool::Tool};

    use crate::state::ConversationState;

    // ── Mock LLM Provider ────────────────────────────────────────────────────

    /// A mock LLM provider that serves pre-configured responses via
    /// `chat_stream()`. Each queued `ChatResponse` is split into a text delta
    /// chunk followed by a `done=true` chunk carrying tool_calls (if any),
    /// mirroring real provider behaviour per DEC-LLM-003.
    ///
    /// `chat()` delegates to `chat_stream()` so both call paths share the queue.
    struct MockProvider {
        /// Responses returned in order; each `chat_stream()` call pops the front.
        responses: Mutex<Vec<ChatResponse>>,
    }

    impl MockProvider {
        fn new(responses: Vec<ChatResponse>) -> Self {
            Self {
                responses: Mutex::new(responses),
            }
        }

        /// Build a plain-text response (no tool calls).
        fn text_response(content: &str) -> ChatResponse {
            ChatResponse {
                content: content.into(),
                usage: None,
                model: "mock".into(),
                tool_calls: vec![],
            }
        }

        /// Build a response requesting a single tool call.
        fn tool_response(tool_name: &str, args: Value) -> ChatResponse {
            ChatResponse {
                content: String::new(),
                usage: None,
                model: "mock".into(),
                tool_calls: vec![ToolCall {
                    function: FunctionCall {
                        name: tool_name.into(),
                        arguments: args,
                    },
                }],
            }
        }

        /// Convert a `ChatResponse` into the `StreamChunk` sequence a real
        /// provider emits: an optional text chunk then the `done=true` chunk.
        fn response_to_chunks(response: ChatResponse) -> Vec<StreamChunk> {
            let mut chunks = Vec::new();
            if !response.content.is_empty() {
                chunks.push(StreamChunk {
                    delta: response.content.clone(),
                    done: false,
                    usage: None,
                    tool_calls: vec![],
                });
            }
            chunks.push(StreamChunk {
                delta: String::new(),
                done: true,
                usage: response.usage,
                tool_calls: response.tool_calls,
            });
            chunks
        }
    }

    #[async_trait]
    impl LlmProvider for MockProvider {
        fn name(&self) -> &str {
            "mock"
        }

        async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, Error> {
            // Delegate to chat_stream so the same response queue serves both paths.
            use futures_util::StreamExt as FutStreamExt;
            let mut stream = self.chat_stream(request).await?;
            let mut content = String::new();
            let mut tool_calls = vec![];
            while let Some(chunk_result) = FutStreamExt::next(&mut stream).await {
                let chunk = chunk_result?;
                content.push_str(&chunk.delta);
                if chunk.done {
                    tool_calls = chunk.tool_calls;
                }
            }
            Ok(ChatResponse {
                content,
                usage: None,
                model: "mock".into(),
                tool_calls,
            })
        }

        async fn chat_stream(&self, _request: ChatRequest) -> Result<ChunkStream, Error> {
            let mut queue = self.responses.lock().unwrap();
            let response = if queue.is_empty() {
                MockProvider::text_response("[mock exhausted]")
            } else {
                queue.remove(0)
            };
            let chunks = MockProvider::response_to_chunks(response);
            Ok(Box::pin(futures_util::stream::iter(
                chunks.into_iter().map(Ok),
            )))
        }
    }

    // ── Mock Tool ─────────────────────────────────────────────────────────────

    /// A mock tool that returns a preset result or error.
    struct MockTool {
        tool_name: String,
        /// If `Some`, return this result; if `None`, return an error.
        result: Option<String>,
    }

    impl MockTool {
        fn success(name: &str, output: &str) -> Self {
            Self {
                tool_name: name.into(),
                result: Some(output.into()),
            }
        }

        fn failing(name: &str) -> Self {
            Self {
                tool_name: name.into(),
                result: None,
            }
        }
    }

    #[async_trait]
    impl Tool for MockTool {
        fn name(&self) -> &str {
            &self.tool_name
        }

        fn description(&self) -> &str {
            "mock tool"
        }

        fn definition(&self) -> sigint_llm::ToolDefinition {
            sigint_llm::ToolDefinition::function(
                self.tool_name.clone(),
                "mock tool",
                json!({ "type": "object", "properties": {} }),
            )
        }

        async fn execute(&self, _args: Value) -> sigint_tools::error::Result<ToolResult> {
            match &self.result {
                Some(output) => Ok(ToolResult {
                    stdout: output.clone(),
                    stderr: String::new(),
                    exit_code: 0,
                    duration: Duration::from_millis(10),
                    structured_data: None,
                    status: Default::default(),
                    truncation: None,
                }),
                None => Err(ToolError::Sandbox("mock tool failure".into())),
            }
        }
    }

    // ── Helper ────────────────────────────────────────────────────────────────

    fn make_state() -> ConversationState {
        let mut s = ConversationState::new(8192);
        s.add_message(ChatMessage::user("run a scan"));
        s
    }

    fn no_tools() -> Vec<ToolDefinition> {
        vec![]
    }

    /// Build a [`ToolLoopOptions`] with common test defaults.
    ///
    /// `db` defaults to `None` and `session_id` to `Uuid::nil()` so existing
    /// tests don't need a database — the persistence path is a no-op.
    fn make_opts<'a>(
        max_iterations: usize,
        bus: &'a EventBus,
        approval_registry: Option<&'a ApprovalRegistry>,
        auto_approve: &'a str,
    ) -> ToolLoopOptions<'a> {
        ToolLoopOptions {
            max_iterations,
            model: "mock",
            event_bus: bus,
            approval_registry,
            auto_approve,
            db: None,
            session_id: Uuid::nil(),
            agent_role: "test",
        }
    }

    // ── Test cases ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn no_tool_calls_returns_text_immediately() {
        let provider = MockProvider::new(vec![MockProvider::text_response("All done!")]);
        let mut state = make_state();
        let bus = EventBus::new();
        let tools: Vec<&dyn Tool> = vec![];

        let result = run_tool_loop(
            &provider,
            &mut state,
            &tools,
            &no_tools(),
            make_opts(5, &bus, None, "all"),
        )
        .await
        .unwrap();

        assert_eq!(result, "All done!");
        // State should NOT have gained an assistant message from a tool-round
        // (the text response isn't appended by the loop — caller handles it).
        // We only have the initial user message.
        assert_eq!(state.to_chat_messages().len(), 1);
    }

    #[tokio::test]
    async fn single_tool_call_then_text() {
        let tool = MockTool::success("nmap_scan", "open ports: 22, 80");
        let tool_def = tool.definition();
        let tool_ref: &dyn Tool = &tool;

        let provider = MockProvider::new(vec![
            MockProvider::tool_response("nmap_scan", json!({"target": "10.0.0.1"})),
            MockProvider::text_response("Found open ports 22 and 80."),
        ]);

        let mut state = make_state();
        let bus = EventBus::new();

        let result = run_tool_loop(
            &provider,
            &mut state,
            &[tool_ref],
            &[tool_def],
            make_opts(5, &bus, None, "all"),
        )
        .await
        .unwrap();

        assert_eq!(result, "Found open ports 22 and 80.");
        // State should contain: original user msg + assistant (tool_calls) + tool result
        let msgs = state.to_chat_messages();
        assert!(
            msgs.iter().any(|m| m.role == "assistant"),
            "assistant message missing"
        );
        assert!(
            msgs.iter().any(|m| m.role == "tool"),
            "tool result message missing"
        );
    }

    #[tokio::test]
    async fn multiple_tool_call_rounds_then_text() {
        let tool = MockTool::success("shell", "scan done");
        let tool_def = tool.definition();
        let tool_ref: &dyn Tool = &tool;

        let provider = MockProvider::new(vec![
            MockProvider::tool_response("shell", json!({"command": "nmap 1.1.1.1"})),
            MockProvider::tool_response("shell", json!({"command": "nmap 2.2.2.2"})),
            MockProvider::text_response("Completed two scans."),
        ]);

        let mut state = make_state();
        let bus = EventBus::new();

        let result = run_tool_loop(
            &provider,
            &mut state,
            &[tool_ref],
            &[tool_def],
            make_opts(5, &bus, None, "all"),
        )
        .await
        .unwrap();

        assert_eq!(result, "Completed two scans.");
        // Two tool rounds → two assistant + two tool messages.
        let msgs = state.to_chat_messages();
        let assistant_count = msgs.iter().filter(|m| m.role == "assistant").count();
        let tool_count = msgs.iter().filter(|m| m.role == "tool").count();
        assert_eq!(assistant_count, 2, "expected 2 assistant messages");
        assert_eq!(tool_count, 2, "expected 2 tool result messages");
    }

    #[tokio::test]
    async fn max_iterations_returns_warning() {
        let tool = MockTool::success("shell", "output");
        let tool_def = tool.definition();
        let tool_ref: &dyn Tool = &tool;

        // Always return a tool call — never a text response.
        let responses: Vec<ChatResponse> = (0..10)
            .map(|_| MockProvider::tool_response("shell", json!({"command": "ls"})))
            .collect();
        let provider = MockProvider::new(responses);

        let mut state = make_state();
        let bus = EventBus::new();

        let result = run_tool_loop(
            &provider,
            &mut state,
            &[tool_ref],
            &[tool_def],
            make_opts(3, &bus, None, "all"), // low limit
        )
        .await
        .unwrap();

        assert!(
            result.contains("[Warning: maximum tool iterations reached]"),
            "expected warning in result: {result}"
        );
    }

    #[tokio::test]
    async fn unknown_tool_feeds_error_back() {
        // Provider requests a tool that does not exist, then responds with text.
        let provider = MockProvider::new(vec![
            MockProvider::tool_response("nonexistent_tool", json!({})),
            MockProvider::text_response("I couldn't use that tool."),
        ]);

        let mut state = make_state();
        let bus = EventBus::new();
        let tools: Vec<&dyn Tool> = vec![];

        let result = run_tool_loop(
            &provider,
            &mut state,
            &tools,
            &no_tools(),
            make_opts(5, &bus, None, "all"),
        )
        .await
        .unwrap();

        assert_eq!(result, "I couldn't use that tool.");
        // The error should have been fed back as a tool-role message.
        let msgs = state.to_chat_messages();
        let tool_msg = msgs
            .iter()
            .find(|m| m.role == "tool")
            .expect("tool message missing");
        assert!(
            tool_msg.content.contains("not available"),
            "expected 'not available' in tool error message: {}",
            tool_msg.content
        );
    }

    #[tokio::test]
    async fn tool_execution_error_feeds_error_back() {
        let tool = MockTool::failing("flaky_tool");
        let tool_def = tool.definition();
        let tool_ref: &dyn Tool = &tool;

        let provider = MockProvider::new(vec![
            MockProvider::tool_response("flaky_tool", json!({})),
            MockProvider::text_response("The tool failed, I'll adapt."),
        ]);

        let mut state = make_state();
        let bus = EventBus::new();

        let result = run_tool_loop(
            &provider,
            &mut state,
            &[tool_ref],
            &[tool_def],
            make_opts(5, &bus, None, "all"),
        )
        .await
        .unwrap();

        assert_eq!(result, "The tool failed, I'll adapt.");
        let msgs = state.to_chat_messages();
        let tool_msg = msgs
            .iter()
            .find(|m| m.role == "tool")
            .expect("tool message missing");
        assert!(
            tool_msg.content.contains("failed"),
            "expected 'failed' in error message: {}",
            tool_msg.content
        );
    }

    #[tokio::test]
    async fn events_emitted_during_tool_call() {
        let tool = MockTool::success("scanner", "hosts: 10.0.0.1");
        let tool_def = tool.definition();
        let tool_ref: &dyn Tool = &tool;

        let provider = MockProvider::new(vec![
            MockProvider::tool_response("scanner", json!({"target": "10.0.0.0/24"})),
            MockProvider::text_response("Scan complete."),
        ]);

        let mut state = make_state();
        let bus = EventBus::new();
        let mut rx = bus.subscribe();

        let result = run_tool_loop(
            &provider,
            &mut state,
            &[tool_ref],
            &[tool_def],
            make_opts(5, &bus, None, "all"),
        )
        .await
        .unwrap();

        assert_eq!(result, "Scan complete.");

        // Collect all events that were emitted.
        let mut events: Vec<Event> = vec![];
        while let Ok(e) = rx.try_recv() {
            events.push(e);
        }

        let has_started = events
            .iter()
            .any(|e| matches!(e, Event::ToolStarted { name, .. } if name == "scanner"));
        let has_output = events
            .iter()
            .any(|e| matches!(e, Event::ToolOutput  { name, .. } if name == "scanner"));
        let has_done = events
            .iter()
            .any(|e| matches!(e, Event::ToolCompleted { name, .. } if name == "scanner"));

        assert!(has_started, "ToolStarted event missing");
        assert!(has_output, "ToolOutput event missing");
        assert!(has_done, "ToolCompleted event missing");
    }

    #[tokio::test]
    async fn provider_error_propagates() {
        struct FailingProvider;

        #[async_trait]
        impl LlmProvider for FailingProvider {
            fn name(&self) -> &str {
                "failing"
            }
            async fn chat(&self, _: ChatRequest) -> Result<ChatResponse, Error> {
                Err(Error::Llm("connection refused".into()))
            }
            async fn chat_stream(&self, _: ChatRequest) -> Result<ChunkStream, Error> {
                Err(Error::Llm("connection refused".into()))
            }
        }

        let mut state = make_state();
        let bus = EventBus::new();
        let tools: Vec<&dyn Tool> = vec![];

        let err = run_tool_loop(
            &FailingProvider,
            &mut state,
            &tools,
            &no_tools(),
            make_opts(3, &bus, None, "all"),
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("connection refused"));
    }

    // ── Approval gate tests ───────────────────────────────────────────────────

    /// A mock tool that self-reports Low risk but whose name ("shell") is in the
    /// ACL with a High floor — used to test that effective_risk overrides the
    /// self-reported value (finding #10 / DEC-AGENT-TOOL-ACL-001).
    struct LowSelfReportShellTool;

    #[async_trait]
    impl Tool for LowSelfReportShellTool {
        fn name(&self) -> &str {
            "shell"
        }
        fn description(&self) -> &str {
            "shell tool self-reporting Low (adversarial)"
        }
        fn definition(&self) -> sigint_llm::ToolDefinition {
            sigint_llm::ToolDefinition::function(
                "shell",
                "shell tool self-reporting Low (adversarial)",
                json!({ "type": "object", "properties": {} }),
            )
        }
        fn risk_level(&self) -> ToolRisk {
            // Adversarially self-reporting Low — ACL must override to High.
            ToolRisk::Low
        }
        async fn execute(&self, _args: Value) -> sigint_tools::error::Result<ToolResult> {
            Ok(ToolResult {
                stdout: "executed_despite_low_claim".into(),
                stderr: String::new(),
                exit_code: 0,
                duration: Duration::from_millis(10),
                structured_data: None,
                status: Default::default(),
                truncation: None,
            })
        }
    }

    /// A High-risk mock tool that always succeeds.
    struct HighRiskTool;

    #[async_trait]
    impl Tool for HighRiskTool {
        fn name(&self) -> &str {
            "dangerous_tool"
        }
        fn description(&self) -> &str {
            "a risky tool"
        }
        fn definition(&self) -> sigint_llm::ToolDefinition {
            sigint_llm::ToolDefinition::function(
                "dangerous_tool",
                "a risky tool",
                json!({ "type": "object", "properties": {} }),
            )
        }
        fn risk_level(&self) -> ToolRisk {
            ToolRisk::High
        }
        async fn execute(&self, _args: Value) -> sigint_tools::error::Result<ToolResult> {
            Ok(ToolResult {
                stdout: "executed".into(),
                stderr: String::new(),
                exit_code: 0,
                duration: Duration::from_millis(10),
                structured_data: None,
                status: Default::default(),
                truncation: None,
            })
        }
    }

    /// A Low-risk tool with auto_approve="low" should execute without any registry.
    #[tokio::test]
    async fn low_risk_auto_approved() {
        let tool = MockTool::success("safe_tool", "output from safe tool");
        let tool_def = tool.definition();
        let tool_ref: &dyn Tool = &tool;

        let provider = MockProvider::new(vec![
            MockProvider::tool_response("safe_tool", json!({})),
            MockProvider::text_response("Safe tool ran fine."),
        ]);

        let mut state = make_state();
        let bus = EventBus::new();

        // No registry: Low risk is within "low" threshold, gate is bypassed.
        let result = run_tool_loop(
            &provider,
            &mut state,
            &[tool_ref],
            &[tool_def],
            make_opts(5, &bus, None, "low"),
        )
        .await
        .unwrap();

        assert_eq!(result, "Safe tool ran fine.");
        let msgs = state.to_chat_messages();
        let tool_msg = msgs
            .iter()
            .find(|m| m.role == "tool")
            .expect("tool result missing");
        assert!(
            tool_msg.content.contains("output from safe tool"),
            "unexpected tool output: {}",
            tool_msg.content
        );
    }

    /// A High-risk tool with auto_approve="low" is approved via registry.
    /// A concurrent task watches for ToolApprovalRequested and responds true.
    #[tokio::test]
    async fn high_risk_tool_approved_via_registry() {
        use std::sync::Arc;

        let tool = HighRiskTool;
        let tool_def = tool.definition();
        let tool_ref: &dyn Tool = &tool;

        let provider = MockProvider::new(vec![
            MockProvider::tool_response("dangerous_tool", json!({})),
            MockProvider::text_response("Dangerous tool completed."),
        ]);

        let mut state = make_state();
        let bus = EventBus::new();
        let registry = Arc::new(ApprovalRegistry::new(Duration::from_secs(5)));
        let registry_for_responder = Arc::clone(&registry);

        // Spawn a task that watches for ToolApprovalRequested and approves it.
        let mut rx = bus.subscribe();
        let responder = tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(Event::ToolApprovalRequested { request_id, .. }) => {
                        registry_for_responder
                            .respond(request_id, true)
                            .expect("respond failed");
                        return;
                    }
                    Ok(_) => continue,
                    Err(e) => panic!("event channel error: {e}"),
                }
            }
        });

        let result = run_tool_loop(
            &provider,
            &mut state,
            &[tool_ref],
            &[tool_def],
            make_opts(5, &bus, Some(registry.as_ref()), "low"),
        )
        .await
        .unwrap();

        responder.await.expect("responder task panicked");

        assert_eq!(result, "Dangerous tool completed.");
        let msgs = state.to_chat_messages();
        let tool_msg = msgs
            .iter()
            .find(|m| m.role == "tool")
            .expect("tool result missing");
        assert!(
            tool_msg.content.contains("executed"),
            "unexpected tool output: {}",
            tool_msg.content
        );
    }

    /// A High-risk tool denied by the registry causes a "denied" message to be
    /// fed back to the LLM; the tool itself does NOT execute.
    #[tokio::test]
    async fn high_risk_tool_denied_returns_error_to_llm() {
        use std::sync::Arc;

        let tool = HighRiskTool;
        let tool_def = tool.definition();
        let tool_ref: &dyn Tool = &tool;

        let provider = MockProvider::new(vec![
            MockProvider::tool_response("dangerous_tool", json!({})),
            // After the denial message is fed back the LLM responds with text.
            MockProvider::text_response("Understood, I will not execute that tool."),
        ]);

        let mut state = make_state();
        let bus = EventBus::new();
        let registry = Arc::new(ApprovalRegistry::new(Duration::from_secs(5)));
        let registry_for_responder = Arc::clone(&registry);

        let mut rx = bus.subscribe();
        let responder = tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(Event::ToolApprovalRequested { request_id, .. }) => {
                        registry_for_responder
                            .respond(request_id, false) // DENY
                            .expect("respond failed");
                        return;
                    }
                    Ok(_) => continue,
                    Err(e) => panic!("event channel error: {e}"),
                }
            }
        });

        let result = run_tool_loop(
            &provider,
            &mut state,
            &[tool_ref],
            &[tool_def],
            make_opts(5, &bus, Some(registry.as_ref()), "low"),
        )
        .await
        .unwrap();

        responder.await.expect("responder task panicked");

        assert_eq!(result, "Understood, I will not execute that tool.");

        // The tool message should say "denied", not contain tool execution output.
        let msgs = state.to_chat_messages();
        let tool_msg = msgs
            .iter()
            .find(|m| m.role == "tool")
            .expect("tool result missing");
        assert!(
            tool_msg.content.contains("denied"),
            "expected 'denied' in tool message: {}",
            tool_msg.content
        );
        assert!(
            !tool_msg.content.contains("executed"),
            "tool should not have executed: {}",
            tool_msg.content
        );
    }

    // ── AgentThinking event tests ─────────────────────────────────────────────

    /// Verifies that the streaming path emits `AgentThinking` and/or
    /// `AgentThinkingDone` events for any response (text or tool-call).
    #[tokio::test]
    async fn streaming_emits_agent_thinking_events() {
        let tool = MockTool::success("scanner", "scan output");
        let tool_def = tool.definition();
        let tool_ref: &dyn Tool = &tool;

        let provider = MockProvider::new(vec![
            MockProvider::tool_response("scanner", json!({"target": "10.0.0.1"})),
            MockProvider::text_response("Scan complete."),
        ]);

        let mut state = make_state();
        let bus = EventBus::new();
        let mut rx = bus.subscribe();

        let result = run_tool_loop(
            &provider,
            &mut state,
            &[tool_ref],
            &[tool_def],
            make_opts(5, &bus, None, "all"),
        )
        .await
        .unwrap();

        assert_eq!(result, "Scan complete.");

        let mut events = vec![];
        while let Ok(e) = rx.try_recv() {
            events.push(e);
        }
        let has_thinking = events
            .iter()
            .any(|e| matches!(e, Event::AgentThinking { .. }));
        let has_done = events
            .iter()
            .any(|e| matches!(e, Event::AgentThinkingDone { .. }));
        assert!(
            has_thinking || has_done,
            "should emit AgentThinking or AgentThinkingDone events"
        );
    }

    /// Verifies that `AgentThinkingDone` carries the correct agent role label.
    #[tokio::test]
    async fn thinking_done_carries_agent_role() {
        let provider = MockProvider::new(vec![MockProvider::text_response("done")]);
        let mut state = make_state();
        let bus = EventBus::new();
        let mut rx = bus.subscribe();

        let _ = run_tool_loop(
            &provider,
            &mut state,
            &[],
            &no_tools(),
            ToolLoopOptions {
                max_iterations: 5,
                model: "mock",
                event_bus: &bus,
                approval_registry: None,
                auto_approve: "all",
                db: None,
                session_id: Uuid::nil(),
                agent_role: "researcher",
            },
        )
        .await
        .unwrap();

        let mut events = vec![];
        while let Ok(e) = rx.try_recv() {
            events.push(e);
        }
        let done_event = events.iter().find(
            |e| matches!(e, Event::AgentThinkingDone { agent_role } if agent_role == "researcher"),
        );
        assert!(
            done_event.is_some(),
            "expected AgentThinkingDone with role 'researcher'"
        );
    }

    // ── Per-chunk timeout tests (8D-1) ────────────────────────────────────────

    /// Build a `ChunkStream` that yields `initial_text` as a delta chunk then
    /// stalls forever (never yields `done=true`). Used to test the 30-second
    /// per-chunk timeout guard (DEC-AGENT-016).
    ///
    /// The stream pends on `std::future::pending::<()>()` after the first chunk
    /// so `StreamExt::next()` will never resolve for the second item.
    fn stalling_stream(initial_text: &str) -> ChunkStream {
        let text = initial_text.to_string();
        let stream = async_stream::stream! {
            yield Ok::<StreamChunk, sigint_core::Error>(StreamChunk {
                delta: text,
                done: false,
                usage: None,
                tool_calls: vec![],
            });
            // Hang forever — simulates a stalled Ollama process.
            std::future::pending::<()>().await;
        };
        Box::pin(stream)
    }

    /// A mock LLM provider that returns a stalling stream (one chunk then hangs).
    struct StallingProvider {
        initial_text: String,
    }

    #[async_trait]
    impl LlmProvider for StallingProvider {
        fn name(&self) -> &str {
            "stalling"
        }
        async fn chat(&self, _: ChatRequest) -> Result<ChatResponse, Error> {
            Err(Error::Llm("not used".into()))
        }
        async fn chat_stream(&self, _: ChatRequest) -> Result<ChunkStream, Error> {
            Ok(stalling_stream(&self.initial_text))
        }
    }

    /// The per-chunk timeout must fire when the LLM stops sending chunks.
    ///
    /// Strategy: use `tokio::time::pause()` + `tokio::time::advance()` to jump
    /// the clock forward 31 seconds without real wall-clock waiting. The loop
    /// engine has a 30-second per-chunk timeout (CHUNK_TIMEOUT_SECS), so after
    /// advancing 31 seconds the timeout elapses and the loop should break and
    /// return the partial accumulated text.
    #[tokio::test(start_paused = true)]
    async fn streaming_timeout_returns_partial_text() {
        let provider = StallingProvider {
            initial_text: "partial output here".to_string(),
        };
        let mut state = make_state();
        let bus = EventBus::new();
        let tools: Vec<&dyn Tool> = vec![];

        // Advance time past the 30-second per-chunk timeout while the loop runs.
        let advance_task = tokio::spawn(async {
            // Yield once so the tool-loop task gets to poll the stalling stream.
            tokio::task::yield_now().await;
            // Jump the clock past the chunk timeout.
            tokio::time::advance(std::time::Duration::from_secs(31)).await;
        });

        let result = run_tool_loop(
            &provider,
            &mut state,
            &tools,
            &no_tools(),
            make_opts(1, &bus, None, "all"),
        )
        .await
        .unwrap();

        advance_task.await.expect("advance task panicked");

        // The partial text from the first chunk should be returned.
        assert_eq!(
            result, "partial output here",
            "expected partial accumulated text; got: {result}"
        );
    }

    /// Verify that conversation state is updated correctly after a tool-call
    /// round in the streaming path (8D-3 accounting check).
    ///
    /// The assistant message (with tool_calls) must be appended to state BEFORE
    /// `trim_to_budget()` is called so the token budget accounts for it. This
    /// mirrors what the non-streaming path has always done.
    #[tokio::test]
    async fn streaming_adds_assistant_message_before_tool_execution() {
        let tool = MockTool::success("probe", "probe output");
        let tool_def = tool.definition();
        let tool_ref: &dyn Tool = &tool;

        let provider = MockProvider::new(vec![
            MockProvider::tool_response("probe", json!({"target": "192.168.1.1"})),
            MockProvider::text_response("Probe complete."),
        ]);

        let mut state = make_state();
        let initial_len = state.to_chat_messages().len();
        let bus = EventBus::new();

        let result = run_tool_loop(
            &provider,
            &mut state,
            &[tool_ref],
            &[tool_def],
            make_opts(5, &bus, None, "all"),
        )
        .await
        .unwrap();

        assert_eq!(result, "Probe complete.");

        let msgs = state.to_chat_messages();
        // After one tool round: initial user msg + assistant (tool_calls) + tool result.
        assert_eq!(
            msgs.len(),
            initial_len + 2,
            "expected initial + assistant + tool messages; got {} messages",
            msgs.len()
        );

        // The assistant message must carry the tool_calls list (non-empty).
        let asst = msgs
            .iter()
            .find(|m| m.role == "assistant")
            .expect("assistant message missing");
        assert!(
            asst.tool_calls.as_ref().is_some_and(|tc| !tc.is_empty()),
            "assistant message should carry tool_calls"
        );

        // The tool-result message follows the assistant message.
        let tool_msg = msgs
            .iter()
            .find(|m| m.role == "tool")
            .expect("tool message missing");
        assert!(
            tool_msg.content.contains("probe output"),
            "tool message should contain probe output: {}",
            tool_msg.content
        );
    }

    // ── Redaction at persistence boundary (P3a) ──────────────────────────────

    /// Verifies that tool-call args containing a Bearer token are redacted
    /// before they reach the ScanRecord store (Finding #12 — DEC-AGENT-PERSIST-REDACT-001).
    ///
    /// Strategy: run a real in-memory Database, drive one tool call whose args
    /// include a Bearer token, then query the stored ScanRecord and assert the
    /// token has been replaced by "<redacted>".
    #[tokio::test]
    async fn scan_record_args_redacted_at_persistence() {
        let secret = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig";
        let tool_args = json!({
            "url": "https://example.com/api",
            "headers": {
                "Authorization": format!("Bearer {secret}")
            }
        });

        let tool = MockTool::success("http_probe", "200 OK");
        let tool_def = tool.definition();
        let tool_ref: &dyn Tool = &tool;

        let provider = MockProvider::new(vec![
            MockProvider::tool_response("http_probe", tool_args),
            MockProvider::text_response("done"),
        ]);

        let db = sigint_store::Database::open_in_memory().expect("in-memory DB");
        // Create a session so foreign-key constraints are satisfied.
        let session = sigint_core::types::Session::new("redact-test");
        db.create_session(&session).expect("create session");

        let mut state = make_state();
        let bus = EventBus::new();

        let _ = run_tool_loop(
            &provider,
            &mut state,
            &[tool_ref],
            &[tool_def],
            ToolLoopOptions {
                max_iterations: 5,
                model: "mock",
                event_bus: &bus,
                approval_registry: None,
                auto_approve: "all",
                db: Some(&db),
                session_id: session.id,
                agent_role: "executor",
            },
        )
        .await
        .unwrap();

        // Retrieve all scan records for this session.
        let records = db.get_scan_records(session.id).expect("get scan records");
        assert!(!records.is_empty(), "expected at least one scan record");

        let record = records
            .iter()
            .find(|r| r.tool == "http_probe")
            .expect("http_probe record missing");

        // The stored args must NOT contain the original token.
        assert!(
            !record.args.contains(secret),
            "secret token leaked into scan record args: {}",
            record.args
        );
        // The stored args must contain the redaction marker.
        assert!(
            record.args.contains("<redacted>"),
            "expected '<redacted>' in scan record args: {}",
            record.args
        );
    }

    // ── Tool ACL gate (P3b) ──────────────────────────────────────────────────

    /// A tool that self-reports Low risk but is named "shell" — the ACL floor
    /// for "shell" is High. With auto_approve="low" the gate must still block
    /// it, proving that effective_risk() overrides the self-reported value.
    ///
    /// The approval responder DENIES the request so we can observe that the
    /// gate fired (not that the tool ran). The LLM is then fed a denial message
    /// and responds with text — the tool output must NOT appear in state.
    #[tokio::test]
    async fn approval_gate_uses_acl_max_not_self_reported() {
        use std::sync::Arc;

        // "shell" self-reports Low but ACL floor is High.
        let tool = LowSelfReportShellTool;
        let tool_def = tool.definition();
        let tool_ref: &dyn Tool = &tool;

        let provider = MockProvider::new(vec![
            MockProvider::tool_response("shell", json!({"command": "grep"})),
            // After the denial message the LLM responds with text.
            MockProvider::text_response("Understood, shell is not approved."),
        ]);

        let mut state = make_state();
        let bus = EventBus::new();
        let registry = Arc::new(ApprovalRegistry::new(Duration::from_secs(5)));
        let registry_for_responder = Arc::clone(&registry);

        // Watch for ToolApprovalRequested; deny it.
        let mut rx = bus.subscribe();
        let responder = tokio::spawn(async move {
            loop {
                match rx.recv().await {
                    Ok(Event::ToolApprovalRequested {
                        request_id,
                        risk_level,
                        ..
                    }) => {
                        // The gate must have escalated to High, not left it at Low.
                        assert_eq!(
                            risk_level,
                            ToolRisk::High,
                            "expected ACL to override self-reported Low to High"
                        );
                        registry_for_responder
                            .respond(request_id, false)
                            .expect("respond failed");
                        return;
                    }
                    Ok(_) => continue,
                    Err(e) => panic!("event channel error: {e}"),
                }
            }
        });

        // auto_approve="low" — would auto-approve if risk stayed at Low,
        // but ACL raises it to High so the gate fires.
        let result = run_tool_loop(
            &provider,
            &mut state,
            &[tool_ref],
            &[tool_def],
            make_opts(5, &bus, Some(registry.as_ref()), "low"),
        )
        .await
        .unwrap();

        responder.await.expect("responder task panicked");

        assert_eq!(result, "Understood, shell is not approved.");

        // The tool must NOT have executed — its output must not appear.
        let msgs = state.to_chat_messages();
        let denied = msgs
            .iter()
            .find(|m| m.role == "tool")
            .expect("tool denial message missing");
        assert!(
            !denied.content.contains("executed_despite_low_claim"),
            "tool executed despite ACL override — gate failed: {}",
            denied.content
        );
        assert!(
            denied.content.contains("denied") || denied.content.contains("denied"),
            "expected denial message, got: {}",
            denied.content
        );
    }
}
