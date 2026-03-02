//! Tool-call loop engine — drives the LLM ↔ tool execution cycle.
//!
//! The loop sends a `ChatRequest` to the provider. If the model responds with
//! tool calls, the engine executes them, appends results to the conversation
//! state, and repeats. The loop terminates when the model produces a plain-text
//! response or `max_iterations` is exceeded.
//!
//! @decision DEC-AGENT-007
//! @title Non-streaming (`chat()`) for all tool-loop iterations
//! @status accepted
//! @rationale Tool calls require complete, structured JSON in the response
//! (`tool_calls` array). Streaming delivers tokens incrementally, which means
//! the tool-calls field is only available on the final chunk — adding latency
//! and complexity for no user-visible benefit during intermediate iterations.
//! The final text-only response CAN be streamed (handled by the caller via
//! `chat_stream`); but while the model is in tool-calling mode every call uses
//! `chat()`. This matches Ollama's behaviour: streaming tool calls are supported
//! but require reassembling the final chunk anyway.
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

use std::time::Instant;

use tracing::{debug, warn};
use uuid::Uuid;

use sigint_core::types::ToolRisk;
use sigint_core::{
    event::{Event, EventBus},
    ApprovalRegistry, Error,
};
use sigint_llm::{
    provider::LlmProvider,
    types::{ChatMessage, ChatRequest, ToolDefinition},
};
use sigint_tools::tool::Tool;

/// Configuration options for [`run_tool_loop`].
///
/// Bundles the execution-policy parameters to keep the function signature
/// within clippy's `too_many_arguments` limit (≤7).
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
    } = opts;

    let mut last_text = String::new();

    for iteration in 0..max_iterations {
        debug!(iteration, "tool loop: sending request to provider");

        // Build the request from current conversation state.
        let request = ChatRequest::new(model, state.to_chat_messages().to_vec())
            .with_tools(tool_defs.to_vec());

        let response = provider.chat(request).await?;

        // Update our last-seen text content (may be empty during tool rounds).
        if !response.content.is_empty() {
            last_text = response.content.clone();
        }

        if !response.has_tool_calls() {
            // Model produced a plain-text response — loop is done.
            debug!(iteration, "tool loop: text response received, exiting");
            return Ok(last_text);
        }

        // ── Tool-call round ──────────────────────────────────────────────────
        debug!(
            iteration,
            tool_call_count = response.tool_calls.len(),
            "tool loop: processing tool calls"
        );

        // Append the assistant turn (with tool_calls) to state.
        let assistant_msg = ChatMessage {
            role: "assistant".into(),
            content: response.content.clone(),
            tool_calls: Some(response.tool_calls.clone()),
        };
        state.add_message(assistant_msg);

        // Execute each requested tool and append a tool-role result message.
        for tool_call in &response.tool_calls {
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
                    let risk = tool.risk_level();
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

                            // Feed full result (with Display formatting) back to model.
                            state.add_message(ChatMessage::tool(result.to_string()));
                        }
                        Err(e) => {
                            warn!(tool_name = %name, error = %e, "tool loop: tool execution error");
                            event_bus.emit(Event::ToolCompleted {
                                name: name.clone(),
                                exit_code: -1,
                            });
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
    use futures_util::stream;
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

    /// A mock LLM provider that returns pre-configured responses in sequence.
    ///
    /// When the response queue is exhausted, returns a default text response
    /// to avoid panics in tests that might call more times than expected.
    struct MockProvider {
        /// Responses returned in order; each `chat()` call pops the front.
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
    }

    #[async_trait]
    impl LlmProvider for MockProvider {
        fn name(&self) -> &str {
            "mock"
        }

        async fn chat(&self, _request: ChatRequest) -> Result<ChatResponse, Error> {
            let mut queue = self.responses.lock().unwrap();
            if queue.is_empty() {
                // Fallback — prevents test panics on unexpected extra calls.
                Ok(MockProvider::text_response("[mock exhausted]"))
            } else {
                Ok(queue.remove(0))
            }
        }

        async fn chat_stream(&self, _request: ChatRequest) -> Result<ChunkStream, Error> {
            // Not used by the tool loop, but required by the trait.
            let s = stream::empty::<Result<StreamChunk, Error>>();
            Ok(Box::pin(s))
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
}
