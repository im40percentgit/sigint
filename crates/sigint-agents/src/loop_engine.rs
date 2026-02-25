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

use std::time::Instant;

use tracing::{debug, warn};

use sigint_core::{Error, event::{Event, EventBus}};
use sigint_llm::{
    provider::LlmProvider,
    types::{ChatMessage, ChatRequest, ToolDefinition},
};
use sigint_tools::tool::Tool;

/// Run the tool-call loop for an agent.
///
/// Sends `state.to_chat_messages()` to the provider with the given tool
/// definitions. If the model responds with tool calls, executes them via the
/// `tools` slice and appends results back to `state`. Repeats until the model
/// returns plain text or `max_iterations` is exhausted.
///
/// # Arguments
/// * `provider`       — LLM backend (Ollama, mock, etc.)
/// * `state`          — Mutable conversation history; updated in-place with
///   assistant and tool-result messages.
/// * `tools`          — Available tool implementations; matched by name.
/// * `tool_defs`      — Tool schemas passed to the LLM in each request.
/// * `max_iterations` — Hard cap on tool-call rounds before giving up.
/// * `model`          — Model identifier string (e.g. `"llama3.2"`).
/// * `event_bus`      — Best-effort event emission for observability.
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
    max_iterations: usize,
    model: &str,
    event_bus: &EventBus,
) -> Result<String, Error> {
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
                    event_bus.emit(Event::Status(format!(
                        "Unknown tool requested: {name}"
                    )));
                    let error_msg = format!("Tool '{name}' is not available.");
                    state.add_message(ChatMessage::tool(error_msg));
                }
                Some(tool) => {
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

    use sigint_core::{Error, event::EventBus};
    use sigint_llm::{
        provider::{ChunkStream, LlmProvider},
        types::{ChatResponse, FunctionCall, StreamChunk, ToolCall},
    };
    use sigint_tools::{result::ToolResult, tool::Tool, error::ToolError};

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
            Self { responses: Mutex::new(responses) }
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

    // ── Test cases ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn no_tool_calls_returns_text_immediately() {
        let provider = MockProvider::new(vec![MockProvider::text_response("All done!")]);
        let mut state = make_state();
        let bus = EventBus::new();
        let tools: Vec<&dyn Tool> = vec![];

        let result = run_tool_loop(&provider, &mut state, &tools, &no_tools(), 5, "mock", &bus)
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
            5,
            "mock",
            &bus,
        )
        .await
        .unwrap();

        assert_eq!(result, "Found open ports 22 and 80.");
        // State should contain: original user msg + assistant (tool_calls) + tool result
        let msgs = state.to_chat_messages();
        assert!(msgs.iter().any(|m| m.role == "assistant"), "assistant message missing");
        assert!(msgs.iter().any(|m| m.role == "tool"), "tool result message missing");
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
            5,
            "mock",
            &bus,
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
            3, // low limit
            "mock",
            &bus,
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

        let result = run_tool_loop(&provider, &mut state, &tools, &no_tools(), 5, "mock", &bus)
            .await
            .unwrap();

        assert_eq!(result, "I couldn't use that tool.");
        // The error should have been fed back as a tool-role message.
        let msgs = state.to_chat_messages();
        let tool_msg = msgs.iter().find(|m| m.role == "tool").expect("tool message missing");
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
            5,
            "mock",
            &bus,
        )
        .await
        .unwrap();

        assert_eq!(result, "The tool failed, I'll adapt.");
        let msgs = state.to_chat_messages();
        let tool_msg = msgs.iter().find(|m| m.role == "tool").expect("tool message missing");
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
            5,
            "mock",
            &bus,
        )
        .await
        .unwrap();

        assert_eq!(result, "Scan complete.");

        // Collect all events that were emitted.
        let mut events: Vec<Event> = vec![];
        while let Ok(e) = rx.try_recv() {
            events.push(e);
        }

        let has_started = events.iter().any(|e| matches!(e, Event::ToolStarted { name, .. } if name == "scanner"));
        let has_output  = events.iter().any(|e| matches!(e, Event::ToolOutput  { name, .. } if name == "scanner"));
        let has_done    = events.iter().any(|e| matches!(e, Event::ToolCompleted { name, .. } if name == "scanner"));

        assert!(has_started, "ToolStarted event missing");
        assert!(has_output,  "ToolOutput event missing");
        assert!(has_done,    "ToolCompleted event missing");
    }

    #[tokio::test]
    async fn provider_error_propagates() {
        struct FailingProvider;

        #[async_trait]
        impl LlmProvider for FailingProvider {
            fn name(&self) -> &str { "failing" }
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

        let err = run_tool_loop(&FailingProvider, &mut state, &tools, &no_tools(), 3, "mock", &bus)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("connection refused"));
    }
}
