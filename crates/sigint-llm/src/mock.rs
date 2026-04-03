//! MockProvider — a deterministic LLM provider for testing.
//!
//! Callers pre-load a queue of `MockResponse` values. Each `chat()` or
//! `chat_stream()` call pops the front of the queue and returns that response.
//! When the queue is exhausted, a fallback text `"[mock exhausted]"` is
//! returned so tests that make more calls than expected produce useful output
//! rather than panicking.
//!
//! @decision DEC-LLM-003
//! @title MockProvider lives in sigint-llm so E2E tests can inject it without
//!        depending on sigint-agents internals
//! @status accepted
//! @rationale Previously the only mock lived inside `orchestrator.rs` behind
//!   `#[cfg(test)]`. E2E tests in the `sigint-e2e` crate and the `ScanService`
//!   provider-override path both need a controllable LLM without spinning up
//!   Ollama. Placing MockProvider in sigint-llm keeps it close to the trait it
//!   implements and avoids a circular dependency (sigint-agents → sigint-e2e
//!   would create a cycle).  The enum `MockResponse` supports both plain text
//!   and tool-call responses so the agent tool-call loop can be exercised in
//!   tests without real LLM infrastructure.

use std::collections::VecDeque;
use std::sync::Mutex;

use async_trait::async_trait;
use futures_util::stream;

use sigint_core::Error;

use crate::{
    provider::{ChunkStream, LlmProvider},
    types::{ChatRequest, ChatResponse, FunctionCall, StreamChunk, ToolCall},
};

// ── MockResponse ──────────────────────────────────────────────────────────────

/// A single pre-configured response that `MockProvider` will return.
#[derive(Debug, Clone)]
pub enum MockResponse {
    /// The LLM returns a plain text content string.
    Text(String),
    /// The LLM returns a tool-call request (no text content).
    ToolCall {
        name: String,
        arguments: serde_json::Value,
    },
}

impl From<&str> for MockResponse {
    fn from(s: &str) -> Self {
        MockResponse::Text(s.to_string())
    }
}

impl From<String> for MockResponse {
    fn from(s: String) -> Self {
        MockResponse::Text(s)
    }
}

// ── MockProvider ──────────────────────────────────────────────────────────────

/// Deterministic LLM provider that returns pre-loaded responses from a queue.
///
/// Thread-safe (`Send + Sync`) via an internal `Mutex<VecDeque<MockResponse>>`.
/// Safe to wrap in `Arc` and share across async agent turns.
///
/// # Example
/// ```rust,ignore
/// let mock = MockProvider::with_responses(vec![
///     MockResponse::Text("Researcher output".into()),
///     MockResponse::ToolCall { name: "nmap".into(), arguments: json!({}) },
/// ]);
/// ```
pub struct MockProvider {
    responses: Mutex<VecDeque<MockResponse>>,
}

impl MockProvider {
    /// Create an empty `MockProvider`. All calls return `"[mock exhausted]"`.
    pub fn new() -> Self {
        Self {
            responses: Mutex::new(VecDeque::new()),
        }
    }

    /// Create a `MockProvider` pre-loaded with the given response queue.
    pub fn with_responses(responses: Vec<MockResponse>) -> Self {
        Self {
            responses: Mutex::new(VecDeque::from(responses)),
        }
    }

    /// Convenience constructor: load text-only responses from string slices.
    ///
    /// All entries are wrapped in `MockResponse::Text`. Matches the signature
    /// used by the legacy orchestrator-internal mock so existing tests can
    /// migrate with minimal changes.
    pub fn from_text(responses: Vec<&str>) -> Self {
        Self::with_responses(
            responses
                .into_iter()
                .map(|s| MockResponse::Text(s.to_string()))
                .collect(),
        )
    }

    /// Convenience constructor: repeat the same text response `count` times.
    pub fn uniform(response: &str, count: usize) -> Self {
        Self::from_text(vec![response; count])
    }

    /// Push an additional response onto the back of the queue at runtime.
    pub fn push_response(&self, response: MockResponse) {
        self.responses.lock().unwrap().push_back(response);
    }

    /// Pop and return the next queued response, or `None` if the queue is empty.
    fn pop_next(&self) -> Option<MockResponse> {
        self.responses.lock().unwrap().pop_front()
    }
}

impl Default for MockProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LlmProvider for MockProvider {
    fn name(&self) -> &str {
        "mock"
    }

    async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, Error> {
        // Delegate to chat_stream so both paths consume from the same queue.
        use futures_util::StreamExt as FutStreamExt;
        let mut s = self.chat_stream(request).await?;
        let mut content = String::new();
        let mut tool_calls = vec![];
        while let Some(chunk) = FutStreamExt::next(&mut s).await {
            let c = chunk?;
            content.push_str(&c.delta);
            tool_calls.extend(c.tool_calls);
        }
        Ok(ChatResponse {
            content,
            usage: None,
            model: "mock".into(),
            tool_calls,
        })
    }

    async fn chat_stream(&self, _request: ChatRequest) -> Result<ChunkStream, Error> {
        let response = self.pop_next();
        let chunks: Vec<Result<StreamChunk, Error>> = match response {
            None => {
                // Queue exhausted — return a text fallback.
                vec![
                    Ok(StreamChunk {
                        delta: "[mock exhausted]".to_string(),
                        done: false,
                        usage: None,
                        tool_calls: vec![],
                    }),
                    Ok(StreamChunk {
                        delta: String::new(),
                        done: true,
                        usage: None,
                        tool_calls: vec![],
                    }),
                ]
            }
            Some(MockResponse::Text(content)) => {
                // Emit content in one delta chunk, then a done=true terminal chunk.
                vec![
                    Ok(StreamChunk {
                        delta: content,
                        done: false,
                        usage: None,
                        tool_calls: vec![],
                    }),
                    Ok(StreamChunk {
                        delta: String::new(),
                        done: true,
                        usage: None,
                        tool_calls: vec![],
                    }),
                ]
            }
            Some(MockResponse::ToolCall { name, arguments }) => {
                // No text delta. Emit a done=true chunk carrying the tool call.
                // The loop engine accumulates tool_calls from all chunks, so a
                // single done chunk is sufficient.
                vec![Ok(StreamChunk {
                    delta: String::new(),
                    done: true,
                    usage: None,
                    tool_calls: vec![ToolCall {
                        function: FunctionCall { name, arguments },
                    }],
                })]
            }
        };
        Ok(Box::pin(stream::iter(chunks)))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::StreamExt;
    use serde_json::json;

    #[tokio::test]
    async fn text_response_via_stream() {
        let mock = MockProvider::from_text(vec!["hello world"]);
        let mut stream = mock
            .chat_stream(ChatRequest::new("m", vec![]))
            .await
            .unwrap();

        let mut content = String::new();
        while let Some(chunk) = stream.next().await {
            let c = chunk.unwrap();
            content.push_str(&c.delta);
        }
        assert_eq!(content, "hello world");
    }

    #[tokio::test]
    async fn tool_call_response_via_stream() {
        let mock = MockProvider::with_responses(vec![MockResponse::ToolCall {
            name: "nmap".into(),
            arguments: json!({"target": "192.168.1.1"}),
        }]);
        let mut stream = mock
            .chat_stream(ChatRequest::new("m", vec![]))
            .await
            .unwrap();

        let mut tool_calls = vec![];
        while let Some(chunk) = stream.next().await {
            let c = chunk.unwrap();
            tool_calls.extend(c.tool_calls);
        }
        assert_eq!(tool_calls.len(), 1);
        assert_eq!(tool_calls[0].function.name, "nmap");
        assert_eq!(tool_calls[0].function.arguments["target"], "192.168.1.1");
    }

    #[tokio::test]
    async fn exhausted_queue_returns_fallback() {
        let mock = MockProvider::new();
        let mut stream = mock
            .chat_stream(ChatRequest::new("m", vec![]))
            .await
            .unwrap();

        let mut content = String::new();
        while let Some(chunk) = stream.next().await {
            content.push_str(&chunk.unwrap().delta);
        }
        assert_eq!(content, "[mock exhausted]");
    }

    #[tokio::test]
    async fn multiple_responses_consumed_in_order() {
        let mock = MockProvider::from_text(vec!["first", "second", "third"]);

        for expected in ["first", "second", "third"] {
            let mut stream = mock
                .chat_stream(ChatRequest::new("m", vec![]))
                .await
                .unwrap();
            let mut got = String::new();
            while let Some(chunk) = stream.next().await {
                got.push_str(&chunk.unwrap().delta);
            }
            assert_eq!(got, expected);
        }

        // Fourth call hits exhausted queue.
        let mut stream = mock
            .chat_stream(ChatRequest::new("m", vec![]))
            .await
            .unwrap();
        let mut got = String::new();
        while let Some(chunk) = stream.next().await {
            got.push_str(&chunk.unwrap().delta);
        }
        assert_eq!(got, "[mock exhausted]");
    }

    #[tokio::test]
    async fn push_response_adds_to_queue() {
        let mock = MockProvider::new();
        mock.push_response(MockResponse::Text("dynamic".into()));

        let mut stream = mock
            .chat_stream(ChatRequest::new("m", vec![]))
            .await
            .unwrap();
        let mut got = String::new();
        while let Some(chunk) = stream.next().await {
            got.push_str(&chunk.unwrap().delta);
        }
        assert_eq!(got, "dynamic");
    }

    #[tokio::test]
    async fn uniform_returns_same_text_n_times() {
        let mock = MockProvider::uniform("ok", 3);
        for _ in 0..3 {
            let mut stream = mock
                .chat_stream(ChatRequest::new("m", vec![]))
                .await
                .unwrap();
            let mut got = String::new();
            while let Some(chunk) = stream.next().await {
                got.push_str(&chunk.unwrap().delta);
            }
            assert_eq!(got, "ok");
        }
    }
}
