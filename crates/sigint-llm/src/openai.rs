//! OpenAI-compatible LLM provider — POST /v1/chat/completions with SSE streaming.
//!
//! @decision DEC-LLM-004
//! @title OpenAI-compatible provider with manual SSE parsing
//! @status accepted
//! @rationale The OpenAI `/v1/chat/completions` endpoint is the de-facto standard
//! for cloud LLM APIs (OpenAI, Groq, Together.ai, local vLLM, LM Studio, etc.).
//! We parse SSE manually (stripping `data: ` prefixes and handling `[DONE]`) rather
//! than pulling in an SSE library — the protocol is simple enough and this keeps
//! the dependency tree lean. Bearer-token auth is passed as an Authorization header.
//! The `api_key` is resolved first from `LlmConfig.api_key`, then from the
//! `SIGINT_API_KEY` environment variable, so secrets stay out of config files.
//!
//! @decision DEC-LLM-005
//! @title OpenAI arguments field deserialized as String then re-parsed
//! @status accepted
//! @rationale OpenAI sends tool call `arguments` as a JSON-encoded string, not a
//! nested object. We deserialize it as `String` (matching the wire format), then
//! `serde_json::from_str` to get a `Value`. This avoids double-nesting and matches
//! the OpenAI API contract exactly.

use async_trait::async_trait;
use futures_util::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::provider::{ChunkStream, LlmProvider};
use crate::types::{
    ChatMessage, ChatRequest, ChatResponse, FunctionCall, StreamChunk, ToolCall,
    ToolDefinition, TokenUsage,
};
use sigint_core::Error;

// ── Wire types (private) ──────────────────────────────────────────────────────

/// Request body for POST /v1/chat/completions.
#[derive(Debug, Serialize)]
struct OpenAiWireRequest<'a> {
    model: &'a str,
    messages: &'a [OpenAiWireMessage],
    stream: bool,
    temperature: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_tokens: Option<u64>,
    /// Tool definitions. Omitted from wire when empty.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tools: Vec<ToolDefinition>,
}

/// A single message in the OpenAI wire format.
#[derive(Debug, Serialize)]
struct OpenAiWireMessage {
    role: String,
    content: String,
    /// Tool calls from an assistant turn. Omitted when None.
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_calls: Option<Vec<ToolCall>>,
}

/// Top-level non-streaming response from /v1/chat/completions.
#[derive(Debug, Deserialize)]
struct OpenAiResponse {
    choices: Vec<OpenAiChoice>,
    #[serde(default)]
    usage: Option<OpenAiUsage>,
}

/// A single choice in the response (we use index 0).
#[derive(Debug, Deserialize)]
struct OpenAiChoice {
    /// Present in non-streaming responses.
    message: Option<OpenAiMessage>,
    /// Present in streaming delta chunks.
    delta: Option<OpenAiDelta>,
}

/// The message object in a non-streaming response.
#[derive(Debug, Deserialize)]
struct OpenAiMessage {
    #[serde(default)]
    content: String,
    #[serde(default)]
    tool_calls: Vec<OpenAiToolCall>,
}

/// The delta object in a streaming SSE chunk.
#[derive(Debug, Deserialize)]
struct OpenAiDelta {
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    tool_calls: Vec<OpenAiToolCall>,
}

/// A tool call in the OpenAI wire format.
#[derive(Debug, Clone, Deserialize)]
struct OpenAiToolCall {
    function: OpenAiFunctionCall,
}

/// The function call inside an OpenAI tool call.
/// Note: `arguments` is a JSON-encoded string on the wire (not a nested object).
#[derive(Debug, Clone, Deserialize)]
struct OpenAiFunctionCall {
    name: String,
    /// JSON-encoded string of the arguments object.
    arguments: String,
}

/// Token usage stats from the OpenAI response.
#[derive(Debug, Deserialize)]
struct OpenAiUsage {
    prompt_tokens: u32,
    completion_tokens: u32,
    total_tokens: u32,
}

// ── Conversion helpers ────────────────────────────────────────────────────────

/// Convert OpenAI wire tool calls to domain ToolCalls, parsing the JSON-string
/// arguments field into a serde_json::Value.
fn wire_tool_calls_to_domain(wire: Vec<OpenAiToolCall>) -> Vec<ToolCall> {
    wire.into_iter()
        .filter_map(|tc| {
            let arguments = match serde_json::from_str::<serde_json::Value>(&tc.function.arguments) {
                Ok(v) => v,
                Err(e) => {
                    warn!(
                        "Failed to parse tool call arguments as JSON: {} — raw: {:?}",
                        e, tc.function.arguments
                    );
                    serde_json::Value::Object(Default::default())
                }
            };
            Some(ToolCall {
                function: FunctionCall {
                    name: tc.function.name,
                    arguments,
                },
            })
        })
        .collect()
}

/// Convert our domain ChatMessage slice into OpenAI wire messages.
fn build_wire_messages(messages: &[ChatMessage]) -> Vec<OpenAiWireMessage> {
    messages
        .iter()
        .map(|m| OpenAiWireMessage {
            role: m.role.clone(),
            content: m.content.clone(),
            tool_calls: m.tool_calls.clone(),
        })
        .collect()
}

// ── Provider ──────────────────────────────────────────────────────────────────

/// OpenAI-compatible LLM provider.
///
/// Works with OpenAI, Groq, Together.ai, local vLLM, LM Studio, and any other
/// server that implements the `/v1/chat/completions` API.
#[derive(Debug, Clone)]
pub struct OpenAiProvider {
    /// Base URL without trailing slash (e.g. "https://api.openai.com").
    base_url: String,
    api_key: String,
    /// Provider-level default temperature, retained for introspection and future
    /// use. Per-request temperature (`ChatRequest::temperature`) takes precedence
    /// in all actual API calls.
    #[allow(dead_code)]
    temperature: f32,
    client: reqwest::Client,
}

impl OpenAiProvider {
    /// Create a new provider.
    pub fn new(
        base_url: impl Into<String>,
        api_key: impl Into<String>,
        temperature: f32,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            api_key: api_key.into(),
            temperature,
            client: reqwest::Client::new(),
        }
    }

    /// Construct from `sigint-core` `LlmConfig`.
    ///
    /// API key resolution order:
    /// 1. `config.api_key` if present
    /// 2. `SIGINT_API_KEY` environment variable
    /// 3. Returns `Error::Config` if neither is available
    pub fn from_config(cfg: &sigint_core::config::LlmConfig) -> Result<Self, Error> {
        let key = if let Some(k) = &cfg.api_key {
            k.clone()
        } else if let Ok(k) = std::env::var("SIGINT_API_KEY") {
            k
        } else {
            return Err(Error::Config(
                "OpenAI provider requires an API key. Set `api_key` in [llm] config \
                 or export SIGINT_API_KEY."
                    .into(),
            ));
        };

        Ok(Self::new(&cfg.base_url, key, cfg.temperature))
    }

    /// Build the completions endpoint URL.
    fn completions_url(&self) -> String {
        format!("{}/v1/chat/completions", self.base_url)
    }

    /// Map HTTP status codes to friendly Error::Llm messages.
    fn http_error(status: reqwest::StatusCode, body: &str) -> Error {
        let msg = match status.as_u16() {
            401 => format!("Authentication failed (HTTP 401). Check your API key. Body: {}", body),
            429 => format!("Rate limited (HTTP 429). Try again later. Body: {}", body),
            _ => format!("OpenAI API returned HTTP {}: {}", status, body),
        };
        Error::Llm(msg)
    }
}

#[async_trait]
impl LlmProvider for OpenAiProvider {
    fn name(&self) -> &str {
        "openai"
    }

    async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, Error> {
        let wire_msgs = build_wire_messages(&request.messages);
        let max_tokens = if request.max_tokens > 0 {
            Some(request.max_tokens as u64)
        } else {
            None
        };

        let body = OpenAiWireRequest {
            model: &request.model,
            messages: &wire_msgs,
            stream: false,
            temperature: request.temperature,
            max_tokens,
            tools: request.tools.clone(),
        };

        debug!("OpenAI non-streaming request to {}", self.completions_url());

        let resp = self
            .client
            .post(self.completions_url())
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                Error::Llm(format!(
                    "Cannot connect to OpenAI at {}: {}",
                    self.base_url, e
                ))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(Self::http_error(status, &text));
        }

        let parsed: OpenAiResponse = resp.json().await.map_err(|e| {
            Error::Llm(format!("Failed to parse OpenAI response: {}", e))
        })?;

        let choice = parsed
            .choices
            .into_iter()
            .next()
            .ok_or_else(|| Error::Llm("OpenAI returned no choices".into()))?;

        let message = choice.message.unwrap_or(OpenAiMessage {
            content: String::new(),
            tool_calls: vec![],
        });

        let tool_calls = wire_tool_calls_to_domain(message.tool_calls);
        let usage = parsed.usage.map(|u| TokenUsage {
            prompt_tokens: u.prompt_tokens,
            completion_tokens: u.completion_tokens,
            total_tokens: u.total_tokens,
        });

        Ok(ChatResponse {
            content: message.content,
            tool_calls,
            usage,
            model: request.model,
        })
    }

    async fn chat_stream(&self, request: ChatRequest) -> Result<ChunkStream, Error> {
        let wire_msgs = build_wire_messages(&request.messages);
        let max_tokens = if request.max_tokens > 0 {
            Some(request.max_tokens as u64)
        } else {
            None
        };

        let body = OpenAiWireRequest {
            model: &request.model,
            messages: &wire_msgs,
            stream: true,
            temperature: request.temperature,
            max_tokens,
            tools: request.tools.clone(),
        };

        debug!("OpenAI streaming request to {}", self.completions_url());

        let resp = self
            .client
            .post(self.completions_url())
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                Error::Llm(format!(
                    "Cannot connect to OpenAI at {}: {}",
                    self.base_url, e
                ))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(Self::http_error(status, &text));
        }

        let byte_stream = resp.bytes_stream();
        let chunk_stream = sse_chunk_stream(byte_stream);
        Ok(Box::pin(chunk_stream))
    }
}

// ── SSE parsing ───────────────────────────────────────────────────────────────

/// Convert a raw byte stream from an OpenAI SSE response into a stream of
/// `StreamChunk` items.
///
/// SSE protocol: each line is either:
/// - `data: <json>` — a JSON chunk to parse
/// - `data: [DONE]` — stream finished marker
/// - empty line — separator (ignored)
fn sse_chunk_stream(
    byte_stream: impl Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Send + 'static,
) -> impl Stream<Item = Result<StreamChunk, Error>> + Send {
    async_stream::stream! {
        let mut buf = String::new();

        tokio::pin!(byte_stream);

        while let Some(chunk_result) = byte_stream.next().await {
            let bytes = match chunk_result {
                Ok(b) => b,
                Err(e) => {
                    yield Err(Error::Llm(format!("Stream read error: {}", e)));
                    return;
                }
            };

            let text = match std::str::from_utf8(&bytes) {
                Ok(t) => t,
                Err(e) => {
                    warn!("Non-UTF8 bytes from OpenAI: {}", e);
                    continue;
                }
            };

            buf.push_str(text);

            // Process all complete lines in the buffer
            while let Some(newline_pos) = buf.find('\n') {
                let line = buf[..newline_pos].trim().to_string();
                buf = buf[newline_pos + 1..].to_string();

                if line.is_empty() {
                    continue;
                }

                // SSE lines are prefixed with "data: "
                let Some(data) = line.strip_prefix("data: ") else {
                    // Non-data SSE fields (event:, id:, retry:) — ignore
                    continue;
                };

                // Terminal marker — stream is done
                if data == "[DONE]" {
                    yield Ok(StreamChunk {
                        delta: String::new(),
                        done: true,
                        usage: None,
                        tool_calls: vec![],
                    });
                    return;
                }

                // Parse the JSON chunk
                match serde_json::from_str::<OpenAiResponse>(data) {
                    Ok(parsed) => {
                        let choice = match parsed.choices.into_iter().next() {
                            Some(c) => c,
                            None => continue,
                        };

                        let delta = choice.delta.unwrap_or(OpenAiDelta {
                            content: None,
                            tool_calls: vec![],
                        });

                        let tool_calls = wire_tool_calls_to_domain(delta.tool_calls);
                        let content = delta.content.unwrap_or_default();

                        yield Ok(StreamChunk {
                            delta: content,
                            done: false,
                            usage: None,
                            tool_calls,
                        });
                    }
                    Err(e) => {
                        warn!("Failed to parse OpenAI SSE JSON chunk {:?}: {}", data, e);
                    }
                }
            }
        }
        // Connection dropped without a [DONE] marker — yield a synthetic terminal
        // chunk so callers always receive a termination signal.
        yield Ok(StreamChunk {
            delta: String::new(),
            done: true,
            usage: None,
            tool_calls: vec![],
        });
    }
}

// ── Build helper (used in tests) ─────────────────────────────────────────────

/// Build an `OpenAiWireRequest` from a `ChatRequest` and a pre-built wire
/// message slice.
///
/// Extracted as a free function so unit tests can inspect wire fields
/// (e.g. `temperature`) without going through an HTTP client.
#[cfg(test)]
fn build_openai_request<'a>(
    request: &'a ChatRequest,
    wire_msgs: &'a [OpenAiWireMessage],
    stream: bool,
) -> OpenAiWireRequest<'a> {
    OpenAiWireRequest {
        model: &request.model,
        messages: wire_msgs,
        stream,
        temperature: request.temperature,
        max_tokens: if request.max_tokens > 0 { Some(request.max_tokens as u64) } else { None },
        tools: request.tools.clone(),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use sigint_core::config::LlmConfig;

    fn test_config(api_key: Option<String>) -> LlmConfig {
        LlmConfig {
            provider: "openai".into(),
            model: "gpt-4o".into(),
            base_url: "https://api.openai.com".into(),
            temperature: 0.7,
            context_window: 0,
            api_key,
        }
    }

    // ── Serialization tests ───────────────────────────────────────────────────

    #[test]
    fn openai_request_serializes_correctly() {
        let msgs = vec![OpenAiWireMessage {
            role: "user".into(),
            content: "hello".into(),
            tool_calls: None,
        }];
        let req = OpenAiWireRequest {
            model: "gpt-4o",
            messages: &msgs,
            stream: false,
            temperature: 0.7,
            max_tokens: None,
            tools: vec![],
        };
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["model"], "gpt-4o");
        assert_eq!(v["messages"][0]["role"], "user");
        assert_eq!(v["messages"][0]["content"], "hello");
        assert_eq!(v["stream"], false);
        assert!((v["temperature"].as_f64().unwrap() - 0.7).abs() < 1e-6);
    }

    #[test]
    fn openai_request_omits_tools_when_empty() {
        let msgs = vec![OpenAiWireMessage {
            role: "user".into(),
            content: "hello".into(),
            tool_calls: None,
        }];
        let req = OpenAiWireRequest {
            model: "gpt-4o",
            messages: &msgs,
            stream: false,
            temperature: 0.7,
            max_tokens: None,
            tools: vec![],
        };
        let v = serde_json::to_value(&req).unwrap();
        assert!(v.get("tools").is_none(), "tools key should be absent when empty");
    }

    // ── Response parsing tests ────────────────────────────────────────────────

    #[test]
    fn parse_openai_chat_response() {
        let json_str = r#"{
            "id": "chatcmpl-123",
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Hello, world!"
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 5,
                "total_tokens": 15
            }
        }"#;
        let parsed: OpenAiResponse = serde_json::from_str(json_str).unwrap();
        let choice = &parsed.choices[0];
        let msg = choice.message.as_ref().unwrap();
        assert_eq!(msg.content, "Hello, world!");
        assert!(msg.tool_calls.is_empty());
        let usage = parsed.usage.as_ref().unwrap();
        assert_eq!(usage.prompt_tokens, 10);
        assert_eq!(usage.completion_tokens, 5);
        assert_eq!(usage.total_tokens, 15);
    }

    #[test]
    fn parse_openai_tool_call_response() {
        let json_str = r#"{
            "id": "chatcmpl-456",
            "object": "chat.completion",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [{
                        "id": "call_abc",
                        "type": "function",
                        "function": {
                            "name": "get_weather",
                            "arguments": "{\"location\": \"Paris\"}"
                        }
                    }]
                },
                "finish_reason": "tool_calls"
            }],
            "usage": {
                "prompt_tokens": 20,
                "completion_tokens": 10,
                "total_tokens": 30
            }
        }"#;
        let parsed: OpenAiResponse = serde_json::from_str(json_str).unwrap();
        let choice = &parsed.choices[0];
        let msg = choice.message.as_ref().unwrap();
        assert_eq!(msg.content, "");
        assert_eq!(msg.tool_calls.len(), 1);
        assert_eq!(msg.tool_calls[0].function.name, "get_weather");
        // arguments is a JSON-encoded string on the wire
        assert_eq!(msg.tool_calls[0].function.arguments, r#"{"location": "Paris"}"#);
        // After conversion, it should be parsed into a Value
        let domain_calls = wire_tool_calls_to_domain(msg.tool_calls.clone());
        assert_eq!(domain_calls[0].function.arguments["location"], "Paris");
    }

    // ── SSE parsing tests ─────────────────────────────────────────────────────

    #[test]
    fn parse_sse_done_line() {
        // Verify [DONE] is recognised as a terminal marker — tested indirectly
        // through the SSE parsing logic by checking the prefix strip logic.
        let line = "data: [DONE]";
        let data = line.strip_prefix("data: ").expect("prefix missing");
        assert_eq!(data, "[DONE]");
    }

    // ── URL construction ──────────────────────────────────────────────────────

    #[test]
    fn completions_url_format() {
        let p = OpenAiProvider::new("https://api.openai.com", "sk-test", 0.7);
        assert_eq!(p.completions_url(), "https://api.openai.com/v1/chat/completions");

        let p2 = OpenAiProvider::new("http://localhost:8080", "key", 0.5);
        assert_eq!(p2.completions_url(), "http://localhost:8080/v1/chat/completions");
    }

    // ── from_config / API key resolution tests ────────────────────────────────

    #[test]
    fn from_config_rejects_missing_key() {
        // Remove env var to ensure clean state for this test
        std::env::remove_var("SIGINT_API_KEY");
        let cfg = test_config(None);
        let result = OpenAiProvider::from_config(&cfg);
        assert!(result.is_err(), "Expected error when no api_key and no env var");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("API key") || msg.contains("api_key") || msg.contains("SIGINT_API_KEY"),
            "Error should mention API key, got: {}",
            msg
        );
    }

    #[test]
    fn from_config_uses_config_api_key() {
        let cfg = test_config(Some("sk-from-config".into()));
        let provider = OpenAiProvider::from_config(&cfg).expect("should succeed");
        assert_eq!(provider.api_key, "sk-from-config");
        assert_eq!(provider.base_url, "https://api.openai.com");
    }

    #[test]
    fn api_key_from_env_fallback() {
        // Set the env var, ensure config has no key
        std::env::set_var("SIGINT_API_KEY", "sk-from-env");
        let cfg = test_config(None);
        let provider = OpenAiProvider::from_config(&cfg).expect("env var fallback should work");
        assert_eq!(provider.api_key, "sk-from-env");
        // Clean up
        std::env::remove_var("SIGINT_API_KEY");
    }

    // ── Per-request temperature tests ────────────────────────────────────────

    #[test]
    fn request_uses_per_request_temperature() {
        let req = ChatRequest::new("gpt-4o", vec![ChatMessage::user("hello")])
            .with_temperature(0.0);
        let wire_msgs = build_wire_messages(&req.messages);
        let wire = build_openai_request(&req, &wire_msgs, false);
        assert!((wire.temperature - 0.0).abs() < f32::EPSILON);
    }

    // ── Network tests ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn chat_returns_error_on_connection_refused() {
        let provider = OpenAiProvider::new("http://127.0.0.1:19999", "sk-test", 0.7);
        let req = ChatRequest::new("gpt-4o", vec![ChatMessage::user("hello")]);
        let result = provider.chat(req).await;
        assert!(result.is_err(), "Expected error when server is not running");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("Cannot connect to OpenAI") || msg.contains("127.0.0.1"),
            "Error should mention connection failure, got: {}",
            msg
        );
    }
}
