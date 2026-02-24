//! Ollama LLM provider — POST /api/chat with newline-delimited JSON streaming.
//!
//! @decision DEC-LLM-001
//! @title Ollama /api/chat with streaming JSON lines (not SSE)
//! @status accepted
//! @rationale Ollama's native API returns newline-delimited JSON, not SSE.
//! eventsource-stream is reserved for OpenAI-compatible endpoints added in
//! Phase 2. This implementation directly parses each JSON line as it arrives,
//! yielding StreamChunk items. Connection errors produce a clear Error::Llm
//! message rather than panicking, satisfying the `sigint chat` error UX spec.

use async_trait::async_trait;
use futures_util::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::provider::{ChunkStream, LlmProvider};
use crate::types::{ChatMessage, ChatRequest, ChatResponse, StreamChunk, TokenUsage};
use sigint_core::Error;

// ── Wire types ────────────────────────────────────────────────────────────────

/// Request body sent to POST /api/chat.
#[derive(Debug, Serialize)]
struct OllamaRequest<'a> {
    model: &'a str,
    messages: &'a [OllamaMessage],
    stream: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    options: Option<OllamaOptions>,
}

#[derive(Debug, Serialize)]
struct OllamaMessage {
    role: String,
    content: String,
}

#[derive(Debug, Serialize)]
struct OllamaOptions {
    temperature: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    num_predict: Option<i32>,
}

/// One line of the streaming JSON response from Ollama.
#[derive(Debug, Deserialize)]
struct OllamaStreamLine {
    message: Option<OllamaMessageContent>,
    done: bool,
    #[serde(default)]
    prompt_eval_count: u32,
    #[serde(default)]
    eval_count: u32,
}

#[derive(Debug, Deserialize)]
struct OllamaMessageContent {
    content: String,
}

// ── Provider ──────────────────────────────────────────────────────────────────

/// Ollama LLM provider. Talks to a local Ollama instance at `base_url`.
#[derive(Debug, Clone)]
pub struct OllamaProvider {
    base_url: String,
    /// Default model name — used when no per-request model is specified.
    /// Phase 2 will expose this for model listing and validation.
    #[allow(dead_code)]
    model: String,
    temperature: f32,
    client: reqwest::Client,
}

impl OllamaProvider {
    /// Create a new provider pointed at `base_url` (e.g. "http://localhost:11434").
    pub fn new(base_url: impl Into<String>, model: impl Into<String>, temperature: f32) -> Self {
        Self {
            base_url: base_url.into(),
            model: model.into(),
            temperature,
            client: reqwest::Client::new(),
        }
    }

    /// Construct from sigint-core config.
    pub fn from_config(cfg: &sigint_core::config::LlmConfig) -> Self {
        Self::new(&cfg.base_url, &cfg.model, cfg.temperature)
    }

    fn chat_url(&self) -> String {
        format!("{}/api/chat", self.base_url)
    }

    fn build_messages(messages: &[ChatMessage]) -> Vec<OllamaMessage> {
        messages
            .iter()
            .map(|m| OllamaMessage {
                role: m.role.clone(),
                content: m.content.clone(),
            })
            .collect()
    }

    fn build_options(&self, max_tokens: usize) -> Option<OllamaOptions> {
        Some(OllamaOptions {
            temperature: self.temperature,
            num_predict: if max_tokens > 0 { Some(max_tokens as i32) } else { None },
        })
    }
}

#[async_trait]
impl LlmProvider for OllamaProvider {
    fn name(&self) -> &str {
        "ollama"
    }

    async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, Error> {
        let ollama_msgs = Self::build_messages(&request.messages);
        let body = OllamaRequest {
            model: &request.model,
            messages: &ollama_msgs,
            stream: false,
            options: self.build_options(request.max_tokens),
        };

        debug!("Ollama non-streaming request to {}", self.chat_url());

        let resp = self
            .client
            .post(&self.chat_url())
            .json(&body)
            .send()
            .await
            .map_err(|e| Error::Llm(format!("Cannot connect to Ollama at {}: {}", self.base_url, e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::Llm(format!("Ollama returned {}: {}", status, text)));
        }

        let line: OllamaStreamLine = resp.json().await.map_err(|e| {
            Error::Llm(format!("Failed to parse Ollama response: {}", e))
        })?;

        let content = line
            .message
            .map(|m| m.content)
            .unwrap_or_default();

        let usage = Some(TokenUsage {
            prompt_tokens: line.prompt_eval_count,
            completion_tokens: line.eval_count,
            total_tokens: line.prompt_eval_count + line.eval_count,
        });

        Ok(ChatResponse {
            content,
            usage,
            model: request.model,
        })
    }

    async fn chat_stream(&self, request: ChatRequest) -> Result<ChunkStream, Error> {
        let ollama_msgs = Self::build_messages(&request.messages);
        let body = OllamaRequest {
            model: &request.model,
            messages: &ollama_msgs,
            stream: true,
            options: self.build_options(request.max_tokens),
        };

        debug!("Ollama streaming request to {}", self.chat_url());

        let resp = self
            .client
            .post(&self.chat_url())
            .json(&body)
            .send()
            .await
            .map_err(|e| {
                Error::Llm(format!(
                    "Cannot connect to Ollama at {}. Is Ollama running? Error: {}",
                    self.base_url, e
                ))
            })?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(Error::Llm(format!("Ollama returned {}: {}", status, text)));
        }

        // Convert the byte stream into a stream of StreamChunks.
        // Ollama sends one JSON object per line; we accumulate bytes into lines
        // and parse each complete line.
        let byte_stream = resp.bytes_stream();

        let chunk_stream = newline_json_stream(byte_stream);

        Ok(Box::pin(chunk_stream))
    }
}

/// Convert a byte stream from Ollama into a stream of `StreamChunk`.
///
/// Ollama streams newline-delimited JSON: each line is a complete JSON object.
/// We buffer bytes until we see `\n`, then parse the line.
fn newline_json_stream(
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
                    warn!("Non-UTF8 bytes from Ollama: {}", e);
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

                match serde_json::from_str::<OllamaStreamLine>(&line) {
                    Ok(parsed) => {
                        let delta = parsed
                            .message
                            .map(|m| m.content)
                            .unwrap_or_default();

                        let usage = if parsed.done && parsed.eval_count > 0 {
                            Some(TokenUsage {
                                prompt_tokens: parsed.prompt_eval_count,
                                completion_tokens: parsed.eval_count,
                                total_tokens: parsed.prompt_eval_count + parsed.eval_count,
                            })
                        } else {
                            None
                        };

                        yield Ok(StreamChunk {
                            delta,
                            done: parsed.done,
                            usage,
                        });

                        if parsed.done {
                            return;
                        }
                    }
                    Err(e) => {
                        warn!("Failed to parse Ollama JSON line {:?}: {}", line, e);
                    }
                }
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use sigint_core::config::LlmConfig;

    #[test]
    fn from_config_sets_fields() {
        let cfg = LlmConfig {
            provider: "ollama".into(),
            model: "llama3.2".into(),
            base_url: "http://localhost:11434".into(),
            temperature: 0.5,
            context_window: 0,
        };
        let provider = OllamaProvider::from_config(&cfg);
        assert_eq!(provider.model, "llama3.2");
        assert_eq!(provider.base_url, "http://localhost:11434");
        assert!((provider.temperature - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn chat_url_format() {
        let p = OllamaProvider::new("http://localhost:11434", "llama3.2", 0.7);
        assert_eq!(p.chat_url(), "http://localhost:11434/api/chat");
    }

    #[test]
    fn build_messages_maps_roles() {
        let msgs = vec![
            ChatMessage::system("you are a pentester"),
            ChatMessage::user("scan example.com"),
        ];
        let built = OllamaProvider::build_messages(&msgs);
        assert_eq!(built.len(), 2);
        assert_eq!(built[0].role, "system");
        assert_eq!(built[1].role, "user");
        assert_eq!(built[1].content, "scan example.com");
    }

    #[test]
    fn provider_name() {
        let p = OllamaProvider::new("http://localhost:11434", "llama3.2", 0.7);
        assert_eq!(p.name(), "ollama");
    }

    /// Verify that chat_stream returns a clear error when Ollama is not running.
    /// This test does NOT require Ollama to be installed.
    #[tokio::test]
    async fn chat_stream_fails_gracefully_when_ollama_not_running() {
        // Use a port that is guaranteed to refuse connections
        let provider = OllamaProvider::new("http://127.0.0.1:19999", "llama3.2", 0.7);
        let req = ChatRequest::new("llama3.2", vec![ChatMessage::user("hello")]);

        let result = provider.chat_stream(req).await;
        assert!(result.is_err(), "Expected error when Ollama is not running");

        // Extract error without unwrap_err (Pin<Box<dyn Stream>> is not Debug)
        let msg = match result {
            Err(e) => e.to_string(),
            Ok(_) => panic!("Expected Err, got Ok"),
        };
        assert!(
            msg.contains("Cannot connect to Ollama") || msg.contains("Ollama"),
            "Error message should mention Ollama, got: {}",
            msg
        );
    }

    #[tokio::test]
    async fn chat_fails_gracefully_when_ollama_not_running() {
        let provider = OllamaProvider::new("http://127.0.0.1:19999", "llama3.2", 0.7);
        let req = ChatRequest::new("llama3.2", vec![ChatMessage::user("hello")]);

        let result = provider.chat(req).await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("Cannot connect to Ollama") || msg.contains("Ollama"));
    }
}
