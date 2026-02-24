//! Shared types for LLM request/response across all providers.
//!
//! @decision DEC-LLM-001
//! @title Provider-agnostic ChatMessage/ChatRequest/ChatResponse types
//! @status accepted
//! @rationale Keeping LLM wire types separate from domain types (sigint-core)
//! allows providers to serialize/deserialize independently without leaking
//! provider-specific fields into the shared domain layer.

use serde::{Deserialize, Serialize};

/// A single message in a chat conversation (provider-agnostic).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

impl ChatMessage {
    pub fn user(content: impl Into<String>) -> Self {
        Self { role: "user".into(), content: content.into() }
    }
    pub fn assistant(content: impl Into<String>) -> Self {
        Self { role: "assistant".into(), content: content.into() }
    }
    pub fn system(content: impl Into<String>) -> Self {
        Self { role: "system".into(), content: content.into() }
    }
}

/// Request sent to an LLM provider.
#[derive(Debug, Clone)]
pub struct ChatRequest {
    pub messages: Vec<ChatMessage>,
    pub model: String,
    pub temperature: f32,
    /// Max tokens to generate (0 = provider default).
    pub max_tokens: usize,
}

impl ChatRequest {
    pub fn new(model: impl Into<String>, messages: Vec<ChatMessage>) -> Self {
        Self {
            messages,
            model: model.into(),
            temperature: 0.7,
            max_tokens: 0,
        }
    }

    pub fn with_temperature(mut self, t: f32) -> Self {
        self.temperature = t;
        self
    }
}

/// Complete (non-streaming) response from an LLM provider.
#[derive(Debug, Clone)]
pub struct ChatResponse {
    pub content: String,
    pub usage: Option<TokenUsage>,
    pub model: String,
}

/// Token usage statistics returned by the provider.
#[derive(Debug, Clone, Default)]
pub struct TokenUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

/// A single streaming chunk delivered during `chat_stream`.
#[derive(Debug, Clone)]
pub struct StreamChunk {
    /// Partial content token(s) in this chunk.
    pub delta: String,
    /// True when the stream is finished.
    pub done: bool,
    /// Usage stats — only populated on the final chunk, if available.
    pub usage: Option<TokenUsage>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chat_message_constructors() {
        let u = ChatMessage::user("hi");
        assert_eq!(u.role, "user");
        assert_eq!(u.content, "hi");

        let a = ChatMessage::assistant("hello");
        assert_eq!(a.role, "assistant");

        let s = ChatMessage::system("be helpful");
        assert_eq!(s.role, "system");
    }

    #[test]
    fn chat_request_defaults() {
        let req = ChatRequest::new("llama3.2", vec![ChatMessage::user("test")]);
        assert_eq!(req.model, "llama3.2");
        assert!((req.temperature - 0.7).abs() < f32::EPSILON);
        assert_eq!(req.max_tokens, 0);
    }

    #[test]
    fn chat_request_with_temperature() {
        let req = ChatRequest::new("llama3.2", vec![])
            .with_temperature(0.1);
        assert!((req.temperature - 0.1).abs() < f32::EPSILON);
    }
}
