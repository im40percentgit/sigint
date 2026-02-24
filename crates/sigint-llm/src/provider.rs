//! LlmProvider trait — implemented by Ollama, OpenAI, Anthropic, etc.

use async_trait::async_trait;
use futures_util::Stream;
use std::pin::Pin;

use crate::types::{ChatRequest, ChatResponse, StreamChunk};
use sigint_core::Error;

/// Boxed stream of StreamChunks returned by `chat_stream`.
pub type ChunkStream = Pin<Box<dyn Stream<Item = Result<StreamChunk, Error>> + Send>>;

/// Trait implemented by every LLM provider backend.
#[async_trait]
pub trait LlmProvider: Send + Sync {
    /// Provider name for logging/display (e.g. "ollama", "openai").
    fn name(&self) -> &str;

    /// Send a blocking (non-streaming) chat request and return the full response.
    async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, Error>;

    /// Send a streaming chat request; returns a stream of token chunks.
    async fn chat_stream(&self, request: ChatRequest) -> Result<ChunkStream, Error>;
}
