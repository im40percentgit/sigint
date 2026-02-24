//! sigint-llm — LLM provider trait and Ollama implementation.
//!
//! @decision DEC-LLM-001
//! @title Ollama-first LLM provider with trait abstraction
//! @status accepted
//! @rationale The LlmProvider trait allows swapping providers without
//! changing call sites. Ollama is default (local privacy); OpenAI/Anthropic
//! can be added as optional features in Phase 2.

pub mod provider;
pub mod ollama;
pub mod types;

pub use provider::LlmProvider;
pub use ollama::OllamaProvider;
pub use types::{
    ChatMessage, ChatRequest, ChatResponse, StreamChunk, TokenUsage,
    ToolDefinition, FunctionDef, ToolCall, FunctionCall,
};
