//! sigint-llm — LLM provider trait, Ollama and OpenAI implementations, and
//! a provider factory for config-driven dispatch.
//!
//! @decision DEC-LLM-001
//! @title Ollama-first LLM provider with trait abstraction
//! @status accepted
//! @rationale The LlmProvider trait allows swapping providers without
//! changing call sites. Ollama is default (local privacy); OpenAI-compatible
//! cloud providers are supported via the openai module added in Phase 5B.

pub mod factory;
pub mod mock;
pub mod ollama;
pub mod openai;
pub mod provider;
pub mod types;

pub use factory::create_provider;
pub use mock::{MockProvider, MockResponse};
pub use ollama::OllamaProvider;
pub use openai::OpenAiProvider;
pub use provider::LlmProvider;
pub use types::{
    ChatMessage, ChatRequest, ChatResponse, FunctionCall, FunctionDef, StreamChunk, TokenUsage,
    ToolCall, ToolDefinition,
};
