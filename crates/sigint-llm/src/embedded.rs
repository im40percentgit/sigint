//! Embedded LLM provider — runs a GGUF model in-process via llama-cpp-2.
//!
//! This module is gated behind the `embedded-llm` Cargo feature flag because
//! llama-cpp-2 requires a C/C++ toolchain and takes several minutes to
//! compile. The default build stays fast and dependency-free; users who want
//! on-device inference without an Ollama daemon rebuild with:
//!
//!   cargo build --features embedded-llm
//!
//! @decision DEC-P19-EMBEDDED-001
//! @title EmbeddedProvider gated behind embedded-llm Cargo feature flag
//! @status accepted
//! @rationale llama-cpp-2 compilation requires a C toolchain and takes several
//! minutes; feature flag keeps default builds fast and dependency-free.
//! Factory returns a descriptive error (mentioning the feature flag) when
//! provider=embedded is requested without the flag.

#[cfg(feature = "embedded-llm")]
use async_trait::async_trait;
#[cfg(feature = "embedded-llm")]
use futures_util::Stream;
#[cfg(feature = "embedded-llm")]
use std::pin::Pin;

#[cfg(feature = "embedded-llm")]
use crate::provider::ChunkStream;
#[cfg(feature = "embedded-llm")]
use crate::types::{ChatRequest, ChatResponse};
#[cfg(feature = "embedded-llm")]
use sigint_core::config::LlmConfig;
#[cfg(feature = "embedded-llm")]
use sigint_core::Error;

/// In-process LLM provider backed by a GGUF model file.
///
/// Loaded via `EmbeddedProvider::load()` which reads the model from
/// `Config::resolved_models_dir()` / `LlmConfig::model`.
///
/// The inference implementation is a stub pending full llama-cpp-2 wiring
/// in a follow-on phase. All `LlmProvider` methods return
/// `Error::Llm("embedded inference not yet implemented")` until that work
/// lands.
#[cfg(feature = "embedded-llm")]
pub struct EmbeddedProvider {
    /// Model display name (from GGUF metadata or config).
    model_name: String,
}

#[cfg(feature = "embedded-llm")]
impl EmbeddedProvider {
    /// Load an `EmbeddedProvider` from the model path in `config`.
    ///
    /// Resolves the model file as:
    ///   `Config::resolved_models_dir() / config.model`
    ///
    /// # Errors
    /// Returns `Error::Config` if `models_dir` cannot be resolved or the
    /// model file does not exist.
    pub fn load(config: &LlmConfig) -> Result<Self, Error> {
        // Resolve models directory with tilde expansion.
        let models_dir_raw = config.models_dir.as_deref()
            .unwrap_or("~/.local/share/sigint/models");
        let models_dir = if let Some(stripped) = models_dir_raw.strip_prefix("~/") {
            if let Ok(home) = std::env::var("HOME") {
                std::path::PathBuf::from(home).join(stripped)
            } else {
                std::path::PathBuf::from(models_dir_raw)
            }
        } else {
            std::path::PathBuf::from(models_dir_raw)
        };

        let model_path = models_dir.join(&config.model);

        if !model_path.exists() {
            return Err(Error::Config(format!(
                "Embedded LLM model not found: {:?}. \
                 Place a GGUF file there or set llm.models_dir in config.",
                model_path
            )));
        }

        Ok(EmbeddedProvider {
            model_name: config.model.clone(),
        })
    }
}

#[cfg(feature = "embedded-llm")]
#[async_trait]
impl crate::provider::LlmProvider for EmbeddedProvider {
    fn name(&self) -> &str {
        "embedded"
    }

    async fn chat(&self, _request: ChatRequest) -> Result<ChatResponse, Error> {
        Err(Error::Llm(
            "embedded inference not yet implemented. \
             Full llama-cpp-2 wiring is planned for Phase 19B."
                .into(),
        ))
    }

    async fn chat_stream(&self, _request: ChatRequest) -> Result<ChunkStream, Error> {
        Err(Error::Llm(
            "embedded inference not yet implemented. \
             Full llama-cpp-2 wiring is planned for Phase 19B."
                .into(),
        ))
    }
}
