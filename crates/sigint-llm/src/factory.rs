//! Provider factory — creates the correct `LlmProvider` from config.
//!
//! @decision DEC-LLM-006
//! @title Centralised provider factory for all LLM backends
//! @status accepted
//! @rationale A single `create_provider` function is the only place that maps
//! provider name strings to concrete types. This keeps `match` logic out of
//! call sites and ensures new providers only need to be registered here.
//! Unknown provider names return a descriptive `Error::Config` that lists the
//! supported options, so misconfigured deployments get actionable errors.

use crate::ollama::OllamaProvider;
use crate::openai::OpenAiProvider;
use crate::provider::LlmProvider;
use sigint_core::config::LlmConfig;
use sigint_core::Error;

/// Create the appropriate `LlmProvider` for the given config.
///
/// # Errors
/// - `Error::Config` if the provider name is unknown.
/// - `Error::Config` if `provider = "openai"` and no API key is available.
pub fn create_provider(config: &LlmConfig) -> Result<Box<dyn LlmProvider>, Error> {
    match config.provider.as_str() {
        "ollama" => Ok(Box::new(OllamaProvider::from_config(config))),
        "openai" => Ok(Box::new(OpenAiProvider::from_config(config)?)),
        "llama-cpp" | "llama.cpp" | "llamacpp" => {
            Ok(Box::new(OpenAiProvider::from_config_local(config)?))
        }
        #[cfg(feature = "embedded-llm")]
        "embedded" => Ok(Box::new(crate::embedded::EmbeddedProvider::load(config)?)),
        #[cfg(not(feature = "embedded-llm"))]
        "embedded" => Err(Error::Config(
            "Embedded LLM requires the 'embedded-llm' feature. Rebuild with: cargo build --features embedded-llm".into()
        )),
        other => Err(Error::Config(format!(
            "Unknown LLM provider '{}'. Supported: ollama, openai, llama-cpp, embedded",
            other
        ))),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_config(provider: &str, api_key: Option<String>) -> LlmConfig {
        LlmConfig {
            provider: provider.into(),
            model: "test-model".into(),
            base_url: "http://localhost:11434".into(),
            temperature: 0.7,
            context_window: 0,
            api_key,
            models_dir: None,
            gpu_layers: None,
            threads: None,
            flash_attention: None,
        }
    }

    #[test]
    fn factory_creates_ollama_by_default() {
        let cfg = make_config("ollama", None);
        let provider = create_provider(&cfg).expect("ollama provider should succeed");
        assert_eq!(provider.name(), "ollama");
    }

    #[test]
    fn factory_creates_openai_with_key() {
        let cfg = make_config("openai", Some("sk-testkey".into()));
        let provider = create_provider(&cfg).expect("openai provider should succeed with key");
        assert_eq!(provider.name(), "openai");
    }

    #[test]
    fn factory_rejects_openai_without_key() {
        // Ensure env var is not set so we get a clean error
        std::env::remove_var("SIGINT_API_KEY");
        let cfg = make_config("openai", None);
        let result = create_provider(&cfg);
        assert!(result.is_err(), "Expected error when openai has no key");
        let msg = match result {
            Err(e) => e.to_string(),
            Ok(_) => panic!("Expected Err, got Ok"),
        };
        assert!(
            msg.contains("API key") || msg.contains("api_key") || msg.contains("SIGINT_API_KEY"),
            "Error should mention API key, got: {}",
            msg
        );
    }

    #[test]
    fn factory_rejects_unknown_provider() {
        let cfg = make_config("anthropic", None);
        let result = create_provider(&cfg);
        assert!(result.is_err(), "Expected error for unknown provider");
        let msg = match result {
            Err(e) => e.to_string(),
            Ok(_) => panic!("Expected Err, got Ok"),
        };
        assert!(
            msg.contains("anthropic") || msg.contains("Unknown"),
            "Error should mention the unknown provider name, got: {}",
            msg
        );
        assert!(
            msg.contains("ollama") || msg.contains("openai"),
            "Error should list supported providers, got: {}",
            msg
        );
    }

    #[test]
    fn factory_creates_llama_cpp_without_key() {
        let mut cfg = make_config("llama-cpp", None);
        // Override base_url to llama.cpp default port
        cfg.base_url = "http://localhost:8080".into();
        let provider =
            create_provider(&cfg).expect("llama-cpp provider should succeed without key");
        // Uses OpenAI provider under the hood (OpenAI-compatible API)
        assert_eq!(provider.name(), "openai");
    }

    #[test]
    fn factory_creates_llamacpp_alias() {
        let mut cfg = make_config("llamacpp", None);
        cfg.base_url = "http://localhost:8080".into();
        let provider = create_provider(&cfg).expect("llamacpp alias should work");
        assert_eq!(provider.name(), "openai");
    }

    #[test]
    fn factory_creates_llama_dot_cpp_alias() {
        let mut cfg = make_config("llama.cpp", None);
        cfg.base_url = "http://localhost:8080".into();
        let provider = create_provider(&cfg).expect("llama.cpp alias should work");
        assert_eq!(provider.name(), "openai");
    }

    #[test]
    fn factory_rejects_embedded_without_feature() {
        #[cfg(not(feature = "embedded-llm"))]
        {
            let cfg = make_config("embedded", None);
            let result = create_provider(&cfg);
            assert!(result.is_err());
            let msg = result.err().unwrap().to_string();
            assert!(
                msg.contains("embedded-llm"),
                "error should mention feature flag: {msg}"
            );
        }
    }

    #[test]
    fn factory_error_mentions_embedded_in_supported_list() {
        // Unknown provider error should now list "embedded" as a supported option.
        let cfg = make_config("bogus-provider", None);
        let result = create_provider(&cfg);
        assert!(result.is_err());
        let msg = result.err().unwrap().to_string();
        assert!(
            msg.contains("embedded"),
            "supported list should mention embedded: {msg}"
        );
    }
}
