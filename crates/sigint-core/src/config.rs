//! Configuration loading for SIGINT.
//!
//! Config is loaded from `~/.config/sigint/config.toml` with sensible
//! defaults when the file is absent or fields are missing.
//!
//! @decision DEC-LLM-001: Ollama-first provider. Local privacy by default;
//! cloud providers added in Phase 2 as optional fallback.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Top-level configuration for SIGINT.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    /// LLM provider settings.
    #[serde(default)]
    pub llm: LlmConfig,

    /// Persistent store settings.
    #[serde(default)]
    pub store: StoreConfig,

    /// Logging settings.
    #[serde(default)]
    pub log: LogConfig,

    /// Agent behavior settings (approval gate, auto-approve thresholds).
    #[serde(default)]
    pub agent: AgentConfig,
}

/// LLM provider configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    /// Provider name: "ollama" (default), "openai", "anthropic".
    #[serde(default = "default_provider")]
    pub provider: String,

    /// Model name passed to the provider.
    #[serde(default = "default_model")]
    pub model: String,

    /// Base URL for the provider API.
    #[serde(default = "default_base_url")]
    pub base_url: String,

    /// Sampling temperature (0.0–1.0).
    #[serde(default = "default_temperature")]
    pub temperature: f32,

    /// Context window size in tokens (0 = provider default).
    #[serde(default)]
    pub context_window: usize,

    /// API key for cloud providers (OpenAI, Anthropic, etc.).
    /// Can also be supplied via the `SIGINT_API_KEY` environment variable.
    #[serde(default)]
    pub api_key: Option<String>,
}

/// SQLite store configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreConfig {
    /// Path to the SQLite database file.
    /// Supports `~` expansion.
    #[serde(default = "default_db_path")]
    pub db_path: String,
}

/// Logging configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    /// `tracing` filter string, e.g. "sigint=debug,warn".
    #[serde(default = "default_log_level")]
    pub level: String,
}

/// Agent behavior configuration — controls the approval gate.
///
/// `auto_approve` determines which risk levels are executed without prompting:
/// - `"none"` — every tool call requires explicit approval
/// - `"low"` — low-risk calls are auto-approved (default)
/// - `"medium"` — low and medium risk calls are auto-approved
/// - `"all"` — all tool calls execute without approval (use with caution)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Maximum risk level that is auto-approved without operator interaction.
    /// Accepted values: "none", "low", "medium", "all".
    #[serde(default = "default_auto_approve")]
    pub auto_approve: String,

    /// Seconds to wait for an operator response before the approval request
    /// is considered timed out (and the tool call is denied).
    #[serde(default = "default_approval_timeout")]
    pub approval_timeout: u64,
}

// ── Default implementations ──────────────────────────────────────────────────

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            provider: default_provider(),
            model: default_model(),
            base_url: default_base_url(),
            temperature: default_temperature(),
            context_window: 0,
            api_key: None,
        }
    }
}

impl Default for StoreConfig {
    fn default() -> Self {
        Self {
            db_path: default_db_path(),
        }
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
        }
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            auto_approve: default_auto_approve(),
            approval_timeout: default_approval_timeout(),
        }
    }
}

fn default_provider() -> String {
    "ollama".into()
}
fn default_model() -> String {
    "llama3.2".into()
}
fn default_base_url() -> String {
    "http://localhost:11434".into()
}
fn default_temperature() -> f32 {
    0.7
}
fn default_db_path() -> String {
    "~/.local/share/sigint/sigint.db".into()
}
fn default_log_level() -> String {
    "sigint=info,warn".into()
}
fn default_auto_approve() -> String {
    "low".into()
}
fn default_approval_timeout() -> u64 {
    300
}

// ── Loading ──────────────────────────────────────────────────────────────────

impl Config {
    /// Load config from `~/.config/sigint/config.toml`.
    ///
    /// Falls back to `Config::default()` if the file does not exist.
    /// Returns an error only if the file exists but cannot be parsed.
    pub fn load() -> crate::Result<Self> {
        let path = Self::default_path();
        if !path.exists() {
            tracing::debug!("No config file at {:?}, using defaults", path);
            return Ok(Self::default());
        }
        let contents = std::fs::read_to_string(&path)
            .map_err(|e| crate::Error::Config(format!("Cannot read {:?}: {}", path, e)))?;
        let config: Self = toml::from_str(&contents)
            .map_err(|e| crate::Error::Config(format!("Cannot parse {:?}: {}", path, e)))?;
        tracing::debug!("Loaded config from {:?}", path);
        Ok(config)
    }

    /// Load from an explicit path (used in tests).
    pub fn load_from(path: &std::path::Path) -> crate::Result<Self> {
        let contents = std::fs::read_to_string(path)
            .map_err(|e| crate::Error::Config(format!("Cannot read {:?}: {}", path, e)))?;
        let config: Self = toml::from_str(&contents)
            .map_err(|e| crate::Error::Config(format!("Cannot parse {:?}: {}", path, e)))?;
        Ok(config)
    }

    /// Expand `~` in `store.db_path` to the actual home directory.
    pub fn resolved_db_path(&self) -> PathBuf {
        let raw = &self.store.db_path;
        if let Some(stripped) = raw.strip_prefix("~/") {
            if let Some(home) = dirs_home() {
                return home.join(stripped);
            }
        }
        PathBuf::from(raw)
    }

    fn default_path() -> PathBuf {
        if let Some(home) = dirs_home() {
            home.join(".config").join("sigint").join("config.toml")
        } else {
            PathBuf::from(".config/sigint/config.toml")
        }
    }
}

/// Minimal home-dir lookup without pulling in the `dirs` crate.
fn dirs_home() -> Option<PathBuf> {
    std::env::var("HOME").ok().map(PathBuf::from)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_valid() {
        let cfg = Config::default();
        assert_eq!(cfg.llm.provider, "ollama");
        assert_eq!(cfg.llm.model, "llama3.2");
        assert_eq!(cfg.llm.base_url, "http://localhost:11434");
        assert!((cfg.llm.temperature - 0.7).abs() < f32::EPSILON);
        assert_eq!(cfg.llm.context_window, 0);
    }

    #[test]
    fn load_from_toml_string() {
        let toml_str = r#"
[llm]
provider = "openai"
model = "gpt-4o"
base_url = "https://api.openai.com"
temperature = 0.3

[store]
db_path = "/tmp/test.db"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse failed");
        assert_eq!(cfg.llm.provider, "openai");
        assert_eq!(cfg.llm.model, "gpt-4o");
        assert!((cfg.llm.temperature - 0.3).abs() < f32::EPSILON);
        assert_eq!(cfg.store.db_path, "/tmp/test.db");
    }

    #[test]
    fn partial_toml_uses_defaults() {
        let toml_str = r#"
[llm]
model = "mistral"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse failed");
        // Explicitly set
        assert_eq!(cfg.llm.model, "mistral");
        // Defaulted
        assert_eq!(cfg.llm.provider, "ollama");
        assert_eq!(cfg.llm.base_url, "http://localhost:11434");
    }

    #[test]
    fn load_from_file() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(f, "[llm]\nmodel = \"phi3\"").unwrap();
        let cfg = Config::load_from(f.path()).expect("load_from failed");
        assert_eq!(cfg.llm.model, "phi3");
    }

    #[test]
    fn config_with_api_key() {
        let toml_str = r#"
[llm]
provider = "openai"
api_key = "sk-test123"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse failed");
        assert_eq!(cfg.llm.api_key, Some("sk-test123".to_string()));
    }

    #[test]
    fn config_without_api_key_defaults_to_none() {
        let cfg = Config::default();
        assert_eq!(cfg.llm.api_key, None);

        // Also verify it's absent when not in TOML
        let toml_str = r#"
[llm]
model = "gpt-4o"
"#;
        let cfg2: Config = toml::from_str(toml_str).expect("parse failed");
        assert_eq!(cfg2.llm.api_key, None);
    }

    #[test]
    fn resolved_db_path_expands_tilde() {
        let cfg = Config::default();
        let path = cfg.resolved_db_path();
        // Should not contain literal ~
        assert!(!path.to_string_lossy().contains('~'));
    }

    #[test]
    fn agent_config_defaults() {
        let cfg = Config::default();
        assert_eq!(cfg.agent.auto_approve, "low");
        assert_eq!(cfg.agent.approval_timeout, 300);
    }

    #[test]
    fn agent_config_from_toml() {
        let toml_str = r#"
[agent]
auto_approve = "medium"
approval_timeout = 60
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse failed");
        assert_eq!(cfg.agent.auto_approve, "medium");
        assert_eq!(cfg.agent.approval_timeout, 60);
    }
}
