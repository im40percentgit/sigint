//! Configuration loading for SIGINT.
//!
//! Config is loaded from `~/.config/sigint/config.toml` with sensible
//! defaults when the file is absent or fields are missing.
//!
//! @decision DEC-LLM-001: Ollama-first provider. Local privacy by default;
//! cloud providers added in Phase 2 as optional fallback.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
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

    /// Tool execution settings (output caps, per-tool overrides).
    #[serde(default)]
    pub tools: ToolsConfig,

    /// Plugin system settings (tool packs, prompt packs).
    #[serde(default)]
    pub plugins: PluginsConfig,
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

    /// Directory where GGUF model files are stored (embedded LLM provider).
    /// Supports `~` expansion. Defaults to `~/.local/share/sigint/models`.
    #[serde(default)]
    pub models_dir: Option<String>,

    /// Number of model layers to offload to GPU (-1 = all, 0 = CPU-only).
    /// Only used by the embedded LLM provider.
    #[serde(default)]
    pub gpu_layers: Option<i32>,

    /// Number of CPU threads for inference (0 = auto-detect).
    /// Only used by the embedded LLM provider. Maps to llama.cpp `-t` flag.
    #[serde(default)]
    pub threads: Option<u32>,

    /// Enable flash attention for faster inference.
    /// Only used by the embedded LLM provider. Maps to llama.cpp `-fa` flag.
    #[serde(default)]
    pub flash_attention: Option<bool>,
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

    /// Enable episodic memory for agents (store and recall past findings).
    #[serde(default)]
    pub memory: bool,

    /// Enable recon-driven planning (attack surface feeds agent prompts).
    #[serde(default)]
    pub recon: bool,
}

/// Tool execution configuration — global defaults and per-tool overrides.
///
/// @decision DEC-P14-TOOLS-001: Per-tool output caps. Allows noisy tools
/// (e.g. nuclei) to have larger caps while keeping the global default tight.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolsConfig {
    /// Default maximum bytes of tool stdout/stderr to capture.
    #[serde(default = "default_output_cap")]
    pub default_output_cap: usize,

    /// Per-tool overrides keyed by tool name (e.g. "nmap", "nuclei").
    #[serde(default)]
    pub overrides: HashMap<String, ToolOverrides>,
}

/// Per-tool configuration overrides.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolOverrides {
    /// Override the output capture cap for this tool (bytes).
    #[serde(default)]
    pub output_cap: Option<usize>,

    /// Override the execution timeout for this tool (seconds).
    #[serde(default)]
    pub timeout: Option<u64>,
}

/// Plugin system settings.
///
/// Controls which prompt pack agents use and which tools are excluded from
/// the registry at startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginsConfig {
    /// Which agent prompt pack to use ("default" = built-in prompts).
    #[serde(default = "default_prompt_pack")]
    pub prompt_pack: String,

    /// Tool names to exclude from the registry.
    #[serde(default)]
    pub disabled_tools: Vec<String>,
}

fn default_prompt_pack() -> String {
    "default".to_string()
}

impl Default for PluginsConfig {
    fn default() -> Self {
        Self {
            prompt_pack: default_prompt_pack(),
            disabled_tools: Vec::new(),
        }
    }
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
            models_dir: None,
            gpu_layers: None,
            threads: None,
            flash_attention: None,
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
            memory: false,
            recon: false,
        }
    }
}

impl Default for ToolsConfig {
    fn default() -> Self {
        Self {
            default_output_cap: default_output_cap(),
            overrides: HashMap::new(),
        }
    }
}

impl ToolsConfig {
    /// Resolve the output cap for a specific tool.
    ///
    /// Returns the tool-specific override if present, otherwise the global default.
    pub fn output_cap_for(&self, tool_name: &str) -> usize {
        self.overrides
            .get(tool_name)
            .and_then(|o| o.output_cap)
            .unwrap_or(self.default_output_cap)
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
fn default_output_cap() -> usize {
    1_048_576
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

    /// Resolve `llm.models_dir` to an absolute path with `~` expansion.
    ///
    /// Falls back to `~/.local/share/sigint/models` when the field is absent.
    pub fn resolved_models_dir(&self) -> PathBuf {
        let raw = self.llm.models_dir.as_deref()
            .unwrap_or("~/.local/share/sigint/models");
        if let Some(stripped) = raw.strip_prefix("~/") {
            if let Some(home) = dirs_home() {
                return home.join(stripped);
            }
        }
        PathBuf::from(raw)
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

    #[test]
    fn agent_config_memory_defaults_false() {
        let cfg = Config::default();
        assert_eq!(cfg.agent.memory, false);
        assert_eq!(cfg.agent.recon, false);
    }

    #[test]
    fn agent_config_memory_from_toml() {
        let toml_str = r#"
[agent]
memory = true
recon = true
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse failed");
        assert_eq!(cfg.agent.memory, true);
        assert_eq!(cfg.agent.recon, true);
    }

    #[test]
    fn tools_config_defaults() {
        let cfg = Config::default();
        assert_eq!(cfg.tools.default_output_cap, 1_048_576);
        assert!(cfg.tools.overrides.is_empty());
    }

    #[test]
    fn tools_config_from_toml() {
        let toml_str = r#"
[tools]
default_output_cap = 2097152

[tools.overrides.nmap]
output_cap = 4194304
timeout = 600

[tools.overrides.nuclei]
timeout = 900
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse failed");
        assert_eq!(cfg.tools.default_output_cap, 2_097_152);
        let nmap = cfg.tools.overrides.get("nmap").expect("nmap override");
        assert_eq!(nmap.output_cap, Some(4_194_304));
        assert_eq!(nmap.timeout, Some(600));
        let nuclei = cfg.tools.overrides.get("nuclei").expect("nuclei override");
        assert_eq!(nuclei.output_cap, None);
        assert_eq!(nuclei.timeout, Some(900));
    }

    #[test]
    fn tools_config_missing_section_uses_defaults() {
        let toml_str = r#"
[llm]
model = "mistral"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse failed");
        assert_eq!(cfg.tools.default_output_cap, 1_048_576);
    }

    #[test]
    fn tools_config_resolve_output_cap() {
        let cfg: Config = toml::from_str(r#"
[tools]
default_output_cap = 1000

[tools.overrides.nmap]
output_cap = 5000
"#).expect("parse failed");
        assert_eq!(cfg.tools.output_cap_for("nmap"), 5000);
        assert_eq!(cfg.tools.output_cap_for("shell"), 1000);
        assert_eq!(cfg.tools.output_cap_for("nonexistent"), 1000);
    }

    #[test]
    fn llm_config_new_fields_default_to_none() {
        let cfg = Config::default();
        assert_eq!(cfg.llm.models_dir, None);
        assert_eq!(cfg.llm.gpu_layers, None);
    }

    #[test]
    fn llm_config_new_fields_parse_from_toml() {
        let toml_str = r#"
[llm]
models_dir = "/data/models"
gpu_layers = 32
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse failed");
        assert_eq!(cfg.llm.models_dir, Some("/data/models".to_string()));
        assert_eq!(cfg.llm.gpu_layers, Some(32));
    }

    #[test]
    fn resolved_models_dir_default_expands_tilde() {
        let cfg = Config::default();
        let path = cfg.resolved_models_dir();
        // Default should expand ~ to home dir — no literal tilde in result.
        assert!(!path.to_string_lossy().contains('~'));
        // Default path ends with sigint/models.
        assert!(path.ends_with("sigint/models"));
    }

    #[test]
    fn resolved_models_dir_explicit_tilde_path() {
        let toml_str = r#"
[llm]
models_dir = "~/.local/share/custom-models"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse failed");
        let path = cfg.resolved_models_dir();
        assert!(!path.to_string_lossy().contains('~'));
        assert!(path.ends_with("custom-models"));
    }

    #[test]
    fn plugins_config_defaults() {
        let config: PluginsConfig = toml::from_str("").unwrap();
        assert_eq!(config.prompt_pack, "default");
        assert!(config.disabled_tools.is_empty());
    }

    #[test]
    fn plugins_config_parses_from_toml() {
        let toml_str = r#"
            prompt_pack = "web-security"
            disabled_tools = ["shell", "msfconsole"]
        "#;
        let config: PluginsConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.prompt_pack, "web-security");
        assert_eq!(config.disabled_tools, vec!["shell", "msfconsole"]);
    }

    #[test]
    fn resolved_models_dir_absolute_path_unchanged() {
        let toml_str = r#"
[llm]
models_dir = "/opt/models"
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse failed");
        let path = cfg.resolved_models_dir();
        assert_eq!(path.to_str().unwrap(), "/opt/models");
    }

    #[test]
    fn llm_config_gpu_layers_zero() {
        let toml_str = r#"
[llm]
gpu_layers = 0
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse failed");
        assert_eq!(cfg.llm.gpu_layers, Some(0));
    }

    #[test]
    fn llm_config_gpu_layers_negative_one() {
        // -1 means "offload all layers to GPU"
        let toml_str = r#"
[llm]
gpu_layers = -1
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse failed");
        assert_eq!(cfg.llm.gpu_layers, Some(-1));
    }
}
