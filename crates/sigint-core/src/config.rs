//! Configuration loading for SIGINT.
//!
//! Config is loaded from `~/.config/sigint/config.toml` with sensible
//! defaults when the file is absent or fields are missing.
//!
//! @decision DEC-LLM-001: Ollama-first provider. Local privacy by default;
//! cloud providers added in Phase 2 as optional fallback.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

fn default_min_eval_examples() -> usize {
    50
}

/// Fine-tuning pipeline configuration.
///
/// Controls the external trainer command, evaluation gating, and job
/// record storage. All fields are optional — the `[train]` section may
/// be omitted from `config.toml` entirely; fine-tuning is a no-op until
/// `finetune_command` is set.
///
/// @decision DEC-P24-001
/// @title Fine-tune backend is an external shell-out command
/// @status accepted
/// @rationale `ollama create` only packages a model — it does not train.
/// llama.cpp finetune is deprecated upstream. Delegating to a user-
/// configured command (unsloth-cli, axolotl, MLX, etc.) keeps sigint
/// toolchain-agnostic and respects user diversity. Env vars
/// (SIGINT_TRAIN_JSONL, SIGINT_TEST_JSONL, SIGINT_BASE_MODEL,
/// SIGINT_OUTPUT_PATH) are the ABI between sigint and the trainer.
/// Addresses: REQ-P24-P0-002, REQ-P24-NOGO-002.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainConfig {
    /// Command invoked by `sigint train finetune`. Receives training data
    /// via environment variables. Leaving this empty (the default) means
    /// `finetune` will refuse to run with a clear error message.
    #[serde(default)]
    pub finetune_command: String,

    /// Minimum test-set examples required before `sigint model promote`
    /// will accept the candidate. Default: 50 (DEC-P24-P1-001).
    #[serde(default = "default_min_eval_examples")]
    pub min_eval_examples: usize,

    /// Directory where JobRecord JSONL and adapter outputs live.
    /// `None` resolves at runtime to `~/.local/share/sigint/training/`.
    #[serde(default)]
    pub job_dir: Option<PathBuf>,
}

impl Default for TrainConfig {
    /// Mirrors the serde defaults so that `TrainConfig::default()` and a
    /// missing `[train]` section in TOML produce identical values.
    ///
    /// The `#[derive(Default)]` macro uses `usize::default()` (= 0) for
    /// `min_eval_examples`, which would silently bypass the P1 gate.
    /// This explicit impl uses `default_min_eval_examples()` (= 50) instead.
    fn default() -> Self {
        Self {
            finetune_command: String::new(),
            min_eval_examples: default_min_eval_examples(),
            job_dir: None,
        }
    }
}

/// Recon engine security configuration.
///
/// Controls whether the engine is permitted to scan private/internal
/// network ranges (loopback, RFC1918, link-local) and provides an
/// explicit per-operator allowlist for internal pentest environments.
///
/// @decision DEC-RECON-VALIDATE-001
/// @title Deny-by-default SSRF guard with opt-in for internal pentests
/// @status accepted
/// @rationale The primary SSRF risk (Finding #3 from the /cso audit) is an
/// unauthenticated attacker passing 169.254.169.254, 10.x.x.x, or 127.0.0.1
/// as the scan target to map the host's internal network or exfiltrate cloud
/// metadata credentials (IMDS). `allow_internal = false` is the default so
/// default-installed SIGINT instances cannot be weaponised for this attack.
/// Operators who legitimately need to scan their own internal infrastructure
/// (VPN-connected lab networks, internal dev servers) can set
/// `allow_internal = true` in their config.toml. The `target_allowlist`
/// provides a finer-grained alternative: specific hosts/CIDRs are permitted
/// even when `allow_internal` is false, which covers staging environments
/// reachable via VPN without opening the entire RFC1918 space.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReconConfig {
    /// Allow recon against loopback / link-local / RFC1918 ranges.
    ///
    /// Default false — operators doing internal pentests must explicitly opt in.
    /// Setting this to true bypasses the SSRF guard entirely, so only set it
    /// when SIGINT is deployed in a trusted, isolated environment.
    #[serde(default)]
    pub allow_internal: bool,

    /// Custom allowlist of CIDR ranges or hostnames to permit even when
    /// `allow_internal` is false. Useful for staging environments behind a VPN.
    ///
    /// Examples: `["10.10.10.0/24", "staging.internal"]`
    #[serde(default)]
    pub target_allowlist: Vec<String>,
}

/// Web UI training configuration — presentation-layer knobs only.
///
/// These settings control how the web server exposes training-related
/// functionality (concurrency cap, display limits, pagination). They are
/// intentionally separate from `[train]` which holds CLI-relevant config
/// such as `finetune_command` and `min_eval_examples`.
///
/// @decision DEC-P26-005
/// @title Config additions scoped to [web.train] for UI-only knobs
/// @status accepted
/// @rationale CLI-relevant config (finetune_command, min_eval_examples,
/// job_dir) lives in [train] unchanged. Web-only presentation settings
/// (concurrency cap, stdout_tail_bytes, pagination) live in [web.train]
/// so CLI users do not see noise, and the finetune_command ABI is not
/// duplicated. The nested struct is serde-deserialized as
/// [web.train] in config.toml. Addresses: REQ-P26-P1-001, REQ-P26-NOGO-004.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebTrainConfig {
    /// Maximum number of fine-tune jobs that may run concurrently.
    ///
    /// `POST /api/train/finetune` returns `429` when this many jobs are
    /// already running. Default: 1 (single-operator tool — serialized training
    /// avoids GPU memory contention). Set to 0 to disable the cap entirely.
    #[serde(default = "default_max_concurrent_jobs")]
    pub max_concurrent_jobs: usize,

    /// Maximum bytes of trainer stdout to include in `TrainingJobProgress`
    /// WebSocket heartbeats and the job-detail drawer.
    ///
    /// Default: 2048. Keeping this bounded prevents chatty trainers from
    /// flooding the broadcast bus (Risk #2 in the Phase 26 plan).
    #[serde(default = "default_stdout_tail_bytes")]
    pub stdout_tail_bytes: usize,

    /// Number of job records to return per page in `GET /api/train/jobs`.
    ///
    /// Default: 20.
    #[serde(default = "default_jobs_page_size")]
    pub jobs_page_size: usize,
}

fn default_max_concurrent_jobs() -> usize {
    1
}
fn default_stdout_tail_bytes() -> usize {
    2048
}
fn default_jobs_page_size() -> usize {
    20
}

impl Default for WebTrainConfig {
    fn default() -> Self {
        Self {
            max_concurrent_jobs: default_max_concurrent_jobs(),
            stdout_tail_bytes: default_stdout_tail_bytes(),
            jobs_page_size: default_jobs_page_size(),
        }
    }
}

/// Web server security configuration.
///
/// Controls API authentication, allowed CORS origins, and bind address.
///
/// @decision DEC-WEB-AUTH-001
/// @title Bearer token + shared secret for API auth (vs OAuth/JWT/mTLS)
/// @status accepted
/// @rationale SIGINT is a single-operator pentest tool, not a multi-tenant
/// service. A shared Bearer secret is the simplest defensible posture: no
/// token rotation infra, no key distribution ceremony, no third-party IDP
/// dependency. OAuth/JWT would add significant complexity for zero practical
/// benefit in a local/VPN-bound deployment. The secret is auto-generated on
/// first boot (DEC-WEB-AUTH-002) so default installs are immediately secure.
///
/// @decision DEC-WEB-AUTH-002
/// @title Auto-generate and persist API key on first boot
/// @status accepted
/// @rationale If no key is configured the server generates a 32-byte
/// URL-safe random token, prints it once to stderr, and persists it to
/// ~/.config/sigint/.api_key (mode 0600). Subsequent restarts load the
/// persisted key so the operator isn't locked out. This beats both
/// "ship with no auth" (insecure) and "refuse to start without a key"
/// (bad UX that causes operators to disable auth entirely).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WebConfig {
    /// Shared Bearer secret for all REST and WebSocket endpoints.
    ///
    /// Resolution order:
    /// 1. This field (from `[web]` in config.toml)
    /// 2. `SIGINT_API_KEY_AUTH` environment variable
    /// 3. Key persisted at `~/.config/sigint/.api_key` (written on first boot)
    /// 4. Auto-generate a 32-byte URL-safe random token; persist + print to stderr
    ///
    /// Note: do NOT set `SIGINT_API_KEY` — that env var is the LLM provider key.
    #[serde(default)]
    pub api_key: Option<String>,

    /// Allowed CORS origins for the web UI.
    ///
    /// Defaults to `["http://localhost:8080", "http://127.0.0.1:8080"]` when
    /// the list is empty, preventing cross-origin access in the default config.
    #[serde(default)]
    pub cors_origins: Vec<String>,

    /// TCP address the web server binds to.
    ///
    /// `None` keeps the CLI's current default (set in the `serve` subcommand).
    /// Setting this in config.toml overrides the CLI default without requiring
    /// a flag on every invocation.
    #[serde(default)]
    pub bind_addr: Option<SocketAddr>,

    /// Web UI training knobs (concurrency cap, stdout tail, pagination).
    ///
    /// The `[web.train]` section is optional — all fields have safe defaults.
    /// CLI-relevant training config (finetune_command, etc.) lives in `[train]`.
    #[serde(default)]
    pub train: WebTrainConfig,
}

impl WebConfig {
    /// Return the list of allowed CORS origins, falling back to localhost
    /// when the configured list is empty.
    pub fn effective_cors_origins(&self) -> Vec<String> {
        if self.cors_origins.is_empty() {
            vec![
                "http://localhost:8080".to_string(),
                "http://127.0.0.1:8080".to_string(),
            ]
        } else {
            self.cors_origins.clone()
        }
    }
}

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

    /// Fine-tuning pipeline settings. The `[train]` section is optional;
    /// all fields default to no-ops until `finetune_command` is set.
    #[serde(default)]
    pub train: TrainConfig,

    /// Web server security settings (auth key, CORS, bind address).
    /// The `[web]` section is optional — safe defaults apply when absent.
    #[serde(default)]
    pub web: WebConfig,

    /// Recon engine security settings (SSRF guard, internal allowlist).
    /// The `[recon]` section is optional — deny-by-default applies when absent.
    #[serde(default)]
    pub recon: ReconConfig,
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

    /// Maximum number of concurrently running scans.
    ///
    /// `POST /api/scan` returns `429 Too Many Requests` when this many scans
    /// are already in `Running` state. Default: 8. Set to 0 to disable the
    /// cap (not recommended for exposed deployments — cost risk per CSO #9).
    ///
    /// Scan concurrency lives in `AgentConfig` rather than `WebConfig` because
    /// the constraint is resource/cost-driven (LLM tokens, sandbox processes)
    /// not purely a web-layer concern. CLI-initiated scans could apply the same
    /// limit in the future.
    #[serde(default = "default_max_concurrent_scans")]
    pub max_concurrent_scans: usize,
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
            max_concurrent_scans: default_max_concurrent_scans(),
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
fn default_max_concurrent_scans() -> usize {
    8
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
        let raw = self
            .llm
            .models_dir
            .as_deref()
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

    /// Return the canonical config file path (`~/.config/sigint/config.toml`).
    ///
    /// Exposed publicly so that CLI commands that need to rewrite the config
    /// file (e.g. `sigint model promote`) can locate it without duplicating the
    /// path resolution logic.
    pub fn config_path() -> PathBuf {
        Self::default_path()
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
        let cfg: Config = toml::from_str(
            r#"
[tools]
default_output_cap = 1000

[tools.overrides.nmap]
output_cap = 5000
"#,
        )
        .expect("parse failed");
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

    #[test]
    fn web_config_defaults_to_empty() {
        let cfg = Config::default();
        assert!(cfg.web.api_key.is_none());
        assert!(cfg.web.cors_origins.is_empty());
        assert!(cfg.web.bind_addr.is_none());
    }

    #[test]
    fn web_config_effective_cors_origins_fallback() {
        let cfg = Config::default();
        let origins = cfg.web.effective_cors_origins();
        assert_eq!(origins.len(), 2);
        assert!(origins.contains(&"http://localhost:8080".to_string()));
        assert!(origins.contains(&"http://127.0.0.1:8080".to_string()));
    }

    #[test]
    fn web_config_effective_cors_origins_custom() {
        let cfg: Config = toml::from_str(
            r#"
[web]
cors_origins = ["https://app.example.com"]
"#,
        )
        .expect("parse failed");
        let origins = cfg.web.effective_cors_origins();
        assert_eq!(origins, vec!["https://app.example.com".to_string()]);
    }

    #[test]
    fn web_config_parses_api_key_from_toml() {
        let cfg: Config = toml::from_str(
            r#"
[web]
api_key = "test-secret-token"
"#,
        )
        .expect("parse failed");
        assert_eq!(cfg.web.api_key, Some("test-secret-token".to_string()));
    }

    #[test]
    fn web_config_parses_bind_addr() {
        let cfg: Config = toml::from_str(
            r#"
[web]
bind_addr = "127.0.0.1:9090"
"#,
        )
        .expect("parse failed");
        let addr = cfg.web.bind_addr.expect("bind_addr should be set");
        assert_eq!(addr.port(), 9090);
        assert_eq!(addr.ip().to_string(), "127.0.0.1");
    }

    #[test]
    fn web_config_missing_section_uses_defaults() {
        let cfg: Config = toml::from_str("[llm]\nmodel = \"mistral\"").expect("parse failed");
        assert!(cfg.web.api_key.is_none());
        assert!(cfg.web.cors_origins.is_empty());
    }

    // ── WebTrainConfig tests (DEC-P26-005) ───────────────────────────────────

    #[test]
    fn web_train_config_defaults() {
        let cfg = Config::default();
        assert_eq!(cfg.web.train.max_concurrent_jobs, 1);
        assert_eq!(cfg.web.train.stdout_tail_bytes, 2048);
        assert_eq!(cfg.web.train.jobs_page_size, 20);
    }

    #[test]
    fn web_train_config_parses_from_toml() {
        let toml_str = r#"
[web.train]
max_concurrent_jobs = 3
stdout_tail_bytes = 4096
jobs_page_size = 50
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse failed");
        assert_eq!(cfg.web.train.max_concurrent_jobs, 3);
        assert_eq!(cfg.web.train.stdout_tail_bytes, 4096);
        assert_eq!(cfg.web.train.jobs_page_size, 50);
    }

    #[test]
    fn web_train_config_partial_toml_uses_defaults() {
        let toml_str = r#"
[web.train]
max_concurrent_jobs = 2
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse failed");
        assert_eq!(cfg.web.train.max_concurrent_jobs, 2);
        // Remaining fields fall back to defaults.
        assert_eq!(cfg.web.train.stdout_tail_bytes, 2048);
        assert_eq!(cfg.web.train.jobs_page_size, 20);
    }

    #[test]
    fn web_train_config_missing_section_uses_defaults() {
        let cfg: Config = toml::from_str("[llm]\nmodel = \"mistral\"").expect("parse failed");
        assert_eq!(cfg.web.train.max_concurrent_jobs, 1);
        assert_eq!(cfg.web.train.stdout_tail_bytes, 2048);
        assert_eq!(cfg.web.train.jobs_page_size, 20);
    }

    #[test]
    fn web_train_config_zero_concurrent_jobs_disables_cap() {
        // max_concurrent_jobs = 0 is valid (disables the cap — unlimited).
        let toml_str = r#"
[web.train]
max_concurrent_jobs = 0
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse failed");
        assert_eq!(cfg.web.train.max_concurrent_jobs, 0);
    }
}
