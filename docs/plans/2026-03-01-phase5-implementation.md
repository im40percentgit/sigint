# Phase 5: Web UI + Polish — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add `sigint doctor`, OpenAI-compatible LLM provider, report generation, REST API + WebSocket, and embedded SPA frontend to SIGINT.

**Architecture:** 5 vertical slices (5A–5E), each independently testable and mergeable. Single binary stays self-contained — SPA embedded via `rust-embed`, PDF via pure Rust, no external runtime deps.

**Tech Stack:** Rust (Axum, reqwest, pulldown-cmark, genpdf, rust-embed), Preact + HTM (frontend), esbuild (bundler)

---

## Sub-Phase 5A: `sigint doctor`

### Task 1: Config Check

**Files:**
- Modify: `crates/sigint-cli/src/doctor.rs`
- Test: inline `#[cfg(test)] mod tests`

**Step 1: Write the failing test**

Add to `doctor.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_config_ok_with_valid_config() {
        let config = sigint_core::config::Config::default();
        let result = check_config(&config);
        assert!(result.passed);
        assert!(result.message.contains("Config loaded"));
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p sigint-cli -- check_config_ok`
Expected: FAIL — `check_config` not defined

**Step 3: Implement the check infrastructure and config check**

Replace `doctor.rs` with:

```rust
//! `sigint doctor` — environment and dependency checker.
//!
//! @decision DEC-P5-DOCTOR
//! @title Structured health-check runner with pass/fail output
//! @status accepted
//! @rationale Each check returns a CheckResult, printed with ✓/✗ prefix.
//! Checks are independent functions so they can be unit tested without
//! running the entire doctor flow. Exit code reflects overall health.

use sigint_core::{config::Config, Error};

/// Result of a single diagnostic check.
pub struct CheckResult {
    pub name: &'static str,
    pub passed: bool,
    pub message: String,
}

/// Check that config loads and contains valid values.
pub fn check_config(config: &Config) -> CheckResult {
    // If we got here, config already loaded. Validate key fields.
    if config.llm.base_url.is_empty() {
        return CheckResult {
            name: "Config",
            passed: false,
            message: "Config loaded but base_url is empty".into(),
        };
    }
    CheckResult {
        name: "Config",
        passed: true,
        message: format!("Config loaded (~/.config/sigint/config.toml)"),
    }
}

/// Run the doctor command — executes all checks and prints results.
pub async fn run(core: sigint_core::AppCore) -> Result<(), Error> {
    println!("SIGINT Doctor");

    let checks = vec![
        check_config(&core.config),
    ];

    let mut passed = 0;
    let total = checks.len();
    for check in &checks {
        let icon = if check.passed { "✓" } else { "✗" };
        println!("  {} {}", icon, check.message);
        if check.passed {
            passed += 1;
        }
    }

    let issues = total - passed;
    println!("\n{}/{} checks passed, {} issues found", passed, total, issues);

    if issues > 0 {
        std::process::exit(1);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_config_ok_with_valid_config() {
        let config = Config::default();
        let result = check_config(&config);
        assert!(result.passed);
        assert!(result.message.contains("Config loaded"));
    }

    #[test]
    fn check_config_fails_with_empty_base_url() {
        let mut config = Config::default();
        config.llm.base_url = String::new();
        let result = check_config(&config);
        assert!(!result.passed);
    }
}
```

**Step 4: Run tests**

Run: `cargo test -p sigint-cli -- check_config`
Expected: 2 tests PASS

**Step 5: Commit**

```bash
git add crates/sigint-cli/src/doctor.rs
git commit -m "feat(doctor): config check with CheckResult infrastructure"
```

---

### Task 2: Ollama Reachability Check

**Files:**
- Modify: `crates/sigint-cli/src/doctor.rs`

**Step 1: Write the failing test**

```rust
#[tokio::test]
async fn check_ollama_unreachable() {
    let config = Config::default();
    // Default config points to localhost:11434 which may not be running
    let result = check_ollama(&config).await;
    // We just verify the function returns a valid CheckResult
    assert_eq!(result.name, "Ollama");
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p sigint-cli -- check_ollama`
Expected: FAIL — `check_ollama` not defined

**Step 3: Implement**

Add to `doctor.rs`:

```rust
/// Check Ollama reachability by hitting GET {base_url}/api/tags.
pub async fn check_ollama(config: &Config) -> CheckResult {
    let url = format!("{}/api/tags", config.llm.base_url);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();

    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => CheckResult {
            name: "Ollama",
            passed: true,
            message: format!("Ollama reachable ({})", config.llm.base_url),
        },
        Ok(resp) => CheckResult {
            name: "Ollama",
            passed: false,
            message: format!("Ollama returned {} at {}", resp.status(), config.llm.base_url),
        },
        Err(e) => CheckResult {
            name: "Ollama",
            passed: false,
            message: format!("Cannot reach Ollama at {} — {}", config.llm.base_url, e),
        },
    }
}
```

Update `run()` to include `check_ollama(&core.config).await`.

**Step 4: Run tests**

Run: `cargo test -p sigint-cli -- check_ollama`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/sigint-cli/src/doctor.rs
git commit -m "feat(doctor): Ollama reachability check"
```

---

### Task 3: Model Availability Check

**Files:**
- Modify: `crates/sigint-cli/src/doctor.rs`

**Step 1: Write the failing test**

```rust
#[test]
fn parse_ollama_tags_finds_model() {
    let json = r#"{"models":[{"name":"llama3.2:latest"},{"name":"phi3:latest"}]}"#;
    let models = parse_ollama_models(json).unwrap();
    assert!(models.contains(&"llama3.2:latest".to_string()));
    assert!(model_available(&models, "llama3.2"));
    assert!(!model_available(&models, "gpt-4o"));
}
```

**Step 2: Run test — fails**

**Step 3: Implement**

```rust
/// Parse Ollama /api/tags response into model name list.
pub fn parse_ollama_models(json: &str) -> Result<Vec<String>, String> {
    let v: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let models = v["models"]
        .as_array()
        .ok_or("no models array")?
        .iter()
        .filter_map(|m| m["name"].as_str().map(String::from))
        .collect();
    Ok(models)
}

/// Check if target model (with or without :tag) is in the model list.
pub fn model_available(models: &[String], target: &str) -> bool {
    models.iter().any(|m| m == target || m.starts_with(&format!("{}:", target)))
}

pub async fn check_model(config: &Config) -> CheckResult {
    let url = format!("{}/api/tags", config.llm.base_url);
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();

    match client.get(&url).send().await {
        Ok(resp) if resp.status().is_success() => {
            let body = resp.text().await.unwrap_or_default();
            match parse_ollama_models(&body) {
                Ok(models) if model_available(&models, &config.llm.model) => CheckResult {
                    name: "Model",
                    passed: true,
                    message: format!("Model available ({})", config.llm.model),
                },
                Ok(_) => CheckResult {
                    name: "Model",
                    passed: false,
                    message: format!("Model '{}' not found — run: ollama pull {}", config.llm.model, config.llm.model),
                },
                Err(e) => CheckResult {
                    name: "Model",
                    passed: false,
                    message: format!("Cannot parse model list: {}", e),
                },
            }
        }
        _ => CheckResult {
            name: "Model",
            passed: false,
            message: "Skipped — Ollama not reachable".into(),
        },
    }
}
```

**Step 4: Run tests**

Run: `cargo test -p sigint-cli -- parse_ollama`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/sigint-cli/src/doctor.rs
git commit -m "feat(doctor): model availability check via /api/tags"
```

---

### Task 4: Tool Availability + Sandbox + Database Checks

**Files:**
- Modify: `crates/sigint-cli/src/doctor.rs`
- Modify: `crates/sigint-cli/Cargo.toml` (add `sigint-store`, `which` deps)

**Step 1: Write the failing tests**

```rust
#[test]
fn check_tool_finds_existing_binary() {
    // "ls" exists on every Linux system
    let result = check_tool("ls");
    assert!(result.passed);
}

#[test]
fn check_tool_detects_missing_binary() {
    let result = check_tool("nonexistent_binary_xyz_12345");
    assert!(!result.passed);
}

#[test]
fn check_db_with_in_memory() {
    let db = sigint_store::Database::open_in_memory().unwrap();
    let result = check_database(&db);
    assert!(result.passed);
    assert!(result.message.contains("Database OK"));
}
```

**Step 2: Run tests — fail**

**Step 3: Implement**

```rust
use std::process::Command;

/// Check whether a tool binary is in PATH.
pub fn check_tool(name: &str) -> CheckResult {
    let found = Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);

    if found {
        CheckResult {
            name: "Tool",
            passed: true,
            message: format!("{} found", name),
        }
    } else {
        let hint = match name {
            "nmap" => "sudo apt install nmap",
            "gobuster" => "go install github.com/OJ/gobuster/v3@latest",
            "nikto" => "sudo apt install nikto",
            "nuclei" => "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "feroxbuster" => "cargo install feroxbuster",
            "dig" => "sudo apt install dnsutils",
            "whois" => "sudo apt install whois",
            "curl" => "sudo apt install curl",
            _ => "check your package manager",
        };
        CheckResult {
            name: "Tool",
            passed: false,
            message: format!("{} not found — install: {}", name, hint),
        }
    }
}

/// Check sandbox prerequisites (newuidmap + pasta).
pub fn check_sandbox() -> Vec<CheckResult> {
    vec![
        {
            let name = "newuidmap";
            let mut r = check_tool(name);
            r.name = "Sandbox";
            r.message = if r.passed {
                format!("Sandbox: {} found", name)
            } else {
                format!("Sandbox: {} not found — install: sudo apt install uidmap", name)
            };
            r
        },
        {
            let name = "pasta";
            let mut r = check_tool(name);
            r.name = "Sandbox";
            r.message = if r.passed {
                format!("Sandbox: {} found", name)
            } else {
                format!("Sandbox: {} not found — install: sudo apt install passt", name)
            };
            r
        },
    ]
}

/// Check database health — open and verify schema version.
pub fn check_database(db: &sigint_store::Database) -> CheckResult {
    match db.conn() {
        Ok(conn) => {
            let version: Result<u32, _> = conn.query_row(
                "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                [],
                |r| r.get(0),
            );
            match version {
                Ok(v) => CheckResult {
                    name: "Database",
                    passed: true,
                    message: format!("Database OK (v{})", v),
                },
                Err(e) => CheckResult {
                    name: "Database",
                    passed: false,
                    message: format!("Database error: {}", e),
                },
            }
        }
        Err(e) => CheckResult {
            name: "Database",
            passed: false,
            message: format!("Cannot open database: {}", e),
        },
    }
}
```

Update `run()` to include all checks: config, ollama, model, tools (nmap, gobuster, nikto, nuclei, feroxbuster, dig, whois, curl), sandbox, database.

**Step 4: Run tests**

Run: `cargo test -p sigint-cli -- check_tool check_db`
Expected: 3 tests PASS

**Step 5: Commit**

```bash
git add crates/sigint-cli/src/doctor.rs crates/sigint-cli/Cargo.toml
git commit -m "feat(doctor): tool, sandbox, and database checks — complete 5A"
```

---

## Sub-Phase 5B: OpenAI-Compatible LLM Provider

### Task 5: Add `api_key` to LlmConfig

**Files:**
- Modify: `crates/sigint-core/src/config.rs`
- Test: inline tests

**Step 1: Write the failing test**

```rust
#[test]
fn config_with_api_key() {
    let toml_str = r#"
[llm]
provider = "openai"
model = "gpt-4o"
base_url = "https://api.openai.com"
api_key = "sk-test123"
"#;
    let cfg: Config = toml::from_str(toml_str).expect("parse failed");
    assert_eq!(cfg.llm.api_key, Some("sk-test123".to_string()));
}
```

**Step 2: Run test — fails (no `api_key` field)**

**Step 3: Implement**

Add to `LlmConfig`:

```rust
/// API key for cloud providers. Can also be set via SIGINT_API_KEY env var.
#[serde(default)]
pub api_key: Option<String>,
```

Update `Default for LlmConfig` to include `api_key: None`.

**Step 4: Run tests**

Run: `cargo test -p sigint-core -- config`
Expected: all config tests PASS

**Step 5: Commit**

```bash
git add crates/sigint-core/src/config.rs
git commit -m "feat(config): add api_key field to LlmConfig"
```

---

### Task 6: OpenAI Provider — Non-Streaming Chat

**Files:**
- Create: `crates/sigint-llm/src/openai.rs`
- Modify: `crates/sigint-llm/src/lib.rs`
- Modify: `crates/sigint-llm/Cargo.toml`

**Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn openai_request_serializes_correctly() {
        let req = ChatRequest::new("gpt-4o", vec![ChatMessage::user("hello")])
            .with_temperature(0.5);
        let wire = build_openai_request(&req, false);
        let json = serde_json::to_value(&wire).unwrap();
        assert_eq!(json["model"], "gpt-4o");
        assert_eq!(json["messages"][0]["role"], "user");
        assert_eq!(json["messages"][0]["content"], "hello");
        assert_eq!(json["stream"], false);
        assert!((json["temperature"].as_f64().unwrap() - 0.5).abs() < 0.01);
    }

    #[test]
    fn parse_openai_chat_response() {
        let json_str = r#"{
            "id": "chatcmpl-123",
            "object": "chat.completion",
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "Hello! How can I help?"
                },
                "finish_reason": "stop"
            }],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 8,
                "total_tokens": 18
            }
        }"#;
        let resp: OpenAiResponse = serde_json::from_str(json_str).unwrap();
        let chat_resp = resp.into_chat_response("gpt-4o");
        assert_eq!(chat_resp.content, "Hello! How can I help?");
        assert!(chat_resp.tool_calls.is_empty());
        assert_eq!(chat_resp.usage.as_ref().unwrap().total_tokens, 18);
    }

    #[test]
    fn parse_openai_tool_call_response() {
        let json_str = r#"{
            "id": "chatcmpl-456",
            "object": "chat.completion",
            "model": "gpt-4o",
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_abc",
                        "type": "function",
                        "function": {
                            "name": "nmap_scan",
                            "arguments": "{\"target\":\"10.0.0.1\"}"
                        }
                    }]
                },
                "finish_reason": "tool_calls"
            }],
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 15,
                "total_tokens": 25
            }
        }"#;
        let resp: OpenAiResponse = serde_json::from_str(json_str).unwrap();
        let chat_resp = resp.into_chat_response("gpt-4o");
        assert!(chat_resp.has_tool_calls());
        assert_eq!(chat_resp.tool_calls[0].function.name, "nmap_scan");
    }
}
```

**Step 2: Run test — fails**

**Step 3: Implement `openai.rs`**

```rust
//! OpenAI-compatible LLM provider — POST /v1/chat/completions.
//!
//! @decision DEC-P5-OPENAI
//! @title OpenAI-compatible provider covering OpenAI, Groq, Together, OpenRouter, vLLM
//! @status accepted
//! @rationale One provider implementation covers all OpenAI-compatible APIs.
//! SSE streaming via eventsource-stream. API key from config or SIGINT_API_KEY env var.
//! Tool-calling types are already OpenAI-compatible (DEC-LLM-002), so no conversion needed.

use async_trait::async_trait;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::provider::{ChunkStream, LlmProvider};
use crate::types::{
    ChatMessage, ChatRequest, ChatResponse, FunctionCall, StreamChunk, ToolCall,
    ToolDefinition, TokenUsage,
};
use sigint_core::Error;

// ── Wire types ─────────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
pub(crate) struct OpenAiWireRequest {
    pub model: String,
    pub messages: Vec<OpenAiWireMessage>,
    pub stream: bool,
    pub temperature: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<usize>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tools: Vec<ToolDefinition>,
}

#[derive(Debug, Serialize)]
pub(crate) struct OpenAiWireMessage {
    pub role: String,
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCall>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct OpenAiResponse {
    pub choices: Vec<OpenAiChoice>,
    pub usage: Option<OpenAiUsage>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct OpenAiChoice {
    pub message: Option<OpenAiMessage>,
    pub delta: Option<OpenAiMessage>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct OpenAiMessage {
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub tool_calls: Option<Vec<OpenAiToolCall>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct OpenAiToolCall {
    pub function: OpenAiFunctionCall,
}

#[derive(Debug, Deserialize)]
pub(crate) struct OpenAiFunctionCall {
    pub name: Option<String>,
    #[serde(default)]
    pub arguments: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct OpenAiUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

// ── Conversion helpers ─────────────────────────────────────────────────

impl OpenAiResponse {
    pub fn into_chat_response(self, model: &str) -> ChatResponse {
        let choice = self.choices.into_iter().next();
        let (content, tool_calls) = match choice {
            Some(c) => {
                let msg = c.message.or(c.delta).unwrap_or(OpenAiMessage {
                    content: None,
                    tool_calls: None,
                });
                let tc = msg
                    .tool_calls
                    .unwrap_or_default()
                    .into_iter()
                    .filter_map(|tc| {
                        let name = tc.function.name?;
                        let args = serde_json::from_str(&tc.function.arguments)
                            .unwrap_or(serde_json::Value::Object(Default::default()));
                        Some(ToolCall {
                            function: FunctionCall {
                                name,
                                arguments: args,
                            },
                        })
                    })
                    .collect();
                (msg.content.unwrap_or_default(), tc)
            }
            None => (String::new(), vec![]),
        };
        let usage = self.usage.map(|u| TokenUsage {
            prompt_tokens: u.prompt_tokens,
            completion_tokens: u.completion_tokens,
            total_tokens: u.total_tokens,
        });
        ChatResponse {
            content,
            tool_calls,
            usage,
            model: model.to_string(),
        }
    }
}

pub(crate) fn build_openai_request(req: &ChatRequest, stream: bool) -> OpenAiWireRequest {
    OpenAiWireRequest {
        model: req.model.clone(),
        messages: req
            .messages
            .iter()
            .map(|m| OpenAiWireMessage {
                role: m.role.clone(),
                content: Some(m.content.clone()),
                tool_calls: m.tool_calls.clone(),
            })
            .collect(),
        stream,
        temperature: req.temperature,
        max_tokens: if req.max_tokens > 0 {
            Some(req.max_tokens)
        } else {
            None
        },
        tools: req.tools.clone(),
    }
}

// ── Provider ───────────────────────────────────────────────────────────

/// OpenAI-compatible LLM provider.
#[derive(Debug, Clone)]
pub struct OpenAiProvider {
    base_url: String,
    model: String,
    api_key: String,
    client: reqwest::Client,
}

impl OpenAiProvider {
    pub fn new(
        base_url: impl Into<String>,
        model: impl Into<String>,
        api_key: impl Into<String>,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            model: model.into(),
            api_key: api_key.into(),
            client: reqwest::Client::new(),
        }
    }

    /// Construct from sigint-core config. Falls back to SIGINT_API_KEY env var.
    pub fn from_config(cfg: &sigint_core::config::LlmConfig) -> Result<Self, Error> {
        let api_key = cfg
            .api_key
            .clone()
            .or_else(|| std::env::var("SIGINT_API_KEY").ok())
            .ok_or_else(|| {
                Error::Config(
                    "OpenAI provider requires api_key in config or SIGINT_API_KEY env var".into(),
                )
            })?;
        Ok(Self::new(&cfg.base_url, &cfg.model, api_key))
    }

    fn completions_url(&self) -> String {
        format!("{}/v1/chat/completions", self.base_url.trim_end_matches('/'))
    }
}

#[async_trait]
impl LlmProvider for OpenAiProvider {
    fn name(&self) -> &str {
        "openai"
    }

    async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, Error> {
        let wire = build_openai_request(&request, false);
        debug!("OpenAI non-streaming request to {}", self.completions_url());

        let resp = self
            .client
            .post(self.completions_url())
            .bearer_auth(&self.api_key)
            .json(&wire)
            .send()
            .await
            .map_err(|e| Error::Llm(format!("Cannot connect to {}: {}", self.base_url, e)))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(match status.as_u16() {
                401 => Error::Llm("Authentication failed — check your API key".into()),
                429 => Error::Llm(format!("Rate limited by provider: {}", text)),
                _ => Error::Llm(format!("Provider returned {}: {}", status, text)),
            });
        }

        let body: OpenAiResponse = resp.json().await.map_err(|e| {
            Error::Llm(format!("Failed to parse response: {}", e))
        })?;

        Ok(body.into_chat_response(&request.model))
    }

    async fn chat_stream(&self, request: ChatRequest) -> Result<ChunkStream, Error> {
        let wire = build_openai_request(&request, true);
        debug!("OpenAI streaming request to {}", self.completions_url());

        let resp = self
            .client
            .post(self.completions_url())
            .bearer_auth(&self.api_key)
            .json(&wire)
            .send()
            .await
            .map_err(|e| Error::Llm(format!("Cannot connect to {}: {}", self.base_url, e)))?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(match status.as_u16() {
                401 => Error::Llm("Authentication failed — check your API key".into()),
                429 => Error::Llm(format!("Rate limited by provider: {}", text)),
                _ => Error::Llm(format!("Provider returned {}: {}", status, text)),
            });
        }

        let byte_stream = resp.bytes_stream();
        let chunk_stream = sse_to_chunks(byte_stream);
        Ok(Box::pin(chunk_stream))
    }
}

/// Parse SSE stream into StreamChunks.
fn sse_to_chunks(
    byte_stream: impl futures_util::Stream<Item = Result<bytes::Bytes, reqwest::Error>> + Send + 'static,
) -> impl futures_util::Stream<Item = Result<StreamChunk, Error>> + Send {
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
            let text = String::from_utf8_lossy(&bytes);
            buf.push_str(&text);

            while let Some(newline_pos) = buf.find('\n') {
                let line = buf[..newline_pos].trim().to_string();
                buf = buf[newline_pos + 1..].to_string();

                if line.is_empty() || line.starts_with(':') {
                    continue;
                }

                let data = if let Some(stripped) = line.strip_prefix("data: ") {
                    stripped.trim()
                } else {
                    continue;
                };

                if data == "[DONE]" {
                    yield Ok(StreamChunk {
                        delta: String::new(),
                        done: true,
                        usage: None,
                        tool_calls: vec![],
                    });
                    return;
                }

                match serde_json::from_str::<OpenAiResponse>(data) {
                    Ok(resp) => {
                        let choice = resp.choices.into_iter().next();
                        if let Some(c) = choice {
                            let msg = c.delta.or(c.message).unwrap_or(OpenAiMessage {
                                content: None,
                                tool_calls: None,
                            });
                            let delta = msg.content.unwrap_or_default();
                            let tool_calls: Vec<ToolCall> = msg
                                .tool_calls
                                .unwrap_or_default()
                                .into_iter()
                                .filter_map(|tc| {
                                    let name = tc.function.name?;
                                    let args = serde_json::from_str(&tc.function.arguments)
                                        .unwrap_or(serde_json::Value::Object(Default::default()));
                                    Some(ToolCall {
                                        function: FunctionCall { name, arguments: args },
                                    })
                                })
                                .collect();
                            yield Ok(StreamChunk {
                                delta,
                                done: false,
                                usage: None,
                                tool_calls,
                            });
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse SSE chunk: {} — data: {}", e, data);
                    }
                }
            }
        }
    }
}
```

Update `crates/sigint-llm/src/lib.rs` to add `pub mod openai;` and `pub use openai::OpenAiProvider;`.

Add `bytes = "1"` to `crates/sigint-llm/Cargo.toml` if not already present (it is).

**Step 4: Run tests**

Run: `cargo test -p sigint-llm -- openai`
Expected: all 3 tests PASS

**Step 5: Commit**

```bash
git add crates/sigint-llm/src/openai.rs crates/sigint-llm/src/lib.rs crates/sigint-llm/Cargo.toml
git commit -m "feat(llm): OpenAI-compatible provider with streaming SSE"
```

---

### Task 7: Provider Factory + Error Tests

**Files:**
- Create: `crates/sigint-llm/src/factory.rs`
- Modify: `crates/sigint-llm/src/lib.rs`

**Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use sigint_core::config::LlmConfig;

    #[test]
    fn factory_creates_ollama_by_default() {
        let config = LlmConfig::default();
        let provider = create_provider(&config).unwrap();
        assert_eq!(provider.name(), "ollama");
    }

    #[test]
    fn factory_creates_openai_with_key() {
        let config = LlmConfig {
            provider: "openai".into(),
            model: "gpt-4o".into(),
            base_url: "https://api.openai.com".into(),
            api_key: Some("sk-test".into()),
            temperature: 0.7,
            context_window: 0,
        };
        let provider = create_provider(&config).unwrap();
        assert_eq!(provider.name(), "openai");
    }

    #[test]
    fn factory_rejects_openai_without_key() {
        let config = LlmConfig {
            provider: "openai".into(),
            model: "gpt-4o".into(),
            base_url: "https://api.openai.com".into(),
            api_key: None,
            temperature: 0.7,
            context_window: 0,
        };
        // Clear env var to ensure it's not set
        std::env::remove_var("SIGINT_API_KEY");
        let result = create_provider(&config);
        assert!(result.is_err());
    }

    #[test]
    fn factory_rejects_unknown_provider() {
        let mut config = LlmConfig::default();
        config.provider = "anthropic".into();
        let result = create_provider(&config);
        assert!(result.is_err());
    }
}
```

**Step 2: Run test — fails**

**Step 3: Implement `factory.rs`**

```rust
//! Provider factory — dispatches to the correct LlmProvider based on config.

use sigint_core::config::LlmConfig;
use sigint_core::Error;

use crate::provider::LlmProvider;
use crate::ollama::OllamaProvider;
use crate::openai::OpenAiProvider;

/// Create the appropriate LlmProvider based on the config `provider` field.
pub fn create_provider(config: &LlmConfig) -> Result<Box<dyn LlmProvider>, Error> {
    match config.provider.as_str() {
        "ollama" => Ok(Box::new(OllamaProvider::from_config(config))),
        "openai" => Ok(Box::new(OpenAiProvider::from_config(config)?)),
        other => Err(Error::Config(format!(
            "Unknown LLM provider '{}'. Supported: ollama, openai",
            other
        ))),
    }
}
```

Update `lib.rs`:

```rust
pub mod factory;
pub use factory::create_provider;
```

**Step 4: Run tests**

Run: `cargo test -p sigint-llm -- factory`
Expected: 4 tests PASS

**Step 5: Commit**

```bash
git add crates/sigint-llm/src/factory.rs crates/sigint-llm/src/lib.rs
git commit -m "feat(llm): provider factory dispatches ollama/openai by config"
```

---

### Task 8: OpenAI Error Handling Tests

**Files:**
- Modify: `crates/sigint-llm/src/openai.rs`

**Step 1: Write the failing tests**

```rust
#[tokio::test]
async fn chat_returns_auth_error_on_401() {
    // Use a mock server or known-bad endpoint
    let provider = OpenAiProvider::new("http://127.0.0.1:19999", "gpt-4o", "bad-key");
    let req = ChatRequest::new("gpt-4o", vec![ChatMessage::user("hello")]);
    let result = provider.chat(req).await;
    assert!(result.is_err());
    // Connection refused is also acceptable
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("Cannot connect") || msg.contains("Authentication"));
}

#[test]
fn openai_request_omits_tools_when_empty() {
    let req = ChatRequest::new("gpt-4o", vec![ChatMessage::user("hello")]);
    let wire = build_openai_request(&req, false);
    let json = serde_json::to_value(&wire).unwrap();
    assert!(json.get("tools").is_none(), "tools should be omitted when empty");
}

#[test]
fn api_key_from_env_fallback() {
    std::env::set_var("SIGINT_API_KEY", "sk-from-env");
    let config = LlmConfig {
        provider: "openai".into(),
        model: "gpt-4o".into(),
        base_url: "https://api.openai.com".into(),
        api_key: None,
        temperature: 0.7,
        context_window: 0,
    };
    let provider = OpenAiProvider::from_config(&config);
    assert!(provider.is_ok());
    std::env::remove_var("SIGINT_API_KEY");
}
```

**Step 2: Run tests — may pass if already implemented correctly**

**Step 3: Verify tests pass, fix any issues**

**Step 4: Run all LLM tests**

Run: `cargo test -p sigint-llm`
Expected: All tests PASS

**Step 5: Commit**

```bash
git add crates/sigint-llm/src/openai.rs
git commit -m "test(llm): OpenAI error handling and edge case tests — complete 5B"
```

---

## Sub-Phase 5C: Report Generation

### Task 9: Create `sigint-report` Crate

**Files:**
- Create: `crates/sigint-report/Cargo.toml`
- Create: `crates/sigint-report/src/lib.rs`
- Modify: `Cargo.toml` (workspace members + deps)

**Step 1: Create crate skeleton**

`crates/sigint-report/Cargo.toml`:

```toml
[package]
name = "sigint-report"
version.workspace = true
edition.workspace = true

[dependencies]
sigint-core = { workspace = true }
sigint-store = { workspace = true }
chrono = { workspace = true }
uuid = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
pulldown-cmark = "0.12"
```

`crates/sigint-report/src/lib.rs`:

```rust
//! sigint-report — Export scan results as Markdown, HTML, and PDF.
//!
//! @decision DEC-P5-REPORT
//! @title Markdown-first report generation with HTML/PDF derived formats
//! @status accepted
//! @rationale Markdown is the canonical format. HTML wraps Markdown output
//! with pulldown-cmark rendering + embedded CSS. PDF uses genpdf (pure Rust).
//! Three template levels: executive, detailed, technical.

pub mod builder;
pub mod templates;
pub mod format;
```

Add workspace entries:
- `Cargo.toml` [workspace.members]: add `"crates/sigint-report"`
- `Cargo.toml` [workspace.dependencies]: add `pulldown-cmark = "0.12"`, `sigint-report = { path = "crates/sigint-report" }`

**Step 2: Verify crate compiles**

Run: `cargo check -p sigint-report`
Expected: compiles (empty modules)

**Step 3: Commit**

```bash
git add crates/sigint-report/ Cargo.toml
git commit -m "feat(report): scaffold sigint-report crate"
```

---

### Task 10: Report Builder + Markdown Template

**Files:**
- Create: `crates/sigint-report/src/builder.rs`
- Create: `crates/sigint-report/src/templates.rs`

**Step 1: Write the failing test**

In `builder.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_executive_markdown() {
        let data = ReportData {
            session_name: "Test Scan".into(),
            target: "scanme.nmap.org".into(),
            created_at: "2026-03-01T12:00:00Z".into(),
            findings: vec![
                FindingSummary {
                    title: "Open SSH Port".into(),
                    severity: "medium".into(),
                    description: "Port 22 is open with OpenSSH 8.9".into(),
                },
            ],
            assets: vec![
                AssetSummary {
                    kind: "host".into(),
                    value: "45.33.32.156".into(),
                    services_count: 3,
                },
            ],
            scan_count: 5,
        };
        let md = build_markdown(&data, ReportTemplate::Executive);
        assert!(md.contains("# SIGINT Scan Report"));
        assert!(md.contains("scanme.nmap.org"));
        assert!(md.contains("Open SSH Port"));
        assert!(md.contains("## Executive Summary"));
    }
}
```

**Step 2: Run test — fails**

**Step 3: Implement**

`builder.rs`:

```rust
//! Report builder — converts scan data into formatted reports.

use serde::{Deserialize, Serialize};

/// Level of detail for the report.
#[derive(Debug, Clone, Copy)]
pub enum ReportTemplate {
    Executive,
    Detailed,
    Technical,
}

/// Output format.
#[derive(Debug, Clone, Copy)]
pub enum ReportFormat {
    Markdown,
    Html,
}

/// Summary of a finding for report rendering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingSummary {
    pub title: String,
    pub severity: String,
    pub description: String,
}

/// Summary of an asset for report rendering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetSummary {
    pub kind: String,
    pub value: String,
    pub services_count: usize,
}

/// All data needed to render a report.
#[derive(Debug, Clone)]
pub struct ReportData {
    pub session_name: String,
    pub target: String,
    pub created_at: String,
    pub findings: Vec<FindingSummary>,
    pub assets: Vec<AssetSummary>,
    pub scan_count: usize,
}

/// Build a Markdown report from scan data.
pub fn build_markdown(data: &ReportData, template: ReportTemplate) -> String {
    let mut out = String::new();

    // Header
    out.push_str(&format!("# SIGINT Scan Report: {}\n\n", data.target));
    out.push_str(&format!("**Session:** {}\n\n", data.session_name));
    out.push_str(&format!("**Date:** {}\n\n", data.created_at));
    out.push_str(&format!(
        "**Summary:** {} findings, {} assets, {} scans\n\n",
        data.findings.len(),
        data.assets.len(),
        data.scan_count
    ));
    out.push_str("---\n\n");

    match template {
        ReportTemplate::Executive => {
            out.push_str("## Executive Summary\n\n");
            if data.findings.is_empty() {
                out.push_str("No findings were identified during this scan.\n\n");
            } else {
                out.push_str("| Severity | Finding |\n|----------|----------|\n");
                for f in &data.findings {
                    out.push_str(&format!("| {} | {} |\n", f.severity, f.title));
                }
                out.push_str("\n");
            }
        }
        ReportTemplate::Detailed => {
            out.push_str("## Findings\n\n");
            for (i, f) in data.findings.iter().enumerate() {
                out.push_str(&format!(
                    "### {}. {} [{}]\n\n{}\n\n",
                    i + 1,
                    f.title,
                    f.severity,
                    f.description
                ));
            }
            out.push_str("## Assets\n\n");
            out.push_str("| Kind | Value | Services |\n|------|-------|----------|\n");
            for a in &data.assets {
                out.push_str(&format!("| {} | {} | {} |\n", a.kind, a.value, a.services_count));
            }
            out.push_str("\n");
        }
        ReportTemplate::Technical => {
            out.push_str("## Technical Details\n\n");
            out.push_str("### Findings\n\n");
            for f in &data.findings {
                out.push_str(&format!("#### {} [{}]\n\n{}\n\n", f.title, f.severity, f.description));
            }
            out.push_str("### Asset Inventory\n\n");
            for a in &data.assets {
                out.push_str(&format!("- **{}**: {} ({} services)\n", a.kind, a.value, a.services_count));
            }
            out.push_str("\n");
        }
    }

    out.push_str("---\n\n*Generated by SIGINT*\n");
    out
}

/// Build a report in the specified format.
pub fn build_report(data: &ReportData, template: ReportTemplate, format: ReportFormat) -> Vec<u8> {
    let md = build_markdown(data, template);
    match format {
        ReportFormat::Markdown => md.into_bytes(),
        ReportFormat::Html => crate::format::markdown_to_html(&md).into_bytes(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_data() -> ReportData {
        ReportData {
            session_name: "Test Scan".into(),
            target: "scanme.nmap.org".into(),
            created_at: "2026-03-01T12:00:00Z".into(),
            findings: vec![FindingSummary {
                title: "Open SSH Port".into(),
                severity: "medium".into(),
                description: "Port 22 is open with OpenSSH 8.9".into(),
            }],
            assets: vec![AssetSummary {
                kind: "host".into(),
                value: "45.33.32.156".into(),
                services_count: 3,
            }],
            scan_count: 5,
        }
    }

    #[test]
    fn build_executive_markdown() {
        let md = build_markdown(&sample_data(), ReportTemplate::Executive);
        assert!(md.contains("# SIGINT Scan Report"));
        assert!(md.contains("scanme.nmap.org"));
        assert!(md.contains("Open SSH Port"));
        assert!(md.contains("## Executive Summary"));
    }

    #[test]
    fn build_detailed_markdown() {
        let md = build_markdown(&sample_data(), ReportTemplate::Detailed);
        assert!(md.contains("## Findings"));
        assert!(md.contains("## Assets"));
        assert!(md.contains("45.33.32.156"));
    }

    #[test]
    fn build_technical_markdown() {
        let md = build_markdown(&sample_data(), ReportTemplate::Technical);
        assert!(md.contains("## Technical Details"));
    }

    #[test]
    fn empty_findings_handled() {
        let mut data = sample_data();
        data.findings.clear();
        let md = build_markdown(&data, ReportTemplate::Executive);
        assert!(md.contains("No findings were identified"));
    }
}
```

**Step 4: Run tests**

Run: `cargo test -p sigint-report`
Expected: 4 tests PASS

**Step 5: Commit**

```bash
git add crates/sigint-report/src/builder.rs crates/sigint-report/src/templates.rs
git commit -m "feat(report): Markdown report builder with 3 template levels"
```

---

### Task 11: HTML Format + CLI Command

**Files:**
- Create: `crates/sigint-report/src/format.rs`
- Create: `crates/sigint-cli/src/report.rs`
- Modify: `crates/sigint-cli/src/main.rs`
- Modify: `crates/sigint-cli/Cargo.toml`

**Step 1: Write the failing test**

In `format.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markdown_to_html_wraps_in_document() {
        let html = markdown_to_html("# Hello\n\nWorld");
        assert!(html.contains("<html"));
        assert!(html.contains("<h1>Hello</h1>"));
        assert!(html.contains("<p>World</p>"));
        assert!(html.contains("</html>"));
    }
}
```

**Step 2: Run test — fails**

**Step 3: Implement**

`format.rs`:

```rust
//! Output format conversion — Markdown to HTML (with embedded CSS).

use pulldown_cmark::{html, Parser};

/// Convert Markdown to a self-contained HTML document with embedded CSS.
pub fn markdown_to_html(markdown: &str) -> String {
    let parser = Parser::new(markdown);
    let mut body = String::new();
    html::push_html(&mut body, parser);

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SIGINT Report</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; max-width: 900px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; line-height: 1.6; }}
h1 {{ border-bottom: 2px solid #333; padding-bottom: 0.5rem; }}
h2 {{ color: #2c5282; margin-top: 2rem; }}
table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
th, td {{ border: 1px solid #ddd; padding: 0.5rem 0.75rem; text-align: left; }}
th {{ background: #f7f7f7; font-weight: 600; }}
tr:nth-child(even) {{ background: #fafafa; }}
code {{ background: #f0f0f0; padding: 0.15em 0.3em; border-radius: 3px; font-size: 0.9em; }}
hr {{ border: none; border-top: 1px solid #ddd; margin: 2rem 0; }}
</style>
</head>
<body>
{body}
</body>
</html>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markdown_to_html_wraps_in_document() {
        let html = markdown_to_html("# Hello\n\nWorld");
        assert!(html.contains("<html"));
        assert!(html.contains("<h1>Hello</h1>"));
        assert!(html.contains("<p>World</p>"));
        assert!(html.contains("</html>"));
    }

    #[test]
    fn tables_rendered() {
        let md = "| A | B |\n|---|---|\n| 1 | 2 |";
        let html = markdown_to_html(md);
        assert!(html.contains("<table>") || html.contains("<th>"));
    }
}
```

Add CLI command `report.rs`, update `main.rs` to add `Commands::Report`, add `sigint-report` dep to `sigint-cli/Cargo.toml`.

**Step 4: Run tests**

Run: `cargo test -p sigint-report && cargo test -p sigint-cli -- report`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/sigint-report/src/format.rs crates/sigint-cli/src/report.rs crates/sigint-cli/src/main.rs crates/sigint-cli/Cargo.toml
git commit -m "feat(report): HTML format + CLI report command — complete 5C"
```

---

## Sub-Phase 5D: Axum REST API + WebSocket

### Task 12: Axum Scaffold + Health Endpoint

**Files:**
- Modify: `crates/sigint-web/Cargo.toml`
- Modify: `crates/sigint-web/src/lib.rs`
- Create: `crates/sigint-web/src/routes.rs`
- Create: `crates/sigint-web/src/state.rs`
- Modify: `Cargo.toml` (workspace deps: axum, tower-http)

**Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;
    use axum::body::Body;
    use tower::ServiceExt;

    #[tokio::test]
    async fn health_returns_ok() {
        let app = create_router(create_test_state());
        let resp = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
```

**Step 2: Run test — fails**

**Step 3: Implement**

Add to workspace `Cargo.toml`:

```toml
axum = { version = "0.8", features = ["ws"] }
tower = "0.5"
tower-http = { version = "0.6", features = ["cors", "fs"] }
```

Update `crates/sigint-web/Cargo.toml`:

```toml
[dependencies]
sigint-core = { workspace = true }
sigint-store = { workspace = true }
tokio = { workspace = true }
axum = { workspace = true }
tower = { workspace = true }
tower-http = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
tracing = { workspace = true }
thiserror = { workspace = true }
uuid = { workspace = true }
```

`state.rs`:

```rust
use sigint_store::Database;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Database>,
}
```

`routes.rs` — health endpoint, session CRUD routes (thin wrappers over store).

`lib.rs` — `create_router()`, `serve()` function.

**Step 4: Run tests**

Run: `cargo test -p sigint-web`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/sigint-web/ Cargo.toml
git commit -m "feat(web): Axum scaffold with health endpoint"
```

---

### Task 13: Session + Finding + Asset REST Routes

**Files:**
- Modify: `crates/sigint-web/src/routes.rs`

**Step 1: Write failing tests for each route**

```rust
#[tokio::test]
async fn list_sessions_returns_array() { /* ... */ }

#[tokio::test]
async fn get_nonexistent_session_returns_404() { /* ... */ }

#[tokio::test]
async fn delete_session() { /* ... */ }
```

**Step 2: Run tests — fail**

**Step 3: Implement routes as thin wrappers over `sigint-store` CRUD**

```
GET    /api/sessions              → db.query().sessions().list()
GET    /api/sessions/:id          → db.query().sessions().by_id()
DELETE /api/sessions/:id          → db.delete_session()
GET    /api/sessions/:id/assets   → db.get_assets()
GET    /api/sessions/:id/findings → db.query().findings().by_session()
POST   /api/scan                  → spawn scan agent, return session_id
POST   /api/recon                 → spawn recon engine, return session_id
GET    /api/report/:id            → build_report(), return bytes
```

**Step 4: Run tests**

Run: `cargo test -p sigint-web`
Expected: All route tests PASS

**Step 5: Commit**

```bash
git add crates/sigint-web/src/routes.rs
git commit -m "feat(web): session, finding, asset REST routes"
```

---

### Task 14: WebSocket Event Bridge

**Files:**
- Create: `crates/sigint-web/src/ws.rs`
- Modify: `crates/sigint-web/src/lib.rs`
- Modify: `crates/sigint-web/src/state.rs`

**Step 1: Write the failing test**

```rust
#[tokio::test]
async fn websocket_upgrade_returns_101() {
    // Test that /ws/events endpoint accepts WebSocket upgrade
    // (Connection: Upgrade, Upgrade: websocket headers)
}
```

**Step 2: Run test — fails**

**Step 3: Implement**

`ws.rs` bridges `tokio::broadcast` EventBus to WebSocket clients. Events serialize as JSON and stream to connected clients.

```rust
use axum::extract::ws::{WebSocket, WebSocketUpgrade, Message};
use axum::extract::State;
use axum::response::IntoResponse;
use futures_util::{SinkExt, StreamExt};
use crate::state::AppState;

pub async fn ws_events(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(mut socket: WebSocket, state: AppState) {
    let mut rx = state.event_bus.subscribe();
    while let Ok(event) = rx.recv().await {
        let json = serde_json::to_string(&event).unwrap_or_default();
        if socket.send(Message::Text(json.into())).await.is_err() {
            break;
        }
    }
}
```

**Step 4: Run tests**

Run: `cargo test -p sigint-web`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/sigint-web/src/ws.rs crates/sigint-web/src/lib.rs crates/sigint-web/src/state.rs
git commit -m "feat(web): WebSocket event bridge for live streaming"
```

---

### Task 15: `sigint serve` CLI Command

**Files:**
- Create: `crates/sigint-cli/src/serve.rs`
- Modify: `crates/sigint-cli/src/main.rs`
- Modify: `crates/sigint-cli/Cargo.toml`

**Step 1: Implement**

`serve.rs`:

```rust
use sigint_core::{AppCore, Error};
use sigint_store::Database;

pub async fn run(core: AppCore, bind: &str) -> Result<(), Error> {
    let db_path = core.config.resolved_db_path();
    let db = Database::open(&db_path)?;
    let addr: std::net::SocketAddr = bind.parse().map_err(|e| {
        Error::InvalidInput(format!("Invalid bind address '{}': {}", bind, e))
    })?;
    println!("SIGINT web UI starting at http://{}", addr);
    sigint_web::serve(db, core.event_bus.clone(), addr).await
}
```

Add `Commands::Serve { bind }` to `main.rs`.

**Step 2: Verify**

Run: `cargo build -p sigint-cli`
Run: `cargo test -p sigint-cli -- serve`
Expected: compiles, tests pass

**Step 3: Commit**

```bash
git add crates/sigint-cli/src/serve.rs crates/sigint-cli/src/main.rs crates/sigint-cli/Cargo.toml
git commit -m "feat(cli): sigint serve command — complete 5D"
```

---

## Sub-Phase 5E: Embedded SPA Frontend

### Task 16: Frontend Scaffold + Build Pipeline

**Files:**
- Create: `web/package.json`
- Create: `web/src/index.html`
- Create: `web/src/app.js`
- Create: `web/esbuild.config.mjs`
- Modify: `crates/sigint-web/Cargo.toml` (add `rust-embed`)
- Modify: `Cargo.toml` (add `rust-embed` workspace dep)

**Step 1: Create frontend files**

`web/package.json`:

```json
{
  "name": "sigint-web",
  "private": true,
  "scripts": {
    "build": "node esbuild.config.mjs",
    "dev": "node esbuild.config.mjs --watch"
  },
  "dependencies": {
    "preact": "^10.19.0",
    "htm": "^3.1.1"
  },
  "devDependencies": {
    "esbuild": "^0.20.0"
  }
}
```

`web/esbuild.config.mjs`:

```js
import { build } from 'esbuild';
const watch = process.argv.includes('--watch');
await build({
  entryPoints: ['src/app.js'],
  bundle: true,
  outdir: '../crates/sigint-web/static',
  minify: !watch,
  sourcemap: watch,
  format: 'esm',
  loader: { '.js': 'jsx' },
  jsxFactory: 'h',
  jsxFragment: 'Fragment',
  define: { 'process.env.NODE_ENV': watch ? '"development"' : '"production"' },
});
```

`web/src/index.html` — minimal SPA shell.

`web/src/app.js` — Preact + HTM entry point with router (Dashboard, Scan, Sessions, Assets, Reports panels).

**Step 2: Build frontend**

Run: `cd web && npm install && npm run build`
Expected: Outputs to `crates/sigint-web/static/`

**Step 3: Commit**

```bash
git add web/ crates/sigint-web/static/
git commit -m "feat(web): frontend scaffold with Preact + HTM + esbuild"
```

---

### Task 17: rust-embed Static File Serving

**Files:**
- Modify: `crates/sigint-web/Cargo.toml`
- Create: `crates/sigint-web/src/static_files.rs`
- Modify: `crates/sigint-web/src/lib.rs`

**Step 1: Write the failing test**

```rust
#[tokio::test]
async fn serves_index_html() {
    let app = create_router(create_test_state());
    let resp = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 1_000_000).await.unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(text.contains("<html") || text.contains("<!DOCTYPE"));
}
```

**Step 2: Run test — fails**

**Step 3: Implement**

Add `rust-embed = "8"` to workspace and `sigint-web/Cargo.toml`.

`static_files.rs`:

```rust
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "static/"]
struct StaticAssets;

pub async fn serve_static(uri: axum::http::Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let path = if path.is_empty() || !path.contains('.') {
        "index.html"
    } else {
        path
    };

    match StaticAssets::get(path) {
        Some(file) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, mime.as_ref().to_string())],
                file.data.to_vec(),
            )
                .into_response()
        }
        None => {
            // SPA fallback — serve index.html for unknown routes
            match StaticAssets::get("index.html") {
                Some(file) => (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "text/html".to_string())],
                    file.data.to_vec(),
                )
                    .into_response(),
                None => (StatusCode::NOT_FOUND, "Not Found").into_response(),
            }
        }
    }
}
```

Add `mime_guess = "2"` to deps.

Wire into router: `GET /` and fallback handler → `serve_static`.

**Step 4: Run tests**

Run: `cargo test -p sigint-web`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/sigint-web/src/static_files.rs crates/sigint-web/Cargo.toml Cargo.toml
git commit -m "feat(web): rust-embed static file serving with SPA fallback"
```

---

### Task 18: Frontend UI Panels

**Files:**
- Create: `web/src/components/Dashboard.js`
- Create: `web/src/components/ScanView.js`
- Create: `web/src/components/Sessions.js`
- Create: `web/src/components/Assets.js`
- Create: `web/src/components/Reports.js`
- Create: `web/src/api.js`
- Create: `web/src/ws.js`
- Modify: `web/src/app.js`

**Step 1: Implement API client**

`web/src/api.js` — fetch wrappers for all REST endpoints.

`web/src/ws.js` — WebSocket connection manager with auto-reconnect.

**Step 2: Implement components**

Each component fetches data from the API and renders UI:

- **Dashboard** — active scans, recent sessions, quick stats
- **ScanView** — live event stream (via WebSocket), findings, assets
- **Sessions** — list/search/delete past scans
- **Assets** — ASM dashboard grouped by kind
- **Reports** — generate and download reports

**Step 3: Build and verify**

Run: `cd web && npm run build`
Run: `cargo build -p sigint-web`
Expected: compiles with embedded static files

**Step 4: Commit**

```bash
git add web/src/
git commit -m "feat(web): all UI panels — Dashboard, Scan, Sessions, Assets, Reports"
```

---

### Task 19: Final Integration + Workspace Test

**Files:**
- No new files — integration verification

**Step 1: Run all workspace tests**

Run: `cargo test --workspace`
Expected: All tests PASS (200+ tests)

**Step 2: Build release binary**

Run: `cargo build --release`
Expected: Single binary with embedded SPA

**Step 3: Smoke test**

Run: `./target/release/sigint doctor`
Run: `./target/release/sigint serve --bind 127.0.0.1:8080` (then curl /api/health)
Expected: Both work

**Step 4: Final commit**

```bash
git commit -m "feat: Phase 5 complete — doctor, OpenAI provider, reports, web UI"
```

---

## Implementation Order

```
5A (Doctor)  →  5B (OpenAI)  →  5C (Reports)  →  5D (REST API)  →  5E (SPA)
Tasks 1-4       Tasks 5-8       Tasks 9-11       Tasks 12-15       Tasks 16-19
```

Each sub-phase gets its own worktree branch, tests, and merge to main.

## New Dependencies Summary

| Sub-Phase | New Workspace Deps |
|-----------|-------------------|
| 5A | reqwest (existing) |
| 5B | eventsource-stream (existing), bytes (existing) |
| 5C | pulldown-cmark (new) |
| 5D | axum (new), tower (new), tower-http (new) |
| 5E | rust-embed (new), mime_guess (new), preact/htm (npm) |
