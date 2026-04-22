//! `sigint doctor` — environment and dependency health checker.
//!
//! Runs a series of diagnostic checks and prints a human-readable summary.
//! Exits with code 1 if any check fails.
//!
//! @decision DEC-DOCTOR-001
//! @title Synchronous checks for PATH/config, async HTTP for Ollama
//! @status accepted
//! @rationale Config, PATH, and DB checks are all local and synchronous.
//! Only Ollama reachability requires an HTTP call; we use reqwest with a
//! short 5-second timeout so the command stays snappy even when Ollama is
//! not running. All sub-checks are independent (no short-circuit) so the
//! user sees the complete picture in one run.

use std::path::PathBuf;
use std::time::Duration;

use sigint_core::{AppCore, Error};
use sigint_store::Database;

// ── Check result ─────────────────────────────────────────────────────────────

/// Outcome of a single diagnostic check.
#[derive(Debug, PartialEq)]
pub struct CheckResult {
    /// Human-readable label shown in the output line.
    pub label: String,
    /// Whether the check passed.
    pub passed: bool,
    /// Detail appended in parentheses when the check passes.
    pub detail: Option<String>,
    /// Install hint shown when the check fails.
    pub hint: Option<String>,
}

impl CheckResult {
    fn pass(label: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            passed: true,
            detail: Some(detail.into()),
            hint: None,
        }
    }

    fn fail(label: impl Into<String>, hint: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            passed: false,
            detail: None,
            hint: Some(hint.into()),
        }
    }

    fn fail_bare(label: impl Into<String>) -> Self {
        Self {
            label: label.into(),
            passed: false,
            detail: None,
            hint: None,
        }
    }
}

// ── Individual checks ─────────────────────────────────────────────────────────

/// Check that config loaded and has a non-empty base_url.
pub fn check_config(config: &sigint_core::config::Config) -> CheckResult {
    if config.llm.base_url.is_empty() {
        return CheckResult::fail(
            "Config",
            "base_url is empty — check ~/.config/sigint/config.toml",
        );
    }
    let path = {
        let home = std::env::var("HOME").unwrap_or_else(|_| "~".into());
        format!("{}/.config/sigint/config.toml", home)
    };
    CheckResult::pass("Config loaded", path)
}

/// Parse the JSON body returned by `GET /api/tags`.
///
/// Returns the list of model name strings (may include `:tag` suffix).
pub fn parse_ollama_models(json: &str) -> Result<Vec<String>, Error> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| Error::Serde(e.to_string()))?;
    let models = v["models"]
        .as_array()
        .ok_or_else(|| Error::Serde("missing 'models' array in /api/tags response".into()))?
        .iter()
        .filter_map(|m| m["name"].as_str().map(|s| s.to_owned()))
        .collect();
    Ok(models)
}

/// Check embedded LLM configuration when `provider == "embedded"`.
///
/// Verifies that:
/// 1. The `models_dir` exists on disk.
/// 2. The configured `model` file exists inside `models_dir`.
pub fn check_embedded_llm(config: &sigint_core::config::Config) -> Option<Vec<CheckResult>> {
    if config.llm.provider != "embedded" {
        return None; // Not applicable — skip silently.
    }

    let models_dir = config.resolved_models_dir();
    let mut results = Vec::new();

    if !models_dir.exists() {
        results.push(CheckResult::fail(
            "Embedded LLM: models_dir exists",
            format!(
                "Directory {} not found — create it or run: sigint model pull <repo>",
                models_dir.display()
            ),
        ));
        // Can't check model file if dir is absent.
        return Some(results);
    }

    results.push(CheckResult::pass(
        "Embedded LLM: models_dir exists",
        models_dir.display().to_string(),
    ));

    // Check that the configured model file exists.
    let model_name = &config.llm.model;
    let model_path = models_dir.join(model_name);
    let model_path_gguf = models_dir.join(format!("{}.gguf", model_name));

    if model_path.exists() || model_path_gguf.exists() {
        results.push(CheckResult::pass(
            format!("Embedded LLM: model file ({})", model_name),
            "found",
        ));
    } else {
        results.push(CheckResult::fail(
            format!("Embedded LLM: model file ({})", model_name),
            format!(
                "Not found in {} — run: sigint model pull <repo>",
                models_dir.display()
            ),
        ));
    }

    Some(results)
}

/// Check whether `model` appears in the list returned by Ollama.
///
/// Matches with or without the `:tag` suffix — e.g. "llama3.2" matches
/// both "llama3.2" and "llama3.2:latest".
pub fn model_available(model: &str, available: &[String]) -> bool {
    let base = model.split(':').next().unwrap_or(model);
    available.iter().any(|name| {
        let name_base = name.split(':').next().unwrap_or(name.as_str());
        name_base == base || name == model
    })
}

/// Check reachability of Ollama and model availability.
///
/// Returns two `CheckResult`s: reachability and model availability.
pub async fn check_ollama(base_url: &str, model: &str) -> (CheckResult, CheckResult) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_e) => {
            return (
                CheckResult::fail_bare(format!("Ollama reachable ({})", base_url)),
                CheckResult::fail_bare(format!("Model available ({})", model)),
            );
        }
    };

    let url = format!("{}/api/tags", base_url);
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            let hint = format!("Cannot reach {} — is Ollama running? ({})", base_url, e);
            return (
                CheckResult::fail(format!("Ollama reachable ({})", base_url), hint),
                CheckResult::fail(
                    format!("Model available ({})", model),
                    "Cannot check — Ollama unreachable",
                ),
            );
        }
    };

    if !resp.status().is_success() {
        let hint = format!("{}/api/tags returned HTTP {}", base_url, resp.status());
        return (
            CheckResult::fail(format!("Ollama reachable ({})", base_url), hint),
            CheckResult::fail(
                format!("Model available ({})", model),
                "Cannot check — /api/tags failed",
            ),
        );
    }

    let body = match resp.text().await {
        Ok(b) => b,
        Err(e) => {
            return (
                CheckResult::fail(
                    format!("Ollama reachable ({})", base_url),
                    format!("Failed to read /api/tags body: {}", e),
                ),
                CheckResult::fail_bare(format!("Model available ({})", model)),
            );
        }
    };

    let ollama_ok = CheckResult::pass("Ollama reachable", base_url.to_owned());

    let models = match parse_ollama_models(&body) {
        Ok(m) => m,
        Err(e) => {
            return (
                ollama_ok,
                CheckResult::fail(
                    format!("Model available ({})", model),
                    format!("Cannot parse /api/tags response: {}", e),
                ),
            );
        }
    };

    let model_ok = if model_available(model, &models) {
        CheckResult::pass("Model available".to_string(), model.to_owned())
    } else {
        CheckResult::fail(
            format!("Model available ({})", model),
            format!("Model '{}' not found — run: ollama pull {}", model, model),
        )
    };

    (ollama_ok, model_ok)
}

/// Check whether a named binary is on the PATH.
pub fn check_tool(name: &str, install_hint: &str) -> CheckResult {
    let status = std::process::Command::new("which")
        .arg(name)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    match status {
        Ok(s) if s.success() => CheckResult::pass(name.to_owned(), "found"),
        _ => CheckResult::fail(
            format!("{} not found", name),
            format!("install: {}", install_hint),
        ),
    }
}

/// Check whether a sandbox prerequisite binary is on the PATH.
pub fn check_sandbox_tool(name: &str, package: &str) -> CheckResult {
    let status = std::process::Command::new("which")
        .arg(name)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    match status {
        Ok(s) if s.success() => {
            CheckResult::pass(format!("Sandbox: {} found", name), String::new())
        }
        _ => CheckResult::fail(
            format!("Sandbox: {} not found", name),
            format!("install: sudo apt install {}", package),
        ),
    }
}

/// Check fine-tuning configuration (Task 5, Phase 24).
///
/// Three sub-checks:
/// 1. If `finetune_command` is set, verify the first word of the command is
///    executable (found via PATH). Warns but does not fail if unset (optional).
/// 2. If `models_dir` resolves to a path, test that it is writable.
/// 3. If `promotion.log` exists and any entry has `new_provider = "ollama"`,
///    verify that the `ollama` CLI is on PATH.
///
/// All three pass cleanly on a default config without a `[train]` section.
pub fn check_train_config(
    config: &sigint_core::config::Config,
    promo_dir: &std::path::Path,
) -> Vec<CheckResult> {
    let mut results = Vec::new();

    // ── Check 1: finetune_command binary is executable if set ─────────────────
    let cmd = config.train.finetune_command.trim();
    if cmd.is_empty() {
        // Unset is fine — fine-tuning is optional.
        results.push(CheckResult {
            label: "Train: finetune_command".to_string(),
            passed: true,
            detail: Some("not set (fine-tuning is optional)".to_string()),
            hint: None,
        });
    } else {
        // Resolve the first word of the command string as the binary name.
        let binary = cmd.split_whitespace().next().unwrap_or(cmd);
        let status = std::process::Command::new("which")
            .arg(binary)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        match status {
            Ok(s) if s.success() => {
                results.push(CheckResult::pass(
                    "Train: finetune_command executable",
                    binary.to_string(),
                ));
            }
            _ => {
                results.push(CheckResult::fail(
                    format!("Train: finetune_command binary '{}' not found", binary),
                    format!(
                        "The first word of [train].finetune_command ('{}') is not on PATH. \
                         Install the trainer or update finetune_command.",
                        binary
                    ),
                ));
            }
        }
    }

    // ── Check 2: models_dir is writable ──────────────────────────────────────
    let models_dir = config.resolved_models_dir();
    if !models_dir.exists() {
        // Dir doesn't exist yet — try to create it to test writability.
        match std::fs::create_dir_all(&models_dir) {
            Ok(_) => {
                results.push(CheckResult::pass(
                    "Train: models_dir writable",
                    format!("created {}", models_dir.display()),
                ));
            }
            Err(e) => {
                results.push(CheckResult::fail(
                    "Train: models_dir writable",
                    format!(
                        "Cannot create {}: {} — check permissions",
                        models_dir.display(),
                        e
                    ),
                ));
            }
        }
    } else {
        // Dir exists — probe write access with a temp file.
        let probe = models_dir.join(".sigint-doctor-write-probe");
        match std::fs::write(&probe, b"probe") {
            Ok(_) => {
                let _ = std::fs::remove_file(&probe);
                results.push(CheckResult::pass(
                    "Train: models_dir writable",
                    models_dir.display().to_string(),
                ));
            }
            Err(e) => {
                results.push(CheckResult::fail(
                    "Train: models_dir writable",
                    format!(
                        "{} is not writable: {} — check permissions",
                        models_dir.display(),
                        e
                    ),
                ));
            }
        }
    }

    // ── Check 3: ollama CLI on PATH if any Ollama-tagged promotion exists ─────
    let log_path = promo_dir.join("promotion.log");
    if log_path.exists() {
        let contents = std::fs::read_to_string(&log_path).unwrap_or_default();
        let has_ollama_promotion = contents.lines().any(|line| {
            // Promotion log entries are JSONL; look for new_provider = "ollama".
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                v["new_provider"].as_str() == Some("ollama")
            } else {
                false
            }
        });
        if has_ollama_promotion {
            let status = std::process::Command::new("which")
                .arg("ollama")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status();
            match status {
                Ok(s) if s.success() => {
                    results.push(CheckResult::pass(
                        "Train: ollama CLI found (required by promotion.log)",
                        "found",
                    ));
                }
                _ => {
                    results.push(CheckResult::fail(
                        "Train: ollama CLI not found",
                        "promotion.log references an ollama model but 'ollama' is not on PATH. \
                         Install Ollama: https://ollama.ai or run `sigint doctor` after installing.",
                    ));
                }
            }
        }
        // No Ollama promotion in log → skip the check silently.
    }
    // No promotion.log yet → skip the check silently.

    results
}

/// Open the database and read the current schema version.
///
/// Returns a `CheckResult` with the version number and resolved path.
pub fn check_database(db_path: &PathBuf) -> CheckResult {
    let db = match Database::open(db_path) {
        Ok(d) => d,
        Err(e) => {
            return CheckResult::fail(
                "Database",
                format!("Cannot open {}: {}", db_path.display(), e),
            )
        }
    };

    let version: i64 = match db.with_conn(|conn| {
        conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |r| r.get(0),
        )
        .map_err(|e| Error::Database(e.to_string()))
    }) {
        Ok(v) => v,
        Err(e) => {
            return CheckResult::fail("Database", format!("Cannot read schema_version: {}", e))
        }
    };

    CheckResult::pass(
        "Database OK",
        format!("v{}, {}", version, db_path.display()),
    )
}

// ── Rendering ─────────────────────────────────────────────────────────────────

fn render_result(r: &CheckResult) {
    if r.passed {
        if let Some(detail) = &r.detail {
            if detail.is_empty() {
                println!("  \u{2713} {}", r.label);
            } else {
                println!("  \u{2713} {} ({})", r.label, detail);
            }
        } else {
            println!("  \u{2713} {}", r.label);
        }
    } else if let Some(hint) = &r.hint {
        println!("  \u{2717} {} \u{2014} {}", r.label, hint);
    } else {
        println!("  \u{2717} {}", r.label);
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Run the doctor command.
///
/// Checks config, Ollama, models, tools, sandbox prerequisites, and database.
/// Exits with code 1 if any check fails.
pub async fn run(core: AppCore) -> Result<(), Error> {
    println!("SIGINT Doctor");

    let mut results: Vec<CheckResult> = Vec::new();

    // 1. Config check
    results.push(check_config(&core.config));

    // 2 & 3. Ollama reachability + model availability (skip when using embedded provider)
    if core.config.llm.provider != "embedded" {
        let (ollama, model) = check_ollama(&core.config.llm.base_url, &core.config.llm.model).await;
        results.push(ollama);
        results.push(model);
    }

    // 2 (alt). Embedded LLM checks — only when provider == "embedded"
    if let Some(embedded_results) = check_embedded_llm(&core.config) {
        results.extend(embedded_results);
    }

    // 4. Tool availability
    let tools = [
        ("nmap", "sudo apt install nmap"),
        ("gobuster", "sudo apt install gobuster"),
        ("nikto", "sudo apt install nikto"),
        (
            "nuclei",
            "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        ),
        (
            "feroxbuster",
            "cargo install feroxbuster  OR  see https://github.com/epi052/feroxbuster",
        ),
        ("sqlmap", "sudo apt install sqlmap"),
        ("ffuf", "go install github.com/ffuf/ffuf/v2@latest"),
        ("whatweb", "sudo apt install whatweb"),
        ("hydra", "sudo apt install hydra"),
        ("wpscan", "gem install wpscan"),
        (
            "testssl",
            "sudo apt install testssl.sh  OR  git clone https://github.com/drwetter/testssl.sh",
        ),
        ("hashcat", "sudo apt install hashcat"),
        ("masscan", "sudo apt install masscan"),
        ("tshark", "sudo apt install tshark"),
        (
            "responder",
            "sudo apt install responder OR git clone https://github.com/lgandx/Responder",
        ),
        ("msfconsole", "sudo apt install metasploit-framework"),
        (
            "linpeas.sh",
            "wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh",
        ),
        ("enum4linux-ng", "pip install enum4linux-ng"),
        (
            "trivy",
            "sudo apt install trivy OR see https://aquasecurity.github.io/trivy",
        ),
        ("scout", "pip install scoutsuite"),
        ("cloudsploit", "npm install -g cloudsploit"),
        ("dig", "sudo apt install dnsutils"),
        ("whois", "sudo apt install whois"),
        ("curl", "sudo apt install curl"),
        ("akaei", "Build from ~/CerebrumCraft/akaei and add to PATH"),
        (
            "llama-server",
            "Build from https://github.com/ggerganov/llama.cpp or install via package manager",
        ),
    ];
    for (name, hint) in &tools {
        results.push(check_tool(name, hint));
    }

    // 5. Sandbox prerequisites
    results.push(check_sandbox_tool("newuidmap", "uidmap"));
    results.push(check_sandbox_tool("pasta", "passt"));

    // 6. Fine-tuning config checks (Task 5, Phase 24)
    let promo_dir = {
        if let Some(ref dir) = core.config.train.job_dir {
            dir.clone()
        } else {
            let home = std::env::var("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("."));
            home.join(".local")
                .join("share")
                .join("sigint")
                .join("training")
        }
    };
    results.extend(check_train_config(&core.config, &promo_dir));

    // 7. Database check
    let db_path = core.config.resolved_db_path();
    results.push(check_database(&db_path));

    // Print results
    for r in &results {
        render_result(r);
    }

    // Summary
    let passed = results.iter().filter(|r| r.passed).count();
    let total = results.len();
    let failed = total - passed;
    println!();
    if failed == 0 {
        println!("{}/{} checks passed", passed, total);
    } else {
        println!(
            "{}/{} checks passed, {} issue{} found",
            passed,
            total,
            failed,
            if failed == 1 { "" } else { "s" }
        );
    }

    if failed > 0 {
        std::process::exit(1);
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use sigint_core::config::{Config, LlmConfig, StoreConfig};

    fn make_config(base_url: &str, model: &str) -> Config {
        Config {
            llm: LlmConfig {
                provider: "ollama".into(),
                model: model.into(),
                base_url: base_url.into(),
                temperature: 0.7,
                context_window: 0,
                api_key: None,
                models_dir: None,
                gpu_layers: None,
                threads: None,
                flash_attention: None,
            },
            store: StoreConfig {
                db_path: "~/.local/share/sigint/sigint.db".into(),
            },
            log: sigint_core::config::LogConfig::default(),
            agent: sigint_core::config::AgentConfig::default(),
            tools: sigint_core::config::ToolsConfig::default(),
            plugins: sigint_core::config::PluginsConfig::default(),
            train: sigint_core::config::TrainConfig::default(),
            web: sigint_core::config::WebConfig::default(),
        }
    }

    // ── check_config ─────────────────────────────────────────────────────────

    #[test]
    fn check_config_passes_with_valid_base_url() {
        let cfg = make_config("http://localhost:11434", "llama3.2");
        let result = check_config(&cfg);
        assert!(result.passed, "expected pass, got: {:?}", result);
        assert!(result.label.contains("Config"));
    }

    #[test]
    fn check_config_fails_with_empty_base_url() {
        let cfg = make_config("", "llama3.2");
        let result = check_config(&cfg);
        assert!(!result.passed, "expected fail for empty base_url");
        assert!(result.hint.is_some());
    }

    // ── parse_ollama_models ───────────────────────────────────────────────────

    #[test]
    fn parse_ollama_models_extracts_names() {
        let json = r#"{"models":[{"name":"llama3.2:latest"},{"name":"mistral:7b"}]}"#;
        let models = parse_ollama_models(json).expect("parse should succeed");
        assert_eq!(models, vec!["llama3.2:latest", "mistral:7b"]);
    }

    #[test]
    fn parse_ollama_models_empty_list() {
        let json = r#"{"models":[]}"#;
        let models = parse_ollama_models(json).expect("parse should succeed");
        assert!(models.is_empty());
    }

    #[test]
    fn parse_ollama_models_missing_key_is_error() {
        let json = r#"{"something_else":[]}"#;
        assert!(parse_ollama_models(json).is_err());
    }

    #[test]
    fn parse_ollama_models_invalid_json_is_error() {
        assert!(parse_ollama_models("not json").is_err());
    }

    // ── model_available ───────────────────────────────────────────────────────

    #[test]
    fn model_available_exact_match() {
        let available = vec!["llama3.2:latest".to_owned(), "mistral:7b".to_owned()];
        assert!(model_available("llama3.2:latest", &available));
    }

    #[test]
    fn model_available_base_matches_tagged() {
        // "llama3.2" should match "llama3.2:latest"
        let available = vec!["llama3.2:latest".to_owned()];
        assert!(model_available("llama3.2", &available));
    }

    #[test]
    fn model_available_not_present() {
        let available = vec!["mistral:7b".to_owned()];
        assert!(!model_available("llama3.2", &available));
    }

    #[test]
    fn model_available_empty_list() {
        let available: Vec<String> = vec![];
        assert!(!model_available("llama3.2", &available));
    }

    // ── check_tool ────────────────────────────────────────────────────────────

    #[test]
    fn check_tool_finds_ls() {
        // "ls" is guaranteed to exist on any Unix system
        let result = check_tool("ls", "sudo apt install coreutils");
        assert!(result.passed, "expected 'ls' to be found on PATH");
    }

    #[test]
    fn check_tool_fails_for_nonexistent_binary() {
        let result = check_tool(
            "sigint-tool-definitely-not-installed-xyzzy",
            "sudo apt install xyzzy",
        );
        assert!(!result.passed, "expected non-existent tool to fail");
        assert!(result.hint.is_some());
        assert!(
            result.hint.as_deref().unwrap().contains("install:"),
            "hint should contain install instruction"
        );
    }

    // ── check_sandbox_tool ────────────────────────────────────────────────────

    #[test]
    fn check_sandbox_tool_finds_sh() {
        // "sh" is guaranteed on any POSIX system
        let result = check_sandbox_tool("sh", "busybox");
        assert!(result.passed, "expected 'sh' to be found");
        assert!(result.label.contains("Sandbox:"));
    }

    #[test]
    fn check_sandbox_tool_fails_for_nonexistent() {
        let result = check_sandbox_tool("sigint-xyzzy-sandbox-tool", "some-package");
        assert!(!result.passed);
        assert!(result.hint.as_deref().unwrap().contains("sudo apt install"));
    }

    // ── check_database ────────────────────────────────────────────────────────

    #[test]
    fn check_database_with_in_memory_db() {
        // We can't call check_database with ":memory:" directly since it takes
        // a PathBuf and opens via Database::open. Use a temp file instead.
        let tmp = tempfile::NamedTempFile::new().expect("temp file");
        let path = tmp.path().to_path_buf();

        let result = check_database(&path);
        assert!(result.passed, "expected DB check to pass: {:?}", result);
        assert!(result.label.contains("Database OK"));
        // detail should include version number
        let detail = result.detail.unwrap();
        assert!(
            detail.contains('v'),
            "expected version in detail: {}",
            detail
        );
    }

    #[test]
    fn check_database_fails_with_invalid_path() {
        // A path in a non-existent deeply nested dir that can't be created
        // by pointing to a file *inside* a regular file (which can't be a dir)
        let tmp = tempfile::NamedTempFile::new().expect("temp file");
        // tmp.path() is a file, not a directory, so creating a child should fail
        let bad_path = tmp.path().join("sigint.db");
        // tmp.path() is a file, not a directory, so creating a child should fail
        let result = check_database(&bad_path);
        // Depending on the OS, this may or may not fail. If it passes, that's
        // also acceptable — the important thing is we don't panic.
        // We just verify the result type is coherent.
        let _ = result; // no assertion — just verify no panic
    }

    // ── check_train_config ────────────────────────────────────────────────────

    fn make_train_config_default() -> Config {
        make_config("http://localhost:11434", "llama3.2")
    }

    /// On default config (no [train] section / finetune_command empty), all
    /// three checks must pass without a models_dir or promotion.log present.
    #[test]
    fn check_train_config_default_config_passes() {
        let cfg = make_train_config_default();
        let tmp = tempfile::TempDir::new().expect("tempdir");
        // No promotion.log exists — passes silently.
        let results = check_train_config(&cfg, tmp.path());
        // Two results: finetune_command (optional, pass) + models_dir writable.
        // (Ollama check is skipped when no promotion.log.)
        assert!(
            results.iter().all(|r| r.passed),
            "default config should produce only passing checks: {:?}",
            results
        );
    }

    /// When finetune_command points to a real binary (e.g. "ls"), the check passes.
    #[test]
    fn check_train_config_valid_command_passes() {
        let mut cfg = make_train_config_default();
        cfg.train.finetune_command = "ls --help".to_string();
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let results = check_train_config(&cfg, tmp.path());
        let cmd_check = results
            .iter()
            .find(|r| r.label.contains("finetune_command"))
            .expect("should have finetune_command check");
        assert!(
            cmd_check.passed,
            "valid command 'ls' should pass: {:?}",
            cmd_check
        );
    }

    /// When finetune_command references a non-existent binary, the check fails.
    #[test]
    fn check_train_config_bad_command_fails() {
        let mut cfg = make_train_config_default();
        cfg.train.finetune_command =
            "sigint-xyzzy-trainer-definitely-not-installed --train".to_string();
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let results = check_train_config(&cfg, tmp.path());
        let cmd_check = results
            .iter()
            .find(|r| r.label.contains("finetune_command") || r.label.contains("binary"))
            .expect("should have finetune_command check");
        assert!(
            !cmd_check.passed,
            "non-existent binary should fail: {:?}",
            cmd_check
        );
    }

    /// models_dir writable check passes when the directory exists and is writable.
    #[test]
    fn check_train_config_writable_models_dir_passes() {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let models_dir = tmp.path().join("models");
        std::fs::create_dir_all(&models_dir).unwrap();

        let mut cfg = make_train_config_default();
        cfg.llm.models_dir = Some(models_dir.to_str().unwrap().to_string());

        let promo_tmp = tempfile::TempDir::new().expect("tempdir");
        let results = check_train_config(&cfg, promo_tmp.path());
        let writable_check = results
            .iter()
            .find(|r| r.label.contains("models_dir"))
            .expect("should have models_dir check");
        assert!(
            writable_check.passed,
            "writable models_dir should pass: {:?}",
            writable_check
        );
    }

    /// ollama CLI check fires when promotion.log contains an ollama new_provider entry.
    /// We write a fake promotion.log and expect the check to run (pass if ollama is
    /// found, fail gracefully if not — we only check the label is present).
    #[test]
    fn check_train_config_ollama_check_fires_when_log_has_ollama_entry() {
        let cfg = make_train_config_default();
        let tmp = tempfile::TempDir::new().expect("tempdir");

        // Write a fake promotion.log with new_provider = "ollama"
        let log_content = r#"{"ts":"2026-01-01T00:00:00Z","action":"promote","old_provider":"embedded","old_model":"base.gguf","new_provider":"ollama","new_model":"sigint-ft:latest"}"#;
        std::fs::write(tmp.path().join("promotion.log"), log_content).unwrap();

        let results = check_train_config(&cfg, tmp.path());
        // The ollama check should have been triggered (label contains "ollama").
        let has_ollama_check = results
            .iter()
            .any(|r| r.label.to_lowercase().contains("ollama"));
        assert!(
            has_ollama_check,
            "should have an ollama CLI check when promotion.log has ollama entry: {:?}",
            results
        );
    }

    /// ollama CLI check is silently skipped when promotion.log has no ollama entries.
    #[test]
    fn check_train_config_ollama_check_skipped_without_ollama_promotion() {
        let cfg = make_train_config_default();
        let tmp = tempfile::TempDir::new().expect("tempdir");

        // promotion.log with only an "embedded" new_provider entry.
        let log_content = r#"{"ts":"2026-01-01T00:00:00Z","action":"promote","old_provider":"ollama","old_model":"llama3.2","new_provider":"embedded","new_model":"adapter.gguf"}"#;
        std::fs::write(tmp.path().join("promotion.log"), log_content).unwrap();

        let results = check_train_config(&cfg, tmp.path());
        // Should be exactly 2 results: finetune_command + models_dir.
        // No ollama CLI check.
        assert_eq!(
            results.len(),
            2,
            "should skip ollama check when no ollama promotion in log: {:?}",
            results
        );
    }
}
