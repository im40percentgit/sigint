//! End-to-end smoke test for the full fine-tune closed loop.
//!
//! Exercises the complete chain against an in-memory DB:
//!   harvest -> export -> finetune (mock command) -> evaluate (MockProvider)
//!     -> promote (via sigint binary) -> rollback (via sigint binary)
//!
//! Validates every config-state transition and that promotion.log accumulates
//! correctly across the round trip.
//!
//! @decision DEC-P24-TEST-002
//! @title E2E smoke test uses in-memory DB + mock trainer + MockProvider
//! @status accepted
//! @rationale Integration tests must be hermetic (no Ollama, no real GPU).
//! The finetune step uses `cp` as the mock trainer (portable, fast).
//! Evaluation uses MockProvider from sigint-llm (DEC-LLM-003) to return
//! canned tool-call predictions. Promote/rollback are tested via the real
//! sigint binary to validate the CLI exit-code contract (same approach as
//! promote_rollback.rs in sigint-cli). The combination covers the full
//! harvest-to-rollback path without network or GPU dependencies.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use sigint_core::types::Session;
use sigint_llm::{MockProvider, MockResponse};
use sigint_store::{db::Database, scans::ScanRecord};
use sigint_train::{
    evaluate::{persist_last_eval, run_comparison},
    extract, finetune, format, split,
};
use tempfile::TempDir;

// -- Helpers ------------------------------------------------------------------

/// Path to the compiled `sigint` binary (mirrors the helper in promote_rollback.rs).
fn sigint_bin() -> PathBuf {
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_sigint") {
        return PathBuf::from(p);
    }
    let exe = std::env::current_exe().expect("current_exe");
    let deps = exe.parent().expect("parent");
    let profile_dir = deps.parent().expect("profile dir");
    profile_dir.join("sigint")
}

/// Seed `count` distinct sessions each with one successful scan record.
///
/// Each session is immediately marked trainable so extract_all picks it up.
fn seed_db(count: usize) -> (Database, Vec<uuid::Uuid>) {
    let db = Database::open_in_memory().expect("in-memory db");
    let mut ids = Vec::with_capacity(count);
    let tools = ["nmap_scan", "gobuster", "shell", "nikto", "masscan"];

    for i in 0..count {
        let name = format!("smoke-session-{}", i);
        let session = Session::new(&name);
        db.create_session(&session).expect("create session");

        let tool = tools[i % tools.len()];
        let args = format!(r#"{{"target":"10.0.0.{}"}}"#, i % 256);
        let mut rec = ScanRecord::new(session.id, tool, &args);
        rec.exit_code = Some(0);
        rec.output = Some(format!("PORT {}/tcp open", 80 + i));
        rec.agent_role = Some("executor".to_string());
        db.create_scan_record(&rec).expect("create scan record");

        // Harvest: opt-in so extract_all includes it.
        db.set_session_trainable(&session.id.to_string(), true)
            .expect("set trainable");

        ids.push(session.id);
    }

    (db, ids)
}

/// Write a minimal config.toml to `$HOME/.config/sigint/config.toml`.
///
/// `min_eval_examples` is written into the `[train]` section so the P1 gate
/// matches the actual test-set size produced by the smoke test's 80/20 split.
fn write_config(home: &std::path::Path, provider: &str, model: &str, min_eval_examples: usize) {
    let config_dir = home.join(".config").join("sigint");
    fs::create_dir_all(&config_dir).unwrap();
    let content = format!(
        "[llm]\nprovider = \"{}\"\nmodel = \"{}\"\n\n[train]\nmin_eval_examples = {}\n",
        provider, model, min_eval_examples
    );
    fs::write(config_dir.join("config.toml"), content).unwrap();
}

/// Read the active `model` field from config.toml in an isolated home.
fn read_active_model(home: &std::path::Path) -> String {
    let path = home.join(".config").join("sigint").join("config.toml");
    let contents = fs::read_to_string(&path).expect("read config");
    for line in contents.lines() {
        if let Some(rest) = line.trim().strip_prefix("model = ") {
            return rest.trim().trim_matches('"').to_string();
        }
    }
    panic!("model field not found:\n{}", contents)
}

fn run_promote(home: &std::path::Path, tag: &str, force: bool) -> std::process::Output {
    let mut cmd = Command::new(sigint_bin());
    cmd.args(["model", "promote", tag]);
    if force {
        cmd.arg("--force");
    }
    cmd.env("HOME", home).env_remove("SIGINT_LOG");
    cmd.output().expect("spawn sigint model promote")
}

fn run_rollback(home: &std::path::Path) -> std::process::Output {
    Command::new(sigint_bin())
        .args(["model", "rollback"])
        .env("HOME", home)
        .env_remove("SIGINT_LOG")
        .output()
        .expect("spawn sigint model rollback")
}

// -- Main smoke test ----------------------------------------------------------

/// Full end-to-end smoke test: harvest -> export -> finetune -> evaluate ->
/// promote -> rollback.
///
/// Assertions:
/// - 60+ examples extracted and split correctly.
/// - Mock trainer copies train.jsonl to output_path (exit 0).
/// - MockProvider evaluation produces a ComparisonReport persisted as last_eval.json.
/// - Config unchanged pre-promote, updated post-promote, restored post-rollback.
/// - promotion.log has exactly 2 entries after promote + rollback.
#[tokio::test]
async fn finetune_loop_end_to_end() {
    let tmp = TempDir::new().expect("tempdir");
    let train_dir = tmp.path().join("training");
    fs::create_dir_all(&train_dir).unwrap();

    // Step 1: seed DB with 70 sessions, all harvested (trainable=1).
    let (db, _session_ids) = seed_db(70);

    // Step 2: extract + export.
    let (examples, stats) = extract::extract_all(&db).expect("extract_all");
    assert!(
        examples.len() >= 60,
        "expected >= 60 examples, got {}",
        examples.len()
    );
    assert_eq!(stats.total_examples, examples.len());

    let (train_examples, test_examples) = split::train_test_split(&examples);
    assert!(!train_examples.is_empty(), "train split must not be empty");
    assert!(!test_examples.is_empty(), "test split must not be empty");

    let train_jsonl = train_dir.join("train.jsonl");
    let test_jsonl = train_dir.join("test.jsonl");
    let train_count =
        format::write_jsonl(&train_examples, &train_jsonl).expect("write train.jsonl");
    let test_count = format::write_jsonl(&test_examples, &test_jsonl).expect("write test.jsonl");
    assert_eq!(train_count, train_examples.len());
    assert_eq!(test_count, test_examples.len());
    assert!(train_jsonl.exists());
    assert!(test_jsonl.exists());

    // Step 3: finetune with mock command (bash cp).
    let output_path = train_dir.join("adapter.bin");
    let job_dir = train_dir.join("jobs");
    let cfg = sigint_core::config::TrainConfig {
        finetune_command: r#"bash -c 'cp "$SIGINT_TRAIN_JSONL" "$SIGINT_OUTPUT_PATH"'"#.to_string(),
        min_eval_examples: 50,
        job_dir: Some(job_dir.clone()),
    };

    let record =
        finetune::run_finetune(&cfg, "llama3.2:8b", &output_path, &train_jsonl, &test_jsonl)
            .expect("run_finetune");

    assert!(
        matches!(record.status, sigint_train::finetune::JobStatus::Success),
        "finetune should succeed: {:?}",
        record.status
    );
    assert!(
        output_path.exists(),
        "output_path must exist after finetune"
    );
    assert!(
        fs::metadata(&output_path).unwrap().len() > 0,
        "output not empty"
    );

    let jobs = finetune::list_jobs(&job_dir).expect("list_jobs");
    assert_eq!(jobs.len(), 1, "expected 1 job entry, got {}", jobs.len());

    // Step 4: evaluate with MockProvider.
    // Both base and candidate return the correct tool name -> tool_accuracy = 1.0.
    let mock_responses: Vec<MockResponse> = test_examples
        .iter()
        .map(|ex| {
            let tool_name = ex
                .messages
                .iter()
                .find(|m| m.role == "assistant")
                .and_then(|m| m.tool_calls.as_ref())
                .and_then(|calls| calls.first())
                .map(|c| c.function.name.clone())
                .unwrap_or_else(|| "nmap_scan".to_string());
            MockResponse::ToolCall {
                name: tool_name,
                arguments: serde_json::json!({"target": "10.0.0.1"}),
            }
        })
        .collect();

    let base_provider = MockProvider::with_responses(mock_responses.clone());
    let cand_provider = MockProvider::with_responses(mock_responses);

    let report = run_comparison(
        &base_provider,
        &cand_provider,
        &test_examples,
        "llama3.2:8b",
        "sigint-ft:latest",
    )
    .await
    .expect("run_comparison");

    assert_eq!(report.total_examples, test_examples.len());
    assert!(
        report.base_results.tool_accuracy > 0.0,
        "base tool_accuracy should be > 0"
    );

    // Persist last_eval.json.
    persist_last_eval(&train_dir, &report).expect("persist_last_eval");
    let eval_path = train_dir.join("last_eval.json");
    assert!(eval_path.exists(), "last_eval.json must exist");

    let eval_raw = fs::read_to_string(&eval_path).expect("read last_eval.json");
    let eval_val: serde_json::Value =
        serde_json::from_str(&eval_raw).expect("parse last_eval.json");
    let persisted_total = eval_val["total_examples"].as_u64().unwrap_or(0) as usize;
    assert!(
        persisted_total > 0,
        "persisted total_examples must be > 0, got {}",
        persisted_total
    );
    assert_eq!(
        persisted_total,
        test_examples.len(),
        "persisted total_examples must match the test set size"
    );

    // Step 5: promote via real sigint binary.
    // Use the actual test-set size as min_eval_examples so the P1 gate passes.
    // (The gate itself is exercised by the dedicated tests in promote_rollback.rs.)
    let home_dir = TempDir::new().expect("home tempdir");
    let home = home_dir.path();

    let models_dir = home
        .join(".local")
        .join("share")
        .join("sigint")
        .join("models");
    fs::create_dir_all(&models_dir).unwrap();
    fs::write(models_dir.join("adapter.gguf"), b"GGUF_STUB").unwrap();

    let home_training_dir = home
        .join(".local")
        .join("share")
        .join("sigint")
        .join("training");
    fs::create_dir_all(&home_training_dir).unwrap();
    fs::copy(&eval_path, home_training_dir.join("last_eval.json")).unwrap();

    // Write config with min_eval_examples = actual test set size so P1 gate passes.
    write_config(home, "ollama", "llama3.2", persisted_total);

    let bin = sigint_bin();
    assert!(bin.exists(), "sigint binary not found at {:?}", bin);

    let pre_promote_model = read_active_model(home);
    assert_eq!(pre_promote_model, "llama3.2");

    let promote_out = run_promote(home, "adapter.gguf", false);
    assert_eq!(
        promote_out.status.code().unwrap_or(-1),
        0,
        "promote should exit 0.\nstderr: {}",
        String::from_utf8_lossy(&promote_out.stderr)
    );

    let post_promote_model = read_active_model(home);
    assert!(
        post_promote_model.contains("adapter"),
        "post-promote model should contain 'adapter', got: {}",
        post_promote_model
    );
    assert_ne!(post_promote_model, pre_promote_model);

    // Step 6: rollback.
    let rollback_out = run_rollback(home);
    assert_eq!(
        rollback_out.status.code().unwrap_or(-1),
        0,
        "rollback should exit 0.\nstderr: {}",
        String::from_utf8_lossy(&rollback_out.stderr)
    );

    let post_rollback_model = read_active_model(home);
    assert_eq!(
        post_rollback_model, pre_promote_model,
        "post-rollback must match original '{}', got: '{}'",
        pre_promote_model, post_rollback_model
    );

    // Verify promotion.log has exactly 2 entries (promote + rollback).
    let log_path = home_training_dir.join("promotion.log");
    assert!(log_path.exists(), "promotion.log must exist");
    let log_contents = fs::read_to_string(&log_path).expect("read promotion.log");
    let entry_count = log_contents
        .lines()
        .filter(|l| !l.trim().is_empty())
        .count();
    assert_eq!(
        entry_count, 2,
        "promotion.log should have 2 entries, got: {}\nlog:\n{}",
        entry_count, log_contents
    );

    let entries: Vec<serde_json::Value> = log_contents
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("parse log entry"))
        .collect();
    assert_eq!(
        entries[0]["action"].as_str(),
        Some("promote"),
        "first entry action"
    );
    assert_eq!(
        entries[1]["action"].as_str(),
        Some("rollback"),
        "second entry action"
    );
}
