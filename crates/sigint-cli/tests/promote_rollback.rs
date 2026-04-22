//! Integration tests for `sigint model promote` and `sigint model rollback`.
//!
//! These tests spawn the real binary with isolated HOME directories so that
//! no test pollution occurs. Each test validates a distinct acceptance criterion
//! from Phase 24 Task 4 (MASTER_PLAN.md lines 1226-1234).
//!
//! # Test coverage
//! - `promote_rollback_roundtrip`: full round-trip (promote → rollback → promote)
//! - `atomic_write_config_backup_preserved`: backup created + .tmp cleaned up on success
//! - `p1_gate_refuses_without_force`: promote exits non-zero when
//!   last_eval.json has total_examples < min_eval_examples (no --force)
//! - `p1_gate_force_overrides`: promote exits 0 with --force even when gate fires
//! - `promotion_log_entry_shape`: JSONL entry has all 6 required fields
//! - `rollback_empty_log_is_actionable_error`: rollback without prior promote
//!   exits non-zero with a human-readable message
//!
//! @decision DEC-P24-TEST-001
//! @title Integration tests for promote/rollback drive the real binary
//! @status accepted
//! @rationale The atomic-write guarantee and P1 gate must be verified at
//! process level, not unit-test level. The binary is the source of truth for
//! exit-code contract. Mirrors the pattern established in finetune_exit_code.rs.

use std::fs;
use std::process::Command;

use tempfile::TempDir;

// ── helpers ──────────────────────────────────────────────────────────────────

/// Path to the compiled `sigint` binary.
///
/// CARGO_BIN_EXE_sigint is set by cargo test for the [[bin]] target.
fn sigint_bin() -> std::path::PathBuf {
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_sigint") {
        return std::path::PathBuf::from(p);
    }
    let exe = std::env::current_exe().expect("current_exe");
    let deps = exe.parent().expect("parent of test binary");
    let profile_dir = deps.parent().expect("profile dir");
    profile_dir.join("sigint")
}

/// Create a minimal isolated HOME with:
/// - `$HOME/.config/sigint/config.toml` set to `provider` + `model`
/// - `$HOME/.local/share/sigint/models/<model_filename>` (empty .gguf stub)
/// - Training dir created (for promotion log)
///
/// Returns `(TempDir, models_dir, training_dir)`.
/// Keep `TempDir` alive for the duration of the test.
fn setup_home_with_model(
    provider: &str,
    model: &str,
    model_filename: &str,
) -> (TempDir, std::path::PathBuf, std::path::PathBuf) {
    let tmp = TempDir::new().expect("tempdir");
    let home = tmp.path();

    let config_dir = home.join(".config").join("sigint");
    fs::create_dir_all(&config_dir).unwrap();

    let models_dir = home
        .join(".local")
        .join("share")
        .join("sigint")
        .join("models");
    fs::create_dir_all(&models_dir).unwrap();

    let training_dir = home
        .join(".local")
        .join("share")
        .join("sigint")
        .join("training");
    fs::create_dir_all(&training_dir).unwrap();

    // Minimal config — only [llm] block.
    let config_content = format!(
        "[llm]\nprovider = \"{}\"\nmodel = \"{}\"\n",
        provider, model
    );
    fs::write(config_dir.join("config.toml"), &config_content).unwrap();

    // Fake GGUF stub (content doesn't matter for promote path detection).
    let gguf_path = models_dir.join(model_filename);
    fs::write(&gguf_path, b"GGUF_STUB").unwrap();

    (tmp, models_dir, training_dir)
}

/// Write a `last_eval.json` stub to the training dir with the given example count.
fn write_eval_result(training_dir: &std::path::Path, total_examples: u64) {
    let content = format!(
        r#"{{"total_examples": {}, "candidate": "test-ft", "base": "llama3.2"}}"#,
        total_examples
    );
    fs::write(training_dir.join("last_eval.json"), content).unwrap();
}

/// Read the active `model` value from `$HOME/.config/sigint/config.toml`.
fn read_active_model(home: &std::path::Path) -> String {
    let config_path = home.join(".config").join("sigint").join("config.toml");
    let contents = fs::read_to_string(&config_path).expect("read config.toml");
    for line in contents.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("model = ") {
            return rest.trim().trim_matches('"').to_string();
        }
    }
    panic!("model field not found in config.toml:\n{}", contents);
}

/// Run `sigint model promote <tag> [--force]` and return the Command output.
fn run_promote(home: &std::path::Path, tag: &str, force: bool) -> std::process::Output {
    let bin = sigint_bin();
    let mut cmd = Command::new(&bin);
    cmd.args(["model", "promote", tag]);
    if force {
        cmd.arg("--force");
    }
    cmd.env("HOME", home).env_remove("SIGINT_LOG");
    cmd.output().expect("failed to spawn sigint model promote")
}

/// Run `sigint model rollback` and return the Command output.
fn run_rollback(home: &std::path::Path) -> std::process::Output {
    let bin = sigint_bin();
    Command::new(&bin)
        .args(["model", "rollback"])
        .env("HOME", home)
        .env_remove("SIGINT_LOG")
        .output()
        .expect("failed to spawn sigint model rollback")
}

// ── Test 1: round-trip ────────────────────────────────────────────────────────

/// Full round-trip: promote → rollback → promote again.
///
/// Validates:
/// - After promote, config.toml refers to the new model.
/// - After rollback, config.toml is restored to the original model.
/// - After a second promote, config.toml refers to the new model again.
/// - promotion.log ends up with 3 entries (2 promotes + 1 rollback).
#[test]
fn promote_rollback_roundtrip() {
    let (home_dir, _models_dir, training_dir) =
        setup_home_with_model("ollama", "llama3.2", "fake-model-q4.gguf");
    let home = home_dir.path();

    // Provide enough examples so the P1 gate passes.
    write_eval_result(&training_dir, 100);

    let bin = sigint_bin();
    assert!(
        bin.exists(),
        "sigint binary not found at {:?}. Run `cargo build` first.",
        bin
    );

    // The original model (before any promotion).
    let original_model = read_active_model(home);
    assert_eq!(original_model, "llama3.2");

    // ── Promote ──────────────────────────────────────────────────────────────
    let out1 = run_promote(home, "fake-model-q4.gguf", false);
    assert_eq!(
        out1.status.code().unwrap_or(-1),
        0,
        "First promote should exit 0.\nstderr: {}",
        String::from_utf8_lossy(&out1.stderr)
    );

    // Config should now point to the GGUF path.
    let after_promote = read_active_model(home);
    assert!(
        after_promote.contains("fake-model-q4"),
        "After promote, model should contain 'fake-model-q4', got: {}",
        after_promote
    );

    // ── Rollback ─────────────────────────────────────────────────────────────
    let out2 = run_rollback(home);
    assert_eq!(
        out2.status.code().unwrap_or(-1),
        0,
        "Rollback should exit 0.\nstderr: {}",
        String::from_utf8_lossy(&out2.stderr)
    );

    let after_rollback = read_active_model(home);
    assert_eq!(
        after_rollback, original_model,
        "After rollback, model should be restored to '{}', got: '{}'",
        original_model, after_rollback
    );

    // ── Second promote ────────────────────────────────────────────────────────
    let out3 = run_promote(home, "fake-model-q4.gguf", false);
    assert_eq!(
        out3.status.code().unwrap_or(-1),
        0,
        "Second promote should exit 0.\nstderr: {}",
        String::from_utf8_lossy(&out3.stderr)
    );

    let after_second_promote = read_active_model(home);
    assert!(
        after_second_promote.contains("fake-model-q4"),
        "After second promote, model should contain 'fake-model-q4', got: {}",
        after_second_promote
    );

    // ── Verify promotion.log has 3 entries ────────────────────────────────────
    let log_path = training_dir.join("promotion.log");
    assert!(
        log_path.exists(),
        "promotion.log should exist after operations"
    );
    let log_contents = fs::read_to_string(&log_path).expect("read promotion.log");
    let entry_count = log_contents
        .lines()
        .filter(|l| !l.trim().is_empty())
        .count();
    assert_eq!(
        entry_count, 3,
        "promotion.log should have 3 entries (promote, rollback, promote), got: {}",
        entry_count
    );
}

// ── Test 2: atomic-write backup integrity ────────────────────────────────────

/// Verify that the backup (.bak) contains the original config after a promote,
/// and that no .tmp orphan is left on success.
///
/// The atomic-write guarantee: if the process crashes after writing .tmp but
/// before rename(), the original config is preserved in .bak. We verify the
/// backup discipline here; a real mid-rename kill would require ptrace.
#[test]
fn atomic_write_config_backup_preserved() {
    let (home_dir, models_dir, training_dir) =
        setup_home_with_model("ollama", "llama3.2", "fake-model-q4.gguf");
    let home = home_dir.path();

    write_eval_result(&training_dir, 100);

    let config_path = home.join(".config").join("sigint").join("config.toml");
    let original_content = fs::read_to_string(&config_path).expect("read original config");

    // Perform a normal promote.
    let out = run_promote(home, "fake-model-q4.gguf", false);
    assert_eq!(
        out.status.code().unwrap_or(-1),
        0,
        "promote should exit 0 in normal case.\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Backup must exist and contain the pre-promote config.
    let bak_path = config_path.with_extension("bak");
    assert!(
        bak_path.exists(),
        "config.toml.bak must exist after promote"
    );

    let bak_content = fs::read_to_string(&bak_path).expect("read config.toml.bak");
    assert_eq!(
        bak_content, original_content,
        "config.toml.bak must contain the pre-promote config"
    );

    // No orphaned .tmp file should remain.
    let tmp_path = config_path.with_extension("tmp");
    assert!(
        !tmp_path.exists(),
        "config.toml.tmp must be cleaned up after successful promote"
    );

    // models_dir still accessible (setup intact).
    assert!(models_dir.exists());
}

// ── Test 3: P1 gate refuses without --force ───────────────────────────────────

/// When last_eval.json has total_examples < min_eval_examples (default 50),
/// `sigint model promote` must exit non-zero unless `--force` is passed.
#[test]
fn p1_gate_refuses_without_force() {
    let (home_dir, _models_dir, training_dir) =
        setup_home_with_model("ollama", "llama3.2", "fake-model-q4.gguf");
    let home = home_dir.path();

    // Only 10 examples — below the default threshold of 50.
    write_eval_result(&training_dir, 10);

    let bin = sigint_bin();
    assert!(
        bin.exists(),
        "sigint binary not found at {:?}. Run `cargo build` first.",
        bin
    );

    let out = run_promote(home, "fake-model-q4.gguf", false);

    let exit_code = out.status.code().unwrap_or(-1);
    assert_ne!(
        exit_code, 0,
        "promote without --force should exit non-zero when total_examples=10 < min=50; got {}\nstderr: {}",
        exit_code,
        String::from_utf8_lossy(&out.stderr)
    );

    // Config must NOT have changed.
    let active = read_active_model(home);
    assert_eq!(
        active, "llama3.2",
        "Config must not change when P1 gate fires without --force"
    );
}

// ── Test 4: P1 gate passes with --force ──────────────────────────────────────

/// With `--force`, promote succeeds even when the P1 gate would fire.
#[test]
fn p1_gate_force_overrides() {
    let (home_dir, _models_dir, training_dir) =
        setup_home_with_model("ollama", "llama3.2", "fake-model-q4.gguf");
    let home = home_dir.path();

    // Only 10 examples — below the default threshold of 50.
    write_eval_result(&training_dir, 10);

    let out = run_promote(home, "fake-model-q4.gguf", true); // --force

    let exit_code = out.status.code().unwrap_or(-1);
    assert_eq!(
        exit_code, 0,
        "promote with --force should exit 0 even when total_examples=10 < min=50; got {}\nstderr: {}\nstdout: {}",
        exit_code,
        String::from_utf8_lossy(&out.stderr),
        String::from_utf8_lossy(&out.stdout)
    );

    // Config should reflect the promoted model.
    let active = read_active_model(home);
    assert!(
        active.contains("fake-model-q4"),
        "Config should point to promoted model after --force promote, got: {}",
        active
    );

    // A WARNING line should appear on stderr about the low example count.
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.to_uppercase().contains("WARNING"),
        "stderr should contain a warning about low example count; got: {}",
        stderr
    );
}

// ── Test 5: promotion log entry shape ────────────────────────────────────────

/// After one promote, the JSONL entry must have all 6 required fields:
/// ts, action, old_provider, old_model, new_provider, new_model
/// plus the optional eval reference path.
#[test]
fn promotion_log_entry_shape() {
    let (home_dir, _models_dir, training_dir) =
        setup_home_with_model("ollama", "llama3.2", "fake-model-q4.gguf");
    let home = home_dir.path();

    write_eval_result(&training_dir, 100);

    let out = run_promote(home, "fake-model-q4.gguf", false);
    assert_eq!(
        out.status.code().unwrap_or(-1),
        0,
        "promote should succeed.\nstderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let log_path = training_dir.join("promotion.log");
    assert!(log_path.exists(), "promotion.log must exist after promote");

    let log_contents = fs::read_to_string(&log_path).expect("read promotion.log");
    let first_line = log_contents
        .lines()
        .find(|l| !l.trim().is_empty())
        .expect("promotion.log must have at least one entry");

    let entry: serde_json::Value =
        serde_json::from_str(first_line).expect("promotion.log entry must be valid JSON");

    // Verify all 6 required fields are present.
    assert!(entry["ts"].is_string(), "Entry must have a 'ts' field");
    assert!(
        entry["action"].is_string(),
        "Entry must have an 'action' field"
    );
    assert!(
        entry["old_provider"].is_string(),
        "Entry must have an 'old_provider' field"
    );
    assert!(
        entry["old_model"].is_string(),
        "Entry must have an 'old_model' field"
    );
    assert!(
        entry["new_provider"].is_string(),
        "Entry must have a 'new_provider' field"
    );
    assert!(
        entry["new_model"].is_string(),
        "Entry must have a 'new_model' field"
    );

    // Verify field values are sensible.
    assert_eq!(entry["action"].as_str().unwrap(), "promote");
    assert_eq!(entry["old_provider"].as_str().unwrap(), "ollama");
    assert_eq!(entry["old_model"].as_str().unwrap(), "llama3.2");
    assert_eq!(entry["new_provider"].as_str().unwrap(), "embedded");
    assert!(
        entry["new_model"]
            .as_str()
            .unwrap()
            .contains("fake-model-q4"),
        "new_model should reference the promoted GGUF, got: {}",
        entry["new_model"]
    );

    // The reference to the evaluation result file should be present.
    assert!(
        !entry["eval_result_ref"].is_null(),
        "eval_result_ref should be present when last_eval.json exists; entry: {}",
        entry
    );
}

// ── Test 6: rollback with no log → actionable error ──────────────────────────

/// `sigint model rollback` with no prior promotion must exit non-zero and
/// print a user-friendly message explaining what to do next.
#[test]
fn rollback_empty_log_is_actionable_error() {
    let (home_dir, _models_dir, _training_dir) =
        setup_home_with_model("ollama", "llama3.2", "fake-model-q4.gguf");
    let home = home_dir.path();

    let bin = sigint_bin();
    assert!(
        bin.exists(),
        "sigint binary not found at {:?}. Run `cargo build` first.",
        bin
    );

    let out = run_rollback(home);
    let exit_code = out.status.code().unwrap_or(-1);
    assert_ne!(
        exit_code,
        0,
        "rollback with no history must exit non-zero; got {}\nstderr: {}",
        exit_code,
        String::from_utf8_lossy(&out.stderr)
    );

    let stderr = String::from_utf8_lossy(&out.stderr);
    // The error message should mention promote, history, or log.
    assert!(
        stderr.contains("promote") || stderr.contains("history") || stderr.contains("log"),
        "rollback error message should mention promote/history/log; got: {}",
        stderr
    );
}
