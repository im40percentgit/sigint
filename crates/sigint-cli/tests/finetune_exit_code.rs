//! Integration test: `sigint train finetune` exit code propagation.
//!
//! Regression guard for the bug where a failed trainer (non-zero exit from the
//! configured `finetune_command`) caused the CLI to print the error but still
//! exit 0. Scripts relying on `sigint train finetune ... && next_step` would
//! continue after a training failure. This test spawns the real binary and
//! asserts process-level exit code behaviour.
//!
//! # Test matrix
//! - `finetune_fails_exits_nonzero`: trainer exits 1 → CLI exits non-zero,
//!   stderr contains the error message, jobs.json contains a Failed record.
//! - `finetune_succeeds_exits_zero`: trainer is `true` (always-success noop) →
//!   CLI exits 0.
//!
//! @decision DEC-P24-BUGFIX-001
//! @title Process-level integration test for trainer exit-code propagation
//! @status accepted
//! @rationale Unit tests in sigint-train confirm the library returns Err on
//! failure, but they cannot prove the CLI process exits non-zero. Only spawning
//! the binary and inspecting output.status catches the full propagation path
//! (run_finetune → train.rs dispatch → main.rs std::process::exit). This is the
//! level at which the tester observed the bug (exit: 0 despite printed error),
//! so the regression test must operate at the same level.

use std::fs;
use std::io::Write as _;
use std::process::Command;

use tempfile::TempDir;

/// Path to the compiled sigint binary under test.
///
/// cargo sets CARGO_BIN_EXE_sigint for integration tests when the crate has a
/// [[bin]] target named "sigint". Falls back to a relative path for local use.
fn sigint_bin() -> std::path::PathBuf {
    // CARGO_BIN_EXE_sigint is set by cargo test for [[bin]] targets.
    if let Ok(p) = std::env::var("CARGO_BIN_EXE_sigint") {
        return std::path::PathBuf::from(p);
    }
    // Fallback: look for the binary in the same profile dir as this test binary.
    // Works when cargo builds everything in the same target profile.
    let exe = std::env::current_exe().expect("current_exe");
    let deps = exe.parent().expect("parent of test binary");
    let profile_dir = deps.parent().expect("profile dir"); // .../target/debug or .../target/release
    profile_dir.join("sigint")
}

/// Set up a minimal HOME directory with:
/// - config.toml containing the given `finetune_command`
/// - train.jsonl + test.jsonl stubs so the "no data" guard is bypassed
///
/// Returns the TempDir (kept alive for the duration of the test) and its path.
fn setup_home(finetune_command: &str) -> TempDir {
    let tmp = TempDir::new().expect("tempdir");
    let home = tmp.path();

    let config_dir = home.join(".config").join("sigint");
    fs::create_dir_all(&config_dir).unwrap();

    let training_dir = home
        .join(".local")
        .join("share")
        .join("sigint")
        .join("training");
    fs::create_dir_all(&training_dir).unwrap();

    // Minimal config: only [train] block needed.
    let config_content = format!(
        "[train]\nfinetune_command = \"{}\"\n",
        // Escape any backslashes in the command for TOML.
        finetune_command.replace('\\', "\\\\")
    );
    fs::write(config_dir.join("config.toml"), &config_content).unwrap();

    // Stub train/test JSONL so run_finetune doesn't abort early.
    let mut tf = fs::File::create(training_dir.join("train.jsonl")).unwrap();
    writeln!(tf, r#"{{"stub":true}}"#).unwrap();
    let mut te = fs::File::create(training_dir.join("test.jsonl")).unwrap();
    writeln!(te, r#"{{"stub":true}}"#).unwrap();

    tmp
}

// ── Test 1: failing trainer → non-zero exit ───────────────────────────────────

/// When the configured `finetune_command` exits non-zero, the CLI process must
/// also exit non-zero so shell scripts detect the failure.
///
/// Additionally asserts:
/// - stderr contains the error message (user sees what went wrong)
/// - jobs.json exists and contains a record with `"Failed"` status (audit log preserved)
#[test]
fn finetune_fails_exits_nonzero() {
    let home_dir = setup_home("false"); // `false` is a POSIX utility that exits 1
    let home = home_dir.path().to_path_buf();

    let bin = sigint_bin();
    assert!(
        bin.exists(),
        "sigint binary not found at {:?}. Run `cargo build` first.",
        bin
    );

    let output = Command::new(&bin)
        .args(["train", "finetune", "--base", "llama3.2:8b", "--output", "test-adapter"])
        .env("HOME", &home)
        // Suppress SIGINT_LOG to keep test output clean.
        .env_remove("SIGINT_LOG")
        .output()
        .expect("failed to spawn sigint");

    // ── Assert: non-zero exit code ──────────────────────────────────────────
    let exit_code = output.status.code().unwrap_or(-1);
    assert_ne!(
        exit_code, 0,
        "sigint train finetune must exit non-zero when trainer fails; got exit {}\nstderr: {}",
        exit_code,
        String::from_utf8_lossy(&output.stderr)
    );

    // ── Assert: error message present on stderr ─────────────────────────────
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("fine-tune") || stderr.contains("error"),
        "stderr should contain error description, got: {}",
        stderr
    );

    // ── Assert: Failed record in jobs.json (audit log preserved) ───────────
    let jobs_path = home
        .join(".local")
        .join("share")
        .join("sigint")
        .join("training")
        .join("jobs.json");
    assert!(
        jobs_path.exists(),
        "jobs.json must exist even after a failed run (audit trail)"
    );

    let contents = fs::read_to_string(&jobs_path).expect("read jobs.json");
    assert!(
        contents.contains("\"Failed\""),
        "jobs.json must contain a Failed record; got: {}",
        contents
    );
}

// ── Test 2: succeeding trainer → exit 0 ──────────────────────────────────────

/// Happy-path sanity check: when the trainer exits 0, the CLI must also exit 0.
/// Uses `true` (always-success POSIX utility) as the finetune command.
#[test]
fn finetune_succeeds_exits_zero() {
    let home_dir = setup_home("true"); // `true` is a POSIX utility that exits 0
    let home = home_dir.path().to_path_buf();

    let bin = sigint_bin();
    assert!(
        bin.exists(),
        "sigint binary not found at {:?}. Run `cargo build` first.",
        bin
    );

    let output = Command::new(&bin)
        .args(["train", "finetune", "--base", "llama3.2:8b", "--output", "test-adapter"])
        .env("HOME", &home)
        .env_remove("SIGINT_LOG")
        .output()
        .expect("failed to spawn sigint");

    let exit_code = output.status.code().unwrap_or(-1);
    assert_eq!(
        exit_code, 0,
        "sigint train finetune must exit 0 when trainer succeeds; got exit {}\nstderr: {}\nstdout: {}",
        exit_code,
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&output.stdout)
    );
}
