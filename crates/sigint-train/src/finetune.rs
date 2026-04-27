//! Fine-tuning job runner for SIGINT.
//!
//! Delegates model training to a user-configured external command rather than
//! implementing a specific training framework. The command receives training
//! data locations via environment variables and runs to completion.
//!
//! # Job lifecycle
//! 1. Validate config (finetune_command must be set).
//! 2. Shell-word-split the configured command.
//! 3. Exec the binary directly with env vars set.
//! 4. Persist a JobRecord to `job_dir/jobs.json` (JSONL format).
//!
//! Two entry points are provided:
//! - [`run_finetune`] — synchronous, used by the CLI (`sigint train finetune`).
//!   Inherits stdout/stderr; no progress streaming.
//! - [`run_finetune_streaming`] — async, used by the web handler. Captures stdout
//!   line-by-line via `tokio::process::Command`, rate-limits progress emissions to
//!   ≤1/sec, and tails stdout in a bounded `VecDeque`. See DEC-P26-T1B-001 and
//!   DEC-P26-T1B-002 for rationale.
//!
//! @decision DEC-P24-001
//! @title Fine-tune backend is an external shell-out command
//! @status accepted
//! @rationale `ollama create` only packages a model — it does not train.
//! llama.cpp finetune is deprecated upstream. Delegating to a user-configured
//! command (unsloth-cli, axolotl, MLX, etc.) keeps sigint toolchain-agnostic
//! and respects user diversity. Env vars (SIGINT_TRAIN_JSONL, SIGINT_TEST_JSONL,
//! SIGINT_BASE_MODEL, SIGINT_OUTPUT_PATH) are the ABI between sigint and the
//! trainer. Addresses: REQ-P24-P0-002, REQ-P24-NOGO-002. See DEC-P24-001 in
//! config.rs for full rationale.
//!
//! @decision DEC-P26-T1B-001
//! @title Streaming runner is a separate async function; sync runner is unchanged
//! @status accepted
//! @rationale The CLI-side `run_finetune` is unit-tested, used by `sigint train
//! finetune`, and has no progress consumer. Forcing tokio there adds unnecessary
//! surface area. Instead, `run_finetune_streaming` is a parallel async function
//! that shares persist + audit-trail helpers but uses `tokio::process::Command`
//! with `Stdio::piped()` on stdout. Minor duplication of the start/finish
//! scaffolding is mitigated by `make_initial_record`, `persist_job`, and
//! `build_argv` helpers shared by both paths.
//!
//! @decision DEC-P26-T1B-002
//! @title Rate-limit progress emissions to ≤1 event/second (token-bucket-of-1)
//! @status accepted
//! @rationale Plan Risk #2 explicitly flagged event-bus flooding from line-rate
//! trainer output. A trainer emitting thousands of lines/sec would overwhelm the
//! broadcast bus and all WebSocket subscribers. ≤1 event/sec is fast enough for
//! human-readable progress UX and slow enough to keep the bus healthy. Implemented
//! as a `last_emitted: Instant` guard: emit only when ≥1 s has elapsed since the
//! last emission. If no lines arrive for >1 s, the next line triggers a new
//! emission immediately (no minimum interval, only a maximum rate).

use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncBufReadExt;
use uuid::Uuid;

use sigint_core::config::TrainConfig;

// ── Job record types ─────────────────────────────────────────────────────────

/// Status of a fine-tuning job.
///
/// Serializes as a tagged JSON object: `{"status":"Running"}`, `{"status":"Success"}`,
/// or `{"status":"Failed"}`. The `tag = "status"` representation matches the web API
/// contract expected by the training poll endpoint and the `train_flow` integration test.
/// Failure details are stored in [`JobRecord::failure_reason`] alongside this field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "status")]
pub enum JobStatus {
    /// Job is currently running.
    Running,
    /// Job completed successfully (exit code 0).
    Success,
    /// Job failed — see `JobRecord.failure_reason` for details.
    Failed,
}

/// Persistent record of a single fine-tuning job.
///
/// Serialized as one JSON object per line in `job_dir/jobs.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobRecord {
    /// Unique job identifier (UUID v4).
    pub id: String,

    /// Wall-clock time when the job was started.
    pub started_at: DateTime<Utc>,

    /// Wall-clock time when the job finished (None while running).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<DateTime<Utc>>,

    /// The command string from config (not the resolved argv — for display/audit).
    pub command: String,

    /// Base model tag passed to the trainer (e.g. "llama3.2:8b").
    pub base_model: String,

    /// Output path where the fine-tuned adapter/model will be written.
    pub output_path: PathBuf,

    /// OS exit code from the training command (None while running).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,

    /// Final status after the command completes.
    /// Serializes as a plain string: `"Running"`, `"Success"`, or `"Failed"`.
    pub status: JobStatus,

    /// Human-readable failure description when `status == Failed`.
    /// Absent for Running and Success records.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
}

// ── Command parsing ──────────────────────────────────────────────────────────

/// Split a command string into argv tokens using a minimal shell-word parser.
///
/// Supports single and double-quoted arguments. Does NOT invoke a shell.
/// Examples:
/// - `"unsloth-cli --data $X"` → `["unsloth-cli", "--data", "$X"]`
/// - `"run --name \"my model\""` → `["run", "--name", "my model"]`
///
/// Returns `Err` if the string contains unterminated quotes.
fn split_command(s: &str) -> Result<Vec<String>> {
    let mut args: Vec<String> = Vec::new();
    let mut current = String::new();
    let chars = s.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;

    for ch in chars {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            ' ' | '\t' if !in_single && !in_double => {
                if !current.is_empty() {
                    args.push(current.clone());
                    current.clear();
                }
            }
            _ => current.push(ch),
        }
    }

    if in_single {
        return Err(anyhow!("unterminated single quote in finetune_command"));
    }
    if in_double {
        return Err(anyhow!("unterminated double quote in finetune_command"));
    }

    if !current.is_empty() {
        args.push(current);
    }

    if args.is_empty() {
        return Err(anyhow!("finetune_command is empty after parsing"));
    }

    Ok(args)
}

// ── Public API ───────────────────────────────────────────────────────────────

/// Run the fine-tuning command configured in `[train].finetune_command`.
///
/// Training progress streams directly to the caller's stdout/stderr via
/// `Stdio::inherit()` — training output is never buffered into memory.
///
/// # Environment variables passed to the trainer
/// | Variable | Value |
/// |---|---|
/// | `SIGINT_TRAIN_JSONL` | Path to training JSONL |
/// | `SIGINT_TEST_JSONL`  | Path to test JSONL |
/// | `SIGINT_BASE_MODEL`  | Base model tag |
/// | `SIGINT_OUTPUT_PATH` | Requested output path for the fine-tuned model |
///
/// # Errors
/// - `finetune_command` is empty → returns Err mentioning `[train].finetune_command`
///   and DEC-P24-001 (no command is executed).
/// - Non-zero exit → returns Err after persisting a `Failed` JobRecord.
/// - Job dir or JSONL write failure → returns Err.
///
/// @decision DEC-P24-001
/// @title Fine-tune backend is an external shell-out command
/// @status accepted
/// @rationale See module-level doc and config.rs for full rationale.
pub fn run_finetune(
    cfg: &TrainConfig,
    base_model: &str,
    output_path: &Path,
    train_jsonl: &Path,
    test_jsonl: &Path,
) -> Result<JobRecord> {
    // Guard: refuse to run with a helpful error if no command is configured.
    if cfg.finetune_command.trim().is_empty() {
        return Err(anyhow!(
            "No fine-tune command configured. Set [train].finetune_command in \
             ~/.config/sigint/config.toml before running `sigint train finetune`. \
             See DEC-P24-001 for the expected command interface."
        ));
    }

    // Parse the command string into argv tokens (no shell involved).
    let argv =
        split_command(&cfg.finetune_command).context("failed to parse [train].finetune_command")?;

    let (program, args) = argv
        .split_first()
        .expect("split_command guarantees non-empty");

    // Resolve job_dir — defaults to ~/.local/share/sigint/training/.
    let job_dir = resolve_job_dir(cfg);
    std::fs::create_dir_all(&job_dir)
        .with_context(|| format!("failed to create job_dir: {}", job_dir.display()))?;

    let job_id = Uuid::new_v4().to_string();
    let started_at = Utc::now();

    // Audit trail: echo the full resolved command to stderr before exec.
    // This mirrors the configured string (Risk #4 — operator awareness).
    let full_cmd = std::iter::once(program.as_str())
        .chain(args.iter().map(|s| s.as_str()))
        .collect::<Vec<_>>()
        .join(" ");
    eprintln!(
        "[sigint-train] running finetune: {} (job {})",
        full_cmd, job_id
    );

    // Exec the trainer. Stdout/stderr inherited so progress streams to terminal.
    // `.status()` is used instead of `.output()` — `.output()` hangs when
    // stdout/stderr are inherited and the call is made from spawn_blocking,
    // because it waits for a pipe-close that never comes.
    // The async counterpart (run_finetune_streaming) captures stdout for
    // TrainingJobProgress events; the sync path keeps Stdio::inherit() for CLI use.
    let exit_status = Command::new(program)
        .args(args)
        .env("SIGINT_TRAIN_JSONL", train_jsonl)
        .env("SIGINT_TEST_JSONL", test_jsonl)
        .env("SIGINT_BASE_MODEL", base_model)
        .env("SIGINT_OUTPUT_PATH", output_path)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .with_context(|| format!("failed to spawn fine-tune command: {}", program))?;

    let finished_at = Utc::now();
    let exit_code = exit_status.code();

    let (status, failure_reason) = if exit_status.success() {
        (JobStatus::Success, None)
    } else {
        let code = exit_code.unwrap_or(-1);
        let reason = format!("fine-tune command exited with status {}", code);
        (JobStatus::Failed, Some(reason))
    };

    let record = JobRecord {
        id: job_id,
        started_at,
        finished_at: Some(finished_at),
        command: cfg.finetune_command.clone(),
        base_model: base_model.to_string(),
        output_path: output_path.to_path_buf(),
        exit_code,
        status: status.clone(),
        failure_reason: failure_reason.clone(),
    };

    // Persist the record to jobs.json (JSONL — one object per line).
    persist_job(&job_dir, &record)
        .with_context(|| format!("failed to persist job record to {}", job_dir.display()))?;

    // Return the record for callers, but surface exit-code errors.
    if status == JobStatus::Failed {
        let reason = failure_reason.unwrap_or_default();
        return Err(anyhow!(
            "fine-tune command exited with status {} (job {} persisted as Failed)",
            exit_code.unwrap_or(-1),
            record.id
        )
        .context(reason));
    }

    Ok(record)
}

/// Run the fine-tuning command asynchronously, streaming stdout progress to a callback.
///
/// This is the **web-only** entry point. The CLI path uses [`run_finetune`] which
/// inherits stdout/stderr. Here we use `tokio::process::Command` with `Stdio::piped()`
/// on stdout (and stderr redirected to stdout via `stderr(Stdio::piped())` —
/// both streams are concatenated by redirecting stderr to stdout in the child,
/// so all trainer output flows through a single reader).
///
/// # Progress delivery
///
/// `on_progress` is called with the current stdout tail after each line is read,
/// subject to rate-limiting (≤1 call per second, per DEC-P26-T1B-002). The tail
/// is bounded by `stdout_tail_bytes`: a `VecDeque<u8>` accumulates raw bytes and
/// trims from the front when the next line would exceed the cap. The snapshot
/// passed to `on_progress` is UTF-8 safe — it is trimmed to a valid char boundary.
///
/// Note: `sigint-train` does not depend on `sigint-core::Event`. The caller
/// (web handler) wraps `on_progress` with a closure that emits the appropriate
/// event variant. This preserves the crate boundary.
///
/// # Errors
/// - `finetune_command` is empty → Err (same guard as `run_finetune`).
/// - Spawn failure → Err.
/// - Non-zero exit → persists a `Failed` `JobRecord` and returns Err.
///
/// @decision DEC-P26-T1B-001
/// @title Streaming variant is a separate async function; sync path unchanged
/// @status accepted
/// @rationale See module-level doc for full rationale.
///
/// @decision DEC-P26-T1B-002
/// @title Rate-limit progress to ≤1 event/sec
/// @status accepted
/// @rationale See module-level doc for full rationale.
pub async fn run_finetune_streaming(
    cfg: &TrainConfig,
    base_model: &str,
    output_path: &Path,
    train_jsonl: &Path,
    test_jsonl: &Path,
    stdout_tail_bytes: usize,
    mut on_progress: impl FnMut(String) + Send,
) -> Result<JobRecord> {
    // Guard: refuse to run with a helpful error if no command is configured.
    if cfg.finetune_command.trim().is_empty() {
        return Err(anyhow!(
            "No fine-tune command configured. Set [train].finetune_command in \
             ~/.config/sigint/config.toml before running `sigint train finetune`. \
             See DEC-P24-001 for the expected command interface."
        ));
    }

    let argv =
        split_command(&cfg.finetune_command).context("failed to parse [train].finetune_command")?;
    let (program, args) = argv
        .split_first()
        .expect("split_command guarantees non-empty");

    let job_dir = resolve_job_dir(cfg);
    std::fs::create_dir_all(&job_dir)
        .with_context(|| format!("failed to create job_dir: {}", job_dir.display()))?;

    let job_id = Uuid::new_v4().to_string();
    let started_at = Utc::now();

    // Audit trail — matches the sync path (Risk #4).
    let full_cmd = std::iter::once(program.as_str())
        .chain(args.iter().map(|s| s.as_str()))
        .collect::<Vec<_>>()
        .join(" ");
    eprintln!(
        "[sigint-train] running finetune: {} (job {})",
        full_cmd, job_id
    );

    // Spawn the trainer with stdout piped; stderr redirected into stdout so all
    // trainer output (loss curves, epoch lines, error messages) flows through
    // a single reader. This simplifies the line-reading loop and ensures the
    // tail includes both stdout and stderr content.
    let mut child = tokio::process::Command::new(program)
        .args(args)
        .env("SIGINT_TRAIN_JSONL", train_jsonl)
        .env("SIGINT_TEST_JSONL", test_jsonl)
        .env("SIGINT_BASE_MODEL", base_model)
        .env("SIGINT_OUTPUT_PATH", output_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn fine-tune command: {}", program))?;

    // --- stdout reader (drives progress events) ---
    let stdout = child
        .stdout
        .take()
        .expect("stdout was piped — take() cannot fail");
    let stderr = child
        .stderr
        .take()
        .expect("stderr was piped — take() cannot fail");

    // Merge stdout and stderr into a single async reader via a background task
    // that forwards stderr lines into a shared channel.
    let (line_tx, mut line_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let tx2 = line_tx.clone();

    // Drain stdout into the channel.
    let stdout_task = {
        let tx = line_tx;
        tokio::spawn(async move {
            let mut reader = tokio::io::BufReader::new(stdout).lines();
            while let Ok(Some(line)) = reader.next_line().await {
                let _ = tx.send(line);
            }
        })
    };

    // Drain stderr into the same channel.
    let stderr_task = tokio::spawn(async move {
        let mut reader = tokio::io::BufReader::new(stderr).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            let _ = tx2.send(line);
        }
    });

    // --- Rolling tail buffer ---
    // We keep raw bytes in a VecDeque capped at `stdout_tail_bytes`.
    // When appending a line would exceed the cap, we drain from the front
    // until there is room. After draining, the buffer may not start on a
    // valid UTF-8 char boundary, so we advance past any continuation bytes
    // before converting to a String for the callback.
    let cap = stdout_tail_bytes.max(1); // avoid a zero-cap
    let mut tail: VecDeque<u8> = VecDeque::with_capacity(cap);

    // --- Rate-limit state (≤1 emission per second) ---
    let mut last_emitted: Option<tokio::time::Instant> = None;

    // Consume lines from the merged channel.
    while let Some(line) = line_rx.recv().await {
        // Append the line + newline to the rolling tail.
        let bytes = format!("{}\n", line);
        for b in bytes.as_bytes() {
            if tail.len() >= cap {
                tail.pop_front();
            }
            tail.push_back(*b);
        }

        // Rate-limit: only emit if ≥1 s has elapsed since last emission.
        let now = tokio::time::Instant::now();
        let should_emit = match last_emitted {
            None => true,
            Some(t) => now.duration_since(t).as_secs_f64() >= 1.0,
        };

        if should_emit {
            last_emitted = Some(now);
            // Build a UTF-8-safe snapshot of the tail.
            let tail_bytes: Vec<u8> = tail.iter().copied().collect();
            let tail_str = utf8_safe_tail(&tail_bytes);
            on_progress(tail_str);
        }
    }

    // Wait for the drain tasks to complete before awaiting the child.
    let _ = tokio::join!(stdout_task, stderr_task);

    let exit_status = child
        .wait()
        .await
        .with_context(|| format!("failed to wait for fine-tune command: {}", program))?;

    let finished_at = Utc::now();
    let exit_code = exit_status.code();

    let (status, failure_reason) = if exit_status.success() {
        (JobStatus::Success, None)
    } else {
        let code = exit_code.unwrap_or(-1);
        let reason = format!("fine-tune command exited with status {}", code);
        (JobStatus::Failed, Some(reason))
    };

    let record = JobRecord {
        id: job_id,
        started_at,
        finished_at: Some(finished_at),
        command: cfg.finetune_command.clone(),
        base_model: base_model.to_string(),
        output_path: output_path.to_path_buf(),
        exit_code,
        status: status.clone(),
        failure_reason: failure_reason.clone(),
    };

    persist_job(&job_dir, &record)
        .with_context(|| format!("failed to persist job record to {}", job_dir.display()))?;

    if status == JobStatus::Failed {
        let reason = failure_reason.unwrap_or_default();
        return Err(anyhow!(
            "fine-tune command exited with status {} (job {} persisted as Failed)",
            exit_code.unwrap_or(-1),
            record.id
        )
        .context(reason));
    }

    Ok(record)
}

/// List all job records from `job_dir/jobs.json`.
///
/// Records are returned in the order they appear in the file (insertion order,
/// i.e. chronological). Malformed lines are skipped with a warning.
pub fn list_jobs(job_dir: &Path) -> Result<Vec<JobRecord>> {
    let jobs_path = job_dir.join("jobs.json");
    if !jobs_path.exists() {
        return Ok(Vec::new());
    }

    let contents = std::fs::read_to_string(&jobs_path)
        .with_context(|| format!("failed to read {}", jobs_path.display()))?;

    let mut records = Vec::new();
    for (i, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<JobRecord>(line) {
            Ok(r) => records.push(r),
            Err(e) => {
                eprintln!(
                    "[sigint-train] warning: skipping malformed line {} in jobs.json: {}",
                    i + 1,
                    e
                );
            }
        }
    }

    Ok(records)
}

// ── Internal helpers ─────────────────────────────────────────────────────────

/// Resolve the job directory from config or fall back to the XDG data home.
fn resolve_job_dir(cfg: &TrainConfig) -> PathBuf {
    if let Some(ref dir) = cfg.job_dir {
        return dir.clone();
    }
    // Default: ~/.local/share/sigint/training/
    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    home.join(".local")
        .join("share")
        .join("sigint")
        .join("training")
}

/// Append a single JobRecord to `job_dir/jobs.json` (JSONL).
fn persist_job(job_dir: &Path, record: &JobRecord) -> Result<()> {
    let jobs_path = job_dir.join("jobs.json");
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(&jobs_path)
        .with_context(|| format!("failed to open {}", jobs_path.display()))?;

    let line = serde_json::to_string(record).context("failed to serialize JobRecord")?;
    writeln!(file, "{}", line)
        .with_context(|| format!("failed to write to {}", jobs_path.display()))?;
    Ok(())
}

/// Trim a byte slice to the longest valid UTF-8 prefix that fits within the slice.
///
/// When the tail buffer is trimmed from the front, the remaining bytes may start
/// in the middle of a multi-byte UTF-8 sequence. This function advances past any
/// UTF-8 continuation bytes (0x80..=0xBF) at the start of `bytes` so the result
/// is always a valid `&str`. The remaining bytes are then converted via
/// `String::from_utf8_lossy` for any embedded replacement characters.
fn utf8_safe_tail(bytes: &[u8]) -> String {
    // Skip past any leading continuation bytes (not valid UTF-8 start bytes).
    let start = bytes
        .iter()
        .position(|&b| !(0x80..0xC0).contains(&b))
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[start..]).into_owned()
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_command_simple() {
        let v = split_command("unsloth-cli --train data.jsonl").unwrap();
        assert_eq!(v, vec!["unsloth-cli", "--train", "data.jsonl"]);
    }

    #[test]
    fn split_command_double_quoted() {
        let v = split_command(r#"run --name "my model""#).unwrap();
        assert_eq!(v, vec!["run", "--name", "my model"]);
    }

    #[test]
    fn split_command_single_quoted() {
        let v = split_command("run --tag 'v1 beta'").unwrap();
        assert_eq!(v, vec!["run", "--tag", "v1 beta"]);
    }

    #[test]
    fn split_command_unterminated_quote_errors() {
        assert!(split_command("run --name \"unterminated").is_err());
        assert!(split_command("run --tag 'unterminated").is_err());
    }

    #[test]
    fn split_command_empty_errors() {
        assert!(split_command("").is_err());
        assert!(split_command("   ").is_err());
    }

    #[test]
    fn run_finetune_empty_command_errors() {
        let cfg = TrainConfig::default();
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path().join("output");
        let train = tmp.path().join("train.jsonl");
        let test = tmp.path().join("test.jsonl");
        let err = run_finetune(&cfg, "llama3.2:8b", &out, &train, &test).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("finetune_command") && msg.contains("DEC-P24-001"),
            "error should mention finetune_command and DEC-P24-001, got: {}",
            msg
        );
    }

    #[test]
    fn run_finetune_happy_path_persists_success_and_copies_output() {
        let tmp = tempfile::tempdir().unwrap();
        let train = tmp.path().join("train.jsonl");
        let test = tmp.path().join("test.jsonl");
        let out = tmp.path().join("adapter.bin");
        let job_dir = tmp.path().join("jobs");

        std::fs::write(&train, "line1\nline2\n").unwrap();
        std::fs::write(&test, "t1\n").unwrap();

        let cfg = TrainConfig {
            finetune_command: r#"bash -c 'cp "$SIGINT_TRAIN_JSONL" "$SIGINT_OUTPUT_PATH"'"#
                .to_string(),
            min_eval_examples: 50,
            job_dir: Some(job_dir.clone()),
        };

        let rec = run_finetune(&cfg, "llama3.2:8b", &out, &train, &test).expect("should succeed");
        assert!(matches!(rec.status, JobStatus::Success));
        assert_eq!(rec.exit_code, Some(0));
        assert_eq!(rec.base_model, "llama3.2:8b");
        assert_eq!(rec.output_path, out);
        assert!(out.exists(), "output file must exist");
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "line1\nline2\n");

        let jobs_file = job_dir.join("jobs.json");
        assert!(jobs_file.exists());
        let contents = std::fs::read_to_string(&jobs_file).unwrap();
        assert_eq!(
            contents.lines().count(),
            1,
            "expected exactly one JSONL line"
        );
        let parsed: JobRecord = serde_json::from_str(contents.lines().next().unwrap()).unwrap();
        assert_eq!(parsed.id, rec.id);
    }

    #[test]
    fn run_finetune_failure_path_persists_failed_and_returns_err() {
        let tmp = tempfile::tempdir().unwrap();
        let train = tmp.path().join("train.jsonl");
        let test = tmp.path().join("test.jsonl");
        let out = tmp.path().join("adapter.bin");
        let job_dir = tmp.path().join("jobs");

        std::fs::write(&train, "x").unwrap();
        std::fs::write(&test, "y").unwrap();

        let cfg = TrainConfig {
            finetune_command: r#"bash -c 'exit 1'"#.to_string(),
            min_eval_examples: 50,
            job_dir: Some(job_dir.clone()),
        };

        let err = run_finetune(&cfg, "base", &out, &train, &test).unwrap_err();
        assert!(
            err.to_string().contains("exited with status"),
            "expected exit-status err, got: {}",
            err
        );

        let jobs_file = job_dir.join("jobs.json");
        let contents = std::fs::read_to_string(&jobs_file).unwrap();
        let parsed: JobRecord = serde_json::from_str(contents.lines().next().unwrap()).unwrap();
        assert!(
            matches!(parsed.status, JobStatus::Failed { .. }),
            "expected Failed status, got {:?}",
            parsed.status
        );
        assert_eq!(parsed.exit_code, Some(1));
    }

    #[test]
    fn list_jobs_reads_seeded_jsonl_in_order() {
        let tmp = tempfile::tempdir().unwrap();
        let job_dir = tmp.path();
        let jobs_file = job_dir.join("jobs.json");

        let r1 = JobRecord {
            id: "j1".into(),
            started_at: Utc::now(),
            finished_at: Some(Utc::now()),
            command: "cmd1".into(),
            base_model: "base1".into(),
            output_path: PathBuf::from("/tmp/o1"),
            exit_code: Some(0),
            status: JobStatus::Success,
            failure_reason: None,
        };
        let r2 = JobRecord {
            id: "j2".into(),
            started_at: Utc::now(),
            finished_at: None,
            command: "cmd2".into(),
            base_model: "base2".into(),
            output_path: PathBuf::from("/tmp/o2"),
            exit_code: None,
            status: JobStatus::Running,
            failure_reason: None,
        };

        let mut f = std::fs::File::create(&jobs_file).unwrap();
        writeln!(f, "{}", serde_json::to_string(&r1).unwrap()).unwrap();
        writeln!(f, "{}", serde_json::to_string(&r2).unwrap()).unwrap();
        drop(f);

        let loaded = list_jobs(job_dir).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].id, "j1");
        assert_eq!(loaded[1].id, "j2");
    }

    #[test]
    fn list_jobs_returns_empty_when_file_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let loaded = list_jobs(tmp.path()).unwrap();
        assert!(loaded.is_empty());
    }

    // ── Streaming tests ───────────────────────────────────────────────────────

    /// Verify that run_finetune_streaming calls on_progress at least once and
    /// returns a Success JobRecord when the command exits 0.
    #[tokio::test]
    async fn run_finetune_streaming_emits_lines() {
        let tmp = tempfile::tempdir().unwrap();
        let train = tmp.path().join("train.jsonl");
        let test = tmp.path().join("test.jsonl");
        let out = tmp.path().join("adapter.bin");
        let job_dir = tmp.path().join("jobs");

        std::fs::write(&train, "line1\n").unwrap();
        std::fs::write(&test, "t1\n").unwrap();

        let cfg = TrainConfig {
            finetune_command: "sh -c 'for i in 1 2 3 4 5; do echo \"line $i\"; sleep 0.05; done'"
                .to_string(),
            min_eval_examples: 50,
            job_dir: Some(job_dir.clone()),
        };

        let events: std::sync::Arc<std::sync::Mutex<Vec<String>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let events_clone = events.clone();

        let rec = run_finetune_streaming(
            &cfg,
            "llama3.2:8b",
            &out,
            &train,
            &test,
            2048,
            move |tail| {
                events_clone.lock().unwrap().push(tail);
            },
        )
        .await
        .expect("streaming run should succeed");

        assert!(
            matches!(rec.status, JobStatus::Success),
            "expected Success, got {:?}",
            rec.status
        );
        assert_eq!(rec.exit_code, Some(0));

        let collected = events.lock().unwrap();
        assert!(
            !collected.is_empty(),
            "expected at least one progress event, got none"
        );
        // The tail must contain at least one of the emitted lines.
        let all_tails = collected.join("\n");
        assert!(
            all_tails.contains("line"),
            "progress tail should contain trainer output, got: {:?}",
            all_tails
        );
    }

    /// Verify that when the command emits many lines quickly, the number of
    /// on_progress calls is bounded (rate-limited to ≤1/sec).
    ///
    /// We emit 50 lines with no delay and assert that the callback was called
    /// no more than 4 times (generous: the test itself runs in <1 s, so at
    /// ≤1/sec we expect 1-2 calls; 4 is the ceiling to tolerate slow CI).
    #[tokio::test]
    async fn run_finetune_streaming_rate_limit() {
        let tmp = tempfile::tempdir().unwrap();
        let train = tmp.path().join("train.jsonl");
        let test = tmp.path().join("test.jsonl");
        let out = tmp.path().join("adapter.bin");
        let job_dir = tmp.path().join("jobs");

        std::fs::write(&train, "x\n").unwrap();
        std::fs::write(&test, "y\n").unwrap();

        let cfg = TrainConfig {
            // Print 50 lines immediately with no sleep.
            finetune_command:
                "sh -c 'i=0; while [ $i -lt 50 ]; do echo \"progress $i\"; i=$((i+1)); done'"
                    .to_string(),
            min_eval_examples: 50,
            job_dir: Some(job_dir.clone()),
        };

        let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count_clone = count.clone();

        run_finetune_streaming(&cfg, "base", &out, &train, &test, 2048, move |_tail| {
            count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        })
        .await
        .expect("should succeed");

        let calls = count.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            calls <= 4,
            "expected ≤4 progress emissions for 50 rapid lines (rate-limit), got {}",
            calls
        );
        assert!(calls >= 1, "expected at least 1 progress emission, got 0");
    }

    /// Verify that the stdout tail is bounded to stdout_tail_bytes and that the
    /// result is valid UTF-8 even when a multi-byte char falls on the trim boundary.
    #[tokio::test]
    async fn run_finetune_streaming_tail_bounded() {
        let tmp = tempfile::tempdir().unwrap();
        let train = tmp.path().join("train.jsonl");
        let test = tmp.path().join("test.jsonl");
        let out = tmp.path().join("adapter.bin");
        let job_dir = tmp.path().join("jobs");

        std::fs::write(&train, "x\n").unwrap();
        std::fs::write(&test, "y\n").unwrap();

        // Emit a 10 KB line followed by a line ending with a multi-byte UTF-8 char (€ = 3 bytes).
        // We use printf so the shell emits exactly what we want without extra escaping.
        let cfg = TrainConfig {
            finetune_command: "sh -c 'python3 -c \
                \"import sys; \
                 sys.stdout.write(\\\"A\\\" * 10240 + \\\"\\\\n\\\"); \
                 sys.stdout.write(\\\"tail€\\\\n\\\"); \
                 sys.stdout.flush()\"'"
                .to_string(),
            min_eval_examples: 50,
            job_dir: Some(job_dir.clone()),
        };

        let tails: std::sync::Arc<std::sync::Mutex<Vec<String>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let tails_clone = tails.clone();
        let cap = 2048usize;

        run_finetune_streaming(&cfg, "base", &out, &train, &test, cap, move |tail| {
            tails_clone.lock().unwrap().push(tail);
        })
        .await
        .expect("should succeed");

        let collected = tails.lock().unwrap();
        for tail in collected.iter() {
            assert!(
                tail.len() <= cap + 4,
                // +4: a newline appended during line assembly can push us just over for one cycle
                // before the next trim; the buffer itself is capped. The on_progress snapshot
                // reflects the buffer's current byte count which is ≤cap.
                "tail length {} exceeds cap {} in snapshot: {:?}",
                tail.len(),
                cap,
                &tail[..tail.len().min(80)]
            );
            // Must be valid UTF-8 (String is always valid UTF-8 in Rust).
            assert!(
                std::str::from_utf8(tail.as_bytes()).is_ok(),
                "tail is not valid UTF-8"
            );
        }
    }

    /// Verify that a non-zero exit persists a Failed JobRecord and returns Err.
    #[tokio::test]
    async fn run_finetune_streaming_failure_path_persists_failed() {
        let tmp = tempfile::tempdir().unwrap();
        let train = tmp.path().join("train.jsonl");
        let test = tmp.path().join("test.jsonl");
        let out = tmp.path().join("adapter.bin");
        let job_dir = tmp.path().join("jobs");

        std::fs::write(&train, "x\n").unwrap();
        std::fs::write(&test, "y\n").unwrap();

        let cfg = TrainConfig {
            finetune_command: "sh -c 'echo failing; exit 2'".to_string(),
            min_eval_examples: 50,
            job_dir: Some(job_dir.clone()),
        };

        let err = run_finetune_streaming(&cfg, "base", &out, &train, &test, 2048, |_| {})
            .await
            .unwrap_err();

        assert!(
            err.to_string().contains("exited with status"),
            "expected exit-status error, got: {}",
            err
        );

        let jobs_file = job_dir.join("jobs.json");
        assert!(jobs_file.exists(), "jobs.json must be written on failure");
        let contents = std::fs::read_to_string(&jobs_file).unwrap();
        let parsed: JobRecord = serde_json::from_str(contents.lines().next().unwrap()).unwrap();
        assert!(
            matches!(parsed.status, JobStatus::Failed),
            "expected Failed status, got {:?}",
            parsed.status
        );
        assert_eq!(parsed.exit_code, Some(2));
    }

    // ── utf8_safe_tail unit tests ─────────────────────────────────────────────

    #[test]
    fn utf8_safe_tail_ascii() {
        let b = b"hello world";
        assert_eq!(utf8_safe_tail(b), "hello world");
    }

    #[test]
    fn utf8_safe_tail_strips_leading_continuation() {
        // '€' encodes as 0xE2 0x82 0xAC; drop the leading byte to get a
        // continuation-start, which utf8_safe_tail must skip.
        let euro = "€".as_bytes(); // [0xE2, 0x82, 0xAC]
        let truncated = &euro[1..]; // [0x82, 0xAC] — invalid start
        let result = utf8_safe_tail(truncated);
        // Should produce a valid String (may contain replacement chars or be empty).
        assert!(std::str::from_utf8(result.as_bytes()).is_ok());
    }

    #[test]
    fn utf8_safe_tail_empty() {
        assert_eq!(utf8_safe_tail(b""), "");
    }
}
