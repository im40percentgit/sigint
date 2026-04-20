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

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use sigint_core::config::TrainConfig;

// ── Job record types ─────────────────────────────────────────────────────────

/// Status of a fine-tuning job.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "status", content = "reason")]
pub enum JobStatus {
    /// Job is currently running.
    Running,
    /// Job completed successfully (exit code 0).
    Success,
    /// Job failed with a description of the failure.
    Failed { reason: String },
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
    pub status: JobStatus,
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
    let argv = split_command(&cfg.finetune_command)
        .context("failed to parse [train].finetune_command")?;

    let (program, args) = argv.split_first().expect("split_command guarantees non-empty");

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
    let output = Command::new(program)
        .args(args)
        .env("SIGINT_TRAIN_JSONL", train_jsonl)
        .env("SIGINT_TEST_JSONL", test_jsonl)
        .env("SIGINT_BASE_MODEL", base_model)
        .env("SIGINT_OUTPUT_PATH", output_path)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()
        .with_context(|| format!("failed to spawn fine-tune command: {}", program))?;

    let finished_at = Utc::now();
    let exit_code = output.status.code();

    let status = if output.status.success() {
        JobStatus::Success
    } else {
        let code = exit_code.unwrap_or(-1);
        JobStatus::Failed {
            reason: format!("fine-tune command exited with status {}", code),
        }
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
    };

    // Persist the record to jobs.json (JSONL — one object per line).
    persist_job(&job_dir, &record)
        .with_context(|| format!("failed to persist job record to {}", job_dir.display()))?;

    // Return the record for callers, but surface exit-code errors.
    if let JobStatus::Failed { ref reason } = status {
        return Err(anyhow!(
            "fine-tune command exited with status {} (job {} persisted as Failed)",
            exit_code.unwrap_or(-1),
            record.id
        )
        .context(reason.clone()));
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
    home.join(".local").join("share").join("sigint").join("training")
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
    writeln!(file, "{}", line).with_context(|| format!("failed to write to {}", jobs_path.display()))?;
    Ok(())
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
        assert_eq!(contents.lines().count(), 1, "expected exactly one JSONL line");
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
}
