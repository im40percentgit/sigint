//! CLI handlers for the `sigint train` subcommand family.
//!
//! Provides four subcommands:
//! - `export`  — extract tool-calling data from scan history → JSONL files
//! - `create`  — generate an Ollama Modelfile for `ollama create`
//! - `stats`   — print training data statistics without writing files
//! - `assess`  — load test JSONL and print accuracy metrics (placeholder)
//!
//! Output directory: `~/.local/share/sigint/training/`
//!
//! @decision DEC-TRAIN-007
//! @title Training output goes to ~/.local/share/sigint/training/ (XDG data home)
//! @status accepted
//! @rationale Follows XDG Base Directory spec and matches the existing sigint
//! data directory convention (sigint.db, sigint.log also live under
//! ~/.local/share/sigint/). Keeps training artifacts out of the project
//! directory so they are not accidentally committed. The path is shown
//! in command output so users know where to find their files.

use std::path::PathBuf;

use sigint_core::{AppCore, Error};
use sigint_llm::factory::create_provider;
use sigint_train::{assess, evaluate, extract, finetune, format, modelfile, split, stats};

/// Return the default training output directory: `~/.local/share/sigint/training/`.
fn training_dir() -> Result<PathBuf, Error> {
    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    let dir = home
        .join(".local")
        .join("share")
        .join("sigint")
        .join("training");
    std::fs::create_dir_all(&dir)
        .map_err(|e| Error::Other(format!("failed to create training dir: {}", e)))?;
    Ok(dir)
}

/// `sigint train export` — extract training data from scan history.
///
/// Queries all sessions (or a specified subset), splits 80/20, and writes
/// `train.jsonl` + `test.jsonl` to the training output directory.
pub async fn run_export(
    core: AppCore,
    output: Option<String>,
    min_examples: usize,
) -> Result<(), Error> {
    let db_path = core.config.resolved_db_path();
    let db = sigint_store::db::Database::open(&db_path)
        .map_err(|e| Error::Database(format!("Cannot open database: {e}")))?;

    println!("Extracting training data from scan history...");
    let (examples, train_stats) = extract::extract_all(&db)
        .map_err(|e| Error::Other(format!("extraction failed: {}", e)))?;

    if examples.is_empty() {
        println!("No training examples found. Run some scans first.");
        return Ok(());
    }

    if examples.len() < min_examples {
        println!(
            "Only {} examples found (minimum: {}). Run more scans to collect training data.",
            examples.len(),
            min_examples
        );
        return Ok(());
    }

    let out_dir = match output {
        Some(ref path) => {
            let p = PathBuf::from(path);
            std::fs::create_dir_all(&p)
                .map_err(|e| Error::Other(format!("failed to create output dir: {}", e)))?;
            p
        }
        None => training_dir()?,
    };

    let (train_examples, test_examples) = split::train_test_split(&examples);

    let train_path = out_dir.join("train.jsonl");
    let test_path = out_dir.join("test.jsonl");

    let train_count = format::write_jsonl(&train_examples, &train_path)
        .map_err(|e| Error::Other(format!("failed to write train.jsonl: {}", e)))?;
    let test_count = format::write_jsonl(&test_examples, &test_path)
        .map_err(|e| Error::Other(format!("failed to write test.jsonl: {}", e)))?;

    println!("Exported {} training examples -> {}", train_count, train_path.display());
    println!("Exported {} test examples     -> {}", test_count, test_path.display());
    println!();
    stats::print_stats(&train_stats);

    Ok(())
}

/// `sigint train create` — generate an Ollama Modelfile.
///
/// Reads training data from the export directory and writes a Modelfile
/// that can be used with `ollama create <name> -f Modelfile`.
pub async fn run_create(
    _core: AppCore,
    base_model: String,
    name: String,
    data: Option<String>,
) -> Result<(), Error> {
    let out_dir = training_dir()?;

    let train_path = match data {
        Some(ref p) => PathBuf::from(p),
        None => out_dir.join("train.jsonl"),
    };

    if !train_path.exists() {
        return Err(Error::Other(format!(
            "Training data not found at {}. Run `sigint train export` first.",
            train_path.display()
        )));
    }

    let modelfile_path = out_dir.join("Modelfile");

    // Pass adapter_path = None: at `create` time, no adapter binary exists yet.
    // The user will replace this after fine-tuning (DEC-P24-007).
    modelfile::generate_modelfile(&base_model, None, None, &modelfile_path)
        .map_err(|e| Error::Other(format!("failed to generate Modelfile: {}", e)))?;

    println!("Generated Modelfile -> {}", modelfile_path.display());
    println!();
    println!("To create the model, run:");
    println!("  ollama create {} -f {}", name, modelfile_path.display());

    Ok(())
}

/// `sigint train stats` — print training data statistics without exporting.
pub async fn run_stats(core: AppCore) -> Result<(), Error> {
    let db_path = core.config.resolved_db_path();
    let db = sigint_store::db::Database::open(&db_path)
        .map_err(|e| Error::Database(format!("Cannot open database: {e}")))?;

    let (_, train_stats) = extract::extract_all(&db)
        .map_err(|e| Error::Other(format!("extraction failed: {}", e)))?;

    stats::print_stats(&train_stats);
    Ok(())
}

/// `sigint train harvest <session_id>` — opt a session into fine-tuning harvest.
///
/// Sets `sessions.trainable = 1` for the given session. Only harvested sessions
/// are included when `sigint train export` extracts training data.
///
/// @decision DEC-P24-002
/// @title Harvest is explicit opt-in; default is trainable=0
/// @status accepted
/// @rationale Engagement logs contain customer PII (IPs, hostnames, tool output).
/// Requiring an explicit harvest step ensures users review data before it enters
/// the fine-tune pipeline. The warning banner below is mandatory per Task 5 plan.
pub async fn run_harvest(core: AppCore, session_id: String) -> Result<(), Error> {
    let db_path = core.config.resolved_db_path();
    let db = sigint_store::db::Database::open(&db_path)
        .map_err(|e| Error::Database(format!("Cannot open database: {e}")))?;

    // Verify the session exists before toggling the flag.
    // Try exact UUID match first; fall back to prefix search.
    let resolved_id = if let Ok(uuid) = uuid::Uuid::parse_str(&session_id) {
        match db.get_session(uuid)? {
            Some(s) => s.id.to_string(),
            None => {
                return Err(Error::Other(format!(
                    "No session found with id '{session_id}'"
                )))
            }
        }
    } else {
        // Accept short prefixes (e.g. first 8 hex chars).
        let s = db
            .get_session_by_prefix(&session_id)
            .map_err(|e| Error::Other(e.to_string()))?;
        s.id.to_string()
    };

    db.set_session_trainable(&resolved_id, true)
        .map_err(|e| Error::Other(format!("Failed to mark session as trainable: {e}")))?;

    println!("Session {resolved_id} marked as trainable.");
    println!();
    println!(
        "WARNING: Training data may contain sensitive engagement data. Review before sharing."
    );
    Ok(())
}

/// `sigint train assess` — evaluate a model against held-out test data.
///
/// Loads the test JSONL and prints accuracy metrics. In a real workflow the
/// caller would supply model predictions; this placeholder reports ground-truth
/// stats to confirm the pipeline wires together correctly.
pub async fn run_assess(
    _core: AppCore,
    _model: Option<String>,
    data: Option<String>,
) -> Result<(), Error> {
    let out_dir = training_dir()?;

    let test_path = match data {
        Some(ref p) => PathBuf::from(p),
        None => out_dir.join("test.jsonl"),
    };

    if !test_path.exists() {
        return Err(Error::Other(format!(
            "Test data not found at {}. Run `sigint train export` first.",
            test_path.display()
        )));
    }

    let examples = format::read_jsonl(&test_path)
        .map_err(|e| Error::Other(format!("failed to read test JSONL: {}", e)))?;

    println!("Loaded {} test examples from {}", examples.len(), test_path.display());
    println!();

    // Placeholder: no live model inference yet. Show what a perfect-prediction
    // result looks like to confirm the assess pipeline is wired correctly.
    let perfect_predictions: Vec<(String, String)> = examples
        .iter()
        .map(|ex| {
            // Extract the ground-truth tool call from each example.
            for msg in &ex.messages {
                if msg.role == "assistant" {
                    if let Some(calls) = &msg.tool_calls {
                        if let Some(call) = calls.first() {
                            return (
                                call.function.name.clone(),
                                call.function.arguments.clone(),
                            );
                        }
                    }
                }
            }
            (String::new(), String::new())
        })
        .collect();

    let results = assess::assess(&perfect_predictions, &examples);
    assess::print_results(&results);
    println!();
    println!("Note: predictions above are ground-truth (self-evaluation). Supply");
    println!("model output to assess real accuracy.");

    Ok(())
}

/// `sigint train finetune --base <tag> --output <name>` — run the configured trainer.
///
/// Loads `[train].finetune_command` from config, resolves paths for
/// `train.jsonl`/`test.jsonl` and the output adapter, and shells out to the
/// user-configured trainer (DEC-P24-001). Stdout/stderr stream live.
pub async fn run_finetune(
    core: AppCore,
    base: String,
    output: String,
    train_dir: Option<String>,
) -> Result<(), Error> {
    let cfg = &core.config.train;

    let data_dir = match train_dir {
        Some(p) => PathBuf::from(p),
        None => training_dir()?,
    };
    let train_jsonl = data_dir.join("train.jsonl");
    let test_jsonl = data_dir.join("test.jsonl");

    if !train_jsonl.exists() || !test_jsonl.exists() {
        return Err(Error::Other(format!(
            "Training data not found in {}. Run `sigint train export` first.",
            data_dir.display()
        )));
    }

    let job_dir = cfg
        .job_dir
        .clone()
        .map(Ok)
        .unwrap_or_else(training_dir)?;
    let output_path = job_dir.join(&output);

    let record = finetune::run_finetune(cfg, &base, &output_path, &train_jsonl, &test_jsonl)
        .map_err(|e| Error::Other(format!("fine-tune failed: {}", e)))?;

    let duration = record
        .finished_at
        .map(|f| f.signed_duration_since(record.started_at).num_seconds())
        .unwrap_or(0);

    println!();
    println!("Fine-tune job {}", record.id);
    println!("  status:    {:?}", record.status);
    println!("  base:      {}", record.base_model);
    println!("  output:    {}", record.output_path.display());
    println!("  exit_code: {:?}", record.exit_code);
    println!("  duration:  {}s", duration);
    Ok(())
}

/// `sigint train jobs` — list all recorded fine-tune jobs.
///
/// Reads `job_dir/jobs.json` (JSONL) and prints one line per record.
pub async fn run_jobs(core: AppCore) -> Result<(), Error> {
    let job_dir = core
        .config
        .train
        .job_dir
        .clone()
        .map(Ok)
        .unwrap_or_else(training_dir)?;

    let records = finetune::list_jobs(&job_dir)
        .map_err(|e| Error::Other(format!("failed to list jobs: {}", e)))?;

    if records.is_empty() {
        println!("No training jobs yet. Run `sigint train finetune ...` to start one.");
        return Ok(());
    }

    for r in &records {
        let duration = r
            .finished_at
            .map(|f| f.signed_duration_since(r.started_at).num_seconds())
            .map(|s| format!("{}s", s))
            .unwrap_or_else(|| "running".to_string());
        println!(
            "{}  {:?}  {} -> {}  {}  {}",
            &r.id[..r.id.len().min(8)],
            r.status,
            r.base_model,
            r.output_path.display(),
            r.started_at.to_rfc3339(),
            duration
        );
    }
    Ok(())
}

/// `sigint train evaluate --base <tag> --candidate <tag>` — live A/B comparison.
///
/// Loads test examples from test_data (or the default training dir), builds
/// two provider configs by cloning core.config.llm and mutating .model,
/// runs live inference on both, and prints a formatted comparison report.
/// Persists the result to job_dir/last_eval.json for Task 4's promote gate.
///
/// @decision DEC-P24-003
/// @title CLI drives run_comparison with factory-created providers
/// @status accepted
/// @rationale create_provider handles all provider-type dispatch centrally.
/// Mutating only .model on a cloned config means auth, base_url, and other
/// provider settings are inherited from the user's live config, so no extra
/// flags are needed for the common Ollama case. Unknown model tags surface
/// as a clean error pointing at `sigint doctor`.
pub async fn run_evaluate(
    core: AppCore,
    base: String,
    candidate: String,
    test_data: Option<String>,
) -> Result<(), Error> {
    let out_dir = training_dir()?;

    let test_path = match test_data {
        Some(ref p) => PathBuf::from(p),
        None => out_dir.join("test.jsonl"),
    };

    if !test_path.exists() {
        return Err(Error::Other(format!(
            "Test data not found at {}. Run `sigint train export` first.",
            test_path.display()
        )));
    }

    let examples = format::read_jsonl(&test_path)
        .map_err(|e| Error::Other(format!("failed to read test JSONL: {}", e)))?;

    if examples.is_empty() {
        return Err(Error::Other(
            "Test set is empty — no examples to compare against.".into(),
        ));
    }

    // Build two provider configs by cloning the live LLM config and mutating
    // only the model tag. This preserves base_url, auth, and provider type.
    let mut base_cfg = core.config.llm.clone();
    base_cfg.model = base.clone();

    let mut cand_cfg = core.config.llm.clone();
    cand_cfg.model = candidate.clone();

    let base_provider = create_provider(&base_cfg).map_err(|e| {
        Error::Other(format!(
            "Cannot create base provider for '{}': {}. Run `sigint doctor` to check your setup.",
            base, e
        ))
    })?;

    let cand_provider = create_provider(&cand_cfg).map_err(|e| {
        Error::Other(format!(
            "Cannot create candidate provider for '{}': {}. Run `sigint doctor` to check your setup.",
            candidate, e
        ))
    })?;

    println!(
        "Comparing {} examples: base='{}' vs candidate='{}'",
        examples.len(),
        base,
        candidate
    );
    println!();

    let report = evaluate::run_comparison(
        base_provider.as_ref(),
        cand_provider.as_ref(),
        &examples,
        &base,
        &candidate,
    )
    .await
    .map_err(|e| Error::Other(format!("comparison failed: {}", e)))?;

    // Print formatted report.
    println!(
        "Base:         {:<30}  tool_accuracy {:5.1}%  argument_match {:5.1}%",
        report.base_tag,
        report.base_results.tool_accuracy * 100.0,
        report.base_results.argument_accuracy * 100.0,
    );
    println!(
        "Candidate:    {:<30}  tool_accuracy {:5.1}%  argument_match {:5.1}%",
        report.candidate_tag,
        report.candidate_results.tool_accuracy * 100.0,
        report.candidate_results.argument_accuracy * 100.0,
    );
    println!();

    let delta_sign = |v: f64| if v >= 0.0 { "+" } else { "" };
    println!(
        "delta tool-acc:   {}{:.1}pp",
        delta_sign(report.tool_accuracy_delta),
        report.tool_accuracy_delta * 100.0,
    );
    println!(
        "delta arg-match:  {}{:.1}pp",
        delta_sign(report.argument_match_delta),
        report.argument_match_delta * 100.0,
    );
    println!();
    println!("Evaluated on {} test examples.", report.total_examples);

    // Persist last_eval.json in job_dir for Task 4's promote gate.
    let job_dir = core
        .config
        .train
        .job_dir
        .clone()
        .map(Ok)
        .unwrap_or_else(training_dir)?;

    evaluate::persist_last_eval(&job_dir, &report)
        .map_err(|e| Error::Other(format!("failed to persist last_eval.json: {}", e)))?;

    println!("Saved comparison report to {}/last_eval.json", job_dir.display());

    Ok(())
}
