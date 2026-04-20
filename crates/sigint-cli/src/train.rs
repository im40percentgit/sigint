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
use sigint_train::{assess, extract, format, modelfile, split, stats};

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
