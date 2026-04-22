//! `sigint model` — manage local GGUF model files.
//!
//! Five subcommands:
//!
//! * `list`     — scan `models_dir` and print a table of available GGUF files.
//! * `pull`     — download a GGUF file from HuggingFace (repo ID) or a direct URL.
//! * `info`     — print detailed metadata for a named model file.
//! * `promote`  — atomically rewrite config to activate a fine-tuned model.
//! * `rollback` — revert to the last promoted model using the promotion log.
//!
//! @decision DEC-P19-MODEL-CLI-001
//! @title model pull uses blocking reqwest streaming without indicatif
//! @status accepted
//! @rationale The pull command needs download progress without adding the
//! `indicatif` crate. A simple byte counter printed every megabyte satisfies
//! the UX requirement while keeping the dependency surface minimal. Reqwest
//! is already a workspace dependency used in the doctor command.
//!
//! @decision DEC-P24-004
//! @title Promotion rewrites config.llm.model atomically via a CLI command
//! @status accepted
//! @rationale Atomic write (tmp + rename) ensures the config is never in a
//! partial state even if the process is killed mid-write. Backup to .bak
//! before every promotion. Append-only promotion.log provides audit trail.
//! Chosen over: config flag (no audit trail), background watcher (premature,
//! non-deterministic). Addresses: REQ-P24-P0-004.
//!
//! @decision DEC-P24-005
//! @title Rollback is manual only (sigint model rollback)
//! @status accepted
//! @rationale No auto-rollback on eval-regression threshold. Keeps the user in
//! control; avoids model-swap thrashing. Rollback reads the last promotion.log
//! entry and reverses it, appending a new rollback entry (never deletes history).
//! Addresses: REQ-P24-P0-005.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use sigint_core::{AppCore, Config, Error};
use sigint_llm::GgufMetadata;

// ── Promotion log types ───────────────────────────────────────────────────────

/// One entry in the append-only `promotion.log` JSONL file.
///
/// Each `promote` or `rollback` command appends exactly one entry.
/// The log is the audit trail for all model-swap operations; nothing is
/// ever deleted from it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromotionEntry {
    /// UTC timestamp when this action was recorded.
    pub ts: DateTime<Utc>,
    /// Action type: "promote" or "rollback".
    pub action: String,
    /// Provider value before this operation.
    pub old_provider: String,
    /// Model value before this operation.
    pub old_model: String,
    /// Provider value after this operation.
    pub new_provider: String,
    /// Model value after this operation.
    pub new_model: String,
    /// Path to `last_eval.json` at promote time (if it existed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eval_result_ref: Option<PathBuf>,
}

// ── Promote / rollback helpers ────────────────────────────────────────────────

/// Resolve the promotion-log directory (same root as job_dir).
///
/// Returns `config.train.job_dir` if set, otherwise
/// `~/.local/share/sigint/training/` (matching `resolve_job_dir` in finetune.rs).
fn resolve_promo_dir(core: &AppCore) -> PathBuf {
    if let Some(ref dir) = core.config.train.job_dir {
        return dir.clone();
    }
    let home = std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."));
    home.join(".local")
        .join("share")
        .join("sigint")
        .join("training")
}

/// Append a `PromotionEntry` to `promo_dir/promotion.log` (JSONL, never truncated).
fn append_promotion_log(promo_dir: &Path, entry: &PromotionEntry) -> Result<(), Error> {
    std::fs::create_dir_all(promo_dir).map_err(|e| {
        Error::Other(format!(
            "Cannot create promotion log dir {}: {}",
            promo_dir.display(),
            e
        ))
    })?;

    let log_path = promo_dir.join("promotion.log");
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(&log_path)
        .map_err(|e| Error::Other(format!("Cannot open {}: {}", log_path.display(), e)))?;

    let line = serde_json::to_string(entry)
        .map_err(|e| Error::Other(format!("Serialise error: {}", e)))?;
    writeln!(file, "{}", line)
        .map_err(|e| Error::Other(format!("Write error on {}: {}", log_path.display(), e)))?;

    Ok(())
}

/// Read all entries from `promo_dir/promotion.log`.
///
/// Malformed lines are skipped with a warning. Returns an empty Vec if the
/// file does not exist.
fn read_promotion_log(promo_dir: &Path) -> Result<Vec<PromotionEntry>, Error> {
    let log_path = promo_dir.join("promotion.log");
    if !log_path.exists() {
        return Ok(Vec::new());
    }

    let contents = std::fs::read_to_string(&log_path)
        .map_err(|e| Error::Other(format!("Cannot read {}: {}", log_path.display(), e)))?;

    let mut entries = Vec::new();
    for (i, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<PromotionEntry>(line) {
            Ok(e) => entries.push(e),
            Err(e) => eprintln!(
                "warning: skipping malformed line {} in promotion.log: {}",
                i + 1,
                e
            ),
        }
    }

    Ok(entries)
}

/// Detect whether `tag` refers to an embedded GGUF file or an Ollama model tag.
///
/// Detection order (DEC-P24-008):
/// 1. Check `models_dir/<tag>` — if it exists and ends in `.gguf`, → embedded.
/// 2. Check `models_dir/<tag>.gguf` — if it exists, → embedded.
/// 3. Probe `ollama list` for the tag name — if found, → ollama.
/// 4. Otherwise → Err with both paths and the ollama-list output for diagnosis.
///
/// Returns `(provider, model_path_or_tag)`.
///
/// @decision DEC-P24-008
/// @title Fine-tune output format is detected, not prescribed
/// @status accepted
/// @rationale Respects user toolchain diversity without forcing one output kind.
/// If $SIGINT_OUTPUT_PATH resolves to an existing .gguf file, treat as embedded.
/// If not, probe ollama list for the basename. Addresses: REQ-P24-P0-004.
fn detect_output_kind(models_dir: &Path, tag: &str) -> Result<(String, String), Error> {
    // Try direct hit: models_dir/<tag>
    let direct = models_dir.join(tag);
    if direct.exists() && direct.extension().and_then(|e| e.to_str()) == Some("gguf") {
        return Ok((
            "embedded".to_string(),
            direct.to_string_lossy().into_owned(),
        ));
    }

    // Try with extension appended: models_dir/<tag>.gguf
    let with_ext = models_dir.join(format!("{}.gguf", tag));
    if with_ext.exists() {
        return Ok((
            "embedded".to_string(),
            with_ext.to_string_lossy().into_owned(),
        ));
    }

    // Probe ollama list.
    let ollama_output = Command::new("ollama")
        .arg("list")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();

    // Check if any line in ollama list output contains the tag as a leading token.
    let found_in_ollama = ollama_output.lines().any(|line| {
        let first_token = line.split_whitespace().next().unwrap_or("");
        first_token == tag || first_token.starts_with(&format!("{}:", tag))
    });

    if found_in_ollama {
        return Ok(("ollama".to_string(), tag.to_string()));
    }

    Err(Error::Other(format!(
        "Model tag '{}' not found.\n\
         Checked GGUF paths:\n  {}\n  {}\n\
         Checked Ollama (tag not in `ollama list` output).\n\
         To use an embedded model, place the .gguf file in {} and re-run.\n\
         To use an Ollama model, run `ollama pull {}` first.",
        tag,
        direct.display(),
        with_ext.display(),
        models_dir.display(),
        tag,
    )))
}

/// Atomically rewrite the config file with updated `llm.provider` and `llm.model`.
///
/// Steps:
/// 1. Read current config path.
/// 2. Backup to `<config>.bak` (overwrite any prior .bak).
/// 3. Mutate the in-memory Config.
/// 4. Serialize to TOML and write to `<config>.tmp`.
/// 5. `fs::rename(&tmp, &config_path)` — atomic on POSIX.
///
/// Comment loss during round-trip is expected and noted in commit body.
/// DEC-P24-004.
fn atomic_config_rewrite(
    config_path: &Path,
    new_provider: &str,
    new_model: &str,
) -> Result<(), Error> {
    // Load the current config (or use defaults if file is absent).
    let mut cfg = if config_path.exists() {
        Config::load_from(config_path)?
    } else {
        Config::default()
    };

    cfg.llm.provider = new_provider.to_string();
    cfg.llm.model = new_model.to_string();

    let toml_str = toml::to_string_pretty(&cfg)
        .map_err(|e| Error::Other(format!("TOML serialise error: {}", e)))?;

    // Backup current config before any write.
    if config_path.exists() {
        let bak = config_path.with_extension("bak");
        std::fs::copy(config_path, &bak).map_err(|e| {
            Error::Other(format!(
                "Cannot backup {} -> {}: {}",
                config_path.display(),
                bak.display(),
                e
            ))
        })?;
    }

    // Ensure parent directory exists (first-run case where config was never written).
    if let Some(parent) = config_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            Error::Other(format!(
                "Cannot create config dir {}: {}",
                parent.display(),
                e
            ))
        })?;
    }

    // Write to .tmp then rename (atomic on POSIX).
    let tmp_path = config_path.with_extension("tmp");
    std::fs::write(&tmp_path, &toml_str)
        .map_err(|e| Error::Other(format!("Cannot write {}: {}", tmp_path.display(), e)))?;

    std::fs::rename(&tmp_path, config_path).map_err(|e| {
        // Clean up the .tmp on failure; ignore cleanup errors.
        let _ = std::fs::remove_file(&tmp_path);
        Error::Other(format!(
            "Cannot rename {} -> {}: {}",
            tmp_path.display(),
            config_path.display(),
            e
        ))
    })?;

    Ok(())
}

// ── Public handlers ───────────────────────────────────────────────────────────

/// `sigint model promote <tag>` — promote a fine-tuned model to active use.
///
/// Checks the P1 gate (min_eval_examples), detects the output kind (GGUF or
/// Ollama tag), backs up the current config, atomically rewrites it, and
/// appends to the promotion log.
///
/// @decision DEC-P24-004
/// @title Promotion rewrites config.llm.model atomically via a CLI command
/// @status accepted
/// @rationale See module-level doc.
pub async fn run_promote(core: AppCore, tag: String, force: bool) -> Result<(), Error> {
    let promo_dir = resolve_promo_dir(&core);
    let models_dir = core.config.resolved_models_dir();

    // ── P1 gate: check last_eval.json ──────────────────────────────────────
    let eval_ref = {
        let eval_path = promo_dir.join("last_eval.json");
        if eval_path.exists() {
            // Parse just enough to read total_examples.
            let raw = std::fs::read_to_string(&eval_path)
                .map_err(|e| Error::Other(format!("Cannot read {}: {}", eval_path.display(), e)))?;
            let val: serde_json::Value = serde_json::from_str(&raw).map_err(|e| {
                Error::Other(format!("Cannot parse {}: {}", eval_path.display(), e))
            })?;

            let total = val["total_examples"]
                .as_u64()
                .map(|n| n as usize)
                .unwrap_or(0);

            let min = core.config.train.min_eval_examples;
            if total < min && !force {
                return Err(Error::Other(format!(
                    "Last evaluation had {} examples (minimum: {}). \
                     Run `sigint train evaluate` with more data, or pass --force to promote anyway.",
                    total, min
                )));
            }

            if total < min {
                eprintln!(
                    "WARNING: promoting despite only {} evaluation examples (minimum: {}). \
                     Model quality is not guaranteed.",
                    total, min
                );
            }

            Some(eval_path)
        } else {
            eprintln!(
                "WARNING: no last_eval.json found in {}. \
                 Run `sigint train evaluate` before promoting for quality assurance.",
                promo_dir.display()
            );
            None
        }
    };

    // ── Detect output kind (DEC-P24-008) ───────────────────────────────────
    let (new_provider, new_model) = detect_output_kind(&models_dir, &tag)?;

    let old_provider = core.config.llm.provider.clone();
    let old_model = core.config.llm.model.clone();

    // ── Atomic config rewrite ──────────────────────────────────────────────
    let config_path = Config::config_path();
    atomic_config_rewrite(&config_path, &new_provider, &new_model)?;

    // ── Append promotion log entry ─────────────────────────────────────────
    let entry = PromotionEntry {
        ts: Utc::now(),
        action: "promote".to_string(),
        old_provider: old_provider.clone(),
        old_model: old_model.clone(),
        new_provider: new_provider.clone(),
        new_model: new_model.clone(),
        eval_result_ref: eval_ref,
    };
    append_promotion_log(&promo_dir, &entry)?;

    println!(
        "Promoted: {} ({}) -> {} ({})",
        old_model, old_provider, new_model, new_provider
    );
    println!("Config written to: {}", config_path.display());
    println!("Backup at: {}", config_path.with_extension("bak").display());

    Ok(())
}

/// `sigint model rollback` — revert to the model active before the last promotion.
///
/// Reads the last entry from `promotion.log` and reverses the provider/model
/// swap, appending a new rollback entry. Never deletes existing log entries.
///
/// @decision DEC-P24-005
/// @title Rollback is manual only (sigint model rollback)
/// @status accepted
/// @rationale See module-level doc.
pub async fn run_rollback(core: AppCore) -> Result<(), Error> {
    let promo_dir = resolve_promo_dir(&core);
    let entries = read_promotion_log(&promo_dir)?;

    let last = entries.last().ok_or_else(|| {
        Error::Other(
            "No promotion history to roll back from. \
             Run `sigint model promote <tag>` first."
                .to_string(),
        )
    })?;

    // Reverse: what we're rolling back to is the old_* values.
    let restore_provider = last.old_provider.clone();
    let restore_model = last.old_model.clone();
    let current_provider = last.new_provider.clone();
    let current_model = last.new_model.clone();

    let config_path = Config::config_path();
    atomic_config_rewrite(&config_path, &restore_provider, &restore_model)?;

    let rollback_entry = PromotionEntry {
        ts: Utc::now(),
        action: "rollback".to_string(),
        old_provider: current_provider.clone(),
        old_model: current_model.clone(),
        new_provider: restore_provider.clone(),
        new_model: restore_model.clone(),
        eval_result_ref: None,
    };
    append_promotion_log(&promo_dir, &rollback_entry)?;

    println!(
        "Rolled back: {} ({}) -> {} ({})",
        current_model, current_provider, restore_model, restore_provider
    );
    println!("Config written to: {}", config_path.display());

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Format a byte count as a human-readable string (KiB, MiB, GiB).
pub fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Given a HuggingFace repo ID (e.g. `"meta-llama/Llama-3.2-8B-GGUF"`),
/// query the HF API to list files and return the download URL for the best
/// GGUF candidate.
///
/// Selection priority:
/// 1. First filename containing "Q4_K_M" (case-insensitive).
/// 2. Otherwise, the first file ending in `.gguf`.
///
/// Returns `(filename, download_url)`.
pub async fn resolve_hf_download(
    client: &reqwest::Client,
    repo: &str,
) -> Result<(String, String), Error> {
    let api_url = format!("https://huggingface.co/api/models/{}/tree/main", repo);
    let resp = client
        .get(&api_url)
        .send()
        .await
        .map_err(|e| Error::Other(format!("HuggingFace API request failed: {}", e)))?;

    if !resp.status().is_success() {
        return Err(Error::Other(format!(
            "HuggingFace API returned HTTP {} for repo '{}'",
            resp.status(),
            repo
        )));
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| Error::Other(format!("Failed to parse HuggingFace API response: {}", e)))?;

    let files = body
        .as_array()
        .ok_or_else(|| Error::Other("Unexpected HuggingFace API response format".into()))?;

    let gguf_files: Vec<&str> = files
        .iter()
        .filter_map(|f| {
            let path = f["path"].as_str()?;
            if path.to_lowercase().ends_with(".gguf") {
                Some(path)
            } else {
                None
            }
        })
        .collect();

    if gguf_files.is_empty() {
        return Err(Error::Other(format!(
            "No GGUF files found in HuggingFace repo '{}'",
            repo
        )));
    }

    // Prefer Q4_K_M quantisation; fall back to first GGUF.
    let chosen = gguf_files
        .iter()
        .find(|f| f.to_lowercase().contains("q4_k_m"))
        .unwrap_or(&gguf_files[0]);

    // Strip any leading directory components to get just the filename.
    let filename = chosen.rsplit('/').next().unwrap_or(chosen).to_owned();

    let download_url = format!("https://huggingface.co/{}/resolve/main/{}", repo, chosen);

    Ok((filename, download_url))
}

/// Resolve a `<name>` argument to a path inside `models_dir`.
///
/// Tries `models_dir/<name>` first, then `models_dir/<name>.gguf`.
pub fn resolve_model_path(models_dir: &Path, name: &str) -> Result<PathBuf, Error> {
    let direct = models_dir.join(name);
    if direct.exists() {
        return Ok(direct);
    }
    let with_ext = models_dir.join(format!("{}.gguf", name));
    if with_ext.exists() {
        return Ok(with_ext);
    }
    Err(Error::Other(format!(
        "Model '{}' not found in {} (tried {:?} and {:?})",
        name,
        models_dir.display(),
        direct,
        with_ext
    )))
}

// ── Subcommand handlers ───────────────────────────────────────────────────────

/// `sigint model list` — list GGUF files in the configured models directory.
pub async fn run_list(core: AppCore) -> Result<(), Error> {
    let models_dir = core.config.resolved_models_dir();

    if !models_dir.exists() {
        println!("No models directory found at {}.", models_dir.display());
        println!("Download a model with:  sigint model pull meta-llama/Llama-3.2-8B-GGUF");
        return Ok(());
    }

    let entries = std::fs::read_dir(&models_dir)
        .map_err(|e| Error::Other(format!("Cannot read {}: {}", models_dir.display(), e)))?;

    let mut rows: Vec<(String, String, String, String)> = Vec::new();

    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("gguf") {
            continue;
        }

        let (name, size, quant, ctx) = match GgufMetadata::read(&path) {
            Ok(meta) => {
                let name = meta.model_name();
                let size = format_bytes(meta.file_size);
                let quant = meta.quantization_name().unwrap_or_else(|| "?".into());
                let ctx = meta
                    .context_length()
                    .map(|n| format!("{}", n))
                    .unwrap_or_else(|| "?".into());
                (name, size, quant, ctx)
            }
            Err(_) => {
                // Still list the file even if metadata can't be read.
                let fname = path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned();
                let size = std::fs::metadata(&path)
                    .map(|m| format_bytes(m.len()))
                    .unwrap_or_else(|_| "?".into());
                (fname, size, "?".into(), "?".into())
            }
        };

        rows.push((name, size, quant, ctx));
    }

    if rows.is_empty() {
        println!("No GGUF models found in {}.", models_dir.display());
        println!("Download a model with:  sigint model pull meta-llama/Llama-3.2-8B-GGUF");
        return Ok(());
    }

    // Print table.
    let name_w = rows.iter().map(|(n, ..)| n.len()).max().unwrap_or(4).max(4);
    let size_w = rows
        .iter()
        .map(|(_, s, ..)| s.len())
        .max()
        .unwrap_or(4)
        .max(4);
    let quant_w = rows
        .iter()
        .map(|(_, _, q, _)| q.len())
        .max()
        .unwrap_or(4)
        .max(4);

    println!(
        "{:<name_w$}  {:>size_w$}  {:<quant_w$}  Context",
        "Name",
        "Size",
        "Quant",
        name_w = name_w,
        size_w = size_w,
        quant_w = quant_w
    );
    println!(
        "{:-<name_w$}  {:->size_w$}  {:-<quant_w$}  -------",
        "",
        "",
        "",
        name_w = name_w,
        size_w = size_w,
        quant_w = quant_w
    );
    for (name, size, quant, ctx) in &rows {
        println!(
            "{:<name_w$}  {:>size_w$}  {:<quant_w$}  {}",
            name,
            size,
            quant,
            ctx,
            name_w = name_w,
            size_w = size_w,
            quant_w = quant_w
        );
    }

    Ok(())
}

/// `sigint model pull <source>` — download a GGUF model.
///
/// Source forms:
/// - `owner/repo` (contains `/` but not `://`) — HuggingFace repo
/// - `https://...` or `http://...` — direct URL
pub async fn run_pull(core: AppCore, source: String) -> Result<(), Error> {
    let models_dir = core.config.resolved_models_dir();
    std::fs::create_dir_all(&models_dir)
        .map_err(|e| Error::Other(format!("Cannot create {}: {}", models_dir.display(), e)))?;

    let client = reqwest::Client::builder()
        .user_agent("sigint/0.1 (model-downloader)")
        .build()
        .map_err(|e| Error::Other(format!("Cannot build HTTP client: {}", e)))?;

    let (filename, download_url) = if source.contains("://") {
        // Direct URL — derive filename from the last path component.
        let filename = source.rsplit('/').next().unwrap_or("model.gguf").to_owned();
        (filename, source.clone())
    } else if source.contains('/') {
        // HuggingFace repo ID.
        println!("Querying HuggingFace for repo '{}'...", source);
        resolve_hf_download(&client, &source).await?
    } else {
        return Err(Error::Other(format!(
            "Cannot parse source '{}'. \
            Provide a HuggingFace repo (e.g. meta-llama/Llama-3.2-8B-GGUF) \
            or a direct URL.",
            source
        )));
    };

    let dest = models_dir.join(&filename);
    println!("Downloading {} -> {}", download_url, dest.display());

    let resp = client
        .get(&download_url)
        .send()
        .await
        .map_err(|e| Error::Other(format!("Download request failed: {}", e)))?;

    if !resp.status().is_success() {
        return Err(Error::Other(format!(
            "Download returned HTTP {}",
            resp.status()
        )));
    }

    let total = resp.content_length();

    let mut file = std::fs::File::create(&dest)
        .map_err(|e| Error::Other(format!("Cannot create {}: {}", dest.display(), e)))?;

    use futures_util::StreamExt;
    let mut stream = resp.bytes_stream();
    let mut downloaded: u64 = 0;
    let mut last_report: u64 = 0;
    const REPORT_INTERVAL: u64 = 1024 * 1024; // 1 MiB

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| Error::Other(format!("Download stream error: {}", e)))?;
        file.write_all(&chunk)
            .map_err(|e| Error::Other(format!("Write error: {}", e)))?;
        downloaded += chunk.len() as u64;

        if downloaded - last_report >= REPORT_INTERVAL {
            last_report = downloaded;
            if let Some(total) = total {
                let pct = downloaded * 100 / total;
                print!(
                    "\r  {} / {} ({}%)",
                    format_bytes(downloaded),
                    format_bytes(total),
                    pct
                );
            } else {
                print!("\r  {} downloaded", format_bytes(downloaded));
            }
            let _ = std::io::stdout().flush();
        }
    }

    // Final newline after progress output.
    if downloaded >= REPORT_INTERVAL || total.is_some() {
        println!();
    }

    println!("Done. Saved to {}", dest.display());
    Ok(())
}

/// `sigint model info <name>` — print detailed metadata for a GGUF model.
pub async fn run_info(core: AppCore, name: String) -> Result<(), Error> {
    let models_dir = core.config.resolved_models_dir();
    let path = resolve_model_path(&models_dir, &name)?;

    let meta = GgufMetadata::read(&path)?;

    println!("File:           {}", path.display());
    println!("Size:           {}", format_bytes(meta.file_size));
    println!("GGUF version:   {}", meta.version);
    println!("Tensor count:   {}", meta.tensor_count);
    println!(
        "Architecture:   {}",
        meta.architecture().unwrap_or("unknown")
    );
    println!("Model name:     {}", meta.model_name());
    println!(
        "Quantization:   {}",
        meta.quantization_name().unwrap_or_else(|| "unknown".into())
    );
    println!(
        "Context length: {}",
        meta.context_length()
            .map(|n| format!("{} tokens", n))
            .unwrap_or_else(|| "unknown".into())
    );
    if let Some(params) = meta.parameter_count() {
        let billions = params as f64 / 1_000_000_000.0;
        println!("Parameters:     {:.1}B (approx)", billions);
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── format_bytes ──────────────────────────────────────────────────────────

    #[test]
    fn format_bytes_gib() {
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GiB");
        assert_eq!(format_bytes(4 * 1024 * 1024 * 1024), "4.0 GiB");
    }

    #[test]
    fn format_bytes_mib() {
        assert_eq!(format_bytes(1024 * 1024), "1.0 MiB");
        assert_eq!(format_bytes(512 * 1024 * 1024), "512.0 MiB");
    }

    #[test]
    fn format_bytes_kib() {
        assert_eq!(format_bytes(1024), "1.0 KiB");
    }

    #[test]
    fn format_bytes_bytes() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(0), "0 B");
    }

    // ── resolve_model_path ────────────────────────────────────────────────────

    #[test]
    fn resolve_model_path_direct_hit() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("llama.gguf");
        std::fs::write(&path, b"fake").unwrap();

        let result = resolve_model_path(&dir.path().to_path_buf(), "llama.gguf");
        assert!(result.is_ok(), "{:?}", result);
        assert_eq!(result.unwrap(), path);
    }

    #[test]
    fn resolve_model_path_adds_extension() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("llama.gguf");
        std::fs::write(&path, b"fake").unwrap();

        // Pass "llama" without extension -- should still resolve.
        let result = resolve_model_path(&dir.path().to_path_buf(), "llama");
        assert!(result.is_ok(), "{:?}", result);
        assert_eq!(result.unwrap(), path);
    }

    #[test]
    fn resolve_model_path_not_found() {
        let dir = tempfile::tempdir().expect("tempdir");
        let result = resolve_model_path(&dir.path().to_path_buf(), "nonexistent");
        assert!(result.is_err());
    }

    // ── Source classification (inline logic) ──────────────────────────────────

    #[test]
    fn source_classification_direct_url() {
        let source = "https://example.com/files/model.gguf";
        assert!(source.contains("://"));
        let filename = source.rsplit('/').next().unwrap_or("model.gguf");
        assert_eq!(filename, "model.gguf");
    }

    #[test]
    fn source_classification_hf_repo() {
        let source = "meta-llama/Llama-3.2-8B-GGUF";
        assert!(!source.contains("://"));
        assert!(source.contains('/'));
    }

    #[test]
    fn source_classification_invalid() {
        let source = "just-a-name";
        assert!(!source.contains("://"));
        assert!(!source.contains('/'));
    }
}
