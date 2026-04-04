//! `sigint model` — manage local GGUF model files.
//!
//! Three subcommands:
//!
//! * `list`  — scan `models_dir` and print a table of available GGUF files.
//! * `pull`  — download a GGUF file from HuggingFace (repo ID) or a direct URL.
//! * `info`  — print detailed metadata for a named model file.
//!
//! @decision DEC-P19-MODEL-CLI-001
//! @title model pull uses blocking reqwest streaming without indicatif
//! @status accepted
//! @rationale The pull command needs download progress without adding the
//! `indicatif` crate. A simple byte counter printed every megabyte satisfies
//! the UX requirement while keeping the dependency surface minimal. Reqwest
//! is already a workspace dependency used in the doctor command.

use std::io::Write;
use std::path::{Path, PathBuf};

use sigint_core::{AppCore, Error};
use sigint_llm::GgufMetadata;

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

    let download_url = format!(
        "https://huggingface.co/{}/resolve/main/{}",
        repo, chosen
    );

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
    let size_w = rows.iter().map(|(_, s, ..)| s.len()).max().unwrap_or(4).max(4);
    let quant_w = rows.iter().map(|(_, _, q, _)| q.len()).max().unwrap_or(4).max(4);

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
        let filename = source
            .rsplit('/')
            .next()
            .unwrap_or("model.gguf")
            .to_owned();
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
