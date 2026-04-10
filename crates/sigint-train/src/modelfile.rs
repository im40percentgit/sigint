//! Ollama Modelfile generation for fine-tuned models.
//!
//! Generates a Modelfile that can be consumed by `ollama create` to register
//! a fine-tuned model. The generated file includes the base model, adapter
//! path, inference parameters, and the agent system prompt.
//!
//! @decision DEC-TRAIN-005
//! @title Modelfile uses ADAPTER directive pointing to training data path
//! @status accepted
//! @rationale Ollama's Modelfile format supports ADAPTER for LoRA adapters
//! produced by fine-tuning. Pointing ADAPTER at the training JSONL path
//! gives users a clear starting point — they replace the path with their
//! actual adapter after running their fine-tuning toolchain. The SYSTEM
//! prompt is embedded so the resulting model inherits the correct persona
//! without the caller needing to set it at inference time.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};

/// Generate an Ollama Modelfile at `output_path`.
///
/// # Arguments
/// * `base_model` — base Ollama model tag (e.g. `"llama3.2:8b"`)
/// * `training_data_path` — path to the training JSONL file (used as ADAPTER)
/// * `output_path` — destination path for the generated Modelfile
pub fn generate_modelfile(
    base_model: &str,
    training_data_path: &Path,
    output_path: &Path,
) -> Result<()> {
    let content = build_modelfile_content(base_model, training_data_path);

    let mut file = std::fs::File::create(output_path)
        .with_context(|| format!("failed to create Modelfile at {}", output_path.display()))?;

    file.write_all(content.as_bytes())
        .with_context(|| format!("failed to write Modelfile to {}", output_path.display()))?;

    Ok(())
}

/// Build the Modelfile content string without writing to disk.
///
/// Exposed for testing without requiring filesystem access.
pub fn build_modelfile_content(base_model: &str, training_data_path: &Path) -> String {
    format!(
        r#"FROM {base_model}
ADAPTER {adapter_path}

PARAMETER temperature 0.1
PARAMETER num_ctx 8192

SYSTEM """
You are SIGINT, an AI-powered penetration testing agent. You have access to
security tools including nmap, gobuster, shell commands, and analysis utilities.
Use these tools methodically and accurately to complete reconnaissance, scanning,
and analysis tasks. Always use the most targeted tool for each task. Report
findings accurately without embellishment.
"""
"#,
        base_model = base_model,
        adapter_path = training_data_path.display(),
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use uuid::Uuid;

    fn tempfile_path() -> PathBuf {
        std::env::temp_dir().join(format!("sigint-modelfile-{}", Uuid::new_v4()))
    }

    #[test]
    fn build_modelfile_content_contains_from() {
        let content = build_modelfile_content("llama3.2:8b", Path::new("/data/train.jsonl"));
        assert!(
            content.contains("FROM llama3.2:8b"),
            "Modelfile must contain FROM directive"
        );
    }

    #[test]
    fn build_modelfile_content_contains_adapter() {
        let content = build_modelfile_content("llama3.2:8b", Path::new("/data/train.jsonl"));
        assert!(
            content.contains("ADAPTER /data/train.jsonl"),
            "Modelfile must contain ADAPTER directive"
        );
    }

    #[test]
    fn build_modelfile_content_contains_system() {
        let content = build_modelfile_content("llama3.2:8b", Path::new("/data/train.jsonl"));
        assert!(
            content.contains("SYSTEM"),
            "Modelfile must contain SYSTEM prompt"
        );
    }

    #[test]
    fn build_modelfile_content_contains_parameters() {
        let content = build_modelfile_content("llama3.2:8b", Path::new("/data/train.jsonl"));
        assert!(content.contains("PARAMETER temperature"));
        assert!(content.contains("PARAMETER num_ctx"));
    }

    #[test]
    fn generate_modelfile_writes_to_disk() {
        let out_path = tempfile_path();
        generate_modelfile(
            "llama3.2:8b",
            Path::new("/tmp/train.jsonl"),
            &out_path,
        )
        .unwrap();

        let content = std::fs::read_to_string(&out_path).unwrap();
        assert!(content.contains("FROM llama3.2:8b"));
        assert!(content.contains("ADAPTER /tmp/train.jsonl"));

        let _ = std::fs::remove_file(&out_path);
    }

    #[test]
    fn generate_modelfile_missing_dir_returns_error() {
        let bad_path = Path::new("/nonexistent/dir/Modelfile");
        let result = generate_modelfile("llama3.2:8b", Path::new("/data/train.jsonl"), bad_path);
        assert!(result.is_err());
    }
}
