//! Ollama Modelfile generation for fine-tuned models.
//!
//! Generates a Modelfile that can be consumed by `ollama create` to register
//! a fine-tuned model. The generated file includes the base model, an optional
//! LoRA adapter path, inference parameters, and the agent system prompt.
//!
//! @decision DEC-P24-007
//! @title Modelfile ADAPTER directive requires a real LoRA adapter binary path
//! @status accepted
//! @rationale Phase 23 (DEC-TRAIN-005) incorrectly pointed ADAPTER at the
//! training JSONL file. Ollama's ADAPTER directive expects a pre-trained
//! adapter binary (GGUF or safetensors), not training data. This fix makes
//! the ADAPTER line conditional: it is emitted only when `adapter_path` is
//! `Some`. When `None`, the Modelfile only declares FROM + optional SYSTEM,
//! suitable for packaging a base model with a custom persona without an
//! adapter. Callers that have completed fine-tuning pass the adapter path
//! explicitly; callers that have not (or are using a non-adapter workflow)
//! pass `None`. Supersedes DEC-TRAIN-005.

use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};

/// Generate an Ollama Modelfile at `output_path`.
///
/// @decision DEC-P24-007
/// @title Emit ADAPTER directive only when a real LoRA adapter binary is present
/// @status accepted
/// @rationale Passing `None` for `adapter_path` is the correct default until
/// the user has completed fine-tuning and has an actual adapter file. This
/// prevents the semantic error in Phase 23 where training JSONL was placed
/// under the ADAPTER directive. Supersedes DEC-TRAIN-005.
///
/// # Arguments
/// * `base_model`             — base Ollama model tag (e.g. `"llama3.2:8b"`)
/// * `adapter_path`           — path to a LoRA adapter binary; `None` skips the
///                              ADAPTER directive entirely
/// * `system_prompt_override` — if `Some`, replaces the default SIGINT system
///                              prompt embedded in the Modelfile
/// * `output_path`            — destination path for the generated Modelfile
pub fn generate_modelfile(
    base_model: &str,
    adapter_path: Option<&Path>,
    system_prompt_override: Option<&str>,
    output_path: &Path,
) -> Result<()> {
    let content = build_modelfile_content(base_model, adapter_path, system_prompt_override);

    let mut file = std::fs::File::create(output_path)
        .with_context(|| format!("failed to create Modelfile at {}", output_path.display()))?;

    file.write_all(content.as_bytes())
        .with_context(|| format!("failed to write Modelfile to {}", output_path.display()))?;

    Ok(())
}

/// Build the Modelfile content string without writing to disk.
///
/// Exposed for testing without requiring filesystem access.
/// The ADAPTER line is included only when `adapter_path` is `Some`.
pub fn build_modelfile_content(
    base_model: &str,
    adapter_path: Option<&Path>,
    system_prompt_override: Option<&str>,
) -> String {
    let adapter_line = adapter_path
        .map(|p| format!("ADAPTER {}\n", p.display()))
        .unwrap_or_default();

    let system_prompt = system_prompt_override.unwrap_or(
        "You are SIGINT, an AI-powered penetration testing agent. You have access to\n\
         security tools including nmap, gobuster, shell commands, and analysis utilities.\n\
         Use these tools methodically and accurately to complete reconnaissance, scanning,\n\
         and analysis tasks. Always use the most targeted tool for each task. Report\n\
         findings accurately without embellishment.",
    );

    format!(
        "FROM {base_model}\n\
         {adapter_line}\
         PARAMETER temperature 0.1\n\
         PARAMETER num_ctx 8192\n\
         \n\
         SYSTEM \"\"\"\n\
         {system_prompt}\n\
         \"\"\"\n",
        base_model = base_model,
        adapter_line = adapter_line,
        system_prompt = system_prompt,
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
        let content = build_modelfile_content("llama3.2:8b", None, None);
        assert!(
            content.contains("FROM llama3.2:8b"),
            "Modelfile must contain FROM directive"
        );
    }

    /// DEC-P24-007: no ADAPTER line when adapter_path is None.
    #[test]
    fn build_modelfile_no_adapter_when_none() {
        let content = build_modelfile_content("llama3.2:8b", None, None);
        assert!(
            !content.contains("ADAPTER"),
            "Modelfile must NOT contain ADAPTER when adapter_path is None; got:\n{content}"
        );
    }

    /// DEC-P24-007: ADAPTER line present and points to the given path when Some.
    #[test]
    fn build_modelfile_adapter_present_when_some() {
        let adapter = Path::new("/models/sigint-ft.gguf");
        let content = build_modelfile_content("llama3.2:8b", Some(adapter), None);
        assert!(
            content.contains("ADAPTER /models/sigint-ft.gguf"),
            "Modelfile must contain ADAPTER directive when path is Some; got:\n{content}"
        );
    }

    #[test]
    fn build_modelfile_content_contains_system() {
        let content = build_modelfile_content("llama3.2:8b", None, None);
        assert!(
            content.contains("SYSTEM"),
            "Modelfile must contain SYSTEM prompt"
        );
    }

    #[test]
    fn build_modelfile_content_contains_parameters() {
        let content = build_modelfile_content("llama3.2:8b", None, None);
        assert!(content.contains("PARAMETER temperature"));
        assert!(content.contains("PARAMETER num_ctx"));
    }

    #[test]
    fn build_modelfile_system_prompt_override() {
        let content =
            build_modelfile_content("llama3.2:8b", None, Some("Custom system prompt here."));
        assert!(content.contains("Custom system prompt here."));
        assert!(!content.contains("SIGINT, an AI-powered"));
    }

    /// DEC-P24-007: exactly one ADAPTER line when path is Some.
    #[test]
    fn build_modelfile_exactly_one_adapter_line_when_some() {
        let adapter = Path::new("/models/adapter.gguf");
        let content = build_modelfile_content("llama3.2:8b", Some(adapter), None);
        let adapter_count = content.lines().filter(|l| l.starts_with("ADAPTER")).count();
        assert_eq!(
            adapter_count, 1,
            "expected exactly 1 ADAPTER line, found {adapter_count}"
        );
    }

    #[test]
    fn generate_modelfile_writes_to_disk_no_adapter() {
        let out_path = tempfile_path();
        generate_modelfile("llama3.2:8b", None, None, &out_path).unwrap();

        let content = std::fs::read_to_string(&out_path).unwrap();
        assert!(content.contains("FROM llama3.2:8b"));
        assert!(!content.contains("ADAPTER"));

        let _ = std::fs::remove_file(&out_path);
    }

    #[test]
    fn generate_modelfile_writes_to_disk_with_adapter() {
        let out_path = tempfile_path();
        let adapter = Path::new("/models/ft.gguf");
        generate_modelfile("llama3.2:8b", Some(adapter), None, &out_path).unwrap();

        let content = std::fs::read_to_string(&out_path).unwrap();
        assert!(content.contains("FROM llama3.2:8b"));
        assert!(content.contains("ADAPTER /models/ft.gguf"));

        let _ = std::fs::remove_file(&out_path);
    }

    #[test]
    fn generate_modelfile_missing_dir_returns_error() {
        let bad_path = Path::new("/nonexistent/dir/Modelfile");
        let result = generate_modelfile("llama3.2:8b", None, None, bad_path);
        assert!(result.is_err());
    }
}
