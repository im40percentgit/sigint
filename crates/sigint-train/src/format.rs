//! JSONL serialization for TrainingExample data.
//!
//! Writes one JSON object per line (newline-delimited JSON) in OpenAI
//! chat-completion format. Each line is a self-contained TrainingExample
//! that can be fed directly to Ollama or compatible fine-tuning tools.
//!
//! @decision DEC-TRAIN-003
//! @title One JSON object per line (JSONL) with no session_id field
//! @status accepted
//! @rationale JSONL is the standard format for LLM fine-tuning datasets.
//! The session_id field is excluded via #[serde(skip_serializing)] so
//! output files are compatible with Ollama, Axolotl, and other toolchains
//! that validate strict OpenAI chat-completion schema.

use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

use anyhow::{Context, Result};

use crate::TrainingExample;

/// Write training examples to a JSONL file (one JSON object per line).
///
/// Returns the number of examples written.
/// Creates or truncates the file at `path`.
pub fn write_jsonl(examples: &[TrainingExample], path: &Path) -> Result<usize> {
    let file = File::create(path)
        .with_context(|| format!("failed to create JSONL file: {}", path.display()))?;
    let mut writer = BufWriter::new(file);

    let mut count = 0;
    for example in examples {
        let line = serde_json::to_string(example)
            .with_context(|| "failed to serialize TrainingExample")?;
        writeln!(writer, "{}", line)
            .with_context(|| format!("failed to write line to {}", path.display()))?;
        count += 1;
    }

    writer
        .flush()
        .with_context(|| format!("failed to flush {}", path.display()))?;
    Ok(count)
}

/// Read training examples from a JSONL file.
///
/// Each non-empty line is parsed as a `TrainingExample`. Returns an error
/// if any line fails to parse. The `session_id` field will be default
/// (nil UUID) since it is excluded from serialization.
pub fn read_jsonl(path: &Path) -> Result<Vec<TrainingExample>> {
    let file = File::open(path)
        .with_context(|| format!("failed to open JSONL file: {}", path.display()))?;
    let reader = BufReader::new(file);

    let mut examples = Vec::new();
    for (i, line) in reader.lines().enumerate() {
        let line = line.with_context(|| format!("failed to read line {} from JSONL", i + 1))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let example: TrainingExample = serde_json::from_str(trimmed)
            .with_context(|| format!("failed to parse JSON on line {}", i + 1))?;
        examples.push(example);
    }

    Ok(examples)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TrainingFunction, TrainingMessage, TrainingToolCall};
    use uuid::Uuid;

    fn make_example(session_id: Uuid) -> TrainingExample {
        TrainingExample {
            session_id,
            messages: vec![
                TrainingMessage {
                    role: "system".to_string(),
                    content: Some("You are a test agent.".to_string()),
                    tool_calls: None,
                    tool_call_id: None,
                },
                TrainingMessage {
                    role: "assistant".to_string(),
                    content: None,
                    tool_calls: Some(vec![TrainingToolCall {
                        id: "call_abc123".to_string(),
                        call_type: "function".to_string(),
                        function: TrainingFunction {
                            name: "nmap_scan".to_string(),
                            arguments: r#"{"target":"10.0.0.1"}"#.to_string(),
                        },
                    }]),
                    tool_call_id: None,
                },
                TrainingMessage {
                    role: "tool".to_string(),
                    content: Some("PORT 80/tcp open http".to_string()),
                    tool_calls: None,
                    tool_call_id: Some("call_abc123".to_string()),
                },
            ],
        }
    }

    #[test]
    fn write_and_read_jsonl_roundtrip() {
        let dir = tempdir();
        let path = dir.path().join("train.jsonl");

        let session_id = Uuid::new_v4();
        let examples = vec![make_example(session_id), make_example(Uuid::new_v4())];

        let count = write_jsonl(&examples, &path).unwrap();
        assert_eq!(count, 2);

        let loaded = read_jsonl(&path).unwrap();
        assert_eq!(loaded.len(), 2);

        // session_id is skip_serializing so it comes back as nil UUID.
        assert_eq!(loaded[0].session_id, Uuid::nil());

        // Messages content is preserved.
        assert_eq!(loaded[0].messages.len(), 3);
        assert_eq!(loaded[0].messages[0].role, "system");

        let asst = &loaded[0].messages[1];
        assert_eq!(asst.role, "assistant");
        let calls = asst.tool_calls.as_ref().unwrap();
        assert_eq!(calls[0].function.name, "nmap_scan");
        assert_eq!(calls[0].function.arguments, r#"{"target":"10.0.0.1"}"#);

        let tool_msg = &loaded[0].messages[2];
        assert_eq!(tool_msg.role, "tool");
        assert_eq!(tool_msg.tool_call_id.as_deref(), Some("call_abc123"));
    }

    #[test]
    fn write_jsonl_empty_produces_empty_file() {
        let dir = tempdir();
        let path = dir.path().join("empty.jsonl");
        let count = write_jsonl(&[], &path).unwrap();
        assert_eq!(count, 0);
        let loaded = read_jsonl(&path).unwrap();
        assert!(loaded.is_empty());
    }

    #[test]
    fn read_jsonl_missing_file_returns_error() {
        let path = std::path::Path::new("/nonexistent/path/train.jsonl");
        assert!(read_jsonl(path).is_err());
    }

    #[test]
    fn jsonl_one_object_per_line() {
        let dir = tempdir();
        let path = dir.path().join("train.jsonl");
        let examples = vec![make_example(Uuid::new_v4()), make_example(Uuid::new_v4())];
        write_jsonl(&examples, &path).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2, "one line per example");

        // Each line must be valid JSON.
        for line in &lines {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(v.get("messages").is_some());
        }
    }

    #[test]
    fn session_id_not_in_jsonl_output() {
        let dir = tempdir();
        let path = dir.path().join("train.jsonl");
        let examples = vec![make_example(Uuid::new_v4())];
        write_jsonl(&examples, &path).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(
            !content.contains("session_id"),
            "session_id should be omitted from JSONL"
        );
    }

    /// Minimal tempdir helper to avoid pulling in the `tempfile` crate.
    fn tempdir() -> TempDir {
        let path = std::env::temp_dir().join(format!("sigint-train-test-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&path).unwrap();
        TempDir { path }
    }

    struct TempDir {
        path: std::path::PathBuf,
    }

    impl TempDir {
        fn path(&self) -> &std::path::Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
