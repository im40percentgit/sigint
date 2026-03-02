//! FeroxbusterTool — sandboxed feroxbuster wrapper for fast content discovery.
//!
//! @decision DEC-TOOL-008
//! @title FeroxbusterTool uses SandboxProfile::bruteforce() for pasta networking
//! @status accepted
//! @rationale feroxbuster is a Rust-native recursive content-discovery tool that
//! outpaces gobuster on large wordlists. SandboxProfile::Bruteforce provides
//! pasta networking with a 300s timeout. The `--no-state -q` flags disable the
//! resume-state file (unnecessary inside an ephemeral sandbox) and suppress the
//! progress bar, keeping stdout clean for the LLM. Thread count is user-tunable
//! to balance speed against target rate-limiting. Extension filtering lets the
//! agent focus on specific file types (php, html, js) rather than all paths.

use async_trait::async_trait;
use serde_json::{json, Value};
use sigint_llm::ToolDefinition;
use sigint_sandbox::profile::SandboxProfile;
use tracing::info;

use crate::error::{Result, ToolError};
use crate::result::ToolResult;
use crate::tool::Tool;
use sigint_core::types::ToolRisk;

const DEFAULT_THREADS: u64 = 50;
const DEFAULT_WORDLIST: &str = "/usr/share/wordlists/dirb/common.txt";

/// Sandboxed feroxbuster tool wrapper.
///
/// Exposes feroxbuster as a `Tool` for the LLM agent layer. Performs recursive
/// content discovery against web targets using wordlist-based bruteforce.
/// Network access is provided via pasta user-mode networking.
pub struct FeroxbusterTool;

#[async_trait]
impl Tool for FeroxbusterTool {
    fn name(&self) -> &str {
        "feroxbuster_scan"
    }

    fn description(&self) -> &str {
        "Run feroxbuster to discover directories and files on a web target via \
         wordlist-based bruteforce. Returns discovered URLs with HTTP status codes. \
         Requires network access — runs inside a sandboxed environment with \
         pasta user-mode networking."
    }

    fn risk_level(&self) -> ToolRisk {
        ToolRisk::Medium
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::function(
            self.name(),
            self.description(),
            json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target URL to scan (e.g. 'http://example.com')."
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "Path to the wordlist file. Defaults to '/usr/share/wordlists/dirb/common.txt'."
                    },
                    "extensions": {
                        "type": "string",
                        "description": "Comma-separated file extensions to append to each wordlist entry \
                                        (e.g. 'php,html,js'). Omit to bruteforce paths only."
                    },
                    "threads": {
                        "type": "integer",
                        "description": "Number of concurrent threads. Defaults to 50. \
                                        Reduce if the target rate-limits aggressively."
                    }
                },
                "required": ["target"]
            }),
        )
    }

    async fn execute(&self, args: Value) -> Result<ToolResult> {
        // Extract required target.
        let target = args["target"]
            .as_str()
            .ok_or_else(|| ToolError::MissingArgument("target".to_string()))?
            .to_string();

        // Extract optional wordlist, default to common.txt.
        let wordlist = args["wordlist"]
            .as_str()
            .unwrap_or(DEFAULT_WORDLIST)
            .to_string();

        // Extract optional extensions (comma-separated).
        let extensions = args["extensions"].as_str().map(|s| s.to_string());

        // Extract optional thread count, default to 50.
        let threads = args["threads"].as_u64().unwrap_or(DEFAULT_THREADS);
        if threads == 0 {
            return Err(ToolError::InvalidArgument {
                name: "threads".to_string(),
                expected: "positive integer".to_string(),
            });
        }

        info!(
            target = %target,
            wordlist = %wordlist,
            extensions = ?extensions,
            threads = threads,
            "executing feroxbuster scan"
        );

        let mut cmd = SandboxProfile::bruteforce().apply("feroxbuster");
        cmd = cmd.arg("-u").arg(&target);
        cmd = cmd.arg("-w").arg(&wordlist);

        // Disable resume-state file (ephemeral sandbox — no persistent state).
        cmd = cmd.arg("--no-state");

        // Suppress progress bar for clean LLM output.
        cmd = cmd.arg("-q");

        // Apply optional extension filter.
        if let Some(ref ext) = extensions {
            cmd = cmd.arg("-x").arg(ext);
        }

        // Apply thread count.
        let thread_str = threads.to_string();
        cmd = cmd.arg("-t").arg(&thread_str);

        // SandboxedCommand::execute() is synchronous — bridge via spawn_blocking.
        let output = tokio::task::spawn_blocking(move || cmd.execute())
            .await
            .map_err(|e| ToolError::Sandbox(format!("spawn_blocking panicked: {e}")))?
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("timed out") || msg.contains("timeout") {
                    ToolError::Timeout(300)
                } else {
                    ToolError::Sandbox(msg)
                }
            })?;

        Ok(ToolResult {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.exit_code,
            duration: output.duration,
            structured_data: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feroxbuster_tool_name_nonempty() {
        assert!(!FeroxbusterTool.name().is_empty());
        assert_eq!(FeroxbusterTool.name(), "feroxbuster_scan");
    }

    #[test]
    fn feroxbuster_tool_description_nonempty() {
        assert!(!FeroxbusterTool.description().is_empty());
    }

    #[test]
    fn feroxbuster_tool_definition_shape() {
        let def = FeroxbusterTool.definition();
        assert_eq!(def.type_, "function");
        assert_eq!(def.function.name, "feroxbuster_scan");

        let params = &def.function.parameters;
        assert_eq!(params["type"], "object");

        // target is required
        let required = params["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "target"), "target should be required");

        // target property exists and is a string
        assert_eq!(params["properties"]["target"]["type"], "string");

        // wordlist is optional (not in required array)
        assert!(params["properties"]["wordlist"].is_object());
        assert!(!required.iter().any(|v| v == "wordlist"), "wordlist should be optional");

        // extensions is optional
        assert!(params["properties"]["extensions"].is_object());
        assert!(!required.iter().any(|v| v == "extensions"), "extensions should be optional");

        // threads is optional integer
        assert_eq!(params["properties"]["threads"]["type"], "integer");
        assert!(!required.iter().any(|v| v == "threads"), "threads should be optional");
    }

    #[tokio::test]
    async fn feroxbuster_missing_target_errors() {
        let err = FeroxbusterTool.execute(json!({})).await.unwrap_err();
        assert!(
            err.to_string().contains("missing required argument"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn feroxbuster_zero_threads_errors() {
        let err = FeroxbusterTool
            .execute(json!({"target": "http://example.com", "threads": 0}))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("invalid argument"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn feroxbuster_default_threads() {
        // Verify the constant is a sensible default
        assert_eq!(DEFAULT_THREADS, 50);
    }

    /// Requires feroxbuster + passt + newuidmap. Run with: cargo test -p sigint-tools -- --ignored
    #[tokio::test]
    #[ignore]
    async fn feroxbuster_executes_against_loopback() {
        let result = FeroxbusterTool
            .execute(json!({
                "target": "http://127.0.0.1",
                "threads": 10
            }))
            .await
            .expect("feroxbuster execution should not error");
        // feroxbuster exits 0 even when target is unreachable
        assert_eq!(result.exit_code, 0, "feroxbuster should exit 0: {:?}", result.stderr);
    }
}
