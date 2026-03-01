//! NiktoTool — sandboxed nikto wrapper for web vulnerability scanning.
//!
//! @decision DEC-TOOL-006
//! @title NiktoTool uses SandboxProfile::web_scanner() for pasta networking
//! @status accepted
//! @rationale nikto is a comprehensive web server scanner that tests for thousands
//! of vulnerabilities, misconfigurations, and outdated software. It runs slowly
//! by design — SandboxProfile::WebScanner provides a 600s timeout to accommodate
//! full scans. The `-Format txt -output -` flags stream plain-text results to
//! stdout, making output easy for the LLM to parse. Tuning codes narrow the
//! test categories when a focused scan is preferred.

use async_trait::async_trait;
use serde_json::{json, Value};
use sigint_llm::ToolDefinition;
use sigint_sandbox::profile::SandboxProfile;
use tracing::info;

use crate::error::{Result, ToolError};
use crate::result::ToolResult;
use crate::tool::Tool;

/// Sandboxed nikto tool wrapper.
///
/// Exposes nikto as a `Tool` for the LLM agent layer. Scans web targets for
/// known vulnerabilities and misconfigurations. Network access is provided via
/// pasta user-mode networking with a 10-minute timeout.
pub struct NiktoTool;

#[async_trait]
impl Tool for NiktoTool {
    fn name(&self) -> &str {
        "nikto_scan"
    }

    fn description(&self) -> &str {
        "Run a nikto web vulnerability scan against a target URL or host. \
         Returns findings including outdated software, misconfigurations, and \
         potential vulnerabilities. Requires network access — runs inside a \
         sandboxed environment with pasta user-mode networking."
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
                        "description": "Target URL or host to scan (e.g. 'http://example.com' or '192.168.1.1')."
                    },
                    "tuning": {
                        "type": "string",
                        "description": "Nikto tuning codes to limit test categories \
                                        (e.g. '1' for interesting files, '2' for misconfigurations, \
                                        '4' for XSS, '9' for SQL injection). Omit to run all tests."
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

        // Extract optional tuning codes.
        let tuning = args["tuning"].as_str().map(|s| s.to_string());

        info!(
            target = %target,
            tuning = ?tuning,
            "executing nikto scan"
        );

        let mut cmd = SandboxProfile::web_scanner().apply("nikto");
        cmd = cmd.arg("-h").arg(&target);

        // Stream plain-text output to stdout for LLM consumption.
        cmd = cmd.arg("-Format").arg("txt");
        cmd = cmd.arg("-output").arg("-");

        // Apply tuning codes when provided.
        if let Some(ref t) = tuning {
            cmd = cmd.arg("-Tuning").arg(t);
        }

        // SandboxedCommand::execute() is synchronous — bridge via spawn_blocking.
        let output = tokio::task::spawn_blocking(move || cmd.execute())
            .await
            .map_err(|e| ToolError::Sandbox(format!("spawn_blocking panicked: {e}")))?
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("timed out") || msg.contains("timeout") {
                    ToolError::Timeout(600)
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
    fn nikto_tool_name_nonempty() {
        assert!(!NiktoTool.name().is_empty());
        assert_eq!(NiktoTool.name(), "nikto_scan");
    }

    #[test]
    fn nikto_tool_description_nonempty() {
        assert!(!NiktoTool.description().is_empty());
    }

    #[test]
    fn nikto_tool_definition_shape() {
        let def = NiktoTool.definition();
        assert_eq!(def.type_, "function");
        assert_eq!(def.function.name, "nikto_scan");

        let params = &def.function.parameters;
        assert_eq!(params["type"], "object");

        // target is required
        let required = params["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "target"), "target should be required");

        // target property exists and is a string
        assert_eq!(params["properties"]["target"]["type"], "string");

        // tuning is optional (not in required array)
        assert!(params["properties"]["tuning"].is_object());
        assert!(!required.iter().any(|v| v == "tuning"), "tuning should be optional");
    }

    #[tokio::test]
    async fn nikto_missing_target_errors() {
        let err = NiktoTool.execute(json!({})).await.unwrap_err();
        assert!(
            err.to_string().contains("missing required argument"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn nikto_tuning_argument_is_optional_string() {
        // Verify the definition schema accepts tuning as an optional string field.
        // No execution needed — this tests the JSON schema shape only.
        let def = NiktoTool.definition();
        let params = &def.function.parameters;
        let required = params["required"].as_array().unwrap();
        // tuning must NOT be in the required array
        assert!(
            !required.iter().any(|v| v == "tuning"),
            "tuning should be optional (not in required)"
        );
        // tuning property must exist and be a string
        assert_eq!(
            params["properties"]["tuning"]["type"], "string",
            "tuning should be a string property"
        );
    }

    /// Requires nikto + passt + newuidmap. Run with: cargo test -p sigint-tools -- --ignored
    #[tokio::test]
    #[ignore]
    async fn nikto_executes_against_loopback() {
        let result = NiktoTool
            .execute(json!({"target": "http://127.0.0.1"}))
            .await
            .expect("nikto execution should not error");
        // nikto exits 0 even when no server responds — it reports "0 host(s) tested"
        assert!(
            result.exit_code == 0 || !result.stderr.is_empty(),
            "nikto should run or report an error: {:?}",
            result
        );
    }
}
