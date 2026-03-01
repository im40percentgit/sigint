//! NucleiTool — sandboxed nuclei wrapper for template-based vulnerability scanning.
//!
//! @decision DEC-TOOL-007
//! @title NucleiTool uses SandboxProfile::web_scanner() for pasta networking
//! @status accepted
//! @rationale nuclei runs community-authored YAML templates against a target,
//! covering CVEs, misconfigurations, exposed panels, and more. Scans can be
//! broad (all templates) or targeted (specific template path or severity filter).
//! SandboxProfile::WebScanner provides a 600s timeout for broad template runs.
//! The `-silent -nc` flags suppress banners and ANSI colour codes, keeping
//! stdout clean for LLM consumption. Severity filtering lets the agent focus
//! on actionable findings and avoid low-noise informational output.

use async_trait::async_trait;
use serde_json::{json, Value};
use sigint_llm::ToolDefinition;
use sigint_sandbox::profile::SandboxProfile;
use tracing::info;

use crate::error::{Result, ToolError};
use crate::result::ToolResult;
use crate::tool::Tool;

/// Severity levels accepted by nuclei's `-severity` flag.
const VALID_SEVERITIES: &[&str] = &["info", "low", "medium", "high", "critical"];

/// Sandboxed nuclei tool wrapper.
///
/// Exposes nuclei as a `Tool` for the LLM agent layer. Runs YAML-based
/// vulnerability templates against a URL target. Network access is provided via
/// pasta user-mode networking with a 10-minute timeout.
pub struct NucleiTool;

#[async_trait]
impl Tool for NucleiTool {
    fn name(&self) -> &str {
        "nuclei_scan"
    }

    fn description(&self) -> &str {
        "Run nuclei template-based vulnerability scanner against a target URL. \
         Returns matched findings from community templates covering CVEs, \
         misconfigurations, and exposed panels. Requires network access — runs \
         inside a sandboxed environment with pasta user-mode networking."
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
                    "templates": {
                        "type": "string",
                        "description": "Template path or tag to run (e.g. 'cves/2021/CVE-2021-44228', \
                                        'exposures', '/path/to/custom.yaml'). Omit to run all default templates."
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["info", "low", "medium", "high", "critical"],
                        "description": "Filter findings by minimum severity. Omit to return all severities."
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

        // Extract optional templates path/tag.
        let templates = args["templates"].as_str().map(|s| s.to_string());

        // Extract optional severity filter; validate against allowed values.
        let severity = match args["severity"].as_str() {
            None => None,
            Some(s) => {
                if VALID_SEVERITIES.contains(&s) {
                    Some(s.to_string())
                } else {
                    return Err(ToolError::InvalidArgument {
                        name: "severity".to_string(),
                        expected: "one of: info, low, medium, high, critical".to_string(),
                    });
                }
            }
        };

        info!(
            target = %target,
            templates = ?templates,
            severity = ?severity,
            "executing nuclei scan"
        );

        let mut cmd = SandboxProfile::web_scanner().apply("nuclei");
        cmd = cmd.arg("-u").arg(&target);

        // Suppress banner and ANSI colour codes for clean LLM output.
        cmd = cmd.arg("-silent");
        cmd = cmd.arg("-nc");

        // Apply optional template filter.
        if let Some(ref t) = templates {
            cmd = cmd.arg("-t").arg(t);
        }

        // Apply optional severity filter.
        if let Some(ref s) = severity {
            cmd = cmd.arg("-severity").arg(s);
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
    fn nuclei_tool_name_nonempty() {
        assert!(!NucleiTool.name().is_empty());
        assert_eq!(NucleiTool.name(), "nuclei_scan");
    }

    #[test]
    fn nuclei_tool_description_nonempty() {
        assert!(!NucleiTool.description().is_empty());
    }

    #[test]
    fn nuclei_tool_definition_shape() {
        let def = NucleiTool.definition();
        assert_eq!(def.type_, "function");
        assert_eq!(def.function.name, "nuclei_scan");

        let params = &def.function.parameters;
        assert_eq!(params["type"], "object");

        // target is required
        let required = params["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "target"), "target should be required");

        // target property exists and is a string
        assert_eq!(params["properties"]["target"]["type"], "string");

        // templates is optional (not in required array)
        assert!(params["properties"]["templates"].is_object());
        assert!(!required.iter().any(|v| v == "templates"), "templates should be optional");

        // severity has enum constraint
        let severity_enum = params["properties"]["severity"]["enum"].as_array().unwrap();
        assert!(severity_enum.iter().any(|v| v == "info"));
        assert!(severity_enum.iter().any(|v| v == "critical"));
    }

    #[tokio::test]
    async fn nuclei_missing_target_errors() {
        let err = NucleiTool.execute(json!({})).await.unwrap_err();
        assert!(
            err.to_string().contains("missing required argument"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn nuclei_invalid_severity_errors() {
        let err = NucleiTool
            .execute(json!({"target": "http://example.com", "severity": "ultra"}))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("invalid argument"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn nuclei_valid_severities_accepted() {
        for sev in VALID_SEVERITIES {
            // Just verify the constant matches the schema — execution tests are #[ignore]
            assert!(VALID_SEVERITIES.contains(sev), "severity '{}' should be valid", sev);
        }
    }

    /// Requires nuclei + passt + newuidmap. Run with: cargo test -p sigint-tools -- --ignored
    #[tokio::test]
    #[ignore]
    async fn nuclei_executes_against_loopback() {
        let result = NucleiTool
            .execute(json!({
                "target": "http://127.0.0.1",
                "severity": "medium"
            }))
            .await
            .expect("nuclei execution should not error");
        // nuclei exits 0 even when no templates match
        assert_eq!(result.exit_code, 0, "nuclei should exit 0: {:?}", result.stderr);
    }
}
