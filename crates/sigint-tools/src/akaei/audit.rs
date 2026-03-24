//! AkaeiAuditTool — RF IoT security audit wrapper.
//!
//! @decision DEC-AKAEI-002
//! @title audit --format json emits a JSON object; parsed directly into structured_data
//! @status accepted
//! @rationale akaei audit supports --format json which writes a single JSON object
//! to stdout. We parse it directly with serde_json::from_str. On parse failure
//! structured_data is None and raw stdout is still available for the agent.

use async_trait::async_trait;
use serde_json::{json, Value};
use sigint_core::types::ToolRisk;
use sigint_llm::ToolDefinition;

use crate::error::{Result, ToolError};
use crate::result::ToolResult;
use crate::tool::Tool;

use super::run_akaei;

/// IoT RF security audit tool.
///
/// Runs an akaei audit profile against the RF environment, testing for known
/// IoT vulnerabilities, replay susceptibility, and protocol weaknesses.
/// Long-running hardware scan — High risk.
pub struct AkaeiAuditTool;

#[async_trait]
impl Tool for AkaeiAuditTool {
    fn name(&self) -> &str {
        "akaei_audit"
    }

    fn description(&self) -> &str {
        "Run an RF IoT security audit using an akaei audit profile. Tests the RF \
         environment for known IoT vulnerabilities, replay susceptibility, and protocol \
         weaknesses. Requires HackRF hardware and an audit profile TOML file."
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::function(
            self.name(),
            self.description(),
            json!({
                "type": "object",
                "properties": {
                    "profile_path": {
                        "type": "string",
                        "description": "Path to the audit profile TOML file."
                    },
                    "dry_run": {
                        "type": "boolean",
                        "description": "Validate the profile without running hardware scans."
                    },
                    "save_captures": {
                        "type": "boolean",
                        "description": "Save IQ captures for each test case."
                    },
                    "output_prefix": {
                        "type": "string",
                        "description": "File prefix for saving captures and reports. Optional."
                    }
                },
                "required": ["profile_path"]
            }),
        )
    }

    fn risk_level(&self) -> ToolRisk {
        ToolRisk::High
    }

    async fn execute(&self, args: Value) -> Result<ToolResult> {
        let profile = args["profile_path"]
            .as_str()
            .ok_or_else(|| ToolError::MissingArgument("profile_path".to_string()))?;

        let mut cmd_args: Vec<String> = vec![
            "--profile".to_string(),
            profile.to_string(),
            "--format".to_string(),
            "json".to_string(),
        ];

        if args["dry_run"].as_bool().unwrap_or(false) {
            cmd_args.push("--dry-run".to_string());
        }
        if args["save_captures"].as_bool().unwrap_or(false) {
            cmd_args.push("--save-captures".to_string());
        }
        if let Some(prefix) = args["output_prefix"].as_str() {
            cmd_args.push("-o".to_string());
            cmd_args.push(prefix.to_string());
        }

        let str_args: Vec<&str> = cmd_args.iter().map(String::as_str).collect();
        let mut result = run_akaei("audit", &str_args, 600).await?;

        // Parse JSON output if present; leave structured_data None on failure.
        if !result.stdout.trim().is_empty() {
            result.structured_data = serde_json::from_str::<Value>(&result.stdout).ok();
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn audit_tool_name() {
        assert_eq!(AkaeiAuditTool.name(), "akaei_audit");
    }

    #[test]
    fn audit_definition_required_fields() {
        let def = AkaeiAuditTool.definition();
        let required = def.function.parameters["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "profile_path"));
    }

    #[test]
    fn audit_risk_is_high() {
        assert_eq!(AkaeiAuditTool.risk_level(), ToolRisk::High);
    }

    #[tokio::test]
    async fn audit_missing_profile_errors() {
        let err = AkaeiAuditTool.execute(json!({})).await.unwrap_err();
        assert!(err.to_string().contains("missing required argument"));
    }
}
