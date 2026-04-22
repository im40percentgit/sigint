//! CloudsploitTool — sandboxed CloudSploit wrapper for cloud security misconfiguration detection.
//!
//! @decision DEC-P15-016
//! @title CloudsploitTool uses SandboxProfile::web_scanner() — pasta networking, 600s timeout, Risk Medium
//! @status accepted
//! @rationale CloudSploit calls cloud provider APIs (AWS, Azure, GCP, Oracle) to
//! detect security misconfigurations and compliance violations. Like ScoutSuite,
//! cloud API enumeration is slow and requires outbound HTTPS; the web_scanner
//! profile's 600s timeout accommodates large accounts. `--json` emits a flat
//! results array (one entry per plugin check) with plugin name, category,
//! status (PASS/FAIL/WARN/UNKNOWN), and message. `parse_cloudsploit_output()`
//! extracts the provider, per-check results, status aggregates, and total
//! failure count. An optional `--compliance` flag narrows output to a specific
//! framework (cis, pci, hipaa). Risk is Medium: read-only API calls reveal
//! misconfigured resources but do not exploit them.

use std::collections::HashMap;

use async_trait::async_trait;
use serde_json::{json, Value};
use sigint_llm::ToolDefinition;
use sigint_sandbox::profile::SandboxProfile;
use tracing::info;

use crate::error::{Result, ToolError};
use crate::result::{ToolResult, TruncationInfo};
use crate::tool::Tool;
use sigint_core::types::ToolRisk;

/// Default 2 MB output cap for CloudSploit.
const DEFAULT_CLOUDSPLOIT_OUTPUT_CAP: usize = 2_097_152;

/// Valid cloud provider values for the `provider` argument.
const VALID_PROVIDERS: &[&str] = &["aws", "azure", "gcp", "oracle"];

/// Sandboxed CloudSploit tool wrapper.
///
/// Exposes CloudSploit as a `Tool` for the LLM agent layer. Detects cloud
/// security misconfigurations and compliance violations across AWS, Azure,
/// GCP, and Oracle Cloud. Network access provided via pasta user-mode networking.
pub struct CloudsploitTool {
    output_cap: usize,
}

impl CloudsploitTool {
    /// Create a new CloudsploitTool with the default output cap.
    pub fn new() -> Self {
        Self {
            output_cap: DEFAULT_CLOUDSPLOIT_OUTPUT_CAP,
        }
    }

    /// Set a custom output cap (builder pattern).
    pub fn with_output_cap(mut self, cap: usize) -> Self {
        self.output_cap = cap;
        self
    }
}

impl Default for CloudsploitTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for CloudsploitTool {
    fn name(&self) -> &str {
        "cloudsploit_scan"
    }

    fn description(&self) -> &str {
        "Run CloudSploit to detect cloud security misconfigurations and compliance violations \
         across AWS, Azure, GCP, or Oracle Cloud. Returns per-plugin check results with \
         PASS/FAIL/WARN status, category, and descriptive messages."
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
                    "provider": {
                        "type": "string",
                        "enum": ["aws", "azure", "gcp", "oracle"],
                        "description": "Cloud provider to scan: 'aws', 'azure', 'gcp', or 'oracle'."
                    },
                    "compliance": {
                        "type": "string",
                        "description": "Compliance framework to filter checks, e.g. 'cis', 'pci', 'hipaa'. \
                                        Omit to run all checks."
                    }
                },
                "required": ["provider"]
            }),
        )
    }

    async fn execute(&self, args: Value) -> Result<ToolResult> {
        // Extract required provider and validate.
        let provider = args["provider"]
            .as_str()
            .ok_or_else(|| ToolError::MissingArgument("provider".to_string()))?
            .to_string();

        if !VALID_PROVIDERS.contains(&provider.as_str()) {
            return Err(ToolError::InvalidArgument {
                name: "provider".to_string(),
                expected: "one of: aws, azure, gcp, oracle".to_string(),
            });
        }

        // Extract optional compliance framework.
        let compliance = args["compliance"].as_str().map(|s| s.to_string());

        info!(
            provider = %provider,
            compliance = ?compliance,
            "executing CloudSploit scan"
        );

        // Build command: cloudsploit scan --provider <provider> --json
        //                                 [--compliance <framework>]
        let mut cmd = SandboxProfile::web_scanner().apply("cloudsploit");
        cmd = cmd.max_output(self.output_cap);
        cmd = cmd.arg("scan");
        cmd = cmd.arg("--provider").arg(&provider);
        cmd = cmd.arg("--json");

        if let Some(ref c) = compliance {
            cmd = cmd.arg("--compliance").arg(c);
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

        let structured_data = parse_cloudsploit_output(&output.stdout, &provider);

        let truncation = output.was_truncated.then_some(TruncationInfo {
            original_bytes: output.original_stdout_len,
            kept_bytes: output.stdout.len(),
        });
        Ok(ToolResult {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.exit_code,
            duration: output.duration,
            structured_data,
            status: Default::default(),
            truncation,
        })
    }
}

/// Parse CloudSploit JSON output into a structured misconfiguration summary.
///
/// CloudSploit `--json` emits a JSON array. Each element is a result object
/// with `plugin`, `category`, `status` (PASS/FAIL/WARN/UNKNOWN), and `message`.
///
/// Output shape:
/// ```json
/// {
///   "provider": "aws",
///   "results": [
///     {"plugin": "instanceMaxCount", "category": "EC2", "status": "FAIL", "message": "..."}
///   ],
///   "by_status": {"PASS": 50, "FAIL": 10, "WARN": 5},
///   "total_failures": 10
/// }
/// ```
///
/// Returns `None` for empty or unparseable output. Returns a summary with
/// zero failures when CloudSploit ran successfully but all checks passed.
pub(crate) fn parse_cloudsploit_output(stdout: &str, provider: &str) -> Option<Value> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return None;
    }

    // CloudSploit may emit log lines before the JSON array — find the first '['.
    let json_start = trimmed.find('[').unwrap_or(0);
    let json_str = &trimmed[json_start..];

    let parsed: Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => return None,
    };

    let items = parsed.as_array()?;

    let mut results: Vec<Value> = Vec::new();
    let mut by_status: HashMap<String, u64> = HashMap::new();
    let mut total_failures: u64 = 0;

    for item in items {
        let plugin = item["plugin"].as_str().unwrap_or("").to_string();
        let category = item["category"].as_str().unwrap_or("").to_string();
        let status = item["status"].as_str().unwrap_or("UNKNOWN").to_string();
        let message = item["message"].as_str().unwrap_or("").to_string();

        *by_status.entry(status.clone()).or_insert(0) += 1;
        if status == "FAIL" {
            total_failures += 1;
        }

        results.push(json!({
            "plugin": plugin,
            "category": category,
            "status": status,
            "message": message,
        }));
    }

    let by_status_json: Value = by_status.into_iter().map(|(k, v)| (k, json!(v))).collect();

    Some(json!({
        "provider": provider,
        "results": results,
        "by_status": by_status_json,
        "total_failures": total_failures,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloudsploit_tool_name() {
        assert_eq!(CloudsploitTool::new().name(), "cloudsploit_scan");
    }

    #[test]
    fn cloudsploit_definition_shape() {
        let def = CloudsploitTool::new().definition();
        assert_eq!(def.type_, "function");
        assert_eq!(def.function.name, "cloudsploit_scan");

        let params = &def.function.parameters;
        assert_eq!(params["type"], "object");

        // provider is required
        let required = params["required"].as_array().unwrap();
        assert!(
            required.iter().any(|v| v == "provider"),
            "provider should be required"
        );

        // provider has enum with all 4 providers
        let provider_enum = params["properties"]["provider"]["enum"].as_array().unwrap();
        assert!(provider_enum.iter().any(|v| v == "aws"));
        assert!(provider_enum.iter().any(|v| v == "azure"));
        assert!(provider_enum.iter().any(|v| v == "gcp"));
        assert!(provider_enum.iter().any(|v| v == "oracle"));

        // compliance is optional
        assert!(params["properties"]["compliance"].is_object());
        assert!(!required.iter().any(|v| v == "compliance"));
    }

    #[tokio::test]
    async fn cloudsploit_missing_provider_errors() {
        let err = CloudsploitTool::new().execute(json!({})).await.unwrap_err();
        assert!(
            err.to_string().contains("missing required argument"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_cloudsploit_typical() {
        let input = r#"[
            {"plugin": "instanceMaxCount", "category": "EC2", "status": "FAIL",
             "message": "More than 100 instances running"},
            {"plugin": "ebsEncryptionEnabled", "category": "EC2", "status": "WARN",
             "message": "EBS encryption not enabled by default"},
            {"plugin": "s3BucketPublicAccess", "category": "S3", "status": "PASS",
             "message": "No public buckets found"},
            {"plugin": "iamMfaEnabled", "category": "IAM", "status": "FAIL",
             "message": "Root account MFA not enabled"}
        ]"#;

        let result = parse_cloudsploit_output(input, "aws").expect("should parse");
        assert_eq!(result["provider"], "aws");

        let results = result["results"].as_array().unwrap();
        assert_eq!(results.len(), 4);
        assert_eq!(results[0]["plugin"], "instanceMaxCount");
        assert_eq!(results[0]["category"], "EC2");
        assert_eq!(results[0]["status"], "FAIL");

        assert_eq!(result["total_failures"], 2);
        assert_eq!(result["by_status"]["FAIL"], 2);
        assert_eq!(result["by_status"]["WARN"], 1);
        assert_eq!(result["by_status"]["PASS"], 1);
    }

    #[test]
    fn parse_cloudsploit_all_pass() {
        let input = r#"[
            {"plugin": "s3BucketPublicAccess", "category": "S3", "status": "PASS", "message": "OK"}
        ]"#;
        let result = parse_cloudsploit_output(input, "aws").expect("should parse");
        assert_eq!(result["total_failures"], 0);
        assert_eq!(result["by_status"]["PASS"], 1);
    }

    #[test]
    fn parse_cloudsploit_invalid_json() {
        assert!(parse_cloudsploit_output("not json", "aws").is_none());
        assert!(parse_cloudsploit_output("", "aws").is_none());
        assert!(parse_cloudsploit_output("   ", "aws").is_none());
    }

    /// Requires CloudSploit (`cloudsploit`) and cloud credentials configured.
    /// Run with: cargo test -p sigint-tools -- --ignored
    #[tokio::test]
    #[ignore]
    async fn cloudsploit_integration_aws() {
        let result = CloudsploitTool::new()
            .execute(json!({
                "provider": "aws"
            }))
            .await
            .expect("CloudSploit execution should not error");
        let _ = result.exit_code;
    }
}
