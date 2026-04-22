//! ScoutSuiteTool — sandboxed ScoutSuite wrapper for cloud infrastructure security auditing.
//!
//! @decision DEC-P15-015
//! @title ScoutSuiteTool uses SandboxProfile::web_scanner() — pasta networking, 600s timeout, Risk Medium
//! @status accepted
//! @rationale ScoutSuite calls cloud provider APIs (AWS, Azure, GCP) to enumerate
//! resource configurations and check against security rules. Cloud API calls are
//! inherently slow — a full AWS account audit can take 5–10 minutes — so the
//! web_scanner profile's 600s timeout is the minimum viable setting. pasta
//! networking provides outbound HTTPS access for API calls while keeping the
//! tool isolated from the host filesystem and process tree.
//! `--report-format json --no-browser` suppresses the HTML report and browser
//! launch, emitting structured JSON to stdout. `parse_scout_suite_output()`
//! extracts the provider, scanned services, and a flat findings list with
//! per-finding severity, service, rule, and affected item count. Risk is Medium:
//! read-only API calls reveal the full security posture of the cloud account but
//! do not modify any resources.

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

/// Default 2 MB output cap for ScoutSuite (cloud reports can be large).
const DEFAULT_SCOUT_SUITE_OUTPUT_CAP: usize = 2_097_152;

/// Valid cloud provider values for the `provider` argument.
const VALID_PROVIDERS: &[&str] = &["aws", "azure", "gcp"];

/// Sandboxed ScoutSuite tool wrapper.
///
/// Exposes ScoutSuite as a `Tool` for the LLM agent layer. Audits cloud
/// infrastructure security across AWS, Azure, or GCP by calling provider APIs
/// and evaluating findings against a built-in rule set. Network access is
/// provided via pasta user-mode networking.
pub struct ScoutSuiteTool {
    output_cap: usize,
}

impl ScoutSuiteTool {
    /// Create a new ScoutSuiteTool with the default output cap.
    pub fn new() -> Self {
        Self {
            output_cap: DEFAULT_SCOUT_SUITE_OUTPUT_CAP,
        }
    }

    /// Set a custom output cap (builder pattern).
    pub fn with_output_cap(mut self, cap: usize) -> Self {
        self.output_cap = cap;
        self
    }
}

impl Default for ScoutSuiteTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for ScoutSuiteTool {
    fn name(&self) -> &str {
        "scout_suite_scan"
    }

    fn description(&self) -> &str {
        "Run ScoutSuite to audit cloud infrastructure security across AWS, Azure, or GCP. \
         Calls provider APIs to enumerate resource configurations and evaluate them \
         against security rules. Returns findings grouped by service, rule, and severity."
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
                        "enum": ["aws", "azure", "gcp"],
                        "description": "Cloud provider to audit: 'aws', 'azure', or 'gcp'."
                    },
                    "services": {
                        "type": "string",
                        "description": "Comma-separated list of services to scan, e.g. 'ec2,s3,iam'. \
                                        Omit to scan all services."
                    },
                    "profile": {
                        "type": "string",
                        "description": "AWS named profile to use for credentials (AWS only). \
                                        Omit to use the default credential chain."
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
                expected: "one of: aws, azure, gcp".to_string(),
            });
        }

        // Extract optional services list.
        let services = args["services"].as_str().map(|s| s.to_string());

        // Extract optional AWS profile name.
        let profile = args["profile"].as_str().map(|s| s.to_string());

        info!(
            provider = %provider,
            services = ?services,
            profile = ?profile,
            "executing ScoutSuite cloud audit"
        );

        // Build command: scout --provider <provider> --report-format json --no-browser
        //                      [--services <services>] [--profile <profile>]
        let mut cmd = SandboxProfile::web_scanner().apply("scout");
        cmd = cmd.max_output(self.output_cap);
        cmd = cmd.arg("--provider").arg(&provider);
        cmd = cmd.arg("--report-format").arg("json");
        cmd = cmd.arg("--no-browser");

        if let Some(ref s) = services {
            cmd = cmd.arg("--services").arg(s);
        }

        if let Some(ref p) = profile {
            cmd = cmd.arg("--profile").arg(p);
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

        let structured_data = parse_scout_suite_output(&output.stdout, &provider);

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

/// Parse ScoutSuite JSON report output into a structured findings summary.
///
/// ScoutSuite `--report-format json` writes the report JSON to stdout. The
/// top-level object contains a `services` map keyed by service name. Each
/// service has a `findings` map keyed by rule ID. Each finding has a
/// `flagged_items` count, a `level` (severity: "danger", "warning", etc.),
/// and a `description` string.
///
/// Output shape:
/// ```json
/// {
///   "provider": "aws",
///   "services_scanned": ["ec2", "s3", "iam"],
///   "findings": [
///     {"service": "s3", "rule": "s3-bucket-public", "severity": "danger", "items": 3}
///   ],
///   "by_severity": {"danger": 2, "warning": 5},
///   "total_findings": 7
/// }
/// ```
///
/// Returns `None` for empty or unparseable output. Returns a summary with
/// empty findings when ScoutSuite ran successfully but found no issues.
pub(crate) fn parse_scout_suite_output(stdout: &str, provider: &str) -> Option<Value> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return None;
    }

    // ScoutSuite may emit log lines before the JSON — find the first '{'.
    let json_start = trimmed.find('{').unwrap_or(0);
    let json_str = &trimmed[json_start..];

    let parsed: Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => return None,
    };

    let mut findings: Vec<Value> = Vec::new();
    let mut by_severity: HashMap<String, u64> = HashMap::new();
    let mut services_scanned: Vec<String> = Vec::new();

    // Walk the services map.
    if let Some(services_map) = parsed["services"].as_object() {
        for (service_name, service_data) in services_map {
            services_scanned.push(service_name.clone());

            // Each service has a `findings` map.
            if let Some(findings_map) = service_data["findings"].as_object() {
                for (rule_id, finding) in findings_map {
                    let flagged = finding["flagged_items"].as_u64().unwrap_or(0);
                    // Skip rules with no flagged items.
                    if flagged == 0 {
                        continue;
                    }
                    let severity = finding["level"].as_str().unwrap_or("unknown").to_string();

                    *by_severity.entry(severity.clone()).or_insert(0) += 1;

                    findings.push(json!({
                        "service": service_name,
                        "rule": rule_id,
                        "severity": severity,
                        "items": flagged,
                    }));
                }
            }
        }
    }

    let total_findings = findings.len() as u64;
    let by_severity_json: Value = by_severity
        .into_iter()
        .map(|(k, v)| (k, json!(v)))
        .collect();

    services_scanned.sort();

    Some(json!({
        "provider": provider,
        "services_scanned": services_scanned,
        "findings": findings,
        "by_severity": by_severity_json,
        "total_findings": total_findings,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scout_suite_tool_name() {
        assert_eq!(ScoutSuiteTool::new().name(), "scout_suite_scan");
    }

    #[test]
    fn scout_suite_definition_shape() {
        let def = ScoutSuiteTool::new().definition();
        assert_eq!(def.type_, "function");
        assert_eq!(def.function.name, "scout_suite_scan");

        let params = &def.function.parameters;
        assert_eq!(params["type"], "object");

        // provider is required
        let required = params["required"].as_array().unwrap();
        assert!(
            required.iter().any(|v| v == "provider"),
            "provider should be required"
        );

        // provider has enum constraint
        let provider_enum = params["properties"]["provider"]["enum"].as_array().unwrap();
        assert!(provider_enum.iter().any(|v| v == "aws"));
        assert!(provider_enum.iter().any(|v| v == "azure"));
        assert!(provider_enum.iter().any(|v| v == "gcp"));

        // services and profile are optional
        assert!(params["properties"]["services"].is_object());
        assert!(params["properties"]["profile"].is_object());
        assert!(!required.iter().any(|v| v == "services"));
        assert!(!required.iter().any(|v| v == "profile"));
    }

    #[tokio::test]
    async fn scout_suite_missing_provider_errors() {
        let err = ScoutSuiteTool::new().execute(json!({})).await.unwrap_err();
        assert!(
            err.to_string().contains("missing required argument"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn scout_suite_invalid_provider_errors() {
        let err = ScoutSuiteTool::new()
            .execute(json!({"provider": "oracle"}))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("invalid argument"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_scout_suite_typical() {
        let input = r#"{
            "services": {
                "s3": {
                    "findings": {
                        "s3-bucket-public": {
                            "flagged_items": 3,
                            "level": "danger",
                            "description": "S3 bucket is publicly accessible"
                        },
                        "s3-bucket-no-logging": {
                            "flagged_items": 5,
                            "level": "warning",
                            "description": "S3 bucket access logging is disabled"
                        }
                    }
                },
                "iam": {
                    "findings": {
                        "iam-root-no-mfa": {
                            "flagged_items": 1,
                            "level": "danger",
                            "description": "Root account has no MFA"
                        },
                        "iam-password-policy-ok": {
                            "flagged_items": 0,
                            "level": "good",
                            "description": "Password policy is compliant"
                        }
                    }
                }
            }
        }"#;

        let result = parse_scout_suite_output(input, "aws").expect("should parse");
        assert_eq!(result["provider"], "aws");

        let services = result["services_scanned"].as_array().unwrap();
        assert_eq!(services.len(), 2);

        let findings = result["findings"].as_array().unwrap();
        // 3 flagged findings (1 iam-password-policy-ok has 0 items, excluded)
        assert_eq!(findings.len(), 3);
        assert_eq!(result["total_findings"], 3);
        assert_eq!(result["by_severity"]["danger"], 2);
        assert_eq!(result["by_severity"]["warning"], 1);
    }

    #[test]
    fn parse_scout_suite_no_findings() {
        let input = r#"{"services": {"s3": {"findings": {}}}}"#;
        let result = parse_scout_suite_output(input, "aws").expect("should parse");
        assert_eq!(result["total_findings"], 0);
        assert_eq!(result["findings"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn parse_scout_suite_invalid_json() {
        assert!(parse_scout_suite_output("not json", "aws").is_none());
        assert!(parse_scout_suite_output("", "aws").is_none());
        assert!(parse_scout_suite_output("   ", "aws").is_none());
    }

    /// Requires ScoutSuite (`scout`) and cloud credentials configured.
    /// Run with: cargo test -p sigint-tools -- --ignored
    #[tokio::test]
    #[ignore]
    async fn scout_suite_integration_aws() {
        let result = ScoutSuiteTool::new()
            .execute(json!({
                "provider": "aws",
                "services": "s3"
            }))
            .await
            .expect("ScoutSuite execution should not error");
        let _ = result.exit_code;
    }
}
