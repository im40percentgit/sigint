//! TrivyTool — sandboxed trivy wrapper for container/filesystem/repo vulnerability scanning.
//!
//! @decision DEC-P15-014
//! @title TrivyTool uses SandboxProfile::recon() — pasta networking, 60s timeout, Risk Low
//! @status accepted
//! @rationale trivy scans container images, filesystems, and git repositories for
//! known CVEs and misconfigurations. Image scans require network access to pull
//! the image manifest and layers from a registry (hence pasta networking), but
//! the scan itself is read-only and low-risk — SandboxProfile::recon() with its
//! 60-second timeout is appropriate for most image scans. For large images the
//! caller should raise the output cap. `--format json --quiet` suppresses banners
//! and emits structured JSON; `parse_trivy_output()` extracts targets, per-target
//! vulnerability lists, severity aggregates, and a total count, storing the
//! compact summary in `structured_data` while preserving full JSON in `stdout`
//! for direct LLM consumption. Risk is Low: trivy only reads metadata and never
//! modifies the scanned target.

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

/// Default 1 MB output cap for trivy.
const DEFAULT_TRIVY_OUTPUT_CAP: usize = 1_048_576;

/// Valid scan types for the `scan_type` argument.
const VALID_SCAN_TYPES: &[&str] = &["image", "fs", "repo"];

/// Sandboxed trivy tool wrapper.
///
/// Exposes trivy as a `Tool` for the LLM agent layer. Scans container images,
/// filesystems, or repositories for CVEs and misconfigurations. Network access
/// is provided via pasta user-mode networking for registry pulls (image scans).
pub struct TrivyTool {
    output_cap: usize,
}

impl TrivyTool {
    /// Create a new TrivyTool with the default output cap.
    pub fn new() -> Self {
        Self {
            output_cap: DEFAULT_TRIVY_OUTPUT_CAP,
        }
    }

    /// Set a custom output cap (builder pattern).
    pub fn with_output_cap(mut self, cap: usize) -> Self {
        self.output_cap = cap;
        self
    }
}

impl Default for TrivyTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for TrivyTool {
    fn name(&self) -> &str {
        "trivy_scan"
    }

    fn description(&self) -> &str {
        "Run trivy to scan container images, filesystems, or repositories for \
         vulnerabilities and misconfigurations. Returns per-target vulnerability \
         lists with CVE IDs, package names, installed versions, and severity counts."
    }

    fn risk_level(&self) -> ToolRisk {
        ToolRisk::Low
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
                        "description": "Target to scan: container image name (e.g. 'nginx:latest'), \
                                        filesystem path, or repository URL."
                    },
                    "scan_type": {
                        "type": "string",
                        "enum": ["image", "fs", "repo"],
                        "description": "Scan type: 'image' (container image, default), \
                                        'fs' (local filesystem path), 'repo' (git repository URL)."
                    },
                    "severity": {
                        "type": "string",
                        "description": "Comma-separated severity levels to include, e.g. \
                                        'CRITICAL,HIGH,MEDIUM,LOW'. Defaults to 'CRITICAL,HIGH'."
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

        // Extract optional scan_type; validate against allowed values.
        let scan_type = match args["scan_type"].as_str() {
            None => "image".to_string(),
            Some(s) => {
                if VALID_SCAN_TYPES.contains(&s) {
                    s.to_string()
                } else {
                    return Err(ToolError::InvalidArgument {
                        name: "scan_type".to_string(),
                        expected: "one of: image, fs, repo".to_string(),
                    });
                }
            }
        };

        // Extract optional severity filter (free-form comma-separated string).
        let severity = args["severity"]
            .as_str()
            .unwrap_or("CRITICAL,HIGH")
            .to_string();

        info!(
            target = %target,
            scan_type = %scan_type,
            severity = %severity,
            "executing trivy scan"
        );

        // Build command: trivy <scan_type> --format json --severity <severity> --quiet <target>
        let mut cmd = SandboxProfile::recon().apply("trivy");
        cmd = cmd.max_output(self.output_cap);
        cmd = cmd.arg(&scan_type);
        cmd = cmd.arg("--format").arg("json");
        cmd = cmd.arg("--severity").arg(&severity);
        cmd = cmd.arg("--quiet");
        cmd = cmd.arg(&target);

        // SandboxedCommand::execute() is synchronous — bridge via spawn_blocking.
        let output = tokio::task::spawn_blocking(move || cmd.execute())
            .await
            .map_err(|e| ToolError::Sandbox(format!("spawn_blocking panicked: {e}")))?
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("timed out") || msg.contains("timeout") {
                    ToolError::Timeout(60)
                } else {
                    ToolError::Sandbox(msg)
                }
            })?;

        let structured_data = parse_trivy_output(&output.stdout);

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

/// Parse trivy JSON output into a structured vulnerability summary.
///
/// trivy `--format json` emits a top-level `Results` array. Each element has
/// a `Target` string and an optional `Vulnerabilities` array. Each vulnerability
/// has `VulnerabilityID`, `PkgName`, `InstalledVersion`, and `Severity` fields.
///
/// Output shape:
/// ```json
/// {
///   "targets": [
///     {
///       "name": "nginx:latest",
///       "vulnerabilities": [
///         {"cve": "CVE-2024-1234", "package": "openssl", "version": "1.1.1", "severity": "CRITICAL"}
///       ]
///     }
///   ],
///   "by_severity": {"CRITICAL": 1, "HIGH": 3},
///   "total_vulns": 4
/// }
/// ```
///
/// Returns `None` for empty or unparseable output. Returns a populated summary
/// with empty vulnerability lists when trivy ran successfully but found nothing.
pub(crate) fn parse_trivy_output(stdout: &str) -> Option<Value> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return None;
    }

    let parsed: Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(_) => return None,
    };

    let results = parsed["Results"].as_array()?;

    let mut targets: Vec<Value> = Vec::new();
    let mut by_severity: HashMap<String, u64> = HashMap::new();
    let mut total_vulns: u64 = 0;

    for result in results {
        let target_name = result["Target"].as_str().unwrap_or("unknown").to_string();

        let mut vulns: Vec<Value> = Vec::new();
        if let Some(vulnerabilities) = result["Vulnerabilities"].as_array() {
            for vuln in vulnerabilities {
                let cve = vuln["VulnerabilityID"].as_str().unwrap_or("").to_string();
                let package = vuln["PkgName"].as_str().unwrap_or("").to_string();
                let version = vuln["InstalledVersion"].as_str().unwrap_or("").to_string();
                let severity = vuln["Severity"].as_str().unwrap_or("UNKNOWN").to_string();

                *by_severity.entry(severity.clone()).or_insert(0) += 1;
                total_vulns += 1;

                vulns.push(json!({
                    "cve": cve,
                    "package": package,
                    "version": version,
                    "severity": severity,
                }));
            }
        }

        targets.push(json!({
            "name": target_name,
            "vulnerabilities": vulns,
        }));
    }

    let by_severity_json: Value = by_severity
        .into_iter()
        .map(|(k, v)| (k, json!(v)))
        .collect();

    Some(json!({
        "targets": targets,
        "by_severity": by_severity_json,
        "total_vulns": total_vulns,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trivy_tool_name() {
        assert_eq!(TrivyTool::new().name(), "trivy_scan");
    }

    #[test]
    fn trivy_risk_is_low() {
        assert_eq!(TrivyTool::new().risk_level(), ToolRisk::Low);
    }

    #[test]
    fn trivy_definition_shape() {
        let def = TrivyTool::new().definition();
        assert_eq!(def.type_, "function");
        assert_eq!(def.function.name, "trivy_scan");

        let params = &def.function.parameters;
        assert_eq!(params["type"], "object");

        // target is required
        let required = params["required"].as_array().unwrap();
        assert!(
            required.iter().any(|v| v == "target"),
            "target should be required"
        );
        assert_eq!(params["properties"]["target"]["type"], "string");

        // scan_type and severity are optional
        assert!(params["properties"]["scan_type"].is_object());
        assert!(params["properties"]["severity"].is_object());
        assert!(
            !required.iter().any(|v| v == "scan_type"),
            "scan_type should be optional"
        );
        assert!(
            !required.iter().any(|v| v == "severity"),
            "severity should be optional"
        );

        // scan_type has enum constraint
        let scan_enum = params["properties"]["scan_type"]["enum"]
            .as_array()
            .unwrap();
        assert!(scan_enum.iter().any(|v| v == "image"));
        assert!(scan_enum.iter().any(|v| v == "fs"));
        assert!(scan_enum.iter().any(|v| v == "repo"));
    }

    #[tokio::test]
    async fn trivy_missing_target_errors() {
        let err = TrivyTool::new().execute(json!({})).await.unwrap_err();
        assert!(
            err.to_string().contains("missing required argument"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_trivy_typical_json() {
        let input = r#"{
            "Results": [
                {
                    "Target": "nginx:latest (debian 12.4)",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-1234",
                            "PkgName": "openssl",
                            "InstalledVersion": "3.0.11",
                            "Severity": "CRITICAL"
                        },
                        {
                            "VulnerabilityID": "CVE-2024-5678",
                            "PkgName": "curl",
                            "InstalledVersion": "7.88.1",
                            "Severity": "HIGH"
                        }
                    ]
                }
            ]
        }"#;

        let result = parse_trivy_output(input).expect("should parse");
        let targets = result["targets"].as_array().unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0]["name"], "nginx:latest (debian 12.4)");

        let vulns = targets[0]["vulnerabilities"].as_array().unwrap();
        assert_eq!(vulns.len(), 2);
        assert_eq!(vulns[0]["cve"], "CVE-2024-1234");
        assert_eq!(vulns[0]["package"], "openssl");
        assert_eq!(vulns[0]["version"], "3.0.11");
        assert_eq!(vulns[0]["severity"], "CRITICAL");

        assert_eq!(result["total_vulns"], 2);
        assert_eq!(result["by_severity"]["CRITICAL"], 1);
        assert_eq!(result["by_severity"]["HIGH"], 1);
    }

    #[test]
    fn parse_trivy_no_vulns() {
        // Vulnerabilities field is null when no findings — Results still present.
        let input = r#"{"Results": [{"Target": "alpine:latest", "Vulnerabilities": null}]}"#;
        let result = parse_trivy_output(input).expect("should parse even with no vulns");
        assert_eq!(result["total_vulns"], 0);
        let targets = result["targets"].as_array().unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0]["vulnerabilities"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn parse_trivy_invalid_json() {
        assert!(parse_trivy_output("not json").is_none());
        assert!(parse_trivy_output("").is_none());
        assert!(parse_trivy_output("   ").is_none());
    }

    /// Requires trivy and passt + newuidmap installed.
    /// Run with: cargo test -p sigint-tools -- --ignored
    #[tokio::test]
    #[ignore]
    async fn trivy_integration_scan_alpine() {
        let result = TrivyTool::new()
            .execute(json!({
                "target": "alpine:latest",
                "scan_type": "image",
                "severity": "CRITICAL,HIGH"
            }))
            .await
            .expect("trivy execution should not error");
        assert_eq!(result.exit_code, 0, "trivy exit code: {:?}", result.stderr);
    }
}
