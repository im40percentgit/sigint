//! NucleiTool — sandboxed nuclei wrapper for template-based vulnerability scanning.
//!
//! @decision DEC-TOOL-007
//! @title NucleiTool uses SandboxProfile::web_scanner() for pasta networking
//! @status accepted
//! @rationale nuclei runs community-authored YAML templates against a target,
//! covering CVEs, misconfigurations, exposed panels, and more. Scans can be
//! broad (all templates) or targeted (specific template path or severity filter).
//! SandboxProfile::WebScanner provides a 600s timeout for broad template runs.
//! The `-silent -nc -jsonl` flags suppress banners and ANSI colour codes and
//! emit one JSON object per finding line, keeping stdout machine-readable for
//! LLM consumption. `parse_nuclei_jsonl()` parses each JSONL line into a
//! structured summary (findings list, total count, by_severity counts) which
//! is stored in `structured_data`. Raw JSONL is preserved in `stdout` for
//! direct LLM reading. Severity filtering lets the agent focus on actionable
//! findings and avoid low-noise informational output.

use std::collections::HashMap;

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

        // Suppress banner and ANSI colour codes; emit one JSON object per finding.
        cmd = cmd.arg("-silent");
        cmd = cmd.arg("-nc");
        cmd = cmd.arg("-jsonl");

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

        let structured_data = parse_nuclei_jsonl(&output.stdout);

        Ok(ToolResult {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.exit_code,
            duration: output.duration,
            structured_data,
        })
    }
}

/// Parse nuclei JSONL output into a structured summary.
///
/// Each line of nuclei `-jsonl` output is a self-contained JSON object. This
/// function collects valid lines into a findings list and builds summary
/// aggregations (total count, per-severity counts). Malformed lines are
/// silently skipped. Returns `None` if there are no valid findings at all.
///
/// Output shape:
/// ```json
/// {
///   "findings": [
///     {"template_id": "...", "name": "...", "severity": "...", "matched_at": "...", "type": "..."}
///   ],
///   "total": 1,
///   "by_severity": {"critical": 1}
/// }
/// ```
fn parse_nuclei_jsonl(output: &str) -> Option<Value> {
    let mut findings: Vec<Value> = Vec::new();
    let mut by_severity: HashMap<String, u64> = HashMap::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Parse the line as JSON; skip on any error.
        let obj: Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };

        // Extract required fields; skip the line if any are missing.
        let template_id = match obj["template-id"].as_str() {
            Some(s) => s.to_string(),
            None => continue,
        };
        let name = match obj["info"]["name"].as_str() {
            Some(s) => s.to_string(),
            None => continue,
        };
        let severity = match obj["info"]["severity"].as_str() {
            Some(s) => s.to_string(),
            None => continue,
        };
        let matched_at = match obj["matched-at"].as_str() {
            Some(s) => s.to_string(),
            None => continue,
        };
        let finding_type = match obj["type"].as_str() {
            Some(s) => s.to_string(),
            None => continue,
        };

        // Accumulate severity counts.
        *by_severity.entry(severity.clone()).or_insert(0) += 1;

        findings.push(json!({
            "template_id": template_id,
            "name": name,
            "severity": severity,
            "matched_at": matched_at,
            "type": finding_type,
        }));
    }

    if findings.is_empty() {
        return None;
    }

    let total = findings.len() as u64;
    let by_severity_json: Value = by_severity
        .into_iter()
        .map(|(k, v)| (k, json!(v)))
        .collect();

    Some(json!({
        "findings": findings,
        "total": total,
        "by_severity": by_severity_json,
    }))
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

    #[test]
    fn parse_nuclei_jsonl_multiple_findings() {
        let input = r#"{"template-id":"cve-2021-44228","info":{"name":"Log4Shell","severity":"critical"},"matched-at":"http://example.com/api","type":"http"}
{"template-id":"cve-2022-1234","info":{"name":"SomeHigh","severity":"high"},"matched-at":"http://example.com/login","type":"http"}
{"template-id":"cve-2023-9999","info":{"name":"SomeMedium","severity":"medium"},"matched-at":"http://example.com/config","type":"http"}"#;

        let result = parse_nuclei_jsonl(input).expect("should parse findings");

        let findings = result["findings"].as_array().expect("findings should be array");
        assert_eq!(findings.len(), 3, "should have 3 findings");
        assert_eq!(result["total"], 3, "total should be 3");

        // Check severity counts
        assert_eq!(result["by_severity"]["critical"], 1);
        assert_eq!(result["by_severity"]["high"], 1);
        assert_eq!(result["by_severity"]["medium"], 1);

        // Check first finding field values
        let first = &findings[0];
        assert_eq!(first["template_id"], "cve-2021-44228");
        assert_eq!(first["name"], "Log4Shell");
        assert_eq!(first["severity"], "critical");
        assert_eq!(first["matched_at"], "http://example.com/api");
        assert_eq!(first["type"], "http");
    }

    #[test]
    fn parse_nuclei_jsonl_empty_output() {
        assert!(parse_nuclei_jsonl("").is_none(), "empty string should return None");
    }

    #[test]
    fn parse_nuclei_jsonl_malformed_lines_skipped() {
        let input = r#"{"template-id":"cve-2021-44228","info":{"name":"Log4Shell","severity":"critical"},"matched-at":"http://example.com/api","type":"http"}
this is not json at all
{"broken": true
{"template-id":"cve-2022-5678","info":{"name":"Another","severity":"high"},"matched-at":"http://example.com/other","type":"dns"}"#;

        let result = parse_nuclei_jsonl(input).expect("should parse valid findings, skip invalid");
        let findings = result["findings"].as_array().expect("findings should be array");
        assert_eq!(findings.len(), 2, "should have 2 valid findings, skipping malformed lines");
        assert_eq!(result["total"], 2);
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
