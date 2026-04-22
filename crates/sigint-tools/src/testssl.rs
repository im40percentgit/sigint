//! TestsslTool — sandboxed testssl.sh wrapper for TLS/SSL configuration analysis.
//!
//! @decision DEC-P15-006
//! @title TestsslTool uses SandboxProfile::recon() for passive TLS analysis
//! @status accepted
//! @rationale testssl.sh tests TLS/SSL configurations by connecting to a target
//! and probing supported protocols, cipher suites, and certificate properties.
//! SandboxProfile::Recon provides pasta networking with a 60s timeout — suitable
//! for a targeted TLS check against a single host without the extended time
//! needed by full vulnerability template scanners. Risk is Low because TLS
//! probing is non-destructive passive reconnaissance. The `--jsonfile /dev/stdout`
//! flag emits a JSON array to stdout for structured parsing. `--quiet --color 0`
//! suppress banner and ANSI codes for clean LLM-readable output. Findings with
//! severity "OK" are filtered out of the structured summary to focus on
//! actionable issues.

use async_trait::async_trait;
use serde_json::{json, Value};
use sigint_llm::ToolDefinition;
use sigint_sandbox::profile::SandboxProfile;
use std::collections::HashMap;
use tracing::info;

use crate::error::{Result, ToolError};
use crate::result::{ToolResult, TruncationInfo};
use crate::tool::Tool;
use sigint_core::types::ToolRisk;

/// Default 1 MB output cap for testssl.
const DEFAULT_TESTSSL_OUTPUT_CAP: usize = 1_048_576;

/// Sandboxed testssl.sh tool wrapper.
///
/// Exposes testssl.sh as a `Tool` for the LLM agent layer. Analyses TLS/SSL
/// configuration of a target host including protocol support, cipher suites,
/// certificate validity, and known vulnerabilities (BEAST, POODLE, Heartbleed,
/// etc.). Network access is provided via pasta user-mode networking with a
/// 1-minute timeout.
pub struct TestsslTool {
    output_cap: usize,
}

impl TestsslTool {
    /// Create a new TestsslTool with the default output cap.
    pub fn new() -> Self {
        Self {
            output_cap: DEFAULT_TESTSSL_OUTPUT_CAP,
        }
    }

    /// Set a custom output cap (builder pattern).
    pub fn with_output_cap(mut self, cap: usize) -> Self {
        self.output_cap = cap;
        self
    }
}

impl Default for TestsslTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for TestsslTool {
    fn name(&self) -> &str {
        "testssl_scan"
    }

    fn description(&self) -> &str {
        "Run testssl.sh to analyse TLS/SSL configuration of a target host. \
         Returns findings on protocols, cipher suites, certificate properties, \
         and known vulnerabilities. Requires network access — runs inside a \
         sandboxed environment with pasta user-mode networking."
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
                        "description": "Target host with optional port (e.g. 'example.com', \
                                        'example.com:8443', '192.168.1.1:443')."
                    },
                    "full": {
                        "type": "boolean",
                        "description": "Run full scan including cipher suite enumeration. \
                                        Slower but more thorough. Defaults to false."
                    },
                    "severity": {
                        "type": "string",
                        "description": "Minimum severity level to include in results. \
                                        One of: LOW, MEDIUM, HIGH, CRITICAL. Omit for all findings."
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

        // Extract optional full scan flag.
        let full = args["full"].as_bool().unwrap_or(false);

        // Extract optional severity filter.
        let severity = args["severity"].as_str().map(|s| s.to_uppercase());

        info!(
            target = %target,
            full = full,
            severity = ?severity,
            "executing testssl scan"
        );

        let mut cmd = SandboxProfile::recon().apply("testssl");
        cmd = cmd.max_output(self.output_cap);

        // Emit JSON output to stdout for structured parsing.
        cmd = cmd.arg("--jsonfile").arg("/dev/stdout");

        // Suppress banner and ANSI colour codes.
        cmd = cmd.arg("--quiet");
        cmd = cmd.arg("--color").arg("0");

        // Full scan enables cipher suite enumeration.
        if full {
            cmd = cmd.arg("-E");
        }

        // Target is the last argument.
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

        let structured_data = parse_testssl_output(&output.stdout, severity.as_deref());

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

/// Parse testssl.sh JSON output into a structured summary.
///
/// testssl.sh with `--jsonfile /dev/stdout` emits a JSON array where each
/// element represents a finding with fields: `id`, `ip`, `port`, `severity`,
/// `finding`, and optionally `cve`. This function:
///
/// 1. Filters out findings with severity "OK" (not actionable).
/// 2. Applies an optional minimum severity filter.
/// 3. Groups protocols separately from other findings.
/// 4. Counts issues by severity level.
///
/// Severity ordering (ascending): OK < INFO < LOW < MEDIUM < HIGH < CRITICAL
///
/// Output shape:
/// ```json
/// {
///   "findings": [
///     {"id": "POODLE_SSL", "severity": "HIGH", "finding": "VULNERABLE", "ip": "1.2.3.4", "port": "443"}
///   ],
///   "protocols": {"TLSv1.2": "offered", "TLSv1.3": "offered", "SSLv3": "not offered"},
///   "by_severity": {"HIGH": 1},
///   "total_issues": 1
/// }
/// ```
///
/// Returns `None` if the output is not valid JSON.
pub(crate) fn parse_testssl_output(stdout: &str, min_severity: Option<&str>) -> Option<Value> {
    // Severity ordering for filtering.
    let severity_rank = |s: &str| -> u8 {
        match s.to_uppercase().as_str() {
            "OK" => 0,
            "INFO" => 1,
            "LOW" => 2,
            "MEDIUM" => 3,
            "HIGH" => 4,
            "CRITICAL" => 5,
            _ => 1,
        }
    };

    let min_rank = min_severity.map(severity_rank).unwrap_or(1); // default: INFO and above

    let arr: Vec<Value> = serde_json::from_str(stdout.trim()).ok()?;

    let mut findings: Vec<Value> = Vec::new();
    let mut protocols: HashMap<String, String> = HashMap::new();
    let mut by_severity: HashMap<String, u64> = HashMap::new();

    for item in &arr {
        let id = item["id"].as_str().unwrap_or("").to_string();
        let severity = item["severity"].as_str().unwrap_or("INFO").to_string();
        let finding = item["finding"].as_str().unwrap_or("").to_string();
        let ip = item["ip"].as_str().unwrap_or("").to_string();
        let port = item["port"].as_str().unwrap_or("").to_string();

        // Separate protocol entries (id starts with "SSLv", "TLSv", "NPN", or "ALPN").
        if id.starts_with("SSLv")
            || id.starts_with("TLSv")
            || id.starts_with("NPN")
            || id.starts_with("ALPN")
        {
            protocols.insert(id, finding);
            continue;
        }

        // Filter out OK findings — not actionable.
        if severity.to_uppercase() == "OK" {
            continue;
        }

        // Apply minimum severity filter.
        if severity_rank(&severity) < min_rank {
            continue;
        }

        // Accumulate severity counts.
        *by_severity.entry(severity.clone()).or_insert(0) += 1;

        let mut entry = json!({
            "id": id,
            "severity": severity,
            "finding": finding,
            "ip": ip,
            "port": port,
        });

        // Include CVE if present and non-empty.
        if let Some(cve) = item["cve"].as_str() {
            if !cve.is_empty() {
                entry["cve"] = json!(cve);
            }
        }

        findings.push(entry);
    }

    let total_issues = findings.len() as u64;
    let protocols_json: Value = protocols.into_iter().map(|(k, v)| (k, json!(v))).collect();
    let by_severity_json: Value = by_severity
        .into_iter()
        .map(|(k, v)| (k, json!(v)))
        .collect();

    Some(json!({
        "findings": findings,
        "protocols": protocols_json,
        "by_severity": by_severity_json,
        "total_issues": total_issues,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testssl_tool_name() {
        assert_eq!(TestsslTool::new().name(), "testssl_scan");
    }

    #[test]
    fn testssl_risk_level_is_low() {
        assert_eq!(
            TestsslTool::new().risk_level(),
            sigint_core::types::ToolRisk::Low
        );
    }

    #[test]
    fn testssl_definition_shape() {
        let def = TestsslTool::new().definition();
        assert_eq!(def.type_, "function");
        assert_eq!(def.function.name, "testssl_scan");

        let params = &def.function.parameters;
        assert_eq!(params["type"], "object");

        // target is required
        let required = params["required"].as_array().unwrap();
        assert!(
            required.iter().any(|v| v == "target"),
            "target should be required"
        );
        assert_eq!(required.len(), 1, "only target should be required");

        // target property exists and is a string
        assert_eq!(params["properties"]["target"]["type"], "string");

        // full is optional boolean
        assert_eq!(params["properties"]["full"]["type"], "boolean");
        assert!(
            !required.iter().any(|v| v == "full"),
            "full should be optional"
        );

        // severity is optional string
        assert_eq!(params["properties"]["severity"]["type"], "string");
        assert!(
            !required.iter().any(|v| v == "severity"),
            "severity should be optional"
        );
    }

    #[tokio::test]
    async fn testssl_missing_target_errors() {
        let err = TestsslTool::new().execute(json!({})).await.unwrap_err();
        assert!(
            err.to_string().contains("missing required argument"),
            "unexpected error: {err}"
        );
    }

    // --- parser unit tests ---

    #[test]
    fn parse_testssl_typical_output() {
        let input = r#"[
            {"id": "SSLv3", "ip": "1.2.3.4", "port": "443", "severity": "NOT OK", "finding": "not offered"},
            {"id": "TLSv1.2", "ip": "1.2.3.4", "port": "443", "severity": "OK", "finding": "offered"},
            {"id": "TLSv1.3", "ip": "1.2.3.4", "port": "443", "severity": "OK", "finding": "offered"},
            {"id": "POODLE_SSL", "ip": "1.2.3.4", "port": "443", "severity": "HIGH", "finding": "VULNERABLE, uses SSLv3+CBC", "cve": "CVE-2014-3566"},
            {"id": "HEARTBLEED", "ip": "1.2.3.4", "port": "443", "severity": "OK", "finding": "not vulnerable"},
            {"id": "cert_trust", "ip": "1.2.3.4", "port": "443", "severity": "LOW", "finding": "self-signed"}
        ]"#;

        let result = parse_testssl_output(input, None).expect("should parse typical output");

        // TLSv1.2 and TLSv1.3 should be in protocols, not findings.
        let protocols = &result["protocols"];
        assert_eq!(protocols["TLSv1.2"], "offered");
        assert_eq!(protocols["TLSv1.3"], "offered");

        // OK findings should be filtered out (HEARTBLEED OK).
        let findings = result["findings"]
            .as_array()
            .expect("findings should be array");

        // POODLE_SSL (HIGH) + cert_trust (LOW) + SSLv3 (NOT OK, non-protocol) = at least 2
        assert!(
            findings.len() >= 2,
            "should have at least POODLE and cert_trust findings, got: {findings:?}"
        );

        // POODLE should be present with CVE.
        let poodle = findings
            .iter()
            .find(|f| f["id"] == "POODLE_SSL")
            .expect("POODLE_SSL should be in findings");
        assert_eq!(poodle["severity"], "HIGH");
        assert_eq!(poodle["cve"], "CVE-2014-3566");

        // Total issues matches findings count.
        assert_eq!(result["total_issues"], findings.len() as u64);
    }

    #[test]
    fn parse_testssl_all_ok_returns_empty_findings() {
        let input = r#"[
            {"id": "TLSv1.2", "ip": "1.2.3.4", "port": "443", "severity": "OK", "finding": "offered"},
            {"id": "TLSv1.3", "ip": "1.2.3.4", "port": "443", "severity": "OK", "finding": "offered"},
            {"id": "HEARTBLEED", "ip": "1.2.3.4", "port": "443", "severity": "OK", "finding": "not vulnerable"},
            {"id": "cert_trust", "ip": "1.2.3.4", "port": "443", "severity": "OK", "finding": "trusted"}
        ]"#;

        let result =
            parse_testssl_output(input, None).expect("should parse output with all OK findings");
        let findings = result["findings"]
            .as_array()
            .expect("findings should be array");
        assert!(
            findings.is_empty(),
            "all OK findings should be filtered out"
        );
        assert_eq!(result["total_issues"], 0);
    }

    #[test]
    fn parse_testssl_protocols_extracted() {
        let input = r#"[
            {"id": "SSLv2", "ip": "1.2.3.4", "port": "443", "severity": "NOT OK", "finding": "not offered"},
            {"id": "SSLv3", "ip": "1.2.3.4", "port": "443", "severity": "NOT OK", "finding": "not offered"},
            {"id": "TLSv1", "ip": "1.2.3.4", "port": "443", "severity": "LOW", "finding": "offered with final"},
            {"id": "TLSv1.1", "ip": "1.2.3.4", "port": "443", "severity": "LOW", "finding": "offered"},
            {"id": "TLSv1.2", "ip": "1.2.3.4", "port": "443", "severity": "OK", "finding": "offered"},
            {"id": "TLSv1.3", "ip": "1.2.3.4", "port": "443", "severity": "OK", "finding": "offered"}
        ]"#;

        let result = parse_testssl_output(input, None).expect("should parse protocols");
        let protocols = &result["protocols"];

        // All TLS/SSL entries go into protocols.
        assert!(protocols["SSLv2"].is_string());
        assert!(protocols["SSLv3"].is_string());
        assert!(protocols["TLSv1"].is_string());
        assert!(protocols["TLSv1.1"].is_string());
        assert!(protocols["TLSv1.2"].is_string());
        assert!(protocols["TLSv1.3"].is_string());

        // Protocol entries should NOT appear in findings.
        let findings = result["findings"].as_array().unwrap();
        assert!(
            !findings.iter().any(|f| f["id"]
                .as_str()
                .map(|s| s.starts_with("TLSv") || s.starts_with("SSLv"))
                .unwrap_or(false)),
            "TLS/SSL entries should not appear in findings"
        );
    }

    #[test]
    fn parse_testssl_invalid_json_returns_none() {
        assert!(parse_testssl_output("not json", None).is_none());
        assert!(parse_testssl_output("{not an array}", None).is_none());
        assert!(parse_testssl_output("", None).is_none());
    }

    /// Requires testssl.sh + passt + newuidmap. Run with: cargo test -p sigint-tools -- --ignored
    #[tokio::test]
    #[ignore]
    async fn testssl_executes_against_loopback() {
        let result = TestsslTool::new()
            .execute(json!({
                "target": "127.0.0.1:443"
            }))
            .await
            .expect("testssl execution should not error");
        // testssl exits non-zero when no TLS service is found — that's expected.
        assert!(
            result.exit_code == 0 || !result.stderr.is_empty() || !result.stdout.is_empty(),
            "testssl should run or report an error: {:?}",
            result.stderr
        );
    }
}
