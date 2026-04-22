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
//!
//! @decision DEC-P13-007
//! @title Best-effort structured parsing of nikto findings
//! @status accepted
//! @rationale Nikto text output lines beginning with `+` are findings. This
//! parser extracts finding text, OSVDB references (e.g. `OSVDB-3092`), and
//! the URL path from each `+`-prefixed line. Lines that don't start with `+`
//! (headers, summary lines, blank lines) are silently skipped. OSVDB refs may
//! be absent on some finding lines — those are captured without the ref field.

use async_trait::async_trait;
use regex::Regex;
use serde_json::{json, Value};
use sigint_llm::ToolDefinition;
use sigint_sandbox::profile::SandboxProfile;
use tracing::info;

use crate::error::{Result, ToolError};
use crate::result::{ToolResult, TruncationInfo};
use crate::tool::Tool;
use sigint_core::types::ToolRisk;

/// Default 1 MB output cap for nikto.
const DEFAULT_NIKTO_OUTPUT_CAP: usize = 1_048_576;

/// Sandboxed nikto tool wrapper.
///
/// Exposes nikto as a `Tool` for the LLM agent layer. Scans web targets for
/// known vulnerabilities and misconfigurations. Network access is provided via
/// pasta user-mode networking with a 10-minute timeout.
pub struct NiktoTool {
    output_cap: usize,
}

impl NiktoTool {
    /// Create a new NiktoTool with the default output cap.
    pub fn new() -> Self {
        Self {
            output_cap: DEFAULT_NIKTO_OUTPUT_CAP,
        }
    }

    /// Set a custom output cap (builder pattern).
    pub fn with_output_cap(mut self, cap: usize) -> Self {
        self.output_cap = cap;
        self
    }
}

impl Default for NiktoTool {
    fn default() -> Self {
        Self::new()
    }
}

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

    fn risk_level(&self) -> ToolRisk {
        ToolRisk::High
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
        cmd = cmd.max_output(self.output_cap);
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

        let structured_data = parse_nikto_output(&output.stdout);
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

/// Parse nikto plain-text output into a structured findings summary.
///
/// Nikto findings lines begin with `+`. The common formats are:
///
///   `+ /admin/: Directory indexing found.`
///   `+ OSVDB-3092: /test/: This might be interesting...`
///   `+ OSVDB-3268: /icons/: Directory indexing found.`
///
/// This parser handles both the with-OSVDB and without-OSVDB forms. The path
/// is extracted from the first `/…/` or `/…` token after the OSVDB ref (or
/// after the `+` if no OSVDB ref). Lines that don't start with `+` (headers,
/// summary stats, blank lines) are silently skipped. Returns `None` when no
/// `+`-prefixed finding lines exist.
///
/// Output shape:
/// ```json
/// {
///   "findings": [
///     {"text": "Directory indexing found.", "osvdb": "OSVDB-3092", "path": "/test/"},
///     {"text": "Something else.", "path": "/admin/"}
///   ],
///   "total": 2
/// }
/// ```
pub(crate) fn parse_nikto_output(stdout: &str) -> Option<Value> {
    // Pattern for an OSVDB reference at the start of a finding body.
    // e.g.  `OSVDB-3092: /test/: Some finding text.`
    // Uses ASCII classes ([0-9], [ \t], [^ \t]) because the workspace regex
    // crate is configured without unicode-perl (\d, \s, \S require it).
    let re_osvdb = Regex::new(r#"^(OSVDB-[0-9]+):[ \t]+(/[^ \t]*?):[ \t]+(.+)$"#)
        .expect("nikto OSVDB regex is valid");

    // Pattern for a finding without an OSVDB ref.
    // e.g.  `/admin/: Directory indexing found.`
    //       `Retrieved x-powered-by header: PHP/7.4`
    let re_path = Regex::new(r#"^(/[^ \t]*?):[ \t]+(.+)$"#).expect("nikto path regex is valid");

    let mut findings: Vec<Value> = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();

        // Only process finding lines — those beginning with `+`.
        let body = match line.strip_prefix("+ ") {
            Some(b) => b.trim(),
            None => continue,
        };

        if let Some(caps) = re_osvdb.captures(body) {
            let osvdb = caps
                .get(1)
                .map(|m: regex::Match| m.as_str())
                .unwrap_or("")
                .to_string();
            let path = caps
                .get(2)
                .map(|m: regex::Match| m.as_str())
                .unwrap_or("")
                .to_string();
            let text = caps
                .get(3)
                .map(|m: regex::Match| m.as_str())
                .unwrap_or("")
                .to_string();
            findings.push(json!({"text": text, "osvdb": osvdb, "path": path}));
        } else if let Some(caps) = re_path.captures(body) {
            let path = caps
                .get(1)
                .map(|m: regex::Match| m.as_str())
                .unwrap_or("")
                .to_string();
            let text = caps
                .get(2)
                .map(|m: regex::Match| m.as_str())
                .unwrap_or("")
                .to_string();
            findings.push(json!({"text": text, "path": path}));
        } else {
            // Finding line without a parseable path — store the full body as text.
            if !body.is_empty() {
                findings.push(json!({"text": body}));
            }
        }
    }

    if findings.is_empty() {
        return None;
    }

    let total = findings.len() as u64;
    Some(json!({
        "findings": findings,
        "total": total,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nikto_risk_level_is_high() {
        assert_eq!(
            NiktoTool::new().risk_level(),
            sigint_core::types::ToolRisk::High
        );
    }

    #[test]
    fn nikto_tool_name_nonempty() {
        assert!(!NiktoTool::new().name().is_empty());
        assert_eq!(NiktoTool::new().name(), "nikto_scan");
    }

    #[test]
    fn nikto_tool_description_nonempty() {
        assert!(!NiktoTool::new().description().is_empty());
    }

    #[test]
    fn nikto_tool_definition_shape() {
        let def = NiktoTool::new().definition();
        assert_eq!(def.type_, "function");
        assert_eq!(def.function.name, "nikto_scan");

        let params = &def.function.parameters;
        assert_eq!(params["type"], "object");

        // target is required
        let required = params["required"].as_array().unwrap();
        assert!(
            required.iter().any(|v| v == "target"),
            "target should be required"
        );

        // target property exists and is a string
        assert_eq!(params["properties"]["target"]["type"], "string");

        // tuning is optional (not in required array)
        assert!(params["properties"]["tuning"].is_object());
        assert!(
            !required.iter().any(|v| v == "tuning"),
            "tuning should be optional"
        );
    }

    #[tokio::test]
    async fn nikto_missing_target_errors() {
        let err = NiktoTool::new().execute(json!({})).await.unwrap_err();
        assert!(
            err.to_string().contains("missing required argument"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn nikto_tuning_argument_is_optional_string() {
        // Verify the definition schema accepts tuning as an optional string field.
        // No execution needed — this tests the JSON schema shape only.
        let def = NiktoTool::new().definition();
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

    // --- parser unit tests ---

    #[test]
    fn parse_nikto_finding_with_osvdb() {
        let input = "+ OSVDB-3092: /test/: This might be interesting...";
        let result = parse_nikto_output(input).expect("should return Some");
        let findings = result["findings"]
            .as_array()
            .expect("findings should be array");
        assert_eq!(findings.len(), 1);
        assert_eq!(result["total"], 1);
        assert_eq!(findings[0]["osvdb"], "OSVDB-3092");
        assert_eq!(findings[0]["path"], "/test/");
        assert_eq!(findings[0]["text"], "This might be interesting...");
    }

    #[test]
    fn parse_nikto_finding_without_osvdb() {
        let input = "+ /admin/: Directory indexing found.";
        let result = parse_nikto_output(input).expect("should return Some");
        let findings = result["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["path"], "/admin/");
        assert_eq!(findings[0]["text"], "Directory indexing found.");
        // no osvdb key when not present
        assert!(
            findings[0].get("osvdb").is_none(),
            "osvdb key should be absent"
        );
    }

    #[test]
    fn parse_nikto_multiple_findings_mixed() {
        // The input below has 8 lines beginning with `+`:
        //   + Target IP, + Target Hostname, + Target Port  (3 metadata lines)
        //   + Server                                       (1 server header)
        //   + OSVDB-3092 finding, + /admin/ finding,
        //   + OSVDB-3268 finding                           (3 structured findings)
        //   + 1 host(s) tested                            (1 summary line)
        // Lines beginning with `-` are skipped entirely.
        let input = r#"- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          127.0.0.1
+ Target Hostname:    127.0.0.1
+ Target Port:        80
---------------------------------------------------------------------------
+ Server: Apache/2.4.41
+ OSVDB-3092: /test/: This might be interesting.
+ /admin/: Directory indexing found.
+ OSVDB-3268: /icons/: Directory indexing found.
+ 1 host(s) tested"#;
        let result = parse_nikto_output(input).expect("should return Some");
        let findings = result["findings"].as_array().unwrap();
        // All 8 `+`-prefixed lines become findings (parser is best-effort).
        assert_eq!(findings.len(), 8, "should have 8 findings from + lines");
        assert_eq!(result["total"], 8);
        // The two OSVDB findings should carry the osvdb key.
        let osvdb_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.get("osvdb").is_some())
            .collect();
        assert_eq!(osvdb_findings.len(), 2, "should have 2 OSVDB findings");
    }

    #[test]
    fn parse_nikto_empty_output_returns_none() {
        assert!(
            parse_nikto_output("").is_none(),
            "empty output should return None"
        );
    }

    #[test]
    fn parse_nikto_no_plus_lines_returns_none() {
        let input = r#"- Nikto v2.1.6
- Target IP: 127.0.0.1
- 0 host(s) tested"#;
        assert!(
            parse_nikto_output(input).is_none(),
            "output with no + lines should return None"
        );
    }

    #[test]
    fn parse_nikto_finding_no_path_stores_text() {
        // Some nikto lines start with `+` but don't follow the path: text pattern.
        let input = "+ Retrieved x-powered-by header: PHP/7.4.3";
        let result = parse_nikto_output(input).expect("should return Some");
        let findings = result["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 1);
        // Should store full body as text, no path or osvdb
        assert!(findings[0]["text"].as_str().unwrap().contains("PHP/7.4.3"));
        assert!(findings[0].get("path").is_none());
        assert!(findings[0].get("osvdb").is_none());
    }

    /// Requires nikto + passt + newuidmap. Run with: cargo test -p sigint-tools -- --ignored
    #[tokio::test]
    #[ignore]
    async fn nikto_executes_against_loopback() {
        let result = NiktoTool::new()
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
