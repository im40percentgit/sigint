//! SqlmapTool — sandboxed sqlmap wrapper for SQL injection detection.
//!
//! @decision DEC-P15-001
//! @title SqlmapTool uses --batch for non-interactive LLM use
//! @status accepted
//! @rationale sqlmap is an interactive tool by default, prompting the user for
//! decisions during the injection process. The `--batch` flag forces
//! non-interactive mode where sqlmap uses default answers for all prompts,
//! making it suitable for autonomous LLM agent use. Combined with
//! `--flush-session` (no cached data reuse) and `--output-dir=/tmp`
//! (ephemeral sandbox output), this ensures deterministic, isolated scans.
//! SandboxProfile::web_scanner() provides a 600s timeout and pasta
//! user-mode networking for HTTP connectivity. Risk is High because sqlmap
//! actively exploits SQL injection vulnerabilities, which can modify data.

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

/// Default 1 MB output cap for sqlmap.
const DEFAULT_SQLMAP_OUTPUT_CAP: usize = 1_048_576;

/// Sandboxed sqlmap tool wrapper.
///
/// Exposes sqlmap as a `Tool` for the LLM agent layer. Detects and exploits SQL
/// injection vulnerabilities in target URLs. Network access is provided via
/// pasta user-mode networking with a 10-minute timeout.
pub struct SqlmapTool {
    output_cap: usize,
}

impl SqlmapTool {
    /// Create a new SqlmapTool with the default output cap.
    pub fn new() -> Self {
        Self {
            output_cap: DEFAULT_SQLMAP_OUTPUT_CAP,
        }
    }

    /// Set a custom output cap (builder pattern).
    pub fn with_output_cap(mut self, cap: usize) -> Self {
        self.output_cap = cap;
        self
    }
}

impl Default for SqlmapTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for SqlmapTool {
    fn name(&self) -> &str {
        "sqlmap_scan"
    }

    fn description(&self) -> &str {
        "Run sqlmap to detect and exploit SQL injection vulnerabilities in a target URL"
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
                        "description": "URL with injectable parameter (e.g. 'http://target/page?id=1')."
                    },
                    "level": {
                        "type": "integer",
                        "description": "Test thoroughness level 1-5. Default is 1. Higher levels \
                                        test more injection payloads and boundary cases."
                    },
                    "risk": {
                        "type": "integer",
                        "description": "Risk of tests 1-3. Default is 1. Higher risk may use \
                                        UPDATE/INSERT statements that can modify data."
                    },
                    "forms": {
                        "type": "boolean",
                        "description": "Automatically detect and test HTML forms on the target page."
                    },
                    "technique": {
                        "type": "string",
                        "description": "SQL injection techniques to test. Combination of: \
                                        B (boolean-based blind), E (error-based), U (UNION query), \
                                        S (stacked queries), T (time-based blind), Q (inline queries). \
                                        Example: 'BEU' for boolean, error, and UNION."
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

        // Extract optional parameters.
        let level = args["level"].as_u64();
        let risk = args["risk"].as_u64();
        let forms = args["forms"].as_bool().unwrap_or(false);
        let technique = args["technique"].as_str().map(|s| s.to_string());

        info!(
            target = %target,
            level = ?level,
            risk = ?risk,
            forms = forms,
            technique = ?technique,
            "executing sqlmap scan"
        );

        let mut cmd = SandboxProfile::web_scanner().apply("sqlmap");
        cmd = cmd.max_output(self.output_cap);
        cmd = cmd.arg("-u").arg(&target);

        // Non-interactive mode — required for LLM agent use.
        cmd = cmd.arg("--batch");

        // Don't reuse cached session data — ensures deterministic scans.
        cmd = cmd.arg("--flush-session");

        // Ephemeral sandbox output directory.
        cmd = cmd.arg("--output-dir=/tmp");

        // Apply optional level (1-5).
        if let Some(level) = level {
            cmd = cmd.arg("--level").arg(level.to_string());
        }

        // Apply optional risk (1-3).
        if let Some(risk) = risk {
            cmd = cmd.arg("--risk").arg(risk.to_string());
        }

        // Apply optional forms auto-detection.
        if forms {
            cmd = cmd.arg("--forms");
        }

        // Apply optional injection technique filter.
        if let Some(ref tech) = technique {
            cmd = cmd.arg("--technique").arg(tech);
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

        let structured_data = parse_sqlmap_output(&output.stdout);

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

/// Parse sqlmap text output into a structured summary.
///
/// Sqlmap produces human-readable text output. This function extracts key
/// information using regex patterns:
///
/// - `Parameter: <name> (<type>)` — injectable parameter and its injection point
/// - `Type: <technique>` — injection technique used (belongs to preceding parameter)
/// - `the back-end DBMS is <name>` — detected database management system
///
/// Parameters and their techniques are grouped: after a `Parameter: X (Y)` line,
/// all subsequent `Type: Z` lines belong to that parameter until the next
/// `Parameter:` line is encountered.
///
/// Output shape:
/// ```json
/// {
///   "vulnerable_params": [
///     {"param": "id", "type": "GET", "techniques": ["boolean-based blind"]}
///   ],
///   "dbms": "MySQL",
///   "total_vulns": 1
/// }
/// ```
///
/// Returns `Some` with `total_vulns: 0` when no vulnerabilities are found,
/// and `Some` with populated fields when vulnerabilities are detected.
pub(crate) fn parse_sqlmap_output(stdout: &str) -> Option<Value> {
    // Pattern: Parameter: <name> (<type>)
    // Uses ASCII-compatible patterns because the workspace regex crate is
    // configured without unicode-perl.
    let param_re = Regex::new(r"Parameter: ([^ ]+) \(([^)]+)\)").expect("param regex is valid");

    // Pattern: Type: <technique description>
    let type_re = Regex::new(r"^[ \t]*Type: (.+)$").expect("type regex is valid");

    // Pattern: the back-end DBMS is <name>
    let dbms_re =
        Regex::new(r"the back-end DBMS is ([^\r\n]+)").expect("dbms regex is valid");

    // Track current parameter context and collect vulnerable params.
    let mut vulnerable_params: Vec<Value> = Vec::new();
    let mut current_param: Option<String> = None;
    let mut current_type: Option<String> = None;
    let mut current_techniques: Vec<String> = Vec::new();
    let mut dbms: Option<String> = None;

    for line in stdout.lines() {
        let line = line.trim();

        // Check for parameter declaration — flush previous param if any.
        if let Some(caps) = param_re.captures(line) {
            // Flush the previous parameter if it had techniques.
            if let (Some(param), Some(ptype)) = (&current_param, &current_type) {
                if !current_techniques.is_empty() {
                    vulnerable_params.push(json!({
                        "param": param,
                        "type": ptype,
                        "techniques": current_techniques,
                    }));
                }
            }

            current_param = caps.get(1).map(|m| m.as_str().to_string());
            current_type = caps.get(2).map(|m| m.as_str().to_string());
            current_techniques = Vec::new();
            continue;
        }

        // Check for technique type — belongs to current parameter.
        if current_param.is_some() {
            if let Some(caps) = type_re.captures(line) {
                if let Some(technique) = caps.get(1) {
                    current_techniques.push(technique.as_str().trim().to_string());
                }
                continue;
            }
        }

        // Check for DBMS detection.
        if let Some(caps) = dbms_re.captures(line) {
            dbms = caps.get(1).map(|m| m.as_str().trim().to_string());
        }
    }

    // Flush the last parameter if any.
    if let (Some(param), Some(ptype)) = (&current_param, &current_type) {
        if !current_techniques.is_empty() {
            vulnerable_params.push(json!({
                "param": param,
                "type": ptype,
                "techniques": current_techniques,
            }));
        }
    }

    let total_vulns = vulnerable_params.len() as u64;

    let mut result = json!({
        "vulnerable_params": vulnerable_params,
        "total_vulns": total_vulns,
    });

    if let Some(ref db) = dbms {
        result["dbms"] = json!(db);
    }

    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlmap_tool_name() {
        assert_eq!(SqlmapTool::new().name(), "sqlmap_scan");
    }

    #[test]
    fn sqlmap_risk_level_is_high() {
        assert_eq!(
            SqlmapTool::new().risk_level(),
            sigint_core::types::ToolRisk::High
        );
    }

    #[test]
    fn sqlmap_definition_shape() {
        let def = SqlmapTool::new().definition();
        assert_eq!(def.type_, "function");
        assert_eq!(def.function.name, "sqlmap_scan");

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

        // Optional properties exist but are not required
        assert!(params["properties"]["level"].is_object());
        assert_eq!(params["properties"]["level"]["type"], "integer");
        assert!(
            !required.iter().any(|v| v == "level"),
            "level should be optional"
        );

        assert!(params["properties"]["risk"].is_object());
        assert_eq!(params["properties"]["risk"]["type"], "integer");
        assert!(
            !required.iter().any(|v| v == "risk"),
            "risk should be optional"
        );

        assert!(params["properties"]["forms"].is_object());
        assert_eq!(params["properties"]["forms"]["type"], "boolean");
        assert!(
            !required.iter().any(|v| v == "forms"),
            "forms should be optional"
        );

        assert!(params["properties"]["technique"].is_object());
        assert_eq!(params["properties"]["technique"]["type"], "string");
        assert!(
            !required.iter().any(|v| v == "technique"),
            "technique should be optional"
        );
    }

    #[tokio::test]
    async fn sqlmap_missing_target_errors() {
        let err = SqlmapTool::new().execute(json!({})).await.unwrap_err();
        assert!(
            err.to_string().contains("missing required argument"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_sqlmap_typical_output() {
        let input = r#"[INFO] testing connection to the target URL
[INFO] testing if the target URL content is stable
[INFO] target URL content is stable
[INFO] testing if GET parameter 'id' is dynamic
[INFO] GET parameter 'id' appears to be dynamic
[INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable
[INFO] testing for SQL injection on GET parameter 'id'
Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 5321=5321

[INFO] the back-end DBMS is MySQL
[INFO] fetching database names"#;

        let result = parse_sqlmap_output(input).expect("should return Some");
        let params = result["vulnerable_params"]
            .as_array()
            .expect("vulnerable_params should be array");
        assert_eq!(params.len(), 1);
        assert_eq!(result["total_vulns"], 1);

        let first = &params[0];
        assert_eq!(first["param"], "id");
        assert_eq!(first["type"], "GET");
        let techniques = first["techniques"].as_array().unwrap();
        assert_eq!(techniques.len(), 1);
        assert_eq!(techniques[0], "boolean-based blind");

        assert_eq!(result["dbms"], "MySQL");
    }

    #[test]
    fn parse_sqlmap_no_vulns() {
        let input = r#"[INFO] testing connection to the target URL
[INFO] testing if the target URL content is stable
[INFO] target URL content is stable
[WARNING] GET parameter 'id' does not seem to be injectable
[CRITICAL] all tested parameters do not appear to be injectable"#;

        let result = parse_sqlmap_output(input).expect("should return Some even with no vulns");
        assert_eq!(result["total_vulns"], 0);
        let params = result["vulnerable_params"]
            .as_array()
            .expect("vulnerable_params should be array");
        assert!(params.is_empty());
    }

    #[test]
    fn parse_sqlmap_multiple_techniques() {
        let input = r#"Parameter: id (GET)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: id=1 AND 5321=5321

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: id=1 AND SLEEP(5)

    Type: UNION query
    Title: Generic UNION query (NULL) - 3 columns
    Payload: id=-1 UNION ALL SELECT NULL,CONCAT(0x71,0x71),NULL-- -"#;

        let result = parse_sqlmap_output(input).expect("should return Some");
        let params = result["vulnerable_params"]
            .as_array()
            .expect("vulnerable_params should be array");
        assert_eq!(params.len(), 1);
        assert_eq!(result["total_vulns"], 1);

        let techniques = params[0]["techniques"].as_array().unwrap();
        assert_eq!(techniques.len(), 3);
        assert_eq!(techniques[0], "boolean-based blind");
        assert_eq!(techniques[1], "time-based blind");
        assert_eq!(techniques[2], "UNION query");
    }

    #[test]
    fn parse_sqlmap_dbms_detection() {
        let input = r#"[INFO] the back-end DBMS is PostgreSQL
[INFO] fetching database names"#;

        let result = parse_sqlmap_output(input).expect("should return Some");
        assert_eq!(result["dbms"], "PostgreSQL");
        assert_eq!(result["total_vulns"], 0);
    }

    /// Requires sqlmap + passt + newuidmap. Run with: cargo test -p sigint-tools -- --ignored
    #[tokio::test]
    #[ignore]
    async fn sqlmap_executes_against_loopback() {
        let result = SqlmapTool::new()
            .execute(json!({
                "target": "http://127.0.0.1/test?id=1",
                "level": 1,
                "risk": 1
            }))
            .await
            .expect("sqlmap execution should not error");
        // sqlmap exits 0 even when no injections are found
        assert_eq!(
            result.exit_code, 0,
            "sqlmap should exit 0: {:?}",
            result.stderr
        );
    }
}
