//! WhatwebTool — sandboxed whatweb wrapper for web technology fingerprinting.
//!
//! @decision DEC-P15-003
//! @title WhatwebTool uses SandboxProfile::recon() for fast passive fingerprinting
//! @status accepted
//! @rationale whatweb fingerprints web technologies, frameworks, and server
//! software by analysing HTTP headers, HTML content, and other response metadata.
//! It is a fast, predominantly passive tool so the Recon profile (60s timeout,
//! pasta networking) is appropriate. The `--log-json=-` flag emits one JSON
//! object per target line to stdout, and `--quiet` suppresses the ASCII banner.
//! `parse_whatweb_output()` extracts a structured technology list from the JSON
//! plugins object, splitting "name/version" strings on the first `/` to separate
//! name from version. Aggression levels 1-4 control scan intensity (1=stealthy,
//! 4=heavy); the default is 1.

use async_trait::async_trait;
use serde_json::{json, Value};
use sigint_llm::ToolDefinition;
use sigint_sandbox::profile::SandboxProfile;
use tracing::info;

use crate::error::{Result, ToolError};
use crate::result::{TruncationInfo, ToolResult};
use crate::tool::Tool;
use sigint_core::types::ToolRisk;

/// Default 1 MB output cap for whatweb.
const DEFAULT_WHATWEB_OUTPUT_CAP: usize = 1_048_576;

/// Sandboxed whatweb tool wrapper.
///
/// Exposes whatweb as a `Tool` for the LLM agent layer. Fingerprints web
/// technologies, frameworks, and server software from a URL target. Network
/// access is provided via pasta user-mode networking with a 60-second timeout.
pub struct WhatwebTool {
    output_cap: usize,
}

impl WhatwebTool {
    /// Create a new WhatwebTool with the default output cap.
    pub fn new() -> Self {
        Self {
            output_cap: DEFAULT_WHATWEB_OUTPUT_CAP,
        }
    }

    /// Set a custom output cap (builder pattern).
    pub fn with_output_cap(mut self, cap: usize) -> Self {
        self.output_cap = cap;
        self
    }
}

impl Default for WhatwebTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for WhatwebTool {
    fn name(&self) -> &str {
        "whatweb_scan"
    }

    fn description(&self) -> &str {
        "Run whatweb to fingerprint web technologies, frameworks, and server software"
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
                        "description": "URL or hostname to fingerprint (e.g. 'http://example.com')."
                    },
                    "aggression": {
                        "type": "integer",
                        "description": "Aggression level 1-4 (1=stealthy, 4=heavy). Default is 1."
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

        // Extract optional aggression level; validate range 1-4.
        let aggression = match args["aggression"].as_i64() {
            None => None,
            Some(a) => {
                if !(1..=4).contains(&a) {
                    return Err(ToolError::InvalidArgument {
                        name: "aggression".to_string(),
                        expected: "1-4".to_string(),
                    });
                }
                Some(a)
            }
        };

        info!(
            target = %target,
            aggression = ?aggression,
            "executing whatweb scan"
        );

        let mut cmd = SandboxProfile::recon().apply("whatweb");
        cmd = cmd.max_output(self.output_cap);
        cmd = cmd.arg("--log-json=-");
        cmd = cmd.arg("--quiet");
        cmd = cmd.arg(&target);

        if let Some(a) = aggression {
            cmd = cmd.arg("-a").arg(a.to_string());
        }

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

        let structured_data = parse_whatweb_output(&output.stdout);

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

/// Parse whatweb JSON output into a structured technology summary.
///
/// whatweb with `--log-json=-` emits one JSON object per line per target.
/// Each object has a `"plugins"` map where keys are technology categories
/// and values contain a `"string"` array of detected values.
///
/// For version extraction: if a string contains `/`, split on the first `/`
/// — left is name, right is version. Otherwise the whole string is the name
/// with no version.
///
/// Returns `None` if no technologies were detected.
///
/// Output shape:
/// ```json
/// {
///   "technologies": [
///     {"name": "nginx", "version": "1.18.0", "category": "HTTPServer"}
///   ],
///   "http_status": 200,
///   "total": 1
/// }
/// ```
fn parse_whatweb_output(output: &str) -> Option<Value> {
    let mut technologies: Vec<Value> = Vec::new();
    let mut http_status: Option<i64> = None;

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

        // Capture http_status from the first valid object that has one.
        if http_status.is_none() {
            http_status = obj["http_status"].as_i64();
        }

        // Extract the plugins object.
        let plugins = match obj["plugins"].as_object() {
            Some(p) => p,
            None => continue,
        };

        for (category, plugin_data) in plugins {
            if let Some(strings) = plugin_data["string"].as_array() {
                for s in strings {
                    if let Some(val) = s.as_str() {
                        let (name, version) = if let Some(slash_pos) = val.find('/') {
                            (
                                val[..slash_pos].to_string(),
                                Some(val[slash_pos + 1..].to_string()),
                            )
                        } else {
                            (val.to_string(), None)
                        };

                        technologies.push(json!({
                            "name": name,
                            "version": version,
                            "category": category,
                        }));
                    }
                }
            }
        }
    }

    if technologies.is_empty() && http_status.is_none() {
        return None;
    }

    let total = technologies.len() as u64;
    Some(json!({
        "technologies": technologies,
        "http_status": http_status,
        "total": total,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn whatweb_tool_name() {
        assert_eq!(WhatwebTool::new().name(), "whatweb_scan");
    }

    #[test]
    fn whatweb_risk_level_is_low() {
        assert_eq!(
            WhatwebTool::new().risk_level(),
            sigint_core::types::ToolRisk::Low
        );
    }

    #[test]
    fn whatweb_definition_shape() {
        let def = WhatwebTool::new().definition();
        assert_eq!(def.type_, "function");
        assert_eq!(def.function.name, "whatweb_scan");

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

        // aggression is optional (not in required array)
        assert!(params["properties"]["aggression"].is_object());
        assert!(
            !required.iter().any(|v| v == "aggression"),
            "aggression should be optional"
        );

        // aggression is an integer
        assert_eq!(params["properties"]["aggression"]["type"], "integer");
    }

    #[tokio::test]
    async fn whatweb_missing_target_errors() {
        let err = WhatwebTool::new().execute(json!({})).await.unwrap_err();
        assert!(
            err.to_string().contains("missing required argument"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn whatweb_aggression_out_of_range() {
        let err = WhatwebTool::new()
            .execute(json!({"target": "http://example.com", "aggression": 5}))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("invalid argument"),
            "unexpected error: {err}"
        );

        // Also test 0 (below range).
        let err = WhatwebTool::new()
            .execute(json!({"target": "http://example.com", "aggression": 0}))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("invalid argument"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_whatweb_json_output() {
        let input = r#"{"target":"http://example.com","http_status":200,"plugins":{"HTTPServer":{"string":["nginx/1.18.0"]},"Title":{"string":["Example Domain"]},"IP":{"string":["93.184.216.34"]},"Country":{"string":["UNITED STATES"]}}}"#;

        let result = parse_whatweb_output(input).expect("should parse technologies");

        let techs = result["technologies"]
            .as_array()
            .expect("technologies should be array");
        assert_eq!(techs.len(), 4, "should have 4 technologies");
        assert_eq!(result["total"], 4, "total should be 4");
        assert_eq!(result["http_status"], 200);
    }

    #[test]
    fn parse_whatweb_empty_plugins() {
        let input = r#"{"target":"http://example.com","http_status":200,"plugins":{}}"#;

        let result = parse_whatweb_output(input).expect("should return Some with http_status");
        let techs = result["technologies"]
            .as_array()
            .expect("technologies should be array");
        assert!(techs.is_empty(), "should have no technologies");
        assert_eq!(result["total"], 0);
        assert_eq!(result["http_status"], 200);
    }

    #[test]
    fn parse_whatweb_version_extraction() {
        let input = r#"{"target":"http://example.com","http_status":200,"plugins":{"HTTPServer":{"string":["nginx/1.18.0"]},"PoweredBy":{"string":["PHP/7.4.3"]}}}"#;

        let result = parse_whatweb_output(input).expect("should parse");
        let techs = result["technologies"]
            .as_array()
            .expect("technologies should be array");

        // Find the nginx entry.
        let nginx = techs
            .iter()
            .find(|t| t["category"] == "HTTPServer")
            .expect("should find HTTPServer");
        assert_eq!(nginx["name"], "nginx");
        assert_eq!(nginx["version"], "1.18.0");

        // Find the PHP entry.
        let php = techs
            .iter()
            .find(|t| t["category"] == "PoweredBy")
            .expect("should find PoweredBy");
        assert_eq!(php["name"], "PHP");
        assert_eq!(php["version"], "7.4.3");
    }

    #[test]
    fn parse_whatweb_no_version() {
        let input = r#"{"target":"http://example.com","http_status":200,"plugins":{"X-Frame-Options":{"string":["DENY"]},"Country":{"string":["UNITED STATES"]}}}"#;

        let result = parse_whatweb_output(input).expect("should parse");
        let techs = result["technologies"]
            .as_array()
            .expect("technologies should be array");

        // DENY has no slash, so version should be null.
        let xfo = techs
            .iter()
            .find(|t| t["category"] == "X-Frame-Options")
            .expect("should find X-Frame-Options");
        assert_eq!(xfo["name"], "DENY");
        assert!(xfo["version"].is_null(), "version should be null for DENY");

        // UNITED STATES has no slash either.
        let country = techs
            .iter()
            .find(|t| t["category"] == "Country")
            .expect("should find Country");
        assert_eq!(country["name"], "UNITED STATES");
        assert!(
            country["version"].is_null(),
            "version should be null for UNITED STATES"
        );
    }

    #[test]
    fn parse_whatweb_empty_output() {
        assert!(
            parse_whatweb_output("").is_none(),
            "empty string should return None"
        );
    }

    /// Requires whatweb + passt + newuidmap. Run with: cargo test -p sigint-tools -- --ignored
    #[tokio::test]
    #[ignore]
    async fn whatweb_executes_against_loopback() {
        let result = WhatwebTool::new()
            .execute(json!({
                "target": "http://127.0.0.1"
            }))
            .await
            .expect("whatweb execution should not error");
        // whatweb may exit non-zero if nothing is listening, but it should not
        // error at the sandbox level.
        println!("whatweb exit_code={}, stderr={}", result.exit_code, result.stderr);
    }
}
