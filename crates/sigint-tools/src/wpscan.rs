//! WpscanTool — sandboxed wpscan wrapper for WordPress enumeration.
//!
//! @decision DEC-P15-005
//! @title WpscanTool uses JSON output format for reliable structured parsing
//! @status accepted
//! @rationale wpscan's --format json provides stable machine-readable output
//! including version detection, plugin enumeration, user discovery, and
//! vulnerability counts. Random user agent avoids WAF detection.

use async_trait::async_trait;
use serde_json::{json, Value};
use sigint_llm::ToolDefinition;
use sigint_sandbox::profile::SandboxProfile;
use tracing::info;

use crate::error::{Result, ToolError};
use crate::result::{ToolResult, TruncationInfo};
use crate::tool::Tool;
use sigint_core::types::ToolRisk;

/// Default 1 MB output cap for wpscan.
const DEFAULT_WPSCAN_OUTPUT_CAP: usize = 1_048_576;

/// Sandboxed wpscan tool wrapper.
///
/// Exposes wpscan as a `Tool` for the LLM agent layer. Enumerates WordPress
/// installations including themes, plugins, users, and vulnerabilities. Network
/// access is provided via pasta user-mode networking with a 10-minute timeout.
pub struct WpscanTool {
    output_cap: usize,
}

impl WpscanTool {
    /// Create a new WpscanTool with the default output cap.
    pub fn new() -> Self {
        Self {
            output_cap: DEFAULT_WPSCAN_OUTPUT_CAP,
        }
    }

    /// Set a custom output cap (builder pattern).
    pub fn with_output_cap(mut self, cap: usize) -> Self {
        self.output_cap = cap;
        self
    }
}

impl Default for WpscanTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for WpscanTool {
    fn name(&self) -> &str {
        "wpscan_scan"
    }

    fn description(&self) -> &str {
        "Run wpscan to enumerate WordPress installations — themes, plugins, users, \
         and vulnerabilities"
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
                    "target": {
                        "type": "string",
                        "description": "WordPress site URL (e.g. 'http://target.com')."
                    },
                    "enumerate": {
                        "type": "string",
                        "description": "Enumeration options — 'vp' (vulnerable plugins), \
                                        'vt' (vulnerable themes), 'u' (users), 'ap' (all plugins), \
                                        'at' (all themes). Default: 'vp,vt,u'."
                    },
                    "api_token": {
                        "type": "string",
                        "description": "WPScan API token for vulnerability data."
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

        // Extract optional enumerate options, defaulting to "vp,vt,u".
        let enumerate = args["enumerate"].as_str().unwrap_or("vp,vt,u").to_string();

        // Extract optional API token.
        let api_token = args["api_token"].as_str().map(|s| s.to_string());

        info!(
            target = %target,
            enumerate = %enumerate,
            api_token = ?api_token.as_ref().map(|_| "<redacted>"),
            "executing wpscan scan"
        );

        let mut cmd = SandboxProfile::web_scanner().apply("wpscan");
        cmd = cmd.max_output(self.output_cap);
        cmd = cmd.arg("--url").arg(&target);
        cmd = cmd.arg("--enumerate").arg(&enumerate);
        cmd = cmd.arg("--format").arg("json");
        cmd = cmd.arg("--no-banner");
        cmd = cmd.arg("--random-user-agent");

        if let Some(ref token) = api_token {
            cmd = cmd.arg("--api-token").arg(token);
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

        let structured_data = parse_wpscan_output(&output.stdout);

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

/// Parse wpscan JSON output into a structured summary.
///
/// wpscan with `--format json` emits a JSON object containing target info,
/// WordPress version, plugins, themes, users, and interesting findings. This
/// function extracts the salient fields into a compact summary for the LLM.
///
/// Output shape:
/// ```json
/// {
///   "wordpress_version": "6.0",
///   "version_status": "outdated",
///   "plugins": [{"name": "contact-form-7", "version": "5.1", "vulnerabilities": 0}],
///   "users": ["admin"],
///   "interesting_findings": 3,
///   "total_vulns": 0
/// }
/// ```
///
/// Returns `None` if the output is not valid JSON.
pub(crate) fn parse_wpscan_output(stdout: &str) -> Option<Value> {
    let parsed: Value = serde_json::from_str(stdout.trim()).ok()?;

    // Extract WordPress version and status.
    let wordpress_version = parsed["version"]["number"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();
    let version_status = parsed["version"]["status"]
        .as_str()
        .unwrap_or("unknown")
        .to_string();

    // Extract plugins with vulnerability counts.
    let mut plugins: Vec<Value> = Vec::new();
    let mut total_vulns: u64 = 0;

    if let Some(plugins_obj) = parsed["plugins"].as_object() {
        for (slug, plugin_data) in plugins_obj {
            let version = plugin_data["version"]["number"]
                .as_str()
                .unwrap_or("unknown")
                .to_string();
            let vuln_count = plugin_data["vulnerabilities"]
                .as_array()
                .map(|a| a.len() as u64)
                .unwrap_or(0);
            total_vulns += vuln_count;
            plugins.push(json!({
                "name": slug,
                "version": version,
                "vulnerabilities": vuln_count,
            }));
        }
    }

    // Extract users.
    let users: Vec<String> = parsed["users"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|u| u["slug"].as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    // Count interesting findings.
    let interesting_findings = parsed["interesting_findings"]
        .as_array()
        .map(|a| a.len() as u64)
        .unwrap_or(0);

    Some(json!({
        "wordpress_version": wordpress_version,
        "version_status": version_status,
        "plugins": plugins,
        "users": users,
        "interesting_findings": interesting_findings,
        "total_vulns": total_vulns,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wpscan_tool_name() {
        assert_eq!(WpscanTool::new().name(), "wpscan_scan");
    }

    #[test]
    fn wpscan_definition_shape() {
        let def = WpscanTool::new().definition();
        assert_eq!(def.type_, "function");
        assert_eq!(def.function.name, "wpscan_scan");

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

        // enumerate is optional
        assert!(params["properties"]["enumerate"].is_object());
        assert_eq!(params["properties"]["enumerate"]["type"], "string");
        assert!(
            !required.iter().any(|v| v == "enumerate"),
            "enumerate should be optional"
        );

        // api_token is optional
        assert!(params["properties"]["api_token"].is_object());
        assert_eq!(params["properties"]["api_token"]["type"], "string");
        assert!(
            !required.iter().any(|v| v == "api_token"),
            "api_token should be optional"
        );
    }

    #[tokio::test]
    async fn wpscan_missing_target_errors() {
        let err = WpscanTool::new().execute(json!({})).await.unwrap_err();
        assert!(
            err.to_string().contains("missing required argument"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_wpscan_typical_output() {
        let input = r#"{
            "target_url": "http://target.com/",
            "effective_url": "http://target.com/",
            "interesting_findings": [
                {"url": "http://target.com/readme.html", "type": "interesting_finding"},
                {"url": "http://target.com/wp-cron.php", "type": "interesting_finding"},
                {"url": "http://target.com/xmlrpc.php", "type": "interesting_finding"}
            ],
            "version": {
                "number": "6.0",
                "status": "outdated"
            },
            "main_theme": {
                "slug": "twentytwentytwo"
            },
            "plugins": {
                "contact-form-7": {
                    "slug": "contact-form-7",
                    "version": {"number": "5.1"},
                    "vulnerabilities": []
                },
                "akismet": {
                    "slug": "akismet",
                    "version": {"number": "4.2"},
                    "vulnerabilities": [
                        {"title": "Akismet < 4.3 - Stored XSS", "fixed_in": "4.3"}
                    ]
                }
            },
            "users": [
                {"id": 1, "slug": "admin"},
                {"id": 2, "slug": "editor"}
            ]
        }"#;

        let result = parse_wpscan_output(input).expect("should parse typical output");

        assert_eq!(result["wordpress_version"], "6.0");
        assert_eq!(result["version_status"], "outdated");

        let plugins = result["plugins"]
            .as_array()
            .expect("plugins should be array");
        assert_eq!(plugins.len(), 2);

        // Find the akismet plugin (order not guaranteed from HashMap iteration).
        let akismet = plugins
            .iter()
            .find(|p| p["name"] == "akismet")
            .expect("akismet plugin should be present");
        assert_eq!(akismet["version"], "4.2");
        assert_eq!(akismet["vulnerabilities"], 1);

        let cf7 = plugins
            .iter()
            .find(|p| p["name"] == "contact-form-7")
            .expect("contact-form-7 plugin should be present");
        assert_eq!(cf7["version"], "5.1");
        assert_eq!(cf7["vulnerabilities"], 0);

        let users = result["users"].as_array().expect("users should be array");
        assert_eq!(users.len(), 2);
        assert!(users.iter().any(|u| u == "admin"));
        assert!(users.iter().any(|u| u == "editor"));

        assert_eq!(result["interesting_findings"], 3);
        assert_eq!(result["total_vulns"], 1);
    }

    #[test]
    fn parse_wpscan_no_vulns() {
        let input = r#"{
            "target_url": "http://clean-site.com/",
            "effective_url": "http://clean-site.com/",
            "interesting_findings": [],
            "version": {
                "number": "6.4",
                "status": "latest"
            },
            "plugins": {
                "jetpack": {
                    "slug": "jetpack",
                    "version": {"number": "12.0"},
                    "vulnerabilities": []
                }
            },
            "users": []
        }"#;

        let result = parse_wpscan_output(input).expect("should parse clean site output");

        assert_eq!(result["wordpress_version"], "6.4");
        assert_eq!(result["version_status"], "latest");
        assert_eq!(result["total_vulns"], 0);
        assert_eq!(result["interesting_findings"], 0);

        let plugins = result["plugins"].as_array().unwrap();
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0]["name"], "jetpack");
        assert_eq!(plugins[0]["vulnerabilities"], 0);

        let users = result["users"].as_array().unwrap();
        assert!(users.is_empty());
    }

    #[test]
    fn parse_wpscan_with_users() {
        let input = r#"{
            "target_url": "http://target.com/",
            "effective_url": "http://target.com/",
            "interesting_findings": [],
            "version": {
                "number": "5.9",
                "status": "outdated"
            },
            "plugins": {},
            "users": [
                {"id": 1, "slug": "admin"},
                {"id": 2, "slug": "author1"},
                {"id": 3, "slug": "subscriber42"}
            ]
        }"#;

        let result = parse_wpscan_output(input).expect("should parse users");

        let users = result["users"].as_array().expect("users should be array");
        assert_eq!(users.len(), 3);
        assert!(users.iter().any(|u| u == "admin"));
        assert!(users.iter().any(|u| u == "author1"));
        assert!(users.iter().any(|u| u == "subscriber42"));
    }

    #[test]
    fn parse_wpscan_invalid_json_returns_none() {
        assert!(parse_wpscan_output("this is not json").is_none());
        assert!(parse_wpscan_output("{broken: json}").is_none());
        assert!(parse_wpscan_output("<!DOCTYPE html><html>").is_none());
    }

    #[test]
    fn parse_wpscan_empty_output() {
        assert!(parse_wpscan_output("").is_none());
        assert!(parse_wpscan_output("   ").is_none());
        assert!(parse_wpscan_output("\n\n").is_none());
    }

    #[test]
    fn wpscan_risk_level_is_medium() {
        assert_eq!(
            WpscanTool::new().risk_level(),
            sigint_core::types::ToolRisk::Medium
        );
    }

    #[test]
    fn wpscan_default_enumerate() {
        // Verify default enumerate value is applied when not provided.
        // We can't test the actual command args without execution, but we can
        // confirm the fallback logic in execute() by testing the definition
        // describes the default.
        let def = WpscanTool::new().definition();
        let enumerate_desc = def.function.parameters["properties"]["enumerate"]["description"]
            .as_str()
            .unwrap();
        assert!(
            enumerate_desc.contains("vp,vt,u"),
            "description should mention default enumerate value"
        );
    }

    /// Requires wpscan + passt + newuidmap. Run with: cargo test -p sigint-tools -- --ignored
    #[tokio::test]
    #[ignore]
    async fn wpscan_executes_against_loopback() {
        let result = WpscanTool::new()
            .execute(json!({
                "target": "http://127.0.0.1"
            }))
            .await
            .expect("wpscan execution should not error");
        // wpscan may exit non-zero when no WordPress is found — that's expected
        assert!(
            result.exit_code == 0 || !result.stderr.is_empty(),
            "wpscan should run or report an error: {:?}",
            result
        );
    }
}
