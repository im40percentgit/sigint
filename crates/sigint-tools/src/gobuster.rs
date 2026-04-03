//! GobusterTool — sandboxed gobuster wrapper for directory and vhost bruteforce.
//!
//! @decision DEC-TOOL-005
//! @title GobusterTool uses SandboxProfile::bruteforce() for pasta networking
//! @status accepted
//! @rationale gobuster is a fast wordlist-based directory/vhost/DNS enumerator.
//! SandboxProfile::Bruteforce provides pasta user-mode networking with a 300s
//! timeout — short enough to bound runaway scans, long enough for large wordlists.
//! DNS mode swaps `-u` for `-d` since the target is a domain, not a URL.
//! The `--no-color -q` flags suppress ANSI escapes and progress bars, keeping
//! stdout clean for LLM consumption.
//!
//! @decision DEC-P13-005
//! @title Best-effort structured parsing of gobuster output
//! @status accepted
//! @rationale Extracts path/status/size from quiet-mode lines. Lines that don't
//! match the expected format are silently skipped. Gobuster quiet-mode (`-q
//! --no-color`) emits one result per line; the format differs by scan mode
//! (dir: `/path (Status: 200) [Size: 1234]`, vhost/dns: simple name lines).
//! A rate-limit heuristic is included: when a scan produces zero results it
//! sets `possibly_rate_limited: true` as a low-cost signal for agents to
//! consider retrying with reduced thread counts.

use async_trait::async_trait;
use regex::Regex;
use serde_json::{json, Value};
use sigint_llm::ToolDefinition;
use sigint_sandbox::profile::SandboxProfile;
use tracing::info;

use crate::error::{Result, ToolError};
use crate::result::{TruncationInfo, ToolResult};
use crate::tool::Tool;
use sigint_core::types::ToolRisk;

const DEFAULT_WORDLIST: &str = "/usr/share/wordlists/dirb/common.txt";

/// Scan mode requested by the LLM agent.
#[derive(Debug, Clone, Copy, PartialEq)]
enum GobusterMode {
    /// `dir` — directory/file bruteforce.
    Dir,
    /// `vhost` — virtual host enumeration.
    Vhost,
    /// `dns` — DNS subdomain bruteforce (target is a domain, not a URL).
    Dns,
}

impl GobusterMode {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "dir" => Some(GobusterMode::Dir),
            "vhost" => Some(GobusterMode::Vhost),
            "dns" => Some(GobusterMode::Dns),
            _ => None,
        }
    }

    fn as_str(&self) -> &'static str {
        match self {
            GobusterMode::Dir => "dir",
            GobusterMode::Vhost => "vhost",
            GobusterMode::Dns => "dns",
        }
    }
}

/// Sandboxed gobuster tool wrapper.
///
/// Exposes gobuster as a `Tool` for the LLM agent layer. Supports dir, vhost,
/// and DNS modes. Network access is provided via pasta user-mode networking.
pub struct GobusterTool;

#[async_trait]
impl Tool for GobusterTool {
    fn name(&self) -> &str {
        "gobuster_scan"
    }

    fn description(&self) -> &str {
        "Run gobuster to bruteforce directories, virtual hosts, or DNS subdomains \
         against a target. Returns discovered paths, hosts, or subdomains. \
         Requires network access — runs inside a sandboxed environment with \
         pasta user-mode networking."
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
                        "description": "Target URL (e.g. 'http://example.com') for dir/vhost mode, \
                                        or domain (e.g. 'example.com') for dns mode."
                    },
                    "mode": {
                        "type": "string",
                        "enum": ["dir", "vhost", "dns"],
                        "description": "Scan mode: 'dir' (directory bruteforce), 'vhost' (virtual host enum), \
                                        'dns' (subdomain enum). Defaults to 'dir'."
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "Path to the wordlist file. Defaults to '/usr/share/wordlists/dirb/common.txt'."
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

        // Extract optional mode, default to Dir.
        let mode = match args["mode"].as_str() {
            None => GobusterMode::Dir,
            Some(s) => GobusterMode::from_str(s).ok_or_else(|| ToolError::InvalidArgument {
                name: "mode".to_string(),
                expected: "one of: dir, vhost, dns".to_string(),
            })?,
        };

        // Extract optional wordlist, default to common.txt.
        let wordlist = args["wordlist"]
            .as_str()
            .unwrap_or(DEFAULT_WORDLIST)
            .to_string();

        info!(
            target = %target,
            ?mode,
            wordlist = %wordlist,
            "executing gobuster scan"
        );

        let mode_str = mode.as_str().to_string();
        let mut cmd = SandboxProfile::bruteforce().apply("gobuster");
        cmd = cmd.max_output(1_048_576);
        cmd = cmd.arg(&mode_str);

        // DNS mode uses -d (domain) instead of -u (URL).
        if mode == GobusterMode::Dns {
            cmd = cmd.arg("-d").arg(&target);
        } else {
            cmd = cmd.arg("-u").arg(&target);
        }

        cmd = cmd.arg("-w").arg(&wordlist);
        cmd = cmd.arg("--no-color");
        cmd = cmd.arg("-q");

        // SandboxedCommand::execute() is synchronous — bridge via spawn_blocking.
        let output = tokio::task::spawn_blocking(move || cmd.execute())
            .await
            .map_err(|e| ToolError::Sandbox(format!("spawn_blocking panicked: {e}")))?
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("timed out") || msg.contains("timeout") {
                    ToolError::Timeout(300)
                } else {
                    ToolError::Sandbox(msg)
                }
            })?;

        let structured_data = parse_gobuster_output(&output.stdout);
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

/// Parse gobuster quiet-mode output into a structured summary.
///
/// Gobuster with `-q --no-color` emits one result per line with no headers or
/// progress bars. In `dir` mode each line looks like:
///
///   `/admin                (Status: 200) [Size: 1234]`
///   `/admin/               (Status: 301) [Size: 0] [--> http://target/admin/]`
///
/// In `vhost` mode lines look like:
///   `Found: admin.example.com (Status: 200) [Size: 4096]`
///
/// In `dns` mode lines are bare subdomain names:
///   `mail.example.com`
///
/// This parser handles all three formats best-effort: lines that don't match any
/// pattern are silently skipped. Returns `None` when no parseable results are found.
///
/// Output shape:
/// ```json
/// {
///   "paths": [{"path": "/admin", "status": 200, "size": 1234}, ...],
///   "total": 1,
///   "possibly_rate_limited": false
/// }
/// ```
pub(crate) fn parse_gobuster_output(stdout: &str) -> Option<Value> {
    // dir/vhost pattern: optional "Found: " prefix, then path/name, then
    // "(Status: NNN)" and optionally "[Size: NNN]".
    // Example: `/admin                (Status: 200) [Size: 1234]`
    // Example: `Found: admin.example.com (Status: 200) [Size: 4096]`
    // Uses ASCII classes ([0-9], [ \t], [^ \t]) because the workspace regex
    // crate is configured without unicode-perl (\d, \s, \S require it).
    let re_status = Regex::new(
        r#"(?:Found:[ \t]+)?([^ \t]+)[ \t]+\(Status:[ \t]*([0-9]+)\)(?:[ \t]+\[Size:[ \t]*([0-9]+)\])?"#,
    )
    .expect("gobuster status regex is valid");

    // dns mode: bare subdomain on its own line (no parens, no brackets).
    // We treat any non-empty line that didn't match the status pattern as a
    // potential bare name, but only after we've tried the status pattern.
    let mut paths: Vec<Value> = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if let Some(caps) = re_status.captures(line) {
            // Matched dir or vhost format.
            let path = caps.get(1).map(|m: regex::Match| m.as_str()).unwrap_or("").to_string();
            let status: u64 = caps
                .get(2)
                .and_then(|m: regex::Match| m.as_str().parse().ok())
                .unwrap_or(0);
            // Size is optional in some gobuster versions.
            let size: Option<u64> = caps.get(3).and_then(|m: regex::Match| m.as_str().parse().ok());

            let entry = if let Some(sz) = size {
                json!({"path": path, "status": status, "size": sz})
            } else {
                json!({"path": path, "status": status})
            };
            paths.push(entry);
        }
        // Lines that don't match the status pattern are silently skipped.
        // DNS-mode bare subdomains have no status code to extract and are
        // less useful without context, so we omit them rather than inventing
        // a status of 0.
    }

    let total = paths.len() as u64;
    // Rate-limit heuristic: a scan that produced no results on a non-empty
    // wordlist is suspicious — the target may be silently dropping requests.
    let possibly_rate_limited = total == 0;

    Some(json!({
        "paths": paths,
        "total": total,
        "possibly_rate_limited": possibly_rate_limited,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gobuster_tool_name_nonempty() {
        assert!(!GobusterTool.name().is_empty());
        assert_eq!(GobusterTool.name(), "gobuster_scan");
    }

    #[test]
    fn gobuster_tool_description_nonempty() {
        assert!(!GobusterTool.description().is_empty());
    }

    #[test]
    fn gobuster_tool_definition_shape() {
        let def = GobusterTool.definition();
        assert_eq!(def.type_, "function");
        assert_eq!(def.function.name, "gobuster_scan");

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

        // mode has enum constraint
        let mode_enum = params["properties"]["mode"]["enum"].as_array().unwrap();
        assert!(mode_enum.iter().any(|v| v == "dir"));
        assert!(mode_enum.iter().any(|v| v == "vhost"));
        assert!(mode_enum.iter().any(|v| v == "dns"));

        // wordlist is optional (not in required array)
        assert!(params["properties"]["wordlist"].is_object());
        assert!(
            !required.iter().any(|v| v == "wordlist"),
            "wordlist should be optional"
        );
    }

    #[tokio::test]
    async fn gobuster_missing_target_errors() {
        let err = GobusterTool.execute(json!({})).await.unwrap_err();
        assert!(
            err.to_string().contains("missing required argument"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn gobuster_invalid_mode_errors() {
        let err = GobusterTool
            .execute(json!({"target": "http://example.com", "mode": "stealth"}))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("invalid argument"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn gobuster_mode_from_str() {
        assert_eq!(GobusterMode::from_str("dir"), Some(GobusterMode::Dir));
        assert_eq!(GobusterMode::from_str("vhost"), Some(GobusterMode::Vhost));
        assert_eq!(GobusterMode::from_str("dns"), Some(GobusterMode::Dns));
        assert_eq!(GobusterMode::from_str("fuzz"), None);
        assert_eq!(GobusterMode::from_str(""), None);
    }

    #[test]
    fn gobuster_mode_as_str() {
        assert_eq!(GobusterMode::Dir.as_str(), "dir");
        assert_eq!(GobusterMode::Vhost.as_str(), "vhost");
        assert_eq!(GobusterMode::Dns.as_str(), "dns");
    }

    // --- parser unit tests ---

    #[test]
    fn parse_gobuster_dir_mode_typical() {
        let input = r#"/admin                (Status: 200) [Size: 1234]
/login                (Status: 200) [Size: 5678]
/static               (Status: 301) [Size: 0]"#;
        let result = parse_gobuster_output(input).expect("should return Some");
        let paths = result["paths"].as_array().expect("paths should be array");
        assert_eq!(paths.len(), 3, "should parse 3 paths");
        assert_eq!(result["total"], 3);
        assert_eq!(paths[0]["path"], "/admin");
        assert_eq!(paths[0]["status"], 200);
        assert_eq!(paths[0]["size"], 1234);
        assert_eq!(paths[2]["status"], 301);
        assert_eq!(result["possibly_rate_limited"], false);
    }

    #[test]
    fn parse_gobuster_with_redirect_suffix() {
        // gobuster dir mode appends [--> URL] for redirects; parser should still
        // extract path and status.
        let input = r#"/admin/               (Status: 301) [Size: 0] [--> http://target/admin/]"#;
        let result = parse_gobuster_output(input).expect("should return Some");
        let paths = result["paths"].as_array().unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0]["path"], "/admin/");
        assert_eq!(paths[0]["status"], 301);
    }

    #[test]
    fn parse_gobuster_vhost_mode() {
        let input = r#"Found: admin.example.com (Status: 200) [Size: 4096]
Found: dev.example.com (Status: 403) [Size: 288]"#;
        let result = parse_gobuster_output(input).expect("should return Some");
        let paths = result["paths"].as_array().unwrap();
        assert_eq!(paths.len(), 2);
        assert_eq!(paths[0]["path"], "admin.example.com");
        assert_eq!(paths[0]["status"], 200);
    }

    #[test]
    fn parse_gobuster_empty_output_returns_some_with_zero() {
        // Empty output: no findings but we still return Some (with total=0 and
        // possibly_rate_limited=true) rather than None, so agents always get
        // structured metadata even from dry runs.
        let result = parse_gobuster_output("").expect("should return Some for empty input");
        assert_eq!(result["total"], 0);
        assert_eq!(result["possibly_rate_limited"], true);
    }

    #[test]
    fn parse_gobuster_malformed_lines_skipped() {
        let input = r#"this is not a gobuster line at all
/valid                (Status: 200) [Size: 99]
[ERROR] something went wrong
"#;
        let result = parse_gobuster_output(input).expect("should return Some");
        let paths = result["paths"].as_array().unwrap();
        assert_eq!(paths.len(), 1, "only valid line should be parsed");
        assert_eq!(paths[0]["path"], "/valid");
    }

    #[test]
    fn parse_gobuster_no_size_field() {
        // Some gobuster versions omit [Size: N] for certain result types.
        let input = r#"/api                  (Status: 200)"#;
        let result = parse_gobuster_output(input).expect("should return Some");
        let paths = result["paths"].as_array().unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(paths[0]["path"], "/api");
        assert_eq!(paths[0]["status"], 200);
        // size key should be absent when not present in output
        assert!(paths[0].get("size").is_none(), "size should be absent");
    }

    #[test]
    fn parse_gobuster_rate_limit_heuristic() {
        // Zero results should trigger the heuristic.
        let result = parse_gobuster_output("   ").expect("should return Some");
        assert_eq!(result["possibly_rate_limited"], true);
    }

    /// Requires gobuster + passt + newuidmap. Run with: cargo test -p sigint-tools -- --ignored
    #[tokio::test]
    #[ignore]
    async fn gobuster_executes_dir_scan() {
        let result = GobusterTool
            .execute(json!({
                "target": "http://127.0.0.1",
                "mode": "dir",
                "wordlist": "/usr/share/wordlists/dirb/common.txt"
            }))
            .await
            .expect("gobuster execution should not error");
        // gobuster exits 0 even when no results are found
        assert_eq!(
            result.exit_code, 0,
            "gobuster should exit 0: {:?}",
            result.stderr
        );
    }
}
