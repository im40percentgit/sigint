//! FeroxbusterTool — sandboxed feroxbuster wrapper for fast content discovery.
//!
//! @decision DEC-TOOL-008
//! @title FeroxbusterTool uses SandboxProfile::bruteforce() for pasta networking
//! @status accepted
//! @rationale feroxbuster is a Rust-native recursive content-discovery tool that
//! outpaces gobuster on large wordlists. SandboxProfile::Bruteforce provides
//! pasta networking with a 300s timeout. The `--no-state -q` flags disable the
//! resume-state file (unnecessary inside an ephemeral sandbox) and suppress the
//! progress bar, keeping stdout clean for the LLM. Thread count is user-tunable
//! to balance speed against target rate-limiting. Extension filtering lets the
//! agent focus on specific file types (php, html, js) rather than all paths.
//!
//! @decision DEC-P13-006
//! @title Best-effort structured parsing of feroxbuster output
//! @status accepted
//! @rationale Feroxbuster quiet-mode (`-q --no-state`) emits one result per line
//! in the format: `STATUS METHOD LINES WORDS CHARS URL`. Lines that don't match
//! the expected format are silently skipped so the parser is resilient to
//! version-specific variations (e.g. extra fields, wildcard entries). A
//! rate-limit heuristic sets `possibly_rate_limited: true` when zero URLs are
//! parsed, giving agents a low-cost signal to retry with fewer threads.

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

const DEFAULT_THREADS: u64 = 50;
const DEFAULT_WORDLIST: &str = "/usr/share/wordlists/dirb/common.txt";

/// Default 1 MB output cap for feroxbuster.
const DEFAULT_FEROXBUSTER_OUTPUT_CAP: usize = 1_048_576;

/// Sandboxed feroxbuster tool wrapper.
///
/// Exposes feroxbuster as a `Tool` for the LLM agent layer. Performs recursive
/// content discovery against web targets using wordlist-based bruteforce.
/// Network access is provided via pasta user-mode networking.
pub struct FeroxbusterTool {
    output_cap: usize,
}

impl FeroxbusterTool {
    /// Create a new FeroxbusterTool with the default output cap.
    pub fn new() -> Self {
        Self {
            output_cap: DEFAULT_FEROXBUSTER_OUTPUT_CAP,
        }
    }

    /// Set a custom output cap (builder pattern).
    pub fn with_output_cap(mut self, cap: usize) -> Self {
        self.output_cap = cap;
        self
    }
}

impl Default for FeroxbusterTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for FeroxbusterTool {
    fn name(&self) -> &str {
        "feroxbuster_scan"
    }

    fn description(&self) -> &str {
        "Run feroxbuster to discover directories and files on a web target via \
         wordlist-based bruteforce. Returns discovered URLs with HTTP status codes. \
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
                        "description": "Target URL to scan (e.g. 'http://example.com')."
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "Path to the wordlist file. Defaults to '/usr/share/wordlists/dirb/common.txt'."
                    },
                    "extensions": {
                        "type": "string",
                        "description": "Comma-separated file extensions to append to each wordlist entry \
                                        (e.g. 'php,html,js'). Omit to bruteforce paths only."
                    },
                    "threads": {
                        "type": "integer",
                        "description": "Number of concurrent threads. Defaults to 50. \
                                        Reduce if the target rate-limits aggressively."
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

        // Extract optional wordlist, default to common.txt.
        let wordlist = args["wordlist"]
            .as_str()
            .unwrap_or(DEFAULT_WORDLIST)
            .to_string();

        // Extract optional extensions (comma-separated).
        let extensions = args["extensions"].as_str().map(|s| s.to_string());

        // Extract optional thread count, default to 50.
        let threads = args["threads"].as_u64().unwrap_or(DEFAULT_THREADS);
        if threads == 0 {
            return Err(ToolError::InvalidArgument {
                name: "threads".to_string(),
                expected: "positive integer".to_string(),
            });
        }

        info!(
            target = %target,
            wordlist = %wordlist,
            extensions = ?extensions,
            threads = threads,
            "executing feroxbuster scan"
        );

        let mut cmd = SandboxProfile::bruteforce().apply("feroxbuster");
        cmd = cmd.max_output(self.output_cap);
        cmd = cmd.arg("-u").arg(&target);
        cmd = cmd.arg("-w").arg(&wordlist);

        // Disable resume-state file (ephemeral sandbox — no persistent state).
        cmd = cmd.arg("--no-state");

        // Suppress progress bar for clean LLM output.
        cmd = cmd.arg("-q");

        // Apply optional extension filter.
        if let Some(ref ext) = extensions {
            cmd = cmd.arg("-x").arg(ext);
        }

        // Apply thread count.
        let thread_str = threads.to_string();
        cmd = cmd.arg("-t").arg(&thread_str);

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

        let structured_data = parse_feroxbuster_output(&output.stdout);
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

/// Parse feroxbuster quiet-mode output into a structured summary.
///
/// Feroxbuster with `-q --no-state` emits one result per line in the format:
///
///   `200      GET      123l      456w     7890c http://target/path`
///   `301      GET        0l        0w        0c http://target/path/ => http://target/path/`
///
/// Columns (space-separated):
///   STATUS  METHOD  LINESl  WORDSw  CHARSc  URL  [=> REDIRECT_URL]
///
/// The `l`, `w`, `c` suffixes on the numeric columns are part of feroxbuster's
/// output format (lines, words, chars). Lines that don't match are silently
/// skipped. Returns `None` when no valid URLs are found.
///
/// Output shape:
/// ```json
/// {
///   "urls": [{"status": 200, "method": "GET", "url": "http://target/path"}, ...],
///   "total": 1,
///   "possibly_rate_limited": false
/// }
/// ```
pub(crate) fn parse_feroxbuster_output(stdout: &str) -> Option<Value> {
    // Pattern: STATUS  METHOD  NUMl  NUMw  NUMc  URL [=> ANYTHING]
    // The numeric columns have l/w/c suffixes. URL must start with http:// or https://.
    // Uses ASCII classes ([0-9], [ \t], [^ \t], [a-zA-Z0-9_]) because the
    // workspace regex crate is configured without unicode-perl.
    let re = Regex::new(
        r#"^([0-9]{3})[ \t]+([a-zA-Z0-9_]+)[ \t]+[0-9]+l[ \t]+[0-9]+w[ \t]+[0-9]+c[ \t]+(https?://[^ \t]+)"#,
    )
    .expect("feroxbuster output regex is valid");

    let mut urls: Vec<Value> = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if let Some(caps) = re.captures(line) {
            let status: u64 = caps
                .get(1)
                .and_then(|m| m.as_str().parse().ok())
                .unwrap_or(0);
            let method = caps
                .get(2)
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();
            // URL may have a " => REDIRECT" suffix appended; strip it by
            // taking only the capture group (which stops at first whitespace).
            let url = caps
                .get(3)
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();

            urls.push(json!({"status": status, "method": method, "url": url}));
        }
        // Lines that don't match are silently skipped.
    }

    let total = urls.len() as u64;
    // Rate-limit heuristic: zero parsed URLs on a live target is suspicious.
    let possibly_rate_limited = total == 0;

    Some(json!({
        "urls": urls,
        "total": total,
        "possibly_rate_limited": possibly_rate_limited,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feroxbuster_tool_name_nonempty() {
        assert!(!FeroxbusterTool::new().name().is_empty());
        assert_eq!(FeroxbusterTool::new().name(), "feroxbuster_scan");
    }

    #[test]
    fn feroxbuster_tool_description_nonempty() {
        assert!(!FeroxbusterTool::new().description().is_empty());
    }

    #[test]
    fn feroxbuster_tool_definition_shape() {
        let def = FeroxbusterTool::new().definition();
        assert_eq!(def.type_, "function");
        assert_eq!(def.function.name, "feroxbuster_scan");

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

        // wordlist is optional (not in required array)
        assert!(params["properties"]["wordlist"].is_object());
        assert!(
            !required.iter().any(|v| v == "wordlist"),
            "wordlist should be optional"
        );

        // extensions is optional
        assert!(params["properties"]["extensions"].is_object());
        assert!(
            !required.iter().any(|v| v == "extensions"),
            "extensions should be optional"
        );

        // threads is optional integer
        assert_eq!(params["properties"]["threads"]["type"], "integer");
        assert!(
            !required.iter().any(|v| v == "threads"),
            "threads should be optional"
        );
    }

    #[tokio::test]
    async fn feroxbuster_missing_target_errors() {
        let err = FeroxbusterTool::new().execute(json!({})).await.unwrap_err();
        assert!(
            err.to_string().contains("missing required argument"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn feroxbuster_zero_threads_errors() {
        let err = FeroxbusterTool::new()
            .execute(json!({"target": "http://example.com", "threads": 0}))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("invalid argument"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn feroxbuster_default_threads() {
        // Verify the constant is a sensible default
        assert_eq!(DEFAULT_THREADS, 50);
    }

    // --- parser unit tests ---

    #[test]
    fn parse_feroxbuster_typical_output() {
        let input = r#"200      GET      123l      456w     7890c http://target/admin
301      GET        0l        0w        0c http://target/static => http://target/static/
403      GET       10l       20w      300c http://target/secret"#;
        let result = parse_feroxbuster_output(input).expect("should return Some");
        let urls = result["urls"].as_array().expect("urls should be array");
        assert_eq!(urls.len(), 3);
        assert_eq!(result["total"], 3);
        assert_eq!(urls[0]["status"], 200);
        assert_eq!(urls[0]["method"], "GET");
        assert_eq!(urls[0]["url"], "http://target/admin");
        assert_eq!(urls[1]["status"], 301);
        // URL should be the base URL without the redirect suffix
        assert_eq!(urls[1]["url"], "http://target/static");
        assert_eq!(result["possibly_rate_limited"], false);
    }

    #[test]
    fn parse_feroxbuster_empty_output_returns_some_with_zero() {
        let result =
            parse_feroxbuster_output("").expect("should return Some even for empty input");
        assert_eq!(result["total"], 0);
        assert_eq!(result["possibly_rate_limited"], true);
    }

    #[test]
    fn parse_feroxbuster_malformed_lines_skipped() {
        let input = r#"this is not feroxbuster output
200      GET      10l       20w      300c http://target/valid
[####################] - 0s         0/0       0/s http://target
WLD      GET      10l       20w      300c Got 200 for http://target/FUZZ"#;
        let result = parse_feroxbuster_output(input).expect("should return Some");
        let urls = result["urls"].as_array().unwrap();
        // Only the valid line with proper format should be parsed.
        // The WLD line doesn't start with a 3-digit status code.
        assert_eq!(urls.len(), 1, "only one parseable line");
        assert_eq!(urls[0]["url"], "http://target/valid");
    }

    #[test]
    fn parse_feroxbuster_https_urls() {
        let input = r#"200      GET       5l       15w      200c https://secure.example.com/api"#;
        let result = parse_feroxbuster_output(input).expect("should return Some");
        let urls = result["urls"].as_array().unwrap();
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0]["url"], "https://secure.example.com/api");
    }

    #[test]
    fn parse_feroxbuster_rate_limit_heuristic() {
        let result = parse_feroxbuster_output("   ").expect("should return Some");
        assert_eq!(result["possibly_rate_limited"], true);
    }

    /// Requires feroxbuster + passt + newuidmap. Run with: cargo test -p sigint-tools -- --ignored
    #[tokio::test]
    #[ignore]
    async fn feroxbuster_executes_against_loopback() {
        let result = FeroxbusterTool::new()
            .execute(json!({
                "target": "http://127.0.0.1",
                "threads": 10
            }))
            .await
            .expect("feroxbuster execution should not error");
        // feroxbuster exits 0 even when target is unreachable
        assert_eq!(
            result.exit_code, 0,
            "feroxbuster should exit 0: {:?}",
            result.stderr
        );
    }
}
