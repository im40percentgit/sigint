//! FfufTool — sandboxed ffuf wrapper for web fuzzing (directories, parameters, vhosts).
//!
//! @decision DEC-P15-002
//! @title ffuf uses JSON output mode (-of json) for reliable parsing
//! @status accepted
//! @rationale ffuf supports multiple output formats; JSON mode (`-of json -o /dev/stdout`)
//! emits structured results that are trivially parseable. Combined with `-s` (silent
//! mode) this eliminates progress-bar noise and gives the LLM a clean, machine-readable
//! payload. The FUZZ keyword in the target URL lets agents fuzz directories, parameters,
//! or virtual hosts with a single tool. SandboxProfile::bruteforce() provides pasta
//! networking with a 300s timeout, matching the other bruteforce tools.

use async_trait::async_trait;
use serde_json::{json, Value};
use sigint_llm::ToolDefinition;
use sigint_sandbox::profile::SandboxProfile;
use tracing::info;

use crate::error::{Result, ToolError};
use crate::result::{ToolResult, TruncationInfo};
use crate::tool::Tool;
use sigint_core::types::ToolRisk;

const DEFAULT_THREADS: u64 = 40;
const DEFAULT_WORDLIST: &str = "/usr/share/wordlists/dirb/common.txt";
const DEFAULT_MATCH_CODES: &str = "200,301,302,403";

/// Default 1 MB output cap for ffuf.
const DEFAULT_FFUF_OUTPUT_CAP: usize = 1_048_576;

/// Sandboxed ffuf tool wrapper.
///
/// Exposes ffuf as a `Tool` for the LLM agent layer. Performs fuzzing of
/// directories, parameters, or virtual hosts against web targets using
/// wordlist-based bruteforce. Network access is provided via pasta user-mode
/// networking. Output is captured in JSON format for reliable parsing.
pub struct FfufTool {
    output_cap: usize,
}

impl FfufTool {
    /// Create a new FfufTool with the default output cap.
    pub fn new() -> Self {
        Self {
            output_cap: DEFAULT_FFUF_OUTPUT_CAP,
        }
    }

    /// Set a custom output cap (builder pattern).
    pub fn with_output_cap(mut self, cap: usize) -> Self {
        self.output_cap = cap;
        self
    }
}

impl Default for FfufTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for FfufTool {
    fn name(&self) -> &str {
        "ffuf_scan"
    }

    fn description(&self) -> &str {
        "Run ffuf to fuzz directories, parameters, or virtual hosts on a web target"
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
                        "description": "URL with FUZZ keyword (e.g. 'http://target/FUZZ')."
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "Path to wordlist file. Defaults to '/usr/share/wordlists/dirb/common.txt'."
                    },
                    "match_codes": {
                        "type": "string",
                        "description": "Comma-separated HTTP status codes to report. Defaults to '200,301,302,403'."
                    },
                    "threads": {
                        "type": "integer",
                        "description": "Number of concurrent threads. Defaults to 40. \
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

        // Extract optional match codes, default to 200,301,302,403.
        let match_codes = args["match_codes"]
            .as_str()
            .unwrap_or(DEFAULT_MATCH_CODES)
            .to_string();

        // Extract optional thread count, default to 40.
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
            match_codes = %match_codes,
            threads = threads,
            "executing ffuf scan"
        );

        let mut cmd = SandboxProfile::bruteforce().apply("ffuf");
        cmd = cmd.max_output(self.output_cap);
        cmd = cmd.arg("-u").arg(&target);
        cmd = cmd.arg("-w").arg(&wordlist);
        cmd = cmd.arg("-mc").arg(&match_codes);
        cmd = cmd.arg("-o").arg("/dev/stdout"); // Output to stdout
        cmd = cmd.arg("-of").arg("json"); // JSON format
        cmd = cmd.arg("-s"); // Silent (no progress bar)
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

        let structured_data = parse_ffuf_output(&output.stdout);
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

/// Parse ffuf JSON output into a structured summary.
///
/// ffuf with `-of json -o /dev/stdout -s` emits a JSON object containing a
/// `results` array. Each result entry has fields like `input`, `status`,
/// `length`, `url`, etc. The JSON payload may be surrounded by other output
/// (e.g. error messages), so we locate the JSON object by searching for
/// `{"commandline"` or `{"results"` markers.
///
/// Returns `None` when no valid JSON can be extracted.
///
/// Output shape:
/// ```json
/// {
///   "results": [{"path": "admin", "status": 200, "length": 1234, "url": "http://target/admin"}],
///   "total": 1
/// }
/// ```
pub(crate) fn parse_ffuf_output(stdout: &str) -> Option<Value> {
    // Locate the JSON object in the output. ffuf JSON starts with
    // {"commandline" typically, but we also accept {"results" for resilience.
    let json_str = find_json_object(stdout)?;

    let parsed: Value = serde_json::from_str(json_str).ok()?;

    let results_arr = parsed.get("results")?.as_array()?;

    let mut results: Vec<Value> = Vec::new();
    for entry in results_arr {
        let path = entry
            .get("input")
            .and_then(|i| i.get("FUZZ"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let status = entry.get("status").and_then(|v| v.as_u64()).unwrap_or(0);
        let length = entry.get("length").and_then(|v| v.as_u64()).unwrap_or(0);
        let url = entry
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        results.push(json!({
            "path": path,
            "status": status,
            "length": length,
            "url": url,
        }));
    }

    let total = results.len() as u64;
    Some(json!({
        "results": results,
        "total": total,
    }))
}

/// Find the outermost JSON object in a string by locating a known ffuf JSON
/// marker and then matching braces to extract the complete object.
fn find_json_object(s: &str) -> Option<&str> {
    // Look for known ffuf JSON start markers.
    let start = s
        .find("{\"commandline\"")
        .or_else(|| s.find("{\"results\""))?;

    // Walk forward matching braces to find the end of the JSON object.
    let bytes = s.as_bytes();
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escape_next = false;

    for (i, &b) in bytes[start..].iter().enumerate() {
        if escape_next {
            escape_next = false;
            continue;
        }
        if b == b'\\' && in_string {
            escape_next = true;
            continue;
        }
        if b == b'"' {
            in_string = !in_string;
            continue;
        }
        if in_string {
            continue;
        }
        if b == b'{' {
            depth += 1;
        } else if b == b'}' {
            depth -= 1;
            if depth == 0 {
                return Some(&s[start..start + i + 1]);
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffuf_tool_name() {
        assert_eq!(FfufTool::new().name(), "ffuf_scan");
    }

    #[test]
    fn ffuf_definition_shape() {
        let def = FfufTool::new().definition();
        assert_eq!(def.type_, "function");
        assert_eq!(def.function.name, "ffuf_scan");

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

        // match_codes is optional
        assert!(params["properties"]["match_codes"].is_object());
        assert!(
            !required.iter().any(|v| v == "match_codes"),
            "match_codes should be optional"
        );

        // threads is optional integer
        assert_eq!(params["properties"]["threads"]["type"], "integer");
        assert!(
            !required.iter().any(|v| v == "threads"),
            "threads should be optional"
        );
    }

    #[tokio::test]
    async fn ffuf_missing_target_errors() {
        let err = FfufTool::new().execute(json!({})).await.unwrap_err();
        assert!(
            err.to_string().contains("missing required argument"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn ffuf_zero_threads_errors() {
        let err = FfufTool::new()
            .execute(json!({"target": "http://example.com/FUZZ", "threads": 0}))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("invalid argument"),
            "unexpected error: {err}"
        );
    }

    // --- parser unit tests ---

    #[test]
    fn parse_ffuf_json_output() {
        let input = concat!(
            r#"{"commandline":"ffuf -u http://target/FUZZ -w wordlist.txt","#,
            r#""time":"2024-01-01","results":["#,
            r#"{"input":{"FUZZ":"admin"},"position":1,"status":200,"length":1234,"#,
            r#""words":56,"lines":12,"content-type":"text/html","url":"http://target/admin"},"#,
            r#"{"input":{"FUZZ":"login"},"position":2,"status":301,"length":456,"#,
            r#""words":10,"lines":3,"content-type":"text/html","url":"http://target/login"},"#,
            r#"{"input":{"FUZZ":"secret"},"position":3,"status":403,"length":789,"#,
            r#""words":20,"lines":5,"content-type":"text/html","url":"http://target/secret"}"#,
            r#"]}"#,
        );
        let result = parse_ffuf_output(input).expect("should return Some");
        let results = result["results"].as_array().expect("results should be array");
        assert_eq!(results.len(), 3);
        assert_eq!(result["total"], 3);

        assert_eq!(results[0]["path"], "admin");
        assert_eq!(results[0]["status"], 200);
        assert_eq!(results[0]["length"], 1234);
        assert_eq!(results[0]["url"], "http://target/admin");

        assert_eq!(results[1]["path"], "login");
        assert_eq!(results[1]["status"], 301);
        assert_eq!(results[1]["length"], 456);

        assert_eq!(results[2]["path"], "secret");
        assert_eq!(results[2]["status"], 403);
    }

    #[test]
    fn parse_ffuf_empty_results() {
        let input = r#"{"commandline":"ffuf -u http://target/FUZZ","results":[]}"#;
        let result = parse_ffuf_output(input).expect("should return Some for empty results");
        let results = result["results"].as_array().expect("results should be array");
        assert_eq!(results.len(), 0);
        assert_eq!(result["total"], 0);
    }

    #[test]
    fn parse_ffuf_no_json_returns_none() {
        assert!(parse_ffuf_output("this is garbage output with no json").is_none());
        assert!(parse_ffuf_output("").is_none());
        assert!(parse_ffuf_output("   \n\n  ").is_none());
    }

    /// Requires ffuf + passt + newuidmap. Run with: cargo test -p sigint-tools -- --ignored
    #[tokio::test]
    #[ignore]
    async fn ffuf_executes_against_loopback() {
        let result = FfufTool::new()
            .execute(json!({
                "target": "http://127.0.0.1/FUZZ",
                "threads": 10
            }))
            .await
            .expect("ffuf execution should not error");
        // ffuf may exit non-zero when target is unreachable, but execution itself
        // should not produce a ToolError.
        println!("ffuf exit code: {}", result.exit_code);
        println!("ffuf stdout len: {}", result.stdout.len());
        println!("ffuf stderr: {}", result.stderr);
    }
}
