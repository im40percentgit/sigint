//! HydraTool — sandboxed hydra wrapper for brute-force credential testing.
//!
//! @decision DEC-P15-004
//! @title HydraTool uses SandboxProfile::bruteforce() with credential-specific args
//! @status accepted
//! @rationale hydra is a fast online password cracker supporting numerous protocols.
//! Bruteforce profile provides pasta networking with 300s timeout. Machine-readable
//! output (-o /dev/stdout) enables structured credential extraction.

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

const DEFAULT_THREADS: u64 = 16;
const DEFAULT_PASSWORD_LIST: &str = "/usr/share/wordlists/rockyou.txt";

/// Default 1 MB output cap for hydra.
const DEFAULT_HYDRA_OUTPUT_CAP: usize = 1_048_576;

/// Sandboxed hydra tool wrapper.
///
/// Exposes hydra as a `Tool` for the LLM agent layer. Brute-forces credentials
/// against network services (SSH, FTP, HTTP, etc.). Network access is provided
/// via pasta user-mode networking with a 300-second timeout.
pub struct HydraTool {
    output_cap: usize,
}

impl HydraTool {
    /// Create a new HydraTool with the default output cap.
    pub fn new() -> Self {
        Self {
            output_cap: DEFAULT_HYDRA_OUTPUT_CAP,
        }
    }

    /// Set a custom output cap (builder pattern).
    pub fn with_output_cap(mut self, cap: usize) -> Self {
        self.output_cap = cap;
        self
    }
}

impl Default for HydraTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for HydraTool {
    fn name(&self) -> &str {
        "hydra_scan"
    }

    fn description(&self) -> &str {
        "Run hydra to brute-force credentials against network services \
         (SSH, FTP, HTTP, etc.)"
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
                        "description": "Target host (e.g. '192.168.1.1')."
                    },
                    "service": {
                        "type": "string",
                        "description": "Service to attack (ssh, ftp, http-get, http-post-form, smb, rdp, mysql, etc.)."
                    },
                    "username": {
                        "type": "string",
                        "description": "Single username to test."
                    },
                    "username_list": {
                        "type": "string",
                        "description": "Path to username wordlist."
                    },
                    "password_list": {
                        "type": "string",
                        "description": "Path to password wordlist. Defaults to '/usr/share/wordlists/rockyou.txt'."
                    },
                    "port": {
                        "type": "integer",
                        "description": "Non-standard service port."
                    },
                    "threads": {
                        "type": "integer",
                        "description": "Parallel tasks. Defaults to 16."
                    }
                },
                "required": ["target", "service"]
            }),
        )
    }

    async fn execute(&self, args: Value) -> Result<ToolResult> {
        // Extract required target.
        let target = args["target"]
            .as_str()
            .ok_or_else(|| ToolError::MissingArgument("target".to_string()))?
            .to_string();

        // Extract required service.
        let service = args["service"]
            .as_str()
            .ok_or_else(|| ToolError::MissingArgument("service".to_string()))?
            .to_string();

        // Extract optional single username.
        let username = args["username"].as_str().map(|s| s.to_string());

        // Extract optional username wordlist.
        let username_list = args["username_list"].as_str().map(|s| s.to_string());

        // Must have either username or username_list.
        if username.is_none() && username_list.is_none() {
            return Err(ToolError::InvalidArgument {
                name: "username".to_string(),
                expected: "either 'username' or 'username_list' must be provided".to_string(),
            });
        }

        // Extract optional password list, default to rockyou.txt.
        let password_list = args["password_list"]
            .as_str()
            .unwrap_or(DEFAULT_PASSWORD_LIST)
            .to_string();

        // Extract optional port.
        let port = args["port"].as_u64();

        // Extract optional thread count, default to 16.
        let threads = args["threads"].as_u64().unwrap_or(DEFAULT_THREADS);
        if threads == 0 {
            return Err(ToolError::InvalidArgument {
                name: "threads".to_string(),
                expected: "positive integer".to_string(),
            });
        }

        info!(
            target = %target,
            service = %service,
            username = ?username,
            username_list = ?username_list,
            password_list = %password_list,
            port = ?port,
            threads = threads,
            "executing hydra scan"
        );

        let mut cmd = SandboxProfile::bruteforce().apply("hydra");
        cmd = cmd.max_output(self.output_cap);

        // Username: -l for single, -L for list.
        if let Some(ref user) = username {
            cmd = cmd.arg("-l").arg(user);
        } else if let Some(ref ulist) = username_list {
            cmd = cmd.arg("-L").arg(ulist);
        }

        // Password list.
        cmd = cmd.arg("-P").arg(&password_list);

        // Optional port.
        if let Some(p) = port {
            cmd = cmd.arg("-s").arg(p.to_string());
        }

        // Threads.
        let thread_str = threads.to_string();
        cmd = cmd.arg("-t").arg(&thread_str);

        // Target and service in protocol://host format.
        cmd = cmd.arg(format!("{}://{}", service, target));

        // Machine-readable output.
        cmd = cmd.arg("-o").arg("/dev/stdout");

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

        let structured_data = parse_hydra_output(&output.stdout);
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

/// Parse hydra output into a structured credential summary.
///
/// Hydra emits one line per discovered credential in the format:
///
///   `[22][ssh] host: 192.168.1.1   login: admin   password: password123`
///
/// Pattern: `[port][service] host: <host>   login: <user>   password: <pass>`
///
/// Lines that don't match are silently skipped. Returns `Some` with a
/// (possibly empty) credentials array and total count.
///
/// Output shape:
/// ```json
/// {
///   "credentials": [
///     {"host": "192.168.1.1", "port": 22, "service": "ssh", "login": "admin", "password": "password123"}
///   ],
///   "total": 1
/// }
/// ```
pub(crate) fn parse_hydra_output(stdout: &str) -> Option<Value> {
    // Pattern: [port][service] host: <host>   login: <user>   password: <pass>
    // Uses ASCII classes because the workspace regex crate is configured without
    // unicode-perl.
    let re = Regex::new(
        r#"^\[([0-9]+)\]\[([a-zA-Z0-9_-]+)\][ \t]+host:[ \t]+([^ \t]+)[ \t]+login:[ \t]+([^ \t]+)[ \t]+password:[ \t]+(.+)$"#,
    )
    .expect("hydra output regex is valid");

    let mut credentials: Vec<Value> = Vec::new();

    for line in stdout.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        if let Some(caps) = re.captures(line) {
            let port: u64 = caps
                .get(1)
                .and_then(|m| m.as_str().parse().ok())
                .unwrap_or(0);
            let service = caps
                .get(2)
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();
            let host = caps
                .get(3)
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();
            let login = caps
                .get(4)
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();
            let password = caps
                .get(5)
                .map(|m| m.as_str().trim().to_string())
                .unwrap_or_default();

            credentials.push(json!({
                "host": host,
                "port": port,
                "service": service,
                "login": login,
                "password": password,
            }));
        }
        // Lines that don't match are silently skipped.
    }

    let total = credentials.len() as u64;
    Some(json!({
        "credentials": credentials,
        "total": total,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hydra_tool_name() {
        assert_eq!(HydraTool::new().name(), "hydra_scan");
    }

    #[test]
    fn hydra_risk_level_is_high() {
        assert_eq!(
            HydraTool::new().risk_level(),
            sigint_core::types::ToolRisk::High
        );
    }

    #[test]
    fn hydra_definition_shape() {
        let def = HydraTool::new().definition();
        assert_eq!(def.type_, "function");
        assert_eq!(def.function.name, "hydra_scan");

        let params = &def.function.parameters;
        assert_eq!(params["type"], "object");

        // target and service are required
        let required = params["required"].as_array().unwrap();
        assert!(
            required.iter().any(|v| v == "target"),
            "target should be required"
        );
        assert!(
            required.iter().any(|v| v == "service"),
            "service should be required"
        );

        // target property exists and is a string
        assert_eq!(params["properties"]["target"]["type"], "string");

        // service property exists and is a string
        assert_eq!(params["properties"]["service"]["type"], "string");

        // username is optional
        assert!(params["properties"]["username"].is_object());
        assert!(
            !required.iter().any(|v| v == "username"),
            "username should be optional"
        );

        // username_list is optional
        assert!(params["properties"]["username_list"].is_object());
        assert!(
            !required.iter().any(|v| v == "username_list"),
            "username_list should be optional"
        );

        // password_list is optional
        assert!(params["properties"]["password_list"].is_object());
        assert!(
            !required.iter().any(|v| v == "password_list"),
            "password_list should be optional"
        );

        // port is optional integer
        assert_eq!(params["properties"]["port"]["type"], "integer");
        assert!(
            !required.iter().any(|v| v == "port"),
            "port should be optional"
        );

        // threads is optional integer
        assert_eq!(params["properties"]["threads"]["type"], "integer");
        assert!(
            !required.iter().any(|v| v == "threads"),
            "threads should be optional"
        );
    }

    #[tokio::test]
    async fn hydra_missing_target_errors() {
        let err = HydraTool::new()
            .execute(json!({"service": "ssh", "username": "admin"}))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("missing required argument"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn hydra_missing_service_errors() {
        let err = HydraTool::new()
            .execute(json!({"target": "192.168.1.1", "username": "admin"}))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("missing required argument"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn hydra_zero_threads_errors() {
        let err = HydraTool::new()
            .execute(json!({
                "target": "192.168.1.1",
                "service": "ssh",
                "username": "admin",
                "threads": 0
            }))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("invalid argument"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn hydra_missing_username_and_username_list_errors() {
        let err = HydraTool::new()
            .execute(json!({
                "target": "192.168.1.1",
                "service": "ssh"
            }))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("invalid argument"),
            "unexpected error: {err}"
        );
    }

    // --- parser unit tests ---

    #[test]
    fn parse_hydra_typical_output() {
        let input = r#"[22][ssh] host: 192.168.1.1   login: admin   password: password123
[22][ssh] host: 192.168.1.1   login: root    password: toor"#;
        let result = parse_hydra_output(input).expect("should return Some");
        let creds = result["credentials"]
            .as_array()
            .expect("credentials should be array");
        assert_eq!(creds.len(), 2);
        assert_eq!(result["total"], 2);

        assert_eq!(creds[0]["host"], "192.168.1.1");
        assert_eq!(creds[0]["port"], 22);
        assert_eq!(creds[0]["service"], "ssh");
        assert_eq!(creds[0]["login"], "admin");
        assert_eq!(creds[0]["password"], "password123");

        assert_eq!(creds[1]["host"], "192.168.1.1");
        assert_eq!(creds[1]["port"], 22);
        assert_eq!(creds[1]["service"], "ssh");
        assert_eq!(creds[1]["login"], "root");
        assert_eq!(creds[1]["password"], "toor");
    }

    #[test]
    fn parse_hydra_no_creds() {
        let input = r#"Hydra v9.4 (c) 2022 by van Hauser/THC & David Maciejak
Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2024-01-15 12:00:00
[DATA] max 16 tasks per 1 server, overall 16 tasks, 14344399 login tries
[DATA] attacking ssh://192.168.1.1:22/
1 of 1 target completed, 0 valid password found"#;
        let result = parse_hydra_output(input).expect("should return Some even with no creds");
        assert_eq!(result["total"], 0);
        let creds = result["credentials"].as_array().unwrap();
        assert!(creds.is_empty(), "should have no credentials");
    }

    #[test]
    fn parse_hydra_single_credential() {
        let input = r#"[21][ftp] host: 10.0.0.5   login: anonymous   password: guest@"#;
        let result = parse_hydra_output(input).expect("should return Some");
        let creds = result["credentials"].as_array().unwrap();
        assert_eq!(creds.len(), 1);
        assert_eq!(result["total"], 1);
        assert_eq!(creds[0]["host"], "10.0.0.5");
        assert_eq!(creds[0]["port"], 21);
        assert_eq!(creds[0]["service"], "ftp");
        assert_eq!(creds[0]["login"], "anonymous");
        assert_eq!(creds[0]["password"], "guest@");
    }

    #[test]
    fn parse_hydra_empty_output() {
        let result = parse_hydra_output("").expect("should return Some even for empty input");
        assert_eq!(result["total"], 0);
        let creds = result["credentials"].as_array().unwrap();
        assert!(creds.is_empty());
    }

    #[test]
    fn parse_hydra_mixed_lines_skips_non_matching() {
        let input = r#"Hydra v9.4 starting...
[DATA] attacking ssh://192.168.1.1:22/
[22][ssh] host: 192.168.1.1   login: admin   password: secret
[STATUS] 1000 tries done
1 of 1 target completed, 1 valid password found"#;
        let result = parse_hydra_output(input).expect("should return Some");
        let creds = result["credentials"].as_array().unwrap();
        assert_eq!(creds.len(), 1, "only one credential line should be parsed");
        assert_eq!(creds[0]["login"], "admin");
        assert_eq!(creds[0]["password"], "secret");
    }

    /// Requires hydra + passt + newuidmap. Run with: cargo test -p sigint-tools -- --ignored
    #[tokio::test]
    #[ignore]
    async fn hydra_executes_against_loopback() {
        let result = HydraTool::new()
            .execute(json!({
                "target": "127.0.0.1",
                "service": "ssh",
                "username": "test",
                "threads": 4
            }))
            .await
            .expect("hydra execution should not error");
        // hydra exits non-zero when no valid passwords found, which is expected
        // against loopback with no SSH server. The important thing is it ran.
        assert!(
            result.exit_code == 0 || !result.stderr.is_empty() || !result.stdout.is_empty(),
            "hydra should run or report an error: {:?}",
            result.stderr
        );
    }
}
