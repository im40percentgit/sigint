//! Enum4linuxTool — sandboxed enum4linux-ng wrapper for SMB/Samba enumeration.
//!
//! @decision DEC-P15-013
//! @title Enum4linuxTool uses SandboxProfile::bruteforce() — pasta networking, 300s
//! @status accepted
//! @rationale enum4linux-ng enumerates SMB shares, users, groups, and password
//! policy on Windows/Samba targets. It requires outbound network access (TCP 445,
//! 139, 135) so the offline profile is unsuitable. SandboxProfile::bruteforce()
//! (pasta networking, 300s) provides enough time for full SMB enumeration across
//! all checks while bounding the tool's wall-clock cost. Risk is Medium: the tool
//! performs authenticated or anonymous enumeration (no exploitation), but the
//! resulting user/share lists directly enable lateral movement and credential attacks.
//! `-oJ /dev/stdout` emits JSON to stdout for structured parsing, avoiding temp files
//! inside the sandbox. `-A` enables all enumeration checks by default.

use async_trait::async_trait;
use serde_json::{json, Value};
use sigint_llm::ToolDefinition;
use sigint_sandbox::profile::SandboxProfile;
use tracing::info;

use crate::error::{Result, ToolError};
use crate::result::{TruncationInfo, ToolResult};
use crate::tool::Tool;
use sigint_core::types::ToolRisk;

/// Default 1 MB output cap for enum4linux-ng.
const DEFAULT_ENUM4LINUX_OUTPUT_CAP: usize = 1_048_576;

/// Sandboxed enum4linux-ng tool wrapper.
///
/// Exposes enum4linux-ng as a `Tool` for the LLM agent layer. Enumerates SMB
/// shares, users, groups, and password policy on Windows/Samba targets using
/// JSON output mode for reliable structured parsing.
pub struct Enum4linuxTool {
    output_cap: usize,
}

impl Enum4linuxTool {
    /// Create a new Enum4linuxTool with the default output cap.
    pub fn new() -> Self {
        Self {
            output_cap: DEFAULT_ENUM4LINUX_OUTPUT_CAP,
        }
    }

    /// Set a custom output cap (builder pattern).
    pub fn with_output_cap(mut self, cap: usize) -> Self {
        self.output_cap = cap;
        self
    }
}

impl Default for Enum4linuxTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for Enum4linuxTool {
    fn name(&self) -> &str {
        "enum4linux_scan"
    }

    fn description(&self) -> &str {
        "Run enum4linux-ng to enumerate SMB shares, users, groups, and password \
         policy on Windows/Samba targets. Outputs structured JSON. \
         Uses anonymous access by default; provide username/password for \
         authenticated enumeration. The 'all' flag (default true) enables \
         all enumeration checks (-A)."
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
                        "description": "Target hostname or IP address to enumerate \
                                        (e.g. '192.168.1.10', 'dc01.corp.local')."
                    },
                    "username": {
                        "type": "string",
                        "description": "SMB username for authenticated enumeration. \
                                        Optional — omit for anonymous/null-session access."
                    },
                    "password": {
                        "type": "string",
                        "description": "SMB password for authenticated enumeration. \
                                        Optional — omit for anonymous/null-session access."
                    },
                    "all": {
                        "type": "boolean",
                        "description": "Enable all enumeration checks (-A flag). Defaults to true."
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

        // Extract optional credentials.
        let username = args["username"].as_str().map(|s| s.to_string());
        let password = args["password"].as_str().map(|s| s.to_string());

        // Default all-checks to true.
        let all_checks = args["all"].as_bool().unwrap_or(true);

        info!(
            target = %target,
            username = ?username,
            all_checks = all_checks,
            "executing enum4linux-ng scan"
        );

        let mut cmd = SandboxProfile::bruteforce().apply("enum4linux-ng");
        cmd = cmd.max_output(self.output_cap);

        // Target goes first.
        cmd = cmd.arg(&target);

        // JSON output to stdout.
        cmd = cmd.arg("-oJ").arg("/dev/stdout");

        // Authenticated credentials if provided.
        if let Some(ref user) = username {
            cmd = cmd.arg("-u").arg(user);
        }
        if let Some(ref pass) = password {
            cmd = cmd.arg("-p").arg(pass);
        }

        // All-checks flag.
        if all_checks {
            cmd = cmd.arg("-A");
        }

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

        let structured_data = parse_enum4linux_output(&output.stdout);

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

/// Parse enum4linux-ng JSON output into a structured SMB enumeration summary.
///
/// enum4linux-ng's `-oJ /dev/stdout` mode emits a JSON document with nested
/// keys for each enumeration category. This function extracts the fields most
/// useful for the LLM's next-step reasoning.
///
/// Expected JSON top-level shape from enum4linux-ng:
/// ```json
/// {
///   "target": {"host": "192.168.1.10", ...},
///   "smb": {"os_info": {"Operating System": "Windows 10"}, ...},
///   "shares": {"ADMIN$": {...}, "C$": {...}},
///   "users": {"Administrator": {...}, "Guest": {...}},
///   "groups": {"Administrators": {...}},
///   "password_policy": {"min_length": 0, ...}
/// }
/// ```
///
/// Output shape:
/// ```json
/// {
///   "os": "Windows 10",
///   "shares": ["ADMIN$", "C$", "IPC$"],
///   "users": ["Administrator", "Guest"],
///   "groups": ["Administrators", "Users"],
///   "total_shares": 3,
///   "total_users": 2
/// }
/// ```
///
/// Returns `None` for empty or non-JSON output. Gracefully handles partial
/// JSON (missing keys produce empty lists, not errors).
pub(crate) fn parse_enum4linux_output(stdout: &str) -> Option<Value> {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return None;
    }

    // enum4linux-ng may emit progress lines before the JSON block.
    // Find the first '{' to locate the JSON start.
    let json_start = trimmed.find('{')?;
    let json_str = &trimmed[json_start..];

    let parsed: Value = serde_json::from_str(json_str).ok()?;

    // Extract OS information from smb.os_info.
    let os = parsed["smb"]["os_info"]["Operating System"]
        .as_str()
        .or_else(|| parsed["smb"]["os_info"]["os"].as_str())
        .unwrap_or("")
        .to_string();

    // Extract share names from the "shares" object.
    let shares: Vec<String> = parsed["shares"]
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();

    // Extract user names from the "users" object.
    let users: Vec<String> = parsed["users"]
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();

    // Extract group names from the "groups" object.
    let groups: Vec<String> = parsed["groups"]
        .as_object()
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();

    let total_shares = shares.len() as u64;
    let total_users = users.len() as u64;

    Some(json!({
        "os": os,
        "shares": shares,
        "users": users,
        "groups": groups,
        "total_shares": total_shares,
        "total_users": total_users,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enum4linux_tool_name() {
        assert_eq!(Enum4linuxTool::new().name(), "enum4linux_scan");
    }

    #[test]
    fn enum4linux_definition_shape() {
        let def = Enum4linuxTool::new().definition();
        assert_eq!(def.type_, "function");
        assert_eq!(def.function.name, "enum4linux_scan");

        let params = &def.function.parameters;
        assert_eq!(params["type"], "object");

        // Only target is required.
        let required = params["required"].as_array().unwrap();
        assert_eq!(required.len(), 1, "only target should be required");
        assert!(
            required.iter().any(|v| v == "target"),
            "target should be required"
        );

        // Optional fields exist.
        assert!(params["properties"]["username"].is_object());
        assert!(params["properties"]["password"].is_object());
        assert!(params["properties"]["all"].is_object());
        // Optional fields are NOT in required.
        assert!(!required.iter().any(|v| v == "username"));
        assert!(!required.iter().any(|v| v == "password"));
        assert!(!required.iter().any(|v| v == "all"));
    }

    #[tokio::test]
    async fn enum4linux_missing_target_errors() {
        let err = Enum4linuxTool::new()
            .execute(json!({}))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("missing required argument"),
            "unexpected error: {err}"
        );
    }

    // --- parser unit tests ---

    #[test]
    fn parse_enum4linux_typical_json() {
        let input = r#"{
  "target": {"host": "192.168.1.10"},
  "smb": {
    "os_info": {"Operating System": "Windows 10 Enterprise", "Build": "19041"}
  },
  "shares": {
    "ADMIN$": {"access": "NO ACCESS"},
    "C$": {"access": "NO ACCESS"},
    "IPC$": {"access": "READ ONLY"},
    "Documents": {"access": "READ ONLY"}
  },
  "users": {
    "Administrator": {"rid": 500},
    "Guest": {"rid": 501},
    "jsmith": {"rid": 1001}
  },
  "groups": {
    "Administrators": {"rid": 544},
    "Users": {"rid": 545}
  }
}"#;
        let result = parse_enum4linux_output(input).expect("should parse");
        assert_eq!(result["os"], "Windows 10 Enterprise");
        assert_eq!(result["total_shares"], 4);
        assert_eq!(result["total_users"], 3);

        let shares = result["shares"].as_array().unwrap();
        assert_eq!(shares.len(), 4);

        let users = result["users"].as_array().unwrap();
        assert_eq!(users.len(), 3);

        let groups = result["groups"].as_array().unwrap();
        assert_eq!(groups.len(), 2);
    }

    #[test]
    fn parse_enum4linux_no_shares() {
        let input = r#"{
  "target": {"host": "192.168.1.10"},
  "smb": {"os_info": {}},
  "shares": {},
  "users": {"Administrator": {"rid": 500}},
  "groups": {}
}"#;
        let result = parse_enum4linux_output(input).expect("should parse");
        assert_eq!(result["total_shares"], 0);
        assert_eq!(result["total_users"], 1);
        let shares = result["shares"].as_array().unwrap();
        assert!(shares.is_empty());
    }

    #[test]
    fn parse_enum4linux_invalid_json_returns_none() {
        assert!(parse_enum4linux_output("not json at all").is_none());
        assert!(parse_enum4linux_output("").is_none());
        assert!(parse_enum4linux_output("   ").is_none());
    }

    #[test]
    fn parse_enum4linux_json_with_preamble() {
        // enum4linux-ng may emit progress lines before the JSON block.
        let input = "Starting enum4linux-ng v1.3.1...\nEnumerating target 192.168.1.10\n{\"target\":{\"host\":\"192.168.1.10\"},\"smb\":{\"os_info\":{}},\"shares\":{\"IPC$\":{}},\"users\":{},\"groups\":{}}";
        let result = parse_enum4linux_output(input).expect("should skip preamble and parse JSON");
        assert_eq!(result["total_shares"], 1);
    }

    /// Requires enum4linux-ng on PATH and a reachable SMB target.
    /// Run with: cargo test -p sigint-tools -- --ignored
    #[tokio::test]
    #[ignore]
    async fn enum4linux_integration_scan() {
        let result = Enum4linuxTool::new()
            .execute(json!({
                "target": "127.0.0.1",
                "all": true
            }))
            .await
            .expect("enum4linux-ng execution should not error");
        let _ = result.exit_code;
        // Structured data should have expected keys even on failure.
        if let Some(data) = result.structured_data {
            assert!(data["shares"].is_array());
            assert!(data["users"].is_array());
        }
    }
}
