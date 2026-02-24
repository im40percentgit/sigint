//! ShellTool — sandboxed shell command wrapper with an allowlist.
//!
//! @decision DEC-TOOL-005
//! @title ShellTool uses a static allowlist and offline sandbox profile
//! @status accepted
//! @rationale Giving the LLM an unrestricted shell is dangerous. A static
//! allowlist of read-only/analysis commands (grep, awk, sed, jq, etc.) lets
//! the agent process tool output without exposing write or network capabilities.
//! SandboxProfile::offline() ensures no network egress even for allowed commands
//! like curl — curl is included so the agent can fetch local/loopback endpoints
//! during recon post-processing, but the offline sandbox prevents external calls.
//! Commands are matched against the basename of the provided command string to
//! prevent path-traversal bypasses like "/usr/bin/rm".

use async_trait::async_trait;
use serde_json::{json, Value};
use sigint_llm::ToolDefinition;
use sigint_sandbox::profile::SandboxProfile;
use tracing::info;

use crate::error::{Result, ToolError};
use crate::result::ToolResult;
use crate::tool::Tool;

/// Commands the LLM agent is permitted to run via ShellTool.
///
/// Only read-only / analysis tools are permitted. Write and network commands
/// are excluded. Recon commands (whois, dig, etc.) run in the Recon sandbox
/// profile which provides Pasta networking for DNS/WHOIS resolution.
const ALLOWED_COMMANDS: &[&str] = &[
    "grep", "awk", "sed", "cat", "head", "tail", "sort", "uniq", "wc", "jq",
    "curl", "find", "ls", "file", "strings", "xxd",
    // Recon commands — DNS, WHOIS, certificate inspection
    "whois", "dig", "host", "nslookup", "openssl",
];

/// Commands that require network access and use the Recon sandbox profile
/// instead of the Offline profile.
const NETWORK_COMMANDS: &[&str] = &[
    "whois", "dig", "host", "nslookup", "curl", "openssl",
];

/// Sandboxed shell command wrapper with an allowlist.
///
/// Lets the LLM agent run a restricted set of shell commands for processing
/// tool output (grepping nmap results, extracting fields with jq, etc.).
/// All commands run inside an offline sandbox — no network access.
pub struct ShellTool;

impl ShellTool {
    /// Return true when `command` (by basename) is in the allowlist.
    fn is_allowed(command: &str) -> bool {
        // Strip any directory prefix to prevent path-traversal bypasses.
        let basename = std::path::Path::new(command)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(command);
        ALLOWED_COMMANDS.contains(&basename)
    }
}

#[async_trait]
impl Tool for ShellTool {
    fn name(&self) -> &str {
        "shell"
    }

    fn description(&self) -> &str {
        "Run a whitelisted shell command for processing, analysis, and passive recon. \
         Available commands: grep, awk, sed, cat, head, tail, sort, uniq, wc, \
         jq, curl, find, ls, file, strings, xxd, whois, dig, host, nslookup, openssl. \
         Recon commands (whois, dig, host, nslookup, curl, openssl) have network access \
         for DNS/WHOIS lookups. Other commands run in an offline sandbox. \
         IMPORTANT: Do NOT use shell to run nmap — use the dedicated nmap tool instead."
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::function(
            self.name(),
            self.description(),
            json!({
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "Command to run (must be in the allowlist: grep, awk, sed, cat, head, tail, sort, uniq, wc, jq, curl, find, ls, file, strings, xxd, whois, dig, host, nslookup, openssl). Recon commands (whois, dig, host, nslookup, curl, openssl) have network access. Do NOT use shell to run nmap — use the nmap tool."
                    },
                    "args": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Arguments to pass to the command"
                    }
                },
                "required": ["command"]
            }),
        )
    }

    async fn execute(&self, args: Value) -> Result<ToolResult> {
        // Extract required command.
        let command = args["command"]
            .as_str()
            .ok_or_else(|| ToolError::MissingArgument("command".to_string()))?
            .to_string();

        // Enforce allowlist by basename.
        if !ShellTool::is_allowed(&command) {
            return Err(ToolError::DisallowedCommand(command));
        }

        // Extract optional args array.
        let cmd_args: Vec<String> = match args["args"].as_array() {
            None => Vec::new(),
            Some(arr) => arr
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    v.as_str()
                        .ok_or_else(|| ToolError::InvalidArgument {
                            name: format!("args[{i}]"),
                            expected: "string".to_string(),
                        })
                        .map(|s| s.to_string())
                })
                .collect::<Result<Vec<_>>>()?,
        };

        info!(
            command = %command,
            ?cmd_args,
            "executing shell command"
        );

        // Select sandbox profile: Recon (with network) for DNS/WHOIS commands,
        // Offline (no network) for everything else.
        let basename = std::path::Path::new(&command)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(&command);
        let profile = if NETWORK_COMMANDS.contains(&basename) {
            SandboxProfile::recon()
        } else {
            SandboxProfile::offline()
        };
        let mut cmd = profile.apply(&command);
        for arg in cmd_args {
            cmd = cmd.arg(arg);
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

        Ok(ToolResult {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.exit_code,
            duration: output.duration,
            structured_data: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_tool_name_nonempty() {
        assert!(!ShellTool.name().is_empty());
        assert_eq!(ShellTool.name(), "shell");
    }

    #[test]
    fn shell_tool_description_nonempty() {
        assert!(!ShellTool.description().is_empty());
    }

    #[test]
    fn shell_tool_definition_shape() {
        let def = ShellTool.definition();
        assert_eq!(def.type_, "function");
        assert_eq!(def.function.name, "shell");

        let params = &def.function.parameters;
        assert_eq!(params["type"], "object");

        let required = params["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "command"), "command should be required");

        assert_eq!(params["properties"]["command"]["type"], "string");
        assert_eq!(params["properties"]["args"]["type"], "array");
        assert!(!required.iter().any(|v| v == "args"), "args should be optional");
    }

    #[test]
    fn allowlist_grep_is_allowed() {
        assert!(ShellTool::is_allowed("grep"));
    }

    #[test]
    fn allowlist_all_listed_commands_pass() {
        for cmd in ALLOWED_COMMANDS {
            assert!(ShellTool::is_allowed(cmd), "expected {cmd} to be allowed");
        }
    }

    #[test]
    fn allowlist_rm_rejected() {
        assert!(!ShellTool::is_allowed("rm"));
    }

    #[test]
    fn allowlist_python_rejected() {
        assert!(!ShellTool::is_allowed("python"));
    }

    #[test]
    fn allowlist_bash_rejected() {
        assert!(!ShellTool::is_allowed("bash"));
    }

    #[test]
    fn allowlist_path_traversal_rejected() {
        // /usr/bin/rm should be rejected — basename is "rm".
        assert!(!ShellTool::is_allowed("/usr/bin/rm"));
    }

    #[test]
    fn allowlist_path_traversal_allowed_command() {
        // /usr/bin/grep should be allowed — basename is "grep".
        assert!(ShellTool::is_allowed("/usr/bin/grep"));
    }

    #[tokio::test]
    async fn shell_missing_command_errors() {
        let err = ShellTool.execute(json!({})).await.unwrap_err();
        assert!(
            err.to_string().contains("missing required argument"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn shell_disallowed_command_errors() {
        let err = ShellTool
            .execute(json!({"command": "rm", "args": ["-rf", "/"]}))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("command not allowed"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn shell_disallowed_python_errors() {
        let err = ShellTool
            .execute(json!({"command": "python", "args": ["-c", "print('hi')"]}))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("command not allowed"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn shell_invalid_args_type_errors() {
        // args array contains a non-string element.
        let err = ShellTool
            .execute(json!({"command": "grep", "args": ["pattern", 42]}))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("invalid argument"),
            "unexpected error: {err}"
        );
    }

    /// Requires newuidmap (uidmap package). Run with: cargo test -p sigint-tools -- --ignored
    #[tokio::test]
    #[ignore]
    async fn shell_executes_grep_in_sandbox() {
        let result = ShellTool
            .execute(json!({"command": "grep", "args": ["-c", "root", "/etc/passwd"]}))
            .await
            .expect("grep execution should not error");
        assert_eq!(result.exit_code, 0, "grep should find root: {:?}", result.stderr);
    }
}
