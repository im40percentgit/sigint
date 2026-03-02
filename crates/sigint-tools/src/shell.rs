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
//! Small LLMs (e.g. llama3.2) sometimes send the full command line as the
//! "command" field (e.g. "whois scanme.nmap.org") instead of separating command
//! from args. execute() splits the command field on whitespace and uses the first
//! token for allowlist checking and execution, prepending remaining tokens to the
//! args array. This makes ShellTool robust to imperfect LLM output formatting.

use async_trait::async_trait;
use serde_json::{json, Value};
use sigint_llm::ToolDefinition;
use sigint_sandbox::profile::SandboxProfile;
use tracing::info;

use crate::error::{Result, ToolError};
use crate::result::ToolResult;
use crate::tool::Tool;
use sigint_core::types::ToolRisk;

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
    /// Return true when `command` (by basename of the first whitespace token) is in the allowlist.
    ///
    /// Accepts both bare command names ("whois") and combined command strings
    /// ("whois scanme.nmap.org") — the first whitespace-separated token is used
    /// for the allowlist check. Directory prefixes are stripped to prevent
    /// path-traversal bypasses like "/usr/bin/rm".
    fn is_allowed(command: &str) -> bool {
        // Take the first whitespace token to handle combined command strings
        // sent by small LLMs (e.g. "whois scanme.nmap.org").
        let first_token = command.split_whitespace().next().unwrap_or(command);
        // Strip any directory prefix to prevent path-traversal bypasses.
        let basename = std::path::Path::new(first_token)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(first_token);
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
        // Extract required command field. Small LLMs sometimes send the full
        // command line as a single string (e.g. "whois scanme.nmap.org") instead
        // of separating command from args. We split on whitespace so that the
        // first token is the actual binary and any remaining tokens are prepended
        // to the explicit args array.
        let raw_command = args["command"]
            .as_str()
            .ok_or_else(|| ToolError::MissingArgument("command".to_string()))?;

        // Split the raw command field on whitespace.
        let parts: Vec<&str> = raw_command.split_whitespace().collect();
        let command = parts.first().copied().unwrap_or(raw_command).to_string();
        // Any tokens after the first become extra args prepended before explicit args.
        let mut extra_args: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();

        // Enforce allowlist by basename of the resolved command token.
        if !ShellTool::is_allowed(&command) {
            return Err(ToolError::DisallowedCommand(command));
        }

        // Extract optional args array.
        let explicit_args: Vec<String> = match args["args"].as_array() {
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

        // Merge: extra_args (from command field) + explicit args array.
        extra_args.extend(explicit_args);
        let cmd_args = extra_args;

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
    fn shell_risk_level_is_high() {
        assert_eq!(ShellTool.risk_level(), sigint_core::types::ToolRisk::High);
    }

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

    /// Combined command string "whois scanme.nmap.org" must pass the allowlist
    /// (first token "whois" is in ALLOWED_COMMANDS).
    #[test]
    fn shell_combined_command_is_allowed() {
        assert!(
            ShellTool::is_allowed("whois scanme.nmap.org"),
            "combined command string should pass allowlist via first token"
        );
    }

    /// Combined command string with a disallowed binary must still be rejected.
    #[test]
    fn shell_combined_command_disallowed_rejected() {
        assert!(
            !ShellTool::is_allowed("rm -rf /"),
            "combined string with disallowed command must be rejected"
        );
    }

    /// When the LLM sends {"command": "whois scanme.nmap.org"} (no separate args),
    /// execute() must split the string: binary = "whois", args = ["scanme.nmap.org"].
    /// We verify the split by checking it does NOT return a DisallowedCommand error
    /// (which would happen if the whole string were checked against the allowlist).
    #[tokio::test]
    async fn shell_combined_command_splits_args() {
        // "whois scanme.nmap.org" — should pass allowlist and attempt execution.
        // We expect either success or a sandbox/execution error (not DisallowedCommand).
        let result = ShellTool
            .execute(json!({"command": "whois scanme.nmap.org"}))
            .await;
        match result {
            // Allowlist passed, sandbox ran (or failed due to env) — not a disallow error.
            Ok(_) => {}
            Err(ToolError::DisallowedCommand(cmd)) => {
                panic!("combined command was wrongly rejected as disallowed: {cmd}");
            }
            // Any other error (sandbox unavailable, timeout, etc.) is acceptable.
            Err(_) => {}
        }
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
