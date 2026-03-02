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

use async_trait::async_trait;
use serde_json::{json, Value};
use sigint_llm::ToolDefinition;
use sigint_sandbox::profile::SandboxProfile;
use tracing::info;

use crate::error::{Result, ToolError};
use crate::result::ToolResult;
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
        assert!(required.iter().any(|v| v == "target"), "target should be required");

        // target property exists and is a string
        assert_eq!(params["properties"]["target"]["type"], "string");

        // mode has enum constraint
        let mode_enum = params["properties"]["mode"]["enum"].as_array().unwrap();
        assert!(mode_enum.iter().any(|v| v == "dir"));
        assert!(mode_enum.iter().any(|v| v == "vhost"));
        assert!(mode_enum.iter().any(|v| v == "dns"));

        // wordlist is optional (not in required array)
        assert!(params["properties"]["wordlist"].is_object());
        assert!(!required.iter().any(|v| v == "wordlist"), "wordlist should be optional");
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
        assert_eq!(result.exit_code, 0, "gobuster should exit 0: {:?}", result.stderr);
    }
}
