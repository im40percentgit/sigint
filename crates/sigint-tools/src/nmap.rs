//! NmapTool — sandboxed nmap wrapper with network access via pasta.
//!
//! @decision DEC-TOOL-004
//! @title NmapTool uses SandboxProfile::nmap() for pasta networking
//! @status accepted
//! @rationale nmap requires real network access to scan targets. SandboxProfile::Nmap
//! applies pasta user-mode networking (300s timeout) so nmap can reach the network
//! while remaining isolated from the host filesystem and process tree. The execute()
//! method is async and bridges to the synchronous SandboxedCommand::execute() via
//! tokio::task::spawn_blocking, matching the pattern documented in DEC-SAND-002.
//! The `-oN -` flag writes normal-format output to stdout, making it easy to
//! return raw scan results to the LLM as text without an XML parsing step.

use async_trait::async_trait;
use serde_json::{json, Value};
use sigint_llm::ToolDefinition;
use sigint_sandbox::profile::SandboxProfile;
use tracing::info;

use crate::error::{Result, ToolError};
use crate::result::ToolResult;
use crate::tool::Tool;

/// Scan type requested by the LLM agent.
#[derive(Debug, Clone, Copy, PartialEq)]
enum ScanType {
    /// `-T4 -F` — fast scan of top 100 ports.
    Quick,
    /// `-T4 -p-` — full scan of all 65535 ports.
    Full,
    /// `-sV --top-ports 1000` — service/version detection on top 1000 ports.
    Service,
}

impl ScanType {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "quick" => Some(ScanType::Quick),
            "full" => Some(ScanType::Full),
            "service" => Some(ScanType::Service),
            _ => None,
        }
    }

    /// nmap flags for this scan type.
    fn flags(&self) -> &'static [&'static str] {
        match self {
            ScanType::Quick => &["-T4", "-F"],
            ScanType::Full => &["-T4", "-p-"],
            ScanType::Service => &["-sV", "--top-ports", "1000"],
        }
    }
}

/// Sandboxed nmap tool wrapper.
///
/// Exposes nmap as a `Tool` for the LLM agent layer. Network access is
/// provided via pasta (user-mode networking) inside a Linux namespace sandbox.
pub struct NmapTool;

#[async_trait]
impl Tool for NmapTool {
    fn name(&self) -> &str {
        "nmap_scan"
    }

    fn description(&self) -> &str {
        "Run an nmap port scan against a target host or network range. \
         Returns scan output including open ports, services, and host state. \
         Requires network access — runs inside a sandboxed environment with \
         pasta user-mode networking."
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
                        "description": "Target host, IP address, or CIDR range to scan (e.g. '192.168.1.1', '10.0.0.0/24')"
                    },
                    "ports": {
                        "type": "string",
                        "description": "Port specification (e.g. '80,443', '1-1024', '80,443,8080-8090'). Omit to use scan_type defaults."
                    },
                    "scan_type": {
                        "type": "string",
                        "enum": ["quick", "full", "service"],
                        "description": "Scan preset: 'quick' (-T4 -F, top 100 ports), 'full' (-T4 -p-, all ports), 'service' (-sV --top-ports 1000, version detection). Defaults to 'quick'."
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

        // Extract optional ports.
        let ports = args["ports"].as_str().map(|s| s.to_string());

        // Extract optional scan_type, default to Quick.
        let scan_type = match args["scan_type"].as_str() {
            None => ScanType::Quick,
            Some(s) => ScanType::from_str(s).ok_or_else(|| ToolError::InvalidArgument {
                name: "scan_type".to_string(),
                expected: "one of: quick, full, service".to_string(),
            })?,
        };

        info!(
            target = %target,
            ?ports,
            ?scan_type,
            "executing nmap scan"
        );

        // Build the sandboxed command.
        let mut cmd = SandboxProfile::nmap().apply("nmap");

        // Apply scan-type flags.
        for flag in scan_type.flags() {
            cmd = cmd.arg(*flag);
        }

        // Apply port specification if provided (overrides scan_type port range).
        if let Some(ref p) = ports {
            cmd = cmd.arg("-p").arg(p);
        }

        // Write normal-format output to stdout for easy LLM consumption.
        cmd = cmd.arg("-oN").arg("-");

        // Append the target last.
        cmd = cmd.arg(&target);

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
    fn nmap_tool_name_nonempty() {
        assert!(!NmapTool.name().is_empty());
        assert_eq!(NmapTool.name(), "nmap_scan");
    }

    #[test]
    fn nmap_tool_description_nonempty() {
        assert!(!NmapTool.description().is_empty());
    }

    #[test]
    fn nmap_tool_definition_shape() {
        let def = NmapTool.definition();
        assert_eq!(def.type_, "function");
        assert_eq!(def.function.name, "nmap_scan");

        let params = &def.function.parameters;
        assert_eq!(params["type"], "object");

        // target is required
        let required = params["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "target"), "target should be required");

        // target property exists and is a string
        assert_eq!(params["properties"]["target"]["type"], "string");

        // ports property is optional (not in required array)
        assert!(params["properties"]["ports"].is_object());
        assert!(!required.iter().any(|v| v == "ports"), "ports should be optional");

        // scan_type has enum constraint
        let scan_type_enum = params["properties"]["scan_type"]["enum"].as_array().unwrap();
        assert!(scan_type_enum.iter().any(|v| v == "quick"));
        assert!(scan_type_enum.iter().any(|v| v == "full"));
        assert!(scan_type_enum.iter().any(|v| v == "service"));
    }

    #[tokio::test]
    async fn nmap_missing_target_errors() {
        let err = NmapTool.execute(json!({})).await.unwrap_err();
        assert!(
            err.to_string().contains("missing required argument"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn nmap_invalid_scan_type_errors() {
        let err = NmapTool
            .execute(json!({"target": "127.0.0.1", "scan_type": "stealth"}))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("invalid argument"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn scan_type_flags() {
        assert_eq!(ScanType::Quick.flags(), &["-T4", "-F"]);
        assert_eq!(ScanType::Full.flags(), &["-T4", "-p-"]);
        assert_eq!(ScanType::Service.flags(), &["-sV", "--top-ports", "1000"]);
    }

    #[test]
    fn scan_type_from_str() {
        assert_eq!(ScanType::from_str("quick"), Some(ScanType::Quick));
        assert_eq!(ScanType::from_str("full"), Some(ScanType::Full));
        assert_eq!(ScanType::from_str("service"), Some(ScanType::Service));
        assert_eq!(ScanType::from_str("stealth"), None);
        assert_eq!(ScanType::from_str(""), None);
    }

    /// Requires nmap + passt + newuidmap. Run with: cargo test -p sigint-tools -- --ignored
    #[tokio::test]
    #[ignore]
    async fn nmap_executes_loopback_quick_scan() {
        let result = NmapTool
            .execute(json!({"target": "127.0.0.1", "scan_type": "quick"}))
            .await
            .expect("nmap execution should not error");
        // nmap on loopback always exits 0 even with no open ports.
        assert_eq!(result.exit_code, 0, "nmap should exit 0: {:?}", result.stderr);
        assert!(
            result.stdout.contains("Nmap scan report"),
            "stdout should contain scan report: {}",
            result.stdout
        );
    }
}
