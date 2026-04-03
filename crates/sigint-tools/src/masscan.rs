//! MasscanTool — sandboxed masscan wrapper for fast large-scale port scanning.
//!
//! @decision DEC-P15-008
//! @title MasscanTool uses SandboxProfile::nmap() for pasta networking
//! @status accepted
//! @rationale masscan performs raw-packet port scanning across large IP ranges
//! (entire /8 blocks, ISP address space, etc.) at multi-million-packets-per-second
//! rates. Like nmap, it requires raw network socket access — the same networking
//! capabilities provided by SandboxProfile::nmap() (pasta user-mode networking,
//! 300s timeout). JSON output (`-oJ -`) writes to stdout for machine-readable
//! parsing. Rate limiting via `--rate` prevents accidentally DOSing targets.
//! `parse_masscan_output()` converts masscan's JSON array into a normalised
//! host/port summary for LLM consumption.

use async_trait::async_trait;
use serde_json::{json, Value};
use sigint_llm::ToolDefinition;
use sigint_sandbox::profile::SandboxProfile;
use tracing::info;

use crate::error::{Result, ToolError};
use crate::result::{TruncationInfo, ToolResult};
use crate::tool::Tool;
use sigint_core::types::ToolRisk;

/// Default 1 MB output cap for masscan.
const DEFAULT_MASSCAN_OUTPUT_CAP: usize = 1_048_576;

/// Sandboxed masscan tool wrapper.
///
/// Exposes masscan as a `Tool` for the LLM agent layer. Performs fast
/// large-scale TCP/UDP port scanning across IP addresses and CIDR ranges.
/// Network access is provided via pasta user-mode networking with a 300s timeout.
pub struct MasscanTool {
    output_cap: usize,
}

impl MasscanTool {
    /// Create a new MasscanTool with the default output cap.
    pub fn new() -> Self {
        Self {
            output_cap: DEFAULT_MASSCAN_OUTPUT_CAP,
        }
    }

    /// Set a custom output cap (builder pattern).
    pub fn with_output_cap(mut self, cap: usize) -> Self {
        self.output_cap = cap;
        self
    }
}

impl Default for MasscanTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for MasscanTool {
    fn name(&self) -> &str {
        "masscan_scan"
    }

    fn description(&self) -> &str {
        "Run masscan for fast large-scale port scanning across IP ranges. \
         Scans entire CIDR blocks at configurable rates. Returns open ports \
         grouped by host. Requires network access — runs inside a sandboxed \
         environment with pasta user-mode networking."
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
                        "description": "Target IP address or CIDR range to scan (e.g. '192.168.1.0/24', '10.0.0.1')."
                    },
                    "ports": {
                        "type": "string",
                        "description": "Port range to scan (e.g. '80,443', '1-1024', '1-65535'). Defaults to '1-65535'."
                    },
                    "rate": {
                        "type": "integer",
                        "description": "Packets per second transmission rate. Higher values are faster but may drop packets or trigger rate limiting. Defaults to 1000."
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

        // Extract optional ports with default.
        let ports = args["ports"]
            .as_str()
            .unwrap_or("1-65535")
            .to_string();

        // Extract optional rate with default; validate.
        let rate = args["rate"].as_i64().unwrap_or(1000);
        if rate <= 0 {
            return Err(ToolError::InvalidArgument {
                name: "rate".to_string(),
                expected: "a positive integer (packets per second)".to_string(),
            });
        }

        info!(
            target = %target,
            ports = %ports,
            rate = rate,
            "executing masscan scan"
        );

        let mut cmd = SandboxProfile::nmap().apply("masscan");
        cmd = cmd.max_output(self.output_cap);
        cmd = cmd.arg(&target);
        cmd = cmd.arg(format!("-p{}", ports));
        cmd = cmd.arg(format!("--rate={}", rate));
        // JSON output to stdout.
        cmd = cmd.arg("-oJ");
        cmd = cmd.arg("-");

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

        let structured_data = parse_masscan_output(&output.stdout);

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

/// Parse masscan JSON output into a structured host/port summary.
///
/// masscan `-oJ -` emits a JSON array of objects, each with an IP and its
/// open ports. This function normalises the data into a summary suitable for
/// LLM consumption (hosts list, total counts). Invalid or unexpected JSON is
/// silently skipped at the object level.
///
/// Expected masscan JSON shape:
/// ```json
/// [{"ip":"1.2.3.4","ports":[{"port":80,"proto":"tcp","status":"open","service":{"name":"http"}}]}]
/// ```
///
/// Output shape:
/// ```json
/// {
///   "hosts": [
///     {"ip": "1.2.3.4", "ports": [{"port": 80, "proto": "tcp", "status": "open", "service": "http"}]}
///   ],
///   "total_hosts": 1,
///   "total_ports": 1
/// }
/// ```
pub fn parse_masscan_output(output: &str) -> Option<Value> {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return None;
    }

    // masscan JSON output is a JSON array.
    let parsed: Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(_) => return None,
    };

    let entries = parsed.as_array()?;

    let mut hosts: Vec<Value> = Vec::new();
    let mut total_ports: u64 = 0;

    for entry in entries {
        let ip = match entry["ip"].as_str() {
            Some(s) => s.to_string(),
            None => continue,
        };

        let ports_arr = match entry["ports"].as_array() {
            Some(arr) => arr,
            None => continue,
        };

        let mut ports: Vec<Value> = Vec::new();
        for port_obj in ports_arr {
            let port_num = match port_obj["port"].as_u64() {
                Some(p) => p,
                None => continue,
            };
            let proto = port_obj["proto"].as_str().unwrap_or("tcp").to_string();
            let status = port_obj["status"].as_str().unwrap_or("open").to_string();
            // service name may be nested under "service": {"name": "..."}
            let service = port_obj["service"]["name"]
                .as_str()
                .unwrap_or("")
                .to_string();

            ports.push(json!({
                "port": port_num,
                "proto": proto,
                "status": status,
                "service": service,
            }));
            total_ports += 1;
        }

        hosts.push(json!({
            "ip": ip,
            "ports": ports,
        }));
    }

    if hosts.is_empty() {
        return None;
    }

    let total_hosts = hosts.len() as u64;
    Some(json!({
        "hosts": hosts,
        "total_hosts": total_hosts,
        "total_ports": total_ports,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masscan_tool_name() {
        assert_eq!(MasscanTool::new().name(), "masscan_scan");
    }

    #[test]
    fn masscan_definition_shape() {
        let def = MasscanTool::new().definition();
        assert_eq!(def.type_, "function");
        assert_eq!(def.function.name, "masscan_scan");

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

        // ports and rate are optional
        assert!(params["properties"]["ports"].is_object());
        assert!(params["properties"]["rate"].is_object());
        assert!(
            !required.iter().any(|v| v == "ports"),
            "ports should be optional"
        );
        assert!(
            !required.iter().any(|v| v == "rate"),
            "rate should be optional"
        );
    }

    #[tokio::test]
    async fn masscan_missing_target_errors() {
        let err = MasscanTool::new().execute(json!({})).await.unwrap_err();
        assert!(
            err.to_string().contains("missing required argument"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn masscan_rate_zero_errors() {
        let err = MasscanTool::new()
            .execute(json!({"target": "192.168.1.0/24", "rate": 0}))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("invalid argument"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn masscan_rate_negative_errors() {
        let err = MasscanTool::new()
            .execute(json!({"target": "192.168.1.0/24", "rate": -100}))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("invalid argument"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_masscan_typical_two_hosts() {
        let input = r#"[
            {"ip":"192.168.1.1","ports":[{"port":80,"proto":"tcp","status":"open","service":{"name":"http"}},{"port":443,"proto":"tcp","status":"open","service":{"name":"https"}}]},
            {"ip":"192.168.1.2","ports":[{"port":22,"proto":"tcp","status":"open","service":{"name":"ssh"}}]}
        ]"#;

        let result = parse_masscan_output(input).expect("should parse");
        let hosts = result["hosts"].as_array().unwrap();
        assert_eq!(hosts.len(), 2, "should have 2 hosts");
        assert_eq!(result["total_hosts"], 2);
        assert_eq!(result["total_ports"], 3);

        // Check first host
        assert_eq!(hosts[0]["ip"], "192.168.1.1");
        let ports = hosts[0]["ports"].as_array().unwrap();
        assert_eq!(ports.len(), 2);
        assert_eq!(ports[0]["port"], 80);
        assert_eq!(ports[0]["proto"], "tcp");
        assert_eq!(ports[0]["status"], "open");
        assert_eq!(ports[0]["service"], "http");

        // Check second host
        assert_eq!(hosts[1]["ip"], "192.168.1.2");
        let ports2 = hosts[1]["ports"].as_array().unwrap();
        assert_eq!(ports2.len(), 1);
        assert_eq!(ports2[0]["port"], 22);
        assert_eq!(ports2[0]["service"], "ssh");
    }

    #[test]
    fn parse_masscan_empty_output() {
        assert!(parse_masscan_output("").is_none());
        assert!(parse_masscan_output("   ").is_none());
    }

    #[test]
    fn parse_masscan_invalid_json() {
        assert!(parse_masscan_output("not json at all").is_none());
        assert!(parse_masscan_output("{broken:").is_none());
    }

    #[test]
    fn parse_masscan_empty_array() {
        // Valid JSON but no hosts — returns None
        assert!(parse_masscan_output("[]").is_none());
    }

    /// Requires masscan + passt + newuidmap. Run with: cargo test -p sigint-tools -- --ignored
    #[tokio::test]
    #[ignore]
    async fn masscan_integration_loopback() {
        let result = MasscanTool::new()
            .execute(json!({
                "target": "127.0.0.1",
                "ports": "80,443",
                "rate": 100
            }))
            .await
            .expect("masscan execution should not error");
        assert_eq!(
            result.exit_code, 0,
            "masscan should exit 0: {:?}",
            result.stderr
        );
    }
}
