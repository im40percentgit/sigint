//! TsharkTool — sandboxed tshark wrapper for network traffic capture and analysis.
//!
//! @decision DEC-P15-009
//! @title TsharkTool uses SandboxProfile::nmap() for raw network access; JSON output for structured analysis
//! @status accepted
//! @rationale tshark requires raw packet capture access (AF_PACKET or equivalent),
//! the same raw networking capability provided by SandboxProfile::nmap() (pasta
//! user-mode networking, 300s timeout). Live captures use `-a duration:<N>` for
//! bounded execution — the agent specifies a duration and tshark exits cleanly
//! after the window. The `-T json` flag produces structured packet data that
//! `parse_tshark_output()` reduces into a protocol/conversation summary for LLM
//! consumption. Optionally, tshark can read a pre-captured pcap file (`-r`) for
//! offline analysis without requiring network access at runtime.

use async_trait::async_trait;
use serde_json::{json, Value};
use sigint_llm::ToolDefinition;
use sigint_sandbox::profile::SandboxProfile;
use tracing::info;

use crate::error::{Result, ToolError};
use crate::result::{TruncationInfo, ToolResult};
use crate::tool::Tool;
use sigint_core::types::ToolRisk;

/// Default 1 MB output cap for tshark.
const DEFAULT_TSHARK_OUTPUT_CAP: usize = 1_048_576;

/// Sandboxed tshark tool wrapper.
///
/// Exposes tshark as a `Tool` for the LLM agent layer. Captures and analyses
/// network traffic either live from an interface or offline from a pcap file.
/// Network access is provided via pasta user-mode networking with a 300s timeout.
pub struct TsharkTool {
    output_cap: usize,
}

impl TsharkTool {
    /// Create a new TsharkTool with the default output cap.
    pub fn new() -> Self {
        Self {
            output_cap: DEFAULT_TSHARK_OUTPUT_CAP,
        }
    }

    /// Set a custom output cap (builder pattern).
    pub fn with_output_cap(mut self, cap: usize) -> Self {
        self.output_cap = cap;
        self
    }
}

impl Default for TsharkTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for TsharkTool {
    fn name(&self) -> &str {
        "tshark_capture"
    }

    fn description(&self) -> &str {
        "Run tshark to capture and analyze network traffic. Supports live capture \
         from a network interface or offline analysis of a pcap file. Returns a \
         structured summary of protocols, packet counts, and conversations. \
         Requires network access — runs inside a sandboxed environment with pasta \
         user-mode networking."
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
                    "interface": {
                        "type": "string",
                        "description": "Network interface to capture from (e.g. 'eth0', 'any'). \
                                        Ignored when read_file is provided. Defaults to 'any'."
                    },
                    "capture_filter": {
                        "type": "string",
                        "description": "BPF capture filter expression (e.g. 'port 80', 'host 192.168.1.1', \
                                        'tcp and port 443'). Only applied during live capture."
                    },
                    "duration": {
                        "type": "integer",
                        "description": "Duration in seconds for live capture. tshark exits after this \
                                        many seconds. Defaults to 30. Ignored when read_file is provided."
                    },
                    "read_file": {
                        "type": "string",
                        "description": "Path to a pcap or pcapng file to analyse offline. \
                                        When provided, interface/duration/capture_filter are ignored."
                    }
                },
                "required": []
            }),
        )
    }

    async fn execute(&self, args: Value) -> Result<ToolResult> {
        // Extract optional parameters with defaults.
        let interface = args["interface"]
            .as_str()
            .unwrap_or("any")
            .to_string();
        let capture_filter = args["capture_filter"].as_str().map(|s| s.to_string());
        let duration = args["duration"].as_i64().unwrap_or(30);
        let read_file = args["read_file"].as_str().map(|s| s.to_string());

        info!(
            interface = %interface,
            capture_filter = ?capture_filter,
            duration = duration,
            read_file = ?read_file,
            "executing tshark capture"
        );

        let mut cmd = SandboxProfile::nmap().apply("tshark");
        cmd = cmd.max_output(self.output_cap);

        if let Some(ref file) = read_file {
            // Offline analysis from pcap file.
            cmd = cmd.arg("-r").arg(file);
        } else {
            // Live capture from interface with bounded duration.
            cmd = cmd.arg("-i").arg(&interface);
            cmd = cmd.arg("-a").arg(format!("duration:{}", duration));
            if let Some(ref filter) = capture_filter {
                cmd = cmd.arg("-f").arg(filter);
            }
        }

        // Structured JSON output.
        cmd = cmd.arg("-T").arg("json");

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

        let structured_data = parse_tshark_output(&output.stdout);

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

/// Parse tshark `-T json` output into a structured traffic summary.
///
/// tshark JSON output is an array of packet objects. Each packet has deeply
/// nested layer data. This function extracts a high-level summary:
/// - protocol counts (from the highest-layer protocol per packet)
/// - unique conversations (src→dst pairs with packet counts)
/// - total packet count
///
/// Returns `None` if output is empty or cannot be parsed.
///
/// Output shape:
/// ```json
/// {
///   "packets": 3,
///   "protocols": {"TCP": 2, "HTTP": 1},
///   "conversations": [
///     {"src": "1.2.3.4", "dst": "5.6.7.8", "proto": "TCP", "packets": 2}
///   ],
///   "total_packets": 3
/// }
/// ```
pub fn parse_tshark_output(output: &str) -> Option<Value> {
    use std::collections::HashMap;

    let trimmed = output.trim();
    if trimmed.is_empty() {
        return None;
    }

    let parsed: Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(_) => return None,
    };

    let packets_arr = parsed.as_array()?;

    if packets_arr.is_empty() {
        return None;
    }

    let mut protocol_counts: HashMap<String, u64> = HashMap::new();
    // Keyed by (src, dst, proto) → packet count
    let mut conv_map: HashMap<(String, String, String), u64> = HashMap::new();

    for packet in packets_arr {
        // tshark JSON structure: packet → _source → layers → frame/ip/tcp/udp/etc.
        let layers = &packet["_source"]["layers"];

        // Determine source and destination IP.
        let src = layers["ip"]["ip.src"]
            .as_str()
            .or_else(|| layers["ipv6"]["ipv6.src"].as_str())
            .unwrap_or("")
            .to_string();
        let dst = layers["ip"]["ip.dst"]
            .as_str()
            .or_else(|| layers["ipv6"]["ipv6.dst"].as_str())
            .unwrap_or("")
            .to_string();

        // Determine highest-level protocol from frame.protocols field.
        // e.g. "eth:ethertype:ip:tcp:http" → last token is "http"
        let proto = layers["frame"]["frame.protocols"]
            .as_str()
            .and_then(|s| s.split(':').next_back())
            .unwrap_or("unknown")
            .to_uppercase();

        *protocol_counts.entry(proto.clone()).or_insert(0) += 1;

        if !src.is_empty() && !dst.is_empty() {
            *conv_map.entry((src, dst, proto)).or_insert(0) += 1;
        }
    }

    let total_packets = packets_arr.len() as u64;

    let protocols_json: Value = protocol_counts
        .into_iter()
        .map(|(k, v)| (k, json!(v)))
        .collect();

    let conversations: Vec<Value> = conv_map
        .into_iter()
        .map(|((src, dst, proto), count)| {
            json!({
                "src": src,
                "dst": dst,
                "proto": proto,
                "packets": count,
            })
        })
        .collect();

    Some(json!({
        "packets": total_packets,
        "protocols": protocols_json,
        "conversations": conversations,
        "total_packets": total_packets,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tshark_tool_name() {
        assert_eq!(TsharkTool::new().name(), "tshark_capture");
    }

    #[test]
    fn tshark_risk_is_high() {
        assert_eq!(TsharkTool::new().risk_level(), ToolRisk::High);
    }

    #[test]
    fn tshark_definition_shape() {
        let def = TsharkTool::new().definition();
        assert_eq!(def.type_, "function");
        assert_eq!(def.function.name, "tshark_capture");

        let params = &def.function.parameters;
        assert_eq!(params["type"], "object");

        // No required fields
        let required = params["required"].as_array().unwrap();
        assert!(required.is_empty(), "tshark should have no required args");

        // All properties exist
        assert!(params["properties"]["interface"].is_object());
        assert!(params["properties"]["capture_filter"].is_object());
        assert!(params["properties"]["duration"].is_object());
        assert!(params["properties"]["read_file"].is_object());
    }

    #[test]
    fn parse_tshark_typical_three_packets() {
        // Minimal tshark JSON structure with 3 packets
        let input = r#"[
            {"_source":{"layers":{"frame":{"frame.protocols":"eth:ethertype:ip:tcp"},"ip":{"ip.src":"192.168.1.1","ip.dst":"192.168.1.2"}}}},
            {"_source":{"layers":{"frame":{"frame.protocols":"eth:ethertype:ip:tcp:http"},"ip":{"ip.src":"192.168.1.1","ip.dst":"192.168.1.2"}}}},
            {"_source":{"layers":{"frame":{"frame.protocols":"eth:ethertype:ip:udp:dns"},"ip":{"ip.src":"192.168.1.1","ip.dst":"8.8.8.8"}}}}
        ]"#;

        let result = parse_tshark_output(input).expect("should parse");
        assert_eq!(result["total_packets"], 3);
        assert_eq!(result["packets"], 3);

        let protocols = &result["protocols"];
        assert!(protocols.is_object(), "protocols should be an object");

        let convs = result["conversations"].as_array().unwrap();
        assert!(!convs.is_empty(), "should have conversations");
    }

    #[test]
    fn parse_tshark_empty_output() {
        assert!(parse_tshark_output("").is_none());
        assert!(parse_tshark_output("   ").is_none());
    }

    #[test]
    fn parse_tshark_empty_array() {
        // Valid JSON but no packets
        assert!(parse_tshark_output("[]").is_none());
    }

    #[test]
    fn parse_tshark_summary_extraction() {
        let input = r#"[
            {"_source":{"layers":{"frame":{"frame.protocols":"eth:ethertype:ip:tcp:http"},"ip":{"ip.src":"10.0.0.1","ip.dst":"10.0.0.2"}}}},
            {"_source":{"layers":{"frame":{"frame.protocols":"eth:ethertype:ip:tcp:http"},"ip":{"ip.src":"10.0.0.1","ip.dst":"10.0.0.2"}}}},
            {"_source":{"layers":{"frame":{"frame.protocols":"eth:ethertype:ip:tcp"},"ip":{"ip.src":"10.0.0.3","ip.dst":"10.0.0.4"}}}},
            {"_source":{"layers":{"frame":{"frame.protocols":"eth:ethertype:ip:udp:dns"},"ip":{"ip.src":"10.0.0.1","ip.dst":"8.8.8.8"}}}}
        ]"#;

        let result = parse_tshark_output(input).expect("should parse");
        assert_eq!(result["total_packets"], 4);

        // HTTP appears 2 times, TCP 1 time, DNS 1 time
        assert_eq!(result["protocols"]["HTTP"], 2);
        assert_eq!(result["protocols"]["TCP"], 1);
        assert_eq!(result["protocols"]["DNS"], 1);

        // Conversations: 10.0.0.1→10.0.0.2 (HTTP, 2), 10.0.0.3→10.0.0.4 (TCP, 1), 10.0.0.1→8.8.8.8 (DNS, 1)
        let convs = result["conversations"].as_array().unwrap();
        assert_eq!(convs.len(), 3, "should have 3 distinct conversations");
    }

    /// Requires tshark + passt + newuidmap. Run with: cargo test -p sigint-tools -- --ignored
    #[tokio::test]
    #[ignore]
    async fn tshark_integration_any_interface() {
        let result = TsharkTool::new()
            .execute(json!({
                "interface": "lo",
                "duration": 2
            }))
            .await
            .expect("tshark execution should not error");
        assert_eq!(
            result.exit_code, 0,
            "tshark should exit 0: {:?}",
            result.stderr
        );
    }
}
