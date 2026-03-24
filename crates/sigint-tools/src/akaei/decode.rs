//! AkaeiDecodeTool — RF protocol decoder wrapper.
//!
//! @decision DEC-AKAEI-002
//! @title decode emits JSON-lines; parser collects into messages array
//! @status accepted
//! @rationale akaei decode --json writes one JSON object per decoded message to
//! stdout. parse_decode_output() collects valid JSON lines into a messages array
//! and returns {protocol, messages, message_count}. Malformed lines are silently
//! skipped so partial output is still usable.

use async_trait::async_trait;
use serde_json::{json, Value};
use sigint_core::types::ToolRisk;
use sigint_llm::ToolDefinition;

use crate::error::{Result, ToolError};
use crate::result::ToolResult;
use crate::tool::Tool;

use super::run_akaei;

/// Parse JSON-lines output from `akaei decode --json`.
///
/// Each line should be a valid JSON object representing one decoded message.
/// Invalid lines are silently skipped. Returns `{protocol, messages, message_count}`.
fn parse_decode_output(output: &str, protocol: &str) -> Value {
    let messages: Vec<Value> = output
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            serde_json::from_str::<Value>(line).ok()
        })
        .collect();
    let count = messages.len();
    json!({
        "protocol": protocol,
        "messages": messages,
        "message_count": count,
    })
}

/// RF protocol decoder tool.
///
/// Decodes RF signals using akaei's 40+ protocol decoders.
/// Can decode from a capture file (offline) or live from HackRF.
pub struct AkaeiDecodeTool;

#[async_trait]
impl Tool for AkaeiDecodeTool {
    fn name(&self) -> &str {
        "akaei_decode"
    }

    fn description(&self) -> &str {
        "Decode RF signals using akaei's protocol decoders. Supports 40+ protocols \
         including OOK, FSK, LoRa, Zigbee, Z-Wave, BLE, and more. Can decode from \
         a capture file or live from HackRF hardware."
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::function(
            self.name(),
            self.description(),
            json!({
                "type": "object",
                "properties": {
                    "protocol": {
                        "type": "string",
                        "description": "Protocol to decode (e.g. 'ook', 'fsk', 'lora', 'zigbee', 'zwave', 'ble')."
                    },
                    "input_file": {
                        "type": "string",
                        "description": "Path to IQ capture file to decode offline. If omitted, decodes live from HackRF."
                    },
                    "frequency": {
                        "type": "string",
                        "description": "Center frequency in Hz for live decode (e.g. '433.92e6')."
                    },
                    "sample_rate": {
                        "type": "string",
                        "description": "Sample rate in Hz (e.g. '2e6'). Optional."
                    },
                    "duration_secs": {
                        "type": "integer",
                        "description": "Live capture duration in seconds (default 30). Ignored for file decode."
                    }
                },
                "required": ["protocol"]
            }),
        )
    }

    fn risk_level(&self) -> ToolRisk {
        ToolRisk::Medium
    }

    async fn execute(&self, args: Value) -> Result<ToolResult> {
        let protocol = args["protocol"]
            .as_str()
            .ok_or_else(|| ToolError::MissingArgument("protocol".to_string()))?;

        let duration = args["duration_secs"].as_u64().unwrap_or(30);
        let timeout_secs = duration + 10;

        let mut cmd_args: Vec<String> = vec![protocol.to_string()];

        if let Some(file) = args["input_file"].as_str() {
            cmd_args.push("-i".to_string());
            cmd_args.push(file.to_string());
        }
        if let Some(freq) = args["frequency"].as_str() {
            cmd_args.push("-f".to_string());
            cmd_args.push(freq.to_string());
        }
        if let Some(rate) = args["sample_rate"].as_str() {
            cmd_args.push("-s".to_string());
            cmd_args.push(rate.to_string());
        }
        cmd_args.push("--json".to_string());

        let str_args: Vec<&str> = cmd_args.iter().map(String::as_str).collect();
        let mut result = run_akaei("decode", &str_args, timeout_secs).await?;
        result.structured_data = Some(parse_decode_output(&result.stdout, protocol));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn decode_tool_name() {
        assert_eq!(AkaeiDecodeTool.name(), "akaei_decode");
    }

    #[test]
    fn decode_definition_required_fields() {
        let def = AkaeiDecodeTool.definition();
        let required = def.function.parameters["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "protocol"));
    }

    #[test]
    fn decode_risk_is_medium() {
        assert_eq!(AkaeiDecodeTool.risk_level(), ToolRisk::Medium);
    }

    #[tokio::test]
    async fn decode_missing_protocol_errors() {
        let err = AkaeiDecodeTool.execute(json!({})).await.unwrap_err();
        assert!(err.to_string().contains("missing required argument"));
    }

    #[test]
    fn parse_decode_valid_jsonlines() {
        let output = r#"{"id":"0x42","value":21.5,"battery":true}
{"id":"0x43","value":22.1,"battery":false}
"#;
        let parsed = parse_decode_output(output, "ook");
        assert_eq!(parsed["protocol"], "ook");
        let msgs = parsed["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0]["id"], "0x42");
        assert_eq!(parsed["message_count"], 2);
    }

    #[test]
    fn parse_decode_skips_invalid_lines() {
        let output = "not json at all\n{\"valid\":true}\nalso not json\n";
        let parsed = parse_decode_output(output, "fsk");
        let msgs = parsed["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(parsed["message_count"], 1);
    }

    #[test]
    fn parse_decode_empty_output() {
        let parsed = parse_decode_output("", "ble");
        assert_eq!(parsed["message_count"], 0);
        assert_eq!(parsed["messages"].as_array().unwrap().len(), 0);
    }
}
