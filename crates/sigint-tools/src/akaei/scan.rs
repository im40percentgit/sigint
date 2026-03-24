//! AkaeiScanTool — RF signal scanner wrapper.
//!
//! @decision DEC-AKAEI-001
//! @title akaei scan uses tokio::process::Command directly — no sandbox
//! @status accepted
//! @rationale HackRF USB access requires the real UID/GID; Linux user namespaces
//! break libusb permission checks. See mod.rs for full rationale.

use async_trait::async_trait;
use serde_json::{json, Value};
use sigint_core::types::ToolRisk;
use sigint_llm::ToolDefinition;

use crate::error::{Result, ToolError};
use crate::result::ToolResult;
use crate::tool::Tool;

use super::run_akaei;

/// Parse `akaei scan` text output into structured detections.
///
/// Each line: `<freq_hz> <power_db> <snr_db> <bw_hz>`
fn parse_scan_output(output: &str) -> Value {
    let detections: Vec<Value> = output
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let mut parts = line.split_whitespace();
            let freq: f64 = parts.next()?.parse().ok()?;
            let power: f64 = parts.next()?.parse().ok()?;
            let snr: f64 = parts.next()?.parse().ok()?;
            let bw: f64 = parts.next()?.parse().ok()?;
            Some(json!({
                "freq_hz": freq,
                "power_db": power,
                "snr_db": snr,
                "bw_hz": bw,
            }))
        })
        .collect();
    json!({ "detections": detections, "count": detections.len() })
}

/// RF signal scanner tool.
///
/// Scans a frequency range for active signals above a threshold.
/// Requires HackRF hardware.
pub struct AkaeiScanTool;

#[async_trait]
impl Tool for AkaeiScanTool {
    fn name(&self) -> &str {
        "akaei_scan"
    }

    fn description(&self) -> &str {
        "Scan an RF frequency range for active signals using HackRF. \
         Reports detections above the threshold with frequency, power, SNR, and bandwidth. \
         Requires HackRF hardware."
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::function(
            self.name(),
            self.description(),
            json!({
                "type": "object",
                "properties": {
                    "start_freq": {
                        "type": "string",
                        "description": "Start frequency in Hz (e.g. '400e6')."
                    },
                    "stop_freq": {
                        "type": "string",
                        "description": "Stop frequency in Hz (e.g. '500e6')."
                    },
                    "threshold_db": {
                        "type": "number",
                        "description": "Signal detection threshold in dBm (e.g. -60). Optional."
                    },
                    "dwell_ms": {
                        "type": "integer",
                        "description": "Dwell time per step in milliseconds. Optional."
                    },
                    "lna_gain": {
                        "type": "integer",
                        "description": "LNA gain 0-40 dB. Optional."
                    },
                    "vga_gain": {
                        "type": "integer",
                        "description": "VGA gain 0-62 dB. Optional."
                    }
                },
                "required": ["start_freq", "stop_freq"]
            }),
        )
    }

    fn risk_level(&self) -> ToolRisk {
        ToolRisk::Medium
    }

    async fn execute(&self, args: Value) -> Result<ToolResult> {
        let start = args["start_freq"]
            .as_str()
            .ok_or_else(|| ToolError::MissingArgument("start_freq".to_string()))?;
        let stop = args["stop_freq"]
            .as_str()
            .ok_or_else(|| ToolError::MissingArgument("stop_freq".to_string()))?;

        let freq_range = format!("{}:{}", start, stop);
        let mut cmd_args: Vec<String> = vec!["-f".to_string(), freq_range];

        if let Some(thr) = args["threshold_db"].as_f64() {
            cmd_args.push("-t".to_string());
            cmd_args.push(thr.to_string());
        }
        if let Some(dwell) = args["dwell_ms"].as_i64() {
            cmd_args.push("-d".to_string());
            cmd_args.push(dwell.to_string());
        }
        if let Some(lna) = args["lna_gain"].as_i64() {
            cmd_args.push("-l".to_string());
            cmd_args.push(lna.to_string());
        }
        if let Some(vga) = args["vga_gain"].as_i64() {
            cmd_args.push("-g".to_string());
            cmd_args.push(vga.to_string());
        }

        let str_args: Vec<&str> = cmd_args.iter().map(String::as_str).collect();
        let mut result = run_akaei("scan", &str_args, 300).await?;
        result.structured_data = Some(parse_scan_output(&result.stdout));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn scan_tool_name() {
        assert_eq!(AkaeiScanTool.name(), "akaei_scan");
    }

    #[test]
    fn scan_definition_required_fields() {
        let def = AkaeiScanTool.definition();
        let required = def.function.parameters["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "start_freq"));
        assert!(required.iter().any(|v| v == "stop_freq"));
    }

    #[test]
    fn scan_risk_is_medium() {
        assert_eq!(AkaeiScanTool.risk_level(), ToolRisk::Medium);
    }

    #[tokio::test]
    async fn scan_missing_start_freq_errors() {
        let err = AkaeiScanTool
            .execute(json!({"stop_freq": "500e6"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("missing required argument"));
    }

    #[tokio::test]
    async fn scan_missing_stop_freq_errors() {
        let err = AkaeiScanTool
            .execute(json!({"start_freq": "400e6"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("missing required argument"));
    }

    #[test]
    fn parse_scan_valid_output() {
        let output = "433920000 -45.2 12.5 200000\n915000000 -38.7 18.3 400000\n";
        let parsed = parse_scan_output(output);
        let dets = parsed["detections"].as_array().unwrap();
        assert_eq!(dets.len(), 2);
        assert!((dets[0]["freq_hz"].as_f64().unwrap() - 433_920_000.0).abs() < 1.0);
        assert!((dets[0]["snr_db"].as_f64().unwrap() - 12.5).abs() < 0.01);
        assert_eq!(parsed["count"], 2);
    }

    #[test]
    fn parse_scan_empty_output() {
        let parsed = parse_scan_output("");
        assert_eq!(parsed["detections"].as_array().unwrap().len(), 0);
        assert_eq!(parsed["count"], 0);
    }

    #[test]
    fn parse_scan_skips_comments() {
        let output = "# header\n433920000 -45.2 12.5 200000\n";
        let parsed = parse_scan_output(output);
        assert_eq!(parsed["detections"].as_array().unwrap().len(), 1);
    }
}
