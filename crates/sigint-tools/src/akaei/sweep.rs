//! AkaeiSweepTool — RF spectrum sweep wrapper.
//!
//! @decision DEC-AKAEI-001
//! @title akaei sweep uses tokio::process::Command directly — no sandbox
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

/// Parse `akaei sweep` text output into a JSON array of `{freq_hz, power_db}`.
///
/// Each output line has the form: `<freq_hz> <power_dB>`
fn parse_sweep_output(output: &str) -> Value {
    let bins: Vec<Value> = output
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let mut parts = line.split_whitespace();
            let freq: f64 = parts.next()?.parse().ok()?;
            let power: f64 = parts.next()?.parse().ok()?;
            Some(json!({ "freq_hz": freq, "power_db": power }))
        })
        .collect();
    json!(bins)
}

/// RF spectrum sweep tool.
///
/// Sweeps a frequency range using HackRF and reports power levels per bin.
/// Requires HackRF hardware connected via USB.
pub struct AkaeiSweepTool;

#[async_trait]
impl Tool for AkaeiSweepTool {
    fn name(&self) -> &str {
        "akaei_sweep"
    }

    fn description(&self) -> &str {
        "Sweep an RF frequency range using HackRF and return power levels per bin. \
         Requires HackRF hardware. Output: array of {freq_hz, power_db} bins."
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
                        "description": "Start frequency in Hz (e.g. '433e6', '433000000')."
                    },
                    "stop_freq": {
                        "type": "string",
                        "description": "Stop frequency in Hz (e.g. '434e6', '434000000')."
                    },
                    "bin_width": {
                        "type": "string",
                        "description": "Bin width in Hz (e.g. '1000000'). Optional."
                    },
                    "lna_gain": {
                        "type": "integer",
                        "description": "LNA gain 0-40 dB in steps of 8. Optional."
                    },
                    "vga_gain": {
                        "type": "integer",
                        "description": "VGA gain 0-62 dB in steps of 2. Optional."
                    },
                    "one_shot": {
                        "type": "boolean",
                        "description": "Exit after one sweep pass (default true)."
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

        if let Some(bw) = args["bin_width"].as_str() {
            cmd_args.push("-w".to_string());
            cmd_args.push(bw.to_string());
        }
        if let Some(lna) = args["lna_gain"].as_i64() {
            cmd_args.push("-l".to_string());
            cmd_args.push(lna.to_string());
        }
        if let Some(vga) = args["vga_gain"].as_i64() {
            cmd_args.push("-g".to_string());
            cmd_args.push(vga.to_string());
        }
        // Default to one-shot mode unless explicitly disabled.
        let one_shot = args["one_shot"].as_bool().unwrap_or(true);
        if one_shot {
            cmd_args.push("-1".to_string());
        }

        let str_args: Vec<&str> = cmd_args.iter().map(String::as_str).collect();
        let mut result = run_akaei("sweep", &str_args, 120).await?;
        result.structured_data = Some(parse_sweep_output(&result.stdout));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sweep_tool_name() {
        assert_eq!(AkaeiSweepTool.name(), "akaei_sweep");
    }

    #[test]
    fn sweep_definition_shape() {
        let def = AkaeiSweepTool.definition();
        assert_eq!(def.function.name, "akaei_sweep");
        let params = &def.function.parameters;
        let required = params["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "start_freq"));
        assert!(required.iter().any(|v| v == "stop_freq"));
    }

    #[test]
    fn sweep_risk_is_medium() {
        assert_eq!(AkaeiSweepTool.risk_level(), ToolRisk::Medium);
    }

    #[tokio::test]
    async fn sweep_missing_start_freq_errors() {
        let err = AkaeiSweepTool
            .execute(json!({"stop_freq": "434e6"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("missing required argument"));
    }

    #[tokio::test]
    async fn sweep_missing_stop_freq_errors() {
        let err = AkaeiSweepTool
            .execute(json!({"start_freq": "433e6"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("missing required argument"));
    }

    #[test]
    fn parse_sweep_valid_lines() {
        let output = "433920000 -45.2\n434000000 -60.1\n434080000 -55.7\n";
        let parsed = parse_sweep_output(output);
        let arr = parsed.as_array().unwrap();
        assert_eq!(arr.len(), 3);
        assert!((arr[0]["freq_hz"].as_f64().unwrap() - 433_920_000.0).abs() < 1.0);
        assert!((arr[0]["power_db"].as_f64().unwrap() - (-45.2)).abs() < 0.01);
    }

    #[test]
    fn parse_sweep_skips_empty_and_comments() {
        let output = "# comment\n\n433920000 -45.2\n";
        let arr = parse_sweep_output(output).as_array().unwrap().clone();
        assert_eq!(arr.len(), 1);
    }

    #[test]
    fn parse_sweep_empty_output() {
        let parsed = parse_sweep_output("");
        assert_eq!(parsed.as_array().unwrap().len(), 0);
    }
}
