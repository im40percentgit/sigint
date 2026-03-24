//! AkaeiAnalyzeTool — IQ capture file signal analysis wrapper.
//!
//! @decision DEC-AKAEI-002
//! @title analyze emits human-readable text; structured_data is the raw text wrapped in JSON
//! @status accepted
//! @rationale akaei analyze has no --json mode; its output is human-readable text
//! (signal summary, pulse stats, frequency peaks, classification labels).
//! structured_data wraps the full stdout text so the agent layer can inspect it
//! programmatically while raw stdout remains available for LLM consumption.

use async_trait::async_trait;
use serde_json::{json, Value};
use sigint_core::types::ToolRisk;
use sigint_llm::ToolDefinition;

use crate::error::{Result, ToolError};
use crate::result::ToolResult;
use crate::tool::Tool;

use super::run_akaei;

/// Wrap analyze text output in a structured envelope.
///
/// Since akaei analyze has no JSON mode, we preserve the full text as
/// `{"analysis": "<stdout>"}` so the agent layer has a consistent shape.
fn wrap_analyze_output(output: &str) -> Value {
    json!({ "analysis": output })
}

/// IQ capture file signal analysis tool.
///
/// Performs offline signal analysis on an IQ capture file.
/// No HackRF hardware required — analysis runs entirely on the file.
pub struct AkaeiAnalyzeTool;

#[async_trait]
impl Tool for AkaeiAnalyzeTool {
    fn name(&self) -> &str {
        "akaei_analyze"
    }

    fn description(&self) -> &str {
        "Analyse an IQ capture file for signals, pulse statistics, frequency peaks, \
         and protocol classification. Runs offline — no HackRF hardware required."
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::function(
            self.name(),
            self.description(),
            json!({
                "type": "object",
                "properties": {
                    "file": {
                        "type": "string",
                        "description": "Path to the IQ capture file to analyze."
                    },
                    "detect_signals": {
                        "type": "boolean",
                        "description": "Detect and list signals present in the capture."
                    },
                    "pulse_stats": {
                        "type": "boolean",
                        "description": "Compute pulse timing statistics."
                    },
                    "freq_peaks": {
                        "type": "boolean",
                        "description": "Identify dominant frequency peaks."
                    },
                    "classify": {
                        "type": "boolean",
                        "description": "Classify signals using built-in heuristics."
                    },
                    "frequency": {
                        "type": "string",
                        "description": "Center frequency in Hz used during capture (for context). Optional."
                    },
                    "sample_rate": {
                        "type": "string",
                        "description": "Sample rate in Hz used during capture (for context). Optional."
                    }
                },
                "required": ["file"]
            }),
        )
    }

    fn risk_level(&self) -> ToolRisk {
        ToolRisk::Low
    }

    async fn execute(&self, args: Value) -> Result<ToolResult> {
        let file = args["file"]
            .as_str()
            .ok_or_else(|| ToolError::MissingArgument("file".to_string()))?;

        let mut cmd_args: Vec<String> = vec![file.to_string()];

        if args["detect_signals"].as_bool().unwrap_or(false) {
            cmd_args.push("--detect-signals".to_string());
        }
        if args["pulse_stats"].as_bool().unwrap_or(false) {
            cmd_args.push("--pulse-stats".to_string());
        }
        if args["freq_peaks"].as_bool().unwrap_or(false) {
            cmd_args.push("--freq-peaks".to_string());
        }
        if args["classify"].as_bool().unwrap_or(false) {
            cmd_args.push("--classify".to_string());
        }
        if let Some(freq) = args["frequency"].as_str() {
            cmd_args.push("-f".to_string());
            cmd_args.push(freq.to_string());
        }
        if let Some(rate) = args["sample_rate"].as_str() {
            cmd_args.push("-s".to_string());
            cmd_args.push(rate.to_string());
        }

        let str_args: Vec<&str> = cmd_args.iter().map(String::as_str).collect();
        let mut result = run_akaei("analyze", &str_args, 180).await?;
        result.structured_data = Some(wrap_analyze_output(&result.stdout));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn analyze_tool_name() {
        assert_eq!(AkaeiAnalyzeTool.name(), "akaei_analyze");
    }

    #[test]
    fn analyze_definition_required_fields() {
        let def = AkaeiAnalyzeTool.definition();
        let required = def.function.parameters["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "file"));
    }

    #[test]
    fn analyze_risk_is_low() {
        assert_eq!(AkaeiAnalyzeTool.risk_level(), ToolRisk::Low);
    }

    #[tokio::test]
    async fn analyze_missing_file_errors() {
        let err = AkaeiAnalyzeTool.execute(json!({})).await.unwrap_err();
        assert!(err.to_string().contains("missing required argument"));
    }

    #[test]
    fn wrap_analyze_preserves_text() {
        let text = "Signal detected at 433.92 MHz\nPulse width: 500us\n";
        let wrapped = wrap_analyze_output(text);
        assert_eq!(wrapped["analysis"].as_str().unwrap(), text);
    }

    #[test]
    fn wrap_analyze_empty_output() {
        let wrapped = wrap_analyze_output("");
        assert_eq!(wrapped["analysis"], "");
    }
}
