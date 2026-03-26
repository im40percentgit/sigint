//! AkaeiFingerprintTool — RF signal fingerprinting wrapper.
//!
//! @decision DEC-AKAEI-002
//! @title fingerprint emits text; parser extracts label/distance/confidence fields
//! @status accepted
//! @rationale akaei fingerprint classify outputs text with a predicted label and
//! distance/confidence on separate lines. parse_fingerprint_output() uses simple
//! line scanning to extract these fields into structured JSON. Training output
//! is wrapped in {"result": "<stdout>"} since it has no fixed schema.

use async_trait::async_trait;
use serde_json::{json, Value};
use sigint_core::types::ToolRisk;
use sigint_llm::ToolDefinition;

use crate::error::{Result, ToolError};
use crate::result::ToolResult;
use crate::tool::Tool;

use super::run_akaei;

/// Fingerprint action.
#[derive(Debug, Clone, Copy, PartialEq)]
enum FingerprintAction {
    /// Classify an IQ file against a trained fingerprint database.
    Classify,
    /// List all known labels in a fingerprint database.
    List,
}

impl FingerprintAction {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "classify" => Some(FingerprintAction::Classify),
            "list" => Some(FingerprintAction::List),
            _ => None,
        }
    }
}

/// Extract structured fields from `akaei fingerprint classify` text output.
///
/// Looks for lines containing "label:", "distance:", "confidence:" (case-insensitive).
/// Returns `{action, predicted_label, distance, confidence}`.
fn parse_fingerprint_output(output: &str, action: &str) -> Value {
    let mut label = String::new();
    let mut distance = String::new();
    let mut confidence = String::new();

    for line in output.lines() {
        let lower = line.to_lowercase();
        if lower.contains("label:") {
            label = line
                .split_once(':')
                .map(|x| x.1)
                .unwrap_or("")
                .trim()
                .to_string();
        } else if lower.contains("distance:") {
            distance = line
                .split_once(':')
                .map(|x| x.1)
                .unwrap_or("")
                .trim()
                .to_string();
        } else if lower.contains("confidence:") {
            confidence = line
                .split_once(':')
                .map(|x| x.1)
                .unwrap_or("")
                .trim()
                .to_string();
        }
    }

    json!({
        "action": action,
        "predicted_label": label,
        "distance": distance,
        "confidence": confidence,
        "raw": output,
    })
}

/// RF signal fingerprinting tool.
///
/// Classifies an IQ capture against a trained fingerprint database,
/// or lists known labels in a database. Offline — no hardware required.
pub struct AkaeiFingerprintTool;

#[async_trait]
impl Tool for AkaeiFingerprintTool {
    fn name(&self) -> &str {
        "akaei_fingerprint"
    }

    fn description(&self) -> &str {
        "Classify an RF signal capture against a trained fingerprint database, or list \
         known labels. Runs offline — no HackRF hardware required for classify/list."
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::function(
            self.name(),
            self.description(),
            json!({
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["classify", "list"],
                        "description": "'classify' identifies a signal file against the database; 'list' shows known labels."
                    },
                    "db_path": {
                        "type": "string",
                        "description": "Path to the fingerprint database file."
                    },
                    "file": {
                        "type": "string",
                        "description": "Path to the IQ capture file to classify. Required for action=classify."
                    },
                    "k": {
                        "type": "integer",
                        "description": "Number of nearest neighbours for classification (default 1). Optional."
                    }
                },
                "required": ["action", "db_path"]
            }),
        )
    }

    fn risk_level(&self) -> ToolRisk {
        ToolRisk::Low
    }

    async fn execute(&self, args: Value) -> Result<ToolResult> {
        let action_str = args["action"]
            .as_str()
            .ok_or_else(|| ToolError::MissingArgument("action".to_string()))?;

        let action =
            FingerprintAction::from_str(action_str).ok_or_else(|| ToolError::InvalidArgument {
                name: "action".to_string(),
                expected: "one of: classify, list".to_string(),
            })?;

        let db = args["db_path"]
            .as_str()
            .ok_or_else(|| ToolError::MissingArgument("db_path".to_string()))?;

        let mut cmd_args: Vec<String> =
            vec![action_str.to_string(), "--db".to_string(), db.to_string()];

        match action {
            FingerprintAction::Classify => {
                let file = args["file"]
                    .as_str()
                    .ok_or_else(|| ToolError::MissingArgument("file".to_string()))?;
                if let Some(k) = args["k"].as_i64() {
                    cmd_args.push("--k".to_string());
                    cmd_args.push(k.to_string());
                }
                cmd_args.push(file.to_string());
            }
            FingerprintAction::List => {}
        }

        let str_args: Vec<&str> = cmd_args.iter().map(String::as_str).collect();
        let mut result = run_akaei("fingerprint", &str_args, 60).await?;
        result.structured_data = Some(parse_fingerprint_output(&result.stdout, action_str));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn fingerprint_tool_name() {
        assert_eq!(AkaeiFingerprintTool.name(), "akaei_fingerprint");
    }

    #[test]
    fn fingerprint_definition_required_fields() {
        let def = AkaeiFingerprintTool.definition();
        let required = def.function.parameters["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "action"));
        assert!(required.iter().any(|v| v == "db_path"));
        let action_enum = def.function.parameters["properties"]["action"]["enum"]
            .as_array()
            .unwrap();
        assert!(action_enum.iter().any(|v| v == "classify"));
        assert!(action_enum.iter().any(|v| v == "list"));
    }

    #[test]
    fn fingerprint_risk_is_low() {
        assert_eq!(AkaeiFingerprintTool.risk_level(), ToolRisk::Low);
    }

    #[tokio::test]
    async fn fingerprint_missing_action_errors() {
        let err = AkaeiFingerprintTool
            .execute(json!({"db_path": "/tmp/fp.db"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("missing required argument"));
    }

    #[tokio::test]
    async fn fingerprint_invalid_action_errors() {
        let err = AkaeiFingerprintTool
            .execute(json!({"action": "train", "db_path": "/tmp/fp.db"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invalid argument"));
    }

    #[tokio::test]
    async fn fingerprint_classify_missing_file_errors() {
        let err = AkaeiFingerprintTool
            .execute(json!({"action": "classify", "db_path": "/tmp/fp.db"}))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("missing required argument"));
    }

    #[test]
    fn parse_fingerprint_classify_output() {
        let text = "Predicted label: garage_door_433\nDistance: 0.142\nConfidence: 87.3%\n";
        let parsed = parse_fingerprint_output(text, "classify");
        assert_eq!(parsed["predicted_label"], "garage_door_433");
        assert_eq!(parsed["distance"], "0.142");
        assert_eq!(parsed["confidence"], "87.3%");
        assert_eq!(parsed["action"], "classify");
    }

    #[test]
    fn parse_fingerprint_empty_output() {
        let parsed = parse_fingerprint_output("", "list");
        assert_eq!(parsed["predicted_label"], "");
        assert_eq!(parsed["action"], "list");
    }

    #[test]
    fn fingerprint_action_from_str() {
        assert_eq!(
            FingerprintAction::from_str("classify"),
            Some(FingerprintAction::Classify)
        );
        assert_eq!(
            FingerprintAction::from_str("list"),
            Some(FingerprintAction::List)
        );
        assert_eq!(FingerprintAction::from_str("train"), None);
    }
}
