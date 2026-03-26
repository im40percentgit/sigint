//! AkaeiFreqdbTool — frequency database lookup wrapper.
//!
//! @decision DEC-AKAEI-002
//! @title Output parsers are command-specific; freqdb emits tab-separated text
//! @status accepted
//! @rationale freqdb output is tab-separated rows (frequency, name, category,
//! description). parse_freqdb_output() splits on tabs and produces a JSON array
//! of objects. No hardware is required — freqdb is a pure database lookup.

use async_trait::async_trait;
use serde_json::{json, Value};
use sigint_core::types::ToolRisk;
use sigint_llm::ToolDefinition;

use crate::error::{Result, ToolError};
use crate::result::ToolResult;
use crate::tool::Tool;

use super::run_akaei;

/// Frequency database action.
#[derive(Debug, Clone, Copy, PartialEq)]
enum FreqdbAction {
    /// Search for a specific frequency.
    Search,
    /// List known frequencies, optionally filtered by category.
    List,
    /// List all available categories.
    Categories,
}

impl FreqdbAction {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "search" => Some(FreqdbAction::Search),
            "list" => Some(FreqdbAction::List),
            "categories" => Some(FreqdbAction::Categories),
            _ => None,
        }
    }
}

/// Parse tab-separated freqdb output into a JSON array.
///
/// Each line is split on tabs. Skips blank lines and `#` comments.
fn parse_freqdb_output(output: &str) -> Value {
    let mut rows: Vec<Value> = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split('\t').collect();
        let entry = match parts.len() {
            0 => continue,
            1 => json!({ "value": parts[0] }),
            2 => json!({ "frequency": parts[0], "name": parts[1] }),
            3 => json!({ "frequency": parts[0], "name": parts[1], "category": parts[2] }),
            _ => json!({
                "frequency": parts[0],
                "name": parts[1],
                "category": parts[2],
                "description": parts[3..].join("\t"),
            }),
        };
        rows.push(entry);
    }
    json!(rows)
}

/// Frequency database lookup tool.
///
/// Provides read-only access to the akaei frequency database.
/// No HackRF hardware is required.
pub struct AkaeiFreqdbTool;

#[async_trait]
impl Tool for AkaeiFreqdbTool {
    fn name(&self) -> &str {
        "akaei_freqdb"
    }

    fn description(&self) -> &str {
        "Look up frequency assignments in the akaei frequency database. \
         Search for a specific frequency, list entries by category, or list all \
         categories. No HackRF hardware required — pure database lookup."
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
                        "enum": ["search", "list", "categories"],
                        "description": "'search' looks up a frequency, 'list' shows all entries (optionally filtered by category), 'categories' lists available categories."
                    },
                    "frequency": {
                        "type": "string",
                        "description": "Frequency to search (e.g. '433.92e6', '433920000'). Required for action=search."
                    },
                    "tolerance": {
                        "type": "string",
                        "description": "Frequency tolerance in Hz for search (e.g. '10000'). Optional."
                    },
                    "category": {
                        "type": "string",
                        "description": "Category filter for action=list (e.g. 'ISM', 'Aviation'). Optional."
                    }
                },
                "required": ["action"]
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
            FreqdbAction::from_str(action_str).ok_or_else(|| ToolError::InvalidArgument {
                name: "action".to_string(),
                expected: "one of: search, list, categories".to_string(),
            })?;

        let mut cmd_args: Vec<String> = vec![action_str.to_string()];

        match action {
            FreqdbAction::Search => {
                let freq = args["frequency"]
                    .as_str()
                    .ok_or_else(|| ToolError::MissingArgument("frequency".to_string()))?;
                cmd_args.push(freq.to_string());
                if let Some(tol) = args["tolerance"].as_str() {
                    cmd_args.push("--tolerance".to_string());
                    cmd_args.push(tol.to_string());
                }
            }
            FreqdbAction::List => {
                if let Some(cat) = args["category"].as_str() {
                    cmd_args.push("--category".to_string());
                    cmd_args.push(cat.to_string());
                }
            }
            FreqdbAction::Categories => {}
        }

        let str_args: Vec<&str> = cmd_args.iter().map(String::as_str).collect();
        let mut result = run_akaei("freqdb", &str_args, 10).await?;
        result.structured_data = Some(parse_freqdb_output(&result.stdout));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn freqdb_tool_name() {
        assert_eq!(AkaeiFreqdbTool.name(), "akaei_freqdb");
    }

    #[test]
    fn freqdb_tool_description_nonempty() {
        assert!(!AkaeiFreqdbTool.description().is_empty());
    }

    #[test]
    fn freqdb_tool_definition_shape() {
        let def = AkaeiFreqdbTool.definition();
        assert_eq!(def.type_, "function");
        assert_eq!(def.function.name, "akaei_freqdb");
        let params = &def.function.parameters;
        assert_eq!(params["type"], "object");
        let required = params["required"].as_array().unwrap();
        assert!(required.iter().any(|v| v == "action"));
        let action_enum = params["properties"]["action"]["enum"].as_array().unwrap();
        assert!(action_enum.iter().any(|v| v == "search"));
        assert!(action_enum.iter().any(|v| v == "list"));
        assert!(action_enum.iter().any(|v| v == "categories"));
    }

    #[test]
    fn freqdb_risk_is_low() {
        assert_eq!(AkaeiFreqdbTool.risk_level(), ToolRisk::Low);
    }

    #[tokio::test]
    async fn freqdb_missing_action_errors() {
        let err = AkaeiFreqdbTool.execute(json!({})).await.unwrap_err();
        assert!(
            err.to_string().contains("missing required argument"),
            "unexpected: {err}"
        );
    }

    #[tokio::test]
    async fn freqdb_invalid_action_errors() {
        let err = AkaeiFreqdbTool
            .execute(json!({"action": "unknown"}))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("invalid argument"),
            "unexpected: {err}"
        );
    }

    #[tokio::test]
    async fn freqdb_search_missing_frequency_errors() {
        let err = AkaeiFreqdbTool
            .execute(json!({"action": "search"}))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("missing required argument"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn parse_freqdb_tab_separated() {
        let output = "433920000\tISM Remote\tISM\tCommon ISM band for remotes\n\
                      868000000\tLoRa EU\tISM\t868 MHz LoRa band\n";
        let parsed = parse_freqdb_output(output);
        let arr = parsed.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["frequency"], "433920000");
        assert_eq!(arr[0]["name"], "ISM Remote");
        assert_eq!(arr[0]["category"], "ISM");
        assert_eq!(arr[1]["frequency"], "868000000");
    }

    #[test]
    fn parse_freqdb_skips_empty_and_comments() {
        let output = "# header comment\n\n433920000\tISM Remote\tISM\n";
        let parsed = parse_freqdb_output(output);
        let arr = parsed.as_array().unwrap();
        assert_eq!(arr.len(), 1);
    }

    #[test]
    fn parse_freqdb_empty_output() {
        let parsed = parse_freqdb_output("");
        assert_eq!(parsed.as_array().unwrap().len(), 0);
    }

    #[test]
    fn freqdb_action_from_str() {
        assert_eq!(FreqdbAction::from_str("search"), Some(FreqdbAction::Search));
        assert_eq!(FreqdbAction::from_str("list"), Some(FreqdbAction::List));
        assert_eq!(
            FreqdbAction::from_str("categories"),
            Some(FreqdbAction::Categories)
        );
        assert_eq!(FreqdbAction::from_str("unknown"), None);
        assert_eq!(FreqdbAction::from_str(""), None);
    }
}
