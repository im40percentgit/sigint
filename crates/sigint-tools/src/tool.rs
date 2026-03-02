//! Tool trait — the common interface for all sandboxed tool wrappers.
//!
//! @decision DEC-TOOL-003
//! @title async_trait for object-safe async Tool methods
//! @status accepted
//! @rationale Rust 1.75+ RPITIT (return-position impl Trait in traits) does not
//! produce object-safe traits — `dyn Tool` would not compile. async_trait rewrites
//! async fn into `Pin<Box<dyn Future>>` which IS object-safe, enabling
//! `Vec<Box<dyn Tool>>` registries and dynamic dispatch at the agent layer.
//! The trade-off (one heap allocation per execute call) is acceptable given that
//! tool calls are coarse-grained network/process operations that dwarf the
//! allocation cost.

use async_trait::async_trait;
use serde_json::Value;
use sigint_core::types::ToolRisk;
use sigint_llm::ToolDefinition;

use crate::error::Result;
use crate::result::ToolResult;

/// Common interface for all sandboxed tool wrappers.
///
/// Implementors encapsulate a specific external tool (nmap, grep, etc.) and
/// expose it to the LLM agent layer via a uniform async execute interface.
///
/// # Object Safety
///
/// `Tool` is object-safe (`dyn Tool` compiles) because `async_trait` rewrites
/// async methods into boxed futures. A tool registry can therefore store
/// `Vec<Box<dyn Tool>>` or `HashMap<String, Arc<dyn Tool>>`.
#[async_trait]
pub trait Tool: Send + Sync {
    /// Short identifier for this tool (matches the function name in the LLM schema).
    fn name(&self) -> &str;

    /// One-sentence description of what this tool does.
    fn description(&self) -> &str;

    /// JSON Schema ToolDefinition to pass to the LLM in the `tools` array.
    fn definition(&self) -> ToolDefinition;

    /// Execute the tool with the given JSON arguments.
    ///
    /// `args` is the parsed `arguments` object from the LLM's `FunctionCall`.
    /// Returns a `ToolResult` on success or a `ToolError` on failure.
    async fn execute(&self, args: Value) -> Result<ToolResult>;

    /// Risk level of this tool (used by the approval gate).
    ///
    /// Defaults to `ToolRisk::Low`. Override in high-impact tools (nikto, shell)
    /// to require user approval before execution.
    fn risk_level(&self) -> ToolRisk {
        ToolRisk::Low
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ToolError;
    use serde_json::json;
    use std::time::Duration;

    /// Minimal Tool implementation used only in tests.
    struct EchoTool;

    #[async_trait]
    impl Tool for EchoTool {
        fn name(&self) -> &str {
            "echo"
        }
        fn description(&self) -> &str {
            "Echoes the input back as stdout."
        }
        fn definition(&self) -> ToolDefinition {
            ToolDefinition::function(
                "echo",
                "Echoes the input back as stdout.",
                json!({
                    "type": "object",
                    "properties": {
                        "message": { "type": "string", "description": "Text to echo" }
                    },
                    "required": ["message"]
                }),
            )
        }
        async fn execute(&self, args: Value) -> Result<ToolResult> {
            let msg = args["message"]
                .as_str()
                .ok_or_else(|| ToolError::MissingArgument("message".to_string()))?;
            Ok(ToolResult {
                stdout: msg.to_string(),
                stderr: String::new(),
                exit_code: 0,
                duration: Duration::from_millis(1),
                structured_data: None,
            })
        }
    }

    #[test]
    fn echo_tool_name_and_description() {
        let t = EchoTool;
        assert!(!t.name().is_empty());
        assert!(!t.description().is_empty());
        assert_eq!(t.name(), "echo");
    }

    #[test]
    fn echo_tool_definition_shape() {
        let t = EchoTool;
        let def = t.definition();
        assert_eq!(def.type_, "function");
        assert_eq!(def.function.name, "echo");
        assert!(!def.function.description.is_empty());
        // parameters must be an object with a "required" array
        let params = &def.function.parameters;
        assert_eq!(params["type"], "object");
        assert!(params["required"].is_array());
    }

    #[tokio::test]
    async fn echo_tool_execute_returns_message() {
        let t = EchoTool;
        let result = t.execute(json!({"message": "hello"})).await.unwrap();
        assert_eq!(result.stdout, "hello");
        assert_eq!(result.exit_code, 0);
        assert!(result.success());
    }

    #[tokio::test]
    async fn echo_tool_execute_missing_arg_errors() {
        let t = EchoTool;
        let err = t.execute(json!({})).await.unwrap_err();
        assert!(err.to_string().contains("missing required argument"));
    }

    #[test]
    fn tool_is_object_safe() {
        // Compiling this function proves dyn Tool works (object safety check).
        fn _takes_dyn(_tool: &dyn Tool) {}
        let _ = _takes_dyn; // suppress unused warning
    }

    /// EchoTool has no risk_level() override, so it must return the default Low.
    #[test]
    fn echo_tool_default_risk_is_low() {
        let t = EchoTool;
        assert_eq!(t.risk_level(), ToolRisk::Low);
    }
}
