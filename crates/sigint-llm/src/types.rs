//! Shared types for LLM request/response across all providers.
//!
//! @decision DEC-LLM-001
//! @title Provider-agnostic ChatMessage/ChatRequest/ChatResponse types
//! @status accepted
//! @rationale Keeping LLM wire types separate from domain types (sigint-core)
//! allows providers to serialize/deserialize independently without leaking
//! provider-specific fields into the shared domain layer.
//!
//! @decision DEC-LLM-002
//! @title Tool-calling types use OpenAI-compatible JSON Schema format
//! @status accepted
//! @rationale Ollama's tool-calling API is OpenAI-compatible. Using the same
//! ToolDefinition / ToolCall shapes here means the same structs work with
//! any OpenAI-compatible provider added in later phases without conversion.

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ── Tool-calling types ─────────────────────────────────────────────────────────

/// Tool definition for Ollama's /api/chat `tools` parameter.
/// Matches OpenAI-compatible JSON Schema format.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    /// Always "function" for current Ollama/OpenAI-compatible providers.
    #[serde(rename = "type")]
    pub type_: String,
    pub function: FunctionDef,
}

impl ToolDefinition {
    /// Convenience constructor for the common "function" type.
    pub fn function(name: impl Into<String>, description: impl Into<String>, parameters: Value) -> Self {
        Self {
            type_: "function".into(),
            function: FunctionDef {
                name: name.into(),
                description: description.into(),
                parameters,
            },
        }
    }
}

/// Definition of a callable function exposed as a tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDef {
    pub name: String,
    pub description: String,
    /// JSON Schema object describing the function parameters.
    pub parameters: Value,
}

/// A tool call requested by the LLM in its response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub function: FunctionCall,
}

/// The specific function the LLM has requested to call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionCall {
    pub name: String,
    /// Parsed arguments as a JSON value (object with named parameters).
    pub arguments: Value,
}

// ── Core message / request / response types ───────────────────────────────────

/// A single message in a chat conversation (provider-agnostic).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
    /// Tool calls requested by the assistant. Only present on role="assistant"
    /// messages when the model chooses to invoke a tool instead of (or in
    /// addition to) generating text content.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCall>>,
}

impl ChatMessage {
    pub fn user(content: impl Into<String>) -> Self {
        Self { role: "user".into(), content: content.into(), tool_calls: None }
    }
    pub fn assistant(content: impl Into<String>) -> Self {
        Self { role: "assistant".into(), content: content.into(), tool_calls: None }
    }
    pub fn system(content: impl Into<String>) -> Self {
        Self { role: "system".into(), content: content.into(), tool_calls: None }
    }
    /// Create a "tool" role message carrying the result of a tool invocation.
    /// The content should be the serialized tool output returned to the model.
    pub fn tool(content: impl Into<String>) -> Self {
        Self { role: "tool".into(), content: content.into(), tool_calls: None }
    }
}

/// Request sent to an LLM provider.
#[derive(Debug, Clone)]
pub struct ChatRequest {
    pub messages: Vec<ChatMessage>,
    pub model: String,
    pub temperature: f32,
    /// Max tokens to generate (0 = provider default).
    pub max_tokens: usize,
    /// Tool definitions available to the model. Empty = no tool calling.
    pub tools: Vec<ToolDefinition>,
}

impl ChatRequest {
    pub fn new(model: impl Into<String>, messages: Vec<ChatMessage>) -> Self {
        Self {
            messages,
            model: model.into(),
            temperature: 0.7,
            max_tokens: 0,
            tools: Vec::new(),
        }
    }

    pub fn with_temperature(mut self, t: f32) -> Self {
        self.temperature = t;
        self
    }

    /// Attach tool definitions to this request.
    pub fn with_tools(mut self, tools: Vec<ToolDefinition>) -> Self {
        self.tools = tools;
        self
    }
}

/// Complete (non-streaming) response from an LLM provider.
#[derive(Debug, Clone)]
pub struct ChatResponse {
    pub content: String,
    pub usage: Option<TokenUsage>,
    pub model: String,
    /// Tool calls requested by the model. Empty when the model responded with
    /// plain text content rather than requesting tool execution.
    pub tool_calls: Vec<ToolCall>,
}

impl ChatResponse {
    /// Returns true when the model requested one or more tool calls.
    pub fn has_tool_calls(&self) -> bool {
        !self.tool_calls.is_empty()
    }
}

/// Token usage statistics returned by the provider.
#[derive(Debug, Clone, Default)]
pub struct TokenUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

/// A single streaming chunk delivered during `chat_stream`.
#[derive(Debug, Clone)]
pub struct StreamChunk {
    /// Partial content token(s) in this chunk.
    pub delta: String,
    /// True when the stream is finished.
    pub done: bool,
    /// Usage stats — only populated on the final chunk, if available.
    pub usage: Option<TokenUsage>,
    /// Tool calls from the model — populated only on the final (done=true)
    /// chunk when the model requested tool execution instead of text output.
    pub tool_calls: Vec<ToolCall>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn chat_message_constructors() {
        let u = ChatMessage::user("hi");
        assert_eq!(u.role, "user");
        assert_eq!(u.content, "hi");
        assert!(u.tool_calls.is_none());

        let a = ChatMessage::assistant("hello");
        assert_eq!(a.role, "assistant");

        let s = ChatMessage::system("be helpful");
        assert_eq!(s.role, "system");
    }

    #[test]
    fn chat_message_tool_constructor() {
        let t = ChatMessage::tool(r#"{"temperature": 22}"#);
        assert_eq!(t.role, "tool");
        assert_eq!(t.content, r#"{"temperature": 22}"#);
        assert!(t.tool_calls.is_none());
    }

    #[test]
    fn chat_request_defaults() {
        let req = ChatRequest::new("llama3.2", vec![ChatMessage::user("test")]);
        assert_eq!(req.model, "llama3.2");
        assert!((req.temperature - 0.7).abs() < f32::EPSILON);
        assert_eq!(req.max_tokens, 0);
        assert!(req.tools.is_empty());
    }

    #[test]
    fn chat_request_with_temperature() {
        let req = ChatRequest::new("llama3.2", vec![])
            .with_temperature(0.1);
        assert!((req.temperature - 0.1).abs() < f32::EPSILON);
    }

    #[test]
    fn chat_request_with_tools() {
        let tool = ToolDefinition::function(
            "get_weather",
            "Get weather for a location",
            json!({
                "type": "object",
                "properties": {
                    "location": {"type": "string", "description": "City name"}
                },
                "required": ["location"]
            }),
        );
        let req = ChatRequest::new("llama3.2", vec![])
            .with_tools(vec![tool]);
        assert_eq!(req.tools.len(), 1);
        assert_eq!(req.tools[0].function.name, "get_weather");
        assert_eq!(req.tools[0].type_, "function");
    }

    #[test]
    fn tool_definition_serializes_correctly() {
        let tool = ToolDefinition::function(
            "get_weather",
            "Get weather for a location",
            json!({
                "type": "object",
                "properties": {
                    "location": {"type": "string"}
                },
                "required": ["location"]
            }),
        );
        let serialized = serde_json::to_value(&tool).unwrap();
        assert_eq!(serialized["type"], "function");
        assert_eq!(serialized["function"]["name"], "get_weather");
        assert_eq!(serialized["function"]["description"], "Get weather for a location");
        assert_eq!(serialized["function"]["parameters"]["type"], "object");
    }

    #[test]
    fn tool_definition_round_trips() {
        let json_str = r#"{
            "type": "function",
            "function": {
                "name": "get_weather",
                "description": "Get weather for a location",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "location": {"type": "string", "description": "City name"}
                    },
                    "required": ["location"]
                }
            }
        }"#;
        let tool: ToolDefinition = serde_json::from_str(json_str).unwrap();
        assert_eq!(tool.type_, "function");
        assert_eq!(tool.function.name, "get_weather");
    }

    #[test]
    fn chat_response_has_tool_calls() {
        let resp_no_tools = ChatResponse {
            content: "Hello".into(),
            usage: None,
            model: "llama3.2".into(),
            tool_calls: vec![],
        };
        assert!(!resp_no_tools.has_tool_calls());

        let resp_with_tools = ChatResponse {
            content: "".into(),
            usage: None,
            model: "llama3.2".into(),
            tool_calls: vec![ToolCall {
                function: FunctionCall {
                    name: "get_weather".into(),
                    arguments: json!({"location": "Paris"}),
                },
            }],
        };
        assert!(resp_with_tools.has_tool_calls());
    }

    #[test]
    fn chat_message_tool_calls_skipped_when_none() {
        // tool_calls: None should not appear in serialized JSON
        let msg = ChatMessage::user("hello");
        let serialized = serde_json::to_string(&msg).unwrap();
        assert!(!serialized.contains("tool_calls"));
    }

    #[test]
    fn tool_call_serializes_correctly() {
        let tc = ToolCall {
            function: FunctionCall {
                name: "get_weather".into(),
                arguments: json!({"location": "Paris"}),
            },
        };
        let serialized = serde_json::to_value(&tc).unwrap();
        assert_eq!(serialized["function"]["name"], "get_weather");
        assert_eq!(serialized["function"]["arguments"]["location"], "Paris");
    }
}
