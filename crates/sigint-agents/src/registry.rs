//! ToolRegistry — stores Tool implementations and filters by agent role ACL.
//!
//! The registry is the single source of truth for which tools exist and which
//! agents may invoke them. The Orchestrator queries it once per agent with
//! `for_agent`, receiving (tool references, tool definitions) pre-filtered to
//! only what that agent's ACL permits.
//!
//! @decision DEC-AGENT-011
//! @title ToolRegistry owns Box<dyn Tool>; for_agent returns &dyn Tool slices
//! @status accepted
//! @rationale Boxed ownership means the registry outlives any agent turn —
//! tools are registered once and shared across all pipeline iterations without
//! cloning. `for_agent` returns borrowed references rather than Arcs because the
//! agent runs synchronously within a single `run_agent` await chain, so the
//! borrow lifetime always outlives the call. This avoids Arc overhead on the hot
//! path (tool lookup per loop iteration). If tools need to be shared across
//! concurrent agent runs in the future, the signature can migrate to Arc<dyn Tool>
//! without changing callers.

use std::collections::HashMap;

use sigint_llm::types::ToolDefinition;
use sigint_tools::tool::Tool;
use tracing::warn;

use crate::agent::Agent;

/// Stores `Tool` implementations and vends filtered subsets by agent ACL.
///
/// Use `register` to add tools at startup. The Orchestrator then calls
/// `for_agent` to get exactly the tools each agent is permitted to use.
pub struct ToolRegistry {
    /// Tool implementations keyed by tool name.
    tools: HashMap<String, Box<dyn Tool>>,
}

impl ToolRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
        }
    }

    /// Register a tool implementation.
    ///
    /// If a tool with the same name was already registered, it is replaced.
    pub fn register(&mut self, tool: Box<dyn Tool>) {
        self.tools.insert(tool.name().to_string(), tool);
    }

    /// Look up a tool by name.
    ///
    /// Returns `None` if no tool with that name is registered.
    pub fn get(&self, name: &str) -> Option<&dyn Tool> {
        self.tools.get(name).map(|t| t.as_ref())
    }

    /// Return the `ToolDefinition` schemas for all registered tools.
    ///
    /// Definitions are returned in arbitrary order (HashMap iteration).
    /// Used to advertise the full tool catalog to components that need it.
    pub fn definitions(&self) -> Vec<ToolDefinition> {
        self.tools.values().map(|t| t.definition()).collect()
    }

    /// Return (tool references, tool definitions) filtered by `agent.allowed_tools()`.
    ///
    /// Only tools whose names appear in the agent's ACL are included. If the
    /// agent's ACL is empty (e.g. Strategist, Reporter), both returned vecs are
    /// empty. Unrecognised names in the ACL (tools that aren't registered) are
    /// silently skipped — the agent simply won't be able to invoke them.
    ///
    /// # Returns
    /// `(tools, definitions)` — parallel vecs, same order. Pass `tools` to
    /// `run_tool_loop` as `&[&dyn Tool]` and `definitions` as `&[ToolDefinition]`.
    pub fn for_agent(&self, agent: &dyn Agent) -> (Vec<&dyn Tool>, Vec<ToolDefinition>) {
        let mut tool_refs: Vec<&dyn Tool> = Vec::new();
        let mut tool_defs: Vec<ToolDefinition> = Vec::new();

        for name in agent.allowed_tools() {
            if let Some(tool) = self.tools.get(name) {
                tool_refs.push(tool.as_ref());
                tool_defs.push(tool.definition());
            } else {
                warn!(
                    agent = agent.name(),
                    tool = %name,
                    "agent ACL references unregistered tool — check tool name matches"
                );
            }
        }

        (tool_refs, tool_defs)
    }
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use serde_json::{json, Value};
    use std::time::Duration;

    use sigint_llm::ToolDefinition;
    use sigint_tools::{error::Result as ToolResult, result::ToolResult as TR};

    use crate::agents::{AnalystAgent, ExecutorAgent, StrategistAgent};

    // ── Minimal test Tool ────────────────────────────────────────────────────

    struct FakeTool {
        name: String,
    }

    impl FakeTool {
        fn new(name: &str) -> Self {
            Self { name: name.into() }
        }
    }

    #[async_trait]
    impl Tool for FakeTool {
        fn name(&self) -> &str {
            &self.name
        }

        fn description(&self) -> &str {
            "fake tool for registry tests"
        }

        fn definition(&self) -> ToolDefinition {
            ToolDefinition::function(
                self.name.clone(),
                "fake tool",
                json!({ "type": "object", "properties": {} }),
            )
        }

        async fn execute(&self, _args: Value) -> ToolResult<TR> {
            Ok(TR {
                stdout: "fake output".into(),
                stderr: String::new(),
                exit_code: 0,
                duration: Duration::from_millis(1),
                structured_data: None,
            })
        }
    }

    // ── Tests ────────────────────────────────────────────────────────────────

    #[test]
    fn register_and_get_by_name() {
        let mut reg = ToolRegistry::new();
        reg.register(Box::new(FakeTool::new("nmap_scan")));

        let tool = reg.get("nmap_scan").expect("should find nmap_scan");
        assert_eq!(tool.name(), "nmap_scan");
    }

    #[test]
    fn get_unregistered_returns_none() {
        let reg = ToolRegistry::new();
        assert!(reg.get("nonexistent").is_none());
    }

    #[test]
    fn register_overwrites_same_name() {
        let mut reg = ToolRegistry::new();
        reg.register(Box::new(FakeTool::new("nmap_scan")));
        reg.register(Box::new(FakeTool::new("nmap_scan"))); // replace
        assert!(reg.get("nmap_scan").is_some());
        assert_eq!(reg.definitions().len(), 1, "should still have exactly one entry");
    }

    #[test]
    fn definitions_returns_all_registered() {
        let mut reg = ToolRegistry::new();
        reg.register(Box::new(FakeTool::new("nmap_scan")));
        reg.register(Box::new(FakeTool::new("shell")));

        let defs = reg.definitions();
        assert_eq!(defs.len(), 2);
        let names: Vec<&str> = defs.iter().map(|d| d.function.name.as_str()).collect();
        assert!(names.contains(&"nmap_scan"));
        assert!(names.contains(&"shell"));
    }

    #[test]
    fn for_agent_executor_returns_all_allowed_tools() {
        let mut reg = ToolRegistry::new();
        reg.register(Box::new(FakeTool::new("nmap_scan")));
        reg.register(Box::new(FakeTool::new("shell")));

        let agent = ExecutorAgent::new();
        let (tools, defs) = reg.for_agent(&agent);

        assert_eq!(tools.len(), 2, "executor should get both tools");
        assert_eq!(defs.len(), 2);
        let names: Vec<&str> = tools.iter().map(|t| t.name()).collect();
        assert!(names.contains(&"nmap_scan"));
        assert!(names.contains(&"shell"));
    }

    #[test]
    fn for_agent_strategist_returns_empty() {
        let mut reg = ToolRegistry::new();
        reg.register(Box::new(FakeTool::new("nmap_scan")));
        reg.register(Box::new(FakeTool::new("shell")));

        let agent = StrategistAgent::new();
        let (tools, defs) = reg.for_agent(&agent);

        assert!(tools.is_empty(), "strategist must get no tools");
        assert!(defs.is_empty());
    }

    #[test]
    fn for_agent_analyst_returns_only_shell() {
        let mut reg = ToolRegistry::new();
        reg.register(Box::new(FakeTool::new("nmap_scan")));
        reg.register(Box::new(FakeTool::new("shell")));

        let agent = AnalystAgent::new();
        let (tools, defs) = reg.for_agent(&agent);

        assert_eq!(tools.len(), 1, "analyst should get only shell");
        assert_eq!(tools[0].name(), "shell");
        assert_eq!(defs.len(), 1);
        assert_eq!(defs[0].function.name, "shell");
    }

    #[test]
    fn for_agent_skips_unregistered_tools_in_acl() {
        // Agent's ACL includes "nmap_scan" but only "shell" is registered.
        let mut reg = ToolRegistry::new();
        reg.register(Box::new(FakeTool::new("shell")));

        let agent = ExecutorAgent::new(); // ACL: [nmap, shell]
        let (tools, defs) = reg.for_agent(&agent);

        assert_eq!(tools.len(), 1, "only shell should be returned");
        assert_eq!(tools[0].name(), "shell");
        assert_eq!(defs.len(), 1);
    }

    #[test]
    fn empty_registry_for_any_agent_returns_empty() {
        let reg = ToolRegistry::new();
        let agent = ExecutorAgent::new();
        let (tools, defs) = reg.for_agent(&agent);
        assert!(tools.is_empty());
        assert!(defs.is_empty());
    }

    #[test]
    fn default_is_empty_registry() {
        let reg = ToolRegistry::default();
        assert!(reg.definitions().is_empty());
    }
}
