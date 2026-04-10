//! sigint-plugin — compile-time plugin registration for SIGINT tool packs.
//!
//! Plugin crates implement `sigint_tools::Tool` and register tools via
//! `register_tool!()`. The main binary calls `collect_plugin_tools()` at
//! startup to discover all registered tools across linked crates.
//!
//! @decision DEC-PLUGIN-001
//! @title inventory crate for zero-boilerplate link-time tool registration
//! @status accepted
//! @rationale The `inventory` crate uses platform-specific linker sections
//! (.init_array on Linux, __DATA on macOS) to collect static submissions at
//! link time — no runtime reflection, no unsafe user code, no manual wiring.
//! Plugin authors call `register_tool!(MyTool)` and the binary discovers it
//! automatically. The alternative (manual `pub fn tools() -> Vec<Box<dyn Tool>>`)
//! requires each plugin to be explicitly called in the binary, defeating the
//! purpose of a plugin system.

pub use sigint_tools::tool::Tool;
pub use sigint_tools::result::ToolResult;
pub use sigint_tools::error::{Result, ToolError};
pub use sigint_core::types::ToolRisk;
pub use sigint_llm::ToolDefinition;
pub use sigint_agents::role::AgentRole;

/// Factory that produces a boxed Tool instance.
///
/// Registered via `register_tool!()` and collected at link time by `inventory`.
pub struct ToolFactory {
    factory: fn() -> Box<dyn Tool>,
    name: &'static str,
}

impl ToolFactory {
    pub const fn new(factory: fn() -> Box<dyn Tool>, name: &'static str) -> Self {
        Self { factory, name }
    }

    pub fn name(&self) -> &'static str {
        self.name
    }
}

inventory::collect!(ToolFactory);

/// Register a tool for automatic discovery at link time.
///
/// The tool type must implement `Tool` and have a `new()` constructor.
///
/// # Example
///
/// ```ignore
/// use sigint_plugin::register_tool;
///
/// pub struct MyTool;
/// // impl Tool for MyTool { ... }
///
/// register_tool!(MyTool);
/// ```
#[macro_export]
macro_rules! register_tool {
    ($tool_type:ty) => {
        ::inventory::submit! {
            $crate::ToolFactory::new(
                || Box::new(<$tool_type>::new()),
                stringify!($tool_type),
            )
        }
    };
}

/// Collect all plugin-registered tools from all linked crates.
///
/// Returns an empty Vec when no plugins are linked — this is the normal
/// case for a vanilla sigint binary with no plugin crates.
pub fn collect_plugin_tools() -> Vec<Box<dyn Tool>> {
    inventory::iter::<ToolFactory>
        .into_iter()
        .map(|f| (f.factory)())
        .collect()
}

/// Returns the names of all registered plugin tool factories.
pub fn list_plugin_tool_names() -> Vec<&'static str> {
    inventory::iter::<ToolFactory>
        .into_iter()
        .map(|f| f.name())
        .collect()
}

/// Agent prompt pack — overrides system prompts for specific agent roles.
///
/// Plugin crates register prompt packs via `register_prompt_pack!()`.
/// The active pack is selected via `config.plugins.prompt_pack`.
pub struct PromptPack {
    pub name: &'static str,
    pub description: &'static str,
    pub prompts: &'static [(AgentRole, &'static str)],
}

impl PromptPack {
    /// Look up the prompt override for a given role, if any.
    pub fn prompt_for(&self, role: AgentRole) -> Option<&'static str> {
        self.prompts
            .iter()
            .find(|(r, _)| *r == role)
            .map(|(_, prompt)| *prompt)
    }
}

inventory::collect!(PromptPack);

/// Register an agent prompt pack for discovery at link time.
#[macro_export]
macro_rules! register_prompt_pack {
    ($pack:expr) => {
        ::inventory::submit! { $pack }
    };
}

/// Find a prompt pack by name from all linked crates.
pub fn find_prompt_pack(name: &str) -> Option<&'static PromptPack> {
    inventory::iter::<PromptPack>
        .into_iter()
        .find(|p| p.name == name)
}

/// List all registered prompt pack names.
pub fn list_prompt_packs() -> Vec<(&'static str, &'static str)> {
    inventory::iter::<PromptPack>
        .into_iter()
        .map(|p| (p.name, p.description))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn collect_plugin_tools_returns_empty_without_plugins() {
        // No plugins are linked in the test binary, so this should be empty.
        let tools = collect_plugin_tools();
        assert!(tools.is_empty());
    }

    #[test]
    fn list_plugin_tool_names_returns_empty_without_plugins() {
        let names = list_plugin_tool_names();
        assert!(names.is_empty());
    }

    #[test]
    fn find_prompt_pack_returns_none_for_unknown() {
        assert!(find_prompt_pack("nonexistent").is_none());
    }

    #[test]
    fn list_prompt_packs_returns_empty_without_plugins() {
        let packs = list_prompt_packs();
        assert!(packs.is_empty());
    }

    #[test]
    fn prompt_pack_prompt_for_returns_none_for_unset_role() {
        let pack = PromptPack {
            name: "test",
            description: "test pack",
            prompts: &[(AgentRole::Strategist, "custom strategist prompt")],
        };
        assert!(pack.prompt_for(AgentRole::Strategist).is_some());
        assert!(pack.prompt_for(AgentRole::Reporter).is_none());
    }
}
