//! Plugin management commands — list registered plugins and scaffold new packs.
//!
//! @decision DEC-PLUGIN-002
//! @title `sigint plugin new` generates workspace member crates
//! @status accepted
//! @rationale Generating a workspace member (instead of an external crate) means
//! the plugin is automatically linked into the binary on `cargo build`. The
//! scaffold writes Cargo.toml, lib.rs, and an example tool implementation —
//! plugin authors only need to replace the example with their own tools.

use anyhow::{bail, Result};
use std::fs;
use std::path::Path;

/// List all registered plugin tools and prompt packs.
pub fn run_list() -> Result<()> {
    // Built-in tools
    let builtin = sigint_tools::all_executor_tools();
    println!("Built-in tools ({}):", builtin.len());
    for tool in &builtin {
        println!("  {} — {}", tool.name(), tool.description());
    }

    // Plugin tools
    let plugin_names = sigint_plugin::list_plugin_tool_names();
    if plugin_names.is_empty() {
        println!("\nPlugin tools: (none)");
    } else {
        let plugin_tools = sigint_plugin::collect_plugin_tools();
        println!("\nPlugin tools ({}):", plugin_tools.len());
        for tool in &plugin_tools {
            println!("  {} — {}", tool.name(), tool.description());
        }
    }

    // Prompt packs
    let packs = sigint_plugin::list_prompt_packs();
    if packs.is_empty() {
        println!("\nPrompt packs: (none — using built-in defaults)");
    } else {
        println!("\nPrompt packs ({}):", packs.len());
        for (name, desc) in &packs {
            println!("  {} — {}", name, desc);
        }
    }

    Ok(())
}

/// Scaffold a new plugin crate in the workspace.
pub fn run_new(name: &str) -> Result<()> {
    // Validate name
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        bail!("Invalid plugin name: use alphanumeric characters, hyphens, or underscores");
    }

    let crate_name = if name.starts_with("sigint-") {
        name.to_string()
    } else {
        format!("sigint-{name}")
    };
    let crate_dir = Path::new("crates").join(&crate_name);

    if crate_dir.exists() {
        bail!("Crate directory already exists: {}", crate_dir.display());
    }

    // Create directory structure
    let src_dir = crate_dir.join("src").join("tools");
    fs::create_dir_all(&src_dir)?;

    // Write Cargo.toml
    let cargo_toml = format!(
        r#"[package]
name = "{crate_name}"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true

[dependencies]
sigint-plugin = {{ workspace = true }}
sigint-tools = {{ workspace = true }}
sigint-core = {{ workspace = true }}
sigint-llm = {{ workspace = true }}
async-trait = {{ workspace = true }}
serde_json = {{ workspace = true }}
inventory = {{ workspace = true }}
"#
    );
    fs::write(crate_dir.join("Cargo.toml"), cargo_toml)?;

    // Write src/lib.rs
    let lib_rs = "mod tools;\npub use tools::*;\n";
    fs::write(crate_dir.join("src").join("lib.rs"), lib_rs)?;

    // Write src/tools/mod.rs
    let tools_mod = "mod example;\npub use example::*;\n";
    fs::write(src_dir.join("mod.rs"), tools_mod)?;

    // Write src/tools/example.rs
    let example_tool = format!(
        r#"//! Example plugin tool — replace with your own implementation.

use async_trait::async_trait;
use serde_json::{{json, Value}};
use sigint_plugin::register_tool;
use sigint_tools::tool::Tool;
use sigint_tools::result::ToolResult;
use sigint_tools::error::{{Result, ToolError}};
use sigint_core::types::ToolRisk;
use sigint_llm::ToolDefinition;
use std::time::Duration;

pub struct ExamplePluginTool;

impl ExamplePluginTool {{
    pub fn new() -> Self {{
        Self
    }}
}}

#[async_trait]
impl Tool for ExamplePluginTool {{
    fn name(&self) -> &str {{
        "{crate_name}_example"
    }}

    fn description(&self) -> &str {{
        "An example plugin tool — replace with your own implementation"
    }}

    fn definition(&self) -> ToolDefinition {{
        ToolDefinition::function(
            "{crate_name}_example",
            "An example plugin tool",
            json!({{
                "type": "object",
                "properties": {{
                    "input": {{ "type": "string", "description": "Input to process" }}
                }},
                "required": ["input"]
            }}),
        )
    }}

    async fn execute(&self, args: Value) -> Result<ToolResult> {{
        let input = args["input"]
            .as_str()
            .ok_or_else(|| ToolError::MissingArgument("input".to_string()))?;
        Ok(ToolResult {{
            stdout: format!("Example plugin processed: {{input}}"),
            stderr: String::new(),
            exit_code: 0,
            duration: Duration::from_millis(1),
            structured_data: None,
            status: Default::default(),
            truncation: None,
        }})
    }}

    fn risk_level(&self) -> ToolRisk {{
        ToolRisk::Low
    }}
}}

register_tool!(ExamplePluginTool);
"#
    );
    fs::write(src_dir.join("example.rs"), example_tool)?;

    println!("Created plugin crate: {}", crate_dir.display());
    println!();
    println!("Next steps:");
    println!("  1. Add \"{crate_name}\" to workspace members in Cargo.toml");
    println!("  2. Add `{crate_name} = {{ workspace = true }}` to workspace.dependencies");
    println!("  3. Add `{crate_name} = {{ workspace = true }}` to crates/sigint-cli/Cargo.toml");
    println!("  4. Run `cargo build` to verify");

    Ok(())
}
