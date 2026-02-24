//! sigint-tools — Sandboxed pentest tool wrappers for the SIGINT agent layer.
//!
//! Provides the `Tool` trait and concrete implementations (NmapTool, ShellTool)
//! that the agent layer uses to give LLMs controlled access to external tools.
//!
//! # Architecture
//!
//! Each tool:
//! 1. Implements the `Tool` trait (async, object-safe via async_trait).
//! 2. Exposes a `definition()` returning a `ToolDefinition` for the LLM `tools` array.
//! 3. Executes inside a Linux namespace sandbox via sigint-sandbox profiles.
//! 4. Returns a `ToolResult` with stdout/stderr/exit_code/duration.
//!
//! @decision DEC-TOOL-003
//! @title Tool trait is the uniform interface for all sandboxed tool wrappers
//! @status accepted
//! @rationale See tool.rs for full rationale. The trait is re-exported here so
//! downstream crates only need `use sigint_tools::Tool` — no sub-module imports.

pub mod error;
pub mod nmap;
pub mod result;
pub mod shell;
pub mod tool;

pub use error::{ToolError, Result};
pub use nmap::NmapTool;
pub use result::ToolResult;
pub use shell::ShellTool;
pub use tool::Tool;
