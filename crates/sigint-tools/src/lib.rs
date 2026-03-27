//! sigint-tools — Sandboxed pentest tool wrappers for the SIGINT agent layer.
//!
//! Provides the `Tool` trait and concrete implementations for nmap, shell,
//! gobuster, nikto, nuclei, feroxbuster, and seven akaei SDR tools that the
//! agent layer uses to give LLMs controlled access to external tools.
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

pub mod akaei;
pub mod error;
pub mod feroxbuster;
pub mod finding;
pub mod gobuster;
pub mod nikto;
pub mod nmap;
pub mod nuclei;
pub mod result;
pub mod shell;
pub mod tool;

pub use akaei::{
    AkaeiAnalyzeTool, AkaeiAuditTool, AkaeiDecodeTool, AkaeiFingerprintTool, AkaeiFreqdbTool,
    AkaeiScanTool, AkaeiSweepTool,
};
pub use error::{Result, ToolError};
pub use feroxbuster::FeroxbusterTool;
// CreateFindingTool is NOT in all_executor_tools() — it requires a FindingCollector
// at construction and is registered separately by the orchestrator per scan.
pub use finding::{new_finding_collector, CreateFindingTool, FindingCollector};
pub use gobuster::GobusterTool;
pub use nikto::NiktoTool;
pub use nmap::NmapTool;
pub use nuclei::NucleiTool;
pub use result::{ScanStatus, ToolResult, TruncationInfo};
pub use shell::ShellTool;
pub use tool::Tool;

/// Return all executor tools for registration with ToolRegistry.
///
/// This is the single source of truth for the tool catalog — both CLI and
/// web scan handlers use this to populate their registries.
///
/// @decision DEC-TOOL-004
/// @title all_executor_tools() is the canonical tool catalog
/// @status accepted
/// @rationale Previously, each call site (CLI, web) registered tools individually,
/// risking drift (CLI gets a new tool, web doesn't). Centralising registration here
/// ensures both consumers always have the same tool set without any sigint-tools →
/// sigint-agents circular dependency.
pub fn all_executor_tools() -> Vec<Box<dyn Tool>> {
    vec![
        // Network pentest tools (sandboxed)
        Box::new(NmapTool),
        Box::new(ShellTool),
        Box::new(GobusterTool),
        Box::new(NiktoTool),
        Box::new(NucleiTool),
        Box::new(FeroxbusterTool),
        // akaei SDR tools (direct process — USB device access required)
        Box::new(AkaeiSweepTool),
        Box::new(AkaeiScanTool),
        Box::new(AkaeiDecodeTool),
        Box::new(AkaeiAnalyzeTool),
        Box::new(AkaeiAuditTool),
        Box::new(AkaeiFingerprintTool),
        Box::new(AkaeiFreqdbTool),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_executor_tools_returns_thirteen_tools() {
        let tools = all_executor_tools();
        assert_eq!(tools.len(), 13);
        let names: Vec<&str> = tools.iter().map(|t| t.name()).collect();
        // Network tools
        assert!(names.contains(&"nmap_scan"));
        assert!(names.contains(&"shell"));
        assert!(names.contains(&"gobuster_scan"));
        assert!(names.contains(&"nikto_scan"));
        assert!(names.contains(&"nuclei_scan"));
        assert!(names.contains(&"feroxbuster_scan"));
        // akaei SDR tools
        assert!(names.contains(&"akaei_sweep"));
        assert!(names.contains(&"akaei_scan"));
        assert!(names.contains(&"akaei_decode"));
        assert!(names.contains(&"akaei_analyze"));
        assert!(names.contains(&"akaei_audit"));
        assert!(names.contains(&"akaei_fingerprint"));
        assert!(names.contains(&"akaei_freqdb"));
    }
}
