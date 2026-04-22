//! sigint-tools — Sandboxed pentest tool wrappers for the SIGINT agent layer.
//!
//! Provides the `Tool` trait and concrete implementations for nmap, shell,
//! gobuster, nikto, nuclei, feroxbuster, sqlmap, ffuf, whatweb, hydra, wpscan,
//! testssl, hashcat, masscan, tshark, responder, msfconsole, linpeas,
//! enum4linux-ng, trivy, scout_suite, cloudsploit, and seven akaei SDR tools
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

pub mod akaei;
pub mod attack_plan;
pub mod cloudsploit;
pub mod enum4linux;
pub mod error;
pub mod feroxbuster;
pub mod ffuf;
pub mod finding;
pub mod gobuster;
pub mod hashcat;
pub mod hydra;
pub mod linpeas;
pub mod masscan;
pub mod msfconsole;
pub mod nikto;
pub mod nmap;
pub mod nuclei;
pub mod responder;
pub mod result;
pub mod scout_suite;
pub mod shell;
pub mod sqlmap;
pub mod testssl;
pub mod tool;
pub mod trivy;
pub mod tshark;
pub mod whatweb;
pub mod wpscan;

pub use akaei::{
    AkaeiAnalyzeTool, AkaeiAuditTool, AkaeiDecodeTool, AkaeiFingerprintTool, AkaeiFreqdbTool,
    AkaeiScanTool, AkaeiSweepTool,
};
// CreateAttackPlanTool is NOT in all_executor_tools() — it requires a PlanCollector
// at construction and is registered separately by the orchestrator per scan.
pub use attack_plan::{new_plan_collector, AttackStep, CreateAttackPlanTool, PlanCollector};
pub use cloudsploit::CloudsploitTool;
pub use enum4linux::Enum4linuxTool;
pub use error::{Result, ToolError};
pub use feroxbuster::FeroxbusterTool;
// CreateFindingTool is NOT in all_executor_tools() — it requires a FindingCollector
// at construction and is registered separately by the orchestrator per scan.
pub use ffuf::FfufTool;
pub use finding::{new_finding_collector, CreateFindingTool, FindingCollector};
pub use gobuster::GobusterTool;
pub use hashcat::HashcatTool;
pub use hydra::HydraTool;
pub use linpeas::LinpeasTool;
pub use masscan::MasscanTool;
pub use msfconsole::MsfconsoleTool;
pub use nikto::NiktoTool;
pub use nmap::NmapTool;
pub use nuclei::NucleiTool;
pub use responder::ResponderTool;
pub use result::{ScanStatus, ToolResult, TruncationInfo};
pub use scout_suite::ScoutSuiteTool;
pub use shell::ShellTool;
pub use sqlmap::SqlmapTool;
pub use testssl::TestsslTool;
pub use tool::Tool;
pub use trivy::TrivyTool;
pub use tshark::TsharkTool;
pub use whatweb::WhatwebTool;
pub use wpscan::WpscanTool;

/// Return all executor tools configured with per-tool output caps from `ToolsConfig`.
///
/// This is the preferred entry point — callers that have access to the loaded
/// config should use this so per-tool cap overrides take effect.
///
/// @decision DEC-TOOL-004
/// @title all_executor_tools() is the canonical tool catalog
/// @status accepted
/// @rationale Previously, each call site (CLI, web) registered tools individually,
/// risking drift (CLI gets a new tool, web doesn't). Centralising registration here
/// ensures both consumers always have the same tool set without any sigint-tools →
/// sigint-agents circular dependency.
pub fn all_executor_tools_with_config(
    tools_config: &sigint_core::config::ToolsConfig,
) -> Vec<Box<dyn Tool>> {
    vec![
        // Network pentest tools (sandboxed)
        Box::new(NmapTool::new().with_output_cap(tools_config.output_cap_for("nmap"))),
        Box::new(ShellTool::new().with_output_cap(tools_config.output_cap_for("shell"))),
        Box::new(GobusterTool::new().with_output_cap(tools_config.output_cap_for("gobuster"))),
        Box::new(NiktoTool::new().with_output_cap(tools_config.output_cap_for("nikto"))),
        Box::new(NucleiTool::new().with_output_cap(tools_config.output_cap_for("nuclei"))),
        Box::new(
            FeroxbusterTool::new().with_output_cap(tools_config.output_cap_for("feroxbuster")),
        ),
        Box::new(SqlmapTool::new().with_output_cap(tools_config.output_cap_for("sqlmap"))),
        Box::new(FfufTool::new().with_output_cap(tools_config.output_cap_for("ffuf"))),
        Box::new(WhatwebTool::new().with_output_cap(tools_config.output_cap_for("whatweb"))),
        Box::new(HydraTool::new().with_output_cap(tools_config.output_cap_for("hydra"))),
        Box::new(WpscanTool::new().with_output_cap(tools_config.output_cap_for("wpscan"))),
        Box::new(TestsslTool::new().with_output_cap(tools_config.output_cap_for("testssl"))),
        Box::new(HashcatTool::new().with_output_cap(tools_config.output_cap_for("hashcat"))),
        // Phase 15C network analysis tools
        Box::new(MasscanTool::new().with_output_cap(tools_config.output_cap_for("masscan"))),
        Box::new(TsharkTool::new().with_output_cap(tools_config.output_cap_for("tshark"))),
        Box::new(ResponderTool::new().with_output_cap(tools_config.output_cap_for("responder"))),
        // Phase 15D post-exploitation tools
        Box::new(MsfconsoleTool::new().with_output_cap(tools_config.output_cap_for("msfconsole"))),
        Box::new(LinpeasTool::new().with_output_cap(tools_config.output_cap_for("linpeas"))),
        Box::new(Enum4linuxTool::new().with_output_cap(tools_config.output_cap_for("enum4linux"))),
        // Phase 15E cloud/container security tools
        Box::new(TrivyTool::new().with_output_cap(tools_config.output_cap_for("trivy"))),
        Box::new(ScoutSuiteTool::new().with_output_cap(tools_config.output_cap_for("scout_suite"))),
        Box::new(
            CloudsploitTool::new().with_output_cap(tools_config.output_cap_for("cloudsploit")),
        ),
        // akaei SDR tools (direct process — USB device access required, no sandbox output caps)
        Box::new(AkaeiSweepTool),
        Box::new(AkaeiScanTool),
        Box::new(AkaeiDecodeTool),
        Box::new(AkaeiAnalyzeTool),
        Box::new(AkaeiAuditTool),
        Box::new(AkaeiFingerprintTool),
        Box::new(AkaeiFreqdbTool),
    ]
}

/// Return all executor tools with default output caps.
///
/// Backward-compatible wrapper for callers that don't have a `ToolsConfig`.
/// Delegates to `all_executor_tools_with_config` with the default config.
pub fn all_executor_tools() -> Vec<Box<dyn Tool>> {
    all_executor_tools_with_config(&sigint_core::config::ToolsConfig::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_executor_tools_returns_twenty_nine_tools() {
        let tools = all_executor_tools();
        assert_eq!(tools.len(), 29);
        let names: Vec<&str> = tools.iter().map(|t| t.name()).collect();
        // Network pentest tools
        assert!(names.contains(&"nmap_scan"));
        assert!(names.contains(&"shell"));
        assert!(names.contains(&"gobuster_scan"));
        assert!(names.contains(&"nikto_scan"));
        assert!(names.contains(&"nuclei_scan"));
        assert!(names.contains(&"feroxbuster_scan"));
        assert!(names.contains(&"sqlmap_scan"));
        assert!(names.contains(&"ffuf_scan"));
        assert!(names.contains(&"whatweb_scan"));
        // Phase 15B auth/exploitation tools
        assert!(names.contains(&"hydra_scan"));
        assert!(names.contains(&"wpscan_scan"));
        assert!(names.contains(&"testssl_scan"));
        assert!(names.contains(&"hashcat_crack"));
        // Phase 15C network analysis tools
        assert!(names.contains(&"masscan_scan"));
        assert!(names.contains(&"tshark_capture"));
        assert!(names.contains(&"responder_poison"));
        // Phase 15D post-exploitation tools
        assert!(names.contains(&"msf_exploit"));
        assert!(names.contains(&"linpeas_enum"));
        assert!(names.contains(&"enum4linux_scan"));
        // Phase 15E cloud/container security tools
        assert!(names.contains(&"trivy_scan"));
        assert!(names.contains(&"scout_suite_scan"));
        assert!(names.contains(&"cloudsploit_scan"));
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
