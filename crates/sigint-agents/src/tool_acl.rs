//! Static minimum-risk ACL for all first-party tool names.
//!
//! `Tool::risk_level()` is self-reported by each tool implementation. A plugin
//! or carelessly authored first-party tool can declare `ToolRisk::Low` while
//! doing destructive things; with `auto_approve = "low"` (the documented
//! default) it would bypass the approval gate entirely.
//!
//! This module provides a policy layer on top of self-reported risk: every
//! known first-party tool name has a static minimum risk that cannot be
//! undercut by the tool's own `risk_level()` return value. The approval gate
//! in `loop_engine` calls `effective_risk(name, tool.risk_level())` and uses
//! the result — whichever value (ACL minimum or self-reported) is higher wins.
//!
//! For tools not in the registry (third-party plugins, future additions),
//! `required_risk()` returns `None` and `effective_risk()` defaults to
//! `ToolRisk::High` — unknown tools are treated as maximally risky until a
//! human adds them to this table.
//!
//! @decision DEC-AGENT-TOOL-ACL-001
//! @title Static ACL registry enforces minimum risk for known tools
//! @status accepted
//! @rationale Self-reported risk levels are insufficient for security-sensitive
//! approval gating: any tool author (including LLM-generated plugin code) can
//! return ToolRisk::Low. A static table mapping tool name → minimum acceptable
//! risk level provides a policy floor that survives changes to individual tool
//! implementations. The table is in source code, so additions go through code
//! review. Unknown tools default to High — fail-secure over fail-open.

use sigint_core::types::ToolRisk;

/// Return the policy-required minimum risk for a known first-party tool name,
/// or `None` if the tool is not in the registry.
///
/// The returned value is a *floor*: `effective_risk` will never return
/// something lower than this. Tools are free to self-report a *higher* risk,
/// and `effective_risk` will honour that.
///
/// Tool names must match `Tool::name()` exactly (as returned by the trait
/// implementation). These were verified against the source files in
/// `crates/sigint-tools/src/` on 2026-04-22.
pub fn required_risk(tool_name: &str) -> Option<ToolRisk> {
    match tool_name {
        // ── Read-only / passive recon ──────────────────────────────────────
        "nmap_scan" => Some(ToolRisk::Low),
        "testssl_scan" => Some(ToolRisk::Low),
        "whatweb_scan" => Some(ToolRisk::Low),
        "trivy_scan" => Some(ToolRisk::Low),
        "create_attack_plan" => Some(ToolRisk::Low),
        "create_finding" => Some(ToolRisk::Low),

        // ── Active scanning (generates traffic, may trigger IDS) ───────────
        "gobuster_scan" => Some(ToolRisk::Medium),
        "ffuf_scan" => Some(ToolRisk::Medium),
        "feroxbuster_scan" => Some(ToolRisk::Medium),
        "masscan_scan" => Some(ToolRisk::Medium),
        "enum4linux_scan" => Some(ToolRisk::Medium),
        "hashcat_crack" => Some(ToolRisk::Medium),
        "linpeas_enum" => Some(ToolRisk::Medium),
        "cloudsploit_scan" => Some(ToolRisk::Medium),
        "scout_suite_scan" => Some(ToolRisk::Medium),
        "wpscan_scan" => Some(ToolRisk::Medium),

        // ── High-risk / exploitation ───────────────────────────────────────
        //
        // nikto: active web scanner known to cause DoS on fragile targets.
        "nikto_scan" => Some(ToolRisk::High),
        // sqlmap: actively attempts SQL injection; can corrupt databases.
        "sqlmap_scan" => Some(ToolRisk::High),
        // hydra: credential brute-force; triggers account lockouts.
        "hydra_scan" => Some(ToolRisk::High),
        // msf_exploit: direct exploitation framework.
        "msf_exploit" => Some(ToolRisk::High),
        // nuclei: executes Go templates that can perform arbitrary HTTP
        // requests; LLM-controllable template path is a code-execution vector
        // (finding #5). Self-reports Medium but policy floor is High.
        "nuclei_scan" => Some(ToolRisk::High),
        // shell: arbitrary shell command execution inside sandbox; primary
        // pivot target for prompt-injection attacks (finding #13).
        "shell" => Some(ToolRisk::High),
        // tshark: packet capture; reads all network traffic on the interface.
        "tshark_capture" => Some(ToolRisk::High),
        // responder: network poisoning (LLMNR/NBT-NS); actively disrupts
        // legitimate traffic on the segment.
        "responder_poison" => Some(ToolRisk::High),

        // Unknown tool — not in first-party registry.
        _ => None,
    }
}

/// Return the effective risk for a tool call, taking the maximum of the
/// policy-required minimum and the tool's self-reported value.
///
/// For unknown tools (not in the static registry), defaults to `ToolRisk::High`
/// — fail-secure: require human approval until the tool is reviewed and added
/// to the registry.
///
/// # Examples
///
/// ```
/// use sigint_agents::tool_acl::effective_risk;
/// use sigint_core::types::ToolRisk;
///
/// // ACL floor wins when self-reported is lower (nuclei self-reports Medium).
/// assert_eq!(effective_risk("nuclei_scan", ToolRisk::Medium), ToolRisk::High);
///
/// // Self-reported wins when higher than floor (nmap self-reports Low but
/// // hypothetically could self-report Medium — that Medium would be kept).
/// assert_eq!(effective_risk("nmap_scan", ToolRisk::Medium), ToolRisk::Medium);
///
/// // Unknown tool defaults to High regardless of self-reported value.
/// assert_eq!(effective_risk("unknown_plugin", ToolRisk::Low), ToolRisk::High);
/// ```
pub fn effective_risk(tool_name: &str, self_reported: ToolRisk) -> ToolRisk {
    match required_risk(tool_name) {
        Some(minimum) => minimum.max(self_reported),
        // Unknown tool — default to High (fail-secure).
        None => ToolRisk::High,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigint_core::types::ToolRisk;

    // ── required_risk ─────────────────────────────────────────────────────────

    #[test]
    fn known_tool_returns_required_risk() {
        assert_eq!(required_risk("nmap_scan"), Some(ToolRisk::Low));
        assert_eq!(required_risk("shell"), Some(ToolRisk::High));
        assert_eq!(required_risk("nuclei_scan"), Some(ToolRisk::High));
        assert_eq!(required_risk("gobuster_scan"), Some(ToolRisk::Medium));
        assert_eq!(required_risk("create_finding"), Some(ToolRisk::Low));
    }

    #[test]
    fn unknown_tool_returns_none() {
        assert_eq!(required_risk("not_a_real_tool"), None);
        assert_eq!(required_risk(""), None);
        assert_eq!(required_risk("rm_rf"), None);
    }

    // ── effective_risk ────────────────────────────────────────────────────────

    #[test]
    fn effective_risk_picks_max_of_two() {
        // ACL says Medium, self-reported Low → effective is Medium.
        assert_eq!(
            effective_risk("gobuster_scan", ToolRisk::Low),
            ToolRisk::Medium
        );
        // ACL says Low, self-reported Medium → effective is Medium.
        assert_eq!(
            effective_risk("nmap_scan", ToolRisk::Medium),
            ToolRisk::Medium
        );
    }

    #[test]
    fn effective_risk_self_reported_higher_wins() {
        // nmap ACL floor is Low; if it self-reports High, High wins.
        assert_eq!(effective_risk("nmap_scan", ToolRisk::High), ToolRisk::High);
    }

    #[test]
    fn effective_risk_unknown_tool_defaults_to_high() {
        assert_eq!(
            effective_risk("mystery_plugin", ToolRisk::Low),
            ToolRisk::High
        );
        assert_eq!(
            effective_risk("mystery_plugin", ToolRisk::Medium),
            ToolRisk::High
        );
        assert_eq!(
            effective_risk("mystery_plugin", ToolRisk::High),
            ToolRisk::High
        );
    }

    #[test]
    fn effective_risk_shell_is_high() {
        // shell must always be High regardless of any self-report.
        assert_eq!(effective_risk("shell", ToolRisk::Low), ToolRisk::High);
        assert_eq!(effective_risk("shell", ToolRisk::Medium), ToolRisk::High);
        assert_eq!(effective_risk("shell", ToolRisk::High), ToolRisk::High);
    }

    #[test]
    fn nuclei_acl_overrides_medium_self_report() {
        // nuclei self-reports Medium but ACL floor is High (finding #5).
        assert_eq!(
            effective_risk("nuclei_scan", ToolRisk::Medium),
            ToolRisk::High
        );
    }

    #[test]
    fn all_known_tools_have_entries() {
        // Verify every tool name that appears in the codebase is covered.
        // This acts as a regression test — if a tool is renamed without updating
        // the ACL, the tool's entry is silently removed and falls to the High
        // default. That's safe but should be noticed. The real check here is
        // that the known tool names we expect return Some(_), not None.
        let known = [
            "nmap_scan",
            "gobuster_scan",
            "ffuf_scan",
            "feroxbuster_scan",
            "nikto_scan",
            "sqlmap_scan",
            "hydra_scan",
            "masscan_scan",
            "msf_exploit",
            "nuclei_scan",
            "shell",
            "enum4linux_scan",
            "hashcat_crack",
            "linpeas_enum",
            "testssl_scan",
            "wpscan_scan",
            "whatweb_scan",
            "cloudsploit_scan",
            "scout_suite_scan",
            "trivy_scan",
            "tshark_capture",
            "responder_poison",
            "create_attack_plan",
            "create_finding",
        ];
        for name in &known {
            assert!(
                required_risk(name).is_some(),
                "tool '{name}' missing from ACL registry"
            );
        }
    }
}
