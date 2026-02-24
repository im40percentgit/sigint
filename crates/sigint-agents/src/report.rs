//! ScanReport — the final output of a completed agent pipeline run.
//!
//! Produced by the Orchestrator after all five agents have completed.
//! Contains the target, the full TaskContext (with all agent outputs and
//! findings), and the Reporter agent's synthesized summary.
//!
//! @decision DEC-AGENT-012
//! @title ScanReport is a plain data struct with Display; no builder pattern
//! @status accepted
//! @rationale The report is always constructed in a single step at the end of
//! `Orchestrator::run_scan` — there is no incremental assembly phase that would
//! benefit from a builder. A plain struct with `new()` keeps construction
//! explicit and avoids the builder complexity tax. `fmt::Display` is the
//! primary rendering path because the primary consumer is the CLI (`sigint scan`
//! printing to stdout); structured access to `context.findings` and
//! `context.agent_outputs` remains available for programmatic callers.

use std::fmt;

use crate::context::TaskContext;

/// The structured output of a completed SIGINT scan pipeline.
///
/// Created by `Orchestrator::run_scan` after the Reporter agent produces its
/// final summary. Callers can display the report via `fmt::Display` or inspect
/// individual fields (`context.agent_outputs`, `context.findings`) for
/// programmatic use.
#[derive(Debug)]
pub struct ScanReport {
    /// The primary scan target (hostname, IP, or CIDR range).
    pub target: String,
    /// Full accumulated engagement context from all five agent turns.
    pub context: TaskContext,
    /// The Reporter agent's synthesized penetration test report.
    pub summary: String,
}

impl ScanReport {
    /// Create a new `ScanReport`.
    pub fn new(target: String, context: TaskContext, summary: String) -> Self {
        Self { target, context, summary }
    }
}

impl fmt::Display for ScanReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "╔══════════════════════════════════════════════════════╗")?;
        writeln!(f, "║              SIGINT SCAN REPORT                     ║")?;
        writeln!(f, "╚══════════════════════════════════════════════════════╝")?;
        writeln!(f)?;
        writeln!(f, "Target: {}", self.target)?;
        writeln!(f)?;

        // Tool execution count from all scan_results collected.
        let tool_count = self.context.scan_results.len();
        if tool_count > 0 {
            writeln!(f, "Tool executions: {tool_count}")?;
            writeln!(f)?;
        }

        // Findings summary.
        let finding_count = self.context.findings.len();
        if finding_count > 0 {
            writeln!(f, "Findings: {finding_count}")?;
            for finding in &self.context.findings {
                writeln!(f, "  - [{:?}] {}", finding.severity, finding.title)?;
            }
            writeln!(f)?;
        }

        writeln!(f, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")?;
        writeln!(f, "SUMMARY")?;
        writeln!(f, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")?;
        writeln!(f)?;
        write!(f, "{}", self.summary)?;

        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::TaskContext;

    #[test]
    fn display_contains_target() {
        let ctx = TaskContext::new("example.com");
        let report = ScanReport::new("example.com".into(), ctx, "Summary text here.".into());
        let output = report.to_string();
        assert!(output.contains("example.com"), "report should contain the target: {output}");
    }

    #[test]
    fn display_contains_summary() {
        let ctx = TaskContext::new("10.0.0.1");
        let report = ScanReport::new("10.0.0.1".into(), ctx, "Critical RCE found.".into());
        let output = report.to_string();
        assert!(output.contains("Critical RCE found."), "report should contain summary: {output}");
    }

    #[test]
    fn display_contains_sigint_header() {
        let ctx = TaskContext::new("target.local");
        let report = ScanReport::new("target.local".into(), ctx, "Clean scan.".into());
        let output = report.to_string();
        assert!(
            output.contains("SIGINT"),
            "report header should mention SIGINT: {output}"
        );
    }

    #[test]
    fn display_no_tool_count_when_empty_scan_results() {
        let ctx = TaskContext::new("example.com");
        let report = ScanReport::new("example.com".into(), ctx, "Done.".into());
        let output = report.to_string();
        // When scan_results is empty, tool execution line should be absent.
        assert!(
            !output.contains("Tool executions:"),
            "should not show tool count when none: {output}"
        );
    }

    #[test]
    fn display_no_findings_section_when_empty() {
        let ctx = TaskContext::new("example.com");
        let report = ScanReport::new("example.com".into(), ctx, "Done.".into());
        let output = report.to_string();
        assert!(
            !output.contains("Findings:"),
            "should not show findings section when none: {output}"
        );
    }
}
