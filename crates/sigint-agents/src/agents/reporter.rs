//! ReporterAgent — penetration test report generation specialist.
//!
//! @decision DEC-AGENT-011
//! @title Reporter has no tools — synthesis only
//! @status accepted
//! @rationale The Reporter's job is to synthesise all prior agent outputs into a
//! coherent, human-readable report. Like the Strategist, it performs pure text
//! reasoning with no need for tool access. Keeping it tool-free prevents it from
//! running additional scans at report time (which would extend engagement duration
//! unpredictably) and ensures the report reflects a fixed point-in-time snapshot
//! of what was actually found during the engagement.

use crate::{agent::Agent, role::AgentRole};

/// Synthesises all agent outputs into a structured penetration test report.
///
/// The Reporter is the final agent in the pipeline. It receives the complete
/// `TaskContext` — including Researcher, Strategist, Executor, and Analyst
/// outputs — and produces a professional penetration test report suitable for
/// delivery to the client.
pub struct ReporterAgent {
    allowed_tools: Vec<String>,
}

impl ReporterAgent {
    pub fn new() -> Self {
        Self {
            allowed_tools: vec![],
        }
    }
}

impl Default for ReporterAgent {
    fn default() -> Self {
        Self::new()
    }
}

impl Agent for ReporterAgent {
    fn name(&self) -> &str {
        "reporter"
    }

    fn role(&self) -> AgentRole {
        AgentRole::Reporter
    }

    fn system_prompt(&self) -> &str {
        "You are a professional penetration test report writer. You receive the \
         complete output of a penetration test engagement — reconnaissance findings, \
         attack strategy, tool execution results, and security analysis — and produce \
         a polished, professional report. \
         \n\n\
         Report structure:\n\
         1. Executive Summary — high-level overview for non-technical stakeholders. \
            What was tested, when, and what was found. Key risk rating.\n\
         2. Scope and Methodology — target, timeframe, tools used, approach taken.\n\
         3. Findings — each finding presented with: title, severity, description, \
            evidence, affected asset, and remediation recommendation.\n\
         4. Risk Summary — table of all findings sorted by severity.\n\
         5. Remediation Roadmap — prioritised list of fixes with effort estimates.\n\
         6. Conclusion — overall security posture assessment.\n\
         \n\
         Writing standards:\n\
         - Use clear, professional language accessible to both technical and \
           non-technical readers.\n\
         - Every finding must include concrete evidence (command output, screenshots \
           described in text, or specific observable behaviour).\n\
         - Remediation recommendations must be specific and actionable — not generic \
           advice like 'apply patches'.\n\
         - Use Markdown formatting for headings, tables, and code blocks."
    }

    fn allowed_tools(&self) -> &[String] {
        &self.allowed_tools
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reporter_identity() {
        let agent = ReporterAgent::new();
        assert_eq!(agent.name(), "reporter");
        assert_eq!(agent.role(), AgentRole::Reporter);
    }

    #[test]
    fn reporter_system_prompt_nonempty_and_relevant() {
        let agent = ReporterAgent::new();
        let prompt = agent.system_prompt();
        assert!(!prompt.is_empty());
        assert!(
            prompt.to_lowercase().contains("report"),
            "prompt should mention report: {prompt}"
        );
        assert!(
            prompt.to_lowercase().contains("finding") || prompt.to_lowercase().contains("remediation"),
            "prompt should mention findings or remediation: {prompt}"
        );
    }

    #[test]
    fn reporter_has_no_tools() {
        let agent = ReporterAgent::new();
        assert!(
            agent.allowed_tools().is_empty(),
            "reporter must have no tools"
        );
    }

    #[test]
    fn reporter_default_equals_new() {
        let a = ReporterAgent::new();
        let b = ReporterAgent::default();
        assert_eq!(a.name(), b.name());
        assert_eq!(a.role(), b.role());
    }
}
