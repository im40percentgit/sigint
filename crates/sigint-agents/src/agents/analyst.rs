//! AnalystAgent — security findings correlation and severity classification.
//!
//! @decision DEC-AGENT-010
//! @title Analyst allowed tools: shell only
//! @status accepted
//! @rationale The Analyst primarily reasons over tool output already captured in
//! TaskContext. Shell access is retained for ad-hoc verification — e.g. querying
//! a CVE database, running a targeted check to confirm a finding, or extracting
//! structured data from raw output with grep/awk. nmap is excluded because the
//! Analyst should not be initiating new scans; that is the Executor's domain.

use crate::{agent::Agent, role::AgentRole};

/// Correlates tool output into structured security findings with severity ratings.
///
/// The Analyst is the fourth agent in the pipeline. It receives raw tool output
/// from the Executor via `TaskContext` and produces structured findings (title,
/// description, severity, evidence) suitable for inclusion in the final report.
pub struct AnalystAgent {
    allowed_tools: Vec<String>,
}

impl AnalystAgent {
    pub fn new() -> Self {
        Self {
            allowed_tools: vec!["shell".to_string()],
        }
    }
}

impl Default for AnalystAgent {
    fn default() -> Self {
        Self::new()
    }
}

impl Agent for AnalystAgent {
    fn name(&self) -> &str {
        "analyst"
    }

    fn role(&self) -> AgentRole {
        AgentRole::Analyst
    }

    fn system_prompt(&self) -> &str {
        "You are a senior security analyst specialising in vulnerability assessment \
         and finding classification. You receive raw tool output from a penetration \
         test and convert it into structured, actionable findings. \
         \n\n\
         For each finding you identify:\n\
         1. Title — a concise, descriptive name (e.g. 'Unauthenticated Redis Exposure').\n\
         2. Description — what the vulnerability is, why it matters, and how it was found.\n\
         3. Severity — Critical, High, Medium, Low, or Info — following CVSS v3 guidelines.\n\
         4. Evidence — the exact tool output or observation that proves the finding.\n\
         5. Asset — the specific host, port, or URL affected.\n\
         \n\
         You have shell access for targeted verification (CVE lookups, banner grabs, \
         lightweight confirmations). Do not initiate new broad scans — that is the \
         Executor's role.\n\
         \n\
         Be precise. Avoid false positives. If the evidence is ambiguous, classify \
         the finding as Info and note what additional evidence would confirm it."
    }

    fn allowed_tools(&self) -> &[String] {
        &self.allowed_tools
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyst_identity() {
        let agent = AnalystAgent::new();
        assert_eq!(agent.name(), "analyst");
        assert_eq!(agent.role(), AgentRole::Analyst);
    }

    #[test]
    fn analyst_system_prompt_nonempty_and_relevant() {
        let agent = AnalystAgent::new();
        let prompt = agent.system_prompt();
        assert!(!prompt.is_empty());
        assert!(
            prompt.to_lowercase().contains("finding")
                || prompt.to_lowercase().contains("vulnerabilit"),
            "prompt should mention findings/vulnerabilities: {prompt}"
        );
        assert!(
            prompt.to_lowercase().contains("severity"),
            "prompt should mention severity: {prompt}"
        );
    }

    #[test]
    fn analyst_allowed_tools() {
        let agent = AnalystAgent::new();
        let tools = agent.allowed_tools();
        assert!(
            tools.contains(&"shell".to_string()),
            "analyst must have shell"
        );
        assert!(
            !tools.contains(&"nmap".to_string()),
            "analyst must not have nmap"
        );
        assert_eq!(tools.len(), 1, "analyst should have exactly 1 tool");
    }

    #[test]
    fn analyst_default_equals_new() {
        let a = AnalystAgent::new();
        let b = AnalystAgent::default();
        assert_eq!(a.name(), b.name());
        assert_eq!(a.role(), b.role());
    }
}
