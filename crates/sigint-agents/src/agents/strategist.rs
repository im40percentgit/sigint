//! StrategistAgent — attack planning and methodology selection specialist.
//!
//! @decision DEC-AGENT-008
//! @title Strategist has no tools — reasoning only
//! @status accepted
//! @rationale The Strategist's job is pure reasoning: analysing recon output and
//! producing a prioritised attack plan. Giving it tools would encourage premature
//! execution before the strategy is fully formed. Keeping it tool-free enforces
//! the pipeline discipline (Researcher gathers, Strategist plans, Executor runs)
//! and keeps the Strategist's context window clear of tool-call overhead.

use crate::{agent::Agent, role::AgentRole};

/// Analyses reconnaissance output and produces a prioritised attack strategy.
///
/// The Strategist is the second agent in the pipeline. It receives the
/// Researcher's findings via `TaskContext` and reasons about which attack
/// vectors are most promising, producing a concrete plan for the Executor.
pub struct StrategistAgent {
    allowed_tools: Vec<String>,
}

impl StrategistAgent {
    pub fn new() -> Self {
        Self {
            allowed_tools: vec![],
        }
    }
}

impl Default for StrategistAgent {
    fn default() -> Self {
        Self::new()
    }
}

impl Agent for StrategistAgent {
    fn name(&self) -> &str {
        "strategist"
    }

    fn role(&self) -> AgentRole {
        AgentRole::Strategist
    }

    fn system_prompt(&self) -> &str {
        "You are a senior penetration tester and attack strategist. \
         You do not execute tools — your role is pure analysis and planning. \
         \n\n\
         Given reconnaissance findings from the Researcher, you must:\n\
         1. Identify the most promising attack vectors (weak services, outdated software, \
            misconfigurations, default credentials, exposed admin interfaces).\n\
         2. Prioritise vectors by estimated likelihood of success and potential impact.\n\
         3. Produce a concrete, ordered list of tool invocations for the Executor to carry out.\n\
         4. Specify exact tool names and arguments where possible (e.g. nmap -sV -p 443, \
            or shell to run gobuster with a wordlist).\n\
         \n\
         Your output is a structured attack plan. Be specific — vague plans waste the \
         Executor's time. Consider OWASP Top 10, PTES methodology, and MITRE ATT&CK \
         when selecting attack vectors.\n\
         \n\
         ## Escalation Markers\n\
         \n\
         When your plan includes actions beyond passive reconnaissance, you MUST emit an \
         escalation marker on its own line to signal the required access level:\n\
         \n\
         - If recommending active exploitation (running exploits, attempting authentication \
           bypass, injecting payloads, brute-forcing credentials, triggering vulnerabilities):\n\
           emit exactly: ESCALATION: exploitation\n\
         \n\
         - If recommending post-exploitation actions (lateral movement, privilege escalation, \
           data exfiltration, installing persistence, pivoting to internal networks):\n\
           emit exactly: ESCALATION: post-exploitation\n\
         \n\
         Emit the highest applicable tier only. If your plan is purely reconnaissance \
         (port scanning, service enumeration, OSINT, directory brute-force for discovery), \
         do not emit any escalation marker."
    }

    fn allowed_tools(&self) -> &[String] {
        &self.allowed_tools
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strategist_identity() {
        let agent = StrategistAgent::new();
        assert_eq!(agent.name(), "strategist");
        assert_eq!(agent.role(), AgentRole::Strategist);
    }

    #[test]
    fn strategist_system_prompt_nonempty_and_relevant() {
        let agent = StrategistAgent::new();
        let prompt = agent.system_prompt();
        assert!(!prompt.is_empty());
        assert!(
            prompt.to_lowercase().contains("attack") || prompt.to_lowercase().contains("strateg"),
            "prompt should mention attack strategy: {prompt}"
        );
        assert!(
            prompt.to_lowercase().contains("plan") || prompt.to_lowercase().contains("prioritis"),
            "prompt should mention planning: {prompt}"
        );
    }

    #[test]
    fn strategist_has_no_tools() {
        let agent = StrategistAgent::new();
        assert!(
            agent.allowed_tools().is_empty(),
            "strategist must have no tools"
        );
    }

    #[test]
    fn strategist_default_equals_new() {
        let a = StrategistAgent::new();
        let b = StrategistAgent::default();
        assert_eq!(a.name(), b.name());
        assert_eq!(a.role(), b.role());
    }

    #[test]
    fn strategist_prompt_includes_escalation_instructions() {
        let agent = StrategistAgent::new();
        let prompt = agent.system_prompt();

        assert!(
            prompt.contains("ESCALATION: exploitation"),
            "prompt should contain exploitation escalation marker instruction: {prompt}"
        );
        assert!(
            prompt.contains("ESCALATION: post-exploitation"),
            "prompt should contain post-exploitation escalation marker instruction: {prompt}"
        );
        assert!(
            prompt.to_lowercase().contains("escalation"),
            "prompt should mention escalation: {prompt}"
        );
        // Verify the instructions distinguish the two tiers
        assert!(
            prompt.contains("lateral movement")
                || prompt.contains("privilege escalation")
                || prompt.contains("post-exploitation"),
            "prompt should describe post-exploitation actions: {prompt}"
        );
        assert!(
            prompt.contains("exploit") || prompt.contains("authentication bypass"),
            "prompt should describe exploitation actions: {prompt}"
        );
    }
}
