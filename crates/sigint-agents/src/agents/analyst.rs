//! AnalystAgent — security findings correlation and severity classification.
//!
//! @decision DEC-AGENT-010
//! @title Analyst allowed tools: shell + create_finding
//! @status accepted
//! @rationale The Analyst primarily reasons over tool output already captured in
//! TaskContext. Shell access is retained for ad-hoc verification — e.g. querying
//! a CVE database, running a targeted check to confirm a finding, or extracting
//! structured data from raw output with grep/awk. nmap is excluded because the
//! Analyst should not be initiating new scans; that is the Executor's domain.
//! `create_finding` is added so the Analyst records each vulnerability as a
//! structured Finding (DEC-FINDING-001) rather than leaving them as prose text.

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
            allowed_tools: vec!["shell".to_string(), "create_finding".to_string()],
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
         IMPORTANT: For every vulnerability or misconfiguration you identify, you MUST \
         call the create_finding tool. Do not merely describe findings in text — use the \
         tool so they are recorded as structured data. Call it once per distinct finding.\n\
         \n\
         For each create_finding call, provide the core fields:\n\
         - title: a concise, descriptive name (e.g. 'Unauthenticated Redis Exposure')\n\
         - severity: critical / high / medium / low / info (CVSS v3 guidelines)\n\
         - description: what the vulnerability is, why it matters, and how it was found\n\
         - evidence: the exact tool output, command, or observation that proves the finding\n\
         - asset: the specific host, port, URL, or service affected\n\
         \n\
         Additionally, enrich every finding with these fields whenever possible:\n\
         - remediation: specific, actionable fix steps (e.g. 'Upgrade OpenSSL to 3.x, \
           disable TLS 1.0/1.1 in server config, rotate any exposed private keys'). \
           Always provide this — a finding without a remediation path has limited value.\n\
         - exploitability: how easily this can be exploited (e.g. 'publicly accessible \
           with no authentication required', 'requires local network access', \
           'requires valid user credentials'). Always provide this.\n\
         - impact: business or technical impact if exploited (e.g. 'full database \
           read/write access', 'remote code execution as www-data', \
           'credential theft affecting all users'). Always provide this.\n\
         - cvss_score: CVSS v3.1 base score (0.0-10.0). Provide when you can make a \
           confident assessment from the available evidence. Use standard CVSS v3.1 \
           scoring criteria: attack vector, complexity, privileges required, user \
           interaction, confidentiality/integrity/availability impact.\n\
         - evidence_ref: if a specific scan record UUID was mentioned in your context \
           as the source of the evidence, include it here so findings can be traced \
           back to the exact tool invocation.\n\
         \n\
         You also have shell access for targeted verification (CVE lookups, banner grabs, \
         lightweight confirmations). Do not initiate new broad scans — that is the \
         Executor's role.\n\
         \n\
         Be precise. Avoid false positives. If the evidence is ambiguous, classify \
         the finding as info and note what additional evidence would confirm it."
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
    fn analyst_system_prompt_includes_enrichment_instructions() {
        let agent = AnalystAgent::new();
        let prompt = agent.system_prompt();
        assert!(
            prompt.contains("remediation"),
            "prompt should instruct Analyst to provide remediation: {prompt}"
        );
        assert!(
            prompt.contains("exploitability"),
            "prompt should instruct Analyst to provide exploitability: {prompt}"
        );
        assert!(
            prompt.contains("impact"),
            "prompt should instruct Analyst to provide impact: {prompt}"
        );
        assert!(
            prompt.contains("cvss_score"),
            "prompt should instruct Analyst to provide cvss_score: {prompt}"
        );
        assert!(
            prompt.contains("evidence_ref"),
            "prompt should instruct Analyst to provide evidence_ref: {prompt}"
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
            tools.contains(&"create_finding".to_string()),
            "analyst must have create_finding"
        );
        assert!(
            !tools.contains(&"nmap_scan".to_string()),
            "analyst must not have nmap_scan"
        );
        assert_eq!(tools.len(), 2, "analyst should have exactly 2 tools: shell + create_finding");
    }

    #[test]
    fn analyst_default_equals_new() {
        let a = AnalystAgent::new();
        let b = AnalystAgent::default();
        assert_eq!(a.name(), b.name());
        assert_eq!(a.role(), b.role());
    }
}
