//! ResearcherAgent — OSINT and initial reconnaissance specialist.
//!
//! @decision DEC-AGENT-007
//! @title Researcher allowed tools: nmap + shell only
//! @status accepted
//! @rationale The Researcher phase focuses on information gathering, not
//! exploitation. nmap covers port/service enumeration; shell covers DNS, WHOIS,
//! certificate transparency, and other passive recon. Restricting to these two
//! tools prevents the Researcher from accidentally triggering exploit code
//! during the recon phase and keeps its context window focused on discovery.

use crate::{agent::Agent, role::AgentRole};

/// Performs open-source intelligence gathering and initial reconnaissance.
///
/// The Researcher is the first agent in the pipeline. It uses nmap and shell
/// commands to enumerate exposed services, subdomains, and technology stack
/// without prior knowledge of the target's internals.
pub struct ResearcherAgent {
    allowed_tools: Vec<String>,
}

impl ResearcherAgent {
    pub fn new() -> Self {
        Self {
            allowed_tools: vec!["nmap_scan".to_string(), "shell".to_string()],
        }
    }
}

impl Default for ResearcherAgent {
    fn default() -> Self {
        Self::new()
    }
}

impl Agent for ResearcherAgent {
    fn name(&self) -> &str {
        "researcher"
    }

    fn role(&self) -> AgentRole {
        AgentRole::Researcher
    }

    fn system_prompt(&self) -> &str {
        "You are an expert penetration tester specialising in OSINT and reconnaissance. \
         Your goal is to gather as much information as possible about the target without \
         triggering intrusion detection systems. \
         \n\n\
         You have access to the following tools:\n\
         - **nmap** (ALWAYS use this tool for port scanning and service detection — never run nmap via shell)\n\
         - **shell** (for DNS lookups with dig/host/nslookup, WHOIS queries, certificate inspection with openssl, \
           and text processing with grep/awk/jq/sed)\n\
         \n\n\
         CRITICAL RULES:\n\
         - For ANY port scanning or service detection, use the nmap tool directly. NEVER run nmap through shell.\n\
         - For DNS/WHOIS/certificate queries, use shell with: whois, dig, host, nslookup, openssl, curl.\n\
         - For processing output, use shell with: grep, awk, sed, jq, sort, uniq.\n\
         \n\n\
         Approach:\n\
         1. Start with passive techniques: use shell for WHOIS, DNS enumeration, certificate transparency logs.\n\
         2. Progress to active scanning: use the nmap tool for SYN scan of common ports, then service version detection.\n\
         3. Note every open port, service banner, and technology indicator.\n\
         4. Summarise your findings clearly so the Strategist can plan the next phase.\n\
         \n\
         Be methodical. Document every discovery with the exact command used and its raw output."
    }

    fn allowed_tools(&self) -> &[String] {
        &self.allowed_tools
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn researcher_identity() {
        let agent = ResearcherAgent::new();
        assert_eq!(agent.name(), "researcher");
        assert_eq!(agent.role(), AgentRole::Researcher);
    }

    #[test]
    fn researcher_system_prompt_nonempty_and_relevant() {
        let agent = ResearcherAgent::new();
        let prompt = agent.system_prompt();
        assert!(!prompt.is_empty());
        assert!(
            prompt.to_lowercase().contains("reconnaissance") || prompt.to_lowercase().contains("recon"),
            "prompt should mention recon: {prompt}"
        );
        assert!(
            prompt.to_lowercase().contains("osint") || prompt.to_lowercase().contains("open-source"),
            "prompt should mention OSINT: {prompt}"
        );
    }

    #[test]
    fn researcher_allowed_tools() {
        let agent = ResearcherAgent::new();
        let tools = agent.allowed_tools();
        assert!(tools.contains(&"nmap_scan".to_string()), "researcher must have nmap_scan");
        assert!(tools.contains(&"shell".to_string()), "researcher must have shell");
        assert_eq!(tools.len(), 2, "researcher should have exactly 2 tools");
    }

    #[test]
    fn researcher_default_equals_new() {
        let a = ResearcherAgent::new();
        let b = ResearcherAgent::default();
        assert_eq!(a.name(), b.name());
        assert_eq!(a.role(), b.role());
    }
}
