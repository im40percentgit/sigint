//! ExecutorAgent — sandboxed tool execution specialist.
//!
//! @decision DEC-AGENT-009
//! @title Executor has full tool access: nmap, shell, gobuster, nikto, nuclei, feroxbuster
//! @status accepted
//! @rationale The Executor is the only agent that runs tools against the target.
//! It receives a concrete plan from the Strategist and is trusted to execute it
//! faithfully. All tool calls go through the sandbox (hakoniwa integration),
//! so broad tool access here is safe — the sandbox enforces the security boundary,
//! not the ACL. Sub-Phase 4C adds gobuster, nikto, nuclei, and feroxbuster so
//! the Executor can perform web enumeration and vulnerability scanning as directed.

use crate::{agent::Agent, role::AgentRole};

/// Executes the attack strategy produced by the Strategist.
///
/// The Executor is the third agent in the pipeline and the only one that
/// directly invokes tools against the target. All invocations run inside the
/// hakoniwa sandbox with per-tool profiles (network, filesystem, time limits).
pub struct ExecutorAgent {
    allowed_tools: Vec<String>,
}

impl ExecutorAgent {
    pub fn new() -> Self {
        Self {
            allowed_tools: vec![
                "nmap_scan".to_string(),
                "shell".to_string(),
                "gobuster_scan".to_string(),
                "nikto_scan".to_string(),
                "nuclei_scan".to_string(),
                "feroxbuster_scan".to_string(),
                "sqlmap_scan".to_string(),
                "ffuf_scan".to_string(),
                "whatweb_scan".to_string(),
            ],
        }
    }
}

impl Default for ExecutorAgent {
    fn default() -> Self {
        Self::new()
    }
}

impl Agent for ExecutorAgent {
    fn name(&self) -> &str {
        "executor"
    }

    fn role(&self) -> AgentRole {
        AgentRole::Executor
    }

    fn system_prompt(&self) -> &str {
        "You are a penetration tester responsible for executing the attack strategy. \
         You have been given a concrete plan by the Strategist. Your job is to carry \
         it out faithfully using the available tools. \
         \n\n\
         You have access to:\n\
         - **nmap** (ALWAYS use this for port scanning, service detection, script scanning — never run nmap via shell)\n\
         - **shell** (for DNS/WHOIS/certificate queries and text processing — NOT for nmap)\n\
         - **gobuster** (directory, vhost, and DNS subdomain bruteforce)\n\
         - **nikto** (web vulnerability and misconfiguration scanning)\n\
         - **nuclei** (template-based CVE and vulnerability scanning)\n\
         - **feroxbuster** (fast recursive content discovery)\n\
         \n\n\
         CRITICAL RULES:\n\
         - For ANY port scanning or service detection, use the nmap tool directly. NEVER run nmap through shell.\n\
         - For DNS/WHOIS/certificate queries, use shell with: whois, dig, host, nslookup, openssl, curl.\n\
         - For processing output, use shell with: grep, awk, sed, jq, sort, uniq.\n\
         - For web directory/vhost enumeration, prefer gobuster or feroxbuster over shell.\n\
         - For web vulnerability scanning, use nikto or nuclei directly.\n\
         \n\n\
         Execution discipline:\n\
         1. Execute each planned step in order. Do not skip steps.\n\
         2. After each tool call, review the output before proceeding.\n\
         3. If a tool fails or produces unexpected output, adapt — try an alternative \
            approach and note the deviation.\n\
         4. Capture the complete output of every tool invocation. The Analyst needs \
            the raw data.\n\
         5. Do not stop early unless you hit a hard blocker. Partial results are \
            less useful than complete ones.\n\
         \n\
         All commands run in a sandboxed environment. You cannot break out of it. \
         Focus on the task.\
         \n\n\
         Handling real-world tool output:\n\
         - If a tool result reports its output was truncated or the scan timed out, \
           note this explicitly in your analysis so the Analyst knows about coverage gaps \
           (e.g. 'nmap scan timed out after 300s — ports above X may be unscanned').\n\
         - If structured_data is null but raw stdout is available, analyse the raw text \
           output directly — it still contains useful information."
    }

    fn allowed_tools(&self) -> &[String] {
        &self.allowed_tools
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executor_identity() {
        let agent = ExecutorAgent::new();
        assert_eq!(agent.name(), "executor");
        assert_eq!(agent.role(), AgentRole::Executor);
    }

    #[test]
    fn executor_system_prompt_nonempty_and_relevant() {
        let agent = ExecutorAgent::new();
        let prompt = agent.system_prompt();
        assert!(!prompt.is_empty());
        assert!(
            prompt.to_lowercase().contains("execut"),
            "prompt should mention execution: {prompt}"
        );
        assert!(
            prompt.to_lowercase().contains("tool") || prompt.to_lowercase().contains("nmap"),
            "prompt should mention tools: {prompt}"
        );
    }

    #[test]
    fn executor_allowed_tools() {
        let agent = ExecutorAgent::new();
        let tools = agent.allowed_tools();
        assert!(
            tools.contains(&"nmap_scan".to_string()),
            "executor must have nmap_scan"
        );
        assert!(
            tools.contains(&"shell".to_string()),
            "executor must have shell"
        );
        assert!(
            tools.contains(&"gobuster_scan".to_string()),
            "executor must have gobuster_scan"
        );
        assert!(
            tools.contains(&"nikto_scan".to_string()),
            "executor must have nikto_scan"
        );
        assert!(
            tools.contains(&"nuclei_scan".to_string()),
            "executor must have nuclei_scan"
        );
        assert!(
            tools.contains(&"feroxbuster_scan".to_string()),
            "executor must have feroxbuster_scan"
        );
        assert!(
            tools.contains(&"sqlmap_scan".to_string()),
            "executor must have sqlmap_scan"
        );
        assert!(
            tools.contains(&"ffuf_scan".to_string()),
            "executor must have ffuf_scan"
        );
        assert!(
            tools.contains(&"whatweb_scan".to_string()),
            "executor must have whatweb_scan"
        );
        assert_eq!(tools.len(), 9, "executor should have exactly 9 tools");
    }

    #[test]
    fn executor_default_equals_new() {
        let a = ExecutorAgent::new();
        let b = ExecutorAgent::default();
        assert_eq!(a.name(), b.name());
        assert_eq!(a.role(), b.role());
    }
}
