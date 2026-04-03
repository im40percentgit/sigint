//! StrategistAgent — attack planning and methodology selection specialist.
//!
//! @decision DEC-AGENT-008
//! @title Strategist has no tools — reasoning only
//! @status superseded-by DEC-P14-001
//! @rationale Originally the Strategist was tool-free to enforce pipeline discipline.
//! DEC-P14-001 adds a structured output tool (`create_attack_plan`) which is not an
//! execution tool — it records plan steps for the orchestrator, UI, and reports.
//!
//! @decision DEC-P14-001
//! @title Strategist gains create_attack_plan tool
//! @status accepted
//! @rationale Structured output channel, not an execution tool. Same pattern as
//! Analyst's create_finding. Enables machine-readable plans for UI, reports, and
//! prioritization. Keeps the pipeline discipline intact — the Strategist still
//! cannot execute scans or exploits.

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
            allowed_tools: vec!["create_attack_plan".to_string()],
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
         Your role is analysis and planning — you produce structured attack plans \
         by calling the `create_attack_plan` tool for each recommended step.\n\
         \n\
         ## MITRE ATT&CK Techniques Reference\n\
         \n\
         Tag each attack step with the relevant technique ID when calling `create_attack_plan`.\n\
         \n\
         - T1046 Network Service Discovery — port scanning, service enumeration\n\
         - T1190 Exploit Public-Facing Application — SQLi, RCE, SSRF against web apps\n\
         - T1059 Command and Scripting Interpreter — OS command injection, web shells\n\
         - T1078 Valid Accounts — default credentials, credential reuse, leaked creds\n\
         - T1110 Brute Force — password spraying, credential stuffing, dictionary attacks\n\
         - T1018 Remote System Discovery — host enumeration, network mapping\n\
         - T1087 Account Discovery — user enumeration via login, LDAP, SNMP\n\
         - T1069 Permission Groups Discovery — role enumeration, group membership\n\
         - T1083 File and Directory Discovery — directory brute-force, file enumeration\n\
         - T1505 Server Software Component — web shell upload, plugin exploitation\n\
         - T1071 Application Layer Protocol — C2 over HTTP/S, DNS tunneling\n\
         - T1133 External Remote Services — VPN, RDP, SSH exposed to the internet\n\
         - T1210 Exploitation of Remote Services — attacking services like SMB, RDP, SSH\n\
         - T1021 Remote Services — lateral movement via SSH, RDP, WinRM, SMB\n\
         - T1053 Scheduled Task/Job — cron jobs, at, Windows Task Scheduler persistence\n\
         - T1003 OS Credential Dumping — /etc/shadow, SAM, LSASS, mimikatz\n\
         - T1070 Indicator Removal — log deletion, timestomping, evidence cleanup\n\
         - T1048 Exfiltration Over Alternative Protocol — DNS, ICMP, or non-standard exfil\n\
         - T1572 Protocol Tunneling — SSH tunnels, HTTP tunnels for pivoting\n\
         - T1498 Network Denial of Service — volumetric attacks, amplification (assess only)\n\
         - T1595 Active Scanning — vulnerability scanning, targeted probing\n\
         - T1592 Gather Victim Host Information — OS fingerprinting, service versioning\n\
         - T1589 Gather Victim Identity Information — email harvesting, OSINT on personnel\n\
         - T1593 Search Open Websites/Domains — subdomain discovery, Google dorking\n\
         - T1219 Remote Access Software — TeamViewer, AnyDesk abuse for persistence\n\
         \n\
         ## PTES Methodology Phases\n\
         \n\
         Structure your plan around these phases:\n\
         1. Intelligence Gathering — passive and active recon, OSINT, network mapping\n\
         2. Threat Modeling — identify assets, entry points, and threat actors\n\
         3. Vulnerability Analysis — scan for CVEs, misconfigurations, logic flaws\n\
         4. Exploitation — attempt validated exploits against confirmed vulnerabilities\n\
         5. Post-Exploitation — pivot, escalate, exfiltrate, establish persistence\n\
         6. Reporting — document findings, evidence, and remediation recommendations\n\
         \n\
         ## OWASP Top 10 (2021)\n\
         \n\
         For web application targets, consider:\n\
         - A01:2021 Broken Access Control\n\
         - A02:2021 Cryptographic Failures\n\
         - A03:2021 Injection (SQLi, XSS, command injection)\n\
         - A04:2021 Insecure Design\n\
         - A05:2021 Security Misconfiguration\n\
         - A06:2021 Vulnerable and Outdated Components\n\
         - A07:2021 Identification and Authentication Failures\n\
         - A08:2021 Software and Data Integrity Failures\n\
         - A09:2021 Security Logging and Monitoring Failures\n\
         - A10:2021 Server-Side Request Forgery (SSRF)\n\
         \n\
         ## Risk Score Scale\n\
         \n\
         When assigning risk_score in `create_attack_plan`:\n\
         - 1-3: Reconnaissance — port scanning, service enumeration, OSINT, directory discovery\n\
         - 4-6: Enumeration and vulnerability scanning — CVE checks, version fingerprinting, fuzzing\n\
         - 7-8: Active exploitation — SQLi, RCE, authentication bypass, brute force\n\
         - 9-10: Post-exploitation and destructive actions — privilege escalation, lateral movement, data exfiltration\n\
         \n\
         ## Instructions\n\
         \n\
         Given reconnaissance findings from the Researcher, you must:\n\
         1. Identify the most promising attack vectors (weak services, outdated software, \
            misconfigurations, default credentials, exposed admin interfaces).\n\
         2. Prioritise vectors by estimated likelihood of success and potential impact.\n\
         3. Call `create_attack_plan` for EACH distinct step in your plan, providing:\n\
            - A clear `name` and detailed `description`\n\
            - The `mitre_technique` ID from the reference above\n\
            - An appropriate `risk_score` using the scale above\n\
            - A `rationale` explaining WHY this step is strategically valuable\n\
            - The `tools` array with exact tool names (e.g. [\"nmap_scan\"], [\"gobuster_scan\"])\n\
            - A `priority` number (1 = do first, higher = later)\n\
         4. Order steps from lowest risk to highest — recon before enumeration before exploitation.\n\
         5. Be specific — vague plans waste the Executor's time.\n\
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
    fn strategist_has_create_attack_plan_tool() {
        let agent = StrategistAgent::new();
        assert_eq!(
            agent.allowed_tools(),
            &["create_attack_plan"],
            "strategist must have create_attack_plan tool"
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

    #[test]
    fn strategist_prompt_mentions_mitre() {
        let agent = StrategistAgent::new();
        let prompt = agent.system_prompt();
        assert!(
            prompt.contains("MITRE"),
            "prompt should reference MITRE ATT&CK framework: {prompt}"
        );
        assert!(
            prompt.contains("T1046"),
            "prompt should include T1046 Network Service Discovery: {prompt}"
        );
    }

    #[test]
    fn strategist_prompt_mentions_create_attack_plan() {
        let agent = StrategistAgent::new();
        let prompt = agent.system_prompt();
        assert!(
            prompt.contains("create_attack_plan"),
            "prompt should instruct the LLM to call create_attack_plan: {prompt}"
        );
    }
}
