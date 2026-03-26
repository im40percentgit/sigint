//! TaskContext — shared state passed between agents by the Orchestrator.
//!
//! As each agent completes its work, its output is stored here and made
//! available to subsequent agents via `to_agent_prompt`. This gives later
//! agents (Strategist, Executor, Analyst, Reporter) full visibility into
//! what earlier agents discovered and decided.
//!
//! @decision DEC-AGENT-003
//! @title TaskContext carries accumulated outputs; each agent sees all prior work
//! @status accepted
//! @rationale Rather than passing raw tool results through shared memory or a
//! database query per agent turn, the Orchestrator accumulates string outputs in
//! a HashMap keyed by AgentRole. `to_agent_prompt` formats only the outputs
//! relevant to each role — Researcher gets a clean slate, Reporter gets
//! everything. This keeps the per-agent prompt focused while preserving the full
//! audit trail in TaskContext for later retrieval or persistence.
//!
//! @decision DEC-AGENT-004
//! @title to_agent_prompt tailors context per role rather than dumping all state
//! @status accepted
//! @rationale Dumping the full TaskContext into every agent's prompt wastes
//! tokens and confuses models (Researcher doesn't need the Analyst's findings;
//! Reporter needs everything). Role-aware formatting keeps each agent's initial
//! context lean and purposeful. The tradeoff is a match arm per role, which is
//! acceptable given the pipeline has exactly five fixed roles.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sigint_core::types::Finding;
use sigint_tools::result::ToolResult;

use crate::{agent::Agent, role::AgentRole};

/// Shared engagement state accumulated across all agent turns.
///
/// The Orchestrator creates one `TaskContext` per `sigint scan` invocation and
/// threads it through each agent in pipeline order. After each agent completes,
/// the Orchestrator stores the agent's final text output in `agent_outputs`.
#[derive(Debug, Serialize, Deserialize)]
pub struct TaskContext {
    /// The primary target (hostname, IP, or CIDR range).
    pub target: String,
    /// Optional port specification forwarded from `--ports` CLI flag.
    ///
    /// When set, the Executor's prompt explicitly instructs the LLM to pass
    /// this value as the `"ports"` argument to `nmap_scan`.
    pub ports: Option<String>,
    /// Security findings raised by the Analyst agent.
    pub findings: Vec<Finding>,
    /// Raw tool execution results collected during Executor phase.
    #[serde(skip)]
    pub scan_results: Vec<ToolResult>,
    /// Text output from each agent, keyed by role.
    pub agent_outputs: HashMap<AgentRole, String>,
    /// Current convergence loop cycle index (0-based).
    ///
    /// The Orchestrator increments this before each Strategist → Executor →
    /// Analyst inner cycle. When `cycle > 0`, `to_agent_prompt` enriches the
    /// Strategist and Executor prompts with accumulated prior-cycle findings and
    /// the previous Analyst assessment so the model can revise its strategy.
    /// Defaults to 0 — single-cycle scans (`max_cycles = 1`) never see cycle > 0.
    pub cycle: usize,
}

impl TaskContext {
    /// Create a new, empty context for the given target.
    pub fn new(target: &str) -> Self {
        Self {
            target: target.to_string(),
            ports: None,
            findings: Vec::new(),
            scan_results: Vec::new(),
            agent_outputs: HashMap::new(),
            cycle: 0,
        }
    }

    /// Set the port specification for this scan engagement.
    ///
    /// The value is threaded into the Executor's initial prompt so that the LLM
    /// can pass it as the `"ports"` argument to `nmap_scan`.
    pub fn with_ports(mut self, ports: Option<String>) -> Self {
        self.ports = ports;
        self
    }

    /// Format the accumulated context into a role-appropriate initial prompt.
    ///
    /// Each role receives only the context it needs:
    /// - **Researcher** — clean slate, just the target.
    /// - **Strategist** — target + Researcher output. On cycle > 0, also includes
    ///   accumulated findings and previous Analyst assessment so the model can
    ///   revise its attack strategy to focus on unexplored areas.
    /// - **Executor** — target + Strategist output. On cycle > 0, notes that this
    ///   is a re-execution pass with a revised strategy.
    /// - **Analyst** — target + Executor output.
    /// - **Reporter** — target + all prior agent outputs.
    pub fn to_agent_prompt(&self, agent: &dyn Agent) -> String {
        match agent.role() {
            AgentRole::RfRecon => {
                format!(
                    "Target: {}. Perform RF spectrum reconnaissance of the wireless \
                     environment. Sweep active frequency bands, identify transmitting \
                     devices, decode detectable protocols, and summarise all RF findings \
                     so the Strategist can plan wireless attack vectors.",
                    self.target
                )
            }
            AgentRole::Researcher => {
                format!(
                    "Target: {}. Perform initial reconnaissance. \
                     Gather open-source intelligence, identify exposed services, \
                     subdomains, and technology stack. Report your findings.",
                    self.target
                )
            }
            AgentRole::Strategist => {
                let researcher_output = self
                    .agent_outputs
                    .get(&AgentRole::Researcher)
                    .map(String::as_str)
                    .unwrap_or("(no researcher output yet)");
                // Include RF recon output when present (HackRF was attached).
                let rf_section = if let Some(rf) = self.agent_outputs.get(&AgentRole::RfRecon) {
                    format!("\n\nRF Recon findings:\n{}", rf)
                } else {
                    String::new()
                };
                let base = format!(
                    "Target: {}. Researcher findings:\n{}{}\n\n\
                     Based on the reconnaissance above, plan the attack strategy. \
                     Identify the most promising attack vectors (network and wireless), \
                     prioritise them by likelihood of success, and specify which tools \
                     to run and in what order.",
                    self.target, researcher_output, rf_section
                );
                // On cycle > 0, inject accumulated findings + prior Analyst output
                // so the model can revise strategy rather than repeating itself.
                if self.cycle > 0 {
                    let findings_list = if self.findings.is_empty() {
                        "(none yet)".to_string()
                    } else {
                        self.findings
                            .iter()
                            .map(|f| format!("- [{}] {}: {}", f.severity, f.title, f.description))
                            .collect::<Vec<_>>()
                            .join("\n")
                    };
                    let analyst_output = self
                        .agent_outputs
                        .get(&AgentRole::Analyst)
                        .map(String::as_str)
                        .unwrap_or("(no prior analyst output)");
                    format!(
                        "{}\n\n## Previous Cycle Results\n\
                         The following findings have been discovered so far:\n{}\n\n\
                         Analyst assessment:\n{}\n\n\
                         Based on these findings, revise your attack strategy. \
                         Focus on unexplored areas or deeper exploitation of \
                         discovered vulnerabilities.",
                        base, findings_list, analyst_output
                    )
                } else {
                    base
                }
            }
            AgentRole::Executor => {
                let strategist_output = self
                    .agent_outputs
                    .get(&AgentRole::Strategist)
                    .map(String::as_str)
                    .unwrap_or("(no strategist output yet)");
                let base = format!(
                    "Target: {}. Strategy:\n{}\n\n\
                     Execute the planned tools against the target. \
                     Use the available tools to carry out the strategy. \
                     Report the raw output of each tool invocation.",
                    self.target, strategist_output
                );
                // On cycle > 0, note this is a re-execution pass so the model
                // understands it should focus on the revised strategy.
                let base = if self.cycle > 0 {
                    format!(
                        "{}\n\nNote: This is re-execution cycle {}. \
                         Focus on the revised strategy above — avoid repeating \
                         tool invocations that already yielded findings.",
                        base, self.cycle
                    )
                } else {
                    base
                };
                if let Some(ref ports) = self.ports {
                    format!(
                        "{}\n\nPort specification: {}. Pass this as the \"ports\" argument to nmap_scan.",
                        base, ports
                    )
                } else {
                    base
                }
            }
            AgentRole::Analyst => {
                let executor_output = self
                    .agent_outputs
                    .get(&AgentRole::Executor)
                    .map(String::as_str)
                    .unwrap_or("(no executor output yet)");
                format!(
                    "Target: {}. Tool results:\n{}\n\n\
                     Analyse the tool output above. Identify security vulnerabilities, \
                     misconfigurations, and notable findings. Classify each finding by \
                     severity (critical/high/medium/low/info) and provide evidence.",
                    self.target, executor_output
                )
            }
            AgentRole::Reporter => {
                let all_outputs = self.format_all_outputs();
                format!(
                    "Target: {}. Full scan data:\n{}\n\n\
                     Generate a comprehensive penetration test report. Include an \
                     executive summary, detailed findings with evidence, risk ratings, \
                     and actionable remediation recommendations.",
                    self.target, all_outputs
                )
            }
        }
    }

    /// Format all agent outputs in pipeline order for the Reporter.
    fn format_all_outputs(&self) -> String {
        let pipeline = [
            AgentRole::RfRecon,
            AgentRole::Researcher,
            AgentRole::Strategist,
            AgentRole::Executor,
            AgentRole::Analyst,
        ];
        let mut parts = Vec::new();
        for role in &pipeline {
            if let Some(output) = self.agent_outputs.get(role) {
                parts.push(format!("=== {} ===\n{}", role, output));
            }
        }
        if parts.is_empty() {
            "(no prior agent outputs)".to_string()
        } else {
            parts.join("\n\n")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agents::{
        AnalystAgent, ExecutorAgent, ReporterAgent, ResearcherAgent, RfReconAgent, StrategistAgent,
    };

    #[test]
    fn new_context_has_empty_state() {
        let ctx = TaskContext::new("example.com");
        assert_eq!(ctx.target, "example.com");
        assert!(ctx.findings.is_empty());
        assert!(ctx.scan_results.is_empty());
        assert!(ctx.agent_outputs.is_empty());
    }

    #[test]
    fn researcher_prompt_contains_target() {
        let ctx = TaskContext::new("10.0.0.1");
        let agent = ResearcherAgent::new();
        let prompt = ctx.to_agent_prompt(&agent);
        assert!(
            prompt.contains("10.0.0.1"),
            "prompt missing target: {prompt}"
        );
        assert!(
            prompt.to_lowercase().contains("reconnaissance"),
            "researcher prompt should mention reconnaissance: {prompt}"
        );
    }

    #[test]
    fn strategist_prompt_includes_researcher_output() {
        let mut ctx = TaskContext::new("example.com");
        ctx.agent_outputs.insert(
            AgentRole::Researcher,
            "Found open ports: 22, 80, 443".to_string(),
        );
        let agent = StrategistAgent::new();
        let prompt = ctx.to_agent_prompt(&agent);
        assert!(
            prompt.contains("Found open ports"),
            "strategist should see researcher output"
        );
        assert!(
            prompt.contains("attack strategy") || prompt.contains("plan"),
            "strategist prompt should mention planning"
        );
    }

    #[test]
    fn executor_prompt_includes_strategist_output() {
        let mut ctx = TaskContext::new("example.com");
        ctx.agent_outputs.insert(
            AgentRole::Strategist,
            "Run nmap full port scan, then gobuster".to_string(),
        );
        let agent = ExecutorAgent::new();
        let prompt = ctx.to_agent_prompt(&agent);
        assert!(
            prompt.contains("Run nmap full port scan"),
            "executor should see strategist output"
        );
    }

    #[test]
    fn analyst_prompt_includes_executor_output() {
        let mut ctx = TaskContext::new("example.com");
        ctx.agent_outputs.insert(
            AgentRole::Executor,
            "PORT 22/tcp open ssh\nPORT 80/tcp open http".to_string(),
        );
        let agent = AnalystAgent::new();
        let prompt = ctx.to_agent_prompt(&agent);
        assert!(
            prompt.contains("PORT 22/tcp"),
            "analyst should see executor output"
        );
        assert!(
            prompt.to_lowercase().contains("vulnerabilit")
                || prompt.to_lowercase().contains("finding"),
            "analyst prompt should mention findings"
        );
    }

    #[test]
    fn reporter_prompt_includes_all_outputs() {
        let mut ctx = TaskContext::new("example.com");
        ctx.agent_outputs
            .insert(AgentRole::Researcher, "recon data".to_string());
        ctx.agent_outputs
            .insert(AgentRole::Strategist, "strategy data".to_string());
        ctx.agent_outputs
            .insert(AgentRole::Executor, "tool output data".to_string());
        ctx.agent_outputs
            .insert(AgentRole::Analyst, "analysis data".to_string());
        let agent = ReporterAgent::new();
        let prompt = ctx.to_agent_prompt(&agent);
        assert!(
            prompt.contains("recon data"),
            "reporter should see researcher output"
        );
        assert!(
            prompt.contains("strategy data"),
            "reporter should see strategist output"
        );
        assert!(
            prompt.contains("tool output data"),
            "reporter should see executor output"
        );
        assert!(
            prompt.contains("analysis data"),
            "reporter should see analyst output"
        );
        assert!(
            prompt.to_lowercase().contains("report"),
            "reporter prompt should mention report"
        );
    }

    #[test]
    fn strategist_fallback_when_no_researcher_output() {
        let ctx = TaskContext::new("example.com");
        let agent = StrategistAgent::new();
        let prompt = ctx.to_agent_prompt(&agent);
        assert!(
            prompt.contains("no researcher output yet"),
            "should show fallback text"
        );
    }

    #[test]
    fn executor_prompt_includes_ports_when_set() {
        let ctx = TaskContext::new("example.com").with_ports(Some("80,443".to_string()));
        // Provide strategist output so the executor prompt is fully populated.
        let mut ctx = ctx;
        ctx.agent_outputs
            .insert(AgentRole::Strategist, "Run nmap scan".to_string());
        let agent = ExecutorAgent::new();
        let prompt = ctx.to_agent_prompt(&agent);
        assert!(
            prompt.contains("80,443"),
            "executor prompt should include ports: {prompt}"
        );
        assert!(
            prompt.contains("Port specification"),
            "executor prompt should mention 'Port specification': {prompt}"
        );
    }

    #[test]
    fn executor_prompt_omits_ports_when_none() {
        let mut ctx = TaskContext::new("example.com");
        ctx.agent_outputs
            .insert(AgentRole::Strategist, "Run nmap scan".to_string());
        let agent = ExecutorAgent::new();
        let prompt = ctx.to_agent_prompt(&agent);
        assert!(
            !prompt.contains("Port specification"),
            "should not mention ports: {prompt}"
        );
    }

    #[test]
    fn rf_recon_prompt_contains_target() {
        let ctx = TaskContext::new("10.0.0.1");
        let agent = RfReconAgent::new();
        let prompt = ctx.to_agent_prompt(&agent);
        assert!(
            prompt.contains("10.0.0.1"),
            "rf_recon prompt missing target: {prompt}"
        );
        assert!(
            prompt.to_lowercase().contains("rf")
                || prompt.to_lowercase().contains("spectrum"),
            "rf_recon prompt should mention RF or spectrum: {prompt}"
        );
    }

    #[test]
    fn strategist_prompt_includes_rf_recon_output_when_present() {
        let mut ctx = TaskContext::new("example.com");
        ctx.agent_outputs.insert(
            AgentRole::Researcher,
            "Found open ports: 22, 80".to_string(),
        );
        ctx.agent_outputs.insert(
            AgentRole::RfRecon,
            "Active at 433.92 MHz: garage door remotes detected".to_string(),
        );
        let agent = StrategistAgent::new();
        let prompt = ctx.to_agent_prompt(&agent);
        assert!(
            prompt.contains("433.92 MHz"),
            "strategist should see RF recon output: {prompt}"
        );
        assert!(
            prompt.contains("Found open ports"),
            "strategist should still see network recon: {prompt}"
        );
    }

    #[test]
    fn strategist_prompt_omits_rf_section_when_no_rf_output() {
        let mut ctx = TaskContext::new("example.com");
        ctx.agent_outputs.insert(
            AgentRole::Researcher,
            "Found open ports: 22, 80".to_string(),
        );
        let agent = StrategistAgent::new();
        let prompt = ctx.to_agent_prompt(&agent);
        assert!(
            !prompt.contains("RF Recon findings"),
            "should not mention RF section when absent: {prompt}"
        );
    }

    #[test]
    fn reporter_prompt_includes_rf_recon_output() {
        let mut ctx = TaskContext::new("example.com");
        ctx.agent_outputs
            .insert(AgentRole::RfRecon, "rf recon data".to_string());
        ctx.agent_outputs
            .insert(AgentRole::Researcher, "recon data".to_string());
        ctx.agent_outputs
            .insert(AgentRole::Analyst, "analysis data".to_string());
        let agent = ReporterAgent::new();
        let prompt = ctx.to_agent_prompt(&agent);
        assert!(
            prompt.contains("rf recon data"),
            "reporter should see rf recon output: {prompt}"
        );
    }

    #[test]
    fn agent_outputs_serialization_roundtrip() {
        let mut ctx = TaskContext::new("example.com");
        ctx.agent_outputs
            .insert(AgentRole::Researcher, "recon results".to_string());
        ctx.agent_outputs
            .insert(AgentRole::Analyst, "analysis results".to_string());

        let json = serde_json::to_string(&ctx).unwrap();
        let back: TaskContext = serde_json::from_str(&json).unwrap();

        assert_eq!(back.target, "example.com");
        assert_eq!(
            back.agent_outputs
                .get(&AgentRole::Researcher)
                .map(String::as_str),
            Some("recon results")
        );
        assert_eq!(
            back.agent_outputs
                .get(&AgentRole::Analyst)
                .map(String::as_str),
            Some("analysis results")
        );
    }
}
