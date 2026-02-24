//! AgentRole — the five specialist roles in the SIGINT agent pipeline.
//!
//! Each role represents a distinct phase of a penetration test engagement.
//! The Orchestrator (P2-4) dispatches tasks to agents in role order:
//! Researcher → Strategist → Executor → Analyst → Reporter.
//!
//! @decision DEC-AGENT-001
//! @title Five-role agent pipeline: Researcher → Strategist → Executor → Analyst → Reporter
//! @status accepted
//! @rationale Separating concerns into five specialist roles mirrors real-world
//! pentest team structure. Each role has a focused system prompt and restricted
//! tool ACL, which keeps individual LLM context windows small and purposeful.
//! The ordered pipeline ensures outputs from earlier phases accumulate in
//! TaskContext and are fed as structured context to later agents.

use serde::{Deserialize, Serialize};

/// The operational role of an agent in the SIGINT pipeline.
///
/// Roles determine:
/// - The agent's system prompt and behavioral focus.
/// - Which tools the agent is permitted to invoke (role-based ACL).
/// - How `TaskContext::to_agent_prompt` formats the accumulated context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AgentRole {
    /// Performs OSINT and initial reconnaissance on the target.
    Researcher,
    /// Analyses recon results and plans the attack strategy.
    Strategist,
    /// Executes the planned tools against the target in the sandbox.
    Executor,
    /// Correlates tool output into structured security findings.
    Analyst,
    /// Compiles all findings into a human-readable penetration test report.
    Reporter,
}

impl std::fmt::Display for AgentRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentRole::Researcher => write!(f, "researcher"),
            AgentRole::Strategist => write!(f, "strategist"),
            AgentRole::Executor => write!(f, "executor"),
            AgentRole::Analyst => write!(f, "analyst"),
            AgentRole::Reporter => write!(f, "reporter"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_roles_are_distinct() {
        let roles = [
            AgentRole::Researcher,
            AgentRole::Strategist,
            AgentRole::Executor,
            AgentRole::Analyst,
            AgentRole::Reporter,
        ];
        for (i, a) in roles.iter().enumerate() {
            for (j, b) in roles.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b, "{a:?} == {b:?} — roles must be distinct");
                }
            }
        }
    }

    #[test]
    fn roles_display_correctly() {
        assert_eq!(AgentRole::Researcher.to_string(), "researcher");
        assert_eq!(AgentRole::Strategist.to_string(), "strategist");
        assert_eq!(AgentRole::Executor.to_string(), "executor");
        assert_eq!(AgentRole::Analyst.to_string(), "analyst");
        assert_eq!(AgentRole::Reporter.to_string(), "reporter");
    }

    #[test]
    fn role_serialize_deserialize_roundtrip() {
        for role in [
            AgentRole::Researcher,
            AgentRole::Strategist,
            AgentRole::Executor,
            AgentRole::Analyst,
            AgentRole::Reporter,
        ] {
            let json = serde_json::to_string(&role).unwrap();
            let back: AgentRole = serde_json::from_str(&json).unwrap();
            assert_eq!(role, back, "round-trip failed for {role:?}");
        }
    }

    #[test]
    fn role_is_copy() {
        let r = AgentRole::Executor;
        let r2 = r; // copy, not move
        assert_eq!(r, r2);
    }
}
