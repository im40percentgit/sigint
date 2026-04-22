//! CreateAttackPlanTool — records a structured attack step during strategic planning.
//!
//! Like `CreateFindingTool`, this is a pure in-memory tool. When the Strategist LLM
//! calls it, the tool validates the arguments, writes the structured attack step to
//! a shared collector, and returns a confirmation message to the LLM.
//!
//! The orchestrator drains the collector after the Strategist agent completes, using
//! the plan to drive subsequent tool execution and prioritisation.
//!
//! @decision DEC-P14-001
//! @title Strategist gains create_attack_plan tool (supersedes DEC-AGENT-008)
//! @status accepted
//! @rationale Structured output channel, not an execution tool. Same pattern as
//! Analyst's create_finding. Enables machine-readable plans for UI, reports, and
//! prioritization.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use sigint_llm::ToolDefinition;

use crate::error::{Result, ToolError};
use crate::result::ToolResult;
use sigint_core::types::ToolRisk;

use crate::tool::Tool;

/// A single step in an attack plan produced by the Strategist LLM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackStep {
    /// Short name for the attack step (e.g. "Port scan target subnet").
    pub name: String,
    /// Detailed description of what this step does and why.
    pub description: String,
    /// MITRE ATT&CK technique ID, if applicable (e.g. "T1046").
    pub mitre_technique: Option<String>,
    /// Risk score from 1 (minimal risk) to 10 (maximum risk).
    pub risk_score: u8,
    /// Why this step is included in the plan — the strategic reasoning.
    pub rationale: String,
    /// Tool names to use for this step (e.g. ["nmap_scan", "gobuster_scan"]).
    pub tools: Vec<String>,
    /// Execution priority — 1 means do first, higher numbers later.
    pub priority: u8,
}

/// Shared collector for attack steps produced by the Strategist LLM.
///
/// Shared between `CreateAttackPlanTool` (writer) and the orchestrator (reader).
/// The orchestrator drains this after the Strategist agent completes.
pub type PlanCollector = Arc<Mutex<Vec<AttackStep>>>;

/// Create a new, empty `PlanCollector`.
pub fn new_plan_collector() -> PlanCollector {
    Arc::new(Mutex::new(Vec::new()))
}

/// Tool that the Strategist LLM calls to record each attack step in its plan.
///
/// Call this once per distinct step in the attack plan. The step data is validated
/// (risk_score range, priority minimum), stored in the shared collector, and a
/// confirmation message is returned to the model so it can continue planning.
pub struct CreateAttackPlanTool {
    /// Shared collector written by this tool, drained by the orchestrator.
    collector: PlanCollector,
}

impl CreateAttackPlanTool {
    /// Construct a new `CreateAttackPlanTool` backed by `collector`.
    pub fn new(collector: PlanCollector) -> Self {
        Self { collector }
    }
}

#[async_trait]
impl Tool for CreateAttackPlanTool {
    fn name(&self) -> &str {
        "create_attack_plan"
    }

    fn description(&self) -> &str {
        "Record an attack step with name, description, risk score, rationale, tools, and priority"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::function(
            "create_attack_plan",
            "Record a structured attack step in the engagement plan. \
             Call this once for each distinct step the Strategist wants to execute.",
            json!({
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Short name for the attack step (e.g. 'Port scan target subnet')"
                    },
                    "description": {
                        "type": "string",
                        "description": "Detailed description of what this step does and why"
                    },
                    "mitre_technique": {
                        "type": "string",
                        "description": "MITRE ATT&CK technique ID, if applicable (e.g. 'T1046')"
                    },
                    "risk_score": {
                        "type": "integer",
                        "description": "Risk score from 1 (minimal risk) to 10 (maximum risk)",
                        "minimum": 1,
                        "maximum": 10
                    },
                    "rationale": {
                        "type": "string",
                        "description": "Why this step is included — the strategic reasoning"
                    },
                    "tools": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Tool names to use for this step (e.g. ['nmap_scan', 'gobuster_scan'])"
                    },
                    "priority": {
                        "type": "integer",
                        "description": "Execution priority — 1 means do first, higher numbers later",
                        "minimum": 1
                    }
                },
                "required": ["name", "description", "risk_score", "rationale", "tools", "priority"]
            }),
        )
    }

    async fn execute(&self, args: Value) -> Result<ToolResult> {
        // ── Required fields ───────────────────────────────────────────────────
        let name = args
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::MissingArgument("name".into()))?;

        let description = args
            .get("description")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::MissingArgument("description".into()))?;

        let risk_score = args
            .get("risk_score")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| ToolError::MissingArgument("risk_score".into()))?;

        let rationale = args
            .get("rationale")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::MissingArgument("rationale".into()))?;

        let tools = args
            .get("tools")
            .and_then(|v| v.as_array())
            .ok_or_else(|| ToolError::MissingArgument("tools".into()))?;

        let priority = args
            .get("priority")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| ToolError::MissingArgument("priority".into()))?;

        // ── Validation ───────────────────────────────────────────────────────
        if !(1..=10).contains(&risk_score) {
            return Err(ToolError::InvalidArgument {
                name: "risk_score".into(),
                expected: format!("an integer in the range 1-10, got {risk_score}"),
            });
        }

        if priority < 1 {
            return Err(ToolError::InvalidArgument {
                name: "priority".into(),
                expected: format!("an integer >= 1, got {priority}"),
            });
        }

        let tools_vec: Vec<String> = tools
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();

        // ── Optional fields ──────────────────────────────────────────────────
        let mitre_technique = args
            .get("mitre_technique")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        // Build the AttackStep struct.
        let step = AttackStep {
            name: name.to_string(),
            description: description.to_string(),
            mitre_technique,
            risk_score: risk_score as u8,
            rationale: rationale.to_string(),
            tools: tools_vec,
            priority: priority as u8,
        };

        {
            // Scope the lock to minimise hold time.
            let mut guard = self.collector.lock().expect("plan collector lock poisoned");
            guard.push(step);
        }

        Ok(ToolResult {
            stdout: format!(
                "Attack step recorded: [P{}] {} (risk: {})",
                priority, name, risk_score
            ),
            stderr: String::new(),
            exit_code: 0,
            duration: std::time::Duration::from_millis(0),
            structured_data: Some(args),
            status: Default::default(),
            truncation: None,
        })
    }

    fn risk_level(&self) -> ToolRisk {
        ToolRisk::Low
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_tool() -> (CreateAttackPlanTool, PlanCollector) {
        let collector = new_plan_collector();
        let tool = CreateAttackPlanTool::new(Arc::clone(&collector));
        (tool, collector)
    }

    #[tokio::test]
    async fn execute_valid_step_returns_confirmation() {
        let (tool, collector) = make_tool();
        let args = json!({
            "name": "Port scan target subnet",
            "description": "Scan all ports on 10.0.0.0/24 to identify live hosts and services",
            "mitre_technique": "T1046",
            "risk_score": 3,
            "rationale": "Initial reconnaissance to map the attack surface",
            "tools": ["nmap_scan"],
            "priority": 1
        });
        let result = tool.execute(args).await.unwrap();
        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.contains("[P1]"));
        assert!(result.stdout.contains("Port scan target subnet"));
        assert!(result.stdout.contains("(risk: 3)"));
        assert!(result.structured_data.is_some());

        let guard = collector.lock().unwrap();
        assert_eq!(guard.len(), 1);
        assert_eq!(guard[0].name, "Port scan target subnet");
        assert_eq!(guard[0].risk_score, 3);
        assert_eq!(guard[0].priority, 1);
        assert_eq!(guard[0].mitre_technique, Some("T1046".to_string()));
        assert_eq!(guard[0].tools, vec!["nmap_scan".to_string()]);
    }

    #[tokio::test]
    async fn execute_without_mitre_technique_succeeds() {
        let (tool, collector) = make_tool();
        let args = json!({
            "name": "Directory brute-force",
            "description": "Enumerate hidden directories on the web server",
            "risk_score": 5,
            "rationale": "Discover admin panels and backup files",
            "tools": ["gobuster_scan"],
            "priority": 2
        });
        let result = tool.execute(args).await.unwrap();
        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.contains("[P2]"));

        let guard = collector.lock().unwrap();
        assert_eq!(guard.len(), 1);
        assert!(guard[0].mitre_technique.is_none());
    }

    #[tokio::test]
    async fn execute_risk_score_out_of_range_high() {
        let (tool, _) = make_tool();
        let args = json!({
            "name": "Test",
            "description": "desc",
            "risk_score": 11,
            "rationale": "reason",
            "tools": ["nmap_scan"],
            "priority": 1
        });
        let err = tool.execute(args).await.unwrap_err();
        assert!(
            err.to_string().contains("risk_score"),
            "error should mention 'risk_score': {err}"
        );
        assert!(
            err.to_string().contains("11"),
            "error should include the invalid value: {err}"
        );
    }

    #[tokio::test]
    async fn execute_risk_score_zero_errors() {
        let (tool, _) = make_tool();
        let args = json!({
            "name": "Test",
            "description": "desc",
            "risk_score": 0,
            "rationale": "reason",
            "tools": ["nmap_scan"],
            "priority": 1
        });
        let err = tool.execute(args).await.unwrap_err();
        assert!(
            err.to_string().contains("risk_score"),
            "error should mention 'risk_score': {err}"
        );
    }

    #[tokio::test]
    async fn execute_priority_zero_errors() {
        let (tool, _) = make_tool();
        let args = json!({
            "name": "Test",
            "description": "desc",
            "risk_score": 5,
            "rationale": "reason",
            "tools": ["nmap_scan"],
            "priority": 0
        });
        let err = tool.execute(args).await.unwrap_err();
        assert!(
            err.to_string().contains("priority"),
            "error should mention 'priority': {err}"
        );
    }

    #[tokio::test]
    async fn execute_missing_name_errors() {
        let (tool, _) = make_tool();
        let args = json!({
            "description": "desc",
            "risk_score": 5,
            "rationale": "reason",
            "tools": ["nmap_scan"],
            "priority": 1
        });
        let err = tool.execute(args).await.unwrap_err();
        assert!(
            err.to_string().contains("name"),
            "error should mention 'name': {err}"
        );
    }

    #[tokio::test]
    async fn execute_missing_tools_errors() {
        let (tool, _) = make_tool();
        let args = json!({
            "name": "Test",
            "description": "desc",
            "risk_score": 5,
            "rationale": "reason",
            "priority": 1
        });
        let err = tool.execute(args).await.unwrap_err();
        assert!(
            err.to_string().contains("tools"),
            "error should mention 'tools': {err}"
        );
    }

    #[tokio::test]
    async fn multiple_steps_accumulate() {
        let (tool, collector) = make_tool();
        for i in 1..=3 {
            let args = json!({
                "name": format!("Step {i}"),
                "description": format!("Description for step {i}"),
                "risk_score": i,
                "rationale": format!("Rationale {i}"),
                "tools": ["nmap_scan"],
                "priority": i
            });
            tool.execute(args).await.unwrap();
        }
        let guard = collector.lock().unwrap();
        assert_eq!(guard.len(), 3);
        assert_eq!(guard[0].name, "Step 1");
        assert_eq!(guard[1].name, "Step 2");
        assert_eq!(guard[2].name, "Step 3");
    }

    #[tokio::test]
    async fn risk_score_boundary_values_accepted() {
        // Both 1 and 10 are valid boundary values.
        for score in [1_u8, 10_u8] {
            let (tool, _) = make_tool();
            let args = json!({
                "name": "Boundary test",
                "description": "desc",
                "risk_score": score,
                "rationale": "reason",
                "tools": ["nmap_scan"],
                "priority": 1
            });
            let result = tool.execute(args).await;
            assert!(result.is_ok(), "risk_score={score} should be accepted");
        }
    }

    #[test]
    fn tool_metadata() {
        let collector = new_plan_collector();
        let tool = CreateAttackPlanTool::new(collector);
        assert_eq!(tool.name(), "create_attack_plan");
        assert_eq!(tool.risk_level(), ToolRisk::Low);
        assert!(!tool.description().is_empty());
    }

    #[test]
    fn tool_definition_has_required_fields() {
        let collector = new_plan_collector();
        let tool = CreateAttackPlanTool::new(collector);
        let def = tool.definition();
        assert_eq!(def.function.name, "create_attack_plan");
        let schema = &def.function.parameters;
        let required = schema
            .get("required")
            .and_then(|r| r.as_array())
            .expect("required array should be present");
        assert!(required.iter().any(|v| v == "name"));
        assert!(required.iter().any(|v| v == "description"));
        assert!(required.iter().any(|v| v == "risk_score"));
        assert!(required.iter().any(|v| v == "rationale"));
        assert!(required.iter().any(|v| v == "tools"));
        assert!(required.iter().any(|v| v == "priority"));
        // mitre_technique must NOT be in required — it is optional
        assert!(
            !required.iter().any(|v| v == "mitre_technique"),
            "'mitre_technique' must not be in required array"
        );
    }
}
