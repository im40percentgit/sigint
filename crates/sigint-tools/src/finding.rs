//! CreateFindingTool — records a structured security finding during analysis.
//!
//! Unlike other tools in this crate that wrap external binaries (nmap, gobuster,
//! nikto), `CreateFindingTool` is a pure in-memory tool. When the Analyst LLM
//! calls it, the tool validates the arguments, writes the structured finding data
//! to a shared collector, and returns a confirmation message to the LLM.
//!
//! The orchestrator drains the collector into `TaskContext::findings` after the
//! Analyst agent completes, then emits `FindingCreated` events and persists to
//! the database.
//!
//! @decision DEC-FINDING-001
//! @title Use a tool call (not text parsing) to extract structured findings
//! @status accepted
//! @rationale Two alternatives were considered:
//!
//!   1. **Text parsing**: have the Analyst write findings as structured JSON/YAML
//!      in its final text output, then parse it after `run_agent` returns.
//!      Rejected because: (a) LLMs produce inconsistent output formats — any
//!      regex or JSON parser becomes brittle against model drift; (b) the final
//!      text is already used for the Reporter's context, mixing structured data
//!      with prose creates a parsing surface we'd have to maintain forever;
//!      (c) no validation at generation time — a malformed severity string
//!      wouldn't be caught until persistence, losing the finding silently.
//!
//!   2. **Tool call with shared collector**: give the Analyst a `create_finding`
//!      tool that it calls once per vulnerability. The tool validates severity
//!      at call time (returning an error the LLM can correct), writes to a
//!      `Arc<Mutex<Vec<Value>>>` collector, and returns a confirmation. After
//!      the agent loop exits, the orchestrator drains the collector.
//!      Accepted because: (a) validation happens immediately with LLM-visible
//!      feedback; (b) the tool-call contract is explicit in the schema — no
//!      parsing surface; (c) consistent with the tool-call pattern used by all
//!      other agents; (d) the collector pattern is O(1) overhead — no IPC,
//!      no extra DB round-trips during the agent loop.
//!
//! The collector stores `Vec<Value>` rather than `Vec<Finding>` because
//! `Finding` requires a `session_id` UUID that only the orchestrator knows.
//! The raw JSON values are converted to `Finding` structs in the orchestrator
//! after the tool loop exits.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde_json::{json, Value};

use sigint_llm::ToolDefinition;

use crate::error::{Result, ToolError};
use crate::result::ToolResult;
use sigint_core::types::ToolRisk;

use crate::tool::Tool;

/// Shared collector for raw finding JSON produced by the Analyst LLM.
///
/// Shared between `CreateFindingTool` (writer) and the orchestrator (reader).
/// The orchestrator drains this after the Analyst agent completes, converting
/// each `Value` into a `Finding` with the scan's `session_id`.
pub type FindingCollector = Arc<Mutex<Vec<Value>>>;

/// Create a new, empty `FindingCollector`.
pub fn new_finding_collector() -> FindingCollector {
    Arc::new(Mutex::new(Vec::new()))
}

/// Tool that the Analyst LLM calls to record each structured security finding.
///
/// Call this once per distinct vulnerability or misconfiguration. The finding
/// data is validated (severity enum), stored in the shared collector, and a
/// confirmation message is returned to the model so it can continue reasoning.
pub struct CreateFindingTool {
    /// Shared collector written by this tool, drained by the orchestrator.
    collector: FindingCollector,
}

impl CreateFindingTool {
    /// Construct a new `CreateFindingTool` backed by `collector`.
    pub fn new(collector: FindingCollector) -> Self {
        Self { collector }
    }
}

#[async_trait]
impl Tool for CreateFindingTool {
    fn name(&self) -> &str {
        "create_finding"
    }

    fn description(&self) -> &str {
        "Record a security finding with title, severity, description, evidence, and affected asset"
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::function(
            "create_finding",
            "Record a structured security finding discovered during analysis. \
             Call this once for each distinct vulnerability or misconfiguration identified.",
            json!({
                "type": "object",
                "properties": {
                    "title": {
                        "type": "string",
                        "description": "Short finding title (e.g. 'SQL Injection in login form')"
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["critical", "high", "medium", "low", "info"],
                        "description": "Severity rating following CVSS v3 guidelines"
                    },
                    "description": {
                        "type": "string",
                        "description": "Detailed description of the vulnerability"
                    },
                    "evidence": {
                        "type": "string",
                        "description": "Evidence: tool output, commands, URLs that prove the finding"
                    },
                    "asset": {
                        "type": "string",
                        "description": "Affected asset (IP, hostname, URL, service name)"
                    }
                },
                "required": ["title", "severity", "description"]
            }),
        )
    }

    async fn execute(&self, args: Value) -> Result<ToolResult> {
        // Validate required fields.
        let title = args
            .get("title")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::MissingArgument("title".into()))?;

        let severity = args
            .get("severity")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::MissingArgument("severity".into()))?;

        let description = args
            .get("description")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::MissingArgument("description".into()))?;

        // Validate severity enum — return an error the LLM can see and correct.
        match severity {
            "critical" | "high" | "medium" | "low" | "info" => {}
            other => {
                return Err(ToolError::InvalidArgument {
                    name: "severity".into(),
                    expected: format!(
                        "one of critical/high/medium/low/info, got '{other}'"
                    ),
                });
            }
        }

        let evidence = args
            .get("evidence")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let asset = args.get("asset").and_then(|v| v.as_str()).unwrap_or("");

        // Build the raw finding value and push to the collector.
        let finding_data = json!({
            "title": title,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "asset": asset,
        });

        {
            // Scope the lock to minimise hold time.
            let mut guard = self
                .collector
                .lock()
                .expect("finding collector lock poisoned");
            guard.push(finding_data.clone());
        }

        Ok(ToolResult {
            stdout: format!(
                "Finding recorded: [{}] {}",
                severity.to_uppercase(),
                title
            ),
            stderr: String::new(),
            exit_code: 0,
            duration: std::time::Duration::from_millis(0),
            structured_data: Some(finding_data),
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

    fn make_tool() -> (CreateFindingTool, FindingCollector) {
        let collector = new_finding_collector();
        let tool = CreateFindingTool::new(Arc::clone(&collector));
        (tool, collector)
    }

    #[tokio::test]
    async fn execute_valid_finding_returns_confirmation() {
        let (tool, collector) = make_tool();
        let args = json!({
            "title": "SQL Injection",
            "severity": "high",
            "description": "Unparameterised query in login form"
        });
        let result = tool.execute(args).await.unwrap();
        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.contains("[HIGH]"));
        assert!(result.stdout.contains("SQL Injection"));

        let guard = collector.lock().unwrap();
        assert_eq!(guard.len(), 1);
        assert_eq!(guard[0]["title"], "SQL Injection");
        assert_eq!(guard[0]["severity"], "high");
    }

    #[tokio::test]
    async fn execute_with_optional_fields() {
        let (tool, collector) = make_tool();
        let args = json!({
            "title": "Open Redis",
            "severity": "critical",
            "description": "Redis instance reachable without authentication",
            "evidence": "redis-cli -h 10.0.0.1 ping -> PONG",
            "asset": "10.0.0.1:6379"
        });
        let result = tool.execute(args).await.unwrap();
        assert!(result.stdout.contains("[CRITICAL]"));

        let guard = collector.lock().unwrap();
        assert_eq!(guard[0]["asset"], "10.0.0.1:6379");
        assert_eq!(guard[0]["evidence"], "redis-cli -h 10.0.0.1 ping -> PONG");
    }

    #[tokio::test]
    async fn execute_missing_title_returns_error() {
        let (tool, _) = make_tool();
        let args = json!({ "severity": "low", "description": "desc" });
        let err = tool.execute(args).await.unwrap_err();
        assert!(
            err.to_string().contains("title"),
            "error should mention 'title': {err}"
        );
    }

    #[tokio::test]
    async fn execute_missing_severity_returns_error() {
        let (tool, _) = make_tool();
        let args = json!({ "title": "Test", "description": "desc" });
        let err = tool.execute(args).await.unwrap_err();
        assert!(
            err.to_string().contains("severity"),
            "error should mention 'severity': {err}"
        );
    }

    #[tokio::test]
    async fn execute_missing_description_returns_error() {
        let (tool, _) = make_tool();
        let args = json!({ "title": "Test", "severity": "low" });
        let err = tool.execute(args).await.unwrap_err();
        assert!(
            err.to_string().contains("description"),
            "error should mention 'description': {err}"
        );
    }

    #[tokio::test]
    async fn execute_invalid_severity_returns_error() {
        let (tool, _) = make_tool();
        let args = json!({
            "title": "Test",
            "severity": "ultra-critical",
            "description": "desc"
        });
        let err = tool.execute(args).await.unwrap_err();
        assert!(
            err.to_string().contains("ultra-critical"),
            "error should include the invalid value: {err}"
        );
    }

    #[tokio::test]
    async fn all_severity_levels_accepted() {
        for sev in ["critical", "high", "medium", "low", "info"] {
            let (tool, _) = make_tool();
            let args = json!({
                "title": "Test",
                "severity": sev,
                "description": "desc"
            });
            let result = tool.execute(args).await;
            assert!(result.is_ok(), "severity '{sev}' should be accepted");
        }
    }

    #[tokio::test]
    async fn multiple_findings_accumulate_in_collector() {
        let (tool, collector) = make_tool();
        for i in 0..3 {
            let args = json!({
                "title": format!("Finding {i}"),
                "severity": "medium",
                "description": "desc"
            });
            tool.execute(args).await.unwrap();
        }
        let guard = collector.lock().unwrap();
        assert_eq!(guard.len(), 3);
    }

    #[test]
    fn tool_metadata() {
        let collector = new_finding_collector();
        let tool = CreateFindingTool::new(collector);
        assert_eq!(tool.name(), "create_finding");
        assert_eq!(tool.risk_level(), ToolRisk::Low);
        assert!(!tool.description().is_empty());
    }

    #[test]
    fn tool_definition_has_required_fields() {
        let collector = new_finding_collector();
        let tool = CreateFindingTool::new(collector);
        let def = tool.definition();
        assert_eq!(def.function.name, "create_finding");
        let schema = &def.function.parameters;
        let required = schema
            .get("required")
            .and_then(|r| r.as_array())
            .expect("required array should be present");
        assert!(required.iter().any(|v| v == "title"));
        assert!(required.iter().any(|v| v == "severity"));
        assert!(required.iter().any(|v| v == "description"));
    }

    #[test]
    fn structured_data_present_on_success() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let (tool, _) = make_tool();
        let result = rt
            .block_on(tool.execute(json!({
                "title": "XSS",
                "severity": "high",
                "description": "Reflected XSS"
            })))
            .unwrap();
        assert!(result.structured_data.is_some());
        let data = result.structured_data.unwrap();
        assert_eq!(data["title"], "XSS");
        assert_eq!(data["severity"], "high");
    }
}
