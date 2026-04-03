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
//!
//! @decision DEC-FINDING-002
//! @title Phase 12B enrichment fields are optional in both schema and execute()
//! @status accepted
//! @rationale All five new fields (remediation, exploitability, impact,
//! cvss_score, evidence_ref) are optional in the JSON schema so that existing
//! calls without them continue to work without modification. CVSS score is the
//! only field with a validation constraint (0.0–10.0) because out-of-range
//! values indicate a model error worth surfacing immediately. The remaining
//! fields are free-form strings — the Analyst is trusted to produce meaningful
//! content given the enriched system prompt. Fields missing from the call are
//! stored as JSON null in the collector so the orchestrator drain logic can use
//! a consistent `.as_str()` / `.as_f64()` access pattern regardless of whether
//! the field was provided.

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
/// data is validated (severity enum, CVSS range), stored in the shared
/// collector, and a confirmation message is returned to the model so it can
/// continue reasoning.
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
                    },
                    "remediation": {
                        "type": "string",
                        "description": "Recommended fix or mitigation steps for this vulnerability"
                    },
                    "exploitability": {
                        "type": "string",
                        "description": "How easily this vulnerability can be exploited \
                                        (e.g., requires authentication, publicly accessible, \
                                        requires local access)"
                    },
                    "impact": {
                        "type": "string",
                        "description": "Business or technical impact if this vulnerability is exploited"
                    },
                    "cvss_score": {
                        "type": "number",
                        "description": "CVSS v3.1 base score (0.0-10.0). Provide when you can \
                                        confidently assess the score based on the evidence."
                    },
                    "evidence_ref": {
                        "type": "string",
                        "description": "UUID of the scan_history record that produced the \
                                        primary evidence for this finding"
                    },
                    "asset_id": {
                        "type": "string",
                        "description": "UUID of the discovered asset this finding relates to"
                    }
                },
                "required": ["title", "severity", "description"]
            }),
        )
    }

    async fn execute(&self, args: Value) -> Result<ToolResult> {
        // ── Required fields ───────────────────────────────────────────────────
        let title = args
            .get("title")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::MissingArgument("title".into()))?;

        let severity_raw = args
            .get("severity")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ToolError::MissingArgument("severity".into()))?;
        // Normalize to lowercase — LLMs often send "High", "Critical", etc.
        let severity = severity_raw.to_lowercase();
        let severity = severity.as_str();

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
                    expected: format!("one of critical/high/medium/low/info, got '{other}'"),
                });
            }
        }

        // ── Optional base fields ─────────────────────────────────────────────
        let evidence = args.get("evidence").and_then(|v| v.as_str()).unwrap_or("");
        let asset = args.get("asset").and_then(|v| v.as_str()).unwrap_or("");

        // ── Optional enrichment fields (Phase 12B) ───────────────────────────
        let remediation = args.get("remediation").and_then(|v| v.as_str());
        let exploitability = args.get("exploitability").and_then(|v| v.as_str());
        let impact = args.get("impact").and_then(|v| v.as_str());
        let evidence_ref = args.get("evidence_ref").and_then(|v| v.as_str());
        let asset_id = args.get("asset_id").and_then(|v| v.as_str());

        // cvss_score: present as JSON number, validated to [0.0, 10.0].
        let cvss_score_raw = args.get("cvss_score").and_then(|v| v.as_f64());
        if let Some(score) = cvss_score_raw {
            if !(0.0..=10.0).contains(&score) {
                return Err(ToolError::InvalidArgument {
                    name: "cvss_score".into(),
                    expected: format!("a number in the range 0.0-10.0, got {score}"),
                });
            }
        }

        // Build the raw finding value. Enrichment fields use null when absent
        // so the orchestrator can use a uniform access pattern on the drained
        // values without special-casing missing keys.
        let finding_data = json!({
            "title": title,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "asset": asset,
            "remediation": remediation,
            "exploitability": exploitability,
            "impact": impact,
            "cvss_score": cvss_score_raw,
            "evidence_ref": evidence_ref,
            "asset_id": asset_id,
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
            stdout: format!("Finding recorded: [{}] {}", severity.to_uppercase(), title),
            stderr: String::new(),
            exit_code: 0,
            duration: std::time::Duration::from_millis(0),
            structured_data: Some(finding_data),
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

    fn make_tool() -> (CreateFindingTool, FindingCollector) {
        let collector = new_finding_collector();
        let tool = CreateFindingTool::new(Arc::clone(&collector));
        (tool, collector)
    }

    // ── Existing tests (backward compat) ─────────────────────────────────────

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
    async fn execute_accepts_capitalized_severity() {
        let collector = new_finding_collector();
        let tool = CreateFindingTool::new(Arc::clone(&collector));
        let args = json!({
            "title": "Test",
            "severity": "High",
            "description": "test"
        });
        let result = tool.execute(args).await.unwrap();
        assert!(result.success());
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

    // ── New tests: Phase 12B enrichment fields ────────────────────────────────

    #[tokio::test]
    async fn execute_with_enriched_fields() {
        let (tool, collector) = make_tool();
        let args = json!({
            "title": "SQL Injection",
            "severity": "critical",
            "description": "Unparameterised query in login form allows authentication bypass",
            "evidence": "' OR '1'='1 returned 200 OK with admin dashboard",
            "asset": "10.0.0.1:443/login",
            "remediation": "Use parameterized queries or prepared statements. Never interpolate user input into SQL.",
            "exploitability": "publicly accessible, no authentication required",
            "impact": "Full database access; attacker can read, modify, or delete all records",
            "cvss_score": 9.8,
            "evidence_ref": "550e8400-e29b-41d4-a716-446655440000"
        });
        let result = tool.execute(args).await.unwrap();
        assert_eq!(result.exit_code, 0);
        assert!(result.stdout.contains("[CRITICAL]"));

        let guard = collector.lock().unwrap();
        assert_eq!(guard.len(), 1);
        let data = &guard[0];
        assert_eq!(
            data["remediation"],
            "Use parameterized queries or prepared statements. Never interpolate user input into SQL."
        );
        assert_eq!(
            data["exploitability"],
            "publicly accessible, no authentication required"
        );
        assert_eq!(
            data["impact"],
            "Full database access; attacker can read, modify, or delete all records"
        );
        assert_eq!(data["cvss_score"], 9.8);
        assert_eq!(data["evidence_ref"], "550e8400-e29b-41d4-a716-446655440000");
    }

    #[tokio::test]
    async fn execute_with_cvss_score() {
        let (tool, collector) = make_tool();
        let args = json!({
            "title": "Weak TLS",
            "severity": "medium",
            "description": "Server accepts TLS 1.0 connections",
            "cvss_score": 5.3
        });
        let result = tool.execute(args).await.unwrap();
        assert_eq!(result.exit_code, 0);

        let guard = collector.lock().unwrap();
        let score = guard[0]["cvss_score"]
            .as_f64()
            .expect("cvss_score should be a number");
        assert!((score - 5.3).abs() < 0.001, "expected 5.3, got {score}");
    }

    #[tokio::test]
    async fn execute_cvss_score_at_boundaries_accepted() {
        // 0.0 and 10.0 are valid boundary values
        for score in [0.0_f64, 10.0_f64] {
            let (tool, _) = make_tool();
            let args = json!({
                "title": "Test",
                "severity": "info",
                "description": "boundary test",
                "cvss_score": score
            });
            let result = tool.execute(args).await;
            assert!(result.is_ok(), "cvss_score={score} should be accepted");
        }
    }

    #[tokio::test]
    async fn execute_cvss_out_of_range_high_returns_error() {
        let (tool, _) = make_tool();
        let args = json!({
            "title": "Test",
            "severity": "high",
            "description": "desc",
            "cvss_score": 10.1
        });
        let err = tool.execute(args).await.unwrap_err();
        assert!(
            err.to_string().contains("cvss_score"),
            "error should mention 'cvss_score': {err}"
        );
        assert!(
            err.to_string().contains("10.1"),
            "error should include the invalid value: {err}"
        );
    }

    #[tokio::test]
    async fn execute_cvss_out_of_range_negative_returns_error() {
        let (tool, _) = make_tool();
        let args = json!({
            "title": "Test",
            "severity": "low",
            "description": "desc",
            "cvss_score": -1.0
        });
        let err = tool.execute(args).await.unwrap_err();
        assert!(
            err.to_string().contains("cvss_score"),
            "error should mention 'cvss_score': {err}"
        );
    }

    #[tokio::test]
    async fn execute_with_evidence_ref() {
        let (tool, collector) = make_tool();
        let uuid = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
        let args = json!({
            "title": "Open Port",
            "severity": "info",
            "description": "Port 22 open",
            "evidence_ref": uuid
        });
        let result = tool.execute(args).await.unwrap();
        assert_eq!(result.exit_code, 0);

        let guard = collector.lock().unwrap();
        assert_eq!(guard[0]["evidence_ref"], uuid);
    }

    #[tokio::test]
    async fn enrichment_fields_absent_when_not_provided() {
        // Calls without new fields must still work; absent fields are null in JSON.
        let (tool, collector) = make_tool();
        let args = json!({
            "title": "Test Finding",
            "severity": "low",
            "description": "minimal call"
        });
        tool.execute(args).await.unwrap();

        let guard = collector.lock().unwrap();
        // Keys are present but their values are JSON null
        assert!(guard[0]["remediation"].is_null());
        assert!(guard[0]["exploitability"].is_null());
        assert!(guard[0]["impact"].is_null());
        assert!(guard[0]["cvss_score"].is_null());
        assert!(guard[0]["evidence_ref"].is_null());
    }

    #[test]
    fn tool_definition_has_enrichment_properties() {
        let collector = new_finding_collector();
        let tool = CreateFindingTool::new(collector);
        let def = tool.definition();
        let props = def
            .function
            .parameters
            .get("properties")
            .expect("properties should be present");
        for field in [
            "remediation",
            "exploitability",
            "impact",
            "cvss_score",
            "evidence_ref",
        ] {
            assert!(
                props.get(field).is_some(),
                "schema should define property '{field}'"
            );
        }
        // New fields must NOT appear in required — they are optional
        let required = def
            .function
            .parameters
            .get("required")
            .and_then(|r| r.as_array())
            .expect("required should be an array");
        for field in [
            "remediation",
            "exploitability",
            "impact",
            "cvss_score",
            "evidence_ref",
        ] {
            assert!(
                !required.iter().any(|v| v == field),
                "'{field}' must not be in required array"
            );
        }
    }

    // ── Tests: asset_id field ────────────────────────────────────────────────

    #[tokio::test]
    async fn execute_with_asset_id() {
        let (tool, collector) = make_tool();
        let args = json!({
            "title": "Open Port",
            "severity": "info",
            "description": "Port 22 open",
            "asset_id": "550e8400-e29b-41d4-a716-446655440000"
        });
        let result = tool.execute(args).await.unwrap();
        assert_eq!(result.exit_code, 0);
        let guard = collector.lock().unwrap();
        assert_eq!(guard[0]["asset_id"], "550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn tool_definition_has_asset_id_property() {
        let collector = new_finding_collector();
        let tool = CreateFindingTool::new(collector);
        let def = tool.definition();
        let props = def.function.parameters.get("properties").expect("properties");
        assert!(props.get("asset_id").is_some(), "schema should define asset_id property");
        let required = def.function.parameters.get("required").and_then(|r| r.as_array()).unwrap();
        assert!(!required.iter().any(|v| v == "asset_id"), "asset_id must not be required");
    }
}
