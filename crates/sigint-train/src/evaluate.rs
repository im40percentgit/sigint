//! Live A/B comparison of two LLM providers against a held-out test set.
//!
//! Calls each provider chat() with the pre-assistant context from every
//! test example, collects the first tool_call from each response, runs
//! assess::assess on both prediction vectors, and returns a ComparisonReport.
//!
//! @decision DEC-P24-003
//! @title Evaluation methodology: live inference of both providers
//! @status accepted
//! @rationale Supersedes the Phase 23 placeholder in assess which returned
//! ground-truth self-evaluation (100% tool-accuracy by construction).
//! Live inference of BOTH base and candidate providers against the held-out
//! test set is the only methodology that closes the fine-tune loop: it detects
//! real regressions introduced by fine-tuning and produces a meaningful delta.
//! Chosen over: offline-only (no inference, can't detect drift); live-session
//! A/B sampling (needs Phase 25 telemetry). REQ-P24-P0-003, REQ-P24-GOAL-002.

use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use sigint_llm::{ChatMessage, ChatRequest, LlmProvider, ToolCall};

use crate::{assess, AssessResults, TrainingExample, TrainingMessage};

// ── Public types ──────────────────────────────────────────────────────────────

/// Results from a live A/B comparison of two LLM providers.
///
/// tool_accuracy_delta and argument_match_delta are expressed as fractions
/// in [-1, 1], matching the convention in AssessResults. Multiply by 100 to
/// convert to percentage-points. A positive delta means candidate beat base.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComparisonReport {
    /// Tag/name of the baseline provider (e.g. "llama3.2:8b").
    pub base_tag: String,
    /// Tag/name of the candidate provider (e.g. "sigint-ft:latest").
    pub candidate_tag: String,
    /// Assessment results for the baseline provider.
    pub base_results: SerializableAssessResults,
    /// Assessment results for the candidate provider.
    pub candidate_results: SerializableAssessResults,
    /// candidate.tool_accuracy - base.tool_accuracy (fraction; positive = candidate better).
    pub tool_accuracy_delta: f64,
    /// candidate.argument_accuracy - base.argument_accuracy (fraction; positive = candidate better).
    pub argument_match_delta: f64,
    /// Number of test examples used in this run.
    pub total_examples: usize,
    /// UTC timestamp when the comparison completed.
    pub evaluated_at: DateTime<Utc>,
}

/// Serializable snapshot of AssessResults for JSON persistence.
///
/// AssessResults is an internal type without Serialize. This mirror struct
/// carries the scalar fields needed in the persisted report. Per-tool metrics
/// are omitted from last_eval.json to keep the file small.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableAssessResults {
    pub total_examples: usize,
    pub correct_tool: usize,
    pub tool_accuracy: f64,
    pub argument_exact_match: usize,
    pub argument_accuracy: f64,
}

impl From<&AssessResults> for SerializableAssessResults {
    fn from(r: &AssessResults) -> Self {
        SerializableAssessResults {
            total_examples: r.total_examples,
            correct_tool: r.correct_tool,
            tool_accuracy: r.tool_accuracy,
            argument_exact_match: r.argument_exact_match,
            argument_accuracy: r.argument_accuracy,
        }
    }
}

// ── Core comparison function ──────────────────────────────────────────────────

/// Run a live A/B comparison of base vs candidate over test_examples.
///
/// For each example the function:
/// 1. Reconstructs the pre-assistant message context (all messages before the
///    first assistant turn).
/// 2. Sends that context to both providers via chat().
/// 3. Extracts the first tool call from each response as (name, arguments_json).
///    If a provider returns no tool_calls (text-only response), records ("", "").
/// 4. Runs assess::assess on both prediction vectors.
/// 5. Returns a ComparisonReport with delta metrics.
///
/// Delta unit: fractions (same as AssessResults::tool_accuracy). Multiply by
/// 100 to express as percentage-points in output.
///
/// @decision DEC-P24-003
/// @title Live inference of both providers, not ground-truth self-comparison
/// @status accepted
/// @rationale See module-level doc.
pub async fn run_comparison(
    base: &dyn LlmProvider,
    candidate: &dyn LlmProvider,
    test_examples: &[TrainingExample],
    base_tag: &str,
    candidate_tag: &str,
) -> Result<ComparisonReport> {
    run_comparison_with_progress(
        base,
        candidate,
        test_examples,
        base_tag,
        candidate_tag,
        |_| {},
    )
    .await
}

/// Run a live A/B comparison with per-example progress callbacks.
///
/// This is the full implementation.  `run_comparison` delegates here with a
/// no-op callback.  Web callers pass a closure that emits
/// `Event::EvaluationProgress` after each example.
///
/// `on_progress(examples_done: usize)` is called after each example pair
/// (base + candidate) is evaluated.
///
/// @decision DEC-P26-001
/// @title EvaluationProgress emitted per-example via callback — no throttling needed
/// @status accepted
/// @rationale `run_comparison` is a pure async tokio loop; each iteration is
/// one pair of LLM calls (base + candidate).  Emitting one EvaluationProgress
/// event per iteration is safe — the event bus has a large capacity and eval
/// sets are small (tens to hundreds of examples, not millions). No rate-limiting
/// is applied; unlike TrainingJobProgress (which tails a process stdout stream),
/// EvaluationProgress has a natural upper bound equal to total_examples.
/// Addresses: REQ-P26-P0-004.
pub async fn run_comparison_with_progress<F>(
    base: &dyn LlmProvider,
    candidate: &dyn LlmProvider,
    test_examples: &[TrainingExample],
    base_tag: &str,
    candidate_tag: &str,
    on_progress: F,
) -> Result<ComparisonReport>
where
    F: Fn(usize),
{
    let mut base_preds: Vec<(String, String)> = Vec::with_capacity(test_examples.len());
    let mut cand_preds: Vec<(String, String)> = Vec::with_capacity(test_examples.len());

    for (i, example) in test_examples.iter().enumerate() {
        let context = build_context_messages(&example.messages);

        // Base provider inference.
        let base_req = ChatRequest::new(base_tag, context.clone());
        let base_resp = base
            .chat(base_req)
            .await
            .context("base provider chat() failed")?;
        base_preds.push(extract_first_tool_call(&base_resp.tool_calls));

        // Candidate provider inference.
        let cand_req = ChatRequest::new(candidate_tag, context);
        let cand_resp = candidate
            .chat(cand_req)
            .await
            .context("candidate provider chat() failed")?;
        cand_preds.push(extract_first_tool_call(&cand_resp.tool_calls));

        // Emit progress after each example pair.  examples_done is 1-based.
        on_progress(i + 1);
    }

    let base_results = assess::assess(&base_preds, test_examples);
    let cand_results = assess::assess(&cand_preds, test_examples);

    let tool_accuracy_delta = cand_results.tool_accuracy - base_results.tool_accuracy;
    let argument_match_delta = cand_results.argument_accuracy - base_results.argument_accuracy;
    let total_examples = test_examples.len();

    Ok(ComparisonReport {
        base_tag: base_tag.to_string(),
        candidate_tag: candidate_tag.to_string(),
        base_results: SerializableAssessResults::from(&base_results),
        candidate_results: SerializableAssessResults::from(&cand_results),
        tool_accuracy_delta,
        argument_match_delta,
        total_examples,
        evaluated_at: Utc::now(),
    })
}

/// Persist a ComparisonReport to job_dir/last_eval.json (latest-only, overwritten each time).
///
/// This file is read by Task 4's sigint model promote to gate promotion behind
/// min_eval_examples (REQ-P24-P1-001).
pub fn persist_last_eval(job_dir: &Path, report: &ComparisonReport) -> Result<()> {
    std::fs::create_dir_all(job_dir)
        .with_context(|| format!("failed to create job_dir: {}", job_dir.display()))?;

    let path = job_dir.join("last_eval.json");
    let json =
        serde_json::to_string_pretty(report).context("failed to serialize ComparisonReport")?;

    std::fs::write(&path, json).with_context(|| format!("failed to write {}", path.display()))?;

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build the chat context from a training example's messages, stopping just
/// before the first assistant turn. This reconstructs what the model saw as
/// input: system prompt + user messages preceding the tool call.
fn build_context_messages(messages: &[TrainingMessage]) -> Vec<ChatMessage> {
    let mut out = Vec::new();
    for msg in messages {
        if msg.role == "assistant" {
            break;
        }
        let content = msg.content.clone().unwrap_or_default();
        let chat_msg = match msg.role.as_str() {
            "system" => ChatMessage::system(content),
            "tool" => ChatMessage::tool(content),
            _ => ChatMessage::user(content),
        };
        out.push(chat_msg);
    }
    out
}

/// Extract the first tool call from a provider response as (name, arguments_json).
/// Returns ("", "") when the model returned text content only (counted as a miss
/// by assess::assess).
fn extract_first_tool_call(tool_calls: &[ToolCall]) -> (String, String) {
    if let Some(tc) = tool_calls.first() {
        let name = tc.function.name.clone();
        // Arguments in LLM types are serde_json::Value; serialize to a JSON
        // string so we can compare with TrainingFunction::arguments which is
        // already a JSON string.
        let args = serde_json::to_string(&tc.function.arguments).unwrap_or_default();
        (name, args)
    } else {
        (String::new(), String::new())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TrainingFunction, TrainingMessage, TrainingToolCall};
    use serde_json::json;
    use sigint_llm::FunctionCall;
    use uuid::Uuid;

    fn make_example(tool_name: &str, tool_args: &str) -> TrainingExample {
        TrainingExample {
            session_id: Uuid::new_v4(),
            messages: vec![
                TrainingMessage {
                    role: "system".to_string(),
                    content: Some("You are a security scanner.".to_string()),
                    tool_calls: None,
                    tool_call_id: None,
                },
                TrainingMessage {
                    role: "user".to_string(),
                    content: Some("Scan the host.".to_string()),
                    tool_calls: None,
                    tool_call_id: None,
                },
                TrainingMessage {
                    role: "assistant".to_string(),
                    content: None,
                    tool_calls: Some(vec![TrainingToolCall {
                        id: "call_test".to_string(),
                        call_type: "function".to_string(),
                        function: TrainingFunction {
                            name: tool_name.to_string(),
                            arguments: tool_args.to_string(),
                        },
                    }]),
                    tool_call_id: None,
                },
            ],
        }
    }

    #[test]
    fn build_context_stops_before_assistant() {
        let example = make_example("nmap_scan", r#"{"target":"10.0.0.1"}"#);
        let ctx = build_context_messages(&example.messages);
        assert_eq!(ctx.len(), 2, "system + user only, not assistant");
        assert_eq!(ctx[0].role, "system");
        assert_eq!(ctx[1].role, "user");
    }

    #[test]
    fn extract_first_tool_call_empty_returns_miss() {
        let result = extract_first_tool_call(&[]);
        assert_eq!(result, (String::new(), String::new()));
    }

    #[test]
    fn extract_first_tool_call_returns_name_and_serialized_args() {
        let tc = ToolCall {
            function: FunctionCall {
                name: "nmap_scan".into(),
                arguments: json!({"target": "10.0.0.1"}),
            },
        };
        let (name, args) = extract_first_tool_call(&[tc]);
        assert_eq!(name, "nmap_scan");
        let parsed: serde_json::Value = serde_json::from_str(&args).unwrap();
        assert_eq!(parsed["target"], "10.0.0.1");
    }

    #[test]
    fn serializable_assess_results_from_ref() {
        use std::collections::HashMap;
        let r = AssessResults {
            total_examples: 10,
            correct_tool: 7,
            tool_accuracy: 0.7,
            argument_exact_match: 5,
            argument_accuracy: 0.5,
            per_tool: HashMap::new(),
        };
        let s = SerializableAssessResults::from(&r);
        assert_eq!(s.total_examples, 10);
        assert!((s.tool_accuracy - 0.7).abs() < 1e-9);
        assert_eq!(s.argument_exact_match, 5);
    }
}
