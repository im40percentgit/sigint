//! Integration tests for sigint_train::evaluate — live A/B comparison.
//!
//! Uses MockProvider from sigint_llm to inject canned tool-call responses
//! without requiring a real LLM server. Two scenarios:
//!
//! Test A: candidate wins on tool accuracy (~+30pp).
//! Test B: persist_last_eval round-trip — write then read JSON.

use serde_json::json;
use sigint_llm::{MockProvider, MockResponse};
use sigint_train::{
    evaluate::{persist_last_eval, run_comparison},
    TrainingExample, TrainingFunction, TrainingMessage, TrainingToolCall,
};
use tempfile::TempDir;
use uuid::Uuid;

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Build a minimal TrainingExample that expects `tool_name(tool_args)`.
fn make_example(tool_name: &str, tool_args: &str) -> TrainingExample {
    TrainingExample {
        session_id: Uuid::new_v4(),
        messages: vec![
            TrainingMessage {
                role: "system".to_string(),
                content: Some("You are a penetration testing assistant.".to_string()),
                tool_calls: None,
                tool_call_id: None,
            },
            TrainingMessage {
                role: "user".to_string(),
                content: Some("Scan the target host.".to_string()),
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

// ── Test A: candidate wins on tool accuracy ───────────────────────────────────

/// Ground truth: all 10 examples expect nmap_scan.
/// Base returns gobuster_scan for 4 of them -> 6/10 correct (60%).
/// Candidate returns nmap_scan for 9/10 -> 9/10 correct (90%).
/// Expected tool_accuracy_delta ≈ +0.30 (i.e. +30pp).
#[tokio::test]
async fn candidate_wins_on_tool_accuracy() {
    let n = 10;
    let examples: Vec<TrainingExample> = (0..n)
        .map(|_| make_example("nmap_scan", r#"{"target":"10.0.0.1"}"#))
        .collect();

    // Base: correct for examples 0-5 (6/10), wrong (gobuster) for 6-9.
    let base_responses: Vec<MockResponse> = (0..n)
        .map(|i| {
            if i < 6 {
                MockResponse::ToolCall {
                    name: "nmap_scan".into(),
                    arguments: json!({"target": "10.0.0.1"}),
                }
            } else {
                MockResponse::ToolCall {
                    name: "gobuster_scan".into(),
                    arguments: json!({"url": "http://10.0.0.1"}),
                }
            }
        })
        .collect();

    // Candidate: correct for examples 0-8 (9/10), wrong for 9.
    let cand_responses: Vec<MockResponse> = (0..n)
        .map(|i| {
            if i < 9 {
                MockResponse::ToolCall {
                    name: "nmap_scan".into(),
                    arguments: json!({"target": "10.0.0.1"}),
                }
            } else {
                MockResponse::ToolCall {
                    name: "gobuster_scan".into(),
                    arguments: json!({"url": "http://10.0.0.1"}),
                }
            }
        })
        .collect();

    let base = MockProvider::with_responses(base_responses);
    let candidate = MockProvider::with_responses(cand_responses);

    let report = run_comparison(&base, &candidate, &examples, "llama3.2:8b", "sigint-ft:latest")
        .await
        .expect("comparison should succeed");

    // Base: 6/10 = 0.60
    assert!(
        (report.base_results.tool_accuracy - 0.6).abs() < 1e-9,
        "base tool_accuracy should be 0.60, got {}",
        report.base_results.tool_accuracy
    );

    // Candidate: 9/10 = 0.90
    assert!(
        (report.candidate_results.tool_accuracy - 0.9).abs() < 1e-9,
        "candidate tool_accuracy should be 0.90, got {}",
        report.candidate_results.tool_accuracy
    );

    // Delta should be positive (~+0.30).
    assert!(
        report.tool_accuracy_delta > 0.0,
        "delta should be positive (candidate beats base)"
    );
    assert!(
        (report.tool_accuracy_delta - 0.3).abs() < 1e-9,
        "delta should be ~+0.30, got {}",
        report.tool_accuracy_delta
    );

    assert_eq!(report.total_examples, n);
    assert_eq!(report.base_tag, "llama3.2:8b");
    assert_eq!(report.candidate_tag, "sigint-ft:latest");
}

// ── Test B: persist_last_eval round-trip ─────────────────────────────────────

/// Write a ComparisonReport to a temp dir, read it back, assert fields match.
#[tokio::test]
async fn persist_last_eval_roundtrip() {
    let tmp = TempDir::new().expect("tempdir");

    // Build a minimal report via a 2-example comparison so we exercise the
    // full code path rather than constructing the struct by hand.
    let examples = vec![
        make_example("nmap_scan", r#"{"target":"192.168.1.1"}"#),
        make_example("shell", r#"{"cmd":"whoami"}"#),
    ];

    let base = MockProvider::with_responses(vec![
        MockResponse::ToolCall {
            name: "nmap_scan".into(),
            arguments: json!({"target": "192.168.1.1"}),
        },
        MockResponse::ToolCall {
            name: "shell".into(),
            arguments: json!({"cmd": "whoami"}),
        },
    ]);

    let candidate = MockProvider::with_responses(vec![
        MockResponse::ToolCall {
            name: "nmap_scan".into(),
            arguments: json!({"target": "192.168.1.1"}),
        },
        // Candidate gets the second one wrong.
        MockResponse::ToolCall {
            name: "gobuster_scan".into(),
            arguments: json!({"url": "http://192.168.1.1"}),
        },
    ]);

    let report = run_comparison(&base, &candidate, &examples, "base-model", "cand-model")
        .await
        .expect("comparison should succeed");

    persist_last_eval(tmp.path(), &report).expect("persist should succeed");

    // Read back and deserialise.
    let json_path = tmp.path().join("last_eval.json");
    assert!(json_path.exists(), "last_eval.json should exist");

    let json_str = std::fs::read_to_string(&json_path).expect("read last_eval.json");
    let restored: sigint_train::evaluate::ComparisonReport =
        serde_json::from_str(&json_str).expect("deserialise ComparisonReport");

    assert_eq!(restored.total_examples, 2);
    assert_eq!(restored.base_tag, "base-model");
    assert_eq!(restored.candidate_tag, "cand-model");

    // Base got both right: tool_accuracy = 1.0
    assert!(
        (restored.base_results.tool_accuracy - 1.0).abs() < 1e-9,
        "base should have 100% tool accuracy, got {}",
        restored.base_results.tool_accuracy
    );

    // Candidate got first right, second wrong: tool_accuracy = 0.5
    assert!(
        (restored.candidate_results.tool_accuracy - 0.5).abs() < 1e-9,
        "candidate should have 50% tool accuracy, got {}",
        restored.candidate_results.tool_accuracy
    );

    // Delta should be negative (candidate worse than base).
    assert!(
        restored.tool_accuracy_delta < 0.0,
        "delta should be negative here, got {}",
        restored.tool_accuracy_delta
    );
    assert!(
        (restored.tool_accuracy_delta - (-0.5)).abs() < 1e-9,
        "delta should be -0.50, got {}",
        restored.tool_accuracy_delta
    );
}

// ── Test C: base wins (negative delta) ───────────────────────────────────────

/// Sanity-check: when candidate is worse, delta is negative and the struct
/// clearly surfaces it. Ensures the sign convention is correct.
#[tokio::test]
async fn base_wins_gives_negative_delta() {
    let examples = vec![make_example("nmap_scan", r#"{"target":"10.0.0.1"}"#)];

    let base = MockProvider::with_responses(vec![MockResponse::ToolCall {
        name: "nmap_scan".into(),
        arguments: json!({"target": "10.0.0.1"}),
    }]);

    // Candidate hallucinates text instead of a tool call — recorded as miss.
    let candidate = MockProvider::with_responses(vec![MockResponse::Text(
        "I will scan the target.".into(),
    )]);

    let report = run_comparison(&base, &candidate, &examples, "base", "cand")
        .await
        .expect("comparison should succeed");

    assert!(
        report.tool_accuracy_delta < 0.0,
        "delta should be negative when candidate misses: {}",
        report.tool_accuracy_delta
    );
    assert_eq!(report.base_results.correct_tool, 1);
    assert_eq!(report.candidate_results.correct_tool, 0);
}
