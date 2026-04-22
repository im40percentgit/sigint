//! Assessment harness for fine-tuned model accuracy.
//!
//! Compares model predictions (tool_name, arguments) against ground-truth
//! TrainingExamples and computes tool selection accuracy, argument exact-match
//! rate, and per-tool precision/recall metrics.
//!
//! @decision DEC-TRAIN-006
//! @title Argument comparison uses exact string match on normalized JSON
//! @status accepted
//! @rationale Semantic argument comparison (e.g. treating {"a":1,"b":2} ==
//! {"b":2,"a":1}) requires re-parsing every argument string. Since training
//! data arguments come from ScanRecord.args which is already serialized
//! deterministically by the tool wrappers, exact string match is sufficient
//! for a first-pass harness. Users who need fuzzy matching can compare the
//! parsed JSON values directly using the public types.

use std::collections::HashMap;

use crate::{AssessResults, ToolAssessMetrics, TrainingExample};

/// Compare model predictions against ground-truth training examples.
///
/// # Arguments
/// * `predictions` — `(tool_name, arguments)` pairs produced by the model,
///   one per ground-truth example in the same order.
/// * `ground_truth` — the test-set TrainingExamples to evaluate against.
///
/// Returns an `AssessResults` with accuracy metrics and per-tool statistics.
pub fn assess(predictions: &[(String, String)], ground_truth: &[TrainingExample]) -> AssessResults {
    let total = ground_truth.len();
    let mut correct_tool = 0usize;
    let mut argument_exact_match = 0usize;
    let mut per_tool: HashMap<String, ToolAssessMetrics> = HashMap::new();

    for (i, example) in ground_truth.iter().enumerate() {
        // Extract the expected tool call from the assistant message.
        let expected = extract_tool_call(example);

        let (pred_tool, pred_args) = predictions
            .get(i)
            .map(|(t, a)| (t.as_str(), a.as_str()))
            .unwrap_or(("", ""));

        match &expected {
            Some((exp_tool, exp_args)) => {
                let tool_correct = pred_tool == exp_tool;
                let args_correct = tool_correct && pred_args == exp_args.as_str();

                if tool_correct {
                    correct_tool += 1;
                }
                if args_correct {
                    argument_exact_match += 1;
                }

                // True positive: predicted the right tool.
                if tool_correct {
                    per_tool.entry(exp_tool.clone()).or_default().true_positives += 1;
                } else {
                    // False negative on expected tool (we missed it).
                    per_tool
                        .entry(exp_tool.clone())
                        .or_default()
                        .false_negatives += 1;

                    // False positive on the wrongly predicted tool.
                    if !pred_tool.is_empty() {
                        per_tool
                            .entry(pred_tool.to_string())
                            .or_default()
                            .false_positives += 1;
                    }
                }
            }
            None => {
                // Ground truth has no tool call — any prediction is a false positive.
                if !pred_tool.is_empty() {
                    per_tool
                        .entry(pred_tool.to_string())
                        .or_default()
                        .false_positives += 1;
                }
            }
        }
    }

    // Compute precision and recall for each tool.
    for metrics in per_tool.values_mut() {
        let tp = metrics.true_positives as f64;
        let fp = metrics.false_positives as f64;
        let fn_ = metrics.false_negatives as f64;

        metrics.precision = if tp + fp > 0.0 { tp / (tp + fp) } else { 0.0 };
        metrics.recall = if tp + fn_ > 0.0 { tp / (tp + fn_) } else { 0.0 };
    }

    let tool_accuracy = if total > 0 {
        correct_tool as f64 / total as f64
    } else {
        0.0
    };
    let argument_accuracy = if total > 0 {
        argument_exact_match as f64 / total as f64
    } else {
        0.0
    };

    AssessResults {
        total_examples: total,
        correct_tool,
        tool_accuracy,
        argument_exact_match,
        argument_accuracy,
        per_tool,
    }
}

/// Extract the first tool call (name, arguments) from a TrainingExample's
/// assistant message. Returns None if the example has no tool call.
fn extract_tool_call(example: &TrainingExample) -> Option<(String, String)> {
    for msg in &example.messages {
        if msg.role == "assistant" {
            if let Some(calls) = &msg.tool_calls {
                if let Some(call) = calls.first() {
                    return Some((call.function.name.clone(), call.function.arguments.clone()));
                }
            }
        }
    }
    None
}

/// Print a formatted assessment results report to stdout.
pub fn print_results(results: &AssessResults) {
    println!("Assessment Results");
    println!("==================");
    println!("Total examples   : {}", results.total_examples);
    println!(
        "Tool accuracy    : {:.1}%  ({}/{})",
        results.tool_accuracy * 100.0,
        results.correct_tool,
        results.total_examples,
    );
    println!(
        "Argument match   : {:.1}%  ({}/{})",
        results.argument_accuracy * 100.0,
        results.argument_exact_match,
        results.total_examples,
    );

    if !results.per_tool.is_empty() {
        println!();
        println!("Per-tool metrics:");
        println!(
            "  {:<30} {:>6} {:>6} {:>6} {:>10} {:>10}",
            "Tool", "TP", "FP", "FN", "Precision", "Recall"
        );
        println!("  {}", "-".repeat(76));

        let mut tools: Vec<(&String, &ToolAssessMetrics)> = results.per_tool.iter().collect();
        tools.sort_by(|a, b| a.0.cmp(b.0));

        for (tool, m) in tools {
            println!(
                "  {:<30} {:>6} {:>6} {:>6} {:>9.1}% {:>9.1}%",
                tool,
                m.true_positives,
                m.false_positives,
                m.false_negatives,
                m.precision * 100.0,
                m.recall * 100.0,
            );
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{TrainingFunction, TrainingMessage, TrainingToolCall};
    use uuid::Uuid;

    fn make_example(tool_name: &str, tool_args: &str) -> TrainingExample {
        let call_id = "call_test".to_string();
        TrainingExample {
            session_id: Uuid::new_v4(),
            messages: vec![
                TrainingMessage {
                    role: "system".to_string(),
                    content: Some("System.".to_string()),
                    tool_calls: None,
                    tool_call_id: None,
                },
                TrainingMessage {
                    role: "assistant".to_string(),
                    content: None,
                    tool_calls: Some(vec![TrainingToolCall {
                        id: call_id.clone(),
                        call_type: "function".to_string(),
                        function: TrainingFunction {
                            name: tool_name.to_string(),
                            arguments: tool_args.to_string(),
                        },
                    }]),
                    tool_call_id: None,
                },
                TrainingMessage {
                    role: "tool".to_string(),
                    content: Some("output".to_string()),
                    tool_calls: None,
                    tool_call_id: Some(call_id),
                },
            ],
        }
    }

    #[test]
    fn perfect_predictions_give_100_percent() {
        let examples = vec![
            make_example("nmap_scan", r#"{"target":"10.0.0.1"}"#),
            make_example("shell", r#"{"cmd":"whoami"}"#),
        ];
        let predictions = vec![
            (
                "nmap_scan".to_string(),
                r#"{"target":"10.0.0.1"}"#.to_string(),
            ),
            ("shell".to_string(), r#"{"cmd":"whoami"}"#.to_string()),
        ];

        let results = assess(&predictions, &examples);

        assert_eq!(results.total_examples, 2);
        assert_eq!(results.correct_tool, 2);
        assert!((results.tool_accuracy - 1.0).abs() < 1e-9);
        assert_eq!(results.argument_exact_match, 2);
        assert!((results.argument_accuracy - 1.0).abs() < 1e-9);
    }

    #[test]
    fn wrong_tool_gives_0_percent() {
        let examples = vec![make_example("nmap_scan", r#"{"target":"10.0.0.1"}"#)];
        let predictions = vec![("shell".to_string(), r#"{"cmd":"ls"}"#.to_string())];

        let results = assess(&predictions, &examples);

        assert_eq!(results.correct_tool, 0);
        assert!((results.tool_accuracy - 0.0).abs() < 1e-9);
        assert_eq!(results.argument_exact_match, 0);
        assert!((results.argument_accuracy - 0.0).abs() < 1e-9);

        // nmap_scan should have a false negative.
        let nmap = results.per_tool.get("nmap_scan").unwrap();
        assert_eq!(nmap.false_negatives, 1);
        assert_eq!(nmap.true_positives, 0);

        // shell was wrongly predicted — false positive.
        let shell = results.per_tool.get("shell").unwrap();
        assert_eq!(shell.false_positives, 1);
    }

    #[test]
    fn correct_tool_wrong_args_counts_only_tool_correct() {
        let examples = vec![make_example("nmap_scan", r#"{"target":"10.0.0.1"}"#)];
        let predictions = vec![(
            "nmap_scan".to_string(),
            r#"{"target":"192.168.1.1"}"#.to_string(),
        )];

        let results = assess(&predictions, &examples);

        assert_eq!(results.correct_tool, 1);
        assert!((results.tool_accuracy - 1.0).abs() < 1e-9);
        assert_eq!(results.argument_exact_match, 0);
        assert!((results.argument_accuracy - 0.0).abs() < 1e-9);
    }

    #[test]
    fn empty_predictions_and_examples_gives_zero_accuracy() {
        let results = assess(&[], &[]);
        assert_eq!(results.total_examples, 0);
        assert!((results.tool_accuracy - 0.0).abs() < 1e-9);
        assert!((results.argument_accuracy - 0.0).abs() < 1e-9);
    }

    #[test]
    fn per_tool_precision_recall_computed_correctly() {
        // 2 nmap examples, model gets 1 right and 1 wrong (predicts "shell" instead).
        let examples = vec![
            make_example("nmap_scan", r#"{"target":"10.0.0.1"}"#),
            make_example("nmap_scan", r#"{"target":"10.0.0.2"}"#),
        ];
        let predictions = vec![
            (
                "nmap_scan".to_string(),
                r#"{"target":"10.0.0.1"}"#.to_string(),
            ),
            ("shell".to_string(), r#"{"cmd":"ls"}"#.to_string()),
        ];

        let results = assess(&predictions, &examples);

        let nmap = results.per_tool.get("nmap_scan").unwrap();
        // TP=1, FP=0, FN=1
        assert_eq!(nmap.true_positives, 1);
        assert_eq!(nmap.false_negatives, 1);
        // precision = 1/(1+0) = 1.0, recall = 1/(1+1) = 0.5
        assert!((nmap.precision - 1.0).abs() < 1e-9);
        assert!((nmap.recall - 0.5).abs() < 1e-9);
    }

    #[test]
    fn print_results_does_not_panic() {
        let examples = vec![make_example("nmap_scan", r#"{"target":"10.0.0.1"}"#)];
        let predictions = vec![(
            "nmap_scan".to_string(),
            r#"{"target":"10.0.0.1"}"#.to_string(),
        )];
        let results = assess(&predictions, &examples);
        // Should not panic.
        print_results(&results);
    }
}
