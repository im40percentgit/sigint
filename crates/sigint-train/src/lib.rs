//! sigint-train — model fine-tuning pipeline for SIGINT tool-calling data.
//!
//! This crate extracts tool-calling training data from scan history, formats
//! it as OpenAI-compatible JSONL, generates Ollama Modelfiles, and provides
//! an accuracy assessment harness.
//!
//! # Workflow
//! 1. `extract` — pull ScanRecord + Message data from SQLite
//! 2. `format`  — serialize TrainingExamples to JSONL (one object per line)
//! 3. `split`   — deterministic 80/20 train/test split by session_id hash
//! 4. `modelfile` — generate an Ollama Modelfile for `ollama create`
//! 5. `assess`  — compare model predictions against ground truth
//! 6. `stats`   — print summary statistics
//!
//! @decision DEC-TRAIN-001
//! @title OpenAI chat-completion format for training JSONL
//! @status accepted
//! @rationale The OpenAI messages format (role/content/tool_calls) is the
//! de-facto standard accepted by Ollama fine-tuning, Axolotl, and most other
//! local fine-tuning toolchains. Using this format means training data is
//! portable across toolchains without conversion.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod assess;
pub mod evaluate;
pub mod extract;
pub mod finetune;
pub mod format;
pub mod modelfile;
pub mod promotion;
pub mod split;
pub mod stats;

// ── Training example types ────────────────────────────────────────────────────

/// A complete multi-turn conversation training example.
///
/// Serializes to OpenAI chat-completion format. The `session_id` field is
/// excluded from serialization — it is only used for train/test splitting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingExample {
    /// Conversation turns in OpenAI messages format.
    pub messages: Vec<TrainingMessage>,

    /// Source session UUID — used for deterministic 80/20 splitting.
    /// Excluded from JSONL output so the file stays standard-compatible.
    /// Defaults to nil UUID when deserializing from JSONL (field is absent).
    #[serde(skip_serializing, default)]
    pub session_id: Uuid,
}

/// A single message turn in the training conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingMessage {
    /// Role: "system", "user", "assistant", or "tool".
    pub role: String,

    /// Message text content (None for assistant messages that only have tool_calls).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,

    /// Tool calls made by the assistant in this turn.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<TrainingToolCall>>,

    /// Tool call ID for "tool" role messages (response to a tool_call).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
}

/// A single tool invocation within an assistant turn.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingToolCall {
    /// Unique identifier for this tool call (used to correlate with tool responses).
    pub id: String,

    /// Always "function" for tool calls.
    #[serde(rename = "type")]
    pub call_type: String,

    /// The function being called.
    pub function: TrainingFunction,
}

/// The function name + serialized arguments for a tool call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingFunction {
    /// Tool name (e.g. "nmap_scan", "shell", "gobuster_scan").
    pub name: String,

    /// JSON-serialized arguments string (e.g. `{"target":"10.0.0.1"}`).
    pub arguments: String,
}

// ── Statistics types ──────────────────────────────────────────────────────────

/// Aggregate statistics from a training data extraction run.
#[derive(Debug, Clone, Default)]
pub struct TrainingStats {
    /// Total number of training examples produced.
    pub total_examples: usize,

    /// Number of distinct sessions that contributed examples.
    pub total_sessions: usize,

    /// Examples broken down by agent role (e.g. "executor", "researcher").
    pub examples_per_agent: HashMap<String, usize>,

    /// Examples broken down by tool name (e.g. "nmap_scan", "shell").
    pub examples_per_tool: HashMap<String, usize>,

    /// Records skipped because exit_code != 0.
    pub skipped_failures: usize,
}

// ── Assessment types ──────────────────────────────────────────────────────────

/// Aggregate accuracy results from comparing model predictions to ground truth.
#[derive(Debug, Clone)]
pub struct AssessResults {
    /// Total number of examples evaluated.
    pub total_examples: usize,

    /// Number of examples where the predicted tool name was correct.
    pub correct_tool: usize,

    /// Tool selection accuracy (correct_tool / total_examples).
    pub tool_accuracy: f64,

    /// Number of examples where both tool name AND arguments were exact matches.
    pub argument_exact_match: usize,

    /// Argument exact match rate (argument_exact_match / total_examples).
    pub argument_accuracy: f64,

    /// Per-tool precision/recall metrics.
    pub per_tool: HashMap<String, ToolAssessMetrics>,
}

/// Precision and recall metrics for a single tool.
#[derive(Debug, Clone, Default)]
pub struct ToolAssessMetrics {
    /// Correct predictions for this tool.
    pub true_positives: usize,

    /// Predictions of this tool that were wrong (predicted but not ground truth).
    pub false_positives: usize,

    /// Ground truth instances of this tool that were not predicted.
    pub false_negatives: usize,

    /// Precision = true_positives / (true_positives + false_positives).
    pub precision: f64,

    /// Recall = true_positives / (true_positives + false_negatives).
    pub recall: f64,
}
