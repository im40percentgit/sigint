//! Event bus for AppCore — broadcasts domain events to all subscribers.
//!
//! Uses `tokio::broadcast` so both TUI and Web interfaces can receive
//! the same event stream without coupling to each other.
//!
//! @decision DEC-ARCH-002
//! @title tokio::broadcast as the shared event bus
//! @status accepted
//! @rationale broadcast channels allow N subscribers (TUI, Web, agents)
//! to each receive a copy of every event without any subscriber blocking
//! another. This decouples the UI layer from the core completely.
//!
//! @decision DEC-P26-001
//! @title WebSocket event variants for Phase 26 training lifecycle
//! @status accepted
//! @rationale Training lifecycle events (job start/progress/completion,
//! evaluation, model promotion/rollback) are delivered over the existing
//! broadcast WebSocket channel rather than polling or SSE. This reuses
//! the established event bus contract without adding new transport
//! complexity. Variants follow the existing externally-tagged serde
//! convention (no #[serde(tag)] attribute). Timestamps use u64 unix epoch
//! seconds to match the existing Event enum field style.

use crate::types::{Asset, EscalationTier, Finding, Message, Session, Task};
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use uuid::Uuid;

/// Capacity of the broadcast channel (number of buffered events).
const BUS_CAPACITY: usize = 256;

/// Domain events emitted by SIGINT components.
///
/// All variants derive `Serialize` so the WebSocket bridge can stream events
/// as JSON to connected browser clients without an intermediate DTO layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Event {
    /// A new chat message was created.
    MessageCreated(Message),
    /// An LLM response token arrived (for streaming display).
    TokenReceived {
        session_id: uuid::Uuid,
        token: String,
    },
    /// LLM streaming completed for a session.
    StreamCompleted { session_id: uuid::Uuid },
    /// A new session was created.
    SessionCreated(Session),
    /// A task changed state.
    TaskUpdated(Task),
    /// A new finding was recorded.
    FindingCreated(Finding),
    /// A tool started executing.
    ToolStarted {
        name: String,
        args: serde_json::Value,
    },
    /// A tool produced output.
    ToolOutput { name: String, output: String },
    /// A tool finished.
    ToolCompleted { name: String, exit_code: i32 },
    /// Generic status message for display.
    Status(String),
    /// Shutdown signal.
    Shutdown,
    /// User submitted text input from the TUI or web interface.
    UserInput { session_id: Uuid, text: String },
    // ── Attack Surface Mapping events ─────────────────────────────────────────
    /// A new asset was discovered during reconnaissance.
    AssetDiscovered(Asset),
    /// A field on an existing asset changed (e.g., metadata updated, status changed).
    AssetChanged {
        asset_id: Uuid,
        field: String,
        old: String,
        new: String,
    },
    /// Reconnaissance started against a target.
    ReconStarted { session_id: Uuid, target: String },
    /// Reconnaissance completed; reports how many assets were found.
    ReconCompleted {
        session_id: Uuid,
        assets_found: usize,
    },
    // ── Streaming reasoning events ────────────────────────────────────────────
    /// Streaming reasoning token from an agent between tool calls.
    ///
    /// Emitted for each incremental token produced by `chat_stream()` while
    /// the model is reasoning before or between tool invocations. The TUI
    /// accumulates these into a live "thinking" buffer for real-time display.
    AgentThinking { agent_role: String, token: String },
    /// Agent finished a reasoning segment (stream iteration complete).
    ///
    /// Emitted after the final `done=true` chunk arrives from `chat_stream()`.
    /// The TUI flushes `reasoning_buffer` into the message list as a "thinking"
    /// role message and clears the live indicator.
    AgentThinkingDone { agent_role: String },
    // ── Approval Gate events ─────────────────────────────────────────────────
    /// A tool call is awaiting human approval before execution.
    ToolApprovalRequested {
        request_id: Uuid,
        session_id: Uuid,
        tool_name: String,
        args: serde_json::Value,
        risk_level: crate::types::ToolRisk,
    },
    /// A pending tool call was approved by the operator.
    ToolApprovalGranted { request_id: Uuid },
    /// A pending tool call was denied by the operator.
    ToolApprovalDenied {
        request_id: Uuid,
        reason: Option<String>,
    },
    // ── Session resume diff events ────────────────────────────────────────────
    /// Diff results from a resume scan comparing findings against a prior session.
    ///
    /// Emitted after a resumed scan completes its diff pass. The TUI and Web
    /// interfaces use this to colour-code findings as new / fixed / unchanged.
    ScanDiffCompleted { diff: crate::diff::ScanDiff },
    // ── Convergence loop events ───────────────────────────────────────────────
    /// One Strategist → Executor → Analyst cycle has completed.
    ///
    /// Emitted by the Orchestrator after each convergence cycle. Consumers
    /// (TUI, Web) can use this to display live cycle progress and finding counts
    /// as the iterative loop runs toward convergence.
    CycleCompleted {
        /// Zero-based cycle index.
        cycle: usize,
        /// Number of new findings discovered in this cycle.
        new_findings: usize,
        /// Cumulative findings recorded across all cycles so far.
        total_findings: usize,
    },
    // ── Escalation gate events ────────────────────────────────────────────────
    /// The Strategist recommended actions beyond the current escalation tier.
    ///
    /// Emitted when `--approval-gates` is enabled and the Strategist output
    /// contains an `ESCALATION:` marker indicating a tier transition. Consumers
    /// (TUI, operator UI) use this to prompt the operator for approval before
    /// the Executor proceeds with potentially destructive actions.
    EscalationRequested {
        /// The current (safe) tier the scan is operating at.
        from: EscalationTier,
        /// The higher-risk tier the Strategist is recommending.
        to: EscalationTier,
        /// Zero-based cycle index when this request was raised.
        cycle: usize,
    },
    /// An escalation request was approved by the operator.
    ///
    /// Emitted after `EscalationRequested` when the operator (or an automated
    /// policy) approves the tier transition. The Executor will proceed with
    /// the escalated actions.
    EscalationApproved {
        from: EscalationTier,
        to: EscalationTier,
    },
    /// An escalation request was denied by the operator.
    ///
    /// Emitted when the operator denies (or a timeout fires on) an
    /// `EscalationRequested` event. The Orchestrator skips the Executor and
    /// Analyst for this cycle and attempts convergence with current findings.
    EscalationDenied {
        from: EscalationTier,
        to: EscalationTier,
    },
    // ── Training lifecycle events (Phase 26) ─────────────────────────────────
    /// A fine-tuning job was submitted and started.
    TrainingJobStarted {
        job_id: String,
        base_model: String,
        output_path: String,
    },
    /// Periodic heartbeat from a running training job with recent stdout.
    TrainingJobProgress {
        job_id: String,
        /// Unix epoch seconds at the time of the heartbeat.
        heartbeat_at: u64,
        /// Last few lines of stdout from the training process.
        stdout_tail: String,
    },
    /// A training job exited successfully or with a non-zero exit code.
    TrainingJobCompleted {
        job_id: String,
        exit_code: i32,
        duration_secs: u64,
    },
    /// A training job failed with an error message.
    TrainingJobFailed { job_id: String, error: String },
    /// An evaluation run comparing two model checkpoints was started.
    EvaluationStarted {
        eval_id: String,
        base_tag: String,
        candidate_tag: String,
        total_examples: usize,
    },
    /// Incremental progress update from a running evaluation.
    EvaluationProgress {
        eval_id: String,
        examples_done: usize,
    },
    /// An evaluation run completed; report is available at the given path.
    EvaluationCompleted {
        eval_id: String,
        report_path: String,
    },
    /// An evaluation run failed (e.g. provider factory error, runtime error).
    EvaluationFailed { eval_id: String, error: String },
    /// The active model was promoted from one provider/model to a new one.
    ModelPromoted {
        old_provider: String,
        old_model: String,
        new_provider: String,
        new_model: String,
    },
    /// The active model was rolled back to a previous provider/model.
    ModelRolledBack {
        old_provider: String,
        old_model: String,
        new_provider: String,
        new_model: String,
    },
}

/// Handle to the broadcast event bus.
///
/// Clone this to get additional sender handles; call `subscribe()` to
/// get a receiver for any component that needs to consume events.
#[derive(Clone, Debug)]
pub struct EventBus {
    tx: broadcast::Sender<Event>,
}

impl EventBus {
    /// Create a new event bus with default capacity.
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(BUS_CAPACITY);
        Self { tx }
    }

    /// Send an event to all subscribers. Ignores send errors (no receivers).
    pub fn emit(&self, event: Event) {
        let _ = self.tx.send(event);
    }

    /// Subscribe to receive future events. Each subscriber gets its own queue.
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.tx.subscribe()
    }

    /// Return a clone of the underlying sender (for passing into tasks).
    pub fn sender(&self) -> broadcast::Sender<Event> {
        self.tx.clone()
    }
}

impl Default for EventBus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn emit_and_receive() {
        let bus = EventBus::new();
        let mut rx = bus.subscribe();

        bus.emit(Event::Status("hello".into()));

        let event = rx.recv().await.expect("should receive event");
        match event {
            Event::Status(s) => assert_eq!(s, "hello"),
            other => panic!("unexpected event: {:?}", other),
        }
    }

    #[tokio::test]
    async fn multiple_subscribers() {
        let bus = EventBus::new();
        let mut rx1 = bus.subscribe();
        let mut rx2 = bus.subscribe();

        bus.emit(Event::Status("broadcast".into()));

        let e1 = rx1.recv().await.unwrap();
        let e2 = rx2.recv().await.unwrap();

        assert!(matches!(e1, Event::Status(_)));
        assert!(matches!(e2, Event::Status(_)));
    }

    #[tokio::test]
    async fn no_receiver_does_not_panic() {
        let bus = EventBus::new();
        // No subscribers — emit should silently discard
        bus.emit(Event::Shutdown);
    }

    #[test]
    fn approval_events_serialize() {
        use crate::types::ToolRisk;

        let req_id = Uuid::new_v4();
        let sess_id = Uuid::new_v4();

        // ToolApprovalRequested
        let ev = Event::ToolApprovalRequested {
            request_id: req_id,
            session_id: sess_id,
            tool_name: "nmap_scan".into(),
            args: serde_json::json!({"target": "192.168.1.0/24"}),
            risk_level: ToolRisk::High,
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("ToolApprovalRequested"));
        assert!(json.contains("nmap_scan"));
        assert!(json.contains("high"));

        // ToolApprovalGranted
        let granted = Event::ToolApprovalGranted { request_id: req_id };
        let json = serde_json::to_string(&granted).unwrap();
        assert!(json.contains("ToolApprovalGranted"));
        assert!(json.contains(&req_id.to_string()));

        // ToolApprovalDenied
        let denied = Event::ToolApprovalDenied {
            request_id: req_id,
            reason: Some("too risky".into()),
        };
        let json = serde_json::to_string(&denied).unwrap();
        assert!(json.contains("ToolApprovalDenied"));
        assert!(json.contains("too risky"));
    }

    #[test]
    fn agent_thinking_serializes() {
        let ev = Event::AgentThinking {
            agent_role: "Researcher".into(),
            token: "analyzing".into(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("AgentThinking"));
        assert!(json.contains("analyzing"));
        let back: Event = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Event::AgentThinking { token, .. } if token == "analyzing"));
    }

    #[test]
    fn agent_thinking_done_serializes() {
        let ev = Event::AgentThinkingDone {
            agent_role: "Executor".into(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("AgentThinkingDone"));
        assert!(json.contains("Executor"));
        let back: Event = serde_json::from_str(&json).unwrap();
        assert!(
            matches!(back, Event::AgentThinkingDone { agent_role } if agent_role == "Executor")
        );
    }

    #[test]
    fn user_input_event_serializes() {
        let ev = Event::UserInput {
            session_id: Uuid::nil(),
            text: "hello".into(),
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("UserInput"));
        assert!(json.contains("hello"));
        // Roundtrip
        let back: Event = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Event::UserInput { text, .. } if text == "hello"));
    }

    #[test]
    fn scan_diff_completed_event_clone() {
        use crate::diff::{DiffSummary, ScanDiff};
        let diff = ScanDiff {
            scan_a: Uuid::new_v4(),
            scan_b: Uuid::new_v4(),
            summary: DiffSummary {
                new: 1,
                fixed: 0,
                unchanged: 2,
            },
            new: vec![],
            fixed: vec![],
            unchanged: vec![],
        };
        let event = Event::ScanDiffCompleted { diff: diff.clone() };
        let cloned = event.clone();
        drop(cloned);
    }

    #[test]
    fn scan_diff_completed_event_serializes() {
        use crate::diff::{DiffSummary, ScanDiff};
        let diff = ScanDiff {
            scan_a: Uuid::new_v4(),
            scan_b: Uuid::new_v4(),
            summary: DiffSummary {
                new: 2,
                fixed: 1,
                unchanged: 3,
            },
            new: vec![],
            fixed: vec![],
            unchanged: vec![],
        };
        let ev = Event::ScanDiffCompleted { diff };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("ScanDiffCompleted"));
        assert!(json.contains("scan_a"));
        assert!(json.contains("scan_b"));
        // Roundtrip
        let back: Event = serde_json::from_str(&json).unwrap();
        assert!(matches!(back, Event::ScanDiffCompleted { .. }));
    }

    // ── Phase 26 training lifecycle round-trip tests ──────────────────────────

    /// Helper: serialize an event to JSON then deserialize back, returning both.
    fn roundtrip(ev: &Event) -> (String, Event) {
        let json = serde_json::to_string(ev).expect("serialize");
        let back: Event = serde_json::from_str(&json).expect("deserialize");
        (json, back)
    }

    #[test]
    fn training_job_started_roundtrip() {
        let ev = Event::TrainingJobStarted {
            job_id: "job-001".into(),
            base_model: "llama3:8b".into(),
            output_path: "/models/fine-tuned/job-001".into(),
        };
        let (json, back) = roundtrip(&ev);
        assert!(json.contains("TrainingJobStarted"), "variant tag present");
        assert!(json.contains("job-001"));
        assert!(json.contains("llama3:8b"));
        assert!(json.contains("/models/fine-tuned/job-001"));
        assert!(
            matches!(back, Event::TrainingJobStarted { ref job_id, ref base_model, ref output_path }
                if job_id == "job-001" && base_model == "llama3:8b" && output_path == "/models/fine-tuned/job-001")
        );
    }

    #[test]
    fn training_job_progress_roundtrip() {
        let ev = Event::TrainingJobProgress {
            job_id: "job-002".into(),
            heartbeat_at: 1_700_000_000u64,
            stdout_tail: "step 100/1000 loss=0.42".into(),
        };
        let (json, back) = roundtrip(&ev);
        assert!(json.contains("TrainingJobProgress"));
        assert!(json.contains("1700000000"));
        assert!(json.contains("step 100"));
        assert!(matches!(
            back,
            Event::TrainingJobProgress {
                heartbeat_at: 1_700_000_000,
                ..
            }
        ));
    }

    #[test]
    fn training_job_completed_roundtrip() {
        let ev = Event::TrainingJobCompleted {
            job_id: "job-003".into(),
            exit_code: 0,
            duration_secs: 3600,
        };
        let (json, back) = roundtrip(&ev);
        assert!(json.contains("TrainingJobCompleted"));
        assert!(json.contains("\"exit_code\":0"));
        assert!(json.contains("3600"));
        assert!(matches!(
            back,
            Event::TrainingJobCompleted {
                exit_code: 0,
                duration_secs: 3600,
                ..
            }
        ));
    }

    #[test]
    fn training_job_failed_roundtrip() {
        let ev = Event::TrainingJobFailed {
            job_id: "job-004".into(),
            error: "CUDA out of memory".into(),
        };
        let (json, back) = roundtrip(&ev);
        assert!(json.contains("TrainingJobFailed"));
        assert!(json.contains("CUDA out of memory"));
        assert!(
            matches!(back, Event::TrainingJobFailed { ref error, .. } if error == "CUDA out of memory")
        );
    }

    #[test]
    fn evaluation_started_roundtrip() {
        let ev = Event::EvaluationStarted {
            eval_id: "eval-001".into(),
            base_tag: "llama3:8b-base".into(),
            candidate_tag: "llama3:8b-ft-v1".into(),
            total_examples: 500,
        };
        let (json, back) = roundtrip(&ev);
        assert!(json.contains("EvaluationStarted"));
        assert!(json.contains("eval-001"));
        assert!(json.contains("500"));
        assert!(matches!(
            back,
            Event::EvaluationStarted {
                total_examples: 500,
                ..
            }
        ));
    }

    #[test]
    fn evaluation_progress_roundtrip() {
        let ev = Event::EvaluationProgress {
            eval_id: "eval-002".into(),
            examples_done: 250,
        };
        let (json, back) = roundtrip(&ev);
        assert!(json.contains("EvaluationProgress"));
        assert!(json.contains("250"));
        assert!(matches!(
            back,
            Event::EvaluationProgress {
                examples_done: 250,
                ..
            }
        ));
    }

    #[test]
    fn evaluation_completed_roundtrip() {
        let ev = Event::EvaluationCompleted {
            eval_id: "eval-003".into(),
            report_path: "/reports/eval-003.json".into(),
        };
        let (json, back) = roundtrip(&ev);
        assert!(json.contains("EvaluationCompleted"));
        assert!(json.contains("/reports/eval-003.json"));
        assert!(
            matches!(back, Event::EvaluationCompleted { ref report_path, .. }
                if report_path == "/reports/eval-003.json")
        );
    }

    #[test]
    fn model_promoted_roundtrip() {
        let ev = Event::ModelPromoted {
            old_provider: "ollama".into(),
            old_model: "llama3:8b".into(),
            new_provider: "ollama".into(),
            new_model: "llama3:8b-ft-v1".into(),
        };
        let (json, back) = roundtrip(&ev);
        assert!(json.contains("ModelPromoted"));
        assert!(json.contains("llama3:8b-ft-v1"));
        assert!(
            matches!(back, Event::ModelPromoted { ref new_model, .. } if new_model == "llama3:8b-ft-v1")
        );
    }

    #[test]
    fn model_rolled_back_roundtrip() {
        let ev = Event::ModelRolledBack {
            old_provider: "ollama".into(),
            old_model: "llama3:8b-ft-v1".into(),
            new_provider: "ollama".into(),
            new_model: "llama3:8b".into(),
        };
        let (json, back) = roundtrip(&ev);
        assert!(json.contains("ModelRolledBack"));
        assert!(json.contains("llama3:8b"));
        assert!(
            matches!(back, Event::ModelRolledBack { ref new_model, .. } if new_model == "llama3:8b")
        );
    }

    #[test]
    fn training_lifecycle_events_all_serialize_and_deserialize() {
        // Confirm all 9 Phase 26 variants round-trip without loss.
        let events: Vec<Event> = vec![
            Event::TrainingJobStarted {
                job_id: "j1".into(),
                base_model: "m".into(),
                output_path: "/p".into(),
            },
            Event::TrainingJobProgress {
                job_id: "j1".into(),
                heartbeat_at: 0,
                stdout_tail: "".into(),
            },
            Event::TrainingJobCompleted {
                job_id: "j1".into(),
                exit_code: 0,
                duration_secs: 1,
            },
            Event::TrainingJobFailed {
                job_id: "j1".into(),
                error: "err".into(),
            },
            Event::EvaluationStarted {
                eval_id: "e1".into(),
                base_tag: "b".into(),
                candidate_tag: "c".into(),
                total_examples: 1,
            },
            Event::EvaluationProgress {
                eval_id: "e1".into(),
                examples_done: 1,
            },
            Event::EvaluationCompleted {
                eval_id: "e1".into(),
                report_path: "/r".into(),
            },
            Event::ModelPromoted {
                old_provider: "o".into(),
                old_model: "old".into(),
                new_provider: "o".into(),
                new_model: "new".into(),
            },
            Event::ModelRolledBack {
                old_provider: "o".into(),
                old_model: "new".into(),
                new_provider: "o".into(),
                new_model: "old".into(),
            },
        ];

        for ev in &events {
            let json = serde_json::to_string(ev).expect("serialize");
            let _back: Event = serde_json::from_str(&json).expect("deserialize roundtrip");
        }
    }
}
