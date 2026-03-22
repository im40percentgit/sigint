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

use crate::types::{Asset, Finding, Message, Session, Task};
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
    UserInput {
        session_id: Uuid,
        text: String,
    },
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
    AgentThinking {
        agent_role: String,
        token: String,
    },
    /// Agent finished a reasoning segment (stream iteration complete).
    ///
    /// Emitted after the final `done=true` chunk arrives from `chat_stream()`.
    /// The TUI flushes `reasoning_buffer` into the message list as a "thinking"
    /// role message and clears the live indicator.
    AgentThinkingDone {
        agent_role: String,
    },
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
    ScanDiffCompleted {
        diff: crate::diff::ScanDiff,
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
        assert!(matches!(back, Event::AgentThinkingDone { agent_role } if agent_role == "Executor"));
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
}
