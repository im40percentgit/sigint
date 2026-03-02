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
    TokenReceived { session_id: uuid::Uuid, token: String },
    /// LLM streaming completed for a session.
    StreamCompleted { session_id: uuid::Uuid },
    /// A new session was created.
    SessionCreated(Session),
    /// A task changed state.
    TaskUpdated(Task),
    /// A new finding was recorded.
    FindingCreated(Finding),
    /// A tool started executing.
    ToolStarted { name: String, args: serde_json::Value },
    /// A tool produced output.
    ToolOutput { name: String, output: String },
    /// A tool finished.
    ToolCompleted { name: String, exit_code: i32 },
    /// Generic status message for display.
    Status(String),
    /// Shutdown signal.
    Shutdown,
    // ── Attack Surface Mapping events ─────────────────────────────────────────
    /// A new asset was discovered during reconnaissance.
    AssetDiscovered(Asset),
    /// A field on an existing asset changed (e.g., metadata updated, status changed).
    AssetChanged { asset_id: Uuid, field: String, old: String, new: String },
    /// Reconnaissance started against a target.
    ReconStarted { session_id: Uuid, target: String },
    /// Reconnaissance completed; reports how many assets were found.
    ReconCompleted { session_id: Uuid, assets_found: usize },
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
}
