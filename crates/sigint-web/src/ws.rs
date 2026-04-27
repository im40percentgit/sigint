//! WebSocket event bridge — bidirectional channel between browser clients and
//! the SIGINT agent loop.
//!
//! Clients connect to `GET /ws/events` and receive a continuous stream of
//! JSON-serialized `sigint_core::event::Event` variants. Clients may also
//! send `{"type":"approve","request_id":"<uuid>"}` or
//! `{"type":"deny","request_id":"<uuid>"}` frames to respond to pending
//! tool-approval requests in the agent loop.
//!
//! @decision DEC-WEB-002
//! @title Bidirectional WebSocket using tokio::select! over broadcast::Receiver and StreamExt
//! @status accepted
//! @rationale The original send-only loop is replaced with a select! that
//! simultaneously waits on the event bus (server→client) and the WebSocket
//! receiver (client→server). This lets the browser both observe events and
//! drive the approval gate without a separate HTTP endpoint. SinkExt/StreamExt
//! from futures-util are used to split the WebSocket into independent halves so
//! the select! arms can borrow them mutably without conflict.

use axum::extract::ws::{Message, WebSocket};
use axum::{
    extract::{State, WebSocketUpgrade},
    response::IntoResponse,
};
use futures_util::{SinkExt, StreamExt};

use crate::state::AppState;

/// Upgrade handler: accepts the WebSocket handshake and spawns the event loop.
pub async fn ws_events(ws: WebSocketUpgrade, State(state): State<AppState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

/// Per-connection bidirectional event loop.
///
/// Simultaneously:
/// - Forwards `EventBus` events to the client as JSON text frames.
/// - Reads incoming frames from the client and dispatches approval/deny commands.
async fn handle_socket(socket: WebSocket, state: AppState) {
    let (mut sender, mut receiver) = socket.split();
    let mut rx = state.event_bus.subscribe();

    loop {
        tokio::select! {
            result = rx.recv() => {
                match result {
                    Ok(event) => {
                        let json = match serde_json::to_string(&event) {
                            Ok(j) => j,
                            Err(e) => {
                                tracing::warn!("ws: serialize error: {}", e);
                                continue;
                            }
                        };
                        if sender.send(Message::Text(json.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("ws: client lagged, skipped {} events", n);
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
            msg = receiver.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        handle_client_message(&text, &state).await;
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    _ => {} // ignore binary, ping, pong
                }
            }
        }
    }
}

/// Dispatch an inbound WebSocket text frame.
///
/// Recognized commands:
/// - `{"type":"approve","request_id":"<uuid>"}` — approve a pending tool call.
/// - `{"type":"deny","request_id":"<uuid>"}` — deny a pending tool call.
///
/// Unknown command types are logged at DEBUG and silently ignored so future
/// client versions can add commands without breaking old servers.
async fn handle_client_message(text: &str, state: &AppState) {
    let msg: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!("ws: invalid JSON from client: {}", e);
            return;
        }
    };

    match msg.get("type").and_then(|t| t.as_str()) {
        Some("approve") => {
            if let Some(id) = msg.get("request_id").and_then(|v| v.as_str()) {
                if let Ok(uuid) = uuid::Uuid::parse_str(id) {
                    let _ = state.approval_registry.respond(uuid, true);
                }
            }
        }
        Some("deny") => {
            if let Some(id) = msg.get("request_id").and_then(|v| v.as_str()) {
                if let Ok(uuid) = uuid::Uuid::parse_str(id) {
                    let _ = state.approval_registry.respond(uuid, false);
                }
            }
        }
        other => {
            tracing::debug!("ws: unknown command type: {:?}", other);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigint_agents::ScanService;
    use sigint_core::{event::EventBus, ApprovalRegistry, Config};
    use sigint_store::Database;
    use std::sync::Arc;
    use std::time::Duration;

    fn test_state() -> AppState {
        let db = Database::open_in_memory().expect("in-memory db");
        let event_bus = EventBus::new();
        let config = Arc::new(Config::default());
        let approval_registry = Arc::new(ApprovalRegistry::new(Duration::from_secs(30)));
        let scan_service = Arc::new(ScanService::new(
            config.clone(),
            event_bus.clone(),
            approval_registry.clone(),
        ));
        let permits = if config.web.train.max_concurrent_jobs == 0 {
            usize::MAX
        } else {
            config.web.train.max_concurrent_jobs
        };
        AppState {
            db: Arc::new(db),
            event_bus,
            config,
            approval_registry,
            scan_service,
            api_key: "test-key".to_string(),
            training_job_semaphore: Arc::new(tokio::sync::Semaphore::new(permits)),
            provider_factory: std::sync::Arc::new(|_cfg| {
                Ok(Box::new(sigint_llm::MockProvider::new()) as Box<dyn sigint_llm::LlmProvider>)
            }),
        }
    }

    #[tokio::test]
    async fn approve_valid_request() {
        let state = test_state();
        let request_id = uuid::Uuid::new_v4();
        let rx = state.approval_registry.request(request_id);

        let msg = format!(r#"{{"type":"approve","request_id":"{}"}}"#, request_id);
        handle_client_message(&msg, &state).await;

        let result = rx.await.unwrap();
        assert!(result, "approval should be true");
    }

    #[tokio::test]
    async fn deny_valid_request() {
        let state = test_state();
        let request_id = uuid::Uuid::new_v4();
        let rx = state.approval_registry.request(request_id);

        let msg = format!(r#"{{"type":"deny","request_id":"{}"}}"#, request_id);
        handle_client_message(&msg, &state).await;

        let result = rx.await.unwrap();
        assert!(!result, "denial should be false");
    }

    #[tokio::test]
    async fn malformed_json_does_not_panic() {
        let state = test_state();
        handle_client_message("not json at all", &state).await;
        // Should not panic — just logs a warning
    }

    #[tokio::test]
    async fn unknown_command_type_does_not_panic() {
        let state = test_state();
        handle_client_message(r#"{"type":"unknown_cmd","data":123}"#, &state).await;
        // Should not panic — logs debug and returns
    }

    #[tokio::test]
    async fn invalid_uuid_does_not_panic() {
        let state = test_state();
        handle_client_message(r#"{"type":"approve","request_id":"not-a-uuid"}"#, &state).await;
        // Should not panic — uuid parse fails silently
    }
}
