//! WebSocket event bridge — streams domain events to browser clients.
//!
//! Clients connect to `GET /ws/events` and receive a continuous stream of
//! JSON-serialized `sigint_core::event::Event` variants. The connection is
//! maintained until either side closes it.
//!
//! @decision DEC-WEB-002
//! @title WebSocket bridge uses tokio::broadcast Receiver per connection
//! @status accepted
//! @rationale Each WebSocket client gets its own `broadcast::Receiver` via
//! `EventBus::subscribe()`. This means events are delivered independently to
//! every connected client without blocking each other. Lagged receivers (slow
//! clients) receive a `RecvError::Lagged` which we treat as a non-fatal skip.
//! The connection is dropped only on `RecvError::Closed` or a send error.

use axum::{
    extract::{State, WebSocketUpgrade},
    response::IntoResponse,
};
use axum::extract::ws::{Message, WebSocket};
use tokio::sync::broadcast::error::RecvError;

use crate::state::AppState;

/// Upgrade handler: accepts the WebSocket handshake and spawns the event loop.
pub async fn ws_events(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

/// Per-connection event loop: subscribes to the event bus and forwards events.
async fn handle_socket(mut socket: WebSocket, state: AppState) {
    let mut rx = state.event_bus.subscribe();

    loop {
        match rx.recv().await {
            Ok(event) => {
                let json = match serde_json::to_string(&event) {
                    Ok(j) => j,
                    Err(e) => {
                        tracing::warn!("ws: failed to serialize event: {}", e);
                        continue;
                    }
                };
                if socket.send(Message::Text(json.into())).await.is_err() {
                    // Client disconnected — exit cleanly.
                    break;
                }
            }
            Err(RecvError::Lagged(n)) => {
                // Slow client skipped messages — log and continue.
                tracing::warn!("ws: client lagged, skipped {} events", n);
            }
            Err(RecvError::Closed) => {
                // Sender dropped (server shutting down) — close the socket.
                break;
            }
        }
    }
}
