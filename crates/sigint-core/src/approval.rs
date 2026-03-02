//! Approval registry for the human-in-the-loop tool gate.
//!
//! When an agent wants to execute a tool whose risk level exceeds the
//! configured `auto_approve` threshold, it registers the pending call here
//! and awaits the operator's decision via a oneshot channel.
//!
//! The registry is intentionally minimal: it stores a sender half and
//! gives the caller the receiver half. A separate event-bus subscriber
//! (e.g. the TUI or WebSocket handler) calls `respond()` when the operator
//! clicks Approve/Deny.
//!
//! @decision DEC-APPROVE-001
//! @title std::sync::Mutex + tokio::sync::oneshot for the approval registry
//! @status accepted
//! @rationale oneshot channels are the idiomatic Tokio primitive for
//! request/response pairs. std::sync::Mutex (not tokio::sync::Mutex) is
//! used for the HashMap because the critical section is always short and
//! non-async — avoiding the need to hold the lock across await points.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;
use tokio::sync::oneshot;
use uuid::Uuid;

/// Thread-safe registry of pending tool-approval requests.
///
/// Create a single instance and share it via `Arc<ApprovalRegistry>` between
/// the agent loop (calls `request`) and the approval responder (calls `respond`).
pub struct ApprovalRegistry {
    pending: Mutex<HashMap<Uuid, oneshot::Sender<bool>>>,
    timeout: Duration,
}

impl ApprovalRegistry {
    /// Create a new registry. `timeout` is advisory — callers are responsible
    /// for racing the receiver against a sleep if they want hard timeouts.
    pub fn new(timeout: Duration) -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
            timeout,
        }
    }

    /// Register a pending approval request and return a receiver that resolves
    /// to `true` (approved) or `false` (denied) when `respond()` is called.
    ///
    /// Panics if the internal mutex is poisoned (indicates a prior panic in
    /// a critical section — we treat this as unrecoverable).
    pub fn request(&self, request_id: Uuid) -> oneshot::Receiver<bool> {
        let (tx, rx) = oneshot::channel();
        self.pending
            .lock()
            .expect("approval registry mutex poisoned")
            .insert(request_id, tx);
        rx
    }

    /// Respond to a pending approval request.
    ///
    /// Returns `Ok(())` if the request was found and the response delivered.
    /// Returns `Err(String)` if no request with that ID is pending (already
    /// responded to, or never registered).
    pub fn respond(&self, request_id: Uuid, approved: bool) -> Result<(), String> {
        let tx = self
            .pending
            .lock()
            .expect("approval registry mutex poisoned")
            .remove(&request_id)
            .ok_or_else(|| format!("no pending approval request for {request_id}"))?;

        // The receiver may have been dropped (agent timed out). That's fine —
        // we log it but still return Ok since our job was to find and consume
        // the entry. The error from send indicates the receiver is gone, which
        // is not an error from the registry's perspective.
        let _ = tx.send(approved);
        Ok(())
    }

    /// Number of requests currently awaiting a response.
    pub fn pending_count(&self) -> usize {
        self.pending
            .lock()
            .expect("approval registry mutex poisoned")
            .len()
    }

    /// The configured timeout advisory value.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn request_and_approve() {
        let registry = ApprovalRegistry::new(Duration::from_secs(30));
        let id = Uuid::new_v4();
        let rx = registry.request(id);

        registry.respond(id, true).expect("respond should succeed");

        let result = rx.await.expect("receiver should not be dropped");
        assert!(result, "expected approved=true");
    }

    #[tokio::test]
    async fn request_and_deny() {
        let registry = ApprovalRegistry::new(Duration::from_secs(30));
        let id = Uuid::new_v4();
        let rx = registry.request(id);

        registry.respond(id, false).expect("respond should succeed");

        let result = rx.await.expect("receiver should not be dropped");
        assert!(!result, "expected approved=false");
    }

    #[test]
    fn respond_to_unknown_request_returns_error() {
        let registry = ApprovalRegistry::new(Duration::from_secs(30));
        let unknown_id = Uuid::new_v4();

        let err = registry.respond(unknown_id, true).unwrap_err();
        assert!(
            err.contains(&unknown_id.to_string()),
            "error should mention the unknown id"
        );
    }

    #[test]
    fn pending_count_tracks_requests() {
        let registry = ApprovalRegistry::new(Duration::from_secs(30));
        assert_eq!(registry.pending_count(), 0);

        let id1 = Uuid::new_v4();
        let id2 = Uuid::new_v4();
        let _rx1 = registry.request(id1);
        let _rx2 = registry.request(id2);
        assert_eq!(registry.pending_count(), 2);

        registry.respond(id1, true).unwrap();
        assert_eq!(registry.pending_count(), 1);

        registry.respond(id2, false).unwrap();
        assert_eq!(registry.pending_count(), 0);
    }

    #[test]
    fn timeout_accessor() {
        let timeout = Duration::from_secs(300);
        let registry = ApprovalRegistry::new(timeout);
        assert_eq!(registry.timeout(), timeout);
    }
}
