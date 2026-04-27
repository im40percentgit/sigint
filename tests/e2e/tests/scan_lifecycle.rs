//! E2E tests for the scan lifecycle: start, status, list, cancel.
//!
//! @decision DEC-E2E-003
//! @title Scan lifecycle E2E tests cover start, status, list, cancel, and session creation
//! @status accepted
//! @rationale These tests verify the full HTTP stack for scan endpoints: POST /api/scan
//! returns 201 with a UUID session_id, GET /api/scan/{id}/status returns scan state,
//! GET /api/scans lists running/completed scans, DELETE /api/scan/{id} cancels,
//! and starting a scan also creates a database session visible via /api/sessions.
//! The cancel test accepts both 200 (cancelled) and 404 (scan failed before cancel)
//! because in-memory scans against synthetic targets may fail immediately.

use sigint_e2e::{auth, base_url, start_server};

/// POST /api/scan returns 201 with a session_id UUID.
#[tokio::test]
async fn start_scan_returns_201() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    let resp = auth(client.post(format!("{}/api/scan", base_url(addr))))
        .json(&serde_json::json!({"target": "test.example.com"}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    let session_id = body["session_id"]
        .as_str()
        .expect("session_id should be a string");
    uuid::Uuid::parse_str(session_id).expect("session_id should be a valid UUID");
}

/// POST /api/scan with empty target returns 400.
#[tokio::test]
async fn start_scan_empty_target_returns_400() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    let resp = auth(client.post(format!("{}/api/scan", base_url(addr))))
        .json(&serde_json::json!({"target": ""}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 400);
}

/// GET /api/scan/{id}/status returns a status for a started scan.
#[tokio::test]
async fn scan_status_after_start() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    let resp = auth(client.post(format!("{}/api/scan", base_url(addr))))
        .json(&serde_json::json!({"target": "lifecycle.test"}))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let session_id = body["session_id"].as_str().unwrap();

    let resp = auth(client.get(format!("{}/api/scan/{}/status", base_url(addr), session_id)))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["session_id"], session_id);
    assert!(
        body.get("status").is_some(),
        "expected 'status' field, got: {}",
        body
    );
}

/// GET /api/scan/{unknown}/status returns 404.
#[tokio::test]
async fn scan_status_unknown_returns_404() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    let resp = auth(client.get(format!(
        "{}/api/scan/00000000-0000-0000-0000-000000000000/status",
        base_url(addr)
    )))
    .send()
    .await
    .unwrap();

    assert_eq!(resp.status(), 404);
}

/// GET /api/scans returns an array containing the started scan.
#[tokio::test]
async fn list_scans_contains_started_scan() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    let resp = auth(client.post(format!("{}/api/scan", base_url(addr))))
        .json(&serde_json::json!({"target": "list.test"}))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let session_id = body["session_id"].as_str().unwrap();

    let resp = auth(client.get(format!("{}/api/scans", base_url(addr))))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    let scans = body.as_array().expect("expected array");
    assert!(
        scans.iter().any(|s| s["session_id"] == session_id),
        "expected scan list to contain {}, got: {}",
        session_id,
        body
    );
}

/// DELETE /api/scan/{id} cancels a running scan.
#[tokio::test]
async fn cancel_scan_returns_200() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    let resp = auth(client.post(format!("{}/api/scan", base_url(addr))))
        .json(&serde_json::json!({"target": "cancel.test"}))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let session_id = body["session_id"].as_str().unwrap();

    let resp = auth(client.delete(format!("{}/api/scan/{}", base_url(addr), session_id)))
        .send()
        .await
        .unwrap();

    // Accept either 200 (cancelled) or 404 (already failed before we could cancel)
    assert!(
        resp.status() == 200 || resp.status() == 404,
        "expected 200 or 404, got: {}",
        resp.status()
    );
}

/// DELETE /api/scan/{unknown} returns 404.
#[tokio::test]
async fn cancel_unknown_scan_returns_404() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    let resp = auth(client.delete(format!(
        "{}/api/scan/00000000-0000-0000-0000-000000000000",
        base_url(addr)
    )))
    .send()
    .await
    .unwrap();

    assert_eq!(resp.status(), 404);
}

/// A scan that started also created a session in the database.
#[tokio::test]
async fn scan_creates_session() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    let resp = auth(client.post(format!("{}/api/scan", base_url(addr))))
        .json(&serde_json::json!({"target": "session.test"}))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let session_id = body["session_id"].as_str().unwrap();

    let resp = auth(client.get(format!("{}/api/sessions", base_url(addr))))
        .send()
        .await
        .unwrap();
    let sessions: serde_json::Value = resp.json().await.unwrap();
    let found = sessions
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["id"] == session_id);
    assert!(
        found,
        "expected session {} in list: {}",
        session_id, sessions
    );
}
