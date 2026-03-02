//! E2E tests for session CRUD endpoints.
//!
//! @decision DEC-E2E-002
//! @title Session CRUD E2E tests cover empty list, 404 on missing, and bad UUID
//! @status accepted
//! @rationale These tests verify the full HTTP stack for session endpoints: routing,
//! UUID parsing, database queries, and JSON serialization. A nil UUID
//! (all-zeros) is used for "not found" cases to avoid depending on real data.
//! Bad UUID input tests that the router/extractor returns 404 rather than 500.

use sigint_e2e::{base_url, start_server};

#[tokio::test]
async fn list_sessions_empty() {
    let addr = start_server().await;
    let client = reqwest::Client::new();
    let url = format!("{}/api/sessions", base_url(addr));

    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body.is_array());
    assert_eq!(body.as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn get_nonexistent_session_returns_404() {
    let addr = start_server().await;
    let client = reqwest::Client::new();
    let url = format!(
        "{}/api/sessions/00000000-0000-0000-0000-000000000000",
        base_url(addr)
    );

    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn get_session_bad_uuid_returns_404() {
    let addr = start_server().await;
    let client = reqwest::Client::new();
    let url = format!("{}/api/sessions/not-a-uuid", base_url(addr));

    let resp = client.get(&url).send().await.unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn delete_nonexistent_session_returns_404() {
    let addr = start_server().await;
    let client = reqwest::Client::new();
    let url = format!(
        "{}/api/sessions/00000000-0000-0000-0000-000000000000",
        base_url(addr)
    );

    let resp = client.delete(&url).send().await.unwrap();
    assert_eq!(resp.status(), 404);
}
