//! Smoke test: health endpoint returns 200 OK.

use sigint_e2e::{base_url, start_server};

#[tokio::test]
async fn health_returns_ok() {
    let addr = start_server().await;
    let url = format!("{}/api/health", base_url(addr));

    let resp = reqwest::get(&url).await.expect("GET /api/health");
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.expect("parse JSON");
    assert_eq!(body["status"], "ok");
}
