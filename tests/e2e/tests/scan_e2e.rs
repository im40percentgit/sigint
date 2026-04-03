//! E2E tests for the scan pipeline with a MockProvider.
//!
//! These tests exercise the full HTTP stack: POST /api/scan → agent pipeline
//! (backed by a deterministic MockProvider) → database persistence → query
//! endpoints. No real Ollama/OpenAI endpoint is needed.
//!
//! @decision DEC-E2E-004
//! @title Scan E2E tests use MockProvider injected via ScanService::with_provider
//! @status accepted
//! @rationale The scan pipeline requires 5 LLM calls (one per agent role with
//!   max_cycles=1 and no tool calls). Previously this always failed in CI
//!   because no Ollama instance is running. Injecting MockProvider via
//!   ScanService::with_provider exercises the full production code path
//!   (ScanService → Orchestrator → agent loop → database) without external
//!   infrastructure. The mock queue is sized to match the exact number of
//!   agent turns; exhaustion falls back to "[mock exhausted]" which is still
//!   valid text output, so tests are tolerant of off-by-one counts.

use std::time::Duration;

use sigint_llm::mock::MockResponse;

use sigint_e2e::{base_url, start_server_with_mock};

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Default mock responses for a 5-agent scan with no tool calls.
///
/// The queue has exactly 5 entries (Researcher, Strategist, Executor, Analyst,
/// Reporter). Extra calls fall back to "[mock exhausted]" — still valid text.
fn five_agent_responses() -> Vec<MockResponse> {
    vec![
        MockResponse::Text("Researcher: found open ports 22 and 80.".into()),
        MockResponse::Text("Strategist: attack via port 80 HTTP.".into()),
        MockResponse::Text("Executor: ran reconnaissance, no critical services.".into()),
        MockResponse::Text("Analyst: no high-severity findings detected.".into()),
        MockResponse::Text("Reporter: SUMMARY — scan of test target complete.".into()),
    ]
}

/// Poll `GET /api/scan/{id}/status` until the scan reaches a terminal state
/// (`completed`, `cancelled`, or `failed`), or until `timeout` elapses.
///
/// Returns the final status string. Panics if the timeout is reached without
/// a terminal state — this typically means the scan is hung.
async fn wait_for_terminal_status(
    client: &reqwest::Client,
    base: &str,
    session_id: &str,
    timeout: Duration,
) -> String {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let resp = client
            .get(format!("{}/api/scan/{}/status", base, session_id))
            .send()
            .await
            .expect("status request failed");

        if resp.status().is_success() {
            let body: serde_json::Value = resp.json().await.unwrap();
            let status = body["status"].as_str().unwrap_or("").to_string();
            // Normalise: serde serialises ScanStatus::Failed("msg") as
            // {"failed":"msg"} (an object), so check the string OR object.
            let is_terminal = status == "completed"
                || status == "cancelled"
                || body["status"].is_object(); // failed variant
            if is_terminal {
                return status;
            }
        }

        if tokio::time::Instant::now() >= deadline {
            panic!(
                "scan {} did not reach terminal state within {:?}",
                session_id, timeout
            );
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// A scan backed by a MockProvider completes successfully and the session
/// appears in /api/sessions.
#[tokio::test]
async fn scan_with_mock_provider_completes() {
    let (addr, _db) = start_server_with_mock(five_agent_responses()).await;
    let client = reqwest::Client::new();
    let base = base_url(addr);

    // Start the scan.
    let resp = client
        .post(format!("{}/api/scan", base))
        .json(&serde_json::json!({"target": "mock.example.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "expected 201 Created");

    let body: serde_json::Value = resp.json().await.unwrap();
    let session_id = body["session_id"]
        .as_str()
        .expect("session_id must be a string");

    // Wait for the scan to finish (up to 10 seconds).
    let final_status =
        wait_for_terminal_status(&client, &base, session_id, Duration::from_secs(10)).await;

    // The scan must reach `completed`, not `failed` or `cancelled`.
    assert_eq!(
        final_status, "completed",
        "expected completed, got: {}",
        final_status
    );

    // The session must appear in /api/sessions.
    let sessions_resp = client
        .get(format!("{}/api/sessions", base))
        .send()
        .await
        .unwrap();
    assert_eq!(sessions_resp.status(), 200);
    let sessions: serde_json::Value = sessions_resp.json().await.unwrap();
    let found = sessions
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["id"] == session_id);
    assert!(
        found,
        "session {} not found in /api/sessions: {}",
        session_id, sessions
    );
}

/// A scan with a ToolCall response in the mock queue exercises the tool-call
/// dispatch path. The Executor issues a `shell` call; it will likely fail
/// (no real binary), but the agent loop handles the error and the scan
/// completes rather than hanging.
#[tokio::test]
async fn scan_with_mock_tool_calls() {
    // Give the Executor a tool-call response; give the others plain text.
    // The Executor gets TWO entries: the tool call + a follow-up text response
    // (so after the tool result is fed back, the agent can produce its summary).
    let responses = vec![
        MockResponse::Text("Researcher: ports 22, 80 open.".into()),
        MockResponse::Text("Strategist: enumerate web service.".into()),
        // Executor turn 1: request a tool call.
        MockResponse::ToolCall {
            name: "shell".into(),
            arguments: serde_json::json!({"command": "echo hello"}),
        },
        // Executor turn 2: after tool result is returned, produce text summary.
        MockResponse::Text("Executor: tool executed, got result.".into()),
        MockResponse::Text("Analyst: no critical findings.".into()),
        MockResponse::Text("Reporter: SUMMARY — tool call test complete.".into()),
    ];

    let (addr, _db) = start_server_with_mock(responses).await;
    let client = reqwest::Client::new();
    let base = base_url(addr);

    let resp = client
        .post(format!("{}/api/scan", base))
        .json(&serde_json::json!({"target": "toolcall.example.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    let body: serde_json::Value = resp.json().await.unwrap();
    let session_id = body["session_id"].as_str().unwrap();

    // Allow up to 15 seconds — tool dispatch adds latency.
    let _final_status =
        wait_for_terminal_status(&client, &base, session_id, Duration::from_secs(15)).await;

    // We don't assert `completed` here because the tool may fail (no real
    // `shell` binary in the sandbox). What matters is the scan reaches *some*
    // terminal state rather than hanging forever.
}

/// Cancelling a scan mid-flight transitions its status to `cancelled`.
#[tokio::test]
async fn scan_cancel_stops_execution() {
    // Use a very large response queue so the scan takes time to process.
    let many_responses: Vec<MockResponse> = std::iter::repeat_with(|| {
        MockResponse::Text("processing...".into())
    })
    .take(100)
    .collect();

    let (addr, _db) = start_server_with_mock(many_responses).await;
    let client = reqwest::Client::new();
    let base = base_url(addr);

    // Start the scan.
    let resp = client
        .post(format!("{}/api/scan", base))
        .json(&serde_json::json!({"target": "cancel.example.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);

    let body: serde_json::Value = resp.json().await.unwrap();
    let session_id = body["session_id"].as_str().unwrap();

    // Give the scan a brief moment to start, then cancel it.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let cancel_resp = client
        .delete(format!("{}/api/scan/{}", base, session_id))
        .send()
        .await
        .unwrap();

    // Accept 200 (cancelled) or 404 (scan already finished before cancel).
    assert!(
        cancel_resp.status() == 200 || cancel_resp.status() == 404,
        "expected 200 or 404, got: {}",
        cancel_resp.status()
    );

    if cancel_resp.status() == 200 {
        // If we cancelled, the status endpoint should now report cancelled.
        let status_resp = client
            .get(format!("{}/api/scan/{}/status", base, session_id))
            .send()
            .await
            .unwrap();
        assert_eq!(status_resp.status(), 200);
        let body: serde_json::Value = status_resp.json().await.unwrap();
        assert_eq!(
            body["status"], "cancelled",
            "expected cancelled, got: {}",
            body
        );
    }
}

/// After a completed mock scan, /api/sessions/{id}/findings returns a valid
/// (possibly empty) findings array. This verifies the findings endpoint is
/// reachable for a session created via the scan pipeline.
#[tokio::test]
async fn scan_findings_endpoint_reachable() {
    let (addr, _db) = start_server_with_mock(five_agent_responses()).await;
    let client = reqwest::Client::new();
    let base = base_url(addr);

    let resp = client
        .post(format!("{}/api/scan", base))
        .json(&serde_json::json!({"target": "findings.example.com"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    let session_id = body["session_id"].as_str().unwrap();

    // Wait for completion.
    let final_status =
        wait_for_terminal_status(&client, &base, session_id, Duration::from_secs(10)).await;
    assert_eq!(
        final_status, "completed",
        "scan did not complete: {}",
        final_status
    );

    // /api/sessions/{id}/findings must return 200 with a JSON array.
    let findings_resp = client
        .get(format!("{}/api/sessions/{}/findings", base, session_id))
        .send()
        .await
        .unwrap();
    assert_eq!(
        findings_resp.status(),
        200,
        "expected 200 from findings endpoint"
    );
    let findings: serde_json::Value = findings_resp.json().await.unwrap();
    assert!(
        findings.is_array(),
        "expected JSON array from findings endpoint, got: {}",
        findings
    );
}
