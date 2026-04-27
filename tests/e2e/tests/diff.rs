//! E2E integration tests for the scan diff endpoint.
//!
//! These tests verify the full HTTP stack for `GET /api/diff/{scan_a}/{scan_b}`:
//! routing, session existence checks, findings retrieval, diff algorithm, and
//! JSON serialization. Each test spins up a real Axum server backed by an
//! in-memory SQLite database and seeds findings directly through the DB handle.
//!
//! @decision DEC-E2E-004
//! @title Diff E2E tests use start_server_with_db() to seed findings before HTTP calls
//! @status accepted
//! @rationale The diff endpoint requires pre-existing findings in two sessions.
//! The standard start_server() helper drops the DB handle after construction,
//! making direct seeding impossible. start_server_with_db() returns Arc<Database>
//! alongside the SocketAddr so tests can call db.create_session() and
//! db.create_finding() before firing HTTP requests. This tests the full path:
//! seeded data → HTTP request → diff engine → JSON response validation.

use sigint_core::types::{Finding, Session, Severity};
use sigint_e2e::{auth, base_url, start_server_with_db};
use uuid::Uuid;

// ── Helper ────────────────────────────────────────────────────────────────────

/// Create a Finding with a specific title and asset, attached to the given session.
fn make_finding(session_id: Uuid, title: &str, asset: &str) -> Finding {
    let mut f = Finding::new(session_id, title, "test description", Severity::Medium);
    f.asset = Some(asset.to_string());
    f
}

// ── Tests ─────────────────────────────────────────────────────────────────────

/// Verify that the diff endpoint correctly categorises findings as new, fixed,
/// and unchanged when comparing two sessions with overlapping findings.
///
/// Session A: XSS + SQLi (both on "10.0.0.1")
/// Session B: XSS + RCE  (both on "10.0.0.1")
/// Expected:  new=1 (RCE), fixed=1 (SQLi), unchanged=1 (XSS)
#[tokio::test]
async fn diff_endpoint_returns_correct_categorisation() {
    let (addr, db) = start_server_with_db().await;

    // Create two sessions.
    let s1 = Session::new("baseline-scan");
    let s2 = Session::new("current-scan");
    db.create_session(&s1).unwrap();
    db.create_session(&s2).unwrap();

    // Seed session A: XSS + SQLi
    let xss_a = make_finding(s1.id, "XSS", "10.0.0.1");
    let sqli_a = make_finding(s1.id, "SQLi", "10.0.0.1");
    db.create_finding(&xss_a).unwrap();
    db.create_finding(&sqli_a).unwrap();

    // Seed session B: XSS (unchanged) + RCE (new)
    let xss_b = make_finding(s2.id, "XSS", "10.0.0.1");
    let rce_b = make_finding(s2.id, "RCE", "10.0.0.1");
    db.create_finding(&xss_b).unwrap();
    db.create_finding(&rce_b).unwrap();

    let client = reqwest::Client::new();
    let url = format!("{}/api/diff/{}/{}", base_url(addr), s1.id, s2.id);
    let resp = auth(client.get(&url)).send().await.unwrap();

    assert_eq!(resp.status(), 200, "expected 200 OK from diff endpoint");

    let body: serde_json::Value = resp.json().await.unwrap();

    // Verify summary counts.
    assert_eq!(
        body["summary"]["new"], 1,
        "expected 1 new finding (RCE), got: {}",
        body["summary"]
    );
    assert_eq!(
        body["summary"]["fixed"], 1,
        "expected 1 fixed finding (SQLi), got: {}",
        body["summary"]
    );
    assert_eq!(
        body["summary"]["unchanged"], 1,
        "expected 1 unchanged finding (XSS), got: {}",
        body["summary"]
    );

    // Verify the actual finding titles in each category.
    let new_titles: Vec<&str> = body["new"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["title"].as_str().unwrap())
        .collect();
    assert_eq!(new_titles, vec!["RCE"], "new findings: {:?}", new_titles);

    let fixed_titles: Vec<&str> = body["fixed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["title"].as_str().unwrap())
        .collect();
    assert_eq!(
        fixed_titles,
        vec!["SQLi"],
        "fixed findings: {:?}",
        fixed_titles
    );

    let unchanged_titles: Vec<&str> = body["unchanged"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["title"].as_str().unwrap())
        .collect();
    assert_eq!(
        unchanged_titles,
        vec!["XSS"],
        "unchanged findings: {:?}",
        unchanged_titles
    );
}

/// Verify that the diff endpoint returns 404 when one of the session IDs does
/// not exist in the database.
#[tokio::test]
async fn diff_nonexistent_session_returns_404() {
    let (addr, db) = start_server_with_db().await;

    // Create one real session; use Uuid::nil() as the missing one.
    let s1 = Session::new("real-session");
    db.create_session(&s1).unwrap();

    let fake_id = Uuid::nil();

    let client = reqwest::Client::new();
    let url = format!("{}/api/diff/{}/{}", base_url(addr), s1.id, fake_id);
    let resp = auth(client.get(&url)).send().await.unwrap();

    assert_eq!(
        resp.status(),
        404,
        "expected 404 when one session does not exist"
    );
}

/// Verify that diffing two sessions with no findings returns all-zero counts
/// and empty arrays — not an error.
#[tokio::test]
async fn diff_empty_sessions_returns_all_zeros() {
    let (addr, db) = start_server_with_db().await;

    let s1 = Session::new("empty-scan-a");
    let s2 = Session::new("empty-scan-b");
    db.create_session(&s1).unwrap();
    db.create_session(&s2).unwrap();

    let client = reqwest::Client::new();
    let url = format!("{}/api/diff/{}/{}", base_url(addr), s1.id, s2.id);
    let resp = auth(client.get(&url)).send().await.unwrap();

    assert_eq!(
        resp.status(),
        200,
        "expected 200 OK for empty sessions diff"
    );

    let body: serde_json::Value = resp.json().await.unwrap();

    assert_eq!(body["summary"]["new"], 0, "expected 0 new");
    assert_eq!(body["summary"]["fixed"], 0, "expected 0 fixed");
    assert_eq!(body["summary"]["unchanged"], 0, "expected 0 unchanged");

    assert_eq!(
        body["new"].as_array().unwrap().len(),
        0,
        "new array should be empty"
    );
    assert_eq!(
        body["fixed"].as_array().unwrap().len(),
        0,
        "fixed array should be empty"
    );
    assert_eq!(
        body["unchanged"].as_array().unwrap().len(),
        0,
        "unchanged array should be empty"
    );
}
