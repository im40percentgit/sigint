# Scan Diff Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a diff engine that compares findings between any two scans, exposed via CLI and REST API.

**Architecture:** Pure diff logic in `sigint-core/src/diff.rs` (no DB dependency). Web handler in `sigint-web/src/routes.rs` loads findings via existing `db.get_findings()` and passes them to the diff function. CLI subcommand in `sigint-cli/src/diff.rs` connects to the DB directly. E2E test verifies the API endpoint.

**Tech Stack:** Rust, Axum, clap, serde, reqwest (E2E tests)

---

### Task 1: Core Diff Engine — Types and Algorithm

**Files:**
- Create: `crates/sigint-core/src/diff.rs`
- Modify: `crates/sigint-core/src/lib.rs:13-24`

**Step 1: Write the failing test**

Add `crates/sigint-core/src/diff.rs` with the test at the bottom and empty struct/function signatures that won't compile yet:

```rust
//! Scan diff engine — compares findings between two scans.
//!
//! The diff algorithm matches findings by (title, asset) key and partitions
//! them into new, fixed, and unchanged buckets.
//!
//! @decision DEC-DIFF-001
//! @title Match findings by (lowercase title, asset) tuple
//! @status accepted
//! @rationale Title identifies the vulnerability class, asset identifies where
//! it was found. Together they form a stable identity across scans. Using
//! lowercase title avoids false mismatches from capitalization differences.
//! Full content hashing was rejected as too brittle — LLM-generated
//! descriptions vary between runs even for the same finding.

use serde::Serialize;
use uuid::Uuid;

use crate::types::Finding;

/// Summary counts for a scan diff.
#[derive(Debug, Clone, Serialize)]
pub struct DiffSummary {
    pub new: usize,
    pub fixed: usize,
    pub unchanged: usize,
}

/// Result of diffing two scans' findings.
#[derive(Debug, Clone, Serialize)]
pub struct ScanDiff {
    pub scan_a: Uuid,
    pub scan_b: Uuid,
    pub summary: DiffSummary,
    pub new: Vec<Finding>,
    pub fixed: Vec<Finding>,
    pub unchanged: Vec<Finding>,
}

/// Compare findings from two scans.
///
/// Matching key: `(title.to_lowercase(), asset.unwrap_or_default())`.
/// - **new**: in `findings_b` but not `findings_a`
/// - **fixed**: in `findings_a` but not `findings_b`
/// - **unchanged**: in both
pub fn diff_findings(
    scan_a: Uuid,
    findings_a: &[Finding],
    scan_b: Uuid,
    findings_b: &[Finding],
) -> ScanDiff {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Severity;

    fn finding(title: &str, asset: Option<&str>, severity: Severity) -> Finding {
        let mut f = Finding::new(Uuid::new_v4(), title, "test description", severity);
        f.asset = asset.map(|s| s.to_string());
        f
    }

    #[test]
    fn empty_scans_produce_empty_diff() {
        let diff = diff_findings(Uuid::new_v4(), &[], Uuid::new_v4(), &[]);
        assert_eq!(diff.summary.new, 0);
        assert_eq!(diff.summary.fixed, 0);
        assert_eq!(diff.summary.unchanged, 0);
    }

    #[test]
    fn new_findings_detected() {
        let a = [];
        let b = [finding("XSS", Some("10.0.0.1"), Severity::High)];
        let diff = diff_findings(Uuid::new_v4(), &a, Uuid::new_v4(), &b);
        assert_eq!(diff.summary.new, 1);
        assert_eq!(diff.new[0].title, "XSS");
    }

    #[test]
    fn fixed_findings_detected() {
        let a = [finding("SQLi", Some("10.0.0.1"), Severity::Critical)];
        let b = [];
        let diff = diff_findings(Uuid::new_v4(), &a, Uuid::new_v4(), &b);
        assert_eq!(diff.summary.fixed, 1);
        assert_eq!(diff.fixed[0].title, "SQLi");
    }

    #[test]
    fn unchanged_findings_detected() {
        let a = [finding("XSS", Some("10.0.0.1"), Severity::High)];
        let b = [finding("XSS", Some("10.0.0.1"), Severity::High)];
        let diff = diff_findings(Uuid::new_v4(), &a, Uuid::new_v4(), &b);
        assert_eq!(diff.summary.unchanged, 1);
        assert_eq!(diff.summary.new, 0);
        assert_eq!(diff.summary.fixed, 0);
    }

    #[test]
    fn matching_is_case_insensitive() {
        let a = [finding("Cross-Site Scripting", Some("host"), Severity::High)];
        let b = [finding("cross-site scripting", Some("host"), Severity::High)];
        let diff = diff_findings(Uuid::new_v4(), &a, Uuid::new_v4(), &b);
        assert_eq!(diff.summary.unchanged, 1);
    }

    #[test]
    fn different_assets_are_different_findings() {
        let a = [finding("XSS", Some("10.0.0.1"), Severity::High)];
        let b = [finding("XSS", Some("10.0.0.2"), Severity::High)];
        let diff = diff_findings(Uuid::new_v4(), &a, Uuid::new_v4(), &b);
        assert_eq!(diff.summary.new, 1);
        assert_eq!(diff.summary.fixed, 1);
        assert_eq!(diff.summary.unchanged, 0);
    }

    #[test]
    fn mixed_scenario() {
        let a = [
            finding("XSS", Some("host-a"), Severity::High),
            finding("SQLi", Some("host-a"), Severity::Critical),
            finding("CSRF", Some("host-a"), Severity::Medium),
        ];
        let b = [
            finding("XSS", Some("host-a"), Severity::High),     // unchanged
            finding("RCE", Some("host-a"), Severity::Critical),  // new
        ];
        let diff = diff_findings(Uuid::new_v4(), &a, Uuid::new_v4(), &b);
        assert_eq!(diff.summary.unchanged, 1);  // XSS
        assert_eq!(diff.summary.new, 1);         // RCE
        assert_eq!(diff.summary.fixed, 2);       // SQLi + CSRF
    }

    #[test]
    fn none_asset_matches_none_asset() {
        let a = [finding("Info Disclosure", None, Severity::Info)];
        let b = [finding("Info Disclosure", None, Severity::Info)];
        let diff = diff_findings(Uuid::new_v4(), &a, Uuid::new_v4(), &b);
        assert_eq!(diff.summary.unchanged, 1);
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p sigint-core diff`
Expected: FAIL — `todo!()` panics

**Step 3: Implement the diff algorithm**

Replace the `todo!()` body in `diff_findings` with:

```rust
use std::collections::HashMap;

pub fn diff_findings(
    scan_a: Uuid,
    findings_a: &[Finding],
    scan_b: Uuid,
    findings_b: &[Finding],
) -> ScanDiff {
    type Key = (String, String);

    let key_fn = |f: &Finding| -> Key {
        (f.title.to_lowercase(), f.asset.clone().unwrap_or_default())
    };

    let map_a: HashMap<Key, &Finding> = findings_a.iter().map(|f| (key_fn(f), f)).collect();
    let map_b: HashMap<Key, &Finding> = findings_b.iter().map(|f| (key_fn(f), f)).collect();

    let mut new = Vec::new();
    let mut unchanged = Vec::new();

    for (key, finding) in &map_b {
        if map_a.contains_key(key) {
            unchanged.push((*finding).clone());
        } else {
            new.push((*finding).clone());
        }
    }

    let fixed: Vec<Finding> = map_a
        .iter()
        .filter(|(key, _)| !map_b.contains_key(key))
        .map(|(_, f)| (*f).clone())
        .collect();

    let summary = DiffSummary {
        new: new.len(),
        fixed: fixed.len(),
        unchanged: unchanged.len(),
    };

    ScanDiff {
        scan_a,
        scan_b,
        summary,
        new,
        fixed,
        unchanged,
    }
}
```

**Step 4: Register the module**

In `crates/sigint-core/src/lib.rs`, add after line 17 (`pub mod types;`):

```rust
pub mod diff;
```

**Step 5: Run tests to verify they pass**

Run: `cargo test -p sigint-core diff`
Expected: 8 tests PASS

**Step 6: Commit**

```bash
git add crates/sigint-core/src/diff.rs crates/sigint-core/src/lib.rs
git commit -m "feat: add scan diff engine with finding comparison algorithm"
```

---

### Task 2: REST API Endpoint

**Files:**
- Modify: `crates/sigint-web/src/routes.rs:193-207` (add after findings section)
- Modify: `crates/sigint-web/src/lib.rs:57-84` (add route to router)

**Step 1: Write the unit test**

Add to the bottom of `crates/sigint-web/src/routes.rs` `mod tests` block (before the closing `}`):

```rust
    // ── Diff ──────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn diff_two_sessions_returns_200() {
        let state = test_state();

        // Create two sessions with findings
        let s1 = sigint_core::types::Session::new("scan-a");
        let s2 = sigint_core::types::Session::new("scan-b");
        state.db.create_session(&s1).unwrap();
        state.db.create_session(&s2).unwrap();

        let mut f1 = sigint_core::types::Finding::new(
            s1.id, "XSS", "reflected xss", sigint_core::types::Severity::High,
        );
        f1.asset = Some("10.0.0.1".into());
        state.db.create_finding(&f1).unwrap();

        let mut f2 = sigint_core::types::Finding::new(
            s2.id, "XSS", "reflected xss", sigint_core::types::Severity::High,
        );
        f2.asset = Some("10.0.0.1".into());
        let mut f3 = sigint_core::types::Finding::new(
            s2.id, "RCE", "remote code exec", sigint_core::types::Severity::Critical,
        );
        f3.asset = Some("10.0.0.1".into());
        state.db.create_finding(&f2).unwrap();
        state.db.create_finding(&f3).unwrap();

        let app = create_router(state);
        let req = Request::builder()
            .uri(format!("/api/diff/{}/{}", s1.id, s2.id))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_string(resp.into_body()).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["summary"]["new"], 1);      // RCE is new
        assert_eq!(v["summary"]["unchanged"], 1); // XSS unchanged
        assert_eq!(v["summary"]["fixed"], 0);     // nothing fixed
    }

    #[tokio::test]
    async fn diff_nonexistent_session_returns_404() {
        let state = test_state();
        let s1 = sigint_core::types::Session::new("exists");
        state.db.create_session(&s1).unwrap();

        let app = create_router(state);
        let fake_id = "00000000-0000-0000-0000-000000000000";
        let req = Request::builder()
            .uri(format!("/api/diff/{}/{}", s1.id, fake_id))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p sigint-web diff`
Expected: FAIL — no route matches `/api/diff/{a}/{b}`

**Step 3: Add the handler**

In `crates/sigint-web/src/routes.rs`, add after the `session_findings` handler (after line 207):

```rust
// ── Diff ─────────────────────────────────────────────────────────────────────

/// `GET /api/diff/{scan_a}/{scan_b}` — compare findings between two scans.
///
/// Returns a JSON diff with new, fixed, and unchanged findings. Both scan IDs
/// must reference existing sessions, otherwise returns 404.
pub async fn diff_scans(
    State(state): State<AppState>,
    Path((id_a, id_b)): Path<(String, String)>,
) -> ApiResult<impl IntoResponse> {
    let uuid_a = parse_uuid(&id_a)?;
    let uuid_b = parse_uuid(&id_b)?;

    // Verify both sessions exist
    state
        .db
        .get_session(uuid_a)
        .map_err(internal)?
        .ok_or_else(|| not_found(format!("session '{}' not found", id_a)))?;
    state
        .db
        .get_session(uuid_b)
        .map_err(internal)?
        .ok_or_else(|| not_found(format!("session '{}' not found", id_b)))?;

    let findings_a = state.db.get_findings(uuid_a).map_err(internal)?;
    let findings_b = state.db.get_findings(uuid_b).map_err(internal)?;

    let diff = sigint_core::diff::diff_findings(uuid_a, &findings_a, uuid_b, &findings_b);
    Ok(Json(diff))
}
```

**Step 4: Register the route**

In `crates/sigint-web/src/lib.rs`, add after the report route (after line 71 `.route("/api/report/{id}", get(routes::get_report))`):

```rust
        // Scan diff
        .route("/api/diff/{scan_a}/{scan_b}", get(routes::diff_scans))
```

**Step 5: Update the route table in the doc comment**

In `crates/sigint-web/src/lib.rs`, add this line to the route map table (after the report line):

```
//! | GET | `/api/diff/{scan_a}/{scan_b}` | [`routes::diff_scans`] |
```

**Step 6: Run tests to verify they pass**

Run: `cargo test -p sigint-web diff`
Expected: 2 tests PASS

**Step 7: Commit**

```bash
git add crates/sigint-web/src/routes.rs crates/sigint-web/src/lib.rs
git commit -m "feat: add GET /api/diff/{a}/{b} endpoint for scan comparison"
```

---

### Task 3: CLI Subcommand

**Files:**
- Create: `crates/sigint-cli/src/diff.rs`
- Modify: `crates/sigint-cli/src/main.rs:44-92` (add Diff variant)
- Modify: `crates/sigint-cli/src/main.rs:120-149` (add match arm)

**Step 1: Create the diff subcommand module**

Create `crates/sigint-cli/src/diff.rs`:

```rust
//! `sigint diff` — compare findings between two scan sessions.
//!
//! @decision DEC-CLI-DIFF-001
//! @title CLI diff uses direct DB access, not HTTP API
//! @status accepted
//! @rationale The CLI binary already has sigint-store as a dependency and
//! direct DB access is simpler than requiring a running web server. The diff
//! logic is the same — both CLI and API call sigint_core::diff::diff_findings.

use sigint_core::{diff::diff_findings, AppCore};
use uuid::Uuid;

/// CLI arguments for `sigint diff`.
#[derive(clap::Args, Debug)]
pub struct DiffArgs {
    /// UUID of the first (baseline) scan session.
    pub scan_a: String,
    /// UUID of the second (comparison) scan session.
    pub scan_b: String,
    /// Output format: "json" (default) or "markdown".
    #[arg(long, default_value = "json")]
    pub format: String,
}

pub async fn run(core: AppCore, args: DiffArgs) -> sigint_core::Result<()> {
    let uuid_a = Uuid::parse_str(&args.scan_a)
        .map_err(|e| sigint_core::Error::Other(format!("Invalid UUID '{}': {}", args.scan_a, e)))?;
    let uuid_b = Uuid::parse_str(&args.scan_b)
        .map_err(|e| sigint_core::Error::Other(format!("Invalid UUID '{}': {}", args.scan_b, e)))?;

    let db = core.database()?;

    // Verify sessions exist
    db.get_session(uuid_a)?
        .ok_or_else(|| sigint_core::Error::Other(format!("Session '{}' not found", uuid_a)))?;
    db.get_session(uuid_b)?
        .ok_or_else(|| sigint_core::Error::Other(format!("Session '{}' not found", uuid_b)))?;

    let findings_a = db.get_findings(uuid_a)?;
    let findings_b = db.get_findings(uuid_b)?;

    let diff = diff_findings(uuid_a, &findings_a, uuid_b, &findings_b);

    match args.format.as_str() {
        "markdown" => print_markdown(&diff),
        _ => {
            let json = serde_json::to_string_pretty(&diff)
                .map_err(|e| sigint_core::Error::Other(e.to_string()))?;
            println!("{}", json);
        }
    }

    Ok(())
}

fn print_markdown(diff: &sigint_core::diff::ScanDiff) {
    println!("# Scan Diff: {} vs {}", diff.scan_a, diff.scan_b);
    println!();
    println!("| Category | Count |");
    println!("|----------|-------|");
    println!("| New      | {}    |", diff.summary.new);
    println!("| Fixed    | {}    |", diff.summary.fixed);
    println!("| Unchanged| {}    |", diff.summary.unchanged);

    if !diff.new.is_empty() {
        println!();
        println!("## New Findings");
        println!();
        println!("| Severity | Title | Asset |");
        println!("|----------|-------|-------|");
        for f in &diff.new {
            println!("| {} | {} | {} |", f.severity, f.title, f.asset.as_deref().unwrap_or("-"));
        }
    }

    if !diff.fixed.is_empty() {
        println!();
        println!("## Fixed Findings");
        println!();
        println!("| Severity | Title | Asset |");
        println!("|----------|-------|-------|");
        for f in &diff.fixed {
            println!("| {} | {} | {} |", f.severity, f.title, f.asset.as_deref().unwrap_or("-"));
        }
    }

    if !diff.unchanged.is_empty() {
        println!();
        println!("## Unchanged Findings");
        println!();
        println!("| Severity | Title | Asset |");
        println!("|----------|-------|-------|");
        for f in &diff.unchanged {
            println!("| {} | {} | {} |", f.severity, f.title, f.asset.as_deref().unwrap_or("-"));
        }
    }
}
```

**Step 2: Register the subcommand in main.rs**

In `crates/sigint-cli/src/main.rs`, add the module declaration after line 16 (`mod recon;`):

```rust
mod diff;
```

Add the `Diff` variant to the `Commands` enum (after the `Recon` variant, before line 92 `}`):

```rust
    /// Compare findings between two scan sessions.
    Diff(diff::DiffArgs),
```

Add the match arm in the `match cli.command` block (after the `Recon` arm, before line 149 `};`):

```rust
        Commands::Diff(args) => diff::run(core, args).await,
```

**Step 3: Verify it compiles**

Run: `cargo build -p sigint-cli`
Expected: BUILD SUCCESS

**Step 4: Verify help text**

Run: `cargo run -p sigint-cli -- diff --help`
Expected: Shows usage with `scan_a`, `scan_b`, `--format` arguments

**Step 5: Commit**

```bash
git add crates/sigint-cli/src/diff.rs crates/sigint-cli/src/main.rs
git commit -m "feat: add sigint diff CLI subcommand"
```

---

### Task 4: E2E Integration Test

**Files:**
- Create: `tests/e2e/tests/diff.rs`

**Step 1: Write the E2E test**

Create `tests/e2e/tests/diff.rs`:

```rust
//! E2E tests for the scan diff API endpoint.
//!
//! Tests the full HTTP path: reqwest → Axum → diff logic → JSON response.
//! Seeds findings via the DB (through the test server's AppState) and verifies
//! the diff endpoint returns correct categorisation.

use sigint_core::types::{Finding, Severity, Session};
use sigint_store::Database;
use sigint_web::AppState;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

/// Start a server and return (addr, db) so tests can seed data.
async fn start_server_with_db() -> (SocketAddr, Arc<Database>) {
    let db = Database::open_in_memory().expect("in-memory db");
    let db = Arc::new(db);
    let event_bus = sigint_core::event::EventBus::new();
    let config = Arc::new(sigint_core::Config::default());
    let approval_registry = Arc::new(sigint_core::ApprovalRegistry::new(Duration::from_secs(30)));
    let scan_service = Arc::new(sigint_agents::ScanService::new(
        config.clone(),
        event_bus.clone(),
        approval_registry.clone(),
    ));
    let state = AppState {
        db: db.clone(),
        event_bus,
        config,
        approval_registry,
        scan_service,
    };

    let app = sigint_web::create_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    (addr, db)
}

fn base_url(addr: SocketAddr) -> String {
    format!("http://{}", addr)
}

#[tokio::test]
async fn diff_endpoint_returns_correct_categorisation() {
    let (addr, db) = start_server_with_db().await;
    let client = reqwest::Client::new();

    // Create two sessions
    let s1 = Session::new("baseline");
    let s2 = Session::new("rescan");
    db.create_session(&s1).unwrap();
    db.create_session(&s2).unwrap();

    // Baseline has: XSS, SQLi
    let mut f1 = Finding::new(s1.id, "XSS", "reflected xss", Severity::High);
    f1.asset = Some("10.0.0.1".into());
    let mut f2 = Finding::new(s1.id, "SQLi", "sql injection", Severity::Critical);
    f2.asset = Some("10.0.0.1".into());
    db.create_finding(&f1).unwrap();
    db.create_finding(&f2).unwrap();

    // Rescan has: XSS (unchanged), RCE (new) — SQLi is fixed
    let mut f3 = Finding::new(s2.id, "XSS", "reflected xss", Severity::High);
    f3.asset = Some("10.0.0.1".into());
    let mut f4 = Finding::new(s2.id, "RCE", "remote code exec", Severity::Critical);
    f4.asset = Some("10.0.0.1".into());
    db.create_finding(&f3).unwrap();
    db.create_finding(&f4).unwrap();

    // Call diff endpoint
    let resp = client
        .get(format!("{}/api/diff/{}/{}", base_url(addr), s1.id, s2.id))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();

    assert_eq!(body["summary"]["new"], 1);
    assert_eq!(body["summary"]["fixed"], 1);
    assert_eq!(body["summary"]["unchanged"], 1);

    // Verify the actual findings
    assert_eq!(body["new"][0]["title"], "RCE");
    assert_eq!(body["fixed"][0]["title"], "SQLi");
    assert_eq!(body["unchanged"][0]["title"], "XSS");
}

#[tokio::test]
async fn diff_nonexistent_session_returns_404() {
    let (addr, db) = start_server_with_db().await;
    let client = reqwest::Client::new();

    let s1 = Session::new("exists");
    db.create_session(&s1).unwrap();

    let fake = Uuid::nil();
    let resp = client
        .get(format!("{}/api/diff/{}/{}", base_url(addr), s1.id, fake))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn diff_empty_sessions_returns_all_zeros() {
    let (addr, db) = start_server_with_db().await;
    let client = reqwest::Client::new();

    let s1 = Session::new("empty-a");
    let s2 = Session::new("empty-b");
    db.create_session(&s1).unwrap();
    db.create_session(&s2).unwrap();

    let resp = client
        .get(format!("{}/api/diff/{}/{}", base_url(addr), s1.id, s2.id))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["summary"]["new"], 0);
    assert_eq!(body["summary"]["fixed"], 0);
    assert_eq!(body["summary"]["unchanged"], 0);
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p e2e-tests diff`
Expected: FAIL — route not found (if Task 2 not done yet) or PASS (if Task 2 is done)

**Step 3: Run tests to verify they pass**

Run: `cargo test -p e2e-tests diff`
Expected: 3 tests PASS

**Step 4: Run full workspace tests**

Run: `cargo test --workspace`
Expected: All existing tests + new diff tests PASS

**Step 5: Commit**

```bash
git add tests/e2e/tests/diff.rs
git commit -m "test: add E2E integration tests for scan diff endpoint"
```

---

### Task 5: Final Verification

**Step 1: Run full workspace test suite**

Run: `cargo test --workspace`
Expected: All tests PASS (including 8 new diff unit tests, 2 web unit tests, 3 E2E tests)

**Step 2: Run clippy**

Run: `cargo clippy --workspace -- -D warnings`
Expected: No warnings

**Step 3: Run fmt check**

Run: `cargo fmt --all -- --check`
Expected: No formatting issues

**Step 4: Verify CLI help**

Run: `cargo run -p sigint-cli -- diff --help`
Expected: Shows scan_a, scan_b positional args and --format flag

**Step 5: Commit any fixes if needed**

Only if clippy/fmt required changes.
