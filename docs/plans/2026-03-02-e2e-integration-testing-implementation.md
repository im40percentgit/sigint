# E2E Integration Testing Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add a workspace-level E2E integration test crate that verifies the full HTTP API + scan lifecycle against a real Axum server, plus a GitHub Actions CI workflow.

**Architecture:** A new `tests/e2e` crate joins the workspace and depends on `sigint-web`, `sigint-agents`, `sigint-core`, and `sigint-store`. Each test starts a real Axum server on a random port using `tokio::TcpListener::bind("127.0.0.1:0")`, then makes HTTP requests with `reqwest`. The LLM provider (`create_provider`) will fail with "connection refused" (no Ollama running) — this is expected and tests the error-path lifecycle (start → Running → Failed). Cancel tests race against the failure timeout.

**Tech Stack:** Rust, tokio, axum, reqwest, serde_json, uuid. GitHub Actions for CI.

---

### Task 1: Create E2E test crate skeleton

**Files:**
- Create: `tests/e2e/Cargo.toml`
- Create: `tests/e2e/src/lib.rs`
- Modify: `Cargo.toml` (workspace root, add member)

**Step 1: Create directory structure**

```bash
mkdir -p tests/e2e/src
```

**Step 2: Write `tests/e2e/Cargo.toml`**

```toml
[package]
name = "sigint-e2e"
version.workspace = true
edition.workspace = true
publish = false

# This crate is test-only; it has no library or binary targets beyond
# the integration tests in tests/*.rs and the helper library in src/lib.rs.

[dependencies]
sigint-web = { workspace = true }
sigint-agents = { workspace = true }
sigint-core = { workspace = true }
sigint-store = { workspace = true }

tokio = { workspace = true }
reqwest = { workspace = true }
serde_json = { workspace = true }
uuid = { workspace = true }
```

**Step 3: Write `tests/e2e/src/lib.rs`** — test helpers

```rust
//! E2E test helpers — shared server bootstrap and HTTP client utilities.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use sigint_agents::ScanService;
use sigint_core::{ApprovalRegistry, Config, event::EventBus};
use sigint_store::Database;
use sigint_web::AppState;

/// Start a real Axum server on a random port. Returns the bound address.
///
/// The server runs in a background tokio task and shuts down when the test
/// runtime is dropped. Uses in-memory SQLite and default config (Ollama
/// provider pointing at localhost:11434 — no Ollama is running, so scans
/// will fail quickly, which is fine for lifecycle testing).
pub async fn start_server() -> SocketAddr {
    let db = Database::open_in_memory().expect("in-memory db");
    let event_bus = EventBus::new();
    let config = Arc::new(Config::default());
    let approval_registry = Arc::new(ApprovalRegistry::new(Duration::from_secs(30)));
    let scan_service = Arc::new(ScanService::new(
        config.clone(),
        event_bus.clone(),
        approval_registry.clone(),
    ));
    let state = AppState {
        db: Arc::new(db),
        event_bus,
        config,
        approval_registry,
        scan_service,
    };

    let app = sigint_web::create_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind to random port");
    let addr = listener.local_addr().expect("local addr");

    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    addr
}

/// Build a base URL from a socket address (e.g. "http://127.0.0.1:12345").
pub fn base_url(addr: SocketAddr) -> String {
    format!("http://{}", addr)
}
```

**Step 4: Add workspace member to root `Cargo.toml`**

In `/home/j/sigint/Cargo.toml`, add `"tests/e2e"` to the `members` array:

```toml
[workspace]
members = [
    "crates/sigint-core",
    "crates/sigint-llm",
    "crates/sigint-agents",
    "crates/sigint-sandbox",
    "crates/sigint-store",
    "crates/sigint-tools",
    "crates/sigint-recon",
    "crates/sigint-tui",
    "crates/sigint-web",
    "crates/sigint-cli",
    "crates/sigint-memory",
    "crates/sigint-report",
    "tests/e2e",
]
```

**Step 5: Verify it compiles**

Run: `cargo check -p sigint-e2e`
Expected: compiles with no errors (warnings about unused imports are OK)

**Step 6: Commit**

```bash
git add tests/e2e/ Cargo.toml Cargo.lock
git commit -m "feat: add E2E integration test crate skeleton"
```

---

### Task 2: Health endpoint E2E test

**Files:**
- Create: `tests/e2e/tests/health.rs`

**Step 1: Write the test**

```rust
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
```

**Step 2: Run the test**

Run: `cargo test -p sigint-e2e --test health`
Expected: PASS — health endpoint serves correctly over real HTTP

**Step 3: Commit**

```bash
git add tests/e2e/tests/health.rs
git commit -m "test: E2E health endpoint smoke test"
```

---

### Task 3: Session CRUD E2E tests

**Files:**
- Create: `tests/e2e/tests/sessions.rs`

**Step 1: Write the tests**

```rust
//! E2E tests for session CRUD endpoints.

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
```

**Step 2: Run the tests**

Run: `cargo test -p sigint-e2e --test sessions`
Expected: all 4 PASS

**Step 3: Commit**

```bash
git add tests/e2e/tests/sessions.rs
git commit -m "test: E2E session CRUD tests"
```

---

### Task 4: Scan lifecycle E2E tests

**Files:**
- Create: `tests/e2e/tests/scan_lifecycle.rs`

**Context:** `ScanService::start()` calls `create_provider(&config.llm)` which constructs an `OllamaProvider` pointing at `http://localhost:11434`. Since Ollama isn't running during tests, the spawned scan task will fail almost immediately with a connection error. This is expected — we test the lifecycle mechanics (start returns 201, status transitions, cancel works).

**Step 1: Write the tests**

```rust
//! E2E tests for the scan lifecycle: start, status, list, cancel.

use sigint_e2e::{base_url, start_server};

/// POST /api/scan returns 201 with a session_id UUID.
#[tokio::test]
async fn start_scan_returns_201() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/api/scan", base_url(addr)))
        .json(&serde_json::json!({"target": "test.example.com"}))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status(), 201);
    let body: serde_json::Value = resp.json().await.unwrap();
    let session_id = body["session_id"].as_str().expect("session_id should be a string");
    // Verify it parses as a UUID
    uuid::Uuid::parse_str(session_id).expect("session_id should be a valid UUID");
}

/// POST /api/scan with empty target returns 400.
#[tokio::test]
async fn start_scan_empty_target_returns_400() {
    let addr = start_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/api/scan", base_url(addr)))
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

    // Start a scan
    let resp = client
        .post(format!("{}/api/scan", base_url(addr)))
        .json(&serde_json::json!({"target": "lifecycle.test"}))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let session_id = body["session_id"].as_str().unwrap();

    // Query status (may be "running" or "failed" depending on timing)
    let resp = client
        .get(format!("{}/api/scan/{}/status", base_url(addr), session_id))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["session_id"], session_id);
    // Status is one of: "running", "completed", "cancelled", or {"failed": "..."}
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

    let resp = client
        .get(format!(
            "{}/api/scan/00000000-0000-0000-0000-000000000000/status",
            base_url(addr)
        ))
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

    // Start a scan
    let resp = client
        .post(format!("{}/api/scan", base_url(addr)))
        .json(&serde_json::json!({"target": "list.test"}))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let session_id = body["session_id"].as_str().unwrap();

    // List scans
    let resp = client
        .get(format!("{}/api/scans", base_url(addr)))
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

    // Start a scan
    let resp = client
        .post(format!("{}/api/scan", base_url(addr)))
        .json(&serde_json::json!({"target": "cancel.test"}))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let session_id = body["session_id"].as_str().unwrap();

    // Cancel immediately (race: may succeed if scan is still Running, or 404 if already Failed)
    let resp = client
        .delete(format!("{}/api/scan/{}", base_url(addr), session_id))
        .send()
        .await
        .unwrap();

    // Accept either 200 (cancelled successfully) or 404 (already failed/not running)
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

    let resp = client
        .delete(format!(
            "{}/api/scan/00000000-0000-0000-0000-000000000000",
            base_url(addr)
        ))
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

    // Start a scan
    let resp = client
        .post(format!("{}/api/scan", base_url(addr)))
        .json(&serde_json::json!({"target": "session.test"}))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let session_id = body["session_id"].as_str().unwrap();

    // The session should exist in the sessions list
    let resp = client
        .get(format!("{}/api/sessions", base_url(addr)))
        .send()
        .await
        .unwrap();
    let sessions: serde_json::Value = resp.json().await.unwrap();
    let found = sessions
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["id"] == session_id);
    assert!(found, "expected session {} in list: {}", session_id, sessions);
}
```

**Step 2: Run the tests**

Run: `cargo test -p sigint-e2e --test scan_lifecycle`
Expected: all 8 PASS

**Step 3: Commit**

```bash
git add tests/e2e/tests/scan_lifecycle.rs
git commit -m "test: E2E scan lifecycle tests (start, status, list, cancel)"
```

---

### Task 5: GitHub Actions CI workflow

**Files:**
- Create: `.github/workflows/ci.yml`

**Step 1: Write the workflow**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:

env:
  CARGO_TERM_COLOR: always
  RUSTFLAGS: "-D warnings"

jobs:
  test:
    name: Test
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable

      - name: Cache cargo registry and build
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
            target
          key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}
          restore-keys: |
            ${{ runner.os }}-cargo-

      - name: Run tests
        run: cargo test --workspace

  clippy:
    name: Clippy
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable
        with:
          components: clippy

      - name: Cache cargo registry and build
        uses: actions/cache@v4
        with:
          path: |
            ~/.cargo/registry
            ~/.cargo/git
            target
          key: ${{ runner.os }}-cargo-${{ hashFiles('**/Cargo.lock') }}
          restore-keys: |
            ${{ runner.os }}-cargo-

      - name: Run clippy
        run: cargo clippy --workspace -- -D warnings

  fmt:
    name: Format
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@stable
        with:
          components: rustfmt

      - name: Check formatting
        run: cargo fmt --all -- --check
```

**Step 2: Verify the workflow YAML is valid**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))" 2>/dev/null || echo "Install PyYAML or visually verify"`
Expected: no error (valid YAML)

**Step 3: Commit**

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add GitHub Actions workflow (test + clippy + fmt)"
```

---

### Task 6: Final workspace verification

**Step 1: Run all E2E tests**

Run: `cargo test -p sigint-e2e`
Expected: all 13 tests PASS (1 health + 4 sessions + 8 scan lifecycle)

**Step 2: Run full workspace tests**

Run: `cargo test --workspace 2>&1 | tail -20`
Expected: all existing tests still pass, new E2E tests also pass. 3 known sandbox failures (pre-existing, require Linux namespace capabilities).

**Step 3: Run clippy on new code**

Run: `cargo clippy -p sigint-e2e -- -D warnings`
Expected: no warnings

**Step 4: Commit any cleanup**

If any fixes needed:
```bash
git add -A
git commit -m "fix: address clippy/test issues in E2E crate"
```
