# E2E Integration Testing — Design Document

**Date:** 2026-03-02
**Status:** approved
**Approach:** Workspace-level integration test crate with real HTTP server

## Context

SIGINT has 278 unit tests across 12 crates but no end-to-end tests that verify multi-crate workflows. Web endpoint tests use `tower::oneshot` (in-process), missing real HTTP serialization and concurrent connection behavior. There is no CI pipeline.

## Design Decisions

- **Test location:** `tests/e2e/` workspace member (integration test crate)
- **HTTP client:** `reqwest` for real HTTP requests against a live server
- **Server pattern:** Bind to `127.0.0.1:0` for random port, `tokio::spawn` the Axum server
- **LLM mocking:** Minimal `MockProvider` in test helpers (existing one is `#[cfg(test)]` in sigint-agents)
- **Database:** `Database::open_in_memory()` per test (existing pattern)
- **CI:** GitHub Actions workflow running `cargo test --workspace` on push/PR

## Test Architecture

```
tests/e2e/
  Cargo.toml          # dev-dependencies on sigint-web, sigint-agents, etc.
  src/
    lib.rs            # Helpers: start_test_server(), TestClient
  tests/
    health.rs         # Smoke test
    scan_lifecycle.rs # Start → status → list → cancel → verify
    sessions.rs       # Session CRUD lifecycle
```

### Test Server Helper

```rust
async fn start_test_server() -> (SocketAddr, AppState) {
    let state = test_state();
    let app = sigint_web::create_router(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (addr, state)
}
```

## Test Scenarios

### health.rs
- GET `/api/health` → 200 `{"status":"ok"}`

### scan_lifecycle.rs
1. POST `/api/scan` `{"target":"test.local"}` → 201 with `session_id`
2. GET `/api/scan/{id}/status` → 200 with status
3. GET `/api/scans` → array containing scan
4. DELETE `/api/scan/{id}` → 200
5. GET `/api/scan/{id}/status` → `Cancelled`
6. GET `/api/scan/{unknown}/status` → 404

### sessions.rs
1. GET `/api/sessions` → `[]`
2. POST `/api/scan` creates a session
3. GET `/api/sessions/{id}` → session details
4. GET `/api/sessions` → contains session
5. DELETE `/api/sessions/{id}` → 200
6. GET `/api/sessions/{id}` → 404

## CI Pipeline

`.github/workflows/ci.yml`:
- Trigger: push to main, pull requests
- Matrix: stable Rust on ubuntu-latest
- Steps: checkout, toolchain, cargo test --workspace
- No external tools required (all mocked)

## Dependencies

New `tests/e2e/Cargo.toml`:
- `sigint-web` (workspace)
- `sigint-agents` (workspace, for MockProvider type)
- `sigint-core` (workspace, for Config, EventBus, ApprovalRegistry)
- `sigint-store` (workspace, for Database)
- `reqwest` (HTTP client)
- `tokio` (async runtime)
- `serde_json` (response parsing)
- `uuid` (ID handling)
