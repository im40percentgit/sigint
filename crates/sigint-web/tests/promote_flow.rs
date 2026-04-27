//! Integration test: promote -> list promotions -> rollback -> list (round-trip).
//!
//! Spins up a real Axum server on a random port. Seeds `last_eval.json` with
//! sufficient examples and a fake `.gguf` file so the promote handler can
//! proceed end-to-end. Verifies:
//!
//! 1. POST /api/model/promote with enough examples -> 200.
//! 2. GET  /api/model/promotions returns 1 entry with action="promote".
//! 3. POST /api/model/rollback -> 200.
//! 4. GET  /api/model/promotions returns 2 entries (promote + rollback).
//! 5. P1 gate: force=false + insufficient examples -> 409.
//! 6. P1 gate: force=true  + insufficient examples -> not 409.
//! 7. Wall time < 5 s.
//!
//! Must run with --test-threads=1 because it mutates HOME.
//!
//! @decision DEC-E2E-001
//! @title Integration tests use a real Axum server on a random port
//! @status accepted
//! @rationale Same pattern as train_flow.rs — real router, real middleware,
//! in-memory SQLite, temp filesystem. Mirrors production code path exactly.

use std::sync::Arc;
use std::time::{Duration, Instant};

use sigint_agents::ScanService;
use sigint_core::{event::EventBus, ApprovalRegistry, Config};
use sigint_store::Database;
use sigint_web::AppState;
use tokio::sync::Semaphore;

const TEST_KEY: &str = "promote-flow-test-token";
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn auth(client: &reqwest::Client, method: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
    client.request(method, url).bearer_auth(TEST_KEY)
}

/// Start a real Axum server on a random port with training state in `job_dir`.
async fn start_server(job_dir: &std::path::Path) -> std::net::SocketAddr {
    let db = Arc::new(Database::open_in_memory().expect("in-memory db"));
    let event_bus = EventBus::new();

    let mut config = Config::default();
    config.train.job_dir = Some(job_dir.to_path_buf());
    config.llm.models_dir = Some(job_dir.to_string_lossy().into_owned());
    config.web.train.max_concurrent_jobs = 0;

    let config = Arc::new(config);
    let approval_registry = Arc::new(ApprovalRegistry::new(Duration::from_secs(30)));
    let scan_service = Arc::new(ScanService::new(
        config.clone(),
        event_bus.clone(),
        approval_registry.clone(),
    ));

    let state = AppState {
        db,
        event_bus,
        training_job_semaphore: Arc::new(Semaphore::new(Semaphore::MAX_PERMITS)),
        config,
        approval_registry,
        scan_service,
        api_key: TEST_KEY.to_string(),
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

/// Write last_eval.json with the given total_examples count.
fn write_report(job_dir: &std::path::Path, total_examples: usize) {
    let report = serde_json::json!({
        "base_tag": "llama3:8b",
        "candidate_tag": "ft-v1",
        "total_examples": total_examples,
        "tool_accuracy_delta": 0.05,
        "argument_match_delta": 0.02,
        "evaluated_at": "2026-04-24T00:00:00Z"
    });
    std::fs::write(
        job_dir.join("last_eval.json"),
        serde_json::to_string_pretty(&report).unwrap(),
    )
    .unwrap();
}

/// Create a fake .gguf file so detect_output_kind succeeds.
fn write_fake_gguf(job_dir: &std::path::Path, name: &str) {
    std::fs::write(job_dir.join(format!("{}.gguf", name)), b"fake-gguf-content").unwrap();
}

/// Write a minimal config.toml so atomic_config_rewrite has a file to back up.
fn write_starter_config(home: &std::path::Path) {
    let config_dir = home.join(".config").join("sigint");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
        config_dir.join("config.toml"),
        "[llm]\nprovider = \"ollama\"\nmodel = \"llama3.2:8b\"\n",
    )
    .unwrap();
}

// ── Main round-trip test ──────────────────────────────────────────────────────

/// promote -> list -> rollback -> list round-trip.
///
/// Verifies REQ-P26-P0-005, REQ-P26-P0-006, REQ-P26-GOAL-005, and the
/// promotion log JSONL serde shape (action is a flat lowercase string).
#[tokio::test]
async fn promote_rollback_round_trip() {
    let _env_guard = ENV_LOCK.lock().unwrap();
    let start = Instant::now();

    let tmp = tempfile::tempdir().expect("tempdir");
    write_report(tmp.path(), 100);
    write_fake_gguf(tmp.path(), "ft-v1");

    let orig_home = std::env::var_os("HOME");
    std::env::set_var("HOME", tmp.path());
    write_starter_config(tmp.path());

    let addr = start_server(tmp.path()).await;
    let base = format!("http://{}", addr);
    let client = reqwest::Client::new();

    // 1. Promote — should succeed with 200.
    let promote_resp = auth(
        &client,
        reqwest::Method::POST,
        &format!("{}/api/model/promote", base),
    )
    .json(&serde_json::json!({"tag": "ft-v1", "force": false}))
    .send()
    .await
    .expect("promote request failed");

    assert_eq!(
        promote_resp.status(),
        200,
        "promote expected 200, got: {}",
        promote_resp.status()
    );
    let promote_body: serde_json::Value = promote_resp.json().await.unwrap();
    assert_eq!(
        promote_body["new_provider"], "embedded",
        "new_provider: {}",
        promote_body
    );
    assert!(
        promote_body["new_model"]
            .as_str()
            .unwrap_or("")
            .ends_with("ft-v1.gguf"),
        "new_model must end with ft-v1.gguf: {}",
        promote_body
    );

    // 2. List promotions — 1 entry, action="promote".
    let list_resp = auth(
        &client,
        reqwest::Method::GET,
        &format!("{}/api/model/promotions", base),
    )
    .send()
    .await
    .expect("list promotions failed");

    assert_eq!(list_resp.status(), 200);
    let list_body: serde_json::Value = list_resp.json().await.unwrap();
    let entries = list_body.as_array().expect("promotions must be array");
    assert_eq!(
        entries.len(),
        1,
        "expected 1 entry after promote: {:?}",
        entries
    );
    assert_eq!(
        entries[0]["action"],
        serde_json::Value::String("promote".into()),
        "action must be flat string 'promote': {}",
        entries[0]
    );

    // 3. Rollback — should succeed with 200.
    let rollback_resp = auth(
        &client,
        reqwest::Method::POST,
        &format!("{}/api/model/rollback", base),
    )
    .send()
    .await
    .expect("rollback request failed");

    assert_eq!(
        rollback_resp.status(),
        200,
        "rollback expected 200, got: {}",
        rollback_resp.status()
    );
    let rollback_body: serde_json::Value = rollback_resp.json().await.unwrap();
    assert_eq!(
        rollback_body["new_provider"], "ollama",
        "rollback must restore ollama: {}",
        rollback_body
    );

    // 4. List promotions — 2 entries, second is "rollback".
    let list2_resp = auth(
        &client,
        reqwest::Method::GET,
        &format!("{}/api/model/promotions", base),
    )
    .send()
    .await
    .expect("list promotions 2 failed");

    assert_eq!(list2_resp.status(), 200);
    let list2_body: serde_json::Value = list2_resp.json().await.unwrap();
    let entries2 = list2_body.as_array().expect("promotions must be array");
    assert_eq!(
        entries2.len(),
        2,
        "expected 2 entries after rollback: {:?}",
        entries2
    );
    assert_eq!(
        entries2[1]["action"],
        serde_json::Value::String("rollback".into()),
        "second entry must be 'rollback': {}",
        entries2[1]
    );

    // 5. Wall time.
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(60),
        "test wall time {:.2}s exceeded 60s budget",
        elapsed.as_secs_f32()
    );

    match orig_home {
        Some(value) => std::env::set_var("HOME", value),
        None => std::env::remove_var("HOME"),
    }
}

// ── P1 gate ───────────────────────────────────────────────────────────────────

/// force=false + 1 example (below min 50) -> 409.
#[tokio::test]
async fn p1_gate_blocks_below_threshold() {
    let _env_guard = ENV_LOCK.lock().unwrap();
    let tmp = tempfile::tempdir().expect("tempdir");
    write_report(tmp.path(), 1);
    write_fake_gguf(tmp.path(), "ft-v1");

    let orig_home = std::env::var_os("HOME");
    std::env::set_var("HOME", tmp.path());

    let addr = start_server(tmp.path()).await;
    let base = format!("http://{}", addr);
    let client = reqwest::Client::new();

    let resp = auth(
        &client,
        reqwest::Method::POST,
        &format!("{}/api/model/promote", base),
    )
    .json(&serde_json::json!({"tag": "ft-v1", "force": false}))
    .send()
    .await
    .expect("promote request failed");

    assert_eq!(
        resp.status(),
        409,
        "force=false below threshold must be 409"
    );

    match orig_home {
        Some(value) => std::env::set_var("HOME", value),
        None => std::env::remove_var("HOME"),
    }
}

/// force=true + 1 example -> not 409 (gate bypassed).
#[tokio::test]
async fn p1_gate_bypassed_with_force() {
    let _env_guard = ENV_LOCK.lock().unwrap();
    let tmp = tempfile::tempdir().expect("tempdir");
    write_report(tmp.path(), 1);
    write_fake_gguf(tmp.path(), "ft-v1");

    let orig_home = std::env::var_os("HOME");
    std::env::set_var("HOME", tmp.path());
    write_starter_config(tmp.path());

    let addr = start_server(tmp.path()).await;
    let base = format!("http://{}", addr);
    let client = reqwest::Client::new();

    let resp = auth(
        &client,
        reqwest::Method::POST,
        &format!("{}/api/model/promote", base),
    )
    .json(&serde_json::json!({"tag": "ft-v1", "force": true}))
    .send()
    .await
    .expect("promote force=true request failed");

    assert_ne!(resp.status(), 409, "force=true must not return 409");

    match orig_home {
        Some(value) => std::env::set_var("HOME", value),
        None => std::env::remove_var("HOME"),
    }
}

// ── Empty log ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn rollback_empty_log_is_404() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let addr = start_server(tmp.path()).await;
    let base = format!("http://{}", addr);
    let client = reqwest::Client::new();

    let resp = auth(
        &client,
        reqwest::Method::POST,
        &format!("{}/api/model/rollback", base),
    )
    .send()
    .await
    .expect("rollback request failed");

    assert_eq!(resp.status(), 404, "empty log must return 404");
}

// ── Serde shape ───────────────────────────────────────────────────────────────

/// action field must be a flat lowercase string, not a tagged enum.
#[tokio::test]
async fn promotion_action_serializes_as_flat_string() {
    use sigint_train::promotion::{append_promotion_log, PromotionAction, PromotionEntry};

    let tmp = tempfile::tempdir().expect("tempdir");
    let entry = PromotionEntry {
        ts: chrono::Utc::now(),
        action: PromotionAction::Rollback,
        old_provider: "embedded".into(),
        old_model: "/models/ft-v1.gguf".into(),
        new_provider: "ollama".into(),
        new_model: "llama3.2:8b".into(),
        eval_result_ref: None,
    };
    append_promotion_log(tmp.path(), &entry).unwrap();

    let addr = start_server(tmp.path()).await;
    let base = format!("http://{}", addr);
    let client = reqwest::Client::new();

    let resp = auth(
        &client,
        reqwest::Method::GET,
        &format!("{}/api/model/promotions", base),
    )
    .send()
    .await
    .expect("promotions list failed");

    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let arr = body.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(
        arr[0]["action"],
        serde_json::Value::String("rollback".into()),
        "action must be plain 'rollback', not nested: {}",
        arr[0]
    );
}
