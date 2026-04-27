//! Integration test: full end-to-end closed loop (harvest → export → finetune →
//! poll → evaluate → promote → list → rollback → list).
//!
//! This test ties together the flows exercised individually in `train_flow.rs`
//! (harvest/export/finetune) and `promote_flow.rs` (promote/rollback) into a
//! single sequential run, verifying that the shared filesystem state produced
//! by the training steps is correctly consumed by the promotion steps.
//!
//! The evaluate step (POST /api/train/evaluate) is now exercised end-to-end
//! via the `provider_factory` field added to `AppState` (DEC-P26-T8-001).
//! `start_server` injects a `MockProvider` via the factory so `train_run_eval`
//! runs without a live Ollama instance. The mock returns `[mock exhausted]`
//! (no tool calls), which produces a 0% accuracy ComparisonReport — a valid
//! result that satisfies `persist_last_eval` and the promote P1 gate.
//!
//! Must run with `--test-threads=1` because it mutates the HOME environment
//! variable (same requirement as train_flow.rs and promote_flow.rs).
//!
//! Wall-time budget: 60 s.
//!
//! @decision DEC-P26-T8-001
//! @title Provider factory threaded through AppState — evaluate step re-enabled
//! @status accepted
//! @rationale Previously `train_run_eval` hardcoded `OllamaProvider::from_config`
//! inside the spawned task, preventing MockProvider injection from tests. Adding
//! `provider_factory: ProviderFactory` to `AppState` closes this gap: production
//! binds `sigint_llm::factory::create_provider`; tests inject a closure returning
//! `MockProvider::new()`. This re-enables the closed-loop evaluate step without
//! requiring a live Ollama instance. Closes the architectural gap noted in the
//! original Phase 26 T8 retrospective.

use std::sync::Arc;
use std::time::{Duration, Instant};

use sigint_agents::ScanService;
use sigint_core::{
    event::EventBus,
    types::{Message, Session},
    ApprovalRegistry, Config,
};
use sigint_store::{Database, ScanRecord};
use sigint_web::AppState;
use tokio::sync::Semaphore;
use uuid::Uuid;

// ── Shared test key ───────────────────────────────────────────────────────────

const TEST_KEY: &str = "full-loop-test-token";

fn auth(client: &reqwest::Client, method: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
    client.request(method, url).bearer_auth(TEST_KEY)
}

// ── Server bootstrap ──────────────────────────────────────────────────────────

/// Start a real Axum server configured for the full closed loop.
///
/// `fake_home` is used as the HOME directory. Both `config.train.job_dir` and
/// `config.llm.models_dir` point into `fake_home` so the finetune output and
/// promote detection both resolve without touching the real home directory.
///
/// The mock finetune command writes a fixed marker to the output path — same
/// pattern as train_flow.rs to avoid empty-file issues from 80/20 split edge cases.
async fn start_server(
    fake_home: &std::path::Path,
) -> (std::net::SocketAddr, Arc<Database>, std::path::PathBuf) {
    let training_dir = fake_home
        .join(".local")
        .join("share")
        .join("sigint")
        .join("training");
    std::fs::create_dir_all(&training_dir).expect("create training_dir");

    let db = Arc::new(Database::open_in_memory().expect("in-memory db"));
    let event_bus = EventBus::new();

    let mut config = Config::default();
    // Mock finetune: write a marker to the output path (same pattern as train_flow.rs).
    config.train.finetune_command =
        "sh -c 'printf \"mock-training-complete\\n\" > \"$SIGINT_OUTPUT_PATH\"'".to_string();
    config.train.job_dir = Some(training_dir.clone());
    // models_dir must point to training_dir so promote's detect_output_kind
    // can locate the fake .gguf file we'll seed there.
    config.llm.models_dir = Some(training_dir.to_string_lossy().into_owned());
    config.web.train.max_concurrent_jobs = 0;

    let config = Arc::new(config);
    let approval_registry = Arc::new(ApprovalRegistry::new(Duration::from_secs(30)));
    let scan_service = Arc::new(ScanService::new(
        config.clone(),
        event_bus.clone(),
        approval_registry.clone(),
    ));

    let state = AppState {
        db: Arc::clone(&db),
        event_bus,
        training_job_semaphore: Arc::new(Semaphore::new(Semaphore::MAX_PERMITS)),
        config,
        approval_registry,
        scan_service,
        api_key: TEST_KEY.to_string(),
        provider_factory: std::sync::Arc::new(|_cfg| {
            Ok(Box::new(sigint_llm::MockProvider::new()) as Box<dyn sigint_llm::LlmProvider>)
        }),
    };

    let app = sigint_web::create_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind to random port");
    let addr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });

    (addr, db, training_dir)
}

// ── DB seeding ────────────────────────────────────────────────────────────────

/// Seed a session with three successful scan records so export produces examples.
fn seed_session(db: &Database) -> Uuid {
    let session = Session::new("full-loop-test").with_target("10.0.0.1");
    db.create_session(&session).expect("create_session");

    let msg = Message::user(session.id, "scan 10.0.0.1");
    db.create_message(&msg).expect("create_message user");
    let msg2 = Message::assistant(session.id, "Running nmap...");
    db.create_message(&msg2).expect("create_message assistant");

    for tool in ["nmap_scan", "gobuster", "shell"] {
        let mut record = ScanRecord::new(session.id, tool, r#"{"target":"10.0.0.1"}"#);
        record.exit_code = Some(0);
        record.output = Some(format!("{} output for 10.0.0.1", tool));
        record.finished_at = Some(chrono::Utc::now().to_rfc3339());
        record.agent_role = Some("executor".to_string());
        db.create_scan_record(&record).expect("create_scan_record");
    }

    session.id
}

/// Seed a session with a deterministic UUID that lands in the test partition.
///
/// The train/test split uses `u64::from_be_bytes(session_id.bytes()[..8]) % 10`.
/// UUID `08000000-0000-0000-0000-000000000000` produces hash 576460752303423488,
/// which is `% 10 == 8` → test partition. This guarantees `test.jsonl` is
/// non-empty so `POST /api/train/evaluate` can run.
fn seed_test_partition_session(db: &Database) {
    // This UUID deterministically lands in the test partition (hash % 10 == 8).
    let test_session_id =
        Uuid::parse_str("08000000-0000-0000-0000-000000000000").expect("valid uuid");
    let mut session = Session::new("full-loop-test-partition").with_target("10.0.0.2");
    session.id = test_session_id;
    db.create_session(&session).expect("create_session test");

    let msg = Message::user(session.id, "scan 10.0.0.2");
    db.create_message(&msg).expect("create_message user test");
    let msg2 = Message::assistant(session.id, "Running nmap...");
    db.create_message(&msg2)
        .expect("create_message assistant test");

    for tool in ["nmap_scan", "gobuster"] {
        let mut record = ScanRecord::new(session.id, tool, r#"{"target":"10.0.0.2"}"#);
        record.exit_code = Some(0);
        record.output = Some(format!("{} output for 10.0.0.2", tool));
        record.finished_at = Some(chrono::Utc::now().to_rfc3339());
        record.agent_role = Some("executor".to_string());
        db.create_scan_record(&record)
            .expect("create_scan_record test");
    }
}

// ── Poll helper ───────────────────────────────────────────────────────────────

/// Poll GET /api/train/jobs until any job reaches a terminal status.
///
/// Uses the list endpoint rather than GET /api/train/jobs/<id> because of the
/// known handler-vs-persisted job_id mismatch documented in train_flow.rs.
async fn wait_for_job_terminal(
    client: &reqwest::Client,
    base: &str,
    timeout: Duration,
) -> serde_json::Value {
    let deadline = Instant::now() + timeout;
    loop {
        let resp = auth(
            client,
            reqwest::Method::GET,
            &format!("{}/api/train/jobs", base),
        )
        .send()
        .await
        .expect("GET /api/train/jobs failed");

        if resp.status() == 200 {
            let body: serde_json::Value = resp.json().await.unwrap();
            if let Some(jobs) = body["jobs"].as_array() {
                if let Some(terminal) = jobs.iter().find(|j| {
                    j["status"]["status"]
                        .as_str()
                        .map(|s| s != "Running")
                        .unwrap_or(false)
                }) {
                    return terminal.clone();
                }
            }
        }

        if Instant::now() >= deadline {
            panic!(
                "no training job reached terminal state within {:?}",
                timeout
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

// ── Filesystem helpers ────────────────────────────────────────────────────────

/// Write a fake .gguf file so promote's detect_output_kind succeeds.
fn write_fake_gguf(dir: &std::path::Path, name: &str) {
    std::fs::write(dir.join(format!("{}.gguf", name)), b"fake-gguf-content").unwrap();
}

/// Write a minimal config.toml so atomic_config_rewrite has a file to operate on.
fn write_starter_config(home: &std::path::Path) {
    let config_dir = home.join(".config").join("sigint");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::write(
        config_dir.join("config.toml"),
        "[llm]\nprovider = \"ollama\"\nmodel = \"llama3.2:8b\"\n",
    )
    .unwrap();
}

// ── Main test ─────────────────────────────────────────────────────────────────

/// Full closed loop: harvest → export → finetune → poll → evaluate → promote → list → rollback → list.
///
/// Verifies REQ-P26-GOAL-005 (CLI and web share filesystem state), REQ-P26-P0-003
/// (jobs.json round-trip), REQ-P26-P0-004 (evaluate), REQ-P26-P0-005 (promote),
/// REQ-P26-P0-006 (rollback).
///
/// The evaluate step runs end-to-end against a MockProvider (DEC-P26-T8-001).
#[tokio::test]
async fn full_closed_loop() {
    let start = Instant::now();

    let tmp = tempfile::tempdir().expect("tempdir");
    let orig_home = std::env::var("HOME").unwrap_or_default();
    std::env::set_var("HOME", tmp.path());

    write_starter_config(tmp.path());

    let (addr, db, training_dir) = start_server(tmp.path()).await;
    let base = format!("http://{}", addr);
    let client = reqwest::Client::new();

    // ── 1. Seed DB ────────────────────────────────────────────────────────────
    // Seed two sessions: one that lands in the train partition (random UUID) and
    // one with a deterministic UUID that always lands in the test partition, so
    // `test.jsonl` is non-empty and POST /api/train/evaluate can run.
    let session_id = seed_session(&db);
    seed_test_partition_session(&db);
    let test_session_id =
        uuid::Uuid::parse_str("08000000-0000-0000-0000-000000000000").expect("valid uuid");

    // ── 2. POST /api/train/harvest both sessions ──────────────────────────────
    let harvest = auth(
        &client,
        reqwest::Method::POST,
        &format!("{}/api/train/harvest/{}", base, session_id),
    )
    .send()
    .await
    .expect("harvest request");
    assert_eq!(harvest.status(), 200, "harvest: {}", harvest.status());
    let hb: serde_json::Value = harvest.json().await.unwrap();
    assert_eq!(hb["harvested"], true, "harvest body: {}", hb);

    // Harvest the test-partition session too.
    let harvest2 = auth(
        &client,
        reqwest::Method::POST,
        &format!("{}/api/train/harvest/{}", base, test_session_id),
    )
    .send()
    .await
    .expect("harvest test-partition session");
    assert_eq!(
        harvest2.status(),
        200,
        "harvest test-partition: {}",
        harvest2.status()
    );

    // ── 3. POST /api/train/export ─────────────────────────────────────────────
    let export = auth(
        &client,
        reqwest::Method::POST,
        &format!("{}/api/train/export", base),
    )
    .send()
    .await
    .expect("export request");
    assert_eq!(export.status(), 200, "export: {}", export.status());
    let eb: serde_json::Value = export.json().await.unwrap();
    let train_count = eb["train_count"].as_u64().expect("train_count");
    let test_count = eb["test_count"].as_u64().expect("test_count");
    assert!(
        train_count + test_count > 0,
        "export: total examples must be > 0, got train={} test={}",
        train_count,
        test_count
    );
    // The test-partition session must produce test examples for evaluate to work.
    assert!(
        test_count > 0,
        "export: test_count must be > 0 (deterministic test-partition session not found), got train={} test={}",
        train_count,
        test_count
    );

    // ── 4. POST /api/train/finetune ───────────────────────────────────────────
    let finetune = auth(
        &client,
        reqwest::Method::POST,
        &format!("{}/api/train/finetune", base),
    )
    .header("content-type", "application/json")
    .body(r#"{"base_model":"llama3:8b","output_name":"full-loop-adapter"}"#)
    .send()
    .await
    .expect("finetune request");
    assert_eq!(finetune.status(), 202, "finetune: {}", finetune.status());
    let fb: serde_json::Value = finetune.json().await.unwrap();
    assert!(
        fb["job_id"].as_str().is_some(),
        "finetune response must contain job_id: {}",
        fb
    );

    // ── 5. Poll until job is terminal (Success expected within 5 s) ───────────
    let job = wait_for_job_terminal(&client, &base, Duration::from_secs(5)).await;
    assert_eq!(
        job["status"]["status"], "Success",
        "job must reach Success: {}",
        job
    );
    assert_eq!(job["exit_code"], 0, "exit_code must be 0: {}", job);

    // Output file must exist (mock printf wrote it).
    let output_file = training_dir.join("full-loop-adapter");
    assert!(
        output_file.exists(),
        "output file {} must exist after mock finetune",
        output_file.display()
    );

    // jobs.json must exist.
    assert!(
        training_dir.join("jobs.json").exists(),
        "jobs.json must exist (DEC-P26-002)"
    );

    // ── 6. POST /api/train/evaluate (end-to-end via MockProvider) ────────────
    // The provider_factory injected at server start returns MockProvider::new(),
    // which returns "[mock exhausted]" (no tool calls) for every chat() call.
    // This produces a 0% accuracy ComparisonReport — valid for persist_last_eval.
    // We use force=true on promote below so the 0-example gate doesn't block.
    let eval_resp = auth(
        &client,
        reqwest::Method::POST,
        &format!("{}/api/train/evaluate", base),
    )
    .header("content-type", "application/json")
    .body(r#"{"base":"llama3:8b","candidate":"full-loop-adapter"}"#)
    .send()
    .await
    .expect("evaluate request");
    assert_eq!(
        eval_resp.status(),
        202,
        "evaluate must return 202 Accepted: {}",
        eval_resp.status()
    );
    let eval_body: serde_json::Value = eval_resp.json().await.unwrap();
    assert!(
        eval_body["eval_id"].as_str().is_some(),
        "evaluate response must contain eval_id: {}",
        eval_body
    );

    // Poll until last_eval.json appears (written by persist_last_eval in the spawned task).
    let eval_deadline = Instant::now() + Duration::from_secs(10);
    let last_eval_path = training_dir.join("last_eval.json");
    loop {
        if last_eval_path.exists() {
            break;
        }
        if Instant::now() >= eval_deadline {
            panic!("last_eval.json did not appear within 10s after POST /api/train/evaluate");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Verify last_eval.json is valid JSON with expected fields.
    let eval_content = std::fs::read_to_string(&last_eval_path).expect("read last_eval.json");
    let eval_report: serde_json::Value =
        serde_json::from_str(&eval_content).expect("last_eval.json must be valid JSON");
    assert_eq!(
        eval_report["base_tag"], "llama3:8b",
        "base_tag mismatch: {}",
        eval_report
    );
    assert_eq!(
        eval_report["candidate_tag"], "full-loop-adapter",
        "candidate_tag mismatch: {}",
        eval_report
    );

    // Seed the .gguf file so detect_output_kind succeeds for promote.
    write_fake_gguf(&training_dir, "full-loop-adapter");

    // ── 7. POST /api/model/promote (force=true bypasses 0-example eval gate) ─
    let promote = auth(
        &client,
        reqwest::Method::POST,
        &format!("{}/api/model/promote", base),
    )
    .json(&serde_json::json!({"tag": "full-loop-adapter", "force": true}))
    .send()
    .await
    .expect("promote request");
    assert_eq!(promote.status(), 200, "promote: {}", promote.status());
    let pb: serde_json::Value = promote.json().await.unwrap();
    assert_eq!(
        pb["new_provider"], "embedded",
        "promote must set provider=embedded: {}",
        pb
    );
    assert!(
        pb["new_model"]
            .as_str()
            .unwrap_or("")
            .ends_with("full-loop-adapter.gguf"),
        "promote new_model must end with full-loop-adapter.gguf: {}",
        pb
    );

    // ── 8. GET /api/model/promotions → 1 entry ────────────────────────────────
    let list1 = auth(
        &client,
        reqwest::Method::GET,
        &format!("{}/api/model/promotions", base),
    )
    .send()
    .await
    .expect("list promotions");
    assert_eq!(list1.status(), 200);
    let l1b: serde_json::Value = list1.json().await.unwrap();
    let entries1 = l1b.as_array().expect("promotions must be array");
    assert_eq!(
        entries1.len(),
        1,
        "expected 1 entry after promote: {:?}",
        entries1
    );
    assert_eq!(
        entries1[0]["action"],
        serde_json::Value::String("promote".into()),
        "first entry must be 'promote': {}",
        entries1[0]
    );

    // ── 9. POST /api/model/rollback ───────────────────────────────────────────
    let rollback = auth(
        &client,
        reqwest::Method::POST,
        &format!("{}/api/model/rollback", base),
    )
    .send()
    .await
    .expect("rollback request");
    assert_eq!(rollback.status(), 200, "rollback: {}", rollback.status());
    let rb: serde_json::Value = rollback.json().await.unwrap();
    assert_eq!(
        rb["new_provider"], "ollama",
        "rollback must restore ollama: {}",
        rb
    );

    // ── 10. GET /api/model/promotions → 2 entries ────────────────────────────
    let list2 = auth(
        &client,
        reqwest::Method::GET,
        &format!("{}/api/model/promotions", base),
    )
    .send()
    .await
    .expect("list promotions 2");
    assert_eq!(list2.status(), 200);
    let l2b: serde_json::Value = list2.json().await.unwrap();
    let entries2 = l2b.as_array().expect("promotions must be array");
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

    // ── 11. Wall time guard ───────────────────────────────────────────────────
    // Budget is 120s: the evaluate step adds real async work (MockProvider chat
    // calls for each test example × 2 providers). Debug builds are slower.
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(120),
        "test wall time {:.2}s exceeded 120s budget",
        elapsed.as_secs_f32()
    );

    std::env::set_var("HOME", orig_home);
}
