//! Integration test: full end-to-end closed loop (harvest → export → finetune →
//! poll → promote → list → rollback → list).
//!
//! This test ties together the flows exercised individually in `train_flow.rs`
//! (harvest/export/finetune) and `promote_flow.rs` (promote/rollback) into a
//! single sequential run, verifying that the shared filesystem state produced
//! by the training steps is correctly consumed by the promotion steps.
//!
//! Evaluate (POST /api/train/evaluate) is deliberately skipped here because
//! that route shells out to `OllamaProvider` which is not injectable from
//! `AppState` — it would require a live Ollama instance.
//! TODO(#21): once TrainingJobProgress events are wired and OllamaProvider is
//! injectable, extend this test with full evaluate coverage.
//!
//! Must run with `--test-threads=1` because it mutates the HOME environment
//! variable (same requirement as train_flow.rs and promote_flow.rs).
//!
//! Wall-time budget: 10 s.
//!
//! @decision DEC-P26-T8-001
//! @title full_loop.rs skips evaluate step — OllamaProvider not injectable from AppState
//! @status accepted
//! @rationale The train_run_eval handler hardcodes `OllamaProvider::new()` inside
//! the spawned task, bypassing AppState. Wiring in a MockProvider requires either
//! an AppState field (scope creep) or a real Ollama instance (CI environment
//! assumption). The rest of the closed loop is fully covered; evaluate is tested
//! independently in sigint-train/tests/evaluate_integration.rs.

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

/// Write last_eval.json with sufficient examples so the P1 gate passes.
fn write_eval_report(dir: &std::path::Path, total_examples: usize) {
    let report = serde_json::json!({
        "base_tag": "llama3:8b",
        "candidate_tag": "full-loop-adapter",
        "total_examples": total_examples,
        "tool_accuracy_delta": 0.04,
        "argument_match_delta": 0.01,
        "evaluated_at": "2026-04-24T00:00:00Z"
    });
    std::fs::write(
        dir.join("last_eval.json"),
        serde_json::to_string_pretty(&report).unwrap(),
    )
    .unwrap();
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

/// Full closed loop: harvest → export → finetune → poll → promote → list → rollback → list.
///
/// Verifies REQ-P26-GOAL-005 (CLI and web share filesystem state), REQ-P26-P0-003
/// (jobs.json round-trip), REQ-P26-P0-005 (promote), REQ-P26-P0-006 (rollback).
///
/// Evaluate (POST /api/train/evaluate) is skipped — see module docstring.
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
    let session_id = seed_session(&db);

    // ── 2. POST /api/train/harvest/<session_id> ───────────────────────────────
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

    // ── 6. Seed promote prerequisites ─────────────────────────────────────────
    // last_eval.json is seeded with sufficient examples so the P1 gate passes.
    // The .gguf file is seeded so detect_output_kind succeeds.
    // NOTE: In production the real workflow would run evaluate first to produce
    // last_eval.json. Here we seed it directly because evaluate requires Ollama.
    write_eval_report(&training_dir, 100);
    write_fake_gguf(&training_dir, "full-loop-adapter");

    // ── 7. POST /api/model/promote ────────────────────────────────────────────
    let promote = auth(
        &client,
        reqwest::Method::POST,
        &format!("{}/api/model/promote", base),
    )
    .json(&serde_json::json!({"tag": "full-loop-adapter", "force": false}))
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
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(10),
        "test wall time {:.2}s exceeded 10s budget",
        elapsed.as_secs_f32()
    );

    std::env::set_var("HOME", orig_home);
}
