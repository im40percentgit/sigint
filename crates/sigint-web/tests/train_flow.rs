//! Integration test: full training HTTP flow (harvest → stats → export → finetune → poll).
//!
//! Spins up a real Axum server on a random port with an in-memory SQLite database.
//! Seeds scan history directly via the store API, then exercises every training
//! endpoint in sequence to verify the end-to-end path works without a real GPU.
//!
//! The finetune command is set to a shell no-op that copies the training JSONL
//! to the output path, simulating a successful training run in < 1 second.
//!
//! @decision DEC-E2E-001
//! @title E2E tests use real Axum server on random port with in-memory SQLite
//! @status accepted
//! @rationale Mirrors the production code path exactly — same router, same state
//! construction, same middleware. In-memory SQLite provides isolation without
//! filesystem cleanup. Random port eliminates parallel-test conflicts.

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

// ── Test API key ─────────────────────────────────────────────────────────────

const TEST_KEY: &str = "train-flow-test-token";

fn auth(client: &reqwest::Client, method: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
    client.request(method, url).bearer_auth(TEST_KEY)
}

// ── Server bootstrap ─────────────────────────────────────────────────────────

/// Start the Axum server with a custom train config.
///
/// `finetune_command` is set to `sh -c 'cp "$SIGINT_TRAIN_JSONL" "$SIGINT_OUTPUT_PATH"'`
/// which copies the training JSONL to the output path — a safe, fast mock that
/// exits 0 and produces an output file for assertion purposes.
///
/// `config.train.job_dir` is set to the same directory that `train_export` will
/// write JSONL files into (`HOME/.local/share/sigint/training/`), computed from
/// the `fake_home` argument. This ensures finetune can find `train.jsonl` and
/// `test.jsonl` written by the export handler.
///
/// The caller must set `HOME` to `fake_home` before calling this function so
/// that `train_export`'s hardcoded `HOME` lookup resolves to the same directory.
/// This test must run with `--test-threads=1` because it mutates the HOME env var.
///
/// @decision DEC-E2E-004
/// @title Seed DB before HTTP calls; custom config injected at AppState construction
/// @status accepted
/// @rationale Training handlers resolve paths from config at request time, so
/// overriding config.train.job_dir and HOME before the server starts is the
/// correct injection point. job_dir is set to match the export output path so
/// train_finetune can locate the JSONL files written by train_export. No
/// routes.rs changes are needed.
async fn start_server_with_train_config(
    fake_home: &std::path::Path,
) -> (std::net::SocketAddr, Arc<Database>, std::path::PathBuf) {
    // This is the same path train_export uses: HOME/.local/share/sigint/training/
    let training_dir = fake_home
        .join(".local")
        .join("share")
        .join("sigint")
        .join("training");
    std::fs::create_dir_all(&training_dir).expect("create training_dir");

    let db = Arc::new(Database::open_in_memory().expect("in-memory db"));
    let event_bus = EventBus::new();

    let mut config = Config::default();
    // Mock finetune command: copy training JSONL to output path via shell.
    // Uses sh -c so env vars are expanded by the shell, not the Rust process.
    // Mock finetune command: write a fixed marker to the output path.
    // We use `printf` rather than `cp "$SIGINT_TRAIN_JSONL"` because the
    // 80/20 session-based split may put all examples in the test partition
    // (session UUID hash % 10 >= 8), leaving train.jsonl empty and making
    // a cp-based mock produce an empty output file. `printf` always writes
    // a non-empty file regardless of split results, while still exercising
    // the env-var expansion and sh -c invocation path (Phase 24 mock ABI).
    config.train.finetune_command =
        "sh -c 'printf \"mock-training-complete\\n\" > \"$SIGINT_OUTPUT_PATH\"'".to_string();
    // Point job_dir to the training subdirectory — same location train_export writes to.
    // This ensures finetune finds train.jsonl and test.jsonl written by export.
    config.train.job_dir = Some(training_dir.clone());
    // Disable the concurrency cap for this test (single job, no contention).
    config.web.train.max_concurrent_jobs = 0;

    let config = Arc::new(config);
    let approval_registry = Arc::new(ApprovalRegistry::new(Duration::from_secs(30)));
    let scan_service = Arc::new(ScanService::new(
        config.clone(),
        event_bus.clone(),
        approval_registry.clone(),
    ));

    // Semaphore: 0 max_concurrent_jobs → cap disabled.
    // Use Semaphore::MAX_PERMITS (tokio's safe upper bound) rather than
    // usize::MAX which exceeds tokio's internal MAX_PERMITS and panics.
    let permits = Semaphore::MAX_PERMITS;

    let state = AppState {
        db: Arc::clone(&db),
        event_bus,
        training_job_semaphore: Arc::new(Semaphore::new(permits)),
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

/// Like `start_server_with_train_config` but also returns the `EventBus` so
/// tests can subscribe to events before the finetune request is sent.
///
/// The finetune command emits multiple lines via `echo` with short sleeps so the
/// streaming runner has time to deliver at least one `TrainingJobProgress` event
/// before the process exits and `TrainingJobCompleted` is emitted.
async fn start_server_with_event_bus(
    fake_home: &std::path::Path,
) -> (
    std::net::SocketAddr,
    Arc<Database>,
    std::path::PathBuf,
    sigint_core::event::EventBus,
) {
    let training_dir = fake_home
        .join(".local")
        .join("share")
        .join("sigint")
        .join("training");
    std::fs::create_dir_all(&training_dir).expect("create training_dir");

    let db = Arc::new(Database::open_in_memory().expect("in-memory db"));
    let event_bus = sigint_core::event::EventBus::new();

    let mut config = Config::default();
    // Emit several lines with small delays so at least one TrainingJobProgress
    // arrives before TrainingJobCompleted. printf writes the output file.
    config.train.finetune_command = concat!(
        "sh -c '",
        "echo progress-line-1; sleep 0.05; ",
        "echo progress-line-2; sleep 0.05; ",
        "echo progress-line-3; ",
        "printf \"mock-training-complete\\n\" > \"$SIGINT_OUTPUT_PATH\"",
        "'"
    )
    .to_string();
    config.train.job_dir = Some(training_dir.clone());
    config.web.train.max_concurrent_jobs = 0;
    // Small tail cap to exercise the bounded-tail path.
    config.web.train.stdout_tail_bytes = 512;

    let config = Arc::new(config);
    let approval_registry = Arc::new(ApprovalRegistry::new(Duration::from_secs(30)));
    let scan_service = Arc::new(ScanService::new(
        config.clone(),
        event_bus.clone(),
        approval_registry.clone(),
    ));

    let state = AppState {
        db: Arc::clone(&db),
        event_bus: event_bus.clone(),
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

    (addr, db, training_dir, event_bus)
}

// ── DB seeding helper ─────────────────────────────────────────────────────────

/// Seed a session with three successful scan records and two messages.
///
/// extract_all requires trainable=1 sessions with at least one scan_record
/// where exit_code=0. We insert three records to ensure split produces
/// at least one train example and makes stats > 0.
fn seed_session(db: &Database) -> Uuid {
    let session = Session::new("train-flow-test").with_target("10.0.0.1");
    db.create_session(&session).expect("create_session");

    // Insert a user message for context window.
    let msg = Message::user(session.id, "scan 10.0.0.1");
    db.create_message(&msg).expect("create_message user");
    let msg2 = Message::assistant(session.id, "Running nmap scan...");
    db.create_message(&msg2).expect("create_message assistant");

    // Three successful tool invocations — each becomes a TrainingExample.
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

// ── Poll helper ──────────────────────────────────────────────────────────────

/// Poll GET /api/train/jobs/<job_id> until the job has a non-Running status.
///
/// Since issue #35 is fixed, the job_id from the 202 body now matches the
/// persisted JobRecord id, so we can look up directly by id.
///
/// Returns the terminal job JSON value.
async fn wait_for_job_terminal(
    client: &reqwest::Client,
    base: &str,
    job_id: &str,
    timeout: Duration,
) -> serde_json::Value {
    let deadline = Instant::now() + timeout;
    loop {
        let resp = auth(
            client,
            reqwest::Method::GET,
            &format!("{}/api/train/jobs/{}", base, job_id),
        )
        .send()
        .await
        .expect("GET /api/train/jobs/<id> failed");

        if resp.status() == 200 {
            let body: serde_json::Value = resp.json().await.unwrap();
            // JobStatus uses serde(tag="status", content="reason"):
            //   running  → {"status":"Running"}
            //   success  → {"status":"Success"}
            //   failed   → {"status":"Failed","reason":"..."}
            // body["status"] is an object; drill into body["status"]["status"].
            let inner = &body["status"]["status"];
            if inner.as_str().map(|s| s != "Running").unwrap_or(false) {
                return body;
            }
        }

        if Instant::now() >= deadline {
            panic!(
                "job '{}' did not reach terminal state within {:?}",
                job_id, timeout
            );
        }

        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

// ── Main test ─────────────────────────────────────────────────────────────────

/// Full training HTTP flow: harvest → stats → export → finetune → poll job.
///
/// All assertions are inline. Wall time must be < 5 s (the mock command is
/// a single `cp` call that completes in < 100 ms on any modern system).
#[tokio::test]
async fn train_flow_end_to_end() {
    let start = Instant::now();

    // Isolated temp directory used as a fake HOME.
    // train_export writes to HOME/.local/share/sigint/training/;
    // we point HOME here so artifacts land in this tmp dir.
    let tmp = tempfile::tempdir().expect("tempdir");

    // Override HOME before starting the server so train_export resolves the
    // same path as config.train.job_dir. Requires --test-threads=1.
    // Safety: single-threaded test environment; no concurrent HOME reads.
    let orig_home = std::env::var("HOME").unwrap_or_default();
    std::env::set_var("HOME", tmp.path());

    // training_dir = HOME/.local/share/sigint/training/ — same as export writes to.
    let (addr, db, training_dir) = start_server_with_train_config(tmp.path()).await;
    let base = format!("http://{}", addr);
    let client = reqwest::Client::new();

    // ── 1. Seed DB: insert session + scan records ────────────────────────────
    let session_id = seed_session(&db);

    // ── 2. POST /api/train/harvest/<session_id> ──────────────────────────────
    let harvest_resp = auth(
        &client,
        reqwest::Method::POST,
        &format!("{}/api/train/harvest/{}", base, session_id),
    )
    .send()
    .await
    .expect("harvest request");

    assert_eq!(
        harvest_resp.status(),
        200,
        "harvest expected 200, got: {}",
        harvest_resp.status()
    );
    let harvest_body: serde_json::Value = harvest_resp.json().await.unwrap();
    assert_eq!(
        harvest_body["harvested"], true,
        "harvest body should contain harvested=true, got: {}",
        harvest_body
    );

    // ── 3. GET /api/train/stats ──────────────────────────────────────────────
    let stats_resp = auth(
        &client,
        reqwest::Method::GET,
        &format!("{}/api/train/stats", base),
    )
    .send()
    .await
    .expect("stats request");

    assert_eq!(
        stats_resp.status(),
        200,
        "stats expected 200, got: {}",
        stats_resp.status()
    );
    let stats_body: serde_json::Value = stats_resp.json().await.unwrap();
    let total_examples = stats_body["total_examples"]
        .as_u64()
        .expect("total_examples must be a number");
    assert!(
        total_examples > 0,
        "stats should show > 0 examples after harvest, got: {}",
        stats_body
    );

    // ── 4. POST /api/train/export ────────────────────────────────────────────
    let export_resp = auth(
        &client,
        reqwest::Method::POST,
        &format!("{}/api/train/export", base),
    )
    .send()
    .await
    .expect("export request");

    assert_eq!(
        export_resp.status(),
        200,
        "export expected 200, got: {}",
        export_resp.status()
    );
    let export_body: serde_json::Value = export_resp.json().await.unwrap();

    let train_count = export_body["train_count"]
        .as_u64()
        .expect("train_count must be a number");
    let test_count = export_body["test_count"]
        .as_u64()
        .expect("test_count must be a number");
    let train_path = export_body["train_path"]
        .as_str()
        .expect("train_path must be a string")
        .to_string();
    let _test_path = export_body["test_path"]
        .as_str()
        .expect("test_path must be a string");

    // With 3 examples: 80/20 split → train=2 or 3, test=0 or 1 (tolerate either).
    assert!(
        train_count + test_count > 0,
        "export should produce > 0 total examples, got train={} test={}",
        train_count,
        test_count
    );

    // ── 5. POST /api/train/finetune ──────────────────────────────────────────
    // The mock command copies train.jsonl to the output path.
    // The output file lives in job_dir per resolve_job_dir() using config.train.job_dir.
    let finetune_resp = auth(
        &client,
        reqwest::Method::POST,
        &format!("{}/api/train/finetune", base),
    )
    .header("content-type", "application/json")
    .body(r#"{"base_model":"llama3:8b","output_name":"test-adapter"}"#)
    .send()
    .await
    .expect("finetune request");

    assert_eq!(
        finetune_resp.status(),
        202,
        "finetune expected 202 Accepted, got: {}",
        finetune_resp.status()
    );
    let finetune_body: serde_json::Value = finetune_resp.json().await.unwrap();
    let job_id = finetune_body["job_id"]
        .as_str()
        .expect("finetune response must contain job_id")
        .to_string();

    // ── 6. Poll GET /api/train/jobs/<job_id> until terminal ──────────────────
    //
    // issue #35 fix: the handler's job_id is now threaded into run_finetune_streaming
    // so the persisted JobRecord carries the same UUID. Looking up by the 202
    // body's job_id now reliably returns the record.
    let job = wait_for_job_terminal(&client, &base, &job_id, Duration::from_secs(5)).await;

    // ── 7. Assertions on completed job ───────────────────────────────────────
    // JobStatus serde representation: job["status"] = {"status":"Success"}.
    assert_eq!(
        job["status"]["status"], "Success",
        "expected job status.status=Success, got: {}",
        job
    );
    assert_eq!(job["exit_code"], 0, "expected exit_code=0, got: {}", job);

    // Issue #35 regression guard: the record's id must match the 202 job_id.
    assert_eq!(
        job["id"].as_str(),
        Some(job_id.as_str()),
        "persisted JobRecord id must match the 202 body job_id (issue #35): got job={}",
        job
    );

    // jobs.json must exist in training_dir (= config.train.job_dir).
    let jobs_json = training_dir.join("jobs.json");
    assert!(
        jobs_json.exists(),
        "jobs.json must exist at {}",
        jobs_json.display()
    );

    // Output file written by the mock `cp` command: training_dir/test-adapter.
    // The finetune handler passes output_path = job_dir.join(output_name).
    let output_file = training_dir.join("test-adapter");
    assert!(
        output_file.exists(),
        "output file {} must exist after mock finetune command",
        output_file.display()
    );

    // Verify the output file is non-empty (mock printf wrote a marker).
    let output_size = std::fs::metadata(&output_file)
        .expect("stat output file")
        .len();
    assert!(
        output_size > 0,
        "output file must be non-empty (mock finetune command should have written to it)"
    );

    // Verify train_path returned by export actually exists on disk.
    assert!(
        std::path::Path::new(&train_path).exists(),
        "train_path {} returned by export must exist on disk",
        train_path
    );

    // ── 8. Wall time guard ───────────────────────────────────────────────────
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(5),
        "test wall time {} s exceeded 5 s budget",
        elapsed.as_secs_f32()
    );

    // Restore HOME so other tests in the workspace aren't affected.
    std::env::set_var("HOME", orig_home);
}

// ── TrainingJobProgress integration test ─────────────────────────────────────

/// Verify that `POST /api/train/finetune` emits at least one `TrainingJobProgress`
/// event on the event bus before `TrainingJobCompleted` is emitted.
///
/// This test subscribes to the event bus before the HTTP request is sent, then
/// collects events until `TrainingJobCompleted` arrives (or timeout).  It asserts
/// that at least one `TrainingJobProgress` was observed in between, proving that
/// the async streaming runner (run_finetune_streaming) is wired into the web
/// handler and progress events reach the bus.
///
/// Must run with `--test-threads=1` (mutates HOME env var, same as the sibling
/// tests in this file).
#[tokio::test]
async fn finetune_handler_emits_training_job_progress_events() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let orig_home = std::env::var("HOME").unwrap_or_default();
    std::env::set_var("HOME", tmp.path());

    let (addr, db, _training_dir, event_bus) = start_server_with_event_bus(tmp.path()).await;
    let base = format!("http://{}", addr);
    let client = reqwest::Client::new();

    // Subscribe to the bus BEFORE the HTTP request so we don't miss early events.
    let mut rx = event_bus.subscribe();

    // Seed a session with scan records so export produces JSONL files.
    let session_id = seed_session(&db);

    // Harvest + export so train.jsonl / test.jsonl exist for the finetune command.
    auth(
        &client,
        reqwest::Method::POST,
        &format!("{}/api/train/harvest/{}", base, session_id),
    )
    .send()
    .await
    .expect("harvest")
    .error_for_status()
    .expect("harvest 200");

    auth(
        &client,
        reqwest::Method::POST,
        &format!("{}/api/train/export", base),
    )
    .send()
    .await
    .expect("export")
    .error_for_status()
    .expect("export 200");

    // Fire the finetune request.
    let resp = auth(
        &client,
        reqwest::Method::POST,
        &format!("{}/api/train/finetune", base),
    )
    .header("content-type", "application/json")
    .body(r#"{"base_model":"llama3:8b","output_name":"progress-test-adapter"}"#)
    .send()
    .await
    .expect("finetune request");

    assert_eq!(
        resp.status(),
        202,
        "finetune expected 202, got {}",
        resp.status()
    );
    let finetune_body: serde_json::Value = resp.json().await.unwrap();
    let job_id = finetune_body["job_id"]
        .as_str()
        .expect("202 body must contain job_id")
        .to_string();

    // Drain events until TrainingJobCompleted (or 8 s timeout).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    let mut saw_progress = false;
    let mut saw_completed = false;

    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }

        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Ok(event)) => match &event {
                sigint_core::event::Event::TrainingJobProgress { .. } => {
                    saw_progress = true;
                }
                sigint_core::event::Event::TrainingJobCompleted { .. } => {
                    saw_completed = true;
                    break;
                }
                sigint_core::event::Event::TrainingJobFailed { error, .. } => {
                    panic!("training job failed unexpectedly: {}", error);
                }
                _ => {}
            },
            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(n))) => {
                // Receiver fell behind — messages were dropped. The test is still
                // valid; we may have missed events but continue draining.
                eprintln!("warn: event bus receiver lagged by {} messages", n);
            }
            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => {
                break;
            }
            Err(_timeout) => {
                break;
            }
        }
    }

    assert!(
        saw_completed,
        "expected TrainingJobCompleted within 8 s timeout"
    );
    assert!(
        saw_progress,
        "expected at least one TrainingJobProgress event before TrainingJobCompleted"
    );

    // ── Issue #35 regression guard ────────────────────────────────────────────
    // After TrainingJobCompleted, the persisted JobRecord must be retrievable
    // via the job_id from the 202 body (previously always 404 due to UUID mismatch).
    let lookup_resp = auth(
        &client,
        reqwest::Method::GET,
        &format!("{}/api/train/jobs/{}", base, job_id),
    )
    .send()
    .await
    .expect("GET /api/train/jobs/<id> failed");

    assert_eq!(
        lookup_resp.status(),
        200,
        "GET /api/train/jobs/{} expected 200 (issue #35 regression), got: {}",
        job_id,
        lookup_resp.status()
    );

    let record: serde_json::Value = lookup_resp.json().await.unwrap();
    assert_eq!(
        record["id"].as_str(),
        Some(job_id.as_str()),
        "persisted JobRecord id must match the 202 job_id (issue #35): got record={}",
        record
    );

    std::env::set_var("HOME", orig_home);
}
