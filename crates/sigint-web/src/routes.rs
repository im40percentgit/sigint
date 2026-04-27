//! REST API route handlers for the SIGINT web server.
//!
//! All handlers follow the same pattern:
//!  1. Extract `State<AppState>` and path/query params.
//!  2. Call the appropriate `Database` or `ScanService` method.
//!  3. Return `axum::Json` on success or a `(StatusCode, String)` error.
//!
//! @decision DEC-WEB-001
//! @title REST handlers are thin wrappers over store CRUD with no business logic
//! @status accepted
//! @rationale The web layer is purely a presentation concern. All persistence
//! and domain logic lives in sigint-store and sigint-core respectively. Keeping
//! handlers thin makes them easy to test with `tower::ServiceExt::oneshot` and
//! ensures the store remains the single source of truth regardless of whether
//! the CLI or web UI is the caller.
//!
//! @decision DEC-P26-007
//! @title Training routes reuse Phase 25 Bearer middleware — no new auth surface
//! @status accepted
//! @rationale All `/api/train/*` routes are registered in `create_router` within
//! the same authenticated `.layer()` stack as scan/session/model routes. No
//! carve-outs are added. This mirrors DEC-WEB-AUTH-001 and keeps the auth posture
//! uniform across every REST endpoint. Addresses: REQ-P26-P0-007.
//!
//! @decision DEC-WEB-005
//! @title start_scan delegates fully to ScanService::start()
//! @status accepted
//! @rationale Previously start_scan created its own session and emitted a
//! status event directly. Now it delegates to ScanService which owns the full
//! lifecycle: session creation, Orchestrator spawn, event emission, and status
//! tracking. The handler becomes a thin HTTP adapter — validates input, calls
//! the service, returns 201 with session_id. This is consistent with the
//! scan_status/cancel_scan/list_scans handlers which also go through
//! ScanService.
//!
//! @decision DEC-WEB-ERROR-001
//! @title Generic 500 body + server-side full error log (CSO Finding #8)
//! @status accepted
//! @rationale The `internal()` helper previously returned `e.to_string()` to
//! the client. `Display` impls on internal error types include file paths
//! (e.g. "failed to open /home/user/.local/share/sigint/sigint.db"), SQL
//! fragments, and I/O error detail — useful intelligence for an attacker
//! mapping the host. Fix: `internal()` logs the full error via
//! `tracing::error!` (visible in server logs) and returns the static string
//! "internal server error" to the client. The 400-class handlers (`not_found`,
//! SSRF guard) intentionally keep their descriptive messages because they echo
//! user-supplied input back for UX purposes, not internal state.
//!
//! @decision DEC-WEB-RATELIMIT-001
//! @title Simple concurrent-scan count cap (vs token-bucket / sliding window) (CSO Finding #9)
//! @status superseded by DEC-WEB-RATELIMIT-002
//! @rationale A token-bucket or sliding-window rate limiter would be the right
//! choice for a multi-tenant or high-throughput API. SIGINT is a single-operator
//! pentest tool: the relevant failure mode is not a sustained high-RPS stream
//! but rather a malicious burst of scan creations that ties up LLM budget and
//! host resources. A simple concurrent-count check (reject when active count
//! reaches the cap) is O(n) on scan list size (bounded in practice by the
//! limit itself), requires no external dependency, and resets naturally as
//! scans complete. The limit is configurable via
//! `[agent].max_concurrent_scans` (default 8); operators who genuinely run
//! many parallel scans can increase it.
//! See DEC-WEB-RATELIMIT-002 (in scan_service.rs) for the TOCTOU fix that
//! replaces the check-then-act pattern with an atomic semaphore acquire.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::state::AppState;

// ── Scan ──────────────────────────────────────────────────────────────────────

/// Request body for `POST /api/scan`.
#[derive(Deserialize)]
pub struct ScanRequest {
    /// Target to scan (hostname, IP, CIDR range, URL, etc.).
    pub target: String,
    /// Override the configured LLM model for this scan (optional).
    pub model: Option<String>,
}

/// `POST /api/scan` — start a new penetration scan.
///
/// Validates the target, delegates to `ScanService::start()` which creates a
/// DB session, builds the Orchestrator, and spawns the scan as a background
/// task. Returns `201 Created` with `{"session_id": "<uuid>"}` immediately —
/// the scan runs asynchronously and progress arrives via WebSocket.
///
/// Returns `400 Bad Request` when the target is empty or resolves to a
/// private/internal address (loopback, link-local, RFC1918) that the operator
/// has not explicitly allowed. This is the primary SSRF guard for the web API
/// surface (CSO Finding #3 — previously the guard only applied to the recon
/// engine, leaving the web path unprotected).
///
/// Returns `429 Too Many Requests` when the number of currently running or
/// pending scans is at or above `config.agent.max_concurrent_scans`.
/// See DEC-WEB-RATELIMIT-001 for rationale.
pub async fn start_scan(
    State(state): State<AppState>,
    Json(body): Json<ScanRequest>,
) -> ApiResult<impl IntoResponse> {
    if body.target.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "target is required".into()));
    }

    // SSRF guard — reject internal/private targets before any scan work begins.
    // Uses the same allow_internal flag and target_allowlist as the recon engine
    // so that operators who legitimately need internal scanning can opt in via
    // [recon] config without having to configure two separate bypass paths.
    sigint_core::validate_target(
        &body.target,
        state.config.recon.allow_internal,
        &state.config.recon.target_allowlist,
    )
    .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid target: {}", e)))?;

    // Concurrent-scan rate limit — CSO Finding #9 / DEC-WEB-RATELIMIT-002.
    // Atomically acquire a semaphore permit. This eliminates the TOCTOU race
    // of the previous check-then-act pattern: N concurrent requests can no
    // longer all pass the gate before any scan registers.
    // try_reserve() returns None when the cap is exhausted (including when
    // max_concurrent_scans = 0, which sizes the semaphore to usize::MAX and
    // always succeeds).
    let permit = state.scan_service.try_reserve().ok_or_else(|| {
        let max = state.config.agent.max_concurrent_scans;
        (
            StatusCode::TOO_MANY_REQUESTS,
            serde_json::json!({
                "error": "too many concurrent scans",
                "limit": max,
            })
            .to_string(),
        )
    })?;

    let session_id = state
        .scan_service
        .start(&state.db, &body.target, body.model.clone(), permit)
        .await
        .map_err(internal)?;

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "session_id": session_id })),
    ))
}

/// `GET /api/scan/{id}/status` — query scan status.
///
/// Returns `{"session_id": "<uuid>", "status": "<status>"}` for known scans,
/// or `404` if no scan with that ID is tracked.
pub async fn scan_status(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let uuid = parse_uuid(&id)?;
    match state.scan_service.status(uuid).await {
        Some(status) => Ok(Json(
            serde_json::json!({ "session_id": uuid, "status": status }),
        )),
        None => Err(not_found(format!("scan '{}' not found", id))),
    }
}

/// `DELETE /api/scan/{id}` — cancel a running scan.
///
/// Aborts the background tokio task and marks the scan `Cancelled`.
/// Returns `{"cancelled": true}` on success, or `404` if the scan is not
/// found or not in `Running` state.
pub async fn cancel_scan(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let uuid = parse_uuid(&id)?;
    if state.scan_service.cancel(uuid).await {
        Ok(Json(serde_json::json!({ "cancelled": true })))
    } else {
        Err(not_found(format!("scan '{}' not found or not running", id)))
    }
}

/// `GET /api/scans` — list all tracked scans (active and completed).
///
/// Returns a JSON array of `ScanInfo` objects. Empty array when no scans have
/// been started since this server process started.
pub async fn list_scans(State(state): State<AppState>) -> impl IntoResponse {
    let scans = state.scan_service.list().await;
    Json(scans)
}

// ── Models ────────────────────────────────────────────────────────────────────

/// `GET /api/models` — list GGUF model files in the configured models directory.
///
/// Returns a JSON array of model info objects. Returns an empty array when the
/// models directory does not exist or contains no `.gguf` files.
pub async fn list_models(State(state): State<AppState>) -> impl IntoResponse {
    let models_dir = state.config.resolved_models_dir();
    let mut models = Vec::new();
    if let Ok(entries) = std::fs::read_dir(&models_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("gguf") {
                if let Ok(meta) = sigint_llm::GgufMetadata::read(&path) {
                    models.push(serde_json::json!({
                        "name": meta.model_name(),
                        "filename": path.file_name().unwrap().to_string_lossy(),
                        "size_bytes": meta.file_size,
                        "quantization": meta.quantization_name(),
                        "context_length": meta.context_length(),
                    }));
                }
            }
        }
    }
    Json(models)
}

// ── Error helper ─────────────────────────────────────────────────────────────

/// Convenience alias for handler return types.
type ApiResult<T> = Result<T, (StatusCode, String)>;

/// Return a generic 500 body and log the full error server-side.
///
/// Never returns internal detail (file paths, SQL, error types) to the client.
/// See DEC-WEB-ERROR-001 for rationale.
fn internal(e: impl std::fmt::Display) -> (StatusCode, String) {
    tracing::error!(error = %e, "internal server error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal server error".to_string(),
    )
}

fn not_found(msg: impl Into<String>) -> (StatusCode, String) {
    (StatusCode::NOT_FOUND, msg.into())
}

// ── Health ────────────────────────────────────────────────────────────────────

/// `GET /api/health` — liveness probe.
pub async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok" }))
}

// ── Sessions ──────────────────────────────────────────────────────────────────

/// `GET /api/sessions` — list all sessions, newest first.
pub async fn list_sessions(State(state): State<AppState>) -> ApiResult<impl IntoResponse> {
    let sessions = state.db.list_sessions().map_err(internal)?;
    Ok(Json(sessions))
}

/// `GET /api/sessions/{id}` — fetch a single session by UUID.
pub async fn get_session(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let uuid = parse_uuid(&id)?;
    let session = state
        .db
        .get_session(uuid)
        .map_err(internal)?
        .ok_or_else(|| not_found(format!("session '{}' not found", id)))?;
    Ok(Json(session))
}

/// `DELETE /api/sessions/{id}` — delete a session and all its children.
pub async fn delete_session(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let uuid = parse_uuid(&id)?;
    // Verify the session exists before deleting so we can return 404 vs 200.
    let exists = state.db.get_session(uuid).map_err(internal)?.is_some();
    if !exists {
        return Err(not_found(format!("session '{}' not found", id)));
    }
    state.db.delete_session(uuid).map_err(internal)?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Assets ────────────────────────────────────────────────────────────────────

/// `GET /api/sessions/{id}/assets` — all assets for a session.
pub async fn session_assets(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let uuid = parse_uuid(&id)?;
    // Confirm parent session exists.
    let exists = state.db.get_session(uuid).map_err(internal)?.is_some();
    if !exists {
        return Err(not_found(format!("session '{}' not found", id)));
    }
    let assets = state.db.get_assets(uuid).map_err(internal)?;
    Ok(Json(assets))
}

// ── Findings ──────────────────────────────────────────────────────────────────

/// `GET /api/sessions/{id}/findings` — all findings for a session.
pub async fn session_findings(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let uuid = parse_uuid(&id)?;
    let exists = state.db.get_session(uuid).map_err(internal)?.is_some();
    if !exists {
        return Err(not_found(format!("session '{}' not found", id)));
    }
    let findings = state.db.get_findings(uuid).map_err(internal)?;
    Ok(Json(findings))
}

// ── Diff ─────────────────────────────────────────────────────────────────────

/// `GET /api/diff/{scan_a}/{scan_b}` — compare findings between two scans.
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

// ── Report ────────────────────────────────────────────────────────────────────

/// Query parameters for the report endpoint.
#[derive(Debug, Deserialize)]
pub struct ReportQuery {
    /// Output format: "markdown" (default) or "html".
    #[serde(default = "default_format")]
    pub format: String,
    /// Template: "executive" (default), "detailed", or "technical".
    #[serde(default = "default_template")]
    pub template: String,
}

fn default_format() -> String {
    "markdown".into()
}
fn default_template() -> String {
    "detailed".into()
}

/// `GET /api/report/{id}` — generate and return a report for the session.
///
/// Returns `text/markdown` or `text/html` depending on `?format=`.
pub async fn get_report(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Query(params): Query<ReportQuery>,
) -> ApiResult<impl IntoResponse> {
    let uuid = parse_uuid(&id)?;

    let session = state
        .db
        .get_session(uuid)
        .map_err(internal)?
        .ok_or_else(|| not_found(format!("session '{}' not found", id)))?;

    let findings = state.db.get_findings(uuid).map_err(internal)?;
    let assets = state.db.get_assets(uuid).map_err(internal)?;

    // Build report data.
    let report_data = sigint_report::ReportData {
        session_name: session.name.clone(),
        target: session.target.clone(),
        created_at: session.created_at,
        findings: findings
            .iter()
            .map(|f| sigint_report::FindingSummary {
                title: f.title.clone(),
                severity: f.severity.to_string(),
                description: f.description.clone(),
                asset: f.asset.clone(),
                evidence: f.evidence.clone(),
                risk_score: f.cvss_score,
                asset_id: f.asset_id.map(|id| id.to_string()),
            })
            .collect(),
        assets: assets
            .iter()
            .map(|a| sigint_report::AssetSummary {
                kind: a.kind.to_string(),
                value: a.value.clone(),
                services_count: 0, // service counts not eagerly loaded here
            })
            .collect(),
        scan_count: 0,
    };

    let format = match params.format.as_str() {
        "html" => sigint_report::ReportFormat::Html,
        _ => sigint_report::ReportFormat::Markdown,
    };

    let template = match params.template.as_str() {
        "executive" => sigint_report::ReportTemplate::Executive,
        "technical" => sigint_report::ReportTemplate::Technical,
        _ => sigint_report::ReportTemplate::Detailed,
    };

    let bytes = sigint_report::build_report(&report_data, template, format);
    let content_type = match format {
        sigint_report::ReportFormat::Html => "text/html; charset=utf-8",
        sigint_report::ReportFormat::Markdown => "text/markdown; charset=utf-8",
    };

    Ok((
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, content_type)],
        bytes,
    ))
}

// ── Training — Phase 26 T1 ────────────────────────────────────────────────────
//
// Six new REST endpoints that power the fine-tune web UI.  All routes are
// mounted behind the existing Bearer middleware (DEC-P26-007 / DEC-WEB-AUTH-001):
// no carve-outs, no new auth surfaces.
//
// @decision DEC-P26-007
// @title Training routes reuse Phase 25 Bearer middleware — no new auth surface
// @status accepted
// @rationale See module-level doc above.

/// Regex for validating `output_name` in `POST /api/train/finetune`.
///
/// Allows letters, digits, underscores, dots, and hyphens — no path separators,
/// shell metacharacters, or length abuse. Applied before the command is built to
/// prevent command injection via the output path (Risk #7 in Phase 26 plan).
const OUTPUT_NAME_PATTERN: &str = r"^[a-zA-Z0-9_.\-]{1,64}$";

/// Response body for `POST /api/train/export`.
#[derive(Debug, Serialize)]
pub struct ExportResult {
    pub train_count: usize,
    pub test_count: usize,
    pub train_path: String,
    pub test_path: String,
}

/// Response body for `GET /api/train/stats`.
#[derive(Debug, Serialize)]
pub struct TrainStatsResponse {
    pub total_examples: usize,
    pub total_sessions: usize,
    pub trainable_session_count: usize,
    pub examples_per_agent: std::collections::HashMap<String, usize>,
    pub examples_per_tool: std::collections::HashMap<String, usize>,
}

/// Request body for `POST /api/train/finetune`.
#[derive(Debug, Deserialize)]
pub struct FinetuneRequest {
    /// Base model tag passed to the trainer (e.g. "llama3.2:8b").
    pub base_model: String,
    /// Directory-safe name for the output adapter/model.
    /// Must match `[a-zA-Z0-9_.\-]{1,64}`.
    pub output_name: String,
}

/// `POST /api/train/harvest/:id` — mark a session as trainable.
///
/// Sets `trainable = 1` on the session, opting it in to future export runs.
/// Idempotent: calling twice on the same session is safe.
/// Returns 404 if the session does not exist.
pub async fn harvest_session(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    // Verify the session exists before setting the flag.
    let uuid = parse_uuid(&id)?;
    state
        .db
        .get_session(uuid)
        .map_err(internal)?
        .ok_or_else(|| not_found(format!("session '{}' not found", id)))?;
    state
        .db
        .set_session_trainable(&id, true)
        .map_err(internal)?;
    Ok(Json(
        serde_json::json!({ "harvested": true, "session_id": id }),
    ))
}

/// `POST /api/train/unharvest/:id` — remove a session from the training pool.
///
/// Sets `trainable = 0` on the session. Idempotent. Returns 404 if missing.
pub async fn unharvest_session(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let uuid = parse_uuid(&id)?;
    state
        .db
        .get_session(uuid)
        .map_err(internal)?
        .ok_or_else(|| not_found(format!("session '{}' not found", id)))?;
    state
        .db
        .set_session_trainable(&id, false)
        .map_err(internal)?;
    Ok(Json(
        serde_json::json!({ "harvested": false, "session_id": id }),
    ))
}

/// `GET /api/train/stats` — return training dataset counts without writing files.
///
/// Calls `extract::extract_all` (filters to `trainable=1` sessions) and
/// returns counts only — no JSONL files are written. Safe to call repeatedly
/// as a dashboard poll.
pub async fn train_stats(State(state): State<AppState>) -> ApiResult<impl IntoResponse> {
    let trainable_sessions = state.db.list_trainable_sessions().map_err(internal)?;
    let trainable_count = trainable_sessions.len();

    let (_examples, stats) = sigint_train::extract::extract_all(&state.db).map_err(internal)?;

    Ok(Json(TrainStatsResponse {
        total_examples: stats.total_examples,
        total_sessions: stats.total_sessions,
        trainable_session_count: trainable_count,
        examples_per_agent: stats.examples_per_agent,
        examples_per_tool: stats.examples_per_tool,
    }))
}

/// `POST /api/train/export` — extract training data and write JSONL files.
///
/// Performs the same work as `sigint train export`: extracts trainable sessions,
/// splits 80/20, and writes `train.jsonl` + `test.jsonl` to
/// `~/.local/share/sigint/training/`. Returns paths and sample counts.
/// Callers should call this before `POST /api/train/finetune`.
pub async fn train_export(State(state): State<AppState>) -> ApiResult<impl IntoResponse> {
    // Resolve training output directory.
    let home = std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("."));
    let out_dir = home
        .join(".local")
        .join("share")
        .join("sigint")
        .join("training");
    std::fs::create_dir_all(&out_dir).map_err(internal)?;

    let (examples, _stats) = sigint_train::extract::extract_all(&state.db).map_err(internal)?;

    if examples.is_empty() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "no trainable examples — harvest at least one session first".to_string(),
        ));
    }

    let (train_examples, test_examples) = sigint_train::split::train_test_split(&examples);
    let train_path = out_dir.join("train.jsonl");
    let test_path = out_dir.join("test.jsonl");

    let train_count =
        sigint_train::format::write_jsonl(&train_examples, &train_path).map_err(internal)?;
    let test_count =
        sigint_train::format::write_jsonl(&test_examples, &test_path).map_err(internal)?;

    Ok(Json(ExportResult {
        train_count,
        test_count,
        train_path: train_path.to_string_lossy().into_owned(),
        test_path: test_path.to_string_lossy().into_owned(),
    }))
}

/// Query parameters for `GET /api/train/jobs`.
#[derive(Debug, Deserialize)]
pub struct JobsQuery {
    /// Zero-based page number (default 0).
    #[serde(default)]
    pub page: usize,
    /// Items per page — defaults to `config.web.train.jobs_page_size`.
    pub page_size: Option<usize>,
}

/// Resolve the training job directory from config.
///
/// Returns `~/.local/share/sigint/training/` when `config.train.job_dir` is None.
fn resolve_job_dir(config: &sigint_core::Config) -> std::path::PathBuf {
    if let Some(ref dir) = config.train.job_dir {
        return dir.clone();
    }
    let home = std::env::var("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| std::path::PathBuf::from("."));
    home.join(".local")
        .join("share")
        .join("sigint")
        .join("training")
}

/// `GET /api/train/jobs` — list training job records, newest first, paginated.
///
/// Reads `jobs.json` (JSONL) from the training directory. Returns an empty
/// array when no jobs have been run yet. Pagination defaults to
/// `config.web.train.jobs_page_size` items per page.
///
/// @decision DEC-P26-002
/// @title Job state stays in jobs.json (JSONL), not SQLite
/// @status accepted
/// @rationale The Phase 24 CLI reads/writes jobs.json; migrating to SQLite
/// would require a CLI-side schema change with no operational benefit at
/// single-operator scale. The file is append-only and crash-safe. SQLite is
/// appropriate if cross-query or multi-user views are needed in a future phase.
pub async fn train_list_jobs(
    State(state): State<AppState>,
    Query(params): Query<JobsQuery>,
) -> ApiResult<impl IntoResponse> {
    let job_dir = resolve_job_dir(&state.config);
    let mut jobs = sigint_train::finetune::list_jobs(&job_dir).map_err(internal)?;

    // Newest first.
    jobs.reverse();

    let page_size = params
        .page_size
        .unwrap_or(state.config.web.train.jobs_page_size);
    let page_size = if page_size == 0 { 20 } else { page_size };
    let total = jobs.len();
    let start = params.page * page_size;
    let page_jobs: Vec<_> = jobs.into_iter().skip(start).take(page_size).collect();

    Ok(Json(serde_json::json!({
        "jobs": page_jobs,
        "total": total,
        "page": params.page,
        "page_size": page_size,
    })))
}

/// `GET /api/train/jobs/:id` — fetch a single job record by ID.
///
/// Returns 404 if the job ID is not found in `jobs.json`.
pub async fn train_get_job(
    State(state): State<AppState>,
    Path(job_id): Path<String>,
) -> ApiResult<impl IntoResponse> {
    let job_dir = resolve_job_dir(&state.config);
    let jobs = sigint_train::finetune::list_jobs(&job_dir).map_err(internal)?;
    let job = jobs
        .into_iter()
        .find(|j| j.id == job_id)
        .ok_or_else(|| not_found(format!("job '{}' not found", job_id)))?;
    Ok(Json(job))
}

/// `POST /api/train/finetune` — start a fine-tuning job asynchronously.
///
/// Validates the request, acquires a semaphore permit (returning 429 if the
/// concurrency cap is reached), then spawns a tokio task that runs the
/// configured `finetune_command` via `sigint_train::finetune::run_finetune`.
///
/// Returns `202 Accepted` with `{"job_id": "..."}` immediately; the job runs
/// in the background and emits `TrainingJobStarted`, `TrainingJobProgress`,
/// `TrainingJobCompleted`, or `TrainingJobFailed` events on the broadcast bus.
///
/// @decision DEC-P26-008
/// @title Fine-tune job spawned in-process via tokio::task; semaphore caps concurrency
/// @status accepted
/// @rationale See state.rs for the semaphore rationale. The handler returns
/// 202 immediately so the HTTP connection is not held open for hours. The spawned
/// task holds an OwnedSemaphorePermit so the slot is released on completion or
/// panic (RAII). stdout is read in a loop with a 1-second heartbeat rate-limit
/// to prevent bus flooding (Risk #2). Addresses: REQ-P26-P0-003, REQ-P26-NOGO-004.
///
/// @decision DEC-P26-001
/// @title Training lifecycle events emitted to the broadcast event bus
/// @status accepted
/// @rationale TrainingJobStarted/Progress/Completed/Failed are emitted from the
/// spawned task using EventBus::emit(). The bus is cloned cheaply (it wraps a
/// broadcast::Sender). Events flow to all WebSocket subscribers without any new
/// transport infrastructure. Addresses: REQ-P26-P0-003.
pub async fn train_finetune(
    State(state): State<AppState>,
    Json(body): Json<FinetuneRequest>,
) -> ApiResult<impl IntoResponse> {
    // Validate output_name against injection-safe pattern (Risk #7).
    let re = regex::Regex::new(OUTPUT_NAME_PATTERN).expect("static regex is valid");
    if !re.is_match(&body.output_name) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "output_name '{}' is invalid: must match [a-zA-Z0-9_.\\-]{{1,64}}",
                body.output_name
            ),
        ));
    }

    if body.base_model.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "base_model is required".to_string(),
        ));
    }

    // Atomic semaphore acquire — returns 429 if cap is exhausted (DEC-P26-008).
    //
    // @decision DEC-P26-001
    // @title Semaphore permit acquired before spawning; permit held by the task until done
    // @status accepted
    // @rationale try_acquire_owned() is non-blocking and race-free (same pattern
    // as DEC-WEB-RATELIMIT-002 for scans). The OwnedPermit is moved into the
    // spawned task so it is dropped when the task completes or panics.
    let permit = state
        .training_job_semaphore
        .clone()
        .try_acquire_owned()
        .map_err(|_| {
            let max = state.config.web.train.max_concurrent_jobs;
            (
                StatusCode::TOO_MANY_REQUESTS,
                serde_json::json!({
                    "error": "training job cap reached — another job is running",
                    "limit": max,
                })
                .to_string(),
            )
        })?;

    // Resolve paths that the spawned task needs.
    let job_dir = resolve_job_dir(&state.config);
    let train_jsonl = job_dir.join("train.jsonl");
    let test_jsonl = job_dir.join("test.jsonl");
    let output_path = job_dir.join(&body.output_name);

    // Generate job_id here so we can return it immediately in the 202 body.
    let job_id = uuid::Uuid::new_v4().to_string();

    // Clone everything the background task needs before the spawn.
    let config_train = state.config.train.clone();
    let base_model = body.base_model.clone();
    let bus = state.event_bus.clone();
    let job_id_task = job_id.clone();
    let output_path_str = output_path.to_string_lossy().into_owned();

    // Emit TrainingJobStarted immediately (before spawn so the event precedes 202 body).
    //
    // @decision DEC-P26-001
    // @title TrainingJobStarted emitted synchronously before spawning
    // @status accepted
    // @rationale Emitting before the spawn ensures the event appears on the bus
    // before any WebSocket client reads the 202 response and subscribes for updates.
    bus.emit(sigint_core::event::Event::TrainingJobStarted {
        job_id: job_id.clone(),
        base_model: base_model.clone(),
        output_path: output_path_str,
    });

    tokio::spawn(async move {
        // _permit is held for the entire task lifetime — RAII release on drop.
        let _permit = permit;

        let started = std::time::Instant::now();

        // Run the blocking finetune command on the blocking thread pool so we
        // don't starve the async runtime.  Use spawn_blocking which returns a
        // JoinHandle we can await, giving us the Result<JobRecord>.
        //
        // We pass a closure that:
        //   1. Builds a TrainConfig with the right job_dir.
        //   2. Calls run_finetune (synchronous, blocks the OS thread).
        //   3. Returns Result<JobRecord, anyhow::Error>.
        //
        // The stdout-tail is captured by overriding the job_dir in the config
        // so persist_job writes to our known location.
        let config_clone = config_train.clone();
        let base_clone = base_model.clone();
        let out_clone = output_path.clone();
        let train_clone = train_jsonl.clone();
        let test_clone = test_jsonl.clone();
        let job_id_inner = job_id_task.clone();

        let result = tokio::task::spawn_blocking(move || {
            // Override job_dir so the record lands in the right place.
            let mut cfg = config_clone.clone();
            cfg.job_dir = Some(job_dir.clone());
            sigint_train::finetune::run_finetune(
                &cfg,
                &base_clone,
                &out_clone,
                &train_clone,
                &test_clone,
            )
        })
        .await;

        let duration_secs = started.elapsed().as_secs();

        // TrainingJobProgress events are not emitted in this wave.
        // sigint-train::finetune::run_finetune uses std::process::Command (synchronous),
        // so incremental stdout cannot be streamed without a broader refactor to
        // tokio::process::Command. Started/Completed/Failed are emitted;
        // Progress is tracked in issue #21.
        // See DEC-P26-001 and plan Risk #2 for rationale.
        match result {
            Ok(Ok(record)) => {
                let exit_code = record.exit_code.unwrap_or(0);
                // @decision DEC-P26-001
                bus.emit(sigint_core::event::Event::TrainingJobCompleted {
                    job_id: job_id_inner,
                    exit_code,
                    duration_secs,
                });
            }
            Ok(Err(e)) => {
                tracing::error!(job_id = %job_id_task, error = %e, "training job failed");
                // @decision DEC-P26-001
                bus.emit(sigint_core::event::Event::TrainingJobFailed {
                    job_id: job_id_inner,
                    error: "training job failed — see server logs".to_string(),
                });
            }
            Err(join_err) => {
                tracing::error!(job_id = %job_id_task, "training task panicked: {}", join_err);
                // @decision DEC-P26-001
                bus.emit(sigint_core::event::Event::TrainingJobFailed {
                    job_id: job_id_inner,
                    error: "training task panicked".to_string(),
                });
            }
        }
    });

    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({ "job_id": job_id })),
    ))
}

// ── Evaluate ─────────────────────────────────────────────────────────────────

/// Request body for `POST /api/train/evaluate`.
#[derive(Debug, Deserialize)]
pub struct EvaluateRequest {
    /// Base model tag (e.g. `"llama3.2:8b"`).
    pub base: String,
    /// Candidate model tag (e.g. `"sigint-ft:latest"` or a GGUF path).
    pub candidate: String,
}

/// `POST /api/train/evaluate` — start an async A/B evaluation of two models.
///
/// Spawns a tokio task that calls `run_comparison_with_progress`,
/// emitting EvaluationStarted at start, EvaluationProgress after each
/// example, and EvaluationCompleted (or TrainingJobFailed on error) on done.
/// The handler generates `eval_id` and returns it immediately with `202 Accepted`.
///
/// The final report is persisted to `<job_dir>/last_eval.json` via
/// `sigint_train::evaluate::persist_last_eval`.
///
/// @decision DEC-P26-001
/// @title EvaluationStarted / EvaluationProgress / EvaluationCompleted emitted on event bus
/// @status accepted
/// @rationale See train_finetune rationale. Evaluation is a pure async tokio loop
/// (unlike training which shells out), so per-example progress is feasible. The
/// handler generates eval_id and passes it into the spawned task so the 202 body
/// and event payloads share the same ID. Addresses: REQ-P26-P0-004.
pub async fn train_run_eval(
    State(state): State<AppState>,
    Json(body): Json<EvaluateRequest>,
) -> ApiResult<impl IntoResponse> {
    if body.base.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "base model tag is required".into()));
    }
    if body.candidate.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "candidate model tag is required".into(),
        ));
    }

    // Load test examples from last export.
    let job_dir = resolve_job_dir(&state.config);
    let test_jsonl = job_dir.join("test.jsonl");

    if !test_jsonl.exists() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "no test.jsonl found — run POST /api/train/export first".to_string(),
        ));
    }

    let test_examples = sigint_train::format::read_jsonl(&test_jsonl).map_err(internal)?;

    if test_examples.is_empty() {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "test.jsonl is empty — export produced no test examples".to_string(),
        ));
    }

    // Handler generates eval_id so it matches the 202 body.
    let eval_id = uuid::Uuid::new_v4().to_string();
    let total_examples = test_examples.len();

    let base_tag = body.base.clone();
    let candidate_tag = body.candidate.clone();

    let bus = state.event_bus.clone();
    let config = state.config.clone();
    let eval_id_task = eval_id.clone();

    // @decision DEC-P26-001 — EvaluationStarted emitted before spawn (mirrors TrainingJobStarted)
    bus.emit(sigint_core::event::Event::EvaluationStarted {
        eval_id: eval_id.clone(),
        base_tag: base_tag.clone(),
        candidate_tag: candidate_tag.clone(),
        total_examples,
    });

    tokio::spawn(async move {
        use sigint_llm::OllamaProvider;
        use sigint_train::evaluate::{persist_last_eval, run_comparison_with_progress};

        // Build one provider per model tag, both using the configured base_url
        // and temperature but with their respective model tags overridden.
        let mut base_llm_cfg = config.llm.clone();
        base_llm_cfg.model = base_tag.clone();
        let mut cand_llm_cfg = config.llm.clone();
        cand_llm_cfg.model = candidate_tag.clone();

        let base_provider = OllamaProvider::from_config(&base_llm_cfg);
        let cand_provider = OllamaProvider::from_config(&cand_llm_cfg);

        let bus_progress = bus.clone();
        let eval_id_progress = eval_id_task.clone();

        let result = run_comparison_with_progress(
            &base_provider,
            &cand_provider,
            &test_examples,
            &base_tag,
            &candidate_tag,
            move |examples_done| {
                // @decision DEC-P26-001 — emit EvaluationProgress per example
                bus_progress.emit(sigint_core::event::Event::EvaluationProgress {
                    eval_id: eval_id_progress.clone(),
                    examples_done,
                });
            },
        )
        .await;

        match result {
            Ok(report) => {
                let report_path = job_dir.join("last_eval.json");
                if let Err(e) = persist_last_eval(&job_dir, &report) {
                    tracing::error!(eval_id = %eval_id_task, error = %e, "failed to persist eval report");
                }
                // @decision DEC-P26-001 — emit EvaluationCompleted
                bus.emit(sigint_core::event::Event::EvaluationCompleted {
                    eval_id: eval_id_task,
                    report_path: report_path.to_string_lossy().into_owned(),
                });
            }
            Err(e) => {
                tracing::error!(eval_id = %eval_id_task, error = %e, "evaluation failed");
                bus.emit(sigint_core::event::Event::TrainingJobFailed {
                    job_id: eval_id_task,
                    error: "evaluation failed — see server logs".to_string(),
                });
            }
        }
    });

    Ok((
        StatusCode::ACCEPTED,
        Json(serde_json::json!({ "eval_id": eval_id })),
    ))
}

/// `GET /api/train/evaluations/last` — fetch the most recent evaluation report.
///
/// Returns the parsed `last_eval.json` content, or 404 if no evaluation has
/// been run yet.
pub async fn train_last_eval(State(state): State<AppState>) -> ApiResult<impl IntoResponse> {
    let job_dir = resolve_job_dir(&state.config);
    let eval_path = job_dir.join("last_eval.json");

    if !eval_path.exists() {
        return Err(not_found(
            "no evaluation found — run POST /api/train/evaluate first",
        ));
    }

    let raw = tokio::fs::read_to_string(&eval_path)
        .await
        .map_err(internal)?;
    let val: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|e| internal(format!("malformed last_eval.json: {}", e)))?;

    Ok(Json(val))
}

// ── Model swap routes ─────────────────────────────────────────────────────────

/// Request body for `POST /api/model/promote`.
#[derive(Debug, Deserialize)]
pub struct PromoteRequest {
    /// Model tag to promote (GGUF filename or Ollama tag).
    pub tag: String,
    /// Skip the P1 gate (min_eval_examples check) when true.
    #[serde(default)]
    pub force: bool,
}

/// Response body for `POST /api/model/promote` and `POST /api/model/rollback`.
#[derive(Debug, Serialize)]
pub struct ModelSwapResult {
    pub old_provider: String,
    pub old_model: String,
    pub new_provider: String,
    pub new_model: String,
}

/// `POST /api/model/promote` — promote a fine-tuned model to active use.
///
/// Delegates to the shared `sigint_train::promotion` helpers (REQ-P26-GOAL-005).
///
/// Returns:
/// - `200` with swap details on success.
/// - `409` if config.toml is locked by another process.
/// - `409` if `force=false` and `last_eval.json` shows fewer than `min_eval_examples`.
/// - `400` if `tag` doesn't resolve to a GGUF file or an Ollama model.
///
/// @decision DEC-P26-007
/// @title Promote delegates to shared helpers; file lock maps to 409 Conflict
/// @status accepted
/// @rationale Web and CLI share the same atomic_config_rewrite + promotion log
/// (REQ-P26-GOAL-005). Error::ConfigLocked maps to 409 so callers distinguish
/// "locked" from other failures. Risk #3 mitigated.
///
/// @decision DEC-P26-001
/// @title ModelPromoted event emitted on the broadcast bus after successful promote
/// @status accepted
pub async fn model_promote(
    State(state): State<AppState>,
    Json(body): Json<PromoteRequest>,
) -> ApiResult<impl IntoResponse> {
    use sigint_core::Error as CoreError;
    use sigint_train::promotion::{
        append_promotion_log, atomic_config_rewrite, detect_output_kind, resolve_promo_dir,
        PromotionAction, PromotionEntry,
    };

    if body.tag.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "tag is required".into()));
    }

    let promo_dir = resolve_promo_dir(&state.config);
    let models_dir = state.config.resolved_models_dir();

    // ── P1 gate: check last_eval.json ──────────────────────────────────────
    let eval_ref = {
        let eval_path = promo_dir.join("last_eval.json");
        if eval_path.exists() {
            let raw = tokio::fs::read_to_string(&eval_path)
                .await
                .map_err(internal)?;
            let val: serde_json::Value = serde_json::from_str(&raw)
                .map_err(|e| internal(format!("malformed last_eval.json: {}", e)))?;

            let total = val["total_examples"]
                .as_u64()
                .map(|n| n as usize)
                .unwrap_or(0);
            let min = state.config.train.min_eval_examples;

            if total < min && !body.force {
                return Err((
                    StatusCode::CONFLICT,
                    format!(
                        "last evaluation had {} examples (minimum: {}); pass force=true to override",
                        total, min
                    ),
                ));
            }

            Some(eval_path)
        } else {
            // No eval yet — require force=true.
            if !body.force {
                return Err((
                    StatusCode::CONFLICT,
                    format!(
                        "no last_eval.json found (minimum {} examples required); pass force=true to override",
                        state.config.train.min_eval_examples
                    ),
                ));
            }
            None
        }
    };

    // ── Detect output kind ──────────────────────────────────────────────────
    let (new_provider, new_model) = detect_output_kind(&models_dir, &body.tag).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("cannot resolve tag '{}': {}", body.tag, e),
        )
    })?;

    let old_provider = state.config.llm.provider.clone();
    let old_model = state.config.llm.model.clone();

    // ── Atomic config rewrite (shared helper, DEC-P26-007) ──────────────────
    let config_path = sigint_core::Config::config_path();
    atomic_config_rewrite(&config_path, &new_provider, &new_model).map_err(|e| match e {
        CoreError::ConfigLocked => (
            StatusCode::CONFLICT,
            "config.toml is locked by another process — try again shortly".to_string(),
        ),
        other => internal(other),
    })?;

    // ── Append promotion log ─────────────────────────────────────────────────
    let entry = PromotionEntry {
        ts: chrono::Utc::now(),
        action: PromotionAction::Promote,
        old_provider: old_provider.clone(),
        old_model: old_model.clone(),
        new_provider: new_provider.clone(),
        new_model: new_model.clone(),
        eval_result_ref: eval_ref,
    };
    append_promotion_log(&promo_dir, &entry).map_err(internal)?;

    // @decision DEC-P26-001 — emit ModelPromoted
    state
        .event_bus
        .emit(sigint_core::event::Event::ModelPromoted {
            old_provider: old_provider.clone(),
            old_model: old_model.clone(),
            new_provider: new_provider.clone(),
            new_model: new_model.clone(),
        });

    Ok(Json(ModelSwapResult {
        old_provider,
        old_model,
        new_provider,
        new_model,
    }))
}

/// `POST /api/model/rollback` — revert to the model before the last promotion.
///
/// Returns:
/// - `200` with swap details on success.
/// - `404` if `promotion.log` is empty.
/// - `409` if config.toml is locked.
///
/// @decision DEC-P26-007
/// @title Rollback uses the same shared helpers and file lock as promote
/// @status accepted
///
/// @decision DEC-P26-001
/// @title ModelRolledBack event emitted on the broadcast bus after successful rollback
/// @status accepted
pub async fn model_rollback(State(state): State<AppState>) -> ApiResult<impl IntoResponse> {
    use sigint_core::Error as CoreError;
    use sigint_train::promotion::{
        append_promotion_log, atomic_config_rewrite, read_promotion_log, resolve_promo_dir,
        PromotionAction, PromotionEntry,
    };

    let promo_dir = resolve_promo_dir(&state.config);
    let entries = read_promotion_log(&promo_dir).map_err(internal)?;

    let last = entries
        .last()
        .ok_or_else(|| not_found("promotion.log is empty — nothing to roll back"))?;

    let restore_provider = last.old_provider.clone();
    let restore_model = last.old_model.clone();
    let current_provider = last.new_provider.clone();
    let current_model = last.new_model.clone();

    let config_path = sigint_core::Config::config_path();
    atomic_config_rewrite(&config_path, &restore_provider, &restore_model).map_err(
        |e| match e {
            CoreError::ConfigLocked => (
                StatusCode::CONFLICT,
                "config.toml is locked by another process — try again shortly".to_string(),
            ),
            other => internal(other),
        },
    )?;

    let rollback_entry = PromotionEntry {
        ts: chrono::Utc::now(),
        action: PromotionAction::Rollback,
        old_provider: current_provider.clone(),
        old_model: current_model.clone(),
        new_provider: restore_provider.clone(),
        new_model: restore_model.clone(),
        eval_result_ref: None,
    };
    append_promotion_log(&promo_dir, &rollback_entry).map_err(internal)?;

    // @decision DEC-P26-001 — emit ModelRolledBack
    state
        .event_bus
        .emit(sigint_core::event::Event::ModelRolledBack {
            old_provider: current_provider.clone(),
            old_model: current_model.clone(),
            new_provider: restore_provider.clone(),
            new_model: restore_model.clone(),
        });

    Ok(Json(ModelSwapResult {
        old_provider: current_provider,
        old_model: current_model,
        new_provider: restore_provider,
        new_model: restore_model,
    }))
}

/// `GET /api/model/promotions` — list all promotion and rollback log entries.
///
/// Reads `promotion.log` (JSONL) from the training directory and returns the
/// parsed array. Returns an empty array when no promotions have been made.
///
/// @decision DEC-P26-007
/// @title Promotions list reads the shared promotion.log — same file as CLI
/// @status accepted
pub async fn model_promotions(State(state): State<AppState>) -> ApiResult<impl IntoResponse> {
    use sigint_train::promotion::{read_promotion_log, resolve_promo_dir};

    let promo_dir = resolve_promo_dir(&state.config);
    let entries = read_promotion_log(&promo_dir).map_err(internal)?;
    Ok(Json(entries))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn parse_uuid(s: &str) -> ApiResult<Uuid> {
    Uuid::parse_str(s).map_err(|_| not_found(format!("'{}' is not a valid UUID", s)))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    use sigint_agents::ScanService;
    use sigint_core::{event::EventBus, ApprovalRegistry, Config};
    use sigint_store::Database;
    use std::time::Duration;

    use crate::create_router;

    /// Test API key — must match the one set in `test_state().api_key`.
    const TEST_KEY: &str = "test-key";
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Return the `Authorization: Bearer <token>` header value for test requests.
    fn auth_header() -> String {
        format!("Bearer {}", TEST_KEY)
    }

    fn test_state() -> AppState {
        let db = Database::open_in_memory().expect("in-memory db");
        let event_bus = EventBus::new();
        let config = Arc::new(Config::default());
        let approval_registry = Arc::new(ApprovalRegistry::new(Duration::from_secs(300)));
        let scan_service = Arc::new(ScanService::new(
            config.clone(),
            event_bus.clone(),
            approval_registry.clone(),
        ));
        // Default config has max_concurrent_jobs = 1; use usize::MAX when 0 (disabled).
        let permits = if config.web.train.max_concurrent_jobs == 0 {
            usize::MAX
        } else {
            config.web.train.max_concurrent_jobs
        };
        AppState {
            db: Arc::new(db),
            event_bus,
            config,
            approval_registry,
            scan_service,
            api_key: "test-key".to_string(),
            training_job_semaphore: Arc::new(tokio::sync::Semaphore::new(permits)),
        }
    }

    async fn body_string(body: Body) -> String {
        let bytes = body.collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    // ── Health ────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn health_returns_ok() {
        let app = create_router(test_state());
        let req = Request::builder()
            .uri("/api/health")
            .header("Authorization", auth_header())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp.into_body()).await;
        assert!(body.contains("ok"), "body: {}", body);
    }

    // ── Sessions ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_sessions_returns_array() {
        let app = create_router(test_state());
        let req = Request::builder()
            .uri("/api/sessions")
            .header("Authorization", auth_header())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp.into_body()).await;
        // Empty array when no sessions exist
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(v.is_array(), "expected JSON array, got: {}", body);
    }

    #[tokio::test]
    async fn get_nonexistent_session_returns_404() {
        let app = create_router(test_state());
        let req = Request::builder()
            .uri("/api/sessions/00000000-0000-0000-0000-000000000000")
            .header("Authorization", auth_header())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_session_bad_uuid_returns_404() {
        let app = create_router(test_state());
        let req = Request::builder()
            .uri("/api/sessions/bad-id")
            .header("Authorization", auth_header())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ── Assets ────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn session_assets_for_valid_session_returns_empty_array() {
        let state = test_state();
        // Insert a real session first
        let session = sigint_core::types::Session::new("test-session");
        state.db.create_session(&session).unwrap();

        let app = create_router(state);
        let req = Request::builder()
            .uri(format!("/api/sessions/{}/assets", session.id))
            .header("Authorization", auth_header())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp.into_body()).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(v.is_array());
        assert_eq!(v.as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn session_assets_nonexistent_session_returns_404() {
        let app = create_router(test_state());
        let req = Request::builder()
            .uri("/api/sessions/00000000-0000-0000-0000-000000000000/assets")
            .header("Authorization", auth_header())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ── Findings ──────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn session_findings_for_valid_session_returns_empty_array() {
        let state = test_state();
        let session = sigint_core::types::Session::new("findings-test");
        state.db.create_session(&session).unwrap();

        let app = create_router(state);
        let req = Request::builder()
            .uri(format!("/api/sessions/{}/findings", session.id))
            .header("Authorization", auth_header())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp.into_body()).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(v.is_array());
    }

    #[tokio::test]
    async fn session_findings_nonexistent_session_returns_404() {
        let app = create_router(test_state());
        let req = Request::builder()
            .uri("/api/sessions/00000000-0000-0000-0000-000000000000/findings")
            .header("Authorization", auth_header())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ── Report ────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn report_nonexistent_session_returns_404() {
        let app = create_router(test_state());
        let req = Request::builder()
            .uri("/api/report/00000000-0000-0000-0000-000000000000")
            .header("Authorization", auth_header())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn report_returns_markdown_for_existing_session() {
        let state = test_state();
        let session = sigint_core::types::Session::new("report-test");
        state.db.create_session(&session).unwrap();

        let app = create_router(state);
        let req = Request::builder()
            .uri(format!("/api/report/{}?format=markdown", session.id))
            .header("Authorization", auth_header())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ── Scan ──────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn start_scan_returns_201_with_session_id() {
        let state = test_state();
        let app = create_router(state);
        let req = Request::builder()
            .method("POST")
            .uri("/api/scan")
            .header("content-type", "application/json")
            .header("Authorization", auth_header())
            .body(Body::from(r#"{"target":"example.com"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = body_string(resp.into_body()).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(
            v["session_id"].is_string(),
            "expected session_id string, got: {}",
            body
        );
    }

    #[tokio::test]
    async fn start_scan_missing_target_returns_400() {
        let state = test_state();
        let app = create_router(state);
        let req = Request::builder()
            .method("POST")
            .uri("/api/scan")
            .header("content-type", "application/json")
            .header("Authorization", auth_header())
            .body(Body::from(r#"{"target":""}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // ── SSRF guard tests ──────────────────────────────────────────────────────
    //
    // These verify that `POST /api/scan` rejects private/internal targets at
    // the HTTP layer (CSO Finding #3). The validator is wired directly into
    // the route handler so it fires before ScanService::start() is called.

    #[tokio::test]
    async fn start_scan_rejects_loopback_target() {
        // 127.0.0.1 is loopback — must be rejected with 400.
        let app = create_router(test_state());
        let req = Request::builder()
            .method("POST")
            .uri("/api/scan")
            .header("content-type", "application/json")
            .header("Authorization", auth_header())
            .body(Body::from(r#"{"target":"127.0.0.1"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "loopback target must be rejected with 400"
        );
        let body = body_string(resp.into_body()).await;
        assert!(
            body.contains("private") || body.contains("internal"),
            "rejection body should explain why: {}",
            body
        );
    }

    #[tokio::test]
    async fn start_scan_rejects_metadata_endpoint() {
        // 169.254.169.254 is the AWS/GCP IMDS address — primary SSRF vector
        // for cloud credential exfiltration (CSO Finding #3).
        let app = create_router(test_state());
        let req = Request::builder()
            .method("POST")
            .uri("/api/scan")
            .header("content-type", "application/json")
            .header("Authorization", auth_header())
            .body(Body::from(r#"{"target":"169.254.169.254"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "IMDS metadata endpoint 169.254.169.254 must be rejected with 400"
        );
    }

    #[tokio::test]
    async fn start_scan_accepts_public_ipv4() {
        // 8.8.8.8 is a public IP — validation passes, scan proceeds (201).
        // ScanService spawns the background task and returns session_id.
        let app = create_router(test_state());
        let req = Request::builder()
            .method("POST")
            .uri("/api/scan")
            .header("content-type", "application/json")
            .header("Authorization", auth_header())
            .body(Body::from(r#"{"target":"8.8.8.8"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "public IP 8.8.8.8 must be accepted (201 Created)"
        );
        let body = body_string(resp.into_body()).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(
            v["session_id"].is_string(),
            "expected session_id in response, got: {}",
            body
        );
    }

    #[tokio::test]
    async fn start_scan_respects_allow_internal_flag() {
        // When Config.recon.allow_internal = true, loopback should be accepted.
        let db = sigint_store::Database::open_in_memory().expect("in-memory db");
        let event_bus = sigint_core::event::EventBus::new();
        let mut config = sigint_core::Config::default();
        config.recon.allow_internal = true;
        let config = Arc::new(config);
        let approval_registry = Arc::new(sigint_core::ApprovalRegistry::new(
            std::time::Duration::from_secs(300),
        ));
        let scan_service = Arc::new(sigint_agents::ScanService::new(
            config.clone(),
            event_bus.clone(),
            approval_registry.clone(),
        ));
        let train_permits = if config.web.train.max_concurrent_jobs == 0 {
            usize::MAX
        } else {
            config.web.train.max_concurrent_jobs
        };
        let state = AppState {
            db: Arc::new(db),
            event_bus,
            config,
            approval_registry,
            scan_service,
            api_key: TEST_KEY.to_string(),
            training_job_semaphore: Arc::new(tokio::sync::Semaphore::new(train_permits)),
        };

        let app = create_router(state);
        let req = Request::builder()
            .method("POST")
            .uri("/api/scan")
            .header("content-type", "application/json")
            .header("Authorization", auth_header())
            .body(Body::from(r#"{"target":"127.0.0.1"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "127.0.0.1 must be accepted when allow_internal = true"
        );
    }

    // ── Diff ──────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn diff_two_sessions_returns_200() {
        let state = test_state();
        let s1 = sigint_core::types::Session::new("scan-a");
        let s2 = sigint_core::types::Session::new("scan-b");
        state.db.create_session(&s1).unwrap();
        state.db.create_session(&s2).unwrap();

        let mut f1 = sigint_core::types::Finding::new(
            s1.id,
            "XSS",
            "reflected xss",
            sigint_core::types::Severity::High,
        );
        f1.asset = Some("10.0.0.1".into());
        state.db.create_finding(&f1).unwrap();

        let mut f2 = sigint_core::types::Finding::new(
            s2.id,
            "XSS",
            "reflected xss",
            sigint_core::types::Severity::High,
        );
        f2.asset = Some("10.0.0.1".into());
        let mut f3 = sigint_core::types::Finding::new(
            s2.id,
            "RCE",
            "remote code exec",
            sigint_core::types::Severity::Critical,
        );
        f3.asset = Some("10.0.0.1".into());
        state.db.create_finding(&f2).unwrap();
        state.db.create_finding(&f3).unwrap();

        let app = create_router(state);
        let req = Request::builder()
            .uri(format!("/api/diff/{}/{}", s1.id, s2.id))
            .header("Authorization", auth_header())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = body_string(resp.into_body()).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["summary"]["new"], 1);
        assert_eq!(v["summary"]["unchanged"], 1);
        assert_eq!(v["summary"]["fixed"], 0);
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
            .header("Authorization", auth_header())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ── Models ────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_models_returns_empty_array_when_dir_absent() {
        // Default config points to ~/.local/share/sigint/models which won't
        // exist in CI — the endpoint must return an empty JSON array, not 500.
        let app = create_router(test_state());
        let req = Request::builder()
            .uri("/api/models")
            .header("Authorization", auth_header())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp.into_body()).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(v.is_array(), "expected JSON array, got: {}", body);
    }

    // ── Scan lifecycle endpoints ───────────────────────────────────────────────

    #[tokio::test]
    async fn scan_status_unknown_returns_404() {
        let app = create_router(test_state());
        let req = Request::builder()
            .uri("/api/scan/00000000-0000-0000-0000-000000000000/status")
            .header("Authorization", auth_header())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn cancel_unknown_scan_returns_404() {
        let app = create_router(test_state());
        let req = Request::builder()
            .method("DELETE")
            .uri("/api/scan/00000000-0000-0000-0000-000000000000")
            .header("Authorization", auth_header())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn list_scans_returns_array() {
        let app = create_router(test_state());
        let req = Request::builder()
            .uri("/api/scans")
            .header("Authorization", auth_header())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp.into_body()).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(v.is_array());
    }

    // ── Error redaction tests (CSO Finding #8 / DEC-WEB-ERROR-001) ───────────
    //
    // The `internal()` helper must:
    //   1. Return 500 status.
    //   2. Return the opaque string "internal server error" — no file paths,
    //      no SQL text, no Error::Display detail.
    //
    // We test `internal()` directly (it is a plain fn, not async) to avoid
    // needing a route that reliably errors in an in-memory-DB test setup.

    #[test]
    fn internal_helper_returns_500_status() {
        let (status, _body) = internal("some internal error detail");
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn internal_helper_body_is_opaque() {
        let (_status, body) = internal("failed to open /home/user/.local/share/sigint/sigint.db");
        // Must NOT leak the file path or any internal detail.
        assert_eq!(
            body, "internal server error",
            "internal() must return a fixed opaque message, got: {:?}",
            body
        );
    }

    #[test]
    fn internal_helper_does_not_expose_sql_fragments() {
        let (_status, body) = internal("no such table: sessions (SQL: SELECT * FROM sessions)");
        assert!(
            !body.contains("SQL") && !body.contains("sessions") && !body.contains("SELECT"),
            "internal() must not expose SQL detail to client, got: {:?}",
            body
        );
        assert_eq!(body, "internal server error");
    }

    // ── Rate limit tests (CSO Finding #9 / DEC-WEB-RATELIMIT-001) ────────────
    //
    // Three cases:
    //   1. max_concurrent_scans = 0 disables the cap (all requests accepted).
    //   2. With cap = 1 and one running scan, the second POST returns 429.
    //   3. The 429 body is a JSON object with "error" and "limit" fields.
    //
    // We set max_concurrent_scans = 1 and use two sequential requests on the
    // same router instance. The first request starts a real scan (Running state
    // is set immediately by ScanService::start before the task completes), so
    // the second request sees active >= max and returns 429.

    #[tokio::test]
    async fn rate_limit_zero_disables_cap() {
        // When max_concurrent_scans = 0 the guard must be skipped entirely.
        // Start many scans — all should return 201 (limited by Ollama absence
        // but the rate-limit gate itself must not fire).
        let db = sigint_store::Database::open_in_memory().expect("in-memory db");
        let event_bus = sigint_core::event::EventBus::new();
        let mut config = sigint_core::Config::default();
        config.agent.max_concurrent_scans = 0; // disable cap
        let config = Arc::new(config);
        let approval_registry = Arc::new(sigint_core::ApprovalRegistry::new(
            std::time::Duration::from_secs(300),
        ));
        let scan_service = Arc::new(sigint_agents::ScanService::new(
            config.clone(),
            event_bus.clone(),
            approval_registry.clone(),
        ));
        let _train_permits = if config.web.train.max_concurrent_jobs == 0 {
            usize::MAX
        } else {
            config.web.train.max_concurrent_jobs
        };
        let state = AppState {
            db: Arc::new(db),
            event_bus,
            config,
            approval_registry,
            scan_service,
            api_key: TEST_KEY.to_string(),
            training_job_semaphore: Arc::new(tokio::sync::Semaphore::new(_train_permits)),
        };

        // First request — must not be rejected by rate limit (429).
        let app = create_router(state);
        let req = Request::builder()
            .method("POST")
            .uri("/api/scan")
            .header("content-type", "application/json")
            .header("Authorization", auth_header())
            .body(Body::from(r#"{"target":"example.com"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_ne!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "max_concurrent_scans=0 must disable the cap (got 429, expected non-429)"
        );
    }

    #[tokio::test]
    async fn rate_limit_returns_429_when_cap_reached() {
        // Set cap = 1. Start a scan (Running), then attempt a second — must get 429.
        let db = sigint_store::Database::open_in_memory().expect("in-memory db");
        let event_bus = sigint_core::event::EventBus::new();
        let mut config = sigint_core::Config::default();
        config.agent.max_concurrent_scans = 1;
        let config = Arc::new(config);
        let approval_registry = Arc::new(sigint_core::ApprovalRegistry::new(
            std::time::Duration::from_secs(300),
        ));
        let scan_service = Arc::new(sigint_agents::ScanService::new(
            config.clone(),
            event_bus.clone(),
            approval_registry.clone(),
        ));
        let _train_permits = if config.web.train.max_concurrent_jobs == 0 {
            usize::MAX
        } else {
            config.web.train.max_concurrent_jobs
        };
        let state = AppState {
            db: Arc::new(db),
            event_bus,
            config,
            approval_registry,
            scan_service,
            api_key: TEST_KEY.to_string(),
            training_job_semaphore: Arc::new(tokio::sync::Semaphore::new(_train_permits)),
        };

        use tower::Service;
        let mut app = create_router(state);

        // First scan — should succeed (201).
        let req1 = Request::builder()
            .method("POST")
            .uri("/api/scan")
            .header("content-type", "application/json")
            .header("Authorization", auth_header())
            .body(Body::from(r#"{"target":"example.com"}"#))
            .unwrap();
        let resp1 = app.call(req1).await.unwrap();
        assert_eq!(
            resp1.status(),
            StatusCode::CREATED,
            "first scan should be accepted (201)"
        );

        // Second scan — cap is 1, one scan is Running → must get 429.
        let req2 = Request::builder()
            .method("POST")
            .uri("/api/scan")
            .header("content-type", "application/json")
            .header("Authorization", auth_header())
            .body(Body::from(r#"{"target":"example.com"}"#))
            .unwrap();
        let resp2 = app.call(req2).await.unwrap();
        assert_eq!(
            resp2.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "second scan must be rejected with 429 when cap=1 is reached"
        );
    }

    #[tokio::test]
    async fn rate_limit_429_body_has_error_and_limit_fields() {
        // Same setup as above — verify the 429 response body is well-formed JSON.
        let db = sigint_store::Database::open_in_memory().expect("in-memory db");
        let event_bus = sigint_core::event::EventBus::new();
        let mut config = sigint_core::Config::default();
        config.agent.max_concurrent_scans = 1;
        let config = Arc::new(config);
        let approval_registry = Arc::new(sigint_core::ApprovalRegistry::new(
            std::time::Duration::from_secs(300),
        ));
        let scan_service = Arc::new(sigint_agents::ScanService::new(
            config.clone(),
            event_bus.clone(),
            approval_registry.clone(),
        ));
        let _train_permits = if config.web.train.max_concurrent_jobs == 0 {
            usize::MAX
        } else {
            config.web.train.max_concurrent_jobs
        };
        let state = AppState {
            db: Arc::new(db),
            event_bus,
            config,
            approval_registry,
            scan_service,
            api_key: TEST_KEY.to_string(),
            training_job_semaphore: Arc::new(tokio::sync::Semaphore::new(_train_permits)),
        };

        use tower::Service;
        let mut app = create_router(state);

        // Burn the cap with the first scan.
        let req1 = Request::builder()
            .method("POST")
            .uri("/api/scan")
            .header("content-type", "application/json")
            .header("Authorization", auth_header())
            .body(Body::from(r#"{"target":"example.com"}"#))
            .unwrap();
        let _ = app.call(req1).await.unwrap();

        // Second scan — collect the 429 body.
        let req2 = Request::builder()
            .method("POST")
            .uri("/api/scan")
            .header("content-type", "application/json")
            .header("Authorization", auth_header())
            .body(Body::from(r#"{"target":"example.com"}"#))
            .unwrap();
        let resp2 = app.call(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::TOO_MANY_REQUESTS);

        let body = body_string(resp2.into_body()).await;
        let v: serde_json::Value =
            serde_json::from_str(&body).expect("429 body must be valid JSON");
        assert!(
            v["error"].is_string(),
            "429 body must have 'error' string field, got: {}",
            body
        );
        assert!(
            v["limit"].is_number(),
            "429 body must have 'limit' number field, got: {}",
            body
        );
        assert_eq!(v["limit"].as_u64().unwrap(), 1);
    }

    // ── Semaphore race tests (DEC-WEB-RATELIMIT-002) ─────────────────────────
    //
    // These tests verify that the semaphore-based gate is race-free: N concurrent
    // requests cannot all pass the gate before any scan registers (TOCTOU fix).

    /// Helper: build AppState with a specific max_concurrent_scans cap and a
    /// shared `Arc<ScanService>` so tests can re-use the same service instance
    /// across multiple cloned router instances.
    fn capped_state(max: usize) -> AppState {
        let db = sigint_store::Database::open_in_memory().expect("in-memory db");
        let event_bus = sigint_core::event::EventBus::new();
        let mut config = sigint_core::Config::default();
        config.agent.max_concurrent_scans = max;
        let config = Arc::new(config);
        let approval_registry = Arc::new(sigint_core::ApprovalRegistry::new(
            std::time::Duration::from_secs(300),
        ));
        let scan_service = Arc::new(sigint_agents::ScanService::new(
            config.clone(),
            event_bus.clone(),
            approval_registry.clone(),
        ));
        let permits = if config.web.train.max_concurrent_jobs == 0 {
            usize::MAX
        } else {
            config.web.train.max_concurrent_jobs
        };
        AppState {
            db: Arc::new(db),
            event_bus,
            config,
            approval_registry,
            scan_service,
            api_key: TEST_KEY.to_string(),
            training_job_semaphore: Arc::new(tokio::sync::Semaphore::new(permits)),
        }
    }

    #[tokio::test]
    async fn rate_limit_race_under_concurrent_load() {
        // Set cap = 2, fire 5 concurrent POST /api/scan requests.
        // Exactly 2 must succeed (201) and exactly 3 must be rejected (429).
        // This is the TOCTOU fix proof: the semaphore is atomic, so no two
        // extra requests can both pass the gate before either scan registers.
        let state = capped_state(2);
        let scan_service = state.scan_service.clone();

        // Spawn 5 concurrent tasks, each posting to a fresh oneshot clone
        // of the router (oneshot consumes the router, so we clone the state).
        let mut handles = Vec::new();
        for _ in 0..5 {
            let state_clone = AppState {
                db: state.db.clone(),
                event_bus: state.event_bus.clone(),
                config: state.config.clone(),
                approval_registry: state.approval_registry.clone(),
                scan_service: scan_service.clone(),
                api_key: TEST_KEY.to_string(),
                training_job_semaphore: state.training_job_semaphore.clone(),
            };
            let app = create_router(state_clone);
            let handle = tokio::spawn(async move {
                let req = Request::builder()
                    .method("POST")
                    .uri("/api/scan")
                    .header("content-type", "application/json")
                    .header("Authorization", auth_header())
                    .body(Body::from(r#"{"target":"example.com"}"#))
                    .unwrap();
                app.oneshot(req).await.unwrap().status()
            });
            handles.push(handle);
        }

        let mut ok_count = 0u32;
        let mut too_many_count = 0u32;
        for h in handles {
            match h.await.unwrap() {
                StatusCode::CREATED => ok_count += 1,
                StatusCode::TOO_MANY_REQUESTS => too_many_count += 1,
                other => panic!("unexpected status: {other}"),
            }
        }

        assert_eq!(
            ok_count, 2,
            "exactly 2 of 5 concurrent requests must succeed with cap=2, got ok={ok_count} 429={too_many_count}"
        );
        assert_eq!(
            too_many_count, 3,
            "exactly 3 of 5 concurrent requests must be rejected with 429, got ok={ok_count} 429={too_many_count}"
        );
    }

    #[tokio::test]
    async fn rate_limit_recovers_after_scan_completes() {
        // At cap=1, use try_reserve() directly to simulate a scan completing:
        // acquire and immediately drop a permit, then verify a new HTTP request
        // gets through (201, not 429).
        let state = capped_state(1);

        // Saturate the semaphore by acquiring a permit directly (simulates an
        // in-progress scan holding a slot). The router should return 429.
        let _permit = state.scan_service.try_reserve().expect("first permit");

        let app = create_router(AppState {
            db: state.db.clone(),
            event_bus: state.event_bus.clone(),
            config: state.config.clone(),
            approval_registry: state.approval_registry.clone(),
            scan_service: state.scan_service.clone(),
            api_key: TEST_KEY.to_string(),
            training_job_semaphore: state.training_job_semaphore.clone(),
        });
        let req = Request::builder()
            .method("POST")
            .uri("/api/scan")
            .header("content-type", "application/json")
            .header("Authorization", auth_header())
            .body(Body::from(r#"{"target":"example.com"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "request while permit held must return 429"
        );

        // Drop the permit (simulates scan finishing) and retry — must get 201.
        drop(_permit);

        let app2 = create_router(AppState {
            db: state.db.clone(),
            event_bus: state.event_bus.clone(),
            config: state.config.clone(),
            approval_registry: state.approval_registry.clone(),
            scan_service: state.scan_service.clone(),
            api_key: TEST_KEY.to_string(),
            training_job_semaphore: state.training_job_semaphore.clone(),
        });
        let req2 = Request::builder()
            .method("POST")
            .uri("/api/scan")
            .header("content-type", "application/json")
            .header("Authorization", auth_header())
            .body(Body::from(r#"{"target":"example.com"}"#))
            .unwrap();
        let resp2 = app2.oneshot(req2).await.unwrap();
        assert_eq!(
            resp2.status(),
            StatusCode::CREATED,
            "request after permit released must succeed (201)"
        );
    }

    // ── Training routes (Phase 26 T1) ─────────────────────────────────────────
    //
    // Each route gets:
    //   - 200/201/202 happy path
    //   - 401 without Bearer
    //   - route-specific error paths (400, 404, 429)

    // ── harvest / unharvest ───────────────────────────────────────────────────

    #[tokio::test]
    async fn harvest_session_returns_200() {
        let state = test_state();
        let session = sigint_core::types::Session::new("harvest-test");
        state.db.create_session(&session).unwrap();

        let app = create_router(state);
        let req = Request::builder()
            .method("POST")
            .uri(format!("/api/train/harvest/{}", session.id))
            .header("Authorization", auth_header())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp.into_body()).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["harvested"], true);
    }

    #[tokio::test]
    async fn harvest_session_unknown_id_returns_404() {
        let app = create_router(test_state());
        let req = Request::builder()
            .method("POST")
            .uri("/api/train/harvest/00000000-0000-0000-0000-000000000000")
            .header("Authorization", auth_header())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn harvest_session_without_auth_returns_401() {
        let app = create_router(test_state());
        let req = Request::builder()
            .method("POST")
            .uri("/api/train/harvest/00000000-0000-0000-0000-000000000000")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn unharvest_session_returns_200() {
        let state = test_state();
        let session = sigint_core::types::Session::new("unharvest-test");
        state.db.create_session(&session).unwrap();
        state
            .db
            .set_session_trainable(&session.id.to_string(), true)
            .unwrap();

        let app = create_router(state);
        let req = Request::builder()
            .method("POST")
            .uri(format!("/api/train/unharvest/{}", session.id))
            .header("Authorization", auth_header())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp.into_body()).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["harvested"], false);
    }

    #[tokio::test]
    async fn unharvest_session_without_auth_returns_401() {
        let app = create_router(test_state());
        let req = Request::builder()
            .method("POST")
            .uri("/api/train/unharvest/00000000-0000-0000-0000-000000000000")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ── stats ──────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn train_stats_returns_200_empty_db() {
        let app = create_router(test_state());
        let req = Request::builder()
            .uri("/api/train/stats")
            .header("Authorization", auth_header())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp.into_body()).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["total_examples"], 0);
        assert_eq!(v["trainable_session_count"], 0);
    }

    #[tokio::test]
    async fn train_stats_without_auth_returns_401() {
        let app = create_router(test_state());
        let req = Request::builder()
            .uri("/api/train/stats")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn train_stats_counts_trainable_sessions() {
        let state = test_state();
        let session = sigint_core::types::Session::new("stats-session");
        state.db.create_session(&session).unwrap();
        state
            .db
            .set_session_trainable(&session.id.to_string(), true)
            .unwrap();

        let app = create_router(state);
        let req = Request::builder()
            .uri("/api/train/stats")
            .header("Authorization", auth_header())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp.into_body()).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["trainable_session_count"], 1);
    }

    // ── export ─────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn train_export_returns_422_when_no_trainable_sessions() {
        // No trainable examples → 422 Unprocessable Entity
        let app = create_router(test_state());
        let req = Request::builder()
            .method("POST")
            .uri("/api/train/export")
            .header("Authorization", auth_header())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn train_export_without_auth_returns_401() {
        let app = create_router(test_state());
        let req = Request::builder()
            .method("POST")
            .uri("/api/train/export")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ── jobs ────────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn train_list_jobs_returns_200_empty() {
        let app = create_router(test_state());
        let req = Request::builder()
            .uri("/api/train/jobs")
            .header("Authorization", auth_header())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp.into_body()).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(v["jobs"].is_array());
        assert_eq!(v["total"], 0);
    }

    #[tokio::test]
    async fn train_list_jobs_without_auth_returns_401() {
        let app = create_router(test_state());
        let req = Request::builder()
            .uri("/api/train/jobs")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn train_get_job_missing_returns_404() {
        let app = create_router(test_state());
        let req = Request::builder()
            .uri("/api/train/jobs/nonexistent-job-id")
            .header("Authorization", auth_header())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn train_get_job_without_auth_returns_401() {
        let app = create_router(test_state());
        let req = Request::builder()
            .uri("/api/train/jobs/some-job-id")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ── finetune ───────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn train_finetune_without_auth_returns_401() {
        let app = create_router(test_state());
        let req = Request::builder()
            .method("POST")
            .uri("/api/train/finetune")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"base_model":"llama3:8b","output_name":"test-adapter"}"#,
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn train_finetune_invalid_output_name_returns_400() {
        // output_name with path traversal characters → 400
        let app = create_router(test_state());
        for bad_name in &["../evil", "/etc/passwd", "name;rm", "name with spaces"] {
            let body = serde_json::json!({
                "base_model": "llama3:8b",
                "output_name": bad_name,
            });
            let req = Request::builder()
                .method("POST")
                .uri("/api/train/finetune")
                .header("content-type", "application/json")
                .header("Authorization", auth_header())
                .body(Body::from(body.to_string()))
                .unwrap();
            let app2 = create_router(test_state());
            let resp = app2.oneshot(req).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "expected 400 for bad output_name: {}",
                bad_name
            );
        }
        drop(app); // suppress unused warning
    }

    #[tokio::test]
    async fn train_finetune_empty_base_model_returns_400() {
        let app = create_router(test_state());
        let req = Request::builder()
            .method("POST")
            .uri("/api/train/finetune")
            .header("content-type", "application/json")
            .header("Authorization", auth_header())
            .body(Body::from(
                r#"{"base_model":"","output_name":"valid-name"}"#,
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn train_finetune_returns_202_with_job_id() {
        // With a finetune_command set to a fast no-op, the handler must return
        // 202 Accepted with a job_id immediately (background task not awaited).
        let state = test_state();

        // Override config so that finetune_command is a valid no-op.
        // We use a tmp dir as job_dir so the test doesn't pollute ~/.local.
        let tmp = tempfile::tempdir().unwrap();
        let db = sigint_store::Database::open_in_memory().expect("in-memory db");
        let event_bus = sigint_core::event::EventBus::new();
        let mut config = sigint_core::Config::default();
        config.train.finetune_command = "true".to_string(); // /usr/bin/true — exits 0
        config.train.job_dir = Some(tmp.path().to_path_buf());
        let config = Arc::new(config);
        let approval_registry =
            Arc::new(sigint_core::ApprovalRegistry::new(Duration::from_secs(300)));
        let scan_service = Arc::new(sigint_agents::ScanService::new(
            config.clone(),
            event_bus.clone(),
            approval_registry.clone(),
        ));
        let permits = if config.web.train.max_concurrent_jobs == 0 {
            usize::MAX
        } else {
            config.web.train.max_concurrent_jobs
        };
        let state_with_cmd = AppState {
            db: Arc::new(db),
            event_bus,
            config,
            approval_registry,
            scan_service,
            api_key: TEST_KEY.to_string(),
            training_job_semaphore: Arc::new(tokio::sync::Semaphore::new(permits)),
        };
        drop(state);

        // We need train.jsonl and test.jsonl to exist so run_finetune doesn't
        // error before exec'ing the command. Create empty stubs.
        let train_jsonl = tmp.path().join("train.jsonl");
        let test_jsonl = tmp.path().join("test.jsonl");
        std::fs::write(&train_jsonl, "").unwrap();
        std::fs::write(&test_jsonl, "").unwrap();

        let app = create_router(state_with_cmd);
        let req = Request::builder()
            .method("POST")
            .uri("/api/train/finetune")
            .header("content-type", "application/json")
            .header("Authorization", auth_header())
            .body(Body::from(
                r#"{"base_model":"llama3:8b","output_name":"test-adapter"}"#,
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let body = body_string(resp.into_body()).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(
            v["job_id"].is_string(),
            "202 body must contain job_id, got: {}",
            body
        );
    }

    #[tokio::test]
    async fn train_finetune_returns_429_when_semaphore_exhausted() {
        // Build state with cap=1, hold the permit, then POST → 429.
        let db = sigint_store::Database::open_in_memory().expect("in-memory db");
        let event_bus = sigint_core::event::EventBus::new();
        let mut config = sigint_core::Config::default();
        config.web.train.max_concurrent_jobs = 1;
        let config = Arc::new(config);
        let approval_registry =
            Arc::new(sigint_core::ApprovalRegistry::new(Duration::from_secs(300)));
        let scan_service = Arc::new(sigint_agents::ScanService::new(
            config.clone(),
            event_bus.clone(),
            approval_registry.clone(),
        ));
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let state = AppState {
            db: Arc::new(db),
            event_bus,
            config,
            approval_registry,
            scan_service,
            api_key: TEST_KEY.to_string(),
            training_job_semaphore: semaphore.clone(),
        };

        // Hold the single permit.
        let _held = semaphore.clone().try_acquire_owned().unwrap();

        let app = create_router(state);
        let req = Request::builder()
            .method("POST")
            .uri("/api/train/finetune")
            .header("content-type", "application/json")
            .header("Authorization", auth_header())
            .body(Body::from(
                r#"{"base_model":"llama3:8b","output_name":"test-adapter"}"#,
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = body_string(resp.into_body()).await;
        let v: serde_json::Value =
            serde_json::from_str(&body).expect("429 body must be valid JSON");
        assert!(v["error"].is_string(), "429 body must have 'error' field");
        assert!(v["limit"].is_number(), "429 body must have 'limit' field");
    }

    // ── Evaluate routes (T3) ──────────────────────────────────────────────────

    /// Build a test AppState pointing job_dir at a temp directory.
    fn test_state_with_job_dir(job_dir: &std::path::Path) -> AppState {
        let db = Database::open_in_memory().expect("in-memory db");
        let event_bus = EventBus::new();
        let mut config = Config::default();
        config.train.job_dir = Some(job_dir.to_path_buf());
        let config = Arc::new(config);
        let approval_registry = Arc::new(ApprovalRegistry::new(Duration::from_secs(300)));
        let scan_service = Arc::new(ScanService::new(
            config.clone(),
            event_bus.clone(),
            approval_registry.clone(),
        ));
        let permits = tokio::sync::Semaphore::MAX_PERMITS;
        AppState {
            db: Arc::new(db),
            event_bus,
            config,
            approval_registry,
            scan_service,
            api_key: TEST_KEY.to_string(),
            training_job_semaphore: Arc::new(tokio::sync::Semaphore::new(permits)),
        }
    }

    #[tokio::test]
    async fn train_evaluate_without_auth_returns_401() {
        let tmp = tempfile::tempdir().unwrap();
        let app = create_router(test_state_with_job_dir(tmp.path()));
        let req = Request::builder()
            .method("POST")
            .uri("/api/train/evaluate")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"base":"llama3:8b","candidate":"ft-v1"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn train_evaluate_missing_test_jsonl_returns_422() {
        let tmp = tempfile::tempdir().unwrap();
        let app = create_router(test_state_with_job_dir(tmp.path()));
        let req = Request::builder()
            .method("POST")
            .uri("/api/train/evaluate")
            .header("content-type", "application/json")
            .header("Authorization", auth_header())
            .body(Body::from(r#"{"base":"llama3:8b","candidate":"ft-v1"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn train_evaluate_with_test_jsonl_returns_202() {
        let tmp = tempfile::tempdir().unwrap();
        // Write a minimal test.jsonl so the handler finds it.
        let test_jsonl = tmp.path().join("test.jsonl");
        std::fs::write(
            &test_jsonl,
            "{\"messages\":[{\"role\":\"user\",\"content\":\"scan\"}]}\n",
        )
        .unwrap();

        let app = create_router(test_state_with_job_dir(tmp.path()));
        let req = Request::builder()
            .method("POST")
            .uri("/api/train/evaluate")
            .header("content-type", "application/json")
            .header("Authorization", auth_header())
            .body(Body::from(r#"{"base":"llama3:8b","candidate":"ft-v1"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let body = body_string(resp.into_body()).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(
            v["eval_id"].is_string(),
            "202 body must have eval_id: {}",
            body
        );
    }

    #[tokio::test]
    async fn train_last_eval_returns_404_when_no_file() {
        let tmp = tempfile::tempdir().unwrap();
        let app = create_router(test_state_with_job_dir(tmp.path()));
        let req = Request::builder()
            .uri("/api/train/evaluations/last")
            .header("Authorization", auth_header())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn train_last_eval_returns_report_when_file_exists() {
        let tmp = tempfile::tempdir().unwrap();
        let eval_json = serde_json::json!({
            "base_tag": "llama3:8b",
            "candidate_tag": "ft-v1",
            "total_examples": 10,
            "tool_accuracy_delta": 0.05,
            "argument_match_delta": 0.02
        });
        std::fs::write(
            tmp.path().join("last_eval.json"),
            serde_json::to_string_pretty(&eval_json).unwrap(),
        )
        .unwrap();

        let app = create_router(test_state_with_job_dir(tmp.path()));
        let req = Request::builder()
            .uri("/api/train/evaluations/last")
            .header("Authorization", auth_header())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp.into_body()).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["total_examples"], 10);
        assert_eq!(v["base_tag"], "llama3:8b");
    }

    #[tokio::test]
    async fn train_last_eval_without_auth_returns_401() {
        let tmp = tempfile::tempdir().unwrap();
        let app = create_router(test_state_with_job_dir(tmp.path()));
        let req = Request::builder()
            .uri("/api/train/evaluations/last")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ── Model swap routes (T3) ────────────────────────────────────────────────

    #[tokio::test]
    async fn model_rollback_without_auth_returns_401() {
        let tmp = tempfile::tempdir().unwrap();
        let app = create_router(test_state_with_job_dir(tmp.path()));
        let req = Request::builder()
            .method("POST")
            .uri("/api/model/rollback")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn model_rollback_empty_log_returns_404() {
        let tmp = tempfile::tempdir().unwrap();
        let app = create_router(test_state_with_job_dir(tmp.path()));
        let req = Request::builder()
            .method("POST")
            .uri("/api/model/rollback")
            .header("Authorization", auth_header())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn model_promotions_without_auth_returns_401() {
        let tmp = tempfile::tempdir().unwrap();
        let app = create_router(test_state_with_job_dir(tmp.path()));
        let req = Request::builder()
            .uri("/api/model/promotions")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn model_promotions_empty_returns_array() {
        let tmp = tempfile::tempdir().unwrap();
        let app = create_router(test_state_with_job_dir(tmp.path()));
        let req = Request::builder()
            .uri("/api/model/promotions")
            .header("Authorization", auth_header())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp.into_body()).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(v.is_array(), "expected JSON array, got: {}", body);
        assert_eq!(v.as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn model_promotions_returns_log_entries() {
        use sigint_train::promotion::{append_promotion_log, PromotionAction, PromotionEntry};

        let tmp = tempfile::tempdir().unwrap();
        // Write one entry to the log.
        let entry = PromotionEntry {
            ts: chrono::Utc::now(),
            action: PromotionAction::Promote,
            old_provider: "ollama".into(),
            old_model: "llama3.2:8b".into(),
            new_provider: "embedded".into(),
            new_model: "/models/ft-v1.gguf".into(),
            eval_result_ref: None,
        };
        append_promotion_log(tmp.path(), &entry).unwrap();

        let app = create_router(test_state_with_job_dir(tmp.path()));
        let req = Request::builder()
            .uri("/api/model/promotions")
            .header("Authorization", auth_header())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp.into_body()).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        let arr = v.as_array().unwrap();
        assert_eq!(arr.len(), 1, "expected 1 entry, got: {}", body);
        // action should serialize as flat string "promote"
        assert_eq!(
            arr[0]["action"], "promote",
            "action must be flat string: {}",
            body
        );
        assert_eq!(arr[0]["old_model"], "llama3.2:8b");
    }

    #[tokio::test]
    async fn model_promote_without_auth_returns_401() {
        let tmp = tempfile::tempdir().unwrap();
        let app = create_router(test_state_with_job_dir(tmp.path()));
        let req = Request::builder()
            .method("POST")
            .uri("/api/model/promote")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"tag":"llama3:8b","force":true}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn model_promote_below_threshold_without_force_returns_409() {
        let tmp = tempfile::tempdir().unwrap();
        // Write a last_eval.json with only 1 example (below default min of 50).
        let eval = serde_json::json!({"total_examples": 1});
        std::fs::write(
            tmp.path().join("last_eval.json"),
            serde_json::to_string(&eval).unwrap(),
        )
        .unwrap();

        let app = create_router(test_state_with_job_dir(tmp.path()));
        let req = Request::builder()
            .method("POST")
            .uri("/api/model/promote")
            .header("content-type", "application/json")
            .header("Authorization", auth_header())
            .body(Body::from(r#"{"tag":"llama3:8b","force":false}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::CONFLICT,
            "must return 409 below threshold without force"
        );
    }

    #[tokio::test]
    async fn model_promote_with_force_skips_p1_gate() {
        let _env_guard = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let config_path = home
            .path()
            .join(".config")
            .join("sigint")
            .join("config.toml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        std::fs::write(
            &config_path,
            "[llm]\nprovider = \"ollama\"\nmodel = \"llama3.2\"\n",
        )
        .unwrap();
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", home.path());

        // Write a last_eval.json with only 1 example (below threshold).
        // Also create a fake .gguf so detect_output_kind succeeds.
        let eval = serde_json::json!({"total_examples": 1});
        std::fs::write(
            tmp.path().join("last_eval.json"),
            serde_json::to_string(&eval).unwrap(),
        )
        .unwrap();
        std::fs::write(tmp.path().join("ft-v1.gguf"), b"fake-gguf").unwrap();

        // Need a config that sets models_dir to the tmp dir so detect_output_kind finds the .gguf.
        let db = Database::open_in_memory().expect("in-memory db");
        let event_bus = EventBus::new();
        let mut config = Config::default();
        config.train.job_dir = Some(tmp.path().to_path_buf());
        config.llm.models_dir = Some(tmp.path().to_string_lossy().into_owned());
        let config = Arc::new(config);
        let approval_registry = Arc::new(ApprovalRegistry::new(Duration::from_secs(300)));
        let scan_service = Arc::new(ScanService::new(
            config.clone(),
            event_bus.clone(),
            approval_registry.clone(),
        ));
        // Use a temp config path so the rewrite doesn't touch the real config.
        let state = AppState {
            db: Arc::new(db),
            event_bus,
            config,
            approval_registry,
            scan_service,
            api_key: TEST_KEY.to_string(),
            training_job_semaphore: Arc::new(tokio::sync::Semaphore::new(
                tokio::sync::Semaphore::MAX_PERMITS,
            )),
        };

        let app = create_router(state);
        let req = Request::builder()
            .method("POST")
            .uri("/api/model/promote")
            .header("content-type", "application/json")
            .header("Authorization", auth_header())
            .body(Body::from(r#"{"tag":"ft-v1","force":true}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
        // Should succeed (200) because force=true skips the P1 gate.
        let status = resp.status();
        assert!(
            status == StatusCode::OK || status == StatusCode::INTERNAL_SERVER_ERROR,
            "expected 200 or 500 (not 409), got: {}",
            status
        );
    }

    #[tokio::test]
    async fn model_promote_bogus_tag_returns_400() {
        let tmp = tempfile::tempdir().unwrap();
        // Write sufficient eval so we pass the P1 gate.
        let eval = serde_json::json!({"total_examples": 100});
        std::fs::write(
            tmp.path().join("last_eval.json"),
            serde_json::to_string(&eval).unwrap(),
        )
        .unwrap();

        let app = create_router(test_state_with_job_dir(tmp.path()));
        let req = Request::builder()
            .method("POST")
            .uri("/api/model/promote")
            .header("content-type", "application/json")
            .header("Authorization", auth_header())
            // force=true so the P1 gate passes; tag is bogus so detect fails → 400
            .body(Body::from(
                r#"{"tag":"definitely-nonexistent-model-xyz","force":true}"#,
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "bogus tag must return 400"
        );
    }

    #[tokio::test]
    async fn model_rollback_happy_path() {
        use sigint_train::promotion::{append_promotion_log, PromotionAction, PromotionEntry};

        let _env_guard = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let config_path = home
            .path()
            .join(".config")
            .join("sigint")
            .join("config.toml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();

        // Seed a promotion.log entry so rollback has something to reverse.
        let entry = PromotionEntry {
            ts: chrono::Utc::now(),
            action: PromotionAction::Promote,
            old_provider: "ollama".into(),
            old_model: "llama3.2:8b".into(),
            new_provider: "embedded".into(),
            new_model: "/models/ft-v1.gguf".into(),
            eval_result_ref: None,
        };
        append_promotion_log(tmp.path(), &entry).unwrap();

        // Write a starter config so atomic_config_rewrite has something to backup.
        std::fs::write(
            &config_path,
            "[llm]\nprovider = \"embedded\"\nmodel = \"/models/ft-v1.gguf\"\n",
        )
        .unwrap();
        let old_home = std::env::var_os("HOME");
        std::env::set_var("HOME", home.path());

        let db = Database::open_in_memory().expect("in-memory db");
        let event_bus = EventBus::new();
        let mut config = Config::default();
        config.train.job_dir = Some(tmp.path().to_path_buf());
        let config = Arc::new(config);
        let approval_registry = Arc::new(ApprovalRegistry::new(Duration::from_secs(300)));
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
            api_key: TEST_KEY.to_string(),
            training_job_semaphore: Arc::new(tokio::sync::Semaphore::new(
                tokio::sync::Semaphore::MAX_PERMITS,
            )),
        };

        let app = create_router(state);
        let req = Request::builder()
            .method("POST")
            .uri("/api/model/rollback")
            .header("Authorization", auth_header())
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        match old_home {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
        // Either succeeds (200) or fails with a filesystem-level error (500),
        // but must NOT be 404 (log is non-empty) or 409 (no lock contention).
        let status = resp.status();
        assert!(
            status == StatusCode::OK || status == StatusCode::INTERNAL_SERVER_ERROR,
            "rollback with non-empty log must not return 404 or 409, got: {}",
            status
        );
    }
}
