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

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
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
pub async fn start_scan(
    State(state): State<AppState>,
    Json(body): Json<ScanRequest>,
) -> ApiResult<impl IntoResponse> {
    if body.target.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "target is required".into()));
    }

    let session_id = state
        .scan_service
        .start(&state.db, &body.target, body.model.clone())
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

fn internal(e: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
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
        AppState {
            db: Arc::new(db),
            event_bus,
            config,
            approval_registry,
            scan_service,
            api_key: "test-key".to_string(),
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
}
