//! REST API route handlers for the SIGINT web server.
//!
//! All handlers follow the same pattern:
//!  1. Extract `State<AppState>` and path/query params.
//!  2. Call the appropriate `Database` method.
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

use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
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
/// Validates the target, creates a session record, emits a `Status` event so
/// WebSocket clients see the scan start immediately, and returns `201 Created`
/// with `{"session_id": "<uuid>"}`.
///
/// The actual orchestrator spawn is intentionally deferred: wiring in
/// sigint-agents / sigint-llm would add significant dependency weight and
/// is handled in a later phase. The endpoint contract (201 + session_id) is
/// stable regardless.
///
/// @decision DEC-WEB-004
/// @title POST /api/scan creates a session but does not spawn the orchestrator yet
/// @status accepted
/// @rationale Decouples the web contract from the agent wiring. The session
/// record exists immediately so the frontend can poll or subscribe via WS,
/// and the orchestrator spawn can be added later without changing the API.
pub async fn start_scan(
    State(state): State<AppState>,
    Json(body): Json<ScanRequest>,
) -> ApiResult<impl IntoResponse> {
    if body.target.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "target is required".into()));
    }

    let session = sigint_core::types::Session::new(
        &format!("web-scan-{}", body.target.replace(['.', '/'], "-"))
    ).with_target(&body.target);

    state.db.create_session(&session).map_err(internal)?;

    let session_id = session.id;
    let target = body.target.clone();

    // Notify WebSocket subscribers that the scan has started.
    state.event_bus.emit(sigint_core::event::Event::Status(
        format!("Scan started for target: {}", target)
    ));

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "session_id": session_id })),
    ))
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

fn default_format() -> String { "markdown".into() }
fn default_template() -> String { "detailed".into() }

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
        findings: findings.iter().map(|f| sigint_report::FindingSummary {
            title: f.title.clone(),
            severity: f.severity.to_string(),
            description: f.description.clone(),
            asset: f.asset.clone(),
            evidence: f.evidence.clone(),
        }).collect(),
        assets: assets.iter().map(|a| sigint_report::AssetSummary {
            kind: a.kind.to_string(),
            value: a.value.clone(),
            services_count: 0, // service counts not eagerly loaded here
        }).collect(),
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
    Uuid::parse_str(s).map_err(|_| {
        not_found(format!("'{}' is not a valid UUID", s))
    })
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

    use sigint_core::{ApprovalRegistry, Config, event::EventBus};
    use sigint_store::Database;
    use std::time::Duration;

    use crate::create_router;

    fn test_state() -> AppState {
        let db = Database::open_in_memory().expect("in-memory db");
        let event_bus = EventBus::new();
        let config = Arc::new(Config::default());
        let approval_registry = Arc::new(ApprovalRegistry::new(Duration::from_secs(300)));
        AppState { db: Arc::new(db), event_bus, config, approval_registry }
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
            .body(Body::from(r#"{"target":"example.com"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = body_string(resp.into_body()).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(v["session_id"].is_string(), "expected session_id string, got: {}", body);
    }

    #[tokio::test]
    async fn start_scan_missing_target_returns_400() {
        let state = test_state();
        let app = create_router(state);
        let req = Request::builder()
            .method("POST")
            .uri("/api/scan")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"target":""}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
