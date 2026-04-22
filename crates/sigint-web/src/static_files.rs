//! Static file serving for the embedded SPA frontend.
//!
//! Embeds the contents of `static/` at compile time using `rust-embed`. In
//! production the binary is self-contained — no external file system access
//! is required to serve the frontend.
//!
//! # Route behaviour
//!
//! The handler is registered as an Axum fallback so all requests not matched
//! by `/api/*` or `/ws/*` routes land here:
//!
//! | Request path | Behaviour |
//! |---|---|
//! | `/` or `/` (empty) | Serves `index.html` |
//! | `/assets/app.js` | Serves bundled JS with `application/javascript` |
//! | `/assets/app.css` | Serves bundled CSS with `text/css` |
//! | `/sessions/abc` | Serves `index.html` (SPA client-side routing) |
//! | Unknown file path | Serves `index.html` (SPA fallback) |
//!
//! @decision DEC-WEB-010
//! @title rust-embed for compile-time asset embedding with mime_guess content-types
//! @status accepted
//! @rationale Embedding static assets at compile time produces a single
//! self-contained binary — ideal for a pentest tool that may be deployed to
//! air-gapped or ephemeral environments. mime_guess infers content-type from
//! file extension, avoiding a hard-coded MIME table. The SPA fallback (serve
//! index.html for unknown paths) enables hash-free client-side routing if
//! needed in future without server configuration changes.

use axum::http::{header, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use rust_embed::Embed;

/// Compile-time embedded static assets from `static/`.
///
/// The folder path is relative to this crate's `Cargo.toml`, so it resolves to
/// `crates/sigint-web/static/`. The directory must be populated before
/// `cargo build` runs (the npm build step populates it).
#[derive(Embed)]
#[folder = "static/"]
struct StaticAssets;

/// Axum fallback handler — serves embedded static files or SPA `index.html`.
///
/// Strips the leading `/` from the URI path. If the path is empty or contains
/// no `.` (i.e. looks like a SPA route rather than a file), serves
/// `index.html`. Otherwise attempts to serve the named file and falls back to
/// `index.html` if not found.
pub async fn serve_static(uri: Uri) -> Response {
    let raw = uri.path().trim_start_matches('/');

    // Determine which file to look up: SPA routes (no dot) → index.html
    let path = if raw.is_empty() || !raw.contains('.') {
        "index.html"
    } else {
        raw
    };

    match StaticAssets::get(path) {
        Some(file) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, mime.as_ref().to_string())],
                file.data.to_vec(),
            )
                .into_response()
        }
        None => {
            // SPA fallback — serve index.html for unknown file paths too
            match StaticAssets::get("index.html") {
                Some(file) => (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "text/html; charset=utf-8".to_string())],
                    file.data.to_vec(),
                )
                    .into_response(),
                None => (StatusCode::NOT_FOUND, "Not Found").into_response(),
            }
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    use sigint_agents::ScanService;
    use sigint_core::{event::EventBus, ApprovalRegistry, Config};
    use sigint_store::Database;
    use std::time::Duration;

    use crate::{create_router, AppState};

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

    async fn body_bytes(body: Body) -> Vec<u8> {
        body.collect().await.unwrap().to_bytes().to_vec()
    }

    async fn body_string(body: Body) -> String {
        String::from_utf8(body_bytes(body).await).unwrap()
    }

    // ── Static file serving ────────────────────────────────────────────────────

    #[tokio::test]
    async fn serves_index_html_at_root() {
        let app = create_router(test_state());
        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(ct.contains("text/html"), "expected text/html, got: {ct}");
        let body = body_string(resp.into_body()).await;
        assert!(
            body.contains("<div id=\"app\">"),
            "body did not contain SPA mount point"
        );
    }

    #[tokio::test]
    async fn serves_js_bundle() {
        let app = create_router(test_state());
        let req = Request::builder()
            .uri("/assets/app.js")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            ct.contains("javascript"),
            "expected JS content-type, got: {ct}"
        );
        let bytes = body_bytes(resp.into_body()).await;
        assert!(!bytes.is_empty(), "JS bundle should not be empty");
    }

    #[tokio::test]
    async fn serves_css_bundle() {
        let app = create_router(test_state());
        let req = Request::builder()
            .uri("/assets/app.css")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(ct.contains("css"), "expected CSS content-type, got: {ct}");
    }

    #[tokio::test]
    async fn spa_fallback_for_unknown_routes() {
        let app = create_router(test_state());
        // A SPA route that doesn't correspond to a file — should get index.html
        let req = Request::builder()
            .uri("/sessions/some-fake-session-id")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let ct = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(
            ct.contains("text/html"),
            "SPA fallback should return HTML, got: {ct}"
        );
    }

    #[tokio::test]
    async fn api_routes_not_caught_by_fallback() {
        let app = create_router(test_state());
        // /api/health must still return JSON, not index.html
        let req = Request::builder()
            .uri("/api/health")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_string(resp.into_body()).await;
        assert!(
            body.contains("ok"),
            "health endpoint should return JSON status:ok, got: {body}"
        );
        // Must NOT be an HTML page
        assert!(
            !body.contains("<html"),
            "health should return JSON, not HTML"
        );
    }
}
