//! Web/HTTP probing module — fingerprints tech stack via curl HEAD requests.
//!
//! @decision DEC-RECON-003
//! @title Web module uses curl -sI (HEAD) via sandbox for HTTP fingerprinting
//! @status accepted
//! @rationale curl HEAD requests capture response headers (Server,
//! X-Powered-By, Content-Type) without downloading the body. This gives
//! tech fingerprinting data cheaply. We probe both HTTP and HTTPS variants
//! to maximize coverage. Using curl via the sandbox provides network
//! isolation without requiring a separate HTTP library at this layer.

use async_trait::async_trait;
use sigint_core::types::{Asset, AssetKind};
use sigint_sandbox::profile::SandboxProfile;
use tracing::info;
use uuid::Uuid;

use crate::error::ReconError;
use crate::module::DiscoveryModule;

/// Holds parsed HTTP header information from a curl HEAD response.
#[derive(Debug, PartialEq, Default)]
pub(crate) struct ParsedHttpHeaders {
    pub status_code: Option<u16>,
    pub server: Option<String>,
    pub x_powered_by: Option<String>,
    pub content_type: Option<String>,
}

/// Probes HTTP/HTTPS endpoints via sandboxed curl and fingerprints technology.
pub struct WebModule;

impl WebModule {
    /// Parse `curl -sI` output into structured header data.
    ///
    /// The first line is the HTTP status line; subsequent lines are `Header: value`.
    pub(crate) fn parse_curl_headers(output: &str) -> ParsedHttpHeaders {
        let mut result = ParsedHttpHeaders::default();

        for (i, line) in output.lines().enumerate() {
            let line = line.trim();

            if i == 0 {
                // Parse status line: "HTTP/1.1 200 OK" or "HTTP/2 301"
                let parts: Vec<&str> = line.splitn(3, ' ').collect();
                if parts.len() >= 2 {
                    result.status_code = parts[1].parse::<u16>().ok();
                }
                continue;
            }

            // Skip blank lines (between HTTP/1.1 continue and final response)
            if line.is_empty() {
                continue;
            }

            // Parse "Header: Value"
            if let Some(colon) = line.find(':') {
                let key = line[..colon].trim().to_ascii_lowercase();
                let value = line[colon + 1..].trim().to_string();

                match key.as_str() {
                    "server" => result.server = Some(value),
                    "x-powered-by" => result.x_powered_by = Some(value),
                    "content-type" => result.content_type = Some(value),
                    _ => {}
                }
            }
        }

        result
    }

    /// Run curl -sI against a URL and return the raw header output.
    async fn probe_url(url: &str) -> Result<String, ReconError> {
        let url = url.to_string();

        let cmd = SandboxProfile::recon()
            .apply("curl")
            .arg("-sI")
            .arg("--max-time")
            .arg("15")
            .arg("--location")
            .arg(&url);

        let output = tokio::task::spawn_blocking(move || cmd.execute())
            .await
            .map_err(|e| ReconError::Sandbox(format!("spawn_blocking panicked: {e}")))?
            .map_err(|e| ReconError::Sandbox(e.to_string()))?;

        Ok(output.stdout)
    }

    /// Build a URL-kind asset from a URL and parsed headers.
    fn headers_to_asset(
        url: &str,
        headers: &ParsedHttpHeaders,
        session_id: Uuid,
    ) -> Asset {
        let metadata = serde_json::json!({
            "status_code": headers.status_code,
            "server": headers.server,
            "x_powered_by": headers.x_powered_by,
            "content_type": headers.content_type,
        });
        Asset {
            id: Uuid::new_v4(),
            session_id,
            kind: AssetKind::Url,
            value: url.to_string(),
            metadata,
            discovered_at: chrono::Utc::now(),
        }
    }
}

#[async_trait]
impl DiscoveryModule for WebModule {
    fn name(&self) -> &str {
        "web"
    }

    async fn discover(&self, target: &str, session_id: Uuid) -> Result<Vec<Asset>, ReconError> {
        info!(target, "web: probing HTTP and HTTPS endpoints");

        let mut assets = Vec::new();

        // Probe HTTP
        let http_url = if target.starts_with("http://") || target.starts_with("https://") {
            target.to_string()
        } else {
            format!("http://{target}")
        };

        match Self::probe_url(&http_url).await {
            Ok(raw) if !raw.is_empty() => {
                let headers = Self::parse_curl_headers(&raw);
                assets.push(Self::headers_to_asset(&http_url, &headers, session_id));
            }
            Ok(_) => tracing::debug!(url = %http_url, "web: HTTP probe returned empty"),
            Err(e) => tracing::warn!(url = %http_url, error = %e, "web: HTTP probe failed"),
        }

        // Probe HTTPS (only if target doesn't already specify scheme)
        if !target.starts_with("http://") && !target.starts_with("https://") {
            let https_url = format!("https://{target}");
            match Self::probe_url(&https_url).await {
                Ok(raw) if !raw.is_empty() => {
                    let headers = Self::parse_curl_headers(&raw);
                    assets.push(Self::headers_to_asset(&https_url, &headers, session_id));
                }
                Ok(_) => tracing::debug!(url = %https_url, "web: HTTPS probe returned empty"),
                Err(e) => tracing::warn!(url = %https_url, error = %e, "web: HTTPS probe failed"),
            }
        }

        info!(target, found = assets.len(), "web: discovery complete");
        Ok(assets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_curl_headers_basic() {
        let output = "\
HTTP/1.1 200 OK\r\n\
Server: Apache/2.4.41 (Ubuntu)\r\n\
Content-Type: text/html; charset=UTF-8\r\n\
X-Powered-By: PHP/7.4.3\r\n\
";
        let h = WebModule::parse_curl_headers(output);
        assert_eq!(h.status_code, Some(200));
        assert_eq!(h.server.as_deref(), Some("Apache/2.4.41 (Ubuntu)"));
        assert_eq!(h.content_type.as_deref(), Some("text/html; charset=UTF-8"));
        assert_eq!(h.x_powered_by.as_deref(), Some("PHP/7.4.3"));
    }

    #[test]
    fn parse_curl_headers_http2() {
        let output = "HTTP/2 301\r\nServer: nginx\r\n";
        let h = WebModule::parse_curl_headers(output);
        assert_eq!(h.status_code, Some(301));
        assert_eq!(h.server.as_deref(), Some("nginx"));
    }

    #[test]
    fn parse_curl_headers_missing_server() {
        let output = "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\n";
        let h = WebModule::parse_curl_headers(output);
        assert_eq!(h.status_code, Some(404));
        assert!(h.server.is_none());
        assert!(h.x_powered_by.is_none());
    }

    #[test]
    fn parse_curl_headers_empty() {
        let h = WebModule::parse_curl_headers("");
        assert_eq!(h.status_code, None);
        assert!(h.server.is_none());
    }

    #[test]
    fn headers_to_asset_creates_url_kind() {
        let sid = Uuid::new_v4();
        let headers = ParsedHttpHeaders {
            status_code: Some(200),
            server: Some("nginx".to_string()),
            x_powered_by: None,
            content_type: Some("text/html".to_string()),
        };
        let asset = WebModule::headers_to_asset("http://example.com", &headers, sid);
        assert_eq!(asset.kind, AssetKind::Url);
        assert_eq!(asset.value, "http://example.com");
        assert_eq!(asset.metadata["status_code"], 200);
        assert_eq!(asset.metadata["server"], "nginx");
    }

    #[test]
    fn parse_curl_redirect_with_blank_line() {
        // curl -L output may have multiple response blocks separated by blank lines
        let output = "\
HTTP/1.1 301 Moved Permanently\r\n\
Location: https://example.com/\r\n\
\r\n\
HTTP/2 200\r\n\
Server: cloudflare\r\n\
";
        let h = WebModule::parse_curl_headers(output);
        // Should pick up status from first line
        assert_eq!(h.status_code, Some(301));
        // Should pick up server from second block
        assert_eq!(h.server.as_deref(), Some("cloudflare"));
    }
}
