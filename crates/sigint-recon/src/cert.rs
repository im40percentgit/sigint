//! Certificate transparency module — queries crt.sh for subdomain enumeration.
//!
//! @decision DEC-RECON-004
//! @title Cert module uses reqwest (not sandbox) to query crt.sh JSON API
//! @status accepted
//! @rationale crt.sh is a TLS-protected JSON API. Using reqwest avoids the
//! overhead of spawning curl in a sandbox for a simple HTTPS GET. The crt.sh
//! API can be slow or rate-limited, so we apply a generous timeout (30s) and
//! return partial results gracefully on error rather than failing the whole run.
//! Duplicate subdomains (same common_name appearing in multiple cert entries)
//! are deduplicated before returning.

use async_trait::async_trait;
use sigint_core::types::{Asset, AssetKind};
use tracing::info;
use uuid::Uuid;

use crate::error::ReconError;
use crate::module::DiscoveryModule;

/// Discovers subdomains and certificate metadata via the crt.sh transparency log API.
pub struct CertModule;

impl CertModule {
    /// Parse a JSON response from crt.sh into deduplicated domain assets.
    ///
    /// Filters out wildcard entries (starting with `*.`) and deduplicates
    /// by domain value. Each unique domain becomes an `AssetKind::Domain` asset.
    pub(crate) fn parse_crtsh_response(json: &serde_json::Value, session_id: Uuid) -> Vec<Asset> {
        let entries = match json.as_array() {
            Some(arr) => arr,
            None => return vec![],
        };

        let mut seen = std::collections::HashSet::new();
        let mut assets = Vec::new();

        for entry in entries {
            // Extract common_name from the JSON object
            let name = match entry.get("common_name").and_then(|v| v.as_str()) {
                Some(n) => n.trim().to_string(),
                None => continue,
            };

            // Skip wildcards and empty names
            if name.is_empty() || name.starts_with("*.") || name.contains(' ') {
                continue;
            }

            // Deduplicate
            if seen.insert(name.clone()) {
                assets.push(Asset {
                    id: Uuid::new_v4(),
                    session_id,
                    kind: AssetKind::Domain,
                    value: name,
                    metadata: serde_json::json!({ "source": "crt.sh" }),
                    discovered_at: chrono::Utc::now(),
                });
            }
        }

        assets
    }
}

#[async_trait]
impl DiscoveryModule for CertModule {
    fn name(&self) -> &str {
        "cert"
    }

    async fn discover(&self, target: &str, session_id: Uuid) -> Result<Vec<Asset>, ReconError> {
        info!(target, "cert: querying crt.sh certificate transparency");

        // Strip scheme if present to get bare domain
        let domain = target
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or(target);

        let url = format!("https://crt.sh/?q=%25.{domain}&output=json");

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(|e| ReconError::Network(format!("reqwest client build failed: {e}")))?;

        let response = client
            .get(&url)
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|e| ReconError::Network(format!("crt.sh request failed: {e}")))?;

        if !response.status().is_success() {
            return Err(ReconError::Network(format!(
                "crt.sh returned HTTP {}",
                response.status()
            )));
        }

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| ReconError::Network(format!("crt.sh JSON parse failed: {e}")))?;

        let assets = Self::parse_crtsh_response(&json, session_id);

        info!(
            target,
            subdomains = assets.len(),
            "cert: discovery complete"
        );
        Ok(assets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid() -> Uuid {
        Uuid::new_v4()
    }

    fn make_crtsh_json(entries: &[(&str,)]) -> serde_json::Value {
        let arr: Vec<serde_json::Value> = entries
            .iter()
            .map(|(name,)| serde_json::json!({ "common_name": name }))
            .collect();
        serde_json::Value::Array(arr)
    }

    #[test]
    fn parse_crtsh_basic_domains() {
        let json = make_crtsh_json(&[
            ("www.example.com",),
            ("mail.example.com",),
            ("api.example.com",),
        ]);
        let assets = CertModule::parse_crtsh_response(&json, sid());
        assert_eq!(assets.len(), 3);
        assert!(assets.iter().all(|a| a.kind == AssetKind::Domain));
        assert!(assets.iter().all(|a| a.metadata["source"] == "crt.sh"));
    }

    #[test]
    fn parse_crtsh_deduplicates() {
        let json = make_crtsh_json(&[
            ("www.example.com",),
            ("www.example.com",),
            ("api.example.com",),
        ]);
        let assets = CertModule::parse_crtsh_response(&json, sid());
        assert_eq!(assets.len(), 2);
    }

    #[test]
    fn parse_crtsh_skips_wildcards() {
        let json = make_crtsh_json(&[("*.example.com",), ("www.example.com",)]);
        let assets = CertModule::parse_crtsh_response(&json, sid());
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].value, "www.example.com");
    }

    #[test]
    fn parse_crtsh_empty_array() {
        let json = serde_json::json!([]);
        let assets = CertModule::parse_crtsh_response(&json, sid());
        assert!(assets.is_empty());
    }

    #[test]
    fn parse_crtsh_not_array_returns_empty() {
        let json = serde_json::json!({"error": "not found"});
        let assets = CertModule::parse_crtsh_response(&json, sid());
        assert!(assets.is_empty());
    }

    #[test]
    fn parse_crtsh_missing_common_name_skipped() {
        let json = serde_json::json!([
            { "issuer_ca_id": 123 },
            { "common_name": "www.example.com" }
        ]);
        let assets = CertModule::parse_crtsh_response(&json, sid());
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].value, "www.example.com");
    }
}
