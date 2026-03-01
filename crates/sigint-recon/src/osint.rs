//! OSINT module — WHOIS lookup via sandboxed whois command.
//!
//! @decision DEC-RECON-005
//! @title OSINT module uses whois via SandboxProfile::recon() with key parsing
//! @status accepted
//! @rationale whois provides registrant info, nameservers, and registration
//! dates that are useful for attack surface mapping. The output format varies
//! by registrar, so we use heuristic key matching rather than strict parsing.
//! We store all parsed fields in asset metadata and return the target domain
//! as an enriched Domain asset.

use async_trait::async_trait;
use sigint_core::types::{Asset, AssetKind};
use sigint_sandbox::profile::SandboxProfile;
use tracing::info;
use uuid::Uuid;

use crate::error::ReconError;
use crate::module::DiscoveryModule;

/// Structured data parsed from whois output.
#[derive(Debug, Default, PartialEq)]
pub(crate) struct ParsedWhois {
    pub registrar: Option<String>,
    pub creation_date: Option<String>,
    pub expiry_date: Option<String>,
    pub nameservers: Vec<String>,
    pub registrant_org: Option<String>,
    pub registrant_email: Option<String>,
}

/// Performs WHOIS lookups and enriches the target as a Domain asset.
pub struct OsintModule;

impl OsintModule {
    /// Parse whois command output into structured metadata.
    ///
    /// Handles common field names across registrar formats (IANA, Verisign, etc.)
    pub(crate) fn parse_whois_output(output: &str) -> ParsedWhois {
        let mut result = ParsedWhois::default();

        for line in output.lines() {
            let line = line.trim();

            // Skip comment lines and empty lines
            if line.is_empty() || line.starts_with('%') || line.starts_with('#') {
                continue;
            }

            // Split on first colon
            let (key, value) = match line.find(':') {
                Some(pos) => {
                    let key = line[..pos].trim().to_ascii_lowercase();
                    let value = line[pos + 1..].trim().to_string();
                    (key, value)
                }
                None => continue,
            };

            if value.is_empty() {
                continue;
            }

            match key.as_str() {
                "registrar" => {
                    if result.registrar.is_none() {
                        result.registrar = Some(value);
                    }
                }
                "creation date" | "created" | "registered" | "domain registered" => {
                    if result.creation_date.is_none() {
                        result.creation_date = Some(value);
                    }
                }
                "registry expiry date" | "expiration date" | "expiry date" | "expires" => {
                    if result.expiry_date.is_none() {
                        result.expiry_date = Some(value);
                    }
                }
                "name server" | "nameserver" | "nserver" => {
                    let ns = value.split_whitespace().next().unwrap_or(&value).to_ascii_lowercase();
                    if !ns.is_empty() && !result.nameservers.contains(&ns) {
                        result.nameservers.push(ns);
                    }
                }
                "registrant organization" | "registrant org" | "org" | "organisation" => {
                    if result.registrant_org.is_none() {
                        result.registrant_org = Some(value);
                    }
                }
                "registrant email" | "tech email" => {
                    if result.registrant_email.is_none() {
                        result.registrant_email = Some(value);
                    }
                }
                _ => {}
            }
        }

        result
    }

    /// Build an enriched Domain asset from whois results.
    pub(crate) fn whois_to_asset(
        target: &str,
        whois: &ParsedWhois,
        session_id: Uuid,
    ) -> Asset {
        let metadata = serde_json::json!({
            "source": "whois",
            "registrar": whois.registrar,
            "creation_date": whois.creation_date,
            "expiry_date": whois.expiry_date,
            "nameservers": whois.nameservers,
            "registrant_org": whois.registrant_org,
            "registrant_email": whois.registrant_email,
        });
        Asset {
            id: Uuid::new_v4(),
            session_id,
            kind: AssetKind::Domain,
            value: target.to_string(),
            metadata,
            discovered_at: chrono::Utc::now(),
        }
    }
}

#[async_trait]
impl DiscoveryModule for OsintModule {
    fn name(&self) -> &str {
        "osint"
    }

    async fn discover(&self, target: &str, session_id: Uuid) -> Result<Vec<Asset>, ReconError> {
        info!(target, "osint: running whois lookup");

        // Strip scheme if present
        let domain = target
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or(target)
            .to_string();

        let cmd = SandboxProfile::recon()
            .apply("whois")
            .arg(&domain);

        let output = tokio::task::spawn_blocking(move || cmd.execute())
            .await
            .map_err(|e| ReconError::Sandbox(format!("spawn_blocking panicked: {e}")))?
            .map_err(|e| ReconError::Sandbox(e.to_string()))?;

        let whois = Self::parse_whois_output(&output.stdout);
        let asset = Self::whois_to_asset(&domain, &whois, session_id);

        info!(
            target,
            registrar = ?whois.registrar,
            nameservers = whois.nameservers.len(),
            "osint: discovery complete"
        );

        Ok(vec![asset])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_whois_basic_fields() {
        let output = "\
Domain Name: EXAMPLE.COM
Registrar: Example Registrar, Inc.
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2023-08-13T04:00:00Z
Name Server: A.IANA-SERVERS.NET
Name Server: B.IANA-SERVERS.NET
Registrant Organization: Internet Assigned Numbers Authority
";
        let w = OsintModule::parse_whois_output(output);
        assert_eq!(w.registrar.as_deref(), Some("Example Registrar, Inc."));
        assert_eq!(w.creation_date.as_deref(), Some("1995-08-14T04:00:00Z"));
        assert_eq!(w.expiry_date.as_deref(), Some("2023-08-13T04:00:00Z"));
        assert_eq!(w.nameservers.len(), 2);
        assert!(w.nameservers.contains(&"a.iana-servers.net".to_string()));
        assert!(w.nameservers.contains(&"b.iana-servers.net".to_string()));
        assert_eq!(w.registrant_org.as_deref(), Some("Internet Assigned Numbers Authority"));
    }

    #[test]
    fn parse_whois_skips_comments() {
        let output = "\
% This is a comment
# Also a comment
Registrar: Test Registrar
";
        let w = OsintModule::parse_whois_output(output);
        assert_eq!(w.registrar.as_deref(), Some("Test Registrar"));
    }

    #[test]
    fn parse_whois_deduplicates_nameservers() {
        let output = "\
Name Server: NS1.EXAMPLE.COM
Name Server: ns1.example.com
Name Server: NS2.EXAMPLE.COM
";
        let w = OsintModule::parse_whois_output(output);
        assert_eq!(w.nameservers.len(), 2);
    }

    #[test]
    fn parse_whois_empty_input() {
        let w = OsintModule::parse_whois_output("");
        assert!(w.registrar.is_none());
        assert!(w.nameservers.is_empty());
    }

    #[test]
    fn parse_whois_first_value_wins() {
        // Some whois output repeats fields — only the first should be used
        let output = "\
Registrar: First Registrar
Registrar: Second Registrar
";
        let w = OsintModule::parse_whois_output(output);
        assert_eq!(w.registrar.as_deref(), Some("First Registrar"));
    }

    #[test]
    fn whois_to_asset_creates_domain_kind() {
        let sid = Uuid::new_v4();
        let whois = ParsedWhois {
            registrar: Some("ICANN".to_string()),
            ..Default::default()
        };
        let asset = OsintModule::whois_to_asset("example.com", &whois, sid);
        assert_eq!(asset.kind, AssetKind::Domain);
        assert_eq!(asset.value, "example.com");
        assert_eq!(asset.metadata["registrar"], "ICANN");
        assert_eq!(asset.metadata["source"], "whois");
    }
}
