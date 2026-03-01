//! DNS enumeration module — resolves A/AAAA records via sandboxed dig.
//!
//! @decision DEC-RECON-001
//! @title DNS module uses dig via SandboxProfile::recon() with spawn_blocking
//! @status accepted
//! @rationale dig is a fast, reliable DNS resolver available on all targets.
//! The Recon sandbox profile provides pasta networking so dig can reach real
//! DNS servers while remaining isolated. SandboxedCommand::execute() is
//! synchronous, so we bridge to async via tokio::task::spawn_blocking per
//! the pattern established in DEC-SAND-002.

use async_trait::async_trait;
use sigint_core::types::{Asset, AssetKind};
use sigint_sandbox::profile::SandboxProfile;
use tracing::info;
use uuid::Uuid;

use crate::error::ReconError;
use crate::module::DiscoveryModule;

/// Discovers A and AAAA records for a target domain via `dig +short`.
pub struct DnsModule;

impl DnsModule {
    /// Parse the stdout from `dig +short <target> A` (or AAAA) into Host assets.
    ///
    /// Each non-empty line is expected to be an IP address. Lines that look like
    /// hostnames (contain letters other than hex digits) are skipped.
    pub(crate) fn parse_dig_output(output: &str, session_id: Uuid) -> Vec<Asset> {
        output
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .filter(|l| is_ip_address(l))
            .map(|ip| Asset {
                id: Uuid::new_v4(),
                session_id,
                kind: AssetKind::Host,
                value: ip.to_string(),
                metadata: serde_json::Value::Null,
                discovered_at: chrono::Utc::now(),
            })
            .collect()
    }

    /// Run a single `dig +short <target> <rtype>` and parse the output.
    async fn run_dig(
        target: &str,
        rtype: &str,
        session_id: Uuid,
    ) -> Result<Vec<Asset>, ReconError> {
        let target = target.to_string();
        let rtype = rtype.to_string();

        let cmd = SandboxProfile::recon()
            .apply("dig")
            .arg("+short")
            .arg(&target)
            .arg(&rtype);

        let output = tokio::task::spawn_blocking(move || cmd.execute())
            .await
            .map_err(|e| ReconError::Sandbox(format!("spawn_blocking panicked: {e}")))?
            .map_err(|e| ReconError::Sandbox(e.to_string()))?;

        Ok(Self::parse_dig_output(&output.stdout, session_id))
    }
}

/// Returns true if `s` looks like an IPv4 or IPv6 address rather than a hostname.
///
/// Heuristic: IPv4 contains only digits and dots; IPv6 contains only hex digits and colons.
fn is_ip_address(s: &str) -> bool {
    // IPv4: all chars are digits or '.'
    if s.chars().all(|c| c.is_ascii_digit() || c == '.') && s.contains('.') {
        return true;
    }
    // IPv6: all chars are hex digits or ':'
    if s.chars().all(|c| c.is_ascii_hexdigit() || c == ':') && s.contains(':') {
        return true;
    }
    false
}

#[async_trait]
impl DiscoveryModule for DnsModule {
    fn name(&self) -> &str {
        "dns"
    }

    async fn discover(&self, target: &str, session_id: Uuid) -> Result<Vec<Asset>, ReconError> {
        info!(target, "dns: running A and AAAA lookups");

        let mut assets = Vec::new();

        // A records (IPv4)
        match Self::run_dig(target, "A", session_id).await {
            Ok(mut a_assets) => assets.append(&mut a_assets),
            Err(e) => tracing::warn!(target, error = %e, "dns: A lookup failed"),
        }

        // AAAA records (IPv6)
        match Self::run_dig(target, "AAAA", session_id).await {
            Ok(mut aaaa_assets) => assets.append(&mut aaaa_assets),
            Err(e) => tracing::warn!(target, error = %e, "dns: AAAA lookup failed"),
        }

        // Also add the target itself as a Domain asset
        assets.push(Asset {
            id: Uuid::new_v4(),
            session_id,
            kind: AssetKind::Domain,
            value: target.to_string(),
            metadata: serde_json::Value::Null,
            discovered_at: chrono::Utc::now(),
        });

        info!(target, count = assets.len(), "dns: discovery complete");
        Ok(assets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid() -> Uuid {
        Uuid::new_v4()
    }

    #[test]
    fn parse_dig_output_ipv4() {
        let output = "93.184.216.34\n";
        let assets = DnsModule::parse_dig_output(output, sid());
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].kind, AssetKind::Host);
        assert_eq!(assets[0].value, "93.184.216.34");
    }

    #[test]
    fn parse_dig_output_ipv6() {
        let output = "2606:2800:220:1:248:1893:25c8:1946\n";
        let assets = DnsModule::parse_dig_output(output, sid());
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].kind, AssetKind::Host);
        assert_eq!(assets[0].value, "2606:2800:220:1:248:1893:25c8:1946");
    }

    #[test]
    fn parse_dig_output_mixed() {
        let output = "93.184.216.34\n2606:2800:220:1:248:1893:25c8:1946\n";
        let assets = DnsModule::parse_dig_output(output, sid());
        assert_eq!(assets.len(), 2);
        assert!(assets.iter().all(|a| a.kind == AssetKind::Host));
    }

    #[test]
    fn parse_dig_output_empty() {
        let assets = DnsModule::parse_dig_output("", sid());
        assert!(assets.is_empty());
    }

    #[test]
    fn parse_dig_output_skips_hostnames() {
        // dig sometimes returns CNAME targets (hostnames) — we skip those
        let output = "example.com.\n93.184.216.34\n";
        let assets = DnsModule::parse_dig_output(output, sid());
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].value, "93.184.216.34");
    }

    #[test]
    fn parse_dig_output_skips_blank_lines() {
        let output = "\n93.184.216.34\n\n";
        let assets = DnsModule::parse_dig_output(output, sid());
        assert_eq!(assets.len(), 1);
    }

    #[test]
    fn is_ip_address_ipv4_true() {
        assert!(is_ip_address("192.168.1.1"));
        assert!(is_ip_address("10.0.0.1"));
        assert!(is_ip_address("93.184.216.34"));
    }

    #[test]
    fn is_ip_address_ipv6_true() {
        assert!(is_ip_address("::1"));
        assert!(is_ip_address("2606:2800:220:1:248:1893:25c8:1946"));
    }

    #[test]
    fn is_ip_address_hostname_false() {
        assert!(!is_ip_address("example.com."));
        assert!(!is_ip_address("example.com"));
        assert!(!is_ip_address(""));
    }
}
