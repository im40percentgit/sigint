//! Port/service discovery module — sandboxed nmap with output parsing.
//!
//! @decision DEC-RECON-002
//! @title Port module uses nmap via SandboxProfile::nmap() (pasta networking)
//! @status accepted
//! @rationale nmap requires real network connectivity. SandboxProfile::Nmap
//! uses pasta user-mode networking and a 300s timeout. The `-oN -` flag
//! emits normal-format output to stdout, which is easier to parse with
//! string operations than XML and is human-readable for debugging.
//! Service assets are created for the target IP/host; the host asset is
//! also returned so callers get a complete picture of what was found.

use async_trait::async_trait;
use regex::Regex;
use sigint_core::types::{Asset, AssetKind};
use sigint_sandbox::profile::SandboxProfile;
use tracing::info;
use uuid::Uuid;

use crate::error::ReconError;
use crate::module::DiscoveryModule;

/// Represents a parsed open port line from nmap's normal output format.
#[derive(Debug, PartialEq)]
pub(crate) struct ParsedPort {
    pub port: i32,
    pub protocol: String,
    pub service: String,
    pub version: Option<String>,
}

/// Discovers open ports and service versions via sandboxed nmap.
pub struct PortModule;

impl PortModule {
    /// Parse nmap normal-format output (`-oN -`) into a list of open ports.
    ///
    /// Matches lines of the form:
    ///   `80/tcp   open  http    Apache httpd 2.4.41`
    ///   `22/tcp   open  ssh`
    pub(crate) fn parse_nmap_output(output: &str) -> Vec<ParsedPort> {
        // Pattern: <port>/<proto>   open  <service>   [<version info>]
        let re = Regex::new(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?$").unwrap();

        output
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                re.captures(line).map(|caps| {
                    let port: i32 = caps[1].parse().unwrap_or(0);
                    let protocol = caps[2].to_string();
                    let service = caps[3].to_string();
                    let version = caps
                        .get(4)
                        .map(|m| m.as_str().trim().to_string())
                        .filter(|s| !s.is_empty());
                    ParsedPort {
                        port,
                        protocol,
                        service,
                        version,
                    }
                })
            })
            .collect()
    }

    /// Convert parsed ports into Service-kind assets for the given target host.
    ///
    /// Each open port becomes one `AssetKind::Service` asset whose value is
    /// `<port>/<proto>` and whose metadata contains the service name and version.
    pub(crate) fn ports_to_assets(
        ports: &[ParsedPort],
        target: &str,
        session_id: Uuid,
    ) -> Vec<Asset> {
        ports
            .iter()
            .map(|p| {
                let metadata = serde_json::json!({
                    "target": target,
                    "port": p.port,
                    "protocol": p.protocol,
                    "service": p.service,
                    "version": p.version,
                });
                Asset {
                    id: Uuid::new_v4(),
                    session_id,
                    kind: AssetKind::Service,
                    value: format!("{}:{}/{}", target, p.port, p.protocol),
                    metadata,
                    discovered_at: chrono::Utc::now(),
                }
            })
            .collect()
    }
}

#[async_trait]
impl DiscoveryModule for PortModule {
    fn name(&self) -> &str {
        "port"
    }

    async fn discover(&self, target: &str, session_id: Uuid) -> Result<Vec<Asset>, ReconError> {
        info!(target, "port: running nmap top-100 service scan");

        let target_str = target.to_string();

        let cmd = SandboxProfile::nmap()
            .apply("nmap")
            .arg("-T4")
            .arg("-sV")
            .arg("--top-ports")
            .arg("100")
            .arg("-oN")
            .arg("-")
            .arg(&target_str);

        let output = tokio::task::spawn_blocking(move || cmd.execute())
            .await
            .map_err(|e| ReconError::Sandbox(format!("spawn_blocking panicked: {e}")))?
            .map_err(|e| ReconError::Sandbox(e.to_string()))?;

        let ports = Self::parse_nmap_output(&output.stdout);
        let mut assets = Self::ports_to_assets(&ports, target, session_id);

        // Always include the target itself as a Host asset
        assets.push(Asset {
            id: Uuid::new_v4(),
            session_id,
            kind: AssetKind::Host,
            value: target.to_string(),
            metadata: serde_json::json!({ "source": "nmap" }),
            discovered_at: chrono::Utc::now(),
        });

        info!(target, open_ports = ports.len(), "port: discovery complete");
        Ok(assets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_nmap_open_ports() {
        let output = "\
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for example.com (93.184.216.34)
Host is up (0.12s latency).

PORT    STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
443/tcp  open  https   nginx 1.18.0
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu

Nmap done: 1 IP address (1 host up) scanned in 5.23 seconds
";
        let ports = PortModule::parse_nmap_output(output);
        assert_eq!(ports.len(), 3);
        assert_eq!(ports[0].port, 80);
        assert_eq!(ports[0].protocol, "tcp");
        assert_eq!(ports[0].service, "http");
        assert!(ports[0].version.as_deref().unwrap_or("").contains("Apache"));

        assert_eq!(ports[1].port, 443);
        assert_eq!(ports[1].service, "https");

        assert_eq!(ports[2].port, 22);
        assert_eq!(ports[2].service, "ssh");
    }

    #[test]
    fn parse_nmap_no_open_ports() {
        let output = "All 100 scanned ports on example.com are in ignored states.\n";
        let ports = PortModule::parse_nmap_output(output);
        assert!(ports.is_empty());
    }

    #[test]
    fn parse_nmap_udp_ports() {
        let output = "53/udp   open  domain  ISC BIND 9.16.1\n";
        let ports = PortModule::parse_nmap_output(output);
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].port, 53);
        assert_eq!(ports[0].protocol, "udp");
        assert_eq!(ports[0].service, "domain");
    }

    #[test]
    fn parse_nmap_port_no_version() {
        let output = "8080/tcp open  http\n";
        let ports = PortModule::parse_nmap_output(output);
        assert_eq!(ports.len(), 1);
        assert_eq!(ports[0].port, 8080);
        assert!(ports[0].version.is_none());
    }

    #[test]
    fn ports_to_assets_creates_service_kind() {
        let sid = Uuid::new_v4();
        let ports = vec![ParsedPort {
            port: 80,
            protocol: "tcp".to_string(),
            service: "http".to_string(),
            version: Some("Apache 2.4".to_string()),
        }];
        let assets = PortModule::ports_to_assets(&ports, "10.0.0.1", sid);
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].kind, AssetKind::Service);
        assert_eq!(assets[0].value, "10.0.0.1:80/tcp");
        assert_eq!(assets[0].metadata["port"], 80);
        assert_eq!(assets[0].metadata["service"], "http");
    }

    #[test]
    fn ports_to_assets_empty() {
        let sid = Uuid::new_v4();
        let assets = PortModule::ports_to_assets(&[], "10.0.0.1", sid);
        assert!(assets.is_empty());
    }
}
