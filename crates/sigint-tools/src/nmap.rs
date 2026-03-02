//! NmapTool — sandboxed nmap wrapper with network access via pasta.
//!
//! @decision DEC-TOOL-004
//! @title NmapTool uses SandboxProfile::nmap() for pasta networking, -oX for structured output
//! @status accepted
//! @rationale nmap requires real network access to scan targets. SandboxProfile::Nmap
//! applies pasta user-mode networking (300s timeout) so nmap can reach the network
//! while remaining isolated from the host filesystem and process tree. The execute()
//! method is async and bridges to the synchronous SandboxedCommand::execute() via
//! tokio::task::spawn_blocking, matching the pattern documented in DEC-SAND-002.
//! The `-oX -` flag writes XML output to stdout. parse_nmap_xml() converts the XML
//! into structured JSON (hosts → address, hostnames, status, ports → port, protocol,
//! state, service, version) for structured_data. Raw XML is preserved in stdout for
//! LLM consumption. quick-xml event-based parsing is used to avoid materialising a
//! DOM tree, keeping memory overhead minimal for large scan outputs.

use async_trait::async_trait;
use quick_xml::events::Event;
use quick_xml::Reader;
use serde_json::{json, Value};
use sigint_llm::ToolDefinition;
use sigint_sandbox::profile::SandboxProfile;
use tracing::info;

use crate::error::{Result, ToolError};
use crate::result::ToolResult;
use crate::tool::Tool;

/// Parse nmap XML output (`-oX -`) into structured JSON.
///
/// Returns `Some(json)` on success, `None` if the input is not valid nmap XML or
/// cannot be parsed. The output shape is:
///
/// ```json
/// {
///   "hosts": [{
///     "address": "93.184.216.34",
///     "hostnames": ["example.com"],
///     "status": "up",
///     "ports": [{
///       "port": 80,
///       "protocol": "tcp",
///       "state": "open",
///       "service": "http",
///       "version": "nginx 1.25.3"
///     }]
///   }]
/// }
/// ```
///
/// Uses quick-xml event-based parsing so no DOM tree is materialised.
fn parse_nmap_xml(xml: &str) -> Option<Value> {
    // Require the input to contain the nmap XML root element as a basic sanity check
    // before spending time on full parsing.
    if !xml.contains("<nmaprun") {
        return None;
    }

    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);

    // Per-host accumulator state.
    let mut hosts: Vec<Value> = Vec::new();

    // Current host being built (Some while inside a <host> element).
    let mut current_host: Option<HostBuilder> = None;
    // Current port being built (Some while inside a <port> element).
    let mut current_port: Option<PortBuilder> = None;

    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => {
                let raw_name = e.name();
                let name = std::str::from_utf8(raw_name.as_ref()).unwrap_or("");
                match name {
                    "host" => {
                        current_host = Some(HostBuilder::default());
                    }
                    "status" if current_host.is_some() => {
                        if let Some(ref mut h) = current_host {
                            if let Some(state) = attr_value(e, b"state") {
                                h.status = state;
                            }
                        }
                    }
                    "address" if current_host.is_some() => {
                        if let Some(ref mut h) = current_host {
                            // Only take the first IPv4/IPv6 address; skip MAC.
                            let addrtype = attr_value(e, b"addrtype").unwrap_or_default();
                            if (addrtype == "ipv4" || addrtype == "ipv6") && h.address.is_empty() {
                                h.address = attr_value(e, b"addr").unwrap_or_default();
                            }
                        }
                    }
                    "hostname" if current_host.is_some() => {
                        if let Some(ref mut h) = current_host {
                            if let Some(hn) = attr_value(e, b"name") {
                                if !hn.is_empty() {
                                    h.hostnames.push(hn);
                                }
                            }
                        }
                    }
                    "port" if current_host.is_some() => {
                        let pb = PortBuilder {
                            protocol: attr_value(e, b"protocol").unwrap_or_default(),
                            port: attr_value(e, b"portid")
                                .and_then(|pid| pid.parse::<u16>().ok())
                                .unwrap_or(0),
                            ..Default::default()
                        };
                        current_port = Some(pb);
                    }
                    "state" if current_port.is_some() => {
                        if let Some(ref mut p) = current_port {
                            p.state = attr_value(e, b"state").unwrap_or_default();
                        }
                    }
                    "service" if current_port.is_some() => {
                        if let Some(ref mut p) = current_port {
                            p.service = attr_value(e, b"name").unwrap_or_default();
                            // Combine product + version into a single version string.
                            let product = attr_value(e, b"product").unwrap_or_default();
                            let version = attr_value(e, b"version").unwrap_or_default();
                            p.version = match (product.is_empty(), version.is_empty()) {
                                (false, false) => format!("{product} {version}"),
                                (false, true) => product,
                                (true, false) => version,
                                (true, true) => String::new(),
                            };
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::End(ref e)) => {
                let raw_name = e.name();
                let name = std::str::from_utf8(raw_name.as_ref()).unwrap_or("");
                match name {
                    "port" => {
                        // Commit the current port into the current host.
                        if let (Some(ref mut h), Some(p)) = (&mut current_host, current_port.take())
                        {
                            h.ports.push(p.into_value());
                        }
                    }
                    "host" => {
                        // Commit the current host.
                        if let Some(h) = current_host.take() {
                            hosts.push(h.into_value());
                        }
                    }
                    _ => {}
                }
            }
            Ok(Event::Eof) => break,
            Err(_) => return None,
            _ => {}
        }
        buf.clear();
    }

    Some(json!({ "hosts": hosts }))
}

/// Per-host accumulator used while parsing nmap XML.
#[derive(Default)]
struct HostBuilder {
    address: String,
    hostnames: Vec<String>,
    status: String,
    ports: Vec<Value>,
}

impl HostBuilder {
    fn into_value(self) -> Value {
        json!({
            "address":   self.address,
            "hostnames": self.hostnames,
            "status":    self.status,
            "ports":     self.ports,
        })
    }
}

/// Per-port accumulator used while parsing nmap XML.
#[derive(Default)]
struct PortBuilder {
    port: u16,
    protocol: String,
    state: String,
    service: String,
    version: String,
}

impl PortBuilder {
    fn into_value(self) -> Value {
        json!({
            "port":     self.port,
            "protocol": self.protocol,
            "state":    self.state,
            "service":  self.service,
            "version":  self.version,
        })
    }
}

/// Extract the value of an XML attribute by name.
fn attr_value(e: &quick_xml::events::BytesStart<'_>, attr_name: &[u8]) -> Option<String> {
    e.attributes()
        .filter_map(|a| a.ok())
        .find(|a| a.key.as_ref() == attr_name)
        .and_then(|a| {
            std::str::from_utf8(a.value.as_ref())
                .ok()
                .map(|s| s.to_owned())
        })
}

/// Scan type requested by the LLM agent.
#[derive(Debug, Clone, Copy, PartialEq)]
enum ScanType {
    /// `-T4 -F` — fast scan of top 100 ports.
    Quick,
    /// `-T4 -p-` — full scan of all 65535 ports.
    Full,
    /// `-sV --top-ports 1000` — service/version detection on top 1000 ports.
    Service,
}

impl ScanType {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "quick" => Some(ScanType::Quick),
            "full" => Some(ScanType::Full),
            "service" => Some(ScanType::Service),
            _ => None,
        }
    }

    /// nmap flags for this scan type.
    fn flags(&self) -> &'static [&'static str] {
        match self {
            ScanType::Quick => &["-T4", "-F"],
            ScanType::Full => &["-T4", "-p-"],
            ScanType::Service => &["-sV", "--top-ports", "1000"],
        }
    }
}

/// Sandboxed nmap tool wrapper.
///
/// Exposes nmap as a `Tool` for the LLM agent layer. Network access is
/// provided via pasta (user-mode networking) inside a Linux namespace sandbox.
pub struct NmapTool;

#[async_trait]
impl Tool for NmapTool {
    fn name(&self) -> &str {
        "nmap_scan"
    }

    fn description(&self) -> &str {
        "Run an nmap port scan against a target host or network range. \
         Returns scan output including open ports, services, and host state. \
         Requires network access — runs inside a sandboxed environment with \
         pasta user-mode networking."
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::function(
            self.name(),
            self.description(),
            json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Target host, IP address, or CIDR range to scan (e.g. '192.168.1.1', '10.0.0.0/24')"
                    },
                    "ports": {
                        "type": "string",
                        "description": "Port specification (e.g. '80,443', '1-1024', '80,443,8080-8090'). Omit to use scan_type defaults."
                    },
                    "scan_type": {
                        "type": "string",
                        "enum": ["quick", "full", "service"],
                        "description": "Scan preset: 'quick' (-T4 -F, top 100 ports), 'full' (-T4 -p-, all ports), 'service' (-sV --top-ports 1000, version detection). Defaults to 'quick'."
                    }
                },
                "required": ["target"]
            }),
        )
    }

    async fn execute(&self, args: Value) -> Result<ToolResult> {
        // Extract required target.
        let target = args["target"]
            .as_str()
            .ok_or_else(|| ToolError::MissingArgument("target".to_string()))?
            .to_string();

        // Extract optional ports.
        let ports = args["ports"].as_str().map(|s| s.to_string());

        // Extract optional scan_type, default to Quick.
        let scan_type = match args["scan_type"].as_str() {
            None => ScanType::Quick,
            Some(s) => ScanType::from_str(s).ok_or_else(|| ToolError::InvalidArgument {
                name: "scan_type".to_string(),
                expected: "one of: quick, full, service".to_string(),
            })?,
        };

        info!(
            target = %target,
            ?ports,
            ?scan_type,
            "executing nmap scan"
        );

        // Build the sandboxed command.
        let mut cmd = SandboxProfile::nmap().apply("nmap");

        // Apply scan-type flags.
        for flag in scan_type.flags() {
            cmd = cmd.arg(*flag);
        }

        // Apply port specification if provided (overrides scan_type port range).
        if let Some(ref p) = ports {
            cmd = cmd.arg("-p").arg(p);
        }

        // Write XML output to stdout. parse_nmap_xml() converts it to structured JSON.
        // Raw XML is preserved in ToolResult::stdout for LLM consumption.
        cmd = cmd.arg("-oX").arg("-");

        // Append the target last.
        cmd = cmd.arg(&target);

        // SandboxedCommand::execute() is synchronous — bridge via spawn_blocking.
        let output = tokio::task::spawn_blocking(move || cmd.execute())
            .await
            .map_err(|e| ToolError::Sandbox(format!("spawn_blocking panicked: {e}")))?
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("timed out") || msg.contains("timeout") {
                    ToolError::Timeout(300)
                } else {
                    ToolError::Sandbox(msg)
                }
            })?;

        // Parse the XML output into structured JSON for the agent layer.
        let structured_data = parse_nmap_xml(&output.stdout);

        Ok(ToolResult {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.exit_code,
            duration: output.duration,
            structured_data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nmap_risk_level_is_low() {
        assert_eq!(NmapTool.risk_level(), sigint_core::types::ToolRisk::Low);
    }

    #[test]
    fn nmap_tool_name_nonempty() {
        assert!(!NmapTool.name().is_empty());
        assert_eq!(NmapTool.name(), "nmap_scan");
    }

    #[test]
    fn nmap_tool_description_nonempty() {
        assert!(!NmapTool.description().is_empty());
    }

    #[test]
    fn nmap_tool_definition_shape() {
        let def = NmapTool.definition();
        assert_eq!(def.type_, "function");
        assert_eq!(def.function.name, "nmap_scan");

        let params = &def.function.parameters;
        assert_eq!(params["type"], "object");

        // target is required
        let required = params["required"].as_array().unwrap();
        assert!(
            required.iter().any(|v| v == "target"),
            "target should be required"
        );

        // target property exists and is a string
        assert_eq!(params["properties"]["target"]["type"], "string");

        // ports property is optional (not in required array)
        assert!(params["properties"]["ports"].is_object());
        assert!(
            !required.iter().any(|v| v == "ports"),
            "ports should be optional"
        );

        // scan_type has enum constraint
        let scan_type_enum = params["properties"]["scan_type"]["enum"]
            .as_array()
            .unwrap();
        assert!(scan_type_enum.iter().any(|v| v == "quick"));
        assert!(scan_type_enum.iter().any(|v| v == "full"));
        assert!(scan_type_enum.iter().any(|v| v == "service"));
    }

    #[tokio::test]
    async fn nmap_missing_target_errors() {
        let err = NmapTool.execute(json!({})).await.unwrap_err();
        assert!(
            err.to_string().contains("missing required argument"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn nmap_invalid_scan_type_errors() {
        let err = NmapTool
            .execute(json!({"target": "127.0.0.1", "scan_type": "stealth"}))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("invalid argument"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn scan_type_flags() {
        assert_eq!(ScanType::Quick.flags(), &["-T4", "-F"]);
        assert_eq!(ScanType::Full.flags(), &["-T4", "-p-"]);
        assert_eq!(ScanType::Service.flags(), &["-sV", "--top-ports", "1000"]);
    }

    #[test]
    fn scan_type_from_str() {
        assert_eq!(ScanType::from_str("quick"), Some(ScanType::Quick));
        assert_eq!(ScanType::from_str("full"), Some(ScanType::Full));
        assert_eq!(ScanType::from_str("service"), Some(ScanType::Service));
        assert_eq!(ScanType::from_str("stealth"), None);
        assert_eq!(ScanType::from_str(""), None);
    }

    // ──────────────────────────────────────────────────────────────────────
    // parse_nmap_xml tests
    // ──────────────────────────────────────────────────────────────────────

    const NMAP_XML_SINGLE_HOST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -T4 -F -oX - 93.184.216.34" start="1709000000" version="7.94">
<host starttime="1709000001" endtime="1709000010">
<status state="up" reason="echo-reply"/>
<address addr="93.184.216.34" addrtype="ipv4"/>
<hostnames>
<hostname name="example.com" type="PTR"/>
</hostnames>
<ports>
<port protocol="tcp" portid="80">
<state state="open" reason="syn-ack"/>
<service name="http" product="nginx" version="1.25.3"/>
</port>
<port protocol="tcp" portid="443">
<state state="open" reason="syn-ack"/>
<service name="https" product="nginx" version="1.25.3"/>
</port>
</ports>
</host>
<runstats><finished time="1709000020" elapsed="19.0"/></runstats>
</nmaprun>"#;

    const NMAP_XML_NO_HOSTS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -T4 -F -oX - 192.0.2.0" start="1709000000" version="7.94">
<runstats><finished time="1709000010" elapsed="10.0"/></runstats>
</nmaprun>"#;

    #[test]
    fn parse_nmap_xml_single_host() {
        let result = parse_nmap_xml(NMAP_XML_SINGLE_HOST).expect("should parse valid nmap XML");

        let hosts = result["hosts"]
            .as_array()
            .expect("hosts should be an array");
        assert_eq!(hosts.len(), 1, "expected exactly 1 host");

        let host = &hosts[0];
        assert_eq!(host["address"], "93.184.216.34", "address mismatch");
        assert_eq!(host["status"], "up", "status mismatch");

        let hostnames = host["hostnames"]
            .as_array()
            .expect("hostnames should be an array");
        assert!(
            hostnames.iter().any(|h| h == "example.com"),
            "expected example.com in hostnames"
        );

        let ports = host["ports"].as_array().expect("ports should be an array");
        assert_eq!(ports.len(), 2, "expected 2 ports");

        // Port 80
        let p80 = ports
            .iter()
            .find(|p| p["port"] == 80)
            .expect("port 80 should be present");
        assert_eq!(p80["protocol"], "tcp");
        assert_eq!(p80["state"], "open");
        assert_eq!(p80["service"], "http");
        assert!(
            p80["version"].as_str().unwrap_or("").contains("nginx"),
            "version should contain nginx"
        );

        // Port 443
        let p443 = ports
            .iter()
            .find(|p| p["port"] == 443)
            .expect("port 443 should be present");
        assert_eq!(p443["protocol"], "tcp");
        assert_eq!(p443["state"], "open");
        assert_eq!(p443["service"], "https");
    }

    #[test]
    fn parse_nmap_xml_malformed_returns_none() {
        assert!(parse_nmap_xml("this is not xml at all").is_none());
        assert!(parse_nmap_xml("").is_none());
        assert!(parse_nmap_xml("<broken>").is_none());
    }

    #[test]
    fn parse_nmap_xml_empty_hosts() {
        let result =
            parse_nmap_xml(NMAP_XML_NO_HOSTS).expect("should parse valid nmap XML with no hosts");

        let hosts = result["hosts"]
            .as_array()
            .expect("hosts should be an array");
        assert_eq!(hosts.len(), 0, "expected empty hosts array");
    }

    /// Requires nmap + passt + newuidmap. Run with: cargo test -p sigint-tools -- --ignored
    #[tokio::test]
    #[ignore]
    async fn nmap_executes_loopback_quick_scan() {
        let result = NmapTool
            .execute(json!({"target": "127.0.0.1", "scan_type": "quick"}))
            .await
            .expect("nmap execution should not error");
        // nmap on loopback always exits 0 even with no open ports.
        assert_eq!(
            result.exit_code, 0,
            "nmap should exit 0: {:?}",
            result.stderr
        );
        assert!(
            result.stdout.contains("Nmap scan report"),
            "stdout should contain scan report: {}",
            result.stdout
        );
    }
}
