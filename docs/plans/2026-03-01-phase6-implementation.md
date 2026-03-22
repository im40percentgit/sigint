# Phase 6: Hybrid — Parsers, Approval Gates, Web Scan — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add structured tool output parsing (nmap XML, nuclei JSONL), human-in-the-loop approval gates for risky tools, and web-triggered scans with bidirectional WebSocket.

**Architecture:** Tool parsers populate `structured_data` on `ToolResult` without changing the tool interface. Approval gates use `tokio::oneshot` channels keyed by UUID, managed by an `ApprovalRegistry` in sigint-core. The loop engine checks tool risk levels and blocks on approval for Medium/High tools. The web layer gains POST /api/scan (spawned task) and bidirectional WebSocket for approval routing.

**Tech Stack:** Rust, quick-xml (nmap XML parsing), tokio::sync::oneshot (approval channels), Axum 0.8, Preact + HTM (frontend)

---

## Sub-Phase 6A: Tool Output Parsers

### Task 1: Add quick-xml dependency

**Files:**
- Modify: `Cargo.toml` (workspace root, `[workspace.dependencies]` section)
- Modify: `crates/sigint-tools/Cargo.toml`

**Step 1: Add quick-xml to workspace dependencies**

In the workspace root `Cargo.toml`, add to `[workspace.dependencies]`:
```toml
quick-xml = "0.37"
```

In `crates/sigint-tools/Cargo.toml`, add:
```toml
quick-xml = { workspace = true }
```

**Step 2: Verify it compiles**

Run: `cargo check -p sigint-tools`
Expected: compiles without errors

**Step 3: Commit**

```bash
git add Cargo.toml crates/sigint-tools/Cargo.toml
git commit -m "chore: add quick-xml dependency for nmap XML parsing"
```

---

### Task 2: nmap XML parser

**Files:**
- Modify: `crates/sigint-tools/src/nmap.rs`

**Context:** Currently nmap runs with `-oN -` (human-readable text). We're switching to `-oX -` (XML to stdout) and parsing the XML into `structured_data`. The raw XML is preserved in `stdout` for LLM consumption.

**Step 1: Write failing tests for the XML parser**

Add these tests at the bottom of the `#[cfg(test)] mod tests` block in `crates/sigint-tools/src/nmap.rs`:

```rust
    #[test]
    fn parse_nmap_xml_single_host() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -oX - 93.184.216.34" start="1709300000">
  <host starttime="1709300001" endtime="1709300005">
    <status state="up" reason="echo-reply"/>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <hostnames><hostname name="example.com" type="PTR"/></hostnames>
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
  <runstats><finished time="1709300010" elapsed="9.50"/></runstats>
</nmaprun>"#;

        let parsed = parse_nmap_xml(xml).expect("should parse valid XML");
        let hosts = parsed["hosts"].as_array().unwrap();
        assert_eq!(hosts.len(), 1);

        let host = &hosts[0];
        assert_eq!(host["address"], "93.184.216.34");
        assert_eq!(host["hostnames"][0], "example.com");
        assert_eq!(host["status"], "up");

        let ports = host["ports"].as_array().unwrap();
        assert_eq!(ports.len(), 2);
        assert_eq!(ports[0]["port"], 80);
        assert_eq!(ports[0]["protocol"], "tcp");
        assert_eq!(ports[0]["state"], "open");
        assert_eq!(ports[0]["service"], "http");
        assert_eq!(ports[0]["version"], "nginx 1.25.3");
    }

    #[test]
    fn parse_nmap_xml_malformed_returns_none() {
        let bad_xml = "this is not xml at all";
        assert!(parse_nmap_xml(bad_xml).is_none());
    }

    #[test]
    fn parse_nmap_xml_empty_hosts() {
        let xml = r#"<?xml version="1.0"?>
<nmaprun scanner="nmap"><runstats><finished time="1" elapsed="0.1"/></runstats></nmaprun>"#;
        let parsed = parse_nmap_xml(xml).expect("should parse empty scan");
        let hosts = parsed["hosts"].as_array().unwrap();
        assert_eq!(hosts.len(), 0);
    }
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p sigint-tools -- parse_nmap_xml`
Expected: FAIL — `parse_nmap_xml` function does not exist

**Step 3: Implement the XML parser**

Add this function in `crates/sigint-tools/src/nmap.rs`, above the `NmapTool` struct:

```rust
use quick_xml::events::Event as XmlEvent;
use quick_xml::Reader;

/// Parse nmap XML output into structured JSON.
///
/// Returns `None` if the XML is malformed or unparseable.
/// The returned JSON has the shape:
/// ```json
/// { "hosts": [{ "address", "hostnames", "status", "ports": [{ "port", "protocol", "state", "service", "version" }] }] }
/// ```
fn parse_nmap_xml(xml: &str) -> Option<serde_json::Value> {
    let mut reader = Reader::from_str(xml);
    let mut hosts = Vec::new();

    // Current parsing state
    let mut in_host = false;
    let mut current_host: Option<serde_json::Map<String, serde_json::Value>> = None;
    let mut current_ports: Vec<serde_json::Value> = Vec::new();
    let mut current_hostnames: Vec<String> = Vec::new();

    loop {
        match reader.read_event() {
            Ok(XmlEvent::Start(ref e)) | Ok(XmlEvent::Empty(ref e)) => {
                let name = std::str::from_utf8(e.name().as_ref()).ok()?;
                match name {
                    "host" => {
                        in_host = true;
                        current_host = Some(serde_json::Map::new());
                        current_ports = Vec::new();
                        current_hostnames = Vec::new();
                    }
                    "address" if in_host => {
                        let mut addr = String::new();
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"addr" {
                                addr = String::from_utf8_lossy(&attr.value).to_string();
                            }
                        }
                        if let Some(ref mut h) = current_host {
                            h.insert("address".into(), serde_json::Value::String(addr));
                        }
                    }
                    "status" if in_host => {
                        let mut state = String::new();
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"state" {
                                state = String::from_utf8_lossy(&attr.value).to_string();
                            }
                        }
                        if let Some(ref mut h) = current_host {
                            h.insert("status".into(), serde_json::Value::String(state));
                        }
                    }
                    "hostname" if in_host => {
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"name" {
                                current_hostnames.push(
                                    String::from_utf8_lossy(&attr.value).to_string(),
                                );
                            }
                        }
                    }
                    "port" if in_host => {
                        let mut port_num: i64 = 0;
                        let mut protocol = String::new();
                        for attr in e.attributes().flatten() {
                            match attr.key.as_ref() {
                                b"portid" => {
                                    port_num = String::from_utf8_lossy(&attr.value)
                                        .parse()
                                        .unwrap_or(0);
                                }
                                b"protocol" => {
                                    protocol = String::from_utf8_lossy(&attr.value).to_string();
                                }
                                _ => {}
                            }
                        }
                        // We'll fill in state/service from child elements.
                        // Store port_num and protocol for now; push to current_ports on </port>.
                        // Use a temporary structure:
                        let port_obj = serde_json::json!({
                            "port": port_num,
                            "protocol": protocol,
                            "state": "",
                            "service": "",
                            "version": "",
                        });
                        current_ports.push(port_obj);
                    }
                    "state" if in_host && !current_ports.is_empty() => {
                        let mut state = String::new();
                        for attr in e.attributes().flatten() {
                            if attr.key.as_ref() == b"state" {
                                state = String::from_utf8_lossy(&attr.value).to_string();
                            }
                        }
                        if let Some(last) = current_ports.last_mut() {
                            last["state"] = serde_json::Value::String(state);
                        }
                    }
                    "service" if in_host && !current_ports.is_empty() => {
                        let mut svc_name = String::new();
                        let mut product = String::new();
                        let mut version = String::new();
                        for attr in e.attributes().flatten() {
                            match attr.key.as_ref() {
                                b"name" => {
                                    svc_name =
                                        String::from_utf8_lossy(&attr.value).to_string();
                                }
                                b"product" => {
                                    product =
                                        String::from_utf8_lossy(&attr.value).to_string();
                                }
                                b"version" => {
                                    version =
                                        String::from_utf8_lossy(&attr.value).to_string();
                                }
                                _ => {}
                            }
                        }
                        let version_str = if !product.is_empty() && !version.is_empty() {
                            format!("{} {}", product, version)
                        } else if !product.is_empty() {
                            product
                        } else {
                            version
                        };
                        if let Some(last) = current_ports.last_mut() {
                            last["service"] = serde_json::Value::String(svc_name);
                            last["version"] = serde_json::Value::String(version_str);
                        }
                    }
                    _ => {}
                }
            }
            Ok(XmlEvent::End(ref e)) => {
                let name = std::str::from_utf8(e.name().as_ref()).unwrap_or("");
                if name == "host" {
                    in_host = false;
                    if let Some(mut h) = current_host.take() {
                        h.insert(
                            "hostnames".into(),
                            serde_json::Value::Array(
                                current_hostnames
                                    .drain(..)
                                    .map(serde_json::Value::String)
                                    .collect(),
                            ),
                        );
                        h.insert(
                            "ports".into(),
                            serde_json::Value::Array(current_ports.drain(..).collect()),
                        );
                        hosts.push(serde_json::Value::Object(h));
                    }
                }
            }
            Ok(XmlEvent::Eof) => break,
            Err(_) => return None,
            _ => {}
        }
    }

    Some(serde_json::json!({ "hosts": hosts }))
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test -p sigint-tools -- parse_nmap_xml`
Expected: 3 tests PASS

**Step 5: Switch nmap to XML output and wire parser**

In `crates/sigint-tools/src/nmap.rs`, in the `execute()` method, replace:
```rust
        // Write normal-format output to stdout for easy LLM consumption.
        cmd = cmd.arg("-oN").arg("-");
```
with:
```rust
        // Write XML output to stdout for structured parsing.
        cmd = cmd.arg("-oX").arg("-");
```

And replace:
```rust
        Ok(ToolResult {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.exit_code,
            duration: output.duration,
            structured_data: None,
        })
```
with:
```rust
        let structured_data = parse_nmap_xml(&output.stdout);
        Ok(ToolResult {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.exit_code,
            duration: output.duration,
            structured_data,
        })
```

Also update the `@decision` doc comment at the top of the file: change `The \`-oN -\` flag writes normal-format output` to `The \`-oX -\` flag writes XML output to stdout for structured parsing. The parse_nmap_xml() function extracts hosts, ports, services, and versions into structured_data JSON.`

**Step 6: Run full test suite**

Run: `cargo test -p sigint-tools`
Expected: all existing tests PASS (the ignored integration test may need `-oX` adjustment)

**Step 7: Commit**

```bash
git add crates/sigint-tools/src/nmap.rs
git commit -m "feat(tools): parse nmap XML output into structured_data"
```

---

### Task 3: nuclei JSONL parser

**Files:**
- Modify: `crates/sigint-tools/src/nuclei.rs`

**Context:** Currently nuclei runs with `-silent -nc`. We're adding `-jsonl` to get JSON lines output. Each line is a JSON finding object. We parse all lines into an aggregated `structured_data`.

**Step 1: Write failing tests for the JSONL parser**

Add these tests at the bottom of the `#[cfg(test)] mod tests` block in `crates/sigint-tools/src/nuclei.rs`:

```rust
    #[test]
    fn parse_nuclei_jsonl_multiple_findings() {
        let jsonl = r#"{"template-id":"cve-2021-44228","info":{"name":"Log4Shell","severity":"critical"},"matched-at":"http://example.com/api","type":"http"}
{"template-id":"tech-detect:nginx","info":{"name":"Nginx Detection","severity":"info"},"matched-at":"http://example.com","type":"http"}
{"template-id":"exposed-panels:phpmyadmin","info":{"name":"phpMyAdmin Panel","severity":"medium"},"matched-at":"http://example.com/phpmyadmin","type":"http"}"#;

        let parsed = parse_nuclei_jsonl(jsonl).expect("should parse valid JSONL");

        assert_eq!(parsed["total"], 3);
        let findings = parsed["findings"].as_array().unwrap();
        assert_eq!(findings.len(), 3);

        assert_eq!(findings[0]["template_id"], "cve-2021-44228");
        assert_eq!(findings[0]["name"], "Log4Shell");
        assert_eq!(findings[0]["severity"], "critical");
        assert_eq!(findings[0]["matched_at"], "http://example.com/api");

        // Severity counts
        assert_eq!(parsed["by_severity"]["critical"], 1);
        assert_eq!(parsed["by_severity"]["info"], 1);
        assert_eq!(parsed["by_severity"]["medium"], 1);
    }

    #[test]
    fn parse_nuclei_jsonl_empty_output() {
        let parsed = parse_nuclei_jsonl("");
        assert!(parsed.is_none());
    }

    #[test]
    fn parse_nuclei_jsonl_malformed_lines_skipped() {
        let jsonl = r#"{"template-id":"valid","info":{"name":"Test","severity":"low"},"matched-at":"http://x","type":"http"}
this is not json
{"template-id":"also-valid","info":{"name":"Test2","severity":"high"},"matched-at":"http://y","type":"http"}"#;

        let parsed = parse_nuclei_jsonl(jsonl).expect("should parse with skipped lines");
        assert_eq!(parsed["total"], 2);
    }
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p sigint-tools -- parse_nuclei_jsonl`
Expected: FAIL — `parse_nuclei_jsonl` function does not exist

**Step 3: Implement the JSONL parser**

Add this function in `crates/sigint-tools/src/nuclei.rs`, above the `NucleiTool` struct:

```rust
use std::collections::HashMap;

/// Parse nuclei JSONL output into structured JSON.
///
/// Returns `None` if there are no valid findings at all.
/// The returned JSON has the shape:
/// ```json
/// { "findings": [{ "template_id", "name", "severity", "matched_at", "type" }], "total": N, "by_severity": { "critical": N, ... } }
/// ```
fn parse_nuclei_jsonl(output: &str) -> Option<serde_json::Value> {
    let mut findings = Vec::new();
    let mut severity_counts: HashMap<String, u64> = HashMap::new();

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(obj) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };

        let template_id = obj["template-id"].as_str().unwrap_or("").to_string();
        let name = obj["info"]["name"].as_str().unwrap_or("").to_string();
        let severity = obj["info"]["severity"].as_str().unwrap_or("unknown").to_string();
        let matched_at = obj["matched-at"].as_str().unwrap_or("").to_string();
        let finding_type = obj["type"].as_str().unwrap_or("").to_string();

        *severity_counts.entry(severity.clone()).or_insert(0) += 1;

        findings.push(serde_json::json!({
            "template_id": template_id,
            "name": name,
            "severity": severity,
            "matched_at": matched_at,
            "type": finding_type,
        }));
    }

    if findings.is_empty() {
        return None;
    }

    Some(serde_json::json!({
        "findings": findings,
        "total": findings.len(),
        "by_severity": severity_counts,
    }))
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test -p sigint-tools -- parse_nuclei_jsonl`
Expected: 3 tests PASS

**Step 5: Add -jsonl flag and wire parser**

In `crates/sigint-tools/src/nuclei.rs`, in the `execute()` method, after the `-nc` line:
```rust
        cmd = cmd.arg("-nc");
```

Add:
```rust
        // Enable JSONL output for structured parsing.
        cmd = cmd.arg("-jsonl");
```

And replace:
```rust
        Ok(ToolResult {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.exit_code,
            duration: output.duration,
            structured_data: None,
        })
```
with:
```rust
        let structured_data = parse_nuclei_jsonl(&output.stdout);
        Ok(ToolResult {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.exit_code,
            duration: output.duration,
            structured_data,
        })
```

Update the `@decision` doc comment to mention `-jsonl` flag and JSONL parsing.

**Step 6: Run full test suite**

Run: `cargo test -p sigint-tools`
Expected: all tests PASS

**Step 7: Commit**

```bash
git add crates/sigint-tools/src/nuclei.rs
git commit -m "feat(tools): parse nuclei JSONL output into structured_data"
```

---

## Sub-Phase 6B: Tool Approval Gate

### Task 4: Add ToolRisk enum to sigint-core

**Files:**
- Modify: `crates/sigint-core/src/types.rs`

**Step 1: Write the failing test**

Add at the bottom of `#[cfg(test)] mod tests` in `crates/sigint-core/src/types.rs`:

```rust
    #[test]
    fn tool_risk_serializes() {
        let json = serde_json::to_string(&ToolRisk::High).unwrap();
        assert_eq!(json, r#""high""#);
        let deserialized: ToolRisk = serde_json::from_str(r#""medium""#).unwrap();
        assert_eq!(deserialized, ToolRisk::Medium);
    }

    #[test]
    fn tool_risk_ordering() {
        // Low < Medium < High
        assert!(ToolRisk::Low < ToolRisk::Medium);
        assert!(ToolRisk::Medium < ToolRisk::High);
    }
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p sigint-core -- tool_risk`
Expected: FAIL — `ToolRisk` not found

**Step 3: Implement ToolRisk**

Add to `crates/sigint-core/src/types.rs`, after the `AssetChange` impl block (before `#[cfg(test)]`):

```rust
// ── Tool Risk ────────────────────────────────────────────────────────────────

/// Risk level for a tool, used by the approval gate to decide whether
/// human confirmation is required before execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolRisk {
    /// Info-gathering tools (nmap, dig, whois, curl).
    Low,
    /// Active scanning tools (gobuster, feroxbuster, nuclei).
    Medium,
    /// Exploitation tools (nikto, shell).
    High,
}

impl std::fmt::Display for ToolRisk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ToolRisk::Low => write!(f, "low"),
            ToolRisk::Medium => write!(f, "medium"),
            ToolRisk::High => write!(f, "high"),
        }
    }
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test -p sigint-core -- tool_risk`
Expected: 2 tests PASS

**Step 5: Commit**

```bash
git add crates/sigint-core/src/types.rs
git commit -m "feat(core): add ToolRisk enum for approval gate classification"
```

---

### Task 5: Add risk_level() to Tool trait

**Files:**
- Modify: `crates/sigint-tools/src/tool.rs`
- Modify: `crates/sigint-tools/src/nmap.rs`
- Modify: `crates/sigint-tools/src/nuclei.rs`
- Modify: `crates/sigint-tools/src/gobuster.rs`
- Modify: `crates/sigint-tools/src/nikto.rs`
- Modify: `crates/sigint-tools/src/feroxbuster.rs`
- Modify: `crates/sigint-tools/src/shell.rs`

**Step 1: Add risk_level() with default to Tool trait**

In `crates/sigint-tools/src/tool.rs`, add this import:
```rust
use sigint_core::types::ToolRisk;
```

Add this method to the `Tool` trait, after `fn definition()`:
```rust
    /// Risk level of this tool for the approval gate.
    /// Defaults to `ToolRisk::Low` (info-gathering).
    fn risk_level(&self) -> ToolRisk {
        ToolRisk::Low
    }
```

**Step 2: Override risk_level() on each tool**

In each file, add the `risk_level()` method to the `impl Tool for ...` block. The `use sigint_core::types::ToolRisk;` import is needed in each file.

- `nmap.rs` — `NmapTool`: `ToolRisk::Low` (default, no override needed)
- `nuclei.rs` — `NucleiTool`: `ToolRisk::Medium`
- `gobuster.rs` — `GobusterTool`: `ToolRisk::Medium`
- `feroxbuster.rs` — `FeroxbusterTool`: `ToolRisk::Medium`
- `nikto.rs` — `NiktoTool`: `ToolRisk::High`
- `shell.rs` — `ShellTool`: `ToolRisk::High`

For each Medium/High tool, add inside the `impl Tool for XxxTool` block:
```rust
    fn risk_level(&self) -> ToolRisk {
        ToolRisk::Medium  // or ToolRisk::High for nikto/shell
    }
```

**Step 3: Write tests**

Add to `crates/sigint-tools/src/tool.rs` tests:
```rust
    #[test]
    fn echo_tool_default_risk_is_low() {
        let t = EchoTool;
        assert_eq!(t.risk_level(), sigint_core::types::ToolRisk::Low);
    }
```

Add to `crates/sigint-tools/src/nmap.rs` tests:
```rust
    #[test]
    fn nmap_risk_level_is_low() {
        assert_eq!(NmapTool.risk_level(), sigint_core::types::ToolRisk::Low);
    }
```

Add to `crates/sigint-tools/src/nuclei.rs` tests:
```rust
    #[test]
    fn nuclei_risk_level_is_medium() {
        assert_eq!(NucleiTool.risk_level(), sigint_core::types::ToolRisk::Medium);
    }
```

Add to `crates/sigint-tools/src/nikto.rs` tests:
```rust
    #[test]
    fn nikto_risk_level_is_high() {
        assert_eq!(NiktoTool.risk_level(), sigint_core::types::ToolRisk::High);
    }
```

**Step 4: Run tests**

Run: `cargo test -p sigint-tools`
Expected: all tests PASS

**Step 5: Commit**

```bash
git add crates/sigint-tools/
git commit -m "feat(tools): add risk_level() to Tool trait with per-tool overrides"
```

---

### Task 6: Add approval events to Event enum

**Files:**
- Modify: `crates/sigint-core/src/event.rs`

**Step 1: Write the failing test**

Add to `#[cfg(test)] mod tests` in `crates/sigint-core/src/event.rs`:

```rust
    #[tokio::test]
    async fn approval_events_serialize() {
        use crate::types::ToolRisk;
        use uuid::Uuid;

        let req_id = Uuid::nil();
        let session_id = Uuid::nil();

        let event = Event::ToolApprovalRequested {
            request_id: req_id,
            session_id,
            tool_name: "nuclei_scan".into(),
            args: serde_json::json!({"target": "example.com"}),
            risk_level: ToolRisk::Medium,
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("ToolApprovalRequested"));
        assert!(json.contains("nuclei_scan"));

        let granted = Event::ToolApprovalGranted { request_id: req_id };
        let json2 = serde_json::to_string(&granted).unwrap();
        assert!(json2.contains("ToolApprovalGranted"));

        let denied = Event::ToolApprovalDenied {
            request_id: req_id,
            reason: Some("too risky".into()),
        };
        let json3 = serde_json::to_string(&denied).unwrap();
        assert!(json3.contains("too risky"));
    }
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p sigint-core -- approval_events`
Expected: FAIL — `ToolApprovalRequested` variant not found

**Step 3: Add the event variants**

In `crates/sigint-core/src/event.rs`, add these variants to the `Event` enum, after the `ReconCompleted` variant:

```rust
    // ── Approval Gate events ─────────────────────────────────────────────────
    /// A tool requires human approval before execution.
    ToolApprovalRequested {
        request_id: Uuid,
        session_id: Uuid,
        tool_name: String,
        args: serde_json::Value,
        risk_level: crate::types::ToolRisk,
    },
    /// Human approved the tool execution.
    ToolApprovalGranted { request_id: Uuid },
    /// Human denied the tool execution.
    ToolApprovalDenied { request_id: Uuid, reason: Option<String> },
```

**Step 4: Run tests**

Run: `cargo test -p sigint-core`
Expected: all tests PASS

**Step 5: Commit**

```bash
git add crates/sigint-core/src/event.rs
git commit -m "feat(core): add ToolApproval{Requested,Granted,Denied} events"
```

---

### Task 7: Implement ApprovalRegistry

**Files:**
- Create: `crates/sigint-core/src/approval.rs`
- Modify: `crates/sigint-core/src/lib.rs`

**Step 1: Write failing tests**

Create `crates/sigint-core/src/approval.rs` with tests only first:

```rust
//! ApprovalRegistry — manages pending tool approval requests.
//!
//! The loop engine creates a request (getting a oneshot Receiver), emits an
//! event, and awaits the receiver. The WebSocket handler (or TUI) calls
//! `respond()` with the request_id and a bool to approve/deny.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use tokio::sync::oneshot;
use uuid::Uuid;

/// Manages pending approval requests for tool execution.
pub struct ApprovalRegistry {
    pending: Mutex<HashMap<Uuid, oneshot::Sender<bool>>>,
    timeout: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn request_and_approve() {
        let registry = ApprovalRegistry::new(Duration::from_secs(5));
        let request_id = Uuid::new_v4();
        let rx = registry.request(request_id);

        // Respond from another task
        assert!(registry.respond(request_id, true).is_ok());
        assert_eq!(rx.await.unwrap(), true);
    }

    #[tokio::test]
    async fn request_and_deny() {
        let registry = ApprovalRegistry::new(Duration::from_secs(5));
        let request_id = Uuid::new_v4();
        let rx = registry.request(request_id);

        assert!(registry.respond(request_id, false).is_ok());
        assert_eq!(rx.await.unwrap(), false);
    }

    #[test]
    fn respond_to_unknown_request_returns_error() {
        let registry = ApprovalRegistry::new(Duration::from_secs(5));
        let result = registry.respond(Uuid::new_v4(), true);
        assert!(result.is_err());
    }

    #[test]
    fn pending_count_tracks_requests() {
        let registry = ApprovalRegistry::new(Duration::from_secs(5));
        assert_eq!(registry.pending_count(), 0);
        let _rx1 = registry.request(Uuid::new_v4());
        assert_eq!(registry.pending_count(), 1);
        let _rx2 = registry.request(Uuid::new_v4());
        assert_eq!(registry.pending_count(), 2);
    }

    #[tokio::test]
    async fn timeout_accessor() {
        let registry = ApprovalRegistry::new(Duration::from_secs(42));
        assert_eq!(registry.timeout(), Duration::from_secs(42));
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p sigint-core -- approval`
Expected: FAIL — methods not implemented

**Step 3: Implement ApprovalRegistry**

Add the implementation to the same file, between the struct and the `#[cfg(test)]`:

```rust
impl ApprovalRegistry {
    /// Create a new registry with the given approval timeout.
    pub fn new(timeout: Duration) -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
            timeout,
        }
    }

    /// Register a new approval request and return a receiver for the response.
    ///
    /// The caller should await this receiver (with a timeout). When `respond()`
    /// is called with the same `request_id`, the receiver resolves.
    pub fn request(&self, request_id: Uuid) -> oneshot::Receiver<bool> {
        let (tx, rx) = oneshot::channel();
        self.pending.lock().unwrap().insert(request_id, tx);
        rx
    }

    /// Respond to a pending approval request.
    ///
    /// Returns `Err` if the request_id is not found (already responded or expired).
    pub fn respond(&self, request_id: Uuid, approved: bool) -> Result<(), String> {
        let tx = self
            .pending
            .lock()
            .unwrap()
            .remove(&request_id)
            .ok_or_else(|| format!("No pending request with id {}", request_id))?;
        // If the receiver was dropped (timeout), send returns Err, but that's fine.
        let _ = tx.send(approved);
        Ok(())
    }

    /// Number of pending (unresolved) approval requests.
    pub fn pending_count(&self) -> usize {
        self.pending.lock().unwrap().len()
    }

    /// The configured timeout for approval requests.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}
```

**Step 4: Register module in lib.rs**

In `crates/sigint-core/src/lib.rs`, add:
```rust
pub mod approval;
```
and:
```rust
pub use approval::ApprovalRegistry;
```

**Step 5: Run tests**

Run: `cargo test -p sigint-core -- approval`
Expected: 5 tests PASS

**Step 6: Commit**

```bash
git add crates/sigint-core/src/approval.rs crates/sigint-core/src/lib.rs
git commit -m "feat(core): implement ApprovalRegistry with oneshot channels"
```

---

### Task 8: Add agent config for auto_approve

**Files:**
- Modify: `crates/sigint-core/src/config.rs`

**Step 1: Write failing test**

Add to `#[cfg(test)] mod tests` in `crates/sigint-core/src/config.rs`:

```rust
    #[test]
    fn agent_config_defaults() {
        let cfg = Config::default();
        assert_eq!(cfg.agent.auto_approve, "low");
        assert_eq!(cfg.agent.approval_timeout, 300);
    }

    #[test]
    fn agent_config_from_toml() {
        let toml_str = r#"
[agent]
auto_approve = "all"
approval_timeout = 60
"#;
        let cfg: Config = toml::from_str(toml_str).expect("parse failed");
        assert_eq!(cfg.agent.auto_approve, "all");
        assert_eq!(cfg.agent.approval_timeout, 60);
    }
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p sigint-core -- agent_config`
Expected: FAIL — `cfg.agent` field doesn't exist

**Step 3: Implement AgentConfig**

In `crates/sigint-core/src/config.rs`, add to the `Config` struct:
```rust
    /// Agent behavior settings.
    #[serde(default)]
    pub agent: AgentConfig,
```

Add the `AgentConfig` struct after `LogConfig`:
```rust
/// Agent execution behavior.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Auto-approve threshold: "none", "low", "medium", "all".
    /// Tools at or below this risk level run without human approval.
    #[serde(default = "default_auto_approve")]
    pub auto_approve: String,

    /// Timeout in seconds for waiting on human approval.
    #[serde(default = "default_approval_timeout")]
    pub approval_timeout: u64,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            auto_approve: default_auto_approve(),
            approval_timeout: default_approval_timeout(),
        }
    }
}

fn default_auto_approve() -> String { "low".into() }
fn default_approval_timeout() -> u64 { 300 }
```

**Step 4: Run tests**

Run: `cargo test -p sigint-core -- agent_config`
Expected: 2 tests PASS

**Step 5: Commit**

```bash
git add crates/sigint-core/src/config.rs
git commit -m "feat(core): add AgentConfig with auto_approve and approval_timeout"
```

---

### Task 9: Integrate approval gate into loop engine

**Files:**
- Modify: `crates/sigint-agents/src/loop_engine.rs`
- Modify: `crates/sigint-agents/Cargo.toml` (if needed for uuid)

**Context:** This is the critical change. The `run_tool_loop` function gains two new parameters: `approval_registry` and `auto_approve`. Before executing a tool, it checks the tool's risk level against the auto_approve threshold and either executes immediately or blocks on approval.

**Step 1: Write failing tests**

Add to the tests module in `crates/sigint-agents/src/loop_engine.rs`:

```rust
    use sigint_core::approval::ApprovalRegistry;
    use sigint_core::types::ToolRisk;

    struct HighRiskTool;

    #[async_trait]
    impl Tool for HighRiskTool {
        fn name(&self) -> &str { "dangerous_tool" }
        fn description(&self) -> &str { "a risky tool" }
        fn definition(&self) -> sigint_llm::ToolDefinition {
            sigint_llm::ToolDefinition::function(
                "dangerous_tool", "a risky tool",
                json!({ "type": "object", "properties": {} }),
            )
        }
        fn risk_level(&self) -> ToolRisk { ToolRisk::High }
        async fn execute(&self, _args: Value) -> sigint_tools::error::Result<ToolResult> {
            Ok(ToolResult {
                stdout: "executed".into(),
                stderr: String::new(),
                exit_code: 0,
                duration: Duration::from_millis(10),
                structured_data: None,
            })
        }
    }

    #[tokio::test]
    async fn low_risk_auto_approved() {
        // Low-risk tool with auto_approve="low" should execute without blocking
        let tool = MockTool::success("nmap_scan", "scan results");
        let tool_def = tool.definition();
        let tool_ref: &dyn Tool = &tool;

        let registry = Arc::new(ApprovalRegistry::new(Duration::from_secs(1)));
        let provider = MockProvider::new(vec![
            MockProvider::tool_response("nmap_scan", json!({"target": "10.0.0.1"})),
            MockProvider::text_response("Done."),
        ]);

        let mut state = make_state();
        let bus = EventBus::new();

        let result = run_tool_loop(
            &provider, &mut state, &[tool_ref], &[tool_def],
            5, "mock", &bus, Some(&registry), "low",
        ).await.unwrap();

        assert_eq!(result, "Done.");
    }

    #[tokio::test]
    async fn high_risk_tool_approved_via_registry() {
        let tool = HighRiskTool;
        let tool_def = tool.definition();
        let tool_ref: &dyn Tool = &tool;

        let registry = Arc::new(ApprovalRegistry::new(Duration::from_secs(5)));
        let provider = MockProvider::new(vec![
            MockProvider::tool_response("dangerous_tool", json!({})),
            MockProvider::text_response("Executed."),
        ]);

        let mut state = make_state();
        let bus = EventBus::new();

        // Spawn a task that approves the request
        let reg_clone = registry.clone();
        let mut rx = bus.subscribe();
        tokio::spawn(async move {
            loop {
                if let Ok(Event::ToolApprovalRequested { request_id, .. }) = rx.recv().await {
                    reg_clone.respond(request_id, true).unwrap();
                    break;
                }
            }
        });

        let result = run_tool_loop(
            &provider, &mut state, &[tool_ref], &[tool_def],
            5, "mock", &bus, Some(&registry), "low",
        ).await.unwrap();

        assert_eq!(result, "Executed.");
    }

    #[tokio::test]
    async fn high_risk_tool_denied_returns_error_to_llm() {
        let tool = HighRiskTool;
        let tool_def = tool.definition();
        let tool_ref: &dyn Tool = &tool;

        let registry = Arc::new(ApprovalRegistry::new(Duration::from_secs(5)));
        let provider = MockProvider::new(vec![
            MockProvider::tool_response("dangerous_tool", json!({})),
            MockProvider::text_response("Tool was denied."),
        ]);

        let mut state = make_state();
        let bus = EventBus::new();

        // Spawn a task that denies the request
        let reg_clone = registry.clone();
        let mut rx = bus.subscribe();
        tokio::spawn(async move {
            loop {
                if let Ok(Event::ToolApprovalRequested { request_id, .. }) = rx.recv().await {
                    reg_clone.respond(request_id, false).unwrap();
                    break;
                }
            }
        });

        let result = run_tool_loop(
            &provider, &mut state, &[tool_ref], &[tool_def],
            5, "mock", &bus, Some(&registry), "low",
        ).await.unwrap();

        assert_eq!(result, "Tool was denied.");
        // Verify the denial message was fed back to the LLM
        let msgs = state.to_chat_messages();
        let tool_msg = msgs.iter().find(|m| m.role == "tool").unwrap();
        assert!(tool_msg.content.contains("denied"), "msg: {}", tool_msg.content);
    }
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p sigint-agents -- high_risk`
Expected: FAIL — `run_tool_loop` signature doesn't accept approval parameters

**Step 3: Modify run_tool_loop signature and add approval logic**

Update the `run_tool_loop` function signature in `crates/sigint-agents/src/loop_engine.rs`:

```rust
pub async fn run_tool_loop(
    provider: &dyn LlmProvider,
    state: &mut crate::state::ConversationState,
    tools: &[&dyn Tool],
    tool_defs: &[ToolDefinition],
    max_iterations: usize,
    model: &str,
    event_bus: &EventBus,
    approval_registry: Option<&sigint_core::ApprovalRegistry>,
    auto_approve: &str,
) -> Result<String, Error> {
```

Add these imports at the top:
```rust
use uuid::Uuid;
use sigint_core::types::ToolRisk;
```

Add this helper function above `run_tool_loop`:
```rust
/// Check if a tool's risk level is auto-approved by the config threshold.
fn is_auto_approved(risk: ToolRisk, threshold: &str) -> bool {
    match threshold {
        "all" => true,
        "none" => false,
        "medium" => risk <= ToolRisk::Medium,
        "low" => risk <= ToolRisk::Low,
        _ => risk <= ToolRisk::Low, // default to "low"
    }
}
```

Then, in the tool execution block (inside `Some(tool) => {`), before `let started = Instant::now();`, add the approval check:

```rust
                    // ── Approval gate ────────────────────────────────
                    let risk = tool.risk_level();
                    if !is_auto_approved(risk, auto_approve) {
                        if let Some(registry) = approval_registry {
                            let request_id = Uuid::new_v4();
                            let rx = registry.request(request_id);

                            event_bus.emit(Event::ToolApprovalRequested {
                                request_id,
                                session_id: Uuid::nil(), // session context not available here
                                tool_name: name.clone(),
                                args: args.clone(),
                                risk_level: risk,
                            });

                            let timeout_dur = registry.timeout();
                            match tokio::time::timeout(timeout_dur, rx).await {
                                Ok(Ok(true)) => {
                                    event_bus.emit(Event::ToolApprovalGranted { request_id });
                                    // Proceed to execution below
                                }
                                Ok(Ok(false)) => {
                                    event_bus.emit(Event::ToolApprovalDenied {
                                        request_id,
                                        reason: None,
                                    });
                                    state.add_message(ChatMessage::tool(
                                        format!("Tool '{}' execution denied by operator.", name),
                                    ));
                                    continue;
                                }
                                Ok(Err(_)) => {
                                    // Sender dropped
                                    state.add_message(ChatMessage::tool(
                                        format!("Tool '{}' approval cancelled.", name),
                                    ));
                                    continue;
                                }
                                Err(_) => {
                                    // Timeout
                                    state.add_message(ChatMessage::tool(
                                        format!("Tool '{}' approval timed out after {}s.", name, timeout_dur.as_secs()),
                                    ));
                                    continue;
                                }
                            }
                        }
                        // If no registry provided, skip approval (legacy mode)
                    }
```

**Step 4: Update all existing call sites**

The existing tests call `run_tool_loop` with the old signature. Update them to add `None, "all"` as the last two parameters (no approval, auto-approve everything):

In `crates/sigint-agents/src/loop_engine.rs` tests, for every `run_tool_loop(...)` call, add `, None, "all"` before the closing `)`.

Also update any callers in other files. Check `crates/sigint-agents/src/orchestrator.rs` or wherever `run_tool_loop` is called — add the two new parameters there too. For now, pass `None, "all"` to preserve existing behavior.

**Step 5: Run tests**

Run: `cargo test -p sigint-agents`
Expected: all tests PASS (old and new)

**Step 6: Run workspace check**

Run: `cargo check --workspace`
Expected: compiles — callers updated

**Step 7: Commit**

```bash
git add crates/sigint-agents/
git commit -m "feat(agents): integrate approval gate into tool execution loop"
```

---

### Task 10: Register all executor tools in a shared function

**Files:**
- Modify: `crates/sigint-tools/src/lib.rs`

**Context:** Currently `sigint-cli/src/scan.rs` only registers NmapTool and ShellTool. The executor agent expects 6 tools. We extract a shared registration function.

**Step 1: Write the test**

In `crates/sigint-tools/src/lib.rs`, add a test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_all_tools_registers_six() {
        let mut registry = ToolRegistry::new();
        register_all_executor_tools(&mut registry);
        assert_eq!(registry.len(), 6);
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p sigint-tools -- register_all`
Expected: FAIL — `register_all_executor_tools` and `ToolRegistry` not found

**Step 3: Implement**

First, check if `ToolRegistry` exists. If not, add a simple one. Based on the codebase, the tool registry is likely in sigint-agents or the orchestrator. If `ToolRegistry` doesn't exist in sigint-tools, we create a minimal one:

Add to `crates/sigint-tools/src/lib.rs`:

```rust
use std::collections::HashMap;

/// Simple tool registry mapping tool names to implementations.
pub struct ToolRegistry {
    tools: HashMap<String, Box<dyn Tool>>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self { tools: HashMap::new() }
    }

    pub fn register(&mut self, tool: impl Tool + 'static) {
        self.tools.insert(tool.name().to_string(), Box::new(tool));
    }

    pub fn get(&self, name: &str) -> Option<&dyn Tool> {
        self.tools.get(name).map(|t| t.as_ref())
    }

    pub fn len(&self) -> usize {
        self.tools.len()
    }

    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }

    pub fn tools(&self) -> Vec<&dyn Tool> {
        self.tools.values().map(|t| t.as_ref()).collect()
    }
}

/// Register all standard executor tools into the given registry.
pub fn register_all_executor_tools(registry: &mut ToolRegistry) {
    registry.register(NmapTool);
    registry.register(ShellTool);
    registry.register(GobusterTool);
    registry.register(NiktoTool);
    registry.register(NucleiTool);
    registry.register(FeroxbusterTool);
}
```

NOTE: If a `ToolRegistry` already exists in another crate, reuse it instead and just add the `register_all_executor_tools` function. Check `crates/sigint-agents/` for an existing registry.

**Step 4: Run tests**

Run: `cargo test -p sigint-tools -- register_all`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/sigint-tools/src/lib.rs
git commit -m "feat(tools): add ToolRegistry and register_all_executor_tools()"
```

---

## Sub-Phase 6C: Bidirectional WebSocket + Web Scan

### Task 11: Expand AppState with config and approval_registry

**Files:**
- Modify: `crates/sigint-web/src/state.rs`
- Modify: `crates/sigint-web/src/lib.rs` (update `serve` signature)

**Step 1: Update AppState**

In `crates/sigint-web/src/state.rs`:

```rust
use sigint_core::approval::ApprovalRegistry;
use sigint_core::config::Config;
use sigint_core::event::EventBus;
use sigint_store::Database;
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Database>,
    pub event_bus: EventBus,
    pub config: Arc<Config>,
    pub approval_registry: Arc<ApprovalRegistry>,
}
```

**Step 2: Update serve() in lib.rs**

Update the `serve` function signature and body:
```rust
pub async fn serve(
    db: Database,
    event_bus: EventBus,
    config: Config,
    addr: std::net::SocketAddr,
) -> Result<(), sigint_core::Error> {
    let approval_timeout = std::time::Duration::from_secs(config.agent.approval_timeout);
    let state = AppState {
        db: Arc::new(db),
        event_bus,
        config: Arc::new(config),
        approval_registry: Arc::new(ApprovalRegistry::new(approval_timeout)),
    };
```

Add the imports:
```rust
use sigint_core::approval::ApprovalRegistry;
use sigint_core::config::Config;
```

**Step 3: Update test helpers in routes.rs**

In `crates/sigint-web/src/routes.rs` tests, update `test_state()`:
```rust
    fn test_state() -> AppState {
        let db = Database::open_in_memory().expect("in-memory db");
        let event_bus = EventBus::new();
        let config = sigint_core::Config::default();
        let registry = sigint_core::ApprovalRegistry::new(std::time::Duration::from_secs(5));
        AppState {
            db: Arc::new(db),
            event_bus,
            config: Arc::new(config),
            approval_registry: Arc::new(registry),
        }
    }
```

**Step 4: Update serve caller in sigint-cli**

In `crates/sigint-cli/src/serve.rs`, update the call to `sigint_web::serve()` to pass the config.

**Step 5: Run tests**

Run: `cargo test -p sigint-web`
Expected: all existing tests PASS

Run: `cargo check --workspace`
Expected: compiles

**Step 6: Commit**

```bash
git add crates/sigint-web/ crates/sigint-cli/src/serve.rs
git commit -m "feat(web): expand AppState with config and approval_registry"
```

---

### Task 12: Make WebSocket bidirectional

**Files:**
- Modify: `crates/sigint-web/src/ws.rs`

**Step 1: Write failing test**

Add to `crates/sigint-web/src/ws.rs` (or to routes.rs tests if WebSocket testing requires an integration approach):

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_client_command_approve() {
        let msg = r#"{"type": "approve", "request_id": "00000000-0000-0000-0000-000000000001"}"#;
        let cmd = parse_client_command(msg).unwrap();
        assert!(matches!(cmd, ClientCommand::Approve { .. }));
    }

    #[test]
    fn parse_client_command_deny() {
        let msg = r#"{"type": "deny", "request_id": "00000000-0000-0000-0000-000000000001", "reason": "too risky"}"#;
        let cmd = parse_client_command(msg).unwrap();
        assert!(matches!(cmd, ClientCommand::Deny { .. }));
    }

    #[test]
    fn parse_client_command_unknown_returns_none() {
        let msg = r#"{"type": "unknown_stuff"}"#;
        assert!(parse_client_command(msg).is_none());
    }

    #[test]
    fn parse_client_command_invalid_json_returns_none() {
        assert!(parse_client_command("not json").is_none());
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p sigint-web -- parse_client`
Expected: FAIL — functions don't exist

**Step 3: Implement bidirectional WebSocket**

Replace the contents of `crates/sigint-web/src/ws.rs`:

```rust
//! WebSocket event bridge — streams domain events and receives commands.
//!
//! Clients connect to `GET /ws/events` and:
//! - Receive JSON-serialized `Event` variants (server → client)
//! - Send JSON commands like approve/deny (client → server)
//!
//! @decision DEC-WEB-003
//! @title Bidirectional WebSocket with select! for approval routing
//! @status accepted
//! @rationale Tool approval requires round-trip communication. The server
//! emits ToolApprovalRequested events; the client responds with approve/deny
//! commands that route to the ApprovalRegistry via oneshot channels.

use axum::{
    extract::{State, WebSocketUpgrade},
    response::IntoResponse,
};
use axum::extract::ws::{Message, WebSocket};
use serde::Deserialize;
use tokio::sync::broadcast::error::RecvError;
use uuid::Uuid;

use crate::state::AppState;

/// Upgrade handler: accepts the WebSocket handshake and spawns the event loop.
pub async fn ws_events(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

/// Client commands sent via WebSocket.
#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum ClientCommand {
    Approve { request_id: Uuid },
    Deny { request_id: Uuid, reason: Option<String> },
}

/// Parse a client message into a command. Returns None for unknown/invalid messages.
fn parse_client_command(text: &str) -> Option<ClientCommand> {
    serde_json::from_str(text).ok()
}

/// Handle an incoming client command (approve/deny).
async fn handle_client_message(msg: Message, state: &AppState) {
    let text = match msg {
        Message::Text(t) => t,
        _ => return, // Ignore binary, ping, pong, close
    };

    let Some(cmd) = parse_client_command(&text) else {
        tracing::debug!("ws: ignoring unrecognized client message");
        return;
    };

    match cmd {
        ClientCommand::Approve { request_id } => {
            if let Err(e) = state.approval_registry.respond(request_id, true) {
                tracing::warn!("ws: approve failed: {}", e);
            }
        }
        ClientCommand::Deny { request_id, reason: _ } => {
            if let Err(e) = state.approval_registry.respond(request_id, false) {
                tracing::warn!("ws: deny failed: {}", e);
            }
        }
    }
}

/// Per-connection event loop: sends events and receives commands via select!.
async fn handle_socket(mut socket: WebSocket, state: AppState) {
    let mut rx = state.event_bus.subscribe();

    loop {
        tokio::select! {
            event_result = rx.recv() => {
                match event_result {
                    Ok(event) => {
                        let json = match serde_json::to_string(&event) {
                            Ok(j) => j,
                            Err(e) => {
                                tracing::warn!("ws: failed to serialize event: {}", e);
                                continue;
                            }
                        };
                        if socket.send(Message::Text(json.into())).await.is_err() {
                            break; // Client disconnected
                        }
                    }
                    Err(RecvError::Lagged(n)) => {
                        tracing::warn!("ws: client lagged, skipped {} events", n);
                    }
                    Err(RecvError::Closed) => {
                        break; // Server shutting down
                    }
                }
            }
            msg_result = socket.recv() => {
                match msg_result {
                    Some(Ok(msg)) => {
                        handle_client_message(msg, &state).await;
                    }
                    Some(Err(e)) => {
                        tracing::warn!("ws: receive error: {}", e);
                        break;
                    }
                    None => {
                        break; // Client disconnected
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_client_command_approve() {
        let msg = r#"{"type": "approve", "request_id": "00000000-0000-0000-0000-000000000001"}"#;
        let cmd = parse_client_command(msg).unwrap();
        assert!(matches!(cmd, ClientCommand::Approve { .. }));
    }

    #[test]
    fn parse_client_command_deny() {
        let msg = r#"{"type": "deny", "request_id": "00000000-0000-0000-0000-000000000001", "reason": "too risky"}"#;
        let cmd = parse_client_command(msg).unwrap();
        assert!(matches!(cmd, ClientCommand::Deny { .. }));
    }

    #[test]
    fn parse_client_command_unknown_returns_none() {
        let msg = r#"{"type": "unknown_stuff"}"#;
        assert!(parse_client_command(msg).is_none());
    }

    #[test]
    fn parse_client_command_invalid_json_returns_none() {
        assert!(parse_client_command("not json").is_none());
    }
}
```

**Step 4: Run tests**

Run: `cargo test -p sigint-web`
Expected: all tests PASS

**Step 5: Commit**

```bash
git add crates/sigint-web/src/ws.rs
git commit -m "feat(web): bidirectional WebSocket with approval command routing"
```

---

### Task 13: POST /api/scan endpoint

**Files:**
- Modify: `crates/sigint-web/src/routes.rs`
- Modify: `crates/sigint-web/src/lib.rs` (add route)
- Modify: `crates/sigint-web/Cargo.toml` (add sigint-llm, sigint-tools, sigint-agents deps)

**Step 1: Add dependencies**

In `crates/sigint-web/Cargo.toml`, add:
```toml
sigint-llm = { workspace = true }
sigint-tools = { workspace = true }
sigint-agents = { workspace = true }
```

**Step 2: Write failing test**

Add to `crates/sigint-web/src/routes.rs` tests:

```rust
    #[tokio::test]
    async fn scan_missing_target_returns_400() {
        let app = create_router(test_state());
        let req = Request::builder()
            .method("POST")
            .uri("/api/scan")
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn scan_with_target_returns_201() {
        let app = create_router(test_state());
        let req = Request::builder()
            .method("POST")
            .uri("/api/scan")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"target": "example.com"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = body_string(resp.into_body()).await;
        let v: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(v["session_id"].is_string(), "should return session_id");
    }
```

**Step 3: Run tests to verify they fail**

Run: `cargo test -p sigint-web -- scan_`
Expected: FAIL — no POST /api/scan route

**Step 4: Implement the handler**

Add to `crates/sigint-web/src/routes.rs`:

```rust
/// Request body for POST /api/scan.
#[derive(Debug, Deserialize)]
pub struct ScanRequest {
    pub target: Option<String>,
    pub model: Option<String>,
}

/// `POST /api/scan` — start a new scan, return session_id immediately.
pub async fn start_scan(
    State(state): State<AppState>,
    Json(body): Json<ScanRequest>,
) -> ApiResult<impl IntoResponse> {
    let target = body.target.ok_or_else(|| {
        (StatusCode::BAD_REQUEST, "Missing required field: target".to_string())
    })?;

    // Create session in DB
    let session = sigint_core::types::Session::new(format!("scan-{}", &target))
        .with_target(&target);
    state.db.create_session(&session).map_err(internal)?;

    let session_id = session.id;

    // Emit session created event
    state.event_bus.emit(sigint_core::event::Event::SessionCreated(session));

    // Note: The actual scan orchestration (building provider, tool registry,
    // spawning the scan task) requires the full Orchestrator which depends on
    // the LLM provider being reachable. For now, we create the session and
    // return the ID. Full orchestration wiring is a follow-up that depends
    // on how the CLI scan.rs is refactored to share code with the web layer.

    Ok((
        StatusCode::CREATED,
        Json(serde_json::json!({ "session_id": session_id.to_string() })),
    ))
}
```

**Step 5: Wire the route in lib.rs**

In `crates/sigint-web/src/lib.rs`, add the route:
```rust
        .route("/api/scan", axum::routing::post(routes::start_scan))
```

Add `routing::post` to the axum import if not present.

**Step 6: Run tests**

Run: `cargo test -p sigint-web`
Expected: all tests PASS

**Step 7: Commit**

```bash
git add crates/sigint-web/
git commit -m "feat(web): add POST /api/scan endpoint with session creation"
```

---

## Sub-Phase 6D: TUI Approval + Frontend Update

### Task 14: TUI approval prompt state

**Files:**
- Modify: `crates/sigint-tui/src/state.rs`

**Context:** Check the current TUI state structure first. The approval prompt needs a field to hold the pending request and a method to accept/deny.

**Step 1: Read the TUI state file**

Read `crates/sigint-tui/src/state.rs` to understand the current `AppState` structure.

**Step 2: Add approval fields**

Add to the TUI `AppState` struct (the field names and types depend on what's already there):

```rust
    /// Pending tool approval request, if any.
    pub pending_approval: Option<PendingApproval>,
```

Add the struct:
```rust
/// A tool execution awaiting human approval in the TUI.
pub struct PendingApproval {
    pub request_id: uuid::Uuid,
    pub tool_name: String,
    pub args_summary: String,
    pub risk_level: sigint_core::types::ToolRisk,
}
```

**Step 3: Write test**

```rust
    #[test]
    fn pending_approval_default_is_none() {
        let state = AppState::new(/* appropriate args */);
        assert!(state.pending_approval.is_none());
    }
```

**Step 4: Run tests**

Run: `cargo test -p sigint-tui`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/sigint-tui/
git commit -m "feat(tui): add pending_approval state for tool approval prompts"
```

---

### Task 15: TUI approval event handling

**Files:**
- Modify: TUI event handler (location depends on codebase — likely `crates/sigint-tui/src/app.rs` or `crates/sigint-tui/src/ui.rs`)

**Context:** When `Event::ToolApprovalRequested` is received, set `pending_approval`. When user presses `y`, emit `ToolApprovalGranted`. When `n`, emit `ToolApprovalDenied`.

**Step 1: Read the TUI event handling code**

Read the TUI's event loop to understand how events are processed and how keyboard input is handled.

**Step 2: Add event handling**

In the event match block, add:
```rust
Event::ToolApprovalRequested { request_id, tool_name, args, risk_level, .. } => {
    let summary = serde_json::to_string(&args).unwrap_or_default();
    let summary = if summary.len() > 80 { format!("{}...", &summary[..80]) } else { summary };
    state.pending_approval = Some(PendingApproval {
        request_id,
        tool_name,
        args_summary: summary,
        risk_level,
    });
}
```

In the keyboard input handler, when `pending_approval.is_some()`:
```rust
KeyCode::Char('y') if state.pending_approval.is_some() => {
    let approval = state.pending_approval.take().unwrap();
    event_bus.emit(Event::ToolApprovalGranted { request_id: approval.request_id });
    // Also call approval_registry.respond() if the registry is accessible
}
KeyCode::Char('n') if state.pending_approval.is_some() => {
    let approval = state.pending_approval.take().unwrap();
    event_bus.emit(Event::ToolApprovalDenied {
        request_id: approval.request_id,
        reason: Some("Denied by operator".into()),
    });
}
```

**Step 3: Add rendering**

In the UI render function, when `state.pending_approval.is_some()`, render a prompt bar:
```
[APPROVAL] Run {tool_name} ({risk_level})? {args_summary} [y/n]
```

**Step 4: Run tests**

Run: `cargo test -p sigint-tui`
Expected: PASS

**Step 5: Commit**

```bash
git add crates/sigint-tui/
git commit -m "feat(tui): handle tool approval events with y/n keyboard prompt"
```

---

### Task 16: Frontend — scan launch button

**Files:**
- Modify: `web/src/components/Dashboard.js`
- Modify: `web/src/api.js`

**Step 1: Add API function**

In `web/src/api.js`, add:
```javascript
export async function startScan(target, model) {
  const resp = await fetch(`${BASE}/api/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target, model: model || undefined }),
  });
  if (!resp.ok) throw new Error(await resp.text());
  return resp.json();
}
```

**Step 2: Add scan form to Dashboard**

In `web/src/components/Dashboard.js`, add a form with a target input and "Start Scan" button. On submit, call `startScan(target)` and navigate to the ScanView for the returned session_id.

**Step 3: Build frontend**

Run: `cd web && npm run build`
Expected: builds to `crates/sigint-web/static/`

**Step 4: Commit**

```bash
git add web/ crates/sigint-web/static/
git commit -m "feat(frontend): add scan launch button to Dashboard"
```

---

### Task 17: Frontend — approval modal

**Files:**
- Modify: `web/src/components/ScanView.js`
- Modify: `web/src/ws.js`

**Step 1: Add WS command sending**

In `web/src/ws.js`, add:
```javascript
export function sendCommand(ws, command) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(command));
  }
}
```

**Step 2: Add approval modal to ScanView**

In `web/src/components/ScanView.js`, add state tracking for approval requests. When a `ToolApprovalRequested` event arrives via WebSocket:
- Show a modal with tool name, args, and risk level badge
- Risk color: Low=green, Medium=yellow/amber, High=red
- "Approve" button sends `{ type: "approve", request_id: "..." }` via WS
- "Deny" button sends `{ type: "deny", request_id: "..." }` via WS

**Step 3: Build frontend**

Run: `cd web && npm run build`

**Step 4: Commit**

```bash
git add web/ crates/sigint-web/static/
git commit -m "feat(frontend): add tool approval modal to ScanView"
```

---

### Task 18: Full workspace test

**Files:** None (verification only)

**Step 1: Run all tests**

Run: `cargo test --workspace`
Expected: All Phase 6 tests pass. Pre-existing sandbox failures (3) are expected.

**Step 2: Count new tests**

Run: `cargo test --workspace 2>&1 | grep "test result"`
Verify new test counts per crate.

**Step 3: Manual smoke test**

Run: `cargo run -- doctor` to verify nothing broke.
Run: `cargo run -- serve` and open `http://localhost:8080` to verify the web UI loads with the new scan button.

---

### Task 19: Final review and cleanup

**Step 1: Run clippy**

Run: `cargo clippy --workspace -- -D warnings`
Fix any warnings.

**Step 2: Check for TODO/FIXME**

Run: grep for any TODO or FIXME left in Phase 6 code.

**Step 3: Commit any fixes**

```bash
git commit -m "chore: Phase 6 clippy fixes and cleanup"
```
