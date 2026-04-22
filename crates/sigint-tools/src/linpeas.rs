//! LinpeasTool — sandboxed linpeas.sh wrapper for Linux privilege escalation enumeration.
//!
//! @decision DEC-P15-012
//! @title LinpeasTool uses SandboxProfile::offline() — no network, 60s timeout
//! @status accepted
//! @rationale linpeas.sh is a local privilege escalation enumeration script.
//! It reads system files, running processes, SUID binaries, cron jobs, and
//! world-writable paths — none of which require outbound network access.
//! SandboxProfile::Offline (no-network, 60s) is the correct constraint: it
//! prevents the script from exfiltrating data while giving sufficient time
//! for a full enumeration pass. `NO_COLOR=1` suppresses ANSI escape sequences
//! so the parser can work on plain text. `-q` suppresses the banner and extra
//! verbose output to reduce noise. Risk is Medium: the tool itself only reads
//! system state, but its output reveals escalation paths for subsequent exploitation.

use async_trait::async_trait;
use serde_json::{json, Value};
use sigint_llm::ToolDefinition;
use sigint_sandbox::profile::SandboxProfile;
use tracing::info;

use crate::error::{Result, ToolError};
use crate::result::{ToolResult, TruncationInfo};
use crate::tool::Tool;
use sigint_core::types::ToolRisk;

/// Default 2 MB output cap for linpeas (output is verbose by design).
const DEFAULT_LINPEAS_OUTPUT_CAP: usize = 2_097_152;

/// Sandboxed linpeas.sh tool wrapper.
///
/// Exposes linpeas.sh as a `Tool` for the LLM agent layer. Enumerates Linux
/// privilege escalation vectors by inspecting the local system. Runs entirely
/// offline with no network access. The script must be present in the sandbox
/// working directory as `linpeas.sh`.
pub struct LinpeasTool {
    output_cap: usize,
}

impl LinpeasTool {
    /// Create a new LinpeasTool with the default output cap.
    pub fn new() -> Self {
        Self {
            output_cap: DEFAULT_LINPEAS_OUTPUT_CAP,
        }
    }

    /// Set a custom output cap (builder pattern).
    pub fn with_output_cap(mut self, cap: usize) -> Self {
        self.output_cap = cap;
        self
    }
}

impl Default for LinpeasTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for LinpeasTool {
    fn name(&self) -> &str {
        "linpeas_enum"
    }

    fn description(&self) -> &str {
        "Run linpeas.sh to enumerate Linux privilege escalation vectors. \
         Checks SUID/SGID binaries, writable paths, cron jobs, running services, \
         kernel exploits, sudo rules, and credential files. \
         Returns enumeration sections, high-priority findings, and total finding count. \
         Runs offline — no network access. linpeas.sh must be present in the sandbox."
    }

    fn risk_level(&self) -> ToolRisk {
        ToolRisk::Medium
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::function(
            self.name(),
            self.description(),
            json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
        )
    }

    async fn execute(&self, _args: Value) -> Result<ToolResult> {
        info!("executing linpeas enumeration");

        // Run `env NO_COLOR=1 bash linpeas.sh -q` to suppress ANSI sequences.
        // SandboxedCommand has no .env() method — we use /usr/bin/env to inject
        // the variable before bash. The offline sandbox profile provides
        // no-network and a 60s timeout.
        let mut cmd = SandboxProfile::offline().apply("env");
        cmd = cmd.max_output(self.output_cap);
        cmd = cmd.arg("NO_COLOR=1");
        cmd = cmd.arg("bash");
        cmd = cmd.arg("linpeas.sh");
        cmd = cmd.arg("-q");

        // SandboxedCommand::execute() is synchronous — bridge via spawn_blocking.
        let output = tokio::task::spawn_blocking(move || cmd.execute())
            .await
            .map_err(|e| ToolError::Sandbox(format!("spawn_blocking panicked: {e}")))?
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("timed out") || msg.contains("timeout") {
                    ToolError::Timeout(60)
                } else {
                    ToolError::Sandbox(msg)
                }
            })?;

        let structured_data = parse_linpeas_output(&output.stdout);

        let truncation = output.was_truncated.then_some(TruncationInfo {
            original_bytes: output.original_stdout_len,
            kept_bytes: output.stdout.len(),
        });
        Ok(ToolResult {
            stdout: output.stdout,
            stderr: output.stderr,
            exit_code: output.exit_code,
            duration: output.duration,
            structured_data,
            status: Default::default(),
            truncation,
        })
    }
}

/// Parse linpeas.sh output into a structured privilege escalation summary.
///
/// linpeas uses Unicode box-drawing characters as section separators:
///   `╔══════════╣ Section Name`
///
/// Within sections, high-priority findings are prefixed with `[+]`.
/// With `NO_COLOR=1`, ANSI escape sequences are stripped.
///
/// Output shape:
/// ```json
/// {
///   "sections": ["System Information", "Network Information", "Users & Groups"],
///   "high_priority": ["[+] /usr/bin/sudo is SUID", "[+] Writable /etc/passwd"],
///   "total_findings": 42
/// }
/// ```
///
/// Returns `None` for empty output. Returns `Some` with empty lists when linpeas
/// ran but produced no parseable sections (e.g. truncated at the banner).
pub(crate) fn parse_linpeas_output(stdout: &str) -> Option<Value> {
    if stdout.trim().is_empty() {
        return None;
    }

    let mut sections: Vec<String> = Vec::new();
    let mut high_priority: Vec<String> = Vec::new();
    let mut total_findings: u64 = 0;

    for line in stdout.lines() {
        let line_trimmed = line.trim();
        if line_trimmed.is_empty() {
            continue;
        }

        // Section headers contain the Unicode separator character.
        // Pattern: `╔══════════╣ Section Name` (may have leading whitespace/color)
        if line_trimmed.contains('\u{2554}') && line_trimmed.contains('\u{2563}') {
            // Extract the section name after the ╣ character.
            if let Some(pos) = line_trimmed.rfind('\u{2563}') {
                let section_name = line_trimmed[pos + '\u{2563}'.len_utf8()..].trim();
                if !section_name.is_empty() {
                    sections.push(section_name.to_string());
                }
            }
        }

        // Count all non-empty lines as findings (conservative count).
        total_findings += 1;

        // Collect [+] high-priority items.
        if line_trimmed.starts_with("[+]") {
            high_priority.push(line_trimmed.to_string());
        }
    }

    Some(json!({
        "sections": sections,
        "high_priority": high_priority,
        "total_findings": total_findings,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linpeas_tool_name() {
        assert_eq!(LinpeasTool::new().name(), "linpeas_enum");
    }

    #[test]
    fn linpeas_risk_level_is_medium() {
        assert_eq!(
            LinpeasTool::new().risk_level(),
            sigint_core::types::ToolRisk::Medium
        );
    }

    #[test]
    fn linpeas_definition_shape() {
        let def = LinpeasTool::new().definition();
        assert_eq!(def.type_, "function");
        assert_eq!(def.function.name, "linpeas_enum");

        let params = &def.function.parameters;
        assert_eq!(params["type"], "object");

        // No required fields — linpeas takes no arguments.
        let required = params["required"].as_array().unwrap();
        assert!(required.is_empty(), "linpeas should have no required args");
    }

    // --- parser unit tests ---

    #[test]
    fn parse_linpeas_empty_returns_none() {
        assert!(parse_linpeas_output("").is_none());
        assert!(parse_linpeas_output("   ").is_none());
    }

    #[test]
    fn parse_linpeas_typical_output() {
        // Simulate linpeas output with section headers and findings.
        // Section header uses Unicode box characters: ╔══════════╣
        let input = "\
╔══════════╣ System Information\n\
Linux version 5.15.0-generic\n\
[+] Kernel: 5.15.0-generic (check for local exploits)\n\
╔══════════╣ Network Information\n\
eth0: 192.168.1.10\n\
╔══════════╣ Users & Groups\n\
uid=1000(user) gid=1000(user)\n\
[+] /etc/passwd is world-readable\n\
";
        let result = parse_linpeas_output(input).expect("should return Some");

        let sections = result["sections"].as_array().unwrap();
        assert_eq!(
            sections.len(),
            3,
            "expected 3 sections, got: {:?}",
            sections
        );
        assert_eq!(sections[0], "System Information");
        assert_eq!(sections[1], "Network Information");
        assert_eq!(sections[2], "Users & Groups");

        let high_priority = result["high_priority"].as_array().unwrap();
        assert_eq!(high_priority.len(), 2);
        assert!(high_priority[0].as_str().unwrap().contains("[+]"));
        assert!(high_priority[1].as_str().unwrap().contains("[+]"));

        // total_findings counts all non-empty lines.
        assert!(
            result["total_findings"].as_u64().unwrap() >= 7,
            "expected at least 7 total findings"
        );
    }

    #[test]
    fn parse_linpeas_no_sections() {
        // Output with findings but no section headers (e.g. truncated run).
        let input = "Some output without sections\n[+] Found something interesting\n";
        let result = parse_linpeas_output(input).expect("should return Some");

        let sections = result["sections"].as_array().unwrap();
        assert!(sections.is_empty(), "expected no sections");

        let high_priority = result["high_priority"].as_array().unwrap();
        assert_eq!(high_priority.len(), 1);
        assert_eq!(
            result["total_findings"].as_u64().unwrap(),
            2,
            "expected 2 lines counted"
        );
    }

    #[test]
    fn parse_linpeas_sections_extracted_correctly() {
        // Verify section name extraction strips leading/trailing whitespace.
        let input = "╔══════════╣  SUID/SGID Files\n/usr/bin/sudo\n";
        let result = parse_linpeas_output(input).expect("should return Some");

        let sections = result["sections"].as_array().unwrap();
        assert_eq!(sections.len(), 1);
        assert_eq!(sections[0], "SUID/SGID Files");
    }

    /// Requires linpeas.sh in the sandbox working directory.
    /// Run with: cargo test -p sigint-tools -- --ignored
    #[tokio::test]
    #[ignore]
    async fn linpeas_integration_enumerate() {
        let result = LinpeasTool::new()
            .execute(json!({}))
            .await
            .expect("linpeas execution should not error");
        // linpeas exits 0 on completion; timeout gives non-zero.
        let _ = result.exit_code;
        // Structured data should have sections array.
        if let Some(data) = result.structured_data {
            assert!(data["sections"].is_array());
        }
    }
}
