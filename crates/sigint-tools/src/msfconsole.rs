//! MsfconsoleTool — sandboxed msfconsole wrapper for Metasploit module execution.
//!
//! @decision DEC-P15-011
//! @title MsfconsoleTool uses SandboxProfile::web_scanner() (600s) for exploitation
//! @status accepted
//! @rationale Metasploit exploits can take significant time to complete — some
//! modules perform multi-stage exploitation involving connection setup, payload
//! delivery, and session establishment. The web_scanner profile (600s, pasta
//! networking) provides enough runway for realistic exploit chains while
//! bounding execution time. Risk is High because this tool executes arbitrary
//! Metasploit modules against targets; callers must have explicit authorization.
//! The `-q` flag suppresses the banner and `-x` executes a command string,
//! enabling scriptable non-interactive use. `exit` is appended to the command
//! string to ensure msfconsole terminates after execution rather than waiting
//! for interactive input.

use async_trait::async_trait;
use serde_json::{json, Value};
use sigint_llm::ToolDefinition;
use sigint_sandbox::profile::SandboxProfile;
use tracing::info;

use crate::error::{Result, ToolError};
use crate::result::{TruncationInfo, ToolResult};
use crate::tool::Tool;
use sigint_core::types::ToolRisk;

/// Default 2 MB output cap for msfconsole (exploit output can be verbose).
const DEFAULT_MSF_OUTPUT_CAP: usize = 2_097_152;

/// Sandboxed msfconsole tool wrapper.
///
/// Exposes Metasploit Framework as a `Tool` for the LLM agent layer. Runs a
/// module in batch mode via `msfconsole -q -x "..."`, collects session counts
/// and success markers, then exits. Requires pasta networking for exploit
/// delivery and a 600s timeout to accommodate slow exploit chains.
pub struct MsfconsoleTool {
    output_cap: usize,
}

impl MsfconsoleTool {
    /// Create a new MsfconsoleTool with the default output cap.
    pub fn new() -> Self {
        Self {
            output_cap: DEFAULT_MSF_OUTPUT_CAP,
        }
    }

    /// Set a custom output cap (builder pattern).
    pub fn with_output_cap(mut self, cap: usize) -> Self {
        self.output_cap = cap;
        self
    }
}

impl Default for MsfconsoleTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for MsfconsoleTool {
    fn name(&self) -> &str {
        "msf_exploit"
    }

    fn description(&self) -> &str {
        "Run Metasploit Framework modules via msfconsole for exploitation. \
         Requires explicit authorization. Executes in batch mode: sets the \
         module, RHOSTS, optional PAYLOAD, and any additional options before \
         running. Returns session counts and success markers. \
         Example: module='exploit/unix/ftp/vsftpd_234_backdoor', \
         target='192.168.1.10', payload='cmd/unix/interact'."
    }

    fn risk_level(&self) -> ToolRisk {
        ToolRisk::High
    }

    fn definition(&self) -> ToolDefinition {
        ToolDefinition::function(
            self.name(),
            self.description(),
            json!({
                "type": "object",
                "properties": {
                    "module": {
                        "type": "string",
                        "description": "Metasploit module path (e.g. 'exploit/unix/ftp/vsftpd_234_backdoor', \
                                        'auxiliary/scanner/smb/smb_ms17_010')."
                    },
                    "target": {
                        "type": "string",
                        "description": "Target host or CIDR range to set as RHOSTS \
                                        (e.g. '192.168.1.10', '10.0.0.0/24')."
                    },
                    "payload": {
                        "type": "string",
                        "description": "Metasploit payload to use (e.g. 'cmd/unix/interact', \
                                        'windows/meterpreter/reverse_tcp'). Optional — omit to use \
                                        the module default."
                    },
                    "options": {
                        "type": "string",
                        "description": "Additional module options as semicolon-separated KEY=VALUE pairs \
                                        (e.g. 'LPORT=4444;THREADS=10'). Each pair becomes a 'set KEY VALUE' \
                                        command. Optional."
                    }
                },
                "required": ["module", "target"]
            }),
        )
    }

    async fn execute(&self, args: Value) -> Result<ToolResult> {
        // Extract required module.
        let module = args["module"]
            .as_str()
            .ok_or_else(|| ToolError::MissingArgument("module".to_string()))?
            .to_string();

        // Extract required target.
        let target = args["target"]
            .as_str()
            .ok_or_else(|| ToolError::MissingArgument("target".to_string()))?
            .to_string();

        // Extract optional payload.
        let payload = args["payload"].as_str().map(|s| s.to_string());

        // Extract optional semicolon-separated options (KEY=VALUE).
        let options = args["options"].as_str().map(|s| s.to_string());

        info!(
            module = %module,
            target = %target,
            payload = ?payload,
            options = ?options,
            "executing msfconsole exploit"
        );

        // Build the msfconsole -x command string.
        //
        // Pattern: "use <module>; set RHOSTS <target>; [set PAYLOAD <payload>;]
        //           [set KEY1 VAL1; set KEY2 VAL2;] run; exit"
        let mut cmd_parts: Vec<String> = vec![
            format!("use {}", module),
            format!("set RHOSTS {}", target),
        ];

        if let Some(ref p) = payload {
            cmd_parts.push(format!("set PAYLOAD {}", p));
        }

        // Parse semicolon-separated KEY=VALUE option pairs.
        if let Some(ref opts) = options {
            for pair in opts.split(';') {
                let pair = pair.trim();
                if pair.is_empty() {
                    continue;
                }
                // Split on first '=' to get KEY and VALUE.
                if let Some(eq_pos) = pair.find('=') {
                    let key = pair[..eq_pos].trim();
                    let val = pair[eq_pos + 1..].trim();
                    cmd_parts.push(format!("set {} {}", key, val));
                }
            }
        }

        cmd_parts.push("run".to_string());
        cmd_parts.push("exit".to_string());

        let msf_cmd = cmd_parts.join("; ");

        let mut cmd = SandboxProfile::web_scanner().apply("msfconsole");
        cmd = cmd.max_output(self.output_cap);
        cmd = cmd.arg("-q");
        cmd = cmd.arg("-x").arg(&msf_cmd);

        // SandboxedCommand::execute() is synchronous — bridge via spawn_blocking.
        let output = tokio::task::spawn_blocking(move || cmd.execute())
            .await
            .map_err(|e| ToolError::Sandbox(format!("spawn_blocking panicked: {e}")))?
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("timed out") || msg.contains("timeout") {
                    ToolError::Timeout(600)
                } else {
                    ToolError::Sandbox(msg)
                }
            })?;

        let structured_data = parse_msf_output(&output.stdout, &module);

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

/// Parse msfconsole output into a structured exploitation summary.
///
/// Scans for:
/// - Session opened lines: `[*] Meterpreter session N opened` or
///   `[*] Command shell session N opened`
/// - Exploit completed banner: `Exploit completed`
/// - Success marker lines starting with `[+]`
///
/// Output shape:
/// ```json
/// {
///   "sessions_opened": 1,
///   "exploit_completed": true,
///   "success_markers": ["[+] 192.168.1.10 - The target is vulnerable."],
///   "module": "exploit/unix/ftp/vsftpd_234_backdoor"
/// }
/// ```
pub(crate) fn parse_msf_output(stdout: &str, module: &str) -> Option<Value> {
    if stdout.trim().is_empty() {
        return None;
    }

    let mut sessions_opened: u64 = 0;
    let mut exploit_completed = false;
    let mut success_markers: Vec<String> = Vec::new();

    for line in stdout.lines() {
        let line_trimmed = line.trim();
        if line_trimmed.is_empty() {
            continue;
        }

        // Count session-opened events.
        // Patterns: "[*] Meterpreter session N opened" or
        //           "[*] Command shell session N opened"
        if (line_trimmed.contains("session") && line_trimmed.contains("opened"))
            || line_trimmed.contains("Meterpreter session")
        {
            sessions_opened += 1;
        }

        // Detect exploit completion (successful session established).
        // "Exploit completed, but no session was created." is a failure message
        // from msfconsole — do NOT count it as success. Only count lines that
        // contain "Exploit completed" without the "no session" qualifier.
        if line_trimmed.contains("Exploit completed")
            && !line_trimmed.contains("no session")
        {
            exploit_completed = true;
        }

        // Collect [+] success markers.
        if line_trimmed.starts_with("[+]") {
            success_markers.push(line_trimmed.to_string());
        }
    }

    Some(json!({
        "sessions_opened": sessions_opened,
        "exploit_completed": exploit_completed,
        "success_markers": success_markers,
        "module": module,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msf_tool_name() {
        assert_eq!(MsfconsoleTool::new().name(), "msf_exploit");
    }

    #[test]
    fn msf_risk_level_is_high() {
        assert_eq!(
            MsfconsoleTool::new().risk_level(),
            sigint_core::types::ToolRisk::High
        );
    }

    #[test]
    fn msf_definition_shape() {
        let def = MsfconsoleTool::new().definition();
        assert_eq!(def.type_, "function");
        assert_eq!(def.function.name, "msf_exploit");

        let params = &def.function.parameters;
        assert_eq!(params["type"], "object");

        // module and target are required.
        let required = params["required"].as_array().unwrap();
        assert!(
            required.iter().any(|v| v == "module"),
            "module should be required"
        );
        assert!(
            required.iter().any(|v| v == "target"),
            "target should be required"
        );
        assert_eq!(required.len(), 2, "only module and target should be required");

        // Optional fields exist.
        assert!(params["properties"]["payload"].is_object());
        assert!(params["properties"]["options"].is_object());
        // Optional fields are NOT in required.
        assert!(!required.iter().any(|v| v == "payload"));
        assert!(!required.iter().any(|v| v == "options"));
    }

    #[tokio::test]
    async fn msf_missing_module_errors() {
        let err = MsfconsoleTool::new()
            .execute(json!({"target": "192.168.1.10"}))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("missing required argument"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn msf_missing_target_errors() {
        let err = MsfconsoleTool::new()
            .execute(json!({"module": "exploit/unix/ftp/vsftpd_234_backdoor"}))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("missing required argument"),
            "unexpected error: {err}"
        );
    }

    // --- parser unit tests ---

    #[test]
    fn parse_msf_session_opened() {
        let input = "\
[*] Started reverse TCP handler on 0.0.0.0:4444\n\
[*] Meterpreter session 1 opened (192.168.1.100:4444 -> 192.168.1.10:49155)\n\
[+] 192.168.1.10 - The target appears to be vulnerable.\n\
Exploit completed, but no session was created.\n\
";
        let result = parse_msf_output(input, "exploit/test").expect("should return Some");
        assert_eq!(result["sessions_opened"], 1);
        assert_eq!(result["module"], "exploit/test");

        let markers = result["success_markers"].as_array().unwrap();
        assert_eq!(markers.len(), 1);
        assert!(
            markers[0].as_str().unwrap().contains("[+]"),
            "success marker should start with [+]"
        );
    }

    #[test]
    fn parse_msf_no_session() {
        let input = "\
[*] Started reverse TCP handler on 0.0.0.0:4444\n\
[-] 192.168.1.10:21 - Exploit failed: no target\n\
Exploit completed, but no session was created.\n\
";
        let result = parse_msf_output(input, "exploit/unix/ftp/vsftpd_234_backdoor")
            .expect("should return Some");
        assert_eq!(result["sessions_opened"], 0);
        assert_eq!(result["exploit_completed"], false);
        let markers = result["success_markers"].as_array().unwrap();
        assert!(markers.is_empty());
    }

    #[test]
    fn parse_msf_exploit_completed_flag() {
        let input = "\
[*] Exploit completed with 0 sessions created.\n\
Exploit completed\n\
";
        let result =
            parse_msf_output(input, "exploit/multi/handler").expect("should return Some");
        assert_eq!(result["exploit_completed"], true);
    }

    #[test]
    fn parse_msf_empty_output_returns_none() {
        assert!(parse_msf_output("", "exploit/test").is_none());
        assert!(parse_msf_output("   ", "exploit/test").is_none());
    }

    /// Requires msfconsole. Run with: cargo test -p sigint-tools -- --ignored
    #[tokio::test]
    #[ignore]
    async fn msf_integration_auxiliary_scan() {
        let result = MsfconsoleTool::new()
            .execute(json!({
                "module": "auxiliary/scanner/portscan/tcp",
                "target": "127.0.0.1",
                "options": "PORTS=22,80,443"
            }))
            .await
            .expect("msfconsole execution should not error");
        // msfconsole exits 0 on normal completion.
        let _ = result.exit_code;
    }
}
