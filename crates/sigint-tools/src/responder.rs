//! ResponderTool — sandboxed Responder wrapper for LLMNR/NBT-NS/MDNS poisoning
//! and credential capture.
//!
//! @decision DEC-P15-010
//! @title Responder defaults to analyze-only mode (passive) for safety; active poisoning requires explicit opt-in
//! @status accepted
//! @rationale Responder in active mode poisons LLMNR/NBT-NS/MDNS name resolution
//! on the local network segment, redirecting authentication attempts to the
//! attacker's machine. This is highly disruptive on production networks. The
//! default `analyze_only = true` sets the `-A` flag which enables passive
//! listening (log events but do not send poisoned responses), making the default
//! safe for reconnaissance. Active poisoning must be explicitly opted into by
//! the agent. SandboxProfile::nmap() provides raw network socket access needed
//! for packet injection. The sandbox 300s timeout kills Responder cleanly since
//! it otherwise runs indefinitely as a daemon.

use async_trait::async_trait;
use serde_json::{json, Value};
use sigint_llm::ToolDefinition;
use sigint_sandbox::profile::SandboxProfile;
use tracing::info;

use crate::error::{Result, ToolError};
use crate::result::{ToolResult, TruncationInfo};
use crate::tool::Tool;
use sigint_core::types::ToolRisk;

/// Default 1 MB output cap for responder.
const DEFAULT_RESPONDER_OUTPUT_CAP: usize = 1_048_576;

/// Sandboxed Responder tool wrapper.
///
/// Exposes Responder as a `Tool` for the LLM agent layer. Captures NetNTLM
/// hashes via LLMNR/NBT-NS/MDNS poisoning on the local network segment.
/// Defaults to passive (analyze-only) mode. Network access is provided via
/// pasta user-mode networking with a 300s timeout.
pub struct ResponderTool {
    output_cap: usize,
}

impl ResponderTool {
    /// Create a new ResponderTool with the default output cap.
    pub fn new() -> Self {
        Self {
            output_cap: DEFAULT_RESPONDER_OUTPUT_CAP,
        }
    }

    /// Set a custom output cap (builder pattern).
    pub fn with_output_cap(mut self, cap: usize) -> Self {
        self.output_cap = cap;
        self
    }
}

impl Default for ResponderTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for ResponderTool {
    fn name(&self) -> &str {
        "responder_poison"
    }

    fn description(&self) -> &str {
        "Run Responder to capture credentials via LLMNR/NBT-NS/MDNS poisoning. \
         In analyze-only mode (default), passively listens and logs observed \
         authentication attempts without sending poisoned responses. In active \
         mode, responds to broadcast name resolution requests to capture \
         NetNTLM hashes. Runs for up to 300 seconds then exits. \
         Requires network access — runs inside a sandboxed environment with \
         pasta user-mode networking."
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
                    "interface": {
                        "type": "string",
                        "description": "Network interface to listen on (e.g. 'eth0', 'ens3'). Defaults to 'eth0'."
                    },
                    "analyze_only": {
                        "type": "boolean",
                        "description": "If true (default), run in passive analyze mode (-A flag): log observed \
                                        authentication requests without poisoning. If false, actively poison \
                                        LLMNR/NBT-NS/MDNS responses to capture hashes. Use false only \
                                        with explicit authorization."
                    }
                },
                "required": []
            }),
        )
    }

    async fn execute(&self, args: Value) -> Result<ToolResult> {
        // Extract optional parameters with defaults.
        let interface = args["interface"].as_str().unwrap_or("eth0").to_string();

        // Default to analyze-only (passive) for safety.
        let analyze_only = args["analyze_only"].as_bool().unwrap_or(true);

        info!(
            interface = %interface,
            analyze_only = analyze_only,
            "executing responder"
        );

        let mut cmd = SandboxProfile::nmap().apply("responder");
        cmd = cmd.max_output(self.output_cap);
        cmd = cmd.arg("-I").arg(&interface);

        if analyze_only {
            // Passive mode: log but do not send poisoned responses.
            cmd = cmd.arg("-A");
        }

        // Enable LM hash downgrade for maximum compatibility.
        cmd = cmd.arg("--lm");

        // SandboxedCommand::execute() is synchronous — bridge via spawn_blocking.
        // Responder runs until killed; the sandbox 300s timeout provides the bound.
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

        let structured_data = parse_responder_output(&output.stdout);

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

/// Parse Responder log output into a structured credential capture summary.
///
/// Responder emits a mix of status lines and captured hash lines. This function
/// extracts:
/// - Captured NetNTLM/NTLMv2 hashes (protocol, type, client IP, user, domain, hash)
/// - Count of poisoned answers sent
///
/// Relevant line patterns:
/// - Poisoned answer: `[*] [LLMNR]  Poisoned answer sent to 192.168.1.5 for name foo`
/// - Hash client:     `[SMB] NTLMv2-SSP Client   : 192.168.1.5`
/// - Hash user:       `[SMB] NTLMv2-SSP Username  : DOMAIN\user`
/// - Hash value:      `[SMB] NTLMv2-SSP Hash       : user::DOMAIN:abc123...`
///
/// Returns `None` if output is empty or no relevant events occurred.
///
/// Output shape:
/// ```json
/// {
///   "captured_hashes": [
///     {"protocol": "SMB", "type": "NTLMv2-SSP", "client": "192.168.1.5",
///      "user": "user", "domain": "DOMAIN", "hash": "abc123..."}
///   ],
///   "poisoned_answers": 3,
///   "total_hashes": 1
/// }
/// ```
pub fn parse_responder_output(output: &str) -> Option<Value> {
    if output.trim().is_empty() {
        return None;
    }

    let mut poisoned_answers: u64 = 0;
    let mut captured_hashes: Vec<Value> = Vec::new();

    // State for assembling multi-line hash records.
    let mut current_protocol: Option<String> = None;
    let mut current_type: Option<String> = None;
    let mut current_client: Option<String> = None;
    let mut current_user: Option<String> = None;
    let mut current_domain: Option<String> = None;

    for line in output.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Count poisoned answers: `[*] [PROTO] Poisoned answer sent to ...`
        if line.contains("Poisoned answer sent to") {
            poisoned_answers += 1;
            continue;
        }

        // Hash lines start with `[PROTO] TYPE Client   : ...`
        // e.g. `[SMB] NTLMv2-SSP Client   : 192.168.1.5`
        if let Some(rest) = strip_proto_prefix(line) {
            // rest is like: "NTLMv2-SSP Client   : 192.168.1.5"
            // or: "NTLMv2-SSP Username  : DOMAIN\user"
            // or: "NTLMv2-SSP Hash       : user::DOMAIN:abc123..."
            let (protocol, remainder) = rest;

            if let Some((hash_type, field, value)) = parse_hash_line(remainder) {
                match field.as_str() {
                    "Client" => {
                        current_protocol = Some(protocol);
                        current_type = Some(hash_type);
                        current_client = Some(value);
                    }
                    "Username" => {
                        // "DOMAIN\user" or "user"
                        let (domain, user) = split_domain_user(&value);
                        current_domain = Some(domain);
                        current_user = Some(user);
                    }
                    "Hash" => {
                        // Hash line: "user::DOMAIN:abc123..."
                        // Extract user/domain from the hash value prefix if not already set.
                        let hash_str = value.clone();
                        let (user, domain) = extract_user_domain_from_hash(&hash_str);

                        let proto = current_protocol.take().unwrap_or_else(|| protocol.clone());
                        let hash_type_final = current_type.take().unwrap_or(hash_type);
                        let client = current_client.take().unwrap_or_default();
                        let final_user = current_user.take().unwrap_or(user);
                        let final_domain = current_domain.take().unwrap_or(domain);

                        captured_hashes.push(json!({
                            "protocol": proto,
                            "type": hash_type_final,
                            "client": client,
                            "user": final_user,
                            "domain": final_domain,
                            "hash": hash_str,
                        }));
                    }
                    _ => {}
                }
            }
        }
    }

    let total_hashes = captured_hashes.len() as u64;

    // Return Some even if no hashes — poisoned_answers count is still useful.
    if total_hashes == 0 && poisoned_answers == 0 {
        return None;
    }

    Some(json!({
        "captured_hashes": captured_hashes,
        "poisoned_answers": poisoned_answers,
        "total_hashes": total_hashes,
    }))
}

/// Strip the `[PROTO]` prefix from a Responder log line.
///
/// Returns `(protocol_str, remainder)` or `None` if the line doesn't start
/// with a `[PROTO]` bracket pattern.
fn strip_proto_prefix(line: &str) -> Option<(String, &str)> {
    if !line.starts_with('[') {
        return None;
    }
    let close = line.find(']')?;
    let proto = line[1..close].to_string();
    // Skip ']' and any leading whitespace after it.
    let rest = line[close + 1..].trim_start();
    // Skip status prefix lines like `[*]` or `[+]`
    if proto == "*" || proto == "+" || proto == "-" || proto == "!" {
        return None;
    }
    Some((proto, rest))
}

/// Parse a Responder hash field line of the form `TYPE Field   : value`.
///
/// Returns `(hash_type, field_name, value)` or `None` if the pattern doesn't match.
fn parse_hash_line(line: &str) -> Option<(String, String, String)> {
    // Split on ` : ` (with spaces around the colon).
    let sep = " : ";
    let colon_pos = line.find(sep)?;
    let left = &line[..colon_pos];
    let value = line[colon_pos + sep.len()..].trim().to_string();

    // left is something like "NTLMv2-SSP Client" or "NTLMv2-SSP Hash"
    // Split on whitespace: first token(s) up to last word = type; last word = field.
    let parts: Vec<&str> = left.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }
    let field = parts.last()?.to_string();
    let hash_type = parts[..parts.len() - 1].join("-");

    Some((hash_type, field, value))
}

/// Split `DOMAIN\user` into `(domain, user)`. If no backslash, returns `("", user)`.
fn split_domain_user(s: &str) -> (String, String) {
    if let Some(pos) = s.find('\\') {
        (s[..pos].to_string(), s[pos + 1..].to_string())
    } else {
        (String::new(), s.to_string())
    }
}

/// Extract user and domain from the NTLMv2 hash string prefix `user::DOMAIN:...`.
fn extract_user_domain_from_hash(hash: &str) -> (String, String) {
    let mut parts = hash.splitn(4, ':');
    let user = parts.next().unwrap_or("").to_string();
    // Second field is empty (the `::` separator).
    let _ = parts.next();
    let domain = parts.next().unwrap_or("").to_string();
    (user, domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn responder_tool_name() {
        assert_eq!(ResponderTool::new().name(), "responder_poison");
    }

    #[test]
    fn responder_risk_is_high() {
        assert_eq!(ResponderTool::new().risk_level(), ToolRisk::High);
    }

    #[test]
    fn responder_definition_shape() {
        let def = ResponderTool::new().definition();
        assert_eq!(def.type_, "function");
        assert_eq!(def.function.name, "responder_poison");

        let params = &def.function.parameters;
        assert_eq!(params["type"], "object");

        // No required fields
        let required = params["required"].as_array().unwrap();
        assert!(
            required.is_empty(),
            "responder should have no required args"
        );

        // interface and analyze_only exist
        assert!(params["properties"]["interface"].is_object());
        assert!(params["properties"]["analyze_only"].is_object());
    }

    #[test]
    fn parse_responder_typical_captured_hash() {
        let input = "\
[*] [LLMNR]  Poisoned answer sent to 192.168.1.5 for name fileserver\n\
[*] [LLMNR]  Poisoned answer sent to 192.168.1.5 for name printer\n\
[*] [LLMNR]  Poisoned answer sent to 192.168.1.6 for name dc01\n\
[SMB] NTLMv2-SSP Client   : 192.168.1.5\n\
[SMB] NTLMv2-SSP Username  : DOMAIN\\jsmith\n\
[SMB] NTLMv2-SSP Hash       : jsmith::DOMAIN:abc123def456::beef\n\
[+] Listening for events...\n\
";
        let result = parse_responder_output(input).expect("should parse");
        assert_eq!(result["poisoned_answers"], 3);
        assert_eq!(result["total_hashes"], 1);

        let hashes = result["captured_hashes"].as_array().unwrap();
        assert_eq!(hashes.len(), 1);

        let h = &hashes[0];
        assert_eq!(h["protocol"], "SMB");
        assert_eq!(h["client"], "192.168.1.5");
    }

    #[test]
    fn parse_responder_no_hashes() {
        // Only status lines — no captured hashes, no poisoned answers
        let input = "[+] Listening for events...\n[*] Some other message\n";
        // No poisoned answers or hashes → None
        assert!(parse_responder_output(input).is_none());
    }

    #[test]
    fn parse_responder_empty_output() {
        assert!(parse_responder_output("").is_none());
        assert!(parse_responder_output("   ").is_none());
    }

    #[test]
    fn parse_responder_poisoned_count() {
        // Only poisoned answer lines, no hash captures
        let input = "\
[*] [NBT-NS] Poisoned answer sent to 10.0.0.5 for name WPAD\n\
[*] [MDNS]   Poisoned answer sent to 10.0.0.6 for name foo.local\n\
";
        let result = parse_responder_output(input).expect("should return Some with poison counts");
        assert_eq!(result["poisoned_answers"], 2);
        assert_eq!(result["total_hashes"], 0);
        let hashes = result["captured_hashes"].as_array().unwrap();
        assert!(hashes.is_empty());
    }

    /// Requires responder + passt + newuidmap + root. Run with: cargo test -p sigint-tools -- --ignored
    #[tokio::test]
    #[ignore]
    async fn responder_integration_analyze_only() {
        let result = ResponderTool::new()
            .execute(json!({
                "interface": "lo",
                "analyze_only": true
            }))
            .await
            .expect("responder execution should not error");
        // Responder is killed by sandbox timeout; exit code may be non-zero
        let _ = result.exit_code;
    }
}
