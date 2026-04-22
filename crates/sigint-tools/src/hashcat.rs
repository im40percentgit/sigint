//! HashcatTool — sandboxed hashcat wrapper for offline password hash cracking.
//!
//! @decision DEC-P15-007
//! @title HashcatTool uses SandboxProfile::offline() — no network, 60s timeout
//! @status accepted
//! @rationale hashcat is a GPU/CPU-accelerated offline hash cracker. It requires
//! no network access — all cracking happens locally against a provided hash and
//! wordlist. SandboxProfile::Offline enforces no-network constraint and provides
//! a 60s timeout suitable for quick dictionary attacks (larger campaigns should
//! be run outside the agent loop). Risk is Medium because cracked credentials
//! can be used for lateral movement but cracking itself is purely local.
//! `--force` bypasses hardware detection warnings for sandbox/CI environments.
//! `--quiet` suppresses progress output. `--outfile-format=2` outputs only the
//! plaintext (no hash prefix) making line parsing trivial. `-o /dev/stdout`
//! captures results inline rather than writing to a file.

use async_trait::async_trait;
use serde_json::{json, Value};
use sigint_llm::ToolDefinition;
use sigint_sandbox::profile::SandboxProfile;
use tracing::info;

use crate::error::{Result, ToolError};
use crate::result::{ToolResult, TruncationInfo};
use crate::tool::Tool;
use sigint_core::types::ToolRisk;

/// Default rockyou wordlist path for hashcat.
const DEFAULT_WORDLIST: &str = "/usr/share/wordlists/rockyou.txt";

/// Default 1 MB output cap for hashcat.
const DEFAULT_HASHCAT_OUTPUT_CAP: usize = 1_048_576;

/// Sandboxed hashcat tool wrapper.
///
/// Exposes hashcat as a `Tool` for the LLM agent layer. Cracks password hashes
/// using dictionary attacks against a provided wordlist. Runs entirely offline
/// with no network access. Results (cracked plaintext passwords) are emitted
/// to stdout for structured parsing.
pub struct HashcatTool {
    output_cap: usize,
}

impl HashcatTool {
    /// Create a new HashcatTool with the default output cap.
    pub fn new() -> Self {
        Self {
            output_cap: DEFAULT_HASHCAT_OUTPUT_CAP,
        }
    }

    /// Set a custom output cap (builder pattern).
    pub fn with_output_cap(mut self, cap: usize) -> Self {
        self.output_cap = cap;
        self
    }
}

impl Default for HashcatTool {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Tool for HashcatTool {
    fn name(&self) -> &str {
        "hashcat_crack"
    }

    fn description(&self) -> &str {
        "Run hashcat to crack password hashes using a dictionary attack. \
         Returns cracked plaintext passwords. Runs offline — no network access required. \
         Common hash types: 0=MD5, 100=SHA1, 1000=NTLM, 1800=sha512crypt, \
         3200=bcrypt. Provide the hash and hash type."
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
                "properties": {
                    "hash": {
                        "type": "string",
                        "description": "The password hash to crack (e.g. '5f4dcc3b5aa765d61d8327deb882cf99' for MD5)."
                    },
                    "hash_type": {
                        "type": "integer",
                        "description": "Hashcat hash type code. Common values: 0=MD5, 100=SHA1, \
                                        1000=NTLM, 1400=SHA256, 1700=SHA512, 1800=sha512crypt(Unix), \
                                        3200=bcrypt, 5500=NetNTLMv1, 5600=NetNTLMv2."
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "Path to the wordlist file. \
                                        Defaults to '/usr/share/wordlists/rockyou.txt'."
                    },
                    "rules": {
                        "type": "string",
                        "description": "Path to a hashcat rules file for word mangling \
                                        (e.g. '/usr/share/hashcat/rules/best64.rule'). Optional."
                    }
                },
                "required": ["hash", "hash_type"]
            }),
        )
    }

    async fn execute(&self, args: Value) -> Result<ToolResult> {
        // Extract required hash.
        let hash = args["hash"]
            .as_str()
            .ok_or_else(|| ToolError::MissingArgument("hash".to_string()))?
            .to_string();

        // Extract required hash_type.
        let hash_type = args["hash_type"]
            .as_u64()
            .ok_or_else(|| ToolError::MissingArgument("hash_type".to_string()))?;

        // Extract optional wordlist, default to rockyou.txt.
        let wordlist = args["wordlist"]
            .as_str()
            .unwrap_or(DEFAULT_WORDLIST)
            .to_string();

        // Extract optional rules file.
        let rules = args["rules"].as_str().map(|s| s.to_string());

        info!(
            hash = %hash,
            hash_type = hash_type,
            wordlist = %wordlist,
            rules = ?rules,
            "executing hashcat crack"
        );

        let mut cmd = SandboxProfile::offline().apply("hashcat");
        cmd = cmd.max_output(self.output_cap);

        // Bypass hardware detection warnings in sandbox/CI environments.
        cmd = cmd.arg("--force");

        // Suppress progress output.
        cmd = cmd.arg("--quiet");

        // Hash type.
        cmd = cmd.arg("-m").arg(hash_type.to_string());

        // The hash to crack.
        cmd = cmd.arg(&hash);

        // The wordlist.
        cmd = cmd.arg(&wordlist);

        // Output format 2 = plaintext only (no hash:plaintext prefix).
        cmd = cmd.arg("--outfile-format=2");

        // Output to stdout.
        cmd = cmd.arg("-o").arg("/dev/stdout");

        // Apply optional rules file.
        if let Some(ref r) = rules {
            cmd = cmd.arg("-r").arg(r);
        }

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

        let structured_data = parse_hashcat_output(&output.stdout);

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

/// Parse hashcat output into a structured cracked-password summary.
///
/// With `--outfile-format=2 -o /dev/stdout`, hashcat emits one plaintext
/// password per line for each cracked hash. Lines that are empty are skipped.
///
/// Output shape:
/// ```json
/// {
///   "cracked": ["password123", "letmein"],
///   "total": 2
/// }
/// ```
///
/// Returns `Some` with an empty `cracked` list (and `total: 0`) when no
/// hashes were cracked, so the LLM can distinguish "ran but cracked nothing"
/// from `None` (which would indicate parse failure).
pub(crate) fn parse_hashcat_output(stdout: &str) -> Option<Value> {
    let cracked: Vec<String> = stdout
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .map(|l| l.to_string())
        .collect();

    let total = cracked.len() as u64;
    Some(json!({
        "cracked": cracked,
        "total": total,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashcat_tool_name() {
        assert_eq!(HashcatTool::new().name(), "hashcat_crack");
    }

    #[test]
    fn hashcat_risk_level_is_medium() {
        assert_eq!(
            HashcatTool::new().risk_level(),
            sigint_core::types::ToolRisk::Medium
        );
    }

    #[test]
    fn hashcat_definition_shape() {
        let def = HashcatTool::new().definition();
        assert_eq!(def.type_, "function");
        assert_eq!(def.function.name, "hashcat_crack");

        let params = &def.function.parameters;
        assert_eq!(params["type"], "object");

        // hash and hash_type are required
        let required = params["required"].as_array().unwrap();
        assert!(
            required.iter().any(|v| v == "hash"),
            "hash should be required"
        );
        assert!(
            required.iter().any(|v| v == "hash_type"),
            "hash_type should be required"
        );
        assert_eq!(
            required.len(),
            2,
            "only hash and hash_type should be required"
        );

        // hash is string, hash_type is integer
        assert_eq!(params["properties"]["hash"]["type"], "string");
        assert_eq!(params["properties"]["hash_type"]["type"], "integer");

        // optional fields exist
        assert!(params["properties"]["wordlist"].is_object());
        assert!(params["properties"]["rules"].is_object());

        // optional fields are not in required
        assert!(!required.iter().any(|v| v == "wordlist"));
        assert!(!required.iter().any(|v| v == "rules"));
    }

    #[tokio::test]
    async fn hashcat_missing_hash_errors() {
        let err = HashcatTool::new()
            .execute(json!({"hash_type": 0}))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("missing required argument"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn hashcat_missing_hash_type_errors() {
        let err = HashcatTool::new()
            .execute(json!({"hash": "5f4dcc3b5aa765d61d8327deb882cf99"}))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("missing required argument"),
            "unexpected error: {err}"
        );
    }

    // --- parser unit tests ---

    #[test]
    fn parse_hashcat_typical_output() {
        // With --outfile-format=2, hashcat emits one plaintext per line.
        let input = "password123\nletmein\nsecret\n";
        let result = parse_hashcat_output(input).expect("should return Some");
        let cracked = result["cracked"]
            .as_array()
            .expect("cracked should be array");
        assert_eq!(cracked.len(), 3);
        assert_eq!(result["total"], 3);
        assert_eq!(cracked[0], "password123");
        assert_eq!(cracked[1], "letmein");
        assert_eq!(cracked[2], "secret");
    }

    #[test]
    fn parse_hashcat_no_results() {
        let input = "";
        let result = parse_hashcat_output(input).expect("should return Some even with no results");
        assert_eq!(result["total"], 0);
        let cracked = result["cracked"]
            .as_array()
            .expect("cracked should be array");
        assert!(cracked.is_empty());
    }

    #[test]
    fn parse_hashcat_whitespace_only() {
        let input = "   \n\n   \n";
        let result =
            parse_hashcat_output(input).expect("should return Some for whitespace-only input");
        assert_eq!(result["total"], 0);
        let cracked = result["cracked"].as_array().unwrap();
        assert!(cracked.is_empty());
    }

    #[test]
    fn parse_hashcat_single_result() {
        let input = "hunter2\n";
        let result = parse_hashcat_output(input).expect("should return Some");
        let cracked = result["cracked"].as_array().unwrap();
        assert_eq!(cracked.len(), 1);
        assert_eq!(cracked[0], "hunter2");
        assert_eq!(result["total"], 1);
    }

    /// Requires hashcat. Run with: cargo test -p sigint-tools -- --ignored
    #[tokio::test]
    #[ignore]
    async fn hashcat_executes_md5_crack() {
        // MD5 of "password" = 5f4dcc3b5aa765d61d8327deb882cf99
        let result = HashcatTool::new()
            .execute(json!({
                "hash": "5f4dcc3b5aa765d61d8327deb882cf99",
                "hash_type": 0
            }))
            .await
            .expect("hashcat execution should not error");
        // hashcat exits 0 on success, 1 when no passwords cracked — both are valid
        assert!(
            result.exit_code == 0 || result.exit_code == 1,
            "hashcat should exit 0 or 1: {:?}",
            result.stderr
        );
    }
}
