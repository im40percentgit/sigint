//! Credential pattern redaction shared by tool-arg persistence and
//! training-data extraction.
//!
//! This module provides a single, regex-based redaction pass that is applied
//! at every persistence boundary — both when tool call arguments are written to
//! the scan-record store, and when training examples are extracted from that
//! store.  Keeping the patterns in one place eliminates coverage gaps that
//! arise from having two independent redaction implementations.
//!
//! @decision DEC-CORE-REDACT-001
//! @title Single regex-based redactor in sigint-core, called at every persistence boundary
//! @status accepted
//! @rationale Centralising redaction in sigint-core (the shared foundation crate)
//! ensures every crate that stores or exports user data applies the same
//! patterns.  Alternatives considered: (1) per-crate ad-hoc stripping — rejected
//! because it fragments coverage and is error-prone when new crates are added;
//! (2) a separate `sigint-redact` crate — rejected because it introduces an
//! unnecessary crate boundary for a small, self-contained module; (3) runtime
//! config knob to disable redaction — rejected because credential leakage must
//! never be opt-in.  The design uses `std::sync::OnceLock` (stable since Rust
//! 1.70) instead of `once_cell` to avoid an external dependency.
//!
//! @decision DEC-CORE-REDACT-002
//! @title Extend password-kv separator to match URL-encoded `=` (%3D / %3d)
//! @status accepted
//! @rationale CSO re-run finding L1: the separator class `[:=]` missed the
//! URL-encoded form `%3D` (and its lowercase variant `%3d`), allowing
//! `password%3Dhunter2` to slip through unredacted. The fix replaces the two-
//! character class with a non-capturing alternation `(?:[:=]|%3[Dd])` which
//! covers bare colon, bare equals, and both case variants of the percent-encoded
//! equals sign. Non-capturing groups are a basic regex feature present in the
//! workspace `regex` crate regardless of unicode feature flags.

use std::sync::OnceLock;

use regex::Regex;

/// A compiled pattern and its replacement string.
struct Pattern {
    re: Regex,
    replacement: &'static str,
}

/// Global list of compiled credential patterns, initialised once.
static REDACT_PATTERNS: OnceLock<Vec<Pattern>> = OnceLock::new();

fn patterns() -> &'static Vec<Pattern> {
    REDACT_PATTERNS.get_or_init(|| {
        vec![
            // Anthropic keys must come before the generic OpenAI sk- pattern
            // because "sk-ant-" is a strict subset of "sk-" and the longer
            // match should win.
            Pattern {
                re: Regex::new(r"sk-ant-[A-Za-z0-9_-]{20,}").unwrap(),
                replacement: "sk-ant-<redacted>",
            },
            // OpenAI keys: sk-... (>=20 alphanumeric/underscore chars)
            Pattern {
                re: Regex::new(r"sk-[A-Za-z0-9_-]{20,}").unwrap(),
                replacement: "sk-<redacted>",
            },
            // AWS access key IDs
            Pattern {
                re: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
                replacement: "AKIA<redacted>",
            },
            // GitHub fine-grained PATs (github_pat_...)
            Pattern {
                re: Regex::new(r"github_pat_[A-Za-z0-9_]{82,}").unwrap(),
                replacement: "github_pat_<redacted>",
            },
            // GitHub classic PATs (ghp_, ghs_, ghr_)
            Pattern {
                re: Regex::new(r"gh[ps]_[A-Za-z0-9]{36,}").unwrap(),
                replacement: "gh*_<redacted>",
            },
            // Slack tokens
            Pattern {
                re: Regex::new(r"xox[baprs]-[A-Za-z0-9-]{10,}").unwrap(),
                replacement: "xox*-<redacted>",
            },
            // Bearer tokens in Authorization headers.
            // The workspace regex dep is compiled with default-features=false
            // (no unicode-case, no unicode-perl), so we avoid (?i) and \s.
            // [ \t] covers the space/tab between "Bearer" and the token value.
            Pattern {
                re: Regex::new(r"[Bb][Ee][Aa][Rr][Ee][Rr][ \t]+[A-Za-z0-9._\-+/=]{20,}")
                    .unwrap(),
                replacement: "Bearer <redacted>",
            },
            // Basic auth in Authorization headers
            Pattern {
                re: Regex::new(r"[Bb][Aa][Ss][Ii][Cc][ \t]+[A-Za-z0-9+/=]{16,}").unwrap(),
                replacement: "Basic <redacted>",
            },
            // password= / passwd= / pwd= / secret= / api_key= patterns.
            // Captures the key name so the replacement is e.g. "password=<redacted>".
            // [ \t]* replaces \s* to stay within the features compiled into the
            // workspace regex crate.  [^ \t"',;}\]]+ replaces [^"'\s,;}\]]+.
            Pattern {
                re: Regex::new(
                    r#"(password|passwd|pwd|secret|api[_-]?key)[ \t]*(?:[:=]|%3[Dd])[ \t]*["']?[^ \t"',;}\]]+"#,
                )
                .unwrap(),
                replacement: "$1=<redacted>",
            },
            // PEM private key blocks (multi-line — collapse to a single token).
            // (?s) makes `.` match `\n`; this flag only requires the `std`
            // feature (enabled) and does NOT need unicode-perl.
            Pattern {
                re: Regex::new(
                    r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
                )
                .unwrap(),
                replacement: "<redacted-private-key>",
            },
        ]
    })
}

/// Walk a text blob and redact every matching credential pattern.
///
/// Returns the redacted string and the count of individual matches replaced.
/// The count may be used by callers to emit a debug/warn log entry so that
/// operators know redaction occurred without logging the original value.
///
/// # Example
///
/// ```
/// let (clean, n) = sigint_core::redact("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload");
/// assert!(clean.contains("Bearer <redacted>"));
/// assert_eq!(n, 1);
/// ```
pub fn redact(input: &str) -> (String, usize) {
    let mut out = input.to_string();
    let mut count = 0usize;

    for p in patterns() {
        // Count matches on the current (already-partially-redacted) string
        // before replacing so we don't double-count after substitution.
        let n = p.re.find_iter(&out).count();
        if n > 0 {
            count += n;
            out = p.re.replace_all(&out, p.replacement).into_owned();
        }
    }

    (out, count)
}

/// Recursively walk a `serde_json::Value`, redacting all `String`-typed leaves.
///
/// Useful for redacting tool-call arguments (which arrive as a JSON object) at
/// persistence time, without having to serialise → redact-string → re-parse.
///
/// Returns the redacted value and the total count of individual pattern matches.
pub fn redact_json(value: &serde_json::Value) -> (serde_json::Value, usize) {
    let mut count = 0usize;
    let redacted = redact_json_inner(value, &mut count);
    (redacted, count)
}

fn redact_json_inner(value: &serde_json::Value, count: &mut usize) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => {
            let (red, n) = redact(s);
            *count += n;
            serde_json::Value::String(red)
        }
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(|v| redact_json_inner(v, count)).collect())
        }
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), redact_json_inner(v, count)))
                .collect(),
        ),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── Pattern tests ─────────────────────────────────────────────────────────

    #[test]
    fn redacts_openai_sk_key() {
        let input = "my key sk-abc123def456ghi789jklm";
        let (out, n) = redact(input);
        assert!(out.contains("sk-<redacted>"), "output: {out}");
        assert!(
            !out.contains("sk-abc123def456ghi789jklm"),
            "secret leaked: {out}"
        );
        assert_eq!(n, 1);
    }

    #[test]
    fn redacts_anthropic_sk_ant_key() {
        // Longer Anthropic key format.
        let input = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH";
        let (out, n) = redact(input);
        assert!(out.contains("sk-ant-<redacted>"), "output: {out}");
        assert!(!out.contains("sk-ant-api03"), "secret leaked: {out}");
        assert_eq!(n, 1);
    }

    #[test]
    fn redacts_aws_akia_key() {
        let input = "AKIAIOSFODNN7EXAMPLE";
        let (out, n) = redact(input);
        assert!(out.contains("AKIA<redacted>"), "output: {out}");
        assert!(
            !out.contains("AKIAIOSFODNN7EXAMPLE"),
            "secret leaked: {out}"
        );
        assert_eq!(n, 1);
    }

    #[test]
    fn redacts_github_pat() {
        // Classic PAT format: ghp_ + 36 alphanumeric chars.
        let token = format!("ghp_{}", "x".repeat(36));
        let input = format!("token={token}");
        let (out, n) = redact(&input);
        assert!(out.contains("gh*_<redacted>"), "output: {out}");
        assert!(!out.contains(&token), "secret leaked: {out}");
        assert_eq!(n, 1);
    }

    #[test]
    fn redacts_bearer_header() {
        // The header name must be preserved; only the token value is redacted.
        let input = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload";
        let (out, n) = redact(input);
        assert!(out.contains("Bearer <redacted>"), "output: {out}");
        assert!(out.contains("Authorization:"), "header name removed: {out}");
        assert!(!out.contains("eyJhbGci"), "token leaked: {out}");
        assert_eq!(n, 1);
    }

    #[test]
    fn redacts_password_kv() {
        let input = "password=hunter2foo";
        let (out, n) = redact(input);
        assert!(out.contains("password=<redacted>"), "output: {out}");
        assert!(!out.contains("hunter2foo"), "secret leaked: {out}");
        assert_eq!(n, 1);
    }

    #[test]
    fn redacts_pem_private_key_block() {
        let pem =
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----";
        let input = format!("key data:\n{pem}\nend");
        let (out, n) = redact(&input);
        assert!(out.contains("<redacted-private-key>"), "output: {out}");
        assert!(!out.contains("MIIEowIBAAKCAQEA"), "key leaked: {out}");
        // The surrounding text is preserved.
        assert!(out.contains("key data:"), "surrounding text lost: {out}");
        assert_eq!(n, 1);
    }

    #[test]
    fn does_not_redact_innocent_text() {
        // "sk" alone, short, not matching minimum length; no other patterns.
        let input = "the quick brown fox sk that's not a key";
        let (out, n) = redact(input);
        assert_eq!(out, input, "innocent text was modified");
        assert_eq!(n, 0);
    }

    // ── JSON walker tests ─────────────────────────────────────────────────────

    #[test]
    fn redact_json_walks_arrays_and_objects() {
        let value = json!({
            "headers": ["Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload"],
            "body": {
                "api_key": "sk-abc123def456ghi789jklm"
            }
        });
        let (out, n) = redact_json(&value);
        let serialised = out.to_string();
        assert!(
            serialised.contains("Bearer <redacted>"),
            "bearer not redacted: {serialised}"
        );
        assert!(
            serialised.contains("sk-<redacted>"),
            "openai key not redacted: {serialised}"
        );
        assert!(
            !serialised.contains("eyJhbGci"),
            "bearer token leaked: {serialised}"
        );
        assert!(
            !serialised.contains("sk-abc123"),
            "openai key leaked: {serialised}"
        );
        assert!(n >= 2, "expected at least 2 redactions, got {n}");
    }

    #[test]
    #[allow(clippy::approx_constant)] // 3.14 is an arbitrary sentinel, not pi
    fn redact_json_preserves_non_string_types() {
        let value = json!({
            "count": 42,
            "enabled": true,
            "nothing": null,
            "ratio": 3.14
        });
        let (out, n) = redact_json(&value);
        assert_eq!(out["count"], json!(42));
        assert_eq!(out["enabled"], json!(true));
        assert_eq!(out["nothing"], json!(null));
        assert_eq!(n, 0);
    }

    // ── URL-encoded separator tests (DEC-CORE-REDACT-002) ────────────────────

    #[test]
    fn redacts_url_encoded_password_separator() {
        // password%3Dhunter2 — uppercase %3D (URL-encoded `=`)
        let input = "password%3Dhunter2foo";
        let (out, n) = redact(input);
        assert!(out.contains("<redacted>"), "output: {out}");
        assert!(!out.contains("hunter2foo"), "secret leaked: {out}");
        assert_eq!(n, 1);
    }

    #[test]
    fn redacts_url_encoded_password_uppercase() {
        // password%3DHUNTER2FOO — test uppercase encoded form
        let input = "password%3DHUNTER2FOO";
        let (out, n) = redact(input);
        assert!(out.contains("<redacted>"), "output: {out}");
        assert!(!out.contains("HUNTER2FOO"), "secret leaked: {out}");
        assert_eq!(n, 1);
    }

    #[test]
    fn redacts_password_lowercase_url_encoded() {
        // PASSWORD%3dfoo — lowercase %3d variant
        let input = "password%3dfoo";
        let (out, n) = redact(input);
        assert!(out.contains("<redacted>"), "output: {out}");
        assert!(!out.contains("foo"), "secret leaked: {out}");
        assert_eq!(n, 1);
    }

    #[test]
    fn redact_returns_count_of_redactions() {
        // Three distinct secret patterns in one string.
        let input = concat!(
            "key1=sk-abc123def456ghi789jklm ",
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload ",
            "AKIAIOSFODNN7EXAMPLE"
        );
        let (out, n) = redact(input);
        // All three should be gone.
        assert!(
            out.contains("sk-<redacted>"),
            "openai key not redacted: {out}"
        );
        assert!(
            out.contains("Bearer <redacted>"),
            "bearer not redacted: {out}"
        );
        assert!(
            out.contains("AKIA<redacted>"),
            "aws key not redacted: {out}"
        );
        assert_eq!(n, 3, "expected 3 redactions, got {n}");
    }
}
