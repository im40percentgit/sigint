//! ToolResult — captured output from a tool execution.
//!
//! @decision DEC-TOOL-002
//! @title ToolResult mirrors SandboxOutput with optional structured data
//! @status accepted
//! @rationale SandboxOutput carries raw stdout/stderr/exit_code/duration from
//! the sandbox layer. ToolResult wraps those same fields and adds an optional
//! `structured_data` field for tools that parse their own output into JSON
//! (e.g., an nmap XML parser in a future phase). The Display impl produces a
//! concise summary suitable for feeding back to the LLM as a tool-role message.

use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Three-state completion status for a tool scan.
///
/// @decision DEC-P13-001
/// @title Three-state scan status (Complete/TimedOut/Partial) provides tool-agnostic completion metadata
/// @status accepted
/// @rationale Agents can reason about coverage gaps without tool-specific logic.
/// A TimedOut result still carries whatever partial output was captured before the
/// timeout. A Partial result carries a human-readable reason so the agent knows
/// why the scan ended early (e.g., "max results reached", "connection refused").
/// Default is Complete so existing construction sites require no change.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ScanStatus {
    /// The tool ran to completion without interruption.
    Complete,
    /// The tool was killed because it exceeded its configured timeout.
    TimedOut,
    /// The tool stopped early for a tool-specific reason.
    Partial(String),
}

impl Default for ScanStatus {
    fn default() -> Self {
        ScanStatus::Complete
    }
}

/// Byte-count metadata for a truncated output field.
///
/// When stdout is capped by the sandbox output cap, this struct records how
/// many bytes were originally produced vs how many were retained so the agent
/// knows how much data was dropped.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TruncationInfo {
    /// Number of bytes in the original (uncapped) stdout.
    pub original_bytes: usize,
    /// Number of bytes retained after truncation.
    pub kept_bytes: usize,
}

/// Captured output from a completed tool execution.
#[derive(Debug, Clone)]
pub struct ToolResult {
    /// Text written to stdout by the tool process.
    pub stdout: String,
    /// Text written to stderr by the tool process.
    pub stderr: String,
    /// Exit code returned by the tool (−1 if killed by signal).
    pub exit_code: i32,
    /// Wall-clock duration of the tool execution.
    pub duration: Duration,
    /// Optional structured representation of the tool output.
    /// Populated by tools that parse their own output (e.g., nmap XML).
    pub structured_data: Option<Value>,
    /// Whether the tool completed, timed out, or stopped early.
    pub status: ScanStatus,
    /// Present when stdout was capped by the sandbox output limit.
    pub truncation: Option<TruncationInfo>,
}

impl ToolResult {
    /// Returns true when the tool exited successfully (exit code 0).
    pub fn success(&self) -> bool {
        self.exit_code == 0
    }
}

impl fmt::Display for ToolResult {
    /// Produce a concise summary for feeding back to the LLM as a tool message.
    ///
    /// Format:
    ///   [TIMED OUT]                              ← only when status == TimedOut
    ///   [PARTIAL: <reason>]                      ← only when status == Partial
    ///   [exit: N | duration: Xms]
    ///   <stdout (truncated to 4 KB if longer, or to sandbox cap if set)>
    ///   [output truncated: X bytes -> Y bytes]   ← only when truncation is Some
    ///   [stderr: <first line of stderr, if non-empty>]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Prepend status prefix when not complete.
        match &self.status {
            ScanStatus::Complete => {}
            ScanStatus::TimedOut => writeln!(f, "[TIMED OUT]")?,
            ScanStatus::Partial(reason) => writeln!(f, "[PARTIAL: {}]", reason)?,
        }

        writeln!(
            f,
            "[exit: {} | duration: {}ms]",
            self.exit_code,
            self.duration.as_millis()
        )?;

        // Truncate stdout to 4 KB to keep LLM context usage reasonable.
        // When TruncationInfo is present (sandbox-level cap), use its byte
        // counts for the truncation message instead of the hardcoded marker.
        const MAX_STDOUT: usize = 4096;
        if self.stdout.len() > MAX_STDOUT {
            write!(f, "{}", &self.stdout[..MAX_STDOUT])?;
            if let Some(ref info) = self.truncation {
                write!(
                    f,
                    "\n[output truncated: {} bytes -> {} bytes]",
                    info.original_bytes, info.kept_bytes
                )?;
            } else {
                write!(f, "\n[... output truncated at 4 KB ...]")?;
            }
        } else if !self.stdout.is_empty() {
            write!(f, "{}", self.stdout.trim_end())?;
            // Show truncation info even when stdout fits under 4 KB (e.g. the
            // sandbox cap was smaller than 4 KB).
            if let Some(ref info) = self.truncation {
                write!(
                    f,
                    "\n[output truncated: {} bytes -> {} bytes]",
                    info.original_bytes, info.kept_bytes
                )?;
            }
        }

        // Append the first line of stderr when non-empty.
        if !self.stderr.is_empty() {
            let first_line = self.stderr.lines().next().unwrap_or("");
            write!(f, "\n[stderr: {}]", first_line)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn make_result(stdout: &str, stderr: &str, exit_code: i32) -> ToolResult {
        ToolResult {
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
            exit_code,
            duration: Duration::from_millis(123),
            structured_data: None,
            status: ScanStatus::Complete,
            truncation: None,
        }
    }

    #[test]
    fn success_true_on_zero_exit() {
        let r = make_result("ok", "", 0);
        assert!(r.success());
    }

    #[test]
    fn success_false_on_nonzero_exit() {
        let r = make_result("", "", 1);
        assert!(!r.success());
    }

    #[test]
    fn display_includes_exit_and_duration() {
        let r = make_result("hello", "", 0);
        let s = r.to_string();
        assert!(s.contains("exit: 0"), "should contain exit code: {s}");
        assert!(
            s.contains("duration: 123ms"),
            "should contain duration: {s}"
        );
    }

    #[test]
    fn display_includes_stdout() {
        let r = make_result("scan output here", "", 0);
        let s = r.to_string();
        assert!(s.contains("scan output here"), "stdout missing: {s}");
    }

    #[test]
    fn display_includes_stderr_first_line() {
        let r = make_result("", "error line 1\nerror line 2", 1);
        let s = r.to_string();
        assert!(s.contains("[stderr: error line 1]"), "stderr missing: {s}");
        assert!(
            !s.contains("error line 2"),
            "only first stderr line should appear: {s}"
        );
    }

    #[test]
    fn display_truncates_long_stdout_no_truncation_info() {
        // Without TruncationInfo the old hardcoded marker should appear.
        let long = "x".repeat(5000);
        let r = make_result(&long, "", 0);
        let s = r.to_string();
        assert!(
            s.contains("truncated at 4 KB"),
            "truncation marker missing: {s}"
        );
    }

    #[test]
    fn display_truncates_long_stdout_with_truncation_info() {
        // With TruncationInfo present, show byte counts instead of old marker.
        let long = "x".repeat(5000);
        let mut r = make_result(&long, "", 0);
        r.truncation = Some(TruncationInfo {
            original_bytes: 8192,
            kept_bytes: 4096,
        });
        let s = r.to_string();
        assert!(
            s.contains("output truncated: 8192 bytes -> 4096 bytes"),
            "byte-count truncation message missing: {s}"
        );
        assert!(
            !s.contains("truncated at 4 KB"),
            "old marker should not appear when TruncationInfo present: {s}"
        );
    }

    #[test]
    fn display_no_stderr_section_when_empty() {
        let r = make_result("data", "", 0);
        let s = r.to_string();
        assert!(!s.contains("[stderr:"), "unexpected stderr section: {s}");
    }

    // --- ScanStatus tests ---

    #[test]
    fn scan_status_complete_no_prefix() {
        let r = make_result("output", "", 0);
        let s = r.to_string();
        assert!(
            !s.contains("TIMED OUT"),
            "Complete should have no TIMED OUT prefix: {s}"
        );
        assert!(
            !s.contains("PARTIAL"),
            "Complete should have no PARTIAL prefix: {s}"
        );
    }

    #[test]
    fn scan_status_timed_out_shows_prefix() {
        let mut r = make_result("partial output", "", -1);
        r.status = ScanStatus::TimedOut;
        let s = r.to_string();
        assert!(s.starts_with("[TIMED OUT]"), "TimedOut prefix missing: {s}");
    }

    #[test]
    fn scan_status_partial_shows_reason() {
        let mut r = make_result("some data", "", 0);
        r.status = ScanStatus::Partial("max results reached".to_string());
        let s = r.to_string();
        assert!(
            s.starts_with("[PARTIAL: max results reached]"),
            "Partial prefix missing: {s}"
        );
    }

    #[test]
    fn scan_status_default_is_complete() {
        assert_eq!(ScanStatus::default(), ScanStatus::Complete);
    }

    // --- TruncationInfo tests ---

    #[test]
    fn truncation_info_short_stdout_with_info() {
        // TruncationInfo appears even when stdout fits under 4 KB.
        let mut r = make_result("short output", "", 0);
        r.truncation = Some(TruncationInfo {
            original_bytes: 1_048_576,
            kept_bytes: 100,
        });
        let s = r.to_string();
        assert!(
            s.contains("output truncated: 1048576 bytes -> 100 bytes"),
            "truncation info missing for short stdout: {s}"
        );
    }
}
