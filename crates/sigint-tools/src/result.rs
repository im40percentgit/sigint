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

use serde_json::Value;

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
    ///   [exit: N | duration: Xms]
    ///   <stdout (truncated to 4 KB if longer)>
    ///   [stderr: <first line of stderr, if non-empty>]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "[exit: {} | duration: {}ms]",
            self.exit_code,
            self.duration.as_millis()
        )?;

        // Truncate stdout to 4 KB to keep LLM context usage reasonable.
        const MAX_STDOUT: usize = 4096;
        if self.stdout.len() > MAX_STDOUT {
            write!(f, "{}", &self.stdout[..MAX_STDOUT])?;
            write!(f, "\n[... output truncated at 4 KB ...]")?;
        } else if !self.stdout.is_empty() {
            write!(f, "{}", self.stdout.trim_end())?;
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
    fn display_truncates_long_stdout() {
        let long = "x".repeat(5000);
        let r = make_result(&long, "", 0);
        let s = r.to_string();
        assert!(
            s.contains("truncated at 4 KB"),
            "truncation marker missing: {s}"
        );
    }

    #[test]
    fn display_no_stderr_section_when_empty() {
        let r = make_result("data", "", 0);
        let s = r.to_string();
        assert!(!s.contains("[stderr:"), "unexpected stderr section: {s}");
    }
}
