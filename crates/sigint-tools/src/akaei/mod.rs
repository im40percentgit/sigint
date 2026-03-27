//! akaei — HackRF SDR tool wrappers for the SIGINT agent layer.
//!
//! This module provides seven tool wrappers around the `akaei` CLI, a full-spectrum
//! HackRF SDR platform supporting RF sweeping, protocol decoding, signal analysis,
//! IoT auditing, and RF fingerprinting.
//!
//! @decision DEC-AKAEI-001
//! @title akaei tools use tokio::process::Command directly — no sandbox
//! @status accepted
//! @rationale akaei requires USB device access (/dev/bus/usb) for HackRF hardware.
//! The hakoniwa sandbox uses Linux user namespaces which break libusb permission
//! checks — libusb needs the real UID/GID to pass the plugdev group check.
//! Using tokio::process::Command directly with tokio::time::timeout provides the
//! same async timeout semantics as the sandboxed path while preserving USB device
//! visibility. Risk is acceptable: akaei is a known user-controlled binary, all
//! arguments are validated before passing, and USB hardware access is the explicit
//! intended use case for this integration.
//!
//! @decision DEC-AKAEI-002
//! @title Output parsers are command-specific (JSON-lines, text, tab-separated)
//! @status accepted
//! @rationale akaei's subcommands emit heterogeneous output formats — `decode`
//! writes JSON-lines, `freqdb` writes tab-separated text, `sweep` and `scan`
//! write space-separated numeric text, `analyze` and `fingerprint` write
//! human-readable text, and `audit` writes JSON. Each tool wrapper contains its
//! own parser that normalises output into structured JSON for the agent layer.
//! A single universal parser would require a discriminated union of all formats
//! and would be harder to test and maintain than per-tool parsers.

use std::time::{Duration, Instant};

use tokio::process::Command;
use tokio::time::timeout;
use tracing::info;

use crate::error::{Result, ToolError};
use crate::result::ToolResult;

pub mod analyze;
pub mod audit;
pub mod decode;
pub mod fingerprint;
pub mod freqdb;
pub mod scan;
pub mod sweep;

pub use analyze::AkaeiAnalyzeTool;
pub use audit::AkaeiAuditTool;
pub use decode::AkaeiDecodeTool;
pub use fingerprint::AkaeiFingerprintTool;
pub use freqdb::AkaeiFreqdbTool;
pub use scan::AkaeiScanTool;
pub use sweep::AkaeiSweepTool;

/// Shared helper: spawn `akaei <subcommand> [args...]` with a timeout.
///
/// Resolves the `akaei` binary via PATH. Captures stdout and stderr. The
/// caller is responsible for parsing the output into structured form.
///
/// # Arguments
/// * `subcommand`    — the akaei subcommand name (e.g., `"sweep"`, `"decode"`)
/// * `args`          — additional arguments appended after the subcommand
/// * `timeout_secs`  — wall-clock timeout; returns `ToolError::Timeout` on expiry
pub(crate) async fn run_akaei(
    subcommand: &str,
    args: &[&str],
    timeout_secs: u64,
) -> Result<ToolResult> {
    info!(subcommand, ?args, timeout_secs, "running akaei subcommand");

    let start = Instant::now();

    let mut cmd = Command::new("akaei");
    cmd.arg(subcommand);
    for arg in args {
        cmd.arg(arg);
    }
    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());

    let child = cmd
        .spawn()
        .map_err(|e| ToolError::Sandbox(format!("failed to spawn akaei: {e}")))?;

    let duration_limit = Duration::from_secs(timeout_secs);

    let output = timeout(duration_limit, child.wait_with_output())
        .await
        .map_err(|_| ToolError::Timeout(timeout_secs))?
        .map_err(|e| ToolError::Sandbox(format!("akaei process error: {e}")))?;

    let duration = start.elapsed();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let exit_code = output.status.code().unwrap_or(-1);

    Ok(ToolResult {
        stdout,
        stderr,
        exit_code,
        duration,
        structured_data: None,
        status: Default::default(),
        truncation: None,
    })
}

#[cfg(test)]
mod tests {
    /// Verify error shape when the binary is absent — no panic, correct error type.
    #[test]
    fn sandbox_error_message_format() {
        let err = crate::error::ToolError::Sandbox("failed to spawn akaei: No such file".into());
        assert!(
            err.to_string().contains("sandbox error:"),
            "unexpected: {err}"
        );
    }
}
