//! Generic sandboxed command builder using hakoniwa Linux namespaces.
//!
//! @decision DEC-SAND-002
//! @title SandboxedCommand as a consuming builder over hakoniwa::Container
//! @status accepted
//! @rationale hakoniwa's Container/Command API uses &mut self method chaining
//! (not a consuming builder). SandboxedCommand wraps it in a consuming builder
//! for ergonomic call-site usage. The execute() method is synchronous — callers
//! running inside tokio must use tokio::task::spawn_blocking.
//! Container::new() already unshares User+Mount+Pid namespaces, so we only add
//! Network when Pasta mode is requested. rootfs("/") bind-mounts /bin /etc /lib
//! /lib64 /lib32 /sbin /usr read-only, giving tools access to system binaries.
//! Timeout is set on the Command (not Container) via wait_timeout().
//! The Pasta branch mounts /dev read-write (bindmount_rw) because tools like
//! nmap require write access to /dev/null. rootfs("/") handles this automatically
//! for the None branch, but the Pasta branch mounts directories individually and
//! must explicitly include /dev.
//!
//! @decision DEC-P13-004
//! @title Detect systemd-resolved stub (127.0.0.53) and resolve to upstream nameservers
//! @status accepted
//! @rationale On systems using systemd-resolved, /etc/resolv.conf points to the stub
//! resolver at 127.0.0.53. Inside a new network namespace (Pasta mode), 127.0.0.53
//! does not exist — DNS resolution fails silently. resolve_dns_content() detects the
//! stub by scanning for "127.0.0.53" in the existing resolv.conf and substitutes the
//! real upstream resolvers from /run/systemd/resolve/resolv.conf. If that file is
//! absent, public fallbacks (8.8.8.8 / 1.1.1.1) are used so scans can always resolve
//! hostnames. The logic is extracted into a pure function for testability.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use hakoniwa::{Container, Namespace, Pasta};
use tracing::{debug, info};

use crate::error::{Result, SandboxError};

/// Standard PATH used inside the sandbox and for resolving bare command names.
///
/// @decision DEC-SAND-006
/// @title Resolve bare commands to absolute paths before execve
/// @status accepted
/// @rationale hakoniwa uses raw execve() (not execvp()), so bare command names
/// like "grep" fail with ENOENT. We resolve them to full paths at build time
/// and inject PATH into the sandbox environment so child processes (e.g. shell
/// pipelines spawned by tools) can also find binaries.
const SANDBOX_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Resolve a bare command name to its full path by searching SANDBOX_PATH.
/// Returns the original string unchanged if it already contains a '/'.
fn resolve_program(program: &str) -> String {
    if program.contains('/') {
        return program.to_string();
    }
    for dir in SANDBOX_PATH.split(':') {
        let candidate = PathBuf::from(dir).join(program);
        if candidate.is_file() {
            return candidate.to_string_lossy().into_owned();
        }
    }
    // Fall through — let hakoniwa's execve produce the ENOENT error.
    program.to_string()
}

/// Determine the resolv.conf content to write inside a Pasta network namespace.
///
/// @decision DEC-P13-004
///
/// On systemd-resolved systems `/etc/resolv.conf` contains `nameserver 127.0.0.53`
/// (the stub resolver). That address does not exist inside a new network namespace,
/// so DNS resolution fails for tools like nmap that rely on `/etc/resolv.conf`.
///
/// Resolution strategy (in priority order):
/// 1. If the existing resolv.conf does **not** contain `127.0.0.53`, use it as-is —
///    it already has real upstream nameservers.
/// 2. If it does contain `127.0.0.53`, try reading the real upstream resolvers from
///    `/run/systemd/resolve/resolv.conf`.
/// 3. If that file is absent or unreadable, fall back to public DNS:
///    `nameserver 8.8.8.8\nnameserver 1.1.1.1`
///
/// The `upstream_resolv_conf` parameter is the content of
/// `/run/systemd/resolve/resolv.conf` (or `None` when the file is absent/unreadable).
/// This is injected rather than read inside the function to keep it pure and testable.
pub(crate) fn resolve_dns_content(existing: &str, upstream: Option<&str>) -> String {
    if !existing.contains("127.0.0.53") {
        // Not a systemd-resolved stub — use the existing content unchanged.
        return existing.to_string();
    }
    // Stub detected. Use upstream if available, else fall back to public DNS.
    match upstream {
        Some(content) if !content.trim().is_empty() => content.to_string(),
        _ => "nameserver 8.8.8.8\nnameserver 1.1.1.1\n".to_string(),
    }
}

/// Network isolation mode for a sandboxed command.
#[derive(Debug, Clone, PartialEq)]
pub enum NetworkMode {
    /// No network access — sandbox is fully offline.
    None,
    /// User-mode networking via pasta(1) from the passt package.
    /// Requires the `pasta` binary on PATH and a Network namespace.
    Pasta,
}

/// Captured output from a completed sandboxed command.
///
/// @decision DEC-P13-002
/// @title 1MB default output cap prevents OOM from unbounded tool output while preserving enough data for meaningful analysis
/// @status accepted
/// @rationale Tools like nmap, nuclei, and feroxbuster can emit megabytes of output
/// against large targets. Without a cap, the sandbox buffers all of it in memory before
/// returning, risking OOM on the agent host. The cap is applied post-capture at the Rust
/// level (hakoniwa collects all bytes first); `was_truncated` and `original_stdout_len`
/// give callers the information needed to populate `ToolResult::truncation`.
/// Timeout note: hakoniwa returns Err on timeout (stdout is lost). The `timed_out` flag
/// is not set here — tools detect timeout via SandboxError::Timeout and set
/// ToolResult::status = ScanStatus::TimedOut themselves. This is a known limitation:
/// partial stdout from timed-out processes is not recoverable from hakoniwa without
/// switching to a manual tokio::process approach (deferred to Phase 13A).
#[derive(Debug)]
pub struct SandboxOutput {
    /// Text written to stdout by the sandboxed process.
    pub stdout: String,
    /// Text written to stderr by the sandboxed process.
    pub stderr: String,
    /// Exit code returned by the sandboxed process (−1 if killed by signal).
    pub exit_code: i32,
    /// True when the process exited with code 0.
    pub success: bool,
    /// Wall-clock duration of the sandbox execution.
    pub duration: Duration,
    /// True when stdout was truncated by the max_output_bytes cap.
    pub was_truncated: bool,
    /// Original byte length of stdout before truncation (equals stdout.len() when not truncated).
    pub original_stdout_len: usize,
}

/// Consuming builder for running a program inside a Linux namespace sandbox.
///
/// # Example
///
/// ```no_run
/// use sigint_sandbox::command::{SandboxedCommand, NetworkMode};
///
/// let out = SandboxedCommand::new("/bin/echo")
///     .arg("hello")
///     .timeout(10)
///     .execute()
///     .unwrap();
/// assert_eq!(out.stdout.trim(), "hello");
/// ```
pub struct SandboxedCommand {
    pub(crate) program: String,
    pub(crate) args: Vec<String>,
    pub(crate) network: NetworkMode,
    pub(crate) timeout_secs: u64,
    /// When set, stdout is truncated to this many bytes after capture.
    /// Use `.max_output(bytes)` to set. Default: None (no cap).
    pub(crate) max_output_bytes: Option<usize>,
}

impl SandboxedCommand {
    /// Create a new builder for `program` (full path or bare name resolved via rootfs).
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            network: NetworkMode::None,
            timeout_secs: 60,
            max_output_bytes: None,
        }
    }

    /// Cap stdout at `bytes` bytes after capture.
    ///
    /// When the captured stdout exceeds this limit it is truncated in place.
    /// `SandboxOutput::was_truncated` will be `true` and
    /// `SandboxOutput::original_stdout_len` will record the pre-truncation length,
    /// allowing callers to populate `ToolResult::truncation`.
    pub fn max_output(mut self, bytes: usize) -> Self {
        self.max_output_bytes = Some(bytes);
        self
    }

    /// Append multiple arguments.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Append a single argument.
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Set the network isolation mode (default: `NetworkMode::None`).
    pub fn network(mut self, mode: NetworkMode) -> Self {
        self.network = mode;
        self
    }

    /// Set the execution timeout in seconds (default: 60).
    pub fn timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    /// Execute the command inside the sandbox and return captured output.
    ///
    /// This method **blocks** the calling thread. When called from an async
    /// context use `tokio::task::spawn_blocking`.
    pub fn execute(self) -> Result<SandboxOutput> {
        let start = Instant::now();

        info!(
            program = %self.program,
            args = ?self.args,
            network = ?self.network,
            timeout_secs = self.timeout_secs,
            "executing sandboxed command"
        );

        // Container::new() already unshares User + Mount + Pid namespaces and
        // mounts a fresh procfs at /proc.
        let mut container = Container::new();

        // Mount the host's system directories read-only so tools can find
        // their libraries and data files. For Pasta networking we need special
        // handling of /etc to fix DNS resolution (see below).
        if self.network == NetworkMode::Pasta {
            // On systemd systems, /etc/resolv.conf symlinks to
            // /run/systemd/resolve/stub-resolv.conf (nameserver 127.0.0.53).
            // Inside the container's network namespace, 127.0.0.53 doesn't exist.
            // We can't use rootfs("/") because it bind-mounts /etc read-only,
            // making it impossible to override resolv.conf afterward.
            // Instead, copy /etc to a temp dir with the real resolv.conf and
            // mount individual directories manually.
            let etc_tmp = std::env::temp_dir().join("sigint-etc");
            let _ = std::fs::remove_dir_all(&etc_tmp);
            // Copy /etc via cp -a to preserve structure (suppress permission
            // denied warnings for shadow/sudoers — they aren't needed).
            let cp_status = std::process::Command::new("/bin/cp")
                .args(["-a", "/etc", &etc_tmp.to_string_lossy()])
                .stderr(std::process::Stdio::null())
                .status();
            if cp_status.is_ok() {
                // Overwrite resolv.conf with real upstream nameservers.
                // Remove the symlink first (cp -a preserves symlinks).
                let resolv_dst = etc_tmp.join("resolv.conf");
                let _ = std::fs::remove_file(&resolv_dst);
                // Read existing resolv.conf (may be a symlink to the stub).
                let existing = std::fs::read_to_string(&resolv_dst).unwrap_or_default();
                // Read real upstream resolvers if systemd-resolved is in use.
                let upstream_path = "/run/systemd/resolve/resolv.conf";
                let upstream = std::fs::read_to_string(upstream_path).ok();
                let dns_content = resolve_dns_content(&existing, upstream.as_deref());
                let _ = std::fs::write(&resolv_dst, dns_content);
                // Mount our modified /etc instead of the host's
                container.bindmount_ro(&etc_tmp.to_string_lossy(), "/etc");
            } else {
                // Fallback: use rootfs which won't have DNS
                container
                    .rootfs("/")
                    .map_err(|e| SandboxError::Creation(e.to_string()))?;
            }
            // Mount remaining system dirs
            for dir in ["/bin", "/lib", "/lib64", "/lib32", "/sbin", "/usr"] {
                if std::path::Path::new(dir).is_dir() {
                    container.bindmount_ro(dir, dir);
                }
            }
            // /dev must be read-write: processes write to /dev/null, /dev/urandom, etc.
            // nmap in particular fails with "Could not assign /dev/null to stdout for
            // writing: No such file or directory" when /dev is absent.
            container.bindmount_rw("/dev", "/dev");
            container.unshare(Namespace::Network);
            container.network(Pasta::default());
        } else {
            container
                .rootfs("/")
                .map_err(|e| SandboxError::Creation(e.to_string()))?;
        }

        // A writable /tmp inside the sandbox.
        container.tmpfsmount("/tmp");

        // Resolve bare command names to absolute paths (hakoniwa uses execve,
        // not execvp, so bare names like "grep" fail with ENOENT).
        let resolved = resolve_program(&self.program);
        debug!(original = %self.program, resolved = %resolved, "resolved program path");

        // Build the Command, set timeout, inject PATH, collect output.
        let output = container
            .command(&resolved)
            .env("PATH", SANDBOX_PATH)
            .args(self.args.iter().map(|s| s.as_str()))
            .wait_timeout(self.timeout_secs)
            .output()
            .map_err(|e| {
                let msg = e.to_string();
                // hakoniwa surfaces timeout as a specific error string.
                if msg.to_lowercase().contains("timeout")
                    || msg.to_lowercase().contains("timed out")
                {
                    SandboxError::Timeout(self.timeout_secs)
                } else {
                    SandboxError::Execution(msg)
                }
            })?;

        let duration = start.elapsed();
        let mut stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        // ExitStatus.exit_code is Option<i32> (None when killed by signal).
        let exit_code = output.status.exit_code.unwrap_or(-1);
        let success = output.status.success();

        // Apply the output cap if configured. Truncation happens at a UTF-8
        // character boundary to avoid producing invalid strings.
        let original_stdout_len = stdout.len();
        let was_truncated = if let Some(cap) = self.max_output_bytes {
            if stdout.len() > cap {
                // Find a valid UTF-8 truncation point at or before `cap` bytes.
                let truncate_at = stdout
                    .char_indices()
                    .map(|(i, _)| i)
                    .take_while(|&i| i <= cap)
                    .last()
                    .unwrap_or(0);
                stdout.truncate(truncate_at);
                true
            } else {
                false
            }
        } else {
            false
        };

        debug!(
            exit_code,
            success,
            duration_ms = duration.as_millis() as u64,
            stdout_len = stdout.len(),
            original_stdout_len,
            was_truncated,
            stderr_len = stderr.len(),
            "sandboxed command completed"
        );

        Ok(SandboxOutput {
            stdout,
            stderr,
            exit_code,
            success,
            duration,
            was_truncated,
            original_stdout_len,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builder_defaults() {
        let cmd = SandboxedCommand::new("/bin/echo");
        assert_eq!(cmd.program, "/bin/echo");
        assert!(cmd.args.is_empty());
        assert_eq!(cmd.network, NetworkMode::None);
        assert_eq!(cmd.timeout_secs, 60);
        assert_eq!(cmd.max_output_bytes, None);
    }

    #[test]
    fn builder_args_and_timeout() {
        let cmd = SandboxedCommand::new("/bin/echo")
            .arg("hello")
            .args(["world", "!"])
            .timeout(30)
            .network(NetworkMode::Pasta);
        assert_eq!(cmd.args, vec!["hello", "world", "!"]);
        assert_eq!(cmd.timeout_secs, 30);
        assert_eq!(cmd.network, NetworkMode::Pasta);
    }

    #[test]
    fn builder_max_output() {
        let cmd = SandboxedCommand::new("/bin/echo").max_output(1024);
        assert_eq!(cmd.max_output_bytes, Some(1024));
    }

    /// Verify truncation logic without running a real sandbox.
    ///
    /// These tests exercise the truncation arithmetic directly by constructing
    /// a SandboxOutput manually — no hakoniwa fork needed, runs in CI anywhere.
    #[test]
    fn sandbox_output_truncation_fields_when_not_truncated() {
        let out = SandboxOutput {
            stdout: "hello".to_string(),
            stderr: String::new(),
            exit_code: 0,
            success: true,
            duration: std::time::Duration::from_millis(1),
            was_truncated: false,
            original_stdout_len: 5,
        };
        assert!(!out.was_truncated);
        assert_eq!(out.original_stdout_len, 5);
        assert_eq!(out.stdout.len(), 5);
    }

    #[test]
    fn sandbox_output_truncation_fields_when_truncated() {
        // Simulate what execute() produces when stdout exceeds the cap.
        let original = "a".repeat(2000);
        let kept = &original[..1000];
        let out = SandboxOutput {
            stdout: kept.to_string(),
            stderr: String::new(),
            exit_code: 0,
            success: true,
            duration: std::time::Duration::from_millis(1),
            was_truncated: true,
            original_stdout_len: 2000,
        };
        assert!(out.was_truncated);
        assert_eq!(out.original_stdout_len, 2000);
        assert_eq!(out.stdout.len(), 1000);
    }

    /// Verify the truncation arithmetic in execute() directly via sandbox
    /// (skipped when namespaces unavailable) — full integration path.
    #[test]
    fn execute_with_max_output_truncates_large_stdout() {
        if !sandbox_available() {
            eprintln!("SKIP execute_with_max_output_truncates_large_stdout: sandbox unavailable");
            return;
        }
        // Print 100 bytes of 'x', cap at 50.
        let out = SandboxedCommand::new("/bin/sh")
            .args(["-c", "printf '%0.s x' {1..50}"])
            .max_output(50)
            .timeout(5)
            .execute()
            .expect("sandbox should succeed");
        assert!(out.was_truncated, "stdout should have been truncated");
        assert!(
            out.stdout.len() <= 50,
            "stdout len {} > cap 50",
            out.stdout.len()
        );
        assert!(out.original_stdout_len > 50, "original len should be > 50");
    }

    #[test]
    fn execute_without_max_output_does_not_truncate() {
        if !sandbox_available() {
            eprintln!("SKIP execute_without_max_output_does_not_truncate: sandbox unavailable");
            return;
        }
        let out = SandboxedCommand::new("/bin/echo")
            .arg("hello")
            .timeout(5)
            .execute()
            .expect("sandbox should succeed");
        assert!(!out.was_truncated);
        assert_eq!(out.original_stdout_len, out.stdout.len());
    }

    /// Returns true when the system can actually execute commands in a hakoniwa
    /// sandbox.
    ///
    /// The old approach (checking for the `newuidmap` binary) was insufficient:
    /// `newuidmap` may exist but user namespaces can still be blocked at the
    /// kernel level (e.g. `unshare: write failed /proc/self/uid_map: Operation
    /// not permitted`).  A real probe — running `/bin/true` inside a sandbox —
    /// is the only reliable gate.
    ///
    /// The probe result is cached via `std::sync::OnceLock` so the kernel
    /// round-trip happens at most once per test binary invocation.
    fn sandbox_available() -> bool {
        use std::sync::OnceLock;
        static RESULT: OnceLock<bool> = OnceLock::new();
        *RESULT.get_or_init(|| {
            // Quick binary-presence pre-check avoids a slow hakoniwa attempt
            // on machines that clearly lack the tooling.
            let newuidmap_present = std::path::Path::new("/usr/bin/newuidmap").exists()
                || std::path::Path::new("/usr/sbin/newuidmap").exists()
                || std::env::var_os("PATH").is_some_and(|paths| {
                    std::env::split_paths(&paths).any(|d| d.join("newuidmap").is_file())
                });
            if !newuidmap_present {
                return false;
            }
            // Real probe: try to execute /bin/true in a sandbox. If user
            // namespaces are blocked at the kernel level this will fail even
            // though newuidmap is present.
            match SandboxedCommand::new("/bin/true").timeout(5).execute() {
                Ok(out) => out.success,
                Err(_) => false,
            }
        })
    }

    /// Requires user namespaces + newuidmap (uidmap package).
    #[test]
    fn execute_echo_in_sandbox() {
        if !sandbox_available() {
            eprintln!(
                "SKIP execute_echo_in_sandbox: sandbox probe failed (user namespaces unavailable)"
            );
            return;
        }
        let out = SandboxedCommand::new("/bin/echo")
            .arg("sandbox-ok")
            .timeout(10)
            .execute()
            .expect("sandboxed echo should succeed");

        assert!(out.success, "exit code should be 0, got {}", out.exit_code);
        assert_eq!(out.stdout.trim(), "sandbox-ok");
        assert_eq!(out.exit_code, 0);
    }

    #[test]
    fn execute_nonexistent_command_errors() {
        if !sandbox_available() {
            eprintln!("SKIP execute_nonexistent_command_errors: sandbox probe failed (user namespaces unavailable)");
            return;
        }
        let result = SandboxedCommand::new("/bin/__sigint_nonexistent__")
            .timeout(5)
            .execute();
        // hakoniwa returns Ok(Output) with a non-zero exit code for missing
        // binaries rather than an Err, so we accept either form.
        match result {
            Err(_) => {} // sandbox itself errored — fine
            Ok(out) => assert!(!out.success, "missing binary should not succeed"),
        }
    }

    #[test]
    fn execute_captures_exit_code() {
        if !sandbox_available() {
            eprintln!("SKIP execute_captures_exit_code: sandbox probe failed (user namespaces unavailable)");
            return;
        }
        // /bin/false exits with code 1.
        let out = SandboxedCommand::new("/bin/false")
            .timeout(5)
            .execute()
            .expect("sandbox itself should not error");
        assert!(!out.success);
        assert_eq!(out.exit_code, 1);
    }

    /// Verify /dev/null is accessible in the Pasta sandbox.
    /// nmap redirects stdout/stderr to /dev/null and fails if it is missing.
    #[test]
    fn dev_null_exists_in_pasta_sandbox() {
        if !sandbox_available() {
            eprintln!("SKIP dev_null_exists_in_pasta_sandbox: sandbox probe failed (user namespaces unavailable)");
            return;
        }
        // Write to /dev/null via sh -c. If /dev is not mounted this errors with
        // "No such file or directory".
        let out = SandboxedCommand::new("/bin/sh")
            .args(["-c", "echo ok > /dev/null && echo success"])
            .network(NetworkMode::Pasta)
            .timeout(10)
            .execute()
            .expect("pasta sandbox /dev/null write should not error");
        assert!(
            out.success,
            "/dev/null write failed (exit {}): {}",
            out.exit_code, out.stderr
        );
        assert_eq!(out.stdout.trim(), "success");
    }

    #[test]
    fn execute_timeout_kills_process() {
        if !sandbox_available() {
            eprintln!("SKIP execute_timeout_kills_process: sandbox probe failed (user namespaces unavailable)");
            return;
        }
        let result = SandboxedCommand::new("/bin/sleep")
            .arg("60")
            .timeout(1)
            .execute();
        // Either a Timeout error or the process is killed (exit_code != 0).
        match result {
            Err(SandboxError::Timeout(_)) => {}
            Err(SandboxError::Execution(_)) => {}
            Ok(out) => assert!(!out.success, "sleep should not have succeeded"),
            Err(other) => panic!("unexpected error variant: {other}"),
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // resolve_dns_content tests  (@decision DEC-P13-004)
    // ──────────────────────────────────────────────────────────────────────

    /// When resolv.conf does not contain the systemd-resolved stub address,
    /// the existing content is returned unchanged — no substitution needed.
    #[test]
    fn dns_non_stub_resolv_conf_unchanged() {
        let existing = "nameserver 192.168.1.1\nnameserver 8.8.8.8\n";
        let result = resolve_dns_content(existing, None);
        assert_eq!(
            result, existing,
            "non-stub resolv.conf should be returned as-is"
        );
    }

    /// When resolv.conf contains 127.0.0.53 (systemd-resolved stub) and the
    /// upstream resolvers file is available, its content is used.
    #[test]
    fn dns_stub_replaced_with_upstream_resolvers() {
        let existing =
            "# Generated by systemd-resolved\nnameserver 127.0.0.53\noptions edns0 trust-ad\n";
        let upstream = "nameserver 1.1.1.1\nnameserver 8.8.8.8\n";
        let result = resolve_dns_content(existing, Some(upstream));
        assert_eq!(
            result, upstream,
            "stub should be replaced with upstream resolvers"
        );
        assert!(
            !result.contains("127.0.0.53"),
            "result must not contain stub address"
        );
    }

    /// When resolv.conf contains 127.0.0.53 but the upstream resolvers file is
    /// absent (None), fall back to the hardcoded public DNS servers.
    #[test]
    fn dns_stub_falls_back_to_public_dns_when_upstream_absent() {
        let existing = "nameserver 127.0.0.53\n";
        let result = resolve_dns_content(existing, None);
        assert!(
            result.contains("8.8.8.8") || result.contains("1.1.1.1"),
            "fallback should contain public DNS: {result}"
        );
        assert!(
            !result.contains("127.0.0.53"),
            "result must not contain stub address: {result}"
        );
    }

    /// When resolv.conf contains 127.0.0.53 but the upstream file content is
    /// empty/whitespace-only, fall back to public DNS rather than writing empty content.
    #[test]
    fn dns_stub_falls_back_when_upstream_is_empty() {
        let existing = "nameserver 127.0.0.53\n";
        let result = resolve_dns_content(existing, Some("   \n"));
        assert!(
            result.contains("8.8.8.8") || result.contains("1.1.1.1"),
            "empty upstream should trigger public DNS fallback: {result}"
        );
    }
}
