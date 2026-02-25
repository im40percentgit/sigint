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
}

impl SandboxedCommand {
    /// Create a new builder for `program` (full path or bare name resolved via rootfs).
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            network: NetworkMode::None,
            timeout_secs: 60,
        }
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
                let resolv_path = "/run/systemd/resolve/resolv.conf";
                if let Ok(contents) = std::fs::read_to_string(resolv_path) {
                    let _ = std::fs::write(&resolv_dst, contents);
                }
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
                if msg.to_lowercase().contains("timeout") || msg.to_lowercase().contains("timed out") {
                    SandboxError::Timeout(self.timeout_secs)
                } else {
                    SandboxError::Execution(msg)
                }
            })?;

        let duration = start.elapsed();
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        // ExitStatus.exit_code is Option<i32> (None when killed by signal).
        let exit_code = output.status.exit_code.unwrap_or(-1);
        let success = output.status.success();

        debug!(
            exit_code,
            success,
            duration_ms = duration.as_millis() as u64,
            stdout_len = stdout.len(),
            stderr_len = stderr.len(),
            "sandboxed command completed"
        );

        Ok(SandboxOutput {
            stdout,
            stderr,
            exit_code,
            success,
            duration,
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

    /// Returns true when the system has the prerequisites for hakoniwa execution:
    /// user namespaces + newuidmap/newgidmap (from the uidmap package).
    ///
    /// hakoniwa's Container::new() maps the current uid via a direct write to
    /// /proc/self/uid_map (single-entry path) or via newuidmap (multi-entry).
    /// Even the single-entry direct-write path fails in some environments.
    /// We probe with newuidmap presence as the reliable gate.
    fn sandbox_available() -> bool {
        // newuidmap is required for hakoniwa's uid mapping step.
        std::path::Path::new("/usr/bin/newuidmap").exists()
            || std::path::Path::new("/usr/sbin/newuidmap").exists()
            || std::env::var_os("PATH").is_some_and(|paths| {
                std::env::split_paths(&paths)
                    .any(|d| d.join("newuidmap").is_file())
            })
    }

    /// Requires user namespaces + newuidmap (uidmap package).
    #[test]
    fn execute_echo_in_sandbox() {
        if !sandbox_available() {
            eprintln!("SKIP execute_echo_in_sandbox: newuidmap not found (install uidmap package)");
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
            eprintln!("SKIP execute_nonexistent_command_errors: newuidmap not found");
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
            eprintln!("SKIP execute_captures_exit_code: newuidmap not found");
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
            eprintln!("SKIP dev_null_exists_in_pasta_sandbox: newuidmap not found");
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
            out.exit_code,
            out.stderr
        );
        assert_eq!(out.stdout.trim(), "success");
    }

    #[test]
    fn execute_timeout_kills_process() {
        if !sandbox_available() {
            eprintln!("SKIP execute_timeout_kills_process: newuidmap not found");
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
}
