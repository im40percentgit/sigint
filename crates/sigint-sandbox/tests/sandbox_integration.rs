//! Integration tests for sigint-sandbox.
//!
//! These tests exercise the full sandbox execution path against real Linux
//! namespaces. They require:
//!   - Unprivileged user namespaces (available on most modern Linux kernels)
//!   - /bin/echo, /bin/false, /bin/sleep present on the host
//!
//! The #[ignore] nmap test additionally requires:
//!   - nmap installed (`apt install nmap`)
//!   - passt installed (`apt install passt`, provides the `pasta` binary)
//!   - Network access to scanme.nmap.org
//!
//! @decision DEC-SAND-005
//! @title Integration tests run against real namespaces, no mocks
//! @status accepted
//! @rationale Sandbox correctness cannot be verified by mocking the OS
//! primitives. Tests fork real child processes inside real namespaces.
//! The nmap test is #[ignore] so CI doesn't require passt/network access,
//! but it can be run manually to prove the full Pasta networking path works.

use sigint_sandbox::{NetworkMode, SandboxedCommand, SandboxError};

/// Returns true when newuidmap is on PATH (required by hakoniwa's uid mapping step).
fn sandbox_available() -> bool {
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|d| d.join("newuidmap").is_file())
    }) || std::path::Path::new("/usr/bin/newuidmap").exists()
        || std::path::Path::new("/usr/sbin/newuidmap").exists()
}

/// Basic execution: stdout capture and zero exit code.
#[test]
fn echo_hello_in_sandbox() {
    if !sandbox_available() {
        eprintln!("SKIP: newuidmap not found — install uidmap package");
        return;
    }
    let out = SandboxedCommand::new("/bin/echo")
        .arg("hello")
        .timeout(10)
        .execute()
        .expect("sandboxed echo should succeed");

    assert!(out.success, "expected success, got exit_code={}", out.exit_code);
    assert_eq!(out.stdout.trim(), "hello");
    assert_eq!(out.exit_code, 0);
    assert!(out.stderr.is_empty() || out.stderr.trim().is_empty());
}

/// Non-zero exit code is captured correctly.
#[test]
fn false_exits_nonzero() {
    if !sandbox_available() {
        eprintln!("SKIP: newuidmap not found — install uidmap package");
        return;
    }
    let out = SandboxedCommand::new("/bin/false")
        .timeout(5)
        .execute()
        .expect("sandbox itself should not fail");

    assert!(!out.success);
    assert_eq!(out.exit_code, 1);
}

/// A missing binary produces an error (not a panic or silent failure).
#[test]
fn nonexistent_command_returns_error() {
    if !sandbox_available() {
        eprintln!("SKIP: newuidmap not found — install uidmap package");
        return;
    }
    let result = SandboxedCommand::new("/bin/__sigint_nonexistent_binary__")
        .timeout(5)
        .execute();

    // hakoniwa may return Ok(Output) with non-zero exit code for missing
    // binaries rather than Err, so we accept either form.
    match result {
        Err(_) => {} // sandbox errored — fine
        Ok(out) => assert!(!out.success, "missing binary should not succeed"),
    }
}

/// Short timeout kills a long-running process.
#[test]
fn timeout_kills_sleep() {
    if !sandbox_available() {
        eprintln!("SKIP: newuidmap not found — install uidmap package");
        return;
    }
    let result = SandboxedCommand::new("/bin/sleep")
        .arg("60")
        .timeout(1)
        .execute();

    // Acceptable outcomes: explicit Timeout error, Execution error,
    // or the process was killed (non-zero exit).
    match result {
        Err(SandboxError::Timeout(_)) => { /* expected */ }
        Err(SandboxError::Execution(_)) => { /* also acceptable */ }
        Ok(out) => assert!(
            !out.success,
            "sleep should not have exited successfully within 1s"
        ),
        Err(other) => panic!("unexpected error variant: {other}"),
    }
}

/// Bare command name (no path) resolves and executes correctly.
#[test]
fn bare_command_name_resolves() {
    if !sandbox_available() {
        eprintln!("SKIP: newuidmap not found — install uidmap package");
        return;
    }
    // "echo" (bare name) should resolve to /bin/echo or /usr/bin/echo.
    let out = SandboxedCommand::new("echo")
        .arg("resolved")
        .timeout(10)
        .execute()
        .expect("bare 'echo' should resolve and execute");

    assert!(out.success, "exit_code={}", out.exit_code);
    assert_eq!(out.stdout.trim(), "resolved");
}

/// Basic Pasta networking: echo still works with network namespace.
#[test]
#[ignore]
fn echo_with_pasta_works() {
    let out = SandboxedCommand::new("echo")
        .arg("pasta-ok")
        .network(NetworkMode::Pasta)
        .timeout(10)
        .execute()
        .expect("echo with Pasta should not error");

    assert!(out.success, "exit_code={}, stderr={}", out.exit_code, out.stderr);
    assert_eq!(out.stdout.trim(), "pasta-ok");
}

/// DNS lookup via dig inside a Pasta-networked sandbox.
///
/// Requires: dig (dnsutils), passt (pasta binary), network access.
/// Run with: cargo test -p sigint-sandbox -- --ignored
#[test]
#[ignore]
fn dig_dns_lookup_via_pasta() {
    let out = SandboxedCommand::new("dig")
        .args(["+short", "scanme.nmap.org"])
        .network(NetworkMode::Pasta)
        .timeout(30)
        .execute()
        .expect("dig sandbox execution should not error");

    assert!(
        out.success,
        "dig exited with code {}. stderr: {}",
        out.exit_code,
        out.stderr
    );
    assert!(
        !out.stdout.trim().is_empty(),
        "expected DNS response, got empty stdout"
    );
}

/// Full nmap scan via pasta networking.
///
/// Requires: nmap, passt (pasta binary), network access.
/// Run with: cargo test -p sigint-sandbox -- --ignored
#[test]
#[ignore]
fn nmap_scan_scanme_via_pasta() {
    let out = SandboxedCommand::new("nmap")
        .args(["-T4", "-F", "scanme.nmap.org"])
        .network(NetworkMode::Pasta)
        .timeout(120)
        .execute()
        .expect("nmap sandbox execution should not error");

    assert!(
        out.success,
        "nmap exited with code {}. stderr: {}",
        out.exit_code,
        out.stderr
    );
    assert!(
        out.stdout.contains("Nmap scan report"),
        "expected 'Nmap scan report' in stdout, got:\n{}",
        out.stdout
    );
}
