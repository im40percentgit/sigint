//! Runtime detection of sandbox prerequisites.
//!
//! Checks whether the current system supports the features needed to run
//! sandboxed commands: user namespaces, pasta networking, and specific tools.
//!
//! @decision DEC-SAND-003
//! @title Capability detection via /proc and PATH walk at runtime
//! @status accepted
//! @rationale Probing at runtime (rather than compile-time feature flags)
//! lets the binary surface actionable error messages on misconfigured hosts
//! without failing to compile. The /proc/sys/kernel/unprivileged_userns_clone
//! check covers Debian/Ubuntu kernels; absent = unrestricted is the safe default
//! for other distros.

use crate::error::{Result, SandboxError};

/// Detected sandbox capabilities of the current system.
pub struct SandboxCapabilities {
    /// Whether unprivileged user namespaces are available.
    pub user_namespaces: bool,
    /// Whether the `pasta` binary (from the passt package) is on PATH.
    pub pasta_available: bool,
    /// Whether `nmap` is on PATH.
    pub nmap_available: bool,
}

impl SandboxCapabilities {
    /// Detect capabilities by probing the running system.
    pub fn detect() -> Self {
        Self {
            user_namespaces: check_user_namespaces(),
            pasta_available: which("pasta").is_some(),
            nmap_available: which("nmap").is_some(),
        }
    }

    /// Verify that the prerequisites for a specific tool are satisfied.
    ///
    /// Returns `Ok(())` if everything needed is present, or the first
    /// `SandboxError` that describes what is missing.
    pub fn check_for_tool(&self, tool: &str, needs_network: bool) -> Result<()> {
        if !self.user_namespaces {
            return Err(SandboxError::NoUserNamespaces);
        }
        if needs_network && !self.pasta_available {
            return Err(SandboxError::PastaNotFound);
        }
        if which(tool).is_none() {
            return Err(SandboxError::ToolNotFound(tool.to_string()));
        }
        Ok(())
    }
}

/// Returns true when unprivileged user namespaces are permitted on this kernel.
///
/// Checks two potential restriction sources:
/// 1. `/proc/sys/kernel/unprivileged_userns_clone` — Debian/Ubuntu sysctl
/// 2. `/proc/sys/kernel/apparmor_restrict_unprivileged_userns` — AppArmor on
///    Ubuntu 24.04+ / kernel 6.x blocks unconfined processes from creating
///    user namespaces even when unprivileged_userns_clone=1.
///
/// If a file is absent the kernel does not enforce that restriction.
fn check_user_namespaces() -> bool {
    let clone_ok = match std::fs::read_to_string("/proc/sys/kernel/unprivileged_userns_clone") {
        Ok(content) => content.trim() == "1",
        Err(_) => true, // file absent → not restricted
    };
    let apparmor_ok =
        match std::fs::read_to_string("/proc/sys/kernel/apparmor_restrict_unprivileged_userns") {
            Ok(content) => content.trim() == "0",
            Err(_) => true, // file absent → not restricted
        };
    clone_ok && apparmor_ok
}

/// Searches PATH for `binary` and returns its full path if found.
fn which(binary: &str) -> Option<std::path::PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|dir| dir.join(binary))
            .find(|path| path.is_file())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_does_not_panic() {
        let caps = SandboxCapabilities::detect();
        let _ = caps.user_namespaces;
    }

    #[test]
    fn which_finds_sh() {
        assert!(which("sh").is_some(), "expected 'sh' on PATH");
    }

    #[test]
    fn which_misses_nonexistent() {
        assert!(which("__sigint_nonexistent_binary__").is_none());
    }

    #[test]
    fn check_for_tool_missing_tool() {
        let caps = SandboxCapabilities {
            user_namespaces: true,
            pasta_available: true,
            nmap_available: false,
        };
        let err = caps
            .check_for_tool("__sigint_nonexistent_binary__", false)
            .unwrap_err();
        assert!(matches!(err, SandboxError::ToolNotFound(_)));
    }

    #[test]
    fn check_for_tool_no_user_ns() {
        let caps = SandboxCapabilities {
            user_namespaces: false,
            pasta_available: true,
            nmap_available: true,
        };
        let err = caps.check_for_tool("sh", false).unwrap_err();
        assert!(matches!(err, SandboxError::NoUserNamespaces));
    }

    #[test]
    fn check_for_tool_needs_pasta_missing() {
        let caps = SandboxCapabilities {
            user_namespaces: true,
            pasta_available: false,
            nmap_available: true,
        };
        let err = caps.check_for_tool("sh", true).unwrap_err();
        assert!(matches!(err, SandboxError::PastaNotFound));
    }
}
