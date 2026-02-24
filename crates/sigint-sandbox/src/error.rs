//! Error types for sigint-sandbox.
//!
//! @decision DEC-SAND-002
//! @title Crate-local SandboxError separate from sigint-core Error
//! @status accepted
//! @rationale A dedicated error enum lets the sandbox crate describe
//! domain-specific failure modes (PastaNotFound, NoUserNamespaces, Timeout)
//! without polluting the workspace-wide Error. Callers convert via
//! `SandboxError → sigint_core::Error::Sandbox(String)` at the boundary.

use thiserror::Error;

/// Errors that can occur during sandbox creation or execution.
#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("sandbox creation failed: {0}")]
    Creation(String),

    #[error("tool not found: {0}")]
    ToolNotFound(String),

    #[error("pasta binary not found — install passt package for network sandboxing")]
    PastaNotFound,

    #[error("user namespaces not available on this system")]
    NoUserNamespaces,

    #[error("sandbox execution failed: {0}")]
    Execution(String),

    #[error("command timed out after {0}s")]
    Timeout(u64),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Convenience Result type for sandbox operations.
pub type Result<T> = std::result::Result<T, SandboxError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_messages() {
        assert_eq!(
            SandboxError::Creation("fork failed".to_string()).to_string(),
            "sandbox creation failed: fork failed"
        );
        assert_eq!(
            SandboxError::ToolNotFound("nmap".to_string()).to_string(),
            "tool not found: nmap"
        );
        assert_eq!(
            SandboxError::PastaNotFound.to_string(),
            "pasta binary not found — install passt package for network sandboxing"
        );
        assert_eq!(
            SandboxError::NoUserNamespaces.to_string(),
            "user namespaces not available on this system"
        );
        assert_eq!(
            SandboxError::Execution("exec failed".to_string()).to_string(),
            "sandbox execution failed: exec failed"
        );
        assert_eq!(
            SandboxError::Timeout(30).to_string(),
            "command timed out after 30s"
        );
    }

    #[test]
    fn io_error_transparent() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file missing");
        let sandbox_err: SandboxError = io_err.into();
        assert!(sandbox_err.to_string().contains("file missing"));
    }
}
