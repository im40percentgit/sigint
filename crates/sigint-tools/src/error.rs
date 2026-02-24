//! Error types for sigint-tools.
//!
//! @decision DEC-TOOL-001
//! @title Crate-local ToolError for tool-specific failure modes
//! @status accepted
//! @rationale Mirrors the pattern established by SandboxError in sigint-sandbox:
//! a dedicated error enum lets the tools crate express domain-specific failures
//! (missing required args, disallowed commands, sandbox errors) without coupling
//! to workspace-wide error types. Callers convert at the boundary.

use thiserror::Error;

/// Errors that can occur when building or executing a tool.
#[derive(Debug, Error)]
pub enum ToolError {
    /// A required argument was missing from the JSON args object.
    #[error("missing required argument: {0}")]
    MissingArgument(String),

    /// An argument had an unexpected type.
    #[error("invalid argument '{name}': expected {expected}")]
    InvalidArgument { name: String, expected: String },

    /// The requested shell command is not in the allowlist.
    #[error("command not allowed: '{0}' — only whitelisted commands are permitted")]
    DisallowedCommand(String),

    /// Sandbox execution failed (wraps SandboxError message).
    #[error("sandbox error: {0}")]
    Sandbox(String),

    /// The tool timed out.
    #[error("tool timed out after {0}s")]
    Timeout(u64),
}

/// Convenience Result type for tool operations.
pub type Result<T> = std::result::Result<T, ToolError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_messages() {
        assert_eq!(
            ToolError::MissingArgument("target".to_string()).to_string(),
            "missing required argument: target"
        );
        assert_eq!(
            ToolError::InvalidArgument {
                name: "ports".to_string(),
                expected: "string".to_string(),
            }
            .to_string(),
            "invalid argument 'ports': expected string"
        );
        assert_eq!(
            ToolError::DisallowedCommand("rm".to_string()).to_string(),
            "command not allowed: 'rm' — only whitelisted commands are permitted"
        );
        assert_eq!(
            ToolError::Sandbox("fork failed".to_string()).to_string(),
            "sandbox error: fork failed"
        );
        assert_eq!(
            ToolError::Timeout(300).to_string(),
            "tool timed out after 300s"
        );
    }
}
