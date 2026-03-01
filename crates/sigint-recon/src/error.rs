//! Error types for the sigint-recon discovery engine.

/// Errors that can arise during reconnaissance operations.
#[derive(Debug, thiserror::Error)]
pub enum ReconError {
    /// A sandboxed command failed to execute or returned unexpected output.
    #[error("sandbox error: {0}")]
    Sandbox(String),

    /// Tool output could not be parsed into structured asset data.
    #[error("parse error: {0}")]
    Parse(String),

    /// An outbound network request (e.g. crt.sh HTTP) failed.
    #[error("network error: {0}")]
    Network(String),

    /// A database read or write operation failed.
    #[error("store error: {0}")]
    Store(String),

    /// ReconEngine was constructed with no discovery modules.
    #[error("no modules configured")]
    NoModules,
}
