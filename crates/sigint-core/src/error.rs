//! Error types for sigint-core and re-exported across the workspace.

use thiserror::Error;

/// Unified error type for SIGINT operations.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Database error: {0}")]
    Database(String),

    #[error("LLM provider error: {0}")]
    Llm(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serde(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Sandbox error: {0}")]
    Sandbox(String),

    /// The config file lock is held by another process or concurrent request.
    ///
    /// Maps to HTTP 409 Conflict when returned from web handlers.
    #[error("config.toml is locked by another process — try again shortly")]
    ConfigLocked,

    #[error("{0}")]
    Other(String),
}

/// Convenience Result type using SIGINT's Error.
pub type Result<T> = std::result::Result<T, Error>;
