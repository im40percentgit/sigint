//! sigint-core — Configuration, domain types, AppCore, and event bus.
//!
//! This crate is the shared foundation for the entire SIGINT workspace.
//! Every other crate depends on sigint-core for Config, error types,
//! and the AppCore runtime handle.
//!
//! @decision DEC-ARCH-001: Single Rust binary via Cargo workspace.
//! Eliminates Docker dependency, enables `cargo install` distribution.
//!
//! @decision DEC-ARCH-002: 10-crate workspace with sigint-core as the
//! shared foundation. All crates depend on this one; none form cycles.

pub mod app;
pub mod approval;
pub mod campaign;
pub mod config;
pub mod diff;
pub mod error;
pub mod event;
pub mod types;
pub mod validate;

pub use app::AppCore;
pub use approval::ApprovalRegistry;
pub use config::{Config, ReconConfig, WebConfig};
pub use error::{Error, Result};
pub use validate::{validate_target, ValidateError};
