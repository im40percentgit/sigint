//! sigint-sandbox — Linux namespace sandboxing via hakoniwa.
//!
//! Provides a generic [`SandboxedCommand`] builder and pre-built [`SandboxProfile`]
//! values for running security tools (nmap, etc.) in isolated Linux namespaces
//! without requiring Docker or root privileges.
//!
//! # Architecture
//!
//! - [`command`] — consuming builder wrapping hakoniwa's Container/Command API
//! - [`capability`] — runtime detection of user-namespace and pasta availability
//! - [`profile`] — named profiles encoding per-tool-class defaults
//! - [`error`] — `SandboxError` enum and `Result<T>` alias
//!
//! @decision DEC-SAND-001
//! @title hakoniwa chosen over Docker for native Linux namespaces
//! @status accepted
//! @rationale Eliminates container daemon dependency, zero-overhead fork/exec,
//! unprivileged user namespaces only — no setuid binaries required.
//!
//! @decision DEC-SAND-002
//! @title SandboxedCommand is synchronous; callers use spawn_blocking
//! @status accepted
//! @rationale hakoniwa uses fork(2) under the hood which is fundamentally
//! incompatible with a multi-threaded tokio runtime. Blocking is confined to
//! the execute() call; tokio::task::spawn_blocking isolates it cleanly.

pub mod capability;
pub mod command;
pub mod error;
pub mod profile;

pub use capability::SandboxCapabilities;
pub use command::{NetworkMode, SandboxOutput, SandboxedCommand};
pub use error::{Result, SandboxError};
pub use profile::SandboxProfile;
