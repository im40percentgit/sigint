//! sigint-sandbox — Linux namespace + seccomp sandboxing via hakoniwa.
//!
//! Phase 2 will implement: per-tool sandbox profiles, network restriction,
//! filesystem isolation using Linux namespaces (no Docker required).
//!
//! @decision DEC-SAND-001: hakoniwa chosen over Docker for native Linux
//! namespaces — eliminates container daemon dependency, zero-overhead.

/// Placeholder init — will be replaced by full sandbox harness in Phase 2.
pub fn init() {}
