//! SSRF guard shim for sigint-recon.
//!
//! The canonical validator lives in `sigint_core::validate`. This module is a
//! thin adapter that maps `sigint_core::ValidateError` to `ReconError::InvalidTarget`
//! so that `ReconEngine::run()` can continue to use `validate_target(...)` via a
//! `?` operator without changing its error type.
//!
//! @decision DEC-RECON-VALIDATE-001
//! @title SSRF validator moved to sigint-core; sigint-recon keeps a shim
//! @status accepted
//! @rationale The validator was originally implemented here, but the web scan
//! path (`POST /api/scan` → `ScanService::start()`) never invokes
//! `ReconEngine::run()`, so the guard was dead code for the primary SSRF attack
//! surface. Moving the validator to `sigint-core` lets `sigint-agents` and
//! `sigint-web` import it without a circular dependency. This shim preserves the
//! existing `ReconEngine` call site unchanged.

use crate::error::ReconError;

/// Validate a recon target, mapping any error to [`ReconError::InvalidTarget`].
///
/// Delegates to [`sigint_core::validate_target`]. See that function for full
/// documentation on the SSRF guard rules, escape hatches, and edge cases.
pub fn validate_target(
    target: &str,
    allow_internal: bool,
    allowlist: &[String],
) -> Result<(), ReconError> {
    sigint_core::validate_target(target, allow_internal, allowlist)
        .map_err(|e| ReconError::InvalidTarget(e.to_string()))
}
