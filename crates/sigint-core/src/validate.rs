//! SSRF target validator — shared across `sigint-recon`, `sigint-agents`, and `sigint-web`.
//!
//! @decision DEC-RECON-VALIDATE-001
//! @title Deny-by-default SSRF guard: reject loopback, link-local, RFC1918, and CIDR overlaps
//! @status accepted
//! @rationale Finding #3 from the /cso security audit (HIGH, 9/10 confidence):
//! the `POST /api/scan` web endpoint accepted any string as a target, allowing an
//! authenticated (and potentially unauthenticated, when auth was absent) caller
//! to trigger scans against 127.0.0.1 (loopback), 169.254.169.254 (AWS/GCP
//! IMDS — cloud metadata credential exfiltration), or any RFC1918 range
//! (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
//!
//! The validator was originally in `sigint-recon::validate` but that created a
//! coverage gap: the web scan path (`POST /api/scan` → `ScanService::start()`)
//! never invoked `ReconEngine::run()`, so the guard was unreachable from the
//! web surface. Moving the validator to `sigint-core` (the workspace root crate)
//! allows `sigint-recon`, `sigint-agents`, and `sigint-web` to all import it
//! without a circular dependency.
//!
//! Two escape hatches exist for legitimate internal-pentest use cases:
//!
//!   1. `allow_internal = true` in `[recon]` config — bypasses all IP checks.
//!   2. `target_allowlist` — explicit per-host or per-CIDR exceptions.
//!
//! We deliberately do NOT perform DNS resolution to avoid TOCTOU races where
//! a hostname resolves to a public IP at validation time but an internal IP
//! when the modules actually run (DNS rebinding). Hostnames that are not
//! literal IPs are accepted by default; the sandbox and network-level controls
//! are the defence-in-depth layer for hostname targets.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use ipnet::IpNet;

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors returned by [`validate_target`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidateError {
    /// The target resolves to a private/internal address (loopback, link-local,
    /// RFC1918) and neither `allow_internal` is `true` nor the target is in
    /// `target_allowlist`.
    InvalidTarget(String),
}

impl fmt::Display for ValidateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidateError::InvalidTarget(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for ValidateError {}

// ── Public API ────────────────────────────────────────────────────────────────

/// Validate a recon target for SSRF safety.
///
/// Call this at every scan entry point (web handler, CLI handler, ScanService)
/// before any network activity is initiated for the target.
///
/// # Arguments
///
/// * `target` — the raw target string (IP, hostname, or CIDR notation).
/// * `allow_internal` — when `true`, all checks are bypassed (opt-in for
///   internal-pentest environments).
/// * `allowlist` — a slice of strings (hostnames, IPs, or CIDRs) that are
///   explicitly permitted even when `allow_internal` is `false`.
///
/// # Behaviour
///
/// 1. If `allow_internal` is `true`, return `Ok(())` immediately.
/// 2. If the target (or its network address for CIDR input) is in `allowlist`,
///    return `Ok(())`.
/// 3. If the target parses as a literal IP address, check it against the
///    blocked ranges and return `Err(ValidateError::InvalidTarget(...))` if it
///    falls inside any blocked range.
/// 4. If the target parses as a CIDR, check whether the network overlaps any
///    blocked range.
/// 5. If the target is a hostname (not a literal IP), accept it — we do not
///    perform DNS resolution to avoid TOCTOU / DNS-rebinding races.
///
/// # Errors
///
/// Returns [`ValidateError::InvalidTarget`] when the target resolves to a
/// private/internal address and no escape hatch permits it.
pub fn validate_target(
    target: &str,
    allow_internal: bool,
    allowlist: &[String],
) -> Result<(), ValidateError> {
    // Escape hatch 1: operator has explicitly opted in to internal scanning.
    if allow_internal {
        return Ok(());
    }

    // Escape hatch 2: target literally matches an allowlist entry.
    // Case-insensitive for hostnames; CIDR-aware for IPs (exact string match
    // is sufficient here — the allowlist is operator-controlled and explicit).
    if allowlist
        .iter()
        .any(|entry| entry.eq_ignore_ascii_case(target))
    {
        return Ok(());
    }

    // Try to parse target as a CIDR network first (e.g. "10.0.0.0/24").
    if let Ok(net) = IpNet::from_str(target) {
        return check_network_blocked(&net, target);
    }

    // Try to parse as a bare IP address.
    if let Ok(ip) = IpAddr::from_str(target) {
        return check_ip_blocked(ip, target);
    }

    // Target is a hostname — accept without DNS resolution.
    Ok(())
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Check whether a single IP address falls within any blocked range.
fn check_ip_blocked(ip: IpAddr, raw: &str) -> Result<(), ValidateError> {
    if is_blocked_ip(ip) {
        return Err(ValidateError::InvalidTarget(format!(
            "target '{}' resolves to a private/internal address and is not permitted \
             (set [recon] allow_internal = true or add to target_allowlist to override)",
            raw
        )));
    }
    Ok(())
}

/// Check whether a CIDR network overlaps any blocked range.
fn check_network_blocked(net: &IpNet, raw: &str) -> Result<(), ValidateError> {
    if overlaps_blocked_ranges(net) {
        return Err(ValidateError::InvalidTarget(format!(
            "target network '{}' overlaps a private/internal range and is not permitted \
             (set [recon] allow_internal = true or add to target_allowlist to override)",
            raw
        )));
    }
    Ok(())
}

/// Return `true` if the IP falls in any of the blocked ranges:
///
/// - Loopback:    127.0.0.0/8  (IPv4)  or  ::1/128  (IPv6)
/// - Link-local:  169.254.0.0/16 (IPv4)  or  fe80::/10  (IPv6)
/// - RFC1918:     10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
/// - Unspecified: 0.0.0.0/32  (IPv4)  or  ::/128  (IPv6)
/// - Broadcast:   255.255.255.255/32
fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()       // 127.0.0.0/8
                || v4.is_link_local()  // 169.254.0.0/16
                || v4.is_private()     // 10/8, 172.16/12, 192.168/16
                || v4.is_unspecified() // 0.0.0.0
                || v4.is_broadcast() // 255.255.255.255
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()          // ::1
                || v6.is_unspecified()    // ::
                || is_ipv6_link_local(v6) // fe80::/10
        }
    }
}

/// IPv6 link-local: fe80::/10
///
/// `std::net::Ipv6Addr::is_unicast_link_local()` is nightly-only, so we
/// check the first 10 bits manually.
fn is_ipv6_link_local(v6: std::net::Ipv6Addr) -> bool {
    let segs = v6.segments();
    // First segment must be 0xfe80..0xfebf (fe80::/10)
    (segs[0] & 0xffc0) == 0xfe80
}

/// Return `true` if `net` overlaps any blocked CIDR range.
///
/// `ipnet` 2.x has no `overlaps` method. Two networks overlap when one
/// contains the other's network address — we check both directions.
fn overlaps_blocked_ranges(net: &IpNet) -> bool {
    // Hardcoded blocked networks — literals are always valid CIDR strings.
    let blocked_v4: &[&str] = &[
        "127.0.0.0/8",        // loopback
        "169.254.0.0/16",     // link-local (includes AWS/GCP IMDS 169.254.169.254)
        "10.0.0.0/8",         // RFC1918
        "172.16.0.0/12",      // RFC1918
        "192.168.0.0/16",     // RFC1918
        "0.0.0.0/8",          // this-network (unspecified)
        "255.255.255.255/32", // broadcast
    ];
    let blocked_v6: &[&str] = &[
        "::1/128",   // loopback
        "::/128",    // unspecified
        "fe80::/10", // link-local
    ];

    let blocked_strs: &[&str] = match net {
        IpNet::V4(_) => blocked_v4,
        IpNet::V6(_) => blocked_v6,
    };

    blocked_strs.iter().any(|b| {
        let blocked: IpNet = b.parse().expect("hardcoded CIDR is valid");
        // Two networks overlap iff one contains the other's network address.
        net.contains(&blocked.network()) || blocked.contains(&net.network())
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn no_allowlist() -> Vec<String> {
        vec![]
    }

    #[test]
    fn loopback_ipv4_rejected() {
        assert!(
            validate_target("127.0.0.1", false, &no_allowlist()).is_err(),
            "127.0.0.1 (loopback) must be rejected"
        );
    }

    #[test]
    fn loopback_ipv6_rejected() {
        assert!(
            validate_target("::1", false, &no_allowlist()).is_err(),
            "::1 (IPv6 loopback) must be rejected"
        );
    }

    #[test]
    fn metadata_rejected() {
        // 169.254.169.254 is the AWS/GCP IMDS address — primary SSRF vector
        // for cloud credential exfiltration (Finding #3).
        assert!(
            validate_target("169.254.169.254", false, &no_allowlist()).is_err(),
            "169.254.169.254 (IMDS / link-local) must be rejected"
        );
    }

    #[test]
    fn rfc1918_10_rejected() {
        assert!(
            validate_target("10.5.5.5", false, &no_allowlist()).is_err(),
            "10.5.5.5 (RFC1918 10/8) must be rejected"
        );
    }

    #[test]
    fn rfc1918_172_rejected() {
        assert!(
            validate_target("172.20.1.1", false, &no_allowlist()).is_err(),
            "172.20.1.1 (RFC1918 172.16/12) must be rejected"
        );
    }

    #[test]
    fn rfc1918_192_rejected() {
        assert!(
            validate_target("192.168.1.1", false, &no_allowlist()).is_err(),
            "192.168.1.1 (RFC1918 192.168/16) must be rejected"
        );
    }

    #[test]
    fn cidr_overlapping_private_rejected() {
        assert!(
            validate_target("10.0.0.0/24", false, &no_allowlist()).is_err(),
            "10.0.0.0/24 (overlaps RFC1918 10/8) must be rejected"
        );
    }

    #[test]
    fn public_ipv4_allowed() {
        assert!(
            validate_target("8.8.8.8", false, &no_allowlist()).is_ok(),
            "8.8.8.8 (Google DNS, public) must be allowed"
        );
    }

    #[test]
    fn public_hostname_allowed() {
        // We do NOT do DNS resolution — just verify the literal hostname
        // string is not rejected by the IP-range checks.
        assert!(
            validate_target("scanme.nmap.org", false, &no_allowlist()).is_ok(),
            "scanme.nmap.org (public hostname) must be allowed without DNS lookup"
        );
    }

    #[test]
    fn allow_internal_bypasses_check() {
        // When allow_internal = true, even loopback must be accepted.
        assert!(
            validate_target("127.0.0.1", true, &no_allowlist()).is_ok(),
            "127.0.0.1 must be allowed when allow_internal = true"
        );
    }

    #[test]
    fn target_allowlist_overrides() {
        // 10.5.5.5 is normally rejected, but explicitly listed in allowlist.
        let allowlist = vec!["10.5.5.5".to_string()];
        assert!(
            validate_target("10.5.5.5", false, &allowlist).is_ok(),
            "10.5.5.5 must be allowed when in target_allowlist"
        );
    }

    #[test]
    fn unspecified_ipv4_rejected() {
        assert!(
            validate_target("0.0.0.0", false, &no_allowlist()).is_err(),
            "0.0.0.0 (unspecified) must be rejected"
        );
    }

    #[test]
    fn broadcast_rejected() {
        assert!(
            validate_target("255.255.255.255", false, &no_allowlist()).is_err(),
            "255.255.255.255 (broadcast) must be rejected"
        );
    }

    #[test]
    fn ipv6_link_local_rejected() {
        assert!(
            validate_target("fe80::1", false, &no_allowlist()).is_err(),
            "fe80::1 (IPv6 link-local) must be rejected"
        );
    }

    #[test]
    fn public_cidr_allowed() {
        assert!(
            validate_target("8.8.8.0/24", false, &no_allowlist()).is_ok(),
            "8.8.8.0/24 (public CIDR) must be allowed"
        );
    }

    #[test]
    fn allowlist_case_insensitive_for_hostname() {
        let allowlist = vec!["Internal.Example.Com".to_string()];
        assert!(
            validate_target("internal.example.com", false, &allowlist).is_ok(),
            "hostname allowlist match should be case-insensitive"
        );
    }

    #[test]
    fn error_message_contains_helpful_hint() {
        let err = validate_target("127.0.0.1", false, &no_allowlist()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("private") || msg.contains("internal"),
            "error message should explain why: {}",
            msg
        );
    }
}
