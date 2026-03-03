//! Scan diff engine — compare findings between two scan sessions.
//!
//! Produces a `ScanDiff` that categorises every finding as new, fixed,
//! or unchanged relative to a baseline scan (scan_a → scan_b).
//!
//! @decision DEC-DIFF-001
//! @title Match findings by (title.to_lowercase(), asset.unwrap_or_default())
//! @status accepted
//! @rationale Finding IDs are per-session UUIDs and cannot be compared
//! across sessions. Severity and description may legitimately change between
//! scans (e.g. the analyst upgrades severity after review). Title + asset
//! captures the *logical identity* of a finding: same vulnerability class on
//! the same target. Lowercasing prevents spurious mismatches from
//! capitalisation differences between scanner runs. The empty string sentinel
//! for `None` asset means "no specific asset" and matches correctly across
//! both scans without an `Option<Option<_>>` key type.

use std::collections::HashMap;

use serde::Serialize;
use uuid::Uuid;

use crate::types::{Finding};

// ── Match key ────────────────────────────────────────────────────────────────

/// The key used to determine whether two findings from different scans refer
/// to the same logical vulnerability. See @decision DEC-DIFF-001.
type MatchKey = (String, String);

fn match_key(f: &Finding) -> MatchKey {
    (
        f.title.to_lowercase(),
        f.asset.clone().unwrap_or_default(),
    )
}

// ── Public types ─────────────────────────────────────────────────────────────

/// Counts of findings in each diff category.
#[derive(Debug, Clone, Serialize)]
pub struct DiffSummary {
    /// Findings present in scan_b but not scan_a (newly introduced).
    pub new: usize,
    /// Findings present in scan_a but not scan_b (remediated or disappeared).
    pub fixed: usize,
    /// Findings present in both scans (still open, carried over).
    pub unchanged: usize,
}

/// The result of comparing two scan sessions' findings.
///
/// `scan_a` is the baseline (older) scan; `scan_b` is the newer scan.
/// Fields `new`, `fixed`, and `unchanged` contain the actual `Finding`
/// objects — callers can inspect them or relay them to the UI layer.
#[derive(Debug, Clone, Serialize)]
pub struct ScanDiff {
    /// UUID of the baseline scan session.
    pub scan_a: Uuid,
    /// UUID of the newer scan session.
    pub scan_b: Uuid,
    /// Aggregate counts for quick display.
    pub summary: DiffSummary,
    /// Findings that appear in scan_b but not scan_a.
    pub new: Vec<Finding>,
    /// Findings that appear in scan_a but not scan_b.
    pub fixed: Vec<Finding>,
    /// Findings that appear in both scans (keyed by scan_b copy).
    pub unchanged: Vec<Finding>,
}

// ── Algorithm ────────────────────────────────────────────────────────────────

/// Compare findings from two scan sessions and produce a `ScanDiff`.
///
/// # Arguments
///
/// * `scan_a` – UUID of the baseline session (older / reference scan).
/// * `findings_a` – All findings from session `scan_a`.
/// * `scan_b` – UUID of the newer session (current scan).
/// * `findings_b` – All findings from session `scan_b`.
///
/// # Complexity
///
/// O(n + m) where n = |findings_a|, m = |findings_b|.
/// Uses a `HashMap` keyed on `(title_lowercase, asset)`.
pub fn diff_findings(
    scan_a: Uuid,
    findings_a: &[Finding],
    scan_b: Uuid,
    findings_b: &[Finding],
) -> ScanDiff {
    // Build an index of scan_a findings by match key.
    // If duplicate keys exist within a single scan we keep the first entry;
    // duplicates within a scan are a data-quality concern outside this module.
    let mut a_index: HashMap<MatchKey, &Finding> = HashMap::with_capacity(findings_a.len());
    for f in findings_a {
        a_index.entry(match_key(f)).or_insert(f);
    }

    // Walk scan_b findings, partitioning into new vs unchanged.
    let mut new: Vec<Finding> = Vec::new();
    let mut unchanged: Vec<Finding> = Vec::new();
    let mut seen_keys: HashMap<MatchKey, bool> = HashMap::with_capacity(findings_b.len());

    for f in findings_b {
        let key = match_key(f);
        if a_index.contains_key(&key) {
            unchanged.push(f.clone());
        } else {
            new.push(f.clone());
        }
        seen_keys.insert(key, true);
    }

    // Fixed = in scan_a but not seen in scan_b.
    let fixed: Vec<Finding> = findings_a
        .iter()
        .filter(|f| !seen_keys.contains_key(&match_key(f)))
        .cloned()
        .collect();

    let summary = DiffSummary {
        new: new.len(),
        fixed: fixed.len(),
        unchanged: unchanged.len(),
    };

    ScanDiff {
        scan_a,
        scan_b,
        summary,
        new,
        fixed,
        unchanged,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Finding, Severity};

    fn make_finding(session_id: Uuid, title: &str, asset: Option<&str>) -> Finding {
        let mut f = Finding::new(session_id, title, "desc", Severity::Medium);
        f.asset = asset.map(str::to_string);
        f
    }

    #[test]
    fn empty_scans_produce_empty_diff() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let diff = diff_findings(a, &[], b, &[]);
        assert_eq!(diff.new.len(), 0);
        assert_eq!(diff.fixed.len(), 0);
        assert_eq!(diff.unchanged.len(), 0);
        assert_eq!(diff.summary.new, 0);
        assert_eq!(diff.summary.fixed, 0);
        assert_eq!(diff.summary.unchanged, 0);
    }

    #[test]
    fn new_findings_detected() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let findings_b = vec![make_finding(b, "XSS", Some("app.example.com"))];
        let diff = diff_findings(a, &[], b, &findings_b);
        assert_eq!(diff.new.len(), 1);
        assert_eq!(diff.fixed.len(), 0);
        assert_eq!(diff.unchanged.len(), 0);
        assert_eq!(diff.new[0].title, "XSS");
    }

    #[test]
    fn fixed_findings_detected() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let findings_a = vec![make_finding(a, "SQLi", Some("db.example.com"))];
        let diff = diff_findings(a, &findings_a, b, &[]);
        assert_eq!(diff.new.len(), 0);
        assert_eq!(diff.fixed.len(), 1);
        assert_eq!(diff.unchanged.len(), 0);
        assert_eq!(diff.fixed[0].title, "SQLi");
    }

    #[test]
    fn unchanged_findings_detected() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let findings_a = vec![make_finding(a, "Open Port 22", Some("host1"))];
        let findings_b = vec![make_finding(b, "Open Port 22", Some("host1"))];
        let diff = diff_findings(a, &findings_a, b, &findings_b);
        assert_eq!(diff.new.len(), 0);
        assert_eq!(diff.fixed.len(), 0);
        assert_eq!(diff.unchanged.len(), 1);
        assert_eq!(diff.summary.unchanged, 1);
    }

    #[test]
    fn matching_is_case_insensitive() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        // scan_a has uppercase title, scan_b has lowercase — should be unchanged
        let findings_a = vec![make_finding(a, "SQL Injection", Some("api.example.com"))];
        let findings_b = vec![make_finding(b, "sql injection", Some("api.example.com"))];
        let diff = diff_findings(a, &findings_a, b, &findings_b);
        assert_eq!(diff.unchanged.len(), 1, "case difference should not create new finding");
        assert_eq!(diff.new.len(), 0);
        assert_eq!(diff.fixed.len(), 0);
    }

    #[test]
    fn different_assets_are_different_findings() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        // Same title, different asset → different logical findings
        let findings_a = vec![make_finding(a, "Open Port 80", Some("host1"))];
        let findings_b = vec![make_finding(b, "Open Port 80", Some("host2"))];
        let diff = diff_findings(a, &findings_a, b, &findings_b);
        // host1 port 80 was fixed, host2 port 80 is new
        assert_eq!(diff.new.len(), 1, "host2 should be new");
        assert_eq!(diff.fixed.len(), 1, "host1 should be fixed");
        assert_eq!(diff.unchanged.len(), 0);
    }

    #[test]
    fn mixed_scenario() {
        // 3 in A, 2 in B → 1 unchanged, 1 new, 2 fixed
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let findings_a = vec![
            make_finding(a, "XSS", Some("app.example.com")),       // will be unchanged
            make_finding(a, "SQLi", Some("db.example.com")),       // will be fixed
            make_finding(a, "Open Redirect", Some("app.example.com")), // will be fixed
        ];
        let findings_b = vec![
            make_finding(b, "XSS", Some("app.example.com")),       // unchanged
            make_finding(b, "RCE", Some("api.example.com")),       // new
        ];
        let diff = diff_findings(a, &findings_a, b, &findings_b);
        assert_eq!(diff.unchanged.len(), 1, "XSS should be unchanged");
        assert_eq!(diff.new.len(), 1, "RCE should be new");
        assert_eq!(diff.fixed.len(), 2, "SQLi and Open Redirect should be fixed");
        assert_eq!(diff.summary.unchanged, 1);
        assert_eq!(diff.summary.new, 1);
        assert_eq!(diff.summary.fixed, 2);
    }

    #[test]
    fn none_asset_matches_none_asset() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        // Both findings have no asset — should match as unchanged
        let findings_a = vec![make_finding(a, "Weak TLS", None)];
        let findings_b = vec![make_finding(b, "Weak TLS", None)];
        let diff = diff_findings(a, &findings_a, b, &findings_b);
        assert_eq!(diff.unchanged.len(), 1, "None asset should match None asset");
        assert_eq!(diff.new.len(), 0);
        assert_eq!(diff.fixed.len(), 0);
    }
}
