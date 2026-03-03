//! `sigint diff` — compare findings between two scan sessions.
//!
//! @decision DEC-CLI-DIFF-001
//! @title CLI diff uses direct DB access, not HTTP API
//! @status accepted
//! @rationale The CLI binary already has sigint-store as a dependency and
//! direct DB access is simpler than requiring a running web server. The diff
//! logic is the same — both CLI and API call sigint_core::diff::diff_findings.
//! AppCore has no `database()` method; the CLI follows the pattern established
//! in sessions.rs: `Database::open(core.config.resolved_db_path())`.

use sigint_core::{diff::diff_findings, AppCore, Error};
use sigint_store::Database;
use uuid::Uuid;

/// CLI arguments for `sigint diff`.
#[derive(clap::Args, Debug)]
pub struct DiffArgs {
    /// UUID of the first (baseline) scan session.
    pub scan_a: String,
    /// UUID of the second (comparison) scan session.
    pub scan_b: String,
    /// Output format: "json" (default) or "markdown".
    #[arg(long, default_value = "json")]
    pub format: String,
}

/// Entry point for `sigint diff`.
///
/// Opens the configured database, validates both session UUIDs exist,
/// fetches their findings, and prints the diff in the requested format.
pub async fn run(core: AppCore, args: DiffArgs) -> Result<(), Error> {
    let uuid_a = Uuid::parse_str(&args.scan_a)
        .map_err(|e| Error::Other(format!("Invalid UUID '{}': {}", args.scan_a, e)))?;
    let uuid_b = Uuid::parse_str(&args.scan_b)
        .map_err(|e| Error::Other(format!("Invalid UUID '{}': {}", args.scan_b, e)))?;

    let db_path = core.config.resolved_db_path();
    let db = Database::open(&db_path)
        .map_err(|e| Error::Database(format!("Cannot open database: {e}")))?;

    db.get_session(uuid_a)?
        .ok_or_else(|| Error::Other(format!("Session '{}' not found", uuid_a)))?;
    db.get_session(uuid_b)?
        .ok_or_else(|| Error::Other(format!("Session '{}' not found", uuid_b)))?;

    let findings_a = db.get_findings(uuid_a)?;
    let findings_b = db.get_findings(uuid_b)?;

    let diff = diff_findings(uuid_a, &findings_a, uuid_b, &findings_b);

    match args.format.as_str() {
        "markdown" => print_markdown(&diff),
        _ => {
            let json =
                serde_json::to_string_pretty(&diff).map_err(|e| Error::Other(e.to_string()))?;
            println!("{}", json);
        }
    }

    Ok(())
}

fn print_markdown(diff: &sigint_core::diff::ScanDiff) {
    println!("# Scan Diff: {} vs {}", diff.scan_a, diff.scan_b);
    println!();
    println!("| Category | Count |");
    println!("|----------|-------|");
    println!("| New      | {}    |", diff.summary.new);
    println!("| Fixed    | {}    |", diff.summary.fixed);
    println!("| Unchanged| {}    |", diff.summary.unchanged);

    if !diff.new.is_empty() {
        println!();
        println!("## New Findings");
        println!();
        println!("| Severity | Title | Asset |");
        println!("|----------|-------|-------|");
        for f in &diff.new {
            println!(
                "| {} | {} | {} |",
                f.severity,
                f.title,
                f.asset.as_deref().unwrap_or("-")
            );
        }
    }

    if !diff.fixed.is_empty() {
        println!();
        println!("## Fixed Findings");
        println!();
        println!("| Severity | Title | Asset |");
        println!("|----------|-------|-------|");
        for f in &diff.fixed {
            println!(
                "| {} | {} | {} |",
                f.severity,
                f.title,
                f.asset.as_deref().unwrap_or("-")
            );
        }
    }

    if !diff.unchanged.is_empty() {
        println!();
        println!("## Unchanged Findings");
        println!();
        println!("| Severity | Title | Asset |");
        println!("|----------|-------|-------|");
        for f in &diff.unchanged {
            println!(
                "| {} | {} | {} |",
                f.severity,
                f.title,
                f.asset.as_deref().unwrap_or("-")
            );
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use sigint_core::types::{Finding, Session, Severity};
    use sigint_store::Database;

    fn db() -> Database {
        Database::open_in_memory().unwrap()
    }

    fn make_session(db: &Database, name: &str) -> Uuid {
        let s = Session::new(name);
        db.create_session(&s).unwrap();
        s.id
    }

    fn make_finding(db: &Database, session_id: Uuid, title: &str, asset: Option<&str>) {
        let mut f = Finding::new(session_id, title, "desc", Severity::Medium);
        f.asset = asset.map(str::to_string);
        db.create_finding(&f).unwrap();
    }

    // ── parse_uuid error path ─────────────────────────────────────────────────

    #[test]
    fn invalid_uuid_a_returns_error() {
        // We test the UUID parsing logic directly since run() is async + needs config
        let result = Uuid::parse_str("not-a-uuid");
        assert!(result.is_err());
        let err = Error::Other(format!(
            "Invalid UUID 'not-a-uuid': {}",
            result.unwrap_err()
        ));
        assert!(err.to_string().contains("Invalid UUID"));
    }

    // ── session validation ────────────────────────────────────────────────────

    #[test]
    fn missing_session_a_returns_none() {
        let db = db();
        let result = db.get_session(Uuid::new_v4()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn missing_session_b_returns_none() {
        let db = db();
        let sid = make_session(&db, "alpha");
        // session_a exists, session_b does not
        let result_a = db.get_session(sid).unwrap();
        let result_b = db.get_session(Uuid::new_v4()).unwrap();
        assert!(result_a.is_some());
        assert!(result_b.is_none());
    }

    // ── diff integration (DB round-trip) ──────────────────────────────────────

    #[test]
    fn diff_new_finding_detected() {
        let db = db();
        let sid_a = make_session(&db, "scan-a");
        let sid_b = make_session(&db, "scan-b");
        // scan_b has a finding not in scan_a
        make_finding(&db, sid_b, "XSS", Some("app.example.com"));

        let fa = db.get_findings(sid_a).unwrap();
        let fb = db.get_findings(sid_b).unwrap();
        let diff = diff_findings(sid_a, &fa, sid_b, &fb);

        assert_eq!(diff.new.len(), 1);
        assert_eq!(diff.fixed.len(), 0);
        assert_eq!(diff.unchanged.len(), 0);
        assert_eq!(diff.new[0].title, "XSS");
    }

    #[test]
    fn diff_fixed_finding_detected() {
        let db = db();
        let sid_a = make_session(&db, "scan-a");
        let sid_b = make_session(&db, "scan-b");
        // scan_a has a finding not in scan_b (fixed)
        make_finding(&db, sid_a, "SQLi", Some("db.example.com"));

        let fa = db.get_findings(sid_a).unwrap();
        let fb = db.get_findings(sid_b).unwrap();
        let diff = diff_findings(sid_a, &fa, sid_b, &fb);

        assert_eq!(diff.new.len(), 0);
        assert_eq!(diff.fixed.len(), 1);
        assert_eq!(diff.unchanged.len(), 0);
    }

    #[test]
    fn diff_unchanged_finding_detected() {
        let db = db();
        let sid_a = make_session(&db, "scan-a");
        let sid_b = make_session(&db, "scan-b");
        make_finding(&db, sid_a, "Open Port 22", Some("host1"));
        make_finding(&db, sid_b, "Open Port 22", Some("host1"));

        let fa = db.get_findings(sid_a).unwrap();
        let fb = db.get_findings(sid_b).unwrap();
        let diff = diff_findings(sid_a, &fa, sid_b, &fb);

        assert_eq!(diff.unchanged.len(), 1);
        assert_eq!(diff.new.len(), 0);
        assert_eq!(diff.fixed.len(), 0);
    }

    // ── print_markdown smoke test ─────────────────────────────────────────────

    #[test]
    fn print_markdown_runs_without_panic() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let diff = diff_findings(a, &[], b, &[]);
        // This would panic if the function has any runtime errors
        print_markdown(&diff);
    }
}
