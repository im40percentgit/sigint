//! CRUD operations for Finding records.
//!
//! @decision DEC-STORE-003
//! @title Findings stored with severity TEXT and optional asset/evidence columns
//! @status accepted
//! @rationale Severity is stored as a TEXT enum value matching the CHECK constraint
//! pattern used for message roles. Asset and evidence are nullable TEXT — a finding
//! may reference a specific asset (e.g. "10.0.0.1:443") or may be session-scoped.
//! CASCADE DELETE on session_id means findings are automatically cleaned up when
//! their parent session is removed.
//!
//! Phase 12A adds six enrichment columns: remediation, exploitability, impact
//! (LLM-generated text), evidence_ref and chain_id (UUID FKs stored as TEXT),
//! and chain_order (INTEGER ordering within an attack chain). All new columns
//! are nullable and default to NULL for backward compatibility.

use rusqlite::params;
use sigint_core::{
    types::{Finding, Severity},
    Error,
};
use uuid::Uuid;

use crate::db::Database;

impl Database {
    /// Insert a new finding. Fails if `finding.id` already exists.
    pub fn create_finding(&self, finding: &Finding) -> Result<(), Error> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO findings (
                     id, session_id, title, description, severity,
                     asset, evidence, created_at, cvss_score,
                     remediation, exploitability, impact,
                     evidence_ref, chain_id, chain_order
                 ) VALUES (
                     ?1, ?2, ?3, ?4, ?5,
                     ?6, ?7, ?8, ?9,
                     ?10, ?11, ?12,
                     ?13, ?14, ?15
                 )",
                params![
                    finding.id.to_string(),
                    finding.session_id.to_string(),
                    finding.title,
                    finding.description,
                    finding.severity.to_string(),
                    finding.asset,
                    finding.evidence,
                    finding.created_at.to_rfc3339(),
                    finding.cvss_score,
                    finding.remediation,
                    finding.exploitability,
                    finding.impact,
                    finding.evidence_ref.map(|u| u.to_string()),
                    finding.chain_id.map(|u| u.to_string()),
                    finding.chain_order,
                ],
            )
            .map_err(|e| Error::Database(format!("create_finding failed: {e}")))?;
            Ok(())
        })
    }

    /// Fetch all findings for a session, ordered by created_at ascending.
    pub fn get_findings(&self, session_id: Uuid) -> Result<Vec<Finding>, Error> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, session_id, title, description, severity,
                            asset, evidence, created_at, cvss_score,
                            remediation, exploitability, impact,
                            evidence_ref, chain_id, chain_order
                     FROM findings WHERE session_id = ?1
                     ORDER BY created_at ASC",
                )
                .map_err(|e| Error::Database(e.to_string()))?;

            let findings = stmt
                .query_map(params![session_id.to_string()], |row| {
                    Ok(row_to_finding(row))
                })
                .map_err(|e| Error::Database(e.to_string()))?
                .filter_map(|r| r.ok())
                .filter_map(|r| r.ok())
                .collect();

            Ok(findings)
        })
    }
}

pub(crate) fn severity_from_str(s: &str) -> Severity {
    match s {
        "low" => Severity::Low,
        "medium" => Severity::Medium,
        "high" => Severity::High,
        "critical" => Severity::Critical,
        _ => Severity::Info,
    }
}

/// Map a SQLite row to a `Finding`.
///
/// Column order must match the SELECT used in `get_findings` and
/// `FindingQuery::list`. Columns 0–8 are the original fields;
/// columns 9–14 are the Phase 12A enrichment additions.
pub(crate) fn row_to_finding(row: &rusqlite::Row<'_>) -> Result<Finding, Error> {
    // ── original columns (0–8) ───────────────────────────────────────────────
    let id_str: String = row.get(0).map_err(|e| Error::Database(e.to_string()))?;
    let session_id_str: String = row.get(1).map_err(|e| Error::Database(e.to_string()))?;
    let title: String = row.get(2).map_err(|e| Error::Database(e.to_string()))?;
    let description: String = row.get(3).map_err(|e| Error::Database(e.to_string()))?;
    let severity_str: String = row.get(4).map_err(|e| Error::Database(e.to_string()))?;
    let asset: Option<String> = row.get(5).map_err(|e| Error::Database(e.to_string()))?;
    let evidence: Option<String> = row.get(6).map_err(|e| Error::Database(e.to_string()))?;
    let created_at_str: String = row.get(7).map_err(|e| Error::Database(e.to_string()))?;
    let cvss_score: Option<f32> = row.get(8).map_err(|e| Error::Database(e.to_string()))?;

    // ── Phase 12A enrichment columns (9–14) ──────────────────────────────────
    let remediation: Option<String> = row.get(9).map_err(|e| Error::Database(e.to_string()))?;
    let exploitability: Option<String> = row.get(10).map_err(|e| Error::Database(e.to_string()))?;
    let impact: Option<String> = row.get(11).map_err(|e| Error::Database(e.to_string()))?;
    let evidence_ref_str: Option<String> =
        row.get(12).map_err(|e| Error::Database(e.to_string()))?;
    let chain_id_str: Option<String> = row.get(13).map_err(|e| Error::Database(e.to_string()))?;
    let chain_order: Option<i32> = row.get(14).map_err(|e| Error::Database(e.to_string()))?;

    // ── parse UUIDs ──────────────────────────────────────────────────────────
    let id = Uuid::parse_str(&id_str)
        .map_err(|e| Error::Database(format!("Invalid UUID '{id_str}': {e}")))?;
    let session_id = Uuid::parse_str(&session_id_str)
        .map_err(|e| Error::Database(format!("Invalid session UUID '{session_id_str}': {e}")))?;
    let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|e| Error::Database(format!("Invalid timestamp: {e}")))?;

    let evidence_ref = evidence_ref_str
        .as_deref()
        .map(|s| {
            Uuid::parse_str(s)
                .map_err(|e| Error::Database(format!("Invalid evidence_ref UUID '{s}': {e}")))
        })
        .transpose()?;

    let chain_id = chain_id_str
        .as_deref()
        .map(|s| {
            Uuid::parse_str(s)
                .map_err(|e| Error::Database(format!("Invalid chain_id UUID '{s}': {e}")))
        })
        .transpose()?;

    Ok(Finding {
        id,
        session_id,
        title,
        description,
        severity: severity_from_str(&severity_str),
        asset,
        evidence,
        created_at,
        cvss_score,
        remediation,
        exploitability,
        impact,
        evidence_ref,
        chain_id,
        chain_order,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;
    use sigint_core::types::Session;

    fn db() -> Database {
        Database::open_in_memory().unwrap()
    }

    fn make_session(db: &Database) -> Uuid {
        let s = Session::new("test-session");
        db.create_session(&s).unwrap();
        s.id
    }

    #[test]
    fn create_and_fetch_finding() {
        let db = db();
        let sid = make_session(&db);
        let f = Finding::new(sid, "XSS", "Reflected XSS in search param", Severity::High);
        db.create_finding(&f).unwrap();

        let findings = db.get_findings(sid).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "XSS");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn finding_severity_roundtrips() {
        let db = db();
        let sid = make_session(&db);
        for severity in [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            let f = Finding::new(sid, "test", "desc", severity.clone());
            db.create_finding(&f).unwrap();
            let findings = db.get_findings(sid).unwrap();
            let found = findings.iter().find(|x| x.id == f.id).unwrap();
            assert_eq!(found.severity, severity);
        }
    }

    #[test]
    fn findings_cascade_delete_with_session() {
        let db = db();
        let sid = make_session(&db);
        let f = Finding::new(sid, "test", "desc", Severity::Info);
        db.create_finding(&f).unwrap();
        db.delete_session(sid).unwrap();
        let findings = db.get_findings(sid).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn finding_with_cvss_score_roundtrips() {
        let db = db();
        let sid = make_session(&db);
        let mut f =
            Finding::new(sid, "RCE", "Remote code execution via log4j", Severity::Critical);
        f.cvss_score = Some(7.5);
        db.create_finding(&f).unwrap();

        let findings = db.get_findings(sid).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].cvss_score, Some(7.5));
    }

    #[test]
    fn finding_without_score_defaults_to_none() {
        let db = db();
        let sid = make_session(&db);
        let f = Finding::new(sid, "Info Leak", "Banner disclosure", Severity::Low);
        // cvss_score not set — should remain None after roundtrip.
        db.create_finding(&f).unwrap();

        let findings = db.get_findings(sid).unwrap();
        assert_eq!(findings.len(), 1);
        assert!(findings[0].cvss_score.is_none());
    }

    // ── Phase 12A enrichment field tests ─────────────────────────────────────

    /// All new fields default to None when not set (backward compat).
    #[test]
    fn finding_new_enrichment_fields_default_to_none() {
        let db = db();
        let sid = make_session(&db);
        let f = Finding::new(sid, "Banner Leak", "Server header exposes version", Severity::Low);
        db.create_finding(&f).unwrap();

        let findings = db.get_findings(sid).unwrap();
        assert_eq!(findings.len(), 1);
        let found = &findings[0];
        assert!(found.remediation.is_none(), "remediation should be None");
        assert!(found.exploitability.is_none(), "exploitability should be None");
        assert!(found.impact.is_none(), "impact should be None");
        assert!(found.evidence_ref.is_none(), "evidence_ref should be None");
        assert!(found.chain_id.is_none(), "chain_id should be None");
        assert!(found.chain_order.is_none(), "chain_order should be None");
    }

    /// All enrichment fields roundtrip correctly when populated.
    #[test]
    fn finding_with_all_enrichment_fields_roundtrips() {
        let db = db();
        let sid = make_session(&db);
        let evidence_ref = Uuid::new_v4();
        let chain_id = Uuid::new_v4();

        let mut f = Finding::new(sid, "SQLi", "Union-based SQL injection", Severity::Critical);
        f.cvss_score = Some(9.8);
        f.remediation = Some("Use parameterized queries; disable error reporting".to_string());
        f.exploitability = Some("publicly accessible, no authentication required".to_string());
        f.impact = Some("Full database exfiltration, authentication bypass".to_string());
        f.evidence_ref = Some(evidence_ref);
        f.chain_id = Some(chain_id);
        f.chain_order = Some(1);

        db.create_finding(&f).unwrap();

        let findings = db.get_findings(sid).unwrap();
        assert_eq!(findings.len(), 1);
        let found = &findings[0];

        assert_eq!(
            found.remediation.as_deref(),
            Some("Use parameterized queries; disable error reporting")
        );
        assert_eq!(
            found.exploitability.as_deref(),
            Some("publicly accessible, no authentication required")
        );
        assert_eq!(
            found.impact.as_deref(),
            Some("Full database exfiltration, authentication bypass")
        );
        assert_eq!(found.evidence_ref, Some(evidence_ref));
        assert_eq!(found.chain_id, Some(chain_id));
        assert_eq!(found.chain_order, Some(1));
        assert_eq!(found.cvss_score, Some(9.8));
    }

    /// Multiple findings in the same chain are retrievable and ordered.
    #[test]
    fn finding_chain_roundtrips() {
        let db = db();
        let sid = make_session(&db);
        let chain_id = Uuid::new_v4();

        let mut f1 = Finding::new(sid, "Recon: open port 22", "SSH exposed", Severity::Info);
        f1.chain_id = Some(chain_id);
        f1.chain_order = Some(0);

        let mut f2 = Finding::new(sid, "Exploit: weak SSH key", "RSA-1024 in use", Severity::High);
        f2.chain_id = Some(chain_id);
        f2.chain_order = Some(1);

        db.create_finding(&f1).unwrap();
        db.create_finding(&f2).unwrap();

        let findings = db.get_findings(sid).unwrap();
        assert_eq!(findings.len(), 2);

        // Both share the same chain_id
        assert_eq!(findings[0].chain_id, Some(chain_id));
        assert_eq!(findings[1].chain_id, Some(chain_id));

        // chain_order values preserved
        let orders: Vec<_> = findings.iter().map(|f| f.chain_order).collect();
        assert!(orders.contains(&Some(0)));
        assert!(orders.contains(&Some(1)));
    }
}
