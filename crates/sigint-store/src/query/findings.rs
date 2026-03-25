//! Typed query builder for Finding records.
//!
//! @decision DEC-P3-QUERY
//! @title Typed query builders replace ad-hoc SQL string construction
//! @status accepted
//! @rationale See query/sessions.rs for full rationale. FindingQuery adds
//! severity and asset filters on top of the base pagination/count pattern.

use sigint_core::{
    types::{Finding, Severity},
    Error,
};
use uuid::Uuid;

use crate::db::Database;
use crate::findings::row_to_finding;

/// Builder for querying Finding records with optional filters and pagination.
pub struct FindingQuery<'a> {
    db: &'a Database,
    session_id: Option<Uuid>,
    severity: Option<Severity>,
    asset: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

impl<'a> FindingQuery<'a> {
    pub(crate) fn new(db: &'a Database) -> Self {
        Self {
            db,
            session_id: None,
            severity: None,
            asset: None,
            limit: None,
            offset: None,
        }
    }

    /// Filter findings belonging to a specific session.
    pub fn by_session(mut self, session_id: Uuid) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Filter findings by severity level.
    pub fn severity(mut self, severity: Severity) -> Self {
        self.severity = Some(severity);
        self
    }

    /// Filter findings by asset string.
    pub fn by_asset(mut self, asset: &str) -> Self {
        self.asset = Some(asset.to_string());
        self
    }

    /// Limit results to at most `n` rows.
    pub fn limit(mut self, n: usize) -> Self {
        self.limit = Some(n);
        self
    }

    /// Skip the first `n` matching rows.
    pub fn offset(mut self, n: usize) -> Self {
        self.offset = Some(n);
        self
    }

    fn build_conditions(&self) -> (Vec<String>, Vec<rusqlite::types::Value>) {
        let mut conditions = Vec::new();
        let mut params: Vec<rusqlite::types::Value> = Vec::new();

        if let Some(sid) = &self.session_id {
            conditions.push(format!("session_id = ?{}", params.len() + 1));
            params.push(rusqlite::types::Value::Text(sid.to_string()));
        }
        if let Some(ref sev) = self.severity {
            conditions.push(format!("severity = ?{}", params.len() + 1));
            params.push(rusqlite::types::Value::Text(sev.to_string()));
        }
        if let Some(ref asset) = self.asset {
            conditions.push(format!("asset = ?{}", params.len() + 1));
            params.push(rusqlite::types::Value::Text(asset.clone()));
        }

        (conditions, params)
    }

    /// Execute the query and return all matching findings.
    pub fn list(self) -> Result<Vec<Finding>, Error> {
        let limit = self.limit;
        let offset = self.offset;
        let (conditions, params) = self.build_conditions();

        self.db.with_conn(|conn| {
            let mut sql = String::from(
                "SELECT id, session_id, title, description, severity, \
                        asset, evidence, created_at, cvss_score, \
                        remediation, exploitability, impact, \
                        evidence_ref, chain_id, chain_order \
                 FROM findings",
            );

            if !conditions.is_empty() {
                sql.push_str(" WHERE ");
                sql.push_str(&conditions.join(" AND "));
            }

            sql.push_str(" ORDER BY created_at ASC");

            if let Some(n) = limit {
                sql.push_str(&format!(" LIMIT {n}"));
            }
            if let Some(n) = offset {
                sql.push_str(&format!(" OFFSET {n}"));
            }

            let mut stmt = conn
                .prepare(&sql)
                .map_err(|e| Error::Database(e.to_string()))?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(params.iter()), |row| {
                    Ok(row_to_finding(row))
                })
                .map_err(|e| Error::Database(e.to_string()))?;

            let mut results = Vec::new();
            for row in rows {
                let finding = row
                    .map_err(|e| Error::Database(e.to_string()))?
                    .map_err(|e| Error::Database(e.to_string()))?;
                results.push(finding);
            }
            Ok(results)
        })
    }

    /// Execute a COUNT query with the same filters (ignores limit/offset).
    pub fn count(self) -> Result<usize, Error> {
        let (conditions, params) = self.build_conditions();

        self.db.with_conn(|conn| {
            let mut sql = String::from("SELECT COUNT(*) FROM findings");

            if !conditions.is_empty() {
                sql.push_str(" WHERE ");
                sql.push_str(&conditions.join(" AND "));
            }

            conn.query_row(&sql, rusqlite::params_from_iter(params.iter()), |row| {
                row.get(0)
            })
            .map_err(|e| Error::Database(e.to_string()))
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::db::Database;
    use sigint_core::types::{Finding, Session, Severity};

    fn setup() -> (Database, uuid::Uuid) {
        let db = Database::open_in_memory().unwrap();
        let s = Session::new("test");
        db.create_session(&s).unwrap();
        (db, s.id)
    }

    #[test]
    fn query_findings_by_session() {
        let (db, sid) = setup();
        let f1 = Finding::new(sid, "XSS", "desc", Severity::High);
        let f2 = Finding::new(sid, "SQLi", "desc", Severity::Critical);
        db.create_finding(&f1).unwrap();
        db.create_finding(&f2).unwrap();

        let results = db.findings().by_session(sid).list().unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn query_findings_by_severity() {
        let (db, sid) = setup();
        let f1 = Finding::new(sid, "XSS", "desc", Severity::High);
        let f2 = Finding::new(sid, "info-leak", "desc", Severity::Info);
        db.create_finding(&f1).unwrap();
        db.create_finding(&f2).unwrap();

        let highs = db
            .findings()
            .by_session(sid)
            .severity(Severity::High)
            .list()
            .unwrap();
        assert_eq!(highs.len(), 1);
        assert_eq!(highs[0].title, "XSS");
    }

    #[test]
    fn query_findings_count() {
        let (db, sid) = setup();
        for i in 0..4 {
            db.create_finding(&Finding::new(sid, format!("f{i}"), "d", Severity::Info))
                .unwrap();
        }
        assert_eq!(db.findings().by_session(sid).count().unwrap(), 4);
    }

    #[test]
    fn query_findings_with_pagination() {
        let (db, sid) = setup();
        for i in 0..6 {
            db.create_finding(&Finding::new(sid, format!("f{i}"), "d", Severity::Info))
                .unwrap();
        }
        let page = db
            .findings()
            .by_session(sid)
            .limit(2)
            .offset(1)
            .list()
            .unwrap();
        assert_eq!(page.len(), 2);
    }
}
