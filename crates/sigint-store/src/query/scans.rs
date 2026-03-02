//! Typed query builder for ScanRecord records.
//!
//! @decision DEC-P3-QUERY
//! @title Typed query builders replace ad-hoc SQL string construction
//! @status accepted
//! @rationale Builder pattern makes filters, pagination, and ordering
//! composable and discoverable without exposing raw SQL to callers.
//! Each terminal method (list, count) constructs and executes exactly
//! one parameterised SQL statement, preventing SQL injection.

use sigint_core::Error;
use uuid::Uuid;

use crate::db::Database;
use crate::scans::{row_to_scan_record, ScanRecord};

/// Builder for querying ScanRecord rows from scan_history with optional filters.
pub struct ScanQuery<'a> {
    db: &'a Database,
    session_id: Option<Uuid>,
    tool: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
}

impl<'a> ScanQuery<'a> {
    pub(crate) fn new(db: &'a Database) -> Self {
        Self {
            db,
            session_id: None,
            tool: None,
            limit: None,
            offset: None,
        }
    }

    /// Filter records to a specific session.
    pub fn by_session(mut self, session_id: Uuid) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Filter records by tool name (exact match, e.g. `"nmap_scan"`).
    pub fn by_tool(mut self, tool: &str) -> Self {
        self.tool = Some(tool.to_string());
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

    /// Execute the query and return all matching scan records.
    pub fn list(self) -> Result<Vec<ScanRecord>, Error> {
        self.db.with_conn(|conn| {
            let mut sql = String::from(
                "SELECT id, session_id, tool, args, output, exit_code, started_at, finished_at \
                 FROM scan_history",
            );
            let mut params: Vec<rusqlite::types::Value> = Vec::new();
            let mut conditions = Vec::new();

            if let Some(sid) = &self.session_id {
                conditions.push(format!("session_id = ?{}", params.len() + 1));
                params.push(rusqlite::types::Value::Text(sid.to_string()));
            }

            if let Some(ref tool) = self.tool {
                conditions.push(format!("tool = ?{}", params.len() + 1));
                params.push(rusqlite::types::Value::Text(tool.clone()));
            }

            if !conditions.is_empty() {
                sql.push_str(" WHERE ");
                sql.push_str(&conditions.join(" AND "));
            }

            sql.push_str(" ORDER BY started_at ASC");

            if let Some(limit) = self.limit {
                sql.push_str(&format!(" LIMIT {limit}"));
            }
            if let Some(offset) = self.offset {
                sql.push_str(&format!(" OFFSET {offset}"));
            }

            let mut stmt = conn
                .prepare(&sql)
                .map_err(|e| Error::Database(e.to_string()))?;

            let rows = stmt
                .query_map(rusqlite::params_from_iter(params.iter()), |row| {
                    Ok(row_to_scan_record(row))
                })
                .map_err(|e| Error::Database(e.to_string()))?;

            let mut results = Vec::new();
            for row in rows {
                let record = row
                    .map_err(|e| Error::Database(e.to_string()))?
                    .map_err(|e| Error::Database(e.to_string()))?;
                results.push(record);
            }
            Ok(results)
        })
    }

    /// Execute a COUNT query with the same filters (ignores limit/offset).
    pub fn count(self) -> Result<usize, Error> {
        self.db.with_conn(|conn| {
            let mut sql = String::from("SELECT COUNT(*) FROM scan_history");
            let mut params: Vec<rusqlite::types::Value> = Vec::new();
            let mut conditions = Vec::new();

            if let Some(sid) = &self.session_id {
                conditions.push(format!("session_id = ?{}", params.len() + 1));
                params.push(rusqlite::types::Value::Text(sid.to_string()));
            }

            if let Some(ref tool) = self.tool {
                conditions.push(format!("tool = ?{}", params.len() + 1));
                params.push(rusqlite::types::Value::Text(tool.clone()));
            }

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
    use crate::scans::ScanRecord;
    use sigint_core::types::Session;

    fn db_with_session() -> (Database, uuid::Uuid) {
        let db = Database::open_in_memory().unwrap();
        let s = Session::new("test");
        db.create_session(&s).unwrap();
        (db, s.id)
    }

    #[test]
    fn query_scans_by_session() {
        let (db, sid) = db_with_session();
        let s2 = Session::new("other");
        db.create_session(&s2).unwrap();

        db.create_scan_record(&ScanRecord::new(sid, "nmap_scan", "{}"))
            .unwrap();
        db.create_scan_record(&ScanRecord::new(s2.id, "shell", "{}"))
            .unwrap();

        let results = db.scans_query().by_session(sid).list().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].tool, "nmap_scan");
    }

    #[test]
    fn query_scans_by_tool() {
        let (db, sid) = db_with_session();
        db.create_scan_record(&ScanRecord::new(sid, "nmap_scan", "{}"))
            .unwrap();
        db.create_scan_record(&ScanRecord::new(sid, "shell", "{}"))
            .unwrap();
        db.create_scan_record(&ScanRecord::new(sid, "nmap_scan", "{}"))
            .unwrap();

        let results = db
            .scans_query()
            .by_session(sid)
            .by_tool("nmap_scan")
            .list()
            .unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|r| r.tool == "nmap_scan"));
    }

    #[test]
    fn query_scans_count() {
        let (db, sid) = db_with_session();
        for tool in ["nmap_scan", "shell", "nmap_scan"] {
            db.create_scan_record(&ScanRecord::new(sid, tool, "{}"))
                .unwrap();
        }
        assert_eq!(db.scans_query().by_session(sid).count().unwrap(), 3);
        assert_eq!(
            db.scans_query()
                .by_session(sid)
                .by_tool("nmap_scan")
                .count()
                .unwrap(),
            2
        );
    }

    #[test]
    fn query_scans_pagination() {
        let (db, sid) = db_with_session();
        for i in 0..6 {
            db.create_scan_record(&ScanRecord::new(sid, format!("tool{i}"), "{}"))
                .unwrap();
        }
        let page = db
            .scans_query()
            .by_session(sid)
            .limit(3)
            .offset(1)
            .list()
            .unwrap();
        assert_eq!(page.len(), 3);
    }
}
