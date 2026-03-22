//! Typed query builder for Session records.
//!
//! @decision DEC-P3-QUERY
//! @title Typed query builders replace ad-hoc SQL string construction
//! @status accepted
//! @rationale Builder pattern makes filters, pagination, and ordering composable
//! and discoverable without exposing raw SQL to callers. Each terminal method
//! (list, count) constructs and executes one SQL statement with bound parameters,
//! avoiding SQL injection. The builders borrow Database to ensure the connection
//! pool outlives the query.

use sigint_core::{types::Session, Error};

use crate::db::Database;
use crate::sessions::row_to_session;

/// Builder for querying Session records with optional filters and pagination.
pub struct SessionQuery<'a> {
    db: &'a Database,
    target: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
    order_desc: bool,
}

impl<'a> SessionQuery<'a> {
    pub(crate) fn new(db: &'a Database) -> Self {
        Self {
            db,
            target: None,
            limit: None,
            offset: None,
            order_desc: false,
        }
    }

    /// Filter sessions by target host/domain.
    pub fn by_target(mut self, target: &str) -> Self {
        self.target = Some(target.to_string());
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

    /// Order results by `created_at` descending (most recent first).
    pub fn order_by_date_desc(mut self) -> Self {
        self.order_desc = true;
        self
    }

    /// Execute the query and return all matching sessions.
    pub fn list(self) -> Result<Vec<Session>, Error> {
        self.db.with_conn(|conn| {
            let mut sql =
                String::from("SELECT id, name, target, created_at, updated_at, parent_session_id FROM sessions");
            let mut params: Vec<rusqlite::types::Value> = Vec::new();
            let mut conditions = Vec::new();

            if let Some(ref target) = self.target {
                conditions.push(format!("target = ?{}", params.len() + 1));
                params.push(rusqlite::types::Value::Text(target.clone()));
            }

            if !conditions.is_empty() {
                sql.push_str(" WHERE ");
                sql.push_str(&conditions.join(" AND "));
            }

            if self.order_desc {
                sql.push_str(" ORDER BY created_at DESC");
            } else {
                sql.push_str(" ORDER BY created_at ASC");
            }

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
                    Ok(row_to_session(row))
                })
                .map_err(|e| Error::Database(e.to_string()))?;

            let mut results = Vec::new();
            for row in rows {
                let session = row
                    .map_err(|e| Error::Database(e.to_string()))?
                    .map_err(|e| Error::Database(e.to_string()))?;
                results.push(session);
            }
            Ok(results)
        })
    }

    /// Execute a COUNT query with the same filters (ignores limit/offset).
    pub fn count(self) -> Result<usize, Error> {
        self.db.with_conn(|conn| {
            let mut sql = String::from("SELECT COUNT(*) FROM sessions");
            let mut params: Vec<rusqlite::types::Value> = Vec::new();
            let mut conditions = Vec::new();

            if let Some(ref target) = self.target {
                conditions.push(format!("target = ?{}", params.len() + 1));
                params.push(rusqlite::types::Value::Text(target.clone()));
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
    use sigint_core::types::Session;

    #[test]
    fn query_sessions_by_target() {
        let db = Database::open_in_memory().unwrap();
        let s1 = Session::new("scan1").with_target("example.com");
        let s2 = Session::new("scan2").with_target("other.com");
        let s3 = Session::new("scan3").with_target("example.com");
        db.create_session(&s1).unwrap();
        db.create_session(&s2).unwrap();
        db.create_session(&s3).unwrap();

        let results = db.sessions().by_target("example.com").list().unwrap();
        assert_eq!(results.len(), 2);
        assert!(results
            .iter()
            .all(|s| s.target.as_deref() == Some("example.com")));
    }

    #[test]
    fn query_sessions_with_pagination() {
        let db = Database::open_in_memory().unwrap();
        for i in 0..10 {
            let s = Session::new(format!("scan{i}"));
            db.create_session(&s).unwrap();
        }

        let page = db.sessions().limit(3).offset(2).list().unwrap();
        assert_eq!(page.len(), 3);
    }

    #[test]
    fn query_sessions_count() {
        let db = Database::open_in_memory().unwrap();
        for i in 0..5 {
            db.create_session(&Session::new(format!("s{i}"))).unwrap();
        }
        assert_eq!(db.sessions().count().unwrap(), 5);
    }

    #[test]
    fn query_sessions_order_by_date_desc() {
        let db = Database::open_in_memory().unwrap();
        let s1 = Session::new("first");
        let s2 = Session::new("second");
        db.create_session(&s1).unwrap();
        db.create_session(&s2).unwrap();

        let results = db.sessions().order_by_date_desc().list().unwrap();
        assert_eq!(results.len(), 2);
        assert!(results[0].created_at >= results[1].created_at);
    }

    #[test]
    fn query_sessions_no_filter_returns_all() {
        let db = Database::open_in_memory().unwrap();
        for i in 0..3 {
            db.create_session(&Session::new(format!("s{i}"))).unwrap();
        }
        let all = db.sessions().list().unwrap();
        assert_eq!(all.len(), 3);
    }
}
