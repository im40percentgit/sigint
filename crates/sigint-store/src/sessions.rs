//! CRUD operations for Session records.
//!
//! @decision DEC-STORE-001
//! @title Sessions stored as UUID-keyed TEXT rows in SQLite
//! @status accepted
//! @rationale UUIDs as TEXT avoids INTEGER rowid aliasing issues and makes
//! rows identifiable across export/import without collision risk.

use rusqlite::params;
use sigint_core::{types::Session, Error};
use uuid::Uuid;

use crate::db::Database;

impl Database {
    /// Insert a new session. Fails if `session.id` already exists.
    pub fn create_session(&self, session: &Session) -> Result<(), Error> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO sessions (id, name, target, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    session.id.to_string(),
                    session.name,
                    session.target,
                    session.created_at.to_rfc3339(),
                    session.updated_at.to_rfc3339(),
                ],
            )
            .map_err(|e| Error::Database(format!("create_session failed: {}", e)))?;
            Ok(())
        })
    }

    /// Fetch a session by ID. Returns `None` if not found.
    pub fn get_session(&self, id: Uuid) -> Result<Option<Session>, Error> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, name, target, created_at, updated_at
                     FROM sessions WHERE id = ?1",
                )
                .map_err(|e| Error::Database(e.to_string()))?;

            let mut rows = stmt
                .query(params![id.to_string()])
                .map_err(|e| Error::Database(e.to_string()))?;

            if let Some(row) = rows.next().map_err(|e| Error::Database(e.to_string()))? {
                Ok(Some(row_to_session(row)?))
            } else {
                Ok(None)
            }
        })
    }

    /// List all sessions ordered by creation time descending.
    pub fn list_sessions(&self) -> Result<Vec<Session>, Error> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, name, target, created_at, updated_at
                     FROM sessions ORDER BY created_at DESC",
                )
                .map_err(|e| Error::Database(e.to_string()))?;

            let sessions = stmt
                .query_map([], |row| {
                    Ok(row_to_session(row).unwrap_or_else(|_| {
                        // Malformed rows are skipped rather than aborting the list
                        Session::new("<error>")
                    }))
                })
                .map_err(|e| Error::Database(e.to_string()))?
                .filter_map(|r| r.ok())
                .collect();

            Ok(sessions)
        })
    }

    /// Update session `updated_at` timestamp (called after any mutation).
    pub fn touch_session(&self, id: Uuid) -> Result<(), Error> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE sessions SET updated_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
                 WHERE id = ?1",
                params![id.to_string()],
            )
            .map_err(|e| Error::Database(format!("touch_session failed: {}", e)))?;
            Ok(())
        })
    }

    /// Delete a session and all its messages (CASCADE).
    pub fn delete_session(&self, id: Uuid) -> Result<(), Error> {
        self.with_conn(|conn| {
            conn.execute(
                "DELETE FROM sessions WHERE id = ?1",
                params![id.to_string()],
            )
            .map_err(|e| Error::Database(format!("delete_session failed: {}", e)))?;
            Ok(())
        })
    }
}

pub(crate) fn row_to_session(row: &rusqlite::Row<'_>) -> Result<Session, Error> {
    let id_str: String = row.get(0).map_err(|e| Error::Database(e.to_string()))?;
    let name: String = row.get(1).map_err(|e| Error::Database(e.to_string()))?;
    let target: Option<String> = row.get(2).map_err(|e| Error::Database(e.to_string()))?;
    let created_at_str: String = row.get(3).map_err(|e| Error::Database(e.to_string()))?;
    let updated_at_str: String = row.get(4).map_err(|e| Error::Database(e.to_string()))?;

    let id = Uuid::parse_str(&id_str)
        .map_err(|e| Error::Database(format!("Invalid UUID '{}': {}", id_str, e)))?;
    let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|e| Error::Database(format!("Invalid timestamp: {}", e)))?;
    let updated_at = chrono::DateTime::parse_from_rfc3339(&updated_at_str)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|e| Error::Database(format!("Invalid timestamp: {}", e)))?;

    Ok(Session {
        id,
        name,
        target,
        created_at,
        updated_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigint_core::types::Session;

    fn db() -> Database {
        Database::open_in_memory().unwrap()
    }

    #[test]
    fn create_and_get_session() {
        let db = db();
        let s = Session::new("test");
        db.create_session(&s).unwrap();

        let fetched = db.get_session(s.id).unwrap().expect("session should exist");
        assert_eq!(fetched.id, s.id);
        assert_eq!(fetched.name, "test");
        assert!(fetched.target.is_none());
    }

    #[test]
    fn get_missing_session_returns_none() {
        let db = db();
        let result = db.get_session(Uuid::new_v4()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn list_sessions_ordered_by_created() {
        let db = db();
        let s1 = Session::new("alpha");
        let s2 = Session::new("beta");
        db.create_session(&s1).unwrap();
        db.create_session(&s2).unwrap();

        let list = db.list_sessions().unwrap();
        assert_eq!(list.len(), 2);
        // Most recent first
        assert_eq!(list[0].name, "beta");
        assert_eq!(list[1].name, "alpha");
    }

    #[test]
    fn delete_session() {
        let db = db();
        let s = Session::new("to-delete");
        db.create_session(&s).unwrap();
        db.delete_session(s.id).unwrap();

        let result = db.get_session(s.id).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn session_with_target_roundtrips() {
        let db = db();
        let s = Session::new("recon").with_target("example.com");
        db.create_session(&s).unwrap();

        let fetched = db.get_session(s.id).unwrap().unwrap();
        assert_eq!(fetched.target.as_deref(), Some("example.com"));
    }
}
