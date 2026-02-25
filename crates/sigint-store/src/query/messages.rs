//! Typed query builder for Message records.
//!
//! @decision DEC-P3-QUERY
//! @title Typed query builders replace ad-hoc SQL string construction
//! @status accepted
//! @rationale Builder pattern makes filters, pagination, and ordering
//! composable and discoverable without exposing raw SQL to callers.
//! Each terminal method (list, count) constructs and executes exactly
//! one parameterised SQL statement, preventing SQL injection.

use sigint_core::{
    types::{Message, Role},
    Error,
};
use uuid::Uuid;

use crate::db::Database;
use crate::messages::row_to_message;

/// Builder for querying Message records with optional filters and pagination.
pub struct MessageQuery<'a> {
    db: &'a Database,
    session_id: Option<Uuid>,
    role: Option<Role>,
    limit: Option<usize>,
    offset: Option<usize>,
    order_desc: bool,
}

impl<'a> MessageQuery<'a> {
    pub(crate) fn new(db: &'a Database) -> Self {
        Self {
            db,
            session_id: None,
            role: None,
            limit: None,
            offset: None,
            order_desc: false,
        }
    }

    /// Filter messages to a specific session.
    pub fn by_session(mut self, session_id: Uuid) -> Self {
        self.session_id = Some(session_id);
        self
    }

    /// Filter messages by role (user / assistant / system / tool).
    pub fn by_role(mut self, role: Role) -> Self {
        self.role = Some(role);
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

    /// Execute the query and return all matching messages.
    pub fn list(self) -> Result<Vec<Message>, Error> {
        self.db.with_conn(|conn| {
            let mut sql = String::from(
                "SELECT id, session_id, role, content, tokens, created_at FROM messages",
            );
            let mut params: Vec<rusqlite::types::Value> = Vec::new();
            let mut conditions = Vec::new();

            if let Some(sid) = &self.session_id {
                conditions.push(format!("session_id = ?{}", params.len() + 1));
                params.push(rusqlite::types::Value::Text(sid.to_string()));
            }

            if let Some(ref role) = self.role {
                conditions.push(format!("role = ?{}", params.len() + 1));
                params.push(rusqlite::types::Value::Text(role.to_string()));
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
                    Ok(row_to_message(row))
                })
                .map_err(|e| Error::Database(e.to_string()))?;

            let mut results = Vec::new();
            for row in rows {
                let msg = row
                    .map_err(|e| Error::Database(e.to_string()))?
                    .map_err(|e| Error::Database(e.to_string()))?;
                results.push(msg);
            }
            Ok(results)
        })
    }

    /// Execute a COUNT query with the same filters (ignores limit/offset/ordering).
    pub fn count(self) -> Result<usize, Error> {
        self.db.with_conn(|conn| {
            let mut sql = String::from("SELECT COUNT(*) FROM messages");
            let mut params: Vec<rusqlite::types::Value> = Vec::new();
            let mut conditions = Vec::new();

            if let Some(sid) = &self.session_id {
                conditions.push(format!("session_id = ?{}", params.len() + 1));
                params.push(rusqlite::types::Value::Text(sid.to_string()));
            }

            if let Some(ref role) = self.role {
                conditions.push(format!("role = ?{}", params.len() + 1));
                params.push(rusqlite::types::Value::Text(role.to_string()));
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
    use sigint_core::types::{Message, Role, Session};

    fn db_with_session() -> (Database, uuid::Uuid) {
        let db = Database::open_in_memory().unwrap();
        let s = Session::new("test");
        db.create_session(&s).unwrap();
        (db, s.id)
    }

    #[test]
    fn query_messages_by_session() {
        let (db, sid) = db_with_session();
        let (_, sid2) = {
            let s2 = Session::new("other");
            db.create_session(&s2).unwrap();
            (db.get_session(s2.id).unwrap(), s2.id)
        };

        db.create_message(&Message::user(sid, "hello")).unwrap();
        db.create_message(&Message::user(sid2, "other session"))
            .unwrap();

        let results = db.messages_query().by_session(sid).list().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].content, "hello");
    }

    #[test]
    fn query_messages_by_role() {
        let (db, sid) = db_with_session();
        db.create_message(&Message::user(sid, "q")).unwrap();
        db.create_message(&Message::assistant(sid, "a")).unwrap();
        db.create_message(&Message::user(sid, "q2")).unwrap();

        let user_msgs = db
            .messages_query()
            .by_session(sid)
            .by_role(Role::User)
            .list()
            .unwrap();
        assert_eq!(user_msgs.len(), 2);
        assert!(user_msgs.iter().all(|m| m.role == Role::User));

        let asst_msgs = db
            .messages_query()
            .by_session(sid)
            .by_role(Role::Assistant)
            .list()
            .unwrap();
        assert_eq!(asst_msgs.len(), 1);
    }

    #[test]
    fn query_messages_order_by_date_desc() {
        let (db, sid) = db_with_session();
        db.create_message(&Message::user(sid, "first")).unwrap();
        db.create_message(&Message::assistant(sid, "second"))
            .unwrap();

        let results = db
            .messages_query()
            .by_session(sid)
            .order_by_date_desc()
            .list()
            .unwrap();
        assert_eq!(results.len(), 2);
        assert!(results[0].created_at >= results[1].created_at);
    }

    #[test]
    fn query_messages_count() {
        let (db, sid) = db_with_session();
        for i in 0..4 {
            db.create_message(&Message::user(sid, format!("msg{i}")))
                .unwrap();
        }
        assert_eq!(db.messages_query().by_session(sid).count().unwrap(), 4);
    }

    #[test]
    fn query_messages_pagination() {
        let (db, sid) = db_with_session();
        for i in 0..8 {
            db.create_message(&Message::user(sid, format!("m{i}")))
                .unwrap();
        }
        let page = db.messages_query().by_session(sid).limit(3).offset(2).list().unwrap();
        assert_eq!(page.len(), 3);
    }
}
