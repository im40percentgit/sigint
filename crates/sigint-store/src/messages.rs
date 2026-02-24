//! CRUD operations for Message records.
//!
//! @decision DEC-STORE-001
//! @title Messages stored with role CHECK constraint and session FK
//! @status accepted
//! @rationale The CHECK constraint on `role` catches programmer errors at
//! the database level. CASCADE DELETE means cleaning up a session also
//! removes its messages without requiring a separate application-level step.

use rusqlite::params;
use sigint_core::{
    types::{Message, Role},
    Error,
};
use uuid::Uuid;

use crate::db::Database;

impl Database {
    /// Insert a new message into the store.
    pub fn create_message(&self, msg: &Message) -> Result<(), Error> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO messages (id, session_id, role, content, tokens, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    msg.id.to_string(),
                    msg.session_id.to_string(),
                    msg.role.to_string(),
                    msg.content,
                    msg.tokens,
                    msg.created_at.to_rfc3339(),
                ],
            )
            .map_err(|e| Error::Database(format!("create_message failed: {}", e)))?;
            Ok(())
        })
    }

    /// Fetch all messages for a session, ordered chronologically.
    pub fn get_messages(&self, session_id: Uuid) -> Result<Vec<Message>, Error> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, session_id, role, content, tokens, created_at
                     FROM messages WHERE session_id = ?1
                     ORDER BY created_at ASC",
                )
                .map_err(|e| Error::Database(e.to_string()))?;

            let messages = stmt
                .query_map(params![session_id.to_string()], |row| {
                    Ok(row_to_message(row))
                })
                .map_err(|e| Error::Database(e.to_string()))?
                .filter_map(|r| r.ok())
                .filter_map(|r| r.ok())
                .collect();

            Ok(messages)
        })
    }

    /// Fetch a single message by ID.
    pub fn get_message(&self, id: Uuid) -> Result<Option<Message>, Error> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, session_id, role, content, tokens, created_at
                     FROM messages WHERE id = ?1",
                )
                .map_err(|e| Error::Database(e.to_string()))?;

            let mut rows = stmt
                .query(params![id.to_string()])
                .map_err(|e| Error::Database(e.to_string()))?;

            if let Some(row) = rows.next().map_err(|e| Error::Database(e.to_string()))? {
                Ok(Some(row_to_message(row)?))
            } else {
                Ok(None)
            }
        })
    }

    /// Update the token count for an existing message (after streaming completes).
    pub fn update_message_tokens(&self, id: Uuid, tokens: u32) -> Result<(), Error> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE messages SET tokens = ?1 WHERE id = ?2",
                params![tokens, id.to_string()],
            )
            .map_err(|e| Error::Database(format!("update_message_tokens failed: {}", e)))?;
            Ok(())
        })
    }
}

fn role_from_str(s: &str) -> Role {
    match s {
        "system" => Role::System,
        "user" => Role::User,
        "assistant" => Role::Assistant,
        "tool" => Role::Tool,
        _ => Role::User, // safe fallback — shouldn't happen due to CHECK constraint
    }
}

fn row_to_message(row: &rusqlite::Row<'_>) -> Result<Message, Error> {
    let id_str: String = row.get(0).map_err(|e| Error::Database(e.to_string()))?;
    let sid_str: String = row.get(1).map_err(|e| Error::Database(e.to_string()))?;
    let role_str: String = row.get(2).map_err(|e| Error::Database(e.to_string()))?;
    let content: String = row.get(3).map_err(|e| Error::Database(e.to_string()))?;
    let tokens: Option<u32> = row.get(4).map_err(|e| Error::Database(e.to_string()))?;
    let created_at_str: String = row.get(5).map_err(|e| Error::Database(e.to_string()))?;

    let id = Uuid::parse_str(&id_str)
        .map_err(|e| Error::Database(format!("Invalid UUID '{}': {}", id_str, e)))?;
    let session_id = Uuid::parse_str(&sid_str)
        .map_err(|e| Error::Database(format!("Invalid session UUID '{}': {}", sid_str, e)))?;
    let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|e| Error::Database(format!("Invalid timestamp: {}", e)))?;

    Ok(Message {
        id,
        session_id,
        role: role_from_str(&role_str),
        content,
        tokens,
        created_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigint_core::types::{Message, Session};

    fn db() -> Database {
        Database::open_in_memory().unwrap()
    }

    fn setup_session(db: &Database) -> Uuid {
        let s = Session::new("test-session");
        db.create_session(&s).unwrap();
        s.id
    }

    #[test]
    fn create_and_fetch_message() {
        let db = db();
        let sid = setup_session(&db);
        let msg = Message::user(sid, "hello world");

        db.create_message(&msg).unwrap();

        let fetched = db.get_message(msg.id).unwrap().expect("message should exist");
        assert_eq!(fetched.id, msg.id);
        assert_eq!(fetched.role, Role::User);
        assert_eq!(fetched.content, "hello world");
        assert!(fetched.tokens.is_none());
    }

    #[test]
    fn get_messages_for_session_ordered() {
        let db = db();
        let sid = setup_session(&db);

        let m1 = Message::user(sid, "first");
        let m2 = Message::assistant(sid, "second");
        let m3 = Message::user(sid, "third");

        db.create_message(&m1).unwrap();
        db.create_message(&m2).unwrap();
        db.create_message(&m3).unwrap();

        let messages = db.get_messages(sid).unwrap();
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0].content, "first");
        assert_eq!(messages[1].content, "second");
        assert_eq!(messages[2].content, "third");
    }

    #[test]
    fn update_message_tokens() {
        let db = db();
        let sid = setup_session(&db);
        let msg = Message::assistant(sid, "response text");
        db.create_message(&msg).unwrap();

        db.update_message_tokens(msg.id, 42).unwrap();

        let fetched = db.get_message(msg.id).unwrap().unwrap();
        assert_eq!(fetched.tokens, Some(42));
    }

    #[test]
    fn messages_cascade_delete_with_session() {
        let db = db();
        let sid = setup_session(&db);
        let msg = Message::user(sid, "will be deleted");
        db.create_message(&msg).unwrap();

        db.delete_session(sid).unwrap();

        let messages = db.get_messages(sid).unwrap();
        assert!(messages.is_empty(), "Messages should be cascade-deleted");
    }

    #[test]
    fn get_message_missing_returns_none() {
        let db = db();
        let result = db.get_message(Uuid::new_v4()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn all_roles_roundtrip() {
        let db = db();
        let sid = setup_session(&db);

        for (role, content) in [
            (Role::System, "sys"),
            (Role::User, "usr"),
            (Role::Assistant, "asst"),
        ] {
            let msg = Message::new(sid, role.clone(), content);
            db.create_message(&msg).unwrap();
            let fetched = db.get_message(msg.id).unwrap().unwrap();
            assert_eq!(fetched.role, role);
        }
    }
}
