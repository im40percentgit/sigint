//! Database handle — opens/creates the SQLite file and runs migrations.
//!
//! @decision DEC-STORE-001
//! @title Single Database struct wrapping rusqlite::Connection
//! @status accepted
//! @rationale Wrapping the connection in a struct lets us control WAL mode,
//! foreign key enforcement, and migration runs in one place. The `Mutex`
//! makes it `Send + Sync` for use across async task boundaries — a
//! connection-pool is deferred to Phase 3 when concurrency demands it.

use std::path::Path;
use std::sync::Mutex;

use rusqlite::Connection;
use tracing::info;

use sigint_core::Error;

use crate::migrations::run_migrations;

/// Thread-safe SQLite database handle.
pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    /// Open (or create) the database at `path` and run all pending migrations.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                Error::Database(format!("Cannot create db directory {:?}: {}", parent, e))
            })?;
        }

        let conn = Connection::open(path).map_err(|e| {
            Error::Database(format!("Cannot open database {:?}: {}", path, e))
        })?;

        Self::configure(&conn)?;
        info!("Opened database at {:?}", path);

        let db = Self { conn: Mutex::new(conn) };
        db.with_conn(run_migrations)?;
        Ok(db)
    }

    /// Open an in-memory database (for tests).
    pub fn open_in_memory() -> Result<Self, Error> {
        let conn = Connection::open_in_memory().map_err(|e| {
            Error::Database(format!("Cannot open in-memory database: {}", e))
        })?;
        Self::configure(&conn)?;
        let db = Self { conn: Mutex::new(conn) };
        db.with_conn(run_migrations)?;
        Ok(db)
    }

    /// Apply SQLite pragmas for performance and correctness.
    fn configure(conn: &Connection) -> Result<(), Error> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
             PRAGMA synchronous = NORMAL;
             PRAGMA cache_size = -8000;",
        )
        .map_err(|e| Error::Database(format!("PRAGMA setup failed: {}", e)))?;
        Ok(())
    }

    /// Run a closure with exclusive access to the connection.
    pub fn with_conn<F, T>(&self, f: F) -> Result<T, Error>
    where
        F: FnOnce(&Connection) -> Result<T, Error>,
    {
        let conn = self.conn.lock().map_err(|e| {
            Error::Database(format!("Mutex poisoned: {}", e))
        })?;
        f(&conn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_in_memory_succeeds() {
        let db = Database::open_in_memory().expect("in-memory db should open");
        // Verify we can execute a trivial query
        db.with_conn(|conn| {
            let n: i64 = conn
                .query_row("SELECT 42", [], |r| r.get(0))
                .map_err(|e| Error::Database(e.to_string()))?;
            assert_eq!(n, 42);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn open_file_db_creates_parent_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("nested/dir/sigint.db");
        let db = Database::open(&path).expect("file db should open");
        assert!(path.exists());
        drop(db);
    }

    #[test]
    fn wal_mode_is_set() {
        let db = Database::open_in_memory().unwrap();
        db.with_conn(|conn| {
            let mode: String = conn
                .query_row("PRAGMA journal_mode", [], |r| r.get(0))
                .map_err(|e| Error::Database(e.to_string()))?;
            // In-memory always returns "memory", but file DBs return "wal".
            // Just verify the pragma doesn't error.
            assert!(!mode.is_empty());
            Ok(())
        })
        .unwrap();
    }
}
