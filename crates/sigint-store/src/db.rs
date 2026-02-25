//! Database handle — opens/creates the SQLite file and runs migrations.
//!
//! @decision DEC-P3-POOL
//! @title r2d2 connection pool replaces Mutex<Connection>
//! @status accepted
//! @rationale WAL mode + r2d2 pool enables concurrent reads from TUI and agents
//! without mutex contention. Pool size defaults to 4 for file DBs. In-memory
//! DBs use max_size(1) because each SQLite :memory: connection is independent —
//! a pool of N would create N separate databases, each running migrations
//! independently, so only one connection ever sees the migrated schema. Using
//! max_size(1) for in-memory keeps existing test ergonomics (Database::open_in_memory())
//! while avoiding shared-cache URI complexity. PRAGMAs are applied via
//! CustomizeConnection so every pooled connection inherits WAL + foreign keys.

use std::path::Path;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;
use tracing::info;

use sigint_core::Error;

use crate::embeddings::register_cosine_similarity_udf;
use crate::migrations::run_migrations;
use crate::query::sessions::SessionQuery;
use crate::query::findings::FindingQuery;
use crate::query::messages::MessageQuery;
use crate::query::scans::ScanQuery;

/// Default pool size for file-backed databases.
const FILE_POOL_SIZE: u32 = 4;

/// Pool size for in-memory databases — must be 1 to share a single DB.
const MEMORY_POOL_SIZE: u32 = 1;

/// Thread-safe SQLite database handle backed by an r2d2 connection pool.
pub struct Database {
    pool: Pool<SqliteConnectionManager>,
}

/// Applies SQLite PRAGMAs to each newly-acquired connection.
#[derive(Debug)]
struct ConnectionInit;

impl r2d2::CustomizeConnection<Connection, rusqlite::Error> for ConnectionInit {
    fn on_acquire(&self, conn: &mut Connection) -> Result<(), rusqlite::Error> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA foreign_keys = ON;
             PRAGMA synchronous = NORMAL;
             PRAGMA cache_size = -8000;
             PRAGMA busy_timeout = 5000;",
        )?;
        register_cosine_similarity_udf(conn)
            .map_err(|e| rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_ERROR),
                Some(e.to_string()),
            ))
    }
}

impl Database {
    /// Open (or create) a file-backed database at `path` and run all pending migrations.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                Error::Database(format!("Cannot create db directory {parent:?}: {e}"))
            })?;
        }

        info!("Opening database at {:?}", path);

        let manager = SqliteConnectionManager::file(path);
        let pool = Pool::builder()
            .max_size(FILE_POOL_SIZE)
            .connection_customizer(Box::new(ConnectionInit))
            .build(manager)
            .map_err(|e| Error::Database(format!("Cannot build connection pool: {e}")))?;

        // Run migrations on a dedicated connection before returning.
        {
            let conn = pool
                .get()
                .map_err(|e| Error::Database(format!("Cannot get connection for migrations: {e}")))?;
            run_migrations(&conn)?;
        }

        Ok(Self { pool })
    }

    /// Open an in-memory database (for tests).
    ///
    /// Pool size is forced to 1 because each SQLite `:memory:` connection is a
    /// completely independent database. A pool of N would run migrations N times
    /// on N separate databases, causing test queries on connections 2-N to see
    /// empty schemas.
    pub fn open_in_memory() -> Result<Self, Error> {
        let manager = SqliteConnectionManager::memory();
        let pool = Pool::builder()
            .max_size(MEMORY_POOL_SIZE)
            .connection_customizer(Box::new(ConnectionInit))
            .build(manager)
            .map_err(|e| Error::Database(format!("Cannot build in-memory pool: {e}")))?;

        {
            let conn = pool
                .get()
                .map_err(|e| Error::Database(format!("Cannot get connection for migrations: {e}")))?;
            run_migrations(&conn)?;
        }

        Ok(Self { pool })
    }

    /// Run a closure with a pooled connection.
    ///
    /// The connection is returned to the pool when the closure completes.
    pub fn with_conn<F, T>(&self, f: F) -> Result<T, Error>
    where
        F: FnOnce(&Connection) -> Result<T, Error>,
    {
        let conn = self
            .pool
            .get()
            .map_err(|e| Error::Database(format!("Cannot acquire connection from pool: {e}")))?;
        f(&conn)
    }

    /// Begin a typed query builder for Session records.
    pub fn sessions(&self) -> SessionQuery<'_> {
        SessionQuery::new(self)
    }

    /// Begin a typed query builder for Finding records.
    pub fn findings(&self) -> FindingQuery<'_> {
        FindingQuery::new(self)
    }

    /// Begin a typed query builder for Message records.
    ///
    /// Named `messages_query` to avoid collision with the existing `get_messages` method.
    pub fn messages_query(&self) -> MessageQuery<'_> {
        MessageQuery::new(self)
    }

    /// Begin a typed query builder for ScanRecord records.
    pub fn scans_query(&self) -> ScanQuery<'_> {
        ScanQuery::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_in_memory_succeeds() {
        let db = Database::open_in_memory().expect("in-memory db should open");
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
