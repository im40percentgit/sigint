//! Embedded SQL migration system for sigint-store.
//!
//! @decision DEC-STORE-001
//! @title Embedded SQL migrations with integer version tracking
//! @status accepted
//! @rationale Migrations are compiled into the binary (no external files).
//! A `schema_version` table tracks which have run. Each migration is
//! idempotent: applied once in order, never re-applied. This is simpler
//! than a full migration framework for a single-file SQLite DB.

use rusqlite::Connection;
use sigint_core::Error;
use tracing::info;

/// All migrations in order. Each entry is (version, description, sql).
/// Version numbers must be consecutive starting from 1.
static MIGRATIONS: &[(u32, &str, &str)] = &[
    (
        1,
        "initial schema",
        "
        CREATE TABLE IF NOT EXISTS schema_version (
            version     INTEGER PRIMARY KEY,
            description TEXT NOT NULL,
            applied_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id          TEXT PRIMARY KEY,
            name        TEXT NOT NULL,
            target      TEXT,
            created_at  TEXT NOT NULL,
            updated_at  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS messages (
            id          TEXT PRIMARY KEY,
            session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
            role        TEXT NOT NULL CHECK(role IN ('system','user','assistant','tool')),
            content     TEXT NOT NULL,
            tokens      INTEGER,
            created_at  TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_messages_session ON messages(session_id, created_at);

        CREATE TABLE IF NOT EXISTS tasks (
            id              TEXT PRIMARY KEY,
            session_id      TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
            title           TEXT NOT NULL,
            description     TEXT NOT NULL DEFAULT '',
            status          TEXT NOT NULL DEFAULT 'pending',
            assigned_agent  TEXT,
            created_at      TEXT NOT NULL,
            updated_at      TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS findings (
            id          TEXT PRIMARY KEY,
            session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
            title       TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            severity    TEXT NOT NULL DEFAULT 'info',
            asset       TEXT,
            evidence    TEXT,
            created_at  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS assets (
            id              TEXT PRIMARY KEY,
            session_id      TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
            kind            TEXT NOT NULL,
            value           TEXT NOT NULL,
            metadata        TEXT NOT NULL DEFAULT 'null',
            discovered_at   TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS asset_services (
            id          TEXT PRIMARY KEY,
            asset_id    TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
            port        INTEGER NOT NULL,
            protocol    TEXT NOT NULL DEFAULT 'tcp',
            service     TEXT,
            version     TEXT,
            banner      TEXT,
            discovered_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS asset_changes (
            id          TEXT PRIMARY KEY,
            asset_id    TEXT NOT NULL REFERENCES assets(id) ON DELETE CASCADE,
            field       TEXT NOT NULL,
            old_value   TEXT,
            new_value   TEXT,
            changed_at  TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scan_history (
            id          TEXT PRIMARY KEY,
            session_id  TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
            tool        TEXT NOT NULL,
            args        TEXT NOT NULL DEFAULT '[]',
            output      TEXT,
            exit_code   INTEGER,
            started_at  TEXT NOT NULL,
            finished_at TEXT
        );

        CREATE TABLE IF NOT EXISTS embeddings (
            id          TEXT PRIMARY KEY,
            source_type TEXT NOT NULL,
            source_id   TEXT NOT NULL,
            model       TEXT NOT NULL,
            vector      BLOB NOT NULL,
            created_at  TEXT NOT NULL,
            UNIQUE(source_type, source_id, model)
        );
        ",
    ),
];

/// Run all pending migrations against the given connection.
///
/// Idempotent: already-applied migrations (by version number) are skipped.
pub fn run_migrations(conn: &Connection) -> Result<(), Error> {
    // Bootstrap: ensure schema_version table exists before we query it
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (
            version     INTEGER PRIMARY KEY,
            description TEXT NOT NULL,
            applied_at  TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
        );",
    )
    .map_err(|e| Error::Database(format!("Cannot create schema_version: {}", e)))?;

    let current_version: u32 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |r| r.get(0),
        )
        .map_err(|e| Error::Database(format!("Cannot read schema_version: {}", e)))?;

    for (version, description, sql) in MIGRATIONS {
        if *version <= current_version {
            continue;
        }
        info!("Applying migration {}: {}", version, description);
        conn.execute_batch(sql)
            .map_err(|e| Error::Database(format!("Migration {} failed: {}", version, e)))?;
        conn.execute(
            "INSERT OR IGNORE INTO schema_version (version, description) VALUES (?1, ?2)",
            rusqlite::params![version, description],
        )
        .map_err(|e| Error::Database(format!("Cannot record migration {}: {}", version, e)))?;
        info!("Migration {} applied successfully", version);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;

    fn in_memory() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        conn
    }

    #[test]
    fn migrations_run_once() {
        let conn = in_memory();
        run_migrations(&conn).expect("first run should succeed");
        run_migrations(&conn).expect("second run should be idempotent");

        let version: u32 = conn
            .query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(version, MIGRATIONS.last().unwrap().0);
    }

    #[test]
    fn all_tables_created() {
        let conn = in_memory();
        run_migrations(&conn).unwrap();

        let expected_tables = [
            "sessions", "messages", "tasks", "findings", "assets",
            "asset_services", "asset_changes", "scan_history", "embeddings",
        ];

        for table in &expected_tables {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    rusqlite::params![table],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "Table '{}' should exist after migration", table);
        }
    }

    #[test]
    fn schema_version_recorded() {
        let conn = in_memory();
        run_migrations(&conn).unwrap();

        let desc: String = conn
            .query_row(
                "SELECT description FROM schema_version WHERE version = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(desc, "initial schema");
    }
}
