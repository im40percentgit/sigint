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
    (
        2,
        "fts5 full-text search",
        "
        -- FTS5 for messages: standalone table with source_id UUID column.
        -- We cannot use content=messages / content_rowid=id because `id` is
        -- a UUID TEXT, not an INTEGER rowid. Standalone FTS5 stores content
        -- copies; triggers keep the index in sync.
        CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
            source_id UNINDEXED,
            content,
            tokenize='porter ascii'
        );
        CREATE TRIGGER IF NOT EXISTS messages_fts_ai AFTER INSERT ON messages BEGIN
            INSERT INTO messages_fts(source_id, content)
                VALUES (new.id, new.content);
        END;
        CREATE TRIGGER IF NOT EXISTS messages_fts_ad AFTER DELETE ON messages BEGIN
            DELETE FROM messages_fts WHERE source_id = old.id;
        END;
        CREATE TRIGGER IF NOT EXISTS messages_fts_au AFTER UPDATE ON messages BEGIN
            DELETE FROM messages_fts WHERE source_id = old.id;
            INSERT INTO messages_fts(source_id, content)
                VALUES (new.id, new.content);
        END;

        -- FTS5 for findings: indexes title + description.
        CREATE VIRTUAL TABLE IF NOT EXISTS findings_fts USING fts5(
            source_id UNINDEXED,
            title,
            description,
            tokenize='porter ascii'
        );
        CREATE TRIGGER IF NOT EXISTS findings_fts_ai AFTER INSERT ON findings BEGIN
            INSERT INTO findings_fts(source_id, title, description)
                VALUES (new.id, new.title, new.description);
        END;
        CREATE TRIGGER IF NOT EXISTS findings_fts_ad AFTER DELETE ON findings BEGIN
            DELETE FROM findings_fts WHERE source_id = old.id;
        END;
        CREATE TRIGGER IF NOT EXISTS findings_fts_au AFTER UPDATE ON findings BEGIN
            DELETE FROM findings_fts WHERE source_id = old.id;
            INSERT INTO findings_fts(source_id, title, description)
                VALUES (new.id, new.title, new.description);
        END;

        -- FTS5 for scan_history: indexes output text.
        CREATE VIRTUAL TABLE IF NOT EXISTS scan_history_fts USING fts5(
            source_id UNINDEXED,
            output,
            tokenize='porter ascii'
        );
        CREATE TRIGGER IF NOT EXISTS scan_history_fts_ai AFTER INSERT ON scan_history BEGIN
            INSERT INTO scan_history_fts(source_id, output)
                VALUES (new.id, COALESCE(new.output, ''));
        END;
        CREATE TRIGGER IF NOT EXISTS scan_history_fts_ad AFTER DELETE ON scan_history BEGIN
            DELETE FROM scan_history_fts WHERE source_id = old.id;
        END;
        CREATE TRIGGER IF NOT EXISTS scan_history_fts_au AFTER UPDATE ON scan_history BEGIN
            DELETE FROM scan_history_fts WHERE source_id = old.id;
            INSERT INTO scan_history_fts(source_id, output)
                VALUES (new.id, COALESCE(new.output, ''));
        END;
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

    #[test]
    fn fts5_virtual_tables_created() {
        let conn = in_memory();
        run_migrations(&conn).unwrap();

        // FTS5 virtual tables appear in sqlite_master with type='table'
        for table in &["messages_fts", "findings_fts", "scan_history_fts"] {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    rusqlite::params![table],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "FTS5 table '{}' should exist after migration 2", table);
        }
    }

    #[test]
    fn fts5_sync_triggers_exist() {
        let conn = in_memory();
        run_migrations(&conn).unwrap();

        let expected_triggers = [
            "messages_fts_ai", "messages_fts_ad", "messages_fts_au",
            "findings_fts_ai", "findings_fts_ad", "findings_fts_au",
            "scan_history_fts_ai", "scan_history_fts_ad", "scan_history_fts_au",
        ];

        for trigger in &expected_triggers {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name=?1",
                    rusqlite::params![trigger],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "Trigger '{}' should exist after migration 2", trigger);
        }
    }
}
