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
    (
        3,
        "session resume: parent_session_id",
        "ALTER TABLE sessions ADD COLUMN parent_session_id TEXT REFERENCES sessions(id)",
    ),
    (
        4,
        "campaigns table",
        "
        CREATE TABLE IF NOT EXISTS campaigns (
            id           TEXT PRIMARY KEY,
            name         TEXT NOT NULL,
            file_path    TEXT,
            created_at   TEXT NOT NULL,
            completed_at TEXT
        )
        ",
    ),
    (
        5,
        "sessions: campaign_id foreign key",
        "ALTER TABLE sessions ADD COLUMN campaign_id TEXT REFERENCES campaigns(id)",
    ),
    (
        6,
        "findings: cvss_score column",
        "ALTER TABLE findings ADD COLUMN cvss_score REAL",
    ),
    (
        7,
        "scan_history: agent_role column",
        "ALTER TABLE scan_history ADD COLUMN agent_role TEXT",
    ),
    (
        8,
        "findings: Phase 12A enrichment columns",
        "
        ALTER TABLE findings ADD COLUMN remediation TEXT;
        ALTER TABLE findings ADD COLUMN exploitability TEXT;
        ALTER TABLE findings ADD COLUMN impact TEXT;
        ALTER TABLE findings ADD COLUMN evidence_ref TEXT;
        ALTER TABLE findings ADD COLUMN chain_id TEXT;
        ALTER TABLE findings ADD COLUMN chain_order INTEGER;
        ",
    ),
    (
        9,
        "findings: asset_id foreign key",
        "
        ALTER TABLE findings ADD COLUMN asset_id TEXT REFERENCES assets(id);
        CREATE INDEX IF NOT EXISTS idx_findings_asset_id ON findings(asset_id);
        ",
    ),
    (
        10,
        "sessions: trainable opt-in column for fine-tuning harvest",
        "ALTER TABLE sessions ADD COLUMN trainable INTEGER NOT NULL DEFAULT 0",
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
            "sessions",
            "messages",
            "tasks",
            "findings",
            "assets",
            "asset_services",
            "asset_changes",
            "scan_history",
            "embeddings",
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
            assert_eq!(
                count, 1,
                "FTS5 table '{}' should exist after migration 2",
                table
            );
        }
    }

    #[test]
    fn fts5_sync_triggers_exist() {
        let conn = in_memory();
        run_migrations(&conn).unwrap();

        let expected_triggers = [
            "messages_fts_ai",
            "messages_fts_ad",
            "messages_fts_au",
            "findings_fts_ai",
            "findings_fts_ad",
            "findings_fts_au",
            "scan_history_fts_ai",
            "scan_history_fts_ad",
            "scan_history_fts_au",
        ];

        for trigger in &expected_triggers {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name=?1",
                    rusqlite::params![trigger],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(
                count, 1,
                "Trigger '{}' should exist after migration 2",
                trigger
            );
        }
    }

    #[test]
    fn parent_session_id_column_exists_and_defaults_to_null() {
        use crate::Database;

        let db = Database::open_in_memory().expect("in-memory db should open");
        db.with_conn(|conn| {
            // Insert a session without specifying parent_session_id — it should default to NULL.
            conn.execute(
                "INSERT INTO sessions (id, name, target, created_at, updated_at)
                 VALUES ('sess-1', 'Test Session', 'example.com', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
                [],
            )
            .map_err(|e| sigint_core::Error::Database(e.to_string()))?;

            // Verify parent_session_id is NULL.
            let parent_id: Option<String> = conn
                .query_row(
                    "SELECT parent_session_id FROM sessions WHERE id = 'sess-1'",
                    [],
                    |r| r.get(0),
                )
                .map_err(|e| sigint_core::Error::Database(e.to_string()))?;

            assert!(
                parent_id.is_none(),
                "parent_session_id should default to NULL, got: {:?}",
                parent_id
            );

            // Also verify we can insert a child session pointing to the parent.
            conn.execute(
                "INSERT INTO sessions (id, name, target, created_at, updated_at, parent_session_id)
                 VALUES ('sess-2', 'Resume Session', 'example.com', '2026-01-02T00:00:00Z', '2026-01-02T00:00:00Z', 'sess-1')",
                [],
            )
            .map_err(|e| sigint_core::Error::Database(e.to_string()))?;

            let child_parent: Option<String> = conn
                .query_row(
                    "SELECT parent_session_id FROM sessions WHERE id = 'sess-2'",
                    [],
                    |r| r.get(0),
                )
                .map_err(|e| sigint_core::Error::Database(e.to_string()))?;

            assert_eq!(
                child_parent.as_deref(),
                Some("sess-1"),
                "child session's parent_session_id should be 'sess-1'"
            );

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn migration_creates_campaigns_table_and_campaign_id_column() {
        use crate::Database;

        let db = Database::open_in_memory().unwrap();
        db.with_conn(|conn| {
            conn.execute(
                "INSERT INTO campaigns (id, name, created_at) VALUES (?1, ?2, ?3)",
                rusqlite::params!["camp-1", "test-campaign", "2026-01-01T00:00:00Z"],
            ).unwrap();
            conn.execute(
                "INSERT INTO sessions (id, name, created_at, updated_at, campaign_id) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params!["sess-1", "test", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", "camp-1"],
            ).unwrap();
            let cid: Option<String> = conn.query_row(
                "SELECT campaign_id FROM sessions WHERE id = 'sess-1'", [], |row| row.get(0)
            ).unwrap();
            assert_eq!(cid.as_deref(), Some("camp-1"));
            Ok(())
        }).unwrap();
    }

    #[test]
    fn migration_adds_cvss_score_column() {
        use crate::Database;

        let db = Database::open_in_memory().unwrap();
        db.with_conn(|conn| {
            // Insert a session first (FK requirement).
            conn.execute(
                "INSERT INTO sessions (id, name, created_at, updated_at) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params!["sess-cvss", "test", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"],
            ).unwrap();

            // Insert a finding without specifying cvss_score — should default to NULL.
            conn.execute(
                "INSERT INTO findings (id, session_id, title, description, severity, created_at)
                 VALUES ('find-1', 'sess-cvss', 'Test Finding', 'desc', 'high', '2026-01-01T00:00:00Z')",
                [],
            ).unwrap();

            // Verify cvss_score defaults to NULL.
            let score: Option<f64> = conn.query_row(
                "SELECT cvss_score FROM findings WHERE id = 'find-1'",
                [],
                |row| row.get(0),
            ).unwrap();
            assert!(score.is_none(), "cvss_score should default to NULL, got: {score:?}");

            // Also verify we can store a non-NULL value.
            conn.execute(
                "INSERT INTO findings (id, session_id, title, description, severity, cvss_score, created_at)
                 VALUES ('find-2', 'sess-cvss', 'Critical Finding', 'desc', 'critical', 9.5, '2026-01-01T00:00:01Z')",
                [],
            ).unwrap();
            let score2: Option<f64> = conn.query_row(
                "SELECT cvss_score FROM findings WHERE id = 'find-2'",
                [],
                |row| row.get(0),
            ).unwrap();
            assert_eq!(score2, Some(9.5));

            Ok(())
        }).unwrap();
    }

    /// Migration 8 adds 6 enrichment columns to `findings`; all default to NULL.
    #[test]
    fn migration_8_adds_enrichment_columns_defaulting_to_null() {
        use crate::Database;

        let db = Database::open_in_memory().unwrap();
        db.with_conn(|conn| {
            // Insert a session (FK requirement).
            conn.execute(
                "INSERT INTO sessions (id, name, created_at, updated_at) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![
                    "sess-m8",
                    "test",
                    "2026-01-01T00:00:00Z",
                    "2026-01-01T00:00:00Z"
                ],
            )
            .unwrap();

            // Insert a finding without the new columns — should work and all new cols = NULL.
            conn.execute(
                "INSERT INTO findings (id, session_id, title, description, severity, created_at)
                 VALUES ('find-m8', 'sess-m8', 'Test', 'desc', 'info', '2026-01-01T00:00:00Z')",
                [],
            )
            .unwrap();

            // Verify all 6 new columns default to NULL.
            let (remediation, exploitability, impact, evidence_ref, chain_id, chain_order):
                (Option<String>, Option<String>, Option<String>,
                 Option<String>, Option<String>, Option<i64>) = conn.query_row(
                "SELECT remediation, exploitability, impact, evidence_ref, chain_id, chain_order
                 FROM findings WHERE id = 'find-m8'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?,
                           row.get(3)?, row.get(4)?, row.get(5)?)),
            ).unwrap();

            assert!(remediation.is_none(), "remediation should be NULL");
            assert!(exploitability.is_none(), "exploitability should be NULL");
            assert!(impact.is_none(), "impact should be NULL");
            assert!(evidence_ref.is_none(), "evidence_ref should be NULL");
            assert!(chain_id.is_none(), "chain_id should be NULL");
            assert!(chain_order.is_none(), "chain_order should be NULL");

            // Also verify we can write and read back non-NULL values.
            conn.execute(
                "INSERT INTO findings (id, session_id, title, description, severity, created_at,
                                       remediation, exploitability, impact,
                                       evidence_ref, chain_id, chain_order)
                 VALUES ('find-m8b', 'sess-m8', 'Enriched', 'desc', 'high', '2026-01-01T00:00:01Z',
                         'Patch it', 'public, no auth', 'Full DB dump',
                         'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                         'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
                         3)",
                [],
            )
            .unwrap();

            let (rem, expl, imp, eref, cid, cord):
                (Option<String>, Option<String>, Option<String>,
                 Option<String>, Option<String>, Option<i64>) = conn.query_row(
                "SELECT remediation, exploitability, impact, evidence_ref, chain_id, chain_order
                 FROM findings WHERE id = 'find-m8b'",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?,
                           row.get(3)?, row.get(4)?, row.get(5)?)),
            ).unwrap();

            assert_eq!(rem.as_deref(), Some("Patch it"));
            assert_eq!(expl.as_deref(), Some("public, no auth"));
            assert_eq!(imp.as_deref(), Some("Full DB dump"));
            assert_eq!(
                eref.as_deref(),
                Some("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
            );
            assert_eq!(cid.as_deref(), Some("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"));
            assert_eq!(cord, Some(3));

            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn migration_9_adds_asset_id_column() {
        let conn = in_memory();
        run_migrations(&conn).unwrap();
        conn.execute(
            "INSERT INTO sessions (id, name, created_at, updated_at) VALUES ('s1', 'test', datetime('now'), datetime('now'))",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO assets (id, session_id, kind, value, discovered_at) VALUES ('a1', 's1', 'host', '10.0.0.1', datetime('now'))",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO findings (id, session_id, title, description, severity, created_at, asset_id) \
             VALUES ('f1', 's1', 'test', 'desc', 'high', datetime('now'), 'a1')",
            [],
        ).unwrap();
        let asset_id: String = conn.query_row(
            "SELECT asset_id FROM findings WHERE id = 'f1'", [], |r| r.get(0)
        ).unwrap();
        assert_eq!(asset_id, "a1");
    }

    /// Migration 10 adds `trainable INTEGER NOT NULL DEFAULT 0` to sessions.
    /// DEC-P24-002: opt-in harvest gating. Default must be 0 (not trainable)
    /// so existing sessions are never silently included in fine-tune datasets.
    #[test]
    fn migration_10_trainable_column_defaults_to_zero() {
        use crate::Database;

        let db = Database::open_in_memory().unwrap();
        db.with_conn(|conn| {
            // Insert session without specifying trainable — must default to 0.
            conn.execute(
                "INSERT INTO sessions (id, name, created_at, updated_at)
                 VALUES ('sess-t1', 'TrainTest', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
                [],
            )
            .map_err(|e| sigint_core::Error::Database(e.to_string()))?;

            let trainable: i64 = conn
                .query_row(
                    "SELECT trainable FROM sessions WHERE id = 'sess-t1'",
                    [],
                    |r| r.get(0),
                )
                .map_err(|e| sigint_core::Error::Database(e.to_string()))?;

            assert_eq!(trainable, 0, "trainable should default to 0 (opt-out)");

            // Verify we can also set it to 1.
            conn.execute(
                "UPDATE sessions SET trainable = 1 WHERE id = 'sess-t1'",
                [],
            )
            .map_err(|e| sigint_core::Error::Database(e.to_string()))?;

            let trainable_after: i64 = conn
                .query_row(
                    "SELECT trainable FROM sessions WHERE id = 'sess-t1'",
                    [],
                    |r| r.get(0),
                )
                .map_err(|e| sigint_core::Error::Database(e.to_string()))?;

            assert_eq!(trainable_after, 1, "trainable should be 1 after UPDATE");

            Ok(())
        })
        .unwrap();
    }
}
