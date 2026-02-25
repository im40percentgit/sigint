//! CRUD operations for scan_history records.
//!
//! Each `ScanRecord` captures one tool execution during a scan pipeline run.
//! Records are keyed by UUID and linked to a parent session via `session_id`.
//! The scan_history table was created in migration 1; no schema changes here.
//!
//! @decision DEC-STORE-002
//! @title ScanRecord stored as denormalized row — one row per tool invocation
//! @status accepted
//! @rationale Each agent turn may invoke multiple tools. Storing one row per
//! invocation (rather than aggregating into JSON blobs) enables per-tool
//! queries, filtering by exit_code, and future diffing across scans. The
//! `args` column is serialized JSON so it remains human-readable without
//! requiring a separate arguments table. `output` combines stdout; stderr is
//! elided from the table (available in the in-memory ScanResult during a
//! live run) to avoid doubling storage for large nmap outputs.

use rusqlite::params;
use sigint_core::Error;
use uuid::Uuid;

use crate::db::Database;

/// A single tool-invocation record persisted in the scan_history table.
#[derive(Debug, Clone)]
pub struct ScanRecord {
    /// Unique record identifier.
    pub id: Uuid,
    /// Parent session this record belongs to.
    pub session_id: Uuid,
    /// Tool name (e.g. "nmap_scan", "shell").
    pub tool: String,
    /// Serialized JSON arguments passed to the tool.
    pub args: String,
    /// Combined stdout output (may be large for nmap full scans).
    pub output: Option<String>,
    /// Process exit code (0 = success).
    pub exit_code: Option<i32>,
    /// ISO-8601 timestamp when the tool started.
    pub started_at: String,
    /// ISO-8601 timestamp when the tool finished (None if still running).
    pub finished_at: Option<String>,
}

impl ScanRecord {
    /// Create a new `ScanRecord` with a fresh UUID and the current timestamp.
    pub fn new(
        session_id: Uuid,
        tool: impl Into<String>,
        args: impl Into<String>,
    ) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            id: Uuid::new_v4(),
            session_id,
            tool: tool.into(),
            args: args.into(),
            output: None,
            exit_code: None,
            started_at: now,
            finished_at: None,
        }
    }
}

impl Database {
    /// Insert a scan_history record. Fails if `record.id` already exists.
    pub fn create_scan_record(&self, record: &ScanRecord) -> Result<(), Error> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO scan_history (id, session_id, tool, args, output, exit_code, started_at, finished_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    record.id.to_string(),
                    record.session_id.to_string(),
                    record.tool,
                    record.args,
                    record.output,
                    record.exit_code,
                    record.started_at,
                    record.finished_at,
                ],
            )
            .map_err(|e| Error::Database(format!("create_scan_record failed: {}", e)))?;
            Ok(())
        })
    }

    /// Return all scan_history records for a session, ordered by started_at ascending.
    pub fn get_scan_records(&self, session_id: Uuid) -> Result<Vec<ScanRecord>, Error> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, session_id, tool, args, output, exit_code, started_at, finished_at
                     FROM scan_history
                     WHERE session_id = ?1
                     ORDER BY started_at ASC",
                )
                .map_err(|e| Error::Database(e.to_string()))?;

            let records = stmt
                .query_map(params![session_id.to_string()], |row| {
                    Ok(row_to_scan_record(row))
                })
                .map_err(|e| Error::Database(e.to_string()))?
                .filter_map(|r| r.ok())
                .filter_map(|r| r.ok())
                .collect();

            Ok(records)
        })
    }
}

pub(crate) fn row_to_scan_record(row: &rusqlite::Row<'_>) -> Result<ScanRecord, Error> {
    let id_str: String = row.get(0).map_err(|e| Error::Database(e.to_string()))?;
    let session_id_str: String = row.get(1).map_err(|e| Error::Database(e.to_string()))?;
    let tool: String = row.get(2).map_err(|e| Error::Database(e.to_string()))?;
    let args: String = row.get(3).map_err(|e| Error::Database(e.to_string()))?;
    let output: Option<String> = row.get(4).map_err(|e| Error::Database(e.to_string()))?;
    let exit_code: Option<i32> = row.get(5).map_err(|e| Error::Database(e.to_string()))?;
    let started_at: String = row.get(6).map_err(|e| Error::Database(e.to_string()))?;
    let finished_at: Option<String> = row.get(7).map_err(|e| Error::Database(e.to_string()))?;

    let id = Uuid::parse_str(&id_str)
        .map_err(|e| Error::Database(format!("Invalid scan record UUID '{}': {}", id_str, e)))?;
    let session_id = Uuid::parse_str(&session_id_str)
        .map_err(|e| Error::Database(format!("Invalid session UUID '{}': {}", session_id_str, e)))?;

    Ok(ScanRecord {
        id,
        session_id,
        tool,
        args,
        output,
        exit_code,
        started_at,
        finished_at,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Database {
        Database::open_in_memory().unwrap()
    }

    fn make_session(db: &Database) -> Uuid {
        let session = sigint_core::types::Session::new("test-session");
        db.create_session(&session).unwrap();
        session.id
    }

    #[test]
    fn create_and_retrieve_scan_record() {
        let db = db();
        let session_id = make_session(&db);

        let mut record = ScanRecord::new(session_id, "nmap_scan", r#"{"target":"10.0.0.1"}"#);
        record.output = Some("Nmap scan report for 10.0.0.1".into());
        record.exit_code = Some(0);
        record.finished_at = Some(chrono::Utc::now().to_rfc3339());

        db.create_scan_record(&record).unwrap();

        let records = db.get_scan_records(session_id).unwrap();
        assert_eq!(records.len(), 1);

        let fetched = &records[0];
        assert_eq!(fetched.id, record.id);
        assert_eq!(fetched.session_id, session_id);
        assert_eq!(fetched.tool, "nmap_scan");
        assert_eq!(fetched.args, r#"{"target":"10.0.0.1"}"#);
        assert_eq!(fetched.output.as_deref(), Some("Nmap scan report for 10.0.0.1"));
        assert_eq!(fetched.exit_code, Some(0));
    }

    #[test]
    fn get_scan_records_empty_for_unknown_session() {
        let db = db();
        let records = db.get_scan_records(Uuid::new_v4()).unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn multiple_records_ordered_by_started_at() {
        let db = db();
        let session_id = make_session(&db);

        let mut r1 = ScanRecord::new(session_id, "nmap_scan", "{}");
        r1.started_at = "2026-01-01T00:00:00Z".into();

        let mut r2 = ScanRecord::new(session_id, "shell", "{}");
        r2.started_at = "2026-01-01T00:01:00Z".into();

        db.create_scan_record(&r1).unwrap();
        db.create_scan_record(&r2).unwrap();

        let records = db.get_scan_records(session_id).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].tool, "nmap_scan");
        assert_eq!(records[1].tool, "shell");
    }

    #[test]
    fn records_isolated_by_session() {
        let db = db();
        let s1 = make_session(&db);

        // Second session
        let s2_session = sigint_core::types::Session::new("session-2");
        db.create_session(&s2_session).unwrap();
        let s2 = s2_session.id;

        db.create_scan_record(&ScanRecord::new(s1, "nmap_scan", "{}")).unwrap();
        db.create_scan_record(&ScanRecord::new(s2, "shell", "{}")).unwrap();

        let s1_records = db.get_scan_records(s1).unwrap();
        let s2_records = db.get_scan_records(s2).unwrap();

        assert_eq!(s1_records.len(), 1);
        assert_eq!(s1_records[0].tool, "nmap_scan");

        assert_eq!(s2_records.len(), 1);
        assert_eq!(s2_records[0].tool, "shell");
    }

    #[test]
    fn nullable_fields_roundtrip() {
        let db = db();
        let session_id = make_session(&db);

        // Record with no output, no exit_code, no finished_at
        let record = ScanRecord::new(session_id, "shell", "[]");
        db.create_scan_record(&record).unwrap();

        let records = db.get_scan_records(session_id).unwrap();
        assert_eq!(records.len(), 1);
        assert!(records[0].output.is_none());
        assert!(records[0].exit_code.is_none());
        assert!(records[0].finished_at.is_none());
    }
}
