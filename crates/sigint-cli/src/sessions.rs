//! `sigint sessions` — session management subcommands.
//!
//! Provides `list`, `export`, and `delete` operations on stored scan sessions.
//! All operations use the SQLite store via `AppCore`'s configured database path.
//!
//! @decision DEC-CLI-003
//! @title sessions subcommand uses best-effort database access, same as scan
//! @status accepted
//! @rationale Consistency with the scan command's error handling philosophy:
//! database errors are reported with a clear message and non-zero exit, but
//! we do not panic or print stack traces. The `--confirm` flag on delete is
//! a safety guard against accidental data loss when called non-interactively.

use clap::Subcommand;
use sigint_core::{AppCore, Error};
use sigint_store::Database;
use uuid::Uuid;

// ── Clap types ────────────────────────────────────────────────────────────────

/// Arguments parsed for the `sessions` top-level command.
#[derive(Debug, clap::Args)]
pub struct SessionsArgs {
    #[command(subcommand)]
    pub command: SessionsCmd,
}

/// Sub-commands available under `sigint sessions`.
#[derive(Debug, Subcommand)]
pub enum SessionsCmd {
    /// List all stored sessions (id, target, created_at, name).
    List,
    /// Dump a session's messages and scan records as JSON to stdout.
    Export {
        /// Session UUID to export.
        id: String,
    },
    /// Delete a session and all its associated records.
    Delete {
        /// Session UUID to delete.
        id: String,
        /// Skip the interactive confirmation prompt.
        #[arg(long)]
        confirm: bool,
    },
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Dispatch to the appropriate sessions sub-command handler.
pub async fn run(core: AppCore, args: SessionsArgs) -> Result<(), Error> {
    let db_path = core.config.resolved_db_path();
    let db = Database::open(&db_path)
        .map_err(|e| Error::Database(format!("Cannot open database: {e}")))?;

    match args.command {
        SessionsCmd::List => list_sessions(&db),
        SessionsCmd::Export { id } => export_session(&db, &id),
        SessionsCmd::Delete { id, confirm } => delete_session(&db, &id, confirm),
    }
}

// ── list ──────────────────────────────────────────────────────────────────────

/// Print all sessions as formatted rows to stdout.
///
/// Output columns: `id  target  created_at  name`
/// When no sessions exist, prints a human-readable message to stderr and
/// returns `Ok(())` — an empty database is not an error condition.
fn list_sessions(db: &Database) -> Result<(), Error> {
    let sessions = db.list_sessions()?;

    if sessions.is_empty() {
        eprintln!("No sessions found. Run `sigint scan <target>` to create one.");
        return Ok(());
    }

    println!("{:<38}  {:<24}  {:<26}  NAME", "ID", "TARGET", "CREATED_AT");
    println!("{}", "-".repeat(100));

    for session in sessions {
        let target = session.target.as_deref().unwrap_or("-");
        println!(
            "{:<38}  {:<24}  {:<26}  {}",
            session.id,
            target,
            session.created_at.to_rfc3339(),
            session.name,
        );
    }

    Ok(())
}

// ── export ────────────────────────────────────────────────────────────────────

/// Serialise a session's messages and scan records to JSON on stdout.
///
/// JSON schema:
/// ```json
/// {
///   "session": { "id": "...", "name": "...", "target": "...", "created_at": "..." },
///   "messages": [ { "role": "...", "content": "..." }, ... ],
///   "scan_records": [ { "tool": "...", "output": "..." }, ... ]
/// }
/// ```
fn export_session(db: &Database, id_str: &str) -> Result<(), Error> {
    let id = parse_uuid(id_str)?;

    let session = db
        .get_session(id)?
        .ok_or_else(|| Error::Database(format!("Session not found: {id_str}")))?;

    let messages = db.get_messages(id)?;
    let scan_records = db.get_scan_records(id)?;

    let export = serde_json::json!({
        "session": {
            "id": session.id.to_string(),
            "name": session.name,
            "target": session.target,
            "created_at": session.created_at.to_rfc3339(),
            "updated_at": session.updated_at.to_rfc3339(),
        },
        "messages": messages.iter().map(|m| serde_json::json!({
            "id": m.id.to_string(),
            "role": m.role.to_string(),
            "content": m.content,
            "tokens": m.tokens,
            "created_at": m.created_at.to_rfc3339(),
        })).collect::<Vec<_>>(),
        "scan_records": scan_records.iter().map(|r| serde_json::json!({
            "id": r.id.to_string(),
            "tool": r.tool,
            "args": r.args,
            "output": r.output,
            "exit_code": r.exit_code,
            "started_at": r.started_at,
            "finished_at": r.finished_at,
        })).collect::<Vec<_>>(),
    });

    println!(
        "{}",
        serde_json::to_string_pretty(&export)
            .map_err(|e| Error::Database(format!("JSON serialization failed: {e}")))?
    );

    Ok(())
}

// ── delete ────────────────────────────────────────────────────────────────────

/// Delete a session after optional interactive confirmation.
///
/// With `--confirm`, skips the prompt (useful for scripts).
/// Without `--confirm`, reads "yes" from stdin before proceeding.
fn delete_session(db: &Database, id_str: &str, confirmed: bool) -> Result<(), Error> {
    let id = parse_uuid(id_str)?;

    // Verify the session exists before asking for confirmation.
    let session = db
        .get_session(id)?
        .ok_or_else(|| Error::Database(format!("Session not found: {id_str}")))?;

    if !confirmed {
        eprint!(
            "Delete session '{}' ({})? This cannot be undone. Type 'yes' to confirm: ",
            session.name, session.id
        );

        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| Error::Database(format!("Failed to read confirmation: {e}")))?;

        if input.trim() != "yes" {
            eprintln!("Aborted.");
            return Ok(());
        }
    }

    db.delete_session(id)?;
    eprintln!("Deleted session {} ('{}')", id, session.name);

    Ok(())
}

// ── helpers ───────────────────────────────────────────────────────────────────

fn parse_uuid(s: &str) -> Result<Uuid, Error> {
    Uuid::parse_str(s)
        .map_err(|_| Error::Database(format!("Invalid session ID (expected UUID): '{s}'")))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use sigint_core::types::Session;
    use sigint_store::Database;
    use uuid::Uuid;

    fn db() -> Database {
        Database::open_in_memory().unwrap()
    }

    // ── list_sessions ─────────────────────────────────────────────────────────

    #[test]
    fn list_sessions_empty_db_returns_ok() {
        let db = db();
        assert!(list_sessions(&db).is_ok());
    }

    #[test]
    fn list_sessions_with_entries_returns_ok() {
        let db = db();
        let s1 = Session::new("alpha").with_target("example.com");
        let s2 = Session::new("beta").with_target("other.com");
        db.create_session(&s1).unwrap();
        db.create_session(&s2).unwrap();
        assert!(list_sessions(&db).is_ok());
    }

    // ── export_session ────────────────────────────────────────────────────────

    #[test]
    fn export_session_missing_id_returns_err() {
        let db = db();
        let result = export_session(&db, &Uuid::new_v4().to_string());
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("not found"), "expected 'not found' in: {msg}");
    }

    #[test]
    fn export_session_invalid_uuid_returns_err() {
        let db = db();
        let result = export_session(&db, "not-a-uuid");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("Invalid session ID"), "expected parse error in: {msg}");
    }

    #[test]
    fn export_session_round_trip() {
        use sigint_core::types::Message;
        use sigint_store::ScanRecord;

        let db = db();
        let session = Session::new("export-test").with_target("scan.local");
        db.create_session(&session).unwrap();

        let msg = Message::user(session.id, "test message");
        db.create_message(&msg).unwrap();

        let mut rec = ScanRecord::new(session.id, "nmap_scan", r#"{"target":"scan.local"}"#);
        rec.output = Some("Nmap 7.94".into());
        rec.exit_code = Some(0);
        db.create_scan_record(&rec).unwrap();

        assert!(export_session(&db, &session.id.to_string()).is_ok());
    }

    // ── delete_session ────────────────────────────────────────────────────────

    #[test]
    fn delete_session_missing_id_returns_err() {
        let db = db();
        let result = delete_session(&db, &Uuid::new_v4().to_string(), true);
        assert!(result.is_err());
    }

    #[test]
    fn delete_session_with_confirm_succeeds() {
        let db = db();
        let session = Session::new("to-delete");
        db.create_session(&session).unwrap();

        let result = delete_session(&db, &session.id.to_string(), true);
        assert!(result.is_ok());

        assert!(db.get_session(session.id).unwrap().is_none());
    }

    #[test]
    fn delete_session_invalid_uuid_returns_err() {
        let db = db();
        let result = delete_session(&db, "bad-uuid", true);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("Invalid session ID"), "expected parse error in: {msg}");
    }

    // ── parse_uuid ────────────────────────────────────────────────────────────

    #[test]
    fn parse_uuid_valid() {
        let id = Uuid::new_v4();
        assert_eq!(parse_uuid(&id.to_string()).unwrap(), id);
    }

    #[test]
    fn parse_uuid_invalid_returns_err() {
        assert!(parse_uuid("not-a-uuid").is_err());
        assert!(parse_uuid("").is_err());
        assert!(parse_uuid("12345").is_err());
    }
}
