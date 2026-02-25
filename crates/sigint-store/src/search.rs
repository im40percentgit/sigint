//! FTS5 full-text search API for sigint-store.
//!
//! @decision DEC-STORE-FTS
//! @title Standalone FTS5 with UUID source_id — not external-content tables
//! @status accepted
//! @rationale The plan called for FTS5 external-content tables with
//! `content_rowid=id`, but `id` is a UUID TEXT column, not an INTEGER rowid.
//! SQLite FTS5 `content_rowid` requires an integer. Using standalone FTS5
//! virtual tables (no `content=` or `content_rowid=`) avoids this mismatch.
//! Each FTS5 table stores an UNINDEXED `source_id` column (UUID text) so
//! callers can join back to the source row. `SearchResult.source_id` is
//! therefore `String` rather than the plan's `i64`.

use sigint_core::Error;

use crate::db::Database;

/// Wrap a raw user query in FTS5 phrase quotes so hyphens, colons, and other
/// special characters are treated as literals rather than FTS5 operators.
///
/// FTS5 phrase syntax: `"cross-site scripting"` matches the exact sequence of
/// tokens after tokenization. This prevents parse errors from inputs like
/// "cross-site scripting" where `-` would otherwise be tokenized as a separator
/// that could confuse the FTS5 query parser.
fn sanitize_query(query: &str) -> String {
    // Escape any embedded double-quotes by doubling them (FTS5 phrase escaping).
    let escaped = query.replace('"', "\"\"");
    format!("\"{}\"", escaped)
}

/// A single full-text search hit from any FTS5-indexed table.
#[derive(Debug, Clone)]
pub struct SearchResult {
    /// Which table produced this result: "message", "finding", or "scan".
    pub source_type: String,
    /// UUID of the originating row in the source table.
    pub source_id: String,
    /// Highlighted snippet from the matched content.
    pub snippet: String,
    /// BM25 rank score (more negative = better match in SQLite FTS5).
    pub rank: f64,
}

impl Database {
    /// Search all FTS5 indexes and return combined results, best-ranked first.
    pub fn search(&self, query: &str) -> Result<Vec<SearchResult>, Error> {
        let mut results = Vec::new();
        results.extend(self.search_messages(query)?);
        results.extend(self.search_findings(query)?);
        results.extend(self.search_scans(query)?);
        // FTS5 rank is negative BM25 — smaller (more negative) = better match.
        // Sort ascending so best matches come first.
        results.sort_by(|a, b| {
            a.rank
                .partial_cmp(&b.rank)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        Ok(results)
    }

    /// Search the messages FTS5 index.
    pub fn search_messages(&self, query: &str) -> Result<Vec<SearchResult>, Error> {
        let q = sanitize_query(query);
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT source_id,
                            snippet(messages_fts, 1, '<b>', '</b>', '...', 32),
                            rank
                     FROM messages_fts
                     WHERE messages_fts MATCH ?1
                     ORDER BY rank
                     LIMIT 50",
                )
                .map_err(|e| Error::Database(e.to_string()))?;

            let rows = stmt
                .query_map([&q], |row| {
                    Ok(SearchResult {
                        source_type: "message".to_string(),
                        source_id: row.get(0)?,
                        snippet: row.get(1)?,
                        rank: row.get(2)?,
                    })
                })
                .map_err(|e| Error::Database(e.to_string()))?;

            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| Error::Database(e.to_string()))
        })
    }

    /// Search the findings FTS5 index (title + description).
    pub fn search_findings(&self, query: &str) -> Result<Vec<SearchResult>, Error> {
        let q = sanitize_query(query);
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT source_id,
                            snippet(findings_fts, 1, '<b>', '</b>', '...', 32),
                            rank
                     FROM findings_fts
                     WHERE findings_fts MATCH ?1
                     ORDER BY rank
                     LIMIT 50",
                )
                .map_err(|e| Error::Database(e.to_string()))?;

            let rows = stmt
                .query_map([&q], |row| {
                    Ok(SearchResult {
                        source_type: "finding".to_string(),
                        source_id: row.get(0)?,
                        snippet: row.get(1)?,
                        rank: row.get(2)?,
                    })
                })
                .map_err(|e| Error::Database(e.to_string()))?;

            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| Error::Database(e.to_string()))
        })
    }

    /// Search the scan_history FTS5 index (output text).
    pub fn search_scans(&self, query: &str) -> Result<Vec<SearchResult>, Error> {
        let q = sanitize_query(query);
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT source_id,
                            snippet(scan_history_fts, 1, '<b>', '</b>', '...', 32),
                            rank
                     FROM scan_history_fts
                     WHERE scan_history_fts MATCH ?1
                     ORDER BY rank
                     LIMIT 50",
                )
                .map_err(|e| Error::Database(e.to_string()))?;

            let rows = stmt
                .query_map([&q], |row| {
                    Ok(SearchResult {
                        source_type: "scan".to_string(),
                        source_id: row.get(0)?,
                        snippet: row.get(1)?,
                        rank: row.get(2)?,
                    })
                })
                .map_err(|e| Error::Database(e.to_string()))?;

            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| Error::Database(e.to_string()))
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::db::Database;
    use sigint_core::types::{Finding, Message, Session, Severity};

    #[test]
    fn search_messages_by_content() {
        let db = Database::open_in_memory().unwrap();
        let session = Session::new("test");
        db.create_session(&session).unwrap();
        db.create_message(&Message::user(session.id, "Found SQL injection in login"))
            .unwrap();
        db.create_message(&Message::user(session.id, "Port 80 is open"))
            .unwrap();

        let results = db.search_messages("SQL injection").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].source_type, "message");
    }

    #[test]
    fn search_findings_by_title_and_description() {
        let db = Database::open_in_memory().unwrap();
        let session = Session::new("test");
        db.create_session(&session).unwrap();
        let f = Finding::new(
            session.id,
            "XSS in search",
            "Cross-site scripting via query param",
            Severity::High,
        );
        db.create_finding(&f).unwrap();

        let results = db.search_findings("cross-site scripting").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].source_type, "finding");
    }

    #[test]
    fn search_all_returns_mixed_results() {
        let db = Database::open_in_memory().unwrap();
        let session = Session::new("test");
        db.create_session(&session).unwrap();
        db.create_message(&Message::user(session.id, "Discovered open Redis port"))
            .unwrap();
        let f = Finding::new(
            session.id,
            "Redis exposed",
            "Port 6379 open without auth",
            Severity::Critical,
        );
        db.create_finding(&f).unwrap();

        let results = db.search("Redis").unwrap();
        assert_eq!(results.len(), 2); // message + finding
    }

    #[test]
    fn search_returns_empty_for_no_match() {
        let db = Database::open_in_memory().unwrap();
        let results = db.search("nonexistent_xyz_abc").unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn search_result_source_id_matches_original() {
        let db = Database::open_in_memory().unwrap();
        let session = Session::new("test");
        db.create_session(&session).unwrap();
        let msg = Message::user(session.id, "buffer overflow in auth module");
        db.create_message(&msg).unwrap();

        let results = db.search_messages("buffer overflow").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].source_id, msg.id.to_string());
    }

    #[test]
    fn search_snippet_contains_matched_term() {
        let db = Database::open_in_memory().unwrap();
        let session = Session::new("test");
        db.create_session(&session).unwrap();
        db.create_message(&Message::user(session.id, "SSRF vulnerability in webhook handler"))
            .unwrap();

        let results = db.search_messages("SSRF").unwrap();
        assert_eq!(results.len(), 1);
        // Snippet should contain the matched term (possibly highlighted)
        assert!(
            results[0].snippet.to_uppercase().contains("SSRF"),
            "Snippet '{}' should contain 'SSRF'",
            results[0].snippet
        );
    }
}
