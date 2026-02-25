# Phase 3 Implementation Plan: TUI + Memory + Embeddings

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Transform SIGINT from a stdout-only CLI into a real-time TUI with persistent memory and semantic search across scan sessions.

**Architecture:** Fork-join across 5 sub-phases. 3A (Store DAL) is the foundation. 3B (Embeddings) and 3D (TUI) run in parallel worktrees — they touch different crates. 3C (Memory) joins both. 3E (Integration) wires everything together. New crate: `sigint-memory`.

**Tech Stack:** r2d2 (connection pool), fastembed + ort (embeddings), bytemuck (vector serialization), ratatui + crossterm (TUI)

**Design Doc:** `docs/plans/2026-02-25-phase-3-tui-memory-embeddings-design.md`

**Decisions:** DEC-P3-001 (sigint-memory crate), DEC-P3-002 (fastembed always-on), DEC-P3-003 (isatty auto-detect), DEC-P3-004 (Reporter as episodic source), DEC-P3-005 (fork-join execution)

---

## Sub-Phase 3A: Store DAL + Connection Pool

**Worktree:** `git worktree add -b feature/phase-3a-store-dal .worktrees/phase-3a-store-dal main`
**Crate:** `sigint-store`
**Merge to main before starting 3B or 3D.**

---

### Task 3A-1: Add r2d2 Dependency and Swap Connection Pool

**Files:**
- Modify: `Cargo.toml` (workspace root, add r2d2 + r2d2_sqlite)
- Modify: `crates/sigint-store/Cargo.toml` (add r2d2, r2d2_sqlite deps)
- Modify: `crates/sigint-store/src/db.rs` (replace Mutex<Connection> with Pool)

**Step 1: Add workspace dependencies**

In workspace root `Cargo.toml`, add to `[workspace.dependencies]`:
```toml
r2d2 = "0.8"
r2d2_sqlite = "0.25"
```

In `crates/sigint-store/Cargo.toml`, add to `[dependencies]`:
```toml
r2d2.workspace = true
r2d2_sqlite.workspace = true
```

**Step 2: Write failing test for concurrent pool access**

Create: `crates/sigint-store/src/pool_tests.rs`

```rust
#[cfg(test)]
mod tests {
    use crate::db::Database;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn concurrent_reads_do_not_deadlock() {
        let db = Database::open_in_memory().unwrap();
        let db = Arc::new(db);

        let handles: Vec<_> = (0..4)
            .map(|_| {
                let db = Arc::clone(&db);
                thread::spawn(move || {
                    db.with_conn(|conn| {
                        conn.query_row("SELECT 1", [], |row| row.get::<_, i64>(0))
                            .map_err(|e| sigint_core::Error::Database(e.to_string()))
                    })
                    .unwrap()
                })
            })
            .collect();

        for h in handles {
            assert_eq!(h.join().unwrap(), 1);
        }
    }

    #[test]
    fn pool_size_is_configurable() {
        let db = Database::open_in_memory().unwrap();
        // Default pool size is 4; verify we can get at least 4 connections
        let db = Arc::new(db);
        let handles: Vec<_> = (0..4)
            .map(|_| {
                let db = Arc::clone(&db);
                thread::spawn(move || {
                    db.with_conn(|conn| {
                        conn.query_row("SELECT 42", [], |row| row.get::<_, i64>(0))
                            .map_err(|e| sigint_core::Error::Database(e.to_string()))
                    })
                    .unwrap()
                })
            })
            .collect();

        for h in handles {
            assert_eq!(h.join().unwrap(), 42);
        }
    }
}
```

**Step 3: Run test to verify it fails**

Run: `cd .worktrees/phase-3a-store-dal && cargo test -p sigint-store pool_tests -- --nocapture`
Expected: Compilation error (pool_tests module not included yet, or Database doesn't support concurrent access)

**Step 4: Rewrite `db.rs` to use r2d2 pool**

Replace `crates/sigint-store/src/db.rs` contents. Key changes:
- `Mutex<Connection>` → `r2d2::Pool<SqliteConnectionManager>`
- `with_conn` gets a pooled connection via `self.pool.get()`
- `configure()` runs on each new connection via `CustomizeConnection`
- `open()` creates pool with 4 connections
- `open_in_memory()` creates pool with shared in-memory DB

```rust
use std::path::Path;

use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;
use tracing::info;

use sigint_core::Error;

use crate::migrations::run_migrations;

const DEFAULT_POOL_SIZE: u32 = 4;

/// @decision DEC-P3-POOL: r2d2 connection pool replaces Mutex<Connection> (accepted)
/// WAL mode + pool enables concurrent reads from TUI + agents without mutex contention.
pub struct Database {
    pool: Pool<SqliteConnectionManager>,
}

struct ConnectionInit;

impl r2d2::CustomizeConnection<Connection, r2d2_sqlite::Error> for ConnectionInit {
    fn on_acquire(&self, conn: &mut Connection) -> Result<(), r2d2_sqlite::Error> {
        configure(conn).map_err(|e| r2d2_sqlite::Error::Other(Box::new(e)))
    }
}

fn configure(conn: &Connection) -> Result<(), Error> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = ON;
         PRAGMA busy_timeout = 5000;"
    )
    .map_err(|e| Error::Database(e.to_string()))?;
    Ok(())
}

impl Database {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Database(format!("Failed to create DB directory: {e}")))?;
        }
        info!("Opening database at {}", path.display());
        let manager = SqliteConnectionManager::file(path);
        let pool = Pool::builder()
            .max_size(DEFAULT_POOL_SIZE)
            .connection_customizer(Box::new(ConnectionInit))
            .build(manager)
            .map_err(|e| Error::Database(e.to_string()))?;

        // Run migrations on a dedicated connection
        let conn = pool.get().map_err(|e| Error::Database(e.to_string()))?;
        run_migrations(&conn)?;

        Ok(Self { pool })
    }

    pub fn open_in_memory() -> Result<Self, Error> {
        let manager = SqliteConnectionManager::memory();
        let pool = Pool::builder()
            .max_size(DEFAULT_POOL_SIZE)
            .connection_customizer(Box::new(ConnectionInit))
            .build(manager)
            .map_err(|e| Error::Database(e.to_string()))?;

        let conn = pool.get().map_err(|e| Error::Database(e.to_string()))?;
        run_migrations(&conn)?;

        Ok(Self { pool })
    }

    pub fn with_conn<F, T>(&self, f: F) -> Result<T, Error>
    where
        F: FnOnce(&Connection) -> Result<T, Error>,
    {
        let conn = self.pool.get().map_err(|e| Error::Database(e.to_string()))?;
        f(&conn)
    }
}
```

**Step 5: Include pool_tests module in lib.rs**

Add to `crates/sigint-store/src/lib.rs`:
```rust
#[cfg(test)]
mod pool_tests;
```

**Step 6: Run all store tests to verify backward compatibility**

Run: `cargo test -p sigint-store -- --nocapture`
Expected: ALL existing tests pass (sessions, messages, scans) + new pool tests pass

**Step 7: Commit**

```bash
git add -A
git commit -m "feat(store): replace Mutex<Connection> with r2d2 connection pool

Concurrent readers no longer block each other. WAL mode + r2d2 pool
with configurable size (default 4). PRAGMAs applied via CustomizeConnection.
All existing CRUD tests pass unchanged.

@decision DEC-P3-POOL: r2d2 pool replaces Mutex<Connection> (accepted)"
```

---

### Task 3A-2: Typed Query Builder — SessionQuery

**Files:**
- Create: `crates/sigint-store/src/query/mod.rs`
- Create: `crates/sigint-store/src/query/sessions.rs`
- Modify: `crates/sigint-store/src/lib.rs` (add query module)
- Modify: `crates/sigint-store/src/db.rs` (add `sessions()` method)

**Step 1: Write failing test**

In `crates/sigint-store/src/query/sessions.rs`:

```rust
#[cfg(test)]
mod tests {
    use crate::db::Database;
    use sigint_core::types::Session;

    #[test]
    fn query_sessions_by_target() {
        let db = Database::open_in_memory().unwrap();
        let s1 = Session::new("scan1").with_target("example.com");
        let s2 = Session::new("scan2").with_target("other.com");
        let s3 = Session::new("scan3").with_target("example.com");
        db.create_session(&s1).unwrap();
        db.create_session(&s2).unwrap();
        db.create_session(&s3).unwrap();

        let results = db.sessions().by_target("example.com").list().unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(|s| s.target.as_deref() == Some("example.com")));
    }

    #[test]
    fn query_sessions_with_pagination() {
        let db = Database::open_in_memory().unwrap();
        for i in 0..10 {
            let s = Session::new(format!("scan{i}"));
            db.create_session(&s).unwrap();
        }

        let page = db.sessions().limit(3).offset(2).list().unwrap();
        assert_eq!(page.len(), 3);
    }

    #[test]
    fn query_sessions_count() {
        let db = Database::open_in_memory().unwrap();
        for i in 0..5 {
            db.create_session(&Session::new(format!("s{i}"))).unwrap();
        }
        assert_eq!(db.sessions().count().unwrap(), 5);
    }

    #[test]
    fn query_sessions_order_by_date_desc() {
        let db = Database::open_in_memory().unwrap();
        let s1 = Session::new("first");
        let s2 = Session::new("second");
        db.create_session(&s1).unwrap();
        db.create_session(&s2).unwrap();

        let results = db.sessions().order_by_date_desc().list().unwrap();
        assert_eq!(results.len(), 2);
        assert!(results[0].created_at >= results[1].created_at);
    }
}
```

**Step 2: Run test to verify it fails**

Run: `cargo test -p sigint-store query::sessions -- --nocapture`
Expected: Compilation error — `sessions()` method and query module don't exist

**Step 3: Implement SessionQuery builder**

Create `crates/sigint-store/src/query/mod.rs`:
```rust
pub mod sessions;
```

Create `crates/sigint-store/src/query/sessions.rs`:
```rust
use rusqlite::params_from_iter;
use sigint_core::types::Session;
use sigint_core::Error;

use crate::db::Database;
use crate::sessions::row_to_session;

pub struct SessionQuery<'a> {
    db: &'a Database,
    target: Option<String>,
    limit: Option<usize>,
    offset: Option<usize>,
    order_desc: bool,
}

impl<'a> SessionQuery<'a> {
    pub(crate) fn new(db: &'a Database) -> Self {
        Self {
            db,
            target: None,
            limit: None,
            offset: None,
            order_desc: false,
        }
    }

    pub fn by_target(mut self, target: &str) -> Self {
        self.target = Some(target.to_string());
        self
    }

    pub fn limit(mut self, n: usize) -> Self {
        self.limit = Some(n);
        self
    }

    pub fn offset(mut self, n: usize) -> Self {
        self.offset = Some(n);
        self
    }

    pub fn order_by_date_desc(mut self) -> Self {
        self.order_desc = true;
        self
    }

    pub fn list(self) -> Result<Vec<Session>, Error> {
        self.db.with_conn(|conn| {
            let mut sql = String::from("SELECT id, name, target, created_at, updated_at FROM sessions");
            let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
            let mut conditions = Vec::new();

            if let Some(ref target) = self.target {
                conditions.push(format!("target = ?{}", params.len() + 1));
                params.push(Box::new(target.clone()));
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

            let mut stmt = conn.prepare(&sql)
                .map_err(|e| Error::Database(e.to_string()))?;
            let rows = stmt
                .query_map(params_from_iter(params.iter().map(|p| p.as_ref())), |row| {
                    row_to_session(row).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))
                })
                .map_err(|e| Error::Database(e.to_string()))?;

            let mut results = Vec::new();
            for row in rows {
                results.push(row.map_err(|e| Error::Database(e.to_string()))?);
            }
            Ok(results)
        })
    }

    pub fn count(self) -> Result<usize, Error> {
        self.db.with_conn(|conn| {
            let mut sql = String::from("SELECT COUNT(*) FROM sessions");
            let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
            let mut conditions = Vec::new();

            if let Some(ref target) = self.target {
                conditions.push(format!("target = ?{}", params.len() + 1));
                params.push(Box::new(target.clone()));
            }

            if !conditions.is_empty() {
                sql.push_str(" WHERE ");
                sql.push_str(&conditions.join(" AND "));
            }

            conn.query_row(&sql, params_from_iter(params.iter().map(|p| p.as_ref())), |row| {
                row.get(0)
            })
            .map_err(|e| Error::Database(e.to_string()))
        })
    }
}
```

Note: `row_to_session` in `sessions.rs` needs to be made `pub(crate)` if it isn't already.

Add to `crates/sigint-store/src/db.rs`:
```rust
use crate::query::sessions::SessionQuery;

impl Database {
    pub fn sessions(&self) -> SessionQuery<'_> {
        SessionQuery::new(self)
    }
}
```

Add to `crates/sigint-store/src/lib.rs`:
```rust
pub mod query;
```

**Step 4: Run tests**

Run: `cargo test -p sigint-store -- --nocapture`
Expected: All tests pass including new query builder tests

**Step 5: Commit**

```bash
git add -A
git commit -m "feat(store): add SessionQuery typed builder with filter/paginate/count"
```

---

### Task 3A-3: Typed Query Builders — FindingQuery, MessageQuery, ScanQuery

**Files:**
- Create: `crates/sigint-store/src/query/findings.rs`
- Create: `crates/sigint-store/src/query/messages.rs`
- Create: `crates/sigint-store/src/query/scans.rs`
- Modify: `crates/sigint-store/src/query/mod.rs`
- Modify: `crates/sigint-store/src/db.rs`

Follow the same pattern as Task 3A-2. Each builder supports:
- `by_session(session_id: Uuid)` — filter by session
- `limit(n)` / `offset(n)` — pagination
- `list()` / `count()` — terminal operations

Additional filters:
- `FindingQuery`: `.severity(Severity)`, `.by_asset(asset: &str)`
- `MessageQuery`: `.by_role(Role)`, `.order_by_date_desc()`
- `ScanQuery`: `.by_tool(tool: &str)`

**Step 1: Write failing tests** (one per builder, similar pattern to Task 3A-2)

**Step 2: Implement each builder following the SessionQuery pattern**

**Step 3: Add `.findings()`, `.messages_query()`, `.scans()` methods to `Database`**

Note: Use `.messages_query()` to avoid naming conflict with existing `get_messages()`.

**Step 4: Run all tests**

Run: `cargo test -p sigint-store -- --nocapture`
Expected: All pass

**Step 5: Commit**

```bash
git add -A
git commit -m "feat(store): add FindingQuery, MessageQuery, ScanQuery typed builders"
```

---

### Task 3A-4: Migration 2 — FTS5 Virtual Tables + Sync Triggers

**Files:**
- Modify: `crates/sigint-store/src/migrations.rs` (add migration 2)

**Step 1: Write failing test**

```rust
#[test]
fn fts5_indexes_existing_messages() {
    let db = Database::open_in_memory().unwrap();
    let session = Session::new("test");
    db.create_session(&session).unwrap();
    let msg = Message::user(session.id, "SQL injection in login form");
    db.create_message(&msg).unwrap();

    // FTS5 search should find it
    let results = db.search_messages("SQL injection").unwrap();
    assert_eq!(results.len(), 1);
    assert!(results[0].snippet.contains("SQL"));
}
```

**Step 2: Run test to verify it fails**

Expected: `search_messages` method doesn't exist

**Step 3: Add migration 2 to MIGRATIONS array**

In `crates/sigint-store/src/migrations.rs`, extend the `MIGRATIONS` array:

```rust
(2, "fts5 full-text search", "
    -- FTS5 for messages
    CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
        content,
        content=messages,
        content_rowid=id
    );
    CREATE TRIGGER IF NOT EXISTS messages_fts_ai AFTER INSERT ON messages BEGIN
        INSERT INTO messages_fts(rowid, content) VALUES (new.id, new.content);
    END;
    CREATE TRIGGER IF NOT EXISTS messages_fts_ad AFTER DELETE ON messages BEGIN
        INSERT INTO messages_fts(messages_fts, rowid, content) VALUES('delete', old.id, old.content);
    END;
    CREATE TRIGGER IF NOT EXISTS messages_fts_au AFTER UPDATE ON messages BEGIN
        INSERT INTO messages_fts(messages_fts, rowid, content) VALUES('delete', old.id, old.content);
        INSERT INTO messages_fts(rowid, content) VALUES (new.id, new.content);
    END;

    -- FTS5 for findings
    CREATE VIRTUAL TABLE IF NOT EXISTS findings_fts USING fts5(
        title,
        description,
        content=findings,
        content_rowid=id
    );
    CREATE TRIGGER IF NOT EXISTS findings_fts_ai AFTER INSERT ON findings BEGIN
        INSERT INTO findings_fts(rowid, title, description) VALUES (new.id, new.title, new.description);
    END;
    CREATE TRIGGER IF NOT EXISTS findings_fts_ad AFTER DELETE ON findings BEGIN
        INSERT INTO findings_fts(findings_fts, rowid, title, description) VALUES('delete', old.id, old.title, old.description);
    END;
    CREATE TRIGGER IF NOT EXISTS findings_fts_au AFTER UPDATE ON findings BEGIN
        INSERT INTO findings_fts(findings_fts, rowid, title, description) VALUES('delete', old.id, old.title, old.description);
        INSERT INTO findings_fts(rowid, title, description) VALUES (new.id, new.title, new.description);
    END;

    -- FTS5 for scan_history
    CREATE VIRTUAL TABLE IF NOT EXISTS scan_history_fts USING fts5(
        output,
        content=scan_history,
        content_rowid=id
    );
    CREATE TRIGGER IF NOT EXISTS scan_history_fts_ai AFTER INSERT ON scan_history BEGIN
        INSERT INTO scan_history_fts(rowid, output) VALUES (new.id, COALESCE(new.output, ''));
    END;
    CREATE TRIGGER IF NOT EXISTS scan_history_fts_ad AFTER DELETE ON scan_history BEGIN
        INSERT INTO scan_history_fts(scan_history_fts, rowid, output) VALUES('delete', old.id, COALESCE(old.output, ''));
    END;
    CREATE TRIGGER IF NOT EXISTS scan_history_fts_au AFTER UPDATE ON scan_history BEGIN
        INSERT INTO scan_history_fts(scan_history_fts, rowid, output) VALUES('delete', old.id, COALESCE(old.output, ''));
        INSERT INTO scan_history_fts(rowid, output) VALUES (new.id, COALESCE(new.output, ''));
    END;
"),
```

**Step 4: Run migration test**

Run: `cargo test -p sigint-store migrations -- --nocapture`
Expected: Migration applies cleanly

**Step 5: Commit**

```bash
git add -A
git commit -m "feat(store): add FTS5 migration with external-content tables and sync triggers"
```

---

### Task 3A-5: FTS5 Search API

**Files:**
- Create: `crates/sigint-store/src/search.rs`
- Modify: `crates/sigint-store/src/lib.rs`
- Modify: `crates/sigint-store/src/db.rs`

**Step 1: Write failing tests**

In `crates/sigint-store/src/search.rs`:

```rust
#[cfg(test)]
mod tests {
    use crate::db::Database;
    use sigint_core::types::{Finding, Message, Session, Severity};

    #[test]
    fn search_messages_by_content() {
        let db = Database::open_in_memory().unwrap();
        let session = Session::new("test");
        db.create_session(&session).unwrap();
        db.create_message(&Message::user(session.id, "Found SQL injection in login")).unwrap();
        db.create_message(&Message::user(session.id, "Port 80 is open")).unwrap();

        let results = db.search_messages("SQL injection").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].source_type, "message");
    }

    #[test]
    fn search_findings_by_title_and_description() {
        let db = Database::open_in_memory().unwrap();
        let session = Session::new("test");
        db.create_session(&session).unwrap();
        // Note: Need create_finding method — add if missing
        let f = Finding::new(session.id, "XSS in search", "Cross-site scripting via query param", Severity::High);
        db.create_finding(&f).unwrap();

        let results = db.search_findings("cross-site scripting").unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn search_all_returns_mixed_results() {
        let db = Database::open_in_memory().unwrap();
        let session = Session::new("test");
        db.create_session(&session).unwrap();
        db.create_message(&Message::user(session.id, "Discovered open Redis port")).unwrap();
        let f = Finding::new(session.id, "Redis exposed", "Port 6379 open without auth", Severity::Critical);
        db.create_finding(&f).unwrap();

        let results = db.search("Redis").unwrap();
        assert_eq!(results.len(), 2); // message + finding
    }

    #[test]
    fn search_returns_empty_for_no_match() {
        let db = Database::open_in_memory().unwrap();
        let results = db.search("nonexistent").unwrap();
        assert!(results.is_empty());
    }
}
```

**Step 2: Implement search API**

```rust
use sigint_core::Error;
use crate::db::Database;

#[derive(Debug, Clone)]
pub struct SearchResult {
    pub source_type: String,
    pub source_id: i64,
    pub snippet: String,
    pub rank: f64,
}

impl Database {
    pub fn search(&self, query: &str) -> Result<Vec<SearchResult>, Error> {
        let mut results = Vec::new();
        results.extend(self.search_messages(query)?);
        results.extend(self.search_findings(query)?);
        results.extend(self.search_scans(query)?);
        results.sort_by(|a, b| a.rank.partial_cmp(&b.rank).unwrap_or(std::cmp::Ordering::Equal));
        Ok(results)
    }

    pub fn search_messages(&self, query: &str) -> Result<Vec<SearchResult>, Error> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT rowid, snippet(messages_fts, 0, '<b>', '</b>', '...', 32), rank
                 FROM messages_fts WHERE messages_fts MATCH ?1
                 ORDER BY rank LIMIT 50"
            ).map_err(|e| Error::Database(e.to_string()))?;

            let rows = stmt.query_map([query], |row| {
                Ok(SearchResult {
                    source_type: "message".to_string(),
                    source_id: row.get(0)?,
                    snippet: row.get(1)?,
                    rank: row.get(2)?,
                })
            }).map_err(|e| Error::Database(e.to_string()))?;

            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| Error::Database(e.to_string()))
        })
    }

    pub fn search_findings(&self, query: &str) -> Result<Vec<SearchResult>, Error> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT rowid, snippet(findings_fts, 0, '<b>', '</b>', '...', 32), rank
                 FROM findings_fts WHERE findings_fts MATCH ?1
                 ORDER BY rank LIMIT 50"
            ).map_err(|e| Error::Database(e.to_string()))?;

            let rows = stmt.query_map([query], |row| {
                Ok(SearchResult {
                    source_type: "finding".to_string(),
                    source_id: row.get(0)?,
                    snippet: row.get(1)?,
                    rank: row.get(2)?,
                })
            }).map_err(|e| Error::Database(e.to_string()))?;

            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| Error::Database(e.to_string()))
        })
    }

    pub fn search_scans(&self, query: &str) -> Result<Vec<SearchResult>, Error> {
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT rowid, snippet(scan_history_fts, 0, '<b>', '</b>', '...', 32), rank
                 FROM scan_history_fts WHERE scan_history_fts MATCH ?1
                 ORDER BY rank LIMIT 50"
            ).map_err(|e| Error::Database(e.to_string()))?;

            let rows = stmt.query_map([query], |row| {
                Ok(SearchResult {
                    source_type: "scan".to_string(),
                    source_id: row.get(0)?,
                    snippet: row.get(1)?,
                    rank: row.get(2)?,
                })
            }).map_err(|e| Error::Database(e.to_string()))?;

            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| Error::Database(e.to_string()))
        })
    }
}
```

**Step 3: Add `create_finding` to Database if missing**

Check `crates/sigint-store/src/` for an existing findings CRUD file. If missing, create `crates/sigint-store/src/findings.rs` with `create_finding` following the sessions.rs pattern.

**Step 4: Run tests**

Run: `cargo test -p sigint-store search -- --nocapture`
Expected: All search tests pass

**Step 5: Commit**

```bash
git add -A
git commit -m "feat(store): add FTS5 search API for messages, findings, and scan history"
```

---

### Task 3A-6: Final Validation + Merge Readiness

**Step 1: Run full test suite**

Run: `cargo test --workspace -- --nocapture`
Expected: All tests pass across all crates

**Step 2: Run clippy**

Run: `cargo clippy --workspace -- -D warnings`
Expected: No warnings

**Step 3: Commit any cleanup**

**Step 4: Merge to main**

```bash
cd /home/j/sigint
git merge feature/phase-3a-store-dal
git worktree remove .worktrees/phase-3a-store-dal
git branch -d feature/phase-3a-store-dal
```

---

## Sub-Phase 3B: Embeddings + Semantic Search

**Worktree:** `git worktree add -b feature/phase-3b-embeddings .worktrees/phase-3b-embeddings main`
**Crate:** `sigint-store`
**Can start in parallel with 3D after 3A merges.**

---

### Task 3B-1: Add fastembed + bytemuck Dependencies

**Files:**
- Modify: `Cargo.toml` (workspace root)
- Modify: `crates/sigint-store/Cargo.toml`

**Step 1: Add workspace dependencies**

In workspace root `Cargo.toml` `[workspace.dependencies]`:
```toml
fastembed = "4"
bytemuck = { version = "1", features = ["derive"] }
```

In `crates/sigint-store/Cargo.toml` `[dependencies]`:
```toml
fastembed.workspace = true
bytemuck.workspace = true
```

**Step 2: Verify it compiles**

Run: `cargo check -p sigint-store`
Expected: Compiles (fastembed downloads may take a moment first time)

**Step 3: Commit**

```bash
git add -A
git commit -m "deps: add fastembed and bytemuck to sigint-store"
```

---

### Task 3B-2: EmbeddingService — Model Loading + Single/Batch Embed

**Files:**
- Create: `crates/sigint-store/src/embeddings.rs`
- Modify: `crates/sigint-store/src/lib.rs`

**Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embed_single_returns_384_dims() {
        let service = EmbeddingService::new().unwrap();
        let vec = service.embed("test sentence").unwrap();
        assert_eq!(vec.len(), 384);
    }

    #[test]
    fn embed_batch_returns_correct_count() {
        let service = EmbeddingService::new().unwrap();
        let texts = vec!["hello world", "foo bar", "test"];
        let vecs = service.embed_batch(&texts).unwrap();
        assert_eq!(vecs.len(), 3);
        assert!(vecs.iter().all(|v| v.len() == 384));
    }

    #[test]
    fn similar_texts_have_high_cosine_similarity() {
        let service = EmbeddingService::new().unwrap();
        let v1 = service.embed("open SSH port 22").unwrap();
        let v2 = service.embed("SSH service on port 22").unwrap();
        let v3 = service.embed("chocolate cake recipe").unwrap();

        let sim_related = cosine_similarity(&v1, &v2);
        let sim_unrelated = cosine_similarity(&v1, &v3);
        assert!(sim_related > sim_unrelated, "Related texts should be more similar");
        assert!(sim_related > 0.7, "Related texts should have high similarity");
    }
}
```

**Step 2: Implement EmbeddingService**

```rust
use fastembed::{EmbeddingModel, InitOptions, TextEmbedding};
use sigint_core::Error;

pub struct EmbeddingService {
    model: TextEmbedding,
}

impl EmbeddingService {
    pub fn new() -> Result<Self, Error> {
        let model = TextEmbedding::try_new(
            InitOptions::new(EmbeddingModel::AllMiniLML6V2).with_show_download_progress(true),
        )
        .map_err(|e| Error::Other(format!("Failed to load embedding model: {e}")))?;

        Ok(Self { model })
    }

    pub fn embed(&self, text: &str) -> Result<Vec<f32>, Error> {
        let results = self
            .model
            .embed(vec![text], None)
            .map_err(|e| Error::Other(format!("Embedding failed: {e}")))?;
        results
            .into_iter()
            .next()
            .ok_or_else(|| Error::Other("No embedding returned".into()))
    }

    pub fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, Error> {
        self.model
            .embed(texts.to_vec(), None)
            .map_err(|e| Error::Other(format!("Batch embedding failed: {e}")))
    }
}

pub fn cosine_similarity(a: &[f32], b: &[f32]) -> f64 {
    assert_eq!(a.len(), b.len(), "Vectors must be same length");
    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm_a == 0.0 || norm_b == 0.0 {
        return 0.0;
    }
    (dot / (norm_a * norm_b)) as f64
}
```

**Step 3: Run tests**

Run: `cargo test -p sigint-store embeddings -- --nocapture`
Expected: All pass (first run may download model ~80MB)

**Step 4: Commit**

```bash
git add -A
git commit -m "feat(store): add EmbeddingService with fastembed all-MiniLM-L6-v2"
```

---

### Task 3B-3: Embedding CRUD + Vector Storage

**Files:**
- Modify: `crates/sigint-store/src/embeddings.rs` (add CRUD methods to Database)
- Modify: `crates/sigint-store/src/db.rs` (if needed for helper)

**Step 1: Write failing tests**

```rust
#[test]
fn store_and_retrieve_embedding() {
    let db = Database::open_in_memory().unwrap();
    let vec: Vec<f32> = (0..384).map(|i| i as f32 / 384.0).collect();

    db.store_embedding("finding", 1, "all-MiniLM-L6-v2", &vec).unwrap();
    let retrieved = db.get_embedding("finding", 1).unwrap().unwrap();

    assert_eq!(retrieved.len(), 384);
    assert!((retrieved[0] - vec[0]).abs() < f32::EPSILON);
    assert!((retrieved[383] - vec[383]).abs() < f32::EPSILON);
}

#[test]
fn has_embedding_returns_false_when_missing() {
    let db = Database::open_in_memory().unwrap();
    assert!(!db.has_embedding("finding", 999).unwrap());
}

#[test]
fn unembedded_returns_ids_without_embeddings() {
    let db = Database::open_in_memory().unwrap();
    let session = Session::new("test");
    db.create_session(&session).unwrap();
    let m1 = Message::user(session.id, "hello");
    let m2 = Message::user(session.id, "world");
    db.create_message(&m1).unwrap();
    db.create_message(&m2).unwrap();

    // Both should be unembedded
    let ids = db.unembedded_messages(2).unwrap();
    assert_eq!(ids.len(), 2);

    // Embed one
    let vec: Vec<f32> = vec![0.0; 384];
    db.store_embedding("message", ids[0], "all-MiniLM-L6-v2", &vec).unwrap();

    // Now only one unembedded
    let ids = db.unembedded_messages(10).unwrap();
    assert_eq!(ids.len(), 1);
}
```

**Step 2: Implement CRUD**

Add to `crates/sigint-store/src/embeddings.rs`:

```rust
use bytemuck;
use crate::db::Database;

impl Database {
    pub fn store_embedding(
        &self,
        source_type: &str,
        source_id: i64,
        model: &str,
        vector: &[f32],
    ) -> Result<(), Error> {
        let blob: &[u8] = bytemuck::cast_slice(vector);
        self.with_conn(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO embeddings (source_type, source_id, model, vector, created_at)
                 VALUES (?1, ?2, ?3, ?4, datetime('now'))",
                rusqlite::params![source_type, source_id, model, blob],
            )
            .map_err(|e| Error::Database(e.to_string()))?;
            Ok(())
        })
    }

    pub fn get_embedding(&self, source_type: &str, source_id: i64) -> Result<Option<Vec<f32>>, Error> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare("SELECT vector FROM embeddings WHERE source_type = ?1 AND source_id = ?2")
                .map_err(|e| Error::Database(e.to_string()))?;

            let result = stmt
                .query_row(rusqlite::params![source_type, source_id], |row| {
                    let blob: Vec<u8> = row.get(0)?;
                    Ok(blob)
                })
                .optional()
                .map_err(|e| Error::Database(e.to_string()))?;

            Ok(result.map(|blob| {
                let floats: &[f32] = bytemuck::cast_slice(&blob);
                floats.to_vec()
            }))
        })
    }

    pub fn has_embedding(&self, source_type: &str, source_id: i64) -> Result<bool, Error> {
        self.with_conn(|conn| {
            conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM embeddings WHERE source_type = ?1 AND source_id = ?2)",
                rusqlite::params![source_type, source_id],
                |row| row.get(0),
            )
            .map_err(|e| Error::Database(e.to_string()))
        })
    }

    pub fn unembedded_messages(&self, limit: usize) -> Result<Vec<i64>, Error> {
        self.unembedded("message", "messages", limit)
    }

    pub fn unembedded_findings(&self, limit: usize) -> Result<Vec<i64>, Error> {
        self.unembedded("finding", "findings", limit)
    }

    fn unembedded(&self, source_type: &str, table: &str, limit: usize) -> Result<Vec<i64>, Error> {
        self.with_conn(|conn| {
            let sql = format!(
                "SELECT t.id FROM {table} t
                 LEFT JOIN embeddings e ON e.source_type = ?1 AND e.source_id = t.id
                 WHERE e.id IS NULL
                 LIMIT ?2"
            );
            let mut stmt = conn.prepare(&sql).map_err(|e| Error::Database(e.to_string()))?;
            let rows = stmt
                .query_map(rusqlite::params![source_type, limit as i64], |row| row.get(0))
                .map_err(|e| Error::Database(e.to_string()))?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| Error::Database(e.to_string()))
        })
    }

    /// Get text content for embedding by source type and IDs.
    pub fn get_texts_for_embedding(&self, source_type: &str, ids: &[i64]) -> Result<Vec<String>, Error> {
        self.with_conn(|conn| {
            let placeholders: Vec<String> = (1..=ids.len()).map(|i| format!("?{i}")).collect();
            let (sql, col) = match source_type {
                "message" => (
                    format!("SELECT content FROM messages WHERE id IN ({}) ORDER BY id", placeholders.join(",")),
                    "content",
                ),
                "finding" => (
                    format!("SELECT title || ' ' || description FROM findings WHERE id IN ({}) ORDER BY id", placeholders.join(",")),
                    "title+desc",
                ),
                "scan" => (
                    format!("SELECT COALESCE(output, '') FROM scan_history WHERE id IN ({}) ORDER BY id", placeholders.join(",")),
                    "output",
                ),
                _ => return Err(Error::InvalidInput(format!("Unknown source type: {source_type}"))),
            };
            let _ = col;
            let params: Vec<Box<dyn rusqlite::types::ToSql>> = ids.iter().map(|id| Box::new(*id) as Box<dyn rusqlite::types::ToSql>).collect();
            let mut stmt = conn.prepare(&sql).map_err(|e| Error::Database(e.to_string()))?;
            let rows = stmt
                .query_map(rusqlite::params_from_iter(params.iter().map(|p| p.as_ref())), |row| row.get(0))
                .map_err(|e| Error::Database(e.to_string()))?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| Error::Database(e.to_string()))
        })
    }
}
```

Note: Add `use rusqlite::OptionalExtension;` for `.optional()`.

**Step 3: Run tests**

Run: `cargo test -p sigint-store embeddings -- --nocapture`
Expected: All pass

**Step 4: Commit**

```bash
git add -A
git commit -m "feat(store): add embedding CRUD — store, retrieve, unembedded queries"
```

---

### Task 3B-4: Cosine Similarity UDF + Semantic Search

**Files:**
- Modify: `crates/sigint-store/src/embeddings.rs` (add UDF registration)
- Modify: `crates/sigint-store/src/db.rs` (register UDF in ConnectionInit)

**Step 1: Write failing tests**

```rust
#[test]
fn cosine_similarity_udf_identical_vectors() {
    let db = Database::open_in_memory().unwrap();
    let vec: Vec<f32> = vec![1.0, 0.0, 0.0];
    let blob: &[u8] = bytemuck::cast_slice(&vec);

    let result: f64 = db.with_conn(|conn| {
        conn.query_row(
            "SELECT cosine_similarity(?1, ?2)",
            rusqlite::params![blob, blob],
            |row| row.get(0),
        )
        .map_err(|e| Error::Database(e.to_string()))
    }).unwrap();

    assert!((result - 1.0).abs() < 0.001);
}

#[test]
fn semantic_search_returns_ranked_results() {
    let db = Database::open_in_memory().unwrap();
    // Store two embeddings with known vectors
    let close_vec: Vec<f32> = vec![1.0, 0.0, 0.0]; // similar to query
    let far_vec: Vec<f32> = vec![0.0, 1.0, 0.0];   // dissimilar
    let query_vec: Vec<f32> = vec![0.9, 0.1, 0.0];  // close to close_vec

    db.store_embedding("finding", 1, "test", &close_vec).unwrap();
    db.store_embedding("finding", 2, "test", &far_vec).unwrap();

    let results = db.semantic_search(&query_vec, 10).unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].source_id, 1); // closer result first
    assert!(results[0].similarity > results[1].similarity);
}
```

**Step 2: Implement UDF registration and semantic search**

Add UDF registration function in `crates/sigint-store/src/embeddings.rs`:

```rust
use rusqlite::functions::FunctionFlags;

pub fn register_cosine_similarity_udf(conn: &Connection) -> Result<(), Error> {
    conn.create_scalar_function(
        "cosine_similarity",
        2,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        |ctx| {
            let a_blob = ctx.get_raw(0).as_blob().map_err(|e| rusqlite::Error::UserFunctionError(Box::new(e)))?;
            let b_blob = ctx.get_raw(1).as_blob().map_err(|e| rusqlite::Error::UserFunctionError(Box::new(e)))?;
            let a: &[f32] = bytemuck::cast_slice(a_blob);
            let b: &[f32] = bytemuck::cast_slice(b_blob);
            Ok(cosine_similarity(a, b))
        },
    )
    .map_err(|e| Error::Database(e.to_string()))
}
```

Register in `db.rs` `ConnectionInit::on_acquire`:
```rust
use crate::embeddings::register_cosine_similarity_udf;

impl r2d2::CustomizeConnection<Connection, r2d2_sqlite::Error> for ConnectionInit {
    fn on_acquire(&self, conn: &mut Connection) -> Result<(), r2d2_sqlite::Error> {
        configure(conn).map_err(|e| r2d2_sqlite::Error::Other(Box::new(e)))?;
        register_cosine_similarity_udf(conn).map_err(|e| r2d2_sqlite::Error::Other(Box::new(e)))?;
        Ok(())
    }
}
```

Add semantic search to Database:

```rust
#[derive(Debug, Clone)]
pub struct SemanticResult {
    pub source_type: String,
    pub source_id: i64,
    pub similarity: f64,
}

impl Database {
    pub fn semantic_search(&self, query_vector: &[f32], top_k: usize) -> Result<Vec<SemanticResult>, Error> {
        let query_blob: &[u8] = bytemuck::cast_slice(query_vector);
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT source_type, source_id, cosine_similarity(vector, ?1) AS sim
                 FROM embeddings
                 ORDER BY sim DESC
                 LIMIT ?2"
            ).map_err(|e| Error::Database(e.to_string()))?;

            let rows = stmt.query_map(rusqlite::params![query_blob, top_k as i64], |row| {
                Ok(SemanticResult {
                    source_type: row.get(0)?,
                    source_id: row.get(1)?,
                    similarity: row.get(2)?,
                })
            }).map_err(|e| Error::Database(e.to_string()))?;

            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| Error::Database(e.to_string()))
        })
    }

    pub fn semantic_search_typed(
        &self,
        query_vector: &[f32],
        source_type: &str,
        top_k: usize,
    ) -> Result<Vec<SemanticResult>, Error> {
        let query_blob: &[u8] = bytemuck::cast_slice(query_vector);
        self.with_conn(|conn| {
            let mut stmt = conn.prepare(
                "SELECT source_type, source_id, cosine_similarity(vector, ?1) AS sim
                 FROM embeddings
                 WHERE source_type = ?2
                 ORDER BY sim DESC
                 LIMIT ?3"
            ).map_err(|e| Error::Database(e.to_string()))?;

            let rows = stmt.query_map(
                rusqlite::params![query_blob, source_type, top_k as i64],
                |row| {
                    Ok(SemanticResult {
                        source_type: row.get(0)?,
                        source_id: row.get(1)?,
                        similarity: row.get(2)?,
                    })
                },
            ).map_err(|e| Error::Database(e.to_string()))?;

            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| Error::Database(e.to_string()))
        })
    }
}
```

**Step 3: Run tests**

Run: `cargo test -p sigint-store embeddings -- --nocapture`
Expected: All pass

**Step 4: Commit**

```bash
git add -A
git commit -m "feat(store): add cosine_similarity UDF and semantic search API"
```

---

### Task 3B-5: Background Embedding Worker

**Files:**
- Create: `crates/sigint-store/src/worker.rs`
- Modify: `crates/sigint-store/src/lib.rs`

**Step 1: Implement worker**

```rust
use std::time::Duration;

use tokio::task;
use tracing::{debug, error, info};

use crate::db::Database;
use crate::embeddings::EmbeddingService;

const BATCH_SIZE: usize = 32;
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Background worker that generates embeddings for new content.
/// Runs in a loop, polling for unembedded rows every POLL_INTERVAL.
pub async fn embedding_worker(db: Database, service: EmbeddingService) {
    info!("Embedding worker started");
    loop {
        let mut total = 0;

        for (source_type, fetch_fn) in [
            ("message", Database::unembedded_messages as fn(&Database, usize) -> _),
            ("finding", Database::unembedded_findings as fn(&Database, usize) -> _),
        ] {
            match process_batch(&db, &service, source_type, fetch_fn) {
                Ok(n) => total += n,
                Err(e) => error!("Embedding worker error for {source_type}: {e}"),
            }
        }

        if total > 0 {
            debug!("Embedded {total} documents");
        }

        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

fn process_batch(
    db: &Database,
    service: &EmbeddingService,
    source_type: &str,
    fetch_fn: fn(&Database, usize) -> Result<Vec<i64>, sigint_core::Error>,
) -> Result<usize, sigint_core::Error> {
    let ids = fetch_fn(db, BATCH_SIZE)?;
    if ids.is_empty() {
        return Ok(0);
    }

    let texts = db.get_texts_for_embedding(source_type, &ids)?;
    let text_refs: Vec<&str> = texts.iter().map(|s| s.as_str()).collect();
    let vectors = service.embed_batch(&text_refs)?;

    for (id, vec) in ids.iter().zip(vectors.iter()) {
        db.store_embedding(source_type, *id, "all-MiniLM-L6-v2", vec)?;
    }

    Ok(ids.len())
}
```

**Step 2: Run full test suite**

Run: `cargo test --workspace -- --nocapture`
Expected: All pass

**Step 3: Commit**

```bash
git add -A
git commit -m "feat(store): add background embedding worker with batch processing"
```

---

### Task 3B-6: Final Validation + Merge

Run full workspace tests, clippy, then merge to main.

---

## Sub-Phase 3D: Ratatui TUI

**Worktree:** `git worktree add -b feature/phase-3d-tui .worktrees/phase-3d-tui main`
**Crate:** `sigint-tui`
**Can start in parallel with 3B after 3A merges.**

---

### Task 3D-1: Add ratatui + crossterm Dependencies

**Files:**
- Modify: `Cargo.toml` (workspace root)
- Modify: `crates/sigint-tui/Cargo.toml`

**Step 1: Add workspace dependencies**

```toml
# workspace root Cargo.toml [workspace.dependencies]
ratatui = "0.29"
crossterm = "0.28"
```

```toml
# crates/sigint-tui/Cargo.toml [dependencies]
ratatui.workspace = true
crossterm.workspace = true
```

**Step 2: Verify compile**

Run: `cargo check -p sigint-tui`

**Step 3: Commit**

```bash
git add -A
git commit -m "deps: add ratatui and crossterm to sigint-tui"
```

---

### Task 3D-2: AppState + Event Application

**Files:**
- Create: `crates/sigint-tui/src/state.rs`
- Modify: `crates/sigint-tui/src/lib.rs`

This is the core state machine — all logic is testable without a terminal.

**Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use sigint_core::event::Event;
    use sigint_core::types::{Finding, Severity, Session};
    use uuid::Uuid;

    #[test]
    fn tool_started_pushes_to_log() {
        let mut state = AppState::new();
        state.apply(Event::ToolStarted {
            name: "nmap_scan".into(),
            args: "-sV example.com".into(),
        });
        assert_eq!(state.tool_log.len(), 1);
        assert_eq!(state.tool_log[0].name, "nmap_scan");
        assert_eq!(state.iteration, 1);
    }

    #[test]
    fn token_received_appends_to_buffer() {
        let mut state = AppState::new();
        let sid = Uuid::new_v4();
        state.apply(Event::TokenReceived {
            session_id: sid,
            token: "Hello".into(),
        });
        state.apply(Event::TokenReceived {
            session_id: sid,
            token: " world".into(),
        });
        assert_eq!(state.streaming_buffer, "Hello world");
    }

    #[test]
    fn stream_completed_flushes_buffer_to_messages() {
        let mut state = AppState::new();
        let sid = Uuid::new_v4();
        state.apply(Event::TokenReceived {
            session_id: sid,
            token: "Analysis complete".into(),
        });
        state.apply(Event::StreamCompleted { session_id: sid });
        assert!(state.streaming_buffer.is_empty());
        assert_eq!(state.messages.len(), 1);
        assert_eq!(state.messages[0].content, "Analysis complete");
    }

    #[test]
    fn finding_created_pushes_to_findings() {
        let mut state = AppState::new();
        let sid = Uuid::new_v4();
        let f = Finding::new(sid, "XSS", "reflected XSS", Severity::High);
        state.apply(Event::FindingCreated(f));
        assert_eq!(state.findings.len(), 1);
        assert_eq!(state.findings[0].title, "XSS");
    }

    #[test]
    fn scroll_up_disables_auto_scroll() {
        let mut state = AppState::new();
        assert!(state.auto_scroll[&Panel::Chat]);
        state.scroll_up(Panel::Chat);
        assert!(!state.auto_scroll[&Panel::Chat]);
    }

    #[test]
    fn jump_to_bottom_re_enables_auto_scroll() {
        let mut state = AppState::new();
        state.scroll_up(Panel::Chat);
        assert!(!state.auto_scroll[&Panel::Chat]);
        state.jump_to_bottom(Panel::Chat);
        assert!(state.auto_scroll[&Panel::Chat]);
    }
}
```

**Step 2: Implement AppState**

```rust
use std::collections::HashMap;
use std::time::Instant;

use sigint_core::event::Event;
use sigint_core::types::{Finding, Message};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Panel {
    Chat,
    ToolOutput,
    Findings,
    Input,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Search(String),
    Command(String),
}

#[derive(Debug, Clone)]
pub struct DisplayMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Clone)]
pub struct ToolEntry {
    pub name: String,
    pub args: String,
    pub output: Option<String>,
    pub exit_code: Option<i32>,
    pub started: Instant,
    pub completed: Option<Instant>,
}

pub struct AppState {
    pub active_agent: Option<(String, Instant)>,
    pub iteration: usize,
    pub messages: Vec<DisplayMessage>,
    pub streaming_buffer: String,
    pub tool_log: Vec<ToolEntry>,
    pub findings: Vec<Finding>,
    pub focused_panel: Panel,
    pub scroll_offsets: HashMap<Panel, usize>,
    pub auto_scroll: HashMap<Panel, bool>,
    pub input: String,
    pub mode: Mode,
    pub should_quit: bool,
}

impl AppState {
    pub fn new() -> Self {
        let mut scroll_offsets = HashMap::new();
        let mut auto_scroll = HashMap::new();
        for panel in [Panel::Chat, Panel::ToolOutput, Panel::Findings, Panel::Input] {
            scroll_offsets.insert(panel, 0);
            auto_scroll.insert(panel, true);
        }

        Self {
            active_agent: None,
            iteration: 0,
            messages: Vec::new(),
            streaming_buffer: String::new(),
            tool_log: Vec::new(),
            findings: Vec::new(),
            focused_panel: Panel::Input,
            scroll_offsets,
            auto_scroll,
            input: String::new(),
            mode: Mode::Normal,
            should_quit: false,
        }
    }

    pub fn apply(&mut self, event: Event) {
        match event {
            Event::Status(msg) => {
                if let Some(agent_name) = msg.strip_prefix("Agent: ").and_then(|s| s.strip_suffix(" started")) {
                    self.active_agent = Some((agent_name.to_string(), Instant::now()));
                    self.iteration = 0;
                }
            }
            Event::ToolStarted { name, args } => {
                self.iteration += 1;
                self.tool_log.push(ToolEntry {
                    name,
                    args,
                    output: None,
                    exit_code: None,
                    started: Instant::now(),
                    completed: None,
                });
            }
            Event::ToolOutput { name: _, output } => {
                if let Some(entry) = self.tool_log.last_mut() {
                    entry.output = Some(output);
                }
            }
            Event::ToolCompleted { name: _, exit_code } => {
                if let Some(entry) = self.tool_log.last_mut() {
                    entry.exit_code = Some(exit_code);
                    entry.completed = Some(Instant::now());
                }
            }
            Event::TokenReceived { session_id: _, token } => {
                self.streaming_buffer.push_str(&token);
            }
            Event::StreamCompleted { session_id: _ } => {
                if !self.streaming_buffer.is_empty() {
                    self.messages.push(DisplayMessage {
                        role: "assistant".to_string(),
                        content: std::mem::take(&mut self.streaming_buffer),
                    });
                }
            }
            Event::MessageCreated(msg) => {
                self.messages.push(DisplayMessage {
                    role: msg.role.to_string(),
                    content: msg.content.clone(),
                });
            }
            Event::FindingCreated(finding) => {
                self.findings.push(finding);
            }
            Event::Shutdown => {
                self.should_quit = true;
            }
            _ => {}
        }
    }

    pub fn scroll_up(&mut self, panel: Panel) {
        self.auto_scroll.insert(panel, false);
        let offset = self.scroll_offsets.entry(panel).or_insert(0);
        *offset = offset.saturating_add(1);
    }

    pub fn scroll_down(&mut self, panel: Panel) {
        let offset = self.scroll_offsets.entry(panel).or_insert(0);
        *offset = offset.saturating_sub(1);
    }

    pub fn jump_to_bottom(&mut self, panel: Panel) {
        self.auto_scroll.insert(panel, true);
        self.scroll_offsets.insert(panel, 0);
    }

    pub fn next_panel(&mut self) {
        self.focused_panel = match self.focused_panel {
            Panel::Chat => Panel::ToolOutput,
            Panel::ToolOutput => Panel::Findings,
            Panel::Findings => Panel::Input,
            Panel::Input => Panel::Chat,
        };
    }
}
```

**Step 3: Run tests**

Run: `cargo test -p sigint-tui -- --nocapture`
Expected: All pass

**Step 4: Commit**

```bash
git add -A
git commit -m "feat(tui): add AppState with event application and scroll management"
```

---

### Task 3D-3: TUI Layout Rendering

**Files:**
- Create: `crates/sigint-tui/src/ui.rs`
- Modify: `crates/sigint-tui/src/lib.rs`

**Step 1: Implement render function**

This renders the 5-panel layout using ratatui's constraint system:

```rust
use ratatui::prelude::*;
use ratatui::widgets::*;

use crate::state::{AppState, Mode, Panel};

pub fn render(frame: &mut Frame, state: &AppState) {
    let area = frame.area();

    // Minimum size check
    if area.width < 80 || area.height < 24 {
        let msg = Paragraph::new("Terminal too small (min 80x24)")
            .alignment(Alignment::Center);
        frame.render_widget(msg, area);
        return;
    }

    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),    // Agent status bar
            Constraint::Min(10),      // Main panels
            Constraint::Length(5),    // Findings
            Constraint::Length(3),    // Input bar
        ])
        .split(area);

    render_status_bar(frame, state, main_layout[0]);
    render_main_panels(frame, state, main_layout[1]);
    render_findings(frame, state, main_layout[2]);
    render_input(frame, state, main_layout[3]);
}

fn render_status_bar(frame: &mut Frame, state: &AppState, area: Rect) {
    let content = if let Some((ref agent, started)) = state.active_agent {
        let elapsed = started.elapsed().as_secs_f64();
        format!(
            " [{}] iteration {}/10 | {:.1}s elapsed",
            agent, state.iteration, elapsed
        )
    } else {
        " Idle — waiting for task".to_string()
    };

    let bar = Paragraph::new(content)
        .style(Style::default().bg(Color::DarkGray).fg(Color::White));
    frame.render_widget(bar, area);
}

fn render_main_panels(frame: &mut Frame, state: &AppState, area: Rect) {
    let panels = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    render_chat(frame, state, panels[0]);
    render_tool_output(frame, state, panels[1]);
}

fn render_chat(frame: &mut Frame, state: &AppState, area: Rect) {
    let focused = state.focused_panel == Panel::Chat;
    let border_style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let mut lines: Vec<Line> = Vec::new();
    for msg in &state.messages {
        let (prefix, color) = match msg.role.as_str() {
            "user" => ("[User] ", Color::Blue),
            "assistant" => ("[Agent] ", Color::Green),
            "system" => ("[System] ", Color::DarkGray),
            "tool" => ("[Tool] ", Color::Yellow),
            _ => ("", Color::White),
        };
        lines.push(Line::from(vec![
            Span::styled(prefix, Style::default().fg(color).bold()),
            Span::raw(&msg.content),
        ]));
    }

    // Show streaming buffer if non-empty
    if !state.streaming_buffer.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("[Agent] ", Style::default().fg(Color::Green).bold()),
            Span::raw(&state.streaming_buffer),
            Span::styled("█", Style::default().fg(Color::Green)),
        ]));
    }

    let chat = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Chat ")
                .borders(Borders::ALL)
                .border_style(border_style),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(chat, area);
}

fn render_tool_output(frame: &mut Frame, state: &AppState, area: Rect) {
    let focused = state.focused_panel == Panel::ToolOutput;
    let border_style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let mut lines: Vec<Line> = Vec::new();
    for entry in &state.tool_log {
        let status = match entry.exit_code {
            Some(0) => "✓",
            Some(_) => "✗",
            None => "…",
        };
        let duration = entry
            .completed
            .map(|c| format!("{:.1}s", (c - entry.started).as_secs_f64()))
            .unwrap_or_else(|| format!("{:.1}s", entry.started.elapsed().as_secs_f64()));

        lines.push(Line::from(vec![
            Span::styled(
                format!("{status} {}", entry.name),
                Style::default().fg(Color::Yellow).bold(),
            ),
            Span::raw(format!(" ({duration})")),
        ]));
        lines.push(Line::from(format!("  {}", entry.args)));
        if let Some(ref output) = entry.output {
            // Show first 3 lines of output
            for line in output.lines().take(3) {
                lines.push(Line::from(format!("  {line}")));
            }
        }
        lines.push(Line::default());
    }

    let panel = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Tools ")
                .borders(Borders::ALL)
                .border_style(border_style),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(panel, area);
}

fn render_findings(frame: &mut Frame, state: &AppState, area: Rect) {
    let focused = state.focused_panel == Panel::Findings;
    let border_style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let rows: Vec<Row> = state
        .findings
        .iter()
        .map(|f| {
            let sev_color = match f.severity {
                sigint_core::types::Severity::Critical => Color::Red,
                sigint_core::types::Severity::High => Color::LightRed,
                sigint_core::types::Severity::Medium => Color::Yellow,
                sigint_core::types::Severity::Low => Color::Blue,
                sigint_core::types::Severity::Info => Color::Gray,
            };
            Row::new(vec![
                Cell::from(f.severity.to_string()).style(Style::default().fg(sev_color)),
                Cell::from(f.title.clone()),
                Cell::from(f.asset.clone().unwrap_or_default()),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Min(20),
            Constraint::Length(20),
        ],
    )
    .header(Row::new(["SEV", "TITLE", "ASSET"]).style(Style::default().bold()))
    .block(
        Block::default()
            .title(" Findings ")
            .borders(Borders::ALL)
            .border_style(border_style),
    );

    frame.render_widget(table, area);
}

fn render_input(frame: &mut Frame, state: &AppState, area: Rect) {
    let focused = state.focused_panel == Panel::Input;
    let border_style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let prefix = match &state.mode {
        Mode::Normal => "> ",
        Mode::Search(_) => "/",
        Mode::Command(_) => ":",
    };

    let input = Paragraph::new(format!("{prefix}{}", state.input))
        .block(
            Block::default()
                .title(" Input ")
                .borders(Borders::ALL)
                .border_style(border_style),
        );

    frame.render_widget(input, area);
}
```

**Step 2: Write render test (no-panic test with TestBackend)**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn render_does_not_panic_at_80x24() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let state = AppState::new();
        terminal.draw(|frame| render(frame, &state)).unwrap();
    }

    #[test]
    fn render_shows_too_small_message_at_40x12() {
        let backend = TestBackend::new(40, 12);
        let mut terminal = Terminal::new(backend).unwrap();
        let state = AppState::new();
        terminal.draw(|frame| render(frame, &state)).unwrap();
        // No panic = pass. Content contains "too small" message.
    }

    #[test]
    fn render_does_not_panic_at_200x50() {
        let backend = TestBackend::new(200, 50);
        let mut terminal = Terminal::new(backend).unwrap();
        let state = AppState::new();
        terminal.draw(|frame| render(frame, &state)).unwrap();
    }
}
```

**Step 3: Run tests**

Run: `cargo test -p sigint-tui -- --nocapture`
Expected: All pass

**Step 4: Commit**

```bash
git add -A
git commit -m "feat(tui): add 5-panel layout rendering with ratatui"
```

---

### Task 3D-4: TuiApp — Terminal Lifecycle + Event Loop

**Files:**
- Create: `crates/sigint-tui/src/app.rs`
- Modify: `crates/sigint-tui/src/lib.rs`

**Step 1: Implement TuiApp**

```rust
use std::io::{self, Stdout};
use std::time::Duration;

use crossterm::event::{self, Event as CEvent, KeyCode, KeyEvent, KeyModifiers};
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::ExecutableCommand;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tokio::sync::broadcast;
use tracing::error;

use sigint_core::event::Event;

use crate::state::{AppState, Mode, Panel};
use crate::ui;

pub struct TuiApp {
    state: AppState,
    event_rx: broadcast::Receiver<Event>,
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl TuiApp {
    pub fn new(event_rx: broadcast::Receiver<Event>) -> Result<Self, io::Error> {
        let terminal = setup_terminal()?;
        Ok(Self {
            state: AppState::new(),
            event_rx,
            terminal,
        })
    }

    pub async fn run(mut self) -> Result<(), io::Error> {
        let tick_rate = Duration::from_millis(33); // ~30fps

        loop {
            // 1. Drain EventBus
            while let Ok(event) = self.event_rx.try_recv() {
                self.state.apply(event);
            }

            // 2. Poll terminal input
            if event::poll(Duration::ZERO)? {
                if let CEvent::Key(key) = event::read()? {
                    if self.handle_key(key) {
                        break;
                    }
                }
            }

            // 3. Check quit flag
            if self.state.should_quit {
                break;
            }

            // 4. Render
            self.terminal
                .draw(|frame| ui::render(frame, &self.state))?;

            // 5. Tick
            tokio::time::sleep(tick_rate).await;
        }

        restore_terminal()?;
        Ok(())
    }

    /// Returns true if the app should quit
    fn handle_key(&mut self, key: KeyEvent) -> bool {
        match (&self.state.mode, key.code) {
            // Quit
            (Mode::Normal, KeyCode::Char('q')) => return true,
            (_, KeyCode::Char('c')) if key.modifiers.contains(KeyModifiers::CONTROL) => {
                return true
            }

            // Panel navigation
            (Mode::Normal, KeyCode::Tab) => self.state.next_panel(),

            // Scrolling
            (Mode::Normal, KeyCode::Char('k') | KeyCode::Up) => {
                self.state.scroll_up(self.state.focused_panel);
            }
            (Mode::Normal, KeyCode::Char('j') | KeyCode::Down) => {
                self.state.scroll_down(self.state.focused_panel);
            }
            (Mode::Normal, KeyCode::Char('G')) => {
                self.state.jump_to_bottom(self.state.focused_panel);
            }

            // Mode switching
            (Mode::Normal, KeyCode::Char('/')) => {
                self.state.mode = Mode::Search(String::new());
            }
            (Mode::Normal, KeyCode::Char(':')) => {
                self.state.mode = Mode::Command(String::new());
            }
            (Mode::Search(_) | Mode::Command(_), KeyCode::Esc) => {
                self.state.mode = Mode::Normal;
            }

            // Input (when Input panel focused)
            (Mode::Normal, KeyCode::Char(c)) if self.state.focused_panel == Panel::Input => {
                self.state.input.push(c);
            }
            (Mode::Normal, KeyCode::Backspace) if self.state.focused_panel == Panel::Input => {
                self.state.input.pop();
            }
            (Mode::Normal, KeyCode::Enter) if self.state.focused_panel == Panel::Input => {
                // TODO: send input to agent pipeline via EventBus
                self.state.input.clear();
            }

            _ => {}
        }
        false
    }
}

fn setup_terminal() -> Result<Terminal<CrosstermBackend<Stdout>>, io::Error> {
    terminal::enable_raw_mode()?;
    let mut stdout = io::stdout();
    stdout.execute(EnterAlternateScreen)?;

    // Panic hook to restore terminal
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = restore_terminal();
        original_hook(info);
    }));

    Terminal::new(CrosstermBackend::new(stdout))
}

fn restore_terminal() -> Result<(), io::Error> {
    terminal::disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;
    Ok(())
}
```

**Step 2: Update lib.rs exports**

```rust
pub mod app;
pub mod state;
pub mod ui;

pub use app::TuiApp;
```

**Step 3: Run tests**

Run: `cargo test -p sigint-tui -- --nocapture`
Expected: All pass (TuiApp itself isn't unit-testable without a terminal, but AppState and ui tests cover logic)

**Step 4: Commit**

```bash
git add -A
git commit -m "feat(tui): add TuiApp with terminal lifecycle, event loop, and keybindings"
```

---

### Task 3D-5: Wire TUI into CLI with isatty Auto-Detection

**Files:**
- Modify: `crates/sigint-cli/src/scan.rs` (add TUI launch)
- Modify: `crates/sigint-cli/src/main.rs` (add --tui/--no-tui flags)
- Modify: `crates/sigint-cli/Cargo.toml` (add sigint-tui dep)

**Step 1: Add sigint-tui dependency to sigint-cli**

```toml
# crates/sigint-cli/Cargo.toml [dependencies]
sigint-tui.workspace = true
```

**Step 2: Add TUI flags to Scan command**

In the `Commands::Scan` variant in `main.rs`, add:
```rust
/// Force TUI mode on
#[arg(long)]
tui: bool,
/// Force TUI mode off (raw stdout)
#[arg(long)]
no_tui: bool,
```

**Step 3: Add TUI launch logic in scan handler**

In `scan.rs`, after EventBus setup:
```rust
let use_tui = if args.tui {
    true
} else if args.no_tui {
    false
} else {
    std::io::stdout().is_terminal()
};

if use_tui {
    let tui = sigint_tui::TuiApp::new(event_bus.subscribe())
        .map_err(|e| sigint_core::Error::Other(e.to_string()))?;
    tokio::spawn(async move {
        if let Err(e) = tui.run().await {
            tracing::error!("TUI error: {e}");
        }
    });
} else {
    // existing stdout event printer
    tokio::spawn(print_events(event_bus.subscribe()));
}
```

**Step 4: Run tests**

Run: `cargo test -p sigint-cli -- --nocapture`
Expected: Existing scan argument parsing tests still pass

**Step 5: Commit**

```bash
git add -A
git commit -m "feat(cli): wire TUI into scan command with isatty auto-detection

@decision DEC-P3-003: TUI auto-detect via isatty (accepted)
--tui forces on, --no-tui forces off, default = isatty(stdout)"
```

---

### Task 3D-6: Final Validation + Merge

Run full workspace tests, clippy, then merge to main.

---

## Sub-Phase 3C: Memory System

**Worktree:** `git worktree add -b feature/phase-3c-memory .worktrees/phase-3c-memory main`
**New crate:** `sigint-memory`
**Start after both 3B and 3D are merged to main.**

---

### Task 3C-1: Create sigint-memory Crate

**Files:**
- Create: `crates/sigint-memory/Cargo.toml`
- Create: `crates/sigint-memory/src/lib.rs`
- Modify: `Cargo.toml` (workspace root — add to members + dependencies)

**Step 1: Create crate structure**

```toml
# crates/sigint-memory/Cargo.toml
[package]
name = "sigint-memory"
version.workspace = true
edition.workspace = true

[dependencies]
sigint-core.workspace = true
sigint-store.workspace = true
tokio.workspace = true
serde.workspace = true
serde_json.workspace = true
thiserror.workspace = true
tracing.workspace = true
chrono.workspace = true
uuid.workspace = true
```

```rust
// crates/sigint-memory/src/lib.rs
//! Memory system for SIGINT — retrieval strategy + prompt injection.
//!
//! Three layers:
//! - Working: current session ConversationState (persisted per turn)
//! - Episodic: session summaries indexed by target + date
//! - Semantic: vector-indexed findings/scans via cosine similarity
//!
//! @decision DEC-P3-001: sigint-memory as separate crate (accepted)

pub mod types;
pub mod service;

pub use service::MemoryService;
pub use types::{MemoryFragment, MemorySource, SessionSummary};
```

Add to workspace `Cargo.toml`:
- `members`: add `"crates/sigint-memory"`
- `[workspace.dependencies]`: add `sigint-memory = { path = "crates/sigint-memory" }`

**Step 2: Verify compile**

Run: `cargo check -p sigint-memory`

**Step 3: Commit**

```bash
git add -A
git commit -m "feat: create sigint-memory crate skeleton

@decision DEC-P3-001: sigint-memory as separate crate (accepted)
Owns retrieval strategy + prompt injection. Depends on sigint-store for
persistence and embeddings."
```

---

### Task 3C-2: Memory Types

**Files:**
- Create: `crates/sigint-memory/src/types.rs`

**Step 1: Implement types**

```rust
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryFragment {
    pub source: MemorySource,
    pub content: String,
    pub relevance: f64,
    pub token_estimate: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MemorySource {
    Episodic {
        session_id: Uuid,
        target: String,
        date: DateTime<Utc>,
    },
    Semantic {
        source_type: String,
        source_id: i64,
    },
    Working,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub session_id: Uuid,
    pub target: String,
    pub date: DateTime<Utc>,
    pub summary: String,
    pub finding_count: usize,
    pub key_findings: Vec<String>,
}

impl MemoryFragment {
    pub fn estimate_tokens(text: &str) -> usize {
        (text.len() + 3) / 4 // ceiling division, same as ConversationState
    }
}
```

**Step 2: Commit**

```bash
git add -A
git commit -m "feat(memory): add MemoryFragment, MemorySource, SessionSummary types"
```

---

### Task 3C-3: MemoryService — Recall + Format

**Files:**
- Create: `crates/sigint-memory/src/service.rs`

**Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use sigint_store::Database;
    use sigint_core::types::{Session, Message, Finding, Severity};

    #[test]
    fn recall_returns_empty_with_no_data() {
        let db = Database::open_in_memory().unwrap();
        let service = MemoryService::new_without_embeddings(db, 1000);
        let fragments = service.recall_episodic("example.com").unwrap();
        assert!(fragments.is_empty());
    }

    #[test]
    fn recall_returns_episodic_summaries_for_target() {
        let db = Database::open_in_memory().unwrap();
        // Create sessions with summaries
        let s1 = Session::new("scan1").with_target("example.com");
        db.create_session(&s1).unwrap();
        // Store episodic summary (need store_episode_summary method on DB)
        // This will be wired once we add the episode storage

        let service = MemoryService::new_without_embeddings(db, 1000);
        // Test will flesh out once episode storage is implemented
    }

    #[test]
    fn format_context_produces_markdown() {
        let fragments = vec![
            MemoryFragment {
                source: MemorySource::Episodic {
                    session_id: Uuid::new_v4(),
                    target: "example.com".into(),
                    date: Utc::now(),
                },
                content: "Found 47 open ports, SSH on 22, HTTP on 80".into(),
                relevance: 1.0,
                token_estimate: 12,
            },
        ];
        let output = MemoryService::format_context(&fragments);
        assert!(output.contains("Prior Intelligence"));
        assert!(output.contains("47 open ports"));
    }

    #[test]
    fn recall_respects_token_budget() {
        // Create fragments totaling 500 tokens
        // Budget is 100 tokens
        // Should only include fragments that fit
        let fragments = vec![
            MemoryFragment {
                source: MemorySource::Episodic {
                    session_id: Uuid::new_v4(),
                    target: "example.com".into(),
                    date: Utc::now(),
                },
                content: "x".repeat(200), // ~50 tokens
                relevance: 1.0,
                token_estimate: 50,
            },
            MemoryFragment {
                source: MemorySource::Episodic {
                    session_id: Uuid::new_v4(),
                    target: "example.com".into(),
                    date: Utc::now(),
                },
                content: "y".repeat(400), // ~100 tokens — won't fit
                relevance: 0.9,
                token_estimate: 100,
            },
        ];

        let budget = 80;
        let fitted: Vec<_> = MemoryService::fit_to_budget(fragments, budget);
        assert_eq!(fitted.len(), 1); // only first one fits
    }
}
```

**Step 2: Implement MemoryService**

```rust
use sigint_core::Error;
use sigint_store::Database;
use sigint_store::embeddings::EmbeddingService;
use crate::types::*;

pub struct MemoryService {
    store: Database,
    embeddings: Option<EmbeddingService>,
    context_budget: usize,
}

impl MemoryService {
    pub fn new(store: Database, embeddings: EmbeddingService, context_window: usize) -> Self {
        Self {
            store,
            embeddings: Some(embeddings),
            context_budget: context_window / 5, // 20%
        }
    }

    /// For testing without embedding model
    pub fn new_without_embeddings(store: Database, context_budget: usize) -> Self {
        Self {
            store,
            embeddings: None,
            context_budget,
        }
    }

    /// Retrieve episodic summaries for a target (most recent first, up to 3)
    pub fn recall_episodic(&self, target: &str) -> Result<Vec<MemoryFragment>, Error> {
        let sessions = self.store.sessions()
            .by_target(target)
            .order_by_date_desc()
            .limit(3)
            .list()?;

        let mut fragments = Vec::new();
        for session in sessions {
            // Look for a stored episode summary message
            let messages = self.store.messages_query()
                .by_session(session.id)
                .by_role(sigint_core::types::Role::System)
                .list()?;

            // Find the episode summary (convention: starts with "EPISODE_SUMMARY:")
            if let Some(summary_msg) = messages.iter().find(|m| m.content.starts_with("EPISODE_SUMMARY:")) {
                let summary = summary_msg.content.trim_start_matches("EPISODE_SUMMARY:").trim();
                let token_est = MemoryFragment::estimate_tokens(summary);
                fragments.push(MemoryFragment {
                    source: MemorySource::Episodic {
                        session_id: session.id,
                        target: session.target.clone().unwrap_or_default(),
                        date: session.created_at,
                    },
                    content: summary.to_string(),
                    relevance: 1.0,
                    token_estimate: token_est,
                });
            }
        }

        Ok(fragments)
    }

    /// Retrieve semantically relevant fragments
    pub fn recall_semantic(&self, query: &str, top_k: usize) -> Result<Vec<MemoryFragment>, Error> {
        let embeddings = match &self.embeddings {
            Some(e) => e,
            None => return Ok(Vec::new()),
        };

        let query_vec = embeddings.embed(query)?;
        let results = self.store.semantic_search(&query_vec, top_k)?;

        let mut fragments = Vec::new();
        for result in results {
            let text = self.store.get_texts_for_embedding(&result.source_type, &[result.source_id])?;
            if let Some(content) = text.into_iter().next() {
                let token_est = MemoryFragment::estimate_tokens(&content);
                fragments.push(MemoryFragment {
                    source: MemorySource::Semantic {
                        source_type: result.source_type,
                        source_id: result.source_id,
                    },
                    content,
                    relevance: result.similarity,
                    token_estimate: token_est,
                });
            }
        }

        Ok(fragments)
    }

    /// Full recall: episodic + semantic, fitted to budget
    pub fn recall(&self, target: &str, query: &str) -> Result<Vec<MemoryFragment>, Error> {
        let mut all = Vec::new();
        all.extend(self.recall_episodic(target)?);
        all.extend(self.recall_semantic(query, 5)?);
        Ok(Self::fit_to_budget(all, self.context_budget))
    }

    pub fn fit_to_budget(fragments: Vec<MemoryFragment>, budget: usize) -> Vec<MemoryFragment> {
        let mut fitted = Vec::new();
        let mut remaining = budget;
        for frag in fragments {
            if frag.token_estimate <= remaining {
                remaining -= frag.token_estimate;
                fitted.push(frag);
            }
        }
        fitted
    }

    pub fn format_context(fragments: &[MemoryFragment]) -> String {
        if fragments.is_empty() {
            return String::new();
        }

        let mut output = String::from("## Prior Intelligence\n\n");

        let episodic: Vec<_> = fragments.iter().filter(|f| matches!(f.source, MemorySource::Episodic { .. })).collect();
        let semantic: Vec<_> = fragments.iter().filter(|f| matches!(f.source, MemorySource::Semantic { .. })).collect();

        for frag in &episodic {
            if let MemorySource::Episodic { target, date, .. } = &frag.source {
                output.push_str(&format!("### Session {} ({})\n", date.format("%Y-%m-%d"), target));
                output.push_str(&frag.content);
                output.push_str("\n\n");
            }
        }

        if !semantic.is_empty() {
            output.push_str("### Relevant Findings\n");
            for frag in &semantic {
                output.push_str(&format!("- {}\n", frag.content));
            }
        }

        output
    }

    /// Store an episodic summary for a completed session
    pub fn store_episode(&self, session_id: uuid::Uuid, reporter_output: &str) -> Result<(), Error> {
        let summary_content = format!("EPISODE_SUMMARY: {reporter_output}");
        let msg = sigint_core::types::Message::system(session_id, &summary_content);
        self.store.create_message(&msg)?;
        Ok(())
    }
}
```

**Step 3: Run tests**

Run: `cargo test -p sigint-memory -- --nocapture`
Expected: All pass

**Step 4: Commit**

```bash
git add -A
git commit -m "feat(memory): implement MemoryService with episodic + semantic recall"
```

---

### Task 3C-4: Wire Memory into Orchestrator

**Files:**
- Modify: `crates/sigint-agents/Cargo.toml` (add sigint-memory dep)
- Modify: `crates/sigint-agents/src/orchestrator.rs`

**Step 1: Add dependency**

```toml
# crates/sigint-agents/Cargo.toml [dependencies]
sigint-memory.workspace = true
```

**Step 2: Modify Orchestrator to accept and use MemoryService**

Add `memory: Option<MemoryService>` field to `Orchestrator`. In `run_agent()`, call `memory.recall()` before building the ConversationState and inject the context as a system message.

Key change in `run_agent()`:
```rust
// After system prompt, before user prompt:
if let Some(ref memory) = self.memory {
    let fragments = memory.recall(&ctx.target, &ctx.to_query_string())?;
    if !fragments.is_empty() {
        let context = MemoryService::format_context(&fragments);
        state.add_message(ChatMessage::system(&context));
    }
}
```

Make `memory` optional so existing tests (without memory) still pass.

**Step 3: Run tests**

Run: `cargo test --workspace -- --nocapture`
Expected: All pass — existing orchestrator tests use `memory: None`

**Step 4: Commit**

```bash
git add -A
git commit -m "feat(agents): wire MemoryService into Orchestrator for context injection"
```

---

### Task 3C-5: Final Validation + Merge

Run full workspace tests, clippy, merge to main.

---

## Sub-Phase 3E: Integration + Polish

**Worktree:** `git worktree add -b feature/phase-3e-integration .worktrees/phase-3e-integration main`
**After 3C merges to main.**

---

### Task 3E-1: Session Management CLI Commands

**Files:**
- Create: `crates/sigint-cli/src/sessions.rs`
- Modify: `crates/sigint-cli/src/main.rs` (add Sessions subcommand)

Implement `sigint sessions list|export|delete` following the existing `chat` and `scan` command patterns. `resume` reconstructs ConversationState via `MemoryService::restore_working_memory()` and re-enters the scan pipeline.

---

### Task 3E-2: Wire Embedding Worker + Episode Persistence

**Files:**
- Modify: `crates/sigint-cli/src/scan.rs`

After scan completes:
1. `memory_service.store_episode(session_id, &report.summary)`
2. Embedding worker is spawned at scan start, picks up new content automatically

---

### Task 3E-3: TUI Keyboard Navigation Polish

**Files:**
- Modify: `crates/sigint-tui/src/app.rs` (add `?` help overlay, `t` task queue toggle)
- Modify: `crates/sigint-tui/src/ui.rs` (render help overlay)

---

### Task 3E-4: End-to-End Validation

**Step 1: Run full workspace tests**

```bash
cargo test --workspace -- --nocapture
```

**Step 2: Run clippy**

```bash
cargo clippy --workspace -- -D warnings
```

**Step 3: Manual smoke test (requires Ollama)**

```bash
# Test TUI mode
sigint scan scanme.nmap.org

# Test non-TUI mode
sigint scan scanme.nmap.org --no-tui

# Test session management
sigint sessions list
sigint sessions export <session-id>
```

**Step 4: Merge to main**

---

## Phase 3 Completion Checklist

After all sub-phases merge:

- [ ] `sigint scan <target>` shows real-time TUI with 5 panels
- [ ] `sigint scan <target> --no-tui` uses stdout (backward compat)
- [ ] FTS5 search works: `db.search("SQL injection")` returns ranked results
- [ ] Embeddings generated in background for new content
- [ ] Semantic search: `db.semantic_search(query_vec, 10)` returns relevant results
- [ ] Memory injection: repeat scans include prior session context
- [ ] Session resume: `sigint sessions resume <id>` restores state
- [ ] All existing Phase 2 tests pass unchanged
- [ ] `cargo clippy --workspace -- -D warnings` clean
- [ ] MASTER_PLAN.md updated: Phase 3 completed, Phase 4 planning
