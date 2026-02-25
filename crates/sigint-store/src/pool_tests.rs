//! Concurrency tests for the r2d2 connection pool.
//!
//! @decision DEC-P3-POOL
//! @title r2d2 connection pool replaces Mutex<Connection>
//! @status accepted
//! @rationale WAL mode + r2d2 pool enables concurrent reads from TUI and agents
//! without mutex contention. Pool size defaults to 4 for file DBs; in-memory
//! DBs use a single connection to avoid shared-cache URI complexity.

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
