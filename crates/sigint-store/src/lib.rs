//! sigint-store — SQLite persistence layer for SIGINT.
//!
//! @decision DEC-STORE-001
//! @title SQLite with rusqlite bundled — no external database
//! @status accepted
//! @rationale Zero-config deployment: the database is a single file.
//! rusqlite `bundled` compiles SQLite into the binary, eliminating the
//! system libsqlite3 dependency. WAL mode enables concurrent reads.

pub mod db;
pub mod migrations;
pub mod sessions;
pub mod messages;
pub mod scans;
pub mod findings;
pub mod query;
pub mod search;

pub use db::Database;
pub use scans::ScanRecord;
pub use search::SearchResult;

#[cfg(test)]
mod pool_tests;
