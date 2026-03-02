//! sigint-store — SQLite persistence layer for SIGINT.
//!
//! @decision DEC-STORE-001
//! @title SQLite with rusqlite bundled — no external database
//! @status accepted
//! @rationale Zero-config deployment: the database is a single file.
//! rusqlite `bundled` compiles SQLite into the binary, eliminating the
//! system libsqlite3 dependency. WAL mode enables concurrent reads.

pub mod assets;
pub mod db;
pub mod embeddings;
pub mod findings;
pub mod messages;
pub mod migrations;
pub mod query;
pub mod scans;
pub mod search;
pub mod sessions;
pub mod worker;

pub use db::Database;
pub use embeddings::{cosine_similarity, EmbeddingService, SemanticResult};
pub use scans::ScanRecord;
pub use search::SearchResult;
pub use worker::embedding_worker;

#[cfg(test)]
mod pool_tests;
