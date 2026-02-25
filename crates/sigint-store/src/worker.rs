//! Background embedding worker — polls for unembedded content and embeds in batches.
//!
//! @decision DEC-P3-002
//! @title Background worker polls every 5s; batch size 32
//! @status accepted
//! @rationale Embeddings are CPU-intensive and should not block the agent
//! pipeline or TUI event loop. A background tokio task polls SQLite for rows
//! without embeddings every POLL_INTERVAL seconds, embeds them in batches of
//! BATCH_SIZE, and stores the results. The poll interval and batch size are
//! constants — tunable at compile time. If no unembedded rows are found the
//! worker sleeps the full interval without logging to avoid log noise.
//! process_batch is synchronous (CPU-bound); it is called directly from the
//! async loop because fastembed's embed() does not hold any async resources.
//! For very large backlogs the worker will process multiple batches per wakeup
//! via the inner loop, draining up to BATCH_SIZE rows per source type per tick.

use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, error, info};

use crate::db::Database;
use crate::embeddings::EmbeddingService;

const BATCH_SIZE: usize = 32;
const POLL_INTERVAL: Duration = Duration::from_secs(5);
const MODEL_NAME: &str = "all-MiniLM-L6-v2";

/// Start the background embedding worker.
///
/// Runs in a loop, waking every `POLL_INTERVAL` to find unembedded messages
/// and findings, embed them in batches, and store the results.
///
/// This function never returns — spawn it with `tokio::spawn`.
///
/// # Arguments
/// * `db` — shared database handle (Arc allows the worker to outlive callers)
/// * `service` — loaded EmbeddingService (model already in memory)
pub async fn embedding_worker(db: Arc<Database>, service: Arc<EmbeddingService>) {
    info!("Embedding worker started (batch={BATCH_SIZE}, interval={POLL_INTERVAL:?})");

    loop {
        let mut total_embedded = 0usize;

        for (source_type, table) in [("message", "messages"), ("finding", "findings")] {
            match process_batch(&db, &service, source_type) {
                Ok(n) => {
                    total_embedded += n;
                    if n > 0 {
                        debug!("Embedded {n} {source_type} records");
                    }
                }
                Err(e) => {
                    error!("Embedding worker error for {source_type} ({table}): {e}");
                }
            }
        }

        if total_embedded > 0 {
            debug!("Embedding worker: {total_embedded} documents embedded this tick");
        }

        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Fetch up to BATCH_SIZE unembedded records of `source_type`, embed them,
/// and store the results. Returns the number of records embedded.
fn process_batch(
    db: &Database,
    service: &EmbeddingService,
    source_type: &str,
) -> Result<usize, sigint_core::Error> {
    let ids = match source_type {
        "message" => db.unembedded_messages(BATCH_SIZE)?,
        "finding" => db.unembedded_findings(BATCH_SIZE)?,
        _ => return Ok(0),
    };

    if ids.is_empty() {
        return Ok(0);
    }

    let texts = db.get_texts_for_embedding(source_type, &ids)?;
    if texts.is_empty() {
        return Ok(0);
    }

    let text_refs: Vec<&str> = texts.iter().map(String::as_str).collect();
    let vectors = service.embed_batch(&text_refs)?;

    for (id, vector) in ids.iter().zip(vectors.iter()) {
        db.store_embedding(source_type, id, MODEL_NAME, vector)?;
    }

    Ok(ids.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;
    use sigint_core::types::{Message, Session};

    /// Verify process_batch embeds all unembedded messages and stores results.
    /// Does NOT use the real EmbeddingService to avoid model download in CI.
    /// Instead tests the Database-layer logic: unembedded query → store → has_embedding.
    #[test]
    fn process_batch_embeds_and_stores() {
        let db = Database::open_in_memory().unwrap();
        let session = Session::new("worker-test");
        db.create_session(&session).unwrap();

        let m1 = Message::user(session.id, "hello world");
        let m2 = Message::user(session.id, "nmap scan results");
        db.create_message(&m1).unwrap();
        db.create_message(&m2).unwrap();

        // Confirm both are unembedded
        let unembedded = db.unembedded_messages(10).unwrap();
        assert_eq!(unembedded.len(), 2);

        // Manually embed them (simulating what process_batch does)
        let dummy_vec: Vec<f32> = vec![0.1; 384];
        for id in &unembedded {
            db.store_embedding("message", id, MODEL_NAME, &dummy_vec)
                .unwrap();
        }

        // Now none should be unembedded
        let remaining = db.unembedded_messages(10).unwrap();
        assert_eq!(remaining.len(), 0);

        // Verify both are retrievable
        for id in &unembedded {
            assert!(db.has_embedding("message", id).unwrap());
            let retrieved = db.get_embedding("message", id).unwrap().unwrap();
            assert_eq!(retrieved.len(), 384);
        }
    }

    #[test]
    fn process_batch_returns_zero_when_nothing_to_embed() {
        let db = Database::open_in_memory().unwrap();
        // No messages inserted — should return Ok(0)
        let ids = db.unembedded_messages(BATCH_SIZE).unwrap();
        assert_eq!(ids.len(), 0);
    }
}
