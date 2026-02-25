//! Embedding service and semantic search for sigint-store.
//!
//! @decision DEC-P3-002
//! @title fastembed always-on with all-MiniLM-L6-v2
//! @status accepted
//! @rationale Semantic search over scan history and findings requires a local
//! embedding model. fastembed wraps ONNX Runtime for CPU inference — no GPU
//! needed, no external service. all-MiniLM-L6-v2 produces 384-dim vectors,
//! small enough for SQLite BLOB storage and fast enough for batch processing.
//! Vectors are stored as raw f32 bytes via bytemuck::cast_slice — zero-copy
//! serialization with no schema overhead.

use bytemuck;
use fastembed::{EmbeddingModel, InitOptions, TextEmbedding};
use rusqlite::functions::FunctionFlags;
use rusqlite::OptionalExtension;
use rusqlite::Connection;
use sigint_core::Error;

use crate::db::Database;

/// Service that wraps a fastembed TextEmbedding model.
///
/// Creating this struct will download the ONNX model (~80MB) on first use;
/// subsequent runs use the cached model from `~/.cache/huggingface/`.
pub struct EmbeddingService {
    model: TextEmbedding,
}

impl EmbeddingService {
    /// Load all-MiniLM-L6-v2 (384 dimensions). Blocks while the model loads.
    pub fn new() -> Result<Self, Error> {
        let model = TextEmbedding::try_new(
            InitOptions::new(EmbeddingModel::AllMiniLML6V2)
                .with_show_download_progress(true),
        )
        .map_err(|e| Error::Other(format!("Failed to load embedding model: {e}")))?;

        Ok(Self { model })
    }

    /// Embed a single document. Returns a 384-dimensional float vector.
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

    /// Embed a batch of documents. Returns one vector per input, in order.
    pub fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, Error> {
        self.model
            .embed(texts.to_vec(), None)
            .map_err(|e| Error::Other(format!("Batch embedding failed: {e}")))
    }
}

/// Cosine similarity between two equal-length float vectors.
///
/// Returns 0.0 if either vector is all-zeros (degenerate case).
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

// ---------------------------------------------------------------------------
// SQLite UDF: cosine_similarity(blob_a, blob_b) -> f64
// ---------------------------------------------------------------------------

/// Register a `cosine_similarity(a, b)` scalar function on the connection.
///
/// Both arguments must be BLOBs of f32 bytes (as produced by bytemuck::cast_slice).
/// Called by ConnectionInit so every pooled connection has the function available.
pub fn register_cosine_similarity_udf(conn: &Connection) -> Result<(), Error> {
    conn.create_scalar_function(
        "cosine_similarity",
        2,
        FunctionFlags::SQLITE_UTF8 | FunctionFlags::SQLITE_DETERMINISTIC,
        |ctx| {
            let a_blob = ctx
                .get_raw(0)
                .as_blob()
                .map_err(|e| rusqlite::Error::UserFunctionError(Box::new(e)))?;
            let b_blob = ctx
                .get_raw(1)
                .as_blob()
                .map_err(|e| rusqlite::Error::UserFunctionError(Box::new(e)))?;

            // Guard against corrupted blobs — bytemuck::cast_slice panics if
            // the byte slice length is not a multiple of 4.
            if a_blob.len() % 4 != 0 || b_blob.len() % 4 != 0 {
                return Err(rusqlite::Error::UserFunctionError(
                    "cosine_similarity: blob length not a multiple of 4".into(),
                ));
            }
            if a_blob.len() != b_blob.len() {
                return Err(rusqlite::Error::UserFunctionError(
                    "cosine_similarity: vectors must have the same dimension".into(),
                ));
            }

            let a: &[f32] = bytemuck::cast_slice(a_blob);
            let b: &[f32] = bytemuck::cast_slice(b_blob);
            Ok(cosine_similarity(a, b))
        },
    )
    .map_err(|e| Error::Database(e.to_string()))
}

// ---------------------------------------------------------------------------
// Embedding CRUD on Database
// ---------------------------------------------------------------------------

/// A semantic search result with similarity score.
#[derive(Debug, Clone)]
pub struct SemanticResult {
    /// The table this result came from ("message", "finding", "scan").
    pub source_type: String,
    /// The UUID of the source record.
    pub source_id: String,
    /// Cosine similarity in [0.0, 1.0] (higher = more similar).
    pub similarity: f64,
}

impl Database {
    /// Store (or replace) the embedding for a given source record.
    ///
    /// `source_type` is one of `"message"`, `"finding"`, `"scan"`.
    /// `source_id` is the TEXT UUID primary key of the record.
    /// `vector` must be 384 f32 values for all-MiniLM-L6-v2.
    pub fn store_embedding(
        &self,
        source_type: &str,
        source_id: &str,
        model: &str,
        vector: &[f32],
    ) -> Result<(), Error> {
        let blob: &[u8] = bytemuck::cast_slice(vector);
        self.with_conn(|conn| {
            conn.execute(
                "INSERT OR REPLACE INTO embeddings
                    (id, source_type, source_id, model, vector, created_at)
                 VALUES (lower(hex(randomblob(16))), ?1, ?2, ?3, ?4, datetime('now'))",
                rusqlite::params![source_type, source_id, model, blob],
            )
            .map_err(|e| Error::Database(e.to_string()))?;
            Ok(())
        })
    }

    /// Retrieve the embedding vector for a source record, if stored.
    pub fn get_embedding(
        &self,
        source_type: &str,
        source_id: &str,
    ) -> Result<Option<Vec<f32>>, Error> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT vector FROM embeddings
                     WHERE source_type = ?1 AND source_id = ?2
                     LIMIT 1",
                )
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

    /// Return true if an embedding exists for the given record.
    pub fn has_embedding(&self, source_type: &str, source_id: &str) -> Result<bool, Error> {
        self.with_conn(|conn| {
            let exists: bool = conn
                .query_row(
                    "SELECT EXISTS(
                         SELECT 1 FROM embeddings
                         WHERE source_type = ?1 AND source_id = ?2
                     )",
                    rusqlite::params![source_type, source_id],
                    |row| row.get(0),
                )
                .map_err(|e| Error::Database(e.to_string()))?;
            Ok(exists)
        })
    }

    /// Return up to `limit` message IDs that have no embedding yet.
    pub fn unembedded_messages(&self, limit: usize) -> Result<Vec<String>, Error> {
        self.unembedded("message", "messages", limit)
    }

    /// Return up to `limit` finding IDs that have no embedding yet.
    pub fn unembedded_findings(&self, limit: usize) -> Result<Vec<String>, Error> {
        self.unembedded("finding", "findings", limit)
    }

    fn unembedded(
        &self,
        source_type: &str,
        table: &str,
        limit: usize,
    ) -> Result<Vec<String>, Error> {
        self.with_conn(|conn| {
            let sql = format!(
                "SELECT t.id FROM {table} t
                 LEFT JOIN embeddings e ON e.source_type = ?1 AND e.source_id = t.id
                 WHERE e.id IS NULL
                 LIMIT ?2"
            );
            let mut stmt = conn
                .prepare(&sql)
                .map_err(|e| Error::Database(e.to_string()))?;
            let rows = stmt
                .query_map(rusqlite::params![source_type, limit as i64], |row| {
                    row.get(0)
                })
                .map_err(|e| Error::Database(e.to_string()))?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| Error::Database(e.to_string()))
        })
    }

    /// Get text content for a batch of source records (for embedding).
    ///
    /// Returns one string per ID, in the same order as `ids`.
    pub fn get_texts_for_embedding(
        &self,
        source_type: &str,
        ids: &[String],
    ) -> Result<Vec<String>, Error> {
        if ids.is_empty() {
            return Ok(vec![]);
        }
        self.with_conn(|conn| {
            let placeholders: Vec<String> =
                (1..=ids.len()).map(|i| format!("?{i}")).collect();
            let sql = match source_type {
                "message" => format!(
                    "SELECT content FROM messages WHERE id IN ({}) ORDER BY id",
                    placeholders.join(",")
                ),
                "finding" => format!(
                    "SELECT title || ' ' || description FROM findings \
                     WHERE id IN ({}) ORDER BY id",
                    placeholders.join(",")
                ),
                "scan" => format!(
                    "SELECT COALESCE(output, '') FROM scan_history \
                     WHERE id IN ({}) ORDER BY id",
                    placeholders.join(",")
                ),
                _ => {
                    return Err(Error::InvalidInput(format!(
                        "Unknown source type: {source_type}"
                    )))
                }
            };

            let mut stmt = conn
                .prepare(&sql)
                .map_err(|e| Error::Database(e.to_string()))?;
            let rows = stmt
                .query_map(
                    rusqlite::params_from_iter(ids.iter()),
                    |row| row.get(0),
                )
                .map_err(|e| Error::Database(e.to_string()))?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| Error::Database(e.to_string()))
        })
    }

    // -----------------------------------------------------------------------
    // Semantic Search
    // -----------------------------------------------------------------------

    /// Brute-force semantic search across all embeddings, ranked by cosine similarity.
    ///
    /// Uses the `cosine_similarity` SQLite UDF registered in ConnectionInit.
    /// Returns up to `top_k` results ordered by descending similarity.
    pub fn semantic_search(
        &self,
        query_vector: &[f32],
        top_k: usize,
    ) -> Result<Vec<SemanticResult>, Error> {
        let query_blob: &[u8] = bytemuck::cast_slice(query_vector);
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT source_type, source_id,
                            cosine_similarity(vector, ?1) AS sim
                     FROM embeddings
                     ORDER BY sim DESC
                     LIMIT ?2",
                )
                .map_err(|e| Error::Database(e.to_string()))?;

            let rows = stmt
                .query_map(rusqlite::params![query_blob, top_k as i64], |row| {
                    Ok(SemanticResult {
                        source_type: row.get(0)?,
                        source_id: row.get(1)?,
                        similarity: row.get(2)?,
                    })
                })
                .map_err(|e| Error::Database(e.to_string()))?;

            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| Error::Database(e.to_string()))
        })
    }

    /// Semantic search filtered to a single source type.
    pub fn semantic_search_typed(
        &self,
        query_vector: &[f32],
        source_type: &str,
        top_k: usize,
    ) -> Result<Vec<SemanticResult>, Error> {
        let query_blob: &[u8] = bytemuck::cast_slice(query_vector);
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT source_type, source_id,
                            cosine_similarity(vector, ?1) AS sim
                     FROM embeddings
                     WHERE source_type = ?2
                     ORDER BY sim DESC
                     LIMIT ?3",
                )
                .map_err(|e| Error::Database(e.to_string()))?;

            let rows = stmt
                .query_map(
                    rusqlite::params![query_blob, source_type, top_k as i64],
                    |row| {
                        Ok(SemanticResult {
                            source_type: row.get(0)?,
                            source_id: row.get(1)?,
                            similarity: row.get(2)?,
                        })
                    },
                )
                .map_err(|e| Error::Database(e.to_string()))?;

            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| Error::Database(e.to_string()))
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;

    // ----- EmbeddingService tests -----

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
        assert!(
            sim_related > sim_unrelated,
            "Related texts should be more similar: {sim_related} vs {sim_unrelated}"
        );
        assert!(
            sim_related > 0.7,
            "Related texts should have high similarity, got {sim_related}"
        );
    }

    // ----- CRUD tests -----

    #[test]
    fn store_and_retrieve_embedding() {
        let db = Database::open_in_memory().unwrap();
        let vec: Vec<f32> = (0..384).map(|i| i as f32 / 384.0).collect();
        let source_id = "aaaaaaaa-0000-0000-0000-000000000001";

        db.store_embedding("finding", source_id, "all-MiniLM-L6-v2", &vec)
            .unwrap();
        let retrieved = db.get_embedding("finding", source_id).unwrap().unwrap();

        assert_eq!(retrieved.len(), 384);
        assert!((retrieved[0] - vec[0]).abs() < f32::EPSILON);
        assert!((retrieved[383] - vec[383]).abs() < f32::EPSILON);
    }

    #[test]
    fn has_embedding_returns_false_when_missing() {
        let db = Database::open_in_memory().unwrap();
        assert!(!db
            .has_embedding("finding", "aaaaaaaa-0000-0000-0000-000000000999")
            .unwrap());
    }

    #[test]
    fn has_embedding_returns_true_after_store() {
        let db = Database::open_in_memory().unwrap();
        let vec: Vec<f32> = vec![0.0; 384];
        let source_id = "bbbbbbbb-0000-0000-0000-000000000001";
        db.store_embedding("message", source_id, "all-MiniLM-L6-v2", &vec)
            .unwrap();
        assert!(db.has_embedding("message", source_id).unwrap());
    }

    #[test]
    fn unembedded_returns_ids_without_embeddings() {
        use sigint_core::types::{Message, Session};

        let db = Database::open_in_memory().unwrap();
        let session = Session::new("test");
        db.create_session(&session).unwrap();
        let m1 = Message::user(session.id, "hello");
        let m2 = Message::user(session.id, "world");
        db.create_message(&m1).unwrap();
        db.create_message(&m2).unwrap();

        // Both should be unembedded
        let ids = db.unembedded_messages(10).unwrap();
        assert_eq!(ids.len(), 2);

        // Embed one
        let vec: Vec<f32> = vec![0.0; 384];
        db.store_embedding("message", &ids[0], "all-MiniLM-L6-v2", &vec)
            .unwrap();

        // Now only one unembedded
        let remaining = db.unembedded_messages(10).unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0], ids[1]);
    }

    // ----- Cosine similarity UDF tests -----

    #[test]
    fn cosine_similarity_udf_identical_vectors() {
        let db = Database::open_in_memory().unwrap();
        let vec: Vec<f32> = vec![1.0_f32, 0.0, 0.0];
        let blob: &[u8] = bytemuck::cast_slice(&vec);

        let result: f64 = db
            .with_conn(|conn| {
                conn.query_row(
                    "SELECT cosine_similarity(?1, ?2)",
                    rusqlite::params![blob, blob],
                    |row| row.get(0),
                )
                .map_err(|e| Error::Database(e.to_string()))
            })
            .unwrap();

        assert!(
            (result - 1.0).abs() < 0.001,
            "Identical vectors should have similarity 1.0, got {result}"
        );
    }

    #[test]
    fn semantic_search_returns_ranked_results() {
        let db = Database::open_in_memory().unwrap();

        let close_vec: Vec<f32> = vec![1.0, 0.0, 0.0];
        let far_vec: Vec<f32> = vec![0.0, 1.0, 0.0];
        let query_vec: Vec<f32> = vec![0.9, 0.1, 0.0];

        let id1 = "cccccccc-0000-0000-0000-000000000001";
        let id2 = "cccccccc-0000-0000-0000-000000000002";

        db.store_embedding("finding", id1, "test", &close_vec)
            .unwrap();
        db.store_embedding("finding", id2, "test", &far_vec)
            .unwrap();

        let results = db.semantic_search(&query_vec, 10).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].source_id, id1, "Closer result should rank first");
        assert!(
            results[0].similarity > results[1].similarity,
            "First result should have higher similarity"
        );
    }

    #[test]
    fn semantic_search_typed_filters_by_source() {
        let db = Database::open_in_memory().unwrap();

        let vec: Vec<f32> = vec![1.0, 0.0, 0.0];
        let query: Vec<f32> = vec![1.0, 0.0, 0.0];

        db.store_embedding("finding", "dddddddd-0001", "test", &vec)
            .unwrap();
        db.store_embedding("message", "dddddddd-0002", "test", &vec)
            .unwrap();

        let results = db.semantic_search_typed(&query, "finding", 10).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].source_type, "finding");
    }
}
