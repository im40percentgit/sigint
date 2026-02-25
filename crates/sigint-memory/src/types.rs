//! Core memory types for the SIGINT memory system.
//!
//! `MemoryFragment` is the unit of retrieved context — one piece of historical
//! information with its source, relevance score, and token cost.
//! `MemorySource` tags each fragment with where it came from so the formatter
//! can group and label fragments appropriately.
//! `SessionSummary` is the structured form of an episodic memory, produced by
//! the Reporter agent and stored for future recall.
//!
//! @decision DEC-P3-001
//! @title sigint-memory as separate crate — types module
//! @status accepted
//! @rationale MemoryFragment/MemorySource/SessionSummary are the shared
//! vocabulary between MemoryService (retrieval) and callers (Orchestrator).
//! Keeping them in a dedicated types module mirrors the pattern established
//! by sigint-core::types and keeps service.rs focused on logic only.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A single unit of retrieved memory ready for prompt injection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryFragment {
    /// Where this fragment came from.
    pub source: MemorySource,
    /// The text content to inject.
    pub content: String,
    /// Relevance score in [0.0, 1.0] — higher is more relevant.
    pub relevance: f64,
    /// Estimated token cost of `content` (ceiling of len / 4).
    pub token_estimate: usize,
}

/// Tags a `MemoryFragment` with its origin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MemorySource {
    /// From a past session's episode summary stored by the Reporter agent.
    Episodic {
        session_id: Uuid,
        target: String,
        date: DateTime<Utc>,
    },
    /// From a semantic vector search over stored messages/findings/scans.
    ///
    /// Note: `source_id` is a TEXT UUID matching SQLite primary keys,
    /// consistent with sigint-store's UUID-as-TEXT schema convention.
    Semantic {
        source_type: String,
        source_id: String,
    },
    /// From the current session's ConversationState (working memory).
    Working,
}

/// Structured form of a completed session's episodic summary.
///
/// Produced by the Reporter agent at the end of a scan and stored via
/// `MemoryService::store_episode` for future recall.
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
    /// Estimate token count for a text string.
    ///
    /// Uses ceiling division of `len / 4`, the same heuristic as
    /// `ConversationState::estimate_tokens` — 4 chars ≈ 1 token.
    pub fn estimate_tokens(text: &str) -> usize {
        text.len().div_ceil(4)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimate_tokens_empty() {
        assert_eq!(MemoryFragment::estimate_tokens(""), 0);
    }

    #[test]
    fn estimate_tokens_exact_multiple() {
        // 8 chars / 4 = 2 tokens exactly
        assert_eq!(MemoryFragment::estimate_tokens("abcdefgh"), 2);
    }

    #[test]
    fn estimate_tokens_ceiling() {
        // 9 chars → ceiling(9/4) = 3
        assert_eq!(MemoryFragment::estimate_tokens("abcdefghi"), 3);
    }

    #[test]
    fn memory_fragment_roundtrips_json() {
        let frag = MemoryFragment {
            source: MemorySource::Episodic {
                session_id: Uuid::new_v4(),
                target: "example.com".into(),
                date: Utc::now(),
            },
            content: "Found SSH on port 22".into(),
            relevance: 0.95,
            token_estimate: 5,
        };
        let json = serde_json::to_string(&frag).unwrap();
        let back: MemoryFragment = serde_json::from_str(&json).unwrap();
        assert_eq!(back.content, frag.content);
        assert!((back.relevance - frag.relevance).abs() < f64::EPSILON);
    }

    #[test]
    fn semantic_source_id_is_string() {
        // Verify source_id is String (UUID text), not i64.
        // Matches sigint-store's UUID-as-TEXT schema convention.
        let src = MemorySource::Semantic {
            source_type: "finding".into(),
            source_id: "aaaaaaaa-0000-0000-0000-000000000001".into(),
        };
        match src {
            MemorySource::Semantic { source_id, .. } => {
                assert!(source_id.contains('-'), "source_id should be a UUID string");
            }
            _ => panic!("unexpected variant"),
        }
    }
}
