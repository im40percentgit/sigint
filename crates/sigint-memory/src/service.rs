//! MemoryService — episodic + semantic recall with token-budget enforcement.
//!
//! Retrieval strategy (in priority order):
//!   1. Episodic: session summaries stored under the same target, most recent first.
//!   2. Semantic: cosine-similarity search over all stored embeddings.
//!
//! Both are combined and greedy-fitted to the token budget before formatting.
//!
//! @decision DEC-P3-001
//! @title MemoryService combines episodic + semantic recall with budget cap
//! @status accepted
//! @rationale Two recall paths cover complementary needs: episodic gives
//! structured per-target history (what happened on this exact host before);
//! semantic gives cross-target relevance (similar CVEs, same service version).
//! A greedy token budget ensures memory never crowds out the agent's working
//! context. The 20% budget (context_window / 5) is a conservative default
//! that leaves room for the agent prompt, tool definitions, and tool outputs.
//! Embeddings are optional so the service can be constructed without the
//! ~80 MB fastembed model in tests and offline scenarios.

use sigint_core::types::{Message, Role};
use sigint_core::Error;
use sigint_store::embeddings::EmbeddingService;
use sigint_store::Database;
use tracing::debug;

use crate::types::{MemoryFragment, MemorySource};

/// Retrieves and formats historical context for prompt injection.
///
/// Create with `MemoryService::new` (requires an `EmbeddingService`) or
/// `MemoryService::new_without_embeddings` (episodic-only, for tests).
pub struct MemoryService {
    store: Database,
    embeddings: Option<EmbeddingService>,
    context_budget: usize,
}

impl MemoryService {
    /// Create a `MemoryService` with full semantic search support.
    ///
    /// `context_window` is the model's total token budget; the memory budget
    /// is set to 20% of that value.
    pub fn new(store: Database, embeddings: EmbeddingService, context_window: usize) -> Self {
        Self {
            store,
            embeddings: Some(embeddings),
            context_budget: context_window / 5,
        }
    }

    /// Create a `MemoryService` without an embedding model.
    ///
    /// Semantic recall will return empty results. Useful for tests and
    /// environments where the fastembed model is not available.
    pub fn new_without_embeddings(store: Database, context_budget: usize) -> Self {
        Self {
            store,
            embeddings: None,
            context_budget,
        }
    }

    /// Retrieve episodic summaries for a target (up to 3, most recent first).
    ///
    /// Episodic summaries are `system`-role messages whose content begins with
    /// the sentinel `"EPISODE_SUMMARY: "`, stored by `store_episode`.
    pub fn recall_episodic(&self, target: &str) -> Result<Vec<MemoryFragment>, Error> {
        let sessions = self
            .store
            .sessions()
            .by_target(target)
            .order_by_date_desc()
            .limit(3)
            .list()?;

        let mut fragments = Vec::new();
        for session in sessions {
            let messages = self
                .store
                .messages_query()
                .by_session(session.id)
                .by_role(Role::System)
                .list()?;

            if let Some(msg) = messages
                .iter()
                .find(|m| m.content.starts_with("EPISODE_SUMMARY:"))
            {
                let summary = msg.content.trim_start_matches("EPISODE_SUMMARY:").trim();
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
                debug!(
                    session_id = %session.id,
                    target,
                    "memory: recalled episodic summary"
                );
            }
        }

        Ok(fragments)
    }

    /// Retrieve semantically relevant fragments via cosine similarity.
    ///
    /// Returns empty if no `EmbeddingService` was provided at construction.
    pub fn recall_semantic(&self, query: &str, top_k: usize) -> Result<Vec<MemoryFragment>, Error> {
        let embeddings = match &self.embeddings {
            Some(e) => e,
            None => return Ok(Vec::new()),
        };

        let query_vec = embeddings.embed(query)?;
        let results = self.store.semantic_search(&query_vec, top_k)?;

        let mut fragments = Vec::new();
        for result in results {
            let texts = self.store.get_texts_for_embedding(
                &result.source_type,
                std::slice::from_ref(&result.source_id),
            )?;
            if let Some(content) = texts.into_iter().next() {
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

    /// Full recall: episodic + semantic, combined and fitted to the token budget.
    pub fn recall(&self, target: &str, query: &str) -> Result<Vec<MemoryFragment>, Error> {
        let mut all = Vec::new();
        all.extend(self.recall_episodic(target)?);
        all.extend(self.recall_semantic(query, 5)?);
        Ok(Self::fit_to_budget(all, self.context_budget))
    }

    /// Greedy-fit fragments into a token budget, preserving order.
    ///
    /// Iterates fragments in the order given and includes each one only if
    /// its `token_estimate` fits within the remaining budget. Fragments that
    /// do not fit are dropped (not reordered or split).
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

    /// Format a slice of memory fragments into a markdown block for prompt injection.
    ///
    /// Returns an empty string if `fragments` is empty.
    /// Episodic fragments are grouped under dated session headers.
    /// Semantic fragments appear under a "Relevant Findings" sub-section.
    pub fn format_context(fragments: &[MemoryFragment]) -> String {
        if fragments.is_empty() {
            return String::new();
        }

        let mut output = String::from("## Prior Intelligence\n\n");

        let episodic: Vec<_> = fragments
            .iter()
            .filter(|f| matches!(f.source, MemorySource::Episodic { .. }))
            .collect();
        let semantic: Vec<_> = fragments
            .iter()
            .filter(|f| matches!(f.source, MemorySource::Semantic { .. }))
            .collect();

        for frag in &episodic {
            if let MemorySource::Episodic { target, date, .. } = &frag.source {
                output.push_str(&format!(
                    "### Session {} ({})\n",
                    date.format("%Y-%m-%d"),
                    target
                ));
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

    /// Persist an episodic summary for a completed session.
    ///
    /// Stores a `system`-role message with the `"EPISODE_SUMMARY: "` sentinel
    /// prefix so `recall_episodic` can find it later. Call this after the
    /// Reporter agent completes its output.
    pub fn store_episode(
        &self,
        session_id: uuid::Uuid,
        reporter_output: &str,
    ) -> Result<(), Error> {
        let content = format!("EPISODE_SUMMARY: {reporter_output}");
        let msg = Message::system(session_id, &content);
        self.store.create_message(&msg)?;
        debug!(%session_id, "memory: stored episode summary");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sigint_core::types::Session;
    use sigint_store::Database;
    use uuid::Uuid;

    fn in_memory_db() -> Database {
        Database::open_in_memory().unwrap()
    }

    // ── recall_episodic ───────────────────────────────────────────────────────

    #[test]
    fn recall_returns_empty_with_no_data() {
        let db = in_memory_db();
        let svc = MemoryService::new_without_embeddings(db, 1000);
        let frags = svc.recall_episodic("example.com").unwrap();
        assert!(frags.is_empty(), "no sessions → no fragments");
    }

    #[test]
    fn recall_episodic_returns_summary_for_target() {
        let db = in_memory_db();
        // Create a session with a target and store an episode summary.
        let session = Session::new("scan1").with_target("example.com");
        db.create_session(&session).unwrap();

        let svc = MemoryService::new_without_embeddings(db, 1000);
        svc.store_episode(session.id, "Found 47 open ports; SSH on 22")
            .unwrap();

        let frags = svc.recall_episodic("example.com").unwrap();
        assert_eq!(frags.len(), 1);
        assert!(frags[0].content.contains("47 open ports"));
        assert_eq!(frags[0].relevance, 1.0);
    }

    #[test]
    fn recall_episodic_skips_sessions_without_summary() {
        let db = in_memory_db();
        let session = Session::new("no-summary").with_target("example.com");
        db.create_session(&session).unwrap();
        // No store_episode call — session has no EPISODE_SUMMARY message.

        let svc = MemoryService::new_without_embeddings(db, 1000);
        let frags = svc.recall_episodic("example.com").unwrap();
        assert!(frags.is_empty());
    }

    #[test]
    fn recall_episodic_ignores_other_targets() {
        let db = in_memory_db();
        let s1 = Session::new("scan-other").with_target("other.com");
        db.create_session(&s1).unwrap();

        let svc = MemoryService::new_without_embeddings(db, 1000);
        svc.store_episode(s1.id, "Other target summary").unwrap();

        let frags = svc.recall_episodic("example.com").unwrap();
        assert!(
            frags.is_empty(),
            "should not return summaries for different targets"
        );
    }

    // ── fit_to_budget ─────────────────────────────────────────────────────────

    #[test]
    fn fit_to_budget_includes_all_when_budget_sufficient() {
        let frags = vec![make_frag(50), make_frag(30)];
        let fitted = MemoryService::fit_to_budget(frags, 100);
        assert_eq!(fitted.len(), 2);
    }

    #[test]
    fn fit_to_budget_drops_fragments_that_exceed_remaining() {
        let frags = vec![
            make_frag(50),  // fits (50 <= 80)
            make_frag(100), // doesn't fit (100 > 30 remaining)
        ];
        let fitted = MemoryService::fit_to_budget(frags, 80);
        assert_eq!(fitted.len(), 1);
        assert_eq!(fitted[0].token_estimate, 50);
    }

    #[test]
    fn fit_to_budget_empty_input() {
        let fitted = MemoryService::fit_to_budget(vec![], 500);
        assert!(fitted.is_empty());
    }

    #[test]
    fn fit_to_budget_zero_budget_drops_all() {
        let frags = vec![make_frag(1), make_frag(2)];
        let fitted = MemoryService::fit_to_budget(frags, 0);
        assert!(fitted.is_empty());
    }

    // ── format_context ────────────────────────────────────────────────────────

    #[test]
    fn format_context_empty_returns_empty_string() {
        let out = MemoryService::format_context(&[]);
        assert!(out.is_empty());
    }

    #[test]
    fn format_context_produces_markdown_with_prior_intelligence_header() {
        let frags = vec![MemoryFragment {
            source: MemorySource::Episodic {
                session_id: Uuid::new_v4(),
                target: "example.com".into(),
                date: Utc::now(),
            },
            content: "Found 47 open ports, SSH on 22, HTTP on 80".into(),
            relevance: 1.0,
            token_estimate: 12,
        }];
        let out = MemoryService::format_context(&frags);
        assert!(
            out.contains("Prior Intelligence"),
            "should have section header"
        );
        assert!(
            out.contains("47 open ports"),
            "should include fragment content"
        );
        assert!(
            out.contains("example.com"),
            "should include target in session header"
        );
    }

    #[test]
    fn format_context_semantic_fragments_appear_under_relevant_findings() {
        let frags = vec![MemoryFragment {
            source: MemorySource::Semantic {
                source_type: "finding".into(),
                source_id: "aaaa-0001".into(),
            },
            content: "CVE-2021-41773 path traversal".into(),
            relevance: 0.87,
            token_estimate: 8,
        }];
        let out = MemoryService::format_context(&frags);
        assert!(out.contains("Relevant Findings"));
        assert!(out.contains("CVE-2021-41773"));
    }

    // ── store_episode / recall round-trip ─────────────────────────────────────

    #[test]
    fn store_and_recall_episode_roundtrip() {
        let db = in_memory_db();
        let session = Session::new("roundtrip").with_target("roundtrip.local");
        db.create_session(&session).unwrap();

        let svc = MemoryService::new_without_embeddings(db, 2000);
        svc.store_episode(session.id, "Critical: Apache 2.4 path traversal found")
            .unwrap();

        let frags = svc.recall_episodic("roundtrip.local").unwrap();
        assert_eq!(frags.len(), 1);
        assert!(frags[0].content.contains("Apache 2.4"));
    }

    // ── helper ────────────────────────────────────────────────────────────────

    fn make_frag(tokens: usize) -> MemoryFragment {
        MemoryFragment {
            source: MemorySource::Episodic {
                session_id: Uuid::new_v4(),
                target: "t.local".into(),
                date: Utc::now(),
            },
            content: "x".repeat(tokens * 4),
            relevance: 1.0,
            token_estimate: tokens,
        }
    }
}
