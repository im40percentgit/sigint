//! Memory system for SIGINT — retrieval strategy + prompt injection.
//!
//! Three layers:
//! - Working: current session ConversationState (persisted per turn)
//! - Episodic: session summaries indexed by target + date
//! - Semantic: vector-indexed findings/scans via cosine similarity
//!
//! @decision DEC-P3-001
//! @title sigint-memory as separate crate
//! @status accepted
//! @rationale The memory subsystem has its own distinct responsibility:
//! retrieving and formatting historical context for prompt injection.
//! Keeping it separate from sigint-agents avoids a circular dependency
//! (agents → memory → store) and makes the retrieval strategy independently
//! testable without spinning up an LLM provider. sigint-agents gains a
//! soft dependency on sigint-memory at the Orchestrator level only.

pub mod service;
pub mod types;

pub use service::MemoryService;
pub use types::{MemoryFragment, MemorySource, SessionSummary};
