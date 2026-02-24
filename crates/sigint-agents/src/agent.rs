//! Agent trait — identity contract for all SIGINT agent implementations.
//!
//! @decision DEC-AGENT-002
//! @title Agent trait is synchronous — no async methods
//! @status accepted
//! @rationale The Agent trait declares identity only (name, role, system prompt,
//! allowed tools). No LLM calls or I/O happen through this trait — those live in
//! the Orchestrator's tool-call loop (P2-4). Keeping the trait sync means it
//! composes trivially with dyn dispatch without async-trait overhead, and agent
//! structs can be stored in plain Vec/HashMap without pinning or boxing futures.

use crate::role::AgentRole;

/// Identity contract for a SIGINT agent.
///
/// An `Agent` declares what it is and what it can do. The Orchestrator (P2-4)
/// uses this information to:
/// 1. Build the `ChatRequest` system message from `system_prompt()`.
/// 2. Restrict tool dispatch to the set returned by `allowed_tools()`.
/// 3. Label outputs in `TaskContext::agent_outputs` by `role()`.
///
/// Implementations must be `Send + Sync` so agents can be held across `.await`
/// points in the async Orchestrator without wrapping in `Arc<Mutex<_>>`.
pub trait Agent: Send + Sync {
    /// Human-readable identifier, e.g. `"researcher"`. Used in log output and
    /// as the key when storing agent outputs in `TaskContext`.
    fn name(&self) -> &str;

    /// The role this agent fills in the pipeline.
    fn role(&self) -> AgentRole;

    /// System prompt injected as the first `ChatMessage::system` in every
    /// conversation this agent participates in.
    fn system_prompt(&self) -> &str;

    /// Names of tools this agent is permitted to call.
    ///
    /// The Orchestrator checks each LLM-requested tool call against this list
    /// before dispatching. Requests for tools not in this slice are rejected
    /// and an error is fed back to the model.
    fn allowed_tools(&self) -> &[String];
}
