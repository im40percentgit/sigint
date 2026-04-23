//! sigint-agents — Agent trait, ConversationState, TaskContext, and 6-role pipeline.
//!
//! This crate provides the identity and state types for the SIGINT agent system.
//! The tool-call loop, ToolRegistry, and Orchestrator complete the pipeline.
//!
//! # Module layout
//!
//! - [`role`] — `AgentRole` enum (6 variants: RfRecon + original 5)
//! - [`agent`] — `Agent` trait (sync identity contract)
//! - [`state`] — `ConversationState` (sliding-window message history)
//! - [`context`] — `TaskContext` (shared engagement state across agents)
//! - [`agents`] — Concrete implementations: RfRecon, Researcher, Strategist,
//!   Executor, Analyst, Reporter
//! - [`loop_engine`] — `run_tool_loop` (LLM ↔ tool execution cycle)
//! - [`registry`] — `ToolRegistry` (tool storage with role-based ACL filtering)
//! - [`orchestrator`] — `Orchestrator` (six-role pipeline coordinator)
//! - [`report`] — `ScanReport` (final pipeline output)
//! - [`prompt_safety`] — Tool-output wrapping and injection-warning constant
//!
//! @decision DEC-AGENT-002
//! @title Agent trait is synchronous; async lives in the Orchestrator
//! @status accepted
//! @rationale Separating the agent identity contract (this crate) from the
//! execution loop keeps sigint-agents dependency-light and testable without a
//! running LLM or sandbox. The Agent trait has no async methods — it is a pure
//! description of what an agent IS (name, role, prompt, ACL). The Orchestrator
//! reads these properties and drives the async tool-call loop externally. This
//! also means agent structs can be stored in plain collections without pinning
//! or boxing futures.

pub mod agent;
pub mod agents;
pub mod context;
pub mod interactive;
pub mod loop_engine;
pub mod orchestrator;
pub mod prompt_pack;
pub mod prompt_safety;
pub mod registry;
pub mod report;
pub mod role;
pub mod scan_service;
pub mod state;
pub mod tool_acl;

// Flat re-exports for ergonomic use by downstream crates.
pub use agent::Agent;
pub use agents::{
    AnalystAgent, ExecutorAgent, ReporterAgent, ResearcherAgent, RfReconAgent, StrategistAgent,
};
pub use context::TaskContext;
pub use interactive::{parse_command, Command, InteractiveSession};
pub use loop_engine::run_tool_loop;
pub use orchestrator::Orchestrator;
pub use prompt_pack::PromptOverrideFn;
pub use prompt_safety::INJECTION_WARNING;
pub use registry::ToolRegistry;
pub use report::ScanReport;
pub use role::AgentRole;
pub use scan_service::ScanService;
pub use state::ConversationState;
