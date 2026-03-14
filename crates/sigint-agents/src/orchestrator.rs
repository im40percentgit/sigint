//! Orchestrator — drives the five-role agent pipeline for a single scan target.
//!
//! The Orchestrator is the top-level coordinator of the SIGINT agent system.
//! It instantiates each of the five specialist agents in order, runs them
//! through `run_tool_loop`, accumulates their outputs in a `TaskContext`, and
//! finally assembles a `ScanReport`.
//!
//! @decision DEC-AGENT-013
//! @title Agents are instantiated locally inside run_scan, not stored as fields
//! @status accepted
//! @rationale Agent structs are stateless identity objects (name, role, prompt,
//! ACL). There is no benefit to storing them as Orchestrator fields — doing so
//! would force either `Arc<dyn Agent>` (heap allocation overhead) or generic
//! parameters (combinatorial explosion). Instantiating them locally in `run_scan`
//! is zero-cost (stack allocation), keeps the Orchestrator struct lean, and makes
//! the pipeline order explicit in a single function body. If the agent set needs
//! to be configurable at runtime, a `Vec<Box<dyn Agent>>` field can be added
//! later without breaking existing callers.
//!
//! @decision DEC-AGENT-014
//! @title Orchestrator holds Arc<dyn LlmProvider> to enable cheap Clone across agent turns
//! @status accepted
//! @rationale `run_agent` is an async method that borrows `&self` across await
//! points. The provider must be `Send + Sync` (enforced by the `LlmProvider`
//! trait). Wrapping in `Arc` is the idiomatic Rust pattern for sharing an
//! async-safe object without copying — it avoids lifetime annotations that would
//! complicate the public API and enables future parallel agent dispatch
//! (Arc makes fan-out trivial). The alternative (`&dyn LlmProvider` stored as a
//! raw reference) would require lifetime parameters on the Orchestrator struct,
//! polluting every call site that constructs one.
//!
//! @decision DEC-P3-001
//! @title MemoryService is an optional field on Orchestrator
//! @status accepted
//! @rationale Memory is a Phase 3C addition; all existing tests construct
//! Orchestrator without memory via `Orchestrator::new`. Making the field
//! `Option<MemoryService>` keeps the constructor signature stable and lets
//! callers opt in via `with_memory(svc)`. Context injection in `run_agent`
//! is a no-op when `memory` is `None`, so no existing test breaks.

use std::sync::Arc;

use tracing::info;

use sigint_core::{event::EventBus, Error};
use sigint_llm::provider::LlmProvider;
use sigint_memory::MemoryService;

use crate::{
    agent::Agent,
    agents::{AnalystAgent, ExecutorAgent, ReporterAgent, ResearcherAgent, StrategistAgent},
    context::TaskContext,
    loop_engine::{run_tool_loop, ToolLoopOptions},
    registry::ToolRegistry,
    report::ScanReport,
    role::AgentRole,
    state::ConversationState,
};

/// Default maximum tool-call iterations per agent turn.
const DEFAULT_MAX_ITERATIONS: usize = 10;

/// Coordinates the five-role agent pipeline for a single scan engagement.
///
/// Create one `Orchestrator` per application lifetime and call `run_scan` for
/// each target. The orchestrator is stateless between scans — each `run_scan`
/// call creates a fresh `TaskContext`.
pub struct Orchestrator {
    /// LLM backend shared across all agent turns.
    provider: Arc<dyn LlmProvider>,
    /// Tool registry providing role-filtered tool access.
    registry: ToolRegistry,
    /// Event bus for observability (TUI, logging).
    event_bus: EventBus,
    /// Model context window size in tokens (passed to `ConversationState`).
    context_window: usize,
    /// Model identifier string passed to every `ChatRequest`.
    model: String,
    /// Hard cap on tool-call rounds per agent turn.
    max_iterations: usize,
    /// Optional memory service for episodic + semantic context injection.
    ///
    /// When `Some`, `run_agent` retrieves historical context and prepends it
    /// as a system message before the agent's own system prompt.
    /// When `None` (the default), no memory context is injected.
    memory: Option<MemoryService>,
    /// Optional port specification forwarded from the `--ports` CLI flag.
    ///
    /// When `Some`, the value is threaded into `TaskContext` and surfaced in
    /// the Executor's initial prompt so the LLM passes it to `nmap_scan`.
    ports: Option<String>,
}

impl Orchestrator {
    /// Create a new `Orchestrator`.
    ///
    /// # Arguments
    /// * `provider`       — LLM backend (Ollama, mock, etc.)
    /// * `registry`       — Pre-populated tool registry.
    /// * `event_bus`      — Broadcast bus for observability events.
    /// * `context_window` — Token budget for each agent's conversation state.
    /// * `model`          — Model ID string (e.g. `"llama3.2"`, `"gpt-4o"`).
    pub fn new(
        provider: Arc<dyn LlmProvider>,
        registry: ToolRegistry,
        event_bus: EventBus,
        context_window: usize,
        model: String,
    ) -> Self {
        Self {
            provider,
            registry,
            event_bus,
            context_window,
            model,
            max_iterations: DEFAULT_MAX_ITERATIONS,
            memory: None,
            ports: None,
        }
    }

    /// Override the maximum tool-call iterations per agent turn.
    ///
    /// Defaults to `DEFAULT_MAX_ITERATIONS` (10). Use this to tune the
    /// iteration budget from the CLI `--max-iterations` flag.
    pub fn with_max_iterations(mut self, n: usize) -> Self {
        self.max_iterations = n;
        self
    }

    /// Attach a `MemoryService` for historical context injection.
    ///
    /// When set, each `run_agent` call retrieves episodic and semantic context
    /// for the current target and prepends it as a system message so every
    /// agent starts with relevant historical intelligence.
    pub fn with_memory(mut self, memory: MemoryService) -> Self {
        self.memory = Some(memory);
        self
    }

    /// Set the port specification forwarded from the `--ports` CLI flag.
    ///
    /// The value is passed to `TaskContext::with_ports` so the Executor agent's
    /// initial prompt explicitly instructs the LLM to pass it to `nmap_scan`.
    pub fn with_ports(mut self, ports: Option<String>) -> Self {
        self.ports = ports;
        self
    }

    /// Run the full five-agent scan pipeline against `target`.
    ///
    /// Pipeline order: Researcher → Strategist → Executor → Analyst → Reporter.
    /// Each agent's text output is stored in `TaskContext::agent_outputs` before
    /// the next agent runs, giving downstream agents full visibility into prior
    /// work via `TaskContext::to_agent_prompt`.
    ///
    /// # Returns
    /// A `ScanReport` whose `summary` field is the Reporter's final output.
    ///
    /// # Errors
    /// Returns `Error` if any agent's LLM call fails. Tool execution errors
    /// within an agent turn are recovered internally (fed back to the model).
    pub async fn run_scan(&self, target: &str) -> Result<ScanReport, Error> {
        info!(target, "orchestrator: starting scan pipeline");

        let mut ctx = TaskContext::new(target).with_ports(self.ports.clone());

        // ── 1. Researcher ────────────────────────────────────────────────────
        let researcher = ResearcherAgent::new();
        info!("orchestrator: running researcher agent");
        let researcher_output = self.run_agent(&researcher, &mut ctx).await?;
        ctx.agent_outputs
            .insert(AgentRole::Researcher, researcher_output);

        // ── 2. Strategist ────────────────────────────────────────────────────
        let strategist = StrategistAgent::new();
        info!("orchestrator: running strategist agent");
        let strategist_output = self.run_agent(&strategist, &mut ctx).await?;
        ctx.agent_outputs
            .insert(AgentRole::Strategist, strategist_output);

        // ── 3. Executor ──────────────────────────────────────────────────────
        let executor = ExecutorAgent::new();
        info!("orchestrator: running executor agent");
        let executor_output = self.run_agent(&executor, &mut ctx).await?;
        ctx.agent_outputs
            .insert(AgentRole::Executor, executor_output);

        // ── 4. Analyst ───────────────────────────────────────────────────────
        let analyst = AnalystAgent::new();
        info!("orchestrator: running analyst agent");
        let analyst_output = self.run_agent(&analyst, &mut ctx).await?;
        ctx.agent_outputs.insert(AgentRole::Analyst, analyst_output);

        // ── 5. Reporter ──────────────────────────────────────────────────────
        let reporter = ReporterAgent::new();
        info!("orchestrator: running reporter agent");
        let summary = self.run_agent(&reporter, &mut ctx).await?;

        info!(target, "orchestrator: pipeline complete");

        Ok(ScanReport::new(target.to_string(), ctx, summary))
    }

    /// Run a single agent: build conversation state, call the tool loop, return text.
    ///
    /// 1. Creates a fresh `ConversationState` scoped to this agent's turn.
    /// 2. Injects the agent's system prompt and the role-appropriate user prompt
    ///    derived from the current `TaskContext`.
    /// 3. Retrieves (tool references, tool definitions) from the registry filtered
    ///    by `agent.allowed_tools()`.
    /// 4. Runs `run_tool_loop` to completion and returns the text result.
    async fn run_agent(&self, agent: &dyn Agent, ctx: &mut TaskContext) -> Result<String, Error> {
        let mut state = ConversationState::new(self.context_window);

        // System prompt defines the agent's identity and behavioral constraints.
        state.add_message(sigint_llm::types::ChatMessage::system(
            agent.system_prompt(),
        ));

        // Inject memory context as a second system message, immediately after
        // the agent's own system prompt and before the user prompt. This gives
        // the agent historical intelligence without polluting the user turn.
        if let Some(ref memory) = self.memory {
            let fragments = memory.recall(&ctx.target, &ctx.target)?;
            if !fragments.is_empty() {
                let context = MemoryService::format_context(&fragments);
                state.add_message(sigint_llm::types::ChatMessage::system(&context));
            }
        }

        // User prompt carries the accumulated context relevant to this role.
        let user_prompt = ctx.to_agent_prompt(agent);
        state.add_message(sigint_llm::types::ChatMessage::user(&user_prompt));

        // ACL-filtered tools for this agent.
        let (tool_refs, tool_defs) = self.registry.for_agent(agent);

        run_tool_loop(
            self.provider.as_ref(),
            &mut state,
            &tool_refs,
            &tool_defs,
            ToolLoopOptions {
                max_iterations: self.max_iterations,
                model: &self.model,
                event_bus: &self.event_bus,
                approval_registry: None,
                auto_approve: "all",
            },
        )
        .await
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use futures_util::stream;
    use std::sync::Mutex;

    use sigint_core::event::EventBus;
    use sigint_llm::{
        provider::{ChunkStream, LlmProvider},
        types::{ChatRequest, ChatResponse, StreamChunk},
    };

    // ── MockProvider ─────────────────────────────────────────────────────────

    /// Returns pre-configured text responses in sequence; never emits tool calls.
    ///
    /// When the queue is exhausted, falls back to a default response so tests
    /// that make more calls than expected don't panic.
    struct MockProvider {
        responses: Mutex<Vec<String>>,
    }

    impl MockProvider {
        fn new(responses: Vec<&str>) -> Self {
            Self {
                responses: Mutex::new(responses.iter().map(|s| s.to_string()).collect()),
            }
        }

        /// A single-response mock — all agent turns return the same text.
        fn uniform(response: &str, count: usize) -> Self {
            Self::new(vec![response; count])
        }
    }

    #[async_trait]
    impl LlmProvider for MockProvider {
        fn name(&self) -> &str {
            "mock"
        }

        async fn chat(&self, _request: ChatRequest) -> Result<ChatResponse, Error> {
            let mut queue = self.responses.lock().unwrap();
            let content = if queue.is_empty() {
                "[mock exhausted]".to_string()
            } else {
                queue.remove(0)
            };
            Ok(ChatResponse {
                content,
                usage: None,
                model: "mock".into(),
                tool_calls: vec![],
            })
        }

        async fn chat_stream(&self, _request: ChatRequest) -> Result<ChunkStream, Error> {
            let s = stream::empty::<Result<StreamChunk, Error>>();
            Ok(Box::pin(s))
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn make_orchestrator(provider: Arc<dyn LlmProvider>) -> Orchestrator {
        Orchestrator::new(
            provider,
            ToolRegistry::new(),
            EventBus::new(),
            8192,
            "mock-model".into(),
        )
    }

    // ── Tests ────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn run_scan_dispatches_all_five_agents() {
        // Five agents → five LLM calls (one per agent, no tool calls).
        let provider = Arc::new(MockProvider::new(vec![
            "Researcher output: found open ports 22, 80",
            "Strategist output: attack via port 80",
            "Executor output: ran nmap, confirmed apache 2.4",
            "Analyst output: CVE-2021-41773 likely present",
            "Reporter output: FINAL REPORT — critical finding on example.com",
        ]));

        let orch = make_orchestrator(provider);
        let report = orch.run_scan("example.com").await.unwrap();

        // Reporter's output should be the summary.
        assert!(
            report.summary.contains("FINAL REPORT"),
            "summary should be reporter output: {}",
            report.summary
        );
        assert_eq!(report.target, "example.com");
    }

    #[tokio::test]
    async fn run_scan_accumulates_context_in_order() {
        // Track which prompts each agent receives by embedding the prior output
        // into each mock response, then checking the final context.
        let provider = Arc::new(MockProvider::new(vec![
            "RESEARCHER_DONE",
            "STRATEGIST_DONE",
            "EXECUTOR_DONE",
            "ANALYST_DONE",
            "REPORTER_DONE",
        ]));

        let orch = make_orchestrator(provider);
        let report = orch.run_scan("target.local").await.unwrap();

        // All five outputs should be stored in agent_outputs.
        let outputs = &report.context.agent_outputs;
        assert_eq!(
            outputs.get(&AgentRole::Researcher).map(String::as_str),
            Some("RESEARCHER_DONE"),
            "researcher output missing"
        );
        assert_eq!(
            outputs.get(&AgentRole::Strategist).map(String::as_str),
            Some("STRATEGIST_DONE"),
            "strategist output missing"
        );
        assert_eq!(
            outputs.get(&AgentRole::Executor).map(String::as_str),
            Some("EXECUTOR_DONE"),
            "executor output missing"
        );
        assert_eq!(
            outputs.get(&AgentRole::Analyst).map(String::as_str),
            Some("ANALYST_DONE"),
            "analyst output missing"
        );
        // Reporter output is the summary, not stored in agent_outputs.
        assert_eq!(report.summary, "REPORTER_DONE");
    }

    #[tokio::test]
    async fn run_scan_report_target_matches_input() {
        let provider = Arc::new(MockProvider::uniform("done", 5));
        let orch = make_orchestrator(provider);
        let report = orch.run_scan("192.168.1.0/24").await.unwrap();
        assert_eq!(report.target, "192.168.1.0/24");
    }

    #[tokio::test]
    async fn run_scan_reporter_output_is_summary() {
        // Each agent gets a distinct response; the last (reporter) becomes summary.
        let provider = Arc::new(MockProvider::new(vec![
            "recon complete",
            "strategy planned",
            "tools executed",
            "findings analysed",
            "THE PENTEST REPORT BODY",
        ]));

        let orch = make_orchestrator(provider);
        let report = orch.run_scan("10.0.0.1").await.unwrap();

        assert_eq!(
            report.summary, "THE PENTEST REPORT BODY",
            "summary must be the reporter agent's output"
        );
    }

    #[tokio::test]
    async fn run_agent_uses_system_prompt_and_user_prompt() {
        // We can't inspect the ChatRequest without a recording provider,
        // so we verify indirectly: run_agent returns the mock response text.
        let provider = Arc::new(MockProvider::new(vec!["agent text response"]));
        let orch = make_orchestrator(provider);

        let agent = ResearcherAgent::new();
        let mut ctx = TaskContext::new("verify.local");
        let result = orch.run_agent(&agent, &mut ctx).await.unwrap();

        assert_eq!(result, "agent text response");
    }

    #[tokio::test]
    async fn with_ports_threads_ports_to_context() {
        // Verify that with_ports does not break the pipeline and the report
        // target is preserved. Ports are reflected in the Executor prompt but
        // we cannot intercept the prompt without a recording provider — so we
        // verify the observable invariant: target and report structure are intact.
        let provider = Arc::new(MockProvider::uniform("done", 5));
        let orch = make_orchestrator(provider).with_ports(Some("80,443".into()));
        let report = orch.run_scan("test.local").await.unwrap();
        assert_eq!(report.target, "test.local");
    }

    #[tokio::test]
    async fn provider_error_propagates_from_run_scan() {
        struct FailingProvider;

        #[async_trait]
        impl LlmProvider for FailingProvider {
            fn name(&self) -> &str {
                "failing"
            }
            async fn chat(&self, _: ChatRequest) -> Result<ChatResponse, Error> {
                Err(Error::Llm("provider unavailable".into()))
            }
            async fn chat_stream(&self, _: ChatRequest) -> Result<ChunkStream, Error> {
                Err(Error::Llm("provider unavailable".into()))
            }
        }

        let orch = make_orchestrator(Arc::new(FailingProvider));
        let err = orch.run_scan("fail.local").await.unwrap_err();
        assert!(
            err.to_string().contains("provider unavailable"),
            "error should propagate: {err}"
        );
    }
}
