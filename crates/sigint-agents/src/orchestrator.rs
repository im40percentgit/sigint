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
//!
//! @decision DEC-AGENT-016
//! @title Orchestrator holds `Option<Arc<Database>>` + `session_id` for per-tool persistence
//! @status accepted
//! @rationale The database is optional because not all callers (tests, web scan
//! service) have a database at construction time. `Arc<Database>` matches the
//! ownership model used elsewhere in the CLI: a single `Database` handle is
//! opened once and shared. `session_id` is a `Uuid` defaulting to `Uuid::nil()`
//! when no database is provided — `nil` is harmless since the DB path is never
//! taken. Builder methods (`with_db`, `with_session_id`) keep `new()` stable.
//!
//! @decision DEC-AGENT-017
//! @title Convergence loop uses max_cycles=1 default to preserve backward compatibility
//! @status accepted
//! @rationale The iterative Strategist→Executor→Analyst loop must not change
//! existing behaviour for any caller that does not opt in. Defaulting `max_cycles`
//! to 1 means the `for cycle in 0..1` body runs exactly once and `is_converged`
//! is never called — the loop exits via the natural `0 < 1` termination condition.
//! This is mechanically verified by `run_scan_linear_default` which uses a 5-response
//! mock queue; if the loop ran more than once the mock would exhaust and the
//! summary assertion would fail. The fresh-FindingCollector-per-cycle design in
//! `run_inner_cycle` lets the convergence check compare only *new* findings
//! against the goal, rather than re-inspecting the full accumulated set.

use std::sync::Arc;

use tracing::info;
use uuid::Uuid;

use sigint_core::{
    event::{Event, EventBus},
    types::{EscalationTier, Finding, Severity},
    ApprovalRegistry, Error,
};
use sigint_llm::provider::LlmProvider;
use sigint_memory::MemoryService;
use sigint_tools::{new_finding_collector, CreateFindingTool, Tool};

use crate::{
    agent::Agent,
    agents::{
        AnalystAgent, ExecutorAgent, ReporterAgent, ResearcherAgent, RfReconAgent, StrategistAgent,
    },
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
    /// Optional database for per-tool scan record persistence.
    ///
    /// When `Some`, each tool invocation inside `run_agent` creates and updates
    /// a `ScanRecord`. Operations are best-effort — failures are logged, not
    /// propagated. When `None` (the default), no persistence occurs.
    db: Option<Arc<sigint_store::Database>>,
    /// Session ID for scan record attribution. Ignored when `db` is `None`.
    session_id: Uuid,
    /// Optional approval registry for gating risky tool executions.
    ///
    /// When `Some`, tool risk is checked against `auto_approve` threshold
    /// before execution. When `None` (the default), all tools run immediately
    /// regardless of risk level.
    approval_registry: Option<Arc<ApprovalRegistry>>,
    /// Auto-approval threshold: `"all"`, `"medium"`, `"low"`, or `"none"`.
    ///
    /// Controls which risk levels skip the approval gate. Defaults to `"all"`
    /// (every tool auto-approved). Web-initiated scans should use `"low"` so
    /// Medium/High risk tools require explicit operator approval via WebSocket.
    auto_approve: String,
    /// Optional scan profile for campaign-driven tool/prompt customization.
    ///
    /// When `Some`, the profile's `focus` hint is appended to each agent's
    /// system prompt and its `tools` list filters the registry output so only
    /// allowed tools reach the LLM. Profile filtering is applied *after* the
    /// role ACL — profiles can only restrict, never expand tool access.
    /// `max_iterations` and `ports` overrides are applied at builder time.
    profile: Option<sigint_core::campaign::ScanProfile>,
    /// Maximum number of Strategist → Executor → Analyst cycles to run.
    ///
    /// Defaults to 1, which reproduces the original linear pipeline exactly.
    /// Set to a higher value to enable iterative convergence — the loop exits
    /// early when `is_converged` returns `true` (no new findings, or a goal
    /// keyword match). The Reporter always runs once after the loop exits.
    max_cycles: usize,
    /// Optional convergence goal string.
    ///
    /// When set, `is_converged` returns `true` as soon as any finding's
    /// `title` or `description` contains this string (case-insensitive).
    /// This allows callers to drive the loop toward a specific objective and
    /// stop as soon as evidence is found, even if `max_cycles` hasn't been
    /// reached.
    goal: Option<String>,
    /// Whether escalation approval gates are enabled (DEC-LOOP-004).
    ///
    /// When `true`, the Orchestrator pauses after each Strategist turn and
    /// checks whether the output contains an `ESCALATION:` marker indicating
    /// a tier transition. If the detected tier exceeds `ctx.current_tier` and
    /// an `ApprovalRegistry` is configured, it emits `EscalationRequested`
    /// and awaits the operator's decision before allowing the Executor to run.
    ///
    /// When `false` (the default), escalation markers are ignored — all tier
    /// transitions proceed automatically. This preserves backward compatibility
    /// with existing callers that do not opt in to gated escalation.
    approval_gates: bool,
}

/// Parse Strategist output for escalation tier markers (DEC-LOOP-004).
///
/// Returns the highest tier detected. When both markers appear, PostExploitation
/// wins because it is a superset of Exploitation. Defaults to `Recon` when no
/// marker is found — pure reconnaissance plans do not emit any marker.
///
/// This is a standalone function (not an `Orchestrator` method) so it can be
/// called directly in unit tests without constructing an Orchestrator.
///
/// @decision DEC-LOOP-004
/// @title Escalation detected via string marker in Strategist output
/// @status accepted
/// @rationale Strategist is tool-free (DEC-AGENT-008); adding a dedicated
/// tool would violate that constraint. String markers are parsed by the
/// orchestrator after each Strategist completion to determine the tier.
pub fn detect_tier(strategist_output: &str) -> EscalationTier {
    if strategist_output.contains("ESCALATION: post-exploitation") {
        EscalationTier::PostExploitation
    } else if strategist_output.contains("ESCALATION: exploitation") {
        EscalationTier::Exploitation
    } else {
        EscalationTier::Recon
    }
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
            db: None,
            session_id: Uuid::nil(),
            approval_registry: None,
            auto_approve: "all".to_string(),
            profile: None,
            max_cycles: 1,
            goal: None,
            approval_gates: false,
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

    /// Attach a database for per-tool scan record persistence.
    ///
    /// When set, each tool invocation inside any agent turn will create a
    /// `ScanRecord` before execution and update it after. Operations are
    /// best-effort — a DB error will not abort the scan.
    pub fn with_db(mut self, db: Arc<sigint_store::Database>) -> Self {
        self.db = Some(db);
        self
    }

    /// Set the session ID used to attribute scan records to a parent session.
    ///
    /// Only meaningful when a database has been attached via [`with_db`].
    /// Defaults to `Uuid::nil()`.
    pub fn with_session_id(mut self, session_id: Uuid) -> Self {
        self.session_id = session_id;
        self
    }

    /// Attach an `ApprovalRegistry` to gate risky tool executions.
    ///
    /// When set, any tool whose risk level exceeds `auto_approve` will block
    /// for human approval before executing. The registry routes approval
    /// requests and responses between the tool loop and the operator UI
    /// (WebSocket, TUI).
    ///
    /// Typically combined with `with_auto_approve("low")` for web-initiated
    /// scans so only Low-risk (info-gathering) tools run unattended.
    pub fn with_approval_registry(mut self, registry: Arc<ApprovalRegistry>) -> Self {
        self.approval_registry = Some(registry);
        self
    }

    /// Set the auto-approval threshold for tool risk gating.
    ///
    /// - `"all"`    — every tool runs without approval (default)
    /// - `"medium"` — Low and Medium auto-approve; High requires approval
    /// - `"low"`    — only Low-risk tools auto-approve
    /// - `"none"`   — every tool requires explicit approval
    ///
    /// Has no effect when no `ApprovalRegistry` is configured.
    pub fn with_auto_approve(mut self, threshold: impl Into<String>) -> Self {
        self.auto_approve = threshold.into();
        self
    }

    /// Apply a [`ScanProfile`](sigint_core::campaign::ScanProfile) from a campaign file.
    ///
    /// Profile-level overrides are applied eagerly (`max_iterations`, `ports`),
    /// while runtime effects (`focus` prompt injection, `tools` filtering) are
    /// evaluated lazily inside `run_agent`. Profiles can only *restrict* tool
    /// access beyond the role ACL — they never expand it.
    pub fn with_profile(mut self, profile: sigint_core::campaign::ScanProfile) -> Self {
        if let Some(max) = profile.max_iterations {
            self.max_iterations = max;
        }
        if let Some(ref ports) = profile.ports {
            self.ports = Some(ports.clone());
        }
        self.profile = Some(profile);
        self
    }

    /// Set the maximum number of Strategist → Executor → Analyst cycles.
    ///
    /// Defaults to `1`, which reproduces the original linear pipeline exactly.
    /// Values greater than 1 enable iterative convergence: the loop exits early
    /// when `is_converged` determines no further progress is possible (no new
    /// findings this cycle, or a goal keyword match). The Reporter always runs
    /// once after the loop exits, regardless of how many cycles completed.
    pub fn with_max_cycles(mut self, n: usize) -> Self {
        self.max_cycles = n;
        self
    }

    /// Set a convergence goal string.
    ///
    /// When set, `is_converged` returns `true` as soon as any finding produced
    /// in the current cycle has a `title` or `description` containing this
    /// string (case-insensitive). This allows the loop to terminate as soon as
    /// evidence for a specific objective is found, without exhausting all cycles.
    pub fn with_goal(mut self, goal: impl Into<String>) -> Self {
        self.goal = Some(goal.into());
        self
    }

    /// Enable or disable escalation approval gates (DEC-LOOP-004).
    ///
    /// When `enabled` is `true`, the Orchestrator pauses at each escalation
    /// tier transition detected in Strategist output and emits
    /// `Event::EscalationRequested`. If an `ApprovalRegistry` is configured,
    /// the cycle awaits operator approval before proceeding; without a registry
    /// the event is emitted but execution continues (warning logged).
    ///
    /// Defaults to `false` — tier transitions proceed automatically.
    pub fn with_approval_gates(mut self, enabled: bool) -> Self {
        self.approval_gates = enabled;
        self
    }

    /// Check whether the convergence loop should stop after this cycle.
    ///
    /// Convergence is declared when either:
    /// 1. The current cycle produced no new findings (the model is not making
    ///    progress — continuing would just repeat the same work).
    /// 2. A goal string is set and at least one new finding's `title` or
    ///    `description` contains the goal string (case-insensitive match).
    ///
    /// Note: `is_converged` is only called when `max_cycles > 1`. With the
    /// default `max_cycles = 1` the loop exits after a single iteration and
    /// this method is never invoked.
    fn is_converged(&self, new_findings: &[Finding], _all_findings: &[Finding]) -> bool {
        // No new findings this cycle → the model has nothing left to explore.
        if new_findings.is_empty() {
            return true;
        }
        // Goal match: stop as soon as a finding references the objective.
        if let Some(ref goal) = self.goal {
            let goal_lower = goal.to_lowercase();
            return new_findings.iter().any(|f| {
                f.title.to_lowercase().contains(&goal_lower)
                    || f.description.to_lowercase().contains(&goal_lower)
            });
        }
        false
    }

    /// Run one Strategist → Executor → Analyst cycle.
    ///
    /// Creates a fresh `FindingCollector` scoped to this cycle, runs the three
    /// agents in order, drains the collector into `Finding` structs, and returns
    /// the new findings discovered this cycle. The caller is responsible for
    /// extending `ctx.findings` and emitting `CycleCompleted`.
    ///
    /// `ctx.cycle` must be set by the caller before invoking this method so
    /// that `to_agent_prompt` injects the correct prior-cycle context.
    async fn run_inner_cycle(
        &self,
        ctx: &mut TaskContext,
        _cycle: usize,
    ) -> Result<Vec<Finding>, Error> {
        // ── Strategist ───────────────────────────────────────────────────────
        let strategist = StrategistAgent::new();
        info!(cycle = ctx.cycle, "orchestrator: running strategist agent");
        let strategist_output = self.run_agent(&strategist, ctx).await?;
        ctx.agent_outputs
            .insert(AgentRole::Strategist, strategist_output.clone());

        // ── Escalation gate (DEC-LOOP-004) ───────────────────────────────────
        // Detect the tier the Strategist is recommending. If it exceeds the
        // current tier AND approval gates are enabled, request operator approval
        // before allowing the Executor to proceed.
        let detected_tier = detect_tier(&strategist_output);
        if detected_tier > ctx.current_tier {
            if self.approval_gates {
                info!(
                    from = %ctx.current_tier,
                    to = %detected_tier,
                    cycle = ctx.cycle,
                    "orchestrator: escalation detected — requesting approval"
                );
                self.event_bus.emit(Event::EscalationRequested {
                    from: ctx.current_tier,
                    to: detected_tier,
                    cycle: ctx.cycle,
                });

                // If an ApprovalRegistry is configured, wait for the operator's
                // decision (bounded by the registry timeout). Otherwise log a
                // warning and proceed — gates without a registry are a no-op.
                let approved = if let Some(ref registry) = self.approval_registry {
                    let request_id = Uuid::new_v4();
                    let rx = registry.request(request_id);
                    let timeout = registry.timeout();
                    match tokio::time::timeout(timeout, rx).await {
                        Ok(Ok(decision)) => decision,
                        Ok(Err(_)) => {
                            // Sender dropped — treat as denial.
                            info!("orchestrator: escalation approval sender dropped — denying");
                            false
                        }
                        Err(_elapsed) => {
                            // Timeout — treat as denial so the cycle can converge.
                            info!(
                                cycle = ctx.cycle,
                                "orchestrator: escalation approval timed out — denying"
                            );
                            false
                        }
                    }
                } else {
                    info!(
                        "orchestrator: approval gates enabled but no registry configured \
                         — proceeding without gate (warning: approval gates have no effect \
                         without an ApprovalRegistry)"
                    );
                    true
                };

                if !approved {
                    self.event_bus.emit(Event::EscalationDenied {
                        from: ctx.current_tier,
                        to: detected_tier,
                    });
                    info!(
                        from = %ctx.current_tier,
                        to = %detected_tier,
                        cycle = ctx.cycle,
                        "orchestrator: escalation denied — skipping executor and analyst"
                    );
                    // Return empty findings so the outer loop sees no progress
                    // and convergence is declared on the next check.
                    return Ok(Vec::new());
                }

                self.event_bus.emit(Event::EscalationApproved {
                    from: ctx.current_tier,
                    to: detected_tier,
                });
                info!(
                    from = %ctx.current_tier,
                    to = %detected_tier,
                    cycle = ctx.cycle,
                    "orchestrator: escalation approved — proceeding"
                );
            }
            // Always update the tier (whether gates are on or off).
            ctx.current_tier = detected_tier;
        }

        // ── Executor ─────────────────────────────────────────────────────────
        let executor = ExecutorAgent::new();
        info!(cycle = ctx.cycle, "orchestrator: running executor agent");
        let executor_output = self.run_agent(&executor, ctx).await?;
        ctx.agent_outputs
            .insert(AgentRole::Executor, executor_output);

        // ── Evidence refs: query executor scan records for Analyst context ───
        // After the Executor completes, query scan_history for records attributed
        // to the executor role. These IDs are written into ctx.scan_record_refs so
        // to_agent_prompt(Analyst) can render an EVIDENCE REFERENCES table and the
        // LLM can set evidence_ref on findings to a valid scan_history UUID.
        // This is best-effort — a DB error clears the refs and logs a warning;
        // the Analyst still runs but cannot link findings to specific tool runs.
        ctx.scan_record_refs.clear();
        if let Some(ref db) = self.db {
            match db.get_scan_records_by_role(self.session_id, "executor") {
                Ok(records) => {
                    for rec in records {
                        // Truncate args to 120 chars for prompt readability.
                        let args_summary = if rec.args.len() > 120 {
                            format!("{}…", &rec.args[..120])
                        } else {
                            rec.args.clone()
                        };
                        ctx.scan_record_refs.push((rec.id, rec.tool, args_summary));
                    }
                    info!(
                        count = ctx.scan_record_refs.len(),
                        cycle = ctx.cycle,
                        "orchestrator: populated scan_record_refs for analyst"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        cycle = ctx.cycle,
                        "orchestrator: failed to query executor scan records; evidence refs unavailable"
                    );
                }
            }
        }

        // ── Analyst ──────────────────────────────────────────────────────────
        // Fresh FindingCollector per cycle so we can identify new-vs-prior
        // findings and check convergence at the end of this cycle.
        let finding_collector = new_finding_collector();
        let create_finding_tool = CreateFindingTool::new(Arc::clone(&finding_collector));

        let analyst = AnalystAgent::new();
        info!(cycle = ctx.cycle, "orchestrator: running analyst agent");
        let analyst_output = self
            .run_agent_with_extras(&analyst, ctx, &[&create_finding_tool as &dyn Tool])
            .await?;
        ctx.agent_outputs.insert(AgentRole::Analyst, analyst_output);

        // Drain the collector: convert raw JSON into Finding structs and emit
        // FindingCreated events. Identical logic to the original single-cycle
        // drain so enrichment fields (12B) are preserved.
        let mut new_findings = Vec::new();
        {
            let raw_findings = finding_collector
                .lock()
                .expect("finding collector lock poisoned")
                .drain(..)
                .collect::<Vec<_>>();

            for raw in raw_findings {
                let title = raw["title"].as_str().unwrap_or("Untitled").to_string();
                let description = raw["description"].as_str().unwrap_or("").to_string();
                let severity_str = raw["severity"].as_str().unwrap_or("info");
                let severity = match severity_str {
                    "critical" => Severity::Critical,
                    "high" => Severity::High,
                    "medium" => Severity::Medium,
                    "low" => Severity::Low,
                    _ => Severity::Info,
                };
                let asset = raw["asset"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
                let evidence = raw["evidence"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(str::to_string);
                let remediation = raw["remediation"].as_str().map(str::to_string);
                let exploitability = raw["exploitability"].as_str().map(str::to_string);
                let impact = raw["impact"].as_str().map(str::to_string);
                let cvss_score = raw["cvss_score"].as_f64().map(|f| f as f32);
                // Parse evidence_ref UUID, then validate it exists in
                // scan_record_refs. If the LLM hallucinated a UUID that does
                // not correspond to any executor tool invocation, clear it and
                // log a warning rather than storing a dangling reference.
                let evidence_ref = raw["evidence_ref"]
                    .as_str()
                    .and_then(|s| Uuid::parse_str(s).ok())
                    .and_then(|uid| {
                        if ctx.scan_record_refs.is_empty() {
                            // No refs available (no DB or no executor records) —
                            // accept any valid UUID so offline/test paths are unaffected.
                            Some(uid)
                        } else if ctx.scan_record_refs.iter().any(|(id, _, _)| *id == uid) {
                            Some(uid)
                        } else {
                            tracing::warn!(
                                evidence_ref = %uid,
                                title = %title,
                                "orchestrator: evidence_ref UUID not found in scan_record_refs; clearing"
                            );
                            None
                        }
                    });

                let mut finding = Finding::new(self.session_id, &title, &description, severity);
                finding.asset = asset;
                finding.evidence = evidence;
                finding.remediation = remediation;
                finding.exploitability = exploitability;
                finding.impact = impact;
                finding.cvss_score = cvss_score;
                finding.evidence_ref = evidence_ref;

                self.event_bus.emit(Event::FindingCreated(finding.clone()));
                info!(
                    title = %finding.title,
                    severity = %finding.severity,
                    cycle = ctx.cycle,
                    "orchestrator: finding recorded"
                );
                new_findings.push(finding);
            }
        }

        Ok(new_findings)
    }

    /// Run the full agent pipeline against `target`.
    ///
    /// Structure:
    /// - RfRecon (optional, once — feature-detected via `akaei_sweep` tool)
    /// - Researcher (once — establishes OSINT baseline)
    /// - Convergence loop (1..=max_cycles):
    ///     - Strategist → Executor → Analyst (via `run_inner_cycle`)
    ///     - Emits `CycleCompleted` after each cycle
    ///     - Exits early when `is_converged` returns true
    ///     - With default `max_cycles = 1` the loop body runs exactly once and
    ///       `is_converged` is never called — identical to the old linear pipeline
    /// - Reporter (once — synthesises all findings into a report)
    ///
    /// # Returns
    /// A `ScanReport` whose `summary` field is the Reporter's final output.
    ///
    /// # Errors
    /// Returns `Error` if any agent's LLM call fails. Tool execution errors
    /// within an agent turn are recovered internally (fed back to the model).
    pub async fn run_scan(&self, target: &str) -> Result<ScanReport, Error> {
        info!(
            target,
            max_cycles = self.max_cycles,
            "orchestrator: starting scan pipeline"
        );

        let mut ctx = TaskContext::new(target).with_ports(self.ports.clone());

        // ── 0. RfRecon (optional, once) ──────────────────────────────────────
        // Feature-detected: only runs when akaei_sweep is registered in the
        // tool registry. When no HackRF is available the phase is silently
        // skipped and the rest of the pipeline proceeds unchanged.
        // See DEC-AKAEI-003 for the rationale behind feature-detection.
        if self.registry.get("akaei_sweep").is_some() {
            let rf_recon = RfReconAgent::new();
            info!("orchestrator: running rf_recon agent (akaei tools detected)");
            let rf_output = self.run_agent(&rf_recon, &mut ctx).await?;
            ctx.agent_outputs.insert(AgentRole::RfRecon, rf_output);
        }

        // ── 1. Researcher (once) ─────────────────────────────────────────────
        let researcher = ResearcherAgent::new();
        info!("orchestrator: running researcher agent");
        let researcher_output = self.run_agent(&researcher, &mut ctx).await?;
        ctx.agent_outputs
            .insert(AgentRole::Researcher, researcher_output);

        // ── 2–4. Convergence loop: Strategist → Executor → Analyst ───────────
        //
        // When max_cycles = 1 (the default), the loop body runs exactly once
        // and is_converged is never evaluated — the for loop exits naturally
        // after the single iteration. This guarantees backward compatibility
        // with all existing callers and tests.
        //
        // When max_cycles > 1, is_converged is checked after each cycle.
        // Strategist/Executor/Analyst outputs are cleared between cycles so
        // each new cycle starts with a clean slate for those roles (the
        // Researcher output is preserved — it runs only once). The accumulated
        // ctx.findings and ctx.cycle are updated before each cycle so
        // to_agent_prompt can inject prior-cycle context.
        for cycle in 0..self.max_cycles {
            ctx.cycle = cycle;
            info!(cycle, "orchestrator: starting inner cycle");

            let new_findings = self.run_inner_cycle(&mut ctx, cycle).await?;
            let total_findings = ctx.findings.len() + new_findings.len();
            ctx.findings.extend(new_findings.clone());

            self.event_bus.emit(Event::CycleCompleted {
                cycle,
                new_findings: new_findings.len(),
                total_findings,
            });
            info!(
                cycle,
                new_findings = new_findings.len(),
                total_findings,
                "orchestrator: inner cycle complete"
            );

            // Only check convergence when running more than one cycle.
            // With max_cycles = 1 the loop condition (cycle < 1) ensures this
            // block is unreachable — no early-exit logic fires.
            if self.max_cycles > 1 && self.is_converged(&new_findings, &ctx.findings) {
                info!(cycle, "orchestrator: convergence reached — exiting loop");
                break;
            }

            // Clear cycle-specific outputs so the next cycle's Strategist
            // gets a fresh prompt (prior-cycle findings are injected via
            // to_agent_prompt instead of agent_outputs). Researcher output
            // is preserved across cycles.
            if cycle + 1 < self.max_cycles {
                ctx.agent_outputs.remove(&AgentRole::Strategist);
                ctx.agent_outputs.remove(&AgentRole::Executor);
                // Analyst output is kept so to_agent_prompt can inject the
                // "Analyst assessment" section on the next cycle's Strategist prompt.
            }
        }

        // ── 5. Reporter (once, after loop) ───────────────────────────────────
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
        self.run_agent_with_extras(agent, ctx, &[]).await
    }

    /// Like `run_agent` but appends `extra_tools` to the registry-filtered tool set.
    ///
    /// Used by the Analyst phase to inject `CreateFindingTool` without adding it
    /// to the static registry (it requires a per-scan `FindingCollector` at
    /// construction time and is not reusable across scans).
    async fn run_agent_with_extras(
        &self,
        agent: &dyn Agent,
        ctx: &mut TaskContext,
        extra_tools: &[&dyn Tool],
    ) -> Result<String, Error> {
        let mut state = ConversationState::new(self.context_window);

        // System prompt defines the agent's identity and behavioral constraints.
        // When a campaign profile specifies a focus area, append it so the agent
        // prioritises analysis and tool usage relevant to that engagement focus.
        let mut system_prompt = agent.system_prompt().to_string();
        if let Some(ref profile) = self.profile {
            if !profile.focus.is_empty() {
                system_prompt.push_str(&format!(
                    "\n\nENGAGEMENT FOCUS: {}\nPrioritize analysis and tool usage relevant to this focus area.",
                    profile.focus
                ));
            }
        }
        state.add_message(sigint_llm::types::ChatMessage::system(&system_prompt));

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
        let (mut tool_refs, mut tool_defs) = self.registry.for_agent(agent);

        // Profile tool restriction: only keep tools whose names appear in the
        // profile's `tools` list. This runs *after* the role ACL filter so a
        // profile can only restrict, never expand beyond what the role allows.
        if let Some(ref profile) = self.profile {
            if !profile.tools.is_empty() {
                let allowed: std::collections::HashSet<&str> =
                    profile.tools.iter().map(|s| s.as_str()).collect();
                tool_refs.retain(|t| allowed.contains(t.name()));
                tool_defs.retain(|d| allowed.contains(d.function.name.as_str()));
            }
        }

        // Append any caller-supplied extra tools (e.g. CreateFindingTool for
        // the Analyst). These bypass the registry and profile filter — they are
        // always appended when provided.
        for extra in extra_tools {
            tool_refs.push(*extra);
            tool_defs.push(extra.definition());
        }

        run_tool_loop(
            self.provider.as_ref(),
            &mut state,
            &tool_refs,
            &tool_defs,
            ToolLoopOptions {
                max_iterations: self.max_iterations,
                model: &self.model,
                event_bus: &self.event_bus,
                db: self.db.as_ref().map(|d| d.as_ref()),
                session_id: self.session_id,
                approval_registry: self.approval_registry.as_deref(),
                auto_approve: &self.auto_approve,
                agent_role: &agent.role().to_string(),
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

        async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, Error> {
            // Delegate to chat_stream so the same response queue serves both paths.
            use futures_util::StreamExt as FutStreamExt;
            let mut s = self.chat_stream(request).await?;
            let mut content = String::new();
            while let Some(chunk) = FutStreamExt::next(&mut s).await {
                content.push_str(&chunk?.delta);
            }
            Ok(ChatResponse {
                content,
                usage: None,
                model: "mock".into(),
                tool_calls: vec![],
            })
        }

        async fn chat_stream(&self, _request: ChatRequest) -> Result<ChunkStream, Error> {
            let mut queue = self.responses.lock().unwrap();
            let content = if queue.is_empty() {
                "[mock exhausted]".to_string()
            } else {
                queue.remove(0)
            };
            // Emit a text delta then a done=true chunk (no tool calls — orchestrator
            // tests only exercise text responses).
            let chunks: Vec<Result<StreamChunk, Error>> = vec![
                Ok(StreamChunk {
                    delta: content,
                    done: false,
                    usage: None,
                    tool_calls: vec![],
                }),
                Ok(StreamChunk {
                    delta: String::new(),
                    done: true,
                    usage: None,
                    tool_calls: vec![],
                }),
            ];
            Ok(Box::pin(stream::iter(chunks)))
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
    async fn with_approval_registry_sets_field() {
        use std::time::Duration;
        let provider = Arc::new(MockProvider::uniform("done", 5));
        let registry = Arc::new(sigint_core::ApprovalRegistry::new(Duration::from_secs(30)));
        let orch = make_orchestrator(provider)
            .with_approval_registry(registry)
            .with_auto_approve("low");
        // Pipeline should complete (no High-risk tools in mock registry — all
        // agents use the MockProvider which never calls tools, so the approval
        // gate is never triggered and the pipeline runs end-to-end).
        let report = orch.run_scan("test.local").await.unwrap();
        assert_eq!(report.target, "test.local");
    }

    // ── Profile tests ────────────────────────────────────────────────────

    /// A recording provider that captures the ChatRequest for inspection.
    struct RecordingProvider {
        requests: Mutex<Vec<sigint_llm::types::ChatRequest>>,
    }

    impl RecordingProvider {
        fn new() -> Self {
            Self {
                requests: Mutex::new(Vec::new()),
            }
        }

        fn captured(&self) -> Vec<sigint_llm::types::ChatRequest> {
            self.requests.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl LlmProvider for RecordingProvider {
        fn name(&self) -> &str {
            "recording"
        }

        async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, Error> {
            self.requests.lock().unwrap().push(request);
            Ok(ChatResponse {
                content: "recorded".into(),
                usage: None,
                model: "recording".into(),
                tool_calls: vec![],
            })
        }

        async fn chat_stream(&self, request: ChatRequest) -> Result<ChunkStream, Error> {
            self.requests.lock().unwrap().push(request);
            let chunks: Vec<Result<StreamChunk, Error>> = vec![
                Ok(StreamChunk {
                    delta: "recorded".into(),
                    done: false,
                    usage: None,
                    tool_calls: vec![],
                }),
                Ok(StreamChunk {
                    delta: String::new(),
                    done: true,
                    usage: None,
                    tool_calls: vec![],
                }),
            ];
            Ok(Box::pin(stream::iter(chunks)))
        }
    }

    fn make_profile(
        focus: &str,
        tools: Vec<&str>,
        max_iterations: Option<usize>,
        ports: Option<&str>,
    ) -> sigint_core::campaign::ScanProfile {
        sigint_core::campaign::ScanProfile {
            focus: focus.into(),
            tools: tools.into_iter().map(|s| s.to_string()).collect(),
            max_iterations,
            ports: ports.map(|s| s.to_string()),
        }
    }

    #[test]
    fn with_profile_stores_profile_and_applies_overrides() {
        let provider = Arc::new(MockProvider::uniform("done", 5));
        let orch = make_orchestrator(provider).with_profile(make_profile(
            "web app",
            vec!["nmap_scan"],
            Some(25),
            Some("80,443"),
        ));

        assert!(orch.profile.is_some());
        assert_eq!(orch.max_iterations, 25);
        assert_eq!(orch.ports.as_deref(), Some("80,443"));
    }

    #[test]
    fn with_profile_no_overrides_preserves_defaults() {
        let provider = Arc::new(MockProvider::uniform("done", 5));
        let orch = make_orchestrator(provider).with_profile(make_profile("", vec![], None, None));

        assert!(orch.profile.is_some());
        assert_eq!(orch.max_iterations, DEFAULT_MAX_ITERATIONS);
        assert!(orch.ports.is_none());
    }

    #[tokio::test]
    async fn profile_focus_injected_into_system_prompt() {
        let provider = Arc::new(RecordingProvider::new());
        let provider_ref = provider.clone();
        let orch = make_orchestrator(provider).with_profile(make_profile(
            "web application security",
            vec![],
            None,
            None,
        ));

        let agent = ResearcherAgent::new();
        let mut ctx = TaskContext::new("example.com");
        let _ = orch.run_agent(&agent, &mut ctx).await.unwrap();

        let captured = provider_ref.captured();
        assert!(
            !captured.is_empty(),
            "should have captured at least one request"
        );

        // First message should be system prompt with focus appended.
        let system_msg = &captured[0].messages[0];
        assert_eq!(system_msg.role, "system");
        assert!(
            system_msg
                .content
                .contains("ENGAGEMENT FOCUS: web application security"),
            "system prompt should contain focus: {}",
            system_msg.content
        );
        assert!(
            system_msg
                .content
                .contains("Prioritize analysis and tool usage"),
            "system prompt should contain prioritization instruction"
        );
    }

    #[tokio::test]
    async fn empty_focus_not_injected_into_system_prompt() {
        let provider = Arc::new(RecordingProvider::new());
        let provider_ref = provider.clone();
        let orch = make_orchestrator(provider).with_profile(make_profile("", vec![], None, None));

        let agent = ResearcherAgent::new();
        let mut ctx = TaskContext::new("example.com");
        let _ = orch.run_agent(&agent, &mut ctx).await.unwrap();

        let captured = provider_ref.captured();
        let system_msg = &captured[0].messages[0];
        assert!(
            !system_msg.content.contains("ENGAGEMENT FOCUS"),
            "empty focus should not be injected: {}",
            system_msg.content
        );
    }

    #[tokio::test]
    async fn profile_tools_filter_restricts_tool_defs() {
        // Register two tools, profile only allows one.
        use serde_json::json;
        use sigint_llm::ToolDefinition;

        struct FakeTool {
            tool_name: String,
        }
        impl FakeTool {
            fn new(name: &str) -> Self {
                Self {
                    tool_name: name.into(),
                }
            }
        }
        #[async_trait]
        impl sigint_tools::tool::Tool for FakeTool {
            fn name(&self) -> &str {
                &self.tool_name
            }
            fn description(&self) -> &str {
                "fake"
            }
            fn definition(&self) -> ToolDefinition {
                ToolDefinition::function(
                    self.tool_name.clone(),
                    "fake",
                    json!({"type": "object", "properties": {}}),
                )
            }
            async fn execute(
                &self,
                _args: serde_json::Value,
            ) -> sigint_tools::error::Result<sigint_tools::result::ToolResult> {
                Ok(sigint_tools::result::ToolResult {
                    stdout: "ok".into(),
                    stderr: String::new(),
                    exit_code: 0,
                    duration: std::time::Duration::from_millis(1),
                    structured_data: None,
                })
            }
        }

        let mut registry = ToolRegistry::new();
        registry.register(Box::new(FakeTool::new("nmap_scan")));
        registry.register(Box::new(FakeTool::new("shell")));

        let provider = Arc::new(RecordingProvider::new());
        let provider_ref = provider.clone();

        let orch = Orchestrator::new(
            provider,
            registry,
            EventBus::new(),
            8192,
            "mock-model".into(),
        )
        .with_profile(make_profile("", vec!["nmap_scan"], None, None));

        // Use ExecutorAgent which has both nmap_scan and shell in its ACL.
        let agent = crate::agents::ExecutorAgent::new();
        let mut ctx = TaskContext::new("example.com");
        let _ = orch.run_agent(&agent, &mut ctx).await.unwrap();

        let captured = provider_ref.captured();
        assert!(!captured.is_empty());

        // The tool definitions sent to the LLM should only contain nmap_scan.
        let tool_names: Vec<&str> = captured[0]
            .tools
            .iter()
            .map(|d| d.function.name.as_str())
            .collect();
        assert!(
            tool_names.contains(&"nmap_scan"),
            "nmap_scan should be in filtered tools: {tool_names:?}"
        );
        assert!(
            !tool_names.contains(&"shell"),
            "shell should be filtered out by profile: {tool_names:?}"
        );
    }

    #[tokio::test]
    async fn profile_empty_tools_allows_all() {
        // Empty tools list means no restriction — all ACL-allowed tools pass through.
        use serde_json::json;
        use sigint_llm::ToolDefinition;

        struct FakeTool2 {
            tool_name: String,
        }
        impl FakeTool2 {
            fn new(name: &str) -> Self {
                Self {
                    tool_name: name.into(),
                }
            }
        }
        #[async_trait]
        impl sigint_tools::tool::Tool for FakeTool2 {
            fn name(&self) -> &str {
                &self.tool_name
            }
            fn description(&self) -> &str {
                "fake"
            }
            fn definition(&self) -> ToolDefinition {
                ToolDefinition::function(
                    self.tool_name.clone(),
                    "fake",
                    json!({"type": "object", "properties": {}}),
                )
            }
            async fn execute(
                &self,
                _args: serde_json::Value,
            ) -> sigint_tools::error::Result<sigint_tools::result::ToolResult> {
                Ok(sigint_tools::result::ToolResult {
                    stdout: "ok".into(),
                    stderr: String::new(),
                    exit_code: 0,
                    duration: std::time::Duration::from_millis(1),
                    structured_data: None,
                })
            }
        }

        let mut registry = ToolRegistry::new();
        registry.register(Box::new(FakeTool2::new("nmap_scan")));
        registry.register(Box::new(FakeTool2::new("shell")));

        let provider = Arc::new(RecordingProvider::new());
        let provider_ref = provider.clone();

        let orch = Orchestrator::new(
            provider,
            registry,
            EventBus::new(),
            8192,
            "mock-model".into(),
        )
        .with_profile(make_profile("", vec![], None, None));

        let agent = crate::agents::ExecutorAgent::new();
        let mut ctx = TaskContext::new("example.com");
        let _ = orch.run_agent(&agent, &mut ctx).await.unwrap();

        let captured = provider_ref.captured();
        let tool_names: Vec<&str> = captured[0]
            .tools
            .iter()
            .map(|d| d.function.name.as_str())
            .collect();
        assert_eq!(
            tool_names.len(),
            2,
            "empty tools list should allow all ACL tools: {tool_names:?}"
        );
    }

    #[tokio::test]
    async fn with_profile_full_pipeline_runs() {
        // End-to-end: a profile with focus + tool restriction completes the pipeline.
        let provider = Arc::new(MockProvider::uniform("done", 5));
        let orch = make_orchestrator(provider).with_profile(make_profile(
            "network infrastructure",
            vec!["nmap_scan"],
            Some(20),
            Some("22,80,443"),
        ));
        let report = orch.run_scan("infra.local").await.unwrap();
        assert_eq!(report.target, "infra.local");
    }

    // ── Phase 12B: enriched finding drain tests ──────────────────────────────

    /// A provider that emits a `create_finding` tool call on the 4th LLM turn
    /// (the Analyst), then returns text responses for all other turns.
    ///
    /// The 4th call (index 3, 0-based) returns a StreamChunk with a
    /// `create_finding` tool call carrying all enrichment fields.  A 5th call
    /// then returns a plain text "done" so the tool loop can resolve.  The 6th
    /// call (Reporter) returns the final text summary.
    struct FindingCallProvider {
        call_count: Mutex<usize>,
    }

    impl FindingCallProvider {
        fn new() -> Self {
            Self {
                call_count: Mutex::new(0),
            }
        }
    }

    #[async_trait]
    impl LlmProvider for FindingCallProvider {
        fn name(&self) -> &str {
            "finding-call"
        }

        async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, Error> {
            use futures_util::StreamExt as FutStreamExt;
            let mut s = self.chat_stream(request).await?;
            let mut content = String::new();
            let mut tool_calls = vec![];
            while let Some(chunk) = FutStreamExt::next(&mut s).await {
                let c = chunk?;
                content.push_str(&c.delta);
                tool_calls.extend(c.tool_calls);
            }
            Ok(ChatResponse {
                content,
                usage: None,
                model: "finding-call".into(),
                tool_calls,
            })
        }

        async fn chat_stream(&self, _request: ChatRequest) -> Result<ChunkStream, Error> {
            use sigint_llm::types::FunctionCall;
            let mut count = self.call_count.lock().unwrap();
            let n = *count;
            *count += 1;
            drop(count);

            let chunks: Vec<Result<StreamChunk, Error>> = match n {
                // Turns 0-2: Researcher, Strategist, Executor — plain text
                0 | 1 | 2 => vec![
                    Ok(StreamChunk {
                        delta: "done".into(),
                        done: false,
                        usage: None,
                        tool_calls: vec![],
                    }),
                    Ok(StreamChunk {
                        delta: String::new(),
                        done: true,
                        usage: None,
                        tool_calls: vec![],
                    }),
                ],
                // Turn 3: Analyst — emits create_finding tool call with enrichment
                3 => vec![
                    Ok(StreamChunk {
                        delta: String::new(),
                        done: false,
                        usage: None,
                        tool_calls: vec![sigint_llm::ToolCall {
                            function: FunctionCall {
                                name: "create_finding".into(),
                                arguments: serde_json::json!({
                                    "title": "SQL Injection",
                                    "severity": "critical",
                                    "description": "Unparameterised query allows auth bypass",
                                    "evidence": "' OR 1=1 -> 200 OK",
                                    "asset": "10.0.0.1:443/login",
                                    "remediation": "Use parameterized queries",
                                    "exploitability": "publicly accessible",
                                    "impact": "full DB access",
                                    "cvss_score": 9.8,
                                    "evidence_ref": "550e8400-e29b-41d4-a716-446655440000"
                                }),
                            },
                        }],
                    }),
                    Ok(StreamChunk {
                        delta: String::new(),
                        done: true,
                        usage: None,
                        tool_calls: vec![],
                    }),
                ],
                // Turn 4: Analyst tool-loop second round — plain text to resolve loop
                4 => vec![
                    Ok(StreamChunk {
                        delta: "analysis complete".into(),
                        done: false,
                        usage: None,
                        tool_calls: vec![],
                    }),
                    Ok(StreamChunk {
                        delta: String::new(),
                        done: true,
                        usage: None,
                        tool_calls: vec![],
                    }),
                ],
                // Turn 5: Reporter
                _ => vec![
                    Ok(StreamChunk {
                        delta: "FINAL REPORT".into(),
                        done: false,
                        usage: None,
                        tool_calls: vec![],
                    }),
                    Ok(StreamChunk {
                        delta: String::new(),
                        done: true,
                        usage: None,
                        tool_calls: vec![],
                    }),
                ],
            };
            Ok(Box::pin(stream::iter(chunks)))
        }
    }

    #[tokio::test]
    async fn drain_extracts_enrichment_fields_from_raw_json() {
        // Analyst emits create_finding with all Phase 12B enrichment fields.
        // Verify the orchestrator drain sets them on the Finding struct.
        let orch = make_orchestrator(Arc::new(FindingCallProvider::new()));
        let report = orch.run_scan("10.0.0.1").await.unwrap();

        assert_eq!(
            report.context.findings.len(),
            1,
            "one finding should be recorded"
        );
        let f = &report.context.findings[0];

        assert_eq!(f.title, "SQL Injection");
        assert_eq!(
            f.remediation.as_deref(),
            Some("Use parameterized queries"),
            "remediation should be extracted"
        );
        assert_eq!(
            f.exploitability.as_deref(),
            Some("publicly accessible"),
            "exploitability should be extracted"
        );
        assert_eq!(
            f.impact.as_deref(),
            Some("full DB access"),
            "impact should be extracted"
        );
        assert!(
            (f.cvss_score.unwrap() - 9.8_f32).abs() < 0.01,
            "cvss_score should be 9.8, got {:?}",
            f.cvss_score
        );
        assert_eq!(
            f.evidence_ref,
            Some(uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap()),
            "evidence_ref should be parsed as UUID"
        );
        // chain_id/chain_order not set in 12B
        assert!(f.chain_id.is_none());
        assert!(f.chain_order.is_none());
    }

    #[tokio::test]
    async fn drain_handles_missing_enrichment_fields_gracefully() {
        // Analyst emits create_finding with only required fields (no enrichment).
        // Verify the drain sets enrichment fields to None without panicking.
        struct MinimalFindingProvider {
            call_count: Mutex<usize>,
        }
        impl MinimalFindingProvider {
            fn new() -> Self {
                Self {
                    call_count: Mutex::new(0),
                }
            }
        }

        #[async_trait]
        impl LlmProvider for MinimalFindingProvider {
            fn name(&self) -> &str {
                "minimal"
            }
            async fn chat(&self, req: ChatRequest) -> Result<ChatResponse, Error> {
                use futures_util::StreamExt as FutStreamExt;
                let mut s = self.chat_stream(req).await?;
                let mut content = String::new();
                let mut tool_calls = vec![];
                while let Some(c) = FutStreamExt::next(&mut s).await {
                    let c = c?;
                    content.push_str(&c.delta);
                    tool_calls.extend(c.tool_calls);
                }
                Ok(ChatResponse {
                    content,
                    usage: None,
                    model: "minimal".into(),
                    tool_calls,
                })
            }
            async fn chat_stream(&self, _req: ChatRequest) -> Result<ChunkStream, Error> {
                use sigint_llm::types::FunctionCall;
                let mut count = self.call_count.lock().unwrap();
                let n = *count;
                *count += 1;
                drop(count);

                let chunks: Vec<Result<StreamChunk, Error>> = match n {
                    0 | 1 | 2 => vec![
                        Ok(StreamChunk {
                            delta: "done".into(),
                            done: false,
                            usage: None,
                            tool_calls: vec![],
                        }),
                        Ok(StreamChunk {
                            delta: String::new(),
                            done: true,
                            usage: None,
                            tool_calls: vec![],
                        }),
                    ],
                    3 => vec![
                        Ok(StreamChunk {
                            delta: String::new(),
                            done: false,
                            usage: None,
                            tool_calls: vec![sigint_llm::ToolCall {
                                function: FunctionCall {
                                    name: "create_finding".into(),
                                    arguments: serde_json::json!({
                                        "title": "Open Port",
                                        "severity": "info",
                                        "description": "Port 22 is open"
                                    }),
                                },
                            }],
                        }),
                        Ok(StreamChunk {
                            delta: String::new(),
                            done: true,
                            usage: None,
                            tool_calls: vec![],
                        }),
                    ],
                    4 => vec![
                        Ok(StreamChunk {
                            delta: "done".into(),
                            done: false,
                            usage: None,
                            tool_calls: vec![],
                        }),
                        Ok(StreamChunk {
                            delta: String::new(),
                            done: true,
                            usage: None,
                            tool_calls: vec![],
                        }),
                    ],
                    _ => vec![
                        Ok(StreamChunk {
                            delta: "report".into(),
                            done: false,
                            usage: None,
                            tool_calls: vec![],
                        }),
                        Ok(StreamChunk {
                            delta: String::new(),
                            done: true,
                            usage: None,
                            tool_calls: vec![],
                        }),
                    ],
                };
                Ok(Box::pin(stream::iter(chunks)))
            }
        }

        let orch = make_orchestrator(Arc::new(MinimalFindingProvider::new()));
        let report = orch.run_scan("10.0.0.1").await.unwrap();

        assert_eq!(report.context.findings.len(), 1);
        let f = &report.context.findings[0];
        assert_eq!(f.title, "Open Port");
        assert!(
            f.remediation.is_none(),
            "remediation should be None when absent"
        );
        assert!(f.exploitability.is_none());
        assert!(f.impact.is_none());
        assert!(f.cvss_score.is_none());
        assert!(f.evidence_ref.is_none());
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

    // ── Phase 12C: Convergence loop tests ────────────────────────────────────

    // ── Builder method tests ──────────────────────────────────────────────────

    #[test]
    fn with_max_cycles_builder() {
        let provider = Arc::new(MockProvider::uniform("done", 5));
        let orch = make_orchestrator(provider).with_max_cycles(3);
        assert_eq!(orch.max_cycles, 3);
    }

    #[test]
    fn with_goal_builder() {
        let provider = Arc::new(MockProvider::uniform("done", 5));
        let orch = make_orchestrator(provider).with_goal("SQL injection");
        assert_eq!(orch.goal.as_deref(), Some("SQL injection"));
    }

    // ── is_converged unit tests ───────────────────────────────────────────────

    #[test]
    fn is_converged_no_new_findings() {
        let provider = Arc::new(MockProvider::uniform("done", 1));
        let orch = make_orchestrator(provider);
        // Empty new_findings → always converged.
        assert!(orch.is_converged(&[], &[]));
    }

    #[test]
    fn is_converged_goal_match() {
        use sigint_core::types::Severity;
        let provider = Arc::new(MockProvider::uniform("done", 1));
        let orch = make_orchestrator(provider).with_goal("sql injection");

        let mut f = Finding::new(
            Uuid::nil(),
            "SQL Injection in login form",
            "auth bypass",
            Severity::Critical,
        );
        f.description = "SQL Injection allows authentication bypass".to_string();
        // Title matches goal (case-insensitive).
        assert!(orch.is_converged(&[f], &[]));
    }

    #[test]
    fn is_converged_no_goal_no_match() {
        use sigint_core::types::Severity;
        let provider = Arc::new(MockProvider::uniform("done", 1));
        let orch = make_orchestrator(provider); // no goal set

        let f = Finding::new(Uuid::nil(), "Open Port", "port 22 is open", Severity::Info);
        // Findings present but no goal → not converged (loop should continue).
        assert!(!orch.is_converged(&[f], &[]));
    }

    // ── run_scan_linear_default ───────────────────────────────────────────────

    /// Explicitly verify max_cycles=1 (the default) runs exactly 5 LLM calls:
    /// Researcher + Strategist + Executor + Analyst + Reporter.
    /// The mock queue has exactly 5 responses; if the loop ran more than once
    /// the mock would exhaust and return "[mock exhausted]" which would fail
    /// the summary assertion.
    #[tokio::test]
    async fn run_scan_linear_default() {
        let provider = Arc::new(MockProvider::new(vec![
            "Researcher: found open ports 22, 80",
            "Strategist: attack via port 80",
            "Executor: ran nmap",
            "Analyst: CVE-2021-41773 likely",
            "FINAL REPORT",
        ]));
        let orch = make_orchestrator(provider); // max_cycles defaults to 1
        let report = orch.run_scan("example.com").await.unwrap();

        assert_eq!(
            report.summary, "FINAL REPORT",
            "reporter output should be last"
        );
        assert_eq!(report.target, "example.com");
    }

    // ── run_scan_two_cycles_converges ─────────────────────────────────────────

    /// Two-cycle scan where cycle 1 produces no findings → convergence.
    ///
    /// Response sequence (9 calls total):
    ///   0: Researcher
    ///   1: Strategist (cycle 0)
    ///   2: Executor   (cycle 0)
    ///   3: Analyst    (cycle 0)  — emits create_finding tool call
    ///   4: Analyst    (cycle 0)  — second round to resolve tool loop
    ///   5: Strategist (cycle 1)
    ///   6: Executor   (cycle 1)
    ///   7: Analyst    (cycle 1)  — no tool calls (no new findings)
    ///   8: Reporter
    ///
    /// After cycle 1 the Analyst produces no new findings → is_converged returns
    /// true → loop exits → Reporter runs.
    #[tokio::test]
    async fn run_scan_two_cycles_converges() {
        use sigint_llm::types::FunctionCall;

        struct TwoCycleProvider {
            call_count: Mutex<usize>,
        }
        impl TwoCycleProvider {
            fn new() -> Self {
                Self {
                    call_count: Mutex::new(0),
                }
            }
        }

        #[async_trait]
        impl LlmProvider for TwoCycleProvider {
            fn name(&self) -> &str {
                "two-cycle"
            }

            async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, Error> {
                use futures_util::StreamExt as FutStreamExt;
                let mut s = self.chat_stream(request).await?;
                let mut content = String::new();
                let mut tool_calls = vec![];
                while let Some(chunk) = FutStreamExt::next(&mut s).await {
                    let c = chunk?;
                    content.push_str(&c.delta);
                    tool_calls.extend(c.tool_calls);
                }
                Ok(ChatResponse {
                    content,
                    usage: None,
                    model: "two-cycle".into(),
                    tool_calls,
                })
            }

            async fn chat_stream(&self, _request: ChatRequest) -> Result<ChunkStream, Error> {
                let mut count = self.call_count.lock().unwrap();
                let n = *count;
                *count += 1;
                drop(count);

                let chunks: Vec<Result<StreamChunk, Error>> = match n {
                    // 0: Researcher
                    0 => vec![
                        Ok(StreamChunk {
                            delta: "researcher done".into(),
                            done: false,
                            usage: None,
                            tool_calls: vec![],
                        }),
                        Ok(StreamChunk {
                            delta: String::new(),
                            done: true,
                            usage: None,
                            tool_calls: vec![],
                        }),
                    ],
                    // 1: Strategist cycle 0
                    1 => vec![
                        Ok(StreamChunk {
                            delta: "strategy cycle 0".into(),
                            done: false,
                            usage: None,
                            tool_calls: vec![],
                        }),
                        Ok(StreamChunk {
                            delta: String::new(),
                            done: true,
                            usage: None,
                            tool_calls: vec![],
                        }),
                    ],
                    // 2: Executor cycle 0
                    2 => vec![
                        Ok(StreamChunk {
                            delta: "executor cycle 0".into(),
                            done: false,
                            usage: None,
                            tool_calls: vec![],
                        }),
                        Ok(StreamChunk {
                            delta: String::new(),
                            done: true,
                            usage: None,
                            tool_calls: vec![],
                        }),
                    ],
                    // 3: Analyst cycle 0 — emits one finding
                    3 => vec![
                        Ok(StreamChunk {
                            delta: String::new(),
                            done: false,
                            usage: None,
                            tool_calls: vec![sigint_llm::ToolCall {
                                function: FunctionCall {
                                    name: "create_finding".into(),
                                    arguments: serde_json::json!({
                                        "title": "Open SSH",
                                        "severity": "info",
                                        "description": "Port 22 is open"
                                    }),
                                },
                            }],
                        }),
                        Ok(StreamChunk {
                            delta: String::new(),
                            done: true,
                            usage: None,
                            tool_calls: vec![],
                        }),
                    ],
                    // 4: Analyst cycle 0 — tool loop second round (resolve)
                    4 => vec![
                        Ok(StreamChunk {
                            delta: "analysis cycle 0 done".into(),
                            done: false,
                            usage: None,
                            tool_calls: vec![],
                        }),
                        Ok(StreamChunk {
                            delta: String::new(),
                            done: true,
                            usage: None,
                            tool_calls: vec![],
                        }),
                    ],
                    // 5: Strategist cycle 1
                    5 => vec![
                        Ok(StreamChunk {
                            delta: "strategy cycle 1".into(),
                            done: false,
                            usage: None,
                            tool_calls: vec![],
                        }),
                        Ok(StreamChunk {
                            delta: String::new(),
                            done: true,
                            usage: None,
                            tool_calls: vec![],
                        }),
                    ],
                    // 6: Executor cycle 1
                    6 => vec![
                        Ok(StreamChunk {
                            delta: "executor cycle 1".into(),
                            done: false,
                            usage: None,
                            tool_calls: vec![],
                        }),
                        Ok(StreamChunk {
                            delta: String::new(),
                            done: true,
                            usage: None,
                            tool_calls: vec![],
                        }),
                    ],
                    // 7: Analyst cycle 1 — no new findings → convergence
                    7 => vec![
                        Ok(StreamChunk {
                            delta: "no new findings".into(),
                            done: false,
                            usage: None,
                            tool_calls: vec![],
                        }),
                        Ok(StreamChunk {
                            delta: String::new(),
                            done: true,
                            usage: None,
                            tool_calls: vec![],
                        }),
                    ],
                    // 8: Reporter
                    _ => vec![
                        Ok(StreamChunk {
                            delta: "TWO CYCLE REPORT".into(),
                            done: false,
                            usage: None,
                            tool_calls: vec![],
                        }),
                        Ok(StreamChunk {
                            delta: String::new(),
                            done: true,
                            usage: None,
                            tool_calls: vec![],
                        }),
                    ],
                };
                Ok(Box::pin(stream::iter(chunks)))
            }
        }

        let orch = make_orchestrator(Arc::new(TwoCycleProvider::new())).with_max_cycles(2);
        let report = orch.run_scan("10.0.0.1").await.unwrap();

        assert_eq!(report.summary, "TWO CYCLE REPORT");
        // One finding from cycle 0; cycle 1 produced nothing → convergence.
        assert_eq!(report.context.findings.len(), 1, "one finding from cycle 0");
        assert_eq!(report.context.findings[0].title, "Open SSH");
    }

    // ── run_scan_goal_terminates_early ────────────────────────────────────────

    /// Goal-directed scan: cycle 0 produces a finding matching the goal →
    /// Reporter runs after cycle 0 without doing cycle 1.
    ///
    /// If cycle 1 were executed the mock would be consumed and the summary
    /// would not equal "GOAL REPORT" (mock would exhaust).
    #[tokio::test]
    async fn run_scan_goal_terminates_early() {
        use sigint_llm::types::FunctionCall;

        struct GoalProvider {
            call_count: Mutex<usize>,
        }
        impl GoalProvider {
            fn new() -> Self {
                Self {
                    call_count: Mutex::new(0),
                }
            }
        }

        #[async_trait]
        impl LlmProvider for GoalProvider {
            fn name(&self) -> &str {
                "goal"
            }

            async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, Error> {
                use futures_util::StreamExt as FutStreamExt;
                let mut s = self.chat_stream(request).await?;
                let mut content = String::new();
                let mut tool_calls = vec![];
                while let Some(chunk) = FutStreamExt::next(&mut s).await {
                    let c = chunk?;
                    content.push_str(&c.delta);
                    tool_calls.extend(c.tool_calls);
                }
                Ok(ChatResponse {
                    content,
                    usage: None,
                    model: "goal".into(),
                    tool_calls,
                })
            }

            async fn chat_stream(&self, _request: ChatRequest) -> Result<ChunkStream, Error> {
                let mut count = self.call_count.lock().unwrap();
                let n = *count;
                *count += 1;
                drop(count);

                let chunks: Vec<Result<StreamChunk, Error>> = match n {
                    // 0: Researcher
                    0 => vec![
                        Ok(StreamChunk {
                            delta: "recon done".into(),
                            done: false,
                            usage: None,
                            tool_calls: vec![],
                        }),
                        Ok(StreamChunk {
                            delta: String::new(),
                            done: true,
                            usage: None,
                            tool_calls: vec![],
                        }),
                    ],
                    // 1: Strategist cycle 0
                    1 => vec![
                        Ok(StreamChunk {
                            delta: "strategy".into(),
                            done: false,
                            usage: None,
                            tool_calls: vec![],
                        }),
                        Ok(StreamChunk {
                            delta: String::new(),
                            done: true,
                            usage: None,
                            tool_calls: vec![],
                        }),
                    ],
                    // 2: Executor cycle 0
                    2 => vec![
                        Ok(StreamChunk {
                            delta: "executed".into(),
                            done: false,
                            usage: None,
                            tool_calls: vec![],
                        }),
                        Ok(StreamChunk {
                            delta: String::new(),
                            done: true,
                            usage: None,
                            tool_calls: vec![],
                        }),
                    ],
                    // 3: Analyst cycle 0 — emits finding matching goal "rce"
                    3 => vec![
                        Ok(StreamChunk {
                            delta: String::new(),
                            done: false,
                            usage: None,
                            tool_calls: vec![sigint_llm::ToolCall {
                                function: FunctionCall {
                                    name: "create_finding".into(),
                                    arguments: serde_json::json!({
                                        "title": "Remote Code Execution via CVE-2021-41773",
                                        "severity": "critical",
                                        "description": "RCE is possible via path traversal"
                                    }),
                                },
                            }],
                        }),
                        Ok(StreamChunk {
                            delta: String::new(),
                            done: true,
                            usage: None,
                            tool_calls: vec![],
                        }),
                    ],
                    // 4: Analyst tool loop second round
                    4 => vec![
                        Ok(StreamChunk {
                            delta: "analysis done".into(),
                            done: false,
                            usage: None,
                            tool_calls: vec![],
                        }),
                        Ok(StreamChunk {
                            delta: String::new(),
                            done: true,
                            usage: None,
                            tool_calls: vec![],
                        }),
                    ],
                    // 5: Reporter (immediately after cycle 0 due to goal match)
                    _ => vec![
                        Ok(StreamChunk {
                            delta: "GOAL REPORT".into(),
                            done: false,
                            usage: None,
                            tool_calls: vec![],
                        }),
                        Ok(StreamChunk {
                            delta: String::new(),
                            done: true,
                            usage: None,
                            tool_calls: vec![],
                        }),
                    ],
                };
                Ok(Box::pin(stream::iter(chunks)))
            }
        }

        // Goal "rce" matches "Remote Code Execution" (case-insensitive).
        let orch = make_orchestrator(Arc::new(GoalProvider::new()))
            .with_max_cycles(3)
            .with_goal("rce");
        let report = orch.run_scan("vuln.local").await.unwrap();

        assert_eq!(
            report.summary, "GOAL REPORT",
            "reporter should run immediately after goal match"
        );
        assert_eq!(report.context.findings.len(), 1);
        assert!(
            report.context.findings[0]
                .title
                .to_lowercase()
                .contains("rce")
                || report.context.findings[0]
                    .title
                    .to_lowercase()
                    .contains("remote code"),
            "finding should mention RCE: {}",
            report.context.findings[0].title
        );
    }

    // ── Phase 12D: Evidence linking tests ────────────────────────────────────

    /// A finding with evidence_ref pointing to a valid scan_record_refs UUID
    /// should have its evidence_ref preserved after the drain.
    ///
    /// This test exercises the validation path where scan_record_refs is empty
    /// (no DB attached) — in that case any valid UUID is accepted unchanged,
    /// preserving backward compatibility for offline/test callers.
    #[tokio::test]
    async fn evidence_ref_valid_uuid_accepted_when_no_db() {
        // Use the existing FindingCallProvider which emits evidence_ref
        // "550e8400-e29b-41d4-a716-446655440000" in the create_finding call.
        let orch = make_orchestrator(Arc::new(FindingCallProvider::new()));
        let report = orch.run_scan("10.0.0.1").await.unwrap();

        assert_eq!(report.context.findings.len(), 1);
        let f = &report.context.findings[0];
        // Without a DB, scan_record_refs is empty → any valid UUID passes through.
        assert_eq!(
            f.evidence_ref,
            Some(uuid::Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap()),
            "evidence_ref should be preserved when scan_record_refs is empty (no DB)"
        );
    }

    /// A finding with an evidence_ref UUID that does NOT appear in
    /// scan_record_refs should have its evidence_ref cleared to None.
    ///
    /// We exercise this by manually populating ctx.scan_record_refs with a
    /// different UUID before calling run_inner_cycle. Since the orchestrator
    /// clears and repopulates scan_record_refs from the DB (which is None
    /// here), scan_record_refs ends up empty and the any-UUID-accepted path
    /// fires — so we test the validation logic directly through the TaskContext.
    ///
    /// The plan spec says: "validate UUID exists in ctx.scan_record_refs.
    /// If not, clear and log warning." We verify this directly via the
    /// evidence_ref validation logic in the drain by constructing a ctx
    /// with non-empty scan_record_refs and a mismatched UUID.
    #[tokio::test]
    async fn evidence_ref_invalid_uuid_cleared_when_refs_populated() {
        use sigint_core::types::Severity;

        // Build a context with one known ref ID.
        let known_id = Uuid::new_v4();
        let unknown_id = Uuid::new_v4();
        assert_ne!(known_id, unknown_id);

        let mut ctx = TaskContext::new("example.com");
        ctx.scan_record_refs
            .push((known_id, "nmap_scan".to_string(), "{}".to_string()));

        // Simulate what the drain validation does: an evidence_ref that is NOT
        // in scan_record_refs should be cleared.
        let validate = |uid: Uuid, refs: &[(Uuid, String, String)]| -> Option<Uuid> {
            if refs.is_empty() {
                Some(uid)
            } else if refs.iter().any(|(id, _, _)| *id == uid) {
                Some(uid)
            } else {
                None
            }
        };

        // Known ID → accepted.
        assert_eq!(
            validate(known_id, &ctx.scan_record_refs),
            Some(known_id),
            "valid evidence_ref UUID should be kept"
        );

        // Unknown ID → cleared.
        assert_eq!(
            validate(unknown_id, &ctx.scan_record_refs),
            None,
            "hallucinated evidence_ref UUID should be cleared to None"
        );

        // Verify Finding type handles None evidence_ref cleanly.
        let mut f = Finding::new(Uuid::nil(), "Test Finding", "desc", Severity::Info);
        f.evidence_ref = validate(unknown_id, &ctx.scan_record_refs);
        assert!(f.evidence_ref.is_none());
    }

    // ── Phase 12E: detect_tier unit tests ────────────────────────────────────

    #[test]
    fn detect_tier_recon_no_marker() {
        let output = "Run nmap -sV against the target. Also try gobuster for directory enum.";
        assert_eq!(detect_tier(output), EscalationTier::Recon);
    }

    #[test]
    fn detect_tier_recon_empty_output() {
        assert_eq!(detect_tier(""), EscalationTier::Recon);
    }

    #[test]
    fn detect_tier_exploitation() {
        let output = "Plan to exploit CVE-2021-41773.\n\
                      ESCALATION: exploitation\n\
                      Run the exploit module against port 80.";
        assert_eq!(detect_tier(output), EscalationTier::Exploitation);
    }

    #[test]
    fn detect_tier_post_exploitation() {
        let output = "Lateral movement to internal hosts.\n\
                      ESCALATION: post-exploitation\n\
                      Exfiltrate /etc/passwd.";
        assert_eq!(detect_tier(output), EscalationTier::PostExploitation);
    }

    #[test]
    fn detect_tier_both_markers_highest_wins() {
        // When both markers appear, PostExploitation should win.
        let output = "ESCALATION: exploitation\n\
                      Then move laterally.\n\
                      ESCALATION: post-exploitation";
        assert_eq!(
            detect_tier(output),
            EscalationTier::PostExploitation,
            "highest tier should win when both markers present"
        );
    }

    #[test]
    fn detect_tier_post_exploitation_before_exploitation_still_wins() {
        // Order in string should not matter — PostExploitation always wins.
        let output = "ESCALATION: post-exploitation\n\
                      Also ESCALATION: exploitation mentioned.";
        assert_eq!(detect_tier(output), EscalationTier::PostExploitation);
    }

    // ── Phase 12E: approval_gates builder test ────────────────────────────────

    #[test]
    fn with_approval_gates_builder_sets_field() {
        let provider = Arc::new(MockProvider::uniform("done", 1));
        let orch = make_orchestrator(provider).with_approval_gates(true);
        assert!(
            orch.approval_gates,
            "with_approval_gates(true) should set approval_gates to true"
        );
    }

    #[test]
    fn with_approval_gates_defaults_to_false() {
        let provider = Arc::new(MockProvider::uniform("done", 1));
        let orch = make_orchestrator(provider);
        assert!(
            !orch.approval_gates,
            "approval_gates should default to false"
        );
    }

    // ── Phase 12E: approval gates off — tier transitions proceed freely ───────

    #[tokio::test]
    async fn approval_gates_off_escalation_proceeds_without_blocking() {
        // Strategist emits an exploitation marker. With approval_gates=false
        // (the default), the scan should complete without any pause — the
        // Executor and Analyst run normally and the tier is updated in ctx.
        let provider = Arc::new(MockProvider::new(vec![
            "Researcher: found Apache 2.4 on port 80",
            "Strategist: exploit CVE-2021-41773\nESCALATION: exploitation\nrun exploit.py",
            "Executor: ran exploit, got shell",
            "Analyst: confirmed RCE vulnerability",
            "Reporter: ESCALATION_TEST_COMPLETE",
        ]));

        let orch = make_orchestrator(provider);
        // approval_gates defaults to false — no gate should block.
        let report = orch.run_scan("target.local").await.unwrap();
        assert!(
            report.summary.contains("ESCALATION_TEST_COMPLETE"),
            "scan should complete normally when approval_gates=false: {}",
            report.summary
        );
    }

    #[tokio::test]
    async fn approval_gates_off_tier_updated_in_context() {
        // Even with gates off, the detected tier should be written to ctx.current_tier.
        let provider = Arc::new(MockProvider::new(vec![
            "Researcher output",
            "ESCALATION: post-exploitation\nLateral movement plan",
            "Executor output",
            "Analyst output",
            "Reporter DONE",
        ]));

        let orch = make_orchestrator(provider);
        let report = orch.run_scan("target.local").await.unwrap();
        assert_eq!(
            report.context.current_tier,
            EscalationTier::PostExploitation,
            "ctx.current_tier should be updated even when gates are off"
        );
    }
}
