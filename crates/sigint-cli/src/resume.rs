//! `sigint resume <session>` — resume a prior scan and diff findings.
//!
//! Mirrors the `scan.rs` pipeline but starts from an existing session:
//! 1. Look up a prior session by UUID prefix.
//! 2. Create a child session with `parent_session_id` linking to the prior.
//! 3. Run the full multi-agent scan pipeline against the same target.
//! 4. Auto-diff findings between prior and new sessions.
//! 5. Print the diff summary to stdout and emit ScanDiffCompleted for TUI.
//!
//! @decision DEC-RESUME-001
//! @title Resume creates a new child session, then auto-diffs after scan completion
//! @status accepted
//! @rationale Preserves the temporal record: each scan is its own session with
//! immutable findings. The parent_session_id link forms a chain that the UI
//! and reporting layers can traverse. Auto-diff after completion gives the user
//! immediate feedback on what changed without a separate `sigint diff` invocation.

use std::io::IsTerminal;
use std::sync::Arc;

use sigint_agents::{Orchestrator, ToolRegistry};
use sigint_core::diff::diff_findings;
use sigint_core::event::Event;
use sigint_core::{AppCore, Error};
use sigint_llm::{create_provider, LlmProvider};
use sigint_memory::MemoryService;
use sigint_store::{embedding_worker, Database, EmbeddingService, ScanRecord};
use tracing::warn;

/// Default model context window in tokens (same as scan.rs).
const DEFAULT_CONTEXT_WINDOW: usize = 8192;

/// Run the `sigint resume` pipeline.
///
/// # Arguments
/// * `core`             — Loaded AppCore (config + event bus).
/// * `session_prefix`   — UUID prefix (min 4 chars) of the prior session.
/// * `model`            — Optional model override (uses config default if None).
/// * `max_iterations`   — Hard cap on tool-call rounds per agent turn.
/// * `force_tui`        — `--tui` flag: force TUI mode on.
/// * `force_no_tui`     — `--no-tui` flag: force stdout mode.
pub async fn run(
    core: AppCore,
    session_prefix: String,
    model: Option<String>,
    max_iterations: usize,
    force_tui: bool,
    force_no_tui: bool,
) -> Result<(), Error> {
    // ── Look up prior session ─────────────────────────────────────────────────
    let db_path = core.config.resolved_db_path();
    let db = Database::open(&db_path)
        .map_err(|e| Error::Database(format!("Cannot open database: {e}")))?;

    let prior = db.get_session_by_prefix(&session_prefix)?;
    let target = prior.target.as_deref().ok_or_else(|| {
        Error::Other(format!(
            "Session {} has no target — cannot resume",
            &prior.id.to_string()[..8]
        ))
    })?;

    let target = target.to_string();
    let model = model.unwrap_or_else(|| core.config.llm.model.clone());

    // ── Banner ────────────────────────────────────────────────────────────────
    println!();
    println!("SIGINT — resume scan");
    println!("  prior  : {} ({})", &prior.id.to_string()[..8], prior.name);
    println!("  target : {}", target);
    println!("  model  : {}", model);
    println!("  agents : researcher → strategist → executor → analyst → reporter");
    println!();

    // ── TUI / stdout event display ────────────────────────────────────────────
    let use_tui = if force_tui {
        true
    } else if force_no_tui {
        false
    } else {
        std::io::stdout().is_terminal()
    };

    if use_tui {
        match sigint_tui::TuiApp::new(core.events.subscribe(), core.events.sender()) {
            Ok(tui) => {
                tokio::spawn(async move {
                    if let Err(e) = tui.run().await {
                        tracing::error!("TUI error: {e}");
                    }
                });
            }
            Err(e) => {
                warn!("TUI init failed, falling back to stdout: {e}");
                spawn_stdout_printer(core.events.subscribe());
            }
        }
    } else {
        spawn_stdout_printer(core.events.subscribe());
    }

    // ── Database + Memory + Embedding worker ──────────────────────────────────
    let context_window = if core.config.llm.context_window > 0 {
        core.config.llm.context_window
    } else {
        DEFAULT_CONTEXT_WINDOW
    };

    // Spawn background embedding worker (best-effort).
    if let Ok(worker_db) = Database::open(&db_path) {
        match EmbeddingService::new() {
            Ok(emb) => {
                tokio::spawn(embedding_worker(Arc::new(worker_db), Arc::new(emb)));
            }
            Err(e) => {
                warn!("Embedding worker not started (model unavailable): {e}");
            }
        }
    }

    // Build MemoryService for episodic recall (without embeddings).
    let memory_service = Database::open(&db_path)
        .ok()
        .map(|mem_db| MemoryService::new_without_embeddings(mem_db, context_window / 5));

    // ── Tool registry ─────────────────────────────────────────────────────────
    let mut registry = ToolRegistry::new();
    for tool in sigint_tools::all_executor_tools_with_config(&core.config.tools) {
        registry.register(tool);
    }

    // ── LLM provider ──────────────────────────────────────────────────────────
    let provider: Arc<dyn LlmProvider> = create_provider(&core.config.llm)?.into();

    // ── Child session — create upfront so per-tool ScanRecords reference it ──
    let mut child_session = sigint_core::types::Session::new(&format!("Resume of {}", prior.name));
    child_session.target = Some(target.clone());
    child_session.parent_session_id = Some(prior.id);
    let child_session_id = child_session.id;

    if let Ok(session_db) = Database::open(&db_path) {
        if let Err(e) = session_db.create_session(&child_session) {
            warn!("resume: cannot create child session upfront: {e}");
        }
    }

    // ── Orchestrator ──────────────────────────────────────────────────────────
    let mut orchestrator = Orchestrator::new(
        provider.clone(),
        registry,
        core.events.clone(),
        context_window,
        model.clone(),
    )
    .with_max_iterations(max_iterations)
    .with_session_id(child_session_id);

    if let Some(memory) = memory_service {
        orchestrator = orchestrator.with_memory(memory);
    }

    // Attach the database so per-tool ScanRecords are written during the scan.
    if let Ok(scan_db) = Database::open(&db_path) {
        orchestrator = orchestrator.with_db(Arc::new(scan_db));
    }

    // ── Interactive session (TUI mode only) ───────────────────────────────────
    if use_tui {
        let interactive_provider: Arc<dyn sigint_llm::provider::LlmProvider> = provider.clone();
        let mut interactive_registry = ToolRegistry::new();
        for tool in sigint_tools::all_executor_tools_with_config(&core.config.tools) {
            interactive_registry.register(tool);
        }
        let interactive_orch = Orchestrator::new(
            interactive_provider,
            interactive_registry,
            core.events.clone(),
            context_window,
            core.config.llm.model.clone(),
        )
        .with_max_iterations(max_iterations);

        let interactive_db = Database::open(&db_path).ok().map(Arc::new);
        let session = sigint_agents::InteractiveSession::new(
            interactive_orch,
            core.events.subscribe(),
            core.events.clone(),
            interactive_db,
        );
        tokio::spawn(async move {
            if let Err(e) = session.run().await {
                tracing::error!("interactive session error: {e}");
            }
        });
    }

    // ── Run the pipeline ──────────────────────────────────────────────────────
    let report = orchestrator.run_scan(&target).await.map_err(|e| {
        let msg = e.to_string();
        if msg.contains("connection refused") || msg.contains("Connection refused") {
            Error::Llm(format!(
                "Cannot reach Ollama. Is it running?\n  hint: ollama serve\n  (original: {})",
                msg
            ))
        } else {
            e
        }
    })?;

    // ── Display the report ────────────────────────────────────────────────────
    println!();
    println!("{}", report);

    // ── Persist pipeline summary (best-effort) ───────────────────────────────
    if let Ok(persist_db) = Database::open(&db_path) {
        let mut record = ScanRecord::new(
            child_session_id,
            "pipeline",
            serde_json::json!({"target": target, "resumed_from": prior.id.to_string()}).to_string(),
        );
        record.output = Some(report.summary.clone());
        record.exit_code = Some(0);
        record.finished_at = Some(chrono::Utc::now().to_rfc3339());
        if let Err(e) = persist_db.create_scan_record(&record) {
            warn!("resume: cannot persist scan history record: {e}");
        }
    }

    // Store episode summary so future scans recall this session.
    if let Ok(mem_db) = Database::open(&db_path) {
        let svc = MemoryService::new_without_embeddings(mem_db, context_window / 5);
        if let Err(e) = svc.store_episode(child_session_id, &report.summary) {
            warn!("Failed to store episode summary: {e}");
        }
    }

    // ── Auto-diff: compare prior findings vs new findings ─────────────────────
    let diff_result = Database::open(&db_path).ok().map(|diff_db| {
        let prior_findings = diff_db.get_findings(prior.id).unwrap_or_default();
        let new_findings = diff_db.get_findings(child_session_id).unwrap_or_default();
        diff_findings(prior.id, &prior_findings, child_session_id, &new_findings)
    });

    if let Some(diff) = diff_result {
        // Emit for TUI consumption
        core.events
            .emit(Event::ScanDiffCompleted { diff: diff.clone() });

        // Print diff summary to stdout
        println!();
        println!(
            "=== Scan Diff: {} vs {} ===",
            &prior.id.to_string()[..8],
            &child_session_id.to_string()[..8]
        );
        println!("New findings:       {}", diff.summary.new);
        println!("Fixed findings:     {}", diff.summary.fixed);
        println!("Unchanged findings: {}", diff.summary.unchanged);

        if !diff.new.is_empty() {
            println!();
            println!("--- New Findings ---");
            for f in &diff.new {
                println!(
                    "  [+] {} ({}) — {}",
                    f.title,
                    f.severity,
                    f.asset.as_deref().unwrap_or("-")
                );
            }
        }
        if !diff.fixed.is_empty() {
            println!();
            println!("--- Fixed Findings ---");
            for f in &diff.fixed {
                println!(
                    "  [-] {} ({}) — {}",
                    f.title,
                    f.severity,
                    f.asset.as_deref().unwrap_or("-")
                );
            }
        }
    }

    Ok(())
}

/// Spawn a detached task that prints tool/status events to stdout.
///
/// Identical to scan.rs — used when TUI is disabled or unavailable.
fn spawn_stdout_printer(mut event_rx: tokio::sync::broadcast::Receiver<Event>) {
    tokio::spawn(async move {
        loop {
            match event_rx.recv().await {
                Ok(Event::ToolStarted { name, .. }) => {
                    println!("[tool] Running {}...", name);
                }
                Ok(Event::ToolOutput { name, output }) => {
                    let preview = if output.len() > 200 {
                        format!("{}...", &output[..200])
                    } else {
                        output.clone()
                    };
                    println!("[tool] {}: {}", name, preview);
                }
                Ok(Event::ToolCompleted { name, exit_code }) => {
                    println!("[tool] {} completed (exit {})", name, exit_code);
                }
                Ok(Event::Status(msg)) => {
                    println!("[status] {}", msg);
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    warn!("event display: dropped {} events (lagged)", n);
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    break;
                }
            }
        }
    });
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use sigint_core::types::{Finding, Session, Severity};
    use sigint_core::diff::diff_findings;
    use sigint_store::Database;

    #[test]
    fn resume_finds_parent_and_creates_child_session() {
        let db = Database::open_in_memory().unwrap();
        let mut parent = Session::new("test-scan");
        parent.target = Some("scanme.nmap.org".to_string());
        db.create_session(&parent).unwrap();

        let prefix = &parent.id.to_string()[..8];
        let found = db.get_session_by_prefix(prefix).unwrap();
        assert_eq!(found.id, parent.id);
        assert_eq!(found.target.as_deref(), Some("scanme.nmap.org"));

        let mut child = Session::new("resume-scan");
        child.target = found.target.clone();
        child.parent_session_id = Some(found.id);
        db.create_session(&child).unwrap();

        let fetched = db.get_session(child.id).unwrap().unwrap();
        assert_eq!(fetched.parent_session_id, Some(parent.id));
        assert_eq!(fetched.target.as_deref(), Some("scanme.nmap.org"));
    }

    #[test]
    fn resume_session_without_target_errors() {
        let db = Database::open_in_memory().unwrap();
        let parent = Session::new("no-target");
        db.create_session(&parent).unwrap();

        let prefix = &parent.id.to_string()[..8];
        let found = db.get_session_by_prefix(prefix).unwrap();
        assert!(found.target.is_none(), "Session should have no target");
    }

    #[test]
    fn resume_diff_detects_new_findings() {
        let db = Database::open_in_memory().unwrap();

        // Prior session — no findings
        let mut prior = Session::new("prior-scan");
        prior.target = Some("example.com".to_string());
        db.create_session(&prior).unwrap();

        // Child session — one new finding
        let mut child = Session::new("resume-scan");
        child.target = Some("example.com".to_string());
        child.parent_session_id = Some(prior.id);
        db.create_session(&child).unwrap();

        let finding = Finding::new(child.id, "Open Port 80", "HTTP server detected", Severity::Medium);
        db.create_finding(&finding).unwrap();

        let prior_findings = db.get_findings(prior.id).unwrap();
        let child_findings = db.get_findings(child.id).unwrap();
        let diff = diff_findings(prior.id, &prior_findings, child.id, &child_findings);

        assert_eq!(diff.summary.new, 1);
        assert_eq!(diff.summary.fixed, 0);
        assert_eq!(diff.summary.unchanged, 0);
        assert_eq!(diff.new[0].title, "Open Port 80");
    }

    #[test]
    fn resume_diff_detects_fixed_findings() {
        let db = Database::open_in_memory().unwrap();

        // Prior session — one finding
        let mut prior = Session::new("prior-scan");
        prior.target = Some("example.com".to_string());
        db.create_session(&prior).unwrap();

        let finding = Finding::new(prior.id, "XSS in /login", "Reflected XSS", Severity::High);
        db.create_finding(&finding).unwrap();

        // Child session — no findings (XSS is fixed)
        let mut child = Session::new("resume-scan");
        child.target = Some("example.com".to_string());
        child.parent_session_id = Some(prior.id);
        db.create_session(&child).unwrap();

        let prior_findings = db.get_findings(prior.id).unwrap();
        let child_findings = db.get_findings(child.id).unwrap();
        let diff = diff_findings(prior.id, &prior_findings, child.id, &child_findings);

        assert_eq!(diff.summary.new, 0);
        assert_eq!(diff.summary.fixed, 1);
        assert_eq!(diff.summary.unchanged, 0);
        assert_eq!(diff.fixed[0].title, "XSS in /login");
    }

    #[test]
    fn resume_child_session_links_to_parent() {
        let db = Database::open_in_memory().unwrap();

        let parent = Session::new("original-scan").with_target("10.0.0.1");
        db.create_session(&parent).unwrap();

        let mut child = Session::new("Resume of original-scan");
        child.target = Some("10.0.0.1".to_string());
        child.parent_session_id = Some(parent.id);
        db.create_session(&child).unwrap();

        // Verify chain
        let fetched_child = db.get_session(child.id).unwrap().unwrap();
        assert_eq!(fetched_child.parent_session_id, Some(parent.id));

        let fetched_parent = db.get_session(parent.id).unwrap().unwrap();
        assert!(fetched_parent.parent_session_id.is_none());
    }
}
