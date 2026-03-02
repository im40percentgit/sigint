//! `sigint scan <target>` — multi-agent penetration scan command.
//!
//! Wires together the full Phase 2 pipeline:
//! 1. Initialise OllamaProvider from config (with optional model override).
//! 2. Register NmapTool and ShellTool in a ToolRegistry.
//! 3. Subscribe to the EventBus and print tool events to stdout as they arrive.
//! 4. Run the Orchestrator's five-agent pipeline against the target.
//! 5. Display the ScanReport.
//! 6. Persist the session and scan records to SQLite (best-effort, non-fatal).
//!
//! @decision DEC-CLI-001
//! @title scan command uses best-effort database persistence
//! @status accepted
//! @rationale A scan against a live target should never fail because the
//! database is unavailable or corrupt. All `db.*` calls are wrapped in
//! `if let Ok(...)` or logged with a warning. The scan output is always
//! printed to stdout regardless of persistence success. This makes the
//! command work in read-only environments and simplifies error handling
//! for the primary user-facing path.
//!
//! @decision DEC-CLI-002
//! @title Event display runs in a detached tokio task; scan does not block on it
//! @status accepted
//! @rationale The EventBus receiver loop must not block `orchestrator.run_scan`.
//! tokio::spawn creates a lightweight green thread that reads from the broadcast
//! receiver concurrently with the scan pipeline. The task is intentionally not
//! awaited — when the function returns and the EventBus is dropped, the broadcast
//! channel closes and the spawned task exits naturally via `RecvError::Closed`.

use std::io::IsTerminal;
use std::sync::Arc;

use sigint_agents::{Orchestrator, ToolRegistry};
use sigint_core::{event::Event, AppCore, Error};
use sigint_llm::OllamaProvider;
use sigint_memory::MemoryService;
use sigint_store::{embedding_worker, Database, EmbeddingService, ScanRecord};
use tracing::warn;

/// Default model context window in tokens.
///
/// 8 192 is a safe lower bound supported by all common Ollama models
/// (llama3.2, mistral, phi3). Larger context windows are used automatically
/// when the model supports them; this floor prevents prompt truncation on
/// smaller models.
const DEFAULT_CONTEXT_WINDOW: usize = 8192;

/// Run the `sigint scan` pipeline.
///
/// # Arguments
/// * `core`           — Loaded AppCore (config + event bus).
/// * `target`         — Hostname, IP, or CIDR range to scan.
/// * `model`          — Optional model override (uses config default if None).
/// * `max_iterations` — Hard cap on tool-call rounds per agent turn.
/// * `force_tui`      — `--tui` flag: force TUI mode on.
/// * `force_no_tui`   — `--no-tui` flag: force stdout mode.
///
/// TUI auto-detection: if neither flag is set, TUI is used when stdout is a
/// terminal (isatty). In CI or when piped, falls back to stdout event printer.
///
/// @decision DEC-P3-003
pub async fn run(
    core: AppCore,
    target: String,
    model: Option<String>,
    max_iterations: usize,
    force_tui: bool,
    force_no_tui: bool,
) -> Result<(), Error> {
    let model = model.unwrap_or_else(|| core.config.llm.model.clone());

    // ── Banner ────────────────────────────────────────────────────────────────
    println!();
    println!("SIGINT — multi-agent scan");
    println!("  target : {}", target);
    println!("  model  : {}", model);
    println!("  agents : researcher → strategist → executor → analyst → reporter");
    println!();

    // ── TUI / stdout event display ────────────────────────────────────────────
    // Subscribe before the scan starts so no events are missed.
    // DEC-P3-003: auto-detect via isatty; --tui/--no-tui override.
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
    let db_path = core.config.resolved_db_path();

    let context_window = if core.config.llm.context_window > 0 {
        core.config.llm.context_window
    } else {
        DEFAULT_CONTEXT_WINDOW
    };

    // Spawn background embedding worker (best-effort — skip if DB or model unavailable).
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

    // Build MemoryService for episodic recall (without embeddings — the worker
    // handles embedding in the background; recall_semantic requires a loaded model
    // which is expensive to hold in the scan path).
    let memory_service = Database::open(&db_path)
        .ok()
        .map(|db| MemoryService::new_without_embeddings(db, context_window / 5));

    // ── Tool registry ─────────────────────────────────────────────────────────
    let mut registry = ToolRegistry::new();
    for tool in sigint_tools::all_executor_tools() {
        registry.register(tool);
    }

    // ── LLM provider ──────────────────────────────────────────────────────────
    let provider = Arc::new(OllamaProvider::from_config(&core.config.llm));

    // ── Orchestrator ──────────────────────────────────────────────────────────
    let mut orchestrator = Orchestrator::new(
        provider,
        registry,
        core.events.clone(),
        context_window,
        model,
    )
    .with_max_iterations(max_iterations);

    if let Some(memory) = memory_service {
        orchestrator = orchestrator.with_memory(memory);
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

    // ── Persist to database + episodic memory (best-effort) ──────────────────
    let session_id = persist_scan(&core, &target, &report).await;

    // Store episode summary so future scans of the same target recall this session.
    if let Some(session_id) = session_id {
        if let Ok(mem_db) = Database::open(&db_path) {
            let svc = MemoryService::new_without_embeddings(mem_db, context_window / 5);
            if let Err(e) = svc.store_episode(session_id, &report.summary) {
                warn!("Failed to store episode summary: {e}");
            }
        }
    }

    Ok(())
}

/// Spawn a detached task that prints tool/status events to stdout.
///
/// Used when TUI is disabled or unavailable.
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

/// Persist the scan session and one summary record to SQLite.
///
/// The current `ToolResult` type carries stdout/stderr/exit_code but not the
/// tool name or arguments — those are resolved at call time by the loop engine
/// and are not re-attached to the result struct. Rather than inventing a lossy
/// workaround, we persist:
///   1. A `sessions` row keyed to this target.
///   2. One `scan_history` row whose `tool` is "pipeline" and `output` is the
///      Reporter's final summary. This gives a queryable audit trail while the
///      per-invocation records remain a future enhancement (tracked in the
///      TaskContext refactor work item).
///
/// All errors are logged as warnings; the scan result is never discarded
/// because persistence fails.
///
/// Returns the session UUID on success so callers can store episodic memory.
async fn persist_scan(
    core: &AppCore,
    target: &str,
    report: &sigint_agents::ScanReport,
) -> Option<uuid::Uuid> {
    let db_path = core.config.resolved_db_path();
    let db = match Database::open(&db_path) {
        Ok(db) => db,
        Err(e) => {
            warn!("scan: cannot open database for persistence: {}", e);
            return None;
        }
    };

    // Create a session record scoped to this scan.
    let session_name = format!(
        "scan-{}-{}",
        target.replace(['.', '/'], "-"),
        chrono::Utc::now().format("%Y%m%d-%H%M%S"),
    );
    let session = sigint_core::types::Session::new(&session_name).with_target(target);

    if let Err(e) = db.create_session(&session) {
        warn!("scan: cannot persist session: {}", e);
        return None;
    }

    // Persist one aggregate scan_history row with the pipeline summary.
    let mut record = ScanRecord::new(
        session.id,
        "pipeline",
        serde_json::json!({"target": target}).to_string(),
    );
    record.output = Some(report.summary.clone());
    record.exit_code = Some(0);
    record.finished_at = Some(chrono::Utc::now().to_rfc3339());

    if let Err(e) = db.create_scan_record(&record) {
        warn!("scan: cannot persist scan history record: {}", e);
    }

    Some(session.id)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use sigint_core::AppCore;

    // ── Clap argument parsing tests ───────────────────────────────────────────

    /// Mirror of the Scan variant in main.rs — used here to test argument parsing
    /// without depending on main.rs internals.
    #[derive(Parser, Debug)]
    #[command(name = "sigint")]
    struct TestCli {
        #[command(subcommand)]
        command: TestCommands,
    }

    #[derive(clap::Subcommand, Debug)]
    enum TestCommands {
        Scan {
            target: String,
            #[arg(short, long)]
            ports: Option<String>,
            #[arg(short, long)]
            model: Option<String>,
            #[arg(long, default_value = "10")]
            max_iterations: usize,
            #[arg(long)]
            tui: bool,
            #[arg(long)]
            no_tui: bool,
        },
    }

    #[test]
    fn parse_minimal_scan_command() {
        let cli = TestCli::parse_from(["sigint", "scan", "scanme.nmap.org"]);
        let TestCommands::Scan {
            target,
            ports,
            model,
            max_iterations,
            ..
        } = cli.command;
        assert_eq!(target, "scanme.nmap.org");
        assert!(ports.is_none());
        assert!(model.is_none());
        assert_eq!(max_iterations, 10, "should default to 10");
    }

    #[test]
    fn parse_full_scan_command() {
        let cli = TestCli::parse_from([
            "sigint",
            "scan",
            "192.168.1.1",
            "--ports",
            "80,443",
            "--model",
            "llama3.2",
            "--max-iterations",
            "5",
        ]);
        let TestCommands::Scan {
            target,
            ports,
            model,
            max_iterations,
            ..
        } = cli.command;
        assert_eq!(target, "192.168.1.1");
        assert_eq!(ports.as_deref(), Some("80,443"));
        assert_eq!(model.as_deref(), Some("llama3.2"));
        assert_eq!(max_iterations, 5);
    }

    #[test]
    fn parse_ip_range_target() {
        let cli = TestCli::parse_from(["sigint", "scan", "10.0.0.0/24"]);
        let TestCommands::Scan { target, .. } = cli.command;
        assert_eq!(target, "10.0.0.0/24");
    }

    #[test]
    fn parse_short_flags() {
        let cli = TestCli::parse_from([
            "sigint",
            "scan",
            "target.local",
            "-p",
            "22,80",
            "-m",
            "mistral",
        ]);
        let TestCommands::Scan {
            target,
            ports,
            model,
            ..
        } = cli.command;
        assert_eq!(target, "target.local");
        assert_eq!(ports.as_deref(), Some("22,80"));
        assert_eq!(model.as_deref(), Some("mistral"));
    }

    // ── scan_history CRUD tests ───────────────────────────────────────────────

    #[test]
    fn scan_record_new_has_valid_uuid() {
        let session_id = uuid::Uuid::new_v4();
        let record = ScanRecord::new(session_id, "nmap_scan", r#"{"target":"10.0.0.1"}"#);
        assert!(!record.id.is_nil());
        assert_eq!(record.session_id, session_id);
        assert_eq!(record.tool, "nmap_scan");
    }

    #[test]
    fn scan_history_crud_roundtrip() {
        let db = Database::open_in_memory().expect("in-memory db");

        // Create a session to satisfy the FK constraint.
        let session = sigint_core::types::Session::new("crud-test");
        db.create_session(&session).unwrap();

        let mut record = ScanRecord::new(session.id, "shell", r#"["ls","-la"]"#);
        record.output = Some("total 8\ndrwxr-xr-x  2 root root".into());
        record.exit_code = Some(0);
        record.finished_at = Some("2026-02-24T00:00:00Z".into());

        db.create_scan_record(&record).unwrap();

        let records = db.get_scan_records(session.id).unwrap();
        assert_eq!(records.len(), 1);

        let r = &records[0];
        assert_eq!(r.tool, "shell");
        assert_eq!(r.exit_code, Some(0));
        assert!(r.output.as_deref().unwrap().contains("drwxr-xr-x"));
        assert_eq!(r.finished_at.as_deref(), Some("2026-02-24T00:00:00Z"));
    }

    // ── Integration test (requires Ollama + sandbox) ──────────────────────────

    /// Full end-to-end scan: requires `ollama serve` and sandbox capabilities.
    /// Run with: cargo test -p sigint-cli -- --ignored
    #[tokio::test]
    #[ignore]
    async fn integration_scan_scanme_nmap_org() {
        let core = AppCore::default_for_test();
        run(core, "scanme.nmap.org".into(), None, 3, false, true)
            .await
            .expect("scan should complete without error");
    }
}
