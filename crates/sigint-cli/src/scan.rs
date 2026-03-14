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
/// * `ports`          — Optional port specification forwarded to nmap (e.g. "80,443").
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
    ports: Option<String>,
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
    if let Some(ref p) = ports {
        println!("  ports  : {}", p);
    }
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
    // Wrapped in Arc so it can be cheaply shared with the interactive session
    // orchestrator (DEC-AGENT-014: Arc avoids lifetime parameters and enables
    // cheap fan-out to concurrent orchestrators).
    let provider: Arc<OllamaProvider> = Arc::new(OllamaProvider::from_config(&core.config.llm));

    // ── Session — create upfront so per-tool ScanRecords can reference it ─────
    // The session row MUST exist before the orchestrator runs because per-tool
    // ScanRecord inserts have a FOREIGN KEY constraint on session_id.
    // Best-effort: if the DB is unavailable the scan still runs.
    let scan_session_id = uuid::Uuid::new_v4();
    if let Ok(session_db) = Database::open(&db_path) {
        let session_name = format!(
            "scan-{}-{}",
            target.replace(['.', '/'], "-"),
            chrono::Utc::now().format("%Y%m%d-%H%M%S"),
        );
        let mut session = sigint_core::types::Session::new(&session_name).with_target(&target);
        session.id = scan_session_id;
        if let Err(e) = session_db.create_session(&session) {
            warn!("scan: cannot create session upfront: {e}");
        }
    }

    // ── Orchestrator ──────────────────────────────────────────────────────────
    let mut orchestrator = Orchestrator::new(
        provider.clone(),
        registry,
        core.events.clone(),
        context_window,
        model,
    )
    .with_max_iterations(max_iterations)
    .with_ports(ports)
    .with_session_id(scan_session_id);

    if let Some(memory) = memory_service {
        orchestrator = orchestrator.with_memory(memory);
    }

    // Attach the database so per-tool ScanRecords are written during the scan.
    // Best-effort: if the DB can't be opened, the scan still runs without persistence.
    if let Ok(scan_db) = Database::open(&db_path) {
        orchestrator = orchestrator.with_db(Arc::new(scan_db));
    }

    // ── Interactive session (TUI mode only) ───────────────────────────────────
    // When the TUI is active, spawn an InteractiveSession alongside the scan
    // pipeline so users can issue follow-up commands (e.g. `scan <target>`)
    // via the Chat input panel while the initial scan is running.
    //
    // A second Orchestrator is built for the interactive session because
    // Orchestrator is not Clone and `run_scan` takes `&self` — both can run
    // concurrently on the same Arc<dyn LlmProvider>. The provider Arc clone is
    // O(1); the tool registry is rebuilt cheaply from the same source.
    if use_tui {
        let interactive_provider: Arc<dyn sigint_llm::provider::LlmProvider> = provider.clone();
        let mut interactive_registry = ToolRegistry::new();
        for tool in sigint_tools::all_executor_tools() {
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

        let session = sigint_agents::InteractiveSession::new(
            interactive_orch,
            core.events.subscribe(),
            core.events.clone(),
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

    // ── Persist to database + episodic memory (best-effort) ──────────────────
    // Pass the pre-generated session_id so the summary record links to the
    // session row created upfront (and matches per-tool ScanRecords).
    let session_id = persist_scan(&core, &target, &report, scan_session_id).await;

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
/// The session was created upfront (before `run_scan`) so that per-tool
/// `ScanRecord` inserts during the pipeline can satisfy the FOREIGN KEY
/// constraint. This function serves as a fallback if the upfront create
/// failed, and always writes the aggregate pipeline summary.
///
/// Persists:
///   1. A `sessions` row keyed to this target, using the pre-generated
///      `session_id`. If the upfront create succeeded this is a harmless
///      no-op (duplicate-key error is ignored).
///   2. One `scan_history` row whose `tool` is "pipeline" and `output` is the
///      Reporter's final summary — an aggregate audit record alongside the
///      per-tool records written during execution.
///
/// All errors are logged as warnings; the scan result is never discarded
/// because persistence fails.
///
/// Returns the session UUID on success so callers can store episodic memory.
async fn persist_scan(
    core: &AppCore,
    target: &str,
    report: &sigint_agents::ScanReport,
    session_id: uuid::Uuid,
) -> Option<uuid::Uuid> {
    let db_path = core.config.resolved_db_path();
    let db = match Database::open(&db_path) {
        Ok(db) => db,
        Err(e) => {
            warn!("scan: cannot open database for persistence: {}", e);
            return None;
        }
    };

    // Attempt to create the session using the pre-generated ID.
    // The session was already created upfront before the orchestrator ran;
    // this is a fallback in case that failed (e.g. DB was transiently
    // unavailable). If the upfront create succeeded this will return a
    // duplicate-key error which we treat as a harmless no-op.
    let session_name = format!(
        "scan-{}-{}",
        target.replace(['.', '/'], "-"),
        chrono::Utc::now().format("%Y%m%d-%H%M%S"),
    );
    let mut session = sigint_core::types::Session::new(&session_name).with_target(target);
    session.id = session_id;
    // INSERT OR IGNORE semantics: ignore duplicate-key errors (upfront create
    // already succeeded), but warn on any other error.
    if let Err(e) = db.create_session(&session) {
        let msg = e.to_string();
        if msg.contains("UNIQUE constraint") || msg.contains("already exists") {
            // Session was created upfront — this is expected and harmless.
        } else {
            warn!("scan: cannot persist session: {}", e);
            return None;
        }
    }

    // Persist one aggregate scan_history row with the pipeline summary.
    let mut record = ScanRecord::new(
        session_id,
        "pipeline",
        serde_json::json!({"target": target}).to_string(),
    );
    record.output = Some(report.summary.clone());
    record.exit_code = Some(0);
    record.finished_at = Some(chrono::Utc::now().to_rfc3339());

    if let Err(e) = db.create_scan_record(&record) {
        warn!("scan: cannot persist scan history record: {}", e);
    }

    Some(session_id)
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
        run(core, "scanme.nmap.org".into(), None, None, 3, false, true)
            .await
            .expect("scan should complete without error");
    }
}
