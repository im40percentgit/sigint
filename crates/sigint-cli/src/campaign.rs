//! `sigint campaign run/status` — multi-target campaign scanning commands.
//!
//! Mirrors the `scan.rs` pipeline but iterates over multiple targets from a
//! campaign JSON file, grouping all sessions under a single Campaign record.
//!
//! @decision DEC-CLI-003
//! @title Campaign CLI commands mirror scan.rs pipeline per-target
//! @status accepted
//! @rationale Each target gets its own session, orchestrator, and tool registry
//! to avoid cross-target state contamination. The campaign record groups them
//! for reporting. Best-effort persistence follows scan.rs precedent: a scan
//! against a live target should never fail because the database is unavailable.

use std::sync::Arc;

use sigint_agents::{Orchestrator, ToolRegistry};
use sigint_core::campaign::CampaignFile;
use sigint_core::event::Event;
use sigint_core::types::Campaign;
use sigint_core::{AppCore, Error};
use sigint_llm::OllamaProvider;
use sigint_memory::MemoryService;
use sigint_store::{embedding_worker, Database, EmbeddingService, ScanRecord};
use tracing::warn;

/// Default model context window in tokens (same as scan.rs).
const DEFAULT_CONTEXT_WINDOW: usize = 8192;

/// Run a multi-target campaign from a JSON file.
///
/// # Arguments
/// * `core`   — Loaded AppCore (config + event bus).
/// * `file`   — Path to the campaign JSON file.
/// * `model`  — Optional model override (uses config default if None).
/// * `no_tui` — Force non-TUI mode.
pub async fn run(
    core: AppCore,
    file: String,
    model: Option<String>,
    no_tui: bool,
) -> Result<(), Error> {
    // ── Parse and validate campaign file ─────────────────────────────────────
    let contents = std::fs::read_to_string(&file)
        .map_err(|e| Error::Other(format!("Cannot read campaign file '{}': {}", file, e)))?;
    let campaign_file: CampaignFile = serde_json::from_str(&contents)
        .map_err(|e| Error::Other(format!("Invalid campaign JSON: {}", e)))?;
    campaign_file
        .validate()
        .map_err(|e| Error::Other(format!("Campaign validation failed: {}", e)))?;

    let model = model.unwrap_or_else(|| core.config.llm.model.clone());
    let target_count = campaign_file.targets.len();

    // ── Banner ───────────────────────────────────────────────────────────────
    println!();
    println!("SIGINT — campaign scan");
    println!("  file    : {}", file);
    println!("  targets : {}", target_count);
    println!("  model   : {}", model);
    println!("  agents  : researcher -> strategist -> executor -> analyst -> reporter");
    println!();

    // ── Event display ────────────────────────────────────────────────────────
    // Campaign mode always uses stdout printing (no TUI) unless we add
    // multi-target TUI support later.
    if !no_tui {
        // Even without --no-tui, campaign mode defaults to stdout for now.
    }
    spawn_stdout_printer(core.events.subscribe());

    // ── Database + Embedding worker ──────────────────────────────────────────
    let db_path = core.config.resolved_db_path();

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

    // ── Create Campaign record ───────────────────────────────────────────────
    let mut campaign = Campaign::new(format!(
        "campaign-{}",
        chrono::Utc::now().format("%Y%m%d-%H%M%S")
    ));
    campaign.file_path = Some(file.clone());
    let campaign_id = campaign.id;

    if let Ok(db) = Database::open(&db_path) {
        if let Err(e) = db.create_campaign(&campaign) {
            warn!("campaign: cannot create campaign record: {e}");
        }
    }

    println!("Campaign {} started", &campaign_id.to_string()[..8]);
    println!();

    // ── LLM provider (shared across targets) ────────────────────────────────
    let provider: Arc<OllamaProvider> = Arc::new(OllamaProvider::from_config(&core.config.llm));

    // ── Iterate targets ──────────────────────────────────────────────────────
    let mut completed = 0usize;
    let mut failed = 0usize;

    for (i, ct) in campaign_file.targets.iter().enumerate() {
        println!(
            "━━━ Target {}/{}: {} ({}) ━━━",
            i + 1,
            target_count,
            ct.name,
            ct.target
        );

        // Resolve profile (if not "default").
        let profile = if ct.profile != "default" {
            campaign_file.profiles.get(&ct.profile).cloned()
        } else {
            None
        };

        // Build MemoryService for episodic recall.
        let memory_service = Database::open(&db_path)
            .ok()
            .map(|db| MemoryService::new_without_embeddings(db, context_window / 5));

        // Build fresh tool registry per target.
        let mut registry = ToolRegistry::new();
        for tool in sigint_tools::all_executor_tools_with_config(&core.config.tools) {
            registry.register(tool);
        }

        // Create session linked to campaign.
        let session_name = format!(
            "campaign-{}-{}",
            ct.target.replace(['.', '/'], "-"),
            chrono::Utc::now().format("%Y%m%d-%H%M%S"),
        );
        let session = sigint_core::types::Session::new(&session_name)
            .with_target(&ct.target)
            .with_campaign_id(campaign_id);
        let session_id = session.id;

        if let Ok(session_db) = Database::open(&db_path) {
            if let Err(e) = session_db.create_session(&session) {
                warn!("campaign: cannot create session for {}: {e}", ct.target);
            }
        }

        // Build Orchestrator.
        let mut orchestrator = Orchestrator::new(
            provider.clone(),
            registry,
            core.events.clone(),
            context_window,
            model.clone(),
        )
        .with_max_iterations(10)
        .with_session_id(session_id);

        // Apply profile overrides if present.
        if let Some(prof) = profile {
            orchestrator = orchestrator.with_profile(prof);
        }

        if let Some(memory) = memory_service {
            orchestrator = orchestrator.with_memory(memory);
        }

        // Attach the database for per-tool ScanRecords.
        if let Ok(scan_db) = Database::open(&db_path) {
            orchestrator = orchestrator.with_db(Arc::new(scan_db));
        }

        // Run the pipeline for this target.
        match orchestrator.run_scan(&ct.target).await {
            Ok(report) => {
                println!();
                println!("{}", report);

                // Persist pipeline summary (best-effort).
                if let Ok(persist_db) = Database::open(&db_path) {
                    let mut record = ScanRecord::new(
                        session_id,
                        "pipeline",
                        serde_json::json!({"target": ct.target, "campaign_id": campaign_id.to_string()})
                            .to_string(),
                    );
                    record.output = Some(report.summary.clone());
                    record.exit_code = Some(0);
                    record.finished_at = Some(chrono::Utc::now().to_rfc3339());
                    if let Err(e) = persist_db.create_scan_record(&record) {
                        warn!(
                            "campaign: cannot persist scan record for {}: {e}",
                            ct.target
                        );
                    }
                }

                // Store episode summary for future recall.
                if let Ok(mem_db) = Database::open(&db_path) {
                    let svc = MemoryService::new_without_embeddings(mem_db, context_window / 5);
                    if let Err(e) = svc.store_episode(session_id, &report.summary) {
                        warn!("Failed to store episode summary: {e}");
                    }
                }

                completed += 1;
            }
            Err(e) => {
                eprintln!("  ERROR scanning {}: {}", ct.target, e);
                failed += 1;
            }
        }

        println!();
    }

    // ── Mark campaign completed ──────────────────────────────────────────────
    if let Ok(db) = Database::open(&db_path) {
        if let Err(e) = db.update_campaign_completed(campaign_id) {
            warn!("campaign: cannot mark campaign completed: {e}");
        }
    }

    // ── Summary ──────────────────────────────────────────────────────────────
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("CAMPAIGN COMPLETE");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("  Campaign : {}", &campaign_id.to_string()[..8]);
    println!("  Completed: {}/{}", completed, target_count);
    if failed > 0 {
        println!("  Failed   : {}", failed);
    }
    println!();

    Ok(())
}

/// Show the status of a campaign by UUID prefix.
pub async fn status(core: AppCore, prefix: String) -> Result<(), Error> {
    let db_path = core.config.resolved_db_path();
    let db = Database::open(&db_path)
        .map_err(|e| Error::Database(format!("Cannot open database: {e}")))?;

    let campaign = db.get_campaign_by_prefix(&prefix)?;
    let sessions = db.get_campaign_sessions(campaign.id)?;

    println!();
    println!("Campaign: {}", campaign.id);
    println!("  Name      : {}", campaign.name);
    if let Some(ref fp) = campaign.file_path {
        println!("  File      : {}", fp);
    }
    println!(
        "  Created   : {}",
        campaign.created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );
    if let Some(completed) = campaign.completed_at {
        println!(
            "  Completed : {}",
            completed.format("%Y-%m-%d %H:%M:%S UTC")
        );
    } else {
        println!("  Status    : in progress");
    }
    println!("  Sessions  : {}", sessions.len());

    if !sessions.is_empty() {
        println!();
        println!("  Linked Sessions:");
        for s in &sessions {
            println!(
                "    {} — {} ({})",
                &s.id.to_string()[..8],
                s.name,
                s.target.as_deref().unwrap_or("-"),
            );
        }
    }

    println!();
    Ok(())
}

/// Spawn a detached task that prints tool/status events to stdout.
///
/// Identical to scan.rs — used for campaign event display.
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
    use sigint_core::campaign::CampaignFile;

    #[test]
    fn parse_campaign_file_from_json() {
        let json = r#"{
            "profiles": {
                "web": { "tools": ["nmap_scan"], "focus": "web" }
            },
            "targets": [
                { "name": "Site", "target": "example.com", "profile": "web" }
            ]
        }"#;
        let cf: CampaignFile = serde_json::from_str(json).unwrap();
        cf.validate().unwrap();
        assert_eq!(cf.targets.len(), 1);
        assert_eq!(cf.targets[0].name, "Site");
        assert_eq!(cf.targets[0].target, "example.com");
        assert_eq!(cf.targets[0].profile, "web");
    }

    #[test]
    fn campaign_validation_catches_missing_profile() {
        let json = r#"{
            "targets": [
                { "name": "X", "target": "x.com", "profile": "bogus" }
            ]
        }"#;
        let cf: CampaignFile = serde_json::from_str(json).unwrap();
        assert!(cf.validate().is_err());
        assert!(cf.validate().unwrap_err().contains("bogus"));
    }

    #[test]
    fn campaign_validation_passes_default_profile() {
        let json = r#"{
            "targets": [
                { "name": "Test", "target": "example.com" }
            ]
        }"#;
        let cf: CampaignFile = serde_json::from_str(json).unwrap();
        cf.validate().unwrap();
        assert_eq!(cf.targets[0].profile, "default");
    }

    #[test]
    fn campaign_validation_catches_empty_targets() {
        let json = r#"{ "targets": [] }"#;
        let cf: CampaignFile = serde_json::from_str(json).unwrap();
        assert!(cf.validate().is_err());
    }

    #[test]
    fn campaign_file_with_multiple_targets() {
        let json = r#"{
            "profiles": {
                "web": { "tools": ["nmap_scan"], "focus": "web apps" },
                "infra": { "tools": ["nmap_scan", "shell"], "focus": "infrastructure", "max_iterations": 20 }
            },
            "targets": [
                { "name": "Site A", "target": "a.example.com", "profile": "web" },
                { "name": "Site B", "target": "b.example.com", "profile": "infra" },
                { "name": "Site C", "target": "c.example.com" }
            ]
        }"#;
        let cf: CampaignFile = serde_json::from_str(json).unwrap();
        cf.validate().unwrap();
        assert_eq!(cf.targets.len(), 3);
        assert_eq!(cf.targets[2].profile, "default");
        assert_eq!(cf.profiles["infra"].max_iterations, Some(20));
    }

    #[test]
    fn campaign_status_db_roundtrip() {
        use sigint_core::types::Campaign;
        use sigint_store::Database;

        let db = Database::open_in_memory().unwrap();
        let mut c = Campaign::new("test-campaign");
        c.file_path = Some("targets.json".to_string());
        db.create_campaign(&c).unwrap();

        let prefix = &c.id.to_string()[..8];
        let found = db.get_campaign_by_prefix(prefix).unwrap();
        assert_eq!(found.id, c.id);
        assert_eq!(found.name, "test-campaign");

        let sessions = db.get_campaign_sessions(c.id).unwrap();
        assert!(sessions.is_empty());
    }
}
