//! `sigint recon <target>` — attack surface reconnaissance subcommand.
//!
//! Wires together the Phase 4 recon pipeline:
//! 1. Open (or create) the scan session in the database.
//! 2. Build a ReconEngine with optional module filter.
//! 3. Subscribe to the EventBus and print recon events to stdout.
//! 4. Run the engine's discovery pipeline against the target.
//! 5. Print a summary of discovered assets.
//! 6. If `--watch` is given, re-run every 300 seconds until Ctrl-C.
//!
//! @decision DEC-4D-RECON-001
//! @title recon command uses best-effort persistence matching scan.rs pattern
//! @status accepted
//! @rationale Consistent with DEC-CLI-001 in scan.rs: the recon run must not
//! fail because the database is unavailable. If Database::open fails, we log
//! an error and exit. All subsequent DB calls are wrapped best-effort. This
//! makes the command work in read-only environments and keeps the primary
//! user-facing output (asset list) always available.
//!
//! @decision DEC-4D-RECON-002
//! @title ReconEngine borrows &Database and &EventBus — both live for the scope of run()
//! @status accepted
//! @rationale ReconEngine<'a> takes &'a Database and &'a EventBus. All three
//! are created on the stack inside run() and the engine is consumed by .run()
//! before any of them are dropped, so the lifetimes are sound. This avoids
//! wrapping Database in Arc<Mutex<>> for the CLI path.

use sigint_core::{event::Event, AppCore, Error};
use sigint_recon::ReconEngine;
use sigint_store::Database;
use tracing::warn;

/// Arguments for the `recon` subcommand.
pub struct ReconArgs {
    /// Target domain, hostname, or IP address.
    pub target: String,
    /// Comma-separated list of module names to enable (None = all modules).
    pub modules: Option<String>,
    /// Continuous mode: re-run every 300 seconds until Ctrl-C.
    pub watch: bool,
}

/// Run the `sigint recon` pipeline.
pub async fn run(core: AppCore, args: ReconArgs) -> Result<(), Error> {
    println!("SIGINT — recon scan");
    println!("  target : {}", args.target);
    if let Some(ref modules) = args.modules {
        println!("  modules: {}", modules);
    }
    println!();

    let db_path = core.config.resolved_db_path();
    let db = Database::open(&db_path).map_err(|e| {
        Error::Database(format!("cannot open database at {:?}: {}", db_path, e))
    })?;

    // Create a session so the recon run is queryable via `sigint sessions`.
    let session_name = format!(
        "recon-{}-{}",
        args.target.replace(['.', '/', ':'], "-"),
        chrono::Utc::now().format("%Y%m%d-%H%M%S"),
    );
    let session = sigint_core::types::Session::new(&session_name).with_target(&args.target);
    if let Err(e) = db.create_session(&session) {
        warn!("recon: cannot persist session (continuing): {}", e);
    }

    // Spawn the event printer before building the engine so no events are missed.
    spawn_recon_printer(core.events.subscribe());

    // Build the engine — filter by module names if --modules was given.
    let engine = if let Some(ref filter) = args.modules {
        let module_names: Vec<&str> = filter.split(',').map(|s| s.trim()).collect();
        ReconEngine::with_modules(&db, &core.events, &module_names)
    } else {
        ReconEngine::new(&db, &core.events)
    };

    // Initial discovery run.
    let assets = engine
        .run(&args.target, session.id)
        .await
        .map_err(|e| Error::Other(e.to_string()))?;

    print_summary(&assets);

    if args.watch {
        println!("\nWatch mode — re-scanning every 300s (Ctrl-C to stop)");
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(300)).await;
            match engine.run(&args.target, session.id).await {
                Ok(new_assets) => {
                    println!(
                        "\n── Re-scan at {} ──",
                        chrono::Utc::now().format("%H:%M:%S")
                    );
                    print_summary(&new_assets);
                }
                Err(e) => {
                    eprintln!("  Re-scan error: {}", e);
                }
            }
        }
    }

    Ok(())
}

/// Print the discovery summary table to stdout.
fn print_summary(assets: &[sigint_core::types::Asset]) {
    println!("\n── Discovery Summary ──");
    println!("  Assets found: {}", assets.len());
    for asset in assets {
        println!("  [{:>13}] {}", asset.kind, asset.value);
    }
}

/// Spawn a detached task that prints recon events to stdout.
///
/// Mirrors the pattern from scan.rs (`spawn_stdout_printer`). The task is
/// intentionally not awaited — when the EventBus is dropped the broadcast
/// channel closes and the task exits via `RecvError::Closed`.
fn spawn_recon_printer(mut event_rx: tokio::sync::broadcast::Receiver<Event>) {
    tokio::spawn(async move {
        loop {
            match event_rx.recv().await {
                Ok(Event::ReconStarted { target, .. }) => {
                    println!("[recon] Starting discovery for {}", target);
                }
                Ok(Event::AssetDiscovered(asset)) => {
                    println!("[recon] Found {:>13}: {}", asset.kind, asset.value);
                }
                Ok(Event::AssetChanged { field, old, new, .. }) => {
                    println!("[recon] Changed {}: {} -> {}", field, old, new);
                }
                Ok(Event::ReconCompleted { assets_found, .. }) => {
                    println!("[recon] Discovery complete — {} assets", assets_found);
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    tracing::warn!("recon printer: dropped {} events", n);
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use clap::Parser;

    /// Mirror of the Recon variant from main.rs — tests clap argument parsing
    /// without depending on main.rs internals (same pattern as scan.rs tests).
    #[derive(Parser, Debug)]
    #[command(name = "sigint")]
    struct TestCli {
        #[command(subcommand)]
        command: TestCommands,
    }

    #[derive(clap::Subcommand, Debug)]
    enum TestCommands {
        Recon {
            target: String,
            #[arg(short, long)]
            modules: Option<String>,
            #[arg(long)]
            watch: bool,
        },
    }

    #[test]
    fn parse_minimal_recon_command() {
        let cli = TestCli::parse_from(["sigint", "recon", "example.com"]);
        let TestCommands::Recon { target, modules, watch } = cli.command;
        assert_eq!(target, "example.com");
        assert!(modules.is_none());
        assert!(!watch);
    }

    #[test]
    fn parse_recon_with_modules() {
        let cli = TestCli::parse_from(["sigint", "recon", "example.com", "--modules", "dns,cert"]);
        let TestCommands::Recon { target, modules, .. } = cli.command;
        assert_eq!(target, "example.com");
        assert_eq!(modules.as_deref(), Some("dns,cert"));
    }

    #[test]
    fn parse_recon_with_watch_flag() {
        let cli = TestCli::parse_from(["sigint", "recon", "10.0.0.1", "--watch"]);
        let TestCommands::Recon { target, watch, .. } = cli.command;
        assert_eq!(target, "10.0.0.1");
        assert!(watch);
    }

    #[test]
    fn parse_recon_ip_target() {
        let cli = TestCli::parse_from(["sigint", "recon", "192.168.1.0/24"]);
        let TestCommands::Recon { target, .. } = cli.command;
        assert_eq!(target, "192.168.1.0/24");
    }

    #[test]
    fn parse_recon_short_modules_flag() {
        let cli = TestCli::parse_from(["sigint", "recon", "target.local", "-m", "port,web"]);
        let TestCommands::Recon { modules, .. } = cli.command;
        assert_eq!(modules.as_deref(), Some("port,web"));
    }
}
