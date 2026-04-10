//! sigint — AI-powered penetration testing tool.
//!
//! Entry point: parses CLI arguments, initialises tracing, and dispatches
//! to subcommand handlers.
//!
//! @decision DEC-ARCH-001
//! @title Single binary entry point via clap derive macros
//! @status accepted
//! @rationale clap derive provides compile-time argument validation and
//! auto-generated help text. All subcommands live in separate modules
//! so the main.rs stays minimal and each command can be tested in isolation.
//!
//! @decision DEC-TUI-002
//! @title Redirect tracing output to a file when TUI is active
//! @status accepted
//! @rationale ratatui occupies the alternate screen buffer on stderr; tracing
//! lines written to stderr corrupt the TUI rendering. The fix detects TUI
//! mode before init (by inspecting the parsed CLI args + isatty) and redirects
//! the tracing subscriber to a log file (~/.local/share/sigint/sigint.log)
//! instead of stderr. No extra crates needed: std::io::IsTerminal (stable
//! since Rust 1.70) and Mutex<File> satisfy MakeWriter requirements.

mod campaign;
mod chat;
mod diff;
mod doctor;
mod log;
mod model;
mod plugin;
mod recon;
mod report;
mod scan;
mod serve;
mod sessions;

use std::io::IsTerminal;
use std::sync::Mutex;

use clap::{Parser, Subcommand};
use sigint_core::{event::Event, AppCore};
use tracing_subscriber::EnvFilter;

/// SIGINT — AI-powered penetration testing, locally.
#[derive(Parser, Debug)]
#[command(
    name = "sigint",
    version,
    about = "AI-powered penetration testing tool",
    long_about = "SIGINT orchestrates AI agents for reconnaissance, strategy,\n\
                  execution, analysis, and reporting — all in one binary.\n\
                  Runs locally with Ollama; no Docker, no cloud required."
)]
struct Cli {
    /// Increase log verbosity (use SIGINT_LOG for fine-grained control).
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start an interactive AI chat session (streams responses from Ollama).
    Chat(chat::ChatArgs),
    /// Check SIGINT's environment and dependencies.
    Doctor,
    /// Manage stored scan sessions (list, export, delete).
    Sessions(sessions::SessionsArgs),
    /// Run a multi-agent penetration scan against a target.
    Scan {
        /// Target hostname, IP address, or CIDR range (e.g. "scanme.nmap.org", "10.0.0.1/24").
        target: String,
        /// Port specification passed to nmap (e.g. "80,443" or "1-1000").
        #[arg(short, long)]
        ports: Option<String>,
        /// LLM model override (uses config default if omitted).
        #[arg(short, long)]
        model: Option<String>,
        /// Maximum tool-call iterations per agent turn.
        #[arg(long, default_value = "10")]
        max_iterations: usize,
        /// Maximum Strategist → Executor → Analyst cycles (convergence loop).
        /// Defaults to 1 (linear pipeline, identical to previous behaviour).
        /// Values > 1 enable iterative refinement until no new findings are
        /// discovered or a goal keyword is matched.
        #[arg(long, default_value = "1")]
        max_cycles: usize,
        /// Convergence goal: stop cycling as soon as any finding title or
        /// description contains this string (case-insensitive). Only meaningful
        /// when --max-cycles > 1.
        #[arg(long)]
        goal: Option<String>,
        /// Gate escalation tier transitions behind operator approval.
        /// When set, the scan pauses if the Strategist recommends exploitation
        /// or post-exploitation actions and waits for approval before proceeding.
        /// Only meaningful when --max-cycles > 1 and the TUI/web approval UI is active.
        #[arg(long, default_value = "false")]
        approval_gates: bool,
        /// Enable episodic memory recall from prior scans of the same target.
        #[arg(long)]
        memory: bool,
        /// Run ReconEngine as a pre-scan step to build asset inventory.
        #[arg(long)]
        recon: bool,
        /// Force TUI mode on (default: auto-detect via isatty).
        #[arg(long)]
        tui: bool,
        /// Force TUI mode off — print events to stdout.
        #[arg(long)]
        no_tui: bool,
    },
    /// Compare findings between two scan sessions.
    Diff(diff::DiffArgs),
    /// Show the chronological engagement log for a scan session.
    Log(log::LogArgs),
    /// Generate a report for a scan session.
    Report(report::ReportArgs),
    /// Start the SIGINT web UI server.
    Serve {
        /// Address to bind (e.g. "127.0.0.1:8080").
        #[arg(long, default_value = "127.0.0.1:8080")]
        bind: String,
    },
    /// Multi-target campaign scanning.
    Campaign {
        #[command(subcommand)]
        action: CampaignAction,
    },
    /// Run attack surface reconnaissance against a target (Phase 4 ASM).
    Recon {
        /// Target domain, hostname, or IP address.
        target: String,
        /// Comma-separated list of modules to run (default: all).
        /// Available: dns, port, web, cert, osint
        #[arg(short, long)]
        modules: Option<String>,
        /// Continuous mode — re-scan every 5 minutes and show changes.
        #[arg(long)]
        watch: bool,
    },
    /// Manage local GGUF models.
    Model {
        #[command(subcommand)]
        command: ModelCommands,
    },
    /// Manage plugin tool packs.
    Plugin {
        #[command(subcommand)]
        command: PluginCommands,
    },
}

#[derive(Subcommand, Debug)]
enum PluginCommands {
    /// List all registered tools and prompt packs (built-in + plugins).
    List,
    /// Scaffold a new plugin crate in the workspace.
    New {
        /// Plugin name (will be prefixed with "sigint-" if not already).
        name: String,
    },
}

#[derive(Subcommand, Debug)]
enum ModelCommands {
    /// List available GGUF models in the configured models directory.
    List,
    /// Download a model from HuggingFace (owner/repo) or a direct URL.
    Pull {
        /// HuggingFace repo ID (e.g. meta-llama/Llama-3.2-8B-GGUF) or direct URL.
        source: String,
    },
    /// Show detailed metadata for a local GGUF model.
    Info {
        /// Model filename or stem (e.g. "llama-3.2-8B-Q4_K_M" or "llama-3.2-8B-Q4_K_M.gguf").
        name: String,
    },
}

#[derive(Subcommand, Debug)]
enum CampaignAction {
    /// Run a campaign from a target file.
    Run {
        /// Path to campaign JSON file.
        #[arg(short, long)]
        file: String,
        /// LLM model override (uses config default if omitted).
        #[arg(short, long)]
        model: Option<String>,
        /// Force TUI mode off — print events to stdout.
        #[arg(long)]
        no_tui: bool,
    },
    /// Show campaign status.
    Status {
        /// Campaign UUID prefix (at least 4 characters).
        campaign: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialise tracing. SIGINT_LOG overrides --verbose.
    let filter = match cli.verbose {
        0 => "sigint=info,warn".to_string(),
        1 => "sigint=debug,warn".to_string(),
        _ => "sigint=trace,debug".to_string(),
    };
    let env_filter =
        EnvFilter::try_from_env("SIGINT_LOG").unwrap_or_else(|_| EnvFilter::new(filter));

    // Determine whether a TUI will be active for this invocation.
    // ratatui occupies the alternate screen on stderr, so any tracing output
    // written to stderr would corrupt the display.  When TUI mode is detected,
    // redirect the subscriber to a log file instead.
    let tui_active = match &cli.command {
        Commands::Scan { tui, no_tui, .. } => {
            if *no_tui {
                false
            } else if *tui {
                true
            } else {
                std::io::stderr().is_terminal()
            }
        }
        Commands::Campaign {
            action: CampaignAction::Run { no_tui, .. },
        } => !no_tui && std::io::stderr().is_terminal(),
        _ => false,
    };

    if tui_active {
        // TUI mode: redirect tracing to a log file so stderr stays clean.
        let log_dir = std::env::var("HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| std::path::PathBuf::from("."))
            .join(".local")
            .join("share")
            .join("sigint");
        let _ = std::fs::create_dir_all(&log_dir);
        let log_file = std::fs::File::create(log_dir.join("sigint.log"))
            .unwrap_or_else(|_| std::fs::File::create("/dev/null").unwrap());
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_target(false)
            .with_ansi(false)
            .with_writer(Mutex::new(log_file))
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_target(false)
            .init();
    }

    // Load AppCore (config + event bus). Errors here are fatal.
    let core = match AppCore::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: Failed to load configuration: {}", e);
            std::process::exit(1);
        }
    };

    // ── Graceful shutdown handler ──────────────────────────────────────────
    // Spawn a background task that listens for Ctrl-C and emits
    // Event::Shutdown so all subscribers (TUI, web) can clean up before the
    // process exits.  The `serve` subcommand additionally wires this signal
    // into axum's graceful shutdown via serve_with_shutdown.
    {
        let events = core.events.clone();
        tokio::spawn(async move {
            if tokio::signal::ctrl_c().await.is_ok() {
                events.emit(Event::Shutdown);
            }
        });
    }

    let result = match cli.command {
        Commands::Chat(args) => chat::run(core, args).await,
        Commands::Doctor => doctor::run(core).await,
        Commands::Sessions(args) => sessions::run(core, args).await,
        Commands::Scan {
            target,
            ports,
            model,
            max_iterations,
            max_cycles,
            goal,
            approval_gates,
            memory,
            recon,
            tui,
            no_tui,
        } => {
            scan::run(
                core,
                scan::ScanArgs {
                    target,
                    ports,
                    model,
                    max_iterations,
                    max_cycles,
                    goal,
                    approval_gates,
                    memory,
                    recon,
                    force_tui: tui,
                    force_no_tui: no_tui,
                },
            )
            .await
        }
        Commands::Campaign { action } => match action {
            CampaignAction::Run {
                file,
                model,
                no_tui,
            } => campaign::run(core, file, model, no_tui).await,
            CampaignAction::Status { campaign: prefix } => campaign::status(core, prefix).await,
        },
        Commands::Diff(args) => diff::run(core, args).await,
        Commands::Log(args) => log::run(core, args).await,
        Commands::Report(args) => report::run(core, args).await,
        Commands::Serve { bind } => serve::run(core, &bind).await,
        Commands::Recon {
            target,
            modules,
            watch,
        } => {
            recon::run(
                core,
                recon::ReconArgs {
                    target,
                    modules,
                    watch,
                },
            )
            .await
        }
        Commands::Model { command } => match command {
            ModelCommands::List => model::run_list(core).await,
            ModelCommands::Pull { source } => model::run_pull(core, source).await,
            ModelCommands::Info { name } => model::run_info(core, name).await,
        },
        Commands::Plugin { command } => match command {
            PluginCommands::List => plugin::run_list()
                .map_err(|e: anyhow::Error| sigint_core::Error::Other(e.to_string())),
            PluginCommands::New { name } => plugin::run_new(&name)
                .map_err(|e: anyhow::Error| sigint_core::Error::Other(e.to_string())),
        },
    };

    if let Err(e) = result {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}
