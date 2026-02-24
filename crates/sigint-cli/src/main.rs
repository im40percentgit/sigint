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

mod chat;
mod doctor;
mod scan;

use clap::{Parser, Subcommand};
use sigint_core::AppCore;
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
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("SIGINT_LOG").unwrap_or_else(|_| {
                EnvFilter::new(filter)
            }),
        )
        .with_target(false)
        .init();

    // Load AppCore (config + event bus). Errors here are fatal.
    let core = match AppCore::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: Failed to load configuration: {}", e);
            std::process::exit(1);
        }
    };

    let result = match cli.command {
        Commands::Chat(args) => chat::run(core, args).await,
        Commands::Doctor => doctor::run(core).await,
        Commands::Scan { target, model, max_iterations, .. } => {
            scan::run(core, target, model, max_iterations).await
        }
    };

    if let Err(e) = result {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}
