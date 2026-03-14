//! `sigint serve` — start the embedded Axum web UI server.
//!
//! Opens the configured SQLite database and binds an HTTP listener on the
//! specified address. The server runs until Ctrl-C is received, at which
//! point it emits `Event::Shutdown` and drains in-flight requests before
//! returning.
//!
//! @decision DEC-CLI-006
//! @title serve subcommand uses serve_with_shutdown for clean Ctrl-C teardown
//! @status accepted
//! @rationale Without a shutdown signal axum keeps accepting connections until
//! the OS kills the process, leaving the terminal in an unknown state and
//! dropping in-flight requests. Using serve_with_shutdown + tokio::signal::ctrl_c
//! gives axum the chance to drain open connections. Event::Shutdown is emitted
//! on the bus so any other subscribers (WebSocket clients, TUI) also clean up.

use sigint_core::{event::Event, AppCore, ApprovalRegistry};
use std::sync::Arc;
use std::time::Duration;

/// Run the web server using the AppCore's configured database path.
///
/// Binds the given address, prints the URL, then serves requests until
/// Ctrl-C.  On Ctrl-C the shutdown future resolves: axum stops accepting
/// new connections, drains in-flight requests, and this function returns.
/// `Event::Shutdown` is emitted so any other bus subscribers also clean up.
pub async fn run(core: AppCore, bind: &str) -> Result<(), sigint_core::Error> {
    let db_path = core.config.resolved_db_path();

    // Ensure the parent directory exists (mirrors sigint-store::Database::open behaviour).
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let db = sigint_store::Database::open(&db_path)?;

    let addr: std::net::SocketAddr = bind.parse().map_err(|e| {
        sigint_core::Error::InvalidInput(format!("Invalid bind address '{}': {}", bind, e))
    })?;

    println!("SIGINT web UI at http://{}", addr);

    let timeout_secs = core.config.agent.approval_timeout;
    let config = core.config.clone(); // Already Arc<Config>
    let approval_registry = Arc::new(ApprovalRegistry::new(Duration::from_secs(timeout_secs)));

    // Build a shutdown future that resolves when Ctrl-C is pressed.
    // Cloning the event bus lets us emit Event::Shutdown to notify any other
    // subscribers (WebSocket clients) that the server is stopping.
    let events = core.events.clone();
    let shutdown = async move {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl-C handler");
        println!("\nShutting down gracefully...");
        events.emit(Event::Shutdown);
    };

    sigint_web::serve_with_shutdown(
        db,
        core.events.clone(),
        config,
        approval_registry,
        addr,
        shutdown,
    )
    .await
}
