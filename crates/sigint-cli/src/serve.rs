//! `sigint serve` — start the embedded Axum web UI server.
//!
//! Opens the configured SQLite database and binds an HTTP listener on the
//! specified address. The server runs until the process is interrupted.

use sigint_core::AppCore;

/// Run the web server using the AppCore's configured database path.
pub async fn run(core: AppCore, bind: &str) -> Result<(), sigint_core::Error> {
    let db_path = core.config.resolved_db_path();

    // Ensure the parent directory exists (mirrors sigint-store::Database::open behaviour).
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let db = sigint_store::Database::open(&db_path)?;

    let addr: std::net::SocketAddr = bind.parse().map_err(|e| {
        sigint_core::Error::InvalidInput(format!(
            "Invalid bind address '{}': {}",
            bind, e
        ))
    })?;

    println!("SIGINT web UI at http://{}", addr);

    sigint_web::serve(db, core.events.clone(), addr).await
}
