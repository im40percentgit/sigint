//! `sigint doctor` — environment and dependency checker (Phase 1 stub).

use sigint_core::{AppCore, Error};

/// Run the doctor command.
///
/// Phase 5 will implement actual checks: Ollama reachability, tool
/// availability (nmap, gobuster), database integrity, model availability.
pub async fn run(_core: AppCore) -> Result<(), Error> {
    println!("sigint doctor: not yet implemented");
    println!("(Phase 5 will check: Ollama, tools, database, models)");
    Ok(())
}
