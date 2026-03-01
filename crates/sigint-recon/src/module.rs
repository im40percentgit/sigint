//! DiscoveryModule trait — the core abstraction for all recon modules.
//!
//! Each module (DNS, port, web, cert, OSINT) implements this trait.
//! The ReconEngine dispatches to all registered modules and collects results.

use async_trait::async_trait;
use sigint_core::types::Asset;
use uuid::Uuid;

use crate::error::ReconError;

/// A pluggable recon discovery module.
///
/// Implementors run a specific class of recon (DNS, port scan, HTTP probe,
/// certificate transparency lookup, OSINT) and return the assets they found.
///
/// All modules run sequentially inside `ReconEngine::run()`. Parallel
/// execution can be added later without changing the trait interface.
#[async_trait]
pub trait DiscoveryModule: Send + Sync {
    /// Short human-readable name for this module (e.g. "dns", "port").
    fn name(&self) -> &str;

    /// Run discovery against `target` (hostname, IP, or domain) within the
    /// given `session_id`. Returns the assets found by this module.
    async fn discover(&self, target: &str, session_id: Uuid) -> Result<Vec<Asset>, ReconError>;
}
