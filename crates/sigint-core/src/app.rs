//! AppCore — the shared runtime handle passed to every SIGINT component.
//!
//! AppCore is constructed once at startup and Arc-cloned into every
//! subsystem (CLI, TUI, Web, agents). It owns the config and event bus.
//!
//! @decision DEC-ARCH-001
//! @title AppCore as the single shared runtime handle
//! @status accepted
//! @rationale A single Arc<AppCore> eliminates the need to pass config
//! and event bus separately to every subsystem. Cloning is cheap (Arc).
//! This pattern scales cleanly as Phase 2 adds the store and agent registry.

use std::sync::Arc;

use crate::{config::Config, error::Result, event::EventBus};

/// Shared runtime handle for all SIGINT subsystems.
///
/// Construct with `AppCore::new()` or `AppCore::load()`, then
/// `Arc::clone` into each subsystem.
#[derive(Debug, Clone)]
pub struct AppCore {
    /// Loaded configuration (immutable after startup).
    pub config: Arc<Config>,
    /// Broadcast event bus for inter-component communication.
    pub events: EventBus,
}

impl AppCore {
    /// Create AppCore with the provided config.
    pub fn new(config: Config) -> Self {
        Self {
            config: Arc::new(config),
            events: EventBus::new(),
        }
    }

    /// Load config from disk and construct AppCore.
    ///
    /// Falls back to defaults if no config file exists.
    pub fn load() -> Result<Self> {
        let config = Config::load()?;
        Ok(Self::new(config))
    }

    /// Create AppCore with default config (useful in tests).
    pub fn default_for_test() -> Self {
        Self::new(Config::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn appcore_constructs_with_defaults() {
        let core = AppCore::default_for_test();
        assert_eq!(core.config.llm.provider, "ollama");
        assert_eq!(core.config.llm.model, "llama3.2");
    }

    #[test]
    fn appcore_clone_shares_config() {
        let core = AppCore::default_for_test();
        let clone = core.clone();
        // Same Arc pointer — not a copy
        assert!(Arc::ptr_eq(&core.config, &clone.config));
    }

    #[tokio::test]
    async fn appcore_event_bus_works() {
        let core = AppCore::default_for_test();
        let mut rx = core.events.subscribe();

        core.events.emit(crate::event::Event::Status("ready".into()));

        let ev = rx.recv().await.unwrap();
        assert!(matches!(ev, crate::event::Event::Status(_)));
    }
}
