//! sigint-recon — Attack surface mapping and change detection.
//!
//! This crate implements the recon engine: a set of pluggable discovery modules
//! (DNS, port, web, cert, OSINT) orchestrated by `ReconEngine`. Each module
//! runs against a target, returns discovered assets, which are persisted via
//! sigint-store, correlated to remove duplicates, and diffed against previously
//! stored state to detect changes.
//!
//! @decision DEC-RECON-008
//! @title ReconEngine orchestrates modules sequentially with best-effort error handling
//! @status accepted
//! @rationale Sequential execution simplifies backpressure, timeout tracking, and
//! partial failure handling. A module that fails (e.g., nmap sandboxing error, crt.sh
//! rate limit) logs a warning and its results are skipped, but the engine continues
//! with remaining modules. This ensures a single broken tool doesn't abort the whole
//! recon run. Parallel execution can be added later by spawning tokio tasks per module.

pub mod cert;
pub mod change;
pub mod correlator;
pub mod dns;
pub mod error;
pub mod module;
pub mod osint;
pub mod port;
pub mod validate;
pub mod web;

use sigint_core::{
    event::{Event, EventBus},
    types::Asset,
};
use sigint_store::db::Database;
use tracing::{info, warn};
use uuid::Uuid;

use crate::{
    change::ChangeDetector, correlator::Correlator, error::ReconError, module::DiscoveryModule,
    validate::validate_target,
};

/// Orchestrates discovery modules, asset persistence, correlation, and change detection.
///
/// The engine enforces an SSRF guard via `validate_target()` before any module
/// is invoked. By default, loopback, link-local, and RFC1918 targets are
/// rejected. Operators can opt in via `[recon] allow_internal = true` or via
/// the `target_allowlist` field in their config.
///
/// # Example
///
/// ```ignore
/// use sigint_recon::ReconEngine;
/// use sigint_store::db::Database;
/// use sigint_core::event::EventBus;
/// use uuid::Uuid;
///
/// let db = Database::open_in_memory().unwrap();
/// let bus = EventBus::new();
/// let engine = ReconEngine::with_modules(&db, &bus, &["dns", "cert"]);
/// let session_id = Uuid::new_v4();
/// // engine.run("example.com", session_id).await.unwrap();
/// ```
pub struct ReconEngine<'a> {
    modules: Vec<Box<dyn DiscoveryModule>>,
    store: &'a Database,
    event_bus: &'a EventBus,
    /// Whether to allow recon against internal/private ranges (opt-in).
    allow_internal: bool,
    /// Explicit allowlist that bypasses the SSRF guard regardless of `allow_internal`.
    target_allowlist: Vec<String>,
}

impl<'a> ReconEngine<'a> {
    /// Create a ReconEngine with all built-in discovery modules enabled.
    ///
    /// Uses deny-by-default SSRF settings (`allow_internal = false`, empty allowlist).
    /// To enable internal scanning, use [`ReconEngine::with_config`].
    pub fn new(store: &'a Database, event_bus: &'a EventBus) -> Self {
        let modules: Vec<Box<dyn DiscoveryModule>> = vec![
            Box::new(dns::DnsModule),
            Box::new(port::PortModule),
            Box::new(web::WebModule),
            Box::new(cert::CertModule),
            Box::new(osint::OsintModule),
        ];
        Self {
            modules,
            store,
            event_bus,
            allow_internal: false,
            target_allowlist: vec![],
        }
    }

    /// Create a ReconEngine with only the named modules enabled.
    ///
    /// `module_names` is a slice of names like `["dns", "cert", "web"]`.
    /// Unknown names are silently skipped (they may be future modules).
    /// Uses deny-by-default SSRF settings.
    pub fn with_modules(
        store: &'a Database,
        event_bus: &'a EventBus,
        module_names: &[&str],
    ) -> Self {
        let all: Vec<Box<dyn DiscoveryModule>> = vec![
            Box::new(dns::DnsModule),
            Box::new(port::PortModule),
            Box::new(web::WebModule),
            Box::new(cert::CertModule),
            Box::new(osint::OsintModule),
        ];

        let modules = all
            .into_iter()
            .filter(|m| module_names.contains(&m.name()))
            .collect();

        Self {
            modules,
            store,
            event_bus,
            allow_internal: false,
            target_allowlist: vec![],
        }
    }

    /// Create a ReconEngine wiring in the `[recon]` config section.
    ///
    /// This is the preferred constructor when the full `sigint_core::Config` is
    /// available (e.g. in the CLI and web service). It applies the operator's
    /// `allow_internal` flag and `target_allowlist` to the SSRF guard.
    pub fn with_config(
        store: &'a Database,
        event_bus: &'a EventBus,
        recon_cfg: &sigint_core::ReconConfig,
    ) -> Self {
        let modules: Vec<Box<dyn DiscoveryModule>> = vec![
            Box::new(dns::DnsModule),
            Box::new(port::PortModule),
            Box::new(web::WebModule),
            Box::new(cert::CertModule),
            Box::new(osint::OsintModule),
        ];
        Self {
            modules,
            store,
            event_bus,
            allow_internal: recon_cfg.allow_internal,
            target_allowlist: recon_cfg.target_allowlist.clone(),
        }
    }

    /// Run all configured modules against `target` for `session_id`.
    ///
    /// Steps:
    /// 0. Validate `target` against the SSRF guard (reject internal ranges
    ///    unless `allow_internal` is set or the target is in `target_allowlist`)
    /// 1. Emit `ReconStarted`
    /// 2. Run each module's `discover()`, collecting all assets
    /// 3. Correlate (deduplicate and link) the raw results
    /// 4. Upsert each asset into the store
    /// 5. Detect and record changes vs. previously stored state
    /// 6. Emit `AssetDiscovered` for each new asset
    /// 7. Emit `ReconCompleted`
    /// 8. Return the full deduplicated asset list
    pub async fn run(&self, target: &str, session_id: Uuid) -> Result<Vec<Asset>, ReconError> {
        if self.modules.is_empty() {
            return Err(ReconError::NoModules);
        }

        // SSRF guard — reject internal/private targets before any module runs.
        validate_target(target, self.allow_internal, &self.target_allowlist)?;

        info!(target, session_id = %session_id, "recon engine: starting");

        self.event_bus.emit(Event::ReconStarted {
            session_id,
            target: target.to_string(),
        });

        // --- Phase 1: Run each module, accumulate raw assets ---
        let mut raw_assets: Vec<Asset> = Vec::new();

        for module in &self.modules {
            info!(module = module.name(), target, "recon: running module");
            match module.discover(target, session_id).await {
                Ok(mut assets) => {
                    info!(
                        module = module.name(),
                        found = assets.len(),
                        "recon: module returned assets"
                    );
                    raw_assets.append(&mut assets);
                }
                Err(e) => {
                    warn!(
                        module = module.name(),
                        error = %e,
                        "recon: module failed (continuing)"
                    );
                }
            }
        }

        // --- Phase 2: Correlate (deduplicate + link) ---
        let mut correlation = Correlator::correlate(raw_assets);
        Correlator::link_domains_to_hosts(&mut correlation.assets, target);

        info!(
            unique_assets = correlation.assets.len(),
            duplicates_merged = correlation.duplicates_merged,
            "recon: correlation complete"
        );

        // --- Phase 3: Detect changes vs. previously stored state ---
        let detector = ChangeDetector::new(self.store);
        match detector.detect_and_record(session_id, &correlation.assets) {
            Ok(changes) => {
                if changes > 0 {
                    info!(
                        changes,
                        "recon: change detection recorded {} changes", changes
                    );
                }
            }
            Err(e) => warn!(error = %e, "recon: change detection failed (continuing)"),
        }

        // --- Phase 4: Upsert assets into the store ---
        let mut persisted_assets: Vec<Asset> = Vec::new();
        let mut new_count = 0usize;

        for asset in &correlation.assets {
            match self.store.upsert_asset(
                session_id,
                asset.kind.clone(),
                &asset.value,
                asset.metadata.clone(),
            ) {
                Ok((stored_asset, is_new)) => {
                    if is_new {
                        new_count += 1;
                        self.event_bus
                            .emit(Event::AssetDiscovered(stored_asset.clone()));
                    }
                    persisted_assets.push(stored_asset);
                }
                Err(e) => {
                    warn!(
                        asset = %asset.value,
                        error = %e,
                        "recon: failed to persist asset (skipping)"
                    );
                }
            }
        }

        info!(
            persisted = persisted_assets.len(),
            new = new_count,
            "recon: asset persistence complete"
        );

        self.event_bus.emit(Event::ReconCompleted {
            session_id,
            assets_found: persisted_assets.len(),
        });

        Ok(persisted_assets)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use sigint_core::types::{Asset, AssetKind, Session};
    use sigint_store::db::Database;

    /// A mock discovery module that returns hardcoded assets.
    struct MockModule {
        name: &'static str,
        assets: Vec<Asset>,
    }

    impl MockModule {
        fn new(name: &'static str, assets: Vec<Asset>) -> Self {
            Self { name, assets }
        }

        fn empty(name: &'static str) -> Self {
            Self {
                name,
                assets: vec![],
            }
        }
    }

    #[async_trait]
    impl DiscoveryModule for MockModule {
        fn name(&self) -> &str {
            self.name
        }

        async fn discover(
            &self,
            _target: &str,
            _session_id: Uuid,
        ) -> Result<Vec<Asset>, ReconError> {
            Ok(self.assets.clone())
        }
    }

    /// A mock module that always fails.
    struct FailingModule;

    #[async_trait]
    impl DiscoveryModule for FailingModule {
        fn name(&self) -> &str {
            "failing"
        }

        async fn discover(
            &self,
            _target: &str,
            _session_id: Uuid,
        ) -> Result<Vec<Asset>, ReconError> {
            Err(ReconError::Sandbox("sandbox exploded".to_string()))
        }
    }

    fn setup_db() -> (Database, Uuid) {
        let db = Database::open_in_memory().unwrap();
        let session = Session::new("test-recon-session");
        db.create_session(&session).unwrap();
        (db, session.id)
    }

    fn make_asset(kind: AssetKind, value: &str, session_id: Uuid) -> Asset {
        Asset {
            id: Uuid::new_v4(),
            session_id,
            kind,
            value: value.to_string(),
            metadata: serde_json::Value::Null,
            discovered_at: chrono::Utc::now(),
        }
    }

    /// Helper: build a ReconEngine with allow_internal=true so orchestration
    /// tests can use internal IPs without hitting the SSRF guard.
    fn make_engine_internal<'a>(
        modules: Vec<Box<dyn DiscoveryModule>>,
        store: &'a Database,
        event_bus: &'a EventBus,
    ) -> ReconEngine<'a> {
        ReconEngine {
            modules,
            store,
            event_bus,
            allow_internal: true,
            target_allowlist: vec![],
        }
    }

    #[tokio::test]
    async fn engine_no_modules_returns_error() {
        let (db, session_id) = setup_db();
        let bus = EventBus::new();

        let engine = make_engine_internal(vec![], &db, &bus);

        let result = engine.run("example.com", session_id).await;
        assert!(matches!(result, Err(ReconError::NoModules)));
    }

    #[tokio::test]
    async fn engine_with_mock_modules_persists_assets() {
        let (db, session_id) = setup_db();
        let bus = EventBus::new();

        let assets = vec![
            make_asset(AssetKind::Host, "93.184.216.34", session_id),
            make_asset(AssetKind::Domain, "example.com", session_id),
        ];

        let engine =
            make_engine_internal(vec![Box::new(MockModule::new("mock", assets))], &db, &bus);

        let result = engine.run("example.com", session_id).await.unwrap();
        assert_eq!(result.len(), 2);

        // Assets should now be in the store
        let stored = db.get_assets(session_id).unwrap();
        assert_eq!(stored.len(), 2);
    }

    #[tokio::test]
    async fn engine_emits_recon_started_and_completed() {
        let (db, session_id) = setup_db();
        let bus = EventBus::new();
        let mut rx = bus.subscribe();

        let engine = make_engine_internal(vec![Box::new(MockModule::empty("mock"))], &db, &bus);

        engine.run("example.com", session_id).await.unwrap();

        let e1 = rx.recv().await.unwrap();
        assert!(matches!(e1, Event::ReconStarted { .. }));

        let e2 = rx.recv().await.unwrap();
        assert!(matches!(
            e2,
            Event::ReconCompleted {
                assets_found: 0,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn engine_continues_when_module_fails() {
        let (db, session_id) = setup_db();
        let bus = EventBus::new();

        let good_assets = vec![make_asset(AssetKind::Host, "10.0.0.1", session_id)];

        let engine = make_engine_internal(
            vec![
                Box::new(FailingModule),
                Box::new(MockModule::new("good", good_assets)),
            ],
            &db,
            &bus,
        );

        // Should not return an error — failing module is skipped
        let result = engine.run("example.com", session_id).await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].value, "10.0.0.1");
    }

    #[tokio::test]
    async fn engine_deduplicates_across_modules() {
        let (db, session_id) = setup_db();
        let bus = EventBus::new();

        // Two modules return the same host — should be deduplicated.
        // allow_internal=true because we use 10.x addresses as test fixtures,
        // not because SSRF is disabled in production.
        let assets1 = vec![make_asset(AssetKind::Host, "10.0.0.1", session_id)];
        let assets2 = vec![make_asset(AssetKind::Host, "10.0.0.1", session_id)];

        let engine = make_engine_internal(
            vec![
                Box::new(MockModule::new("module1", assets1)),
                Box::new(MockModule::new("module2", assets2)),
            ],
            &db,
            &bus,
        );

        let result = engine.run("10.0.0.1", session_id).await.unwrap();
        assert_eq!(result.len(), 1, "duplicates should be merged");

        let stored = db.get_assets(session_id).unwrap();
        assert_eq!(stored.len(), 1, "only one row in store");
    }

    #[tokio::test]
    async fn engine_emits_asset_discovered_for_new_assets() {
        let (db, session_id) = setup_db();
        let bus = EventBus::new();
        let mut rx = bus.subscribe();

        let assets = vec![make_asset(AssetKind::Host, "10.0.0.1", session_id)];

        let engine =
            make_engine_internal(vec![Box::new(MockModule::new("mock", assets))], &db, &bus);

        engine.run("10.0.0.1", session_id).await.unwrap();

        // Events: ReconStarted, AssetDiscovered, ReconCompleted
        let e1 = rx.recv().await.unwrap();
        assert!(matches!(e1, Event::ReconStarted { .. }));

        let e2 = rx.recv().await.unwrap();
        assert!(matches!(e2, Event::AssetDiscovered(_)));

        let e3 = rx.recv().await.unwrap();
        assert!(matches!(
            e3,
            Event::ReconCompleted {
                assets_found: 1,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn engine_with_modules_filter() {
        let (db, _session_id) = setup_db();
        let bus = EventBus::new();

        let engine = ReconEngine::with_modules(&db, &bus, &["dns", "cert"]);
        assert_eq!(engine.modules.len(), 2);
        let names: Vec<&str> = engine.modules.iter().map(|m| m.name()).collect();
        assert!(names.contains(&"dns"));
        assert!(names.contains(&"cert"));
        assert!(!names.contains(&"port"));
    }

    #[tokio::test]
    async fn engine_new_has_all_modules() {
        let (db, _session_id) = setup_db();
        let bus = EventBus::new();

        let engine = ReconEngine::new(&db, &bus);
        assert_eq!(engine.modules.len(), 5);
    }

    // ── SSRF guard integration tests ──────────────────────────────────────────

    #[tokio::test]
    async fn engine_ssrf_guard_rejects_loopback_by_default() {
        let (db, session_id) = setup_db();
        let bus = EventBus::new();
        // ReconEngine::new uses allow_internal=false — loopback must be rejected.
        let engine = ReconEngine {
            modules: vec![Box::new(MockModule::empty("mock"))],
            store: &db,
            event_bus: &bus,
            allow_internal: false,
            target_allowlist: vec![],
        };
        let result = engine.run("127.0.0.1", session_id).await;
        assert!(
            matches!(result, Err(ReconError::InvalidTarget(_))),
            "127.0.0.1 must be rejected by default SSRF guard, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn engine_ssrf_guard_rejects_metadata_endpoint() {
        let (db, session_id) = setup_db();
        let bus = EventBus::new();
        let engine = ReconEngine {
            modules: vec![Box::new(MockModule::empty("mock"))],
            store: &db,
            event_bus: &bus,
            allow_internal: false,
            target_allowlist: vec![],
        };
        // 169.254.169.254 is the AWS/GCP IMDS address — primary SSRF vector.
        let result = engine.run("169.254.169.254", session_id).await;
        assert!(
            matches!(result, Err(ReconError::InvalidTarget(_))),
            "169.254.169.254 (IMDS) must be rejected, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn engine_ssrf_guard_allows_public_target() {
        let (db, session_id) = setup_db();
        let bus = EventBus::new();
        let engine = make_engine_internal(vec![Box::new(MockModule::empty("mock"))], &db, &bus);
        // Use allow_internal=true so the public-target test doesn't need network.
        // Separately, test with allow_internal=false and a public IP.
        let engine2 = ReconEngine {
            modules: vec![Box::new(MockModule::empty("mock"))],
            store: &db,
            event_bus: &bus,
            allow_internal: false,
            target_allowlist: vec![],
        };
        let result = engine2.run("8.8.8.8", session_id).await;
        assert!(
            result.is_ok(),
            "8.8.8.8 (public IP) must be allowed, got: {:?}",
            result
        );
        // Suppress unused variable warning.
        drop(engine);
    }

    #[tokio::test]
    async fn engine_ssrf_guard_allow_internal_flag_bypasses() {
        let (db, session_id) = setup_db();
        let bus = EventBus::new();
        let engine = ReconEngine {
            modules: vec![Box::new(MockModule::empty("mock"))],
            store: &db,
            event_bus: &bus,
            allow_internal: true,
            target_allowlist: vec![],
        };
        // With allow_internal=true, even loopback must be accepted.
        let result = engine.run("127.0.0.1", session_id).await;
        assert!(
            result.is_ok(),
            "127.0.0.1 must be allowed when allow_internal=true, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn engine_ssrf_guard_allowlist_permits_internal_target() {
        let (db, session_id) = setup_db();
        let bus = EventBus::new();
        let engine = ReconEngine {
            modules: vec![Box::new(MockModule::empty("mock"))],
            store: &db,
            event_bus: &bus,
            allow_internal: false,
            target_allowlist: vec!["10.5.5.5".to_string()],
        };
        // 10.5.5.5 is RFC1918 but is in the allowlist.
        let result = engine.run("10.5.5.5", session_id).await;
        assert!(
            result.is_ok(),
            "10.5.5.5 must be allowed when in target_allowlist, got: {:?}",
            result
        );
    }
}
