//! CRUD operations for Asset, AssetService, and AssetChange records.
//!
//! @decision DEC-ASM-001
//! @title Asset store uses SELECT-then-INSERT for upsert, no UPSERT SQL
//! @status accepted
//! @rationale The `assets` table has no UNIQUE constraint on (session_id, kind, value),
//! so `INSERT OR REPLACE` would silently create duplicates on schema drift. An explicit
//! SELECT-then-INSERT within a single `with_conn` closure gives deterministic behaviour:
//! return the existing row (is_new=false) if found, insert and return (is_new=true)
//! if not. This matches the pattern used throughout sigint-store and keeps the upsert
//! logic explicit and auditable.

use chrono::DateTime;
use rusqlite::params;
use sigint_core::{
    types::{Asset, AssetChange, AssetKind, AssetService},
    Error,
};
use uuid::Uuid;

use crate::db::Database;

// ── Row parsers ───────────────────────────────────────────────────────────────

fn row_to_asset(row: &rusqlite::Row<'_>) -> Result<Asset, Error> {
    let id_str: String = row.get(0).map_err(|e| Error::Database(e.to_string()))?;
    let session_id_str: String = row.get(1).map_err(|e| Error::Database(e.to_string()))?;
    let kind_str: String = row.get(2).map_err(|e| Error::Database(e.to_string()))?;
    let value: String = row.get(3).map_err(|e| Error::Database(e.to_string()))?;
    let metadata_str: String = row.get(4).map_err(|e| Error::Database(e.to_string()))?;
    let discovered_at_str: String = row.get(5).map_err(|e| Error::Database(e.to_string()))?;

    let id = Uuid::parse_str(&id_str)
        .map_err(|e| Error::Database(format!("Invalid asset UUID '{id_str}': {e}")))?;
    let session_id = Uuid::parse_str(&session_id_str)
        .map_err(|e| Error::Database(format!("Invalid session UUID '{session_id_str}': {e}")))?;
    let kind: AssetKind = kind_str.parse().unwrap_or(AssetKind::Other);
    let metadata: serde_json::Value =
        serde_json::from_str(&metadata_str).unwrap_or(serde_json::Value::Null);
    let discovered_at = DateTime::parse_from_rfc3339(&discovered_at_str)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|e| Error::Database(format!("Invalid timestamp '{discovered_at_str}': {e}")))?;

    Ok(Asset { id, session_id, kind, value, metadata, discovered_at })
}

fn row_to_service(row: &rusqlite::Row<'_>) -> Result<AssetService, Error> {
    let id_str: String = row.get(0).map_err(|e| Error::Database(e.to_string()))?;
    let asset_id_str: String = row.get(1).map_err(|e| Error::Database(e.to_string()))?;
    let port: i32 = row.get(2).map_err(|e| Error::Database(e.to_string()))?;
    let protocol: String = row.get(3).map_err(|e| Error::Database(e.to_string()))?;
    // `service` is nullable in schema — default to empty string
    let service: String = row
        .get::<_, Option<String>>(4)
        .map_err(|e| Error::Database(e.to_string()))?
        .unwrap_or_default();
    let version: Option<String> = row.get(5).map_err(|e| Error::Database(e.to_string()))?;
    let banner: Option<String> = row.get(6).map_err(|e| Error::Database(e.to_string()))?;
    let discovered_at_str: String = row.get(7).map_err(|e| Error::Database(e.to_string()))?;

    let id = Uuid::parse_str(&id_str)
        .map_err(|e| Error::Database(format!("Invalid service UUID '{id_str}': {e}")))?;
    let asset_id = Uuid::parse_str(&asset_id_str)
        .map_err(|e| Error::Database(format!("Invalid asset UUID '{asset_id_str}': {e}")))?;
    let discovered_at = DateTime::parse_from_rfc3339(&discovered_at_str)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|e| Error::Database(format!("Invalid timestamp '{discovered_at_str}': {e}")))?;

    Ok(AssetService { id, asset_id, port, protocol, service, version, banner, discovered_at })
}

fn row_to_change(row: &rusqlite::Row<'_>) -> Result<AssetChange, Error> {
    let id_str: String = row.get(0).map_err(|e| Error::Database(e.to_string()))?;
    let asset_id_str: String = row.get(1).map_err(|e| Error::Database(e.to_string()))?;
    let field: String = row.get(2).map_err(|e| Error::Database(e.to_string()))?;
    // old_value and new_value are nullable in schema — default to empty string
    let old_value: String = row
        .get::<_, Option<String>>(3)
        .map_err(|e| Error::Database(e.to_string()))?
        .unwrap_or_default();
    let new_value: String = row
        .get::<_, Option<String>>(4)
        .map_err(|e| Error::Database(e.to_string()))?
        .unwrap_or_default();
    let changed_at_str: String = row.get(5).map_err(|e| Error::Database(e.to_string()))?;

    let id = Uuid::parse_str(&id_str)
        .map_err(|e| Error::Database(format!("Invalid change UUID '{id_str}': {e}")))?;
    let asset_id = Uuid::parse_str(&asset_id_str)
        .map_err(|e| Error::Database(format!("Invalid asset UUID '{asset_id_str}': {e}")))?;
    let changed_at = DateTime::parse_from_rfc3339(&changed_at_str)
        .map(|dt| dt.with_timezone(&chrono::Utc))
        .map_err(|e| Error::Database(format!("Invalid timestamp '{changed_at_str}': {e}")))?;

    Ok(AssetChange { id, asset_id, field, old_value, new_value, changed_at })
}

// ── Database impl ─────────────────────────────────────────────────────────────

impl Database {
    // ── Assets ────────────────────────────────────────────────────────────────

    /// Insert a new asset for `session_id`. Fails if the generated UUID already exists.
    pub fn create_asset(
        &self,
        session_id: Uuid,
        kind: AssetKind,
        value: &str,
        metadata: serde_json::Value,
    ) -> Result<Asset, Error> {
        let asset = Asset {
            id: Uuid::new_v4(),
            session_id,
            kind,
            value: value.to_string(),
            metadata,
            discovered_at: chrono::Utc::now(),
        };
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO assets (id, session_id, kind, value, metadata, discovered_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    asset.id.to_string(),
                    asset.session_id.to_string(),
                    asset.kind.to_string(),
                    asset.value,
                    asset.metadata.to_string(),
                    asset.discovered_at.to_rfc3339(),
                ],
            )
            .map_err(|e| Error::Database(format!("create_asset failed: {e}")))?;
            Ok(asset.clone())
        })
    }

    /// Return all assets belonging to `session_id`, ordered by discovery time ascending.
    pub fn get_assets(&self, session_id: Uuid) -> Result<Vec<Asset>, Error> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, session_id, kind, value, metadata, discovered_at
                     FROM assets WHERE session_id = ?1
                     ORDER BY discovered_at ASC",
                )
                .map_err(|e| Error::Database(e.to_string()))?;

            let assets = stmt
                .query_map(params![session_id.to_string()], |row| {
                    Ok(row_to_asset(row))
                })
                .map_err(|e| Error::Database(e.to_string()))?
                .filter_map(|r| r.ok())
                .filter_map(|r| r.ok())
                .collect();

            Ok(assets)
        })
    }

    /// Return all assets of a specific kind for `session_id`.
    pub fn get_assets_by_kind(
        &self,
        session_id: Uuid,
        kind: AssetKind,
    ) -> Result<Vec<Asset>, Error> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, session_id, kind, value, metadata, discovered_at
                     FROM assets WHERE session_id = ?1 AND kind = ?2
                     ORDER BY discovered_at ASC",
                )
                .map_err(|e| Error::Database(e.to_string()))?;

            let assets = stmt
                .query_map(params![session_id.to_string(), kind.to_string()], |row| {
                    Ok(row_to_asset(row))
                })
                .map_err(|e| Error::Database(e.to_string()))?
                .filter_map(|r| r.ok())
                .filter_map(|r| r.ok())
                .collect();

            Ok(assets)
        })
    }

    /// Insert or retrieve an asset by (session_id, kind, value).
    ///
    /// Returns `(asset, true)` if a new row was inserted, or `(asset, false)` if
    /// an existing row was found. When found, the stored metadata is updated to
    /// the provided value and the existing row (with original `discovered_at`) is
    /// returned.
    pub fn upsert_asset(
        &self,
        session_id: Uuid,
        kind: AssetKind,
        value: &str,
        metadata: serde_json::Value,
    ) -> Result<(Asset, bool), Error> {
        self.with_conn(|conn| {
            // SELECT first — check for existing (session_id, kind, value)
            let existing: Option<Asset> = {
                let mut stmt = conn
                    .prepare(
                        "SELECT id, session_id, kind, value, metadata, discovered_at
                         FROM assets
                         WHERE session_id = ?1 AND kind = ?2 AND value = ?3
                         LIMIT 1",
                    )
                    .map_err(|e| Error::Database(e.to_string()))?;

                let mut rows = stmt
                    .query(params![
                        session_id.to_string(),
                        kind.to_string(),
                        value,
                    ])
                    .map_err(|e| Error::Database(e.to_string()))?;

                if let Some(row) = rows.next().map_err(|e| Error::Database(e.to_string()))? {
                    Some(row_to_asset(row)?)
                } else {
                    None
                }
            };

            match existing {
                Some(mut asset) => {
                    // Update metadata on the existing row
                    conn.execute(
                        "UPDATE assets SET metadata = ?1 WHERE id = ?2",
                        params![metadata.to_string(), asset.id.to_string()],
                    )
                    .map_err(|e| Error::Database(format!("upsert_asset update failed: {e}")))?;
                    asset.metadata = metadata;
                    Ok((asset, false))
                }
                None => {
                    // INSERT new row
                    let asset = Asset {
                        id: Uuid::new_v4(),
                        session_id,
                        kind,
                        value: value.to_string(),
                        metadata,
                        discovered_at: chrono::Utc::now(),
                    };
                    conn.execute(
                        "INSERT INTO assets (id, session_id, kind, value, metadata, discovered_at)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                        params![
                            asset.id.to_string(),
                            asset.session_id.to_string(),
                            asset.kind.to_string(),
                            asset.value,
                            asset.metadata.to_string(),
                            asset.discovered_at.to_rfc3339(),
                        ],
                    )
                    .map_err(|e| Error::Database(format!("upsert_asset insert failed: {e}")))?;
                    Ok((asset, true))
                }
            }
        })
    }

    // ── Asset Services ────────────────────────────────────────────────────────

    /// Insert a new service associated with `asset_id`.
    pub fn create_service(
        &self,
        asset_id: Uuid,
        port: i32,
        protocol: &str,
        service: &str,
        version: Option<&str>,
        banner: Option<&str>,
    ) -> Result<AssetService, Error> {
        let svc = AssetService {
            id: Uuid::new_v4(),
            asset_id,
            port,
            protocol: protocol.to_string(),
            service: service.to_string(),
            version: version.map(|s| s.to_string()),
            banner: banner.map(|s| s.to_string()),
            discovered_at: chrono::Utc::now(),
        };
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO asset_services
                 (id, asset_id, port, protocol, service, version, banner, discovered_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    svc.id.to_string(),
                    svc.asset_id.to_string(),
                    svc.port,
                    svc.protocol,
                    svc.service,
                    svc.version,
                    svc.banner,
                    svc.discovered_at.to_rfc3339(),
                ],
            )
            .map_err(|e| Error::Database(format!("create_service failed: {e}")))?;
            Ok(svc.clone())
        })
    }

    /// Return all services for `asset_id`, ordered by port ascending.
    pub fn get_services(&self, asset_id: Uuid) -> Result<Vec<AssetService>, Error> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, asset_id, port, protocol, service, version, banner, discovered_at
                     FROM asset_services WHERE asset_id = ?1
                     ORDER BY port ASC",
                )
                .map_err(|e| Error::Database(e.to_string()))?;

            let services = stmt
                .query_map(params![asset_id.to_string()], |row| {
                    Ok(row_to_service(row))
                })
                .map_err(|e| Error::Database(e.to_string()))?
                .filter_map(|r| r.ok())
                .filter_map(|r| r.ok())
                .collect();

            Ok(services)
        })
    }

    // ── Asset Changes ─────────────────────────────────────────────────────────

    /// Record a field-level change to an asset.
    pub fn record_change(
        &self,
        asset_id: Uuid,
        field: &str,
        old_value: &str,
        new_value: &str,
    ) -> Result<AssetChange, Error> {
        let change = AssetChange {
            id: Uuid::new_v4(),
            asset_id,
            field: field.to_string(),
            old_value: old_value.to_string(),
            new_value: new_value.to_string(),
            changed_at: chrono::Utc::now(),
        };
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO asset_changes (id, asset_id, field, old_value, new_value, changed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    change.id.to_string(),
                    change.asset_id.to_string(),
                    change.field,
                    change.old_value,
                    change.new_value,
                    change.changed_at.to_rfc3339(),
                ],
            )
            .map_err(|e| Error::Database(format!("record_change failed: {e}")))?;
            Ok(change.clone())
        })
    }

    /// Return all recorded changes for `asset_id`, ordered by change time ascending.
    pub fn get_changes(&self, asset_id: Uuid) -> Result<Vec<AssetChange>, Error> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, asset_id, field, old_value, new_value, changed_at
                     FROM asset_changes WHERE asset_id = ?1
                     ORDER BY changed_at ASC",
                )
                .map_err(|e| Error::Database(e.to_string()))?;

            let changes = stmt
                .query_map(params![asset_id.to_string()], |row| {
                    Ok(row_to_change(row))
                })
                .map_err(|e| Error::Database(e.to_string()))?
                .filter_map(|r| r.ok())
                .filter_map(|r| r.ok())
                .collect();

            Ok(changes)
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Database;
    use sigint_core::types::Session;

    fn db() -> Database {
        Database::open_in_memory().unwrap()
    }

    fn make_session(db: &Database) -> Uuid {
        let s = Session::new("test-session");
        db.create_session(&s).unwrap();
        s.id
    }

    // ── Asset CRUD ────────────────────────────────────────────────────────────

    #[test]
    fn create_and_get_asset() {
        let db = db();
        let sid = make_session(&db);
        let asset = db
            .create_asset(sid, AssetKind::Host, "192.168.1.1", serde_json::Value::Null)
            .unwrap();

        let assets = db.get_assets(sid).unwrap();
        assert_eq!(assets.len(), 1);
        assert_eq!(assets[0].id, asset.id);
        assert_eq!(assets[0].value, "192.168.1.1");
        assert_eq!(assets[0].kind, AssetKind::Host);
        assert_eq!(assets[0].session_id, sid);
    }

    #[test]
    fn get_assets_empty_session() {
        let db = db();
        let sid = make_session(&db);
        let assets = db.get_assets(sid).unwrap();
        assert!(assets.is_empty());
    }

    #[test]
    fn get_assets_by_kind_filters_correctly() {
        let db = db();
        let sid = make_session(&db);
        db.create_asset(sid, AssetKind::Host, "10.0.0.1", serde_json::Value::Null).unwrap();
        db.create_asset(sid, AssetKind::Domain, "example.com", serde_json::Value::Null).unwrap();
        db.create_asset(sid, AssetKind::Host, "10.0.0.2", serde_json::Value::Null).unwrap();

        let hosts = db.get_assets_by_kind(sid, AssetKind::Host).unwrap();
        let domains = db.get_assets_by_kind(sid, AssetKind::Domain).unwrap();
        let urls = db.get_assets_by_kind(sid, AssetKind::Url).unwrap();

        assert_eq!(hosts.len(), 2);
        assert_eq!(domains.len(), 1);
        assert!(urls.is_empty());
    }

    #[test]
    fn asset_metadata_roundtrips() {
        let db = db();
        let sid = make_session(&db);
        let metadata = serde_json::json!({"os": "Linux", "ttl": 64});
        let asset = db.create_asset(sid, AssetKind::Host, "10.0.0.1", metadata.clone()).unwrap();

        let fetched = db.get_assets(sid).unwrap();
        assert_eq!(fetched[0].id, asset.id);
        assert_eq!(fetched[0].metadata, metadata);
    }

    #[test]
    fn assets_cascade_delete_with_session() {
        let db = db();
        let sid = make_session(&db);
        db.create_asset(sid, AssetKind::Host, "10.0.0.1", serde_json::Value::Null).unwrap();
        db.delete_session(sid).unwrap();
        let assets = db.get_assets(sid).unwrap();
        assert!(assets.is_empty());
    }

    // ── Upsert ────────────────────────────────────────────────────────────────

    #[test]
    fn upsert_asset_creates_new() {
        let db = db();
        let sid = make_session(&db);
        let (asset, is_new) = db
            .upsert_asset(sid, AssetKind::Host, "10.0.0.1", serde_json::Value::Null)
            .unwrap();

        assert!(is_new);
        assert_eq!(asset.value, "10.0.0.1");
        assert_eq!(db.get_assets(sid).unwrap().len(), 1);
    }

    #[test]
    fn upsert_asset_returns_existing() {
        let db = db();
        let sid = make_session(&db);

        let (first, is_new1) = db
            .upsert_asset(sid, AssetKind::Host, "10.0.0.1", serde_json::Value::Null)
            .unwrap();
        let meta2 = serde_json::json!({"updated": true});
        let (second, is_new2) = db
            .upsert_asset(sid, AssetKind::Host, "10.0.0.1", meta2.clone())
            .unwrap();

        assert!(is_new1);
        assert!(!is_new2);
        assert_eq!(first.id, second.id, "same UUID — same row");
        assert_eq!(second.metadata, meta2, "metadata should be updated");
        assert_eq!(db.get_assets(sid).unwrap().len(), 1, "no duplicate rows");
    }

    #[test]
    fn upsert_distinguishes_by_kind() {
        let db = db();
        let sid = make_session(&db);

        // Same value, different kind — should create two distinct assets
        let (_, is_new1) = db
            .upsert_asset(sid, AssetKind::Host, "example.com", serde_json::Value::Null)
            .unwrap();
        let (_, is_new2) = db
            .upsert_asset(sid, AssetKind::Domain, "example.com", serde_json::Value::Null)
            .unwrap();

        assert!(is_new1);
        assert!(is_new2);
        assert_eq!(db.get_assets(sid).unwrap().len(), 2);
    }

    // ── Asset Services ────────────────────────────────────────────────────────

    #[test]
    fn create_and_get_service() {
        let db = db();
        let sid = make_session(&db);
        let asset = db
            .create_asset(sid, AssetKind::Host, "10.0.0.1", serde_json::Value::Null)
            .unwrap();

        let svc = db
            .create_service(asset.id, 443, "tcp", "https", Some("nginx/1.24"), Some("HTTP/1.1"))
            .unwrap();

        let services = db.get_services(asset.id).unwrap();
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].id, svc.id);
        assert_eq!(services[0].port, 443);
        assert_eq!(services[0].protocol, "tcp");
        assert_eq!(services[0].service, "https");
        assert_eq!(services[0].version.as_deref(), Some("nginx/1.24"));
        assert_eq!(services[0].banner.as_deref(), Some("HTTP/1.1"));
    }

    #[test]
    fn service_optional_fields_nullable() {
        let db = db();
        let sid = make_session(&db);
        let asset = db
            .create_asset(sid, AssetKind::Host, "10.0.0.1", serde_json::Value::Null)
            .unwrap();

        db.create_service(asset.id, 22, "tcp", "ssh", None, None).unwrap();

        let services = db.get_services(asset.id).unwrap();
        assert_eq!(services.len(), 1);
        assert!(services[0].version.is_none());
        assert!(services[0].banner.is_none());
    }

    #[test]
    fn services_ordered_by_port() {
        let db = db();
        let sid = make_session(&db);
        let asset = db
            .create_asset(sid, AssetKind::Host, "10.0.0.1", serde_json::Value::Null)
            .unwrap();

        db.create_service(asset.id, 8080, "tcp", "http", None, None).unwrap();
        db.create_service(asset.id, 22, "tcp", "ssh", None, None).unwrap();
        db.create_service(asset.id, 443, "tcp", "https", None, None).unwrap();

        let services = db.get_services(asset.id).unwrap();
        let ports: Vec<i32> = services.iter().map(|s| s.port).collect();
        assert_eq!(ports, vec![22, 443, 8080]);
    }

    #[test]
    fn services_cascade_delete_with_asset() {
        let db = db();
        let sid = make_session(&db);
        let asset = db
            .create_asset(sid, AssetKind::Host, "10.0.0.1", serde_json::Value::Null)
            .unwrap();
        db.create_service(asset.id, 443, "tcp", "https", None, None).unwrap();
        db.delete_session(sid).unwrap();
        // Asset is deleted by session CASCADE; service is deleted by asset CASCADE
        let services = db.get_services(asset.id).unwrap();
        assert!(services.is_empty());
    }

    // ── Asset Changes ─────────────────────────────────────────────────────────

    #[test]
    fn record_and_get_changes() {
        let db = db();
        let sid = make_session(&db);
        let asset = db
            .create_asset(sid, AssetKind::Host, "10.0.0.1", serde_json::Value::Null)
            .unwrap();

        let change = db
            .record_change(asset.id, "metadata.os", "unknown", "Linux")
            .unwrap();

        let changes = db.get_changes(asset.id).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].id, change.id);
        assert_eq!(changes[0].field, "metadata.os");
        assert_eq!(changes[0].old_value, "unknown");
        assert_eq!(changes[0].new_value, "Linux");
    }

    #[test]
    fn changes_ordered_by_time() {
        let db = db();
        let sid = make_session(&db);
        let asset = db
            .create_asset(sid, AssetKind::Host, "10.0.0.1", serde_json::Value::Null)
            .unwrap();

        db.record_change(asset.id, "status", "unknown", "up").unwrap();
        db.record_change(asset.id, "os", "unknown", "Linux").unwrap();
        db.record_change(asset.id, "version", "old", "new").unwrap();

        let changes = db.get_changes(asset.id).unwrap();
        assert_eq!(changes.len(), 3);
        // Verify field ordering matches insertion order (timestamps are monotonic)
        let fields: Vec<&str> = changes.iter().map(|c| c.field.as_str()).collect();
        assert_eq!(fields, vec!["status", "os", "version"]);
    }

    #[test]
    fn changes_cascade_delete_with_asset() {
        let db = db();
        let sid = make_session(&db);
        let asset = db
            .create_asset(sid, AssetKind::Host, "10.0.0.1", serde_json::Value::Null)
            .unwrap();
        db.record_change(asset.id, "field", "old", "new").unwrap();
        db.delete_session(sid).unwrap();
        let changes = db.get_changes(asset.id).unwrap();
        assert!(changes.is_empty());
    }
}
