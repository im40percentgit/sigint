//! Change detection — compares newly discovered assets against previously stored state.
//!
//! @decision DEC-RECON-007
//! @title Change detector compares metadata JSON blobs as strings for simplicity
//! @status accepted
//! @rationale Full JSON diffing would require walking the object tree recursively,
//! which adds complexity for the Phase 4B scope. A string comparison of the
//! serialized metadata is sufficient to detect any change and trigger a change
//! record. The field name "metadata" is stored in asset_changes so the UI can
//! display what changed. Future phases can refine this to per-key diffs.

use sigint_core::types::Asset;
use sigint_store::db::Database;
use uuid::Uuid;

use crate::error::ReconError;

/// Detects changes between newly discovered assets and what was previously stored.
pub struct ChangeDetector<'a> {
    db: &'a Database,
}

impl<'a> ChangeDetector<'a> {
    /// Create a new ChangeDetector backed by the given store.
    pub fn new(db: &'a Database) -> Self {
        Self { db }
    }

    /// Compare `new_assets` against what is currently stored for `session_id`.
    ///
    /// For each asset in `new_assets` that already exists in the store
    /// (matched by kind + value), check if metadata has changed. If it has,
    /// call `db.record_change()` to create a change record.
    ///
    /// Returns the number of changes recorded.
    pub fn detect_and_record(
        &self,
        session_id: Uuid,
        new_assets: &[Asset],
    ) -> Result<usize, ReconError> {
        // Load previously stored assets for comparison
        let stored = self
            .db
            .get_assets(session_id)
            .map_err(|e| ReconError::Store(e.to_string()))?;

        let mut changes = 0;

        for new_asset in new_assets {
            // Find a matching stored asset by (kind, value)
            if let Some(stored_asset) = stored
                .iter()
                .find(|s| s.kind == new_asset.kind && s.value == new_asset.value)
            {
                let old_meta = stored_asset.metadata.to_string();
                let new_meta = new_asset.metadata.to_string();

                if old_meta != new_meta {
                    self.db
                        .record_change(stored_asset.id, "metadata", &old_meta, &new_meta)
                        .map_err(|e| ReconError::Store(e.to_string()))?;
                    changes += 1;
                }
            }
        }

        Ok(changes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigint_core::types::{AssetKind, Session};
    use sigint_store::db::Database;

    fn setup_db() -> (Database, Uuid) {
        let db = Database::open_in_memory().unwrap();
        let session = Session::new("test");
        db.create_session(&session).unwrap();
        (db, session.id)
    }

    #[test]
    fn no_changes_when_metadata_same() {
        let (db, sid) = setup_db();
        // Store the asset with initial metadata
        db.upsert_asset(
            sid,
            AssetKind::Host,
            "10.0.0.1",
            serde_json::json!({"os": "Linux"}),
        )
        .unwrap();

        // New asset with same metadata
        let new_asset = Asset {
            id: Uuid::new_v4(),
            session_id: sid,
            kind: AssetKind::Host,
            value: "10.0.0.1".to_string(),
            metadata: serde_json::json!({"os": "Linux"}),
            discovered_at: chrono::Utc::now(),
        };

        let detector = ChangeDetector::new(&db);
        let count = detector.detect_and_record(sid, &[new_asset]).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn detects_metadata_change() {
        let (db, sid) = setup_db();
        // Store with old metadata
        let (stored, _) = db
            .upsert_asset(
                sid,
                AssetKind::Host,
                "10.0.0.1",
                serde_json::json!({"os": "unknown"}),
            )
            .unwrap();

        // New asset with different metadata
        let new_asset = Asset {
            id: Uuid::new_v4(),
            session_id: sid,
            kind: AssetKind::Host,
            value: "10.0.0.1".to_string(),
            metadata: serde_json::json!({"os": "Linux"}),
            discovered_at: chrono::Utc::now(),
        };

        let detector = ChangeDetector::new(&db);
        let count = detector.detect_and_record(sid, &[new_asset]).unwrap();
        assert_eq!(count, 1);

        // Verify change was recorded
        let changes = db.get_changes(stored.id).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].field, "metadata");
    }

    #[test]
    fn new_asset_not_in_store_is_skipped() {
        let (db, sid) = setup_db();

        // No stored asset — new asset should produce zero changes
        let new_asset = Asset {
            id: Uuid::new_v4(),
            session_id: sid,
            kind: AssetKind::Domain,
            value: "example.com".to_string(),
            metadata: serde_json::Value::Null,
            discovered_at: chrono::Utc::now(),
        };

        let detector = ChangeDetector::new(&db);
        let count = detector.detect_and_record(sid, &[new_asset]).unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn null_to_json_is_change() {
        let (db, sid) = setup_db();
        let (stored, _) = db
            .upsert_asset(sid, AssetKind::Host, "10.0.0.1", serde_json::Value::Null)
            .unwrap();

        let new_asset = Asset {
            id: Uuid::new_v4(),
            session_id: sid,
            kind: AssetKind::Host,
            value: "10.0.0.1".to_string(),
            metadata: serde_json::json!({"server": "nginx"}),
            discovered_at: chrono::Utc::now(),
        };

        let detector = ChangeDetector::new(&db);
        let count = detector.detect_and_record(sid, &[new_asset]).unwrap();
        assert_eq!(count, 1);

        let changes = db.get_changes(stored.id).unwrap();
        assert_eq!(changes.len(), 1);
    }

    #[test]
    fn only_changed_assets_are_recorded() {
        let (db, sid) = setup_db();

        db.upsert_asset(
            sid,
            AssetKind::Host,
            "10.0.0.1",
            serde_json::json!({"os": "Linux"}),
        )
        .unwrap();
        let (domain_asset, _) = db
            .upsert_asset(
                sid,
                AssetKind::Domain,
                "example.com",
                serde_json::json!({"registrar": "ICANN"}),
            )
            .unwrap();

        let new_assets = vec![
            Asset {
                // unchanged
                id: Uuid::new_v4(),
                session_id: sid,
                kind: AssetKind::Host,
                value: "10.0.0.1".to_string(),
                metadata: serde_json::json!({"os": "Linux"}),
                discovered_at: chrono::Utc::now(),
            },
            Asset {
                // changed
                id: Uuid::new_v4(),
                session_id: sid,
                kind: AssetKind::Domain,
                value: "example.com".to_string(),
                metadata: serde_json::json!({"registrar": "NEW"}),
                discovered_at: chrono::Utc::now(),
            },
        ];

        let detector = ChangeDetector::new(&db);
        let count = detector.detect_and_record(sid, &new_assets).unwrap();
        assert_eq!(count, 1);

        let changes = db.get_changes(domain_asset.id).unwrap();
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].field, "metadata");
    }
}
