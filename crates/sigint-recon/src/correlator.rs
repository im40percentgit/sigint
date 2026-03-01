//! Asset correlator — deduplicates and links related assets from discovery modules.
//!
//! @decision DEC-RECON-006
//! @title Correlator deduplicates by (kind, value) and enriches metadata with relationships
//! @status accepted
//! @rationale Multiple discovery modules may return the same asset (e.g., DNS
//! and port modules both produce a Host asset for the same IP). The correlator
//! merges these by (kind, value) as the unique key, combining metadata fields
//! from all sources. It also records relationships in metadata (e.g., which
//! domain resolved to which IPs) so the engine doesn't need to query the store
//! for graph traversal during a single run.

use sigint_core::types::{Asset, AssetKind};
use std::collections::HashMap;

#[cfg(test)]
use uuid::Uuid;

/// A deduplication key that can be used in a HashMap (AssetKind doesn't impl Hash).
type DedupeKey = (String, String);

/// Result of a correlation pass — deduplicated assets with merged metadata.
#[derive(Debug)]
pub struct CorrelationResult {
    /// All unique assets found, with merged metadata.
    pub assets: Vec<Asset>,
    /// Number of duplicate assets merged (total input - unique output).
    pub duplicates_merged: usize,
}

/// Deduplicates and correlates assets from multiple discovery modules.
pub struct Correlator;

impl Correlator {
    /// Deduplicate a list of assets by `(kind, value)`, merging metadata from duplicates.
    ///
    /// When two assets have the same `(kind, value)`:
    /// - The first asset's `id` and `discovered_at` are kept.
    /// - Metadata objects are merged: keys from later assets fill in missing
    ///   keys from the first. Non-null values from the first always take precedence.
    pub fn correlate(assets: Vec<Asset>) -> CorrelationResult {
        let input_len = assets.len();
        let mut seen: HashMap<DedupeKey, Asset> = HashMap::new();
        let mut order: Vec<DedupeKey> = Vec::new();

        for asset in assets {
            let key = (asset.kind.to_string(), asset.value.clone());

            match seen.get_mut(&key) {
                Some(existing) => {
                    // Merge metadata: fill in missing keys from the new asset
                    merge_metadata(&mut existing.metadata, &asset.metadata);
                }
                None => {
                    order.push(key.clone());
                    seen.insert(key, asset);
                }
            }
        }

        let assets: Vec<Asset> = order
            .into_iter()
            .filter_map(|k| seen.remove(&k))
            .collect();

        let duplicates_merged = input_len.saturating_sub(assets.len());

        CorrelationResult { assets, duplicates_merged }
    }

    /// Link Host assets to the domains that resolved to them.
    ///
    /// For each Domain asset, finds Host assets whose value appears in the
    /// domain's context (heuristic: any Host asset in the same batch is
    /// considered potentially related). Adds a `resolved_from` metadata key
    /// to Host assets and a `resolves_to` key on Domain assets.
    ///
    /// This is a best-effort pass — we don't re-run DNS queries here.
    pub fn link_domains_to_hosts(assets: &mut Vec<Asset>, domain: &str) {
        let host_ips: Vec<String> = assets
            .iter()
            .filter(|a| a.kind == AssetKind::Host)
            .map(|a| a.value.clone())
            .collect();

        if host_ips.is_empty() {
            return;
        }

        for asset in assets.iter_mut() {
            if asset.kind == AssetKind::Domain && asset.value == domain {
                // Ensure metadata is an object (upgrade from Null if needed)
                if asset.metadata.is_null() {
                    asset.metadata = serde_json::json!({});
                }
                if let Some(obj) = asset.metadata.as_object_mut() {
                    obj.insert(
                        "resolves_to".to_string(),
                        serde_json::Value::Array(
                            host_ips.iter().map(|ip| serde_json::json!(ip)).collect(),
                        ),
                    );
                }
            }
            if asset.kind == AssetKind::Host {
                // Ensure metadata is an object (upgrade from Null if needed)
                if asset.metadata.is_null() {
                    asset.metadata = serde_json::json!({});
                }
                if let Some(obj) = asset.metadata.as_object_mut() {
                    if !obj.contains_key("resolved_from") {
                        obj.insert(
                            "resolved_from".to_string(),
                            serde_json::json!(domain),
                        );
                    }
                }
            }
        }
    }
}

/// Merge `source` metadata into `dest`, only filling in keys that are missing or null in `dest`.
fn merge_metadata(dest: &mut serde_json::Value, source: &serde_json::Value) {
    match (dest.as_object_mut(), source.as_object()) {
        (Some(dest_obj), Some(src_obj)) => {
            for (key, val) in src_obj {
                let dest_val = dest_obj.get(key);
                if dest_val.is_none() || dest_val == Some(&serde_json::Value::Null) {
                    dest_obj.insert(key.clone(), val.clone());
                }
            }
        }
        _ => {
            // If dest is null and source has content, replace
            if dest.is_null() && !source.is_null() {
                *dest = source.clone();
            }
        }
    }
}

/// Build a placeholder Asset for testing.
#[cfg(test)]
pub(crate) fn make_asset(kind: AssetKind, value: &str, session_id: Uuid) -> Asset {
    Asset {
        id: Uuid::new_v4(),
        session_id,
        kind,
        value: value.to_string(),
        metadata: serde_json::Value::Null,
        discovered_at: chrono::Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid() -> Uuid {
        Uuid::new_v4()
    }

    #[test]
    fn correlate_no_duplicates() {
        let sid = sid();
        let assets = vec![
            make_asset(AssetKind::Host, "10.0.0.1", sid),
            make_asset(AssetKind::Domain, "example.com", sid),
        ];
        let result = Correlator::correlate(assets);
        assert_eq!(result.assets.len(), 2);
        assert_eq!(result.duplicates_merged, 0);
    }

    #[test]
    fn correlate_merges_same_kind_and_value() {
        let sid = sid();
        let mut a1 = make_asset(AssetKind::Host, "10.0.0.1", sid);
        a1.metadata = serde_json::json!({"source": "dns"});
        let mut a2 = make_asset(AssetKind::Host, "10.0.0.1", sid);
        a2.metadata = serde_json::json!({"source": "port", "extra": "data"});

        let result = Correlator::correlate(vec![a1, a2]);
        assert_eq!(result.assets.len(), 1);
        assert_eq!(result.duplicates_merged, 1);
        // First value wins for "source"
        assert_eq!(result.assets[0].metadata["source"], "dns");
        // Missing keys get filled in
        assert_eq!(result.assets[0].metadata["extra"], "data");
    }

    #[test]
    fn correlate_preserves_first_id() {
        let sid = sid();
        let a1 = make_asset(AssetKind::Host, "10.0.0.1", sid);
        let first_id = a1.id;
        let a2 = make_asset(AssetKind::Host, "10.0.0.1", sid);

        let result = Correlator::correlate(vec![a1, a2]);
        assert_eq!(result.assets[0].id, first_id);
    }

    #[test]
    fn correlate_different_kinds_same_value() {
        // Domain and Host with same value string should NOT be merged
        let sid = sid();
        let assets = vec![
            make_asset(AssetKind::Domain, "example.com", sid),
            make_asset(AssetKind::Host, "example.com", sid),
        ];
        let result = Correlator::correlate(assets);
        assert_eq!(result.assets.len(), 2);
        assert_eq!(result.duplicates_merged, 0);
    }

    #[test]
    fn correlate_preserves_order() {
        let sid = sid();
        let assets = vec![
            make_asset(AssetKind::Host, "10.0.0.3", sid),
            make_asset(AssetKind::Host, "10.0.0.1", sid),
            make_asset(AssetKind::Host, "10.0.0.2", sid),
        ];
        let result = Correlator::correlate(assets);
        let values: Vec<&str> = result.assets.iter().map(|a| a.value.as_str()).collect();
        assert_eq!(values, vec!["10.0.0.3", "10.0.0.1", "10.0.0.2"]);
    }

    #[test]
    fn merge_metadata_fills_missing_keys() {
        let mut dest = serde_json::json!({"a": 1});
        let source = serde_json::json!({"b": 2, "c": 3});
        merge_metadata(&mut dest, &source);
        assert_eq!(dest["a"], 1);
        assert_eq!(dest["b"], 2);
        assert_eq!(dest["c"], 3);
    }

    #[test]
    fn merge_metadata_does_not_overwrite_existing() {
        let mut dest = serde_json::json!({"key": "original"});
        let source = serde_json::json!({"key": "replacement"});
        merge_metadata(&mut dest, &source);
        assert_eq!(dest["key"], "original");
    }

    #[test]
    fn link_domains_to_hosts_adds_metadata() {
        let sid = sid();
        let mut assets = vec![
            make_asset(AssetKind::Domain, "example.com", sid),
            make_asset(AssetKind::Host, "93.184.216.34", sid),
        ];
        // Give host a mutable metadata object
        assets[1].metadata = serde_json::json!({});

        Correlator::link_domains_to_hosts(&mut assets, "example.com");

        // Domain should have resolves_to
        let domain = assets.iter().find(|a| a.kind == AssetKind::Domain).unwrap();
        assert!(domain.metadata["resolves_to"].is_array());

        // Host should have resolved_from
        let host = assets.iter().find(|a| a.kind == AssetKind::Host).unwrap();
        assert_eq!(host.metadata["resolved_from"], "example.com");
    }
}
