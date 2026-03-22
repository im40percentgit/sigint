//! Campaign configuration types for multi-target scan orchestration.
//!
//! This module implements the serde-deserializable types used to parse campaign
//! YAML/JSON files (DEC-CAMPAIGN-001). A campaign file groups one or more
//! targets with named scan profiles, letting operators run coordinated,
//! profile-driven scans across an entire engagement without re-specifying
//! tool/port options for every target.
//!
//! @decision DEC-CAMPAIGN-001: Campaign files use a flat profiles map + targets
//! list model. Profiles are referenced by name; "default" is an implicit
//! built-in that requires no explicit declaration.

use serde::Deserialize;
use std::collections::HashMap;

/// A campaign configuration file (DEC-CAMPAIGN-001).
///
/// Deserializes from a JSON or TOML document with an optional `profiles` map
/// and a required non-empty `targets` list. Call [`CampaignFile::validate`]
/// after deserialization to catch forward-reference errors.
#[derive(Debug, Clone, Deserialize)]
pub struct CampaignFile {
    #[serde(default)]
    pub profiles: HashMap<String, ScanProfile>,
    pub targets: Vec<CampaignTarget>,
}

/// A scan profile adjusting orchestrator behavior for a set of targets.
///
/// All fields have sensible defaults so a profile block may be as minimal as
/// `{ }`. Optional fields (`max_iterations`, `ports`) are omitted from the
/// orchestrator context when absent.
#[derive(Debug, Clone, Deserialize)]
pub struct ScanProfile {
    /// Allowed tool names for this profile (empty = no restriction).
    #[serde(default)]
    pub tools: Vec<String>,
    /// Free-text focus hint passed to the agent system prompt.
    #[serde(default)]
    pub focus: String,
    /// Cap on orchestrator iterations for targets using this profile.
    pub max_iterations: Option<usize>,
    /// Port specification forwarded to nmap/gobuster (e.g. `"80,443,8080"`).
    pub ports: Option<String>,
}

/// A single target in a campaign.
///
/// `profile` defaults to `"default"` when omitted, mapping to implicit
/// built-in behaviour with no profile-level overrides.
#[derive(Debug, Clone, Deserialize)]
pub struct CampaignTarget {
    /// Human-readable label used in reports and log output.
    pub name: String,
    /// Hostname, IP address, or CIDR range to scan.
    pub target: String,
    /// Name of the [`ScanProfile`] to apply; defaults to `"default"`.
    #[serde(default = "default_profile")]
    pub profile: String,
}

fn default_profile() -> String {
    "default".into()
}

impl CampaignFile {
    /// Validate that the campaign is well-formed.
    ///
    /// Checks:
    /// 1. The `targets` list is non-empty.
    /// 2. Every target that references a non-`"default"` profile has a
    ///    matching entry in `profiles`.
    ///
    /// Returns `Ok(())` on success, or an `Err` with a human-readable
    /// description of the first problem found.
    pub fn validate(&self) -> Result<(), String> {
        if self.targets.is_empty() {
            return Err("Campaign has no targets".into());
        }
        for t in &self.targets {
            if t.profile != "default" && !self.profiles.contains_key(&t.profile) {
                return Err(format!(
                    "Target '{}' references unknown profile '{}'",
                    t.name, t.profile
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_campaign_file() {
        let json = r#"{
            "profiles": {
                "web": {
                    "tools": ["nmap_scan", "shell"],
                    "focus": "web application security"
                }
            },
            "targets": [
                { "name": "Main Site", "target": "example.com", "profile": "web" }
            ]
        }"#;
        let cf: CampaignFile = serde_json::from_str(json).unwrap();
        assert_eq!(cf.targets.len(), 1);
        assert_eq!(cf.profiles["web"].focus, "web application security");
    }

    #[test]
    fn validate_missing_profile_errors() {
        let cf = CampaignFile {
            profiles: HashMap::new(),
            targets: vec![CampaignTarget {
                name: "Test".into(),
                target: "example.com".into(),
                profile: "missing".into(),
            }],
        };
        assert!(cf.validate().unwrap_err().contains("missing"));
    }

    #[test]
    fn validate_empty_targets_errors() {
        let cf = CampaignFile {
            profiles: HashMap::new(),
            targets: vec![],
        };
        assert!(cf.validate().is_err());
    }

    #[test]
    fn profile_defaults_applied() {
        let json = r#"{ "tools": [], "focus": "" }"#;
        let p: ScanProfile = serde_json::from_str(json).unwrap();
        assert!(p.tools.is_empty());
        assert!(p.max_iterations.is_none());
    }

    #[test]
    fn campaign_target_default_profile() {
        let json = r#"{ "name": "Test", "target": "example.com" }"#;
        let t: CampaignTarget = serde_json::from_str(json).unwrap();
        assert_eq!(t.profile, "default");
    }
}
