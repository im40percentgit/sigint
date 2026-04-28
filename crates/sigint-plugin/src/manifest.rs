//! Plugin manifest schema — JSON v1.
//!
//! Defines the [`PluginManifest`] struct and the [`parse_manifest`] /
//! [`validate_manifest`] helpers.  Every `.sgnt-pack` archive contains a
//! `manifest.json` at its root; this module owns both the schema and its
//! validation rules.
//!
//! @decision DEC-P27-002
//! @title Manifest schema: JSON with `manifest_version: 1` discriminator
//! @status accepted
//! @rationale JSON is the lingua franca for SDK manifests, machine-validated
//! easily, version-discriminated cleanly via `manifest_version`.  Required
//! fields: `manifest_version`, `id`, `version`, `target_triple`,
//! `entry_symbol`.  Optional fields: `display_name`, `description`, `author`,
//! `homepage`, `license`, `library_filename`.  Schema is open for additive
//! fields; unknown optional fields are captured in `extra` and never cause
//! validation failure.  Phase 28 seam: `manifest_version: 2` (signed packs)
//! can be introduced without breaking v1 parsing — the discriminator check
//! in `validate_manifest` surfaces a clear error for unsupported versions.
//!
//! # Phase 28 seams preserved
//!
//! **Seam #1 — reserved fields:** `signature`, `signed_by`,
//! `signature_algorithm`, and `library_kind` are typed optional fields on
//! the struct.  Phase 27 ignores their values after parsing; Phase 28 wires
//! signature verification without a manifest version bump.
//!
//! **Seam #2 — version discriminator:** `validate_manifest` rejects
//! `manifest_version != 1` with a structured `PackError::UnsupportedManifestVersion`
//! carrying the version found.  Phase 28 increments the supported version
//! constant here; old sigint builds surface the "upgrade" error message
//! automatically.

use serde::{Deserialize, Serialize};
use serde_json::Map;

use crate::pack::PackError;

/// Supported manifest version.  Phase 28 bumps this to 2 for signed packs.
///
/// Phase 28 seam #2: change this constant (and add v2 validation logic in
/// `validate_manifest`) to accept `manifest_version: 2` packs.
pub const SUPPORTED_MANIFEST_VERSION: u32 = 1;

/// Parsed plugin manifest from a `.sgnt-pack` archive.
///
/// # Required fields
///
/// | Field | Description |
/// |-------|-------------|
/// | `manifest_version` | Schema version — must be `1` for Phase 27 packs. |
/// | `id` | Semver-stable plugin identifier, e.g. `"com.example.recon-foo"`. |
/// | `version` | Plugin version string (semver), e.g. `"0.1.0"`. |
/// | `target_triple` | Rust target triple the library was compiled for, e.g. `"x86_64-unknown-linux-gnu"`. |
/// | `entry_symbol` | C-ABI entry function name exported by the library, e.g. `"sigint_plugin_entry"`. |
///
/// # Optional fields
///
/// `display_name`, `description`, `author`, `homepage`, `license`,
/// `library_filename` (defaults to the platform-derived name if absent).
///
/// # Phase 28 reserved fields (Seam #1)
///
/// `signature`, `signed_by`, `signature_algorithm`, `library_kind` are
/// reserved but unused in Phase 27.  They are present as typed `Option<String>`
/// fields so Phase 28 can populate and verify them without a manifest schema
/// change.
///
/// # Forward compatibility
///
/// Unknown fields are captured in `extra` via `#[serde(flatten)]`.  They do
/// not cause validation failure.  This preserves the ability to add new
/// optional fields in future manifest versions without breaking Phase 27
/// installs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginManifest {
    // --- Required fields ---
    /// Manifest schema version.  Must equal `SUPPORTED_MANIFEST_VERSION` (1).
    pub manifest_version: u32,

    /// Semver-stable plugin identifier, e.g. `"com.example.recon-foo"`.
    /// Used as the directory name component under the install base.
    pub id: String,

    /// Plugin version string, e.g. `"0.1.0"`.
    pub version: String,

    /// Rust target triple the library was compiled for, e.g.
    /// `"x86_64-unknown-linux-gnu"`.  The install command validates this
    /// against the host triple before unpacking.
    pub target_triple: String,

    /// C-ABI entry function name exported by the shared library.
    /// Default is `"sigint_plugin_entry"` (see [`crate::abi::DEFAULT_ENTRY_SYMBOL`]).
    pub entry_symbol: String,

    // --- Optional metadata fields ---
    /// Human-readable plugin name shown by `sigint plugin list`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// Short description of what the plugin provides.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Plugin author(s).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,

    /// Plugin homepage URL.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,

    /// SPDX license identifier, e.g. `"MIT"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,

    /// Filename of the dynamic library inside the `lib/` directory of the
    /// archive.  When absent, the loader derives the name from `id` using
    /// platform conventions (`lib<id>.so`, `<id>.dylib`, `<id>.dll`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub library_filename: Option<String>,

    // --- Phase 28 reserved fields (Seam #1) ---
    /// Base64-encoded signature over the library bytes.  Unused in Phase 27.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,

    /// Key identifier or fingerprint of the signing key.  Unused in Phase 27.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,

    /// Signature algorithm identifier, e.g. `"ed25519"`.  Unused in Phase 27.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_algorithm: Option<String>,

    /// Library kind hint for future loaders.  Reserved for WASM support
    /// (REQ-P27-P2-002).  Unused in Phase 27.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub library_kind: Option<String>,

    // --- Forward-compat catch-all ---
    /// Any extra fields not recognised by this version of the manifest schema.
    /// Captured losslessly so future fields round-trip through old installs
    /// without being silently dropped.
    #[serde(flatten)]
    pub extra: Map<String, serde_json::Value>,
}

/// Parse and validate a plugin manifest from raw JSON bytes.
///
/// This is the primary entry point for manifest ingestion.  It delegates to
/// [`validate_manifest`] after deserialisation — callers never receive an
/// invalid manifest from this function.
///
/// # Errors
///
/// - [`PackError::Json`] — bytes are not valid JSON or have wrong types.
/// - [`PackError::MissingField`] — a required field is absent or empty.
/// - [`PackError::UnsupportedManifestVersion`] — `manifest_version` is not 1.
pub fn parse_manifest(json: &[u8]) -> Result<PluginManifest, PackError> {
    let manifest: PluginManifest = serde_json::from_slice(json)?;
    validate_manifest(&manifest)?;
    Ok(manifest)
}

/// Validate a parsed manifest.
///
/// Separated from [`parse_manifest`] so Phase 28 can re-validate after
/// adding signature fields without re-parsing the JSON.
///
/// # Validation rules
///
/// 1. `manifest_version` must equal [`SUPPORTED_MANIFEST_VERSION`].
/// 2. `id` must not be empty.
/// 3. `version` must not be empty.
/// 4. `target_triple` must not be empty.
/// 5. `entry_symbol` must not be empty.
///
/// Unknown fields in `extra` are silently accepted (forward-compat).
///
/// # Errors
///
/// - [`PackError::UnsupportedManifestVersion`] — version is not 1.
/// - [`PackError::MissingField`] — a required field is empty or absent.
pub fn validate_manifest(m: &PluginManifest) -> Result<(), PackError> {
    // Phase 28 seam #2: the version gate.  When Phase 28 introduces
    // manifest_version: 2, update SUPPORTED_MANIFEST_VERSION and add a v2
    // validation branch here rather than changing the error path.
    if m.manifest_version != SUPPORTED_MANIFEST_VERSION {
        return Err(PackError::UnsupportedManifestVersion {
            got: m.manifest_version,
        });
    }

    if m.id.trim().is_empty() {
        return Err(PackError::MissingField { field: "id" });
    }
    if m.version.trim().is_empty() {
        return Err(PackError::MissingField { field: "version" });
    }
    if m.target_triple.trim().is_empty() {
        return Err(PackError::MissingField {
            field: "target_triple",
        });
    }
    if m.entry_symbol.trim().is_empty() {
        return Err(PackError::MissingField {
            field: "entry_symbol",
        });
    }

    Ok(())
}

/// Derive the conventional library filename for a plugin on this platform.
///
/// When `manifest.library_filename` is set, that value is returned directly.
/// Otherwise the name is derived from `manifest.id` using OS conventions:
/// - Linux:   `lib<id>.so`
/// - macOS:   `lib<id>.dylib`
/// - Windows: `<id>.dll`
pub fn library_filename(manifest: &PluginManifest) -> String {
    if let Some(ref name) = manifest.library_filename {
        return name.clone();
    }
    #[cfg(target_os = "macos")]
    return format!("lib{}.dylib", manifest.id);
    #[cfg(target_os = "windows")]
    return format!("{}.dll", manifest.id);
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    format!("lib{}.so", manifest.id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_manifest_json(manifest_version: u32) -> String {
        serde_json::json!({
            "manifest_version": manifest_version,
            "id": "com.example.test",
            "version": "0.1.0",
            "target_triple": "x86_64-unknown-linux-gnu",
            "entry_symbol": "sigint_plugin_entry",
        })
        .to_string()
    }

    // -------------------------------------------------------------------------
    // parse_manifest_minimal
    // -------------------------------------------------------------------------
    #[test]
    fn parse_manifest_minimal() {
        let json = minimal_manifest_json(1);
        let m = parse_manifest(json.as_bytes()).expect("minimal manifest should parse");
        assert_eq!(m.manifest_version, 1);
        assert_eq!(m.id, "com.example.test");
        assert_eq!(m.version, "0.1.0");
        assert_eq!(m.target_triple, "x86_64-unknown-linux-gnu");
        assert_eq!(m.entry_symbol, "sigint_plugin_entry");
        assert!(m.display_name.is_none());
        assert!(m.signature.is_none());
        assert!(m.extra.is_empty());
    }

    // -------------------------------------------------------------------------
    // parse_manifest_full — every field populated, including Phase 28 reserved
    // -------------------------------------------------------------------------
    #[test]
    fn parse_manifest_full() {
        let json = serde_json::json!({
            "manifest_version": 1,
            "id": "com.example.full",
            "version": "1.2.3",
            "target_triple": "aarch64-unknown-linux-gnu",
            "entry_symbol": "my_entry",
            "display_name": "Full Plugin",
            "description": "A complete manifest example",
            "author": "Alice <alice@example.com>",
            "homepage": "https://example.com",
            "license": "MIT",
            "library_filename": "libfull.so",
            // Phase 28 reserved fields (Seam #1)
            "signature": "base64signaturehere==",
            "signed_by": "key-id-abc123",
            "signature_algorithm": "ed25519",
            "library_kind": "cdylib",
        })
        .to_string();

        let m = parse_manifest(json.as_bytes()).expect("full manifest should parse");
        assert_eq!(m.id, "com.example.full");
        assert_eq!(m.display_name.as_deref(), Some("Full Plugin"));
        assert_eq!(m.author.as_deref(), Some("Alice <alice@example.com>"));
        assert_eq!(m.library_filename.as_deref(), Some("libfull.so"));
        // Phase 28 reserved fields preserved
        assert_eq!(m.signature.as_deref(), Some("base64signaturehere=="));
        assert_eq!(m.signed_by.as_deref(), Some("key-id-abc123"));
        assert_eq!(m.signature_algorithm.as_deref(), Some("ed25519"));
        assert_eq!(m.library_kind.as_deref(), Some("cdylib"));
    }

    // -------------------------------------------------------------------------
    // parse_manifest_unsupported_version — manifest_version: 2 → clear error
    // -------------------------------------------------------------------------
    #[test]
    fn parse_manifest_unsupported_version() {
        let json = minimal_manifest_json(2);
        let err = parse_manifest(json.as_bytes()).expect_err("version 2 should be rejected");
        match err {
            PackError::UnsupportedManifestVersion { got } => {
                assert_eq!(got, 2);
                // The error message must mention the unsupported version
                let msg = err.to_string();
                assert!(
                    msg.contains("2"),
                    "error message should contain the bad version: {msg}"
                );
            }
            other => panic!("expected UnsupportedManifestVersion, got: {other}"),
        }
    }

    // -------------------------------------------------------------------------
    // parse_manifest_missing_required_field — drop `id`, assert named in error
    // -------------------------------------------------------------------------
    #[test]
    fn parse_manifest_missing_required_field() {
        let json = serde_json::json!({
            "manifest_version": 1,
            // "id" deliberately absent
            "version": "0.1.0",
            "target_triple": "x86_64-unknown-linux-gnu",
            "entry_symbol": "sigint_plugin_entry",
        })
        .to_string();

        // serde fills `id` with the default (empty string) because String's
        // default is "".  validate_manifest must catch it as MissingField.
        let err = parse_manifest(json.as_bytes()).expect_err("missing id should be rejected");
        match &err {
            PackError::MissingField { field } => {
                assert_eq!(*field, "id", "error should name the missing field");
            }
            PackError::Json(_) => {
                // Also acceptable — if serde rejects the missing field itself.
            }
            other => panic!("expected MissingField or Json, got: {other}"),
        }
    }

    // -------------------------------------------------------------------------
    // parse_manifest_unknown_field_preserved — future field lands in `extra`
    // -------------------------------------------------------------------------
    #[test]
    fn parse_manifest_unknown_field_preserved() {
        let json = serde_json::json!({
            "manifest_version": 1,
            "id": "com.example.future",
            "version": "0.1.0",
            "target_triple": "x86_64-unknown-linux-gnu",
            "entry_symbol": "sigint_plugin_entry",
            "runtime_capabilities": ["network", "filesystem"],
        })
        .to_string();

        let m = parse_manifest(json.as_bytes()).expect("future field should not fail");
        let caps = m
            .extra
            .get("runtime_capabilities")
            .expect("extra must capture unknown field");
        assert!(caps.is_array(), "extra value should be array");
    }

    // -------------------------------------------------------------------------
    // validate_manifest_target_triple — basic shape sanity
    // -------------------------------------------------------------------------
    #[test]
    fn validate_manifest_target_triple() {
        // Valid triple passes
        let json = serde_json::json!({
            "manifest_version": 1,
            "id": "com.example.triple",
            "version": "0.1.0",
            "target_triple": "x86_64-unknown-linux-gnu",
            "entry_symbol": "sigint_plugin_entry",
        })
        .to_string();
        assert!(parse_manifest(json.as_bytes()).is_ok());

        // Empty triple fails
        let json_empty = serde_json::json!({
            "manifest_version": 1,
            "id": "com.example.triple",
            "version": "0.1.0",
            "target_triple": "",
            "entry_symbol": "sigint_plugin_entry",
        })
        .to_string();
        let err = parse_manifest(json_empty.as_bytes()).expect_err("empty triple should fail");
        assert!(
            matches!(
                err,
                PackError::MissingField {
                    field: "target_triple"
                }
            ),
            "expected MissingField(target_triple), got: {err}"
        );
    }

    // -------------------------------------------------------------------------
    // library_filename derives platform name when not set
    // -------------------------------------------------------------------------
    #[test]
    fn library_filename_derived_when_absent() {
        let m = PluginManifest {
            manifest_version: 1,
            id: "myplug".to_string(),
            version: "0.1.0".to_string(),
            target_triple: "x86_64-unknown-linux-gnu".to_string(),
            entry_symbol: "sigint_plugin_entry".to_string(),
            display_name: None,
            description: None,
            author: None,
            homepage: None,
            license: None,
            library_filename: None,
            signature: None,
            signed_by: None,
            signature_algorithm: None,
            library_kind: None,
            extra: Map::new(),
        };
        let name = library_filename(&m);
        // On Linux this should be "libmyplug.so"
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        assert_eq!(name, "libmyplug.so");
    }

    #[test]
    fn library_filename_explicit_overrides_default() {
        let m = PluginManifest {
            manifest_version: 1,
            id: "myplug".to_string(),
            version: "0.1.0".to_string(),
            target_triple: "x86_64-unknown-linux-gnu".to_string(),
            entry_symbol: "sigint_plugin_entry".to_string(),
            display_name: None,
            description: None,
            author: None,
            homepage: None,
            license: None,
            library_filename: Some("custom.so".to_string()),
            signature: None,
            signed_by: None,
            signature_algorithm: None,
            library_kind: None,
            extra: Map::new(),
        };
        assert_eq!(library_filename(&m), "custom.so");
    }
}
