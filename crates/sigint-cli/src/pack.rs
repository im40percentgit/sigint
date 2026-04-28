//! `sigint plugin pack` — package a cdylib crate into a `.sgnt-pack` archive.
//!
//! # Manifest resolution priority
//!
//! 1. `--manifest <path>` — explicit path, highest priority.
//! 2. `<crate-path>/manifest.json` — conventional location.
//! 3. `[package.metadata.sigint-plugin]` in the crate's `Cargo.toml`,
//!    supplemented by `[package]` fields (`version`, `description`, etc.).
//!
//! @decision DEC-P27-007
//! @title Plugin metadata via `[package.metadata.sigint-plugin]` in Cargo.toml
//! @status accepted
//! @rationale Plugin authors should not have to maintain a separate
//! `manifest.json` when the same information is already present in Cargo.toml.
//! The `[package.metadata.*]` key is the standard Cargo extension point for
//! tool-specific metadata (used by `wasm-pack`, `cargo-deb`, `uniffi`, etc.).
//! The CLI reads this section during `pack` and synthesises a valid manifest
//! automatically, falling back to package-level fields (`version`, `authors`,
//! `description`, `license`) for any field not explicitly set in the metadata
//! block.  An explicit `manifest.json` or `--manifest` flag always wins.
//!
//! @decision DEC-P27-008
//! @title CLI: extend `sigint plugin` with `pack/install/uninstall/info` subcommands
//! @status accepted (T2 implements `pack`; T4 implements `install`/`uninstall`; T5 implements `info`)
//! @rationale A unified `sigint plugin <verb>` surface keeps the UX consistent
//! with `sigint model <verb>` and `sigint train <verb>`.  Each verb is a
//! separate Rust function in the `plugin` module, making them easy to test in
//! isolation.  The `pack` verb is the user-facing entry point for creating
//! distributable plugin archives — it ties together T1's archive primitives,
//! T2's manifest resolution, and the cdylib build step (cargo invocation).

use anyhow::{bail, Context, Result};
use serde_json::Map;
use std::path::{Path, PathBuf};
use std::process::Command;

use sigint_plugin::{
    abi::DEFAULT_ENTRY_SYMBOL, manifest::SUPPORTED_MANIFEST_VERSION, pack::pack_directory,
    PluginManifest,
};

// ─── Public entry point ───────────────────────────────────────────────────────

/// Run `sigint plugin pack <crate_path>`.
///
/// # Arguments
///
/// - `crate_path` — path to the Rust crate (must contain a `Cargo.toml` with
///   `crate-type = ["cdylib", ...]`).
/// - `output` — optional output path for the resulting `.sgnt-pack` file.
///   Defaults to `<crate-name>-<version>.sgnt-pack` in the current directory.
/// - `release` — build with `--release` (true) or `--debug` (false).
/// - `manifest_override` — optional explicit path to a `manifest.json`.
/// - `force` — overwrite an existing output file when true; refuse otherwise.
pub fn run_pack(
    crate_path: &Path,
    output: Option<&Path>,
    release: bool,
    manifest_override: Option<&Path>,
    force: bool,
) -> Result<()> {
    // ── Step 1: Validate crate path & Cargo.toml ──────────────────────────
    if !crate_path.exists() {
        bail!("crate path does not exist: {}", crate_path.display());
    }
    let cargo_toml_path = crate_path.join("Cargo.toml");
    if !cargo_toml_path.exists() {
        bail!(
            "Cargo.toml not found in crate path: {}",
            crate_path.display()
        );
    }
    let cargo_toml_src = std::fs::read_to_string(&cargo_toml_path)
        .with_context(|| format!("reading {}", cargo_toml_path.display()))?;
    let cargo_toml: toml::Value = toml::from_str(&cargo_toml_src)
        .with_context(|| format!("parsing {}", cargo_toml_path.display()))?;

    validate_cdylib(&cargo_toml)?;

    // ── Step 2: Determine package name & version ───────────────────────────
    let pkg = cargo_toml
        .get("package")
        .and_then(|p| p.as_table())
        .with_context(|| "Cargo.toml has no [package] section")?;

    let package_name = pkg
        .get("name")
        .and_then(|v| v.as_str())
        .with_context(|| "Cargo.toml [package] has no name field")?
        .to_string();

    let package_version = pkg
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("0.0.0")
        .to_string();

    // ── Step 3: Resolve manifest ───────────────────────────────────────────
    let manifest = resolve_manifest(
        crate_path,
        manifest_override,
        &cargo_toml,
        &package_name,
        &package_version,
    )?;

    // ── Step 4: Determine output path ──────────────────────────────────────
    let output_path = match output {
        Some(p) => p.to_path_buf(),
        None => PathBuf::from(format!("{}-{}.sgnt-pack", package_name, manifest.version)),
    };

    if output_path.exists() && !force {
        bail!(
            "output file already exists: {}; use --force to overwrite",
            output_path.display()
        );
    }

    // ── Step 5: Build the cdylib ──────────────────────────────────────────
    let profile = if release { "release" } else { "debug" };
    build_cdylib(crate_path, &package_name, release)?;

    // ── Step 6: Locate built artifact ─────────────────────────────────────
    // Cargo normalises '-' → '_' for the library filename.
    let lib_stem = package_name.replace('-', "_");
    let lib_filename = platform_lib_filename(&lib_stem);

    // The workspace root may be different from crate_path; locate it.
    let workspace_root =
        find_workspace_root(crate_path).unwrap_or_else(|| crate_path.to_path_buf());
    let artifact = workspace_root
        .join("target")
        .join(profile)
        .join(&lib_filename);

    if !artifact.exists() {
        bail!(
            "expected built artifact at {} but file not found\n\
             Hint: cargo build completed successfully, but the output path is unexpected.",
            artifact.display()
        );
    }

    // ── Step 7: Stage temporary directory ─────────────────────────────────
    let staging = tempfile::tempdir().with_context(|| "creating staging directory")?;
    let stage_path = staging.path();

    // Determine the library filename to use inside the archive.
    // Prefer manifest.library_filename, else derive from package name.
    let archive_lib_name = manifest
        .library_filename
        .clone()
        .unwrap_or_else(|| lib_filename.clone());

    // Write manifest.json to staging root
    let manifest_json =
        serde_json::to_string_pretty(&manifest).with_context(|| "serialising manifest to JSON")?;
    std::fs::write(stage_path.join("manifest.json"), &manifest_json)
        .with_context(|| "writing manifest.json to staging dir")?;

    // Write lib/<archive_lib_name>
    let lib_dir = stage_path.join("lib");
    std::fs::create_dir_all(&lib_dir).with_context(|| "creating lib/ in staging dir")?;
    std::fs::copy(&artifact, lib_dir.join(&archive_lib_name))
        .with_context(|| format!("copying {} to staging lib/", artifact.display()))?;

    // ── Step 8: Build the archive ─────────────────────────────────────────
    pack_directory(stage_path, &output_path)
        .with_context(|| format!("building archive {}", output_path.display()))?;

    // ── Step 9: Print success summary ─────────────────────────────────────
    let size = std::fs::metadata(&output_path)
        .map(|m| m.len())
        .unwrap_or(0);

    println!("Packed: {}", output_path.display());
    println!("  id:              {}", manifest.id);
    println!("  version:         {}", manifest.version);
    println!("  target_triple:   {}", manifest.target_triple);
    println!("  entry_symbol:    {}", manifest.entry_symbol);
    if let Some(desc) = &manifest.description {
        println!("  description:     {desc}");
    }
    if let Some(author) = &manifest.author {
        println!("  author:          {author}");
    }
    if let Some(license) = &manifest.license {
        println!("  license:         {license}");
    }
    println!("  library:         lib/{archive_lib_name}");
    println!("  size:            {size} bytes");

    Ok(())
}

// ─── Manifest resolution ──────────────────────────────────────────────────────

/// Resolve the `PluginManifest` from the three possible sources, in priority
/// order: explicit `--manifest`, `manifest.json` in the crate root, or
/// synthesis from `[package.metadata.sigint-plugin]`.
fn resolve_manifest(
    crate_path: &Path,
    manifest_override: Option<&Path>,
    cargo_toml: &toml::Value,
    package_name: &str,
    package_version: &str,
) -> Result<PluginManifest> {
    // Priority 1: explicit --manifest flag
    if let Some(mpath) = manifest_override {
        let bytes = std::fs::read(mpath)
            .with_context(|| format!("reading manifest override: {}", mpath.display()))?;
        let m =
            sigint_plugin::parse_manifest(&bytes).with_context(|| "parsing manifest override")?;
        return Ok(m);
    }

    // Priority 2: manifest.json in crate root
    let manifest_json_path = crate_path.join("manifest.json");
    if manifest_json_path.exists() {
        let bytes = std::fs::read(&manifest_json_path)
            .with_context(|| format!("reading {}", manifest_json_path.display()))?;
        let m = sigint_plugin::parse_manifest(&bytes).with_context(|| "parsing manifest.json")?;
        return Ok(m);
    }

    // Priority 3: synthesise from [package.metadata.sigint-plugin] + [package]
    synthesise_manifest_from_cargo_toml(cargo_toml, package_name, package_version)
        .with_context(|| "synthesising manifest from Cargo.toml metadata")
}

/// Build a `PluginManifest` from `[package.metadata.sigint-plugin]` and
/// `[package]` fields, filling in defaults where the metadata block is absent
/// or a field is unset.
///
/// # Field resolution
///
/// | Manifest field    | Source                                       |
/// |-------------------|----------------------------------------------|
/// | `id`              | `metadata.id` (required)                     |
/// | `version`         | `metadata.version` → `package.version`       |
/// | `target_triple`   | `rustc -vV` host triple                      |
/// | `entry_symbol`    | `metadata.entry_symbol` → `DEFAULT_ENTRY_SYMBOL` |
/// | `display_name`    | `metadata.display_name`                      |
/// | `description`     | `metadata.description` → `package.description` |
/// | `author`          | `metadata.author` → `package.authors[0]`     |
/// | `homepage`        | `metadata.homepage` → `package.homepage`     |
/// | `license`         | `metadata.license` → `package.license`       |
/// | `library_filename`| `metadata.library_filename` (optional)       |
pub fn synthesise_manifest_from_cargo_toml(
    cargo_toml: &toml::Value,
    package_name: &str,
    package_version: &str,
) -> Result<PluginManifest> {
    let pkg = cargo_toml
        .get("package")
        .and_then(|p| p.as_table())
        .with_context(|| "Cargo.toml has no [package] section")?;

    // Locate [package.metadata.sigint-plugin] (may not exist)
    let meta = cargo_toml
        .get("package")
        .and_then(|p| p.get("metadata"))
        .and_then(|m| m.get("sigint-plugin"))
        .and_then(|s| s.as_table());

    let meta_str = |key: &str| -> Option<String> {
        meta.and_then(|m| m.get(key))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    };

    // id is required from the metadata block
    let id = meta_str("id").with_context(|| {
        format!(
            "crate '{package_name}' has no manifest.json and no \
             [package.metadata.sigint-plugin] section with an 'id' field.\n\
             Add one of:\n  \
             a) a manifest.json in the crate root, or\n  \
             b) [package.metadata.sigint-plugin] with at least id = \"...\""
        )
    })?;

    let version = meta_str("version")
        .or_else(|| {
            pkg.get("version")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_else(|| package_version.to_string());

    let target_triple = detect_host_triple();

    let entry_symbol = meta_str("entry_symbol").unwrap_or_else(|| DEFAULT_ENTRY_SYMBOL.to_string());

    let display_name = meta_str("display_name");

    let description = meta_str("description").or_else(|| {
        pkg.get("description")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });

    let author = meta_str("author").or_else(|| {
        pkg.get("authors")
            .and_then(|v| v.as_array())
            .and_then(|arr| arr.first())
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });

    let homepage = meta_str("homepage").or_else(|| {
        pkg.get("homepage")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });

    let license = meta_str("license").or_else(|| {
        pkg.get("license")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    });

    let library_filename = meta_str("library_filename");

    Ok(PluginManifest {
        manifest_version: SUPPORTED_MANIFEST_VERSION,
        id,
        version,
        target_triple,
        entry_symbol,
        display_name,
        description,
        author,
        homepage,
        license,
        library_filename,
        signature: None,
        signed_by: None,
        signature_algorithm: None,
        library_kind: None,
        extra: Map::new(),
    })
}

// ─── Validation helpers ───────────────────────────────────────────────────────

/// Verify that the Cargo.toml declares `crate-type = ["cdylib", ...]`.
pub fn validate_cdylib(cargo_toml: &toml::Value) -> Result<()> {
    let lib_section = cargo_toml.get("lib").and_then(|v| v.as_table());
    let crate_types: Vec<&str> = lib_section
        .and_then(|lib| lib.get("crate-type"))
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();

    if !crate_types.contains(&"cdylib") {
        bail!(
            "this crate is not a cdylib; sigint plugins require \
             crate-type = [\"cdylib\"] (or [\"cdylib\", \"rlib\"]) \
             in the [lib] section of Cargo.toml.\n\
             Current crate-type: {}",
            if crate_types.is_empty() {
                "(unset — defaults to rlib)".to_string()
            } else {
                format!("{:?}", crate_types)
            }
        );
    }
    Ok(())
}

// ─── Build helpers ────────────────────────────────────────────────────────────

/// Run `cargo build [-p <package_name>] [--release]` from the workspace root.
fn build_cdylib(crate_path: &Path, package_name: &str, release: bool) -> Result<()> {
    let mut cmd = Command::new("cargo");
    cmd.arg("build").arg("-p").arg(package_name);
    if release {
        cmd.arg("--release");
    }

    // Run from the crate directory so cargo finds the workspace.
    cmd.current_dir(crate_path);

    eprintln!(
        "Building {} ({})",
        package_name,
        if release { "release" } else { "debug" }
    );

    let status = cmd
        .status()
        .with_context(|| "failed to spawn `cargo build`")?;

    if !status.success() {
        bail!(
            "cargo build failed with exit code {}",
            status.code().unwrap_or(-1)
        );
    }

    Ok(())
}

/// Determine the cargo output directory `target/` root by searching for the
/// workspace root (the Cargo.toml that has `[workspace]`).
fn find_workspace_root(start: &Path) -> Option<PathBuf> {
    let mut current = start.to_path_buf();
    loop {
        let candidate = current.join("Cargo.toml");
        if candidate.exists() {
            if let Ok(src) = std::fs::read_to_string(&candidate) {
                if src.contains("[workspace]") {
                    return Some(current);
                }
            }
        }
        if !current.pop() {
            return None;
        }
    }
}

/// Return the platform-conventional library filename for a stem (without
/// `lib` prefix or extension).
///
/// - Linux:   `lib<stem>.so`
/// - macOS:   `lib<stem>.dylib`
/// - Windows: `<stem>.dll`
pub fn platform_lib_filename(stem: &str) -> String {
    #[cfg(target_os = "macos")]
    return format!("lib{stem}.dylib");
    #[cfg(target_os = "windows")]
    return format!("{stem}.dll");
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    format!("lib{stem}.so")
}

/// Detect the host Rust target triple by running `rustc -vV`.
///
/// Returns `"unknown"` if rustc is not available or the output is unparseable.
fn detect_host_triple() -> String {
    let out = Command::new("rustc").args(["-vV"]).output();
    match out {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            for line in text.lines() {
                if let Some(rest) = line.strip_prefix("host: ") {
                    return rest.trim().to_string();
                }
            }
            "unknown".to_string()
        }
        _ => "unknown".to_string(),
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use toml::Value;

    // ── Helpers ──

    fn toml_with_metadata(extra_pkg: &str, meta_block: &str) -> Value {
        let src = format!(
            r#"
[package]
name = "my-plugin"
version = "1.2.3"
edition = "2021"
description = "A test plugin"
authors = ["Alice <alice@example.com>"]
license = "MIT"
homepage = "https://example.com"

{extra_pkg}

[lib]
crate-type = ["cdylib", "rlib"]

{meta_block}
"#
        );
        Value::from_str(&src).expect("valid toml")
    }

    fn toml_no_meta() -> Value {
        toml_with_metadata("", "")
    }

    fn toml_with_sigint_meta(meta_fields: &str) -> Value {
        toml_with_metadata(
            "",
            &format!("[package.metadata.sigint-plugin]\n{meta_fields}"),
        )
    }

    // ── parse_metadata_from_cargo_toml ──

    /// Given a Cargo.toml with `[package.metadata.sigint-plugin]`, the
    /// synthesiser reads the id field correctly.
    #[test]
    fn parse_metadata_from_cargo_toml() {
        let toml = toml_with_sigint_meta(r#"id = "com.example.my-plugin""#);
        let m = synthesise_manifest_from_cargo_toml(&toml, "my-plugin", "1.2.3")
            .expect("should synthesise");
        assert_eq!(m.id, "com.example.my-plugin");
        assert_eq!(m.version, "1.2.3"); // falls back to package.version
        assert_eq!(m.entry_symbol, DEFAULT_ENTRY_SYMBOL);
    }

    /// Version from metadata block overrides package.version.
    #[test]
    fn synthesise_manifest_uses_metadata_priority() {
        let toml = toml_with_sigint_meta(
            r#"id = "com.example.x"
version = "9.9.9""#,
        );
        let m = synthesise_manifest_from_cargo_toml(&toml, "my-plugin", "1.2.3")
            .expect("should synthesise");
        assert_eq!(
            m.version, "9.9.9",
            "metadata version should override package.version"
        );
    }

    /// Without metadata block, synthesiser reads author from package.authors.
    #[test]
    fn synthesise_manifest_falls_back_to_cargo_toml() {
        let toml = toml_with_sigint_meta(r#"id = "com.example.fallback""#);
        let m = synthesise_manifest_from_cargo_toml(&toml, "my-plugin", "1.2.3")
            .expect("should synthesise");
        assert_eq!(
            m.author.as_deref(),
            Some("Alice <alice@example.com>"),
            "author should come from package.authors[0]"
        );
        assert_eq!(m.license.as_deref(), Some("MIT"));
        assert_eq!(m.description.as_deref(), Some("A test plugin"));
        assert_eq!(m.homepage.as_deref(), Some("https://example.com"));
    }

    /// Dashes in the package name are normalised to underscores in the library
    /// filename.
    #[test]
    fn library_filename_default_normalizes_dashes() {
        let stem = "sigint-plugin-hello".replace('-', "_");
        let filename = platform_lib_filename(&stem);
        assert_eq!(filename, "libsigint_plugin_hello.so");
    }

    /// A Cargo.toml without `cdylib` in `crate-type` should return a clear error.
    #[test]
    fn pack_rejects_non_cdylib() {
        let src = r#"
[package]
name = "not-a-plugin"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["rlib"]
"#;
        let toml = Value::from_str(src).unwrap();
        let err = validate_cdylib(&toml).expect_err("should reject non-cdylib");
        let msg = err.to_string();
        assert!(
            msg.contains("cdylib"),
            "error message should mention cdylib: {msg}"
        );
    }

    /// A Cargo.toml without any `[lib]` section should also fail.
    #[test]
    fn pack_rejects_missing_lib_section() {
        let src = r#"
[package]
name = "no-lib"
version = "0.1.0"
edition = "2021"
"#;
        let toml = Value::from_str(src).unwrap();
        let err = validate_cdylib(&toml).expect_err("should reject missing lib section");
        let msg = err.to_string();
        assert!(
            msg.contains("cdylib"),
            "error message should mention cdylib: {msg}"
        );
    }

    /// Both `cdylib` and `rlib` in crate-type should pass.
    #[test]
    fn pack_accepts_cdylib_plus_rlib() {
        let toml = toml_no_meta();
        validate_cdylib(&toml).expect("cdylib + rlib should be accepted");
    }

    /// No `[package.metadata.sigint-plugin]` and no manifest.json → error that
    /// guides the user to add one.
    #[test]
    fn synthesise_fails_without_id() {
        let toml = toml_no_meta(); // no metadata.sigint-plugin
        let err = synthesise_manifest_from_cargo_toml(&toml, "my-plugin", "1.2.3")
            .expect_err("should fail without id");
        let msg = err.to_string();
        assert!(
            msg.contains("manifest.json") || msg.contains("sigint-plugin"),
            "error should guide user: {msg}"
        );
    }

    /// `detect_host_triple` returns a non-empty string (assumes rustc is on PATH).
    #[test]
    fn detect_host_triple_returns_nonempty() {
        let triple = detect_host_triple();
        assert!(!triple.is_empty(), "host triple should be non-empty");
        // On most CI machines it should contain "linux" or "darwin" or "windows"
        assert!(
            triple.contains('-'),
            "triple should contain dashes: {triple}"
        );
    }
}

// ─── Integration test ─────────────────────────────────────────────────────────

#[cfg(test)]
mod integration_tests {
    use super::*;
    use sigint_plugin::pack::read_manifest_from_archive;

    /// End-to-end test: pack the hello example and read back the manifest.
    ///
    /// This test invokes `cargo build` internally (via `run_pack`), which is
    /// slow (~30s cold).  It is marked `#[ignore]` to keep the default test
    /// suite fast.  Run explicitly with:
    ///
    /// ```bash
    /// cargo test -p sigint-cli -- --ignored integration_tests::pack_hello_example_round_trip
    /// ```
    #[test]
    #[ignore = "invokes cargo build; slow on cold cache (~30s)"]
    fn pack_hello_example_round_trip() {
        // Find the workspace root (two levels up from this crate).
        let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = crate_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("workspace root");

        let hello_path = workspace_root.join("examples").join("sigint-plugin-hello");
        assert!(
            hello_path.exists(),
            "hello example must exist at {}",
            hello_path.display()
        );

        let out_dir = tempfile::tempdir().expect("tempdir");
        let out_path = out_dir.path().join("hello.sgnt-pack");

        run_pack(
            &hello_path,
            Some(&out_path),
            false, // debug build (faster)
            None,  // use manifest.json in hello_path
            true,  // force overwrite
        )
        .expect("run_pack should succeed");

        assert!(
            out_path.exists(),
            "output .sgnt-pack should exist at {}",
            out_path.display()
        );

        let manifest =
            read_manifest_from_archive(&out_path).expect("should read manifest from .sgnt-pack");
        assert_eq!(manifest.id, "com.sigint.example.hello");
        assert_eq!(manifest.version, "0.1.0");
        assert_eq!(manifest.entry_symbol, "sigint_plugin_entry");
        assert!(
            manifest.library_filename.as_deref() == Some("libsigint_plugin_hello.so"),
            "library_filename mismatch: {:?}",
            manifest.library_filename
        );
    }
}
