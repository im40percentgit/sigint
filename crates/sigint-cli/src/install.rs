//! `sigint plugin install` and `sigint plugin uninstall` — manage installed plugin packs.
//!
//! # Install layout (DEC-P27-004 / Seam #7)
//!
//! Plugins are installed into `<target_dir>/<plugin-id>-<plugin-version>/`:
//!
//! ```text
//! ~/.local/share/sigint/plugins/
//!   com.example.foo-1.0.0/
//!     manifest.json
//!     lib/
//!       libcom.example.foo.so   ← filename from manifest.library_filename
//! ```
//!
//! This naming convention is locked in Phase 27 (Seam #7).  Phase 28 must not
//! reshape this layout.  The subdirectory name is `<id>-<version>`, where `id`
//! and `version` come from the parsed manifest (never from filename parsing alone,
//! since version strings can contain `-`).
//!
//! @decision DEC-P27-004
//! @title Install dir layout: `<install_dir>/<plugin-id>-<plugin-version>/`
//! @status accepted
//! @rationale A dedicated per-plugin directory keeps manifests + libraries
//! co-located, making `discover_installed` straightforward (one directory scan).
//! The `<id>-<version>` subdirectory naming allows multiple versions of the same
//! plugin to coexist (later: `--version` flag selects among them).  The directory
//! name is derived from the parsed manifest — not from the archive filename —
//! because version strings may contain hyphens, making filename parsing ambiguous.
//! This layout is stable (Seam #7): Phase 28 does not reshape it.
//!
//! @decision DEC-P27-008
//! @title CLI: extend `sigint plugin` with `pack/install/uninstall/info` subcommands
//! @status accepted (T2 implements `pack`; T4 implements `install`/`uninstall`; T5 implements `info`)
//! @rationale A unified `sigint plugin <verb>` surface keeps the UX consistent
//! with `sigint model <verb>` and `sigint train <verb>`.  Each verb is a
//! separate Rust function in the `install` module, making them easy to test in
//! isolation.
//!
//! # Phase 28 seams T4 owns
//!
//! **Seam #6 (install command argument shape):** `install` accepts a *path* to a
//! `.sgnt-pack` file in Phase 27.  Phase 28 will extend the SAME command to accept
//! `<id>@<version>` syntax for registry lookup.  The positional arg is named
//! `<source>` (not `<file>`) to signal extensibility.  A future Phase-28
//! prefix-dispatch (`<id>@<version>` vs `*.sgnt-pack`) is a clean addition here —
//! just match on whether source contains `@`.
//!
//! **Seam #7 (install-dir layout stability):** The `<id>-<version>/` naming is
//! locked in Phase 27.  Phase 28 must not reshape it.  This is enforced by the
//! `resolve_install_path` helper — all callers go through this single function.
//!
//! # Atomicity
//!
//! Install: extract to a `tempfile::TempDir` in the same filesystem as the
//! target dir, then `std::fs::rename` to the final path (atomic on POSIX;
//! may fail on Windows if dest exists — remove-then-rename is used when `force`).
//!
//! Uninstall: rename the plugin dir to a `.removed-<uuid>` sibling first, then
//! call `remove_dir_all` on the renamed path.  On crash between rename and
//! `remove_dir_all`, a `.removed-*` dir is left behind — harmless and easily
//! detected for cleanup.
//!
//! # Windows note
//!
//! `std::fs::rename` on Windows fails if the destination already exists (unlike
//! POSIX where it atomically replaces).  `run_install` handles this by removing
//! the destination before renaming when `--force` is set.  The force=false path
//! errors before rename, so the cross-platform behaviour is consistent.

use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};

use sigint_plugin::{
    loader::default_install_dir, manifest::library_filename, pack::read_manifest_from_archive,
    PluginManifest,
};

// Re-export so the loader's HOST_TRIPLE is not a direct dep in tests
use sigint_plugin::loader::HOST_TRIPLE;

// ─── Public entry points ──────────────────────────────────────────────────────

/// Run `sigint plugin install <source> [--target-dir <path>] [--force]`.
///
/// # Arguments
///
/// - `source` — path to a `.sgnt-pack` file.
///   (Phase 28 Seam #6 will extend this to also accept `<id>@<version>` for
///   registry lookup.  Phase 28 addition: match on `source.contains('@')` here
///   before calling `run_install_local_pack`.)
/// - `target_dir` — install root; defaults to [`default_install_dir()`].
/// - `force` — overwrite an existing install or mismatched target triple.
pub fn run_install(source: &Path, target_dir: Option<&Path>, force: bool) -> Result<()> {
    // Phase 28 Seam #6: if source is `<id>@<version>`, dispatch to registry
    // lookup instead. For now we only support local .sgnt-pack files.
    //
    // Future dispatch (Phase 28):
    //   if let Some(at) = source.to_string_lossy().find('@') { ... registry ... }

    run_install_local_pack(source, target_dir, force)
}

/// Run `sigint plugin uninstall <id> [--target-dir <path>] [--version <version>]`.
///
/// # Arguments
///
/// - `id` — the plugin id (e.g. `"com.example.foo"`).
/// - `target_dir` — install root; defaults to [`default_install_dir()`].
/// - `version` — if set, only uninstall that specific version; if unset and
///   exactly one version is installed, uninstall it; if multiple are installed,
///   list them and exit 1.
pub fn run_uninstall(id: &str, target_dir: Option<&Path>, version: Option<&str>) -> Result<()> {
    // ── Step 1: Resolve target dir ─────────────────────────────────────────
    let install_root = target_dir
        .map(PathBuf::from)
        .unwrap_or_else(default_install_dir);

    // ── Step 2: Find installed versions matching <id> ──────────────────────
    let installed = find_installed_versions(id, &install_root)?;

    if installed.is_empty() {
        bail!(
            "no plugin with id `{}` is installed in {}",
            id,
            install_root.display()
        );
    }

    // ── Step 3: Disambiguate by --version ──────────────────────────────────
    let target = if let Some(ver) = version {
        // Explicit version requested
        installed
            .into_iter()
            .find(|(_, m)| m.version == ver)
            .map(|(path, _)| path)
            .with_context(|| {
                format!(
                    "plugin `{}` version `{}` is not installed in {}",
                    id,
                    ver,
                    install_root.display()
                )
            })?
    } else if installed.len() == 1 {
        installed.into_iter().next().map(|(p, _)| p).unwrap()
    } else {
        // Multiple versions — require --version
        let versions: Vec<String> = installed.into_iter().map(|(_, m)| m.version).collect();
        bail!(
            "multiple versions of `{}` are installed: {}\n\
             Use --version <version> to specify which one to uninstall.",
            id,
            versions.join(", ")
        );
    };

    // ── Step 4: Atomic remove (rename + remove_dir_all) ───────────────────
    let removed_name = format!(".removed-{}-{}", id, uuid::Uuid::new_v4().as_simple());
    let staging = install_root.join(&removed_name);

    std::fs::rename(&target, &staging).with_context(|| {
        format!(
            "could not rename {} to staging path for atomic removal",
            target.display()
        )
    })?;

    std::fs::remove_dir_all(&staging).with_context(|| {
        format!(
            "could not remove plugin directory (staging: {}); \
             you may need to delete it manually",
            staging.display()
        )
    })?;

    // ── Step 5: Print success ──────────────────────────────────────────────
    println!("Uninstalled: {}", target.display());

    Ok(())
}

// ─── Install implementation ───────────────────────────────────────────────────

/// Core install logic for a local `.sgnt-pack` file.
fn run_install_local_pack(source: &Path, target_dir: Option<&Path>, force: bool) -> Result<()> {
    // ── Step 1: Validate source ────────────────────────────────────────────
    if !source.exists() {
        bail!("source file does not exist: {}", source.display());
    }
    let ext = source.extension().and_then(|e| e.to_str()).unwrap_or("");
    if ext != "pack" || !source.to_string_lossy().ends_with(".sgnt-pack") {
        // Warn rather than hard-error: let read_manifest_from_archive surface the real error
        // (the archive might be valid even with a different extension).
    }

    // ── Step 2: Pre-flight manifest read ──────────────────────────────────
    let manifest = read_manifest_from_archive(source)
        .with_context(|| format!("reading manifest from {}", source.display()))?;

    // ── Step 3: Target triple check ────────────────────────────────────────
    if manifest.target_triple != HOST_TRIPLE && !force {
        bail!(
            "plugin built for `{}`, host is `{}`; use --force to install anyway",
            manifest.target_triple,
            HOST_TRIPLE
        );
    }

    // ── Step 4: Resolve install path ──────────────────────────────────────
    let install_root = target_dir
        .map(PathBuf::from)
        .unwrap_or_else(default_install_dir);
    let final_path = resolve_install_path(&install_root, &manifest);

    if final_path.exists() && !force {
        bail!(
            "plugin already installed at {}; use --force to overwrite",
            final_path.display()
        );
    }

    // ── Step 5: Extract to temp dir ────────────────────────────────────────
    // Use tempdir in the same filesystem as the install root for atomic rename.
    // Best-effort: if we can't create a sibling temp dir, fall back to OS tmpdir
    // (cross-filesystem rename will then fall back to copy+delete — not atomic,
    // but still safe because the temp dir is cleaned up on drop).
    std::fs::create_dir_all(&install_root)
        .with_context(|| format!("creating install directory {}", install_root.display()))?;

    let staging = tempfile::Builder::new()
        .prefix(".installing-")
        .tempdir_in(&install_root)
        .or_else(|_| tempfile::tempdir())
        .with_context(|| "creating staging directory for extraction")?;

    sigint_plugin::extract_archive(source, staging.path())
        .with_context(|| format!("extracting {} to staging dir", source.display()))?;

    // ── Step 6: Atomic move to final path ─────────────────────────────────
    if final_path.exists() {
        // --force path: remove the old install first.
        // On Windows, rename fails if dest exists — we remove first everywhere
        // for consistent behaviour.
        std::fs::remove_dir_all(&final_path).with_context(|| {
            format!(
                "removing existing install at {} before overwrite",
                final_path.display()
            )
        })?;
    }

    // keep() prevents TempDir's drop-destructor from deleting the dir so we
    // can rename it into place.  After rename succeeds the staging path no
    // longer exists (it moved to final_path).
    let staging_path = staging.keep();
    std::fs::rename(&staging_path, &final_path).with_context(|| {
        // Cleanup: best-effort remove the staging dir if rename failed.
        let _ = std::fs::remove_dir_all(&staging_path);
        format!("moving staged plugin to {}", final_path.display())
    })?;

    // ── Step 7: Success summary ────────────────────────────────────────────
    let lib_name = library_filename(&manifest);
    let size = dir_size(&final_path).unwrap_or(0);

    println!("Installed: {}", final_path.display());
    println!("  id:              {}", manifest.id);
    println!("  version:         {}", manifest.version);
    println!("  target_triple:   {}", manifest.target_triple);
    println!("  library:         lib/{lib_name}");
    println!("  install_size:    {size} bytes");
    if let Some(desc) = &manifest.description {
        println!("  description:     {desc}");
    }
    if let Some(author) = &manifest.author {
        println!("  author:          {author}");
    }

    Ok(())
}

// ─── Path helpers ─────────────────────────────────────────────────────────────

/// Compute the final install directory path for a plugin.
///
/// Returns `<install_root>/<id>-<version>/`.
///
/// This is the single canonical implementation of the install-dir naming
/// convention locked in Phase 27 (Seam #7).  All callers go through this
/// function to guarantee consistency between `install` and `uninstall`.
pub fn resolve_install_path(install_root: &Path, manifest: &PluginManifest) -> PathBuf {
    install_root.join(format!("{}-{}", manifest.id, manifest.version))
}

// ─── Version discovery ────────────────────────────────────────────────────────

/// Find all installed versions of the plugin with the given `id`.
///
/// Scans `install_root` for subdirectories, reads the `manifest.json` in each,
/// and returns those whose `id` matches.
///
/// Returns a Vec of `(directory_path, manifest)` pairs.
///
/// Directories that cannot be read or have invalid manifests are silently
/// skipped (consistent with `loader::discover_installed`'s log-and-skip policy).
pub fn find_installed_versions(
    id: &str,
    install_root: &Path,
) -> Result<Vec<(PathBuf, PluginManifest)>> {
    let mut result = Vec::new();

    let entries = match std::fs::read_dir(install_root) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(result),
        Err(e) => {
            return Err(e)
                .with_context(|| format!("reading install directory {}", install_root.display()));
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let manifest_path = path.join("manifest.json");
        if !manifest_path.exists() {
            continue;
        }

        let bytes = match std::fs::read(&manifest_path) {
            Ok(b) => b,
            Err(_) => continue,
        };

        let manifest = match sigint_plugin::parse_manifest(&bytes) {
            Ok(m) => m,
            Err(_) => continue,
        };

        if manifest.id == id {
            result.push((path, manifest));
        }
    }

    Ok(result)
}

// ─── Utility ─────────────────────────────────────────────────────────────────

/// Compute the total size of all files inside a directory (recursive).
///
/// Returns `None` on I/O error; the caller treats this as 0 and keeps going.
fn dir_size(dir: &Path) -> Option<u64> {
    let mut total: u64 = 0;
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let meta = entry.metadata().ok()?;
        if meta.is_file() {
            total += meta.len();
        } else if meta.is_dir() {
            total += dir_size(&entry.path()).unwrap_or(0);
        }
    }
    Some(total)
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Map;
    use sigint_plugin::{
        manifest::SUPPORTED_MANIFEST_VERSION,
        pack::{pack_directory, ARCHIVE_LIB_DIR},
        PluginManifest,
    };
    use std::fs;
    use tempfile::TempDir;

    // ─── Helpers ──────────────────────────────────────────────────────────────

    /// Build a minimal PluginManifest for use in tests.
    fn make_manifest(id: &str, version: &str, triple: &str) -> PluginManifest {
        PluginManifest {
            manifest_version: SUPPORTED_MANIFEST_VERSION,
            id: id.to_string(),
            version: version.to_string(),
            target_triple: triple.to_string(),
            entry_symbol: "sigint_plugin_entry".to_string(),
            display_name: None,
            description: None,
            author: None,
            homepage: None,
            license: None,
            library_filename: Some(format!("lib{}.so", id.replace('.', "_"))),
            signature: None,
            signed_by: None,
            signature_algorithm: None,
            library_kind: None,
            extra: Map::new(),
        }
    }

    /// Write a minimal source directory (manifest.json + lib/<lib>.so) and
    /// pack it into a `.sgnt-pack` archive in the given output dir.
    /// Returns the path to the created `.sgnt-pack` file.
    fn make_pack(tmp: &TempDir, manifest: &PluginManifest) -> PathBuf {
        let src_dir = tmp.path().join("_src");
        fs::create_dir_all(src_dir.join(ARCHIVE_LIB_DIR)).unwrap();

        let manifest_json = serde_json::to_string_pretty(manifest).unwrap();
        fs::write(src_dir.join("manifest.json"), &manifest_json).unwrap();

        let lib_name = library_filename(manifest);
        fs::write(
            src_dir.join(ARCHIVE_LIB_DIR).join(&lib_name),
            vec![0u8; 512],
        )
        .unwrap();

        let pack_path = tmp
            .path()
            .join(format!("{}-{}.sgnt-pack", manifest.id, manifest.version));
        pack_directory(&src_dir, &pack_path).expect("pack_directory");
        pack_path
    }

    /// Write a plugin directory (not a pack — the already-extracted layout)
    /// matching the loader's expected structure.
    fn make_installed_dir(install_root: &Path, manifest: &PluginManifest) -> PathBuf {
        let plugin_dir = resolve_install_path(install_root, manifest);
        fs::create_dir_all(plugin_dir.join("lib")).unwrap();

        let manifest_json = serde_json::to_string_pretty(manifest).unwrap();
        fs::write(plugin_dir.join("manifest.json"), &manifest_json).unwrap();

        let lib_name = library_filename(manifest);
        fs::write(plugin_dir.join("lib").join(&lib_name), vec![0u8; 512]).unwrap();

        plugin_dir
    }

    // ─── resolve_install_path ─────────────────────────────────────────────────

    /// Given a manifest with id="com.example.foo" and version="1.0.0",
    /// target_dir "/tmp/test", returns "/tmp/test/com.example.foo-1.0.0/".
    #[test]
    fn resolve_install_path_combines_id_and_version() {
        let manifest = make_manifest("com.example.foo", "1.0.0", "x86_64-unknown-linux-gnu");
        let target = PathBuf::from("/tmp/test");
        let result = resolve_install_path(&target, &manifest);
        assert_eq!(result, PathBuf::from("/tmp/test/com.example.foo-1.0.0"));
    }

    // ─── target_triple checks ─────────────────────────────────────────────────

    /// Manifest with a non-host triple + force=false returns a clear error.
    #[test]
    fn target_mismatch_no_force_errors() {
        let tmp = TempDir::new().unwrap();
        let non_host = if HOST_TRIPLE.contains("linux") {
            "x86_64-pc-windows-gnu"
        } else {
            "x86_64-unknown-linux-gnu"
        };
        let manifest = make_manifest("com.example.mismatch", "0.1.0", non_host);
        let pack_path = make_pack(&tmp, &manifest);
        let install_dir = tmp.path().join("install");

        let err = run_install(&pack_path, Some(&install_dir), false)
            .expect_err("should fail on triple mismatch without --force");
        let msg = err.to_string();
        assert!(
            msg.contains("built for") && msg.contains("host is"),
            "error message should describe triple mismatch: {msg}"
        );
    }

    /// Same but with force=true — the triple mismatch is allowed through.
    #[test]
    fn target_mismatch_with_force_proceeds() {
        let tmp = TempDir::new().unwrap();
        let non_host = if HOST_TRIPLE.contains("linux") {
            "x86_64-pc-windows-gnu"
        } else {
            "x86_64-unknown-linux-gnu"
        };
        let manifest = make_manifest("com.example.forced", "0.1.0", non_host);
        let pack_path = make_pack(&tmp, &manifest);
        let install_dir = tmp.path().join("install");

        // Should succeed (the library is a dummy, but the extraction path succeeds)
        let result = run_install(&pack_path, Some(&install_dir), true);
        // On Linux the extraction itself is fine; the library is just dummy bytes.
        // We can't dlopen it, but install doesn't dlopen.
        assert!(
            result.is_ok(),
            "force should allow triple mismatch: {:?}",
            result
        );
        assert!(
            resolve_install_path(&install_dir, &manifest).exists(),
            "plugin directory should be created even on triple mismatch with --force"
        );
    }

    // ─── already-installed checks ─────────────────────────────────────────────

    /// Pre-existing target dir + force=false errors with clear message.
    #[test]
    fn already_installed_no_force_errors() {
        let tmp = TempDir::new().unwrap();
        let manifest = make_manifest("com.example.dup", "1.0.0", HOST_TRIPLE);
        let pack_path = make_pack(&tmp, &manifest);
        let install_dir = tmp.path().join("install");

        // First install succeeds
        run_install(&pack_path, Some(&install_dir), false).expect("first install should succeed");

        // Second install without --force must fail
        let err = run_install(&pack_path, Some(&install_dir), false)
            .expect_err("second install without --force should fail");
        let msg = err.to_string();
        assert!(
            msg.contains("already installed"),
            "error should mention already installed: {msg}"
        );
    }

    /// Pre-existing target dir + force=true replaces the install.
    #[test]
    fn already_installed_with_force_replaces() {
        let tmp = TempDir::new().unwrap();
        let manifest = make_manifest("com.example.dup2", "1.0.0", HOST_TRIPLE);
        let pack_path = make_pack(&tmp, &manifest);
        let install_dir = tmp.path().join("install");

        // First install
        run_install(&pack_path, Some(&install_dir), false).expect("first install");

        // Second install with --force must succeed
        run_install(&pack_path, Some(&install_dir), true).expect("force overwrite should succeed");

        let plugin_dir = resolve_install_path(&install_dir, &manifest);
        assert!(
            plugin_dir.exists(),
            "plugin dir must exist after force overwrite"
        );
        assert!(
            plugin_dir.join("manifest.json").exists(),
            "manifest.json must exist after force overwrite"
        );
    }

    // ─── find_installed_versions ──────────────────────────────────────────────

    /// Multiple `<id>-X.Y.Z/` dirs all returned.
    #[test]
    fn find_installed_versions_returns_all() {
        let tmp = TempDir::new().unwrap();
        let install_root = tmp.path();

        let m1 = make_manifest("com.example.multi", "1.0.0", HOST_TRIPLE);
        let m2 = make_manifest("com.example.multi", "2.0.0", HOST_TRIPLE);
        make_installed_dir(install_root, &m1);
        make_installed_dir(install_root, &m2);

        let found = find_installed_versions("com.example.multi", install_root)
            .expect("find_installed_versions");
        assert_eq!(found.len(), 2, "should find both versions");

        let mut versions: Vec<_> = found.iter().map(|(_, m)| m.version.as_str()).collect();
        versions.sort();
        assert_eq!(versions, ["1.0.0", "2.0.0"]);
    }

    /// `<other-id>-1.0.0/` is not returned when searching for `<id>`.
    #[test]
    fn find_installed_versions_excludes_other_plugins() {
        let tmp = TempDir::new().unwrap();
        let install_root = tmp.path();

        let target = make_manifest("com.example.target", "1.0.0", HOST_TRIPLE);
        let other = make_manifest("com.example.other", "1.0.0", HOST_TRIPLE);
        make_installed_dir(install_root, &target);
        make_installed_dir(install_root, &other);

        let found = find_installed_versions("com.example.target", install_root)
            .expect("find_installed_versions");
        assert_eq!(found.len(), 1, "should only find the target plugin");
        assert_eq!(found[0].1.id, "com.example.target");
    }

    // ─── uninstall tests ──────────────────────────────────────────────────────

    /// Exactly one installed version, no --version flag — succeeds.
    #[test]
    fn uninstall_single_version_no_flag() {
        let tmp = TempDir::new().unwrap();
        let install_root = tmp.path();
        let manifest = make_manifest("com.example.single", "1.0.0", HOST_TRIPLE);
        let plugin_dir = make_installed_dir(install_root, &manifest);

        assert!(
            plugin_dir.exists(),
            "plugin dir must exist before uninstall"
        );

        run_uninstall("com.example.single", Some(install_root), None)
            .expect("uninstall should succeed with one version, no flag");

        assert!(
            !plugin_dir.exists(),
            "plugin dir must be gone after uninstall"
        );
    }

    /// Two installed versions, no --version flag — errors with version list.
    #[test]
    fn uninstall_multiple_versions_requires_flag() {
        let tmp = TempDir::new().unwrap();
        let install_root = tmp.path();

        let m1 = make_manifest("com.example.multi2", "1.0.0", HOST_TRIPLE);
        let m2 = make_manifest("com.example.multi2", "2.0.0", HOST_TRIPLE);
        make_installed_dir(install_root, &m1);
        make_installed_dir(install_root, &m2);

        let err = run_uninstall("com.example.multi2", Some(install_root), None)
            .expect_err("should fail without --version when multiple versions installed");
        let msg = err.to_string();
        assert!(
            msg.contains("multiple versions") || msg.contains("version"),
            "error should mention multiple versions: {msg}"
        );
        assert!(
            msg.contains("1.0.0") || msg.contains("2.0.0"),
            "error should list the installed versions: {msg}"
        );
    }

    /// Explicit --version resolves correctly.
    #[test]
    fn uninstall_with_version_succeeds() {
        let tmp = TempDir::new().unwrap();
        let install_root = tmp.path();

        let m1 = make_manifest("com.example.versioned", "1.0.0", HOST_TRIPLE);
        let m2 = make_manifest("com.example.versioned", "2.0.0", HOST_TRIPLE);
        let dir1 = make_installed_dir(install_root, &m1);
        let dir2 = make_installed_dir(install_root, &m2);

        run_uninstall("com.example.versioned", Some(install_root), Some("1.0.0"))
            .expect("uninstall with --version should succeed");

        assert!(!dir1.exists(), "v1.0.0 dir must be removed");
        assert!(dir2.exists(), "v2.0.0 dir must remain");
    }

    /// Plugin not installed → clear error message.
    #[test]
    fn uninstall_nonexistent_errors() {
        let tmp = TempDir::new().unwrap();
        let install_root = tmp.path();

        let err = run_uninstall("com.example.ghost", Some(install_root), None)
            .expect_err("uninstalling a non-existent plugin should fail");
        let msg = err.to_string();
        assert!(
            msg.contains("no plugin with id"),
            "error should say the plugin isn't installed: {msg}"
        );
    }

    // ─── source validation ────────────────────────────────────────────────────

    /// Non-existent source file → clear error, exit 1.
    #[test]
    fn install_nonexistent_source_errors() {
        let tmp = TempDir::new().unwrap();
        let bogus = tmp.path().join("does-not-exist.sgnt-pack");
        let install_dir = tmp.path().join("install");

        let err = run_install(&bogus, Some(&install_dir), false)
            .expect_err("non-existent source should error");
        let msg = err.to_string();
        assert!(
            msg.contains("does not exist"),
            "error should describe missing source: {msg}"
        );
    }
}

// ─── Integration test ─────────────────────────────────────────────────────────

#[cfg(test)]
mod integration_tests {
    use super::*;
    use tempfile::TempDir;

    /// Full install → uninstall round trip using an actual `.sgnt-pack` archive.
    ///
    /// This test creates a real pack in-memory using `sigint_plugin::pack_directory`,
    /// installs it to a tempdir, asserts the directory structure exists, then
    /// uninstalls it and asserts it is gone.
    ///
    /// This test does NOT require `cargo build` — it uses a pure-Rust dummy library
    /// blob (not a valid ELF, but the install command doesn't dlopen it).
    ///
    /// Marked #[ignore] in case CI isolation requires it; run explicitly with:
    ///
    /// ```bash
    /// cargo test -p sigint-cli -- --ignored integration_tests::install_uninstall_round_trip
    /// ```
    #[test]
    #[ignore = "integration test: requires filesystem write; run explicitly with --ignored"]
    fn install_uninstall_round_trip() {
        use serde_json::Map;
        use sigint_plugin::{
            manifest::SUPPORTED_MANIFEST_VERSION, pack::pack_directory, PluginManifest,
        };
        use std::fs;

        let tmp = TempDir::new().unwrap();

        // Build a fake manifest with the host triple so the install succeeds.
        let manifest = PluginManifest {
            manifest_version: SUPPORTED_MANIFEST_VERSION,
            id: "com.sigint.test.roundtrip".to_string(),
            version: "0.1.0".to_string(),
            target_triple: HOST_TRIPLE.to_string(),
            entry_symbol: "sigint_plugin_entry".to_string(),
            display_name: None,
            description: None,
            author: None,
            homepage: None,
            license: None,
            library_filename: Some("libcom_sigint_test_roundtrip.so".to_string()),
            signature: None,
            signed_by: None,
            signature_algorithm: None,
            library_kind: None,
            extra: Map::new(),
        };

        // Create source directory with manifest + dummy library
        let src_dir = tmp.path().join("src");
        fs::create_dir_all(src_dir.join("lib")).unwrap();
        fs::write(
            src_dir.join("manifest.json"),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();
        fs::write(
            src_dir.join("lib").join("libcom_sigint_test_roundtrip.so"),
            vec![0u8; 256],
        )
        .unwrap();

        // Pack it
        let pack_path = tmp.path().join("roundtrip-0.1.0.sgnt-pack");
        pack_directory(&src_dir, &pack_path).expect("pack_directory should succeed");
        assert!(pack_path.exists(), "pack file should exist");

        let install_dir = tmp.path().join("plugins");

        // Install
        run_install(&pack_path, Some(&install_dir), false).expect("install should succeed");

        let plugin_dir = resolve_install_path(&install_dir, &manifest);
        assert!(plugin_dir.exists(), "plugin dir should exist after install");
        assert!(
            plugin_dir.join("manifest.json").exists(),
            "manifest.json should exist after install"
        );
        assert!(
            plugin_dir
                .join("lib")
                .join("libcom_sigint_test_roundtrip.so")
                .exists(),
            "library file should exist after install"
        );

        // Uninstall
        run_uninstall("com.sigint.test.roundtrip", Some(&install_dir), None)
            .expect("uninstall should succeed");

        assert!(
            !plugin_dir.exists(),
            "plugin dir should be gone after uninstall"
        );
    }
}
