//! Plugin management commands — list, info, scaffold, pack, install, uninstall.
//!
//! @decision DEC-PLUGIN-002
//! @title `sigint plugin new` generates workspace member crates
//! @status accepted
//! @rationale Generating a workspace member (instead of an external crate) means
//! the plugin is automatically linked into the binary on `cargo build`. The
//! scaffold writes Cargo.toml, lib.rs, and an example tool implementation —
//! plugin authors only need to replace the example with their own tools.
//!
//! @decision DEC-P27-008
//! @title CLI: extend `sigint plugin` with `list` and `info` subcommands (T5)
//! @status accepted
//! @rationale `list` shows both compile-time built-in tools AND runtime-installed
//! plugins in a unified table, tagged by source.  `info <id>` prints the full
//! manifest for an installed plugin or describes a built-in.  Neither command
//! calls `dlopen` — they read manifest.json files directly via
//! `sigint_plugin::list_installed_manifests` (DEC-P27-005 companion function).
//! This keeps `list` fast even with many installed plugins.

use anyhow::{bail, Result};
use std::fs;
use std::path::{Path, PathBuf};

use sigint_plugin::{library_filename, list_installed_manifests, PluginManifest};

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Resolve the install root: use the user-supplied path or fall back to the
/// platform default (`~/.local/share/sigint/plugins/` on Linux).
fn resolve_install_root(target_dir: Option<&Path>) -> PathBuf {
    target_dir
        .map(PathBuf::from)
        .unwrap_or_else(sigint_plugin::default_install_dir)
}

/// Column widths used by the `list` table.
struct ColWidths {
    source: usize,
    id: usize,
    version: usize,
    name: usize,
}

impl ColWidths {
    fn header() -> Self {
        ColWidths {
            source: "SOURCE".len(),
            id: "ID".len(),
            version: "VERSION".len(),
            name: "NAME".len(),
        }
    }

    fn update_from_builtin(&mut self, id: &str, name: &str) {
        self.source = self.source.max("built-in".len());
        self.id = self.id.max(id.len());
        self.version = self.version.max("—".len());
        self.name = self.name.max(name.len());
    }

    fn update_from_installed(&mut self, m: &PluginManifest) {
        self.source = self.source.max("installed".len());
        self.id = self.id.max(m.id.len());
        self.version = self.version.max(m.version.len());
        let display = m.display_name.as_deref().unwrap_or("—");
        self.name = self.name.max(display.len());
    }

    fn separator(&self) -> String {
        format!(
            "  {:-<src$}  {:-<id$}  {:-<ver$}  {:-<name$}",
            "",
            "",
            "",
            "",
            src = self.source,
            id = self.id,
            ver = self.version,
            name = self.name
        )
    }

    fn header_row(&self) -> String {
        format!(
            "  {:<src$}  {:<id$}  {:<ver$}  {:<name$}",
            "SOURCE",
            "ID",
            "VERSION",
            "NAME",
            src = self.source,
            id = self.id,
            ver = self.version,
            name = self.name
        )
    }

    fn builtin_row(&self, id: &str, name: &str) -> String {
        format!(
            "  {:<src$}  {:<id$}  {:<ver$}  {:<name$}",
            "built-in",
            id,
            "—",
            name,
            src = self.source,
            id = self.id,
            ver = self.version,
            name = self.name
        )
    }

    fn installed_row(&self, m: &PluginManifest) -> String {
        let display = m.display_name.as_deref().unwrap_or("—");
        format!(
            "  {:<src$}  {:<id$}  {:<ver$}  {:<name$}",
            "installed",
            m.id,
            m.version,
            display,
            src = self.source,
            id = self.id,
            ver = self.version,
            name = self.name
        )
    }
}

// ─── `sigint plugin list` ────────────────────────────────────────────────────

/// Source filter for `sigint plugin list --source`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListSource {
    BuiltIn,
    Installed,
    All,
}

impl ListSource {
    pub fn from_str(s: &str) -> Result<Self> {
        match s {
            "built-in" | "builtin" => Ok(ListSource::BuiltIn),
            "installed" => Ok(ListSource::Installed),
            "all" => Ok(ListSource::All),
            other => {
                bail!("unknown --source value `{other}`; expected one of: built-in, installed, all")
            }
        }
    }
}

/// List registered tools and installed plugins.
///
/// Shows both compile-time built-in tools AND runtime-installed plugins in a
/// unified aligned table, tagged by source.  No `dlopen` is performed — installed
/// plugins are enumerated by reading manifest.json files directly.
///
/// `--source` filters the output to `built-in`, `installed`, or `all` (default).
pub fn run_list(target_dir: Option<&Path>, source: ListSource) -> Result<()> {
    let install_root = resolve_install_root(target_dir);
    let installed = list_installed_manifests(&install_root);

    // Collect built-in tools (compile-time inventory)
    let builtin_tools = sigint_tools::all_executor_tools();
    let plugin_tools = sigint_plugin::collect_plugin_tools();

    // ── compute column widths ─────────────────────────────────────────────────
    let mut cols = ColWidths::header();

    if matches!(source, ListSource::BuiltIn | ListSource::All) {
        for t in &builtin_tools {
            cols.update_from_builtin(t.name(), t.description());
        }
        for t in &plugin_tools {
            cols.update_from_builtin(t.name(), t.description());
        }
    }

    if matches!(source, ListSource::Installed | ListSource::All) {
        for (m, _) in &installed {
            cols.update_from_installed(m);
        }
    }

    // ── print table ───────────────────────────────────────────────────────────
    println!("{}", cols.header_row());
    println!("{}", cols.separator());

    if matches!(source, ListSource::BuiltIn | ListSource::All) {
        for t in &builtin_tools {
            println!("{}", cols.builtin_row(t.name(), t.description()));
        }
        for t in &plugin_tools {
            println!("{}", cols.builtin_row(t.name(), t.description()));
        }
    }

    if matches!(source, ListSource::Installed | ListSource::All) {
        for (m, _) in &installed {
            println!("{}", cols.installed_row(m));
        }
    }

    // ── summary footer ────────────────────────────────────────────────────────
    let builtin_count = builtin_tools.len() + plugin_tools.len();
    let installed_count = installed.len();

    println!();
    match source {
        ListSource::BuiltIn => println!("{builtin_count} built-in tool(s)"),
        ListSource::Installed => {
            println!(
                "{installed_count} installed plugin(s) in {}",
                install_root.display()
            );
        }
        ListSource::All => {
            println!(
                "{builtin_count} built-in tool(s), {installed_count} installed plugin(s) in {}",
                install_root.display()
            );
        }
    }

    // Prompt packs (always shown unless filtered to installed-only)
    if !matches!(source, ListSource::Installed) {
        let packs = sigint_plugin::list_prompt_packs();
        if packs.is_empty() {
            println!("Prompt packs: (none — using built-in defaults)");
        } else {
            println!("Prompt packs ({}):", packs.len());
            for (name, desc) in &packs {
                println!("  {} — {}", name, desc);
            }
        }
    }

    Ok(())
}

// ─── `sigint plugin info` ────────────────────────────────────────────────────

/// Show detailed information about a plugin by id.
///
/// For installed plugins: prints all manifest fields plus install path, library
/// filename, library file size, and whether the library file exists.
///
/// For built-in plugins: prints source: built-in, id, description.
///
/// If `<id>` matches both an installed AND a built-in plugin, shows both with
/// a note.  If `<id>` matches multiple installed versions and `--version` is
/// omitted, lists available versions and exits with an error.
///
/// # Errors
///
/// - Plugin not found anywhere → exit 1 with clear message.
/// - Multiple installed versions, `--version` omitted → exit 1 listing versions.
pub fn run_info(id: &str, target_dir: Option<&Path>, version: Option<&str>) -> Result<()> {
    let install_root = resolve_install_root(target_dir);
    let installed = list_installed_manifests(&install_root);

    // Collect matching installed versions
    let mut matches: Vec<(PluginManifest, PathBuf)> =
        installed.into_iter().filter(|(m, _)| m.id == id).collect();

    // Filter by --version if specified
    if let Some(ver) = version {
        matches.retain(|(m, _)| m.version == ver);
        if matches.is_empty() {
            // Check if it exists in a different version to give a better error
            bail!(
                "plugin `{id}` version `{ver}` is not installed in {}",
                install_root.display()
            );
        }
    }

    // Check built-in tools
    let builtin_tools = sigint_tools::all_executor_tools();
    let plugin_tools = sigint_plugin::collect_plugin_tools();
    let builtin_match: Vec<_> = builtin_tools
        .iter()
        .chain(plugin_tools.iter())
        .filter(|t| t.name() == id)
        .collect();

    let found_installed = !matches.is_empty();
    let found_builtin = !builtin_match.is_empty();

    if !found_installed && !found_builtin {
        bail!(
            "no plugin with id `{id}` found (checked installed: {}, built-in tools)",
            install_root.display()
        );
    }

    // Handle multiple installed versions without --version flag
    if found_installed && matches.len() > 1 {
        let versions: Vec<&str> = matches.iter().map(|(m, _)| m.version.as_str()).collect();
        bail!(
            "multiple versions of `{id}` are installed: {}\nUse --version <version> to select one.",
            versions.join(", ")
        );
    }

    // Print installed info
    if found_installed {
        let (manifest, plugin_dir) = &matches[0];
        print_installed_info(manifest, plugin_dir);
    }

    // Print built-in info
    if found_builtin {
        if found_installed {
            println!();
            println!("Note: `{id}` also exists as a built-in tool:");
        }
        for tool in &builtin_match {
            println!("  Source:       built-in (compiled into sigint binary)");
            println!("  ID:           {}", tool.name());
            println!("  Description:  {}", tool.description());
        }
    }

    Ok(())
}

/// Print full details for one installed plugin.
fn print_installed_info(manifest: &PluginManifest, plugin_dir: &Path) {
    let lib_name = library_filename(manifest);
    let lib_path = plugin_dir.join("lib").join(&lib_name);
    let lib_exists = lib_path.exists();
    let lib_size = if lib_exists {
        fs::metadata(&lib_path).map(|m| m.len()).ok()
    } else {
        None
    };

    println!("Source:           installed");
    println!("Install path:     {}", plugin_dir.display());
    println!("ID:               {}", manifest.id);
    println!("Version:          {}", manifest.version);
    println!("Target triple:    {}", manifest.target_triple);
    println!("Entry symbol:     {}", manifest.entry_symbol);

    if let Some(name) = &manifest.display_name {
        println!("Display name:     {name}");
    }
    if let Some(desc) = &manifest.description {
        println!("Description:      {desc}");
    }
    if let Some(author) = &manifest.author {
        println!("Author:           {author}");
    }
    if let Some(license) = &manifest.license {
        println!("License:          {license}");
    }
    if let Some(homepage) = &manifest.homepage {
        println!("Homepage:         {homepage}");
    }

    println!("Library file:     lib/{lib_name}");
    if lib_exists {
        let size_str = lib_size
            .map(|s| format!("{s} bytes"))
            .unwrap_or_else(|| "unknown".to_string());
        println!("Library size:     {size_str}");
        println!("Library present:  yes");
    } else {
        println!("Library present:  NO (missing — reinstall the plugin)");
    }
}

// ─── `sigint plugin new` ─────────────────────────────────────────────────────

/// Scaffold a new plugin crate in the workspace.
pub fn run_new(name: &str) -> Result<()> {
    // Validate name
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
    {
        bail!("Invalid plugin name: use alphanumeric characters, hyphens, or underscores");
    }

    let crate_name = if name.starts_with("sigint-") {
        name.to_string()
    } else {
        format!("sigint-{name}")
    };
    let crate_dir = Path::new("crates").join(&crate_name);

    if crate_dir.exists() {
        bail!("Crate directory already exists: {}", crate_dir.display());
    }

    // Create directory structure
    let src_dir = crate_dir.join("src").join("tools");
    fs::create_dir_all(&src_dir)?;

    // Write Cargo.toml
    let cargo_toml = format!(
        r#"[package]
name = "{crate_name}"
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true

[dependencies]
sigint-plugin = {{ workspace = true }}
sigint-tools = {{ workspace = true }}
sigint-core = {{ workspace = true }}
sigint-llm = {{ workspace = true }}
async-trait = {{ workspace = true }}
serde_json = {{ workspace = true }}
inventory = {{ workspace = true }}
"#
    );
    fs::write(crate_dir.join("Cargo.toml"), cargo_toml)?;

    // Write src/lib.rs
    let lib_rs = "mod tools;\npub use tools::*;\n";
    fs::write(crate_dir.join("src").join("lib.rs"), lib_rs)?;

    // Write src/tools/mod.rs
    let tools_mod = "mod example;\npub use example::*;\n";
    fs::write(src_dir.join("mod.rs"), tools_mod)?;

    // Write src/tools/example.rs
    let example_tool = format!(
        r#"//! Example plugin tool — replace with your own implementation.

use async_trait::async_trait;
use serde_json::{{json, Value}};
use sigint_plugin::register_tool;
use sigint_tools::tool::Tool;
use sigint_tools::result::ToolResult;
use sigint_tools::error::{{Result, ToolError}};
use sigint_core::types::ToolRisk;
use sigint_llm::ToolDefinition;
use std::time::Duration;

pub struct ExamplePluginTool;

impl ExamplePluginTool {{
    pub fn new() -> Self {{
        Self
    }}
}}

#[async_trait]
impl Tool for ExamplePluginTool {{
    fn name(&self) -> &str {{
        "{crate_name}_example"
    }}

    fn description(&self) -> &str {{
        "An example plugin tool — replace with your own implementation"
    }}

    fn definition(&self) -> ToolDefinition {{
        ToolDefinition::function(
            "{crate_name}_example",
            "An example plugin tool",
            json!({{
                "type": "object",
                "properties": {{
                    "input": {{ "type": "string", "description": "Input to process" }}
                }},
                "required": ["input"]
            }}),
        )
    }}

    async fn execute(&self, args: Value) -> Result<ToolResult> {{
        let input = args["input"]
            .as_str()
            .ok_or_else(|| ToolError::MissingArgument("input".to_string()))?;
        Ok(ToolResult {{
            stdout: format!("Example plugin processed: {{input}}"),
            stderr: String::new(),
            exit_code: 0,
            duration: Duration::from_millis(1),
            structured_data: None,
            status: Default::default(),
            truncation: None,
        }})
    }}

    fn risk_level(&self) -> ToolRisk {{
        ToolRisk::Low
    }}
}}

register_tool!(ExamplePluginTool);
"#
    );
    fs::write(src_dir.join("example.rs"), example_tool)?;

    println!("Created plugin crate: {}", crate_dir.display());
    println!();
    println!("Next steps:");
    println!("  1. Add \"{crate_name}\" to workspace members in Cargo.toml");
    println!("  2. Add `{crate_name} = {{ workspace = true }}` to workspace.dependencies");
    println!("  3. Add `{crate_name} = {{ workspace = true }}` to crates/sigint-cli/Cargo.toml");
    println!("  4. Run `cargo build` to verify");

    Ok(())
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Map;
    use sigint_plugin::manifest::SUPPORTED_MANIFEST_VERSION;
    use std::fs;
    use tempfile::TempDir;

    // ─── Fixture helpers ──────────────────────────────────────────────────────

    fn make_manifest(id: &str, version: &str) -> PluginManifest {
        PluginManifest {
            manifest_version: SUPPORTED_MANIFEST_VERSION,
            id: id.to_string(),
            version: version.to_string(),
            target_triple: "x86_64-unknown-linux-gnu".to_string(),
            entry_symbol: "sigint_plugin_entry".to_string(),
            display_name: Some(format!("Test Plugin {id}")),
            description: Some("A test plugin".to_string()),
            author: Some("Test Author".to_string()),
            homepage: Some("https://example.com".to_string()),
            license: Some("MIT".to_string()),
            library_filename: Some(format!("lib{}.so", id.replace('.', "_"))),
            signature: None,
            signed_by: None,
            signature_algorithm: None,
            library_kind: None,
            extra: Map::new(),
        }
    }

    /// Write a plugin install directory (manifest + dummy library).
    fn make_installed_dir(install_root: &Path, manifest: &PluginManifest) -> PathBuf {
        let plugin_dir = install_root.join(format!("{}-{}", manifest.id, manifest.version));
        let lib_dir = plugin_dir.join("lib");
        fs::create_dir_all(&lib_dir).unwrap();

        let manifest_json = serde_json::to_string_pretty(manifest).unwrap();
        fs::write(plugin_dir.join("manifest.json"), manifest_json).unwrap();

        let lib_name = library_filename(manifest);
        fs::write(lib_dir.join(&lib_name), vec![0u8; 512]).unwrap();

        plugin_dir
    }

    // ─── list_installed_manifests (via loader) ────────────────────────────────

    #[test]
    fn list_installed_empty_dir_returns_empty() {
        let tmp = TempDir::new().unwrap();
        let result = list_installed_manifests(tmp.path());
        assert!(
            result.is_empty(),
            "empty install dir should return empty list"
        );
    }

    #[test]
    fn list_installed_nonexistent_dir_returns_empty() {
        let result = list_installed_manifests(Path::new("/nonexistent/sigint/plugins/path/xyz"));
        assert!(
            result.is_empty(),
            "nonexistent dir should return empty, not panic"
        );
    }

    #[test]
    fn list_installed_skips_invalid_manifests() {
        let tmp = TempDir::new().unwrap();
        let install_root = tmp.path();

        // Valid plugin
        let m = make_manifest("com.example.valid", "1.0.0");
        make_installed_dir(install_root, &m);

        // Invalid: directory with corrupt manifest.json
        let bad_dir = install_root.join("com.example.bad-0.1.0");
        fs::create_dir_all(&bad_dir).unwrap();
        fs::write(bad_dir.join("manifest.json"), b"not valid json at all").unwrap();

        let result = list_installed_manifests(install_root);
        assert_eq!(result.len(), 1, "should return only the valid manifest");
        assert_eq!(result[0].0.id, "com.example.valid");
    }

    #[test]
    fn list_installed_returns_all_versions() {
        let tmp = TempDir::new().unwrap();
        let install_root = tmp.path();

        let m1 = make_manifest("com.example.multi", "1.0.0");
        let m2 = make_manifest("com.example.multi", "2.0.0");
        let m3 = make_manifest("com.example.multi", "3.0.0");
        make_installed_dir(install_root, &m1);
        make_installed_dir(install_root, &m2);
        make_installed_dir(install_root, &m3);

        let result = list_installed_manifests(install_root);
        assert_eq!(result.len(), 3, "should return all 3 versions");

        let versions: Vec<&str> = result.iter().map(|(m, _)| m.version.as_str()).collect();
        assert!(
            versions.contains(&"1.0.0")
                && versions.contains(&"2.0.0")
                && versions.contains(&"3.0.0"),
            "all versions should be present: {:?}",
            versions
        );
    }

    #[test]
    fn list_installed_skips_staging_dirs() {
        let tmp = TempDir::new().unwrap();
        let install_root = tmp.path();

        // Valid plugin
        let m = make_manifest("com.example.real", "1.0.0");
        make_installed_dir(install_root, &m);

        // Staging dirs that should be skipped
        let staging = install_root.join(".installing-abc123");
        fs::create_dir_all(&staging).unwrap();
        fs::write(
            staging.join("manifest.json"),
            serde_json::to_string(&m).unwrap(),
        )
        .unwrap();

        let removed = install_root.join(".removed-xyz-abc");
        fs::create_dir_all(&removed).unwrap();

        let result = list_installed_manifests(install_root);
        assert_eq!(result.len(), 1, "staging/removed dirs should be skipped");
        assert_eq!(result[0].0.id, "com.example.real");
    }

    #[test]
    fn list_installed_sorted_by_id_then_version() {
        let tmp = TempDir::new().unwrap();
        let install_root = tmp.path();

        let m_b = make_manifest("com.example.beta", "1.0.0");
        let m_a2 = make_manifest("com.example.alpha", "2.0.0");
        let m_a1 = make_manifest("com.example.alpha", "1.0.0");
        make_installed_dir(install_root, &m_b);
        make_installed_dir(install_root, &m_a2);
        make_installed_dir(install_root, &m_a1);

        let result = list_installed_manifests(install_root);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].0.id, "com.example.alpha");
        assert_eq!(result[0].0.version, "1.0.0");
        assert_eq!(result[1].0.id, "com.example.alpha");
        assert_eq!(result[1].0.version, "2.0.0");
        assert_eq!(result[2].0.id, "com.example.beta");
    }

    // ─── run_info ─────────────────────────────────────────────────────────────

    #[test]
    fn info_finds_installed_plugin() {
        let tmp = TempDir::new().unwrap();
        let install_root = tmp.path();

        let m = make_manifest("com.example.info-test", "1.0.0");
        make_installed_dir(install_root, &m);

        // Should succeed without error
        let result = run_info("com.example.info-test", Some(install_root), None);
        assert!(
            result.is_ok(),
            "run_info should succeed for installed plugin: {:?}",
            result
        );
    }

    #[test]
    fn info_disambiguates_versions() {
        let tmp = TempDir::new().unwrap();
        let install_root = tmp.path();

        let m1 = make_manifest("com.example.multi-info", "1.0.0");
        let m2 = make_manifest("com.example.multi-info", "2.0.0");
        make_installed_dir(install_root, &m1);
        make_installed_dir(install_root, &m2);

        let err = run_info("com.example.multi-info", Some(install_root), None)
            .expect_err("should error when multiple versions installed without --version");
        let msg = err.to_string();
        assert!(
            msg.contains("multiple versions") || msg.contains("1.0.0"),
            "error should mention multiple versions: {msg}"
        );
    }

    #[test]
    fn info_with_version_returns_specific() {
        let tmp = TempDir::new().unwrap();
        let install_root = tmp.path();

        let m1 = make_manifest("com.example.versioned-info", "1.0.0");
        let m2 = make_manifest("com.example.versioned-info", "2.0.0");
        make_installed_dir(install_root, &m1);
        make_installed_dir(install_root, &m2);

        // Requesting version 1.0.0 specifically should succeed
        let result = run_info(
            "com.example.versioned-info",
            Some(install_root),
            Some("1.0.0"),
        );
        assert!(
            result.is_ok(),
            "run_info with explicit version should succeed: {:?}",
            result
        );
    }

    #[test]
    fn info_unknown_id_errors() {
        let tmp = TempDir::new().unwrap();
        let install_root = tmp.path();

        let err = run_info("com.example.nonexistent", Some(install_root), None)
            .expect_err("should error for unknown plugin id");
        let msg = err.to_string();
        assert!(
            msg.contains("no plugin with id") || msg.contains("nonexistent"),
            "error should mention the unknown id: {msg}"
        );
    }

    #[test]
    fn info_wrong_version_errors() {
        let tmp = TempDir::new().unwrap();
        let install_root = tmp.path();

        let m = make_manifest("com.example.one-version", "1.0.0");
        make_installed_dir(install_root, &m);

        let err = run_info("com.example.one-version", Some(install_root), Some("9.9.9"))
            .expect_err("should error when requested version is not installed");
        let msg = err.to_string();
        assert!(
            msg.contains("9.9.9") || msg.contains("not installed"),
            "error should mention the missing version: {msg}"
        );
    }

    // ─── run_list smoke tests ─────────────────────────────────────────────────

    #[test]
    fn list_with_empty_install_dir_succeeds() {
        let tmp = TempDir::new().unwrap();
        // Should not panic or error with an empty install dir
        let result = run_list(Some(tmp.path()), ListSource::All);
        assert!(
            result.is_ok(),
            "run_list with empty dir should succeed: {:?}",
            result
        );
    }

    #[test]
    fn list_installed_source_filter() {
        let tmp = TempDir::new().unwrap();
        let install_root = tmp.path();

        let m = make_manifest("com.example.filter-test", "1.0.0");
        make_installed_dir(install_root, &m);

        let result = run_list(Some(install_root), ListSource::Installed);
        assert!(
            result.is_ok(),
            "run_list with installed filter should succeed: {:?}",
            result
        );
    }

    // ─── Integration test (ignored) ───────────────────────────────────────────

    /// Full install → list → info → uninstall round trip.
    ///
    /// Requires a real `.sgnt-pack` archive.  Marked #[ignore] for routine CI;
    /// run explicitly with:
    ///
    /// ```bash
    /// cargo test -p sigint-cli -- --ignored integration_tests::list_after_install_round_trip
    /// ```
    #[test]
    #[ignore = "integration: requires filesystem and a real .sgnt-pack; run explicitly with --ignored"]
    fn list_after_install_round_trip() {
        use sigint_plugin::{manifest::SUPPORTED_MANIFEST_VERSION, pack::pack_directory};

        let tmp = TempDir::new().unwrap();
        let install_root = tmp.path().join("plugins");
        fs::create_dir_all(&install_root).unwrap();

        // Build a fake manifest
        let manifest = PluginManifest {
            manifest_version: SUPPORTED_MANIFEST_VERSION,
            id: "com.sigint.test.listinfo".to_string(),
            version: "0.1.0".to_string(),
            target_triple: sigint_plugin::loader::HOST_TRIPLE.to_string(),
            entry_symbol: "sigint_plugin_entry".to_string(),
            display_name: Some("List Info Test Plugin".to_string()),
            description: Some("Round-trip test plugin".to_string()),
            author: None,
            homepage: None,
            license: Some("MIT".to_string()),
            library_filename: Some("libcom_sigint_test_listinfo.so".to_string()),
            signature: None,
            signed_by: None,
            signature_algorithm: None,
            library_kind: None,
            extra: Map::new(),
        };

        // Create source dir
        let src_dir = tmp.path().join("src");
        fs::create_dir_all(src_dir.join("lib")).unwrap();
        fs::write(
            src_dir.join("manifest.json"),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();
        fs::write(
            src_dir.join("lib").join("libcom_sigint_test_listinfo.so"),
            vec![0u8; 256],
        )
        .unwrap();

        // Pack and install
        let pack_path = tmp.path().join("test-0.1.0.sgnt-pack");
        pack_directory(&src_dir, &pack_path).expect("pack_directory");

        crate::install::run_install(&pack_path, Some(&install_root), false)
            .expect("install should succeed");

        // list should show the installed plugin
        run_list(Some(&install_root), ListSource::Installed)
            .expect("list after install should succeed");

        // info should find it
        run_info("com.sigint.test.listinfo", Some(&install_root), None)
            .expect("info should succeed after install");

        // uninstall
        crate::install::run_uninstall("com.sigint.test.listinfo", Some(&install_root), None)
            .expect("uninstall should succeed");

        // list should be empty again
        let result = list_installed_manifests(&install_root);
        assert!(result.is_empty(), "list should be empty after uninstall");
    }
}
