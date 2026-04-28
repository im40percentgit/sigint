# sigint-plugin-hello

An example sigint runtime plugin that demonstrates the `.sgnt-pack` archive format
and the C-ABI entry-symbol contract.  Use this as a template for third-party plugin
authors.

## What this plugin does

The plugin exposes a single C-ABI entry symbol (`sigint_plugin_entry`) that returns
plugin identity metadata to the sigint runtime loader.  No tools are registered in
Phase 27 — the entry symbol is the entire contract.

This is the fixture used by T8's closed-loop e2e test (Phase 27): the test packs
this plugin, installs it, and asserts the loader discovers it correctly at startup.

## Files

| File | Purpose |
|------|---------|
| `Cargo.toml` | Workspace member; `crate-type = ["cdylib", "rlib"]` |
| `src/lib.rs` | Entry symbol + unit tests |
| `manifest.json` | Plugin manifest for the installer / loader |
| `README.md` | This file |

## Build

```bash
# From workspace root
cargo build --release -p sigint-plugin-hello

# Output (Linux)
ls target/release/libsigint_plugin_hello.so

# Output (macOS)
ls target/release/libsigint_plugin_hello.dylib

# Verify symbol is exported (Linux)
nm -D target/release/libsigint_plugin_hello.so | grep sigint_plugin_entry
```

The symbol should appear as `T sigint_plugin_entry` (uppercase T = defined in text
section, exported).

## Pack

```bash
# From workspace root
sigint plugin pack examples/sigint-plugin-hello \
    --output sigint-plugin-hello-0.1.0.sgnt-pack
```

`sigint plugin pack` assembles a `.tar.gz` archive with this layout:

```
manifest.json
lib/libsigint_plugin_hello.so   # (or .dylib / .dll on other platforms)
```

Manifest metadata is read from `[package.metadata.sigint-plugin]` in
`Cargo.toml`.  The `target_triple` field is filled in automatically from
the build host — no manual editing needed.

## Install

```bash
sigint plugin install sigint-plugin-hello-0.1.0.sgnt-pack
```

This command:
1. Validates the manifest (version check, target triple check).
2. Unpacks the archive to `~/.local/share/sigint/plugins/com.sigint.example.hello-0.1.0/`.
3. Places the library at `lib/libsigint_plugin_hello.so` inside that directory.

At the next sigint startup, `discover_installed` walks the plugins directory and
loads this plugin via `dlopen`.

## Full quickstart

```bash
# 1. Build
cargo build --release -p sigint-plugin-hello

# 2. Verify symbol export
nm -D target/release/libsigint_plugin_hello.so | grep sigint_plugin_entry

# 3. Pack
sigint plugin pack examples/sigint-plugin-hello \
    --output sigint-plugin-hello-0.1.0.sgnt-pack

# 4. Install
sigint plugin install sigint-plugin-hello-0.1.0.sgnt-pack

# 5. Verify installation
sigint plugin list --source installed
sigint plugin info com.sigint.example.hello

# 6. Uninstall
sigint plugin uninstall com.sigint.example.hello
```

## Install dir layout expected by the loader

```
~/.local/share/sigint/plugins/
  com.sigint.example.hello-0.1.0/
    manifest.json
    lib/
      libsigint_plugin_hello.so
```

## C-ABI contract

The entry function signature (must match exactly):

```rust
#[no_mangle]
pub unsafe extern "C" fn sigint_plugin_entry() -> *const sigint_plugin::abi::PluginEntrypoint {
    &ENTRYPOINT
}
```

The returned pointer must point to memory valid for the library's lifetime.  Using
a `static` value (as this plugin does) is the simplest and safest approach.

## Authoring a new plugin

1. Copy this directory to a new location.
2. Change the `id`, `display_name`, and `description` in `manifest.json`.
3. Update `plugin_id` and `display_name` in `src/lib.rs` to match the manifest.
4. Rename the package in `Cargo.toml` and update `library_filename` in `manifest.json`
   to `lib<package-name-with-underscores>.so`.
5. Add your tool implementations using `sigint_plugin::Tool` and
   `sigint_plugin::register_tool!`.
6. Build, pack, and install.
