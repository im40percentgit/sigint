//! C-ABI entry-symbol contract for runtime-loaded plugins.
//!
//! This module defines the FFI boundary between the sigint host process and a
//! dynamically-loaded plugin shared library.  The contract is intentionally
//! minimal — a single `extern "C"` entry function whose name is declared in
//! the plugin's manifest.
//!
//! # Design
//!
//! @decision DEC-P27-003
//! @title Loader: `libloading` + C-ABI entry symbol
//! @status accepted
//! @rationale `libloading` is the standard Rust dynamic-loading crate.
//! In-process, zero-overhead, matches the unsandboxed-trust model Phase 27
//! commits to.  The entry symbol is an `extern "C"` function named in the
//! manifest (default `sigint_plugin_entry`).  It returns a `*const
//! PluginEntrypoint` C struct carrying plugin identity and a factory table.
//! WASM-based sandboxing is deferred to Phase 28 (REQ-P27-P2-002).
//! Phase 28 seam: swap `libloading::Library::new` for a sandboxed-loader
//! call without changing the entry-symbol contract.
//!
//! # Safety contract for plugin authors
//!
//! 1. The plugin shared library MUST export a `#[no_mangle] pub extern "C"
//!    fn` matching the name declared in `manifest.entry_symbol`.
//! 2. That function MUST return a valid `*const PluginEntrypoint` whose
//!    memory lives for the lifetime of the loaded library (i.e., static or
//!    Box::leak'd).
//! 3. The pointed-to `PluginEntrypoint` MUST have correct `api_version`
//!    (use `PLUGIN_API_VERSION`) so the loader can detect ABI mismatches.
//! 4. All strings inside `PluginEntrypoint` MUST be valid null-terminated
//!    C strings (`*const libc::c_char` semantics — the host uses `CStr`).
//!
//! # Example (plugin crate)
//!
//! ```ignore
//! use sigint_plugin::abi::{PluginEntrypoint, PLUGIN_API_VERSION};
//!
//! static ENTRYPOINT: PluginEntrypoint = PluginEntrypoint {
//!     api_version: PLUGIN_API_VERSION,
//!     plugin_id:   c"com.example.hello".as_ptr().cast(),
//!     display_name: c"Hello Plugin".as_ptr().cast(),
//! };
//!
//! #[no_mangle]
//! pub extern "C" fn sigint_plugin_entry() -> *const PluginEntrypoint {
//!     &ENTRYPOINT
//! }
//! ```

/// Current plugin API version.  Increment here when the `PluginEntrypoint`
/// ABI changes.  The loader rejects plugins whose `api_version` differs.
///
/// Phase 28 seam: if the C-ABI struct gains new mandatory fields, bump this
/// constant; old plugins return the old struct size and must be rejected or
/// tolerated by the loader depending on policy.
pub const PLUGIN_API_VERSION: u32 = 1;

/// Default entry-symbol name used when `manifest.entry_symbol` is empty.
///
/// Plugin crates may export any name as long as the manifest matches, but
/// using the default keeps the convention visible.
pub const DEFAULT_ENTRY_SYMBOL: &str = "sigint_plugin_entry";

/// C-ABI struct returned by the plugin entry function.
///
/// All pointer fields point to null-terminated C strings (`*const u8` for
/// simplicity — in real code you'd use `*const std::ffi::c_char`).  They
/// MUST remain valid for the lifetime of the loaded library.
///
/// Fields are `#[repr(C)]` padded by the host compiler.  Plugin crates
/// compiled for the same target triple will have identical layout because
/// both sides use the same Rust/LLVM toolchain.
///
/// # Phase 28 extension note
///
/// New *optional* fields can be appended to the end of this struct without
/// breaking Phase 27 plugins as long as the loader uses `api_version` to
/// decide how many fields to read.  New *required* fields require a
/// `PLUGIN_API_VERSION` bump.
#[repr(C)]
pub struct PluginEntrypoint {
    /// Must equal `PLUGIN_API_VERSION`.  Loader rejects mismatches.
    pub api_version: u32,

    /// Null-terminated UTF-8 string: the semver-stable plugin id from the
    /// manifest (e.g. `b"com.example.hello\0"`).
    pub plugin_id: *const u8,

    /// Null-terminated UTF-8 string: human-readable display name, or NULL.
    pub display_name: *const u8,
}

// SAFETY: `PluginEntrypoint` contains raw pointers, but the host only reads
// them — it never writes through them.  The plugin is responsible for
// ensuring the pointed-to data lives as long as the library is loaded.
// The struct itself is never sent across threads by the host loader.
unsafe impl Send for PluginEntrypoint {}
unsafe impl Sync for PluginEntrypoint {}

/// Type alias for the entry function signature.
///
/// The loader resolves this symbol from the shared library:
/// ```text
/// extern "C" fn() -> *const PluginEntrypoint
/// ```
///
/// This typedef exists so T3 (the loader) can write:
/// ```ignore
/// let entry: PluginEntryFn = unsafe { lib.get(symbol_bytes)? };
/// let ep = unsafe { &*entry() };
/// ```
pub type PluginEntryFn = unsafe extern "C" fn() -> *const PluginEntrypoint;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_version_is_one() {
        assert_eq!(PLUGIN_API_VERSION, 1);
    }

    #[test]
    fn default_entry_symbol_name() {
        assert_eq!(DEFAULT_ENTRY_SYMBOL, "sigint_plugin_entry");
    }

    #[test]
    fn plugin_entrypoint_is_repr_c() {
        // Smoke-test: verify the struct has the expected fields accessible.
        let ep = PluginEntrypoint {
            api_version: PLUGIN_API_VERSION,
            plugin_id: c"test".as_ptr().cast(),
            display_name: std::ptr::null(),
        };
        assert_eq!(ep.api_version, 1);
        assert!(!ep.plugin_id.is_null());
        assert!(ep.display_name.is_null());
    }
}
