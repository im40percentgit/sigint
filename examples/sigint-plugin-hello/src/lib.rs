//! Example sigint plugin demonstrating the C-ABI entry symbol contract.
//!
//! This is a third-party-style plugin: it depends only on `sigint-plugin`'s
//! public type definitions, not on any internal APIs.  The output of
//! `cargo build --release -p sigint-plugin-hello` produces
//! `target/release/libsigint_plugin_hello.so` (or the platform-equivalent),
//! which can be packaged into a `.sgnt-pack` archive and installed via
//! `sigint plugin install`.
//!
//! # Structure of this file
//!
//! 1. A `static ENTRYPOINT: PluginEntrypoint` holding the plugin identity.
//! 2. The exported entry function `sigint_plugin_entry` (the C-ABI symbol
//!    resolved by the loader).
//! 3. A private sanity-check unit test verifying that the entry function
//!    compiles and returns a non-null, correctly-versioned pointer.
//!
//! @decision DEC-P27-T7-001
//! @title Example plugin uses static ENTRYPOINT for zero-allocation ABI return
//! @status accepted
//! @rationale The loader requires the returned `*const PluginEntrypoint` to
//! remain valid for the lifetime of the loaded library.  A `'static` reference
//! satisfies this without heap allocation or synchronization overhead.
//! `Box::leak` is an alternative, but a named static makes the intent explicit
//! and is trivially readable by third-party plugin authors using this crate as
//! a template.

use sigint_plugin::abi::{PluginEntrypoint, PLUGIN_API_VERSION};

/// Plugin identity, returned by the entry function.
///
/// The `static` lifetime guarantees this memory lives as long as the shared
/// library is mapped into the host process — satisfying the loader's safety
/// contract documented in `sigint_plugin::abi`.
///
/// # String representation
///
/// `PluginEntrypoint`'s pointer fields are typed `*const u8` (null-terminated
/// UTF-8 bytes).  The `c"..."` literal (Rust 1.77+) produces a `*const i8`
/// via `CStr::as_ptr()`, so we cast to `*const u8` with `.cast::<u8>()`.
/// The cast is safe because both types have identical bit representations;
/// the only difference is the signedness annotation, which Rust uses for
/// C-char compatibility.
static ENTRYPOINT: PluginEntrypoint = PluginEntrypoint {
    api_version: PLUGIN_API_VERSION,
    plugin_id: c"com.sigint.example.hello".as_ptr().cast::<u8>(),
    display_name: c"Hello Plugin".as_ptr().cast::<u8>(),
};

/// Entry symbol resolved by the sigint runtime loader (`discover_installed`).
///
/// The loader looks up this symbol by the name declared in `manifest.json`'s
/// `entry_symbol` field (default: `"sigint_plugin_entry"`).  It then calls the
/// function and validates the returned `PluginEntrypoint`:
/// - `api_version` must equal [`PLUGIN_API_VERSION`] (currently 1).
/// - `plugin_id` must be a non-null, null-terminated UTF-8 string.
///
/// # Safety
///
/// The returned pointer points to static memory (`ENTRYPOINT`) and is valid for
/// the entire lifetime of the loaded shared library.  The caller (loader) must
/// not write through this pointer.
#[no_mangle]
pub unsafe extern "C" fn sigint_plugin_entry() -> *const PluginEntrypoint {
    &raw const ENTRYPOINT
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigint_plugin::abi::PLUGIN_API_VERSION;

    /// Verify the entry symbol is callable in-process and returns the expected
    /// values.
    ///
    /// This is NOT a test of the `dlopen` path (that requires T8's integration
    /// test) — it is a compile-time sanity check that the entry function:
    /// - returns a non-null pointer
    /// - carries the correct `api_version`
    /// - carries non-null `plugin_id` and `display_name` pointers
    #[test]
    fn entry_returns_valid_entrypoint() {
        // SAFETY: we are in the same process; the entry fn is called directly.
        let ep_ptr = unsafe { sigint_plugin_entry() };
        assert!(
            !ep_ptr.is_null(),
            "sigint_plugin_entry must not return a null pointer"
        );

        // SAFETY: we just confirmed `ep_ptr` is non-null; it points to `ENTRYPOINT`
        // (static memory), which is valid for the duration of this test.
        let ep = unsafe { &*ep_ptr };
        assert_eq!(
            ep.api_version, PLUGIN_API_VERSION,
            "api_version must match PLUGIN_API_VERSION"
        );
        assert!(
            !ep.plugin_id.is_null(),
            "plugin_id must be a non-null pointer"
        );
        assert!(
            !ep.display_name.is_null(),
            "display_name must be a non-null pointer"
        );
    }

    /// Verify the plugin_id string content matches the manifest declaration.
    #[test]
    fn plugin_id_is_correct() {
        use std::ffi::CStr;
        let ep_ptr = unsafe { sigint_plugin_entry() };
        let ep = unsafe { &*ep_ptr };
        // SAFETY: plugin_id is a null-terminated static string literal.
        let id = unsafe { CStr::from_ptr(ep.plugin_id.cast()) };
        assert_eq!(
            id.to_str().expect("plugin_id must be valid UTF-8"),
            "com.sigint.example.hello"
        );
    }
}
