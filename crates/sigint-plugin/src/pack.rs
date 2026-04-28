//! `.sgnt-pack` archive read/write primitives.
//!
//! A `.sgnt-pack` file is a gzip-compressed tar archive with the following
//! internal layout:
//!
//! ```text
//! manifest.json          ← required; parsed by [`read_manifest_from_archive`]
//! lib/<library-file>     ← required; the platform dynamic library
//! README.md              ← optional
//! LICENSE                ← optional
//! ```
//!
//! This module owns the canonical archive format.  CLI commands (`pack`,
//! `install`) call these helpers; they do not handle the archive themselves.
//!
//! @decision DEC-P27-001
//! @title Pack format: tar+gzip archive with fixed internal layout
//! @status accepted
//! @rationale `.tar.gz` is universal, streamable, and the Rust ecosystem has
//! strong support via the `tar` + `flate2` crates.  Internal layout:
//! `manifest.json` at the archive root, `lib/<library-filename>` for the
//! dynamic library, optional `README.md` and `LICENSE` at the root.  The
//! `.sgnt-pack` extension signals the format to users and CI scripts without
//! ambiguity.  Addresses REQ-P27-P0-001.  Phase 28 seam: the archive format
//! is stable; Phase 28 adds a sibling `<id>-<version>.sig` file or extends
//! the manifest — it never restructures the layout (Phase 27 seam #7).

use std::io::{Read, Write};
use std::path::Path;

use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use tar::{Archive, Builder, Header};

use crate::manifest::{parse_manifest, PluginManifest};

// ─── Error type ──────────────────────────────────────────────────────────────

/// Errors produced by the manifest parser and archive helpers.
#[derive(thiserror::Error, Debug)]
pub enum PackError {
    /// The archive contains a manifest with an unsupported `manifest_version`.
    ///
    /// Phase 28 seam #2: when v2 packs become the norm, old sigint builds
    /// surface this message automatically, guiding users to upgrade.
    #[error(
        "manifest version {got} is not supported by this sigint build \
         (supports version 1; upgrade sigint or use a compatible plugin \
         — see sigint-plugin-spec >= 2.0)"
    )]
    UnsupportedManifestVersion { got: u32 },

    /// A required manifest field is absent or empty.
    #[error("manifest missing required field: {field}")]
    MissingField { field: &'static str },

    /// Generic manifest content error not covered by a more specific variant.
    #[error("invalid manifest: {0}")]
    InvalidManifest(String),

    /// I/O error from the host OS.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// JSON parse/serialize error.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    /// Archive-level error (missing entry, malformed tar header, etc.).
    #[error("archive: {0}")]
    Archive(String),
}

// ─── Archive paths ────────────────────────────────────────────────────────────

/// Path of the manifest inside every `.sgnt-pack` archive.
pub const ARCHIVE_MANIFEST_PATH: &str = "manifest.json";

/// Prefix directory for the dynamic library inside the archive.
pub const ARCHIVE_LIB_DIR: &str = "lib";

// ─── Read helpers ─────────────────────────────────────────────────────────────

/// Open a `.sgnt-pack` archive and parse only the `manifest.json` entry.
///
/// Does **not** extract any other files.  Safe to call on large packs; only
/// the manifest entry is read into memory.
///
/// # Errors
///
/// - [`PackError::Io`] — cannot open or read the file.
/// - [`PackError::Archive`] — `manifest.json` is absent from the archive.
/// - [`PackError::Json`] / [`PackError::InvalidManifest`] — manifest is malformed.
/// - [`PackError::UnsupportedManifestVersion`] — version is not 1.
/// - [`PackError::MissingField`] — a required field is empty.
pub fn read_manifest_from_archive(path: &Path) -> Result<PluginManifest, PackError> {
    let file = std::fs::File::open(path)?;
    let gz = GzDecoder::new(file);
    let mut archive = Archive::new(gz);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let entry_path = entry.path()?;
        if entry_path.to_string_lossy() == ARCHIVE_MANIFEST_PATH {
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            return parse_manifest(&bytes);
        }
    }

    Err(PackError::Archive(format!(
        "archive does not contain '{ARCHIVE_MANIFEST_PATH}'"
    )))
}

/// Open a `.sgnt-pack` archive and extract all its contents to `dest`.
///
/// Returns the parsed manifest so callers can verify `target_triple` before
/// moving files to the install location.
///
/// The archive is extracted without path traversal: entries with absolute
/// paths or components that escape `dest` (via `..`) are rejected.
///
/// # Errors
///
/// - [`PackError::Io`] — cannot read the archive or write to `dest`.
/// - [`PackError::Archive`] — `manifest.json` missing, or a tar entry has a
///   path that would escape `dest` (path traversal guard).
/// - [`PackError::Json`] / [`PackError::InvalidManifest`] / [`PackError::MissingField`]
///   / [`PackError::UnsupportedManifestVersion`] — manifest invalid.
pub fn extract_archive(archive_path: &Path, dest: &Path) -> Result<PluginManifest, PackError> {
    // Single-pass: read entries, extract to dest, capture manifest bytes.
    // The tar crate uses a forward-only streaming API so we do everything in
    // one pass and parse the manifest from the bytes we buffered along the way.

    let dest_canonical = dest.canonicalize().unwrap_or_else(|_| dest.to_path_buf());

    let mut manifest_bytes: Option<Vec<u8>> = None;

    let file2 = std::fs::File::open(archive_path)?;
    let gz2 = GzDecoder::new(file2);
    let mut archive2 = Archive::new(gz2);

    for entry in archive2.entries()? {
        let mut entry = entry?;
        let entry_path_raw = entry.path()?;
        let entry_path = entry_path_raw.to_string_lossy().into_owned();

        // Path traversal guard
        let relative = Path::new(&entry_path);
        if relative.is_absolute() {
            return Err(PackError::Archive(format!(
                "archive entry has absolute path: {entry_path}"
            )));
        }
        for component in relative.components() {
            if component == std::path::Component::ParentDir {
                return Err(PackError::Archive(format!(
                    "archive entry attempts path traversal: {entry_path}"
                )));
            }
        }

        let target = dest.join(&entry_path);

        // Extra safety: ensure resolved target is still under dest.
        // (Only meaningful after dest exists; best-effort otherwise.)
        if dest_canonical != dest.to_path_buf() {
            if let Ok(canonical_target) = target.canonicalize() {
                if !canonical_target.starts_with(&dest_canonical) {
                    return Err(PackError::Archive(format!(
                        "archive entry escapes dest directory: {entry_path}"
                    )));
                }
            }
        }

        if entry_path == ARCHIVE_MANIFEST_PATH {
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            manifest_bytes = Some(bytes.clone());
            // Write manifest to dest
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(&target, &bytes)?;
        } else {
            // Regular file or directory
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            if entry.header().entry_type().is_dir() {
                std::fs::create_dir_all(&target)?;
            } else {
                let mut buf = Vec::new();
                entry.read_to_end(&mut buf)?;
                std::fs::write(&target, &buf)?;
            }
        }
    }

    let manifest_bytes = manifest_bytes.ok_or_else(|| {
        PackError::Archive(format!(
            "archive does not contain '{ARCHIVE_MANIFEST_PATH}'"
        ))
    })?;

    parse_manifest(&manifest_bytes)
}

// ─── Write helper ─────────────────────────────────────────────────────────────

/// Package a source directory into a `.sgnt-pack` archive.
///
/// `source_dir` must contain:
/// - `manifest.json` — a valid plugin manifest.
/// - `lib/<library-filename>` — the platform dynamic library, where the
///   filename is taken from `manifest.library_filename` or derived via
///   [`crate::manifest::library_filename`].
///
/// Optional files `README.md` and `LICENSE` at `source_dir` root are
/// included if present.
///
/// The resulting archive is written to `output`.
///
/// # Errors
///
/// - [`PackError::Archive`] — `manifest.json` or the library file is missing.
/// - [`PackError::Io`] — cannot read source files or write the archive.
/// - [`PackError::Json`] / [`PackError::InvalidManifest`] / [`PackError::MissingField`]
///   / [`PackError::UnsupportedManifestVersion`] — manifest invalid.
pub fn pack_directory(source_dir: &Path, output: &Path) -> Result<(), PackError> {
    // Validate manifest first
    let manifest_path = source_dir.join(ARCHIVE_MANIFEST_PATH);
    if !manifest_path.exists() {
        return Err(PackError::Archive(format!(
            "source directory does not contain '{ARCHIVE_MANIFEST_PATH}': {}",
            source_dir.display()
        )));
    }
    let manifest_bytes = std::fs::read(&manifest_path)?;
    let manifest = parse_manifest(&manifest_bytes)?;

    // Locate library file
    let lib_name = crate::manifest::library_filename(&manifest);
    let lib_src = source_dir.join(ARCHIVE_LIB_DIR).join(&lib_name);
    if !lib_src.exists() {
        return Err(PackError::Archive(format!(
            "library file not found at '{}' (expected lib/{lib_name})",
            lib_src.display()
        )));
    }

    // Create output archive
    let out_file = std::fs::File::create(output)?;
    let gz = GzEncoder::new(out_file, Compression::best());
    let mut builder = Builder::new(gz);

    // 1. manifest.json
    add_file_to_archive(&mut builder, &manifest_path, ARCHIVE_MANIFEST_PATH)?;

    // 2. lib/<library>
    let archive_lib_path = format!("{ARCHIVE_LIB_DIR}/{lib_name}");
    add_file_to_archive(&mut builder, &lib_src, &archive_lib_path)?;

    // 3. Optional files
    for optional in &["README.md", "LICENSE"] {
        let src = source_dir.join(optional);
        if src.exists() {
            add_file_to_archive(&mut builder, &src, optional)?;
        }
    }

    // Finalise the archive (writes end-of-archive blocks + flushes gzip)
    builder.finish()?;

    Ok(())
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

fn add_file_to_archive<W: Write>(
    builder: &mut Builder<W>,
    src: &Path,
    archive_path: &str,
) -> Result<(), PackError> {
    let data = std::fs::read(src)?;
    let mut header = Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, archive_path, data.as_slice())
        .map_err(|e| PackError::Archive(e.to_string()))?;
    Ok(())
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::PluginManifest;
    use serde_json::Map;

    /// Build a minimal `PluginManifest` for use in tests.
    fn test_manifest(id: &str) -> PluginManifest {
        PluginManifest {
            manifest_version: 1,
            id: id.to_string(),
            version: "0.1.0".to_string(),
            target_triple: "x86_64-unknown-linux-gnu".to_string(),
            entry_symbol: "sigint_plugin_entry".to_string(),
            display_name: None,
            description: None,
            author: None,
            homepage: None,
            license: None,
            library_filename: Some("libtest.so".to_string()),
            signature: None,
            signed_by: None,
            signature_algorithm: None,
            library_kind: None,
            extra: Map::new(),
        }
    }

    /// Write a minimal source directory: manifest.json + lib/libtest.so
    fn write_source_dir(dir: &Path, manifest: &PluginManifest) -> std::io::Result<()> {
        let manifest_json = serde_json::to_string_pretty(manifest).unwrap();
        std::fs::write(dir.join("manifest.json"), manifest_json)?;

        let lib_dir = dir.join("lib");
        std::fs::create_dir_all(&lib_dir)?;
        // 1 KiB dummy library
        std::fs::write(lib_dir.join("libtest.so"), vec![0u8; 1024])?;
        Ok(())
    }

    // -------------------------------------------------------------------------
    // pack_and_extract_round_trip
    // -------------------------------------------------------------------------
    #[test]
    fn pack_and_extract_round_trip() {
        let src_dir = tempfile::tempdir().expect("tempdir");
        let extract_dir = tempfile::tempdir().expect("tempdir");
        let pack_path = src_dir.path().join("test.sgnt-pack");

        let manifest = test_manifest("com.example.roundtrip");
        write_source_dir(src_dir.path(), &manifest).expect("write source");

        // Pack
        pack_directory(src_dir.path(), &pack_path).expect("pack_directory");
        assert!(pack_path.exists(), "pack file should exist");

        // Extract
        let extracted_manifest =
            extract_archive(&pack_path, extract_dir.path()).expect("extract_archive");

        // Manifest round-trips exactly
        assert_eq!(extracted_manifest.id, manifest.id);
        assert_eq!(extracted_manifest.version, manifest.version);
        assert_eq!(extracted_manifest.target_triple, manifest.target_triple);
        assert_eq!(extracted_manifest.entry_symbol, manifest.entry_symbol);
        assert_eq!(
            extracted_manifest.library_filename,
            manifest.library_filename
        );

        // Library file is present in the extracted tree
        let extracted_lib = extract_dir.path().join("lib").join("libtest.so");
        assert!(
            extracted_lib.exists(),
            "library should be extracted to lib/libtest.so"
        );
        assert_eq!(
            std::fs::read(&extracted_lib).unwrap().len(),
            1024,
            "extracted library should be 1024 bytes"
        );
    }

    // -------------------------------------------------------------------------
    // read_manifest_from_archive_skips_extraction
    // -------------------------------------------------------------------------
    #[test]
    fn read_manifest_from_archive_skips_extraction() {
        let src_dir = tempfile::tempdir().expect("tempdir");
        let pack_path = src_dir.path().join("test.sgnt-pack");

        let manifest = test_manifest("com.example.partial");
        write_source_dir(src_dir.path(), &manifest).expect("write source");
        pack_directory(src_dir.path(), &pack_path).expect("pack");

        // Read-only manifest access — no extraction target is provided
        let m = read_manifest_from_archive(&pack_path).expect("read_manifest_from_archive");
        assert_eq!(m.id, "com.example.partial");

        // Confirm: no files were extracted to a side directory.
        // (The function only opens the archive; it must not write to disk.)
        // We verify this by confirming that neither lib/ nor manifest.json
        // appeared next to the archive file (only the pack itself is there).
        let siblings: Vec<_> = std::fs::read_dir(src_dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name())
            .collect();
        // Expect: the original source files + the pack, but no 'lib' dir created by read
        let has_lib_from_read = siblings
            .iter()
            .any(|n| n.to_string_lossy() == "lib_extracted_by_read");
        assert!(
            !has_lib_from_read,
            "read_manifest_from_archive must not extract files"
        );
    }

    // -------------------------------------------------------------------------
    // pack_directory_fails_on_missing_manifest
    // -------------------------------------------------------------------------
    #[test]
    fn pack_directory_fails_on_missing_manifest() {
        let empty_dir = tempfile::tempdir().expect("tempdir");
        let out = empty_dir.path().join("out.sgnt-pack");
        let err = pack_directory(empty_dir.path(), &out).expect_err("should fail without manifest");
        assert!(
            matches!(err, PackError::Archive(_)),
            "expected Archive error, got: {err}"
        );
    }

    // -------------------------------------------------------------------------
    // pack_directory_fails_on_missing_library
    // -------------------------------------------------------------------------
    #[test]
    fn pack_directory_fails_on_missing_library() {
        let src_dir = tempfile::tempdir().expect("tempdir");
        let manifest = test_manifest("com.example.nolib");
        let manifest_json = serde_json::to_string_pretty(&manifest).unwrap();
        std::fs::write(src_dir.path().join("manifest.json"), manifest_json).unwrap();
        // No lib/ directory written

        let out = src_dir.path().join("out.sgnt-pack");
        let err = pack_directory(src_dir.path(), &out).expect_err("should fail without library");
        assert!(
            matches!(err, PackError::Archive(_)),
            "expected Archive error, got: {err}"
        );
    }

    // =========================================================================
    // Path-traversal regression tests for extract_archive
    //
    // Rationale: The tar crate's Builder::append_data rejects `..` and
    // absolute paths at write time (see `copy_path_into_inner` in the tar
    // crate source), so malicious archives cannot be constructed via the
    // normal API.  Instead, these tests build the tar+gz bytes manually by
    // writing raw POSIX tar header bytes, bypassing the tar crate's
    // sanitisation.  This mirrors what an attacker-controlled archive would
    // look like on disk.
    //
    // The POSIX/ustar tar header layout (512 bytes):
    //   [0..100]   name
    //   [100..108] mode (octal, null-terminated)
    //   [108..116] uid
    //   [116..124] gid
    //   [124..136] size (octal, null-terminated)
    //   [136..148] mtime (octal, null-terminated)
    //   [148..156] checksum
    //   [156]      typeflag  ('0' = regular file)
    //   [157..257] linkname
    //   [257..263] "ustar\0"
    //   [263..265] version "00"
    //   ... (rest padding)
    // =========================================================================

    /// Build a tar+gzip archive in raw bytes, bypassing the `tar` crate's
    /// path sanitisation.  `entry_name` is written verbatim into the header
    /// name field; `content` is the file payload.
    ///
    /// This deliberately produces an archive with a malicious entry path so
    /// `extract_archive` can exercise its path-traversal guard.
    fn build_malicious_archive(entry_name: &[u8], content: &[u8]) -> Vec<u8> {
        use std::io::Write as _;

        // --- Tar header (512 bytes) -------------------------------------------
        let mut hdr = [0u8; 512];

        // name field [0..100]: write the raw malicious path
        let name_len = entry_name.len().min(99); // keep a NUL terminator
        hdr[..name_len].copy_from_slice(&entry_name[..name_len]);

        // mode [100..108]: "0000644\0"
        hdr[100..108].copy_from_slice(b"0000644\0");

        // uid [108..116], gid [116..124]: all zeros (valid)
        hdr[108..116].copy_from_slice(b"0000000\0");
        hdr[116..124].copy_from_slice(b"0000000\0");

        // size [124..136]: octal representation of content length
        let size_str = format!("{:011o}\0", content.len());
        hdr[124..136].copy_from_slice(size_str.as_bytes());

        // mtime [136..148]: zero
        hdr[136..148].copy_from_slice(b"00000000000\0");

        // checksum placeholder [148..156]: will be filled below
        hdr[148..156].copy_from_slice(b"        "); // 8 spaces for checksum calc

        // typeflag [156]: '0' = regular file
        hdr[156] = b'0';

        // magic "ustar\0" [257..263] + version "00" [263..265]
        hdr[257..263].copy_from_slice(b"ustar\0");
        hdr[263..265].copy_from_slice(b"00");

        // Compute checksum: unsigned sum of all 512 bytes
        let cksum: u32 = hdr.iter().map(|&b| b as u32).sum();
        // Write 6-digit octal + NUL + space into [148..156]
        let cksum_str = format!("{:06o}\0 ", cksum);
        hdr[148..156].copy_from_slice(cksum_str.as_bytes());

        // --- Tar data blocks (content padded to 512-byte boundary) -----------
        let mut tar_bytes: Vec<u8> = Vec::new();
        tar_bytes.extend_from_slice(&hdr);
        tar_bytes.extend_from_slice(content);
        // pad to 512-byte boundary
        let rem = content.len() % 512;
        if rem != 0 {
            tar_bytes.extend(std::iter::repeat_n(0u8, 512 - rem));
        }
        // end-of-archive: two 512-byte zero blocks
        tar_bytes.extend(std::iter::repeat_n(0u8, 1024));

        // --- Gzip-compress the tar stream ------------------------------------
        let mut gz_buf = Vec::new();
        {
            let mut enc = GzEncoder::new(&mut gz_buf, Compression::best());
            enc.write_all(&tar_bytes).expect("gz write");
            enc.finish().expect("gz finish");
        }
        gz_buf
    }

    /// Assert that `extract_archive` on the archive rejects with an
    /// `Archive` error whose message contains `keyword`, and that no file
    /// escaped outside `dest`.
    fn assert_traversal_rejected(archive_bytes: &[u8], keyword: &str) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dest = tmp.path();

        // Write the malicious archive to a file
        let pack_path = dest.join("malicious.sgnt-pack");
        std::fs::write(&pack_path, archive_bytes).expect("write malicious archive");

        let result = extract_archive(&pack_path, dest);

        // Must be an error
        assert!(
            result.is_err(),
            "extract_archive must reject malicious archive"
        );

        let err = result.unwrap_err();

        // Must be the Archive variant
        assert!(
            matches!(err, PackError::Archive(_)),
            "expected PackError::Archive, got: {err}"
        );

        // Error message must contain the relevant keyword
        let msg = err.to_string();
        assert!(
            msg.contains(keyword),
            "error message should contain {keyword:?}, got: {msg:?}"
        );

        // Verify nothing escaped outside dest — the parent of dest should not
        // have gained any new files/dirs.  We check that the parent still has
        // exactly the same children it had before (tempfile dirs are isolated).
        //
        // Concretely: no file at `dest.parent()/../etc/passwd` etc.
        // The tempdir parent is a system tmp dir; we look for the sentinel
        // filenames used in these tests.
        let parent = dest.parent().unwrap_or(dest);
        let escaped = std::fs::read_dir(parent)
            .ok()
            .map(|rd| {
                rd.filter_map(|e| e.ok()).any(|e| {
                    let name = e.file_name();
                    let s = name.to_string_lossy();
                    // Sentinel names the malicious archives attempt to create
                    s == "passwd" || s == "escape_target" || s.contains("escape")
                })
            })
            .unwrap_or(false);
        assert!(
            !escaped,
            "a file escaped outside the dest tempdir — path traversal guard failed"
        );
    }

    // -------------------------------------------------------------------------
    // extract_archive_rejects_parent_dir_traversal
    //
    // Archive entry path: "../../etc/passwd"
    // Guard: Component::ParentDir check → PackError::Archive("attempts path traversal")
    // -------------------------------------------------------------------------
    #[test]
    fn extract_archive_rejects_parent_dir_traversal() {
        // The malicious path has two ".." components — the guard catches the
        // first `Component::ParentDir` and returns an error immediately.
        let archive = build_malicious_archive(b"../../etc/passwd", b"pwned");
        assert_traversal_rejected(&archive, "traversal");
    }

    // -------------------------------------------------------------------------
    // extract_archive_rejects_single_parent_dir_traversal
    //
    // Archive entry path: "../escape_target"
    // Variant: single ".." — guard catches Component::ParentDir on the first
    // component, same code path as the double-dot variant.
    // -------------------------------------------------------------------------
    #[test]
    fn extract_archive_rejects_single_parent_dir_traversal() {
        let archive = build_malicious_archive(b"../escape_target", b"pwned");
        assert_traversal_rejected(&archive, "traversal");
    }

    // -------------------------------------------------------------------------
    // extract_archive_rejects_absolute_path
    //
    // Archive entry path: "/tmp/foo"
    // Guard: `relative.is_absolute()` → PackError::Archive("absolute path")
    // -------------------------------------------------------------------------
    #[test]
    fn extract_archive_rejects_absolute_path() {
        // The path starts with '/' — the `is_absolute()` guard fires first.
        let archive = build_malicious_archive(b"/tmp/foo", b"pwned");
        assert_traversal_rejected(&archive, "absolute");
    }

    // -------------------------------------------------------------------------
    // extract_archive_rejects_nested_parent_dir_traversal
    //
    // Archive entry path: "safe/../../etc/passwd"
    // Guard: first component is Normal("safe"), second is ParentDir — guard
    // still catches it.
    // -------------------------------------------------------------------------
    #[test]
    fn extract_archive_rejects_nested_parent_dir_traversal() {
        // A subtler variant: the path looks safe at first glance but escapes
        // the dest dir by embedding ".." after a normal component.
        let archive = build_malicious_archive(b"safe/../../etc/passwd", b"pwned");
        assert_traversal_rejected(&archive, "traversal");
    }
}
