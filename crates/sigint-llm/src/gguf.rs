//! GGUF binary file header reader.
//!
//! Parses the GGUF binary format (version 3) to extract model metadata
//! WITHOUT loading model weights. The reader opens the file, reads only
//! the header section (magic + version + tensor count + key-value pairs),
//! and returns a structured `GgufMetadata` value.
//!
//! GGUF format layout (little-endian):
//! - 4 bytes : magic  `0x46475547` ("GGUF")
//! - 4 bytes : version (u32, expect 3)
//! - 8 bytes : tensor_count (u64)
//! - 8 bytes : metadata_kv_count (u64)
//! - N * (key + value) : metadata key-value pairs
//!
//! @decision DEC-P19-GGUF-001
//! @title Pure-Rust GGUF header reader, no weight loading
//! @status accepted
//! @rationale Model discovery only needs architecture/quantisation metadata,
//! not the multi-GB weight tensors. A bespoke reader keeps the dependency
//! surface minimal and avoids linking llama-cpp-2 for the listing path.

use std::collections::HashMap;
use std::io::{self, Read};
use std::path::Path;

use sigint_core::Error;

// ── GGUF constants ────────────────────────────────────────────────────────────

/// Expected magic bytes at the start of every GGUF file.
const GGUF_MAGIC: u32 = 0x4647_4755; // "GGUF" in little-endian u32

/// The only GGUF version this reader supports.
const GGUF_VERSION_SUPPORTED: u32 = 3;

/// Maximum metadata key count we will attempt to read.
/// Guards against malformed files that claim an astronomically large count.
const MAX_KV_COUNT: u64 = 100_000;

/// Maximum byte length of a single metadata string or key.
/// Guards against malformed files that claim huge string lengths.
const MAX_STRING_LEN: u64 = 1_048_576; // 1 MiB

/// Maximum number of array elements we will read in one ARRAY value.
const MAX_ARRAY_ELEMENTS: u64 = 65_536;

// ── Value type ────────────────────────────────────────────────────────────────

/// A single metadata value from the GGUF key-value store.
#[derive(Debug, Clone)]
pub enum GgufValue {
    U8(u8),
    I8(i8),
    U16(u16),
    I16(i16),
    U32(u32),
    I32(i32),
    F32(f32),
    U64(u64),
    I64(i64),
    F64(f64),
    Bool(bool),
    Str(String),
    Array(Vec<GgufValue>),
}

impl GgufValue {
    /// Return the inner u32 value if this is a `U32` variant.
    pub fn as_u32(&self) -> Option<u32> {
        match self {
            GgufValue::U32(v) => Some(*v),
            _ => None,
        }
    }

    /// Return the inner u64 value if this is a `U64` variant.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            GgufValue::U64(v) => Some(*v),
            _ => None,
        }
    }

    /// Return the inner string reference if this is a `Str` variant.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            GgufValue::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }
}

// ── Public metadata type ──────────────────────────────────────────────────────

/// Metadata extracted from a GGUF model file header.
///
/// Only the header is read; weight tensors are never loaded into memory.
#[derive(Debug, Clone)]
pub struct GgufMetadata {
    /// File name (stem + extension) of the source file.
    pub filename: String,
    /// Total size of the file in bytes.
    pub file_size: u64,
    /// GGUF format version (always 3 for files accepted by this reader).
    pub version: u32,
    /// Number of weight tensors declared in the file.
    pub tensor_count: u64,
    /// All metadata key-value pairs from the header.
    pub metadata: HashMap<String, GgufValue>,
}

impl GgufMetadata {
    // ── Constructor ───────────────────────────────────────────────────────────

    /// Open a GGUF file at `path` and read its header metadata.
    ///
    /// Only the header section is read; weight data is never loaded.
    ///
    /// # Errors
    /// Returns `Error::Llm` if the file cannot be opened, is not a valid GGUF
    /// file, uses an unsupported version, or contains a malformed header.
    pub fn read(path: &Path) -> Result<Self, Error> {
        let filename = path
            .file_name()
            .unwrap_or(path.as_os_str())
            .to_string_lossy()
            .into_owned();

        let file_size = std::fs::metadata(path)
            .map_err(|e| Error::Llm(format!("Cannot stat {:?}: {}", path, e)))?
            .len();

        let file = std::fs::File::open(path)
            .map_err(|e| Error::Llm(format!("Cannot open {:?}: {}", path, e)))?;
        let mut reader = io::BufReader::new(file);

        let mut ctx = ReadCtx { reader: &mut reader, path };

        // Magic
        let magic = ctx.read_u32()?;
        if magic != GGUF_MAGIC {
            return Err(Error::Llm(format!(
                "{:?}: not a GGUF file (magic 0x{:08X}, expected 0x{:08X})",
                path, magic, GGUF_MAGIC
            )));
        }

        // Version
        let version = ctx.read_u32()?;
        if version != GGUF_VERSION_SUPPORTED {
            return Err(Error::Llm(format!(
                "{:?}: unsupported GGUF version {} (only v3 is supported)",
                path, version
            )));
        }

        let tensor_count = ctx.read_u64()?;
        let kv_count = ctx.read_u64()?;

        if kv_count > MAX_KV_COUNT {
            return Err(Error::Llm(format!(
                "{:?}: metadata_kv_count {} exceeds safety limit {}",
                path, kv_count, MAX_KV_COUNT
            )));
        }

        let mut metadata = HashMap::with_capacity(kv_count as usize);
        for _ in 0..kv_count {
            let key = ctx.read_string()?;
            let value_type = ctx.read_u32()?;
            let value = ctx.read_value(value_type)?;
            metadata.insert(key, value);
        }

        Ok(GgufMetadata { filename, file_size, version, tensor_count, metadata })
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    /// Architecture string, e.g. `"llama"`, `"mistral"`.
    ///
    /// Corresponds to the `general.architecture` metadata key.
    pub fn architecture(&self) -> Option<&str> {
        self.metadata.get("general.architecture")?.as_str()
    }

    /// Context window length (tokens) declared in the model header.
    ///
    /// Reads `{arch}.context_length` where `arch` is `general.architecture`.
    /// Falls back to reading the key under `"llama"` if the architecture is absent.
    pub fn context_length(&self) -> Option<u64> {
        let arch = self.architecture().unwrap_or("llama");
        let key = format!("{}.context_length", arch);
        let val = self.metadata.get(&key)?;
        match val {
            GgufValue::U32(v) => Some(*v as u64),
            GgufValue::U64(v) => Some(*v),
            GgufValue::I32(v) if *v >= 0 => Some(*v as u64),
            _ => None,
        }
    }

    /// Quantisation name derived from `general.file_type`.
    ///
    /// Returns `None` if the key is absent or maps to an unrecognised value.
    pub fn quantization_name(&self) -> Option<String> {
        let ft = self.metadata.get("general.file_type")?.as_u32()?;
        Some(file_type_to_quant_name(ft).to_owned())
    }

    /// Human-readable model name.
    ///
    /// Prefers `general.name`; falls back to the filename stem.
    pub fn model_name(&self) -> String {
        if let Some(name) = self.metadata.get("general.name").and_then(|v| v.as_str()) {
            if !name.is_empty() {
                return name.to_owned();
            }
        }
        // Strip extension(s) from filename to get the stem.
        let stem = self.filename
            .split('.')
            .next()
            .unwrap_or(&self.filename);
        stem.to_owned()
    }

    /// Rough parameter count estimate.
    ///
    /// Approximates as `block_count * embedding_length^2 * 4` using
    /// `{arch}.block_count` and `{arch}.embedding_length`. Returns `None`
    /// if either key is missing.
    pub fn parameter_count(&self) -> Option<u64> {
        let arch = self.architecture().unwrap_or("llama");

        let block_count = self
            .metadata
            .get(&format!("{}.block_count", arch))
            .and_then(|v| match v {
                GgufValue::U32(n) => Some(*n as u64),
                GgufValue::U64(n) => Some(*n),
                _ => None,
            })?;

        let embed_len = self
            .metadata
            .get(&format!("{}.embedding_length", arch))
            .and_then(|v| match v {
                GgufValue::U32(n) => Some(*n as u64),
                GgufValue::U64(n) => Some(*n),
                _ => None,
            })?;

        Some(block_count * embed_len * embed_len * 4)
    }
}

// ── file_type → quantisation name ────────────────────────────────────────────

/// Map a GGUF `general.file_type` value to a quantisation name string.
fn file_type_to_quant_name(ft: u32) -> &'static str {
    match ft {
        0 => "F32",
        1 => "F16",
        2 => "Q4_0",
        3 => "Q4_1",
        7 => "Q8_0",
        8 => "Q5_0",
        9 => "Q5_1",
        10 => "Q2_K",
        11 => "Q3_K_S",
        12 => "Q3_K_M",
        13 => "Q3_K_L",
        14 => "Q4_K_S",
        15 => "Q4_K_M",
        16 => "Q5_K_S",
        17 => "Q5_K_M",
        18 => "Q6_K",
        _ => "unknown",
    }
}

// ── Low-level reader ──────────────────────────────────────────────────────────

struct ReadCtx<'a, 'p, R: Read> {
    reader: &'a mut R,
    path: &'p Path,
}

impl<'a, 'p, R: Read> ReadCtx<'a, 'p, R> {
    fn read_exact_buf(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        self.reader.read_exact(buf).map_err(|e| {
            Error::Llm(format!("IO error reading {:?}: {}", self.path, e))
        })
    }

    fn read_u8(&mut self) -> Result<u8, Error> {
        let mut buf = [0u8; 1];
        self.read_exact_buf(&mut buf)?;
        Ok(buf[0])
    }

    fn read_i8(&mut self) -> Result<i8, Error> {
        Ok(self.read_u8()? as i8)
    }

    fn read_u16(&mut self) -> Result<u16, Error> {
        let mut buf = [0u8; 2];
        self.read_exact_buf(&mut buf)?;
        Ok(u16::from_le_bytes(buf))
    }

    fn read_i16(&mut self) -> Result<i16, Error> {
        let mut buf = [0u8; 2];
        self.read_exact_buf(&mut buf)?;
        Ok(i16::from_le_bytes(buf))
    }

    fn read_u32(&mut self) -> Result<u32, Error> {
        let mut buf = [0u8; 4];
        self.read_exact_buf(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn read_i32(&mut self) -> Result<i32, Error> {
        let mut buf = [0u8; 4];
        self.read_exact_buf(&mut buf)?;
        Ok(i32::from_le_bytes(buf))
    }

    fn read_f32(&mut self) -> Result<f32, Error> {
        let mut buf = [0u8; 4];
        self.read_exact_buf(&mut buf)?;
        Ok(f32::from_le_bytes(buf))
    }

    fn read_u64(&mut self) -> Result<u64, Error> {
        let mut buf = [0u8; 8];
        self.read_exact_buf(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn read_i64(&mut self) -> Result<i64, Error> {
        let mut buf = [0u8; 8];
        self.read_exact_buf(&mut buf)?;
        Ok(i64::from_le_bytes(buf))
    }

    fn read_f64(&mut self) -> Result<f64, Error> {
        let mut buf = [0u8; 8];
        self.read_exact_buf(&mut buf)?;
        Ok(f64::from_le_bytes(buf))
    }

    /// Read a length-prefixed UTF-8 string (u64 length + bytes).
    fn read_string(&mut self) -> Result<String, Error> {
        let len = self.read_u64()?;
        if len > MAX_STRING_LEN {
            return Err(Error::Llm(format!(
                "{:?}: string length {} exceeds safety limit {}",
                self.path, len, MAX_STRING_LEN
            )));
        }
        let mut buf = vec![0u8; len as usize];
        self.read_exact_buf(&mut buf)?;
        String::from_utf8(buf).map_err(|e| {
            Error::Llm(format!("{:?}: invalid UTF-8 in string: {}", self.path, e))
        })
    }

    /// Read a single value given its type discriminant.
    fn read_value(&mut self, value_type: u32) -> Result<GgufValue, Error> {
        match value_type {
            0 => Ok(GgufValue::U8(self.read_u8()?)),
            1 => Ok(GgufValue::I8(self.read_i8()?)),
            2 => Ok(GgufValue::U16(self.read_u16()?)),
            3 => Ok(GgufValue::I16(self.read_i16()?)),
            4 => Ok(GgufValue::U32(self.read_u32()?)),
            5 => Ok(GgufValue::I32(self.read_i32()?)),
            6 => Ok(GgufValue::F32(self.read_f32()?)),
            7 => {
                let b = self.read_u8()?;
                Ok(GgufValue::Bool(b != 0))
            }
            8 => Ok(GgufValue::Str(self.read_string()?)),
            9 => {
                let elem_type = self.read_u32()?;
                let count = self.read_u64()?;
                if count > MAX_ARRAY_ELEMENTS {
                    return Err(Error::Llm(format!(
                        "{:?}: array length {} exceeds safety limit {}",
                        self.path, count, MAX_ARRAY_ELEMENTS
                    )));
                }
                let mut elements = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    elements.push(self.read_value(elem_type)?);
                }
                Ok(GgufValue::Array(elements))
            }
            10 => Ok(GgufValue::U64(self.read_u64()?)),
            11 => Ok(GgufValue::I64(self.read_i64()?)),
            12 => Ok(GgufValue::F64(self.read_f64()?)),
            other => Err(Error::Llm(format!(
                "{:?}: unknown GGUF value type {}",
                self.path, other
            ))),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a `GgufMetadata` value directly (bypassing the file reader) for
    /// testing the accessor methods in isolation.
    fn make_meta(kv: Vec<(&str, GgufValue)>) -> GgufMetadata {
        GgufMetadata {
            filename: "test-model-Q4_K_M.gguf".to_owned(),
            file_size: 4_294_967_296,
            version: 3,
            tensor_count: 291,
            metadata: kv.into_iter().map(|(k, v)| (k.to_owned(), v)).collect(),
        }
    }

    // ── architecture ──────────────────────────────────────────────────────────

    #[test]
    fn architecture_present() {
        let m = make_meta(vec![
            ("general.architecture", GgufValue::Str("llama".into())),
        ]);
        assert_eq!(m.architecture(), Some("llama"));
    }

    #[test]
    fn architecture_absent() {
        let m = make_meta(vec![]);
        assert_eq!(m.architecture(), None);
    }

    // ── context_length ────────────────────────────────────────────────────────

    #[test]
    fn context_length_u32() {
        let m = make_meta(vec![
            ("general.architecture", GgufValue::Str("llama".into())),
            ("llama.context_length", GgufValue::U32(4096)),
        ]);
        assert_eq!(m.context_length(), Some(4096));
    }

    #[test]
    fn context_length_u64() {
        let m = make_meta(vec![
            ("general.architecture", GgufValue::Str("mistral".into())),
            ("mistral.context_length", GgufValue::U64(32768)),
        ]);
        assert_eq!(m.context_length(), Some(32768));
    }

    #[test]
    fn context_length_falls_back_to_llama_when_arch_missing() {
        let m = make_meta(vec![
            ("llama.context_length", GgufValue::U32(2048)),
        ]);
        assert_eq!(m.context_length(), Some(2048));
    }

    #[test]
    fn context_length_absent() {
        let m = make_meta(vec![
            ("general.architecture", GgufValue::Str("llama".into())),
        ]);
        assert_eq!(m.context_length(), None);
    }

    // ── quantization_name ─────────────────────────────────────────────────────

    #[test]
    fn quantization_name_known_values() {
        let cases: &[(u32, &str)] = &[
            (0, "F32"),
            (1, "F16"),
            (2, "Q4_0"),
            (3, "Q4_1"),
            (7, "Q8_0"),
            (8, "Q5_0"),
            (9, "Q5_1"),
            (10, "Q2_K"),
            (11, "Q3_K_S"),
            (12, "Q3_K_M"),
            (13, "Q3_K_L"),
            (14, "Q4_K_S"),
            (15, "Q4_K_M"),
            (16, "Q5_K_S"),
            (17, "Q5_K_M"),
            (18, "Q6_K"),
        ];
        for (ft, expected) in cases {
            let m = make_meta(vec![
                ("general.file_type", GgufValue::U32(*ft)),
            ]);
            assert_eq!(
                m.quantization_name().as_deref(),
                Some(*expected),
                "file_type={} should map to {}",
                ft,
                expected
            );
        }
    }

    #[test]
    fn quantization_name_unknown_value() {
        let m = make_meta(vec![
            ("general.file_type", GgufValue::U32(99)),
        ]);
        assert_eq!(m.quantization_name().as_deref(), Some("unknown"));
    }

    #[test]
    fn quantization_name_absent() {
        let m = make_meta(vec![]);
        assert_eq!(m.quantization_name(), None);
    }

    // ── model_name ────────────────────────────────────────────────────────────

    #[test]
    fn model_name_from_general_name() {
        let m = make_meta(vec![
            ("general.name", GgufValue::Str("Llama-3.1-8B-Instruct".into())),
        ]);
        assert_eq!(m.model_name(), "Llama-3.1-8B-Instruct");
    }

    #[test]
    fn model_name_falls_back_to_filename_stem() {
        let m = make_meta(vec![]);
        // filename = "test-model-Q4_K_M.gguf" -> stem is "test-model-Q4_K_M"
        assert_eq!(m.model_name(), "test-model-Q4_K_M");
    }

    #[test]
    fn model_name_empty_general_name_falls_back() {
        let m = make_meta(vec![
            ("general.name", GgufValue::Str("".into())),
        ]);
        assert_eq!(m.model_name(), "test-model-Q4_K_M");
    }

    // ── parameter_count ───────────────────────────────────────────────────────

    #[test]
    fn parameter_count_computed() {
        // 32 blocks * 4096^2 * 4 = 2_147_483_648
        let m = make_meta(vec![
            ("general.architecture", GgufValue::Str("llama".into())),
            ("llama.block_count", GgufValue::U32(32)),
            ("llama.embedding_length", GgufValue::U32(4096)),
        ]);
        assert_eq!(m.parameter_count(), Some(32 * 4096 * 4096 * 4));
    }

    #[test]
    fn parameter_count_missing_block_count() {
        let m = make_meta(vec![
            ("general.architecture", GgufValue::Str("llama".into())),
            ("llama.embedding_length", GgufValue::U32(4096)),
        ]);
        assert_eq!(m.parameter_count(), None);
    }

    #[test]
    fn parameter_count_missing_embedding_length() {
        let m = make_meta(vec![
            ("general.architecture", GgufValue::Str("llama".into())),
            ("llama.block_count", GgufValue::U32(32)),
        ]);
        assert_eq!(m.parameter_count(), None);
    }

    // ── file reader ───────────────────────────────────────────────────────────

    /// Write a minimal valid GGUF v3 file into a temp dir and read it back.
    #[test]
    fn read_minimal_valid_gguf() {
        use std::io::Write;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("test.gguf");
        let mut f = std::fs::File::create(&path).expect("create");

        // Magic
        f.write_all(&0x4647_4755u32.to_le_bytes()).unwrap();
        // Version 3
        f.write_all(&3u32.to_le_bytes()).unwrap();
        // tensor_count = 5
        f.write_all(&5u64.to_le_bytes()).unwrap();
        // kv_count = 1
        f.write_all(&1u64.to_le_bytes()).unwrap();

        // KV: "general.architecture" = "llama"
        let key = b"general.architecture";
        f.write_all(&(key.len() as u64).to_le_bytes()).unwrap();
        f.write_all(key).unwrap();
        f.write_all(&8u32.to_le_bytes()).unwrap(); // type = STRING
        let val = b"llama";
        f.write_all(&(val.len() as u64).to_le_bytes()).unwrap();
        f.write_all(val).unwrap();

        drop(f);

        let meta = GgufMetadata::read(&path).expect("read failed");
        assert_eq!(meta.version, 3);
        assert_eq!(meta.tensor_count, 5);
        assert_eq!(meta.architecture(), Some("llama"));
        assert_eq!(meta.filename, "test.gguf");
    }

    #[test]
    fn read_rejects_bad_magic() {
        use std::io::Write;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bad.bin");
        let mut f = std::fs::File::create(&path).expect("create");
        f.write_all(&0xDEAD_BEEFu32.to_le_bytes()).unwrap();
        drop(f);

        let result = GgufMetadata::read(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not a GGUF file"));
    }

    #[test]
    fn read_rejects_wrong_version() {
        use std::io::Write;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("v2.gguf");
        let mut f = std::fs::File::create(&path).expect("create");
        f.write_all(&0x4647_4755u32.to_le_bytes()).unwrap(); // correct magic
        f.write_all(&2u32.to_le_bytes()).unwrap();           // version 2 (unsupported)
        drop(f);

        let result = GgufMetadata::read(&path);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unsupported GGUF version"));
    }

    // ── GgufValue accessors ───────────────────────────────────────────────────

    #[test]
    fn gguf_value_as_u32() {
        assert_eq!(GgufValue::U32(42).as_u32(), Some(42));
        assert_eq!(GgufValue::U64(42).as_u32(), None);
        assert_eq!(GgufValue::Str("x".into()).as_u32(), None);
    }

    #[test]
    fn gguf_value_as_u64() {
        assert_eq!(GgufValue::U64(99).as_u64(), Some(99));
        assert_eq!(GgufValue::U32(99).as_u64(), None);
    }

    #[test]
    fn gguf_value_as_str() {
        assert_eq!(GgufValue::Str("hello".into()).as_str(), Some("hello"));
        assert_eq!(GgufValue::U32(1).as_str(), None);
    }
}
