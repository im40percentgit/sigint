//! Embedded LLM provider — runs a GGUF model in-process via llama-cpp-2.
//!
//! This module is gated behind the `embedded-llm` Cargo feature flag because
//! llama-cpp-2 requires a C/C++ toolchain and takes several minutes to
//! compile. The default build stays fast and dependency-free; users who want
//! on-device inference without an Ollama daemon rebuild with:
//!
//!   cargo build --features embedded-llm
//!
//! ## Architecture
//!
//! `LlamaModel` is not `Send + Sync` — it holds raw C pointers. To satisfy
//! Tokio's async executor we load a fresh backend + model + context inside
//! `spawn_blocking` on every call. For pentest workloads (one active session
//! at a time, not high-throughput chat) this is acceptable; the model weights
//! stay in the OS page cache after the first load so subsequent calls are
//! fast.
//!
//! For streaming, a `tokio::sync::mpsc` channel bridges the blocking inference
//! thread and the async `chat_stream` caller: the `spawn_blocking` closure
//! sends each decoded token piece across the channel and the `async_stream`
//! wrapper yields them as `StreamChunk` items.
//!
//! @decision DEC-P19-EMBEDDED-001
//! @title EmbeddedProvider gated behind embedded-llm Cargo feature flag
//! @status accepted
//! @rationale llama-cpp-2 compilation requires a C toolchain and takes several
//! minutes; feature flag keeps default builds fast and dependency-free.
//! Factory returns a descriptive error (mentioning the feature flag) when
//! provider=embedded is requested without the flag.
//!
//! @decision DEC-P19-EMBEDDED-002
//! @title Load model fresh inside spawn_blocking rather than storing in struct
//! @status accepted
//! @rationale LlamaModel is not Send+Sync (raw C pointers). Loading fresh per
//! call avoids unsafe Send impls while keeping the async executor happy.
//! Model weights stay in the OS page cache so re-opens are fast. For the
//! single-session pentest use-case this cost is negligible.

#[cfg(feature = "embedded-llm")]
mod inner {
    use async_trait::async_trait;
    use llama_cpp_2::{
        context::params::LlamaContextParams,
        llama_backend::LlamaBackend,
        llama_batch::LlamaBatch,
        model::{
            params::LlamaModelParams, AddBos, LlamaChatMessage, LlamaModel,
        },
        sampling::LlamaSampler,
    };
    use std::num::NonZeroU32;
    use std::path::{Path, PathBuf};
    use tokio::sync::mpsc;
    use tracing::{debug, warn};

    use crate::provider::ChunkStream;
    use crate::types::{ChatRequest, ChatResponse, FunctionCall, StreamChunk, ToolCall};
    use sigint_core::config::LlmConfig;
    use sigint_core::Error;

    // ── Config constants ──────────────────────────────────────────────────────

    /// Default context window in tokens when not specified in config.
    const DEFAULT_CONTEXT_WINDOW: u32 = 4096;

    /// Default batch size for the decode loop.
    const DEFAULT_BATCH_SIZE: u32 = 512;

    /// Channel buffer depth for streaming token pieces.
    const STREAM_CHANNEL_CAPACITY: usize = 256;

    // ── EmbeddedProvider ─────────────────────────────────────────────────────

    /// In-process LLM provider backed by a GGUF model file.
    ///
    /// Loaded via `EmbeddedProvider::load()` which resolves the model from
    /// `LlmConfig::models_dir` / `LlmConfig::model`. The model file is
    /// validated at construction time but weights are loaded lazily on the
    /// first inference call inside `spawn_blocking`.
    #[derive(Debug)]
    pub struct EmbeddedProvider {
        /// Resolved absolute path to the GGUF model file.
        pub(crate) model_path: PathBuf,
        /// Human-readable model name for logging / display.
        pub(crate) model_name: String,
        /// Context window in tokens.
        pub(crate) context_window: u32,
        /// Sampling temperature.
        pub(crate) temperature: f32,
        /// Number of layers to offload to GPU. 0 = CPU-only.
        pub(crate) gpu_layers: u32,
        /// Number of CPU threads (0 = auto-detect).
        pub(crate) threads: u32,
        /// Enable flash attention.
        pub(crate) flash_attention: bool,
    }

    impl EmbeddedProvider {
        /// Load an `EmbeddedProvider` from the model path described in `config`.
        ///
        /// Resolves the model file as:
        ///   `resolved_models_dir / config.model`
        ///
        /// If that path does not exist, also tries appending `.gguf`.
        ///
        /// # Errors
        /// Returns `Error::Config` if the model file cannot be found.
        pub fn load(config: &LlmConfig) -> Result<Self, Error> {
            let models_dir = resolve_models_dir(config);
            let model_path = find_model_file(&models_dir, &config.model)?;

            let context_window = if config.context_window == 0 {
                DEFAULT_CONTEXT_WINDOW
            } else {
                config.context_window as u32
            };

            let gpu_layers = config.gpu_layers.unwrap_or(0) as u32;
            let threads = config.threads.unwrap_or(0);
            let flash_attention = config.flash_attention.unwrap_or(false);

            Ok(EmbeddedProvider {
                model_path,
                model_name: config.model.clone(),
                context_window,
                temperature: config.temperature,
                gpu_layers,
                threads,
                flash_attention,
            })
        }
    }

    #[async_trait]
    impl crate::provider::LlmProvider for EmbeddedProvider {
        fn name(&self) -> &str {
            "embedded"
        }

        /// Run a blocking (non-streaming) inference request.
        ///
        /// The actual inference happens inside `spawn_blocking` so the async
        /// executor is never blocked.
        async fn chat(&self, request: ChatRequest) -> Result<ChatResponse, Error> {
            let model_path = self.model_path.clone();
            let model_name = self.model_name.clone();
            let context_window = self.context_window;
            let temperature = self.temperature;
            let gpu_layers = self.gpu_layers;
            let threads = self.threads;
            let flash_attention = self.flash_attention;

            tokio::task::spawn_blocking(move || {
                run_inference(
                    &model_path,
                    &model_name,
                    context_window,
                    temperature,
                    gpu_layers,
                    threads,
                    flash_attention,
                    request,
                )
            })
            .await
            .map_err(|e| Error::Llm(format!("spawn_blocking join error: {}", e)))?
        }

        /// Run a streaming inference request.
        ///
        /// Token pieces are sent over an mpsc channel from the blocking
        /// thread and yielded as `StreamChunk` items by the async side.
        async fn chat_stream(&self, request: ChatRequest) -> Result<ChunkStream, Error> {
            let model_path = self.model_path.clone();
            let model_name = self.model_name.clone();
            let context_window = self.context_window;
            let temperature = self.temperature;
            let gpu_layers = self.gpu_layers;
            let threads = self.threads;
            let flash_attention = self.flash_attention;

            let (tx, mut rx) =
                mpsc::channel::<Result<StreamChunk, Error>>(STREAM_CHANNEL_CAPACITY);

            tokio::task::spawn_blocking(move || {
                run_inference_streaming(
                    &model_path,
                    &model_name,
                    context_window,
                    temperature,
                    gpu_layers,
                    threads,
                    flash_attention,
                    request,
                    tx,
                );
            });

            let stream = async_stream::stream! {
                while let Some(chunk) = rx.recv().await {
                    let done = chunk.as_ref().map(|c| c.done).unwrap_or(false);
                    yield chunk;
                    if done {
                        break;
                    }
                }
            };

            Ok(Box::pin(stream))
        }
    }

    // ── Inference implementation ──────────────────────────────────────────────

    /// Full non-streaming inference: returns a complete `ChatResponse`.
    #[allow(clippy::too_many_arguments)]
    fn run_inference(
        model_path: &PathBuf,
        model_name: &str,
        context_window: u32,
        temperature: f32,
        gpu_layers: u32,
        threads: u32,
        flash_attention: bool,
        request: ChatRequest,
    ) -> Result<ChatResponse, Error> {
        let mut content = String::new();
        let (_, tool_calls) = run_generation_streaming(
            model_path,
            context_window,
            temperature,
            gpu_layers,
            threads,
            flash_attention,
            &request,
            |piece| content.push_str(piece),
        )?;

        Ok(ChatResponse {
            content,
            usage: None,
            model: model_name.to_owned(),
            tool_calls,
        })
    }

    /// Streaming inference: sends `StreamChunk` items over `tx` as they are produced.
    #[allow(clippy::too_many_arguments)]
    fn run_inference_streaming(
        model_path: &PathBuf,
        _model_name: &str,
        context_window: u32,
        temperature: f32,
        gpu_layers: u32,
        threads: u32,
        flash_attention: bool,
        request: ChatRequest,
        tx: mpsc::Sender<Result<StreamChunk, Error>>,
    ) {
        let send = |chunk: Result<StreamChunk, Error>| {
            // best-effort: if receiver dropped, we continue (and discard)
            let _ = tx.blocking_send(chunk);
        };

        match run_generation_streaming(
            model_path,
            context_window,
            temperature,
            gpu_layers,
            threads,
            flash_attention,
            &request,
            |piece: &str| {
                send(Ok(StreamChunk {
                    delta: piece.to_owned(),
                    done: false,
                    usage: None,
                    tool_calls: vec![],
                }));
            },
        ) {
            Ok((_full_output, tool_calls)) => {
                // Final chunk — marks end-of-stream and carries tool calls
                send(Ok(StreamChunk {
                    delta: String::new(),
                    done: true,
                    usage: None,
                    tool_calls,
                }));
            }
            Err(e) => {
                send(Err(e));
            }
        }
    }

    // ── Core generation loop ──────────────────────────────────────────────────

    /// Core generation loop shared by streaming and non-streaming paths.
    ///
    /// Calls `on_token` for each decoded token piece as it is produced.
    /// Returns `(accumulated_output, tool_calls)` on success.
    ///
    /// This function:
    /// 1. Initialises the llama.cpp backend (idempotent)
    /// 2. Loads the model and creates an inference context
    /// 3. Formats the chat prompt via the model's built-in template
    /// 4. Tokenises the prompt and runs the prefill decode
    /// 5. Samples tokens one-at-a-time until EOS or context overflow
    /// 6. Parses tool calls from the output when tools were provided
    #[allow(clippy::too_many_arguments)]
    fn run_generation_streaming<F>(
        model_path: &PathBuf,
        context_window: u32,
        temperature: f32,
        gpu_layers: u32,
        threads: u32,
        flash_attention: bool,
        request: &ChatRequest,
        mut on_token: F,
    ) -> Result<(String, Vec<ToolCall>), Error>
    where
        F: FnMut(&str),
    {
        // 1. Initialise the llama.cpp backend (idempotent across calls).
        let backend = match LlamaBackend::init() {
            Ok(b) => b,
            Err(llama_cpp_2::LlamaCppError::BackendAlreadyInitialized) => {
                // Already initialised in this process — idempotent, safe to ignore.
                // The backend static state is still available; init() failure here
                // just means we raced with another call. Try once more.
                LlamaBackend::init()
                    .map_err(|e| Error::Llm(format!("llama backend init: {}", e)))?
            }
            Err(e) => return Err(Error::Llm(format!("llama backend init: {}", e))),
        };

        // 2. Load the model.
        let model_params =
            std::pin::pin!(LlamaModelParams::default().with_n_gpu_layers(gpu_layers));
        let model = LlamaModel::load_from_file(&backend, model_path, &model_params)
            .map_err(|e| Error::Llm(format!("Failed to load model {:?}: {}", model_path, e)))?;

        // 3. Create inference context.
        let n_ctx = NonZeroU32::new(context_window)
            .unwrap_or_else(|| NonZeroU32::new(DEFAULT_CONTEXT_WINDOW).unwrap());
        let mut ctx_params = LlamaContextParams::default()
            .with_n_ctx(Some(n_ctx))
            .with_n_batch(DEFAULT_BATCH_SIZE);
        if threads > 0 {
            ctx_params = ctx_params.with_n_threads(threads as i32);
            ctx_params = ctx_params.with_n_threads_batch(threads as i32);
        }
        if flash_attention {
            ctx_params = ctx_params.with_flash_attention_policy(1);
        }
        let mut ctx = model
            .new_context(&backend, ctx_params)
            .map_err(|e| Error::Llm(format!("Failed to create llama context: {}", e)))?;

        // 4. Format the prompt using the model's built-in chat template.
        //    Use tools-aware template when tools are provided; fall back to plain template.
        let chat_messages: Vec<LlamaChatMessage> = request
            .messages
            .iter()
            .map(|m| {
                LlamaChatMessage::new(m.role.clone(), m.content.clone())
                    .expect("message role/content should not contain null bytes")
            })
            .collect();

        let tmpl = model
            .chat_template(None)
            .map_err(|e| Error::Llm(format!("chat_template: {}", e)))?;

        let (prompt, template_result) = if !request.tools.is_empty() {
            let tools_json = serde_json::to_string(&request.tools)
                .map_err(|e| Error::Llm(format!("serialize tools: {}", e)))?;
            let result = model
                .apply_chat_template_with_tools_oaicompat(
                    &tmpl,
                    &chat_messages,
                    Some(&tools_json),
                    None, // no extra JSON schema constraint
                    true, // add_generation_prompt
                )
                .map_err(|e| {
                    Error::Llm(format!("apply_chat_template_with_tools: {}", e))
                })?;
            let p = result.prompt.clone();
            debug!(
                "embedded: tools-aware template, parse_tool_calls={}",
                result.parse_tool_calls
            );
            (p, Some(result))
        } else {
            let p = model
                .apply_chat_template(&tmpl, &chat_messages, true)
                .map_err(|e| Error::Llm(format!("apply_chat_template: {}", e)))?;
            (p, None)
        };

        debug!("embedded: prompt length {} chars", prompt.len());

        // 5. Tokenise the prompt.
        let tokens = model
            .str_to_token(&prompt, AddBos::Always)
            .map_err(|e| Error::Llm(format!("tokenise: {}", e)))?;

        let n_prompt = tokens.len();
        let max_new_tokens = (context_window as usize).saturating_sub(n_prompt);
        if max_new_tokens == 0 {
            return Err(Error::Llm(format!(
                "Prompt ({} tokens) fills the context window ({}). \
                 Reduce input or increase llm.context_window in config.",
                n_prompt, context_window
            )));
        }

        // 6. Prefill batch — add all prompt tokens, request logits only for the last.
        let mut batch = LlamaBatch::new(DEFAULT_BATCH_SIZE as usize, 1);
        let last_idx = tokens.len() - 1;
        for (i, &token) in tokens.iter().enumerate() {
            batch
                .add(token, i as i32, &[0], i == last_idx)
                .map_err(|e| Error::Llm(format!("batch add (prefill): {}", e)))?;
        }
        ctx.decode(&mut batch)
            .map_err(|e| Error::Llm(format!("decode (prefill): {}", e)))?;

        // 7. Sample loop — one token at a time until EOS or context limit.
        let mut sampler = LlamaSampler::chain_simple([
            LlamaSampler::temp(temperature),
            LlamaSampler::top_p(0.95, 1),
            LlamaSampler::min_p(0.05, 1),
            LlamaSampler::dist(42),
        ]);

        let extra_stops: Vec<String> = template_result
            .as_ref()
            .map(|r| r.additional_stops.clone())
            .unwrap_or_default();

        // Stateful UTF-8 decoder — reused across token pieces for correct
        // multi-byte character reconstruction at token boundaries.
        let mut decoder = encoding_rs::UTF_8.new_decoder();

        let mut output = String::new();
        let mut n_cur = tokens.len() as i32;

        for _ in 0..max_new_tokens {
            let token = sampler.sample(&ctx, batch.n_tokens() - 1);

            if model.is_eog_token(token) {
                break;
            }

            let piece = model
                .token_to_piece(token, &mut decoder, true, None)
                .unwrap_or_default();

            output.push_str(&piece);

            // Check template-provided stop sequences (e.g. "<|eot_id|>").
            if let Some(stop) = extra_stops.iter().find(|s| output.ends_with(s.as_str())) {
                let trim_len = output.len() - stop.len();
                output.truncate(trim_len);
                break;
            }

            on_token(&piece);
            sampler.accept(token);

            batch.clear();
            batch
                .add(token, n_cur, &[0], true)
                .map_err(|e| Error::Llm(format!("batch add (generation): {}", e)))?;
            ctx.decode(&mut batch)
                .map_err(|e| Error::Llm(format!("decode (generation): {}", e)))?;
            n_cur += 1;
        }

        // 8. Parse tool calls when the template flagged the output for parsing.
        let tool_calls = match template_result.as_ref() {
            Some(r) if r.parse_tool_calls => parse_tool_calls(r, &output),
            _ => vec![],
        };

        Ok((output, tool_calls))
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /// Resolve the models directory from config, expanding `~/` prefixes.
    fn resolve_models_dir(config: &LlmConfig) -> PathBuf {
        let raw = config
            .models_dir
            .as_deref()
            .unwrap_or("~/.local/share/sigint/models");

        if let Some(rest) = raw.strip_prefix("~/") {
            if let Ok(home) = std::env::var("HOME") {
                return PathBuf::from(home).join(rest);
            }
        }
        PathBuf::from(raw)
    }

    /// Find a model file in `models_dir` given the configured model name.
    ///
    /// Tries the name as-is first, then appends `.gguf` if the name has no
    /// `.gguf` suffix and the direct path does not exist.
    fn find_model_file(models_dir: &Path, model_name: &str) -> Result<PathBuf, Error> {
        let direct = models_dir.join(model_name);
        if direct.exists() {
            return Ok(direct);
        }

        if !model_name.ends_with(".gguf") {
            let with_ext = models_dir.join(format!("{}.gguf", model_name));
            if with_ext.exists() {
                return Ok(with_ext);
            }
        }

        Err(Error::Config(format!(
            "Embedded LLM model not found: {:?}. \
             Also tried with .gguf extension. \
             Place a GGUF file there or set llm.models_dir in config.",
            direct
        )))
    }

    /// Parse tool calls from model output via `ChatTemplateResult::parse_response_oaicompat`.
    ///
    /// Returns an empty vec on any parse failure (logged as a warning).
    fn parse_tool_calls(
        tmpl_result: &llama_cpp_2::model::ChatTemplateResult,
        output: &str,
    ) -> Vec<ToolCall> {
        match tmpl_result.parse_response_oaicompat(output, false) {
            Ok(json_str) => extract_tool_calls_from_oaicompat_json(&json_str),
            Err(e) => {
                warn!("embedded: tool call parse failed: {}", e);
                vec![]
            }
        }
    }

    /// Extract `tool_calls` from an OpenAI-compatible message JSON string.
    ///
    /// The JSON looks like:
    /// ```json
    /// {"role":"assistant","content":null,"tool_calls":[
    ///   {"id":"...","type":"function","function":{"name":"...","arguments":"{...}"}}
    /// ]}
    /// ```
    ///
    /// `arguments` may be a JSON-encoded string or an inline object depending
    /// on the model; both are handled.
    fn extract_tool_calls_from_oaicompat_json(json_str: &str) -> Vec<ToolCall> {
        let val: serde_json::Value = match serde_json::from_str(json_str) {
            Ok(v) => v,
            Err(e) => {
                warn!("embedded: failed to parse oaicompat JSON: {}", e);
                return vec![];
            }
        };

        let tool_calls_arr = match val.get("tool_calls").and_then(|v| v.as_array()) {
            Some(arr) => arr,
            None => return vec![],
        };

        let mut result = Vec::new();
        for tc in tool_calls_arr {
            let func = match tc.get("function") {
                Some(f) => f,
                None => continue,
            };
            let name = match func.get("name").and_then(|v| v.as_str()) {
                Some(n) => n.to_owned(),
                None => continue,
            };
            // `arguments` may be a serialised JSON string or an inline object.
            let arguments = match func.get("arguments") {
                Some(serde_json::Value::String(s)) => serde_json::from_str(s)
                    .unwrap_or(serde_json::Value::Object(serde_json::Map::new())),
                Some(v) => v.clone(),
                None => serde_json::Value::Object(serde_json::Map::new()),
            };
            result.push(ToolCall {
                function: FunctionCall { name, arguments },
            });
        }
        result
    }
}

// ── Public re-exports (only with feature) ────────────────────────────────────

#[cfg(feature = "embedded-llm")]
pub use inner::EmbeddedProvider;

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "embedded-llm"))]
mod tests {
    use super::inner::EmbeddedProvider;
    use crate::provider::LlmProvider;
    use sigint_core::config::LlmConfig;

    fn make_config(model: &str, models_dir: Option<String>) -> LlmConfig {
        LlmConfig {
            provider: "embedded".into(),
            model: model.into(),
            base_url: "".into(),
            temperature: 0.7,
            context_window: 0,
            api_key: None,
            models_dir,
            gpu_layers: None,
            threads: None,
            flash_attention: None,
        }
    }

    /// `load()` should fail with a clear message when the model file does not exist.
    #[test]
    fn load_fails_when_model_missing() {
        let cfg = make_config(
            "nonexistent-model",
            Some("/tmp/no-such-models-dir".into()),
        );
        let result = EmbeddedProvider::load(&cfg);
        assert!(result.is_err(), "Expected Err when model file is absent");
        let msg = result.unwrap_err().to_string();
        assert!(
            msg.contains("not found") || msg.contains("nonexistent-model"),
            "Error should mention the missing model: {msg}"
        );
    }

    /// `load()` with a `.gguf` extension already present should not double-append.
    #[test]
    fn load_fails_with_descriptive_path_when_gguf_extension_given() {
        let cfg = make_config(
            "mymodel.gguf",
            Some("/tmp/no-such-models-dir".into()),
        );
        let result = EmbeddedProvider::load(&cfg);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        // Should mention the configured model path, not "mymodel.gguf.gguf"
        assert!(
            msg.contains("mymodel.gguf") && !msg.contains("mymodel.gguf.gguf"),
            "Path in error should not double-append .gguf: {msg}"
        );
    }

    /// `load()` should succeed when a GGUF file exists at the resolved path.
    #[test]
    fn load_succeeds_when_model_exists() {
        use std::io::Write;
        let dir = tempfile::tempdir().expect("tempdir");
        let model_path = dir.path().join("test.gguf");
        std::fs::File::create(&model_path)
            .expect("create")
            .write_all(b"placeholder")
            .unwrap();

        let cfg = make_config(
            "test.gguf",
            Some(dir.path().to_string_lossy().into_owned()),
        );
        let result = EmbeddedProvider::load(&cfg);
        assert!(result.is_ok(), "Expected Ok when model file exists: {:?}", result);
    }

    /// `load()` should find a model by appending `.gguf` automatically.
    #[test]
    fn load_auto_appends_gguf_extension() {
        use std::io::Write;
        let dir = tempfile::tempdir().expect("tempdir");
        let model_path = dir.path().join("mymodel.gguf");
        std::fs::File::create(&model_path)
            .expect("create")
            .write_all(b"placeholder")
            .unwrap();

        let cfg = make_config(
            "mymodel",
            Some(dir.path().to_string_lossy().into_owned()),
        );
        let result = EmbeddedProvider::load(&cfg);
        assert!(
            result.is_ok(),
            "Expected Ok when model file exists with .gguf suffix: {:?}",
            result
        );
    }

    /// Provider name must be "embedded".
    #[test]
    fn provider_name_is_embedded() {
        use std::io::Write;
        let dir = tempfile::tempdir().expect("tempdir");
        let model_path = dir.path().join("test.gguf");
        std::fs::File::create(&model_path)
            .unwrap()
            .write_all(b"x")
            .unwrap();
        let cfg = make_config(
            "test.gguf",
            Some(dir.path().to_string_lossy().into_owned()),
        );
        let provider = EmbeddedProvider::load(&cfg).unwrap();
        assert_eq!(provider.name(), "embedded");
    }

    /// Context window defaults to 4096 when config specifies 0.
    #[test]
    fn context_window_defaults_to_4096() {
        use std::io::Write;
        let dir = tempfile::tempdir().expect("tempdir");
        let model_path = dir.path().join("test.gguf");
        std::fs::File::create(&model_path)
            .unwrap()
            .write_all(b"x")
            .unwrap();
        let mut cfg = make_config(
            "test.gguf",
            Some(dir.path().to_string_lossy().into_owned()),
        );
        cfg.context_window = 0;
        let provider = EmbeddedProvider::load(&cfg).unwrap();
        assert_eq!(provider.context_window, 4096);
    }

    /// Context window is taken from config when non-zero.
    #[test]
    fn context_window_from_config() {
        use std::io::Write;
        let dir = tempfile::tempdir().expect("tempdir");
        let model_path = dir.path().join("test.gguf");
        std::fs::File::create(&model_path)
            .unwrap()
            .write_all(b"x")
            .unwrap();
        let mut cfg = make_config(
            "test.gguf",
            Some(dir.path().to_string_lossy().into_owned()),
        );
        cfg.context_window = 8192;
        let provider = EmbeddedProvider::load(&cfg).unwrap();
        assert_eq!(provider.context_window, 8192);
    }
}
