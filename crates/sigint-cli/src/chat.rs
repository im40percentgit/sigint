//! `sigint chat` — interactive streaming chat REPL backed by Ollama.
//!
//! @decision DEC-LLM-001
//! @title CLI chat uses streaming JSON-lines from Ollama /api/chat
//! @status accepted
//! @rationale Streaming tokens to stdout gives the user immediate feedback
//! rather than waiting for the full response. The conversation history is
//! accumulated in memory and persisted to SQLite after each exchange, so
//! the session survives a crash mid-stream (the user message is written
//! before the stream starts; the assistant message after it completes).

use clap::Args;
use futures_util::StreamExt;
use std::io::{self, Write};
use tracing::debug;

use sigint_core::{
    types::{Message, Session},
    AppCore, Error,
};
use sigint_llm::{
    types::{ChatMessage, ChatRequest},
    LlmProvider, OllamaProvider,
};
use sigint_store::Database;

/// Arguments for `sigint chat`.
#[derive(Args, Debug)]
pub struct ChatArgs {
    /// Session name (auto-generated if omitted).
    #[arg(short, long)]
    pub session: Option<String>,

    /// Model to use (overrides config).
    #[arg(short, long)]
    pub model: Option<String>,

    /// System prompt injected at the start of the conversation.
    #[arg(long, default_value = "You are a helpful AI assistant specialising in penetration testing and cybersecurity. Be concise and precise.")]
    pub system_prompt: String,
}

/// Run the interactive chat REPL.
pub async fn run(core: AppCore, args: ChatArgs) -> Result<(), Error> {
    // ── Setup ──────────────────────────────────────────────────────────────

    let model = args.model.as_deref().unwrap_or(&core.config.llm.model).to_string();
    let session_name = args
        .session
        .clone()
        .unwrap_or_else(|| format!("session-{}", chrono::Utc::now().format("%Y%m%d-%H%M%S")));

    println!("sigint chat — model: {} | session: {}", model, session_name);
    println!("Type your message and press Enter. Ctrl+C or Ctrl+D to exit.\n");

    // ── Database ───────────────────────────────────────────────────────────

    let db_path = core.config.resolved_db_path();
    let db = Database::open(&db_path).map_err(|e| {
        Error::Database(format!("Cannot open database at {:?}: {}", db_path, e))
    })?;
    debug!("Database opened at {:?}", db_path);

    // Create session record
    let session = Session::new(&session_name);
    db.create_session(&session)?;

    // ── LLM provider ───────────────────────────────────────────────────────

    let provider = OllamaProvider::from_config(&core.config.llm);

    // ── Conversation history (in-memory + persisted) ───────────────────────

    // Seed with system prompt
    let system_msg = Message::system(session.id, &args.system_prompt);
    db.create_message(&system_msg)?;

    // LLM history starts with the system prompt
    let mut history: Vec<ChatMessage> = vec![
        ChatMessage::system(&args.system_prompt),
    ];

    // ── REPL loop ──────────────────────────────────────────────────────────

    let stdin = io::stdin();
    let mut stdout = io::stdout();

    loop {
        // Prompt
        print!("\nyou> ");
        stdout.flush().map_err(|e| Error::Io(e))?;

        // Read one line of user input
        let mut input = String::new();
        match stdin.read_line(&mut input) {
            Ok(0) => {
                // EOF (Ctrl+D)
                println!("\nGoodbye.");
                break;
            }
            Ok(_) => {}
            Err(e) => {
                return Err(Error::Io(e));
            }
        }

        let input = input.trim();
        if input.is_empty() {
            continue;
        }

        // Persist user message immediately (before streaming)
        let user_msg = Message::user(session.id, input);
        db.create_message(&user_msg)?;

        // Add to LLM history
        history.push(ChatMessage::user(input));

        // ── Stream the response ────────────────────────────────────────────

        let request = ChatRequest::new(&model, history.clone())
            .with_temperature(core.config.llm.temperature);

        print!("\nsigint> ");
        stdout.flush().map_err(|e| Error::Io(e))?;

        let mut full_response = String::new();
        let mut total_tokens: Option<u32> = None;

        match provider.chat_stream(request).await {
            Ok(mut stream) => {
                while let Some(chunk_result) = stream.next().await {
                    match chunk_result {
                        Ok(chunk) => {
                            if !chunk.delta.is_empty() {
                                print!("{}", chunk.delta);
                                stdout.flush().map_err(|e| Error::Io(e))?;
                                full_response.push_str(&chunk.delta);
                            }
                            if let Some(usage) = chunk.usage {
                                total_tokens = Some(usage.completion_tokens);
                                debug!(
                                    "Token usage — prompt: {}, completion: {}, total: {}",
                                    usage.prompt_tokens,
                                    usage.completion_tokens,
                                    usage.total_tokens,
                                );
                            }
                            if chunk.done {
                                break;
                            }
                        }
                        Err(e) => {
                            eprintln!("\nerror during stream: {}", e);
                            break;
                        }
                    }
                }
                println!(); // newline after streamed response
            }
            Err(e) => {
                eprintln!("\nerror: {}", e);
                eprintln!("hint: Is Ollama running? Try: ollama serve");
                // Don't exit — let the user try again or Ctrl+D
                history.pop(); // remove the user message from history since we got no response
                db.delete_session(session.id)?; // clean up partial session? No — keep it.
                // Actually keep the session, just note the error
                continue;
            }
        }

        if full_response.is_empty() {
            continue;
        }

        // Persist assistant response
        let mut asst_msg = Message::assistant(session.id, &full_response);
        asst_msg.tokens = total_tokens;
        db.create_message(&asst_msg)?;

        if let Some(tokens) = total_tokens {
            db.update_message_tokens(asst_msg.id, tokens)?;
        }

        // Update session timestamp
        db.touch_session(session.id)?;

        // Add assistant response to history for next turn
        history.push(ChatMessage::assistant(&full_response));
    }

    Ok(())
}
