//! InteractiveSession — bridges TUI input events to the Orchestrator pipeline.
//!
//! Subscribes to the EventBus, listens for `Event::UserInput`, parses the
//! input as a command, and dispatches accordingly. Runs as a long-lived
//! tokio task alongside the TUI event loop.
//!
//! Command syntax (first word dispatch):
//! - `scan <target>` — run the full five-agent pipeline against `<target>`
//! - `help`          — emit available commands as a Status event
//! - anything else   — emit an "unknown command" Status event
//!
//! @decision DEC-AGENT-018
//! @title InteractiveSession as EventBus consumer for TUI input routing
//! @status accepted
//! @rationale The Orchestrator stays unchanged — run_scan() still takes a
//! target string. InteractiveSession is the bridge between the event-driven
//! TUI world and the Orchestrator's imperative API. Extracting `parse_command`
//! as a pure free function makes the command parsing logic unit-testable
//! without requiring a live Orchestrator or LLM provider.

use tokio::sync::broadcast;
use tracing::warn;

use sigint_core::event::{Event, EventBus};
use sigint_core::Error;

use crate::Orchestrator;

// ── Command ───────────────────────────────────────────────────────────────────

/// A parsed user command.
///
/// Returned by [`parse_command`] so that command dispatch logic can be tested
/// independently of the `InteractiveSession` event loop.
#[derive(Debug, PartialEq)]
pub enum Command {
    /// Run a full scan pipeline against the given target.
    Scan(String),
    /// Resume a prior session by session-ID prefix.
    Resume(String),
    /// List resumable sessions (bare "resume" with no argument).
    ResumeList,
    /// Display available commands.
    Help,
    /// Input was not a recognised command.
    Unknown(String),
}

/// Parse a raw user input string into a [`Command`].
///
/// Leading and trailing whitespace is trimmed before matching. The `scan`
/// prefix is case-sensitive. An empty scan target (`"scan "` with no target
/// after the prefix) is treated as `Unknown` so the caller can emit a usage
/// hint rather than attempting a zero-length scan.
///
/// # Examples
/// ```
/// use sigint_agents::interactive::{parse_command, Command};
/// assert_eq!(parse_command("scan example.com"), Command::Scan("example.com".into()));
/// assert_eq!(parse_command("help"), Command::Help);
/// assert!(matches!(parse_command("foo"), Command::Unknown(_)));
/// ```
pub fn parse_command(input: &str) -> Command {
    let input = input.trim();
    if let Some(rest) = input.strip_prefix("scan ") {
        let target = rest.trim();
        if target.is_empty() {
            Command::Unknown("scan requires a target".into())
        } else {
            Command::Scan(target.to_string())
        }
    } else if input == "resume" {
        Command::ResumeList
    } else if let Some(prefix) = input.strip_prefix("resume ") {
        let prefix = prefix.trim();
        if prefix.is_empty() {
            Command::ResumeList
        } else {
            Command::Resume(prefix.to_string())
        }
    } else if input == "help" {
        Command::Help
    } else {
        Command::Unknown(input.to_string())
    }
}

// ── InteractiveSession ────────────────────────────────────────────────────────

/// Bridges TUI/Web input events to the Orchestrator scan pipeline.
///
/// Owns one `Orchestrator` instance and drives `run_scan` in response to
/// `Event::UserInput` events received from the `EventBus`. Results and status
/// messages are emitted back onto the bus so the TUI can display them without
/// any direct coupling to this struct.
///
/// Spawn via `tokio::spawn(session.run())` alongside the TUI event loop.
/// The session exits cleanly when `Event::Shutdown` is received or the
/// broadcast channel closes.
pub struct InteractiveSession {
    orchestrator: Orchestrator,
    event_rx: broadcast::Receiver<Event>,
    event_bus: EventBus,
}

impl InteractiveSession {
    /// Create a new `InteractiveSession`.
    ///
    /// # Arguments
    /// * `orchestrator` — A ready-to-use Orchestrator (owns the LLM provider,
    ///   tool registry, and event bus reference for tool-level events).
    /// * `event_rx`     — Broadcast receiver for the same bus that the TUI
    ///   writes `UserInput` events onto.
    /// * `event_bus`    — Bus handle for emitting Status and result events back
    ///   to the TUI.
    pub fn new(
        orchestrator: Orchestrator,
        event_rx: broadcast::Receiver<Event>,
        event_bus: EventBus,
    ) -> Self {
        Self {
            orchestrator,
            event_rx,
            event_bus,
        }
    }

    /// Run the session event loop.
    ///
    /// Blocks until `Event::Shutdown` is received or the broadcast channel
    /// closes. Returns `Ok(())` in both cases — shutdown is not an error.
    ///
    /// # Errors
    /// This function does not return an error under normal operation. The
    /// `Result` return type reserves the capability for callers that want to
    /// propagate internal scan errors in the future.
    pub async fn run(mut self) -> Result<(), Error> {
        loop {
            match self.event_rx.recv().await {
                Ok(Event::UserInput {
                    session_id: _,
                    text,
                }) => {
                    self.handle_input(&text).await;
                }
                Ok(Event::Shutdown) => break,
                Ok(_) => continue,
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!("interactive session: lagged {n} events");
                }
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
        Ok(())
    }

    /// Dispatch a single user input string to the appropriate handler.
    async fn handle_input(&self, text: &str) {
        match parse_command(text) {
            Command::Scan(target) => {
                self.event_bus
                    .emit(Event::Status(format!("Starting scan of {target}...")));
                match self.orchestrator.run_scan(&target).await {
                    Ok(report) => {
                        self.event_bus
                            .emit(Event::Status(format!("Scan of {target} complete.")));
                        self.event_bus.emit(Event::Status(report.summary.clone()));
                    }
                    Err(e) => {
                        self.event_bus
                            .emit(Event::Status(format!("Scan failed: {e}")));
                    }
                }
            }
            Command::ResumeList => {
                let _ = self.event_bus.emit(Event::Status(
                    "Use 'resume <session-prefix>' to resume a prior scan. Use CLI 'sigint sessions list' to see sessions.".into()
                ));
            }
            Command::Resume(prefix) => {
                let _ = self.event_bus.emit(Event::Status(
                    format!("Resume not yet wired in TUI. Use CLI: sigint resume {prefix}")
                ));
            }
            Command::Help => {
                self.event_bus.emit(Event::Status(
                    "Available commands: scan <target>, resume [prefix], help".to_string(),
                ));
            }
            Command::Unknown(ref raw) if raw.is_empty() => {
                // Silently ignore empty input — user just pressed Enter.
            }
            Command::Unknown(raw) => {
                self.event_bus.emit(Event::Status(format!(
                    "Unknown command: '{raw}'. Type 'help' for available commands."
                )));
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── parse_command ─────────────────────────────────────────────────────────

    #[test]
    fn parse_scan_command() {
        assert_eq!(
            parse_command("scan example.com"),
            Command::Scan("example.com".into())
        );
    }

    #[test]
    fn parse_scan_with_leading_whitespace() {
        assert_eq!(
            parse_command("  scan example.com"),
            Command::Scan("example.com".into())
        );
    }

    #[test]
    fn parse_scan_with_extra_spaces_around_target() {
        assert_eq!(
            parse_command("scan   example.com  "),
            Command::Scan("example.com".into())
        );
    }

    #[test]
    fn parse_scan_ip_target() {
        assert_eq!(
            parse_command("scan 192.168.1.0/24"),
            Command::Scan("192.168.1.0/24".into())
        );
    }

    #[test]
    fn parse_help() {
        assert_eq!(parse_command("help"), Command::Help);
    }

    #[test]
    fn parse_help_with_surrounding_whitespace() {
        assert_eq!(parse_command("  help  "), Command::Help);
    }

    #[test]
    fn parse_unknown_command() {
        assert!(matches!(parse_command("foobar"), Command::Unknown(_)));
    }

    #[test]
    fn parse_empty_input_is_unknown() {
        assert!(matches!(parse_command(""), Command::Unknown(_)));
    }

    #[test]
    fn parse_whitespace_only_is_unknown() {
        assert!(matches!(parse_command("   "), Command::Unknown(_)));
    }

    #[test]
    fn parse_empty_scan_target_is_unknown() {
        assert!(matches!(parse_command("scan "), Command::Unknown(_)));
    }

    #[test]
    fn parse_scan_only_no_space_is_unknown() {
        // "scan" without a trailing space + target — treated as unknown command
        assert!(matches!(parse_command("scan"), Command::Unknown(_)));
    }

    #[test]
    fn parse_scan_preserves_target_with_port() {
        assert_eq!(
            parse_command("scan target.local:8080"),
            Command::Scan("target.local:8080".into())
        );
    }

    #[test]
    fn unknown_variant_captures_raw_text() {
        match parse_command("recon target.com") {
            Command::Unknown(raw) => assert_eq!(raw, "recon target.com"),
            other => panic!("expected Unknown, got {other:?}"),
        }
    }

    // ── InteractiveSession event loop ─────────────────────────────────────────

    /// Verify that the session loop exits cleanly when Shutdown is received.
    /// We cannot construct a real Orchestrator in unit tests (needs LLM provider),
    /// so we use the test helper to build a no-op one.
    #[tokio::test]
    async fn shutdown_event_exits_loop() {
        use crate::ToolRegistry;
        use async_trait::async_trait;
        use futures_util::stream;
        use sigint_core::event::EventBus;
        use sigint_llm::{
            provider::{ChunkStream, LlmProvider},
            types::{ChatRequest, ChatResponse, StreamChunk},
        };
        use std::sync::Arc;

        struct NoopProvider;

        #[async_trait]
        impl LlmProvider for NoopProvider {
            fn name(&self) -> &str {
                "noop"
            }
            async fn chat(&self, _: ChatRequest) -> Result<ChatResponse, Error> {
                Ok(ChatResponse {
                    content: "noop".into(),
                    usage: None,
                    model: "noop".into(),
                    tool_calls: vec![],
                })
            }
            async fn chat_stream(&self, _: ChatRequest) -> Result<ChunkStream, Error> {
                let chunks: Vec<Result<StreamChunk, Error>> = vec![Ok(StreamChunk {
                    delta: "noop".into(),
                    done: true,
                    usage: None,
                    tool_calls: vec![],
                })];
                Ok(Box::pin(stream::iter(chunks)))
            }
        }

        let bus = EventBus::new();
        let rx = bus.subscribe();
        let orch = Orchestrator::new(
            Arc::new(NoopProvider),
            ToolRegistry::new(),
            bus.clone(),
            8192,
            "noop-model".into(),
        );
        let session = InteractiveSession::new(orch, rx, bus.clone());

        // Send Shutdown before running — the session should exit immediately.
        bus.emit(Event::Shutdown);

        tokio::time::timeout(std::time::Duration::from_millis(200), session.run())
            .await
            .expect("session.run() should exit on Shutdown within 200ms")
            .expect("run() should return Ok(())");
    }

    #[test]
    fn parse_resume_command_with_prefix() {
        let cmd = parse_command("resume a1b2c3d4");
        assert!(matches!(cmd, Command::Resume(ref p) if p == "a1b2c3d4"));
    }

    #[test]
    fn parse_resume_without_args_is_list() {
        let cmd = parse_command("resume");
        assert!(matches!(cmd, Command::ResumeList));
    }

    #[test]
    fn parse_resume_with_whitespace() {
        let cmd = parse_command("  resume   abcd1234  ");
        assert!(matches!(cmd, Command::Resume(ref p) if p == "abcd1234"));
    }

    /// Verify that help command emits a Status event with the command list.
    #[tokio::test]
    async fn help_command_emits_status() {
        use crate::ToolRegistry;
        use async_trait::async_trait;
        use futures_util::stream;
        use sigint_core::event::EventBus;
        use sigint_llm::{
            provider::{ChunkStream, LlmProvider},
            types::{ChatRequest, ChatResponse, StreamChunk},
        };
        use std::sync::Arc;

        struct NoopProvider;

        #[async_trait]
        impl LlmProvider for NoopProvider {
            fn name(&self) -> &str {
                "noop"
            }
            async fn chat(&self, _: ChatRequest) -> Result<ChatResponse, Error> {
                Ok(ChatResponse {
                    content: "".into(),
                    usage: None,
                    model: "noop".into(),
                    tool_calls: vec![],
                })
            }
            async fn chat_stream(&self, _: ChatRequest) -> Result<ChunkStream, Error> {
                Ok(Box::pin(stream::iter(vec![Ok(StreamChunk {
                    delta: "".into(),
                    done: true,
                    usage: None,
                    tool_calls: vec![],
                })])))
            }
        }

        let bus = EventBus::new();
        let mut status_rx = bus.subscribe();
        let cmd_rx = bus.subscribe();

        let orch = Orchestrator::new(
            Arc::new(NoopProvider),
            ToolRegistry::new(),
            bus.clone(),
            8192,
            "noop".into(),
        );
        let session = InteractiveSession::new(orch, cmd_rx, bus.clone());

        // Send help then Shutdown
        bus.emit(Event::UserInput {
            session_id: uuid::Uuid::nil(),
            text: "help".into(),
        });
        bus.emit(Event::Shutdown);

        session.run().await.expect("run() should return Ok");

        // Drain events looking for a Status containing "help" info
        let mut found_help = false;
        loop {
            match status_rx.try_recv() {
                Ok(Event::Status(msg)) if msg.contains("scan") && msg.contains("help") => {
                    found_help = true;
                    break;
                }
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        assert!(
            found_help,
            "help command should emit a Status event listing commands"
        );
    }
}
