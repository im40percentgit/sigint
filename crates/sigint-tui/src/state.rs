//! TUI application state machine.
//!
//! `AppState` is the single source of truth for all TUI rendering.
//! It is mutated by `apply(Event)` — no terminal I/O touches this module,
//! making all logic unit-testable without a real terminal.
//!
//! @decision DEC-P3-TUI-001
//! @title AppState as pure event-driven state machine
//! @status accepted
//! @rationale Separating state from rendering (ui.rs) and I/O (app.rs) lets
//! every state transition be exercised by a simple unit test. The render
//! function is a pure function of AppState, tested with ratatui TestBackend.
//! This mirrors the Elm architecture and eliminates the need for mocking
//! terminal I/O in tests.

use std::collections::HashMap;
use std::time::Instant;

use sigint_core::event::Event;
use sigint_core::types::Finding;

/// Which panel currently has keyboard focus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Panel {
    Chat,
    ToolOutput,
    Findings,
    Input,
}

/// Current editor/navigation mode (vi-inspired).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// Default navigation mode.
    Normal,
    /// Incremental search active; inner String is the current query.
    Search(String),
    /// Command entry (`:q`, `:scan`, …); inner String is the buffer.
    Command(String),
}

/// A message displayed in the Chat panel.
#[derive(Debug, Clone)]
pub struct DisplayMessage {
    /// Role string: "user", "assistant", "system", "tool".
    pub role: String,
    pub content: String,
}

/// A single tool invocation entry in the Tool Output panel.
#[derive(Debug, Clone)]
pub struct ToolEntry {
    pub name: String,
    /// Serialised args (JSON value rendered to string for display).
    pub args: String,
    pub output: Option<String>,
    pub exit_code: Option<i32>,
    pub started: Instant,
    pub completed: Option<Instant>,
}

/// All mutable state owned by the TUI runtime.
pub struct AppState {
    /// Currently active agent name and when it started.
    pub active_agent: Option<(String, Instant)>,
    /// Tool-call iteration counter within the current agent turn.
    pub iteration: usize,
    /// Completed chat messages (flushed from streaming_buffer on StreamCompleted).
    pub messages: Vec<DisplayMessage>,
    /// Accumulator for in-progress LLM streaming output.
    pub streaming_buffer: String,
    /// Tool invocation log (append-only; entries are updated in place).
    pub tool_log: Vec<ToolEntry>,
    /// Security findings discovered during the scan.
    pub findings: Vec<Finding>,
    /// Panel that currently receives keyboard events.
    pub focused_panel: Panel,
    /// Per-panel scroll offset (lines scrolled up from bottom).
    pub scroll_offsets: HashMap<Panel, usize>,
    /// Per-panel auto-scroll flag; set to false when user scrolls up.
    pub auto_scroll: HashMap<Panel, bool>,
    /// Text entered in the Input bar.
    pub input: String,
    /// Current interaction mode.
    pub mode: Mode,
    /// Set to true when the TUI should exit.
    pub should_quit: bool,
}

impl AppState {
    /// Create a fresh state with sensible defaults.
    pub fn new() -> Self {
        let mut scroll_offsets = HashMap::new();
        let mut auto_scroll = HashMap::new();
        for panel in [Panel::Chat, Panel::ToolOutput, Panel::Findings, Panel::Input] {
            scroll_offsets.insert(panel, 0);
            auto_scroll.insert(panel, true);
        }

        Self {
            active_agent: None,
            iteration: 0,
            messages: Vec::new(),
            streaming_buffer: String::new(),
            tool_log: Vec::new(),
            findings: Vec::new(),
            focused_panel: Panel::Input,
            scroll_offsets,
            auto_scroll,
            input: String::new(),
            mode: Mode::Normal,
            should_quit: false,
        }
    }

    /// Apply a domain event, mutating state accordingly.
    ///
    /// This is the single entry point for all state updates — the event loop
    /// in `app.rs` drains the broadcast receiver and calls `apply` for each
    /// received event.
    pub fn apply(&mut self, event: Event) {
        match event {
            Event::Status(msg) => {
                // Parse "Agent: <name> started" to track the active agent.
                if let Some(agent_name) = msg
                    .strip_prefix("Agent: ")
                    .and_then(|s| s.strip_suffix(" started"))
                {
                    self.active_agent = Some((agent_name.to_string(), Instant::now()));
                    self.iteration = 0;
                }
            }
            Event::ToolStarted { name, args } => {
                self.iteration += 1;
                self.tool_log.push(ToolEntry {
                    name,
                    // serde_json::Value -> display string for the TUI panel.
                    args: args.to_string(),
                    output: None,
                    exit_code: None,
                    started: Instant::now(),
                    completed: None,
                });
            }
            Event::ToolOutput { name: _, output } => {
                if let Some(entry) = self.tool_log.last_mut() {
                    entry.output = Some(output);
                }
            }
            Event::ToolCompleted { name: _, exit_code } => {
                if let Some(entry) = self.tool_log.last_mut() {
                    entry.exit_code = Some(exit_code);
                    entry.completed = Some(Instant::now());
                }
            }
            Event::TokenReceived { session_id: _, token } => {
                self.streaming_buffer.push_str(&token);
            }
            Event::StreamCompleted { session_id: _ } => {
                if !self.streaming_buffer.is_empty() {
                    self.messages.push(DisplayMessage {
                        role: "assistant".to_string(),
                        content: std::mem::take(&mut self.streaming_buffer),
                    });
                }
            }
            Event::MessageCreated(msg) => {
                self.messages.push(DisplayMessage {
                    role: msg.role.to_string(),
                    content: msg.content.clone(),
                });
            }
            Event::FindingCreated(finding) => {
                self.findings.push(finding);
            }
            Event::Shutdown => {
                self.should_quit = true;
            }
            // SessionCreated, TaskUpdated — no TUI state change needed yet.
            _ => {}
        }
    }

    /// Scroll a panel up by one line and disable auto-scroll for that panel.
    pub fn scroll_up(&mut self, panel: Panel) {
        self.auto_scroll.insert(panel, false);
        let offset = self.scroll_offsets.entry(panel).or_insert(0);
        *offset = offset.saturating_add(1);
    }

    /// Scroll a panel down by one line (toward the bottom).
    pub fn scroll_down(&mut self, panel: Panel) {
        let offset = self.scroll_offsets.entry(panel).or_insert(0);
        *offset = offset.saturating_sub(1);
    }

    /// Jump to the bottom of a panel and re-enable auto-scroll.
    pub fn jump_to_bottom(&mut self, panel: Panel) {
        self.auto_scroll.insert(panel, true);
        self.scroll_offsets.insert(panel, 0);
    }

    /// Cycle focus to the next panel in order.
    pub fn next_panel(&mut self) {
        self.focused_panel = match self.focused_panel {
            Panel::Chat => Panel::ToolOutput,
            Panel::ToolOutput => Panel::Findings,
            Panel::Findings => Panel::Input,
            Panel::Input => Panel::Chat,
        };
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use sigint_core::event::Event;
    use sigint_core::types::{Finding, Severity};
    use uuid::Uuid;

    #[test]
    fn tool_started_pushes_to_log() {
        let mut state = AppState::new();
        state.apply(Event::ToolStarted {
            name: "nmap_scan".into(),
            args: serde_json::json!("-sV example.com"),
        });
        assert_eq!(state.tool_log.len(), 1);
        assert_eq!(state.tool_log[0].name, "nmap_scan");
        assert_eq!(state.iteration, 1);
    }

    #[test]
    fn tool_started_increments_iteration_each_call() {
        let mut state = AppState::new();
        state.apply(Event::ToolStarted {
            name: "tool_a".into(),
            args: serde_json::json!({}),
        });
        state.apply(Event::ToolStarted {
            name: "tool_b".into(),
            args: serde_json::json!({}),
        });
        assert_eq!(state.iteration, 2);
        assert_eq!(state.tool_log.len(), 2);
    }

    #[test]
    fn token_received_appends_to_buffer() {
        let mut state = AppState::new();
        let sid = Uuid::new_v4();
        state.apply(Event::TokenReceived {
            session_id: sid,
            token: "Hello".into(),
        });
        state.apply(Event::TokenReceived {
            session_id: sid,
            token: " world".into(),
        });
        assert_eq!(state.streaming_buffer, "Hello world");
    }

    #[test]
    fn stream_completed_flushes_buffer_to_messages() {
        let mut state = AppState::new();
        let sid = Uuid::new_v4();
        state.apply(Event::TokenReceived {
            session_id: sid,
            token: "Analysis complete".into(),
        });
        state.apply(Event::StreamCompleted { session_id: sid });
        assert!(state.streaming_buffer.is_empty());
        assert_eq!(state.messages.len(), 1);
        assert_eq!(state.messages[0].content, "Analysis complete");
        assert_eq!(state.messages[0].role, "assistant");
    }

    #[test]
    fn stream_completed_with_empty_buffer_does_not_push_message() {
        let mut state = AppState::new();
        let sid = Uuid::new_v4();
        state.apply(Event::StreamCompleted { session_id: sid });
        assert_eq!(state.messages.len(), 0);
    }

    #[test]
    fn finding_created_pushes_to_findings() {
        let mut state = AppState::new();
        let sid = Uuid::new_v4();
        let f = Finding::new(sid, "XSS", "reflected XSS", Severity::High);
        state.apply(Event::FindingCreated(f));
        assert_eq!(state.findings.len(), 1);
        assert_eq!(state.findings[0].title, "XSS");
    }

    #[test]
    fn scroll_up_disables_auto_scroll() {
        let mut state = AppState::new();
        assert!(state.auto_scroll[&Panel::Chat]);
        state.scroll_up(Panel::Chat);
        assert!(!state.auto_scroll[&Panel::Chat]);
    }

    #[test]
    fn scroll_up_increments_offset() {
        let mut state = AppState::new();
        assert_eq!(state.scroll_offsets[&Panel::Chat], 0);
        state.scroll_up(Panel::Chat);
        assert_eq!(state.scroll_offsets[&Panel::Chat], 1);
        state.scroll_up(Panel::Chat);
        assert_eq!(state.scroll_offsets[&Panel::Chat], 2);
    }

    #[test]
    fn scroll_down_does_not_go_below_zero() {
        let mut state = AppState::new();
        state.scroll_down(Panel::Chat);
        assert_eq!(state.scroll_offsets[&Panel::Chat], 0);
    }

    #[test]
    fn jump_to_bottom_re_enables_auto_scroll() {
        let mut state = AppState::new();
        state.scroll_up(Panel::Chat);
        assert!(!state.auto_scroll[&Panel::Chat]);
        state.jump_to_bottom(Panel::Chat);
        assert!(state.auto_scroll[&Panel::Chat]);
    }

    #[test]
    fn jump_to_bottom_resets_offset() {
        let mut state = AppState::new();
        state.scroll_up(Panel::Chat);
        state.scroll_up(Panel::Chat);
        state.jump_to_bottom(Panel::Chat);
        assert_eq!(state.scroll_offsets[&Panel::Chat], 0);
    }

    #[test]
    fn next_panel_cycles_all_four() {
        let mut state = AppState::new();
        assert_eq!(state.focused_panel, Panel::Input);
        state.next_panel();
        assert_eq!(state.focused_panel, Panel::Chat);
        state.next_panel();
        assert_eq!(state.focused_panel, Panel::ToolOutput);
        state.next_panel();
        assert_eq!(state.focused_panel, Panel::Findings);
        state.next_panel();
        assert_eq!(state.focused_panel, Panel::Input);
    }

    #[test]
    fn shutdown_sets_should_quit() {
        let mut state = AppState::new();
        assert!(!state.should_quit);
        state.apply(Event::Shutdown);
        assert!(state.should_quit);
    }
}
