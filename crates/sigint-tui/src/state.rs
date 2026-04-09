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
//!
//! @decision DEC-4D-STATE-001
//! @title Assets panel added as fifth panel in the Tab cycle
//! @status accepted
//! @rationale Sub-Phase 4D introduces attack-surface-mapped assets discovered
//! by sigint-recon. A dedicated panel (between Findings and Input in the Tab
//! cycle) keeps asset data visually separate from security findings. Assets
//! accumulate via AssetDiscovered events; AssetChanged and ReconStarted/
//! ReconCompleted are acknowledged but produce no immediate state mutation
//! because the asset list is the canonical source of truth rendered by ui.rs.
//!
//! @decision DEC-P6-APPROVAL-001
//! @title PendingApproval held in AppState; approval responses emitted by app.rs
//! @status accepted
//! @rationale AppState remains a pure data structure (no channel handles).
//! When ToolApprovalRequested arrives, apply() records it in pending_approval.
//! When the operator presses y/n, app.rs reads pending_approval from state,
//! emits the corresponding ToolApprovalGranted/ToolApprovalDenied event on the
//! event bus sender it already owns, then clears pending_approval. This keeps
//! apply() side-effect-free and fully unit-testable.

use std::collections::HashMap;
use std::time::Instant;

use sigint_core::diff::ScanDiff;
use sigint_core::event::Event;
use sigint_core::types::{Asset, Finding, Session};

/// Which top-level view (tab) is currently shown.
///
/// Number keys 1-6 switch views. Each view owns a distinct set of panels
/// that participate in the Tab cycle (see `AppState::next_panel`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum View {
    /// Live scan activity: Chat, ToolOutput, Findings, Assets, Input.
    #[default]
    Scan,
    /// Aggregate stats and recent sessions.
    Dashboard,
    /// Historical session list + per-session message replay.
    Sessions,
    /// All findings across sessions, filterable by severity.
    Findings,
    /// Report generation and preview.
    Reports,
    /// TUI-local settings (shadows Arc<Config> without mutating it).
    Settings,
}

/// Diff classification for a finding relative to the previous scan.
///
/// Computed by `AppState::diff_status` from the stored `ScanDiff`.
/// `NoDiff` is returned when no diff has been loaded (i.e. `scan_diff` is
/// `None`), allowing callers to render findings without diff decorations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffStatus {
    /// Finding is present in the newer scan but not the baseline — newly introduced.
    New,
    /// Finding is present in the baseline but not the newer scan — remediated.
    Fixed,
    /// Finding is present in both scans — still open.
    Unchanged,
    /// No diff has been computed yet; status is unknown.
    NoDiff,
}

/// Which panel currently has keyboard focus.
///
/// Panel variants are grouped by view — Tab cycles only through panels relevant
/// to the active view (see `AppState::next_panel`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Panel {
    // ── Scan view ──────────────────────────────────────────────────────────────
    Chat,
    ToolOutput,
    Findings,
    Assets,
    Input,
    // ── Sessions view ──────────────────────────────────────────────────────────
    SessionList,
    SessionDetail,
    // ── Findings view ──────────────────────────────────────────────────────────
    FindingList,
    FindingDetail,
    // ── Reports view ───────────────────────────────────────────────────────────
    ReportList,
    ReportPreview,
    // ── Settings view ──────────────────────────────────────────────────────────
    SettingsForm,
}

/// Aggregate dashboard statistics.
///
/// Populated by TuiApp from DB queries on Dashboard view activation.
/// All fields are optional so the dashboard renders gracefully before data loads.
#[derive(Debug, Clone, Default)]
pub struct DashboardData {
    pub total_sessions: usize,
    pub total_findings: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub total_assets: usize,
    /// Most recent sessions (up to 5) for the recent-activity table.
    pub recent_sessions: Vec<Session>,
}

/// A row in the Sessions view session list.
pub type SessionRow = Session;

/// Detail data for a selected session (messages + tool log snapshot).
#[derive(Debug, Clone, Default)]
pub struct SessionDetail {
    pub session: Option<Session>,
    /// Messages loaded from DB for this session.
    pub messages: Vec<DisplayMessage>,
    /// Tool records loaded from DB for this session.
    pub tool_summaries: Vec<String>,
}

/// A row in the Findings view finding list (flattened from DB query).
pub type FindingRow = Finding;

/// Detail data for a selected finding.
#[derive(Debug, Clone, Default)]
pub struct FindingDetailData {
    pub finding: Option<Finding>,
}

/// TUI-local settings that shadow the global `Arc<Config>` without mutating it.
///
/// @decision DEC-P21-SETTINGS-001
/// @title TuiSettings shadows Arc<Config> without mutating it
/// @status accepted
/// @rationale AppState must remain pure (no IO, no Arc mutation). TuiSettings
/// holds TUI-specific overrides set via `:set key value` commands. The TuiApp
/// event loop applies these settings when dispatching actions. This avoids the
/// need for interior mutability on the shared Config.
#[derive(Debug, Clone)]
pub struct TuiSettings {
    /// Auto-approve low-risk tool calls without prompting.
    pub auto_approve_low: bool,
    /// Show agent reasoning (<think> blocks) in the Chat panel.
    pub show_reasoning: bool,
    /// Maximum lines of tool output shown per entry.
    pub tool_output_lines: usize,
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

/// A tool execution awaiting operator approval.
///
/// Populated from `Event::ToolApprovalRequested`; cleared when the operator
/// presses 'y' (grant) or 'n' (deny) in the TUI. The approval response is
/// emitted as `Event::ToolApprovalGranted` / `Event::ToolApprovalDenied` by
/// `app.rs` so AppState remains side-effect-free.
#[derive(Debug, Clone)]
pub struct PendingApproval {
    pub request_id: uuid::Uuid,
    pub tool_name: String,
    /// Compact JSON summary of the tool arguments, truncated to ~100 chars.
    pub args_summary: String,
    pub risk_level: sigint_core::types::ToolRisk,
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
///
/// @decision DEC-P21-STATE-001
/// @title AppState extended with multi-view fields; IO ownership stays in TuiApp
/// @status accepted
/// @rationale The pure-state-machine invariant (no IO in AppState) is preserved.
/// TuiApp owns Arc<Database> and pushes query results into the new view-specific
/// fields here (dashboard, session_list, etc.). AppState only holds the cached
/// data and selection indices. This keeps all state transitions unit-testable
/// without a real database or terminal.
pub struct AppState {
    // ── Global ────────────────────────────────────────────────────────────────
    /// Which tab is currently shown.
    pub current_view: View,
    /// Set to true when the TUI should exit.
    pub should_quit: bool,
    /// Whether the `?` help overlay is visible.
    pub show_help: bool,
    /// Current interaction mode.
    pub mode: Mode,
    /// Active session ID (nil until a real session is created by the scan pipeline).
    pub session_id: uuid::Uuid,
    /// Active search query (set by Mode::Search on Enter).
    pub search_query: Option<String>,
    /// TUI-local settings (shadows Arc<Config>).
    pub tui_settings: TuiSettings,

    // ── Scan view ─────────────────────────────────────────────────────────────
    /// Currently active agent name and when it started.
    pub active_agent: Option<(String, Instant)>,
    /// Tool-call iteration counter within the current agent turn.
    pub iteration: usize,
    /// Completed chat messages (flushed from streaming_buffer on StreamCompleted).
    pub messages: Vec<DisplayMessage>,
    /// Accumulator for in-progress LLM streaming output.
    pub streaming_buffer: String,
    /// Accumulator for in-progress agent reasoning (streamed between tool calls).
    ///
    /// Populated by `AgentThinking` events; flushed to `messages` as a
    /// `role="thinking"` entry by `AgentThinkingDone`.
    pub reasoning_buffer: String,
    /// Which agent is currently thinking (for display label in the Chat panel).
    pub thinking_agent: Option<String>,
    /// Tool invocation log (append-only; entries are updated in place).
    pub tool_log: Vec<ToolEntry>,
    /// Security findings discovered during the scan.
    pub findings: Vec<Finding>,
    /// Discovered attack-surface assets from sigint-recon.
    pub assets: Vec<Asset>,
    /// Text entered in the Input bar.
    pub input: String,

    // ── Dashboard view ────────────────────────────────────────────────────────
    /// Aggregate stats populated by TuiApp from DB queries on view activation.
    pub dashboard: DashboardData,

    // ── Sessions view ─────────────────────────────────────────────────────────
    /// Session list loaded from DB on Sessions view activation.
    pub session_list: Vec<SessionRow>,
    /// Currently selected row in the session list.
    pub selected_session_idx: usize,
    /// Detail data for the selected session (messages, tool log snapshot).
    pub session_detail: SessionDetail,

    // ── Findings view ─────────────────────────────────────────────────────────
    /// All findings from DB (all sessions), loaded on Findings view activation.
    pub finding_list: Vec<FindingRow>,
    /// Currently selected row in the findings list.
    pub selected_finding_idx: usize,
    /// Detail data for the selected finding.
    pub finding_detail: FindingDetailData,

    // ── Reports view ──────────────────────────────────────────────────────────
    /// Sessions available for report generation, mirrored from session_list.
    pub report_list: Vec<SessionRow>,
    /// Currently generated report text (Markdown), empty until generated.
    pub report_preview: String,
    /// Currently selected session index in the report list.
    pub selected_report_idx: usize,

    // ── Navigation / rendering ────────────────────────────────────────────────
    /// Panel that currently receives keyboard events.
    pub focused_panel: Panel,
    /// Per-panel scroll offset (lines scrolled up from bottom).
    pub scroll_offsets: HashMap<Panel, usize>,
    /// Per-panel auto-scroll flag; set to false when user scrolls up.
    pub auto_scroll: HashMap<Panel, bool>,

    // ── Approval / diff ───────────────────────────────────────────────────────
    /// A tool execution waiting for operator approval (y/n).
    ///
    /// When `Some`, the UI renders an approval bar and keypresses 'y'/'n'
    /// are intercepted by `app.rs` to emit the grant/deny events.
    pub pending_approval: Option<PendingApproval>,
    /// The most recent scan diff, populated when `Event::ScanDiffCompleted` arrives.
    ///
    /// Used by `diff_status()` to classify each finding as New, Fixed, or Unchanged
    /// for diff-aware rendering in the Findings panel.
    pub scan_diff: Option<ScanDiff>,
}

impl AppState {
    /// Create a fresh state with sensible defaults.
    pub fn new() -> Self {
        let mut scroll_offsets = HashMap::new();
        let mut auto_scroll = HashMap::new();
        for panel in [
            Panel::Chat,
            Panel::ToolOutput,
            Panel::Findings,
            Panel::Assets,
            Panel::Input,
            Panel::SessionList,
            Panel::SessionDetail,
            Panel::FindingList,
            Panel::FindingDetail,
            Panel::ReportList,
            Panel::ReportPreview,
            Panel::SettingsForm,
        ] {
            scroll_offsets.insert(panel, 0);
            auto_scroll.insert(panel, true);
        }

        Self {
            // ── Global ───────────────────────────────────────────────────────
            current_view: View::Scan,
            should_quit: false,
            show_help: false,
            mode: Mode::Normal,
            session_id: uuid::Uuid::nil(),
            search_query: None,
            tui_settings: TuiSettings {
                auto_approve_low: false,
                show_reasoning: true,
                tool_output_lines: 3,
            },
            // ── Scan view ────────────────────────────────────────────────────
            active_agent: None,
            iteration: 0,
            messages: Vec::new(),
            streaming_buffer: String::new(),
            reasoning_buffer: String::new(),
            thinking_agent: None,
            tool_log: Vec::new(),
            findings: Vec::new(),
            assets: Vec::new(),
            input: String::new(),
            // ── Dashboard ────────────────────────────────────────────────────
            dashboard: DashboardData::default(),
            // ── Sessions ─────────────────────────────────────────────────────
            session_list: Vec::new(),
            selected_session_idx: 0,
            session_detail: SessionDetail::default(),
            // ── Findings ─────────────────────────────────────────────────────
            finding_list: Vec::new(),
            selected_finding_idx: 0,
            finding_detail: FindingDetailData::default(),
            // ── Reports ──────────────────────────────────────────────────────
            report_list: Vec::new(),
            report_preview: String::new(),
            selected_report_idx: 0,
            // ── Navigation / rendering ────────────────────────────────────────
            focused_panel: Panel::Input,
            scroll_offsets,
            auto_scroll,
            // ── Approval / diff ───────────────────────────────────────────────
            pending_approval: None,
            scan_diff: None,
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
            Event::TokenReceived {
                session_id: _,
                token,
            } => {
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
            Event::AssetDiscovered(asset) => {
                self.assets.push(asset);
            }
            Event::AssetChanged { .. } => {
                // Asset changes are persisted to the store; the TUI shows the
                // cumulative discovered-asset list and does not patch entries in-place.
            }
            Event::ReconStarted { .. } | Event::ReconCompleted { .. } => {
                // Informational events — could update a status bar indicator in
                // a future iteration. No AppState mutation required for MVP.
            }
            Event::Shutdown => {
                self.should_quit = true;
            }
            Event::UserInput {
                session_id: _,
                text,
            } => {
                self.messages.push(DisplayMessage {
                    role: "user".to_string(),
                    content: text,
                });
            }
            // ── Approval gate events ───────────────────────────────────────
            Event::ToolApprovalRequested {
                request_id,
                session_id: _,
                tool_name,
                args,
                risk_level,
            } => {
                // Build a compact args summary (≤100 chars) for display.
                let mut args_summary =
                    serde_json::to_string(&args).unwrap_or_else(|_| String::from("{…}"));
                if args_summary.len() > 100 {
                    args_summary.truncate(97);
                    args_summary.push_str("...");
                }
                self.pending_approval = Some(PendingApproval {
                    request_id,
                    tool_name,
                    args_summary,
                    risk_level,
                });
            }
            // ToolApprovalGranted / ToolApprovalDenied are emitted BY the TUI
            // (via app.rs) and consumed by the approval registry in sigint-core.
            // The TUI does not need to react to its own responses.
            Event::ToolApprovalGranted { .. } | Event::ToolApprovalDenied { .. } => {}
            // ── Streaming reasoning events ─────────────────────────────────
            Event::AgentThinking { agent_role, token } => {
                self.thinking_agent = Some(agent_role);
                self.reasoning_buffer.push_str(&token);
            }
            Event::AgentThinkingDone { agent_role: _ } => {
                if !self.reasoning_buffer.is_empty() {
                    self.messages.push(DisplayMessage {
                        role: "thinking".to_string(),
                        content: std::mem::take(&mut self.reasoning_buffer),
                    });
                }
                self.thinking_agent = None;
            }
            Event::ScanDiffCompleted { diff } => {
                self.scan_diff = Some(diff);
            }
            // SessionCreated, TaskUpdated — no TUI state change needed yet.
            _ => {}
        }
    }

    /// Classify a finding relative to the stored scan diff.
    ///
    /// Returns `DiffStatus::NoDiff` when no diff has been loaded.
    /// Matching uses the same `(title.to_lowercase(), asset)` key as the diff
    /// engine in `sigint-core` — see @decision DEC-DIFF-001.
    pub fn diff_status(&self, finding: &Finding) -> DiffStatus {
        let Some(ref diff) = self.scan_diff else {
            return DiffStatus::NoDiff;
        };
        let key = (
            finding.title.to_lowercase(),
            finding.asset.clone().unwrap_or_default(),
        );
        if diff
            .new
            .iter()
            .any(|f| (f.title.to_lowercase(), f.asset.clone().unwrap_or_default()) == key)
        {
            DiffStatus::New
        } else if diff
            .fixed
            .iter()
            .any(|f| (f.title.to_lowercase(), f.asset.clone().unwrap_or_default()) == key)
        {
            DiffStatus::Fixed
        } else {
            DiffStatus::Unchanged
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
    ///
    /// Tab cycles only through panels relevant to the current view.
    /// Panels from other views are unreachable via Tab but may be focused
    /// programmatically (e.g. when switching views).
    pub fn next_panel(&mut self) {
        self.focused_panel = match self.current_view {
            View::Scan => match self.focused_panel {
                Panel::Chat => Panel::ToolOutput,
                Panel::ToolOutput => Panel::Findings,
                Panel::Findings => Panel::Assets,
                Panel::Assets => Panel::Input,
                _ => Panel::Chat,
            },
            View::Dashboard => Panel::SessionList,
            View::Sessions => match self.focused_panel {
                Panel::SessionList => Panel::SessionDetail,
                _ => Panel::SessionList,
            },
            View::Findings => match self.focused_panel {
                Panel::FindingList => Panel::FindingDetail,
                _ => Panel::FindingList,
            },
            View::Reports => match self.focused_panel {
                Panel::ReportList => Panel::ReportPreview,
                _ => Panel::ReportList,
            },
            View::Settings => Panel::SettingsForm,
        };
    }

    /// Switch to a view and reset focus to the primary panel for that view.
    pub fn switch_view(&mut self, view: View) {
        self.current_view = view;
        self.focused_panel = match view {
            View::Scan => Panel::Input,
            View::Dashboard => Panel::SessionList,
            View::Sessions => Panel::SessionList,
            View::Findings => Panel::FindingList,
            View::Reports => Panel::ReportList,
            View::Settings => Panel::SettingsForm,
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
    use sigint_core::diff::{DiffSummary, ScanDiff};
    use sigint_core::event::Event;
    use sigint_core::types::{Asset, AssetKind, Finding, Severity};
    use uuid::Uuid;

    fn make_finding(title: &str, asset: Option<&str>) -> Finding {
        let mut f = Finding::new(Uuid::new_v4(), title, "", Severity::Medium);
        f.asset = asset.map(|s| s.to_string());
        f
    }

    #[test]
    fn scan_diff_completed_stores_diff() {
        let mut state = AppState::default();
        assert!(state.scan_diff.is_none());
        let diff = ScanDiff {
            scan_a: Uuid::new_v4(),
            scan_b: Uuid::new_v4(),
            summary: DiffSummary {
                new: 1,
                fixed: 1,
                unchanged: 0,
            },
            new: vec![make_finding("New Vuln", Some("host1"))],
            fixed: vec![make_finding("Old Vuln", Some("host1"))],
            unchanged: vec![],
        };
        state.apply(Event::ScanDiffCompleted { diff: diff.clone() });
        assert!(state.scan_diff.is_some());
        assert_eq!(state.scan_diff.as_ref().unwrap().summary.new, 1);
    }

    #[test]
    fn diff_status_new_finding_detected() {
        let mut state = AppState::default();
        let finding = make_finding("New Vuln", Some("host1"));
        let diff = ScanDiff {
            scan_a: Uuid::new_v4(),
            scan_b: Uuid::new_v4(),
            summary: DiffSummary {
                new: 1,
                fixed: 0,
                unchanged: 0,
            },
            new: vec![finding.clone()],
            fixed: vec![],
            unchanged: vec![],
        };
        state.apply(Event::ScanDiffCompleted { diff });
        assert_eq!(state.diff_status(&finding), DiffStatus::New);
    }

    #[test]
    fn diff_status_fixed_finding_detected() {
        let mut state = AppState::default();
        let finding = make_finding("Old Vuln", Some("host1"));
        let diff = ScanDiff {
            scan_a: Uuid::new_v4(),
            scan_b: Uuid::new_v4(),
            summary: DiffSummary {
                new: 0,
                fixed: 1,
                unchanged: 0,
            },
            new: vec![],
            fixed: vec![finding.clone()],
            unchanged: vec![],
        };
        state.apply(Event::ScanDiffCompleted { diff });
        assert_eq!(state.diff_status(&finding), DiffStatus::Fixed);
    }

    #[test]
    fn diff_status_no_diff_returns_nodiff() {
        let state = AppState::default();
        let finding = make_finding("Test", None);
        assert_eq!(state.diff_status(&finding), DiffStatus::NoDiff);
    }

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
    fn next_panel_cycles_all_five() {
        let mut state = AppState::new();
        assert_eq!(state.focused_panel, Panel::Input);
        state.next_panel();
        assert_eq!(state.focused_panel, Panel::Chat);
        state.next_panel();
        assert_eq!(state.focused_panel, Panel::ToolOutput);
        state.next_panel();
        assert_eq!(state.focused_panel, Panel::Findings);
        state.next_panel();
        assert_eq!(state.focused_panel, Panel::Assets);
        state.next_panel();
        assert_eq!(state.focused_panel, Panel::Input);
    }

    #[test]
    fn asset_discovered_pushes_to_assets() {
        let mut state = AppState::new();
        assert_eq!(state.assets.len(), 0);
        let sid = Uuid::new_v4();
        let asset = Asset::new(sid, AssetKind::Host, "10.0.0.1");
        state.apply(Event::AssetDiscovered(asset));
        assert_eq!(state.assets.len(), 1);
        assert_eq!(state.assets[0].value, "10.0.0.1");
        assert_eq!(state.assets[0].kind, AssetKind::Host);
    }

    #[test]
    fn asset_discovered_multiple_accumulates() {
        let mut state = AppState::new();
        let sid = Uuid::new_v4();
        for value in ["10.0.0.1", "example.com", "https://example.com/login"] {
            let asset = Asset::new(sid, AssetKind::Host, value);
            state.apply(Event::AssetDiscovered(asset));
        }
        assert_eq!(state.assets.len(), 3);
    }

    #[test]
    fn assets_panel_in_scroll_maps() {
        // Assets panel must be present in the scroll_offsets and auto_scroll maps
        // so scroll_up/down operations on it don't panic.
        let state = AppState::new();
        assert!(state.scroll_offsets.contains_key(&Panel::Assets));
        assert!(state.auto_scroll.contains_key(&Panel::Assets));
    }

    #[test]
    fn recon_events_do_not_panic() {
        let mut state = AppState::new();
        let sid = Uuid::new_v4();
        // These should all pass through the wildcard arm without panicking.
        state.apply(Event::ReconStarted {
            session_id: sid,
            target: "example.com".to_string(),
        });
        state.apply(Event::AssetChanged {
            asset_id: Uuid::new_v4(),
            field: "value".to_string(),
            old: "old.example.com".to_string(),
            new: "new.example.com".to_string(),
        });
        state.apply(Event::ReconCompleted {
            session_id: sid,
            assets_found: 5,
        });
        // State is unaffected (assets unchanged).
        assert_eq!(state.assets.len(), 0);
    }

    #[test]
    fn shutdown_sets_should_quit() {
        let mut state = AppState::new();
        assert!(!state.should_quit);
        state.apply(Event::Shutdown);
        assert!(state.should_quit);
    }

    #[test]
    fn approval_requested_sets_pending() {
        use sigint_core::types::ToolRisk;

        let mut state = AppState::new();
        assert!(state.pending_approval.is_none());

        let req_id = Uuid::new_v4();
        let sess_id = Uuid::new_v4();
        state.apply(Event::ToolApprovalRequested {
            request_id: req_id,
            session_id: sess_id,
            tool_name: "nmap_scan".into(),
            args: serde_json::json!({"target": "192.168.1.0/24"}),
            risk_level: ToolRisk::High,
        });

        let approval = state
            .pending_approval
            .expect("should have pending approval");
        assert_eq!(approval.request_id, req_id);
        assert_eq!(approval.tool_name, "nmap_scan");
        assert_eq!(approval.risk_level, ToolRisk::High);
        assert!(!approval.args_summary.is_empty());
    }

    #[test]
    fn approval_requested_truncates_long_args() {
        use sigint_core::types::ToolRisk;

        let mut state = AppState::new();
        // Construct a very long args value.
        let long_string = "x".repeat(200);
        state.apply(Event::ToolApprovalRequested {
            request_id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            tool_name: "tool".into(),
            args: serde_json::json!({"data": long_string}),
            risk_level: ToolRisk::Medium,
        });

        let approval = state.pending_approval.unwrap();
        assert!(
            approval.args_summary.len() <= 100,
            "args_summary exceeded 100 chars: {} chars",
            approval.args_summary.len()
        );
        assert!(
            approval.args_summary.ends_with("..."),
            "truncated summary should end with ..."
        );
    }

    #[test]
    fn approval_granted_clears_pending() {
        use sigint_core::types::ToolRisk;

        // Simulate the grant flow: state records pending; app.rs would emit
        // ToolApprovalGranted and clear pending_approval. We test the clear
        // directly since the emit side lives in app.rs.
        let mut state = AppState::new();
        let req_id = Uuid::new_v4();

        // Set up pending approval.
        state.apply(Event::ToolApprovalRequested {
            request_id: req_id,
            session_id: Uuid::new_v4(),
            tool_name: "run_cmd".into(),
            args: serde_json::json!({}),
            risk_level: ToolRisk::Low,
        });
        assert!(state.pending_approval.is_some());

        // Simulate what app.rs does on 'y': clear pending_approval.
        state.pending_approval = None;
        assert!(state.pending_approval.is_none());
    }

    #[test]
    fn user_input_adds_message_to_chat() {
        let mut state = AppState::new();
        state.apply(Event::UserInput {
            session_id: Uuid::nil(),
            text: "scan 10.0.0.1".to_string(),
        });
        assert_eq!(state.messages.len(), 1);
        assert_eq!(state.messages[0].role, "user");
        assert_eq!(state.messages[0].content, "scan 10.0.0.1");
    }

    #[test]
    fn approval_second_request_replaces_first() {
        use sigint_core::types::ToolRisk;

        let mut state = AppState::new();
        let req1 = Uuid::new_v4();
        let req2 = Uuid::new_v4();

        state.apply(Event::ToolApprovalRequested {
            request_id: req1,
            session_id: Uuid::new_v4(),
            tool_name: "first_tool".into(),
            args: serde_json::json!({}),
            risk_level: ToolRisk::Low,
        });
        state.apply(Event::ToolApprovalRequested {
            request_id: req2,
            session_id: Uuid::new_v4(),
            tool_name: "second_tool".into(),
            args: serde_json::json!({}),
            risk_level: ToolRisk::High,
        });

        let approval = state.pending_approval.unwrap();
        assert_eq!(
            approval.request_id, req2,
            "second request should replace first"
        );
        assert_eq!(approval.tool_name, "second_tool");
    }

    #[test]
    fn agent_thinking_accumulates_in_buffer() {
        let mut state = AppState::new();
        state.apply(Event::AgentThinking {
            agent_role: "Researcher".into(),
            token: "Let me ".into(),
        });
        state.apply(Event::AgentThinking {
            agent_role: "Researcher".into(),
            token: "analyze this.".into(),
        });
        assert_eq!(state.reasoning_buffer, "Let me analyze this.");
        assert_eq!(state.thinking_agent.as_deref(), Some("Researcher"));
    }

    #[test]
    fn agent_thinking_done_flushes_to_messages() {
        let mut state = AppState::new();
        state.apply(Event::AgentThinking {
            agent_role: "Executor".into(),
            token: "Running nmap...".into(),
        });
        state.apply(Event::AgentThinkingDone {
            agent_role: "Executor".into(),
        });
        assert!(state.reasoning_buffer.is_empty());
        assert!(state.thinking_agent.is_none());
        assert_eq!(state.messages.len(), 1);
        assert_eq!(state.messages[0].role, "thinking");
        assert_eq!(state.messages[0].content, "Running nmap...");
    }

    #[test]
    fn agent_thinking_done_with_empty_buffer_does_not_push_message() {
        let mut state = AppState::new();
        // No AgentThinking events first — buffer is empty.
        state.apply(Event::AgentThinkingDone {
            agent_role: "Reporter".into(),
        });
        assert_eq!(state.messages.len(), 0);
        assert!(state.thinking_agent.is_none());
    }
}
