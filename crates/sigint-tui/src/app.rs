//! TUI application lifecycle — terminal setup, event loop, key handling.
//!
//! `TuiApp` owns the terminal handle, the broadcast receiver from AppCore,
//! and an optional Arc<Database> for historical data queries. It runs an
//! async loop at ~30fps: drain events, poll input, render.
//!
//! @decision DEC-P3-TUI-003
//! @title TuiApp separates terminal I/O from state; state lives in AppState
//! @status accepted
//! @rationale Terminal setup/teardown and the event loop are inherently
//! impure (raw mode, alternate screen, panic hooks). Isolating them in
//! app.rs lets state.rs and ui.rs remain pure and fully unit-testable.
//! The panic hook restores the terminal before propagating, preventing a
//! broken terminal state on unexpected panics.
//!
//! @decision DEC-P3-003
//! @title TUI auto-detected via isatty(stdout); --tui/--no-tui override
//! @status accepted
//! @rationale When stdout is a TTY the user is interactive — show TUI.
//! When piped or in CI, fall back to the existing stdout event printer.
//! --tui and --no-tui flags override the heuristic for scripting and testing.
//!
//! @decision DEC-TUI-BUG-001
//! @title TerminalGuard drop-guard ensures terminal is restored on all exit paths
//! @status accepted
//! @rationale The explicit restore_terminal() call in run() handles normal
//! returns and error propagation. The panic hook in setup_terminal() handles
//! panics. TerminalGuard adds a third layer: its Drop fires on any unwind,
//! including future code paths that bypass both (e.g. std::process::exit
//! from a spawned thread). Redundant calls to disable_raw_mode are safe
//! (no-op when not in raw mode), so over-restoring is harmless.
//!
//! @decision DEC-TUI-BUG-002
//! @title Resize events consumed and redrawn immediately via the normal render cycle
//! @status accepted
//! @rationale crossterm emits CEvent::Resize(w,h) when the terminal resizes.
//! ratatui's Terminal::draw() always queries the current area from the backend
//! on each call, so no explicit size update is needed — draw() on the next tick
//! reflows the layout automatically. Consuming the event prevents it from
//! being silently dropped through the wildcard arm, and the unconditional
//! draw at step 4 handles the resize within one tick (≤33ms).
//!
//! @decision DEC-P21-DB-001
//! @title TuiApp owns Arc<Database>; queries run via spawn_blocking
//! @status accepted
//! @rationale AppState must remain pure (no IO). TuiApp holds an
//! Arc<Database> and pushes query results into AppState on view activation.
//! r2d2 pool calls are blocking, so they run in tokio::task::spawn_blocking
//! to avoid blocking the async event loop. Results are cached in AppState and
//! only refreshed when the user switches views, not on every 33ms render tick.

use std::io::{self, Stdout};
use std::sync::Arc;
use std::time::Duration;

use crossterm::event::{self, Event as CEvent, KeyCode, KeyEvent, KeyModifiers};
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::ExecutableCommand;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tokio::sync::broadcast;
use tracing::error;

use sigint_core::event::Event;
use sigint_store::Database;

use crate::state::{AppState, Mode, Panel, View};
use crate::ui;

/// The main TUI application handle.
///
/// Create with `TuiApp::new(event_rx, event_tx)` then drive with `.run().await`.
/// Terminal is restored on drop via `restore_terminal()` in `run()`.
///
/// `event_tx` is used to emit `ToolApprovalGranted` / `ToolApprovalDenied`
/// events when the operator presses 'y' or 'n' on an approval prompt.
pub struct TuiApp {
    state: AppState,
    event_rx: broadcast::Receiver<Event>,
    event_tx: broadcast::Sender<Event>,
    terminal: Terminal<CrosstermBackend<Stdout>>,
    /// Optional database handle for historical data queries.
    /// When Some, view activations trigger background queries that populate
    /// AppState with session lists, findings, dashboard stats, etc.
    db: Option<Arc<Database>>,
}

impl TuiApp {
    /// Create a new `TuiApp`, entering raw mode and the alternate screen.
    ///
    /// `event_tx` is the sender side of the event bus, used to emit approval
    /// responses when the operator presses 'y'/'n' on a pending approval prompt.
    ///
    /// `db` is an optional database handle. Pass `Some(Arc::new(Database::open(...)?)))`
    /// to enable historical data views (sessions, findings, dashboard, reports).
    /// Pass `None` to run in scan-only mode with no DB-backed views.
    ///
    /// On failure the terminal is left unmodified — the caller should not
    /// attempt cleanup since `setup_terminal` failed before taking over.
    pub fn new(
        event_rx: broadcast::Receiver<Event>,
        event_tx: broadcast::Sender<Event>,
    ) -> Result<Self, io::Error> {
        let terminal = setup_terminal()?;
        Ok(Self {
            state: AppState::new(),
            event_rx,
            event_tx,
            terminal,
            db: None,
        })
    }

    /// Attach a database to enable historical data views.
    ///
    /// Call after `new()` before `run()` to enable session browser, findings
    /// history, dashboard stats, and report generation.
    pub fn with_db(mut self, db: Arc<Database>) -> Self {
        self.db = Some(db);
        self
    }

    /// Run the TUI event loop until the user quits or `Event::Shutdown` is received.
    ///
    /// Renders at ~30fps (33ms tick). Always restores the terminal before returning,
    /// including on error paths and panics (via `TerminalGuard`).
    pub async fn run(mut self) -> Result<(), io::Error> {
        let tick_rate = Duration::from_millis(33);

        // Belt-and-suspenders terminal cleanup: the explicit restore_terminal()
        // below handles normal and error returns; TerminalGuard's Drop handles
        // panic unwinds and any future exit paths that bypass the explicit call.
        // See @decision DEC-TUI-BUG-001.
        let _guard = TerminalGuard;

        let result = self.run_inner(tick_rate).await;

        // Always restore terminal, even if run_inner returned an error.
        if let Err(e) = restore_terminal() {
            error!("TUI: failed to restore terminal: {e}");
        }

        result
    }

    async fn run_inner(&mut self, tick_rate: Duration) -> Result<(), io::Error> {
        // Load initial data for the default view (Scan).
        self.refresh_view_data().await;

        loop {
            // 1. Drain the EventBus — apply all pending domain events.
            loop {
                match self.event_rx.try_recv() {
                    Ok(event) => self.state.apply(event),
                    Err(broadcast::error::TryRecvError::Empty) => break,
                    Err(broadcast::error::TryRecvError::Lagged(n)) => {
                        tracing::warn!("TUI: dropped {n} events (lagged)");
                    }
                    Err(broadcast::error::TryRecvError::Closed) => {
                        break;
                    }
                }
            }

            // 2. Poll terminal input (non-blocking).
            if event::poll(Duration::ZERO)? {
                match event::read()? {
                    CEvent::Key(key) => {
                        let prev_view = self.state.current_view;
                        if self.handle_key(key) {
                            break;
                        }
                        // If the view changed, refresh DB data for the new view.
                        if self.state.current_view != prev_view {
                            self.refresh_view_data().await;
                        }
                    }
                    CEvent::Resize(_, _) => {
                        // ratatui queries size on each draw() — handled automatically.
                    }
                    _ => {}
                }
            }

            // 3. Check quit flag (set by Shutdown event or 'q' key).
            if self.state.should_quit {
                break;
            }

            // 4. Render frame.
            self.terminal.draw(|frame| ui::render(frame, &self.state))?;

            // 5. Yield for tick duration to cap CPU usage at ~30fps.
            tokio::time::sleep(tick_rate).await;
        }

        Ok(())
    }

    /// Refresh AppState with DB data for the currently active view.
    ///
    /// Called on startup and whenever the view changes. Queries run in
    /// `spawn_blocking` to avoid blocking the async event loop.
    /// All failures are silently ignored — views degrade gracefully to
    /// empty lists when the DB is unavailable.
    async fn refresh_view_data(&mut self) {
        let Some(ref db) = self.db else { return };
        let db = db.clone();

        match self.state.current_view {
            View::Dashboard => {
                let result = tokio::task::spawn_blocking(move || {
                    let sessions = db.list_sessions().unwrap_or_default();
                    let recent: Vec<_> = sessions.iter().take(5).cloned().collect();
                    let total_sessions = sessions.len();
                    // Count findings across all sessions (best-effort).
                    let mut critical = 0usize;
                    let mut high = 0usize;
                    let mut medium = 0usize;
                    let mut low = 0usize;
                    let mut total_findings = 0usize;
                    for s in &sessions {
                        let findings = db.get_findings(s.id).unwrap_or_default();
                        for f in &findings {
                            total_findings += 1;
                            match f.severity {
                                sigint_core::types::Severity::Critical => critical += 1,
                                sigint_core::types::Severity::High => high += 1,
                                sigint_core::types::Severity::Medium => medium += 1,
                                sigint_core::types::Severity::Low => low += 1,
                                sigint_core::types::Severity::Info => {}
                            }
                        }
                    }
                    crate::state::DashboardData {
                        total_sessions,
                        total_findings,
                        critical_count: critical,
                        high_count: high,
                        medium_count: medium,
                        low_count: low,
                        total_assets: 0, // Asset count requires session iteration
                        recent_sessions: recent,
                    }
                })
                .await;
                if let Ok(data) = result {
                    self.state.dashboard = data;
                }
            }
            View::Sessions => {
                let result =
                    tokio::task::spawn_blocking(move || db.list_sessions().unwrap_or_default())
                        .await;
                if let Ok(sessions) = result {
                    self.state.session_list = sessions.clone();
                    self.state.report_list = sessions;
                }
            }
            View::Findings => {
                let result = tokio::task::spawn_blocking(move || {
                    let sessions = db.list_sessions().unwrap_or_default();
                    let mut all_findings = Vec::new();
                    for s in sessions {
                        let mut findings = db.get_findings(s.id).unwrap_or_default();
                        all_findings.append(&mut findings);
                    }
                    all_findings
                })
                .await;
                if let Ok(findings) = result {
                    self.state.finding_list = findings;
                    self.state.selected_finding_idx = 0;
                }
            }
            View::Reports => {
                let result =
                    tokio::task::spawn_blocking(move || db.list_sessions().unwrap_or_default())
                        .await;
                if let Ok(sessions) = result {
                    self.state.report_list = sessions;
                    self.state.selected_report_idx = 0;
                }
            }
            _ => {}
        }
    }

    /// Handle a key event. Returns `true` if the app should quit.
    fn handle_key(&mut self, key: KeyEvent) -> bool {
        match (&self.state.mode, key.code) {
            // Quit in any mode with Ctrl-C.
            (_, KeyCode::Char('c')) if key.modifiers.contains(KeyModifiers::CONTROL) => {
                return true;
            }

            // ── Approval prompt: 'y' grants, 'n' denies ───────────────────
            (Mode::Normal, KeyCode::Char('y')) if self.state.pending_approval.is_some() => {
                if let Some(approval) = self.state.pending_approval.take() {
                    let _ = self.event_tx.send(Event::ToolApprovalGranted {
                        request_id: approval.request_id,
                    });
                }
            }
            (Mode::Normal, KeyCode::Char('n')) if self.state.pending_approval.is_some() => {
                if let Some(approval) = self.state.pending_approval.take() {
                    let _ = self.event_tx.send(Event::ToolApprovalDenied {
                        request_id: approval.request_id,
                        reason: Some("Denied by TUI operator".into()),
                    });
                }
            }

            // Help overlay toggle.
            (_, KeyCode::Char('?'))
                if !matches!(self.state.mode, Mode::Search(_) | Mode::Command(_)) =>
            {
                self.state.show_help = !self.state.show_help;
            }

            // Dismiss help overlay with Esc.
            (Mode::Normal, KeyCode::Esc) if self.state.show_help => {
                self.state.show_help = false;
            }

            // ── View switching via number keys 1-6 ────────────────────────
            (Mode::Normal, KeyCode::Char('1')) => {
                self.state.switch_view(View::Scan);
            }
            (Mode::Normal, KeyCode::Char('2')) => {
                self.state.switch_view(View::Dashboard);
            }
            (Mode::Normal, KeyCode::Char('3')) => {
                self.state.switch_view(View::Sessions);
            }
            (Mode::Normal, KeyCode::Char('4')) => {
                self.state.switch_view(View::Findings);
            }
            (Mode::Normal, KeyCode::Char('5')) => {
                self.state.switch_view(View::Reports);
            }
            (Mode::Normal, KeyCode::Char('6')) => {
                self.state.switch_view(View::Settings);
            }

            // Normal mode bindings.
            (Mode::Normal, KeyCode::Char('q')) => return true,
            (Mode::Normal, KeyCode::Tab) => self.state.next_panel(),
            // ── j/k: view-specific list navigation takes priority over generic scroll ──
            // These guards must come before the generic k/j scroll arms.
            (Mode::Normal, KeyCode::Char('k') | KeyCode::Up)
                if self.state.current_view == View::Sessions
                    && self.state.focused_panel == Panel::SessionList =>
            {
                self.state.selected_session_idx = self.state.selected_session_idx.saturating_sub(1);
            }
            (Mode::Normal, KeyCode::Char('j') | KeyCode::Down)
                if self.state.current_view == View::Sessions
                    && self.state.focused_panel == Panel::SessionList =>
            {
                let max = self.state.session_list.len().saturating_sub(1);
                if self.state.selected_session_idx < max {
                    self.state.selected_session_idx += 1;
                }
            }
            (Mode::Normal, KeyCode::Char('k') | KeyCode::Up)
                if self.state.current_view == View::Findings
                    && self.state.focused_panel == Panel::FindingList =>
            {
                self.state.selected_finding_idx = self.state.selected_finding_idx.saturating_sub(1);
            }
            (Mode::Normal, KeyCode::Char('j') | KeyCode::Down)
                if self.state.current_view == View::Findings
                    && self.state.focused_panel == Panel::FindingList =>
            {
                let max = self.state.finding_list.len().saturating_sub(1);
                if self.state.selected_finding_idx < max {
                    self.state.selected_finding_idx += 1;
                }
            }
            // ── Generic scroll (all views, all other panels) ─────────────
            (Mode::Normal, KeyCode::Char('k') | KeyCode::Up) => {
                let panel = self.state.focused_panel;
                self.state.scroll_up(panel);
            }
            (Mode::Normal, KeyCode::Char('j') | KeyCode::Down) => {
                let panel = self.state.focused_panel;
                self.state.scroll_down(panel);
            }
            (Mode::Normal, KeyCode::Char('G')) => {
                let panel = self.state.focused_panel;
                self.state.jump_to_bottom(panel);
            }
            (Mode::Normal, KeyCode::Char('/')) => {
                self.state.mode = Mode::Search(String::new());
            }
            (Mode::Normal, KeyCode::Char(':')) => {
                self.state.mode = Mode::Command(String::new());
            }

            // ── Input panel text entry (Normal mode, Scan view, Input panel) ──
            (Mode::Normal, KeyCode::Char(c))
                if self.state.focused_panel == Panel::Input
                    && self.state.current_view == View::Scan =>
            {
                self.state.input.push(c);
            }
            (Mode::Normal, KeyCode::Backspace)
                if self.state.focused_panel == Panel::Input
                    && self.state.current_view == View::Scan =>
            {
                self.state.input.pop();
            }
            (Mode::Normal, KeyCode::Enter)
                if self.state.focused_panel == Panel::Input
                    && self.state.current_view == View::Scan
                    && !self.state.input.is_empty() =>
            {
                let text = std::mem::take(&mut self.state.input);
                let session_id = self.state.session_id;
                let _ = self.event_tx.send(Event::UserInput { session_id, text });
            }

            // ── Command mode: character accumulation ─────────────────────
            (Mode::Command(ref buf), KeyCode::Char(c)) => {
                let mut new_buf = buf.clone();
                new_buf.push(c);
                self.state.mode = Mode::Command(new_buf);
            }
            (Mode::Command(ref buf), KeyCode::Backspace) => {
                let mut new_buf = buf.clone();
                new_buf.pop();
                self.state.mode = Mode::Command(new_buf);
            }
            (Mode::Command(ref buf), KeyCode::Enter) => {
                let cmd = buf.clone();
                self.state.mode = Mode::Normal;
                self.execute_command(&cmd);
            }
            (Mode::Command(_), KeyCode::Esc) => {
                self.state.mode = Mode::Normal;
            }

            // ── Search mode: character accumulation ──────────────────────
            (Mode::Search(ref buf), KeyCode::Char(c)) => {
                let mut new_buf = buf.clone();
                new_buf.push(c);
                self.state.mode = Mode::Search(new_buf);
            }
            (Mode::Search(ref buf), KeyCode::Backspace) => {
                let mut new_buf = buf.clone();
                new_buf.pop();
                self.state.mode = Mode::Search(new_buf);
            }
            (Mode::Search(ref buf), KeyCode::Enter) => {
                let query = if buf.is_empty() {
                    None
                } else {
                    Some(buf.clone())
                };
                self.state.search_query = query;
                self.state.mode = Mode::Normal;
            }
            (Mode::Search(_), KeyCode::Esc) => {
                self.state.search_query = None;
                self.state.mode = Mode::Normal;
            }

            _ => {}
        }

        false
    }

    /// Parse and dispatch a command buffer (the text after ':').
    ///
    /// Supported commands:
    /// - `q` / `quit`             — quit the TUI
    /// - `scan <target>`          — emit UserInput to trigger a scan
    /// - `set <key> <value>`      — modify TuiSettings
    /// - `session <prefix>`       — switch to Sessions view
    /// - `report [session_id]`    — switch to Reports view
    fn execute_command(&mut self, cmd: &str) {
        let parts: Vec<&str> = cmd.trim().splitn(3, ' ').collect();
        match parts.as_slice() {
            ["q"] | ["quit"] => {
                self.state.should_quit = true;
            }
            ["scan", target] => {
                let session_id = self.state.session_id;
                let _ = self.event_tx.send(Event::UserInput {
                    session_id,
                    text: format!("scan {target}"),
                });
            }
            ["set", key, value] => {
                apply_tui_setting(&mut self.state, key, value);
            }
            ["session", _prefix] => {
                self.state.switch_view(View::Sessions);
            }
            ["report"] | ["report", _] => {
                self.state.switch_view(View::Reports);
            }
            _ => {
                // Unknown command — silently ignored (could show status bar msg in future).
            }
        }
    }
}

/// Apply a `:set key value` command to TuiSettings.
fn apply_tui_setting(state: &mut AppState, key: &str, value: &str) {
    match key {
        "auto_approve_low" => {
            state.tui_settings.auto_approve_low = value == "true" || value == "1";
        }
        "show_reasoning" => {
            state.tui_settings.show_reasoning = value == "true" || value == "1";
        }
        "tool_output_lines" => {
            if let Ok(n) = value.parse::<usize>() {
                state.tui_settings.tool_output_lines = n;
            }
        }
        _ => {}
    }
}

/// RAII guard that restores terminal state on drop.
///
/// Fires on any exit path: normal return, `?` error propagation, or panic
/// unwind. Calls are best-effort — errors are silently ignored since this runs
/// during cleanup where there is nothing useful to do with an error.
///
/// See @decision DEC-TUI-BUG-001 in the module doc.
struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
        let _ = io::stdout().execute(LeaveAlternateScreen);
    }
}

/// Enter raw mode and the alternate screen; install a panic hook that
/// restores the terminal before propagating the panic.
fn setup_terminal() -> Result<Terminal<CrosstermBackend<Stdout>>, io::Error> {
    terminal::enable_raw_mode()?;
    let mut stdout = io::stdout();
    stdout.execute(EnterAlternateScreen)?;

    // Panic hook: restore terminal state before the default panic handler runs.
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = terminal::disable_raw_mode();
        let _ = io::stdout().execute(LeaveAlternateScreen);
        original_hook(info);
    }));

    Terminal::new(CrosstermBackend::new(stdout))
}

/// Leave the alternate screen and disable raw mode.
fn restore_terminal() -> Result<(), io::Error> {
    terminal::disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{AppState, View};

    // ── Command parsing tests ──────────────────────────────────────────────────

    fn make_state() -> AppState {
        AppState::new()
    }

    fn run_cmd(state: &mut AppState, cmd: &str) {
        // Inline execute_command logic for unit testing without a full TuiApp.
        let parts: Vec<&str> = cmd.trim().splitn(3, ' ').collect();
        match parts.as_slice() {
            ["q"] | ["quit"] => {
                state.should_quit = true;
            }
            ["set", key, value] => {
                apply_tui_setting(state, key, value);
            }
            ["session", _prefix] => {
                state.switch_view(View::Sessions);
            }
            ["report"] | ["report", _] => {
                state.switch_view(View::Reports);
            }
            _ => {}
        }
    }

    #[test]
    fn command_q_sets_should_quit() {
        let mut state = make_state();
        run_cmd(&mut state, "q");
        assert!(state.should_quit);
    }

    #[test]
    fn command_quit_sets_should_quit() {
        let mut state = make_state();
        run_cmd(&mut state, "quit");
        assert!(state.should_quit);
    }

    #[test]
    fn command_set_auto_approve_low_true() {
        let mut state = make_state();
        assert!(!state.tui_settings.auto_approve_low);
        run_cmd(&mut state, "set auto_approve_low true");
        assert!(state.tui_settings.auto_approve_low);
    }

    #[test]
    fn command_set_show_reasoning_false() {
        let mut state = make_state();
        assert!(state.tui_settings.show_reasoning);
        run_cmd(&mut state, "set show_reasoning false");
        assert!(!state.tui_settings.show_reasoning);
    }

    #[test]
    fn command_set_tool_output_lines() {
        let mut state = make_state();
        assert_eq!(state.tui_settings.tool_output_lines, 3);
        run_cmd(&mut state, "set tool_output_lines 10");
        assert_eq!(state.tui_settings.tool_output_lines, 10);
    }

    #[test]
    fn command_set_tool_output_lines_invalid_is_noop() {
        let mut state = make_state();
        let original = state.tui_settings.tool_output_lines;
        run_cmd(&mut state, "set tool_output_lines notanumber");
        assert_eq!(state.tui_settings.tool_output_lines, original);
    }

    #[test]
    fn command_set_unknown_key_is_noop() {
        let mut state = make_state();
        // Should not panic on unknown keys.
        run_cmd(&mut state, "set nonexistent_key value");
    }

    #[test]
    fn command_session_switches_view() {
        let mut state = make_state();
        assert_eq!(state.current_view, View::Scan);
        run_cmd(&mut state, "session abc1");
        assert_eq!(state.current_view, View::Sessions);
    }

    #[test]
    fn command_report_switches_view() {
        let mut state = make_state();
        run_cmd(&mut state, "report");
        assert_eq!(state.current_view, View::Reports);
    }

    #[test]
    fn command_unknown_is_noop() {
        let mut state = make_state();
        // Unknown commands must not panic or change state.
        run_cmd(&mut state, "unknowncommand");
        assert!(!state.should_quit);
    }

    #[test]
    fn command_empty_is_noop() {
        let mut state = make_state();
        run_cmd(&mut state, "");
        assert!(!state.should_quit);
    }

    // ── TuiSettings tests ─────────────────────────────────────────────────────

    #[test]
    fn tui_settings_default_values() {
        let state = AppState::new();
        let s = &state.tui_settings;
        assert!(!s.auto_approve_low, "auto_approve_low should default false");
        assert!(s.show_reasoning, "show_reasoning should default true");
        assert_eq!(s.tool_output_lines, 3, "tool_output_lines should default 3");
    }

    #[test]
    fn apply_tui_setting_set_numeric_with_one() {
        let mut state = make_state();
        // "1" is treated as truthy for booleans.
        apply_tui_setting(&mut state, "auto_approve_low", "1");
        assert!(state.tui_settings.auto_approve_low);
    }

    // ── View switching tests ──────────────────────────────────────────────────

    #[test]
    fn view_switch_resets_focused_panel() {
        let mut state = AppState::new();
        state.switch_view(View::Sessions);
        assert_eq!(state.focused_panel, Panel::SessionList);

        state.switch_view(View::Findings);
        assert_eq!(state.focused_panel, Panel::FindingList);

        state.switch_view(View::Scan);
        assert_eq!(state.focused_panel, Panel::Input);
    }

    #[test]
    fn next_panel_cycles_scan_view() {
        let mut state = AppState::new();
        // Default is Scan view, focused on Input.
        assert_eq!(state.focused_panel, Panel::Input);
        state.next_panel(); // Input -> Chat (Scan view cycle wraps around)
        assert_eq!(state.focused_panel, Panel::Chat);
        state.next_panel();
        assert_eq!(state.focused_panel, Panel::ToolOutput);
    }

    #[test]
    fn next_panel_cycles_sessions_view() {
        let mut state = AppState::new();
        state.switch_view(View::Sessions);
        assert_eq!(state.focused_panel, Panel::SessionList);
        state.next_panel();
        assert_eq!(state.focused_panel, Panel::SessionDetail);
        state.next_panel();
        assert_eq!(state.focused_panel, Panel::SessionList);
    }
}
