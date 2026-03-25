//! TUI application lifecycle — terminal setup, event loop, key handling.
//!
//! `TuiApp` owns the terminal handle and the broadcast receiver from AppCore.
//! It runs an async loop at ~30fps: drain events, poll input, render.
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

use std::io::{self, Stdout};
use std::time::Duration;

use crossterm::event::{self, Event as CEvent, KeyCode, KeyEvent, KeyModifiers};
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::ExecutableCommand;
use ratatui::backend::CrosstermBackend;
use ratatui::Terminal;
use tokio::sync::broadcast;
use tracing::error;

use sigint_core::event::Event;

use crate::state::{AppState, Mode, Panel};
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
}

impl TuiApp {
    /// Create a new `TuiApp`, entering raw mode and the alternate screen.
    ///
    /// `event_tx` is the sender side of the event bus, used to emit approval
    /// responses when the operator presses 'y'/'n' on a pending approval prompt.
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
        })
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
        // TerminalGuard::drop will also run, making this redundant on clean
        // paths, but calling disable_raw_mode twice is harmless.
        if let Err(e) = restore_terminal() {
            error!("TUI: failed to restore terminal: {e}");
        }

        result
    }

    async fn run_inner(&mut self, tick_rate: Duration) -> Result<(), io::Error> {
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
                        // Channel closed — scan completed. Keep the TUI running
                        // so the user can review results. They'll press 'q' to exit.
                        break;
                    }
                }
            }

            // 2. Poll terminal input (non-blocking).
            if event::poll(Duration::ZERO)? {
                match event::read()? {
                    CEvent::Key(key) => {
                        if self.handle_key(key) {
                            break;
                        }
                    }
                    CEvent::Resize(_, _) => {
                        // Terminal resized — ratatui queries size on each draw(),
                        // so the next render tick reflows automatically.
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

    /// Handle a key event. Returns `true` if the app should quit.
    fn handle_key(&mut self, key: KeyEvent) -> bool {
        match (&self.state.mode, key.code) {
            // Quit in any mode with Ctrl-C.
            (_, KeyCode::Char('c')) if key.modifiers.contains(KeyModifiers::CONTROL) => {
                return true;
            }

            // ── Approval prompt: 'y' grants, 'n' denies ───────────────────
            // These are intercepted regardless of mode when an approval is pending,
            // giving the operator a clear, dedicated response path.
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

            // Normal mode bindings.
            (Mode::Normal, KeyCode::Char('q')) => return true,
            (Mode::Normal, KeyCode::Tab) => self.state.next_panel(),
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

            // Input panel text entry (Normal mode, Input panel focused).
            (Mode::Normal, KeyCode::Char(c)) if self.state.focused_panel == Panel::Input => {
                self.state.input.push(c);
            }
            (Mode::Normal, KeyCode::Backspace) if self.state.focused_panel == Panel::Input => {
                self.state.input.pop();
            }
            (Mode::Normal, KeyCode::Enter) if self.state.focused_panel == Panel::Input => {
                if !self.state.input.is_empty() {
                    let text = std::mem::take(&mut self.state.input);
                    let _ = self.event_tx.send(Event::UserInput {
                        session_id: uuid::Uuid::nil(), // No active session yet — Phase 8
                        text,
                    });
                }
            }

            // Escape exits Search/Command modes.
            (Mode::Search(_) | Mode::Command(_), KeyCode::Esc) => {
                self.state.mode = Mode::Normal;
            }

            _ => {}
        }

        false
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

    // Panic hook: restore terminal state before the default panic handler runs,
    // so the user's shell is not left in raw mode after a crash.
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // Best-effort — ignore errors here since we're already panicking.
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
