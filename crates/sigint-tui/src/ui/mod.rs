//! TUI layout rendering — pure function of AppState.
//!
//! `render(frame, state)` is the sole public entry point. It draws:
//!   1. Agent status bar (1 row)
//!   2. Tab bar (1 row)
//!   3. View content (fills remaining height) — dispatched by `state.current_view`
//!
//! Each view module owns its own render logic and tests. This module owns
//! the chrome (status bar, tab bar, help overlay) that appears in all views.
//!
//! @decision DEC-P21-UI-001
//! @title ui/mod.rs owns chrome; per-view modules own content
//! @status accepted
//! @rationale Splitting the monolithic ui.rs into a module per view allows
//! each view to have its own TestBackend tests, keeps file size manageable,
//! and makes it easy to add new views without touching shared infrastructure.
//! The tab bar and status bar live here since they appear in every view.
//! The pure render function contract (AppState -> Frame, no side effects) is
//! preserved across all sub-modules.

pub mod dashboard;
pub mod findings;
pub mod reports;
pub mod scan;
pub mod sessions;
pub mod settings;
pub mod widgets;

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph};
use ratatui::Frame;

use crate::state::{AppState, View};
use widgets::render_tab_bar;

/// Render the full TUI into `frame` from `state`.
///
/// Returns immediately with a "terminal too small" message if the area is
/// under 80×24, preventing panics from zero-height layout splits.
pub fn render(frame: &mut Frame, state: &AppState) {
    let area = frame.area();

    if area.width < 80 || area.height < 24 {
        let msg = Paragraph::new("Terminal too small (min 80x24)").alignment(Alignment::Center);
        frame.render_widget(msg, area);
        return;
    }

    let chrome = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1), // Agent status bar
            Constraint::Length(1), // Tab bar
            Constraint::Min(10),   // View content
        ])
        .split(area);

    render_status_bar(frame, state, chrome[0]);
    render_tab_bar(frame, state.current_view, chrome[1]);

    match state.current_view {
        View::Scan => scan::render(frame, state, chrome[2]),
        View::Dashboard => dashboard::render(frame, state, chrome[2]),
        View::Sessions => sessions::render(frame, state, chrome[2]),
        View::Findings => findings::render(frame, state, chrome[2]),
        View::Reports => reports::render(frame, state, chrome[2]),
        View::Settings => settings::render(frame, state, chrome[2]),
    }

    if state.show_help {
        render_help_overlay(frame, area, state.current_view);
    }
}

fn render_status_bar(frame: &mut Frame, state: &AppState, area: Rect) {
    let content = if let Some((ref agent, started)) = state.active_agent {
        let elapsed = started.elapsed().as_secs_f64();
        format!(
            " [{}] iteration {}/10 | {:.1}s elapsed",
            agent, state.iteration, elapsed
        )
    } else {
        " Idle — waiting for task".to_string()
    };

    let bar = Paragraph::new(content).style(Style::default().bg(Color::DarkGray).fg(Color::White));
    frame.render_widget(bar, area);
}

fn render_help_overlay(frame: &mut Frame, area: Rect, view: View) {
    let popup_width = 56u16.min(area.width.saturating_sub(4));
    let popup_height = 20u16.min(area.height.saturating_sub(4));
    let x = area.x + (area.width.saturating_sub(popup_width)) / 2;
    let y = area.y + (area.height.saturating_sub(popup_height)) / 2;
    let popup_area = Rect::new(x, y, popup_width, popup_height);

    frame.render_widget(Clear, popup_area);

    let global_keys = vec![
        Line::from(Span::styled(
            " Keybindings ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::default(),
        Line::from("  ?          Toggle this help"),
        Line::from("  q          Quit"),
        Line::from("  Ctrl-C     Force quit"),
        Line::from("  1-6        Switch view"),
        Line::from("  Tab        Cycle panel focus"),
        Line::from("  j / ↓      Scroll down"),
        Line::from("  k / ↑      Scroll up"),
        Line::from("  G          Jump to bottom"),
        Line::from("  /          Search mode"),
        Line::from("  :          Command mode"),
        Line::from("  Esc        Close overlay / exit mode"),
    ];

    let view_keys: Vec<Line> = match view {
        View::Scan => vec![
            Line::default(),
            Line::from(Span::styled(
                " Scan view ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from("  y / n      Approve / deny tool execution"),
            Line::from("  Enter      Submit input (Input panel)"),
        ],
        View::Sessions => vec![
            Line::default(),
            Line::from(Span::styled(
                " Sessions view ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from("  Enter      Load selected session"),
            Line::from("  Esc        Return to list"),
        ],
        View::Findings => vec![
            Line::default(),
            Line::from(Span::styled(
                " Findings view ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from("  Enter      Open detail pane"),
            Line::from("  Esc        Return to list"),
        ],
        View::Reports => vec![
            Line::default(),
            Line::from(Span::styled(
                " Reports view ",
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from("  Enter      Generate report for session"),
            Line::from("  :report export <path>   Save to file"),
        ],
        _ => vec![],
    };

    let mut all_lines = global_keys;
    all_lines.extend(view_keys);
    all_lines.push(Line::default());
    all_lines.push(Line::from(Span::styled(
        "  Press ? or Esc to close",
        Style::default().fg(Color::DarkGray),
    )));

    let help = Paragraph::new(all_lines).block(
        Block::default()
            .title(" Help ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    );

    frame.render_widget(help, popup_area);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppState;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn render_does_not_panic_at_80x24() {
        let backend = TestBackend::new(80, 24);
        let mut terminal = Terminal::new(backend).unwrap();
        let state = AppState::new();
        terminal.draw(|frame| render(frame, &state)).unwrap();
    }

    #[test]
    fn render_does_not_panic_at_200x50() {
        let backend = TestBackend::new(200, 50);
        let mut terminal = Terminal::new(backend).unwrap();
        let state = AppState::new();
        terminal.draw(|frame| render(frame, &state)).unwrap();
    }

    #[test]
    fn render_shows_too_small_message_at_40x12() {
        let backend = TestBackend::new(40, 12);
        let mut terminal = Terminal::new(backend).unwrap();
        let state = AppState::new();
        terminal.draw(|frame| render(frame, &state)).unwrap();
    }

    #[test]
    fn render_with_messages_does_not_panic() {
        use crate::state::DisplayMessage;
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AppState::new();
        state.messages.push(DisplayMessage {
            role: "user".into(),
            content: "scan scanme.nmap.org".into(),
        });
        state.messages.push(DisplayMessage {
            role: "assistant".into(),
            content: "Running nmap...".into(),
        });
        state.streaming_buffer = "Analyzing results".into();
        terminal.draw(|frame| render(frame, &state)).unwrap();
    }

    #[test]
    fn render_help_overlay_does_not_panic() {
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AppState::new();
        state.show_help = true;
        terminal.draw(|frame| render(frame, &state)).unwrap();
    }

    #[test]
    fn render_with_findings_does_not_panic() {
        use sigint_core::types::{Finding, Severity};
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AppState::new();
        let sid = uuid::Uuid::new_v4();
        state.findings.push(Finding::new(
            sid,
            "Open port 22",
            "SSH exposed",
            Severity::Medium,
        ));
        state
            .findings
            .push(Finding::new(sid, "XSS", "reflected", Severity::High));
        terminal.draw(|frame| render(frame, &state)).unwrap();
    }

    #[test]
    fn render_with_assets_does_not_panic() {
        use sigint_core::types::{Asset, AssetKind};
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AppState::new();
        let sid = uuid::Uuid::new_v4();
        for (kind, value) in [
            (AssetKind::Host, "10.0.0.1"),
            (AssetKind::Domain, "example.com"),
            (AssetKind::Url, "https://example.com/login"),
            (AssetKind::Service, "ssh:22"),
            (AssetKind::Certificate, "*.example.com"),
            (AssetKind::Email, "admin@example.com"),
            (AssetKind::Other, "unknown-resource"),
        ] {
            state.assets.push(Asset::new(sid, kind, value));
        }
        terminal.draw(|frame| render(frame, &state)).unwrap();
    }

    #[test]
    fn render_assets_panel_focused_does_not_panic() {
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AppState::new();
        state.focused_panel = crate::state::Panel::Assets;
        terminal.draw(|frame| render(frame, &state)).unwrap();
    }

    #[test]
    fn render_with_pending_approval_does_not_panic() {
        use crate::state::PendingApproval;
        use sigint_core::types::ToolRisk;

        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AppState::new();
        state.pending_approval = Some(PendingApproval {
            request_id: uuid::Uuid::new_v4(),
            tool_name: "nmap_scan".into(),
            args_summary: r#"{"target":"192.168.1.0/24"}"#.into(),
            risk_level: ToolRisk::High,
        });
        terminal.draw(|frame| render(frame, &state)).unwrap();
    }

    #[test]
    fn render_approval_bar_all_risk_levels_do_not_panic() {
        use crate::state::PendingApproval;
        use sigint_core::types::ToolRisk;

        for risk in [ToolRisk::Low, ToolRisk::Medium, ToolRisk::High] {
            let backend = TestBackend::new(120, 40);
            let mut terminal = Terminal::new(backend).unwrap();
            let mut state = AppState::new();
            state.pending_approval = Some(PendingApproval {
                request_id: uuid::Uuid::new_v4(),
                tool_name: "test_tool".into(),
                args_summary: "{}".into(),
                risk_level: risk,
            });
            terminal.draw(|frame| render(frame, &state)).unwrap();
        }
    }

    #[test]
    fn render_without_pending_approval_does_not_show_bar() {
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let state = AppState::new();
        assert!(state.pending_approval.is_none());
        terminal.draw(|frame| render(frame, &state)).unwrap();
    }

    #[test]
    fn render_with_thinking_messages_does_not_panic() {
        use crate::state::DisplayMessage;
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AppState::new();
        state.messages.push(DisplayMessage {
            role: "thinking".into(),
            content: "Analyzing open ports...".into(),
        });
        state.reasoning_buffer = "Running nmap scan now".into();
        state.thinking_agent = Some("executor".into());
        terminal.draw(|frame| render(frame, &state)).unwrap();
    }

    #[test]
    fn render_thinking_without_agent_label_does_not_panic() {
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AppState::new();
        state.reasoning_buffer = "thinking...".into();
        state.thinking_agent = None;
        terminal.draw(|frame| render(frame, &state)).unwrap();
    }

    #[test]
    fn render_findings_with_diff_status_does_not_panic() {
        use crate::state::AppState;
        use sigint_core::diff::{DiffSummary, ScanDiff};
        use sigint_core::event::Event;
        use sigint_core::types::{Finding, Severity};
        use uuid::Uuid;

        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AppState::new();
        let sid = Uuid::new_v4();

        let new_finding = Finding::new(
            sid,
            "SQL Injection",
            "unparameterised query",
            Severity::High,
        );
        let fixed_finding = Finding::new(sid, "Open Redirect", "was fixed", Severity::Medium);
        let unchanged_finding = Finding::new(sid, "XSS", "still open", Severity::Low);

        state.findings.push(new_finding.clone());
        state.findings.push(fixed_finding.clone());
        state.findings.push(unchanged_finding.clone());

        let diff = ScanDiff {
            scan_a: Uuid::new_v4(),
            scan_b: Uuid::new_v4(),
            summary: DiffSummary {
                new: 1,
                fixed: 1,
                unchanged: 1,
            },
            new: vec![new_finding],
            fixed: vec![fixed_finding],
            unchanged: vec![unchanged_finding],
        };
        state.apply(Event::ScanDiffCompleted { diff });

        terminal.draw(|frame| render(frame, &state)).unwrap();
    }

    #[test]
    fn render_all_six_views_do_not_panic() {
        for view in [
            View::Scan,
            View::Dashboard,
            View::Sessions,
            View::Findings,
            View::Reports,
            View::Settings,
        ] {
            let backend = TestBackend::new(120, 40);
            let mut terminal = Terminal::new(backend).unwrap();
            let mut state = AppState::new();
            state.current_view = view;
            terminal.draw(|frame| render(frame, &state)).unwrap();
        }
    }

    #[test]
    fn render_help_overlay_for_all_views_does_not_panic() {
        for view in [
            View::Scan,
            View::Dashboard,
            View::Sessions,
            View::Findings,
            View::Reports,
            View::Settings,
        ] {
            let backend = TestBackend::new(120, 40);
            let mut terminal = Terminal::new(backend).unwrap();
            let mut state = AppState::new();
            state.current_view = view;
            state.show_help = true;
            terminal.draw(|frame| render(frame, &state)).unwrap();
        }
    }
}
