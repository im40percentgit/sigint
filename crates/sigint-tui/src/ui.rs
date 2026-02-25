//! TUI layout rendering — pure function of AppState.
//!
//! `render(frame, state)` is the sole entry point. It has no side effects
//! beyond writing to the ratatui Frame, making it fully testable via
//! `ratatui::backend::TestBackend` without a real terminal.
//!
//! Layout (top-to-bottom):
//!   1. Agent status bar  (1 row)
//!   2. Chat | Tool output  (fills available height)
//!   3. Findings table    (5 rows)
//!   4. Input bar         (3 rows)
//!
//! @decision DEC-P3-TUI-002
//! @title render() is a pure function of AppState with no side effects
//! @status accepted
//! @rationale A pure render function (AppState -> Frame writes) enables
//! full layout testing via ratatui TestBackend without a real terminal or
//! process state. No mutable global state, no I/O in this module.
//! The 5-panel layout uses ratatui Constraint::Percentage + Constraint::Length
//! so panels fill available space deterministically at any terminal size.

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap};
use ratatui::Frame;

use crate::state::{AppState, Mode, Panel};

/// Render the full TUI into `frame` from `state`.
///
/// Returns immediately with a "terminal too small" message if the area
/// is under 80×24, preventing panics from zero-height layout splits.
pub fn render(frame: &mut Frame, state: &AppState) {
    let area = frame.area();

    if area.width < 80 || area.height < 24 {
        let msg = Paragraph::new("Terminal too small (min 80x24)")
            .alignment(Alignment::Center);
        frame.render_widget(msg, area);
        return;
    }

    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),  // Agent status bar
            Constraint::Min(10),    // Chat + Tool panels
            Constraint::Length(5),  // Findings table
            Constraint::Length(3),  // Input bar
        ])
        .split(area);

    render_status_bar(frame, state, main_layout[0]);
    render_main_panels(frame, state, main_layout[1]);
    render_findings(frame, state, main_layout[2]);
    render_input(frame, state, main_layout[3]);
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

    let bar = Paragraph::new(content)
        .style(Style::default().bg(Color::DarkGray).fg(Color::White));
    frame.render_widget(bar, area);
}

fn render_main_panels(frame: &mut Frame, state: &AppState, area: Rect) {
    let panels = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    render_chat(frame, state, panels[0]);
    render_tool_output(frame, state, panels[1]);
}

fn render_chat(frame: &mut Frame, state: &AppState, area: Rect) {
    let focused = state.focused_panel == Panel::Chat;
    let border_style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let mut lines: Vec<Line> = Vec::new();
    for msg in &state.messages {
        let (prefix, color) = match msg.role.as_str() {
            "user"      => ("[User] ", Color::Blue),
            "assistant" => ("[Agent] ", Color::Green),
            "system"    => ("[System] ", Color::DarkGray),
            "tool"      => ("[Tool] ", Color::Yellow),
            _           => ("", Color::White),
        };
        lines.push(Line::from(vec![
            Span::styled(prefix, Style::default().fg(color).add_modifier(Modifier::BOLD)),
            Span::raw(msg.content.clone()),
        ]));
    }

    // Show streaming buffer with cursor indicator when non-empty.
    if !state.streaming_buffer.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("[Agent] ", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
            Span::raw(state.streaming_buffer.clone()),
            Span::styled("\u{2588}", Style::default().fg(Color::Green)),
        ]));
    }

    let chat = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Chat ")
                .borders(Borders::ALL)
                .border_style(border_style),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(chat, area);
}

fn render_tool_output(frame: &mut Frame, state: &AppState, area: Rect) {
    let focused = state.focused_panel == Panel::ToolOutput;
    let border_style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let mut lines: Vec<Line> = Vec::new();
    for entry in &state.tool_log {
        let status = match entry.exit_code {
            Some(0) => "ok",
            Some(_) => "err",
            None    => "...",
        };
        let duration = entry
            .completed
            .map(|c| format!("{:.1}s", (c - entry.started).as_secs_f64()))
            .unwrap_or_else(|| format!("{:.1}s", entry.started.elapsed().as_secs_f64()));

        lines.push(Line::from(vec![
            Span::styled(
                format!("[{}] {}", status, entry.name),
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(" ({})", duration)),
        ]));
        lines.push(Line::from(format!("  {}", entry.args)));
        if let Some(ref output) = entry.output {
            for line in output.lines().take(3) {
                lines.push(Line::from(format!("  {line}")));
            }
        }
        lines.push(Line::default());
    }

    let panel = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Tools ")
                .borders(Borders::ALL)
                .border_style(border_style),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(panel, area);
}

fn render_findings(frame: &mut Frame, state: &AppState, area: Rect) {
    let focused = state.focused_panel == Panel::Findings;
    let border_style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let rows: Vec<Row> = state
        .findings
        .iter()
        .map(|f| {
            let sev_color = match f.severity {
                sigint_core::types::Severity::Critical => Color::Red,
                sigint_core::types::Severity::High     => Color::LightRed,
                sigint_core::types::Severity::Medium   => Color::Yellow,
                sigint_core::types::Severity::Low      => Color::Blue,
                sigint_core::types::Severity::Info     => Color::Gray,
            };
            Row::new(vec![
                Cell::from(f.severity.to_string())
                    .style(Style::default().fg(sev_color)),
                Cell::from(f.title.clone()),
                Cell::from(f.asset.clone().unwrap_or_default()),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Min(20),
            Constraint::Length(20),
        ],
    )
    .header(
        Row::new(["SEV", "TITLE", "ASSET"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .title(" Findings ")
            .borders(Borders::ALL)
            .border_style(border_style),
    );

    frame.render_widget(table, area);
}

fn render_input(frame: &mut Frame, state: &AppState, area: Rect) {
    let focused = state.focused_panel == Panel::Input;
    let border_style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let prefix = match &state.mode {
        Mode::Normal      => "> ",
        Mode::Search(_)   => "/",
        Mode::Command(_)  => ":",
    };

    let input = Paragraph::new(format!("{prefix}{}", state.input))
        .block(
            Block::default()
                .title(" Input ")
                .borders(Borders::ALL)
                .border_style(border_style),
        );

    frame.render_widget(input, area);
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
        // Must not panic; renders "terminal too small" message path.
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
    fn render_with_findings_does_not_panic() {
        use sigint_core::types::{Finding, Severity};
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AppState::new();
        let sid = uuid::Uuid::new_v4();
        state.findings.push(Finding::new(sid, "Open port 22", "SSH exposed", Severity::Medium));
        state.findings.push(Finding::new(sid, "XSS", "reflected", Severity::High));
        terminal.draw(|frame| render(frame, &state)).unwrap();
    }
}
