//! Settings view — TUI-local overrides display and editing.
//!
//! Shows a read-only summary of the active config alongside editable
//! TuiSettings fields. Changes take effect immediately without touching
//! the Arc<Config> (see DEC-P21-SETTINGS-001).

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::state::AppState;

/// Render the Settings view into `area`.
pub fn render(frame: &mut Frame, state: &AppState, area: Rect) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    render_tui_settings(frame, state, layout[0]);
    render_settings_help(frame, layout[1]);
}

fn render_tui_settings(frame: &mut Frame, state: &AppState, area: Rect) {
    let s = &state.tui_settings;

    let lines = vec![
        Line::from(Span::styled(
            "TUI Settings",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::default(),
        setting_row(
            "auto_approve_low",
            &bool_display(s.auto_approve_low),
            "Auto-approve Low-risk tool calls without prompting",
        ),
        setting_row(
            "show_reasoning  ",
            &bool_display(s.show_reasoning),
            "Show agent <think> blocks in the Chat panel",
        ),
        setting_row(
            "tool_output_lines",
            &s.tool_output_lines.to_string(),
            "Lines of tool output shown per entry in Tools panel",
        ),
        Line::default(),
        Line::from(Span::styled(
            "Use  :set <key> <value>  to change settings.",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(Span::styled(
            "Example:  :set show_reasoning false",
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let panel = Paragraph::new(lines).block(
        Block::default()
            .title(" TUI Settings ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan)),
    );

    frame.render_widget(panel, area);
}

fn render_settings_help(frame: &mut Frame, area: Rect) {
    let lines = vec![
        Line::from(Span::styled(
            "Keybindings",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::default(),
        Line::from("  1–6    Switch view"),
        Line::from("  Tab    Cycle panel focus"),
        Line::from("  j/k    Scroll up/down"),
        Line::from("  G      Jump to bottom"),
        Line::from("  /      Search mode"),
        Line::from("  :      Command mode"),
        Line::from("  ?      Toggle help overlay"),
        Line::from("  q      Quit"),
        Line::default(),
        Line::from(Span::styled(
            "Commands",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )),
        Line::default(),
        Line::from("  :q / :quit               Quit"),
        Line::from("  :scan <target>           Start a new scan"),
        Line::from("  :set <key> <value>       Change TUI setting"),
        Line::from("  :session <prefix>        Jump to session"),
        Line::from("  :report [session_id]     Generate report"),
    ];

    let panel = Paragraph::new(lines).block(
        Block::default()
            .title(" Help & Commands ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    frame.render_widget(panel, area);
}

fn setting_row<'a>(key: &'a str, value: &str, desc: &'a str) -> Line<'a> {
    Line::from(vec![
        Span::styled(
            format!("  {key}  "),
            Style::default().add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("{:<8}", value),
            Style::default().fg(Color::Yellow),
        ),
        Span::styled(format!("  {desc}"), Style::default().fg(Color::DarkGray)),
    ])
}

fn bool_display(v: bool) -> String {
    if v { "true".into() } else { "false".into() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppState;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn render_settings_default_does_not_panic() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let state = AppState::new();
        terminal
            .draw(|frame| render(frame, &state, frame.area()))
            .unwrap();
    }

    #[test]
    fn render_settings_with_overrides_does_not_panic() {
        use crate::state::TuiSettings;

        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AppState::new();
        state.tui_settings = TuiSettings {
            auto_approve_low: true,
            show_reasoning: false,
            tool_output_lines: 10,
        };
        terminal
            .draw(|frame| render(frame, &state, frame.area()))
            .unwrap();
    }
}
