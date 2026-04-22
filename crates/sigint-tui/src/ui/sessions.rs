//! Sessions view — historical session list with per-session message replay.
//!
//! Left pane: session list (j/k to navigate, Enter to load detail).
//! Right pane: message history for the selected session.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap};
use ratatui::Frame;

use crate::state::{AppState, Panel};

/// Render the Sessions view into `area`.
pub fn render(frame: &mut Frame, state: &AppState, area: Rect) {
    let layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(35), Constraint::Percentage(65)])
        .split(area);

    render_session_list(frame, state, layout[0]);
    render_session_detail(frame, state, layout[1]);
}

fn render_session_list(frame: &mut Frame, state: &AppState, area: Rect) {
    let focused = state.focused_panel == Panel::SessionList;
    let border_style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let rows: Vec<Row> = state
        .session_list
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let row = Row::new(vec![
                Cell::from(s.id.to_string()[..8].to_string()),
                Cell::from(s.target.clone().unwrap_or_else(|| "-".into())),
                Cell::from(s.created_at.format("%m-%d %H:%M").to_string()),
            ]);
            if i == state.selected_session_idx {
                row.style(
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )
            } else {
                row
            }
        })
        .collect();

    let title = format!(" Sessions ({}) ", state.session_list.len());
    let table = Table::new(
        rows,
        [
            Constraint::Length(9),
            Constraint::Min(14),
            Constraint::Length(12),
        ],
    )
    .header(Row::new(["ID", "TARGET", "DATE"]).style(Style::default().add_modifier(Modifier::BOLD)))
    .block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(border_style),
    );

    frame.render_widget(table, area);
}

fn render_session_detail(frame: &mut Frame, state: &AppState, area: Rect) {
    let focused = state.focused_panel == Panel::SessionDetail;
    let border_style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let detail = &state.session_detail;

    let title = match &detail.session {
        Some(s) => format!(
            " {} — {} ",
            s.name,
            s.target.as_deref().unwrap_or("no target")
        ),
        None => " Select a session ".to_string(),
    };

    if detail.messages.is_empty() && detail.session.is_none() {
        let placeholder = Paragraph::new("Press Enter on a session to load its history")
            .style(Style::default().fg(Color::DarkGray))
            .block(
                Block::default()
                    .title(title)
                    .borders(Borders::ALL)
                    .border_style(border_style),
            );
        frame.render_widget(placeholder, area);
        return;
    }

    let mut lines: Vec<Line> = Vec::new();
    for msg in &detail.messages {
        let (prefix, color) = match msg.role.as_str() {
            "user" => ("[User] ", Color::Blue),
            "assistant" => ("[Agent] ", Color::Green),
            "thinking" => ("[Think] ", Color::Gray),
            "system" => ("[Sys] ", Color::DarkGray),
            _ => ("", Color::White),
        };
        for (i, text_line) in msg.content.split('\n').enumerate() {
            if i == 0 {
                lines.push(Line::from(vec![
                    Span::styled(
                        prefix,
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(text_line.to_string()),
                ]));
            } else {
                lines.push(Line::from(Span::raw(text_line.to_string())));
            }
        }
    }

    let scroll_up = state
        .scroll_offsets
        .get(&Panel::SessionDetail)
        .copied()
        .unwrap_or(0);
    let inner_height = area.height.saturating_sub(2) as usize;
    let bottom = lines.len().saturating_sub(inner_height);
    let vertical = if scroll_up == 0 {
        bottom as u16
    } else {
        bottom.saturating_sub(scroll_up) as u16
    };

    let panel = Paragraph::new(lines)
        .block(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(border_style),
        )
        .wrap(Wrap { trim: false })
        .scroll((vertical, 0));

    frame.render_widget(panel, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{AppState, DisplayMessage, SessionDetail};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn render_empty_sessions_does_not_panic() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let state = AppState::new();
        terminal
            .draw(|frame| render(frame, &state, frame.area()))
            .unwrap();
    }

    #[test]
    fn render_session_list_with_selection_does_not_panic() {
        use sigint_core::types::Session;

        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AppState::new();
        state.session_list = vec![
            Session::new("scan-a").with_target("10.0.0.1"),
            Session::new("scan-b").with_target("example.com"),
        ];
        state.selected_session_idx = 1;
        terminal
            .draw(|frame| render(frame, &state, frame.area()))
            .unwrap();
    }

    #[test]
    fn render_session_detail_with_messages_does_not_panic() {
        use sigint_core::types::Session;

        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AppState::new();
        state.session_detail = SessionDetail {
            session: Some(Session::new("scan-example").with_target("example.com")),
            messages: vec![
                DisplayMessage {
                    role: "user".into(),
                    content: "scan example.com".into(),
                },
                DisplayMessage {
                    role: "assistant".into(),
                    content: "Running nmap...".into(),
                },
            ],
            tool_summaries: vec!["nmap_scan (ok, 2.3s)".into()],
        };
        terminal
            .draw(|frame| render(frame, &state, frame.area()))
            .unwrap();
    }
}
