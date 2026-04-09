//! Dashboard view — aggregate stats and recent session activity.
//!
//! Renders stat cards (session count, findings by severity, asset count)
//! and a recent sessions table. Data is populated by TuiApp from DB queries
//! on view activation and stored in `state.dashboard`.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table};
use ratatui::Frame;

use crate::state::AppState;

/// Render the Dashboard view into `area`.
pub fn render(frame: &mut Frame, state: &AppState, area: Rect) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5), // Stat cards row
            Constraint::Min(8),    // Recent sessions table
        ])
        .split(area);

    render_stat_cards(frame, state, layout[0]);
    render_recent_sessions(frame, state, layout[1]);
}

fn render_stat_cards(frame: &mut Frame, state: &AppState, area: Rect) {
    let cards = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(20), // Sessions
            Constraint::Percentage(16), // Critical
            Constraint::Percentage(16), // High
            Constraint::Percentage(16), // Medium
            Constraint::Percentage(16), // Low
            Constraint::Percentage(16), // Assets
        ])
        .split(area);

    let d = &state.dashboard;

    render_stat_card(
        frame,
        " Sessions ",
        &d.total_sessions.to_string(),
        Color::Cyan,
        cards[0],
    );
    render_stat_card(
        frame,
        " Critical ",
        &d.critical_count.to_string(),
        Color::Red,
        cards[1],
    );
    render_stat_card(
        frame,
        " High ",
        &d.high_count.to_string(),
        Color::LightRed,
        cards[2],
    );
    render_stat_card(
        frame,
        " Medium ",
        &d.medium_count.to_string(),
        Color::Yellow,
        cards[3],
    );
    render_stat_card(
        frame,
        " Low ",
        &d.low_count.to_string(),
        Color::Blue,
        cards[4],
    );
    render_stat_card(
        frame,
        " Assets ",
        &d.total_assets.to_string(),
        Color::Green,
        cards[5],
    );
}

fn render_stat_card(frame: &mut Frame, title: &str, value: &str, color: Color, area: Rect) {
    let content = Paragraph::new(Line::from(vec![Span::styled(
        value.to_string(),
        Style::default()
            .fg(color)
            .add_modifier(Modifier::BOLD),
    )]))
    .block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(content, area);
}

fn render_recent_sessions(frame: &mut Frame, state: &AppState, area: Rect) {
    let rows: Vec<Row> = state
        .dashboard
        .recent_sessions
        .iter()
        .map(|s| {
            Row::new(vec![
                Cell::from(s.id.to_string()[..8].to_string()),
                Cell::from(s.name.clone()),
                Cell::from(s.target.clone().unwrap_or_else(|| "-".into())),
                Cell::from(s.created_at.format("%Y-%m-%d %H:%M").to_string()),
            ])
        })
        .collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Min(20),
            Constraint::Length(20),
            Constraint::Length(17),
        ],
    )
    .header(
        Row::new(["ID", "NAME", "TARGET", "CREATED"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .title(" Recent Sessions ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    frame.render_widget(table, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{AppState, DashboardData};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn render_empty_dashboard_does_not_panic() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let state = AppState::new();
        terminal
            .draw(|frame| render(frame, &state, frame.area()))
            .unwrap();
    }

    #[test]
    fn render_populated_dashboard_does_not_panic() {
        use sigint_core::types::Session;

        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AppState::new();
        state.dashboard = DashboardData {
            total_sessions: 5,
            total_findings: 12,
            critical_count: 1,
            high_count: 3,
            medium_count: 5,
            low_count: 3,
            total_assets: 18,
            recent_sessions: vec![
                Session::new("scan-example.com-20260408").with_target("example.com"),
                Session::new("scan-10.0.0.1-20260407").with_target("10.0.0.1"),
            ],
        };
        terminal
            .draw(|frame| render(frame, &state, frame.area()))
            .unwrap();
    }

    #[test]
    fn render_dashboard_at_minimum_size() {
        let backend = TestBackend::new(80, 15);
        let mut terminal = Terminal::new(backend).unwrap();
        let state = AppState::new();
        terminal
            .draw(|frame| render(frame, &state, frame.area()))
            .unwrap();
    }
}
