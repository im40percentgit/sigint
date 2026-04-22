//! Findings view — all findings across sessions with detail pane.
//!
//! Top pane: findings table (j/k to navigate, severity coloring, diff styling).
//! Bottom pane: detail for the selected finding (description, evidence, remediation).

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap};
use ratatui::Frame;

use crate::state::{AppState, Panel};
use crate::ui::scan::severity_color;

/// Render the Findings view into `area`.
pub fn render(frame: &mut Frame, state: &AppState, area: Rect) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    render_finding_table(frame, state, layout[0]);
    render_finding_detail(frame, state, layout[1]);
}

fn render_finding_table(frame: &mut Frame, state: &AppState, area: Rect) {
    let focused = state.focused_panel == Panel::FindingList;
    let border_style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let rows: Vec<Row> = state
        .finding_list
        .iter()
        .enumerate()
        .map(|(i, f)| {
            let sev_color = severity_color(f.severity.clone());
            let mut row = Row::new(vec![
                Cell::from(f.severity.to_string()).style(Style::default().fg(sev_color)),
                Cell::from(f.title.clone()),
                Cell::from(f.asset.clone().unwrap_or_default()),
                Cell::from(
                    f.chain_id
                        .map(|id| format!("chain:{}", &id.to_string()[..4]))
                        .unwrap_or_default(),
                ),
            ]);
            if i == state.selected_finding_idx {
                row = row.style(
                    Style::default()
                        .bg(Color::DarkGray)
                        .add_modifier(Modifier::BOLD),
                );
            }
            row
        })
        .collect();

    let title = format!(" Findings ({}) ", state.finding_list.len());
    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Min(20),
            Constraint::Length(18),
            Constraint::Length(12),
        ],
    )
    .header(
        Row::new(["SEV", "TITLE", "ASSET", "CHAIN"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_style(border_style),
    );

    frame.render_widget(table, area);
}

fn render_finding_detail(frame: &mut Frame, state: &AppState, area: Rect) {
    let focused = state.focused_panel == Panel::FindingDetail;
    let border_style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let finding = state
        .finding_detail
        .finding
        .as_ref()
        .or_else(|| state.finding_list.get(state.selected_finding_idx));

    let Some(f) = finding else {
        let placeholder = Paragraph::new("No finding selected — press j/k to navigate")
            .style(Style::default().fg(Color::DarkGray))
            .block(
                Block::default()
                    .title(" Detail ")
                    .borders(Borders::ALL)
                    .border_style(border_style),
            );
        frame.render_widget(placeholder, area);
        return;
    };

    let sev_color = severity_color(f.severity.clone());

    let mut lines: Vec<Line> = vec![
        Line::from(vec![
            Span::styled("Title:  ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(f.title.clone()),
        ]),
        Line::from(vec![
            Span::styled("Sev:    ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(
                f.severity.to_string(),
                Style::default().fg(sev_color).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Asset:  ", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(f.asset.clone().unwrap_or_else(|| "-".into())),
        ]),
        Line::default(),
        Line::from(Span::styled(
            "Description:",
            Style::default().add_modifier(Modifier::BOLD),
        )),
    ];

    for line in f.description.lines() {
        lines.push(Line::from(format!("  {line}")));
    }

    if let Some(ref rem) = f.remediation {
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            "Remediation:",
            Style::default().add_modifier(Modifier::BOLD),
        )));
        for line in rem.lines() {
            lines.push(Line::from(format!("  {line}")));
        }
    }

    if let Some(ref ev) = f.evidence {
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            "Evidence:",
            Style::default().add_modifier(Modifier::BOLD),
        )));
        for line in ev.lines().take(5) {
            lines.push(Line::from(format!("  {line}")));
        }
    }

    if let Some(chain_id) = f.chain_id {
        lines.push(Line::default());
        lines.push(Line::from(vec![
            Span::styled("Chain:  ", Style::default().add_modifier(Modifier::BOLD)),
            Span::styled(chain_id.to_string(), Style::default().fg(Color::Magenta)),
            Span::raw(format!(
                " (step {})",
                f.chain_order
                    .map(|o| o.to_string())
                    .unwrap_or_else(|| "?".into())
            )),
        ]));
    }

    let panel = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Detail ")
                .borders(Borders::ALL)
                .border_style(border_style),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(panel, area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppState;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn render_empty_findings_view_does_not_panic() {
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let state = AppState::new();
        terminal
            .draw(|frame| render(frame, &state, frame.area()))
            .unwrap();
    }

    #[test]
    fn render_findings_with_selection_does_not_panic() {
        use sigint_core::types::{Finding, Severity};
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AppState::new();
        let sid = uuid::Uuid::new_v4();
        state.finding_list = vec![
            Finding::new(sid, "SQL Injection", "union-based", Severity::Critical),
            Finding::new(sid, "XSS", "reflected", Severity::High),
            Finding::new(sid, "Info Leak", "banner disclosure", Severity::Low),
        ];
        state.selected_finding_idx = 1;
        terminal
            .draw(|frame| render(frame, &state, frame.area()))
            .unwrap();
    }

    #[test]
    fn render_finding_detail_with_all_fields_does_not_panic() {
        use crate::state::FindingDetailData;
        use sigint_core::types::{Finding, Severity};
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AppState::new();
        let sid = uuid::Uuid::new_v4();
        let chain_id = uuid::Uuid::new_v4();
        let mut f = Finding::new(sid, "SQLi", "union-based injection", Severity::Critical);
        f.remediation = Some("Use parameterized queries".into());
        f.evidence = Some("GET /search?q=1' UNION SELECT...".into());
        f.chain_id = Some(chain_id);
        f.chain_order = Some(2);
        state.finding_detail = FindingDetailData { finding: Some(f) };
        terminal
            .draw(|frame| render(frame, &state, frame.area()))
            .unwrap();
    }

    #[test]
    fn render_all_severity_colors_do_not_panic() {
        use sigint_core::types::{Finding, Severity};
        let backend = TestBackend::new(120, 30);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AppState::new();
        let sid = uuid::Uuid::new_v4();
        for sev in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ] {
            state
                .finding_list
                .push(Finding::new(sid, "test", "desc", sev));
        }
        terminal
            .draw(|frame| render(frame, &state, frame.area()))
            .unwrap();
    }
}
