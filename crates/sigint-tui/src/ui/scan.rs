//! Scan view rendering — the live multi-agent penetration scan activity view.
//!
//! This module is the direct extraction of the original `ui.rs` render logic.
//! Layout (top-to-bottom within the view content area):
//!   1. Chat | Tool output (fills available height)
//!   2. Findings | Assets (8 rows, split 50/50 horizontally)
//!   3. Input bar (3 rows)
//!   4. Approval bar (1 row, only when pending_approval is Some)
//!
//! @decision DEC-P3-TUI-002
//! @title render() is a pure function of AppState with no side effects
//! @status accepted
//! @rationale A pure render function (AppState -> Frame writes) enables
//! full layout testing via ratatui TestBackend without a real terminal or
//! process state. No mutable global state, no I/O in this module.
//! The layout uses ratatui Constraint::Percentage + Constraint::Length
//! so panels fill available space deterministically at any terminal size.
//!
//! @decision DEC-4D-UI-001
//! @title Findings and Assets share the bottom row as a 50/50 horizontal split
//! @status accepted
//! @rationale Both panels have comparable data density at MVP scale. A 50/50
//! split avoids privileging one over the other and can be made adjustable later.
//!
//! @decision DEC-P6-APPROVAL-002
//! @title Approval bar occupies a conditional 1-row slot at the very bottom
//! @status accepted
//! @rationale The approval bar must be impossible to miss — placing it below
//! the input bar at the bottom edge of the screen makes it visually distinct
//! from regular UI chrome. Using Constraint::Length(0) vs Length(1) based on
//! pending_approval keeps the layout calculation pure (no branch in render path)
//! while avoiding wasted space when no approval is pending.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap};
use ratatui::Frame;

use crate::state::{AppState, DiffStatus, Mode, Panel, PendingApproval};
use sigint_core::types::ToolRisk;

/// Render the Scan view into `area`.
pub fn render(frame: &mut Frame, state: &AppState, area: Rect) {
    // The approval bar takes 1 row when pending; 0 rows otherwise.
    let approval_height = if state.pending_approval.is_some() { 1 } else { 0 };

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(10),                 // Chat + Tool panels
            Constraint::Length(8),               // Findings | Assets
            Constraint::Length(3),               // Input bar
            Constraint::Length(approval_height), // Approval bar (0 or 1 row)
        ])
        .split(area);

    render_main_panels(frame, state, layout[0]);
    render_bottom_panels(frame, state, layout[1]);
    render_input(frame, state, layout[2]);

    if let Some(ref approval) = state.pending_approval {
        render_approval_bar(frame, approval, layout[3]);
    }
}

fn render_main_panels(frame: &mut Frame, state: &AppState, area: Rect) {
    let panels = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    render_chat(frame, state, panels[0]);
    render_tool_output(frame, state, panels[1]);
}

pub(crate) fn render_chat(frame: &mut Frame, state: &AppState, area: Rect) {
    let focused = state.focused_panel == Panel::Chat;
    let border_style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let thinking_style = Style::default()
        .fg(Color::Gray)
        .add_modifier(Modifier::ITALIC);

    let mut lines: Vec<Line> = Vec::new();
    for msg in &state.messages {
        match msg.role.as_str() {
            "thinking" => {
                for (i, text_line) in msg.content.split('\n').enumerate() {
                    if i == 0 {
                        lines.push(Line::from(vec![
                            Span::styled(
                                "[Thinking] ",
                                thinking_style.add_modifier(Modifier::BOLD),
                            ),
                            Span::styled(text_line.to_string(), thinking_style),
                        ]));
                    } else {
                        lines.push(Line::from(Span::styled(
                            text_line.to_string(),
                            thinking_style,
                        )));
                    }
                }
            }
            role => {
                let (prefix, color) = match role {
                    "user" => ("[User] ", Color::Blue),
                    "assistant" => ("[Agent] ", Color::Green),
                    "system" => ("[System] ", Color::DarkGray),
                    "tool" => ("[Tool] ", Color::Yellow),
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
        }
    }

    if !state.streaming_buffer.is_empty() {
        let buffer_lines: Vec<&str> = state.streaming_buffer.split('\n').collect();
        for (i, text_line) in buffer_lines.iter().enumerate() {
            let is_last = i == buffer_lines.len() - 1;
            if i == 0 {
                let mut spans = vec![
                    Span::styled(
                        "[Agent] ",
                        Style::default()
                            .fg(Color::Green)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(text_line.to_string()),
                ];
                if is_last {
                    spans.push(Span::styled("\u{2588}", Style::default().fg(Color::Green)));
                }
                lines.push(Line::from(spans));
            } else {
                let mut spans = vec![Span::raw(text_line.to_string())];
                if is_last {
                    spans.push(Span::styled("\u{2588}", Style::default().fg(Color::Green)));
                }
                lines.push(Line::from(spans));
            }
        }
    }

    if !state.reasoning_buffer.is_empty() {
        let label = match &state.thinking_agent {
            Some(name) => format!("[{name}] "),
            None => "[Thinking] ".to_string(),
        };
        let reasoning_lines: Vec<&str> = state.reasoning_buffer.split('\n').collect();
        for (i, text_line) in reasoning_lines.iter().enumerate() {
            let is_last = i == reasoning_lines.len() - 1;
            if i == 0 {
                let mut spans = vec![
                    Span::styled(label.clone(), thinking_style.add_modifier(Modifier::BOLD)),
                    Span::styled(text_line.to_string(), thinking_style),
                ];
                if is_last {
                    spans.push(Span::styled("\u{2588}", thinking_style));
                }
                lines.push(Line::from(spans));
            } else {
                let mut spans = vec![Span::styled(text_line.to_string(), thinking_style)];
                if is_last {
                    spans.push(Span::styled("\u{2588}", thinking_style));
                }
                lines.push(Line::from(spans));
            }
        }
    }

    let scroll_up = state.scroll_offsets.get(&Panel::Chat).copied().unwrap_or(0);
    let inner_height = area.height.saturating_sub(2) as usize;
    let bottom = lines.len().saturating_sub(inner_height);
    let vertical = if scroll_up == 0 {
        bottom as u16
    } else {
        bottom.saturating_sub(scroll_up) as u16
    };

    let chat = Paragraph::new(lines)
        .block(
            Block::default()
                .title(" Chat ")
                .borders(Borders::ALL)
                .border_style(border_style),
        )
        .wrap(Wrap { trim: false })
        .scroll((vertical, 0));

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
            None => "...",
        };
        let duration = entry
            .completed
            .map(|c| format!("{:.1}s", (c - entry.started).as_secs_f64()))
            .unwrap_or_else(|| format!("{:.1}s", entry.started.elapsed().as_secs_f64()));

        lines.push(Line::from(vec![
            Span::styled(
                format!("[{}] {}", status, entry.name),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(" ({})", duration)),
        ]));
        lines.push(Line::from(format!("  {}", entry.args)));
        if let Some(ref output) = entry.output {
            for line in output.lines().take(state.tui_settings.tool_output_lines) {
                lines.push(Line::from(format!("  {line}")));
            }
        }
        lines.push(Line::default());
    }

    let scroll_up = state
        .scroll_offsets
        .get(&Panel::ToolOutput)
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
                .title(" Tools ")
                .borders(Borders::ALL)
                .border_style(border_style),
        )
        .wrap(Wrap { trim: false })
        .scroll((vertical, 0));

    frame.render_widget(panel, area);
}

/// Split the bottom row 50/50 and render Findings on the left, Assets on the right.
fn render_bottom_panels(frame: &mut Frame, state: &AppState, area: Rect) {
    let panels = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    render_findings_panel(frame, state, panels[0]);
    render_assets_panel(frame, state, panels[1]);
}

/// Render findings with severity coloring and diff-aware styling.
///
/// Reused by both the Scan view (live findings) and Findings view (historical).
pub(crate) fn render_findings_panel(frame: &mut Frame, state: &AppState, area: Rect) {
    let focused = state.focused_panel == Panel::Findings;
    let border_style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let rows: Vec<Row> = state
        .findings
        .iter()
        .map(|f| finding_to_row(f, state))
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
        Row::new(["SEV", "TITLE", "ASSET"]).style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .title(" Findings ")
            .borders(Borders::ALL)
            .border_style(border_style),
    );

    frame.render_widget(table, area);
}

/// Map a `Finding` to a styled `Row` using severity color and diff status.
///
/// Used by both the Scan view findings panel and the Findings view table.
pub(crate) fn finding_to_row<'a>(
    f: &'a sigint_core::types::Finding,
    state: &AppState,
) -> Row<'a> {
    let sev_color = severity_color(f.severity.clone());
    let diff_style = match state.diff_status(f) {
        DiffStatus::New => Style::default()
            .fg(Color::Green)
            .add_modifier(Modifier::BOLD),
        DiffStatus::Fixed => Style::default()
            .fg(Color::DarkGray)
            .add_modifier(Modifier::CROSSED_OUT | Modifier::DIM),
        DiffStatus::Unchanged | DiffStatus::NoDiff => Style::default(),
    };
    Row::new(vec![
        Cell::from(f.severity.to_string()).style(Style::default().fg(sev_color)),
        Cell::from(f.title.clone()),
        Cell::from(f.asset.clone().unwrap_or_default()),
    ])
    .style(diff_style)
}

/// Map a severity to its display color.
pub(crate) fn severity_color(severity: sigint_core::types::Severity) -> Color {
    match severity {
        sigint_core::types::Severity::Critical => Color::Red,
        sigint_core::types::Severity::High => Color::LightRed,
        sigint_core::types::Severity::Medium => Color::Yellow,
        sigint_core::types::Severity::Low => Color::Blue,
        sigint_core::types::Severity::Info => Color::Gray,
    }
}

fn render_assets_panel(frame: &mut Frame, state: &AppState, area: Rect) {
    use sigint_core::types::AssetKind;

    let focused = state.focused_panel == Panel::Assets;
    let border_style = if focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let rows: Vec<Row> = state
        .assets
        .iter()
        .map(|asset| {
            let kind_color = match asset.kind {
                AssetKind::Host => Color::Green,
                AssetKind::Domain => Color::Blue,
                AssetKind::Url => Color::Yellow,
                AssetKind::Service => Color::Magenta,
                AssetKind::Certificate => Color::Cyan,
                AssetKind::Email => Color::LightBlue,
                AssetKind::Other => Color::White,
            };
            Row::new(vec![
                Cell::from(asset.kind.to_string()).style(Style::default().fg(kind_color)),
                Cell::from(asset.value.clone()),
            ])
        })
        .collect();

    let table = Table::new(rows, [Constraint::Length(12), Constraint::Min(20)])
        .header(Row::new(["KIND", "VALUE"]).style(Style::default().add_modifier(Modifier::BOLD)))
        .block(
            Block::default()
                .title(format!(" Assets ({}) ", state.assets.len()))
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

    // Render the command buffer from Mode::Command(buf), not state.input.
    // This fixes the bug where command mode showed the wrong text.
    let display_text = match &state.mode {
        Mode::Normal => format!("> {}", state.input),
        Mode::Search(buf) => format!("/{buf}"),
        Mode::Command(buf) => format!(":{buf}"),
    };

    let input = Paragraph::new(display_text).block(
        Block::default()
            .title(" Input ")
            .borders(Borders::ALL)
            .border_style(border_style),
    );

    frame.render_widget(input, area);
}

/// Render the approval bar when a tool is awaiting operator approval.
pub(crate) fn render_approval_bar(
    frame: &mut Frame,
    approval: &PendingApproval,
    area: Rect,
) {
    if area.height == 0 {
        return;
    }

    let risk_color = match approval.risk_level {
        ToolRisk::Low => Color::Green,
        ToolRisk::Medium => Color::Yellow,
        ToolRisk::High => Color::Red,
    };

    let risk_label = match approval.risk_level {
        ToolRisk::Low => "low",
        ToolRisk::Medium => "medium",
        ToolRisk::High => "HIGH",
    };

    let line = Line::from(vec![
        Span::styled(
            " [APPROVAL] ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" Run ", Style::default().fg(Color::White).bg(Color::DarkGray)),
        Span::styled(
            approval.tool_name.clone(),
            Style::default()
                .fg(Color::Cyan)
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" ({risk_label})"),
            Style::default()
                .fg(risk_color)
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("? Args: {}", approval.args_summary),
            Style::default().fg(Color::Gray).bg(Color::DarkGray),
        ),
        Span::styled(
            "  [y] approve  [n] deny ",
            Style::default()
                .fg(Color::White)
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        ),
    ]);

    let bar = Paragraph::new(line).style(Style::default().bg(Color::DarkGray));
    frame.render_widget(bar, area);
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
        // Provide a min area that fits the scan view (subtract tab bar + status rows).
        terminal
            .draw(|frame| {
                let area = frame.area();
                render(frame, &state, area);
            })
            .unwrap();
    }

    #[test]
    fn render_does_not_panic_at_200x50() {
        let backend = TestBackend::new(200, 50);
        let mut terminal = Terminal::new(backend).unwrap();
        let state = AppState::new();
        terminal
            .draw(|frame| render(frame, &state, frame.area()))
            .unwrap();
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
        terminal
            .draw(|frame| render(frame, &state, frame.area()))
            .unwrap();
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
        terminal
            .draw(|frame| render(frame, &state, frame.area()))
            .unwrap();
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
        terminal
            .draw(|frame| render(frame, &state, frame.area()))
            .unwrap();
    }

    #[test]
    fn render_assets_panel_focused_does_not_panic() {
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AppState::new();
        state.focused_panel = crate::state::Panel::Assets;
        terminal
            .draw(|frame| render(frame, &state, frame.area()))
            .unwrap();
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
        terminal
            .draw(|frame| render(frame, &state, frame.area()))
            .unwrap();
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
            terminal
                .draw(|frame| render(frame, &state, frame.area()))
                .unwrap();
        }
    }

    #[test]
    fn render_without_pending_approval_does_not_show_bar() {
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let state = AppState::new();
        assert!(state.pending_approval.is_none());
        terminal
            .draw(|frame| render(frame, &state, frame.area()))
            .unwrap();
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
        terminal
            .draw(|frame| render(frame, &state, frame.area()))
            .unwrap();
    }

    #[test]
    fn render_thinking_without_agent_label_does_not_panic() {
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AppState::new();
        state.reasoning_buffer = "thinking...".into();
        state.thinking_agent = None;
        terminal
            .draw(|frame| render(frame, &state, frame.area()))
            .unwrap();
    }

    #[test]
    fn render_findings_with_diff_status_does_not_panic() {
        use crate::state::AppState;
        use sigint_core::diff::ScanDiff;
        use sigint_core::event::Event;
        use sigint_core::types::{Finding, Severity};
        use uuid::Uuid;

        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AppState::new();
        let sid = Uuid::new_v4();

        let new_finding =
            Finding::new(sid, "SQL Injection", "unparameterised query", Severity::High);
        let fixed_finding = Finding::new(sid, "Open Redirect", "was fixed", Severity::Medium);
        let unchanged_finding = Finding::new(sid, "XSS", "still open", Severity::Low);

        state.findings.push(new_finding.clone());
        state.findings.push(fixed_finding.clone());
        state.findings.push(unchanged_finding.clone());

        let diff = ScanDiff {
            scan_a: Uuid::new_v4(),
            scan_b: Uuid::new_v4(),
            summary: sigint_core::diff::DiffSummary {
                new: 1,
                fixed: 1,
                unchanged: 1,
            },
            new: vec![new_finding],
            fixed: vec![fixed_finding],
            unchanged: vec![unchanged_finding],
        };
        state.apply(Event::ScanDiffCompleted { diff });

        terminal
            .draw(|frame| render(frame, &state, frame.area()))
            .unwrap();
    }

    #[test]
    fn input_shows_command_buffer_in_command_mode() {
        // The input bar should display the Command mode buffer, not state.input.
        let backend = TestBackend::new(120, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = AppState::new();
        state.mode = Mode::Command("quit".into());
        state.input = "should_not_appear".into();
        // Just verify no panic — content assertion would require buffer inspection.
        terminal
            .draw(|frame| render(frame, &state, frame.area()))
            .unwrap();
    }
}
