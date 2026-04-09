//! Shared TUI widgets used across multiple views.
//!
//! `render_tab_bar` draws the 6-tab navigation bar at the top of every view.
//! `scroll_indicator` formats a `[line/total]` string for panel borders.

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

use crate::state::View;

/// Render the six-tab navigation bar occupying `area`.
///
/// The active tab is highlighted in cyan+bold; inactive tabs are dim gray.
/// Number hints (1–6) appear as a prefix so the keybindings are self-documenting.
pub fn render_tab_bar(frame: &mut Frame, current_view: View, area: Rect) {
    let tabs = [
        (View::Scan, "1:Scan"),
        (View::Dashboard, "2:Dashboard"),
        (View::Sessions, "3:Sessions"),
        (View::Findings, "4:Findings"),
        (View::Reports, "5:Reports"),
        (View::Settings, "6:Settings"),
    ];

    let mut spans: Vec<Span> = Vec::new();
    for (i, (view, label)) in tabs.iter().enumerate() {
        if *view == current_view {
            spans.push(Span::styled(
                format!(" {label} "),
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ));
        } else {
            spans.push(Span::styled(
                format!(" {label} "),
                Style::default().fg(Color::DarkGray),
            ));
        }
        // Separator between tabs (not after the last one).
        if i < tabs.len() - 1 {
            spans.push(Span::styled("│", Style::default().fg(Color::DarkGray)));
        }
    }

    let bar = Paragraph::new(Line::from(spans)).style(Style::default().bg(Color::Black));
    frame.render_widget(bar, area);
}

/// Format a scroll position indicator string: `[current/total]`.
///
/// Used in panel border titles to show the user's scroll position.
/// Returns an empty string when `total` is 0 to avoid cluttering empty panels.
pub fn scroll_indicator(current_line: usize, total_lines: usize) -> String {
    if total_lines == 0 {
        String::new()
    } else {
        format!("[{}/{}]", current_line.min(total_lines), total_lines)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    #[test]
    fn tab_bar_renders_without_panic_for_each_view() {
        for view in [
            View::Scan,
            View::Dashboard,
            View::Sessions,
            View::Findings,
            View::Reports,
            View::Settings,
        ] {
            let backend = TestBackend::new(120, 2);
            let mut terminal = Terminal::new(backend).unwrap();
            terminal
                .draw(|frame| {
                    let area = frame.area();
                    render_tab_bar(frame, view, area);
                })
                .unwrap();
        }
    }

    #[test]
    fn scroll_indicator_formats_correctly() {
        assert_eq!(scroll_indicator(3, 24), "[3/24]");
        assert_eq!(scroll_indicator(0, 10), "[0/10]");
        assert_eq!(scroll_indicator(10, 10), "[10/10]");
    }

    #[test]
    fn scroll_indicator_empty_for_zero_total() {
        assert_eq!(scroll_indicator(0, 0), "");
        assert_eq!(scroll_indicator(5, 0), "");
    }

    #[test]
    fn scroll_indicator_clamps_at_total() {
        // current > total — clamp to total.
        assert_eq!(scroll_indicator(100, 24), "[24/24]");
    }
}
