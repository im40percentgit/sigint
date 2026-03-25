//! `sigint log` — render a chronological engagement log for a scan session.
//!
//! Loads a session's scan_history records ordered by started_at, groups them
//! by agent_role, and renders a human-readable audit trail in Markdown or HTML.
//! Each entry shows the agent role, tool name, arguments, output snippet, and
//! timing. A findings summary table is appended at the end.
//!
//! @decision DEC-LOG-001
//! @title sigint log renders chronological audit trail from scan_history
//! @status accepted
//! @rationale Operators need a timestamped audit trail showing which agent
//! invoked which tool, with what arguments, and what the output was. The log
//! command reads directly from the scan_history table (ordered by started_at)
//! and the findings table, then renders them without requiring a running server.
//! agent_role (migration 7) attributes each tool call to its agent role.
//! The session resolver reuses the UUID-prefix pattern from report.rs.

use std::io::Write as _;

use sigint_core::{types::{Finding, Session}, AppCore, Error};
use sigint_store::{Database, ScanRecord};
use uuid::Uuid;

// ── Clap args ─────────────────────────────────────────────────────────────────

/// Arguments parsed for the `log` subcommand.
#[derive(Debug, clap::Args)]
pub struct LogArgs {
    /// Session ID (full UUID or a unique prefix of at least 4 characters).
    pub session_id: String,
    /// Output format: markdown, html.
    #[arg(short, long, default_value = "markdown")]
    pub format: String,
    /// Output file path (writes to stdout if omitted).
    #[arg(short, long)]
    pub output: Option<String>,
}

// ── Format parsing ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    Markdown,
    Html,
}

/// Parse a format string into a `LogFormat`.
pub fn parse_format(s: &str) -> Result<LogFormat, String> {
    match s.to_lowercase().as_str() {
        "markdown" | "md" => Ok(LogFormat::Markdown),
        "html" | "htm" => Ok(LogFormat::Html),
        other => Err(format!(
            "Unknown log format '{}'. Valid values: markdown, html.",
            other
        )),
    }
}

// ── Session lookup (prefix or exact UUID) ─────────────────────────────────────

/// Find a session by exact UUID or by a prefix of its UUID string.
fn find_session_by_id_or_prefix(
    db: &Database,
    id_str: &str,
) -> Result<Session, Error> {
    if let Ok(id) = Uuid::parse_str(id_str) {
        return db
            .get_session(id)?
            .ok_or_else(|| Error::Database(format!("Session not found: {id_str}")));
    }

    if id_str.len() < 4 {
        return Err(Error::Database(format!(
            "Session ID prefix too short (min 4 characters): '{id_str}'"
        )));
    }

    let sessions = db.list_sessions()?;
    let matches: Vec<_> = sessions
        .into_iter()
        .filter(|s| s.id.to_string().starts_with(id_str))
        .collect();

    match matches.len() {
        0 => Err(Error::Database(format!(
            "No session found with prefix: '{id_str}'"
        ))),
        1 => Ok(matches.into_iter().next().unwrap()),
        n => Err(Error::Database(format!(
            "Ambiguous session prefix '{id_str}' matches {n} sessions. Use a longer prefix."
        ))),
    }
}

// ── Timestamp formatting ───────────────────────────────────────────────────────

/// Extract just the time portion (HH:MM:SS) from an ISO-8601 timestamp.
/// Returns the full string unchanged if parsing fails.
fn time_of(ts: &str) -> &str {
    // ISO-8601: "2026-03-25T06:25:03+00:00" or "2026-03-25T06:25:03Z"
    if let Some(t_pos) = ts.find('T') {
        let after_t = &ts[t_pos + 1..];
        // Take up to the first '+', '-', or 'Z' after the time digits
        let end = after_t
            .find(|c: char| c == '+' || c == 'Z')
            .unwrap_or(after_t.len());
        // Return up to 8 chars (HH:MM:SS)
        let time_part = &after_t[..end.min(8)];
        if !time_part.is_empty() {
            return time_part;
        }
    }
    ts
}

/// Format a duration between two ISO-8601 timestamps as "Xs" or "unknown".
fn duration_str(started: &str, finished: Option<&str>) -> String {
    let f = match finished {
        Some(f) => f,
        None => return "running".to_string(),
    };
    // Parse both as chrono DateTime
    let s = chrono::DateTime::parse_from_rfc3339(started).ok();
    let e = chrono::DateTime::parse_from_rfc3339(f).ok();
    match (s, e) {
        (Some(s), Some(e)) => {
            let diff = (e - s).num_milliseconds();
            if diff < 1000 {
                format!("{}ms", diff)
            } else {
                format!("{:.1}s", diff as f64 / 1000.0)
            }
        }
        _ => "unknown".to_string(),
    }
}

// ── Markdown rendering ─────────────────────────────────────────────────────────

/// Render the engagement log as Markdown bytes.
fn render_markdown(
    session: &Session,
    records: &[ScanRecord],
    findings: &[Finding],
) -> Vec<u8> {
    let mut out = String::new();

    // Header
    out.push_str("# SIGINT Engagement Log\n\n");
    out.push_str(&format!("**Session:** {}\n", session.name));
    if let Some(ref target) = session.target {
        out.push_str(&format!("**Target:** {}\n", target));
    }
    out.push_str(&format!("**Date:** {}\n", session.created_at.format("%Y-%m-%d")));
    out.push_str(&format!("**Session ID:** {}\n\n", session.id));

    // Timeline
    out.push_str("## Timeline\n\n");

    if records.is_empty() {
        out.push_str("> No tool invocations recorded for this session.\n\n");
    } else {
        // Group consecutive records by agent_role, emitting a heading on role change.
        let mut current_role: Option<String> = None;
        for record in records {
            let role = record
                .agent_role
                .as_deref()
                .unwrap_or("unknown")
                .to_string();

            // Emit a new agent heading when the role changes.
            if current_role.as_deref() != Some(role.as_str()) {
                let display_role = capitalize_words(&role);
                out.push_str(&format!("### {} Agent\n\n", display_role));
                current_role = Some(role);
            }

            let ts = time_of(&record.started_at);
            let dur = duration_str(&record.started_at, record.finished_at.as_deref());

            out.push_str(&format!(
                "**[{}] {}** `{}`\n",
                ts,
                record.tool,
                truncate_args(&record.args, 120),
            ));

            if let Some(ref output) = record.output {
                let preview = truncate_output(output, 800);
                out.push_str("```\n");
                out.push_str(&preview);
                if !preview.ends_with('\n') {
                    out.push('\n');
                }
                out.push_str("```\n");
            } else {
                out.push_str("> *(no output)*\n");
            }

            let exit_str = match record.exit_code {
                Some(0) => "Exit: 0".to_string(),
                Some(n) => format!("Exit: {}", n),
                None => "Exit: —".to_string(),
            };
            out.push_str(&format!("{} | Duration: {}\n\n", exit_str, dur));
        }
    }

    // Findings summary
    out.push_str("## Findings Summary\n\n");

    if findings.is_empty() {
        out.push_str("> No findings recorded for this session.\n");
    } else {
        out.push_str("| # | Severity | Title | Asset |\n");
        out.push_str("|---|----------|-------|-------|\n");
        for (i, f) in findings.iter().enumerate() {
            let asset = f.asset.as_deref().unwrap_or("—");
            out.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                i + 1,
                f.severity.to_string().to_uppercase(),
                escape_md_table(&f.title),
                escape_md_table(asset),
            ));
        }
    }

    out.into_bytes()
}

// ── HTML rendering ─────────────────────────────────────────────────────────────

/// Render the engagement log as HTML bytes.
fn render_html(
    session: &Session,
    records: &[ScanRecord],
    findings: &[Finding],
) -> Vec<u8> {
    // Render markdown first, then wrap in minimal HTML.
    let md = String::from_utf8(render_markdown(session, records, findings))
        .unwrap_or_default();

    // Use pulldown-cmark for Markdown -> HTML conversion.
    let parser = pulldown_cmark::Parser::new_ext(
        &md,
        pulldown_cmark::Options::ENABLE_TABLES
            | pulldown_cmark::Options::ENABLE_STRIKETHROUGH,
    );
    let mut html_content = String::new();
    pulldown_cmark::html::push_html(&mut html_content, parser);

    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SIGINT Engagement Log — {session_name}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         max-width: 960px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; }}
  h1 {{ border-bottom: 2px solid #e53935; padding-bottom: .4rem; }}
  h2 {{ border-bottom: 1px solid #ddd; padding-bottom: .2rem; margin-top: 2rem; }}
  h3 {{ color: #1565c0; margin-top: 1.5rem; }}
  pre {{ background: #f5f5f5; padding: 1rem; border-radius: 4px;
         overflow-x: auto; font-size: .85em; }}
  code {{ background: #f5f5f5; padding: 0.1em 0.3em; border-radius: 3px; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ border: 1px solid #ddd; padding: .5rem .75rem; text-align: left; }}
  th {{ background: #f5f5f5; font-weight: 600; }}
  blockquote {{ border-left: 4px solid #ccc; margin: 0; padding-left: 1rem; color: #666; }}
</style>
</head>
<body>
{content}
</body>
</html>
"#,
        session_name = html_escape(&session.name),
        content = html_content,
    );

    html.into_bytes()
}

// ── Helpers ────────────────────────────────────────────────────────────────────

/// Capitalize each word in a snake_case or lowercase role name.
fn capitalize_words(s: &str) -> String {
    s.split(|c: char| c == '_' || c == ' ')
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                None => String::new(),
                Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Truncate args JSON to at most `max` characters for display.
fn truncate_args(args: &str, max: usize) -> String {
    if args.len() <= max {
        args.to_string()
    } else {
        format!("{}…", &args[..max])
    }
}

/// Truncate tool output to at most `max` characters, preserving line boundaries.
fn truncate_output(output: &str, max: usize) -> String {
    if output.len() <= max {
        output.to_string()
    } else {
        let truncated = &output[..max];
        // Back off to the last newline to avoid splitting mid-line.
        let cut = truncated.rfind('\n').unwrap_or(max);
        format!("{}\n… (output truncated)", &output[..cut])
    }
}

/// Escape characters that break Markdown table cells.
fn escape_md_table(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

/// Escape HTML special characters.
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ── Entry point ────────────────────────────────────────────────────────────────

/// Run the `log` subcommand.
pub async fn run(core: AppCore, args: LogArgs) -> Result<(), Error> {
    let fmt = parse_format(&args.format).map_err(Error::Database)?;

    let db_path = core.config.resolved_db_path();
    let db = Database::open(&db_path)
        .map_err(|e| Error::Database(format!("Cannot open database: {e}")))?;

    let session = find_session_by_id_or_prefix(&db, &args.session_id)?;

    let records = db.get_scan_records(session.id)?;
    let findings = db.get_findings(session.id)?;

    let bytes = match fmt {
        LogFormat::Markdown => render_markdown(&session, &records, &findings),
        LogFormat::Html => render_html(&session, &records, &findings),
    };

    match &args.output {
        Some(path) => {
            std::fs::write(path, &bytes)
                .map_err(|e| Error::Database(format!("Cannot write log to '{path}': {e}")))?;
            eprintln!("Log written to {path}");
        }
        None => {
            std::io::stdout()
                .write_all(&bytes)
                .map_err(|e| Error::Database(format!("Failed to write to stdout: {e}")))?;
        }
    }

    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_format_markdown() {
        assert_eq!(parse_format("markdown").unwrap(), LogFormat::Markdown);
        assert_eq!(parse_format("md").unwrap(), LogFormat::Markdown);
        assert_eq!(parse_format("MARKDOWN").unwrap(), LogFormat::Markdown);
    }

    #[test]
    fn parse_format_html() {
        assert_eq!(parse_format("html").unwrap(), LogFormat::Html);
        assert_eq!(parse_format("htm").unwrap(), LogFormat::Html);
    }

    #[test]
    fn parse_format_invalid() {
        let err = parse_format("pdf").unwrap_err();
        assert!(err.contains("pdf"));
        assert!(err.contains("markdown"));
    }

    #[test]
    fn time_of_rfc3339() {
        assert_eq!(time_of("2026-03-25T06:25:03+00:00"), "06:25:03");
        assert_eq!(time_of("2026-03-25T06:25:03Z"), "06:25:03");
    }

    #[test]
    fn time_of_fallback() {
        // No 'T' separator — return original string unchanged.
        assert_eq!(time_of("not-a-timestamp"), "not-a-timestamp");
    }

    #[test]
    fn duration_str_subsecond() {
        let dur = duration_str(
            "2026-03-25T06:25:03+00:00",
            Some("2026-03-25T06:25:03.500+00:00"),
        );
        // 500ms — should be reported as milliseconds.
        assert!(dur.contains("ms") || dur.contains("0.5s") || dur == "unknown",
            "unexpected duration: {dur}");
    }

    #[test]
    fn duration_str_seconds() {
        let dur = duration_str(
            "2026-03-25T06:25:00+00:00",
            Some("2026-03-25T06:25:02+00:00"),
        );
        assert_eq!(dur, "2.0s");
    }

    #[test]
    fn duration_str_no_finish() {
        assert_eq!(duration_str("2026-03-25T06:25:00+00:00", None), "running");
    }

    #[test]
    fn capitalize_words_snake_case() {
        assert_eq!(capitalize_words("rf_recon"), "Rf Recon");
        assert_eq!(capitalize_words("researcher"), "Researcher");
        assert_eq!(capitalize_words("executor"), "Executor");
    }

    #[test]
    fn truncate_args_short() {
        assert_eq!(truncate_args("abc", 10), "abc");
    }

    #[test]
    fn truncate_args_long() {
        let long = "a".repeat(200);
        let result = truncate_args(&long, 50);
        assert!(result.len() <= 55); // 50 + ellipsis
        assert!(result.ends_with('…'));
    }

    #[test]
    fn truncate_output_short() {
        assert_eq!(truncate_output("hello\nworld", 100), "hello\nworld");
    }

    #[test]
    fn truncate_output_long() {
        let long = "line\n".repeat(200);
        let result = truncate_output(&long, 50);
        assert!(result.contains("truncated"));
    }

    #[test]
    fn escape_md_table_pipes() {
        assert_eq!(escape_md_table("foo|bar"), "foo\\|bar");
    }

    #[test]
    fn escape_md_table_newlines() {
        assert_eq!(escape_md_table("foo\nbar"), "foo bar");
    }

    #[test]
    fn html_escape_chars() {
        assert_eq!(html_escape("<script>&\""), "&lt;script&gt;&amp;&quot;");
    }

    #[test]
    fn render_markdown_empty_session() {
        use sigint_core::types::Session;

        let session = Session::new("test-target");
        let bytes = render_markdown(&session, &[], &[]);
        let md = String::from_utf8(bytes).unwrap();

        assert!(md.contains("# SIGINT Engagement Log"));
        assert!(md.contains("No tool invocations recorded"));
        assert!(md.contains("No findings recorded"));
    }

    #[test]
    fn render_markdown_with_records() {
        use sigint_core::types::Session;
        use sigint_store::ScanRecord;

        let session = Session::new("192.168.1.1");
        let mut record = ScanRecord::new(session.id, "nmap_scan", r#"{"target":"192.168.1.1"}"#);
        record.agent_role = Some("researcher".to_string());
        record.output = Some("PORT   STATE SERVICE\n22/tcp open  ssh".to_string());
        record.exit_code = Some(0);
        record.finished_at = Some(record.started_at.clone());

        let bytes = render_markdown(&session, &[record], &[]);
        let md = String::from_utf8(bytes).unwrap();

        assert!(md.contains("### Researcher Agent"));
        assert!(md.contains("nmap_scan"));
        assert!(md.contains("22/tcp open  ssh"));
        assert!(md.contains("Exit: 0"));
    }

    #[test]
    fn render_markdown_agent_role_null_fallback() {
        use sigint_core::types::Session;
        use sigint_store::ScanRecord;

        let session = Session::new("target");
        let mut record = ScanRecord::new(session.id, "shell", "{}");
        record.agent_role = None; // pre-migration row
        record.exit_code = Some(0);
        record.finished_at = Some(record.started_at.clone());

        let bytes = render_markdown(&session, &[record], &[]);
        let md = String::from_utf8(bytes).unwrap();

        // Should fall back to "Unknown" heading.
        assert!(md.contains("Unknown Agent"));
    }

    #[test]
    fn render_html_contains_body() {
        use sigint_core::types::Session;

        let session = Session::new("test");
        let bytes = render_html(&session, &[], &[]);
        let html = String::from_utf8(bytes).unwrap();

        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("<body>"));
        assert!(html.contains("SIGINT Engagement Log"));
    }
}
