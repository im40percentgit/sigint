//! `sigint report` — generate a report from a stored scan session.
//!
//! Loads a session from the SQLite database, fetches its findings, assets, and
//! scan records, then renders a Markdown or HTML report to stdout or a file.
//!
//! @decision DEC-CLI-005
//! @title report command accepts UUID prefix for session_id
//! @status accepted
//! @rationale Full UUIDs are 36 characters and hard to type.  Prefix matching
//! (at least 4 characters) makes interactive use comfortable.  The database
//! scan is O(n sessions) which is acceptable given typical session counts.
//! Ambiguous prefixes (2+ matches) are reported as errors rather than silently
//! picking the first, to avoid generating reports for the wrong session.

use std::io::Write as _;

use sigint_core::{AppCore, Error};
use sigint_report::{
    build_report, AssetSummary, FindingSummary, ReportData, ReportFormat, ReportTemplate,
};
use sigint_store::Database;
use uuid::Uuid;

// ── Clap args ─────────────────────────────────────────────────────────────────

/// Arguments parsed for the `report` subcommand.
#[derive(Debug, clap::Args)]
pub struct ReportArgs {
    /// Session ID (full UUID or a unique prefix of at least 4 characters).
    pub session_id: String,
    /// Output format: markdown, html.
    #[arg(short, long, default_value = "markdown")]
    pub format: String,
    /// Report template: executive, detailed, technical.
    #[arg(short, long, default_value = "detailed")]
    pub template: String,
    /// Output file path (writes to stdout if omitted).
    #[arg(short, long)]
    pub output: Option<String>,
}

// ── Format / template parsing ─────────────────────────────────────────────────

/// Parse a format string into a `ReportFormat`.
///
/// Returns an error message string for unknown values so that tests can assert
/// on the error text without wiring up the full CLI machinery.
pub fn parse_format(s: &str) -> Result<ReportFormat, String> {
    match s.to_lowercase().as_str() {
        "markdown" | "md" => Ok(ReportFormat::Markdown),
        "html" | "htm" => Ok(ReportFormat::Html),
        other => Err(format!(
            "Unknown report format '{}'. Valid values: markdown, html.",
            other
        )),
    }
}

/// Parse a template string into a `ReportTemplate`.
pub fn parse_template(s: &str) -> Result<ReportTemplate, String> {
    match s.to_lowercase().as_str() {
        "executive" | "exec" => Ok(ReportTemplate::Executive),
        "detailed" | "detail" => Ok(ReportTemplate::Detailed),
        "technical" | "tech" => Ok(ReportTemplate::Technical),
        other => Err(format!(
            "Unknown report template '{}'. Valid values: executive, detailed, technical.",
            other
        )),
    }
}

// ── Session lookup (prefix or exact UUID) ─────────────────────────────────────

/// Find a session by exact UUID or by a prefix of its UUID string.
///
/// Returns `Err` if the string is not a valid prefix, no session matches,
/// or more than one session matches (ambiguous prefix).
fn find_session_by_id_or_prefix(
    db: &Database,
    id_str: &str,
) -> Result<sigint_core::types::Session, Error> {
    // Try exact parse first.
    if let Ok(id) = Uuid::parse_str(id_str) {
        return db
            .get_session(id)?
            .ok_or_else(|| Error::Database(format!("Session not found: {id_str}")));
    }

    // Prefix match — require at least 4 characters to avoid overly broad matches.
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

// ── Entry point ───────────────────────────────────────────────────────────────

/// Run the `report` subcommand.
pub async fn run(core: AppCore, args: ReportArgs) -> Result<(), Error> {
    let fmt = parse_format(&args.format).map_err(Error::Database)?;
    let tmpl = parse_template(&args.template).map_err(Error::Database)?;

    let db_path = core.config.resolved_db_path();
    let db = Database::open(&db_path)
        .map_err(|e| Error::Database(format!("Cannot open database: {e}")))?;

    // Resolve the session.
    let session = find_session_by_id_or_prefix(&db, &args.session_id)?;

    // Load findings.
    let raw_findings = db.get_findings(session.id)?;
    let findings: Vec<FindingSummary> = raw_findings
        .into_iter()
        .map(|f| FindingSummary {
            title: f.title,
            severity: f.severity.to_string(),
            description: f.description,
            asset: f.asset,
            evidence: f.evidence,
            risk_score: f.cvss_score,
            asset_id: f.asset_id.map(|id| id.to_string()),
        })
        .collect();

    // Load assets.
    let raw_assets = db.get_assets(session.id)?;
    let assets: Vec<AssetSummary> = raw_assets
        .into_iter()
        .map(|a| AssetSummary {
            kind: a.kind.to_string(),
            value: a.value,
            services_count: 0, // services_count is informational; detailed query omitted for CLI
        })
        .collect();

    // Count scan records.
    let scan_records = db.get_scan_records(session.id)?;
    let scan_count = scan_records.len();

    let data = ReportData {
        session_name: session.name.clone(),
        target: session.target.clone(),
        created_at: session.created_at,
        findings,
        assets,
        scan_count,
    };

    let bytes = build_report(&data, tmpl, fmt);

    // Write output.
    match &args.output {
        Some(path) => {
            std::fs::write(path, &bytes)
                .map_err(|e| Error::Database(format!("Cannot write report to '{path}': {e}")))?;
            eprintln!("Report written to {path}");
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

    // ── parse_format ──────────────────────────────────────────────────────────

    #[test]
    fn parse_format_valid_markdown() {
        assert!(matches!(
            parse_format("markdown"),
            Ok(ReportFormat::Markdown)
        ));
        assert!(matches!(
            parse_format("Markdown"),
            Ok(ReportFormat::Markdown)
        ));
        assert!(matches!(parse_format("md"), Ok(ReportFormat::Markdown)));
    }

    #[test]
    fn parse_format_valid_html() {
        assert!(matches!(parse_format("html"), Ok(ReportFormat::Html)));
        assert!(matches!(parse_format("HTML"), Ok(ReportFormat::Html)));
        assert!(matches!(parse_format("htm"), Ok(ReportFormat::Html)));
    }

    #[test]
    fn parse_format_invalid_returns_err() {
        let result = parse_format("pdf");
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(
            msg.contains("pdf"),
            "error should mention the bad input: {msg}"
        );
        assert!(
            msg.contains("markdown"),
            "error should list valid values: {msg}"
        );
    }

    // ── parse_template ────────────────────────────────────────────────────────

    #[test]
    fn parse_template_valid_executive() {
        assert!(matches!(
            parse_template("executive"),
            Ok(ReportTemplate::Executive)
        ));
        assert!(matches!(
            parse_template("exec"),
            Ok(ReportTemplate::Executive)
        ));
        assert!(matches!(
            parse_template("EXECUTIVE"),
            Ok(ReportTemplate::Executive)
        ));
    }

    #[test]
    fn parse_template_valid_detailed() {
        assert!(matches!(
            parse_template("detailed"),
            Ok(ReportTemplate::Detailed)
        ));
        assert!(matches!(
            parse_template("detail"),
            Ok(ReportTemplate::Detailed)
        ));
    }

    #[test]
    fn parse_template_valid_technical() {
        assert!(matches!(
            parse_template("technical"),
            Ok(ReportTemplate::Technical)
        ));
        assert!(matches!(
            parse_template("tech"),
            Ok(ReportTemplate::Technical)
        ));
    }

    #[test]
    fn parse_template_invalid_returns_err() {
        let result = parse_template("summary");
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(
            msg.contains("summary"),
            "error should mention the bad input: {msg}"
        );
        assert!(
            msg.contains("executive"),
            "error should list valid values: {msg}"
        );
    }
}
