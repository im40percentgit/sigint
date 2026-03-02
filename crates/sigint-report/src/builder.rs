//! Report builder — converts raw session data into formatted Markdown and HTML.
//!
//! Three templates are supported:
//! - **Executive**: high-level finding summary table, suitable for management.
//! - **Detailed**: numbered findings with descriptions, plus an asset table.
//! - **Technical**: full findings with evidence blocks, plus a service inventory.
//!
//! @decision DEC-REPORT-001
//! @title Report builder is pure Rust with no template engine dependency
//! @status accepted
//! @rationale Keeping report generation in plain Rust string formatting avoids
//! pulling in a template engine (Tera, Handlebars, etc.) which would add
//! significant compile time and a learning curve for contributors.  The
//! templates are simple enough that format!() macros and a push-based string
//! builder are maintainable and fast.  HTML output is produced by piping the
//! Markdown through pulldown-cmark, so both formats share a single template
//! code path and the HTML is always in sync with the Markdown.

use chrono::{DateTime, Utc};

// ── Public data types ─────────────────────────────────────────────────────────

/// A single finding summarised for inclusion in a report.
#[derive(Debug, Clone)]
pub struct FindingSummary {
    /// Short title of the finding.
    pub title: String,
    /// Severity level (maps to the core `Severity` enum).
    pub severity: String,
    /// Human-readable description of the finding.
    pub description: String,
    /// Optional asset the finding relates to (e.g. "10.0.0.1:443").
    pub asset: Option<String>,
    /// Optional raw evidence or proof-of-concept output.
    pub evidence: Option<String>,
}

/// A single asset summarised for inclusion in a report.
#[derive(Debug, Clone)]
pub struct AssetSummary {
    /// Asset category (host, domain, url, …).
    pub kind: String,
    /// The asset value (IP address, FQDN, URL, …).
    pub value: String,
    /// Number of services discovered on this asset.
    pub services_count: usize,
}

/// All data needed to render any template variant.
#[derive(Debug, Clone)]
pub struct ReportData {
    /// The session name.
    pub session_name: String,
    /// Optional primary target of the engagement.
    pub target: Option<String>,
    /// When the session was created.
    pub created_at: DateTime<Utc>,
    /// All findings for this session.
    pub findings: Vec<FindingSummary>,
    /// All assets discovered during this session.
    pub assets: Vec<AssetSummary>,
    /// Total number of scan tool invocations.
    pub scan_count: usize,
}

/// Which report layout to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportTemplate {
    /// Brief, management-friendly summary.
    Executive,
    /// Full findings with descriptions and asset table.
    Detailed,
    /// Findings with raw evidence and full asset service inventory.
    Technical,
}

/// The output file format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportFormat {
    /// UTF-8 Markdown text.
    Markdown,
    /// Self-contained HTML document.
    Html,
}

// ── Severity helpers ──────────────────────────────────────────────────────────

fn severity_order(s: &str) -> u8 {
    match s.to_lowercase().as_str() {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => 4,
    }
}

fn severity_counts(findings: &[FindingSummary]) -> (usize, usize, usize, usize, usize) {
    let mut critical = 0usize;
    let mut high = 0usize;
    let mut medium = 0usize;
    let mut low = 0usize;
    let mut info = 0usize;
    for f in findings {
        match f.severity.to_lowercase().as_str() {
            "critical" => critical += 1,
            "high" => high += 1,
            "medium" => medium += 1,
            "low" => low += 1,
            _ => info += 1,
        }
    }
    (critical, high, medium, low, info)
}

// ── Report header ─────────────────────────────────────────────────────────────

fn render_header(data: &ReportData, variant_label: &str) -> String {
    let target_line = match &data.target {
        Some(t) => format!("**Target:** {t}  \n"),
        None => String::new(),
    };
    format!(
        "# SIGINT Security Report — {variant_label}\n\n\
         **Session:** {}  \n\
         {target_line}\
         **Date:** {}  \n\
         **Scans run:** {}  \n\n",
        data.session_name,
        data.created_at.format("%Y-%m-%d %H:%M UTC"),
        data.scan_count,
    )
}

// ── Executive template ────────────────────────────────────────────────────────

fn render_executive(data: &ReportData) -> String {
    let mut out = render_header(data, "Executive Summary");

    let (critical, high, medium, low, info) = severity_counts(&data.findings);
    let total = data.findings.len();

    out.push_str("## Summary\n\n");
    out.push_str("| Severity | Count |\n");
    out.push_str("|----------|-------|\n");
    out.push_str(&format!("| Critical | {critical} |\n"));
    out.push_str(&format!("| High     | {high} |\n"));
    out.push_str(&format!("| Medium   | {medium} |\n"));
    out.push_str(&format!("| Low      | {low} |\n"));
    out.push_str(&format!("| Info     | {info} |\n"));
    out.push_str(&format!("| **Total** | **{total}** |\n\n"));

    if data.findings.is_empty() {
        out.push_str("_No findings recorded for this session._\n\n");
    } else {
        out.push_str("## Findings Overview\n\n");
        out.push_str("| # | Severity | Title | Asset |\n");
        out.push_str("|---|----------|-------|-------|\n");

        let mut sorted: Vec<&FindingSummary> = data.findings.iter().collect();
        sorted.sort_by_key(|f| severity_order(&f.severity));

        for (i, f) in sorted.iter().enumerate() {
            let asset = f.asset.as_deref().unwrap_or("—");
            out.push_str(&format!(
                "| {} | {} | {} | {} |\n",
                i + 1,
                f.severity,
                f.title,
                asset,
            ));
        }
        out.push('\n');
    }

    out.push_str(&format!(
        "## Attack Surface\n\n\
         {} asset(s) discovered across {} scan(s).\n",
        data.assets.len(),
        data.scan_count,
    ));

    out
}

// ── Detailed template ─────────────────────────────────────────────────────────

fn render_detailed(data: &ReportData) -> String {
    let mut out = render_header(data, "Detailed");

    // Findings section
    out.push_str("## Findings\n\n");
    if data.findings.is_empty() {
        out.push_str("_No findings recorded for this session._\n\n");
    } else {
        let mut sorted: Vec<&FindingSummary> = data.findings.iter().collect();
        sorted.sort_by_key(|f| severity_order(&f.severity));

        for (i, f) in sorted.iter().enumerate() {
            let asset_line = f
                .asset
                .as_deref()
                .map(|a| format!("**Asset:** {a}  \n"))
                .unwrap_or_default();
            out.push_str(&format!(
                "### {}. {} `[{}]`\n\n\
                 {asset_line}\
                 {}\n\n",
                i + 1,
                f.title,
                f.severity,
                f.description,
            ));
        }
    }

    // Asset table
    out.push_str("## Assets\n\n");
    if data.assets.is_empty() {
        out.push_str("_No assets recorded for this session._\n\n");
    } else {
        out.push_str("| Kind | Value | Services |\n");
        out.push_str("|------|-------|----------|\n");
        for a in &data.assets {
            out.push_str(&format!(
                "| {} | {} | {} |\n",
                a.kind, a.value, a.services_count
            ));
        }
        out.push('\n');
    }

    out
}

// ── Technical template ────────────────────────────────────────────────────────

fn render_technical(data: &ReportData) -> String {
    let mut out = render_header(data, "Technical");

    // Findings with evidence
    out.push_str("## Technical Findings\n\n");
    if data.findings.is_empty() {
        out.push_str("_No findings recorded for this session._\n\n");
    } else {
        let mut sorted: Vec<&FindingSummary> = data.findings.iter().collect();
        sorted.sort_by_key(|f| severity_order(&f.severity));

        for (i, f) in sorted.iter().enumerate() {
            let asset_line = f
                .asset
                .as_deref()
                .map(|a| format!("**Asset:** {a}  \n"))
                .unwrap_or_default();
            out.push_str(&format!(
                "### {}. {} `[{}]`\n\n\
                 {asset_line}\
                 {}\n\n",
                i + 1,
                f.title,
                f.severity,
                f.description,
            ));

            if let Some(ev) = &f.evidence {
                out.push_str("**Evidence:**\n\n");
                out.push_str("```\n");
                out.push_str(ev);
                out.push_str("\n```\n\n");
            }
        }
    }

    // Asset inventory with service counts
    out.push_str("## Asset Inventory\n\n");
    if data.assets.is_empty() {
        out.push_str("_No assets recorded for this session._\n\n");
    } else {
        out.push_str("| Kind | Value | Services Discovered |\n");
        out.push_str("|------|-------|--------------------|\n");
        for a in &data.assets {
            out.push_str(&format!(
                "| {} | {} | {} |\n",
                a.kind, a.value, a.services_count
            ));
        }
        out.push('\n');
    }

    out.push_str(&format!(
        "## Scan Statistics\n\n\
         - Total scans run: {}\n\
         - Total assets found: {}\n\
         - Total findings: {}\n",
        data.scan_count,
        data.assets.len(),
        data.findings.len(),
    ));

    out
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Render the report as a Markdown string.
pub fn build_markdown(data: &ReportData, template: ReportTemplate) -> String {
    match template {
        ReportTemplate::Executive => render_executive(data),
        ReportTemplate::Detailed => render_detailed(data),
        ReportTemplate::Technical => render_technical(data),
    }
}

/// Render the report and return raw bytes in the requested format.
///
/// For `ReportFormat::Markdown`, the bytes are UTF-8 Markdown.
/// For `ReportFormat::Html`, the Markdown is rendered to a complete HTML
/// document via `pulldown-cmark` and wrapped in professional CSS.
pub fn build_report(data: &ReportData, template: ReportTemplate, format: ReportFormat) -> Vec<u8> {
    let md = build_markdown(data, template);
    match format {
        ReportFormat::Markdown => md.into_bytes(),
        ReportFormat::Html => crate::format::markdown_to_html(&md).into_bytes(),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn sample_data() -> ReportData {
        ReportData {
            session_name: "Test Engagement".into(),
            target: Some("example.com".into()),
            created_at: Utc::now(),
            findings: vec![
                FindingSummary {
                    title: "SQL Injection".into(),
                    severity: "critical".into(),
                    description: "Unparameterized query in login endpoint.".into(),
                    asset: Some("example.com:443".into()),
                    evidence: Some("' OR 1=1 --".into()),
                },
                FindingSummary {
                    title: "XSS".into(),
                    severity: "high".into(),
                    description: "Reflected XSS in search parameter.".into(),
                    asset: Some("example.com".into()),
                    evidence: None,
                },
            ],
            assets: vec![AssetSummary {
                kind: "host".into(),
                value: "192.168.1.1".into(),
                services_count: 3,
            }],
            scan_count: 5,
        }
    }

    fn empty_data() -> ReportData {
        ReportData {
            session_name: "Empty Session".into(),
            target: None,
            created_at: Utc::now(),
            findings: vec![],
            assets: vec![],
            scan_count: 0,
        }
    }

    #[test]
    fn build_executive_markdown() {
        let md = build_markdown(&sample_data(), ReportTemplate::Executive);
        // Must contain a header
        assert!(
            md.contains("# SIGINT Security Report"),
            "missing main header"
        );
        // Must contain summary table header
        assert!(md.contains("| Severity | Count |"), "missing summary table");
        // Severity column entries
        assert!(md.contains("Critical"), "missing Critical row");
        assert!(md.contains("High"), "missing High row");
    }

    #[test]
    fn build_detailed_markdown() {
        let md = build_markdown(&sample_data(), ReportTemplate::Detailed);
        assert!(md.contains("## Findings"), "missing Findings section");
        // Numbered finding headers
        assert!(md.contains("### 1."), "missing numbered finding");
        // Asset table present
        assert!(md.contains("## Assets"), "missing Assets section");
        assert!(md.contains("| Kind | Value |"), "missing asset table");
    }

    #[test]
    fn build_technical_markdown() {
        let md = build_markdown(&sample_data(), ReportTemplate::Technical);
        assert!(
            md.contains("## Technical Findings"),
            "missing Technical Findings section"
        );
        // Evidence block rendered as fenced code block
        assert!(md.contains("**Evidence:**"), "missing Evidence label");
        assert!(md.contains("```"), "missing code fence");
        // Asset inventory section
        assert!(
            md.contains("## Asset Inventory"),
            "missing Asset Inventory section"
        );
        assert!(
            md.contains("Services Discovered"),
            "missing services column"
        );
    }

    #[test]
    fn empty_findings_handled() {
        let md = build_markdown(&empty_data(), ReportTemplate::Detailed);
        assert!(
            md.contains("No findings recorded"),
            "should emit graceful empty message"
        );
        assert!(
            md.contains("No assets recorded"),
            "should emit graceful empty assets message"
        );
    }

    #[test]
    fn build_report_html() {
        let bytes = build_report(
            &sample_data(),
            ReportTemplate::Executive,
            ReportFormat::Html,
        );
        let html = String::from_utf8(bytes).expect("HTML should be valid UTF-8");
        assert!(html.contains("<html"), "HTML bytes should contain <html");
        assert!(
            html.contains("</html>"),
            "HTML bytes should end with </html>"
        );
    }
}
