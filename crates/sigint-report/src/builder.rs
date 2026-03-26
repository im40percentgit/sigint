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
    /// Optional numeric risk score (0.0–10.0) for CVSS-style prioritisation.
    pub risk_score: Option<f32>,
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

// ── Severity pie chart ───────────────────────────────────────────────────────

/// Generate an inline SVG pie chart for severity distribution.
///
/// Returns an empty string if there are no findings.  The SVG is self-contained
/// (no JavaScript, no external resources) and is emitted as raw HTML so that
/// pulldown-cmark passes it through to the final HTML document unchanged.
fn render_severity_chart(findings: &[FindingSummary]) -> String {
    if findings.is_empty() {
        return String::new();
    }

    let critical = findings
        .iter()
        .filter(|f| f.severity.eq_ignore_ascii_case("critical"))
        .count();
    let high = findings
        .iter()
        .filter(|f| f.severity.eq_ignore_ascii_case("high"))
        .count();
    let medium = findings
        .iter()
        .filter(|f| f.severity.eq_ignore_ascii_case("medium"))
        .count();
    let low = findings
        .iter()
        .filter(|f| f.severity.eq_ignore_ascii_case("low"))
        .count();
    let info = findings
        .iter()
        .filter(|f| f.severity.eq_ignore_ascii_case("info"))
        .count();
    let total = findings.len() as f64;

    let segments: Vec<(&str, usize, &str)> = vec![
        ("Critical", critical, "#dc2626"),
        ("High", high, "#ea580c"),
        ("Medium", medium, "#ca8a04"),
        ("Low", low, "#2563eb"),
        ("Info", info, "#6b7280"),
    ];

    // Filter out zero-count segments.
    let active: Vec<_> = segments.iter().filter(|(_, count, _)| *count > 0).collect();

    if active.is_empty() {
        return String::new();
    }

    // Pie geometry: circle centre (cx, cy) and radius.
    let cx = 100.0_f64;
    let cy = 100.0_f64;
    let r = 80.0_f64;

    // Single severity → full circle (no arcs needed).
    if active.len() == 1 {
        let (label, count, color) = active[0];
        return format!(
            "<svg width=\"320\" height=\"200\" viewBox=\"0 0 320 200\">\
             <circle cx=\"{cx}\" cy=\"{cy}\" r=\"{r}\" fill=\"{color}\"/>\
             <text x=\"{cx}\" y=\"105\" text-anchor=\"middle\" fill=\"white\" \
             font-size=\"14\" font-family=\"sans-serif\">{label}: {count}</text>\
             <rect x=\"210\" y=\"91\" width=\"10\" height=\"10\" fill=\"{color}\"/>\
             <text x=\"225\" y=\"100\" font-size=\"11\" fill=\"#333\" \
             font-family=\"sans-serif\">{label}: {count}</text>\
             </svg>\n\n"
        );
    }

    // Multiple segments: draw pie wedge arcs with a legend to the right.
    let mut svg = String::from("<svg width=\"320\" height=\"200\" viewBox=\"0 0 320 200\">\n");
    let mut start_angle = -90.0_f64; // 12 o'clock

    for (_label, count, color) in &segments {
        if *count == 0 {
            continue;
        }
        let sweep = (*count as f64 / total) * 360.0;
        let end_angle = start_angle + sweep;

        let start_rad = start_angle.to_radians();
        let end_rad = end_angle.to_radians();

        let x1 = cx + r * start_rad.cos();
        let y1 = cy + r * start_rad.sin();
        let x2 = cx + r * end_rad.cos();
        let y2 = cy + r * end_rad.sin();

        let large_arc = if sweep > 180.0 { 1 } else { 0 };

        svg.push_str(&format!(
            "<path d=\"M {cx} {cy} L {x1:.1} {y1:.1} A {r} {r} 0 {large_arc} 1 \
             {x2:.1} {y2:.1} Z\" fill=\"{color}\"/>\n"
        ));

        start_angle = end_angle;
    }

    // Legend — positioned to the right of the pie.
    let mut ly = 40.0_f64;
    for (label, count, color) in &segments {
        if *count == 0 {
            continue;
        }
        let ty = ly + 9.0;
        svg.push_str(&format!(
            "<rect x=\"210\" y=\"{ly:.0}\" width=\"10\" height=\"10\" fill=\"{color}\"/>\
             <text x=\"225\" y=\"{ty:.0}\" font-size=\"11\" fill=\"#333\" \
             font-family=\"sans-serif\">{label}: {count}</text>\n"
        ));
        ly += 18.0;
    }

    svg.push_str("</svg>\n\n");
    svg
}

// ── Executive summary section ─────────────────────────────────────────────────

fn render_executive_summary(data: &ReportData) -> String {
    let total = data.findings.len();
    let asset_count = data.assets.len();
    let critical = data
        .findings
        .iter()
        .filter(|f| f.severity.eq_ignore_ascii_case("critical"))
        .count();
    let high = data
        .findings
        .iter()
        .filter(|f| f.severity.eq_ignore_ascii_case("high"))
        .count();
    let medium = data
        .findings
        .iter()
        .filter(|f| f.severity.eq_ignore_ascii_case("medium"))
        .count();
    let low = data
        .findings
        .iter()
        .filter(|f| f.severity.eq_ignore_ascii_case("low"))
        .count();

    let mut out = String::from("## Executive Summary\n\n");
    out.push_str(&format!(
        "This engagement identified **{}** findings across **{}** assets: \
         **{}** critical, **{}** high, **{}** medium, **{}** low.\n\n",
        total, asset_count, critical, high, medium, low
    ));

    // Highest-risk finding
    if let Some(highest) = data.findings.iter().max_by(|a, b| {
        let sa = a.risk_score.unwrap_or(0.0);
        let sb = b.risk_score.unwrap_or(0.0);
        sa.partial_cmp(&sb).unwrap_or(std::cmp::Ordering::Equal)
    }) {
        out.push_str(&format!(
            "The highest-risk finding is \"{}\" ({}) affecting {}.\n\n",
            highest.title,
            highest.severity,
            highest.asset.as_deref().unwrap_or("unspecified assets")
        ));
    }

    if critical > 0 || high > 0 {
        out.push_str(
            "Immediate remediation is recommended for all critical and high findings.\n\n",
        );
    }

    out.push_str(&render_severity_chart(&data.findings));

    out
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

    out.push_str(&render_executive_summary(data));

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

    out.push_str(&render_executive_summary(data));

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
            let risk_line = f
                .risk_score
                .map(|s| format!("**Risk Score:** {:.1}/10.0  \n", s))
                .unwrap_or_default();
            out.push_str(&format!(
                "### {}. {} `[{}]`\n\n\
                 {asset_line}\
                 {risk_line}\
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

    out.push_str(&render_executive_summary(data));

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
            let risk_line = f
                .risk_score
                .map(|s| format!("**Risk Score:** {:.1}/10.0  \n", s))
                .unwrap_or_default();
            out.push_str(&format!(
                "### {}. {} `[{}]`\n\n\
                 {asset_line}\
                 {risk_line}\
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

// ── Campaign types ────────────────────────────────────────────────────────────

/// Aggregated report data for a multi-target campaign.
pub struct CampaignReportData {
    /// Name of the campaign.
    pub campaign_name: String,
    /// Per-target data: (target_name, per-target ReportData).
    pub targets: Vec<(String, ReportData)>,
}

// ── Campaign severity helper ──────────────────────────────────────────────────

/// Count critical / high / medium / low findings (case-insensitive).
fn count_severities(findings: &[FindingSummary]) -> (usize, usize, usize, usize) {
    let c = findings
        .iter()
        .filter(|f| f.severity.eq_ignore_ascii_case("critical"))
        .count();
    let h = findings
        .iter()
        .filter(|f| f.severity.eq_ignore_ascii_case("high"))
        .count();
    let m = findings
        .iter()
        .filter(|f| f.severity.eq_ignore_ascii_case("medium"))
        .count();
    let l = findings
        .iter()
        .filter(|f| f.severity.eq_ignore_ascii_case("low"))
        .count();
    (c, h, m, l)
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

/// Render an aggregated Markdown report covering every target in a campaign.
///
/// The output contains:
/// 1. A campaign-level overview with total finding counts.
/// 2. A per-target severity table.
/// 3. Inline per-target detail sections produced by [`build_markdown`].
pub fn build_campaign_markdown(data: &CampaignReportData, template: ReportTemplate) -> String {
    let mut out = format!("# SIGINT Campaign Report — {}\n\n", data.campaign_name);
    out.push_str("## Campaign Overview\n\n");
    out.push_str(&format!("- **Targets scanned:** {}\n", data.targets.len()));

    // Total findings across all targets
    let total: usize = data.targets.iter().map(|(_, rd)| rd.findings.len()).sum();
    out.push_str(&format!("- **Total findings:** {}\n\n", total));

    // Severity aggregation table
    out.push_str("| Target | Findings | Critical | High | Medium | Low |\n");
    out.push_str("|--------|----------|----------|------|--------|-----|\n");
    for (name, rd) in &data.targets {
        let (c, h, m, l) = count_severities(&rd.findings);
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            name,
            rd.findings.len(),
            c,
            h,
            m,
            l,
        ));
    }

    // Per-target details
    out.push_str("\n## Per-Target Details\n\n");
    for (i, (name, rd)) in data.targets.iter().enumerate() {
        out.push_str(&format!("### {}. {}\n\n", i + 1, name));
        out.push_str(&build_markdown(rd, template));
        out.push('\n');
    }
    out
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
                    risk_score: None,
                },
                FindingSummary {
                    title: "XSS".into(),
                    severity: "high".into(),
                    description: "Reflected XSS in search parameter.".into(),
                    asset: Some("example.com".into()),
                    evidence: None,
                    risk_score: None,
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

    // ── Edge-case tests ───────────────────────────────────────────────────────

    /// All three templates must produce non-empty output even with no findings
    /// or assets.  This guards against panics in the empty-state branches.
    #[test]
    fn all_templates_non_empty_with_zero_findings() {
        let data = empty_data();
        for template in [
            ReportTemplate::Executive,
            ReportTemplate::Detailed,
            ReportTemplate::Technical,
        ] {
            let md = build_markdown(&data, template);
            assert!(
                !md.is_empty(),
                "template {:?} produced empty output with zero findings",
                template
            );
            assert!(
                md.contains("# SIGINT Security Report"),
                "template {:?} missing main header",
                template
            );
        }
    }

    /// HTML output must include the four structural tags that make it a valid
    /// self-contained document: `<!DOCTYPE html>`, `<html`, `<body>`, `</body>`.
    #[test]
    fn html_output_contains_structural_tags() {
        for template in [
            ReportTemplate::Executive,
            ReportTemplate::Detailed,
            ReportTemplate::Technical,
        ] {
            let bytes = build_report(&sample_data(), template, ReportFormat::Html);
            let html = String::from_utf8(bytes).expect("HTML must be valid UTF-8");

            assert!(
                html.contains("<!DOCTYPE html>"),
                "template {:?}: missing <!DOCTYPE html>",
                template
            );
            assert!(
                html.contains("<html"),
                "template {:?}: missing <html",
                template
            );
            assert!(
                html.contains("<body>"),
                "template {:?}: missing <body>",
                template
            );
            assert!(
                html.contains("</body>"),
                "template {:?}: missing </body>",
                template
            );
            assert!(
                html.contains("</html>"),
                "template {:?}: missing </html>",
                template
            );
        }
    }

    /// A finding with `asset: None` must render without panicking and must
    /// show the em-dash placeholder in the Executive table.
    #[test]
    fn finding_with_no_asset_renders_placeholder() {
        let data = ReportData {
            session_name: "No Asset Test".into(),
            target: None,
            created_at: chrono::Utc::now(),
            findings: vec![FindingSummary {
                title: "Open Port".into(),
                severity: "low".into(),
                description: "Port 8080 open with no service banner.".into(),
                asset: None,
                evidence: None,
                risk_score: None,
            }],
            assets: vec![],
            scan_count: 1,
        };

        let md = build_markdown(&data, ReportTemplate::Executive);
        // The em-dash placeholder must appear in the findings overview table.
        assert!(
            md.contains("—"),
            "nil asset should render em-dash placeholder in executive table"
        );
    }

    /// A finding with `evidence: None` in the Technical template must not
    /// emit the Evidence block at all — no panic, no stray fence markers.
    #[test]
    fn technical_template_skips_evidence_block_when_none() {
        let data = ReportData {
            session_name: "No Evidence Test".into(),
            target: None,
            created_at: chrono::Utc::now(),
            findings: vec![FindingSummary {
                title: "Outdated TLS".into(),
                severity: "medium".into(),
                description: "Server still accepts TLSv1.0.".into(),
                asset: Some("10.0.0.1:443".into()),
                evidence: None,
                risk_score: None,
            }],
            assets: vec![],
            scan_count: 1,
        };

        let md = build_markdown(&data, ReportTemplate::Technical);
        // The evidence header must not appear when evidence is None.
        assert!(
            !md.contains("**Evidence:**"),
            "evidence block should be absent when evidence is None"
        );
    }

    /// Findings must be sorted critical → high → medium → low in the rendered
    /// output regardless of the order they are supplied.
    #[test]
    fn findings_sorted_by_severity_in_output() {
        let data = ReportData {
            session_name: "Sort Test".into(),
            target: None,
            created_at: chrono::Utc::now(),
            findings: vec![
                FindingSummary {
                    title: "Low Finding".into(),
                    severity: "low".into(),
                    description: "Minor issue.".into(),
                    asset: None,
                    evidence: None,
                    risk_score: None,
                },
                FindingSummary {
                    title: "Critical Finding".into(),
                    severity: "critical".into(),
                    description: "Very bad issue.".into(),
                    asset: None,
                    evidence: None,
                    risk_score: None,
                },
                FindingSummary {
                    title: "Medium Finding".into(),
                    severity: "medium".into(),
                    description: "Moderate issue.".into(),
                    asset: None,
                    evidence: None,
                    risk_score: None,
                },
            ],
            assets: vec![],
            scan_count: 0,
        };

        let md = build_markdown(&data, ReportTemplate::Detailed);

        // Find positions of each title in the findings section (look for
        // the numbered heading markers to avoid matching a title that may
        // also appear in the executive summary paragraph).
        let pos_critical = md
            .find("Critical Finding `[critical]`")
            .expect("Critical Finding heading must appear");
        let pos_medium = md
            .find("Medium Finding `[medium]`")
            .expect("Medium Finding heading must appear");
        let pos_low = md
            .find("Low Finding `[low]`")
            .expect("Low Finding heading must appear");

        assert!(
            pos_critical < pos_medium,
            "critical must appear before medium"
        );
        assert!(pos_medium < pos_low, "medium must appear before low");
    }

    /// A very long description (10 000 characters) must survive the round-trip
    /// through every template without being truncated or causing a panic.
    #[test]
    fn very_long_description_preserved() {
        let long_desc = "A".repeat(10_000);
        let data = ReportData {
            session_name: "Long Desc Test".into(),
            target: None,
            created_at: chrono::Utc::now(),
            findings: vec![FindingSummary {
                title: "Verbose Finding".into(),
                severity: "info".into(),
                description: long_desc.clone(),
                asset: None,
                evidence: None,
                risk_score: None,
            }],
            assets: vec![],
            scan_count: 1,
        };

        for template in [
            ReportTemplate::Executive,
            ReportTemplate::Detailed,
            ReportTemplate::Technical,
        ] {
            // Executive template only shows the title in the overview table,
            // not the description — so only check Detailed and Technical.
            let md = build_markdown(&data, template);
            if template != ReportTemplate::Executive {
                assert!(
                    md.contains(&long_desc),
                    "template {:?}: long description must not be truncated",
                    template
                );
            }
            // All templates must produce non-empty output without panicking.
            assert!(
                !md.is_empty(),
                "template {:?}: output must not be empty",
                template
            );
        }
    }

    // ── Campaign report helpers ───────────────────────────────────────────────

    /// Build a minimal ReportData with `n` findings all at severity "high".
    fn make_report_data(name: &str, n: usize) -> ReportData {
        ReportData {
            session_name: name.into(),
            target: Some(name.into()),
            created_at: Utc::now(),
            findings: (0..n)
                .map(|i| FindingSummary {
                    title: format!("Finding {i}"),
                    severity: "high".into(),
                    description: format!("Description {i}"),
                    asset: None,
                    evidence: None,
                    risk_score: None,
                })
                .collect(),
            assets: vec![],
            scan_count: 1,
        }
    }

    // ── Campaign report tests ─────────────────────────────────────────────────

    #[test]
    fn campaign_report_includes_all_targets() {
        let data = CampaignReportData {
            campaign_name: "Test Campaign".into(),
            targets: vec![
                ("web.example.com".into(), make_report_data("web", 3)),
                ("api.example.com".into(), make_report_data("api", 2)),
            ],
        };
        let md = build_campaign_markdown(&data, ReportTemplate::Executive);
        assert!(md.contains("web.example.com"), "missing web target");
        assert!(md.contains("api.example.com"), "missing api target");
        assert!(md.contains("Campaign Overview"), "missing overview section");
        assert!(md.contains("Targets scanned:** 2"), "wrong target count");
    }

    #[test]
    fn campaign_report_total_findings() {
        let data = CampaignReportData {
            campaign_name: "Count Campaign".into(),
            targets: vec![
                ("host-a".into(), make_report_data("a", 3)),
                ("host-b".into(), make_report_data("b", 2)),
            ],
        };
        let md = build_campaign_markdown(&data, ReportTemplate::Executive);
        // 3 + 2 = 5 total findings
        assert!(
            md.contains("Total findings:** 5"),
            "wrong total findings count"
        );
    }

    #[test]
    fn campaign_report_severity_table() {
        let mut target_data = make_report_data("mixed", 0);
        target_data.findings = vec![
            FindingSummary {
                title: "Crit".into(),
                severity: "critical".into(),
                description: "desc".into(),
                asset: None,
                evidence: None,
                risk_score: None,
            },
            FindingSummary {
                title: "High".into(),
                severity: "high".into(),
                description: "desc".into(),
                asset: None,
                evidence: None,
                risk_score: None,
            },
            FindingSummary {
                title: "Medium".into(),
                severity: "medium".into(),
                description: "desc".into(),
                asset: None,
                evidence: None,
                risk_score: None,
            },
        ];

        let data = CampaignReportData {
            campaign_name: "Severity Campaign".into(),
            targets: vec![("mixed-host".into(), target_data)],
        };
        let md = build_campaign_markdown(&data, ReportTemplate::Detailed);

        // The severity table must exist
        assert!(
            md.contains("| Target | Findings |"),
            "missing severity table header"
        );
        // mixed-host row: 3 findings, 1 critical, 1 high, 1 medium, 0 low
        assert!(
            md.contains("| mixed-host | 3 | 1 | 1 | 1 | 0 |"),
            "wrong severity row"
        );
    }

    #[test]
    fn campaign_report_empty_targets() {
        let data = CampaignReportData {
            campaign_name: "Empty Campaign".into(),
            targets: vec![],
        };
        let md = build_campaign_markdown(&data, ReportTemplate::Executive);
        assert!(md.contains("Targets scanned:** 0"), "zero targets");
        assert!(md.contains("Total findings:** 0"), "zero findings");
    }

    #[test]
    fn campaign_report_per_target_details() {
        let data = CampaignReportData {
            campaign_name: "Detail Campaign".into(),
            targets: vec![
                ("first.host".into(), make_report_data("first", 1)),
                ("second.host".into(), make_report_data("second", 1)),
            ],
        };
        let md = build_campaign_markdown(&data, ReportTemplate::Detailed);
        assert!(
            md.contains("## Per-Target Details"),
            "missing per-target section"
        );
        assert!(
            md.contains("### 1. first.host"),
            "missing first target heading"
        );
        assert!(
            md.contains("### 2. second.host"),
            "missing second target heading"
        );
    }

    /// `target: None` must not panic and must produce a valid header without
    /// the target line.
    #[test]
    fn no_target_produces_valid_header() {
        let data = ReportData {
            session_name: "Targetless Session".into(),
            target: None,
            created_at: chrono::Utc::now(),
            findings: vec![],
            assets: vec![],
            scan_count: 0,
        };

        for template in [
            ReportTemplate::Executive,
            ReportTemplate::Detailed,
            ReportTemplate::Technical,
        ] {
            let md = build_markdown(&data, template);
            assert!(
                md.contains("# SIGINT Security Report"),
                "template {:?}: must have report header even without target",
                template
            );
            assert!(
                !md.contains("**Target:**"),
                "template {:?}: must not emit Target line when target is None",
                template
            );
        }
    }

    // ── Executive summary and risk score tests ────────────────────────────────

    /// Build a ReportData whose findings are supplied as a slice of
    /// (title, severity, asset, risk_score) tuples.
    fn make_report_data_with_findings(
        findings: Vec<(&str, &str, Option<&str>, Option<f32>)>,
    ) -> ReportData {
        ReportData {
            session_name: "Summary Test Session".into(),
            target: Some("test.example.com".into()),
            created_at: Utc::now(),
            findings: findings
                .into_iter()
                .map(|(title, severity, asset, risk_score)| FindingSummary {
                    title: title.into(),
                    severity: severity.into(),
                    description: format!("Description for {title}"),
                    asset: asset.map(|a| a.to_string()),
                    evidence: None,
                    risk_score,
                })
                .collect(),
            assets: vec![
                AssetSummary {
                    kind: "host".into(),
                    value: "api.example.com".into(),
                    services_count: 2,
                },
                AssetSummary {
                    kind: "host".into(),
                    value: "web.example.com".into(),
                    services_count: 1,
                },
            ],
            scan_count: 3,
        }
    }

    #[test]
    fn executive_summary_in_executive_template() {
        let data = make_report_data_with_findings(vec![
            (
                "SQL Injection",
                "critical",
                Some("api.example.com"),
                Some(9.5),
            ),
            ("XSS", "medium", Some("web.example.com"), Some(5.5)),
        ]);
        let md = build_markdown(&data, ReportTemplate::Executive);
        assert!(
            md.contains("Executive Summary"),
            "missing Executive Summary section"
        );
        assert!(md.contains("2** findings"), "wrong finding count");
        assert!(md.contains("1** critical"), "wrong critical count");
        assert!(
            md.contains("SQL Injection"),
            "missing highest-risk finding title"
        );
    }

    #[test]
    fn executive_summary_in_detailed_template() {
        let data = make_report_data_with_findings(vec![("Test", "high", None, None)]);
        let md = build_markdown(&data, ReportTemplate::Detailed);
        assert!(
            md.contains("Executive Summary"),
            "Detailed template missing Executive Summary"
        );
    }

    #[test]
    fn executive_summary_empty_findings() {
        let data = make_report_data_with_findings(vec![]);
        let md = build_markdown(&data, ReportTemplate::Executive);
        assert!(
            md.contains("Executive Summary"),
            "missing Executive Summary section"
        );
        assert!(md.contains("0** findings"), "wrong zero finding count");
    }

    #[test]
    fn risk_score_displayed_in_detailed() {
        let data = make_report_data_with_findings(vec![("Vuln", "high", None, Some(8.0))]);
        let md = build_markdown(&data, ReportTemplate::Detailed);
        assert!(
            md.contains("8.0"),
            "risk score 8.0 not rendered in Detailed template"
        );
    }

    // ── SVG severity pie chart tests ─────────────────────────────────────────

    /// Build a minimal FindingSummary for chart tests.
    fn make_finding_summary(
        title: &str,
        severity: &str,
        risk_score: Option<f32>,
    ) -> FindingSummary {
        FindingSummary {
            title: title.into(),
            severity: severity.into(),
            description: format!("Description for {title}"),
            asset: None,
            evidence: None,
            risk_score,
        }
    }

    #[test]
    fn severity_chart_contains_svg() {
        let findings = vec![
            make_finding_summary("Vuln1", "critical", Some(9.5)),
            make_finding_summary("Vuln2", "high", Some(8.0)),
            make_finding_summary("Vuln3", "medium", Some(5.5)),
        ];
        let svg = render_severity_chart(&findings);
        assert!(svg.contains("<svg"), "must contain opening SVG tag");
        assert!(svg.contains("</svg>"), "must contain closing SVG tag");
        assert!(svg.contains("#dc2626"), "must contain critical color");
        assert!(svg.contains("#ea580c"), "must contain high color");
    }

    #[test]
    fn severity_chart_empty_findings() {
        let svg = render_severity_chart(&[]);
        assert!(svg.is_empty(), "empty findings must produce empty string");
    }

    #[test]
    fn severity_chart_single_severity() {
        let findings = vec![make_finding_summary("Only", "critical", None)];
        let svg = render_severity_chart(&findings);
        assert!(
            svg.contains("<circle"),
            "single severity must use full circle, not arcs"
        );
        assert!(svg.contains("Critical: 1"), "must show label and count");
    }

    #[test]
    fn severity_chart_legend_shows_all_active() {
        let findings = vec![
            make_finding_summary("A", "critical", None),
            make_finding_summary("B", "high", None),
            make_finding_summary("C", "low", None),
        ];
        let svg = render_severity_chart(&findings);
        assert!(svg.contains("Critical: 1"), "legend must show Critical");
        assert!(svg.contains("High: 1"), "legend must show High");
        assert!(svg.contains("Low: 1"), "legend must show Low");
        // Medium and Info have zero counts — must NOT appear in legend.
        assert!(
            !svg.contains("Medium:"),
            "legend must not show zero-count Medium"
        );
        assert!(
            !svg.contains("Info:"),
            "legend must not show zero-count Info"
        );
    }

    #[test]
    fn executive_summary_includes_chart_in_html() {
        let data = make_report_data_with_findings(vec![("Vuln", "critical", None, Some(9.5))]);
        let md = build_markdown(&data, ReportTemplate::Executive);
        assert!(
            md.contains("<svg"),
            "Executive template must embed SVG chart when findings exist"
        );
    }

    #[test]
    fn executive_summary_no_chart_when_empty() {
        let data = make_report_data_with_findings(vec![]);
        let md = build_markdown(&data, ReportTemplate::Executive);
        assert!(
            !md.contains("<svg"),
            "Executive template must not embed SVG chart when no findings"
        );
    }
}
