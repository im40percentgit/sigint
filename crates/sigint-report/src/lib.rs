//! sigint-report — report generation for SIGINT scan sessions.
//!
//! Provides Markdown and HTML report output in three templates:
//! - [`ReportTemplate::Executive`] — management summary with severity counts.
//! - [`ReportTemplate::Detailed`] — full findings with descriptions and asset table.
//! - [`ReportTemplate::Technical`] — findings with raw evidence and service inventory.
//!
//! # Quick start
//!
//! ```rust,no_run
//! use sigint_report::{ReportData, ReportTemplate, ReportFormat, build_report};
//! use chrono::Utc;
//!
//! let data = ReportData {
//!     session_name: "Example Engagement".into(),
//!     target: Some("example.com".into()),
//!     created_at: Utc::now(),
//!     findings: vec![],
//!     assets: vec![],
//!     scan_count: 0,
//! };
//!
//! let bytes = build_report(&data, ReportTemplate::Detailed, ReportFormat::Markdown);
//! println!("{}", String::from_utf8(bytes).unwrap());
//! ```

pub mod builder;
pub mod format;

pub use builder::{
    AssetSummary, FindingSummary, ReportData, ReportFormat, ReportTemplate,
    build_markdown, build_report,
};
pub use format::markdown_to_html;
