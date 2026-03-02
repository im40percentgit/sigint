//! HTML rendering for Markdown report output.
//!
//! Converts Markdown (produced by the builder module) into a complete,
//! self-contained HTML document using the `pulldown-cmark` library.
//!
//! @decision DEC-REPORT-002
//! @title pulldown-cmark for Markdown-to-HTML rendering
//! @status accepted
//! @rationale pulldown-cmark is the de-facto Rust Markdown parser: it is fast,
//! well-maintained, CommonMark-compliant, and handles tables and fenced code
//! blocks which the report templates rely on.  The alternative (rendering HTML
//! directly without Markdown) would require duplicating all template logic.
//! Piping through pulldown-cmark keeps the builder templates readable as
//! Markdown while still producing valid HTML output.

use pulldown_cmark::{html, Options, Parser};

/// Embedded CSS for the HTML wrapper.
///
/// Deliberately minimal: readable on screen, print-friendly, no external
/// dependencies.  The palette is dark-on-light for professional reports.
const EMBEDDED_CSS: &str = r#"
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    font-size: 15px;
    line-height: 1.6;
    color: #1a1a2e;
    background: #ffffff;
    max-width: 900px;
    margin: 40px auto;
    padding: 0 24px 60px;
  }
  h1 { font-size: 2em; border-bottom: 2px solid #1a1a2e; padding-bottom: 8px; }
  h2 { font-size: 1.4em; border-bottom: 1px solid #d0d0d0; padding-bottom: 4px; margin-top: 2em; }
  h3 { font-size: 1.1em; margin-top: 1.5em; }
  table { border-collapse: collapse; width: 100%; margin: 1em 0; }
  th, td { border: 1px solid #c8c8c8; padding: 6px 12px; text-align: left; }
  th { background: #f4f4f8; font-weight: 600; }
  tr:nth-child(even) { background: #f9f9fb; }
  code { background: #f0f0f4; border-radius: 3px; padding: 1px 5px; font-size: 0.9em; }
  pre { background: #1a1a2e; color: #e8e8f0; border-radius: 6px; padding: 16px; overflow-x: auto; }
  pre code { background: none; padding: 0; color: inherit; }
  blockquote { border-left: 4px solid #c8c8d8; margin-left: 0; padding-left: 16px; color: #555; }
  strong { font-weight: 700; }
  @media print {
    body { max-width: 100%; margin: 0; padding: 0 1cm; }
    h1 { page-break-after: avoid; }
    table { page-break-inside: avoid; }
  }
"#;

/// Convert a Markdown string into a complete, self-contained HTML document.
///
/// The HTML uses embedded CSS (no external resources), making it suitable for
/// sending as an email attachment or saving as a standalone file.
pub fn markdown_to_html(markdown: &str) -> String {
    // Enable extensions that the report templates use: tables and strikethrough.
    let opts = Options::ENABLE_TABLES
        | Options::ENABLE_STRIKETHROUGH
        | Options::ENABLE_HEADING_ATTRIBUTES;

    let parser = Parser::new_ext(markdown, opts);

    let mut body = String::with_capacity(markdown.len() * 2);
    html::push_html(&mut body, parser);

    format!(
        "<!DOCTYPE html>\n\
         <html lang=\"en\">\n\
         <head>\n\
         <meta charset=\"UTF-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>SIGINT Security Report</title>\n\
         <style>{EMBEDDED_CSS}</style>\n\
         </head>\n\
         <body>\n\
         {body}\
         </body>\n\
         </html>\n"
    )
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markdown_to_html_wraps_in_document() {
        let html = markdown_to_html("# Hello World\n\nSome text.");
        assert!(html.contains("<html"), "should open <html> tag");
        assert!(html.contains("<h1>"), "should render h1");
        assert!(html.contains("Hello World"), "should preserve heading text");
        assert!(html.contains("</html>"), "should close with </html>");
    }

    #[test]
    fn tables_rendered() {
        let md = "| A | B |\n|---|---|\n| 1 | 2 |\n";
        let html = markdown_to_html(md);
        assert!(html.contains("<table>"), "should render HTML table");
        assert!(html.contains("<th>"), "should render table headers");
        assert!(html.contains("<td>"), "should render table cells");
    }

    #[test]
    fn code_blocks_rendered() {
        let md = "```\nfoo --bar\n```\n";
        let html = markdown_to_html(md);
        assert!(html.contains("<pre>"), "should render code block as <pre>");
        assert!(html.contains("<code>"), "should wrap code in <code>");
        assert!(html.contains("foo --bar"), "should preserve code content");
    }
}
