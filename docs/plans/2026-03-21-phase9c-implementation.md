# Phase 9C: Report Polish + Risk Scoring — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add severity-based risk scoring to findings, executive summary sections to reports, and an inline SVG severity pie chart in HTML output.

**Architecture:** New `cvss_score: Option<f32>` field on Finding, severity-to-score mapping, executive summary prepended to all report templates, SVG pie chart generated in Rust and embedded in HTML output.

**Tech Stack:** Rust, rusqlite (migration), pulldown-cmark (HTML), inline SVG generation (no JS deps).

**Design doc:** `docs/plans/2026-03-21-phase9-design.md` (Sub-Phase 9C, lines 603-688)

---

### Task 1: Migration + Finding Type — cvss_score Field

**Files:**
- Modify: `crates/sigint-store/src/migrations.rs`
- Modify: `crates/sigint-core/src/types.rs` (Finding struct, ~line 215)
- Modify: `crates/sigint-store/src/findings.rs`

Add migration 6: `ALTER TABLE findings ADD COLUMN cvss_score REAL`

Add `cvss_score: Option<f32>` to Finding struct. Initialize as `None` in constructors.

Add `severity_default_score(severity: &Severity) -> f32` mapping:
- Critical: 9.5, High: 8.0, Medium: 5.5, Low: 2.0, Info: 0.0

Update `create_finding()` INSERT and `get_findings()` SELECT to include cvss_score.

**Tests:** migration test, roundtrip with score, severity_default_score mapping, finding without score defaults to None.

---

### Task 2: FindingSummary — Risk Score + Executive Summary

**Files:**
- Modify: `crates/sigint-report/src/builder.rs`

Add `risk_score: Option<f32>` to FindingSummary.

Add executive summary section to all three templates. Insert after header, before findings:

```markdown
## Executive Summary

This engagement identified **{total}** findings across **{asset_count}** assets:
**{critical}** critical, **{high}** high, **{medium}** medium, **{low}** low.

The highest-risk finding is "{highest_title}" ({highest_severity}) affecting {highest_asset}.

Immediate remediation is recommended for all critical and high findings.
```

Add risk score display in detailed/technical templates when present.

**Tests:** executive summary present in all templates, risk score displayed when set, highest finding identified correctly, empty findings handled.

---

### Task 3: SVG Severity Pie Chart in HTML

**Files:**
- Modify: `crates/sigint-report/src/format.rs`
- Modify: `crates/sigint-report/src/builder.rs`

Generate an inline SVG pie chart showing severity distribution. Pure Rust arc path calculation — no JS, no external deps.

Add `render_severity_chart(findings: &[FindingSummary]) -> String` that produces an `<svg>` element with colored segments:
- Critical: #dc2626 (red)
- High: #ea580c (orange)
- Medium: #ca8a04 (yellow)
- Low: #2563eb (blue)
- Info: #6b7280 (gray)

Embed the SVG in the markdown as a raw HTML block (pulldown-cmark passes HTML through). Insert it in the executive summary section.

**Tests:** SVG contains `<svg`, correct segment count, empty findings produces no chart, single-severity fills full circle.

---

### Task 4: Full Workspace Verification

- `cargo test --workspace` — all pass
- `cargo clippy --workspace`
- Verify HTML report contains SVG and executive summary
- Commit and prepare for merge

---

## Verification

1. Unit tests for score mapping, executive summary, SVG generation
2. `cargo run -- report --help` still works
3. Generate a test report with findings and verify executive summary + chart appear in HTML output
