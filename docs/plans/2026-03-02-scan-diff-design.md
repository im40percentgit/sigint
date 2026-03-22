# Scan Diff & Trending — Design Document

**Date:** 2026-03-02
**Status:** approved
**Approach:** Pure diff engine in sigint-core, exposed via CLI + API

## Context

SIGINT can run scans and produce findings, but has no way to compare results across scans. Users want to see what changed between two scans of the same target — new vulnerabilities, fixed issues, and unchanged findings.

## Design Decisions

- **Scope:** Findings only (not assets or services). Extensible later.
- **Matching key:** `(title.to_lowercase(), asset.unwrap_or_default())` — same vulnerability on same target = same finding
- **Categories:** New (in B not A), Fixed (in A not B), Unchanged (in both)
- **Interfaces:** CLI (`sigint diff <a> <b>`) + API (`GET /api/diff/{a}/{b}`)
- **Output formats:** JSON (default) and markdown (CLI flag)
- **Architecture:** Pure diff logic in `sigint-core/src/diff.rs`, no DB dependency in diff function

## Data Model

Existing `Finding` struct provides all needed fields:
- `title: String` — finding name (part of match key)
- `asset: Option<String>` — affected target (part of match key)
- `severity: Severity` — for display/sorting
- `description: String` — for display
- `session_id: Uuid` — links finding to scan

## Diff Algorithm

```rust
pub struct ScanDiff {
    pub scan_a: Uuid,
    pub scan_b: Uuid,
    pub new: Vec<Finding>,       // in B but not A
    pub fixed: Vec<Finding>,     // in A but not B
    pub unchanged: Vec<Finding>, // in both
}

pub fn diff_findings(scan_a: Uuid, findings_a: &[Finding], scan_b: Uuid, findings_b: &[Finding]) -> ScanDiff
```

1. Build HashMap from match key → Finding for each scan
2. Iterate B's keys: if not in A → new; if in A → unchanged
3. Iterate A's keys: if not in B → fixed

## API Endpoint

`GET /api/diff/{scan_a}/{scan_b}` → 200 JSON:
```json
{
  "scan_a": "uuid-a",
  "scan_b": "uuid-b",
  "summary": { "new": 3, "fixed": 1, "unchanged": 5 },
  "new": [{ "title": "...", "severity": "high", "asset": "..." }],
  "fixed": [{ "title": "...", "severity": "medium", "asset": "..." }],
  "unchanged": [{ "title": "...", "severity": "...", "asset": "..." }]
}
```

Error cases: 404 if either scan ID doesn't exist, 400 if UUIDs malformed.

## CLI Command

```
sigint diff <scan_a> <scan_b> [--format json|markdown]
```

- Default format: JSON (consistent with other commands)
- Markdown format: human-readable table with severity-sorted sections
- Exit code 0 on success, 1 on error

## Files

- `sigint-core/src/diff.rs` (new) — ScanDiff struct + diff_findings()
- `sigint-web/src/routes.rs` — add diff handler + route
- `sigint-cli/src/diff.rs` (new) — diff subcommand
- `sigint-cli/src/main.rs` — add Diff variant to clap
- `tests/e2e/tests/diff.rs` (new) — E2E test for diff endpoint

## Dependencies

No new crate dependencies. Uses existing:
- `sigint-core` (Finding, Severity types)
- `sigint-store` (get_findings for DB access)
- `sigint-web` (Axum routing)
- `sigint-cli` (clap subcommands)
