# Phase 9 Design: Session Intelligence & Campaign Mode

**Date:** 2026-03-21
**Status:** proposed
**Complexity:** Tier 2 (Standard)
**Crates touched:** sigint-core, sigint-store, sigint-cli, sigint-tui, sigint-agents, sigint-report, sigint-web

---

## Problem Statement

SIGINT scans are currently one-shot: each `sigint scan` creates a new session and runs from
scratch. When pentesters revisit a target days or weeks later they must manually compare
previous reports to identify what changed. The existing scan diff engine (`sigint diff`) can
compare two sessions, but the user must know both session UUIDs and run a separate command. There
is no way to say "re-scan this target and show me what's new."

Separately, pentesters working on large engagements with 10-50 targets must run SIGINT
individually against each one, manually tracking which targets have been scanned and mentally
aggregating results. There is no batch execution or cross-target reporting.

These gaps reduce SIGINT's value for real-world engagements where iterative scanning and
multi-target operations are table stakes.

## Goals

- REQ-GOAL-001: Pentesters can resume a prior session with one command and immediately see what
  findings changed since the last scan
- REQ-GOAL-002: Batch execution across multiple targets produces per-target and aggregated
  cross-target reports without manual orchestration
- REQ-GOAL-003: Diff results are visible inline in both TUI and Web interfaces with
  color-coded visual distinction
- REQ-GOAL-004: Campaign profiles are data-driven (JSON) and extensible without code changes

## Non-Goals

- REQ-NOGO-001: Parallel/concurrent multi-target scanning -- targets execute sequentially in
  Phase 9; parallelism is a future optimization (requires careful resource management and
  output interleaving)
- REQ-NOGO-002: Continuous monitoring / scheduled rescans -- Phase 9 is manual invocation
  only; cron-style scheduling is a separate feature
- REQ-NOGO-003: CVSS v4 score calculator with full vector string parsing -- 9C adds a
  simplified severity scoring model, not a standards-compliant CVSS calculator
- REQ-NOGO-004: Target discovery / network enumeration for campaign files -- users provide
  the target list; SIGINT does not auto-discover targets
- REQ-NOGO-005: Campaign file format for non-JSON (YAML, TOML) -- JSON is the only format
  for v1; extensibility comes from the profile system, not the file format

## Requirements

### Must-Have (P0)

- REQ-P0-001: `sigint resume <session-uuid-prefix>` CLI command that re-scans the same target
  as the prior session and auto-diffs against prior findings
  - Acceptance: Given a prior session with target "example.com" and 3 findings, When
    `sigint resume <prefix>` runs, Then a new session is created targeting "example.com",
    the scan completes, and the diff (new/fixed/unchanged) is printed to stdout

- REQ-P0-002: Session lookup by UUID prefix (minimum 4 characters) using existing
  `list_sessions()` with client-side prefix filtering
  - Acceptance: Given sessions with UUIDs starting "a1b2c..." and "a1d3e...", When the user
    provides prefix "a1b2", Then the correct session is uniquely matched; When "a1" matches
    multiple, Then an error lists all matches

- REQ-P0-003: TUI session picker that lists prior sessions for resume selection
  - Acceptance: Given 5 prior sessions, When the user types "resume" in the TUI input bar,
    Then a selectable list of sessions appears showing name, target, date, and finding count;
    When a session is selected, Then a resume scan starts against that session's target

- REQ-P0-004: Diff highlights in TUI -- new findings (green), fixed (strikethrough/dim),
  unchanged (default)
  - Acceptance: Given a resume scan that produces diff results, When the TUI Findings panel
    renders, Then new findings appear with green foreground, fixed findings appear with
    strikethrough/dim styling, and unchanged findings appear in default style

- REQ-P0-005: `sigint campaign run --file targets.json` CLI command for batch multi-target
  execution
  - Acceptance: Given a targets.json with 3 entries, When `sigint campaign run --file targets.json`
    runs, Then each target is scanned sequentially, per-target results are printed, and an
    aggregated summary is printed at the end

- REQ-P0-006: Campaign file format with name, target, and profile fields parsed and validated
  before execution begins
  - Acceptance: Given a targets.json with `[{"name":"web","target":"example.com","profile":"web"}]`,
    When parsed, Then the target, name, and profile are extracted; When a required field is
    missing, Then a clear error is shown before any scans start

- REQ-P0-007: Profile templates that map to tool subsets and agent prompt adjustments,
  loaded from JSON without code changes
  - Acceptance: Given a profile "web" with `tools: ["nmap_scan", "gobuster"]` and
    `focus: "web application vulnerabilities"`, When a campaign target uses this profile,
    Then the orchestrator's agent prompts are adjusted to focus on web vulnerabilities and
    only the specified tools are available

### Nice-to-Have (P1)

- REQ-P1-001: Aggregated cross-target campaign report in Markdown and HTML
- REQ-P1-002: Web UI diff highlights (CSS classes) via WebSocket DiffResult events
- REQ-P1-003: `sigint campaign status` to show progress of an in-progress or completed campaign
- REQ-P1-004: Resume scan handles unreachable targets gracefully with a clear error message
  rather than a scan failure

### Future Consideration (P2)

- REQ-P2-001: CVSS-style severity scoring for findings with numeric score field
- REQ-P2-002: Executive summary section in reports with auto-generated narrative
- REQ-P2-003: HTML report severity pie chart and remediation timeline
- REQ-P2-004: Parallel campaign execution (2-4 concurrent targets)
- REQ-P2-005: Campaign diff -- compare results of the same campaign run at two different times

---

## Architectural Decisions

### DEC-RESUME-001: Resume creates a new session linked to the prior session, then auto-diffs

**Problem:** How should `sigint resume` relate the new scan to the prior session?

**Options considered:**
1. Modify the existing session in-place (append new findings to the same session) -- rejected:
   destroys the temporal record; the user cannot see "what was found on March 1 vs March 21"
2. Create a new session with a `parent_session_id` foreign key linking to the prior session,
   then auto-diff after scan completes -- **selected**
3. Create a standalone session and require the user to manually diff -- rejected: defeats the
   purpose of the `resume` command

**Decision:** `resume` creates a new session with the same target. A new nullable column
`parent_session_id` on the `sessions` table links child to parent. After the scan completes,
`diff_findings()` is called automatically with the parent session's findings as scan_a and
the new session's findings as scan_b. The diff result is printed and emitted via EventBus.

**Rationale:** The parent link enables the TUI and Web to offer "resume again" without the
user needing to know UUIDs. It also enables future chain-of-scans visualization (session A
-> B -> C). The diff engine already exists in `sigint-core/src/diff.rs` and requires only
two sets of findings -- no new algorithm needed.

**Migration:** `ALTER TABLE sessions ADD COLUMN parent_session_id TEXT REFERENCES sessions(id)`.
Nullable, so all existing sessions remain valid.

**Addresses:** REQ-P0-001, REQ-P0-002, REQ-GOAL-001

### DEC-RESUME-002: UUID prefix matching via client-side filter on list_sessions()

**Problem:** Users should not need to type full 36-char UUIDs for resume.

**Options considered:**
1. SQL LIKE query: `WHERE id LIKE 'prefix%'` -- rejected: TEXT UUIDs with LIKE are fine
   but coupling prefix logic to the store layer adds a new query method for a simple operation
2. Client-side filter: call `list_sessions()`, filter by `starts_with(prefix)` -- **selected**
3. Shortest-unique-prefix matching (git style) -- rejected: over-engineering for the session
   count we expect (tens to hundreds)

**Decision:** The CLI calls `db.list_sessions()` and filters by UUID prefix. If exactly one
match, proceed. If zero matches, error. If multiple matches, print all matches and ask the
user to provide a longer prefix.

**Rationale:** Reuses the existing `list_sessions()` query. The session count for any
realistic SIGINT deployment is small enough (< 1000) that loading all sessions and filtering
client-side is negligible overhead. This matches the existing pattern in `report.rs`
(DEC-CLI-005) which already does prefix matching for the report command.

**Addresses:** REQ-P0-002

### DEC-CAMPAIGN-001: Campaign file is a flat JSON array with per-target profile references

**Problem:** What format should campaign files use, and how should profiles work?

**Options considered:**
1. Inline all configuration per target -- rejected: massive duplication for 50-target campaigns
2. Separate profiles section + target references -- **selected**: `{ "profiles": {...}, "targets": [...] }`
3. External profile files referenced by path -- rejected: complicates distribution; the campaign
   file should be self-contained

**Decision:** Campaign file structure:
```json
{
  "profiles": {
    "web": {
      "tools": ["nmap_scan", "shell"],
      "focus": "web application security testing",
      "max_iterations": 15
    },
    "infra": {
      "tools": ["nmap_scan", "shell"],
      "focus": "infrastructure and network security",
      "max_iterations": 10
    }
  },
  "targets": [
    { "name": "Main Website", "target": "example.com", "profile": "web" },
    { "name": "Internal API", "target": "api.internal.com", "profile": "web" },
    { "name": "VPN Gateway", "target": "vpn.example.com", "profile": "infra" }
  ]
}
```

Profiles define: `tools` (which tools the orchestrator makes available), `focus` (injected
into agent system prompts to steer reasoning), `max_iterations` (optional override). Targets
reference profiles by name.

**Rationale:** Self-contained JSON is easy to version control, share between team members,
and validate upfront before any scans run. The profile mechanism is extensible -- new fields
(ports, scan_type, timeout) can be added later without breaking existing files (serde
`#[serde(default)]`). No code changes needed to add new profiles -- only the JSON file changes.

**Addresses:** REQ-P0-005, REQ-P0-006, REQ-P0-007, REQ-GOAL-002, REQ-GOAL-004

### DEC-CAMPAIGN-002: Campaign state stored as a session group with a campaign_id column

**Problem:** How to persist campaign results for aggregated reporting?

**Options considered:**
1. No persistence -- just run scans and print results -- rejected: loses the ability to
   generate aggregated reports after the fact
2. New `campaigns` table with a `campaign_id` FK on sessions -- **selected**
3. Tags/labels on sessions -- rejected: less structured, harder to query reliably

**Decision:** New `campaigns` table: `(id TEXT PK, name TEXT, file_path TEXT, created_at TEXT,
completed_at TEXT)`. Add nullable `campaign_id TEXT REFERENCES campaigns(id)` to sessions.
Each campaign run creates one campaigns row and N session rows linked by campaign_id.

**Rationale:** Enables `sigint campaign status` and aggregated report generation by querying
all sessions for a campaign_id. The FK on sessions is nullable so non-campaign sessions
(regular scans, resumes) are unaffected.

**Migration:** Two statements: CREATE TABLE campaigns, ALTER TABLE sessions ADD COLUMN campaign_id.

**Addresses:** REQ-P0-005, REQ-P1-001, REQ-P1-003

### DEC-DIFF-UI-001: Diff results emitted as a new Event::ScanDiffCompleted variant

**Problem:** How do TUI and Web interfaces receive diff results for rendering?

**Options considered:**
1. TUI polls the database for diff after scan completes -- rejected: violates the event-driven
   architecture (DEC-P3-TUI-001); polling adds latency and complexity
2. New `Event::ScanDiffCompleted(ScanDiff)` event -- **selected**

**Decision:** After a resume scan completes and `diff_findings()` runs, emit
`Event::ScanDiffCompleted { diff: ScanDiff }` on the EventBus. The TUI's `AppState.apply()`
stores the diff and the Findings panel renderer uses it to color-code findings. The Web
WebSocket handler serializes it to JSON for browser clients.

**Rationale:** Consistent with the existing event-driven architecture. ScanDiff is already
`Serialize` (via `#[derive(Serialize)]` in `sigint-core/src/diff.rs`), so it flows through
the EventBus and WebSocket without changes. AppState remains a pure state machine.

**Addresses:** REQ-P0-004, REQ-P1-002, REQ-GOAL-003

### DEC-REPORT-003: Campaign report reuses existing ReportData with a cross-target aggregation wrapper

**Problem:** How to generate aggregated campaign reports without duplicating the report builder?

**Options considered:**
1. New report builder for campaigns -- rejected: duplicates template code
2. Wrapper that collects per-target ReportData and adds a summary section -- **selected**

**Decision:** New `CampaignReportData` struct wraps `Vec<(String, ReportData)>` (target name
+ per-target data). The campaign report builder renders a "Campaign Overview" section with
cross-target severity counts and per-target summary tables, then appends each per-target
report. Uses the existing `build_markdown()` for per-target sections.

**Rationale:** Reuses all existing report infrastructure. The overview section is new code
(severity aggregation across targets) but each target's detail section is rendered by the
existing builder unchanged.

**Addresses:** REQ-P1-001

### Research Skip Justification

All Phase 9 decisions use well-understood patterns already established in the codebase:
- Session resume builds on the existing diff engine (DEC-DIFF-001) and session store (DEC-STORE-001)
- Campaign mode is sequential orchestration with JSON config -- no new technology choices
- Report improvements extend the existing builder pattern (DEC-REPORT-001)
- TUI diff rendering extends AppState with one new field and uses ratatui styles already in use

No external research needed. All decisions are internal architecture refinements.

---

## Implementation Plan

### Sub-Phase 9A: Session Resume + Diff UI (Foundation)

**Files modified:**

- `crates/sigint-store/src/migrations.rs` -- add migration for `parent_session_id` column
  on sessions table
- `crates/sigint-store/src/sessions.rs` -- extend `create_session()` to accept optional
  parent_session_id; add `find_sessions_by_target(target: &str)` query; add
  `get_session_by_prefix(prefix: &str)` that calls list_sessions + filter
- `crates/sigint-core/src/types.rs` -- add `parent_session_id: Option<Uuid>` to Session struct
- `crates/sigint-core/src/event.rs` -- add `Event::ScanDiffCompleted { diff: ScanDiff }` variant
- `crates/sigint-cli/src/main.rs` -- add `Resume` subcommand with `session` positional arg
- `crates/sigint-cli/src/resume.rs` -- **NEW**: resume command handler
  - Parse session UUID prefix
  - Look up prior session via prefix match
  - Verify target field is present
  - Create new session with parent_session_id = prior session
  - Run scan pipeline (reuse logic from scan.rs)
  - Fetch findings for both sessions from DB
  - Call `diff_findings()` and emit `Event::ScanDiffCompleted`
  - Print diff summary to stdout
- `crates/sigint-tui/src/state.rs` -- add `scan_diff: Option<ScanDiff>` field; handle
  `ScanDiffCompleted` in `apply()`; add `diff_status(finding: &Finding) -> DiffStatus` method
  that checks if a finding is in the diff's new/fixed/unchanged lists
- `crates/sigint-tui/src/ui.rs` -- in Findings panel rendering, apply diff-aware styles:
  - `DiffStatus::New` -> green foreground (`Style::default().fg(Color::Green)`)
  - `DiffStatus::Fixed` -> dim + crossed-out (`Style::default().fg(Color::DarkGray).add_modifier(Modifier::CROSSED_OUT)`)
  - `DiffStatus::Unchanged` -> default style
  - `DiffStatus::NoDiff` -> default style (non-resume scans)
- `crates/sigint-agents/src/interactive.rs` -- extend `handle_input()` to support
  `resume <prefix>` command in TUI

**Session picker for TUI (REQ-P0-003):**

When the user types "resume" without arguments in the TUI, emit a status message listing
recent sessions with their UUID prefixes, targets, and dates. The user then types
`resume <prefix>` to select one. This avoids building a modal picker widget (which would
require significant TUI rework) and reuses the existing command dispatch pattern from
Phase 8B.

**Specific changes to `sessions.rs`:**

```rust
/// Find a session by UUID prefix (minimum 4 characters).
/// Returns Ok(session) if exactly one match, Err with all matches if ambiguous.
pub fn get_session_by_prefix(&self, prefix: &str) -> Result<Session, Error> {
    if prefix.len() < 4 {
        return Err(Error::Other("UUID prefix must be at least 4 characters".into()));
    }
    let sessions = self.list_sessions()?;
    let matches: Vec<Session> = sessions
        .into_iter()
        .filter(|s| s.id.to_string().starts_with(prefix))
        .collect();
    match matches.len() {
        0 => Err(Error::Other(format!("No session found matching prefix '{prefix}'"))),
        1 => Ok(matches.into_iter().next().unwrap()),
        n => {
            let listing: Vec<String> = matches.iter()
                .map(|s| format!("  {} — {} ({})", &s.id.to_string()[..8],
                    s.target.as_deref().unwrap_or("-"), s.name))
                .collect();
            Err(Error::Other(format!(
                "Prefix '{prefix}' matches {n} sessions:\n{}", listing.join("\n")
            )))
        }
    }
}
```

**Specific changes to `event.rs`:**

Add one new variant:
```rust
/// Diff results from a resume scan comparing new findings against a prior session.
ScanDiffCompleted {
    diff: crate::diff::ScanDiff,
},
```

**Specific changes to `state.rs`:**

Add field and helper:
```rust
/// Diff results from the most recent resume scan (None for non-resume scans).
pub scan_diff: Option<sigint_core::diff::ScanDiff>,
```

In `apply()`:
```rust
Event::ScanDiffCompleted { diff } => {
    self.scan_diff = Some(diff);
}
```

Helper enum and method:
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffStatus {
    New,
    Fixed,
    Unchanged,
    NoDiff,
}

impl AppState {
    /// Determine the diff status of a finding for color-coding in the Findings panel.
    pub fn diff_status(&self, finding: &Finding) -> DiffStatus {
        let Some(ref diff) = self.scan_diff else { return DiffStatus::NoDiff };
        let key = (finding.title.to_lowercase(), finding.asset.clone().unwrap_or_default());
        if diff.new.iter().any(|f| (f.title.to_lowercase(), f.asset.clone().unwrap_or_default()) == key) {
            DiffStatus::New
        } else if diff.fixed.iter().any(|f| (f.title.to_lowercase(), f.asset.clone().unwrap_or_default()) == key) {
            DiffStatus::Fixed
        } else {
            DiffStatus::Unchanged
        }
    }
}
```

**Specific changes to `resume.rs` (new file):**

```rust
/// Entry point for `sigint resume <session-prefix>`.
///
/// 1. Look up the prior session by UUID prefix.
/// 2. Verify it has a target.
/// 3. Create a new session with parent_session_id pointing to the prior session.
/// 4. Run the scan pipeline (same as scan.rs).
/// 5. Diff findings between prior and new session.
/// 6. Emit ScanDiffCompleted event.
/// 7. Print diff summary.
pub async fn run(
    core: AppCore,
    session_prefix: String,
    model: Option<String>,
    max_iterations: usize,
    force_tui: bool,
    force_no_tui: bool,
) -> Result<(), Error> { ... }
```

This function shares substantial setup with `scan::run()`. Extract common setup (provider
creation, registry, TUI/stdout printer, interactive session, DB/memory wiring) into a shared
helper or accept some duplication for clarity. The critical difference: resume looks up a
prior session, creates a child session with `parent_session_id`, and diffs after completion.

**Handling unreachable targets (REQ-P1-004):**

If the scan fails (e.g., target unreachable), emit a status event with a clear message:
"Resume scan of {target} failed: {error}. The prior session's findings remain unchanged."
The diff is not computed (no new findings to compare against).

**Tests for 9A:**

1. `sessions.rs`: `get_session_by_prefix_unique_match` -- exact prefix returns session
2. `sessions.rs`: `get_session_by_prefix_ambiguous_lists_matches` -- 2+ matches returns error
3. `sessions.rs`: `get_session_by_prefix_no_match_returns_error` -- no match
4. `sessions.rs`: `get_session_by_prefix_too_short_rejects` -- < 4 chars
5. `sessions.rs`: `session_with_parent_id_roundtrips` -- create session with parent, fetch, verify
6. `state.rs`: `scan_diff_completed_stores_diff` -- verify apply() stores ScanDiff
7. `state.rs`: `diff_status_new_finding_detected` -- finding in diff.new -> DiffStatus::New
8. `state.rs`: `diff_status_fixed_finding_detected` -- finding in diff.fixed -> DiffStatus::Fixed
9. `state.rs`: `diff_status_no_diff_returns_nodiff` -- when scan_diff is None
10. `event.rs`: `scan_diff_completed_serializes` -- JSON roundtrip
11. `resume.rs`: `resume_missing_target_errors` -- session without target field -> clear error
12. Integration: `sigint resume` against a known prior session (manual, requires Ollama)

**Estimated complexity:** Medium-high. The scan pipeline reuse and diff engine are
straightforward, but wiring up the TUI diff rendering and the CLI resume command touches
many files. The migration adds a schema change that must be tested.

---

### Sub-Phase 9B: Multi-Target Campaign Mode (Depends on 9A for patterns)

**Files modified:**

- `crates/sigint-store/src/migrations.rs` -- add migration for `campaigns` table and
  `campaign_id` column on sessions
- `crates/sigint-store/src/campaigns.rs` -- **NEW**: CRUD operations for campaigns table
  (`create_campaign`, `get_campaign`, `update_campaign_completed`, `get_campaign_sessions`)
- `crates/sigint-store/src/lib.rs` -- export campaigns module
- `crates/sigint-core/src/types.rs` -- add `Campaign` struct; add `campaign_id: Option<Uuid>`
  to Session
- `crates/sigint-cli/src/main.rs` -- add `Campaign` subcommand group with `run` and `status`
  sub-subcommands
- `crates/sigint-cli/src/campaign.rs` -- **NEW**: campaign command handler
- `crates/sigint-agents/src/orchestrator.rs` -- add `with_profile(profile: ScanProfile)` builder
  method that adjusts agent prompt focus and tool filtering

**Campaign file parsing:**

```rust
/// A campaign configuration file.
#[derive(Debug, Deserialize)]
pub struct CampaignFile {
    /// Named scan profiles with tool and prompt customization.
    #[serde(default)]
    pub profiles: HashMap<String, ScanProfile>,
    /// Targets to scan, each referencing a profile.
    pub targets: Vec<CampaignTarget>,
}

/// A scan profile that adjusts orchestrator behavior.
#[derive(Debug, Clone, Deserialize)]
pub struct ScanProfile {
    /// Which tools to make available (empty = all tools).
    #[serde(default)]
    pub tools: Vec<String>,
    /// Focus area injected into agent system prompts.
    #[serde(default)]
    pub focus: String,
    /// Override for max tool-call iterations per agent.
    pub max_iterations: Option<usize>,
    /// Override for port specification.
    pub ports: Option<String>,
}

/// A single target in a campaign.
#[derive(Debug, Deserialize)]
pub struct CampaignTarget {
    /// Human-readable name for this target.
    pub name: String,
    /// The target to scan (hostname, IP, CIDR).
    pub target: String,
    /// Name of the profile to use (must exist in profiles map).
    #[serde(default = "default_profile")]
    pub profile: String,
}
```

**Campaign execution flow:**

```rust
pub async fn run_campaign(core: AppCore, file_path: &str, ...) -> Result<(), Error> {
    // 1. Read and parse campaign file
    let content = std::fs::read_to_string(file_path)?;
    let campaign_file: CampaignFile = serde_json::from_str(&content)?;

    // 2. Validate: all target profiles exist in profiles map
    for target in &campaign_file.targets {
        if !campaign_file.profiles.contains_key(&target.profile) {
            return Err(Error::Other(format!(
                "Target '{}' references unknown profile '{}'", target.name, target.profile
            )));
        }
    }

    // 3. Create campaign record in DB
    let campaign = Campaign::new(&campaign_file, file_path);
    db.create_campaign(&campaign)?;

    // 4. Execute each target sequentially
    let mut results: Vec<(String, ScanReport, Option<ScanDiff>)> = Vec::new();
    for (i, target) in campaign_file.targets.iter().enumerate() {
        println!("\n[{}/{}] Scanning: {} ({})", i+1, campaign_file.targets.len(),
            target.name, target.target);

        let profile = &campaign_file.profiles[&target.profile];

        // Create session linked to campaign
        let session = Session::new(&target.name)
            .with_target(&target.target)
            .with_campaign_id(campaign.id);

        // Build orchestrator with profile adjustments
        let mut orchestrator = build_orchestrator(...)
            .with_profile(profile.clone());

        let report = orchestrator.run_scan(&target.target).await?;
        results.push((target.name.clone(), report, None));
    }

    // 5. Mark campaign complete
    db.update_campaign_completed(campaign.id)?;

    // 6. Print aggregated summary
    print_campaign_summary(&results);

    Ok(())
}
```

**Profile injection into Orchestrator:**

The `with_profile()` method on Orchestrator stores a `ScanProfile`. When `run_agent()` builds
the system prompt for each agent, it appends the profile's `focus` string:

```
[Original system prompt]

ENGAGEMENT FOCUS: {profile.focus}
Prioritize analysis and tool usage relevant to this focus area.
```

When the profile specifies `tools`, `ToolRegistry::for_role()` is filtered further to only
include tools in the profile's list. If `tools` is empty, all role-allowed tools are available
(default behavior).

**Tests for 9B:**

1. `campaign.rs`: `parse_valid_campaign_file` -- deserialize sample JSON
2. `campaign.rs`: `parse_campaign_with_missing_profile_errors` -- validation catches missing profile
3. `campaign.rs`: `parse_campaign_with_empty_targets_errors` -- validation catches empty targets
4. `campaign.rs`: `profile_defaults_applied` -- missing optional fields get defaults
5. `campaigns.rs`: `create_and_get_campaign_roundtrip` -- DB CRUD
6. `campaigns.rs`: `get_campaign_sessions_returns_linked` -- FK query
7. `orchestrator.rs`: `with_profile_filters_tools` -- profile with tools=["nmap_scan"] only
   exposes nmap
8. `orchestrator.rs`: `with_profile_injects_focus` -- system prompt contains focus text
9. Integration: `sigint campaign run --file test.json` with mock provider (manual)

**Estimated complexity:** Medium. Campaign parsing is straightforward serde. The Orchestrator
profile injection touches the hot path (system prompt + tool registry) but is additive -- no
existing behavior changes. Sequential execution is simpler than parallel.

---

### Sub-Phase 9C: Report Polish + Risk Scoring (Independent, P1/P2)

**Files modified:**

- `crates/sigint-core/src/types.rs` -- add optional `cvss_score: Option<f32>` field to Finding
- `crates/sigint-store/src/findings.rs` -- extend create/get to handle cvss_score column
- `crates/sigint-store/src/migrations.rs` -- add migration for cvss_score column
- `crates/sigint-report/src/builder.rs` -- add `CampaignReportData` struct and
  `build_campaign_markdown()`; add executive summary section to all templates; add severity
  score display when cvss_score is present
- `crates/sigint-report/src/format.rs` -- extend HTML template with severity pie chart
  (inline SVG, no JS dependencies) and remediation priority table

**Severity scoring model (simplified):**

Rather than full CVSS v3.1/v4.0 vector parsing, use a numeric severity score that maps from
the existing Severity enum:
- Critical: 9.0-10.0
- High: 7.0-8.9
- Medium: 4.0-6.9
- Low: 0.1-3.9
- Info: 0.0

The LLM Analyst agent can optionally set a more precise score within the range during analysis.
The `cvss_score` field on Finding is populated by the analyst's output when it includes a
numeric score; otherwise, it defaults to the midpoint of the severity range.

**Executive summary section:**

Added to all three templates (Executive, Detailed, Technical) as a second section after the
header:

```markdown
## Executive Summary

This engagement identified **{total}** findings across **{asset_count}** assets:
**{critical}** critical, **{high}** high, **{medium}** medium, **{low}** low.

The highest-risk finding is "{highest_title}" ({highest_severity}) affecting {highest_asset}.

Immediate remediation is recommended for all critical and high findings.
```

**Campaign report structure:**

```markdown
# SIGINT Campaign Report — {campaign_name}

## Campaign Overview
- **Targets scanned:** {count}
- **Total findings:** {total across all targets}
- **Date range:** {first scan start} to {last scan end}

| Target | Findings | Critical | High | Medium | Low |
|--------|----------|----------|------|--------|-----|
| web.example.com | 12 | 1 | 3 | 5 | 3 |
| api.example.com | 5  | 0 | 1 | 2 | 2 |

## Per-Target Details

### 1. web.example.com
[Full detailed report for this target, rendered by existing build_markdown()]

### 2. api.example.com
[Full detailed report for this target]
```

**HTML pie chart (inline SVG):**

A simple SVG pie chart generated in Rust using arc path calculations. No JavaScript, no
external dependencies. Segments colored by severity (red=critical, orange=high, yellow=medium,
blue=low, gray=info). The SVG is inlined directly in the HTML output.

**Tests for 9C:**

1. `builder.rs`: `executive_summary_included_in_all_templates` -- verify "Executive Summary"
   heading present
2. `builder.rs`: `campaign_report_includes_all_targets` -- verify each target appears
3. `builder.rs`: `campaign_report_severity_aggregation_correct` -- verify cross-target counts
4. `format.rs`: `html_pie_chart_rendered` -- verify `<svg` present in HTML output
5. `findings.rs`: `finding_with_cvss_score_roundtrips` -- DB CRUD with score
6. `types.rs`: `severity_to_default_score` -- verify enum -> score mapping

**Estimated complexity:** Medium. Report changes are additive (new functions, not modifications
to existing). The SVG pie chart is the most complex new code but is self-contained.

---

## Dependency Graph

```
9A (Session Resume + Diff UI) ──────────────┐
                                             ├──> 9B (Campaign Mode)
9C (Report Polish + Risk Scoring) [independent]
```

- **9A** is the foundation -- establishes the resume pattern, UUID prefix matching, and diff
  UI rendering that 9B reuses for campaign status display
- **9B** depends on 9A for the session creation patterns and diff infrastructure, but the
  Orchestrator profile injection is independent
- **9C** is fully independent -- report improvements and scoring touch no code in 9A or 9B

## Implementation Order

1. **Phase 9A** (first) -- Session Resume + Diff UI. Highest user-facing value; unlocks
   iterative scanning workflow. Medium-high risk due to schema migration and multi-file changes.
2. **Phase 9C** (parallel with 9A) -- Report Polish. Independent, lower risk, improves
   output quality. Can be started immediately.
3. **Phase 9B** (after 9A) -- Campaign Mode. Builds on 9A patterns. Lower risk since it
   follows established patterns; the new code is mostly orchestration glue.

## Definition of Done

- [ ] REQ-P0-001: `sigint resume <prefix>` re-scans target and prints diff
- [ ] REQ-P0-002: UUID prefix matching works with >= 4 characters
- [ ] REQ-P0-003: TUI "resume" command lists sessions; "resume <prefix>" starts resume scan
- [ ] REQ-P0-004: TUI Findings panel shows diff colors (green=new, dim+strikethrough=fixed)
- [ ] REQ-P0-005: `sigint campaign run --file targets.json` scans all targets sequentially
- [ ] REQ-P0-006: Campaign file validated before first scan starts
- [ ] REQ-P0-007: Profile templates adjust tools and agent prompts
- [ ] All existing tests still pass (no regressions)
- [ ] New tests added for resume command (minimum 12 tests)
- [ ] New tests added for campaign parsing and execution (minimum 9 tests)
- [ ] Schema migration adds parent_session_id and campaigns table without data loss
- [ ] Manual verification: `sigint scan target` then `sigint resume <prefix>` shows diff

## Risk Assessment

| Risk | Impact | Likelihood | Mitigation |
|------|--------|------------|------------|
| Schema migration breaks existing sessions | High | Low | Nullable columns only; all existing data valid post-migration; test with populated DB |
| Resume scan of unreachable target hangs | Medium | Medium | Orchestrator already has per-tool timeouts (DEC-SAND-004); add overall scan timeout |
| Campaign file parsing edge cases (Unicode, empty strings) | Low | Medium | Validate upfront with clear error messages; serde handles Unicode natively |
| Profile tool filtering conflicts with role-based ACL | Medium | Low | Profile filter is applied AFTER role ACL; intersection of both sets |
| EventBus backpressure from ScanDiffCompleted (large diff) | Low | Low | Bus capacity 256; diff is one event per resume scan, not per-finding |
| TUI diff colors invisible on some terminal themes | Low | Medium | Use both color AND modifier (strikethrough, bold) so the signal survives monochrome |

## Files Summary

| File | Sub-Phase | Change Type |
|------|-----------|-------------|
| `crates/sigint-core/src/types.rs` | 9A, 9B, 9C | Add parent_session_id, campaign_id, cvss_score fields |
| `crates/sigint-core/src/event.rs` | 9A | Add ScanDiffCompleted variant |
| `crates/sigint-store/src/migrations.rs` | 9A, 9B, 9C | Add migrations for new columns/tables |
| `crates/sigint-store/src/sessions.rs` | 9A | Add get_session_by_prefix, parent_session_id support |
| `crates/sigint-store/src/campaigns.rs` | 9B | NEW: Campaign CRUD |
| `crates/sigint-store/src/findings.rs` | 9C | Extend for cvss_score column |
| `crates/sigint-cli/src/main.rs` | 9A, 9B | Add Resume and Campaign subcommands |
| `crates/sigint-cli/src/resume.rs` | 9A | NEW: Resume command handler |
| `crates/sigint-cli/src/campaign.rs` | 9B | NEW: Campaign command handler |
| `crates/sigint-tui/src/state.rs` | 9A | Add scan_diff field, DiffStatus, diff_status() |
| `crates/sigint-tui/src/ui.rs` | 9A | Diff-aware finding colors |
| `crates/sigint-agents/src/orchestrator.rs` | 9B | Add with_profile() builder, focus injection |
| `crates/sigint-agents/src/interactive.rs` | 9A | Add "resume" command to TUI input |
| `crates/sigint-report/src/builder.rs` | 9C | CampaignReportData, executive summary, scores |
| `crates/sigint-report/src/format.rs` | 9C | SVG pie chart in HTML |
