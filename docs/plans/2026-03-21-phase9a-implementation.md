# Phase 9A: Session Resume + Diff UI — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable `sigint resume <prefix>` to re-scan a prior session's target and display color-coded diff results in the TUI.

**Architecture:** Add `parent_session_id` FK to sessions table, UUID prefix matching for session lookup, auto-diff after resume scan completes, `Event::ScanDiffCompleted` for TUI rendering with green/dim+strikethrough/default finding styles.

**Tech Stack:** Rust, rusqlite (migration), ratatui (diff colors), clap (new subcommand), existing diff engine in `sigint-core/src/diff.rs`.

**Design doc:** `docs/plans/2026-03-21-phase9-design.md` (DEC-RESUME-001, DEC-RESUME-002, DEC-DIFF-UI-001)

---

### Task 1: Schema Migration — parent_session_id Column

**Files:**
- Modify: `crates/sigint-store/src/migrations.rs`
- Test: `crates/sigint-store/src/migrations.rs` (inline tests)

- [ ] **Step 1: Write the failing test**

In `crates/sigint-store/src/migrations.rs`, add a test that opens an in-memory DB, runs migrations, and verifies the `parent_session_id` column exists on `sessions`:

```rust
#[test]
fn migration_adds_parent_session_id_column() {
    let db = Database::open_in_memory().unwrap();
    // Insert a session, verify parent_session_id defaults to NULL
    db.with_conn(|conn| {
        conn.execute(
            "INSERT INTO sessions (id, name, created_at, updated_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params!["test-id", "test", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z"],
        ).unwrap();
        let parent: Option<String> = conn.query_row(
            "SELECT parent_session_id FROM sessions WHERE id = ?1",
            ["test-id"],
            |row| row.get(0),
        ).unwrap();
        assert!(parent.is_none());
        Ok(())
    }).unwrap();
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p sigint-store migration_adds_parent_session_id`
Expected: FAIL — column `parent_session_id` does not exist.

- [ ] **Step 3: Add the migration**

In `migrations.rs`, add a new migration to the migrations array:

```rust
// Migration N: Add parent_session_id for session resume (Phase 9A, DEC-RESUME-001)
"ALTER TABLE sessions ADD COLUMN parent_session_id TEXT REFERENCES sessions(id)",
```

Add it after the last existing migration in the `MIGRATIONS` array.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p sigint-store migration_adds_parent_session_id`
Expected: PASS

- [ ] **Step 5: Run full store tests to check for regressions**

Run: `cargo test -p sigint-store`
Expected: All tests pass (existing sessions remain valid since column is nullable).

- [ ] **Step 6: Commit**

```bash
git add crates/sigint-store/src/migrations.rs
git commit -m "feat(store): add parent_session_id migration for session resume"
```

---

### Task 2: Session Type — Add parent_session_id Field

**Files:**
- Modify: `crates/sigint-core/src/types.rs` (Session struct, ~line 21–45)
- Modify: `crates/sigint-store/src/sessions.rs` (~lines 17–131)

- [ ] **Step 1: Write the failing test**

In `crates/sigint-store/src/sessions.rs`, add:

```rust
#[test]
fn session_with_parent_id_roundtrips() {
    let db = Database::open_in_memory().unwrap();
    let parent = Session::new("parent-session");
    db.create_session(&parent).unwrap();

    let mut child = Session::new("child-session");
    child.parent_session_id = Some(parent.id);
    db.create_session(&child).unwrap();

    let fetched = db.get_session(child.id).unwrap().unwrap();
    assert_eq!(fetched.parent_session_id, Some(parent.id));
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p sigint-store session_with_parent_id_roundtrips`
Expected: FAIL — `parent_session_id` field does not exist on Session.

- [ ] **Step 3: Add parent_session_id to Session struct**

In `crates/sigint-core/src/types.rs`, add to the Session struct:

```rust
pub parent_session_id: Option<Uuid>,
```

Update `Session::new()` to initialize it as `None`.

- [ ] **Step 4: Update session CRUD in sessions.rs**

In `crates/sigint-store/src/sessions.rs`:

1. `create_session()`: Add `parent_session_id` to the INSERT statement. Store as `session.parent_session_id.map(|u| u.to_string())`.

2. `row_to_session()`: Parse `parent_session_id` from the row. Use:
   ```rust
   parent_session_id: row.get::<_, Option<String>>("parent_session_id")?
       .and_then(|s| Uuid::parse_str(&s).ok()),
   ```

3. `get_session()` and `list_sessions()`: SELECT must now include `parent_session_id`.

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -p sigint-store session_with_parent_id`
Expected: PASS

- [ ] **Step 6: Run full workspace build**

Run: `cargo build --workspace`
Expected: Compiles. Fix any uses of `Session::new()` or Session struct literals that now need the new field.

- [ ] **Step 7: Commit**

```bash
git add crates/sigint-core/src/types.rs crates/sigint-store/src/sessions.rs
git commit -m "feat(core,store): add parent_session_id to Session for resume chains"
```

---

### Task 3: UUID Prefix Session Lookup

**Files:**
- Modify: `crates/sigint-store/src/sessions.rs`

- [ ] **Step 1: Write the failing tests**

Add three tests in `crates/sigint-store/src/sessions.rs`:

```rust
#[test]
fn get_session_by_prefix_unique_match() {
    let db = Database::open_in_memory().unwrap();
    let s = Session::new("test");
    db.create_session(&s).unwrap();
    let prefix = &s.id.to_string()[..8];
    let found = db.get_session_by_prefix(prefix).unwrap();
    assert_eq!(found.id, s.id);
}

#[test]
fn get_session_by_prefix_no_match() {
    let db = Database::open_in_memory().unwrap();
    let result = db.get_session_by_prefix("zzzzzzzz");
    assert!(result.is_err());
}

#[test]
fn get_session_by_prefix_too_short() {
    let db = Database::open_in_memory().unwrap();
    let result = db.get_session_by_prefix("ab");
    assert!(result.is_err());
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("4 characters"));
}

#[test]
fn get_session_by_prefix_ambiguous_lists_matches() {
    let db = Database::open_in_memory().unwrap();
    let s1 = Session::new("session-1");
    let s2 = Session::new("session-2");
    db.create_session(&s1).unwrap();
    db.create_session(&s2).unwrap();
    // Use a 1-char prefix that matches both (all UUIDs share some prefix)
    // Since UUIDs are random, use a prefix that's deliberately too broad
    let result = db.get_session_by_prefix("0000"); // unlikely to match, but demonstrates the pattern
    // In practice, test by finding a shared prefix between two known UUIDs
    // or by inserting sessions and checking the error contains "matches"
}
```

Note: the ambiguous-match test is tricky with random UUIDs. The implementer should either use deterministic UUIDs or insert enough sessions that a short prefix (4 chars) collides. The design spec requires this test (test #2 from the spec).

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p sigint-store get_session_by_prefix`
Expected: FAIL — method does not exist.

- [ ] **Step 3: Implement get_session_by_prefix**

Add to `sessions.rs` (on the Database impl block):

```rust
/// Find a session by UUID prefix (minimum 4 characters).
/// Returns Ok(session) if exactly one match, Err if zero or ambiguous.
pub fn get_session_by_prefix(&self, prefix: &str) -> Result<Session, crate::Error> {
    if prefix.len() < 4 {
        return Err(Error::Other(
            "UUID prefix must be at least 4 characters".into(),
        ));
    }
    let sessions = self.list_sessions()?;
    let matches: Vec<Session> = sessions
        .into_iter()
        .filter(|s| s.id.to_string().starts_with(prefix))
        .collect();
    match matches.len() {
        0 => Err(Error::Other(format!(
            "No session found matching prefix '{prefix}'"
        ))),
        1 => Ok(matches.into_iter().next().unwrap()),
        n => {
            let listing: Vec<String> = matches
                .iter()
                .map(|s| {
                    format!(
                        "  {} — {} ({})",
                        &s.id.to_string()[..8],
                        s.target.as_deref().unwrap_or("-"),
                        s.name
                    )
                })
                .collect();
            Err(Error::Other(format!(
                "Prefix '{prefix}' matches {n} sessions:\n{}",
                listing.join("\n")
            )))
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p sigint-store get_session_by_prefix`
Expected: All 3 PASS

- [ ] **Step 5: Commit**

```bash
git add crates/sigint-store/src/sessions.rs
git commit -m "feat(store): add UUID prefix matching for session lookup"
```

---

### Task 4: Event::ScanDiffCompleted Variant

**Files:**
- Modify: `crates/sigint-core/src/event.rs` (~line 26–111)

- [ ] **Step 1: Write the failing test**

In `crates/sigint-core/src/event.rs` tests (or a new test file if tests are in a separate module):

```rust
#[test]
fn scan_diff_completed_event_clone() {
    use crate::diff::{ScanDiff, DiffSummary};
    let diff = ScanDiff {
        scan_a: Uuid::new_v4(),
        scan_b: Uuid::new_v4(),
        summary: DiffSummary { new: 1, fixed: 0, unchanged: 2 },
        new: vec![],
        fixed: vec![],
        unchanged: vec![],
    };
    let event = Event::ScanDiffCompleted { diff: diff.clone() };
    let cloned = event.clone();
    // Verify it compiles and clones — the Event enum must derive Clone
    drop(cloned);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p sigint-core scan_diff_completed`
Expected: FAIL — no variant `ScanDiffCompleted` on Event.

- [ ] **Step 3: Add the variant**

In `crates/sigint-core/src/event.rs`, add to the Event enum:

```rust
/// Diff results from a resume scan comparing findings against a prior session.
ScanDiffCompleted {
    diff: crate::diff::ScanDiff,
},
```

Ensure `ScanDiff` derives `Clone` (check `diff.rs` — it likely already does since Event requires Clone for broadcast). If not, add `#[derive(Clone)]` to `ScanDiff`, `DiffSummary`, and any contained types.

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p sigint-core scan_diff_completed`
Expected: PASS

- [ ] **Step 5: Build workspace to check all match arms**

Run: `cargo build --workspace`
Expected: May fail on exhaustive match arms in TUI state.rs and elsewhere. Add `Event::ScanDiffCompleted { .. } => {}` placeholder arms where needed to compile.

- [ ] **Step 6: Commit**

```bash
git add crates/sigint-core/src/event.rs crates/sigint-core/src/diff.rs
git commit -m "feat(core): add Event::ScanDiffCompleted for resume diff display"
```

---

### Task 5: TUI State — DiffStatus + ScanDiff Storage

**Files:**
- Modify: `crates/sigint-tui/src/state.rs` (~lines 99–140 for AppState, apply() method)

- [ ] **Step 1: Write the failing tests**

Add to `crates/sigint-tui/src/state.rs` test module:

```rust
#[test]
fn scan_diff_completed_stores_diff() {
    let mut state = AppState::default();
    assert!(state.scan_diff.is_none());

    let diff = ScanDiff {
        scan_a: Uuid::new_v4(),
        scan_b: Uuid::new_v4(),
        summary: DiffSummary { new: 1, fixed: 1, unchanged: 0 },
        new: vec![make_finding("New Vuln", Some("host1"))],
        fixed: vec![make_finding("Old Vuln", Some("host1"))],
        unchanged: vec![],
    };
    state.apply(Event::ScanDiffCompleted { diff: diff.clone() });
    assert!(state.scan_diff.is_some());
    assert_eq!(state.scan_diff.as_ref().unwrap().summary.new, 1);
}

#[test]
fn diff_status_new_finding_detected() {
    let mut state = AppState::default();
    let finding = make_finding("SQL Injection", Some("api.example.com"));
    let diff = ScanDiff {
        scan_a: Uuid::new_v4(),
        scan_b: Uuid::new_v4(),
        summary: DiffSummary { new: 1, fixed: 0, unchanged: 0 },
        new: vec![finding.clone()],
        fixed: vec![],
        unchanged: vec![],
    };
    state.apply(Event::ScanDiffCompleted { diff });
    assert_eq!(state.diff_status(&finding), DiffStatus::New);
}

#[test]
fn diff_status_fixed_finding_detected() {
    let mut state = AppState::default();
    let finding = make_finding("XSS", Some("web.example.com"));
    let diff = ScanDiff {
        scan_a: Uuid::new_v4(),
        scan_b: Uuid::new_v4(),
        summary: DiffSummary { new: 0, fixed: 1, unchanged: 0 },
        new: vec![],
        fixed: vec![finding.clone()],
        unchanged: vec![],
    };
    state.apply(Event::ScanDiffCompleted { diff });
    assert_eq!(state.diff_status(&finding), DiffStatus::Fixed);
}

#[test]
fn diff_status_no_diff_returns_nodiff() {
    let state = AppState::default();
    let finding = make_finding("Test", None);
    assert_eq!(state.diff_status(&finding), DiffStatus::NoDiff);
}
```

Note: `make_finding` is a test helper — create it if it doesn't exist:
```rust
fn make_finding(title: &str, asset: Option<&str>) -> Finding {
    Finding {
        id: Uuid::new_v4(),
        session_id: Uuid::new_v4(),
        title: title.to_string(),
        description: String::new(),
        severity: sigint_core::types::Severity::Medium,
        asset: asset.map(|s| s.to_string()),
        evidence: None,
        created_at: chrono::Utc::now(),
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p sigint-tui diff_status`
Expected: FAIL — `scan_diff` field and `diff_status` method don't exist.

- [ ] **Step 3: Add DiffStatus enum, scan_diff field, and diff_status method**

In `crates/sigint-tui/src/state.rs`:

1. Add the enum:
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffStatus {
    New,
    Fixed,
    Unchanged,
    NoDiff,
}
```

2. Add field to AppState:
```rust
pub scan_diff: Option<sigint_core::diff::ScanDiff>,
```

Initialize as `None` in `Default` impl.

3. Add handler in `apply()`:
```rust
Event::ScanDiffCompleted { diff } => {
    self.scan_diff = Some(diff);
}
```

4. Add method on AppState:
```rust
pub fn diff_status(&self, finding: &Finding) -> DiffStatus {
    let Some(ref diff) = self.scan_diff else {
        return DiffStatus::NoDiff;
    };
    let key = (
        finding.title.to_lowercase(),
        finding.asset.clone().unwrap_or_default(),
    );
    if diff.new.iter().any(|f| {
        (f.title.to_lowercase(), f.asset.clone().unwrap_or_default()) == key
    }) {
        DiffStatus::New
    } else if diff.fixed.iter().any(|f| {
        (f.title.to_lowercase(), f.asset.clone().unwrap_or_default()) == key
    }) {
        DiffStatus::Fixed
    } else {
        DiffStatus::Unchanged
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p sigint-tui diff_status`
Expected: All 4 PASS

- [ ] **Step 5: Commit**

```bash
git add crates/sigint-tui/src/state.rs
git commit -m "feat(tui): add DiffStatus enum and scan_diff state for resume diff rendering"
```

---

### Task 6: TUI Rendering — Diff-Aware Finding Colors

**Files:**
- Modify: `crates/sigint-tui/src/ui.rs` (findings panel rendering)

- [ ] **Step 1: Read ui.rs to locate findings rendering**

Find where findings are rendered as a Table/List. Look for `state.findings` iteration and the ratatui `Style` application.

- [ ] **Step 2: Add diff-aware styling**

Where each finding row is rendered, apply styles based on `state.diff_status(&finding)`:

```rust
let style = match state.diff_status(finding) {
    DiffStatus::New => Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
    DiffStatus::Fixed => Style::default()
        .fg(Color::DarkGray)
        .add_modifier(Modifier::CROSSED_OUT),
    DiffStatus::Unchanged | DiffStatus::NoDiff => Style::default(),
};
```

Apply this style to the finding row's `Row::new(cells).style(style)`.

- [ ] **Step 3: Build and verify no compile errors**

Run: `cargo build -p sigint-tui`
Expected: Compiles.

- [ ] **Step 4: Run TUI tests**

Run: `cargo test -p sigint-tui`
Expected: All pass.

- [ ] **Step 5: Commit**

```bash
git add crates/sigint-tui/src/ui.rs
git commit -m "feat(tui): color-code findings by diff status (green=new, dim+strikethrough=fixed)"
```

---

### Task 7: Interactive Session — Resume Command

**Files:**
- Modify: `crates/sigint-agents/src/interactive.rs` (~lines 36–73, 145–176)

- [ ] **Step 1: Write the failing tests**

Add to `crates/sigint-agents/src/interactive.rs` tests:

```rust
#[test]
fn parse_resume_command_with_prefix() {
    let cmd = parse_command("resume a1b2c3d4");
    assert!(matches!(cmd, Command::Resume(ref p) if p == "a1b2c3d4"));
}

#[test]
fn parse_resume_without_args_is_list() {
    let cmd = parse_command("resume");
    assert!(matches!(cmd, Command::ResumeList));
}

#[test]
fn parse_resume_with_whitespace() {
    let cmd = parse_command("  resume   abcd1234  ");
    assert!(matches!(cmd, Command::Resume(ref p) if p == "abcd1234"));
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p sigint-agents parse_resume`
Expected: FAIL — no `Resume` or `ResumeList` variants.

- [ ] **Step 3: Extend Command enum and parse_command**

In `crates/sigint-agents/src/interactive.rs`:

1. Add variants to Command:
```rust
pub enum Command {
    Scan(String),
    Resume(String),     // resume <prefix>
    ResumeList,         // resume (no args) — list sessions
    Help,
    Unknown(String),
}
```

2. Extend `parse_command()`:
```rust
// After the "scan" match, before "help":
if trimmed == "resume" {
    return Command::ResumeList;
}
if let Some(prefix) = trimmed.strip_prefix("resume ") {
    let prefix = prefix.trim();
    if prefix.is_empty() {
        return Command::ResumeList;
    }
    return Command::Resume(prefix.to_string());
}
```

- [ ] **Step 4: Update handle_input for resume commands**

In `handle_input()`, add arms for `Command::ResumeList` and `Command::Resume(prefix)`:

For `ResumeList`: Emit a status event with "Use 'resume <session-prefix>' to resume a prior scan. Recent sessions:" followed by listing from the database (requires `InteractiveSession` to have DB access — this may need passing `Arc<Database>` to InteractiveSession, or just emit a help message pointing to `sigint sessions list`).

For `Resume(prefix)`: This is complex — it needs DB lookup and orchestrator dispatch. For the TUI path, emit a status message "Resuming session {prefix}..." and trigger a scan of the prior session's target. The full resume logic will be in the CLI `resume.rs`; the TUI path calls the same core logic.

**Note:** The TUI resume handler will be fully wired in Task 9 (CLI resume command) since both paths share the same logic. For now, add the command parsing and a placeholder handler that emits a status message.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p sigint-agents parse_resume`
Expected: All 3 PASS

- [ ] **Step 6: Commit**

```bash
git add crates/sigint-agents/src/interactive.rs
git commit -m "feat(agents): add resume command parsing to InteractiveSession"
```

---

### Task 8: CLI Resume Subcommand — Clap Wiring

**Files:**
- Modify: `crates/sigint-cli/src/main.rs` (~lines 36–72)
- Create: `crates/sigint-cli/src/resume.rs`

- [ ] **Step 1: Add Resume to Commands enum**

In `crates/sigint-cli/src/main.rs`, add to the `Commands` enum:

```rust
/// Resume a prior scan session and diff findings
Resume {
    /// Session UUID prefix (minimum 4 characters)
    session: String,
    /// Override the LLM model
    #[arg(short, long)]
    model: Option<String>,
    /// Maximum tool-call iterations per agent
    #[arg(long, default_value = "10")]
    max_iterations: usize,
    /// Force TUI mode
    #[arg(long)]
    tui: bool,
    /// Force non-TUI mode
    #[arg(long)]
    no_tui: bool,
},
```

- [ ] **Step 2: Create resume.rs stub**

Create `crates/sigint-cli/src/resume.rs`:

```rust
use sigint_core::AppCore;

/// @decision DEC-RESUME-001: Resume creates a new session with parent_session_id,
/// then auto-diffs after scan completion. Preserves temporal record.

pub async fn run(
    core: AppCore,
    session_prefix: String,
    model: Option<String>,
    max_iterations: usize,
    force_tui: bool,
    force_no_tui: bool,
) -> Result<(), sigint_core::Error> {
    todo!("Phase 9A: resume implementation")
}
```

- [ ] **Step 3: Wire the dispatch in main.rs**

In the match on `Commands`:

```rust
Commands::Resume { session, model, max_iterations, tui, no_tui } => {
    resume::run(core, session, model, max_iterations, tui, no_tui).await?;
}
```

Add `mod resume;` to `main.rs`.

- [ ] **Step 4: Build to verify wiring compiles**

Run: `cargo build -p sigint-cli`
Expected: Compiles (todo!() is fine for now).

- [ ] **Step 5: Commit**

```bash
git add crates/sigint-cli/src/main.rs crates/sigint-cli/src/resume.rs
git commit -m "feat(cli): add 'sigint resume' subcommand skeleton"
```

---

### Task 9: CLI Resume — Full Implementation

**Files:**
- Modify: `crates/sigint-cli/src/resume.rs`
- Reference: `crates/sigint-cli/src/scan.rs` (reuse patterns)

- [ ] **Step 1: Write integration-style test**

In `crates/sigint-cli/src/resume.rs`, add a test that verifies prefix lookup + session creation with parent_id (unit-level, no Ollama needed):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use sigint_store::Database;
    use sigint_core::types::Session;

    #[test]
    fn resume_finds_parent_and_creates_child_session() {
        let db = Database::open_in_memory().unwrap();
        let mut parent = Session::new("test-scan");
        parent.target = Some("scanme.nmap.org".to_string());
        db.create_session(&parent).unwrap();

        let prefix = &parent.id.to_string()[..8];
        let found = db.get_session_by_prefix(prefix).unwrap();
        assert_eq!(found.id, parent.id);
        assert_eq!(found.target.as_deref(), Some("scanme.nmap.org"));

        // Create child session with parent link
        let mut child = Session::new("resume-scan");
        child.target = found.target.clone();
        child.parent_session_id = Some(found.id);
        db.create_session(&child).unwrap();

        let fetched_child = db.get_session(child.id).unwrap().unwrap();
        assert_eq!(fetched_child.parent_session_id, Some(parent.id));
        assert_eq!(fetched_child.target.as_deref(), Some("scanme.nmap.org"));
    }

    #[test]
    fn resume_session_without_target_errors() {
        let db = Database::open_in_memory().unwrap();
        let parent = Session::new("no-target-session");
        // parent.target is None
        db.create_session(&parent).unwrap();

        let prefix = &parent.id.to_string()[..8];
        let found = db.get_session_by_prefix(prefix).unwrap();
        assert!(found.target.is_none());
        // The resume logic should detect this and return an error
    }
}
```

- [ ] **Step 2: Implement resume::run()**

Replace the `todo!()` with full implementation. Follow `scan.rs` patterns:

```rust
pub async fn run(
    core: AppCore,
    session_prefix: String,
    model: Option<String>,
    max_iterations: usize,
    force_tui: bool,
    force_no_tui: bool,
) -> Result<(), sigint_core::Error> {
    // 1. Open database
    let db = Database::open(&core.config.resolved_db_path())?;

    // 2. Look up prior session by prefix
    let prior = db.get_session_by_prefix(&session_prefix)?;
    let target = prior.target.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "Session {} has no target — cannot resume a session without a target",
            &prior.id.to_string()[..8]
        )
    })?;

    println!("Resuming scan of {} (prior session: {})", target, &prior.id.to_string()[..8]);

    // 3. Create new child session with parent link
    let mut session = Session::new(&format!("Resume of {}", prior.name));
    session.target = Some(target.to_string());
    session.parent_session_id = Some(prior.id);
    db.create_session(&session)?;

    // 4. Run scan pipeline (mirror scan.rs setup)
    //    — provider, registry, orchestrator, TUI/stdout, etc.
    //    Reuse the same patterns from scan.rs lines 85-184.
    //    Key difference: session already exists with parent_session_id set.

    // [Copy scan pipeline setup from scan.rs — provider, event_bus, TUI,
    //  tool registry, orchestrator, run_scan, persist findings]

    // 5. After scan completes, auto-diff
    let prior_findings = db.get_findings(prior.id)?;
    let new_findings = db.get_findings(session.id)?;
    let diff = sigint_core::diff::diff_findings(
        prior.id, &prior_findings,
        session.id, &new_findings,
    );

    // 6. Emit ScanDiffCompleted event for TUI
    let _ = event_bus.emit(Event::ScanDiffCompleted { diff: diff.clone() });

    // 7. Print diff summary to stdout
    println!("\n=== Scan Diff: {} vs {} ===", &prior.id.to_string()[..8], &session.id.to_string()[..8]);
    println!("New findings:       {}", diff.summary.new);
    println!("Fixed findings:     {}", diff.summary.fixed);
    println!("Unchanged findings: {}", diff.summary.unchanged);

    if !diff.new.is_empty() {
        println!("\n--- New Findings ---");
        for f in &diff.new {
            println!("  [+] {} ({}) — {}", f.title, f.severity, f.asset.as_deref().unwrap_or("-"));
        }
    }
    if !diff.fixed.is_empty() {
        println!("\n--- Fixed Findings ---");
        for f in &diff.fixed {
            println!("  [-] {} ({}) — {}", f.title, f.severity, f.asset.as_deref().unwrap_or("-"));
        }
    }

    Ok(())
}
```

**Note:** The scan pipeline setup (provider creation, tool registry, TUI, orchestrator) should be extracted from scan.rs or duplicated with comments pointing to the shared pattern. This is the largest implementation step.

- [ ] **Step 3: Run tests**

Run: `cargo test -p sigint-cli resume`
Expected: Unit tests pass. The full pipeline requires Ollama (integration test, manual).

- [ ] **Step 4: Build full workspace**

Run: `cargo build --workspace`
Expected: Compiles cleanly.

- [ ] **Step 5: Commit**

```bash
git add crates/sigint-cli/src/resume.rs
git commit -m "feat(cli): implement sigint resume with auto-diff and parent session linkage"
```

---

### Task 10: Wire TUI Resume Handler to Full Logic

**Files:**
- Modify: `crates/sigint-agents/src/interactive.rs`

- [ ] **Step 1: Add Database access to InteractiveSession**

InteractiveSession needs DB access for resume. Add `Option<Arc<Database>>` to the struct:

```rust
pub struct InteractiveSession {
    orchestrator: Orchestrator,
    event_rx: broadcast::Receiver<Event>,
    event_bus: EventBus,
    db: Option<Arc<Database>>,
}
```

Update the constructor and the call site in `scan.rs` to pass the DB.

- [ ] **Step 2: Implement ResumeList handler**

In `handle_input()`, for `Command::ResumeList`:

```rust
Command::ResumeList => {
    if let Some(ref db) = self.db {
        match db.list_sessions() {
            Ok(sessions) if sessions.is_empty() => {
                let _ = self.event_bus.emit(Event::Status("No prior sessions found.".into()));
            }
            Ok(sessions) => {
                let mut msg = String::from("Recent sessions (use 'resume <prefix>'):\n");
                for s in sessions.iter().take(10) {
                    msg.push_str(&format!(
                        "  {} — {} ({})\n",
                        &s.id.to_string()[..8],
                        s.target.as_deref().unwrap_or("-"),
                        s.name
                    ));
                }
                let _ = self.event_bus.emit(Event::Status(msg));
            }
            Err(e) => {
                let _ = self.event_bus.emit(Event::Status(format!("Error listing sessions: {e}")));
            }
        }
    } else {
        let _ = self.event_bus.emit(Event::Status(
            "Database not available. Use 'sigint resume <prefix>' from CLI.".into(),
        ));
    }
}
```

- [ ] **Step 3: Implement Resume(prefix) handler**

For `Command::Resume(prefix)`:

```rust
Command::Resume(prefix) => {
    if let Some(ref db) = self.db {
        match db.get_session_by_prefix(&prefix) {
            Ok(prior) => {
                if let Some(target) = &prior.target {
                    let _ = self.event_bus.emit(Event::Status(
                        format!("Resuming scan of {} (prior: {})...", target, &prior.id.to_string()[..8])
                    ));
                    // Run the scan
                    // Create child session before scan so we have the ID
                    let mut child = Session::new(&format!("Resume of {}", prior.name));
                    child.target = Some(target.clone());
                    child.parent_session_id = Some(prior.id);
                    let _ = db.create_session(&child);

                    match self.orchestrator.run_scan(target).await {
                        Ok(report) => {
                            // Auto-diff using child session ID
                            if let (Ok(prior_findings), Ok(new_findings)) = (
                                db.get_findings(prior.id),
                                db.get_findings(child.id),
                            ) {
                                let diff = sigint_core::diff::diff_findings(
                                    prior.id, &prior_findings,
                                    child.id, &new_findings,
                                );
                                let _ = self.event_bus.emit(Event::ScanDiffCompleted { diff });
                            }
                            let _ = self.event_bus.emit(Event::Status(
                                format!("Resume scan complete. {}", report.summary)
                            ));
                        }
                        Err(e) => {
                            let _ = self.event_bus.emit(Event::Status(format!("Resume scan failed: {e}")));
                        }
                    }
                } else {
                    let _ = self.event_bus.emit(Event::Status(
                        format!("Session {} has no target — cannot resume.", &prior.id.to_string()[..8])
                    ));
                }
            }
            Err(e) => {
                let _ = self.event_bus.emit(Event::Status(format!("{e}")));
            }
        }
    }
}
```

- [ ] **Step 4: Update scan.rs to pass DB to InteractiveSession**

Where InteractiveSession is constructed in `scan.rs`, pass the database handle.

- [ ] **Step 5: Run tests**

Run: `cargo test -p sigint-agents`
Expected: All existing + new tests pass.

- [ ] **Step 6: Build full workspace**

Run: `cargo build --workspace`
Expected: Compiles.

- [ ] **Step 7: Commit**

```bash
git add crates/sigint-agents/src/interactive.rs crates/sigint-cli/src/scan.rs
git commit -m "feat(agents): wire TUI resume command to orchestrator with auto-diff"
```

---

### Task 11: Full Workspace Tests + Regression Check

**Files:** None (verification only)

- [ ] **Step 1: Run full workspace tests**

Run: `cargo test --workspace`
Expected: All tests pass. Note the total count for regression tracking.

- [ ] **Step 2: Run clippy for lint check**

Run: `cargo clippy --workspace -- -D warnings`
Expected: No warnings.

- [ ] **Step 3: Verify CLI help shows resume command**

Run: `cargo run -- --help`
Expected: Output includes `resume` subcommand.

Run: `cargo run -- resume --help`
Expected: Shows session argument and options.

- [ ] **Step 4: Commit any fixups**

If clippy or tests revealed issues, fix and commit:
```bash
git commit -m "fix: address clippy warnings and test failures from Phase 9A"
```

---

## Verification Plan

After all tasks complete:

1. **Unit tests:** `cargo test --workspace` — all pass, 0 failures
2. **CLI smoke test:** `cargo run -- resume --help` shows the subcommand
3. **Manual integration test (requires Ollama):**
   - `sigint scan scanme.nmap.org` → creates session, note UUID prefix
   - `sigint resume <prefix>` → re-scans, prints diff summary
   - With TUI: type `resume` → see session list, type `resume <prefix>` → see color-coded findings
4. **Schema migration:** Verify `parent_session_id` column exists:
   ```bash
   sqlite3 ~/.local/share/sigint/sigint.db ".schema sessions"
   ```
