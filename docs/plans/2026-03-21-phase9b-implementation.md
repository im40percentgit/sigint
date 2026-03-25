# Phase 9B: Multi-Target Campaign Mode — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Enable `sigint campaign run --file targets.json` for batch multi-target scanning with profile-driven tool/prompt customization and aggregated reporting.

**Architecture:** New `campaigns` table + `campaign_id` FK on sessions. Campaign JSON file parsed into `CampaignFile` struct with named profiles. Each target scanned sequentially by a fresh Orchestrator configured via `with_profile()`. Per-target results aggregated into `CampaignReportData` for cross-target summary.

**Tech Stack:** Rust, serde_json (campaign parsing), rusqlite (migration), clap (subcommand), existing Orchestrator + ToolRegistry.

**Design doc:** `docs/plans/2026-03-21-phase9-design.md` (DEC-CAMPAIGN-001, DEC-CAMPAIGN-002, DEC-REPORT-003)

---

## File Map

| File | Action | Responsibility |
|------|--------|---------------|
| `crates/sigint-store/src/migrations.rs` | Modify | Migration 4+5: campaigns table, campaign_id column |
| `crates/sigint-core/src/types.rs` | Modify | Campaign struct, campaign_id on Session |
| `crates/sigint-core/src/campaign.rs` | **Create** | CampaignFile, ScanProfile, CampaignTarget — serde types + validation |
| `crates/sigint-core/src/lib.rs` | Modify | Export campaign module |
| `crates/sigint-store/src/campaigns.rs` | **Create** | Campaign CRUD (create, get, update_completed, get_sessions) |
| `crates/sigint-store/src/lib.rs` | Modify | Export campaigns module |
| `crates/sigint-store/src/sessions.rs` | Modify | campaign_id in create/read |
| `crates/sigint-agents/src/orchestrator.rs` | Modify | `with_profile()` builder — focus injection + tool filtering |
| `crates/sigint-cli/src/main.rs` | Modify | Campaign subcommand group |
| `crates/sigint-cli/src/campaign.rs` | **Create** | Campaign run + status handlers |
| `crates/sigint-report/src/builder.rs` | Modify | CampaignReportData + build_campaign_markdown() |

---

### Task 1: Schema Migrations — campaigns table + campaign_id

**Files:**
- Modify: `crates/sigint-store/src/migrations.rs`

- [ ] **Step 1: Write failing test**

```rust
#[test]
fn migration_creates_campaigns_table_and_campaign_id_column() {
    let db = Database::open_in_memory().unwrap();
    db.with_conn(|conn| {
        // campaigns table exists
        conn.execute(
            "INSERT INTO campaigns (id, name, created_at) VALUES (?1, ?2, ?3)",
            rusqlite::params!["camp-1", "test-campaign", "2026-01-01T00:00:00Z"],
        ).unwrap();
        // campaign_id column on sessions
        conn.execute(
            "INSERT INTO sessions (id, name, created_at, updated_at, campaign_id) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params!["sess-1", "test", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", "camp-1"],
        ).unwrap();
        // Verify FK
        let cid: Option<String> = conn.query_row(
            "SELECT campaign_id FROM sessions WHERE id = 'sess-1'", [], |row| row.get(0)
        ).unwrap();
        assert_eq!(cid.as_deref(), Some("camp-1"));
        Ok(())
    }).unwrap();
}
```

- [ ] **Step 2: Run test — verify FAIL**

Run: `cargo test -p sigint-store migration_creates_campaigns`
Expected: FAIL — no such table: campaigns

- [ ] **Step 3: Add migrations 4 and 5**

```rust
// Migration 4: campaigns table (Phase 9B, DEC-CAMPAIGN-002)
"CREATE TABLE IF NOT EXISTS campaigns (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    file_path TEXT,
    created_at TEXT NOT NULL,
    completed_at TEXT
)",
// Migration 5: campaign_id FK on sessions (Phase 9B, DEC-CAMPAIGN-002)
"ALTER TABLE sessions ADD COLUMN campaign_id TEXT REFERENCES campaigns(id)",
```

- [ ] **Step 4: Run test — verify PASS**
- [ ] **Step 5: `cargo test -p sigint-store` — no regressions**
- [ ] **Step 6: Commit**

```
feat(store): add campaigns table and campaign_id migration
```

---

### Task 2: Campaign Types — CampaignFile, ScanProfile, CampaignTarget

**Files:**
- Create: `crates/sigint-core/src/campaign.rs`
- Modify: `crates/sigint-core/src/lib.rs`

- [ ] **Step 1: Write failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_valid_campaign_file() {
        let json = r#"{
            "profiles": {
                "web": { "tools": ["nmap_scan", "shell"], "focus": "web application security" }
            },
            "targets": [
                { "name": "Main Site", "target": "example.com", "profile": "web" }
            ]
        }"#;
        let cf: CampaignFile = serde_json::from_str(json).unwrap();
        assert_eq!(cf.targets.len(), 1);
        assert_eq!(cf.profiles.len(), 1);
        assert_eq!(cf.targets[0].target, "example.com");
        assert_eq!(cf.profiles["web"].focus, "web application security");
    }

    #[test]
    fn validate_missing_profile_errors() {
        let cf = CampaignFile {
            profiles: HashMap::new(),
            targets: vec![CampaignTarget {
                name: "Test".into(), target: "example.com".into(), profile: "missing".into(),
            }],
        };
        let err = cf.validate().unwrap_err();
        assert!(err.contains("missing"));
    }

    #[test]
    fn validate_empty_targets_errors() {
        let cf = CampaignFile { profiles: HashMap::new(), targets: vec![] };
        let err = cf.validate().unwrap_err();
        assert!(err.contains("empty") || err.contains("no targets"));
    }

    #[test]
    fn profile_defaults_applied() {
        let json = r#"{ "tools": [], "focus": "" }"#;
        let p: ScanProfile = serde_json::from_str(json).unwrap();
        assert!(p.tools.is_empty());
        assert!(p.max_iterations.is_none());
    }

    #[test]
    fn campaign_target_default_profile() {
        let json = r#"{ "name": "Test", "target": "example.com" }"#;
        let t: CampaignTarget = serde_json::from_str(json).unwrap();
        assert_eq!(t.profile, "default");
    }
}
```

- [ ] **Step 2: Run tests — verify FAIL**
- [ ] **Step 3: Implement types**

```rust
use serde::Deserialize;
use std::collections::HashMap;

/// A campaign configuration file (DEC-CAMPAIGN-001).
#[derive(Debug, Deserialize)]
pub struct CampaignFile {
    #[serde(default)]
    pub profiles: HashMap<String, ScanProfile>,
    pub targets: Vec<CampaignTarget>,
}

/// A scan profile adjusting orchestrator behavior.
#[derive(Debug, Clone, Deserialize)]
pub struct ScanProfile {
    #[serde(default)]
    pub tools: Vec<String>,
    #[serde(default)]
    pub focus: String,
    pub max_iterations: Option<usize>,
    pub ports: Option<String>,
}

/// A single target in a campaign.
#[derive(Debug, Deserialize)]
pub struct CampaignTarget {
    pub name: String,
    pub target: String,
    #[serde(default = "default_profile")]
    pub profile: String,
}

fn default_profile() -> String { "default".into() }

impl CampaignFile {
    pub fn validate(&self) -> Result<(), String> {
        if self.targets.is_empty() {
            return Err("Campaign has no targets".into());
        }
        for t in &self.targets {
            if t.profile != "default" && !self.profiles.contains_key(&t.profile) {
                return Err(format!(
                    "Target '{}' references unknown profile '{}'", t.name, t.profile
                ));
            }
        }
        Ok(())
    }
}
```

Add `pub mod campaign;` to `crates/sigint-core/src/lib.rs`.

- [ ] **Step 4: Run tests — verify PASS**
- [ ] **Step 5: `cargo build --workspace` — compiles**
- [ ] **Step 6: Commit**

```
feat(core): add CampaignFile, ScanProfile, CampaignTarget types with validation
```

---

### Task 3: Campaign Struct + campaign_id on Session

**Files:**
- Modify: `crates/sigint-core/src/types.rs`
- Modify: `crates/sigint-store/src/sessions.rs`

- [ ] **Step 1: Write failing tests**

In `types.rs` tests or `sessions.rs` tests:
```rust
#[test]
fn session_with_campaign_id_roundtrips() {
    let db = Database::open_in_memory().unwrap();
    let mut s = Session::new("campaign-target");
    s.campaign_id = Some(Uuid::new_v4());
    db.create_session(&s).unwrap();
    let fetched = db.get_session(s.id).unwrap().unwrap();
    assert_eq!(fetched.campaign_id, s.campaign_id);
}
```

- [ ] **Step 2: Run test — verify FAIL**
- [ ] **Step 3: Add campaign_id to Session**

In `types.rs`, add to Session struct:
```rust
pub campaign_id: Option<Uuid>,
```
Initialize as `None` in `Session::new()`. Add builder method:
```rust
pub fn with_campaign_id(mut self, id: Uuid) -> Self {
    self.campaign_id = Some(id);
    self
}
```

In `sessions.rs`:
- `create_session()`: Add campaign_id to INSERT, bind as `session.campaign_id.map(|u| u.to_string())`
- `row_to_session()`: Parse campaign_id same pattern as parent_session_id
- All SELECT queries: Include campaign_id

Also add a Campaign struct to `types.rs`:
```rust
pub struct Campaign {
    pub id: Uuid,
    pub name: String,
    pub file_path: Option<String>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}
```

- [ ] **Step 4: Run tests — verify PASS**
- [ ] **Step 5: `cargo build --workspace` — fix any struct literal mismatches**
- [ ] **Step 6: Commit**

```
feat(core,store): add campaign_id to Session, Campaign struct
```

---

### Task 4: Campaign CRUD in Store

**Files:**
- Create: `crates/sigint-store/src/campaigns.rs`
- Modify: `crates/sigint-store/src/lib.rs`

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn create_and_get_campaign_roundtrip() {
    let db = Database::open_in_memory().unwrap();
    let c = Campaign { id: Uuid::new_v4(), name: "Test Campaign".into(),
        file_path: Some("targets.json".into()),
        created_at: Utc::now(), completed_at: None };
    db.create_campaign(&c).unwrap();
    let fetched = db.get_campaign(c.id).unwrap().unwrap();
    assert_eq!(fetched.name, "Test Campaign");
    assert!(fetched.completed_at.is_none());
}

#[test]
fn update_campaign_completed() {
    let db = Database::open_in_memory().unwrap();
    let c = Campaign { id: Uuid::new_v4(), name: "Test".into(),
        file_path: None, created_at: Utc::now(), completed_at: None };
    db.create_campaign(&c).unwrap();
    db.update_campaign_completed(c.id).unwrap();
    let fetched = db.get_campaign(c.id).unwrap().unwrap();
    assert!(fetched.completed_at.is_some());
}

#[test]
fn get_campaign_sessions_returns_linked() {
    let db = Database::open_in_memory().unwrap();
    let c = Campaign { id: Uuid::new_v4(), name: "Test".into(),
        file_path: None, created_at: Utc::now(), completed_at: None };
    db.create_campaign(&c).unwrap();
    let mut s = Session::new("target-1");
    s.campaign_id = Some(c.id);
    db.create_session(&s).unwrap();
    let sessions = db.get_campaign_sessions(c.id).unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].id, s.id);
}
```

- [ ] **Step 2: Run tests — verify FAIL**
- [ ] **Step 3: Implement campaigns.rs**

```rust
use crate::Database;
use sigint_core::types::Campaign;
use uuid::Uuid;
use chrono::Utc;

impl Database {
    pub fn create_campaign(&self, campaign: &Campaign) -> Result<(), sigint_core::Error> { ... }
    pub fn get_campaign(&self, id: Uuid) -> Result<Option<Campaign>, sigint_core::Error> { ... }
    pub fn update_campaign_completed(&self, id: Uuid) -> Result<(), sigint_core::Error> { ... }
    pub fn get_campaign_sessions(&self, campaign_id: Uuid) -> Result<Vec<sigint_core::types::Session>, sigint_core::Error> { ... }
}
```

Export via `pub mod campaigns;` in store's `lib.rs`.

- [ ] **Step 4: Run tests — verify PASS**
- [ ] **Step 5: Commit**

```
feat(store): add Campaign CRUD operations
```

---

### Task 5: Orchestrator — with_profile() Builder

**Files:**
- Modify: `crates/sigint-agents/src/orchestrator.rs`

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn with_profile_stores_focus() {
    let profile = ScanProfile { tools: vec![], focus: "web application security".into(),
        max_iterations: None, ports: None };
    // Build orchestrator with profile, verify focus is stored
    // (Test the profile field, not the full scan pipeline)
}

#[test]
fn profile_focus_injected_into_system_prompt() {
    // Verify that when a profile with focus is set, the agent system prompt
    // contains "ENGAGEMENT FOCUS: {focus}"
}
```

- [ ] **Step 2: Run tests — verify FAIL**
- [ ] **Step 3: Implement with_profile()**

Add to Orchestrator struct:
```rust
profile: Option<ScanProfile>,
```

Add builder method:
```rust
pub fn with_profile(mut self, profile: ScanProfile) -> Self {
    if let Some(max) = profile.max_iterations {
        self.max_iterations = max;
    }
    if let Some(ref ports) = profile.ports {
        self.ports = Some(ports.clone());
    }
    self.profile = Some(profile);
    self
}
```

In `run_agent()`, when building the system prompt, append profile focus:
```rust
let mut system_prompt = agent.system_prompt(target).to_string();
if let Some(ref profile) = self.profile {
    if !profile.focus.is_empty() {
        system_prompt.push_str(&format!(
            "\n\nENGAGEMENT FOCUS: {}\nPrioritize analysis and tool usage relevant to this focus area.",
            profile.focus
        ));
    }
}
```

In `run_agent()`, after getting tools via `registry.for_agent(agent)`, filter further if profile specifies tools. The `for_agent()` method returns `(Vec<&dyn Tool>, Vec<ToolDefinition>)` — profile filtering intersects with the role ACL result:

```rust
let (mut tool_refs, mut tool_defs) = self.registry.for_agent(agent);

// Profile tool filtering: intersect role-allowed tools with profile-specified tools
if let Some(ref profile) = self.profile {
    if !profile.tools.is_empty() {
        let allowed: std::collections::HashSet<&str> = profile.tools.iter().map(|s| s.as_str()).collect();
        tool_refs.retain(|t| allowed.contains(t.name()));
        tool_defs.retain(|d| allowed.contains(d.function.name.as_str()));
    }
}
```

**Note:** This applies AFTER the role ACL filter. A profile can only restrict tools, never expand beyond what the role allows.

- [ ] **Step 4: Run tests — verify PASS**
- [ ] **Step 5: `cargo build --workspace`**
- [ ] **Step 6: Commit**

```
feat(agents): add with_profile() for campaign tool/prompt customization
```

---

### Task 6: CLI Campaign Subcommand + Execution

**Files:**
- Modify: `crates/sigint-cli/src/main.rs`
- Create: `crates/sigint-cli/src/campaign.rs`

- [ ] **Step 1: Add Campaign to Commands enum**

```rust
/// Multi-target campaign scanning
Campaign {
    #[command(subcommand)]
    action: CampaignAction,
},
```

With:
```rust
#[derive(Subcommand, Debug)]
enum CampaignAction {
    /// Run a campaign from a target file
    Run {
        /// Path to campaign JSON file
        #[arg(short, long)]
        file: String,
        /// LLM model override
        #[arg(short, long)]
        model: Option<String>,
        /// Force non-TUI mode
        #[arg(long)]
        no_tui: bool,
    },
    /// Show campaign status
    Status {
        /// Campaign UUID prefix
        campaign: String,
    },
}
```

- [ ] **Step 2: Create campaign.rs with tests**

Unit tests for parsing:
```rust
#[test]
fn parse_campaign_file_from_json() {
    let json = r#"{ "profiles": { "web": { "tools": ["nmap_scan"], "focus": "web" } },
        "targets": [{ "name": "Site", "target": "example.com", "profile": "web" }] }"#;
    let cf: CampaignFile = serde_json::from_str(json).unwrap();
    cf.validate().unwrap();
    assert_eq!(cf.targets.len(), 1);
}

#[test]
fn campaign_validation_catches_missing_profile() {
    let json = r#"{ "targets": [{ "name": "X", "target": "x.com", "profile": "bogus" }] }"#;
    let cf: CampaignFile = serde_json::from_str(json).unwrap();
    assert!(cf.validate().is_err());
}
```

- [ ] **Step 3: Implement campaign::run()**

Follow scan.rs/resume.rs pipeline pattern. Key differences:
1. Read and parse campaign JSON file
2. Validate profiles upfront (fail-fast before any scans)
3. Create Campaign record in DB
4. Loop over targets sequentially:
   - Create session with `campaign_id`
   - Build Orchestrator with `.with_profile(profile)`
   - Run scan, persist findings
   - Collect per-target results
5. Mark campaign completed
6. Print aggregated summary

```rust
pub async fn run(
    core: AppCore,
    file_path: String,
    model: Option<String>,
    force_no_tui: bool,
) -> Result<(), Error> {
    // 1. Parse campaign file
    let content = std::fs::read_to_string(&file_path)
        .map_err(|e| Error::Other(format!("Cannot read campaign file: {e}")))?;
    let campaign_file: CampaignFile = serde_json::from_str(&content)
        .map_err(|e| Error::Other(format!("Invalid campaign JSON: {e}")))?;
    campaign_file.validate()
        .map_err(|e| Error::Other(e))?;

    // 2. Open DB, create campaign record
    let db = Database::open(&core.config.resolved_db_path())?;
    let campaign = Campaign { id: Uuid::new_v4(), name: campaign_file.targets.first()
        .map(|t| format!("Campaign: {}", t.name)).unwrap_or_default(),
        file_path: Some(file_path.clone()), created_at: Utc::now(), completed_at: None };
    db.create_campaign(&campaign)?;

    println!("Campaign started: {} targets", campaign_file.targets.len());

    // 3. Setup provider + event display (mirror scan.rs pattern)
    let provider: Arc<dyn sigint_llm::LlmProvider> = Arc::new(
        sigint_llm::ollama::OllamaProvider::from_config(&core.config.llm)?
    );
    let model_name = model.unwrap_or_else(|| core.config.llm.model.clone());
    let context_window = core.config.llm.context_window;
    let event_bus = core.events.clone();

    // Spawn stdout event printer (campaign always uses stdout, not TUI)
    // Mirror scan.rs: subscribe to event_bus and print events
    let mut event_rx = event_bus.subscribe();
    tokio::spawn(async move {
        while let Ok(event) = event_rx.recv().await {
            // Print status/tool events to stdout
            match &event {
                Event::Status(msg) => println!("  [status] {msg}"),
                Event::ToolCompleted { tool, .. } => println!("  [tool] {tool} completed"),
                _ => {}
            }
        }
    });

    let mut target_results = Vec::new();

    for (i, target_entry) in campaign_file.targets.iter().enumerate() {
        println!("\n[{}/{}] Scanning: {} ({})",
            i + 1, campaign_file.targets.len(), target_entry.name, target_entry.target);

        let profile = campaign_file.profiles.get(&target_entry.profile).cloned()
            .unwrap_or_else(|| ScanProfile { tools: vec![], focus: String::new(),
                max_iterations: None, ports: None });

        // Create session linked to campaign
        let session = Session::new(&target_entry.name)
            .with_target(&target_entry.target)
            .with_campaign_id(campaign.id);
        db.create_session(&session)?;

        // Build orchestrator with profile (mirror scan.rs constructor pattern)
        let mut registry = ToolRegistry::new();
        for tool in sigint_tools::all_executor_tools() {
            registry.register(tool);
        }

        let orchestrator = Orchestrator::new(
            Arc::clone(&provider), registry, event_bus.clone(),
            context_window, model_name.clone(),
        )
        .with_max_iterations(profile.max_iterations.unwrap_or(10))
        .with_profile(profile)
        .with_db(Arc::new(db.clone()))
        .with_session_id(session.id);

        match orchestrator.run_scan(&target_entry.target).await {
            Ok(report) => {
                // Persist findings
                persist_scan(&db, &session, &report);
                target_results.push((target_entry.name.clone(), target_entry.target.clone(), Some(report)));
            }
            Err(e) => {
                eprintln!("  Error scanning {}: {e}", target_entry.target);
                target_results.push((target_entry.name.clone(), target_entry.target.clone(), None));
            }
        }
    }

    // 4. Mark campaign complete
    db.update_campaign_completed(campaign.id)?;

    // 5. Print summary
    println!("\n=== Campaign Complete ===");
    println!("Targets: {}", target_results.len());
    let successes = target_results.iter().filter(|(_, _, r)| r.is_some()).count();
    println!("Succeeded: {successes}");
    println!("Failed: {}", target_results.len() - successes);

    Ok(())
}
```

- [ ] **Step 4: Implement campaign::status()**

Simple DB lookup:
```rust
pub async fn status(core: AppCore, campaign_prefix: String) -> Result<(), Error> {
    let db = Database::open(&core.config.resolved_db_path())?;
    // Look up campaign by prefix (reuse the list+filter pattern)
    // Print campaign info + per-target session status
}
```

- [ ] **Step 5: Wire dispatch in main.rs**
- [ ] **Step 6: `cargo build --workspace`**
- [ ] **Step 7: `cargo test -p sigint-cli`**
- [ ] **Step 8: Commit**

```
feat(cli): add sigint campaign run/status commands
```

---

### Task 7: Campaign Report Aggregation

**Files:**
- Modify: `crates/sigint-report/src/builder.rs`

- [ ] **Step 1: Write failing tests**

```rust
#[test]
fn campaign_report_includes_all_targets() {
    let data = CampaignReportData {
        campaign_name: "Test Campaign".into(),
        targets: vec![
            ("web.example.com".into(), make_report_data(3)),
            ("api.example.com".into(), make_report_data(2)),
        ],
    };
    let md = build_campaign_markdown(&data, ReportTemplate::Executive);
    assert!(md.contains("web.example.com"));
    assert!(md.contains("api.example.com"));
    assert!(md.contains("Campaign Overview"));
}

#[test]
fn campaign_report_severity_aggregation() {
    let data = CampaignReportData {
        campaign_name: "Test".into(),
        targets: vec![
            ("t1".into(), make_report_data_with_severities(1, 2, 0, 0)),
            ("t2".into(), make_report_data_with_severities(0, 1, 3, 0)),
        ],
    };
    let md = build_campaign_markdown(&data, ReportTemplate::Executive);
    // Total: 1 critical, 3 high, 3 medium
    assert!(md.contains("1") && md.contains("critical"));
}
```

- [ ] **Step 2: Run tests — verify FAIL**
- [ ] **Step 3: Implement CampaignReportData + build_campaign_markdown**

```rust
pub struct CampaignReportData {
    pub campaign_name: String,
    pub targets: Vec<(String, ReportData)>,
}

pub fn build_campaign_markdown(data: &CampaignReportData, template: ReportTemplate) -> String {
    let mut out = format!("# SIGINT Campaign Report — {}\n\n", data.campaign_name);
    out.push_str("## Campaign Overview\n\n");
    out.push_str(&format!("- **Targets scanned:** {}\n", data.targets.len()));

    // Severity aggregation table
    out.push_str("\n| Target | Findings | Critical | High | Medium | Low |\n");
    out.push_str("|--------|----------|----------|------|--------|-----|\n");
    for (name, rd) in &data.targets {
        let (c, h, m, l) = count_severities(&rd.findings);
        out.push_str(&format!("| {} | {} | {} | {} | {} | {} |\n",
            name, rd.findings.len(), c, h, m, l));
    }

    // Per-target details
    out.push_str("\n## Per-Target Details\n\n");
    for (i, (name, rd)) in data.targets.iter().enumerate() {
        out.push_str(&format!("### {}. {}\n\n", i + 1, name));
        out.push_str(&build_markdown(rd, template.clone()));
        out.push('\n');
    }
    out
}
```

- [ ] **Step 4: Run tests — verify PASS**
- [ ] **Step 5: Commit**

```
feat(report): add CampaignReportData and cross-target aggregated report
```

---

### Task 8: Full Workspace Verification

**Files:** None (verification only)

- [ ] **Step 1: Run full workspace tests**

Run: `cargo test --workspace`
Expected: All pass, 0 failures.

- [ ] **Step 2: Run clippy**

Run: `cargo clippy --workspace -- -D warnings`

- [ ] **Step 3: Verify CLI help**

Run: `cargo run -- campaign --help`
Expected: Shows `run` and `status` subcommands.

Run: `cargo run -- campaign run --help`
Expected: Shows `--file` argument.

- [ ] **Step 4: Test with sample campaign file**

Create `tmp/test-campaign.json`:
```json
{
  "profiles": {
    "web": { "tools": ["nmap_scan", "shell"], "focus": "web application security", "max_iterations": 5 },
    "infra": { "tools": ["nmap_scan"], "focus": "infrastructure reconnaissance", "max_iterations": 5 }
  },
  "targets": [
    { "name": "Example Web", "target": "scanme.nmap.org", "profile": "web" }
  ]
}
```

Verify it parses: test via unit test or `cargo run -- campaign run --file tmp/test-campaign.json --no-tui` (requires Ollama for full execution).

- [ ] **Step 5: Fix any issues and commit**

---

## Verification Plan

1. **Unit tests:** `cargo test --workspace` — all pass
2. **CLI:** `cargo run -- campaign run --help` shows subcommand
3. **Parsing:** Campaign JSON with profiles parses and validates correctly
4. **Manual (requires Ollama):** `sigint campaign run --file targets.json --no-tui` scans targets sequentially
5. **Campaign status:** `sigint campaign status <prefix>` shows campaign info
