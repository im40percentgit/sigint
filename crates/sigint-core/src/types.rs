//! Domain types shared across the SIGINT workspace.
//!
//! These are the core data structures that flow through the event bus,
//! get persisted to SQLite, and are passed between agents.
//!
//! @decision DEC-ARCH-002
//! @title Cargo workspace with sigint-core as shared domain layer
//! @status accepted
//! @rationale All crates depend on these types. Centralizing them in
//! sigint-core eliminates duplicate definitions and ensures the event
//! bus, store, and LLM crates all speak the same language.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ── Session ──────────────────────────────────────────────────────────────────

/// A top-level conversation/engagement session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub name: String,
    pub target: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// When set, this session resumes a previous one. Forms a linked chain
    /// for session resume tracking (Phase 9A).
    pub parent_session_id: Option<Uuid>,
    /// When set, this session belongs to a multi-target campaign (DEC-CAMPAIGN-002).
    pub campaign_id: Option<Uuid>,
}

impl Session {
    pub fn new(name: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            target: None,
            created_at: now,
            updated_at: now,
            parent_session_id: None,
            campaign_id: None,
        }
    }

    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    pub fn with_campaign_id(mut self, id: Uuid) -> Self {
        self.campaign_id = Some(id);
        self
    }
}

// ── Campaign ──────────────────────────────────────────────────────────────────

/// A multi-target scanning campaign (DEC-CAMPAIGN-002).
///
/// Groups multiple sessions under a named campaign, optionally backed by
/// a file (e.g. a target list). Completed campaigns record a timestamp
/// so reports can be scoped to the full campaign duration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Campaign {
    pub id: Uuid,
    pub name: String,
    pub file_path: Option<String>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

impl Campaign {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            file_path: None,
            created_at: Utc::now(),
            completed_at: None,
        }
    }
}

// ── Message ──────────────────────────────────────────────────────────────────

/// Role of a message participant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    System,
    User,
    Assistant,
    Tool,
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Role::System => write!(f, "system"),
            Role::User => write!(f, "user"),
            Role::Assistant => write!(f, "assistant"),
            Role::Tool => write!(f, "tool"),
        }
    }
}

/// A chat message in a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: Uuid,
    pub session_id: Uuid,
    pub role: Role,
    pub content: String,
    pub created_at: DateTime<Utc>,
    /// Token count if known (populated after LLM response).
    pub tokens: Option<u32>,
}

impl Message {
    pub fn new(session_id: Uuid, role: Role, content: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            session_id,
            role,
            content: content.into(),
            created_at: Utc::now(),
            tokens: None,
        }
    }

    pub fn user(session_id: Uuid, content: impl Into<String>) -> Self {
        Self::new(session_id, Role::User, content)
    }

    pub fn assistant(session_id: Uuid, content: impl Into<String>) -> Self {
        Self::new(session_id, Role::Assistant, content)
    }

    pub fn system(session_id: Uuid, content: impl Into<String>) -> Self {
        Self::new(session_id, Role::System, content)
    }
}

// ── Task ─────────────────────────────────────────────────────────────────────

/// Status of an agent task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// An agent-assigned work item within a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: Uuid,
    pub session_id: Uuid,
    pub title: String,
    pub description: String,
    pub status: TaskStatus,
    pub assigned_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Task {
    pub fn new(session_id: Uuid, title: impl Into<String>, description: impl Into<String>) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            session_id,
            title: title.into(),
            description: description.into(),
            status: TaskStatus::Pending,
            assigned_agent: None,
            created_at: now,
            updated_at: now,
        }
    }
}

// ── Finding ──────────────────────────────────────────────────────────────────

/// Severity level of a security finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Low => write!(f, "low"),
            Severity::Medium => write!(f, "medium"),
            Severity::High => write!(f, "high"),
            Severity::Critical => write!(f, "critical"),
        }
    }
}

impl Severity {
    /// Default CVSS-style score for this severity level.
    ///
    /// These values align with the CVSS v3.1 severity rating scale:
    /// Critical ≥9.0, High 7.0–8.9, Medium 4.0–6.9, Low 0.1–3.9, Info/None = 0.0.
    pub fn default_score(&self) -> f32 {
        match self {
            Severity::Critical => 9.5,
            Severity::High => 8.0,
            Severity::Medium => 5.5,
            Severity::Low => 2.0,
            Severity::Info => 0.0,
        }
    }
}

/// A security finding discovered during a session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: Uuid,
    pub session_id: Uuid,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub asset: Option<String>,
    pub evidence: Option<String>,
    pub created_at: DateTime<Utc>,
    /// Optional CVSS-style numeric score (0.0–10.0). When `None`, callers
    /// may fall back to `severity.default_score()` for reporting purposes.
    pub cvss_score: Option<f32>,
}

impl Finding {
    pub fn new(
        session_id: Uuid,
        title: impl Into<String>,
        description: impl Into<String>,
        severity: Severity,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            session_id,
            title: title.into(),
            description: description.into(),
            severity,
            asset: None,
            evidence: None,
            created_at: Utc::now(),
            cvss_score: None,
        }
    }
}

// ── Asset ────────────────────────────────────────────────────────────────────

/// Type of network/application asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AssetKind {
    Host,
    Domain,
    Url,
    Service,
    Certificate,
    Email,
    Other,
}

impl std::fmt::Display for AssetKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssetKind::Host => write!(f, "host"),
            AssetKind::Domain => write!(f, "domain"),
            AssetKind::Url => write!(f, "url"),
            AssetKind::Service => write!(f, "service"),
            AssetKind::Certificate => write!(f, "certificate"),
            AssetKind::Email => write!(f, "email"),
            AssetKind::Other => write!(f, "other"),
        }
    }
}

impl std::str::FromStr for AssetKind {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "host" => Ok(AssetKind::Host),
            "domain" => Ok(AssetKind::Domain),
            "url" => Ok(AssetKind::Url),
            "service" => Ok(AssetKind::Service),
            "certificate" => Ok(AssetKind::Certificate),
            "email" => Ok(AssetKind::Email),
            _ => Ok(AssetKind::Other),
        }
    }
}

/// A discovered asset in the attack surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub id: Uuid,
    pub session_id: Uuid,
    pub kind: AssetKind,
    pub value: String,
    pub metadata: serde_json::Value,
    pub discovered_at: DateTime<Utc>,
}

impl Asset {
    pub fn new(session_id: Uuid, kind: AssetKind, value: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            session_id,
            kind,
            value: value.into(),
            metadata: serde_json::Value::Null,
            discovered_at: Utc::now(),
        }
    }
}

// ── AssetService ──────────────────────────────────────────────────────────────

/// A network service discovered on an asset port.
///
/// Represents a row in the `asset_services` table — one entry per
/// (asset, port, protocol) combination discovered during reconnaissance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetService {
    pub id: Uuid,
    pub asset_id: Uuid,
    pub port: i32,
    pub protocol: String,
    pub service: String,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub discovered_at: DateTime<Utc>,
}

impl AssetService {
    /// Construct a new service with required fields; optional fields default to `None`.
    pub fn new(
        asset_id: Uuid,
        port: i32,
        protocol: impl Into<String>,
        service: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            asset_id,
            port,
            protocol: protocol.into(),
            service: service.into(),
            version: None,
            banner: None,
            discovered_at: Utc::now(),
        }
    }
}

// ── AssetChange ───────────────────────────────────────────────────────────────

/// An audited field-level change to an asset.
///
/// Stored in `asset_changes` to provide a full history of how an asset's
/// properties evolved over the course of a session. Both old and new values
/// are stored as strings for schema simplicity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssetChange {
    pub id: Uuid,
    pub asset_id: Uuid,
    pub field: String,
    pub old_value: String,
    pub new_value: String,
    pub changed_at: DateTime<Utc>,
}

impl AssetChange {
    /// Record a change to a single field on an asset.
    pub fn new(
        asset_id: Uuid,
        field: impl Into<String>,
        old_value: impl Into<String>,
        new_value: impl Into<String>,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            asset_id,
            field: field.into(),
            old_value: old_value.into(),
            new_value: new_value.into(),
            changed_at: Utc::now(),
        }
    }
}

// ── ToolRisk ──────────────────────────────────────────────────────────────────

/// Risk classification for a tool call, used by the approval gate to decide
/// whether to auto-approve or prompt the user.
///
/// Variants are ordered from lowest to highest risk so comparison operators
/// work as expected (Low < Medium < High).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolRisk {
    Low,
    Medium,
    High,
}

impl std::fmt::Display for ToolRisk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ToolRisk::Low => write!(f, "low"),
            ToolRisk::Medium => write!(f, "medium"),
            ToolRisk::High => write!(f, "high"),
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_creation() {
        let s = Session::new("test-session");
        assert_eq!(s.name, "test-session");
        assert!(s.target.is_none());
        assert!(s.created_at <= Utc::now());
    }

    #[test]
    fn session_with_target() {
        let s = Session::new("recon").with_target("example.com");
        assert_eq!(s.target.as_deref(), Some("example.com"));
    }

    #[test]
    fn message_roles() {
        let sid = Uuid::new_v4();
        let u = Message::user(sid, "hello");
        let a = Message::assistant(sid, "hi");
        let s = Message::system(sid, "you are helpful");

        assert_eq!(u.role, Role::User);
        assert_eq!(a.role, Role::Assistant);
        assert_eq!(s.role, Role::System);
        assert_eq!(u.session_id, sid);
        assert_eq!(u.content, "hello");
    }

    #[test]
    fn role_display() {
        assert_eq!(Role::User.to_string(), "user");
        assert_eq!(Role::Assistant.to_string(), "assistant");
        assert_eq!(Role::System.to_string(), "system");
        assert_eq!(Role::Tool.to_string(), "tool");
    }

    #[test]
    fn finding_severity() {
        let sid = Uuid::new_v4();
        let f = Finding::new(
            sid,
            "SQL Injection",
            "Unparameterized query",
            Severity::Critical,
        );
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.severity.to_string(), "critical");
    }

    #[test]
    fn severity_default_scores() {
        assert_eq!(Severity::Critical.default_score(), 9.5);
        assert_eq!(Severity::High.default_score(), 8.0);
        assert_eq!(Severity::Medium.default_score(), 5.5);
        assert_eq!(Severity::Low.default_score(), 2.0);
        assert_eq!(Severity::Info.default_score(), 0.0);
    }

    #[test]
    fn finding_cvss_score_defaults_to_none() {
        let sid = Uuid::new_v4();
        let f = Finding::new(sid, "Test", "desc", Severity::High);
        assert!(f.cvss_score.is_none());
    }

    #[test]
    fn task_defaults_to_pending() {
        let sid = Uuid::new_v4();
        let t = Task::new(sid, "Port scan", "Run nmap on target");
        assert_eq!(t.status, TaskStatus::Pending);
        assert!(t.assigned_agent.is_none());
    }

    #[test]
    fn asset_kinds_serialize() {
        let sid = Uuid::new_v4();
        let a = Asset::new(sid, AssetKind::Host, "192.168.1.1");
        let json = serde_json::to_string(&a).unwrap();
        assert!(json.contains("\"host\""));
        assert!(json.contains("192.168.1.1"));
    }

    #[test]
    fn tool_risk_serializes() {
        // Serialize High -> "high"
        let high_json = serde_json::to_string(&ToolRisk::High).unwrap();
        assert_eq!(high_json, "\"high\"");

        // Deserialize "medium" -> Medium
        let medium: ToolRisk = serde_json::from_str("\"medium\"").unwrap();
        assert_eq!(medium, ToolRisk::Medium);

        // Display trait
        assert_eq!(ToolRisk::Low.to_string(), "low");
        assert_eq!(ToolRisk::Medium.to_string(), "medium");
        assert_eq!(ToolRisk::High.to_string(), "high");
    }

    #[test]
    fn tool_risk_ordering() {
        assert!(ToolRisk::Low < ToolRisk::Medium);
        assert!(ToolRisk::Medium < ToolRisk::High);
        assert!(ToolRisk::Low < ToolRisk::High);

        // Ensure equality works
        assert_eq!(ToolRisk::Medium, ToolRisk::Medium);

        // Verify min/max via comparison
        let risks = [ToolRisk::High, ToolRisk::Low, ToolRisk::Medium];
        assert_eq!(risks.iter().min(), Some(&ToolRisk::Low));
        assert_eq!(risks.iter().max(), Some(&ToolRisk::High));
    }
}
