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
        }
    }

    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
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
        let f = Finding::new(sid, "SQL Injection", "Unparameterized query", Severity::Critical);
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.severity.to_string(), "critical");
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
}
