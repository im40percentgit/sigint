//! CRUD operations for Campaign records.
//!
//! @decision DEC-CAMPAIGN-002
//! @title Campaigns stored as UUID-keyed TEXT rows with optional completed_at
//! @status accepted
//! @rationale Mirrors the sessions.rs pattern. UUIDs as TEXT, timestamps as
//! RFC-3339 strings. `completed_at` is NULL until `update_campaign_completed`
//! sets it, enabling simple "is active?" checks via IS NULL.

use chrono::Utc;
use rusqlite::params;
use sigint_core::{
    types::{Campaign, Session},
    Error,
};
use uuid::Uuid;

use crate::{db::Database, sessions::row_to_session};

impl Database {
    /// Insert a new campaign. Fails if `campaign.id` already exists.
    pub fn create_campaign(&self, campaign: &Campaign) -> Result<(), Error> {
        self.with_conn(|conn| {
            conn.execute(
                "INSERT INTO campaigns (id, name, file_path, created_at, completed_at)
                 VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    campaign.id.to_string(),
                    campaign.name,
                    campaign.file_path,
                    campaign.created_at.to_rfc3339(),
                    campaign.completed_at.map(|dt| dt.to_rfc3339()),
                ],
            )
            .map_err(|e| Error::Database(format!("create_campaign failed: {}", e)))?;
            Ok(())
        })
    }

    /// Fetch a campaign by ID. Returns `None` if not found.
    pub fn get_campaign(&self, id: Uuid) -> Result<Option<Campaign>, Error> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, name, file_path, created_at, completed_at
                     FROM campaigns WHERE id = ?1",
                )
                .map_err(|e| Error::Database(e.to_string()))?;

            let mut rows = stmt
                .query(params![id.to_string()])
                .map_err(|e| Error::Database(e.to_string()))?;

            if let Some(row) = rows.next().map_err(|e| Error::Database(e.to_string()))? {
                Ok(Some(row_to_campaign(row)?))
            } else {
                Ok(None)
            }
        })
    }

    /// List all campaigns ordered by creation time descending.
    pub fn list_campaigns(&self) -> Result<Vec<Campaign>, Error> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, name, file_path, created_at, completed_at
                     FROM campaigns ORDER BY created_at DESC",
                )
                .map_err(|e| Error::Database(e.to_string()))?;

            let campaigns = stmt
                .query_map([], |row| {
                    Ok(row_to_campaign(row).unwrap_or_else(|_| Campaign::new("<error>")))
                })
                .map_err(|e| Error::Database(e.to_string()))?
                .filter_map(|r| r.ok())
                .collect();

            Ok(campaigns)
        })
    }

    /// Look up a campaign by UUID prefix.
    ///
    /// The prefix must be at least 4 characters. Returns an error if 0 or
    /// more than 1 campaign matches.
    pub fn get_campaign_by_prefix(&self, prefix: &str) -> Result<Campaign, Error> {
        if prefix.len() < 4 {
            return Err(Error::Other(
                "UUID prefix must be at least 4 characters".into(),
            ));
        }
        let campaigns = self.list_campaigns()?;
        let matches: Vec<Campaign> = campaigns
            .into_iter()
            .filter(|c| c.id.to_string().starts_with(prefix))
            .collect();
        match matches.len() {
            0 => Err(Error::Other(format!(
                "No campaign found matching prefix '{prefix}'"
            ))),
            1 => Ok(matches.into_iter().next().unwrap()),
            n => {
                let listing: Vec<String> = matches
                    .iter()
                    .map(|c| format!("  {} — {}", &c.id.to_string()[..12], c.name))
                    .collect();
                Err(Error::Other(format!(
                    "Ambiguous: {n} campaigns match '{prefix}':\n{}",
                    listing.join("\n")
                )))
            }
        }
    }

    /// Mark a campaign as completed by setting `completed_at` to now.
    pub fn update_campaign_completed(&self, id: Uuid) -> Result<(), Error> {
        self.with_conn(|conn| {
            conn.execute(
                "UPDATE campaigns SET completed_at = ?1 WHERE id = ?2",
                params![Utc::now().to_rfc3339(), id.to_string()],
            )
            .map_err(|e| Error::Database(format!("update_campaign_completed failed: {}", e)))?;
            Ok(())
        })
    }

    /// Return all sessions that belong to the given campaign.
    pub fn get_campaign_sessions(&self, campaign_id: Uuid) -> Result<Vec<Session>, Error> {
        self.with_conn(|conn| {
            let mut stmt = conn
                .prepare(
                    "SELECT id, name, target, created_at, updated_at, parent_session_id, campaign_id
                     FROM sessions WHERE campaign_id = ?1 ORDER BY created_at ASC",
                )
                .map_err(|e| Error::Database(e.to_string()))?;

            let sessions = stmt
                .query_map(params![campaign_id.to_string()], |row| {
                    Ok(row_to_session(row).unwrap_or_else(|_| Session::new("<error>")))
                })
                .map_err(|e| Error::Database(e.to_string()))?
                .filter_map(|r| r.ok())
                .collect();

            Ok(sessions)
        })
    }
}

fn row_to_campaign(row: &rusqlite::Row<'_>) -> Result<Campaign, Error> {
    let id_str: String = row.get(0).map_err(|e| Error::Database(e.to_string()))?;
    let name: String = row.get(1).map_err(|e| Error::Database(e.to_string()))?;
    let file_path: Option<String> = row.get(2).map_err(|e| Error::Database(e.to_string()))?;
    let created_at_str: String = row.get(3).map_err(|e| Error::Database(e.to_string()))?;
    let completed_at_str: Option<String> = row.get(4).map_err(|e| Error::Database(e.to_string()))?;

    let id = Uuid::parse_str(&id_str)
        .map_err(|e| Error::Database(format!("Invalid UUID '{}': {}", id_str, e)))?;
    let created_at = chrono::DateTime::parse_from_rfc3339(&created_at_str)
        .map(|dt| dt.with_timezone(&Utc))
        .map_err(|e| Error::Database(format!("Invalid timestamp: {}", e)))?;
    let completed_at = completed_at_str
        .map(|s| {
            chrono::DateTime::parse_from_rfc3339(&s)
                .map(|dt| dt.with_timezone(&Utc))
                .map_err(|e| Error::Database(format!("Invalid completed_at: {}", e)))
        })
        .transpose()?;

    Ok(Campaign {
        id,
        name,
        file_path,
        created_at,
        completed_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigint_core::types::{Campaign, Session};

    #[test]
    fn create_and_get_campaign_roundtrip() {
        let db = Database::open_in_memory().unwrap();
        let c = Campaign::new("Test Campaign");
        db.create_campaign(&c).unwrap();
        let fetched = db.get_campaign(c.id).unwrap().unwrap();
        assert_eq!(fetched.name, "Test Campaign");
        assert!(fetched.completed_at.is_none());
    }

    #[test]
    fn update_campaign_completed() {
        let db = Database::open_in_memory().unwrap();
        let c = Campaign::new("Test");
        db.create_campaign(&c).unwrap();
        db.update_campaign_completed(c.id).unwrap();
        let fetched = db.get_campaign(c.id).unwrap().unwrap();
        assert!(fetched.completed_at.is_some());
    }

    #[test]
    fn get_campaign_sessions_returns_linked() {
        let db = Database::open_in_memory().unwrap();
        let c = Campaign::new("Test");
        db.create_campaign(&c).unwrap();
        let s = Session::new("target-1").with_campaign_id(c.id);
        db.create_session(&s).unwrap();
        let sessions = db.get_campaign_sessions(c.id).unwrap();
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].id, s.id);
    }

    #[test]
    fn get_campaign_missing_returns_none() {
        let db = Database::open_in_memory().unwrap();
        let result = db.get_campaign(Uuid::new_v4()).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn get_campaign_sessions_empty_for_no_sessions() {
        let db = Database::open_in_memory().unwrap();
        let c = Campaign::new("Empty");
        db.create_campaign(&c).unwrap();
        let sessions = db.get_campaign_sessions(c.id).unwrap();
        assert!(sessions.is_empty());
    }

    #[test]
    fn campaign_with_file_path_roundtrips() {
        let db = Database::open_in_memory().unwrap();
        let mut c = Campaign::new("File Campaign");
        c.file_path = Some("/tmp/targets.json".to_string());
        db.create_campaign(&c).unwrap();
        let fetched = db.get_campaign(c.id).unwrap().unwrap();
        assert_eq!(fetched.file_path.as_deref(), Some("/tmp/targets.json"));
    }

    #[test]
    fn list_campaigns_ordered_by_created() {
        let db = Database::open_in_memory().unwrap();
        let c1 = Campaign::new("alpha");
        let c2 = Campaign::new("beta");
        db.create_campaign(&c1).unwrap();
        db.create_campaign(&c2).unwrap();
        let list = db.list_campaigns().unwrap();
        assert_eq!(list.len(), 2);
        // Most recent first
        assert_eq!(list[0].name, "beta");
        assert_eq!(list[1].name, "alpha");
    }

    #[test]
    fn get_campaign_by_prefix_unique_match() {
        let db = Database::open_in_memory().unwrap();
        let c = Campaign::new("Test");
        db.create_campaign(&c).unwrap();
        let prefix = &c.id.to_string()[..8];
        let found = db.get_campaign_by_prefix(prefix).unwrap();
        assert_eq!(found.id, c.id);
    }

    #[test]
    fn get_campaign_by_prefix_no_match() {
        let db = Database::open_in_memory().unwrap();
        let result = db.get_campaign_by_prefix("zzzzzzzz");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No campaign found"));
    }

    #[test]
    fn get_campaign_by_prefix_too_short() {
        let db = Database::open_in_memory().unwrap();
        let result = db.get_campaign_by_prefix("ab");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("4 characters"));
    }
}
