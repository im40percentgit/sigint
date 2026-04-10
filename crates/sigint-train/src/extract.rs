//! Training data extraction from SQLite scan history.
//!
//! Queries sessions + scan_records + messages from sigint-store and produces
//! `TrainingExample` structs in OpenAI chat-completion format.
//!
//! @decision DEC-TRAIN-002
//! @title Extract one TrainingExample per successful ScanRecord tool call
//! @status accepted
//! @rationale Each successful tool invocation is a discrete supervisory signal:
//! given the system prompt + prior message context, the model should predict
//! this tool call with these arguments. Unsuccessful calls (exit_code != 0)
//! are skipped because they represent noise or misconfigured environments,
//! not ground-truth correct tool usage. Up to 5 prior message turns are
//! included as context so the model learns sequencing, not just isolated calls.

use anyhow::Result;
use uuid::Uuid;

use sigint_store::db::Database;

use crate::{TrainingExample, TrainingFunction, TrainingMessage, TrainingStats, TrainingToolCall};

/// Extract training examples from all sessions in the database.
pub fn extract_all(db: &Database) -> Result<(Vec<TrainingExample>, TrainingStats)> {
    let sessions = db.list_sessions()?;
    let session_ids: Vec<Uuid> = sessions.iter().map(|s| s.id).collect();
    extract_sessions(db, &session_ids)
}

/// Extract training examples from a specific set of sessions.
pub fn extract_sessions(
    db: &Database,
    session_ids: &[Uuid],
) -> Result<(Vec<TrainingExample>, TrainingStats)> {
    let mut examples = Vec::new();
    let mut stats = TrainingStats::default();
    let mut sessions_with_examples = 0usize;

    for &session_id in session_ids {
        let records = db.get_scan_records(session_id)?;
        let messages = db.get_messages(session_id)?;
        let session_example_count_before = examples.len();

        for (idx, record) in records.iter().enumerate() {
            // Skip failed tool invocations — they are noise, not correct usage.
            if record.exit_code != Some(0) {
                stats.skipped_failures += 1;
                continue;
            }

            // Determine system prompt from agent role.
            let role = record.agent_role.as_deref().unwrap_or("executor");
            let system_prompt = agent_system_prompt(role);

            // Build context window: up to 5 prior message turns.
            // We use the message list chronologically; the window is the last
            // min(5, total_messages) messages before this record's position.
            let context_window: Vec<TrainingMessage> = {
                // Use the first `idx` messages as prior context (bounded to 5).
                // For a more accurate window, we use scan record index as a
                // rough proxy for message position (records and messages are
                // both ordered chronologically).
                let msg_end = std::cmp::min(
                    idx.saturating_mul(2), // rough: ~2 messages per tool call
                    messages.len(),
                );
                let msg_start = msg_end.saturating_sub(5);
                messages[msg_start..msg_end]
                    .iter()
                    .map(|m| TrainingMessage {
                        role: m.role.to_string().to_lowercase(),
                        content: Some(m.content.clone()),
                        tool_calls: None,
                        tool_call_id: None,
                    })
                    .collect()
            };

            let tool_output = record
                .output
                .as_deref()
                .map(|o| truncate_output(o, 2000))
                .unwrap_or_default();

            let example = build_example(
                system_prompt,
                context_window,
                &record.tool,
                &record.args,
                &tool_output,
                session_id,
            );

            // Update stats.
            *stats
                .examples_per_agent
                .entry(role.to_string())
                .or_insert(0) += 1;
            *stats
                .examples_per_tool
                .entry(record.tool.clone())
                .or_insert(0) += 1;
            stats.total_examples += 1;

            examples.push(example);
        }

        if examples.len() > session_example_count_before {
            sessions_with_examples += 1;
        }
    }

    stats.total_sessions = sessions_with_examples;
    Ok((examples, stats))
}

/// Build a single `TrainingExample` from extracted components.
///
/// Produces the message sequence:
/// 1. system — agent role system prompt
/// 2. (optional) prior context messages
/// 3. assistant — tool_call for this invocation
/// 4. tool — tool result / output
pub fn build_example(
    system_prompt: &str,
    context: Vec<TrainingMessage>,
    tool_name: &str,
    tool_args: &str,
    tool_output: &str,
    session_id: Uuid,
) -> TrainingExample {
    let tool_call_id = format!("call_{}", &Uuid::new_v4().to_string()[..8]);

    let mut messages = Vec::new();

    // System message.
    messages.push(TrainingMessage {
        role: "system".to_string(),
        content: Some(system_prompt.to_string()),
        tool_calls: None,
        tool_call_id: None,
    });

    // Prior context turns.
    messages.extend(context);

    // Assistant turn: makes the tool call.
    messages.push(TrainingMessage {
        role: "assistant".to_string(),
        content: None,
        tool_calls: Some(vec![TrainingToolCall {
            id: tool_call_id.clone(),
            call_type: "function".to_string(),
            function: TrainingFunction {
                name: tool_name.to_string(),
                arguments: tool_args.to_string(),
            },
        }]),
        tool_call_id: None,
    });

    // Tool result turn.
    messages.push(TrainingMessage {
        role: "tool".to_string(),
        content: Some(tool_output.to_string()),
        tool_calls: None,
        tool_call_id: Some(tool_call_id),
    });

    TrainingExample {
        messages,
        session_id,
    }
}

/// Truncate output to `max_len` characters, appending an ellipsis if cut.
pub fn truncate_output(output: &str, max_len: usize) -> String {
    if output.len() <= max_len {
        output.to_string()
    } else {
        let mut s = output[..max_len].to_string();
        s.push_str("...[truncated]");
        s
    }
}

/// Return a training-appropriate system prompt for the given agent role.
///
/// These prompts instruct the model to behave as a penetration testing agent
/// with access to specific tools, appropriate for each specialization.
pub fn agent_system_prompt(role: &str) -> &'static str {
    match role {
        "executor" => {
            "You are an Executor agent in a penetration testing pipeline. \
             Your job is to execute specific technical tasks using available tools. \
             Choose the most appropriate tool for each task and use it with precise, \
             correct arguments. Always prefer targeted scans over broad ones. \
             Report results accurately without interpretation."
        }
        "researcher" => {
            "You are a Researcher agent in a penetration testing pipeline. \
             Your job is to gather information about targets using OSINT and \
             enumeration tools. Use tools methodically to map the attack surface \
             before recommending actions. Focus on accuracy and completeness."
        }
        "analyst" => {
            "You are an Analyst agent in a penetration testing pipeline. \
             Your job is to analyze scan results and identify security findings. \
             Use tools to verify discovered services and vulnerabilities. \
             Prioritize findings by severity and provide evidence-backed assessments."
        }
        "strategist" => {
            "You are a Strategist agent in a penetration testing pipeline. \
             Your job is to plan the overall approach and coordinate other agents. \
             Use tools to assess scope and guide the engagement strategy. \
             Balance thoroughness with operational security."
        }
        _ => {
            "You are a penetration testing agent with access to security tools. \
             Use the available tools to complete your assigned tasks accurately \
             and efficiently. Follow security best practices."
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_example_produces_correct_message_structure() {
        let session_id = Uuid::new_v4();
        let example = build_example(
            "You are a test agent.",
            vec![TrainingMessage {
                role: "user".to_string(),
                content: Some("Scan 10.0.0.1".to_string()),
                tool_calls: None,
                tool_call_id: None,
            }],
            "nmap_scan",
            r#"{"target":"10.0.0.1"}"#,
            "PORT 80/tcp open http",
            session_id,
        );

        assert_eq!(example.session_id, session_id);
        assert_eq!(example.messages.len(), 4, "system + context + assistant + tool");

        // system
        assert_eq!(example.messages[0].role, "system");
        assert_eq!(
            example.messages[0].content.as_deref(),
            Some("You are a test agent.")
        );
        assert!(example.messages[0].tool_calls.is_none());

        // context turn
        assert_eq!(example.messages[1].role, "user");
        assert_eq!(
            example.messages[1].content.as_deref(),
            Some("Scan 10.0.0.1")
        );

        // assistant with tool_call
        assert_eq!(example.messages[2].role, "assistant");
        assert!(example.messages[2].content.is_none());
        let calls = example.messages[2].tool_calls.as_ref().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].function.name, "nmap_scan");
        assert_eq!(calls[0].function.arguments, r#"{"target":"10.0.0.1"}"#);
        assert_eq!(calls[0].call_type, "function");

        // tool result
        assert_eq!(example.messages[3].role, "tool");
        assert_eq!(
            example.messages[3].content.as_deref(),
            Some("PORT 80/tcp open http")
        );
        // tool_call_id should match assistant's call id
        assert_eq!(
            example.messages[3].tool_call_id,
            Some(calls[0].id.clone())
        );
    }

    #[test]
    fn build_example_no_context_has_3_messages() {
        let example = build_example(
            "System prompt.",
            vec![],
            "shell",
            r#"{"cmd":"whoami"}"#,
            "root",
            Uuid::new_v4(),
        );
        assert_eq!(example.messages.len(), 3, "system + assistant + tool");
    }

    #[test]
    fn truncate_output_short_string_unchanged() {
        let s = "hello world";
        assert_eq!(truncate_output(s, 2000), s);
    }

    #[test]
    fn truncate_output_long_string_is_capped() {
        let long = "x".repeat(3000);
        let result = truncate_output(&long, 2000);
        assert!(result.starts_with(&"x".repeat(2000)));
        assert!(result.ends_with("...[truncated]"));
        // Total length = 2000 + len("...[truncated]")
        assert_eq!(result.len(), 2000 + "...[truncated]".len());
    }

    #[test]
    fn truncate_output_exact_length_unchanged() {
        let s = "x".repeat(2000);
        assert_eq!(truncate_output(&s, 2000), s);
    }

    #[test]
    fn agent_system_prompt_returns_known_roles() {
        for role in &["executor", "researcher", "analyst", "strategist"] {
            let prompt = agent_system_prompt(role);
            assert!(!prompt.is_empty(), "prompt for {role} should not be empty");
        }
    }

    #[test]
    fn agent_system_prompt_unknown_role_returns_fallback() {
        let prompt = agent_system_prompt("unknown_role_xyz");
        assert!(!prompt.is_empty());
    }

    #[test]
    fn extract_all_empty_db_returns_empty() {
        let db = sigint_store::db::Database::open_in_memory().unwrap();
        let (examples, stats) = extract_all(&db).unwrap();
        assert!(examples.is_empty());
        assert_eq!(stats.total_examples, 0);
        assert_eq!(stats.total_sessions, 0);
        assert_eq!(stats.skipped_failures, 0);
    }

    #[test]
    fn extract_sessions_skips_failed_records() {
        use sigint_core::types::Session;
        use sigint_store::scans::ScanRecord;

        let db = sigint_store::db::Database::open_in_memory().unwrap();
        let session = Session::new("test");
        db.create_session(&session).unwrap();

        // One failing record (exit_code = 1).
        let mut fail_rec = ScanRecord::new(session.id, "nmap_scan", r#"{"target":"1.1.1.1"}"#);
        fail_rec.exit_code = Some(1);
        fail_rec.output = Some("Error".to_string());
        db.create_scan_record(&fail_rec).unwrap();

        let (examples, stats) = extract_sessions(&db, &[session.id]).unwrap();
        assert!(examples.is_empty(), "failed records should be skipped");
        assert_eq!(stats.skipped_failures, 1);
        assert_eq!(stats.total_examples, 0);
    }

    #[test]
    fn extract_sessions_produces_example_for_successful_record() {
        use sigint_core::types::Session;
        use sigint_store::scans::ScanRecord;

        let db = sigint_store::db::Database::open_in_memory().unwrap();
        let session = Session::new("test");
        db.create_session(&session).unwrap();

        let mut rec = ScanRecord::new(session.id, "nmap_scan", r#"{"target":"10.0.0.1"}"#);
        rec.exit_code = Some(0);
        rec.output = Some("PORT 80/tcp open http".to_string());
        rec.agent_role = Some("executor".to_string());
        db.create_scan_record(&rec).unwrap();

        let (examples, stats) = extract_sessions(&db, &[session.id]).unwrap();
        assert_eq!(examples.len(), 1);
        assert_eq!(stats.total_examples, 1);
        assert_eq!(stats.total_sessions, 1);
        assert_eq!(stats.skipped_failures, 0);

        // Verify the example structure.
        let ex = &examples[0];
        assert_eq!(ex.session_id, session.id);
        // system + assistant + tool (no prior context messages)
        assert!(ex.messages.len() >= 3);
        assert_eq!(ex.messages[0].role, "system");

        // Find the assistant message with tool_calls.
        let asst = ex.messages.iter().find(|m| m.role == "assistant").unwrap();
        let calls = asst.tool_calls.as_ref().unwrap();
        assert_eq!(calls[0].function.name, "nmap_scan");

        // per-tool stats
        assert_eq!(stats.examples_per_tool.get("nmap_scan"), Some(&1));
        assert_eq!(stats.examples_per_agent.get("executor"), Some(&1));
    }
}
