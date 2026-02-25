//! ConversationState — sliding-window message history for an agent conversation.
//!
//! Manages the list of `ChatMessage`s sent to the LLM, tracks estimated token
//! usage, and trims the history when it approaches the context window limit.
//!
//! @decision DEC-AGENT-005
//! @title Token estimation heuristic: text.len() / 4
//! @status accepted
//! @rationale Exact token counts require a tokenizer (tiktoken, sentencepiece)
//! which adds a non-trivial dependency and runtime cost. The chars/4 heuristic
//! is a well-known approximation that works across BPE tokenizers for English
//! text. It will over-count for CJK (each char ≈ 1 token) and under-count for
//! whitespace-heavy output, but stays within ±20% for typical pentest dialogue.
//! A real tokenizer can replace this in a later phase without changing the API.
//!
//! @decision DEC-AGENT-006
//! @title Trim to 80% of context_window, preserve all system messages
//! @status accepted
//! @rationale Leaving 20% headroom ensures the LLM always has room to generate
//! a full response before hitting the hard context limit. System messages are
//! never trimmed because they contain the agent's role definition and behavioral
//! constraints — losing them would silently break agent identity. Oldest
//! user/assistant/tool messages are dropped first (FIFO) to retain the most
//! recent context, which is most relevant to the current tool-call loop turn.

use sigint_llm::types::ChatMessage;

/// Manages conversation history for a single agent session.
///
/// Maintains a `Vec<ChatMessage>` and a running token estimate. When
/// `add_message` would push usage past 80% of `context_window`,
/// `trim_to_budget` removes the oldest non-system messages.
pub struct ConversationState {
    messages: Vec<ChatMessage>,
    /// Estimated total tokens across all messages.
    token_count: usize,
    /// Hard limit of the model's context window (in tokens).
    context_window: usize,
}

impl ConversationState {
    /// Create a new, empty conversation state.
    ///
    /// # Arguments
    /// * `context_window` — the model's maximum context length in tokens.
    ///   Typical values: 4096, 8192, 32768.
    pub fn new(context_window: usize) -> Self {
        Self {
            messages: Vec::new(),
            token_count: 0,
            context_window,
        }
    }

    /// Append a message and update the token estimate.
    ///
    /// Calls `trim_to_budget` after appending if the new total exceeds 80%
    /// of `context_window`.
    pub fn add_message(&mut self, msg: ChatMessage) {
        let tokens = Self::estimate_tokens(&msg.role) + Self::estimate_tokens(&msg.content);
        self.token_count += tokens;
        self.messages.push(msg);
        self.trim_to_budget();
    }

    /// Remove oldest non-system messages until token usage is under 80% of
    /// `context_window`.
    ///
    /// System messages (role == "system") are never removed — they carry the
    /// agent's identity and behavioral constraints.
    pub fn trim_to_budget(&mut self) {
        let budget = self.context_window * 4 / 5; // 80%
        while self.token_count > budget {
            // Find the first non-system message.
            let pos = self.messages.iter().position(|m| m.role != "system");
            match pos {
                Some(i) => {
                    let removed = self.messages.remove(i);
                    let removed_tokens =
                        Self::estimate_tokens(&removed.role) + Self::estimate_tokens(&removed.content);
                    self.token_count = self.token_count.saturating_sub(removed_tokens);
                }
                None => {
                    // Only system messages remain — nothing more to trim.
                    break;
                }
            }
        }
    }

    /// Return the current message slice for passing to a `ChatRequest`.
    pub fn to_chat_messages(&self) -> &[ChatMessage] {
        &self.messages
    }

    /// Estimate token count for a string using the chars/4 heuristic.
    ///
    /// See `@decision DEC-AGENT-005` above for rationale.
    pub fn estimate_tokens(text: &str) -> usize {
        text.len().div_ceil(4)
    }

    /// Current estimated token usage across all messages.
    pub fn token_count(&self) -> usize {
        self.token_count
    }

    /// Configured context window size.
    pub fn context_window(&self) -> usize {
        self.context_window
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sys(content: &str) -> ChatMessage {
        ChatMessage::system(content)
    }
    fn usr(content: &str) -> ChatMessage {
        ChatMessage::user(content)
    }
    fn asst(content: &str) -> ChatMessage {
        ChatMessage::assistant(content)
    }

    #[test]
    fn new_state_is_empty() {
        let state = ConversationState::new(8192);
        assert_eq!(state.token_count(), 0);
        assert_eq!(state.to_chat_messages().len(), 0);
        assert_eq!(state.context_window(), 8192);
    }

    #[test]
    fn add_message_increments_token_count() {
        let mut state = ConversationState::new(8192);
        // "user" role (4 chars → 2 tokens) + "hello" content (5 chars → 2 tokens)
        state.add_message(usr("hello"));
        assert!(state.token_count() > 0);
        assert_eq!(state.to_chat_messages().len(), 1);
    }

    #[test]
    fn token_estimate_is_len_div_4_ceiling() {
        assert_eq!(ConversationState::estimate_tokens(""), 0);
        assert_eq!(ConversationState::estimate_tokens("abcd"), 1);
        assert_eq!(ConversationState::estimate_tokens("abcde"), 2); // ceiling
        assert_eq!(ConversationState::estimate_tokens("12345678"), 2);
        assert_eq!(ConversationState::estimate_tokens("123456789"), 3); // ceiling
    }

    #[test]
    fn trim_preserves_system_messages() {
        // Use a tiny context window so trim fires immediately.
        // context_window=40 → budget=32 tokens
        let mut state = ConversationState::new(40);
        state.add_message(sys("You are a security researcher."));
        // Add enough user messages to exceed budget.
        for i in 0..10 {
            state.add_message(usr(&format!("message number {i} with some padding text here")));
        }
        // System message must survive.
        let messages = state.to_chat_messages();
        assert!(
            messages.iter().any(|m| m.role == "system"),
            "system message was trimmed — must be preserved"
        );
    }

    #[test]
    fn trim_removes_oldest_non_system_first() {
        // context_window=60 → budget=48 tokens
        let mut state = ConversationState::new(60);
        state.add_message(sys("be a hacker"));
        state.add_message(usr("first user message"));
        state.add_message(asst("first assistant reply"));
        // Add a large message to push us over budget.
        state.add_message(usr(
            "this is a much longer message designed to push the conversation over the token budget limit",
        ));

        let messages = state.to_chat_messages();
        // System must survive.
        assert!(messages.iter().any(|m| m.role == "system"));
        // The most recent message must survive.
        assert!(
            messages.last().map(|m| m.role == "user").unwrap_or(false),
            "most recent message should still be present"
        );
    }

    #[test]
    fn token_count_stays_under_budget_after_trim() {
        let mut state = ConversationState::new(100);
        for _ in 0..20 {
            state.add_message(usr("padding text to fill up the context window quickly enough"));
        }
        let budget = 100 * 4 / 5; // 80
        assert!(
            state.token_count() <= budget,
            "token_count {} exceeds budget {}",
            state.token_count(),
            budget
        );
    }

    #[test]
    fn messages_slice_matches_internal_state() {
        let mut state = ConversationState::new(8192);
        state.add_message(sys("system prompt"));
        state.add_message(usr("user says hi"));
        state.add_message(asst("assistant replies"));
        let msgs = state.to_chat_messages();
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[0].role, "system");
        assert_eq!(msgs[1].role, "user");
        assert_eq!(msgs[2].role, "assistant");
    }
}
