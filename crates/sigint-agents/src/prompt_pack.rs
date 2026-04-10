//! PromptOverride — a function-pointer type for agent system-prompt overrides.
//!
//! The Orchestrator stores a `PromptOverrideFn` (a bare fn pointer) rather than
//! a concrete `PromptPack` reference. This decouples sigint-agents from
//! sigint-plugin, avoiding the circular dependency that would arise if
//! sigint-agents imported sigint-plugin (which already imports sigint-agents).
//!
//! @decision DEC-PLUGIN-003
//! @title Orchestrator uses fn-pointer for prompt overrides to break the crate cycle
//! @status accepted
//! @rationale sigint-plugin depends on sigint-agents (for AgentRole and the
//! Agent trait). If sigint-agents depended on sigint-plugin for PromptPack,
//! the two crates would form an irresolvable Cargo dependency cycle. The fix is
//! to express the override as a bare function pointer `fn(AgentRole) -> Option<&'static str>`
//! in sigint-agents. The sigint-plugin crate defines its own `PromptPack` struct
//! (with `inventory::collect!`) and provides `prompt_pack_override_fn` to adapt
//! a `&'static PromptPack` into this function pointer type. The CLI bridges the
//! two: it calls `sigint_plugin::find_prompt_pack()`, converts via the adapter,
//! and passes the result to `orchestrator.with_prompt_override()`. No shared
//! concrete types cross the crate boundary.

use crate::role::AgentRole;

/// A bare function pointer that maps an `AgentRole` to an optional prompt override.
///
/// `None` means "use the agent's built-in system_prompt()".
/// `Some(s)` means "use this string instead".
///
/// Using a bare `fn` pointer (not a closure/`Box<dyn Fn>`) keeps the type
/// `Copy + 'static` with no heap allocation.
pub type PromptOverrideFn = fn(AgentRole) -> Option<&'static str>;

#[cfg(test)]
mod tests {
    use super::*;

    fn web_security_overrides(role: AgentRole) -> Option<&'static str> {
        match role {
            AgentRole::Strategist => Some("You are a web security expert"),
            _ => None,
        }
    }

    #[test]
    fn prompt_override_fn_returns_override_for_matching_role() {
        assert_eq!(
            web_security_overrides(AgentRole::Strategist),
            Some("You are a web security expert"),
        );
    }

    #[test]
    fn prompt_override_fn_returns_none_for_unset_role() {
        assert!(web_security_overrides(AgentRole::Reporter).is_none());
    }
}
