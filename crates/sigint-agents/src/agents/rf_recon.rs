//! RfReconAgent — wireless RF spectrum reconnaissance specialist.
//!
//! @decision DEC-AKAEI-003
//! @title RfRecon runs before Researcher; skipped when akaei tools absent
//! @status accepted
//! @rationale When HackRF hardware is present (akaei tools registered), RF recon
//! provides the Strategist with wireless attack surface intelligence before
//! network recon begins. The agent uses akaei_sweep to survey the spectrum,
//! akaei_freqdb to identify known protocols, akaei_scan to locate active
//! transmitters, akaei_decode to extract protocol messages, and akaei_analyze
//! for offline signal analysis. When no akaei tools are registered the
//! Orchestrator skips this agent entirely — see orchestrator.rs.

use crate::{agent::Agent, role::AgentRole};

/// Wireless RF spectrum reconnaissance agent.
///
/// Surveys the radio environment around the target using HackRF tools.
/// Runs as the first pipeline stage when akaei tools are registered.
/// Its output is stored in `TaskContext::agent_outputs[RfRecon]` and
/// fed into the Strategist's prompt alongside network findings.
pub struct RfReconAgent {
    allowed_tools: Vec<String>,
}

impl RfReconAgent {
    pub fn new() -> Self {
        Self {
            allowed_tools: vec![
                "akaei_sweep".to_string(),
                "akaei_scan".to_string(),
                "akaei_decode".to_string(),
                "akaei_analyze".to_string(),
                "akaei_freqdb".to_string(),
                "shell".to_string(),
            ],
        }
    }
}

impl Default for RfReconAgent {
    fn default() -> Self {
        Self::new()
    }
}

impl Agent for RfReconAgent {
    fn name(&self) -> &str {
        "rf_recon"
    }

    fn role(&self) -> AgentRole {
        AgentRole::RfRecon
    }

    fn system_prompt(&self) -> &str {
        "You are an expert wireless security analyst specialising in RF spectrum \
         reconnaissance using HackRF SDR hardware via the akaei toolkit.\n\n\
         You have access to the following tools:\n\
         - **akaei_sweep** — broad spectrum sweep to identify active frequency bands\n\
         - **akaei_scan** — targeted scan for active transmitters above a power threshold\n\
         - **akaei_decode** — decode RF signals using protocol-specific decoders\n\
         - **akaei_analyze** — offline analysis of captured IQ files\n\
         - **akaei_freqdb** — look up known frequency assignments by band\n\
         - **shell** — for text processing of tool output\n\n\
         APPROACH:\n\
         1. Start with a broad sweep (akaei_sweep) across ISM bands and any \
            target-relevant frequencies to identify active bands.\n\
         2. Use akaei_freqdb to identify what protocols are known at active frequencies.\n\
         3. Run akaei_scan on the most active bands to locate specific transmitters.\n\
         4. Attempt akaei_decode on detected signals using the most likely protocol.\n\
         5. Use akaei_analyze on any captures to extract signal characteristics.\n\
         6. Document every active frequency, likely protocol, power level, and \
            any decoded messages.\n\n\
         FOCUS:\n\
         - Identify IoT devices transmitting wirelessly (garage doors, smart meters, \
           sensors, key fobs, access control systems).\n\
         - Note any unencrypted or replay-vulnerable protocols.\n\
         - Summarise findings so the Strategist can plan RF-based attack vectors \
           alongside network findings.\n\n\
         Be methodical. Record exact frequencies, power levels, and raw tool output."
    }

    fn allowed_tools(&self) -> &[String] {
        &self.allowed_tools
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rf_recon_identity() {
        let agent = RfReconAgent::new();
        assert_eq!(agent.name(), "rf_recon");
        assert_eq!(agent.role(), AgentRole::RfRecon);
    }

    #[test]
    fn rf_recon_system_prompt_nonempty_and_relevant() {
        let agent = RfReconAgent::new();
        let prompt = agent.system_prompt();
        assert!(!prompt.is_empty());
        assert!(
            prompt.to_lowercase().contains("rf") || prompt.to_lowercase().contains("spectrum"),
            "prompt should mention RF/spectrum: {prompt}"
        );
        assert!(
            prompt.to_lowercase().contains("hackrf") || prompt.to_lowercase().contains("akaei"),
            "prompt should mention HackRF or akaei: {prompt}"
        );
    }

    #[test]
    fn rf_recon_allowed_tools() {
        let agent = RfReconAgent::new();
        let tools = agent.allowed_tools();
        assert!(tools.contains(&"akaei_sweep".to_string()));
        assert!(tools.contains(&"akaei_scan".to_string()));
        assert!(tools.contains(&"akaei_decode".to_string()));
        assert!(tools.contains(&"akaei_analyze".to_string()));
        assert!(tools.contains(&"akaei_freqdb".to_string()));
        assert!(tools.contains(&"shell".to_string()));
        assert_eq!(tools.len(), 6, "rf_recon should have exactly 6 tools");
    }

    #[test]
    fn rf_recon_default_equals_new() {
        let a = RfReconAgent::new();
        let b = RfReconAgent::default();
        assert_eq!(a.name(), b.name());
        assert_eq!(a.role(), b.role());
    }
}
