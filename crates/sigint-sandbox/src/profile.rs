//! Pre-configured sandbox profiles for common SIGINT tools.
//!
//! A `SandboxProfile` encodes the network mode and timeout appropriate for a
//! class of tools, so callers do not have to repeat the same builder incantations.
//!
//! @decision DEC-SAND-004
//! @title Named profiles encode tool-class defaults (nmap, offline, web scanner, bruteforce)
//! @status accepted
//! @rationale Callers (sigint-recon etc.) should not need to know that nmap
//! requires pasta networking and a 5-minute timeout — that knowledge lives here.
//! Adding a new tool class means adding an enum variant and a match arm, not
//! scattering builder calls across the codebase.
//! WebScanner (600s) covers nikto/nuclei which are slow template-based scanners.
//! Bruteforce (300s) covers gobuster/feroxbuster which are fast wordlist tools.

use crate::command::{NetworkMode, SandboxedCommand};

/// Pre-built sandbox configurations for known tool categories.
pub enum SandboxProfile {
    /// Network-capable profile for nmap: pasta networking, 5-minute timeout.
    Nmap,
    /// Offline profile: no network, 1-minute timeout.
    Offline,
    /// Recon profile: pasta networking, 1-minute timeout.
    /// For passive recon commands (whois, dig, host, curl) that need DNS/network.
    Recon,
    /// Web scanner profile: pasta networking, 10-minute timeout.
    /// For slow template-based scanners (nikto, nuclei) that need extended time.
    WebScanner,
    /// Bruteforce profile: pasta networking, 5-minute timeout.
    /// For fast wordlist-based discovery tools (gobuster, feroxbuster).
    Bruteforce,
}

impl SandboxProfile {
    /// Convenience constructor for the nmap profile.
    pub fn nmap() -> Self {
        SandboxProfile::Nmap
    }

    /// Convenience constructor for the offline profile.
    pub fn offline() -> Self {
        SandboxProfile::Offline
    }

    /// Convenience constructor for the recon profile.
    pub fn recon() -> Self {
        SandboxProfile::Recon
    }

    /// Convenience constructor for the web scanner profile (nikto, nuclei).
    pub fn web_scanner() -> Self {
        SandboxProfile::WebScanner
    }

    /// Convenience constructor for the bruteforce profile (gobuster, feroxbuster).
    pub fn bruteforce() -> Self {
        SandboxProfile::Bruteforce
    }

    /// Apply this profile's settings to `program`, returning a configured
    /// `SandboxedCommand` ready for further `.arg()` calls or `.execute()`.
    pub fn apply(&self, program: &str) -> SandboxedCommand {
        match self {
            SandboxProfile::Nmap => SandboxedCommand::new(program)
                .network(NetworkMode::Pasta)
                .timeout(300),
            SandboxProfile::Offline => SandboxedCommand::new(program)
                .network(NetworkMode::None)
                .timeout(60),
            SandboxProfile::Recon => SandboxedCommand::new(program)
                .network(NetworkMode::Pasta)
                .timeout(60),
            SandboxProfile::WebScanner => SandboxedCommand::new(program)
                .network(NetworkMode::Pasta)
                .timeout(600),
            SandboxProfile::Bruteforce => SandboxedCommand::new(program)
                .network(NetworkMode::Pasta)
                .timeout(300),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::NetworkMode;

    #[test]
    fn nmap_profile_settings() {
        let cmd = SandboxProfile::nmap().apply("/usr/bin/nmap");
        assert_eq!(cmd.network, NetworkMode::Pasta);
        assert_eq!(cmd.timeout_secs, 300);
        assert_eq!(cmd.program, "/usr/bin/nmap");
    }

    #[test]
    fn offline_profile_settings() {
        let cmd = SandboxProfile::offline().apply("/usr/bin/dig");
        assert_eq!(cmd.network, NetworkMode::None);
        assert_eq!(cmd.timeout_secs, 60);
    }

    #[test]
    fn recon_profile_settings() {
        let cmd = SandboxProfile::recon().apply("/usr/bin/whois");
        assert_eq!(cmd.network, NetworkMode::Pasta);
        assert_eq!(cmd.timeout_secs, 60);
        assert_eq!(cmd.program, "/usr/bin/whois");
    }

    #[test]
    fn web_scanner_profile_settings() {
        let cmd = SandboxProfile::web_scanner().apply("/usr/bin/nikto");
        assert_eq!(cmd.network, NetworkMode::Pasta);
        assert_eq!(cmd.timeout_secs, 600);
        assert_eq!(cmd.program, "/usr/bin/nikto");
    }

    #[test]
    fn bruteforce_profile_settings() {
        let cmd = SandboxProfile::bruteforce().apply("/usr/bin/gobuster");
        assert_eq!(cmd.network, NetworkMode::Pasta);
        assert_eq!(cmd.timeout_secs, 300);
        assert_eq!(cmd.program, "/usr/bin/gobuster");
    }
}
