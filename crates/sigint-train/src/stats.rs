//! Training data statistics printer.
//!
//! Formats and prints a `TrainingStats` summary to stdout — total examples,
//! per-agent breakdown, per-tool breakdown, and skipped failures.

use crate::TrainingStats;

/// Print a formatted summary of training data statistics.
pub fn print_stats(stats: &TrainingStats) {
    println!("Training Data Statistics");
    println!("========================");
    println!("Total examples : {}", stats.total_examples);
    println!("Total sessions : {}", stats.total_sessions);
    println!("Skipped (fail) : {}", stats.skipped_failures);

    if !stats.examples_per_agent.is_empty() {
        println!();
        println!("Examples per agent role:");
        let mut roles: Vec<(&String, &usize)> = stats.examples_per_agent.iter().collect();
        roles.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        for (role, count) in roles {
            println!("  {:20} {}", role, count);
        }
    }

    if !stats.examples_per_tool.is_empty() {
        println!();
        println!("Examples per tool:");
        let mut tools: Vec<(&String, &usize)> = stats.examples_per_tool.iter().collect();
        tools.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        for (tool, count) in tools {
            println!("  {:30} {}", tool, count);
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn print_stats_does_not_panic_on_empty() {
        let stats = TrainingStats::default();
        // Should not panic.
        print_stats(&stats);
    }

    #[test]
    fn print_stats_does_not_panic_with_data() {
        let mut stats = TrainingStats::default();
        stats.total_examples = 42;
        stats.total_sessions = 5;
        stats.skipped_failures = 3;
        stats.examples_per_agent.insert("executor".to_string(), 30);
        stats
            .examples_per_agent
            .insert("researcher".to_string(), 12);
        stats.examples_per_tool.insert("nmap_scan".to_string(), 20);
        stats.examples_per_tool.insert("shell".to_string(), 22);
        // Should not panic.
        print_stats(&stats);
    }
}
