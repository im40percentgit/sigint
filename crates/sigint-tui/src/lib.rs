//! sigint-tui — Ratatui terminal user interface.
//!
//! Provides a tab-based multi-view TUI driven by the AppCore event bus.
//!
//! Views (number keys 1–6):
//!   1. Scan     — live agent activity: Chat, Tools, Findings, Assets, Input
//!   2. Dashboard — aggregate stats and recent sessions
//!   3. Sessions  — historical session browser with message replay
//!   4. Findings  — all findings across sessions with detail pane
//!   5. Reports   — report generation and Markdown preview
//!   6. Settings  — TUI-local configuration overrides
//!
//! Entry point: `TuiApp::new(event_rx, event_tx)?.run().await`

pub mod app;
pub mod state;
pub mod ui;

pub use app::TuiApp;
