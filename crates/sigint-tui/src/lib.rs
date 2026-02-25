//! sigint-tui — Ratatui terminal user interface.
//!
//! Provides a 5-panel TUI driven by the AppCore event bus:
//!   - Agent status bar (top)
//!   - Chat panel (left 60%) + Tool output panel (right 40%)
//!   - Findings table (bottom section)
//!   - Input bar (bottom)
//!
//! Entry point: `TuiApp::new(event_rx)?.run().await`

pub mod app;
pub mod state;
pub mod ui;

pub use app::TuiApp;
