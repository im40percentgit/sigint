# Documentation & Release Prep — Design Document

**Date:** 2026-03-02
**Status:** approved
**Approach:** 4 core documentation files for public GitHub repo

## Context

SIGINT has excellent internal documentation (@decision annotations, lib.rs doc comments across all 12 crates, CLI help text) but is missing all user-facing documentation. No README, LICENSE file, CHANGELOG, or CONTRIBUTING guide exists. The project is at v0.1.0 with CI in place.

## Design Decisions

- **Scope:** README.md, LICENSE, CHANGELOG.md, CONTRIBUTING.md — the 4 files every GitHub repo needs
- **Tone:** Technical/hacker — concise, code-heavy, no marketing fluff
- **Release workflow:** Deferred to a future session
- **Cargo doc / GitHub Pages:** Deferred to a future session

## README.md

- One-line description: AI-powered penetration testing, locally
- What it does: orchestrates AI agents for recon, strategy, execution, analysis, reporting
- Quick Start: prerequisites (Rust, Ollama, nmap), install from source
- Usage: key commands with examples (scan, diff, recon, report, serve, chat, doctor)
- Architecture: 12-crate workspace map (condensed from lib.rs doc comments)
- Development: cargo test, cargo clippy, link to CONTRIBUTING.md
- No badges, no GIFs, no screenshots

## LICENSE

MIT license text. Copyright holder: "SIGINT Contributors" (matches Cargo.toml).

## CHANGELOG.md

Keep-a-Changelog format. Single v0.1.0 entry covering:
- Phase 1-2: Core architecture, agent system, tool wrappers, sandbox
- Phase 3: TUI, memory system, embeddings
- Phase 4: Attack surface mapping, recon modules
- Phase 5: Web UI, REST API, WebSocket
- Phase 6: Hybrid LLM support, OpenAI provider
- Recent: E2E integration tests, CI pipeline, clippy hardening, scan diff

## CONTRIBUTING.md

- Prerequisites: Rust stable, Ollama, nmap
- Development setup: clone, cargo build, cargo test --workspace
- Architecture overview: crate map reference
- PR workflow: branch from main, CI must pass (test + clippy + fmt)
- Code conventions: @decision annotations on 50+ line files, thin web handlers, TDD
