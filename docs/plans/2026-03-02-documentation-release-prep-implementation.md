# Documentation & Release Prep Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add the 4 core documentation files every public GitHub repo needs: README.md, LICENSE, CHANGELOG.md, CONTRIBUTING.md.

**Architecture:** Pure documentation — no code changes. Each file is self-contained and can be written and committed independently. Content is derived from existing lib.rs doc comments, CLI help text, and git history.

**Tech Stack:** Markdown, MIT license text

---

### Task 1: LICENSE

**Files:**
- Create: `LICENSE`

**Step 1: Create the MIT license file**

Create `LICENSE` at the project root with the standard MIT license text. Use "2025-2026" as the year range and "SIGINT Contributors" as the copyright holder (matching `Cargo.toml`).

```
MIT License

Copyright (c) 2025-2026 SIGINT Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

**Step 2: Verify**

Run: `cat LICENSE | head -3`
Expected: Shows "MIT License" and copyright line

**Step 3: Commit**

```bash
git add LICENSE
git commit -m "docs: add MIT LICENSE file"
```

---

### Task 2: README.md

**Files:**
- Create: `README.md`

**Step 1: Write the README**

Create `README.md` at the project root. The README must include these sections in order:

**Header:** Project name, one-line description, what it does in 2-3 sentences.

```markdown
# SIGINT

AI-powered penetration testing, locally.

SIGINT orchestrates AI agents for reconnaissance, strategy, execution, analysis, and reporting — all from a single Rust binary. Runs locally with [Ollama](https://ollama.ai); no Docker, no cloud required.
```

**Quick Start:** Prerequisites and install from source.

```markdown
## Quick Start

### Prerequisites

- [Rust](https://rustup.rs/) (stable toolchain)
- [Ollama](https://ollama.ai/) running locally with a model pulled (e.g. `ollama pull llama3.1`)
- [nmap](https://nmap.org/) installed and on PATH

### Install

```bash
git clone https://github.com/<owner>/sigint.git
cd sigint
cargo install --path crates/sigint-cli
```
```

**Usage:** Key commands with brief examples. Include these commands:

- `sigint scan <target>` — run a multi-agent penetration scan
- `sigint recon <target>` — attack surface reconnaissance
- `sigint diff <scan_a> <scan_b>` — compare findings between scans
- `sigint report <session_id>` — generate a report
- `sigint serve` — start the web UI
- `sigint chat` — interactive AI chat
- `sigint doctor` — check environment
- `sigint sessions list` — manage stored sessions

Format each as a short code block showing the command and a one-line description.

**Architecture:** Crate map table. Use this exact table derived from the lib.rs doc comments:

```markdown
## Architecture

SIGINT is a Cargo workspace with 12 crates:

| Crate | Purpose |
|-------|---------|
| `sigint-core` | Shared types, config, event bus, approval registry |
| `sigint-llm` | LLM provider trait + Ollama/OpenAI implementations |
| `sigint-agents` | Multi-agent orchestrator (5-role pipeline), scan service |
| `sigint-store` | SQLite persistence, FTS5 search, query builders |
| `sigint-tools` | Sandboxed tool wrappers (nmap, nikto, nuclei, gobuster, etc.) |
| `sigint-sandbox` | Linux namespace isolation (pasta networking) |
| `sigint-recon` | Attack surface mapping — DNS, port, web, cert, OSINT modules |
| `sigint-tui` | Terminal UI (ratatui, 5-panel layout) |
| `sigint-web` | REST API + WebSocket server (Axum) |
| `sigint-memory` | Working/episodic/semantic memory system |
| `sigint-report` | Report generation (Markdown/HTML) |
| `sigint-cli` | CLI entry point (clap) |
```

**Development:** Brief section linking to CONTRIBUTING.md.

```markdown
## Development

```bash
cargo build
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for full development setup.
```

**License:** One-liner at the bottom.

```markdown
## License

MIT — see [LICENSE](LICENSE).
```

**Step 2: Verify**

Run: `wc -l README.md`
Expected: ~80-120 lines (concise but complete)

Run: `head -5 README.md`
Expected: Shows "# SIGINT" and tagline

**Step 3: Commit**

```bash
git add README.md
git commit -m "docs: add README with quick start, usage, and architecture"
```

---

### Task 3: CHANGELOG.md

**Files:**
- Create: `CHANGELOG.md`

**Step 1: Write the changelog**

Create `CHANGELOG.md` using [Keep a Changelog](https://keepachangelog.com/) format. Single release entry for v0.1.0. Organize by category (Added, Changed, Fixed). Content derived from git history:

```markdown
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-03-02

### Added

#### Core Architecture
- Cargo workspace with 12 crates and shared dependency management
- `sigint-core`: configuration, event bus, approval registry, domain types
- `sigint-store`: SQLite persistence with r2d2 connection pool, FTS5 full-text search, typed query builders
- `sigint-llm`: LLM provider trait with Ollama and OpenAI-compatible implementations, streaming SSE

#### Agent System
- Multi-agent orchestrator with 5-role pipeline (researcher, strategist, executor, analyst, reporter)
- Tool-calling loop with approval gates and risk classification
- `ScanService` for managing scan lifecycle (start, status, cancel, list)

#### Tools & Sandbox
- Sandboxed tool wrappers: nmap, nikto, nuclei, gobuster, feroxbuster
- Linux namespace isolation via pasta networking
- Nmap XML and Nuclei JSONL output parsers

#### Reconnaissance
- Attack surface mapping engine with pluggable discovery modules
- DNS, port scanning, web probing, certificate transparency, OSINT modules
- Asset correlation and change detection

#### User Interfaces
- Terminal UI with ratatui (5-panel layout, approval prompts)
- REST API with Axum (sessions, findings, assets, reports, scans, diff)
- WebSocket event bridge for real-time updates
- Embedded SPA frontend with Preact + rust-embed
- CLI with 8 subcommands: scan, recon, diff, report, serve, chat, doctor, sessions

#### Memory & Search
- Working, episodic, and semantic memory system
- fastembed vector embeddings with cosine similarity search
- Background embedding worker

#### Reports
- Markdown and HTML report generation
- Executive, detailed, and technical templates

#### Scan Diff
- Compare findings between any two scans (new, fixed, unchanged)
- REST API endpoint: `GET /api/diff/{scan_a}/{scan_b}`
- CLI command: `sigint diff <scan_a> <scan_b> [--format json|markdown]`

#### Quality
- 290+ tests across all crates plus 16 E2E integration tests
- GitHub Actions CI: test, clippy (`-D warnings`), rustfmt
- `@decision` annotations on all significant architectural choices
```

**Step 2: Verify**

Run: `head -10 CHANGELOG.md`
Expected: Shows header and format note

**Step 3: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs: add CHANGELOG with v0.1.0 release notes"
```

---

### Task 4: CONTRIBUTING.md

**Files:**
- Create: `CONTRIBUTING.md`

**Step 1: Write the contributing guide**

Create `CONTRIBUTING.md`:

```markdown
# Contributing to SIGINT

## Prerequisites

- [Rust](https://rustup.rs/) stable toolchain
- [Ollama](https://ollama.ai/) running locally (for LLM integration tests)
- [nmap](https://nmap.org/) (for tool wrapper tests)
- Linux recommended (sandbox uses namespaces; tests skip gracefully on other platforms)

## Development Setup

```bash
git clone https://github.com/<owner>/sigint.git
cd sigint
cargo build
cargo test --workspace
```

Three sandbox tests require Linux namespace capabilities and will fail in unprivileged environments — this is expected.

## Running Tests

```bash
# Full test suite
cargo test --workspace

# Single crate
cargo test -p sigint-core

# E2E integration tests only
cargo test -p sigint-e2e
```

## Code Quality

CI enforces all three checks on every PR:

```bash
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```

## Pull Request Workflow

1. Create a branch from `main`
2. Make your changes with tests
3. Ensure all three CI checks pass locally
4. Open a PR — CI runs automatically

## Code Conventions

- **`@decision` annotations:** Files over ~50 lines should include a `@decision` block in the module doc comment explaining key architectural choices. Format:
  ```rust
  //! @decision DEC-EXAMPLE-001
  //! @title Short title
  //! @status accepted
  //! @rationale Why this approach was chosen.
  ```
- **Thin web handlers:** REST handlers in `sigint-web` are pure presentation — no business logic. All domain logic lives in `sigint-core` or `sigint-store`.
- **Sandboxed tools:** Tool wrappers in `sigint-tools` execute commands through `sigint-sandbox`. Never shell out directly.
- **In-memory SQLite for tests:** Use `Database::open_in_memory()` for test isolation.

## Architecture

See the crate map in [README.md](README.md#architecture).
```

**Step 2: Verify**

Run: `wc -l CONTRIBUTING.md`
Expected: ~60-80 lines

**Step 3: Commit**

```bash
git add CONTRIBUTING.md
git commit -m "docs: add CONTRIBUTING guide with setup, conventions, and PR workflow"
```

---

### Task 5: Final Verification

**Step 1: Verify all 4 files exist**

Run: `ls -la LICENSE README.md CHANGELOG.md CONTRIBUTING.md`
Expected: All 4 files present

**Step 2: Verify no broken links between docs**

- README links to CONTRIBUTING.md and LICENSE — verify filenames match
- CONTRIBUTING links to README.md#architecture — verify anchor exists

**Step 3: Verify workspace still builds**

Run: `cargo check --workspace`
Expected: Clean (docs don't affect builds, but sanity check)

**Step 4: Check git log**

Run: `git log --oneline -5`
Expected: 4 doc commits in order
