# SIGINT

```
 ███████╗██╗ ██████╗ ██╗███╗   ██╗████████╗
 ██╔════╝██║██╔════╝ ██║████╗  ██║╚══██╔══╝
 ███████╗██║██║  ███╗██║██╔██╗ ██║   ██║
 ╚════██║██║██║   ██║██║██║╚██╗██║   ██║
 ███████║██║╚██████╔╝██║██║ ╚████║   ██║
 ╚══════╝╚═╝ ╚═════╝ ╚═╝╚═╝  ╚═══╝   ╚═╝
```

**AI-Powered Penetration Testing Tool**

![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)
![Platform: Linux](https://img.shields.io/badge/Platform-Linux-green.svg)

---

## What is SIGINT?

SIGINT is a single-binary AI-powered penetration testing tool. It replaces
multi-container orchestration solutions (like PentAGI) with a local-first
design built on:

- **Ollama** — local LLM inference, no data leaves your machine
- **hakoniwa** — Linux namespace sandboxing for every tool invocation
- **SQLite** — embedded storage with FTS5 full-text search and vector embeddings

A six-role agent system coordinates 29 sandboxed security tools to execute
structured attack plans. Findings are mapped to MITRE ATT&CK techniques.
Results are surfaced through a terminal TUI or embedded web dashboard — no
external services required.

---

## Features

- **6-role agent system** — Orchestrator → Researcher → Strategist → Executor
  → Analyst → Reporter, each with a focused mandate and controlled tool access
- **29 sandboxed tools** across 8 categories: network scanning, web enumeration,
  vulnerability detection, service fingerprinting, authentication testing,
  post-exploitation, cloud/container security, and SDR/RF analysis
- **Structured attack plans** with MITRE ATT&CK technique mapping and
  step-level approval gating
- **Iterative convergence loops** — agents re-evaluate findings and escalate
  intelligently, with operator approval at each risk boundary
- **Dual interface** — terminal TUI for interactive sessions, embedded web
  dashboard for remote access and long-running engagements
- **Episode memory** — cross-engagement context recall; prior findings from the
  same target inform new scans
- **Report generation** — Executive, Detailed, and Technical reports in both
  HTML and Markdown, auto-generated at scan completion

---

## Quickstart

```bash
# Install from source
cargo install --path crates/sigint-cli

# Check your environment (tools, Ollama, sandbox)
sigint doctor

# Run a scan
sigint scan scanme.nmap.org

# Start the web UI
sigint serve
# Open http://localhost:3000

# Interactive AI chat
sigint chat
```

---

## Requirements

| Requirement | Notes |
|-------------|-------|
| **Rust 1.75+** | Required to build from source |
| **Ollama** | `ollama serve` must be running locally |
| **Linux** | User namespaces required (`sysctl kernel.unprivileged_userns_clone=1`) |
| **nmap, gobuster, nikto, nuclei, ...** | Optional — run `sigint doctor` to check |

The sandboxing layer uses Linux user namespaces and seccomp-bpf. This requires
an unprivileged namespace-capable kernel. Most modern distributions enable this
by default. If not:

```bash
sudo sysctl -w kernel.unprivileged_userns_clone=1
```

To persist across reboots, add to `/etc/sysctl.d/99-sigint.conf`.

---

## CLI Reference

```
sigint scan <target>          Multi-agent scan against a target
sigint scan <target> --memory With episodic recall from prior scans
sigint scan <target> --recon  With ReconEngine pre-step (ASM mapping)
sigint chat                   Interactive AI chat (no scan context)
sigint serve                  Start web UI on :3000
sigint doctor                 Check environment, tools, Ollama, sandbox
sigint sessions               List all scan sessions
sigint report <session-id>    Generate report for a completed scan
sigint diff <id-a> <id-b>     Compare findings between two sessions
sigint log <session-id>       View engagement audit log
sigint recon <target>         Run standalone recon (no agent scan)
sigint campaign run --file targets.json   Multi-target campaign
```

### Examples

```bash
# Scan with memory and recon enabled
sigint scan 10.0.0.1 --memory --recon

# Generate an HTML report
sigint report abc123 --format html --output report.html

# Compare two scans of the same target
sigint diff abc123 def456

# Campaign against multiple targets
sigint campaign run --file targets.json --concurrency 3
```

---

## Configuration

SIGINT reads configuration from `~/.config/sigint/config.toml`. Copy the
example configuration to get started:

```bash
mkdir -p ~/.config/sigint
cp config.example.toml ~/.config/sigint/config.toml
```

See `config.example.toml` in this repository for all available options with
documentation comments.

---

## Architecture

SIGINT is a 12-crate Rust workspace. Each crate has a single responsibility:

```
sigint-cli ─── sigint-agents ─── sigint-llm (Ollama/OpenAI)
    │              │
    ├── sigint-tui │── sigint-tools (29 tools)
    ├── sigint-web │── sigint-sandbox (hakoniwa)
    │              │── sigint-memory (episodic + semantic)
    ├── sigint-store (SQLite + FTS5)
    ├── sigint-report (MD/HTML)
    ├── sigint-recon (ASM engine)
    └── sigint-core (config, types, events)
```

| Crate | Responsibility |
|-------|---------------|
| `sigint-core` | Config loading, domain types, AppCore, event bus |
| `sigint-llm` | LLM provider trait, Ollama and OpenAI adapters, tool-calling support |
| `sigint-agents` | Agent trait, Orchestrator, 5 specialist roles, tool-call loop |
| `sigint-sandbox` | Linux namespace + seccomp-bpf isolation via hakoniwa |
| `sigint-store` | SQLite + FTS5 full-text search + vector embeddings |
| `sigint-tools` | Tool trait, 29 sandboxed wrappers, tool registry |
| `sigint-recon` | Attack surface mapping, service fingerprinting, change detection |
| `sigint-memory` | Episodic memory store, semantic search over prior findings |
| `sigint-tui` | Ratatui terminal interface, live agent output, approval prompts |
| `sigint-web` | Axum embedded server, REST API, WebSocket live updates |
| `sigint-report` | Markdown and HTML report generation |
| `sigint-cli` | Binary entry point, subcommand dispatch |

---

## Tool Catalog

| # | Tool | Category | Binary |
|---|------|----------|--------|
| 1 | `nmap_scan` | Network | `nmap` |
| 2 | `shell` | General | `bash` |
| 3 | `gobuster_scan` | Web Enumeration | `gobuster` |
| 4 | `nikto_scan` | Web Vulnerability | `nikto` |
| 5 | `nuclei_scan` | Vulnerability | `nuclei` |
| 6 | `feroxbuster_scan` | Web Enumeration | `feroxbuster` |
| 7 | `sqlmap_scan` | Web Vulnerability | `sqlmap` |
| 8 | `ffuf_scan` | Web Fuzzing | `ffuf` |
| 9 | `whatweb_scan` | Fingerprint | `whatweb` |
| 10 | `hydra_scan` | Auth Testing | `hydra` |
| 11 | `wpscan_scan` | Web Vulnerability | `wpscan` |
| 12 | `testssl_scan` | Fingerprint | `testssl.sh` |
| 13 | `hashcat_crack` | Auth Testing | `hashcat` |
| 14 | `masscan_scan` | Network | `masscan` |
| 15 | `tshark_capture` | Network | `tshark` |
| 16 | `responder_poison` | Auth Testing | `responder` |
| 17 | `msf_exploit` | Post-Exploitation | `msfconsole` |
| 18 | `linpeas_enum` | Post-Exploitation | `linpeas.sh` |
| 19 | `enum4linux_scan` | Fingerprint | `enum4linux-ng` |
| 20 | `trivy_scan` | Cloud/Container | `trivy` |
| 21 | `scout_suite_scan` | Cloud | `scout_suite` |
| 22 | `cloudsploit_scan` | Cloud | `cloudsploit` |
| 23 | `akaei_sweep` | SDR/RF | `akaei` |
| 24 | `akaei_scan` | SDR/RF | `akaei` |
| 25 | `akaei_decode` | SDR/RF | `akaei` |
| 26 | `akaei_analyze` | SDR/RF | `akaei` |
| 27 | `akaei_audit` | SDR/RF | `akaei` |
| 28 | `akaei_fingerprint` | SDR/RF | `akaei` |
| 29 | `akaei_freqdb` | SDR/RF | `akaei` |

---

## License

MIT — see [LICENSE](LICENSE)
