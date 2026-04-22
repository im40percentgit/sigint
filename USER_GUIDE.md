# SIGINT User Guide

SIGINT is an AI-powered penetration testing tool that orchestrates six specialist
agents — researcher, strategist, executor, analyst, reporter, and optionally an RF
recon agent — to run a full engagement against a target, entirely on your local machine.

---

## Getting Started

### 1. Install Ollama

SIGINT uses Ollama to run LLMs locally. No GPU required for smaller models.

```bash
# Linux / macOS
curl -fsSL https://ollama.com/install.sh | sh

# Start the daemon (if not auto-started)
ollama serve
```

Download a capable model. `llama3.2` is a good default:

```bash
ollama pull llama3.2
```

For better reasoning on complex targets, consider a larger model:

```bash
ollama pull llama3.1:70b   # requires ~40 GB RAM
ollama pull mistral:7b     # lighter alternative
```

### 2. Build and install sigint

```bash
git clone https://github.com/your-org/sigint
cd sigint
cargo build --release
sudo cp target/release/sigint /usr/local/bin/
```

### 3. Create a configuration file

```bash
mkdir -p ~/.config/sigint
cp config.example.toml ~/.config/sigint/config.toml
```

Edit `~/.config/sigint/config.toml` to set your preferred model and any other
options. See the Configuration Reference section below.

### 4. Verify your environment

```bash
sigint doctor
```

This checks: config loaded, Ollama reachable, model available, all tool binaries
on PATH, sandbox prerequisites (`newuidmap`, `pasta`), and database accessible.
Install any missing tools using the hints it prints.

---

## Your First Scan

```bash
sigint scan scanme.nmap.org --no-tui
```

`--no-tui` prints events to stdout. Omit it (or use `--tui`) for the full
terminal interface.

### What happens

1. **AppCore loads** — config and SQLite database are opened; a session UUID is minted.
2. **Researcher** runs OSINT and initial reconnaissance: DNS lookups, whois,
   service detection via nmap. Findings are streamed as events.
3. **Strategist** analyses the recon results and produces a structured attack plan
   aligned to MITRE ATT&CK tactics.
4. **Executor** runs the planned tools (nmap, nikto, nuclei, gobuster, etc.)
   inside Linux namespace sandboxes. Each tool's stdout is capped at 1 MB by
   default to avoid context overflow.
5. **Analyst** correlates tool output into structured findings
   (title / severity / evidence / remediation). Each finding is written to the
   database and emitted as a `FindingCreated` event.
6. **Reporter** synthesises all findings into a penetration test report and saves
   it to the session.

At the end of the scan, the session ID is printed. Use it to generate a report:

```bash
sigint report <session-id>
```

---

## Using the TUI

When a terminal is detected, the TUI launches automatically. Force it on or off:

```bash
sigint scan target.example.com --tui        # force TUI on
sigint scan target.example.com --no-tui     # force TUI off
```

### Panel layout

```
┌─────────────────────────────────────────────────────────────┐
│  Agent status bar  [Researcher] [Strategist] [Executor]...  │
├──────────────────────────────┬──────────────────────────────┤
│                              │                              │
│   Chat / reasoning panel     │   Tool output panel          │
│   (agent thinking tokens,    │   (stdout from nmap,         │
│    messages, findings)       │    gobuster, etc.)           │
│                              │                              │
├──────────────────────────────┴──────────────────────────────┤
│  Findings table  [Critical] [High] [Medium] [Low] [Info]    │
├─────────────────────────────────────────────────────────────┤
│  > input bar                                               │
└─────────────────────────────────────────────────────────────┘
```

### Navigation

- **Tab** — cycle focus between panels
- **Arrow keys** — scroll within the focused panel
- **Enter** — submit text in the input bar
- **q** or **Ctrl-C** — quit

### Approval prompts

When the agent attempts a medium- or high-risk tool call and
`auto_approve = "low"` (the default), the TUI pauses and displays a prompt:

```
[APPROVAL REQUIRED]
Tool: nmap_scan
Args: {"target": "10.0.0.0/8", "args": "-sV -O"}
Risk: High

Approve? [Y/N]
```

Type `Y` and press Enter to allow, or `N` to deny. The agent receives the
outcome and continues.

### Chat panel

Type commands or questions in the input bar during a scan. The agent can respond
to follow-up instructions like:
- "focus on port 443"
- "generate the report now"
- "look for SQL injection vulnerabilities"

---

## Using the Web UI

```bash
sigint serve
# or bind to a specific address:
sigint serve --bind 127.0.0.1:8080
```

Open `http://localhost:8080` in your browser.

### Dashboard overview

The dashboard shows recent sessions with target name, scan date, finding counts
by severity, and a status badge (running / completed / failed).

### Starting a new scan

Click **New Scan**, enter a target (hostname, IP, or CIDR), optionally set ports
and a goal keyword, then click **Start**. The scan begins immediately and the
page transitions to the live view.

### Watching live scan progress

The **Pipeline** panel shows each agent's status in real time:

```
[Researcher]  done      [Strategist]  done
[Executor]    running   [Analyst]     waiting
[Reporter]    waiting
```

The **Event log** below streams every tool execution, output snippet, and
finding as it arrives over the WebSocket connection. No page refresh needed.

### Reviewing findings

The **Findings** tab lists all findings for the current session, sortable by
severity. Click any finding to expand its full description, evidence, and
remediation advice.

### Generating reports

The **Report** tab offers three templates:

| Template | Audience | Content |
|----------|----------|---------|
| Executive | Board / management | Severity summary, risk rating, top recommendations |
| Detailed | Security team | All findings with descriptions, affected assets, remediation |
| Technical | Pentesters | Full findings + raw tool evidence + service inventory |

Select a template, choose Markdown or HTML, and click **Download**.

### Comparing scans (diff)

Navigate to **Sessions**, select two sessions for the same target, and click
**Compare**. The diff view shows:

- **New** findings (appeared in the later scan, not in the earlier)
- **Fixed** findings (present in the earlier scan, gone now)
- **Unchanged** findings (present in both)

This is useful for tracking remediation progress between engagements.

---

## Advanced Features

### Iterative convergence (`--max-cycles`)

By default, the Strategist → Executor → Analyst loop runs once. Increasing
`--max-cycles` lets SIGINT iterate until no new findings are discovered:

```bash
sigint scan target.example.com --max-cycles 5
```

Each cycle the Strategist plans based on what the Analyst found in the
previous cycle, potentially uncovering deeper vulnerabilities.

### Goal-driven convergence (`--goal`)

Stop as soon as a specific finding is confirmed:

```bash
sigint scan target.example.com --max-cycles 5 --goal "sql injection"
```

The loop exits as soon as any finding title or description contains the goal
string (case-insensitive).

### Approval gates (`--approval-gates`)

With `--max-cycles > 1`, the Strategist may recommend escalating from
reconnaissance to exploitation. The `--approval-gates` flag pauses the scan
and prompts the operator before any tier transition:

```bash
sigint scan target.example.com --max-cycles 3 --approval-gates
```

Tier order: `Recon` → `Exploitation` → `PostExploitation`. Denying an
escalation skips the Executor for that cycle and attempts convergence with
the current finding set.

### Episodic memory (`--memory`)

SIGINT can recall findings and strategies from prior scans of the same target:

```bash
sigint scan target.example.com --memory
```

Before the Researcher runs, relevant prior session summaries and findings are
injected into the agent prompts, enabling cumulative knowledge across engagements.

Memory can also be enabled globally in config:

```toml
[agent]
memory = true
```

### Attack surface pre-scan (`--recon`)

Run the `ReconEngine` before the agent pipeline to build a comprehensive asset
inventory first:

```bash
sigint scan target.example.com --recon
```

The engine runs five discovery modules in sequence: DNS, port, web, certificate
transparency, and OSINT. Discovered assets are stored in the database and fed
into the Strategist prompt, giving it a richer picture of the attack surface.

### Standalone recon

Run the recon engine independently with `sigint recon`:

```bash
sigint recon example.com
sigint recon example.com --modules dns,cert   # specific modules only
sigint recon example.com --watch              # re-scan every 5 minutes
```

`--watch` mode emits `AssetChanged` events when previously discovered services
change (new ports, new certificates, service version changes).

### Campaign mode

Scan multiple targets from a JSON file:

```bash
sigint campaign run --file targets.json
```

`targets.json` format:

```json
[
  { "target": "app1.example.com" },
  { "target": "app2.example.com", "goal": "find RCE" },
  { "target": "192.168.1.0/24", "max_cycles": 3 }
]
```

Check campaign status:

```bash
sigint campaign status <campaign-uuid-prefix>
```

### OpenAI / cloud providers

Switch to an OpenAI-compatible API by setting the provider in config:

```toml
[llm]
provider = "openai"
model = "gpt-4o"
base_url = "https://api.openai.com"
api_key = "sk-..."
```

Or via the `SIGINT_API_KEY` environment variable. Any OpenAI-compatible
endpoint works (Anthropic via proxy, local OpenAI-compatible servers, etc.).

---

## Tool Dependencies

Install the following tools to enable their corresponding capabilities.
`sigint doctor` reports which are missing.

| Tool | Install command | Category |
|------|----------------|----------|
| `nmap` | `sudo apt install nmap` | Network scanning |
| `masscan` | `sudo apt install masscan` | Fast port scanning |
| `gobuster` | `sudo apt install gobuster` | Directory brute-force |
| `feroxbuster` | `cargo install feroxbuster` | Recursive directory brute-force |
| `ffuf` | `go install github.com/ffuf/ffuf/v2@latest` | HTTP fuzzing |
| `nikto` | `sudo apt install nikto` | Web vulnerability scanning |
| `nuclei` | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` | Template-based scanning |
| `whatweb` | `sudo apt install whatweb` | Web technology fingerprinting |
| `wpscan` | `gem install wpscan` | WordPress vulnerability scanning |
| `sqlmap` | `sudo apt install sqlmap` | SQL injection testing |
| `hydra` | `sudo apt install hydra` | Credential brute-force |
| `testssl` | `sudo apt install testssl.sh` | TLS/SSL analysis |
| `hashcat` | `sudo apt install hashcat` | Password cracking |
| `tshark` | `sudo apt install tshark` | Network traffic capture |
| `responder` | `sudo apt install responder` | LLMNR/NBT-NS poisoning |
| `msfconsole` | `sudo apt install metasploit-framework` | Exploitation framework |
| `linpeas.sh` | `wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh` | Linux privilege escalation enum |
| `enum4linux-ng` | `pip install enum4linux-ng` | Windows/Samba enumeration |
| `trivy` | `sudo apt install trivy` | Container / cloud vulnerability scanning |
| `scout` | `pip install scoutsuite` | Multi-cloud security auditing |
| `cloudsploit` | `npm install -g cloudsploit` | Cloud configuration analysis |
| `dig` | `sudo apt install dnsutils` | DNS resolution |
| `whois` | `sudo apt install whois` | Domain registration lookup |
| `curl` | `sudo apt install curl` | HTTP requests |
| `akaei` | Build from source + add to PATH | SDR / HackRF radio recon |

### Sandbox prerequisites

The sandbox requires two user-space binaries for unprivileged namespace isolation:

| Binary | Install command | Purpose |
|--------|----------------|---------|
| `newuidmap` | `sudo apt install uidmap` | User namespace UID mapping |
| `pasta` | `sudo apt install passt` | User-space networking for sandboxed tools |

---

## Configuration Reference

All fields in `~/.config/sigint/config.toml`. Every field is optional and
defaults to the value shown.

```toml
[llm]
# Provider: "ollama" (default), "openai", "anthropic"
provider = "ollama"

# Model name passed to the provider
model = "llama3.2"

# Provider API base URL
base_url = "http://localhost:11434"

# Sampling temperature (0.0 = deterministic, 1.0 = creative)
temperature = 0.7

# Context window in tokens (0 = provider default)
context_window = 8192

# API key for cloud providers
# Can also be set via SIGINT_API_KEY environment variable
# api_key = "sk-..."


[store]
# SQLite database path (~ is expanded to $HOME)
db_path = "~/.local/share/sigint/sigint.db"


[log]
# Tracing filter string (SIGINT_LOG env var overrides this)
level = "sigint=info,warn"


[agent]
# Auto-approve tool calls up to this risk level without operator prompt.
# Values: "none" | "low" | "medium" | "all"
# "low" auto-approves safe read-only tools (nmap, whatweb, dig).
# "medium" also auto-approves active scanning (nikto, nuclei, gobuster).
# "all" runs everything without prompting (use with caution).
auto_approve = "low"

# Seconds to wait for operator approval before timing out (and denying).
approval_timeout = 300

# Enable episodic memory by default (equivalent to --memory flag).
memory = false

# Enable ReconEngine pre-step by default (equivalent to --recon flag).
recon = false


[tools]
# Global output cap: maximum bytes captured from any single tool's stdout+stderr.
# Output beyond this limit is truncated and a TruncationInfo is recorded.
default_output_cap = 1048576   # 1 MB

# Per-tool overrides. Key is the tool name as reported by `sigint doctor`.
# Useful for noisy tools like nuclei or long-running tools like masscan.
#
# [tools.overrides.nuclei]
# output_cap = 2097152   # 2 MB
# timeout = 900          # 15 minutes
#
# [tools.overrides.nmap]
# output_cap = 4194304   # 4 MB
# timeout = 600
```

### Environment variables

| Variable | Purpose |
|----------|---------|
| `SIGINT_LOG` | Override log filter (e.g. `sigint=debug,warn`) |
| `SIGINT_API_KEY` | API key for cloud LLM providers |

---

## Report Formats

SIGINT generates reports in two formats (Markdown and HTML) across three templates:

### Executive

Intended for management or board presentations. Contains:
- Engagement metadata (target, date, scan count)
- Overall risk rating
- Finding count by severity (Critical / High / Medium / Low / Info)
- Top recommendations

### Detailed

Intended for the security team conducting remediation. Contains:
- All Executive content
- Full finding list with title, severity, affected asset, description, and
  recommended remediation
- Asset inventory table (hosts / services discovered)

### Technical

Intended for penetration testers reviewing raw evidence. Contains:
- All Detailed content
- Raw tool evidence for each finding (nmap output, exploit proof, etc.)
- Full service inventory with version information
- Scan history (which tools ran, with what arguments)

Generate from the CLI:

```bash
# Markdown to stdout
sigint report <session-id>

# HTML to file
sigint report <session-id> --format html --output report.html

# Specific template
sigint report <session-id> --template executive
sigint report <session-id> --template technical
```

---

## Troubleshooting

### "Cannot reach Ollama" / Ollama unreachable

```
  ✗ Ollama reachable (http://localhost:11434) — Cannot reach http://localhost:11434 — is Ollama running?
```

Start the Ollama daemon:

```bash
ollama serve
```

If Ollama is running on a different address, update `base_url` in `config.toml`.

### "Model not found" / model not available

```
  ✗ Model available (llama3.2) — Model 'llama3.2' not found — run: ollama pull llama3.2
```

Pull the model:

```bash
ollama pull llama3.2
```

### "User namespace not available" / sandbox fails on Linux

Some Linux distributions disable unprivileged user namespaces by default:

```bash
# Check current setting
sysctl kernel.unprivileged_userns_clone

# Enable (requires root, persists until reboot)
sudo sysctl kernel.unprivileged_userns_clone=1

# Enable permanently
echo 'kernel.unprivileged_userns_clone=1' | sudo tee /etc/sysctl.d/99-userns.conf
sudo sysctl -p /etc/sysctl.d/99-userns.conf
```

On Ubuntu 24.04+ the equivalent setting is:

```bash
sudo sysctl kernel.apparmor_restrict_unprivileged_userns=0
```

### "Tool not found" / missing binary

```bash
sigint doctor    # see which tools are missing and their install commands
```

Install the missing tool using the hint printed by doctor.

### Sandbox failures — pasta / newuidmap missing

```
  ✗ Sandbox: pasta not found — install: sudo apt install passt
  ✗ Sandbox: newuidmap not found — install: sudo apt install uidmap
```

Install the missing packages:

```bash
sudo apt install passt uidmap
```

### TUI renders incorrectly or is blank

- Ensure your terminal supports at least 80 columns and a 256-colour mode.
- If log output is corrupting the display, check that `--no-tui` was not
  accidentally set while SIGINT_LOG is verbose.
- Tracing output is redirected to `~/.local/share/sigint/sigint.log` when
  the TUI is active. Check that file for errors.

### Scan hangs / no output

- Check `sigint doctor` to verify Ollama and the model are available.
- Run with `--no-tui -v` to see debug output in the terminal.
- Check `~/.local/share/sigint/sigint.log` for tracing errors.
- If an approval request is pending, the scan waits for operator input. The
  TUI displays the prompt; in `--no-tui` mode, watch for "APPROVAL REQUIRED"
  lines on stdout.

### Database migration errors

The database is migrated automatically on first run. If you see a migration
error after upgrading, the safest fix is to delete the database and let it
be recreated (this loses scan history):

```bash
rm ~/.local/share/sigint/sigint.db
sigint doctor    # verify database OK
```

---

## Session Management

List all stored sessions:

```bash
sigint sessions list
```

Export a session as JSON:

```bash
sigint sessions export <session-id>
```

Delete a session and all its findings:

```bash
sigint sessions delete <session-id>
```

### Scan diff from the CLI

```bash
sigint diff <session-a-id> <session-b-id>
```

Prints new, fixed, and unchanged findings between two sessions.

### Engagement log

```bash
sigint log <session-id>
```

Prints the chronological engagement log: every agent message, tool call, and
finding in the order they occurred.

---

## Fine-tuning Workflow

SIGINT supports an optional closed-loop fine-tuning pipeline that adapts the LLM
to your engagement style and tool-calling patterns. The pipeline is entirely
opt-in: session data is never harvested automatically.

**Privacy notice:** Training data is derived from your engagement logs. These
logs may contain sensitive target data (IP addresses, hostnames, credentials,
tool output). Review all harvested data before fine-tuning or sharing the
resulting adapter. You are responsible for ensuring you have the right to use
the data.

### Step 1 — Harvest

Mark a session as approved for fine-tuning:

```bash
sigint train harvest <session_id>
```

This sets `trainable=1` on the session. Only harvested sessions are included in
exported training data. Run this once per session you wish to include.

### Step 2 — Export

Extract training data from all harvested sessions and split 80/20:

```bash
sigint train export
```

Writes `train.jsonl` and `test.jsonl` to `~/.local/share/sigint/training/`.
The minimum required examples threshold (default: 50) is enforced at export
time. Add more harvested sessions if you fall short.

### Step 3 — Fine-tune

Run your configured trainer with the exported data:

```bash
sigint train finetune --base <base-model-tag> --output <adapter-name>
```

Requires `[train].finetune_command` in `config.toml`. The command receives
training data via environment variables (`SIGINT_TRAIN_JSONL`, `SIGINT_TEST_JSONL`,
`SIGINT_BASE_MODEL`, `SIGINT_OUTPUT_PATH`). See `config.example.toml` for
examples using unsloth, axolotl, or MLX.

### Step 4 — Evaluate

Compare the fine-tuned candidate against the base model on the held-out test set:

```bash
sigint train evaluate --base <base-tag> --candidate <new-tag>
```

Runs live inference on both models and reports tool-selection accuracy and
argument match rate. Saves `last_eval.json` to the training directory for the
promote gate.

### Step 5 — Promote

Promote the candidate model to active use:

```bash
sigint model promote <tag>
```

Atomically rewrites `config.toml` to use the new model. Requires at least
`min_eval_examples` (default: 50) in `last_eval.json`. Use `--force` to
override the gate. A backup of the previous config is saved as `config.toml.bak`,
and a `promotion.log` audit entry is appended.

### Step 6 — Rollback

Revert to the previous model if the promoted model underperforms:

```bash
sigint model rollback
```

Reads the last entry from `promotion.log` and restores the previous provider
and model in `config.toml`. A rollback entry is appended to the log for
auditability.
