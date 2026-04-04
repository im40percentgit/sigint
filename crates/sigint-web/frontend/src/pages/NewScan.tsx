/**
 * NewScan — form page for launching a new SIGINT scan session.
 *
 * Collects target and configuration parameters then POSTs to the /api/scan
 * endpoint via api.scans.start(). On success, navigates to the live scan view
 * at #/scan/{id}. Non-fatal validation is handled inline; network errors are
 * displayed above the submit button.
 *
 * The scan parameters that map to the agent configuration (model,
 * max_iterations, max_cycles, goal, memory, recon, approval_gates) are passed
 * through StartScanParams.options as string key-value pairs so the backend
 * can forward them to the orchestrator without a schema change.
 *
 * @decision DEC-WEB-031
 * @title NewScan encodes agent config fields into StartScanParams.options map
 * @status accepted
 * @rationale StartScanParams only exposes target/tool/session_id directly.
 * Funnelling extended config through the options map avoids a breaking API
 * change while still surfacing all meaningful scan settings to the user.
 * The backend reads these keys to configure the orchestrator run.
 */

import { h } from "preact";
import { useState, useEffect } from "preact/hooks";
import { api } from "../api";
import type { ModelInfo } from "../types";

// ── Component ──────────────────────────────────────────────────────────────

export function NewScan() {
  // Required
  const [target, setTarget] = useState("");

  // Optional extras
  const [ports, setPorts] = useState("");
  const [model, setModel] = useState("");
  const [availableModels, setAvailableModels] = useState<ModelInfo[]>([]);

  // Fetch available embedded models on mount (best-effort — fails silently)
  useEffect(() => {
    api.models
      .list()
      .then((models) => setAvailableModels(models))
      .catch(() => setAvailableModels([]));
  }, []);
  const [maxIterations, setMaxIterations] = useState(10);
  const [maxCycles, setMaxCycles] = useState(1);
  const [goal, setGoal] = useState("");
  const [memory, setMemory] = useState(false);
  const [recon, setRecon] = useState(false);
  const [approvalGates, setApprovalGates] = useState(false);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: Event) {
    e.preventDefault();
    if (!target.trim()) return;

    setLoading(true);
    setError(null);

    // Build options map from optional fields
    const options: Record<string, string> = {};
    if (ports.trim()) options["ports"] = ports.trim();
    if (model.trim()) options["model"] = model.trim();
    options["max_iterations"] = String(maxIterations);
    options["max_cycles"] = String(maxCycles);
    if (goal.trim()) options["goal"] = goal.trim();
    options["memory"] = String(memory);
    options["recon"] = String(recon);
    options["approval_gates"] = String(approvalGates);

    try {
      const scan = await api.scans.start({
        target: target.trim(),
        tool: "orchestrator",
        options,
      });
      location.hash = `#/scan/${scan.id}`;
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
      setLoading(false);
    }
  }

  return (
    <div class="page" style={{ maxWidth: "600px" }}>
      <div class="page-title">New Scan</div>

      <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: "0" }}>
        {/* Target — required */}
        <div class="form-group">
          <label for="target">Target *</label>
          <input
            id="target"
            type="text"
            value={target}
            onInput={(e) => setTarget((e.target as HTMLInputElement).value)}
            placeholder="scanme.nmap.org"
            required
            style={{ width: "100%" }}
          />
        </div>

        {/* Ports */}
        <div class="form-group">
          <label for="ports">Ports</label>
          <input
            id="ports"
            type="text"
            value={ports}
            onInput={(e) => setPorts((e.target as HTMLInputElement).value)}
            placeholder="80,443"
            style={{ width: "100%" }}
          />
        </div>

        {/* Model — dropdown when embedded models available, text input otherwise */}
        <div class="form-group">
          <label for="model">Model</label>
          {availableModels.length > 0 ? (
            <select
              id="model"
              value={model}
              onChange={(e) => setModel((e.target as HTMLSelectElement).value)}
              style={{ width: "100%" }}
            >
              <option value="">-- use server default --</option>
              {availableModels.map((m) => (
                <option key={m.filename} value={m.filename}>
                  {m.name} ({m.quantization ?? "?"},{" "}
                  {m.context_length ? `${m.context_length} ctx` : "?"})
                </option>
              ))}
            </select>
          ) : (
            <input
              id="model"
              type="text"
              value={model}
              onInput={(e) => setModel((e.target as HTMLInputElement).value)}
              placeholder="llama3.2"
              style={{ width: "100%" }}
            />
          )}
        </div>

        {/* Iteration / Cycle counts in a 2-col row */}
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
          <div class="form-group">
            <label for="max-iterations">Max Iterations</label>
            <input
              id="max-iterations"
              type="number"
              min={1}
              max={200}
              value={maxIterations}
              onInput={(e) =>
                setMaxIterations(Number((e.target as HTMLInputElement).value))
              }
              style={{ width: "100%" }}
            />
          </div>
          <div class="form-group">
            <label for="max-cycles">Max Cycles</label>
            <input
              id="max-cycles"
              type="number"
              min={1}
              max={20}
              value={maxCycles}
              onInput={(e) =>
                setMaxCycles(Number((e.target as HTMLInputElement).value))
              }
              style={{ width: "100%" }}
            />
          </div>
        </div>

        {/* Goal */}
        <div class="form-group">
          <label for="goal">Goal</label>
          <input
            id="goal"
            type="text"
            value={goal}
            onInput={(e) => setGoal((e.target as HTMLInputElement).value)}
            placeholder="Find all open ports and running services"
            style={{ width: "100%" }}
          />
        </div>

        {/* Checkboxes */}
        <div
          style={{
            display: "flex",
            gap: "24px",
            marginBottom: "16px",
            flexWrap: "wrap",
          }}
        >
          <label style={{ display: "flex", alignItems: "center", gap: "6px", cursor: "pointer" }}>
            <input
              type="checkbox"
              checked={memory}
              onChange={(e) => setMemory((e.target as HTMLInputElement).checked)}
            />
            Memory
          </label>
          <label style={{ display: "flex", alignItems: "center", gap: "6px", cursor: "pointer" }}>
            <input
              type="checkbox"
              checked={recon}
              onChange={(e) => setRecon((e.target as HTMLInputElement).checked)}
            />
            Recon
          </label>
          <label style={{ display: "flex", alignItems: "center", gap: "6px", cursor: "pointer" }}>
            <input
              type="checkbox"
              checked={approvalGates}
              onChange={(e) =>
                setApprovalGates((e.target as HTMLInputElement).checked)
              }
            />
            Approval Gates
          </label>
        </div>

        {/* Error display */}
        {error && (
          <div
            style={{
              color: "var(--danger)",
              background: "rgba(248,81,73,0.08)",
              border: "1px solid var(--danger)",
              borderRadius: "var(--radius-sm)",
              padding: "8px 12px",
              marginBottom: "12px",
              fontSize: "12px",
            }}
          >
            {error}
          </div>
        )}

        <button
          type="submit"
          class="btn btn-primary"
          disabled={loading || !target.trim()}
          style={{ alignSelf: "flex-start" }}
        >
          {loading ? "Starting…" : "Start Scan"}
        </button>
      </form>
    </div>
  );
}
