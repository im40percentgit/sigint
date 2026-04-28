/**
 * Train — operator workbench page for the fine-tune pipeline.
 *
 * Layout: four sequential cards + a jobs mini-table.
 *   1. Stats card      — dataset counts, refresh button
 *   2. Export card     — write JSONL files, show paths
 *   3. Fine-tune card  — base model, output name, start job, live WS status
 *   4. Evaluate card   — link to /train/evaluate
 *   5. Jobs table      — last 5 jobs, click → /train/jobs/<id>
 *
 * WebSocket: subscribes to wsManager singleton (DEC-WEB-023).
 * Handles TrainingJobStarted, TrainingJobProgress, TrainingJobCompleted,
 * TrainingJobFailed events to drive the fine-tune card state machine.
 *
 * Fine-tune card state machine:
 *   idle → starting (POST sent)
 *      → running (TrainingJobStarted received, job_id matches)
 *      → done    (TrainingJobCompleted)
 *      → failed  (TrainingJobFailed)
 * Any error from the POST itself transitions directly to failed.
 *
 * @decision DEC-P26-T6-001
 * @title Train page uses local useState per-card; WS events drive finetune card only
 * @status accepted
 * @rationale Each card has independent loading/error state. The fine-tune card
 * is the only one with async live updates; the WS subscription is scoped to
 * the component so it unsubscribes on unmount, preventing stale closures from
 * accumulating in wsManager's handler set.
 *
 * @decision DEC-P26-T6-002
 * @title Job-detail drawer with live stdout updates via WS subscription
 * @status accepted
 * @rationale Clicking a Jobs-table row opens a slide-in JobDetailDrawer.
 * The drawer shows the full JobRecord (id, model, status, duration, exit code,
 * stdout_tail). For running jobs it subscribes to wsManager for
 * TrainingJobProgress events and filters by job_id, updating the displayed
 * tail in real time without polling. The drawer unsubscribes on unmount.
 * Backend: stdout_tail is now stored on JobRecord (Option<String>, populated
 * by run_finetune_streaming; None for CLI-initiated jobs that use
 * Stdio::inherit). See JobDetailDrawer.tsx for the full decision rationale.
 */

import { h } from "preact";
import { useState, useEffect } from "preact/hooks";
import { api } from "../api";
import { wsManager } from "../ws";
import type {
  TrainStats,
  ExportResult,
  TrainingJob,
  ModelInfo,
  WsEvent,
} from "../types";
import { DataTable } from "../components/DataTable";
import type { Column } from "../components/DataTable";
import { JobDetailDrawer } from "../components/JobDetailDrawer";

// ── Constants ──────────────────────────────────────────────────────────────

/** Regex used server-side and mirrored client-side for output_name validation. */
const OUTPUT_NAME_RE = /^[a-zA-Z0-9_.\-]{1,64}$/;

// ── Helpers ────────────────────────────────────────────────────────────────

function relativeTime(iso: string): string {
  const diffMs = Date.now() - new Date(iso).getTime();
  const secs = Math.floor(diffMs / 1000);
  if (secs < 60) return `${secs}s ago`;
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function durationLabel(job: TrainingJob): string {
  if (!job.finished_at) return "—";
  const start = new Date(job.started_at).getTime();
  const end = new Date(job.finished_at).getTime();
  const secs = Math.round((end - start) / 1000);
  if (secs < 60) return `${secs}s`;
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  return `${m}m ${s}s`;
}

function jobStatusColor(status: TrainingJob["status"]): string {
  switch (status.status) {
    case "Running": return "var(--accent)";
    case "Success": return "var(--success)";
    case "Failed":  return "var(--danger)";
    default:        return "var(--text-secondary)";
  }
}

// ── InlineError ────────────────────────────────────────────────────────────

function InlineError({ msg }: { msg: string }) {
  return (
    <div style={{
      color: "var(--danger)",
      background: "rgba(248,81,73,0.08)",
      border: "1px solid var(--danger)",
      borderRadius: "var(--radius-sm)",
      padding: "8px 12px",
      marginTop: "10px",
      fontSize: "12px",
    }}>
      {msg}
    </div>
  );
}

// ── StatsCard ──────────────────────────────────────────────────────────────

function StatsCard() {
  const [stats, setStats] = useState<TrainStats | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function load() {
    setLoading(true);
    setError(null);
    api.train
      .stats()
      .then(s => {
        setStats(s);
        setLoading(false);
      })
      .catch((e: Error) => {
        setError(e.message);
        setLoading(false);
      });
  }

  useEffect(() => { load(); }, []);

  return (
    <div class="card" style={{ marginBottom: "16px" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "12px" }}>
        <div class="card-title" style={{ marginBottom: 0 }}>Dataset Stats</div>
        <button class="btn btn-sm" onClick={load} disabled={loading}>
          {loading ? "Loading…" : "Refresh"}
        </button>
      </div>

      {error && <InlineError msg={error} />}

      {stats && (
        <div style={{ display: "flex", gap: "24px", flexWrap: "wrap" }}>
          {/* Summary numbers */}
          <table style={{ borderCollapse: "collapse", fontSize: "12px" }}>
            <tbody>
              <tr>
                <td style={tdLabel}>Total examples</td>
                <td style={tdValue}>{stats.total_examples}</td>
              </tr>
              <tr>
                <td style={tdLabel}>Total sessions</td>
                <td style={tdValue}>{stats.total_sessions}</td>
              </tr>
              <tr>
                <td style={tdLabel}>Trainable sessions</td>
                <td style={tdValue}>{stats.trainable_session_count}</td>
              </tr>
            </tbody>
          </table>

          {/* Per-agent */}
          {Object.keys(stats.examples_per_agent).length > 0 && (
            <div>
              <div style={{ fontSize: "11px", fontWeight: 600, textTransform: "uppercase", color: "var(--text-secondary)", marginBottom: "6px" }}>
                By Agent
              </div>
              <table style={{ borderCollapse: "collapse", fontSize: "12px" }}>
                <tbody>
                  {Object.entries(stats.examples_per_agent).map(([agent, count]) => (
                    <tr key={agent}>
                      <td style={tdLabel}>{agent}</td>
                      <td style={tdValue}>{count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* Per-tool */}
          {Object.keys(stats.examples_per_tool).length > 0 && (
            <div>
              <div style={{ fontSize: "11px", fontWeight: 600, textTransform: "uppercase", color: "var(--text-secondary)", marginBottom: "6px" }}>
                By Tool
              </div>
              <table style={{ borderCollapse: "collapse", fontSize: "12px" }}>
                <tbody>
                  {Object.entries(stats.examples_per_tool).map(([tool, count]) => (
                    <tr key={tool}>
                      <td style={tdLabel}>{tool}</td>
                      <td style={tdValue}>{count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {!stats && !loading && !error && (
        <div style={{ color: "var(--text-secondary)", fontSize: "12px" }}>No data yet.</div>
      )}
    </div>
  );
}

const tdLabel: h.JSX.CSSProperties = {
  paddingRight: "16px",
  paddingBottom: "4px",
  color: "var(--text-secondary)",
};

const tdValue: h.JSX.CSSProperties = {
  fontWeight: 600,
  color: "var(--text)",
  paddingBottom: "4px",
};

// ── ExportCard ─────────────────────────────────────────────────────────────

function ExportCard() {
  const [result, setResult] = useState<ExportResult | null>(null);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function doExport() {
    setRunning(true);
    setError(null);
    api.train
      .export()
      .then(r => {
        setResult(r);
        setRunning(false);
      })
      .catch((e: Error) => {
        setError(e.message);
        setRunning(false);
      });
  }

  return (
    <div class="card" style={{ marginBottom: "16px" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "12px" }}>
        <div class="card-title" style={{ marginBottom: 0 }}>Export Dataset</div>
        <button class="btn btn-primary" onClick={doExport} disabled={running}>
          {running ? "Exporting…" : "Export now"}
        </button>
      </div>

      {error && <InlineError msg={error} />}

      {result && (
        <div style={{ fontSize: "12px" }}>
          <table style={{ borderCollapse: "collapse" }}>
            <tbody>
              <tr>
                <td style={tdLabel}>Train examples</td>
                <td style={tdValue}>{result.train_count}</td>
              </tr>
              <tr>
                <td style={tdLabel}>Test examples</td>
                <td style={tdValue}>{result.test_count}</td>
              </tr>
              <tr>
                <td style={tdLabel}>Train file</td>
                <td style={{ ...tdValue, fontFamily: "var(--font-mono)", fontSize: "11px" }}>
                  {result.train_path}
                </td>
              </tr>
              <tr>
                <td style={tdLabel}>Test file</td>
                <td style={{ ...tdValue, fontFamily: "var(--font-mono)", fontSize: "11px" }}>
                  {result.test_path}
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      )}

      {!result && !running && !error && (
        <div style={{ color: "var(--text-secondary)", fontSize: "12px" }}>
          Click "Export now" to write JSONL training files.
        </div>
      )}
    </div>
  );
}

// ── FinetuneCard ───────────────────────────────────────────────────────────

type FtStatus =
  | { kind: "idle" }
  | { kind: "starting" }
  | { kind: "running"; jobId: string; startedAt: number; lastUpdate: number }
  | { kind: "done"; jobId: string; exitCode: number; durationSecs: number }
  | { kind: "failed"; jobId: string | null; error: string };

function FinetuneCard({ onJobStarted }: { onJobStarted: () => void }) {
  const [models, setModels] = useState<ModelInfo[]>([]);
  const [baseModel, setBaseModel] = useState("");
  const [outputName, setOutputName] = useState("");
  const [advancedOpen, setAdvancedOpen] = useState(false);
  const [advancedJson, setAdvancedJson] = useState("");
  const [status, setStatus] = useState<FtStatus>({ kind: "idle" });
  const [formError, setFormError] = useState<string | null>(null);
  const [elapsed, setElapsed] = useState(0);

  // Fetch models list for dropdown
  useEffect(() => {
    api.models.list().then(setModels).catch(() => { /* fallback to freetext */ });
  }, []);

  // Elapsed timer while running
  useEffect(() => {
    if (status.kind !== "running") return;
    const start = status.startedAt;
    const id = setInterval(() => {
      setElapsed(Math.floor((Date.now() - start) / 1000));
    }, 1000);
    return () => clearInterval(id);
  }, [status.kind]);

  // WS subscription — drive status machine
  useEffect(() => {
    const unsub = wsManager.subscribe((event: WsEvent) => {
      switch (event.type) {
        case "training_job_started":
          setStatus(prev => {
            if (prev.kind !== "running") return prev;
            // Already transitioned by POST response — just update jobId if needed
            return { ...prev, jobId: event.data.job_id };
          });
          break;

        case "training_job_progress":
          setStatus(prev => {
            if (prev.kind !== "running") return prev;
            if (prev.jobId !== event.data.job_id) return prev;
            return { ...prev, lastUpdate: event.data.heartbeat_at * 1000 };
          });
          break;

        case "training_job_completed":
          setStatus(prev => {
            if (prev.kind !== "running") return prev;
            if (prev.jobId !== event.data.job_id) return prev;
            return {
              kind: "done",
              jobId: event.data.job_id,
              exitCode: event.data.exit_code,
              durationSecs: event.data.duration_secs,
            };
          });
          onJobStarted(); // refresh jobs table
          break;

        case "training_job_failed":
          setStatus(prev => {
            if (prev.kind !== "running") return prev;
            if (prev.jobId !== event.data.job_id) return prev;
            return { kind: "failed", jobId: event.data.job_id, error: event.data.error };
          });
          onJobStarted(); // refresh jobs table
          break;

        default:
          break;
      }
    });
    return unsub;
  }, [onJobStarted]);

  function validate(): string | null {
    if (!baseModel.trim()) return "Base model is required.";
    if (!OUTPUT_NAME_RE.test(outputName)) {
      return "Output name must be 1-64 characters: letters, digits, _, ., or -.";
    }
    if (advancedOpen && advancedJson.trim()) {
      try { JSON.parse(advancedJson); } catch {
        return "Advanced options is not valid JSON.";
      }
    }
    return null;
  }

  function startJob() {
    const err = validate();
    if (err) { setFormError(err); return; }
    setFormError(null);
    setStatus({ kind: "starting" });

    api.train
      .finetune({ base_model: baseModel.trim(), output_name: outputName.trim() })
      .then(({ job_id }) => {
        setStatus({
          kind: "running",
          jobId: job_id,
          startedAt: Date.now(),
          lastUpdate: Date.now(),
        });
        setElapsed(0);
        onJobStarted(); // refresh jobs table
      })
      .catch((e: Error) => {
        setStatus({ kind: "failed", jobId: null, error: e.message });
      });
  }

  function reset() {
    setStatus({ kind: "idle" });
    setFormError(null);
  }

  const isRunning = status.kind === "starting" || status.kind === "running";

  // ── Status banner ──────────────────────────────────────────────────────
  let statusBanner: h.JSX.Element | null = null;

  if (status.kind === "starting") {
    statusBanner = (
      <div style={bannerStyle("var(--accent)")}>Starting…</div>
    );
  } else if (status.kind === "running") {
    const secsSinceUpdate = Math.floor((Date.now() - status.lastUpdate) / 1000);
    statusBanner = (
      <div style={bannerStyle("var(--accent)")}>
        Running… {elapsed}s elapsed
        {secsSinceUpdate > 5 && ` (last update ${secsSinceUpdate}s ago)`}
      </div>
    );
  } else if (status.kind === "done") {
    statusBanner = (
      <div style={bannerStyle("var(--success)")}>
        Done — exit code {status.exitCode}, duration {status.durationSecs}s
        <button class="btn btn-sm" style={{ marginLeft: "12px" }} onClick={reset}>
          New job
        </button>
      </div>
    );
  } else if (status.kind === "failed") {
    statusBanner = (
      <div style={bannerStyle("var(--danger)")}>
        Failed: {status.error}
        <button class="btn btn-sm" style={{ marginLeft: "12px" }} onClick={reset}>
          Retry
        </button>
      </div>
    );
  }

  return (
    <div class="card" style={{ marginBottom: "16px" }}>
      <div class="card-title">Fine-tune</div>

      {/* Base model */}
      <div style={fieldRow}>
        <label style={labelStyle}>Base Model</label>
        {models.length > 0 ? (
          <select
            value={baseModel}
            onChange={e => setBaseModel((e.target as HTMLSelectElement).value)}
            disabled={isRunning}
            style={inputStyle}
          >
            <option value="">— select a model —</option>
            {models.map(m => (
              <option key={m.name} value={m.name}>{m.name}</option>
            ))}
          </select>
        ) : (
          <input
            type="text"
            placeholder="e.g. llama3.2:3b"
            value={baseModel}
            onInput={e => setBaseModel((e.target as HTMLInputElement).value)}
            disabled={isRunning}
            style={inputStyle}
          />
        )}
      </div>

      {/* Output name */}
      <div style={fieldRow}>
        <label style={labelStyle}>Output Name</label>
        <input
          type="text"
          placeholder="e.g. sigint-v1"
          value={outputName}
          onInput={e => setOutputName((e.target as HTMLInputElement).value)}
          disabled={isRunning}
          style={{
            ...inputStyle,
            borderColor: outputName && !OUTPUT_NAME_RE.test(outputName)
              ? "var(--danger)" : "var(--border)",
          }}
        />
      </div>

      {/* Advanced options (collapsed) */}
      <div style={{ marginBottom: "12px" }}>
        <button
          class="btn btn-sm"
          style={{ marginBottom: "6px" }}
          onClick={() => setAdvancedOpen(o => !o)}
          disabled={isRunning}
        >
          {advancedOpen ? "Hide" : "Show"} Advanced Options
        </button>
        {advancedOpen && (
          <textarea
            rows={5}
            placeholder='{"epochs": 3, "learning_rate": 1e-4}'
            value={advancedJson}
            onInput={e => setAdvancedJson((e.target as HTMLTextAreaElement).value)}
            disabled={isRunning}
            style={{
              ...inputStyle,
              width: "100%",
              resize: "vertical",
              display: "block",
            }}
          />
        )}
      </div>

      {formError && <InlineError msg={formError} />}

      <button
        class="btn btn-primary"
        onClick={startJob}
        disabled={isRunning || status.kind === "done"}
        style={{ marginTop: "10px" }}
      >
        {isRunning ? "Running…" : "Start Fine-tune"}
      </button>

      {statusBanner && <div style={{ marginTop: "12px" }}>{statusBanner}</div>}
    </div>
  );
}

function bannerStyle(color: string): h.JSX.CSSProperties {
  return {
    display: "flex",
    alignItems: "center",
    padding: "8px 12px",
    borderRadius: "var(--radius-sm)",
    border: `1px solid ${color}`,
    background: `${color}18`,
    color,
    fontSize: "12px",
    fontWeight: 600,
  };
}

const fieldRow: h.JSX.CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: "12px",
  marginBottom: "10px",
};

const labelStyle: h.JSX.CSSProperties = {
  width: "110px",
  flexShrink: 0,
  fontSize: "12px",
  color: "var(--text-secondary)",
};

const inputStyle: h.JSX.CSSProperties = {
  flex: 1,
  background: "var(--bg)",
  border: "1px solid var(--border)",
  borderRadius: "var(--radius-sm)",
  color: "var(--text)",
  fontFamily: "var(--font-mono)",
  fontSize: "12px",
  padding: "5px 8px",
};

// ── EvaluateCard ───────────────────────────────────────────────────────────

function EvaluateCard() {
  return (
    <div class="card" style={{ marginBottom: "16px" }}>
      <div class="card-title">Evaluate</div>
      <div style={{ fontSize: "12px", color: "var(--text-secondary)", marginBottom: "12px" }}>
        Run A/B evaluation to compare a fine-tuned model against the current base model.
      </div>
      <button
        class="btn btn-primary"
        onClick={() => { location.hash = "#/train/evaluate"; }}
      >
        Open Evaluate Workbench
      </button>
    </div>
  );
}

// ── JobsTable ──────────────────────────────────────────────────────────────

/**
 * Flat row type for DataTable — extracts status.status string for display.
 * Index signature required by DataTable's `Record<string, unknown>` constraint.
 */
interface JobRow {
  id: string;
  base_model: string;
  statusLabel: string;
  statusColor: string;
  started_at: string;
  duration: string;
  /** Original TrainingJob kept for click handler. */
  _raw: TrainingJob;
  [key: string]: unknown;
}

function JobsTable({
  refreshKey,
  onRowClick,
}: {
  refreshKey: number;
  onRowClick: (job: TrainingJob) => void;
}) {
  const [jobs, setJobs] = useState<TrainingJob[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.train
      .jobs()
      .then(js => setJobs(js.slice(0, 5)))
      .catch((e: Error) => setError(e.message));
  }, [refreshKey]);

  const rows: JobRow[] = jobs.map(j => ({
    id: j.id,
    base_model: j.base_model,
    statusLabel: j.status.status,
    statusColor: jobStatusColor(j.status),
    started_at: j.started_at,
    duration: durationLabel(j),
    _raw: j,
  }));

  const columns: Column<JobRow>[] = [
    {
      key: "id",
      label: "Job ID",
      render: (v) => <code style={{ fontSize: "11px" }}>{String(v).slice(0, 12)}…</code>,
    },
    { key: "base_model", label: "Base Model" },
    {
      key: "statusLabel",
      label: "Status",
      render: (_v, row) => (
        <span style={{ color: row.statusColor, fontWeight: 600 }}>{row.statusLabel}</span>
      ),
    },
    {
      key: "started_at",
      label: "Started",
      render: (v) => (
        <span style={{ color: "var(--text-secondary)" }}>{relativeTime(String(v))}</span>
      ),
    },
    { key: "duration", label: "Duration" },
  ];

  return (
    <div class="card">
      <div class="card-title">Recent Jobs (last 5)</div>
      {error && <InlineError msg={error} />}
      <DataTable
        columns={columns}
        data={rows}
        onRowClick={(row) => onRowClick(row._raw as TrainingJob)}
      />
    </div>
  );
}

// ── Train page root ────────────────────────────────────────────────────────

export function Train() {
  // Incrementing this key causes JobsTable to re-fetch
  const [jobsRefreshKey, setJobsRefreshKey] = useState(0);
  // Job-detail drawer state (DEC-P26-T6-002)
  const [drawerJob, setDrawerJob] = useState<TrainingJob | null>(null);

  function refreshJobs() {
    setJobsRefreshKey(k => k + 1);
  }

  return (
    <div class="page">
      <div class="page-header">
        <div class="page-title">Training Workbench</div>
      </div>

      <StatsCard />
      <ExportCard />
      <FinetuneCard onJobStarted={refreshJobs} />
      <EvaluateCard />
      <JobsTable refreshKey={jobsRefreshKey} onRowClick={setDrawerJob} />

      {drawerJob && (
        <JobDetailDrawer
          job={drawerJob}
          onClose={() => setDrawerJob(null)}
        />
      )}
    </div>
  );
}
