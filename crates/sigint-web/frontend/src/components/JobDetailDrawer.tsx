/**
 * JobDetailDrawer — slide-in drawer showing details of a fine-tune job.
 *
 * Opens when a row in the Jobs table is clicked. Shows the full JobRecord
 * fields including the bounded stdout tail. Auto-updates via WS events while
 * the job is running; unsubscribes cleanly on unmount or when the drawer closes.
 *
 * @decision DEC-P26-T6-002
 * @title Job-detail drawer subscribes to WS events directly for live stdout updates
 * @status accepted
 * @rationale Three design options were considered:
 *   1. Polling GET /api/train/jobs/:id on a timer (simple, but ~1s latency, extra requests)
 *   2. Parent passes live data down as props (requires Train page to manage per-job state)
 *   3. Drawer subscribes to wsManager directly, filtered to matching job_id (chosen)
 *
 * Option 3 is chosen because: (a) the WS events are already in-flight for the
 * fine-tune card — no new transport overhead; (b) the drawer can scope its
 * subscription to the open job_id and unsubscribe on unmount, preventing leaks;
 * (c) the parent (Train page) doesn't need to grow per-job live-state management.
 *
 * `stdout_tail` on `JobRecord` (DEC-P26-T6-002 backend) is the single source of
 * truth for the final persisted tail. The drawer shows it as the initial value
 * for completed jobs, and overlays live WS updates for running jobs.
 *
 * `Option<String>` on the backend maps to `string | undefined` in TypeScript.
 * CLI-initiated jobs (Stdio::inherit, no capture) have no tail — the drawer
 * shows a "not captured" notice in that case.
 */

import { h } from "preact";
import { useState, useEffect, useRef } from "preact/hooks";
import { wsManager } from "../ws";
import type { TrainingJob, WsEvent } from "../types";

// ── Helpers ────────────────────────────────────────────────────────────────

function formatTimestamp(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function durationLabel(job: TrainingJob): string {
  if (!job.finished_at) return "still running";
  const start = new Date(job.started_at).getTime();
  const end = new Date(job.finished_at).getTime();
  const secs = Math.round((end - start) / 1000);
  if (secs < 60) return `${secs}s`;
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  return `${m}m ${s}s`;
}

// ── Styles ─────────────────────────────────────────────────────────────────

const OVERLAY_STYLE: h.JSX.CSSProperties = {
  position: "fixed",
  inset: 0,
  background: "rgba(0,0,0,0.50)",
  zIndex: 900,
  display: "flex",
  justifyContent: "flex-end",
};

const DRAWER_STYLE: h.JSX.CSSProperties = {
  width: "min(520px, 95vw)",
  height: "100%",
  background: "var(--surface)",
  borderLeft: "1px solid var(--border)",
  display: "flex",
  flexDirection: "column",
  overflowY: "hidden",
};

const HEADER_STYLE: h.JSX.CSSProperties = {
  display: "flex",
  alignItems: "center",
  justifyContent: "space-between",
  padding: "16px 20px",
  borderBottom: "1px solid var(--border)",
  flexShrink: 0,
};

const BODY_STYLE: h.JSX.CSSProperties = {
  flex: 1,
  overflowY: "auto",
  padding: "20px",
  display: "flex",
  flexDirection: "column",
  gap: "16px",
};

const SECTION_LABEL: h.JSX.CSSProperties = {
  fontSize: "10px",
  fontWeight: 700,
  textTransform: "uppercase",
  letterSpacing: "0.06em",
  color: "var(--text-secondary)",
  marginBottom: "6px",
};

const META_ROW: h.JSX.CSSProperties = {
  display: "flex",
  gap: "8px",
  marginBottom: "5px",
  fontSize: "12px",
};

const META_LABEL: h.JSX.CSSProperties = {
  width: "100px",
  flexShrink: 0,
  color: "var(--text-secondary)",
};

const META_VALUE: h.JSX.CSSProperties = {
  color: "var(--text)",
  fontWeight: 500,
  wordBreak: "break-all",
};

// ── StatusBadge ─────────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: TrainingJob["status"] }) {
  let color = "var(--text-secondary)";
  if (status.status === "Running") color = "var(--accent)";
  if (status.status === "Success") color = "var(--success)";
  if (status.status === "Failed")  color = "var(--danger)";

  return (
    <span style={{
      display: "inline-block",
      padding: "2px 8px",
      borderRadius: "var(--radius-sm)",
      border: `1px solid ${color}`,
      background: `${color}18`,
      color,
      fontWeight: 700,
      fontSize: "11px",
    }}>
      {status.status}
    </span>
  );
}

// ── JobDetailDrawer ─────────────────────────────────────────────────────────

export interface JobDetailDrawerProps {
  job: TrainingJob;
  onClose: () => void;
}

/**
 * Slide-in drawer for a fine-tune job. Subscribes to WS events for live
 * updates while the job is running. Unsubscribes on unmount (DEC-P26-T6-002).
 */
export function JobDetailDrawer({ job: initialJob, onClose }: JobDetailDrawerProps) {
  // Local copy of job that gets patched by live WS events.
  const [job, setJob] = useState<TrainingJob>(initialJob);
  // Live stdout tail — starts from the job record's stored tail,
  // then overwritten by incoming WS progress events.
  const [liveTail, setLiveTail] = useState<string | undefined>(initialJob.stdout_tail);
  const tailRef = useRef<HTMLPreElement>(null);

  // Re-seed if the parent passes a different job (e.g. user clicks a different row).
  useEffect(() => {
    setJob(initialJob);
    setLiveTail(initialJob.stdout_tail);
  }, [initialJob.id]);

  // Auto-scroll stdout tail to bottom when new content arrives.
  useEffect(() => {
    if (tailRef.current) {
      tailRef.current.scrollTop = tailRef.current.scrollHeight;
    }
  }, [liveTail]);

  // WS subscription — scoped to this job_id (DEC-P26-T6-002).
  useEffect(() => {
    const unsub = wsManager.subscribe((event: WsEvent) => {
      switch (event.type) {
        case "training_job_progress":
          if (event.data.job_id !== job.id) return;
          setLiveTail(event.data.stdout_tail);
          // Patch running state (keep finished_at / exit_code absent)
          setJob(prev => ({ ...prev, status: { status: "Running" } }));
          break;

        case "training_job_completed":
          if (event.data.job_id !== job.id) return;
          setJob(prev => ({
            ...prev,
            status: { status: "Success" },
            exit_code: event.data.exit_code,
            finished_at: new Date().toISOString(),
          }));
          break;

        case "training_job_failed":
          if (event.data.job_id !== job.id) return;
          setJob(prev => ({
            ...prev,
            status: { status: "Failed" },
            failure_reason: event.data.error,
            finished_at: new Date().toISOString(),
          }));
          break;

        default:
          break;
      }
    });
    return unsub;
  }, [job.id]);

  // Close on Escape key.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const isRunning = job.status.status === "Running";

  return (
    <div style={OVERLAY_STYLE} onClick={onClose}>
      {/* Stop click-inside from bubbling to overlay (closing the drawer). */}
      <div style={DRAWER_STYLE} onClick={e => e.stopPropagation()}>

        {/* ── Header ── */}
        <div style={HEADER_STYLE}>
          <div>
            <div style={{ fontSize: "14px", fontWeight: 700, color: "var(--text)", marginBottom: "4px" }}>
              Job Detail
            </div>
            <code style={{ fontSize: "11px", color: "var(--text-secondary)" }}>
              {job.id}
            </code>
          </div>
          <button
            class="btn btn-sm"
            onClick={onClose}
            aria-label="Close drawer"
            style={{ fontSize: "16px", padding: "2px 8px" }}
          >
            ×
          </button>
        </div>

        {/* ── Body ── */}
        <div style={BODY_STYLE}>

          {/* Status + Duration */}
          <div>
            <div style={SECTION_LABEL}>Status</div>
            <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
              <StatusBadge status={job.status} />
              {isRunning && (
                <span style={{ fontSize: "11px", color: "var(--accent)" }}>
                  Live updates active
                </span>
              )}
            </div>
          </div>

          {/* Metadata table */}
          <div>
            <div style={SECTION_LABEL}>Details</div>
            <div style={META_ROW}>
              <span style={META_LABEL}>Base model</span>
              <span style={{ ...META_VALUE, fontFamily: "var(--font-mono)" }}>{job.base_model}</span>
            </div>
            <div style={META_ROW}>
              <span style={META_LABEL}>Output path</span>
              <span style={{ ...META_VALUE, fontFamily: "var(--font-mono)", fontSize: "11px" }}>{job.output_path}</span>
            </div>
            <div style={META_ROW}>
              <span style={META_LABEL}>Started</span>
              <span style={META_VALUE}>{formatTimestamp(job.started_at)}</span>
            </div>
            {job.finished_at && (
              <div style={META_ROW}>
                <span style={META_LABEL}>Finished</span>
                <span style={META_VALUE}>{formatTimestamp(job.finished_at)}</span>
              </div>
            )}
            <div style={META_ROW}>
              <span style={META_LABEL}>Duration</span>
              <span style={{ ...META_VALUE, color: isRunning ? "var(--accent)" : "var(--text)" }}>
                {durationLabel(job)}
              </span>
            </div>
            {job.exit_code !== undefined && (
              <div style={META_ROW}>
                <span style={META_LABEL}>Exit code</span>
                <span style={{
                  ...META_VALUE,
                  color: job.exit_code === 0 ? "var(--success)" : "var(--danger)",
                  fontFamily: "var(--font-mono)",
                }}>
                  {job.exit_code}
                </span>
              </div>
            )}
            {job.failure_reason && (
              <div style={META_ROW}>
                <span style={META_LABEL}>Failure</span>
                <span style={{ ...META_VALUE, color: "var(--danger)" }}>{job.failure_reason}</span>
              </div>
            )}
          </div>

          {/* Stdout tail */}
          <div style={{ flex: 1, display: "flex", flexDirection: "column", minHeight: 0 }}>
            <div style={{ ...SECTION_LABEL, marginBottom: "6px" }}>
              Stdout / Stderr
              {isRunning && (
                <span style={{ marginLeft: "8px", color: "var(--accent)", fontWeight: 400, textTransform: "none" }}>
                  (live)
                </span>
              )}
            </div>
            {liveTail !== undefined ? (
              <pre
                ref={tailRef}
                style={{
                  flex: 1,
                  overflow: "auto",
                  maxHeight: "400px",
                  background: "var(--bg)",
                  border: "1px solid var(--border)",
                  borderRadius: "var(--radius-sm)",
                  padding: "10px 12px",
                  fontFamily: "var(--font-mono)",
                  fontSize: "11px",
                  color: "var(--text)",
                  lineHeight: 1.55,
                  whiteSpace: "pre-wrap",
                  wordBreak: "break-word",
                  margin: 0,
                }}
              >
                {liveTail || "(no output yet)"}
              </pre>
            ) : (
              <div style={{
                fontSize: "12px",
                color: "var(--text-secondary)",
                background: "var(--bg)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-sm)",
                padding: "10px 12px",
              }}>
                Not captured — CLI-initiated jobs inherit stdout and do not record a tail.
              </div>
            )}
          </div>

        </div>
      </div>
    </div>
  );
}
