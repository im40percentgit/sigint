/**
 * ScanLive — real-time scan monitoring page.
 *
 * Layout: PipelineStatus panel (280px left) + EventLog feed (flex-1 right).
 *
 * Event handling strategy:
 *   - All WsEvent objects from the WebSocket are appended to local state and
 *     forwarded to EventLog for rendering.
 *   - Pipeline stage tracking infers agent role from log_line content:
 *     lines matching "[<Role>]" set the activeStage; scan_completed clears it.
 *   - Stage durations are recorded when a new stage becomes active (the
 *     previous stage is considered complete) and on scan_completed.
 *   - Cycle count increments on each scan_completed event (agents may fire
 *     multiple scans per cycle in practice; this approximates cycle progress).
 *   - approval_required events surface the ApprovalModal. The user's
 *     approve/deny choice sends an ApprovalResponse over the WebSocket then
 *     dismisses the modal.
 *   - api.scans.status() is polled every 5 s to detect terminal states
 *     (complete, failed, cancelled) independent of WebSocket events.
 *
 * @decision DEC-WEB-035
 * @title ScanLive infers pipeline stage from log_line role tags
 * @status accepted
 * @rationale The WsEvent union (types.ts) does not include dedicated agent
 * lifecycle events — stage transitions are encoded in log_line.data.line as
 * "[RoleName] message" prefixes emitted by the orchestrator. Parsing these is
 * the lowest-coupling approach: it requires no backend schema change and
 * degrades gracefully (unknown prefixes leave the pipeline unchanged).
 */

import { h } from "preact";
import { useState, useEffect, useRef } from "preact/hooks";
import { api } from "../api";
import { wsManager } from "../ws";
import type { WsEvent, AttackStep } from "../types";
import { PipelineStatus } from "../components/PipelineStatus";
import { EventLog } from "../components/EventLog";
import { ApprovalModal } from "../components/ApprovalModal";

// ── Constants ──────────────────────────────────────────────────────────────

const POLL_INTERVAL_MS = 5000;

const KNOWN_STAGES = [
  "RfRecon",
  "Researcher",
  "Strategist",
  "Executor",
  "Analyst",
  "Reporter",
];

// ── Helpers ────────────────────────────────────────────────────────────────

/**
 * Attempt to parse an agent role from a log line of the form "[RoleName] ...".
 * Returns the matched role name or null.
 */
function parseRoleFromLine(line: string): string | null {
  const m = line.match(/^\[([A-Za-z]+)\]/);
  if (!m) return null;
  const candidate = m[1];
  return KNOWN_STAGES.includes(candidate) ? candidate : null;
}

// ── Component ──────────────────────────────────────────────────────────────

interface ScanLiveProps {
  scanId: string;
}

interface ApprovalRequest {
  step: AttackStep;
}

export function ScanLive({ scanId }: ScanLiveProps) {
  const [events, setEvents] = useState<WsEvent[]>([]);
  const [activeStage, setActiveStage] = useState<string>("");
  const [completedStages, setCompletedStages] = useState<Map<string, number>>(
    new Map()
  );
  const [cycle, setCycle] = useState(0);
  const [approval, setApproval] = useState<ApprovalRequest | null>(null);
  const [scanDone, setScanDone] = useState(false);
  const [scanStatus, setScanStatus] = useState<string>("");

  // Refs for stage timing (mutable, don't need re-render on change)
  const stageStartRef = useRef<number>(Date.now());
  const activeStageRef = useRef<string>("");

  // Keep ref in sync with state for use inside event handler closure
  useEffect(() => {
    activeStageRef.current = activeStage;
  }, [activeStage]);

  // ── WebSocket subscription ────────────────────────────────────────────────
  useEffect(() => {
    const unsub = wsManager.subscribe((event: WsEvent) => {
      setEvents(prev => [...prev, event]);

      if (event.type === "log_line") {
        const role = parseRoleFromLine(event.data.line);
        if (role && role !== activeStageRef.current) {
          // Record duration for the previously active stage
          const prev = activeStageRef.current;
          if (prev) {
            const dur = (Date.now() - stageStartRef.current) / 1000;
            setCompletedStages(m => {
              const next = new Map(m);
              next.set(prev, dur);
              return next;
            });
          }
          stageStartRef.current = Date.now();
          setActiveStage(role);
        }
      }

      if (event.type === "scan_completed") {
        // Mark the last active stage as complete
        const prev = activeStageRef.current;
        if (prev) {
          const dur = (Date.now() - stageStartRef.current) / 1000;
          setCompletedStages(m => {
            const next = new Map(m);
            next.set(prev, dur);
            return next;
          });
        }
        setActiveStage("");
        setCycle(c => c + 1);
        setScanDone(true);
        setScanStatus("complete");
      }

      if (event.type === "approval_required") {
        setApproval({ step: event.data });
      }
    });
    return unsub;
  }, []);

  // ── Poll scan status every 5 s ────────────────────────────────────────────
  useEffect(() => {
    if (scanDone) return;
    const id = setInterval(async () => {
      try {
        const record = await api.scans.status(scanId);
        if (
          record.status === "complete" ||
          record.status === "failed" ||
          record.status === "cancelled"
        ) {
          setScanDone(true);
          setScanStatus(record.status);
          clearInterval(id);
        }
      } catch {
        // Ignore transient polling failures
      }
    }, POLL_INTERVAL_MS);
    return () => clearInterval(id);
  }, [scanId, scanDone]);

  // ── Approval handlers ─────────────────────────────────────────────────────
  function handleApprove() {
    if (!approval) return;
    wsManager.send({ step_id: approval.step.id, approved: true });
    setApproval(null);
  }

  function handleDeny() {
    if (!approval) return;
    wsManager.send({ step_id: approval.step.id, approved: false });
    setApproval(null);
  }

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <div style={{ display: "flex", height: "100%", overflow: "hidden" }}>
      {/* Left: Pipeline status */}
      <PipelineStatus
        activeStage={activeStage}
        completedStages={completedStages}
        cycle={cycle}
      />

      {/* Right: Event log + completion banner */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>
        {scanDone && (
          <div
            style={{
              background:
                scanStatus === "complete"
                  ? "rgba(63,185,80,0.10)"
                  : "rgba(248,81,73,0.10)",
              border: `1px solid ${scanStatus === "complete" ? "var(--success)" : "var(--danger)"}`,
              borderRadius: "var(--radius-sm)",
              padding: "10px 16px",
              margin: "12px 16px 0",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              fontSize: "13px",
            }}
          >
            <span
              style={{
                color:
                  scanStatus === "complete" ? "var(--success)" : "var(--danger)",
                fontWeight: 600,
              }}
            >
              Scan {scanStatus === "complete" ? "Complete" : scanStatus}
            </span>
            {scanStatus === "complete" && (
              <a
                href={`#/sessions/${scanId}`}
                style={{ color: "var(--accent)", fontSize: "12px" }}
              >
                View session details
              </a>
            )}
          </div>
        )}

        <EventLog events={events} />
      </div>

      {/* Approval modal — rendered above everything when present */}
      {approval && (
        <ApprovalModal
          requestId={approval.step.id}
          tier={approval.step.status}
          rationale={approval.step.reasoning ?? approval.step.description}
          onApprove={handleApprove}
          onDeny={handleDeny}
        />
      )}
    </div>
  );
}
