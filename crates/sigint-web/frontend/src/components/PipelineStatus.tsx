/**
 * PipelineStatus — vertical pipeline stage tracker for a live scan.
 *
 * Displays the fixed set of SIGINT agent roles in order. Each stage is shown
 * as pending (gray), active (accent + pulse), or completed (green + duration).
 *
 * Props:
 *   activeStage      — name of the currently running stage (or empty string)
 *   completedStages  — Map<stageName, durationSeconds>
 *   cycle            — current cycle number (0 = first/only cycle)
 *
 * @decision DEC-WEB-032
 * @title PipelineStatus uses CSS keyframes pulse animation on the active stage icon
 * @status accepted
 * @rationale A CSS animation on the icon avoids a JS setInterval for visual
 * feedback; the pulse keyframe is already defined in theme.css so the pattern
 * is consistent with the existing status-dot animation.
 */

import { h } from "preact";

// ── Constants ──────────────────────────────────────────────────────────────

const STAGES = [
  "RfRecon",
  "Researcher",
  "Strategist",
  "Executor",
  "Analyst",
  "Reporter",
] as const;

// ── Sub-components ─────────────────────────────────────────────────────────

interface StageIconProps {
  state: "pending" | "active" | "completed";
}

function StageIcon({ state }: StageIconProps) {
  if (state === "completed") {
    return (
      <span
        style={{
          width: "18px",
          height: "18px",
          borderRadius: "50%",
          background: "var(--success)",
          display: "inline-flex",
          alignItems: "center",
          justifyContent: "center",
          flexShrink: 0,
          fontSize: "11px",
          color: "#0d1117",
          fontWeight: 700,
        }}
      >
        ✓
      </span>
    );
  }
  if (state === "active") {
    return (
      <span
        style={{
          width: "18px",
          height: "18px",
          borderRadius: "50%",
          border: "2px solid var(--accent)",
          display: "inline-flex",
          alignItems: "center",
          justifyContent: "center",
          flexShrink: 0,
          animation: "pulse 1.2s ease-in-out infinite",
          background: "rgba(88,166,255,0.15)",
        }}
      />
    );
  }
  // pending
  return (
    <span
      style={{
        width: "18px",
        height: "18px",
        borderRadius: "50%",
        border: "2px solid var(--border)",
        display: "inline-block",
        flexShrink: 0,
        opacity: 0.5,
      }}
    />
  );
}

// ── Main component ─────────────────────────────────────────────────────────

interface PipelineStatusProps {
  activeStage: string;
  completedStages: Map<string, number>;
  cycle: number;
}

export function PipelineStatus({
  activeStage,
  completedStages,
  cycle,
}: PipelineStatusProps) {
  return (
    <div
      style={{
        width: "280px",
        flexShrink: 0,
        padding: "16px",
        borderRight: "1px solid var(--border)",
        overflowY: "auto",
      }}
    >
      {/* Cycle counter */}
      {cycle > 0 && (
        <div
          style={{
            fontSize: "11px",
            fontWeight: 600,
            color: "var(--accent)",
            textTransform: "uppercase",
            letterSpacing: "0.06em",
            marginBottom: "16px",
          }}
        >
          Cycle {cycle}
        </div>
      )}

      <div
        style={{
          fontSize: "11px",
          fontWeight: 600,
          textTransform: "uppercase",
          letterSpacing: "0.06em",
          color: "var(--text-secondary)",
          marginBottom: "12px",
        }}
      >
        Pipeline
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
        {STAGES.map((stage) => {
          const isActive = stage === activeStage;
          const duration = completedStages.get(stage);
          const isCompleted = duration !== undefined;
          const state = isCompleted ? "completed" : isActive ? "active" : "pending";

          return (
            <div
              key={stage}
              style={{
                display: "flex",
                alignItems: "center",
                gap: "10px",
                padding: "6px 0",
              }}
            >
              <StageIcon state={state} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div
                  style={{
                    fontSize: "12px",
                    fontWeight: isActive ? 600 : 400,
                    color: isActive
                      ? "var(--accent)"
                      : isCompleted
                      ? "var(--text)"
                      : "var(--text-secondary)",
                    opacity: state === "pending" ? 0.6 : 1,
                  }}
                >
                  {stage}
                </div>
                {isCompleted && (
                  <div
                    style={{
                      fontSize: "11px",
                      color: "var(--text-secondary)",
                      marginTop: "1px",
                    }}
                  >
                    {duration.toFixed(1)}s
                  </div>
                )}
                {isActive && (
                  <div
                    style={{
                      fontSize: "11px",
                      color: "var(--accent)",
                      opacity: 0.7,
                      marginTop: "1px",
                    }}
                  >
                    running…
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
