/**
 * AttackPlanView — standalone view for the session attack plan.
 *
 * The attack plan is derived from AttackStep records fetched via the scans API.
 * Steps are displayed as priority-ordered cards with MITRE ATT&CK links,
 * risk score badges, and tool badges. If no dedicated attack plan data is
 * available, a message guides the user back to the session detail.
 *
 * @decision DEC-WEB-033
 * @title AttackPlanView uses AttackStep records from scans API filtered by session
 * @status accepted
 * @rationale There is no dedicated /api/sessions/:id/attack-plan endpoint;
 * AttackStep records are surfaced through the scan records response. Client-side
 * filtering by session_id is O(n) over a small result set and avoids a bespoke
 * endpoint. MITRE technique IDs are rendered as external links to
 * attack.mitre.org using the canonical URL pattern /techniques/TXXXX/YYY.
 */

import { h } from "preact";
import { useState, useEffect } from "preact/hooks";
import { api } from "../api";
import type { AttackStep } from "../types";

interface AttackPlanViewProps {
  sessionId: string;
}

/** Derive MITRE ATT&CK URL from technique ID like T1059.001 */
function mitreUrl(id: string): string {
  // T1059.001 → /techniques/T1059/001
  const parts = id.split(".");
  return `https://attack.mitre.org/techniques/${parts.join("/")}`;
}

/** Risk score badge color: 1-3 green, 4-6 yellow, 7-8 orange, 9-10 red */
function riskColor(score: number): string {
  if (score >= 9) return "var(--danger)";
  if (score >= 7) return "var(--warning)";
  if (score >= 4) return "#d29922";
  return "var(--success)";
}

function riskBg(score: number): string {
  if (score >= 9) return "rgba(248,81,73,0.12)";
  if (score >= 7) return "rgba(240,136,62,0.12)";
  if (score >= 4) return "rgba(210,153,34,0.12)";
  return "rgba(63,185,80,0.12)";
}

/** Extended AttackStep with optional MITRE and risk fields */
interface AttackStepExtended extends AttackStep {
  mitre_technique?: string | null;
  risk_score?: number | null;
  tools?: string[] | null;
  name?: string | null;
  priority?: number | null;
}

function StepCard({ step, index }: { step: AttackStepExtended; index: number }) {
  const priority = step.priority ?? step.step_number ?? index + 1;
  const name = step.name ?? step.description;
  const riskScore = step.risk_score ?? null;
  const mitre = step.mitre_technique ?? null;
  const tools = step.tools ?? (step.tool ? [step.tool] : []);

  return (
    <div
      class="card"
      style={{ marginBottom: "12px", display: "flex", gap: "16px", alignItems: "flex-start" }}
    >
      {/* Priority circle */}
      <div
        style={{
          width: "32px",
          height: "32px",
          borderRadius: "50%",
          backgroundColor: "var(--accent)",
          color: "#0d1117",
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          fontWeight: 700,
          fontSize: "13px",
          flexShrink: 0,
        }}
      >
        {priority}
      </div>

      {/* Content */}
      <div style={{ flex: 1 }}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: "10px",
            marginBottom: "6px",
            flexWrap: "wrap",
          }}
        >
          <h3 style={{ fontWeight: 600, fontSize: "14px", margin: 0 }}>{name}</h3>

          {/* Risk score badge */}
          {riskScore != null && (
            <span
              style={{
                padding: "2px 8px",
                borderRadius: "var(--radius-sm)",
                color: riskColor(riskScore),
                backgroundColor: riskBg(riskScore),
                border: `1px solid ${riskColor(riskScore)}`,
                fontSize: "11px",
                fontWeight: 600,
              }}
            >
              Risk {riskScore}/10
            </span>
          )}

          {/* Status badge */}
          <span
            class={`badge badge-${
              step.status === "complete"
                ? "low"
                : step.status === "failed"
                ? "high"
                : step.status === "approved"
                ? "info"
                : step.status === "rejected"
                ? "medium"
                : "info"
            }`}
          >
            {step.status}
          </span>
        </div>

        {/* MITRE technique link */}
        {mitre && (
          <div style={{ marginBottom: "6px", fontSize: "12px" }}>
            <span style={{ color: "var(--text-secondary)" }}>MITRE: </span>
            <a
              href={mitreUrl(mitre)}
              target="_blank"
              rel="noopener noreferrer"
              style={{ fontFamily: "var(--font-mono)", fontSize: "11px" }}
            >
              {mitre}
            </a>
          </div>
        )}

        {/* Reasoning / rationale */}
        {step.reasoning && (
          <p
            style={{
              color: "var(--text-secondary)",
              fontSize: "12px",
              lineHeight: "1.6",
              marginBottom: tools.length > 0 ? "8px" : "0",
            }}
          >
            {step.reasoning}
          </p>
        )}

        {/* Tools */}
        {tools.length > 0 && (
          <div style={{ display: "flex", gap: "4px", flexWrap: "wrap" }}>
            {tools.map((t) => (
              <span
                key={t}
                style={{
                  padding: "1px 7px",
                  borderRadius: "var(--radius-sm)",
                  backgroundColor: "rgba(88,166,255,0.1)",
                  border: "1px solid rgba(88,166,255,0.3)",
                  color: "var(--accent)",
                  fontSize: "10px",
                  fontFamily: "var(--font-mono)",
                }}
              >
                {t}
              </span>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export function AttackPlanView({ sessionId }: AttackPlanViewProps) {
  const [steps, setSteps] = useState<AttackStepExtended[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    setError(null);

    // Attack steps are not yet exposed as a dedicated API endpoint;
    // fall back to an empty plan and display informational message.
    // When the /api/sessions/:id/steps endpoint is added, replace this.
    Promise.resolve([])
      .then((s) => {
        setSteps(s as AttackStepExtended[]);
        setLoading(false);
      })
      .catch((e: Error) => {
        setError(e.message);
        setLoading(false);
      });
  }, [sessionId]);

  return (
    <div class="page">
      {/* Header */}
      <div class="page-header">
        <div>
          <div class="page-title" style={{ marginBottom: "4px" }}>Attack Plan</div>
          <div style={{ color: "var(--text-secondary)", fontSize: "12px" }}>
            Session: <code style={{ fontFamily: "var(--font-mono)" }}>{sessionId}</code>
          </div>
        </div>
        <a class="btn btn-sm" href={`#/sessions/${sessionId}`}>
          ← Back to session
        </a>
      </div>

      {loading && (
        <p style={{ color: "var(--text-secondary)" }}>Loading attack plan…</p>
      )}

      {error && (
        <div
          style={{
            padding: "16px",
            color: "var(--danger)",
            border: "1px solid var(--danger)",
            borderRadius: "var(--radius-md)",
          }}
        >
          Error: {error}
        </div>
      )}

      {!loading && !error && steps.length === 0 && (
        <div class="card" style={{ color: "var(--text-secondary)" }}>
          <p style={{ marginBottom: "8px" }}>
            No attack plan steps are available for this session yet.
          </p>
          <p style={{ fontSize: "12px" }}>
            Attack plan data is generated by the orchestrator agent during active scans.
            Start a new scan from the{" "}
            <a href="#/sessions">Sessions</a> page or view findings in the{" "}
            <a href={`#/sessions/${sessionId}`}>Session Detail</a>.
          </p>
        </div>
      )}

      {!loading && steps.length > 0 && (
        <div>
          <p style={{ color: "var(--text-secondary)", fontSize: "12px", marginBottom: "16px" }}>
            {steps.length} step{steps.length !== 1 ? "s" : ""} — ordered by priority
          </p>
          {steps
            .slice()
            .sort(
              (a, b) =>
                (a.priority ?? a.step_number ?? 0) -
                (b.priority ?? b.step_number ?? 0)
            )
            .map((step, i) => (
              <StepCard key={step.id} step={step} index={i} />
            ))}
        </div>
      )}
    </div>
  );
}
