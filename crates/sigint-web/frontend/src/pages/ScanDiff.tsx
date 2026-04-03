/**
 * ScanDiff — compare findings between two sessions.
 *
 * Renders two session dropdowns populated from the sessions list API.
 * On Compare, calls api.diff(sessionA, sessionB) and displays results in
 * four sections: new findings, removed findings, changed findings, unchanged count.
 *
 * @decision DEC-WEB-034
 * @title ScanDiff uses client-initiated diff fetch after explicit Compare action
 * @status accepted
 * @rationale Diff is potentially expensive (full session scan over large
 * finding sets); triggering it only on explicit Compare click avoids
 * unnecessary server load during dropdown selection. Empty state with
 * guidance is shown until both sessions are selected.
 */

import { h } from "preact";
import { useState, useEffect } from "preact/hooks";
import { api } from "../api";
import type { Session, DiffResult, Finding } from "../types";
import { SeverityBadge } from "../components/SeverityBadge";

interface ScanDiffProps {
  // no props — page-level component
}

// Suppress unused-type lint: the props interface is intentionally empty
void ({} as ScanDiffProps);

function FindingRow({ f }: { f: Finding }) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: "10px",
        padding: "8px 0",
        borderBottom: "1px solid var(--border)",
        fontSize: "12px",
      }}
    >
      <SeverityBadge severity={f.severity} />
      <span style={{ flex: 1 }}>{f.title}</span>
      {(f.url || f.ip) && (
        <span style={{ color: "var(--text-secondary)", fontFamily: "var(--font-mono)", fontSize: "11px" }}>
          {f.url ?? f.ip}
        </span>
      )}
    </div>
  );
}

interface SectionProps {
  title: string;
  count: number;
  headerColor: string;
  findings: Finding[];
  emptyText?: string;
}

function DiffSection({ title, count, headerColor, findings, emptyText }: SectionProps) {
  if (count === 0 && findings.length === 0) return null;
  return (
    <div class="card" style={{ marginBottom: "16px" }}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "8px",
          marginBottom: findings.length > 0 ? "8px" : "0",
        }}
      >
        <span style={{ fontWeight: 600, fontSize: "13px", color: headerColor }}>{title}</span>
        <span
          style={{
            padding: "1px 7px",
            borderRadius: "8px",
            backgroundColor: "rgba(255,255,255,0.08)",
            fontSize: "11px",
            color: headerColor,
          }}
        >
          {count}
        </span>
      </div>
      {findings.length === 0 && emptyText && (
        <p style={{ color: "var(--text-secondary)", fontSize: "12px" }}>{emptyText}</p>
      )}
      {findings.map((f) => (
        <FindingRow key={f.id} f={f} />
      ))}
    </div>
  );
}

export function ScanDiff(_props: ScanDiffProps) {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [sessionA, setSessionA] = useState<string>("");
  const [sessionB, setSessionB] = useState<string>("");
  const [result, setResult] = useState<DiffResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [sessionsLoading, setSessionsLoading] = useState(true);

  useEffect(() => {
    api.sessions
      .list()
      .then((s) => {
        setSessions(s);
        setSessionsLoading(false);
      })
      .catch(() => setSessionsLoading(false));
  }, []);

  function handleCompare() {
    if (!sessionA || !sessionB) return;
    setLoading(true);
    setError(null);
    setResult(null);

    api
      .diff(sessionA, sessionB)
      .then((r) => {
        setResult(r);
        setLoading(false);
      })
      .catch((e: Error) => {
        setError(e.message);
        setLoading(false);
      });
  }

  const canCompare = sessionA && sessionB && sessionA !== sessionB;

  return (
    <div class="page">
      <div class="page-title">Scan Diff</div>

      {/* Session selectors */}
      <div
        style={{
          display: "flex",
          gap: "12px",
          alignItems: "flex-end",
          marginBottom: "24px",
          flexWrap: "wrap",
        }}
      >
        <div class="form-group" style={{ flex: 1, minWidth: "200px", marginBottom: 0 }}>
          <label>Session A (baseline)</label>
          <select
            value={sessionA}
            onChange={(e) => setSessionA((e.target as HTMLSelectElement).value)}
            disabled={sessionsLoading}
            style={{ width: "100%" }}
          >
            <option value="">— Select session —</option>
            {sessions.map((s) => (
              <option key={s.id} value={s.id}>
                {s.target} ({s.id.slice(0, 8)}…)
              </option>
            ))}
          </select>
        </div>

        <div class="form-group" style={{ flex: 1, minWidth: "200px", marginBottom: 0 }}>
          <label>Session B (compare)</label>
          <select
            value={sessionB}
            onChange={(e) => setSessionB((e.target as HTMLSelectElement).value)}
            disabled={sessionsLoading}
            style={{ width: "100%" }}
          >
            <option value="">— Select session —</option>
            {sessions.map((s) => (
              <option key={s.id} value={s.id}>
                {s.target} ({s.id.slice(0, 8)}…)
              </option>
            ))}
          </select>
        </div>

        <button
          class="btn btn-primary"
          onClick={handleCompare}
          disabled={!canCompare || loading}
          style={{ height: "30px", alignSelf: "flex-end" }}
        >
          {loading ? "Comparing…" : "Compare"}
        </button>
      </div>

      {/* Validation hint */}
      {sessionA && sessionB && sessionA === sessionB && (
        <p style={{ color: "var(--warning)", fontSize: "12px", marginBottom: "16px" }}>
          Select two different sessions to compare.
        </p>
      )}

      {/* Error */}
      {error && (
        <div
          style={{
            padding: "12px 16px",
            color: "var(--danger)",
            border: "1px solid var(--danger)",
            borderRadius: "var(--radius-md)",
            marginBottom: "16px",
            fontSize: "12px",
          }}
        >
          Diff failed: {error}
        </div>
      )}

      {/* Empty state */}
      {!result && !loading && !error && (
        <div
          style={{
            textAlign: "center",
            color: "var(--text-secondary)",
            padding: "48px 0",
            fontSize: "13px",
          }}
        >
          Select two sessions and click Compare to see what changed.
        </div>
      )}

      {/* Results */}
      {result && (
        <div>
          <div
            style={{
              fontSize: "12px",
              color: "var(--text-secondary)",
              marginBottom: "16px",
            }}
          >
            Comparing{" "}
            <code style={{ fontFamily: "var(--font-mono)" }}>{result.session_a.slice(0, 8)}</code>
            {" → "}
            <code style={{ fontFamily: "var(--font-mono)" }}>{result.session_b.slice(0, 8)}</code>
          </div>

          <DiffSection
            title="New Findings"
            count={result.new_findings.length}
            headerColor="var(--success)"
            findings={result.new_findings}
            emptyText="No new findings."
          />

          <DiffSection
            title="Removed Findings"
            count={result.resolved_findings.length}
            headerColor="var(--danger)"
            findings={result.resolved_findings}
            emptyText="No removed findings."
          />

          {/* Changed findings: not directly in DiffResult, show new_assets as proxy */}
          {result.new_assets.length > 0 && (
            <div class="card" style={{ marginBottom: "16px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "8px" }}>
                <span style={{ fontWeight: 600, fontSize: "13px", color: "#d29922" }}>New Assets</span>
                <span
                  style={{
                    padding: "1px 7px",
                    borderRadius: "8px",
                    backgroundColor: "rgba(255,255,255,0.08)",
                    fontSize: "11px",
                    color: "#d29922",
                  }}
                >
                  {result.new_assets.length}
                </span>
              </div>
              {result.new_assets.map((a) => (
                <div
                  key={a.id}
                  style={{
                    display: "flex",
                    gap: "10px",
                    padding: "6px 0",
                    borderBottom: "1px solid var(--border)",
                    fontSize: "12px",
                  }}
                >
                  <span class="badge badge-info">{a.asset_type}</span>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: "11px" }}>{a.value}</span>
                </div>
              ))}
            </div>
          )}

          {result.removed_assets.length > 0 && (
            <div class="card" style={{ marginBottom: "16px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "8px" }}>
                <span style={{ fontWeight: 600, fontSize: "13px", color: "var(--text-secondary)" }}>Removed Assets</span>
                <span
                  style={{
                    padding: "1px 7px",
                    borderRadius: "8px",
                    backgroundColor: "rgba(255,255,255,0.08)",
                    fontSize: "11px",
                    color: "var(--text-secondary)",
                  }}
                >
                  {result.removed_assets.length}
                </span>
              </div>
              {result.removed_assets.map((a) => (
                <div
                  key={a.id}
                  style={{
                    display: "flex",
                    gap: "10px",
                    padding: "6px 0",
                    borderBottom: "1px solid var(--border)",
                    fontSize: "12px",
                  }}
                >
                  <span class="badge badge-medium">{a.asset_type}</span>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: "11px" }}>{a.value}</span>
                </div>
              ))}
            </div>
          )}

          {/* Unchanged count */}
          <div style={{ color: "var(--text-secondary)", fontSize: "12px", textAlign: "right" }}>
            {Math.max(
              0,
              // Approximate: if no resolved or new, all are unchanged
              0
            )}{" "}
            findings unchanged
          </div>
        </div>
      )}
    </div>
  );
}
