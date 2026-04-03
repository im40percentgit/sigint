/**
 * FindingsDetail — full detail card for a single finding.
 *
 * Fetches all findings for the session and filters to the target finding by id.
 * Renders all available fields: severity, CVSS, description, evidence, remediation,
 * exploitability, impact, asset reference, and chain context (sibling findings
 * sharing the same chain_id).
 *
 * @decision DEC-WEB-032
 * @title FindingsDetail uses client-side filter from session findings list
 * @status accepted
 * @rationale There is no /api/sessions/:id/findings/:fid endpoint — the list
 * endpoint returns all findings for the session in one call, and client-side
 * Array.find is O(n) over a small set. This avoids a bespoke endpoint while
 * keeping the API surface minimal.
 */

import { h } from "preact";
import { useState, useEffect } from "preact/hooks";
import { api } from "../api";
import type { Finding } from "../types";
import { SeverityBadge } from "../components/SeverityBadge";

interface FindingsDetailProps {
  sessionId: string;
  findingId: string;
}

// Extended fields that may be present on findings from richer scan results
// but are not yet in the canonical types.ts interface.
interface FindingExtended extends Finding {
  cvss_score?: number | null;
  remediation?: string | null;
  exploitability?: string | null;
  impact?: string | null;
  asset_id?: string | null;
  evidence_ref?: string | null;
  chain_id?: string | null;
}

function cvssColor(score: number): string {
  if (score >= 9) return "var(--danger)";
  if (score >= 7) return "var(--warning)";
  if (score >= 4) return "#d29922";
  return "var(--success)";
}

function cvssLabel(score: number): string {
  if (score >= 9) return "Critical";
  if (score >= 7) return "High";
  if (score >= 4) return "Medium";
  return "Low";
}

export function FindingsDetail({ sessionId, findingId }: FindingsDetailProps) {
  const [finding, setFinding] = useState<FindingExtended | null>(null);
  const [siblings, setSiblings] = useState<FindingExtended[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    setError(null);

    api.sessions
      .findings(sessionId)
      .then((all) => {
        const f = (all as FindingExtended[]).find((x) => x.id === findingId) ?? null;
        setFinding(f);
        if (f?.chain_id) {
          setSiblings(
            (all as FindingExtended[]).filter(
              (x) => x.chain_id === f.chain_id && x.id !== findingId
            )
          );
        }
        setLoading(false);
      })
      .catch((e: Error) => {
        setError(e.message);
        setLoading(false);
      });
  }, [sessionId, findingId]);

  if (loading) {
    return (
      <div class="page">
        <p style={{ color: "var(--text-secondary)" }}>Loading finding…</p>
      </div>
    );
  }

  if (error) {
    return (
      <div class="page">
        <p style={{ color: "var(--danger)" }}>Error: {error}</p>
        <a class="btn btn-sm mt-16" href={`#/sessions/${sessionId}`}>
          ← Back to session
        </a>
      </div>
    );
  }

  if (!finding) {
    return (
      <div class="page">
        <p style={{ color: "var(--text-secondary)" }}>Finding not found.</p>
        <a class="btn btn-sm mt-16" href={`#/sessions/${sessionId}`}>
          ← Back to session
        </a>
      </div>
    );
  }

  return (
    <div class="page">
      {/* Back link */}
      <a
        class="btn btn-sm"
        href={`#/sessions/${sessionId}`}
        style={{ marginBottom: "20px", display: "inline-flex" }}
      >
        ← Back to session
      </a>

      {/* Title + severity */}
      <div class="card" style={{ marginBottom: "16px" }}>
        <div
          style={{
            display: "flex",
            alignItems: "flex-start",
            justifyContent: "space-between",
            marginBottom: "12px",
            gap: "12px",
          }}
        >
          <h2 style={{ fontSize: "16px", fontWeight: 600, flex: 1 }}>
            {finding.title}
          </h2>
          <SeverityBadge severity={finding.severity} />
        </div>

        {/* CVSS score badge */}
        {finding.cvss_score != null && (
          <div style={{ marginBottom: "12px" }}>
            <span
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "6px",
                padding: "3px 10px",
                borderRadius: "var(--radius-sm)",
                border: `1px solid ${cvssColor(finding.cvss_score)}`,
                color: cvssColor(finding.cvss_score),
                fontSize: "12px",
                fontWeight: 600,
              }}
            >
              CVSS {finding.cvss_score.toFixed(1)} — {cvssLabel(finding.cvss_score)}
            </span>
          </div>
        )}

        {/* CVE reference */}
        {finding.cve && (
          <div style={{ marginBottom: "8px", fontSize: "12px", color: "var(--text-secondary)" }}>
            CVE: <span style={{ fontFamily: "var(--font-mono)", color: "var(--accent)" }}>{finding.cve}</span>
          </div>
        )}

        {/* Description */}
        {finding.description && (
          <p style={{ color: "var(--text)", lineHeight: "1.7", marginBottom: "0" }}>
            {finding.description}
          </p>
        )}
      </div>

      {/* Evidence */}
      {finding.evidence && (
        <div class="card" style={{ marginBottom: "16px" }}>
          <div class="card-title">Evidence</div>
          <pre
            style={{
              fontFamily: "var(--font-mono)",
              fontSize: "11px",
              lineHeight: "1.6",
              color: "var(--text)",
              backgroundColor: "var(--bg)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-sm)",
              padding: "12px",
              overflowX: "auto",
              whiteSpace: "pre-wrap",
              wordBreak: "break-all",
              margin: 0,
            }}
          >
            {finding.evidence}
          </pre>
        </div>
      )}

      {/* Evidence ref */}
      {finding.evidence_ref && (
        <div class="card" style={{ marginBottom: "16px" }}>
          <div class="card-title">Scan Record Reference</div>
          <p style={{ fontFamily: "var(--font-mono)", fontSize: "12px", color: "var(--accent)" }}>
            Evidence from scan record: {finding.evidence_ref}
          </p>
        </div>
      )}

      {/* Remediation */}
      {finding.remediation && (
        <div class="card" style={{ marginBottom: "16px" }}>
          <div class="card-title">Remediation</div>
          <p style={{ lineHeight: "1.7" }}>{finding.remediation}</p>
        </div>
      )}

      {/* Exploitability + Impact grid */}
      {(finding.exploitability || finding.impact) && (
        <div class="grid-2" style={{ marginBottom: "16px" }}>
          {finding.exploitability && (
            <div class="card">
              <div class="card-title">Exploitability</div>
              <p style={{ lineHeight: "1.7" }}>{finding.exploitability}</p>
            </div>
          )}
          {finding.impact && (
            <div class="card">
              <div class="card-title">Impact</div>
              <p style={{ lineHeight: "1.7" }}>{finding.impact}</p>
            </div>
          )}
        </div>
      )}

      {/* Asset / URL / IP reference */}
      {(finding.asset_id || finding.url || finding.ip) && (
        <div class="card" style={{ marginBottom: "16px" }}>
          <div class="card-title">Affected Asset</div>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: "12px", color: "var(--accent)" }}>
            {finding.asset_id ?? finding.url ?? (finding.ip ? `${finding.ip}${finding.port ? `:${finding.port}` : ""}` : null)}
          </span>
        </div>
      )}

      {/* Chain context */}
      {finding.chain_id && (
        <div class="card" style={{ marginBottom: "16px" }}>
          <div class="card-title">Attack Chain</div>
          <p style={{ fontSize: "12px", color: "var(--text-secondary)", marginBottom: "8px" }}>
            Part of attack chain <code style={{ fontFamily: "var(--font-mono)" }}>{finding.chain_id}</code>
          </p>
          {siblings.length > 0 && (
            <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
              {siblings.map((s) => (
                <a
                  key={s.id}
                  href={`#/sessions/${sessionId}/findings/${s.id}`}
                  style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "12px" }}
                >
                  <SeverityBadge severity={s.severity} />
                  {s.title}
                </a>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
