/**
 * SessionDetail — full session view with tabbed sub-pages.
 *
 * Fetches session metadata, findings, and assets in parallel on mount.
 * Renders four tabs: Findings, Assets, Scan History, Attack Plan.
 * Row clicks in the Findings tab navigate to the FindingsDetail page.
 *
 * @decision DEC-WEB-030
 * @title SessionDetail uses parallel Promise.all fetch + tab state
 * @status accepted
 * @rationale Fetching session, findings, and assets in parallel minimises
 * time-to-interactive on the detail page; local useState tab tracking avoids
 * a URL sub-route per tab while keeping the URL clean for bookmarking.
 */

import { h } from "preact";
import { useState, useEffect } from "preact/hooks";
import { api } from "../api";
import type { Session, Finding, Asset, ScanRecord } from "../types";
import { SeverityBadge } from "../components/SeverityBadge";
import { DataTable } from "../components/DataTable";
import type { Column } from "../components/DataTable";

interface SessionDetailProps {
  sessionId: string;
}

type Tab = "findings" | "assets" | "scans" | "plan";

// ── Helpers ──────────────────────────────────────────────────────────────────

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function truncate(s: string, max: number): string {
  return s.length > max ? s.slice(0, max) + "…" : s;
}

function metaPreview(meta: Record<string, string> | null): string {
  if (!meta) return "";
  try {
    return truncate(JSON.stringify(meta), 50);
  } catch {
    return "";
  }
}

function roleBadgeColor(role: string): string {
  const colors: Record<string, string> = {
    recon: "var(--accent)",
    exploit: "var(--danger)",
    report: "var(--success)",
    orchestrator: "var(--warning)",
    validator: "#a371f7",
  };
  return colors[role.toLowerCase()] ?? "var(--text-secondary)";
}

// ── Findings tab columns ──────────────────────────────────────────────────────

const findingColumns: Column<Finding>[] = [
  {
    key: "severity",
    label: "Severity",
    render: (v) => <SeverityBadge severity={String(v)} />,
  },
  { key: "title", label: "Title" },
  {
    key: "url",
    label: "Asset",
    render: (v, row) => (
      <span style={{ fontFamily: "var(--font-mono)", fontSize: "11px" }}>
        {String(row.url ?? row.ip ?? row.tool ?? "")}
      </span>
    ),
  },
  {
    key: "cve",
    label: "CVE / Ref",
    render: (v) => <span style={{ color: "var(--text-secondary)" }}>{String(v ?? "—")}</span>,
  },
];

// ── Assets tab columns ────────────────────────────────────────────────────────

const assetColumns: Column<Asset>[] = [
  { key: "asset_type", label: "Kind" },
  { key: "value", label: "Value" },
  {
    key: "metadata",
    label: "Metadata",
    render: (v) => (
      <span style={{ fontFamily: "var(--font-mono)", fontSize: "11px", color: "var(--text-secondary)" }}>
        {metaPreview(v as Record<string, string> | null)}
      </span>
    ),
  },
];

// ── Sub-views ─────────────────────────────────────────────────────────────────

function FindingsTab({
  findings,
  sessionId,
}: {
  findings: Finding[];
  sessionId: string;
}) {
  return (
    <DataTable
      columns={findingColumns}
      data={findings}
      onRowClick={(f) => {
        window.location.hash = `#/sessions/${sessionId}/findings/${f.id}`;
      }}
    />
  );
}

function AssetsTab({ assets }: { assets: Asset[] }) {
  return <DataTable columns={assetColumns} data={assets} />;
}

function ScansTab({ scans }: { scans: ScanRecord[] }) {
  if (scans.length === 0) {
    return (
      <p style={{ color: "var(--text-secondary)", padding: "16px 0" }}>
        No scan records for this session.
      </p>
    );
  }
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "8px" }}>
      {scans.map((s) => {
        const duration =
          s.started_at && s.finished_at
            ? `${(
                (new Date(s.finished_at).getTime() -
                  new Date(s.started_at).getTime()) /
                1000
              ).toFixed(1)}s`
            : s.started_at
            ? "running…"
            : "—";
        return (
          <div
            key={s.id}
            class="card"
            style={{ display: "flex", alignItems: "center", gap: "12px", padding: "10px 14px" }}
          >
            <span
              class="badge"
              style={{
                backgroundColor: "rgba(0,0,0,0.3)",
                color: roleBadgeColor("recon"),
                border: `1px solid ${roleBadgeColor("recon")}`,
                minWidth: "64px",
                textAlign: "center",
              }}
            >
              {s.tool}
            </span>
            <span style={{ flex: 1, fontFamily: "var(--font-mono)", fontSize: "12px" }}>
              {s.target}
            </span>
            <span style={{ color: "var(--text-secondary)", fontSize: "11px" }}>{duration}</span>
            <span
              style={{
                color: s.exit_code === 0 ? "var(--success)" : s.exit_code == null ? "var(--text-secondary)" : "var(--danger)",
                fontSize: "11px",
                fontFamily: "var(--font-mono)",
              }}
            >
              exit:{s.exit_code ?? "—"}
            </span>
          </div>
        );
      })}
    </div>
  );
}

function AttackPlanTab({ scans }: { scans: ScanRecord[] }) {
  // Attack plan data lives in structured scan output; if nothing available,
  // show a navigational message pointing to the dedicated AttackPlanView page.
  void scans; // suppress unused-var warning; future: parse structured_data
  return (
    <div style={{ color: "var(--text-secondary)", padding: "16px 0" }}>
      <p>
        Attack plan data is available in the{" "}
        <a href={`#/sessions/${location.hash.split("/")[2]}/plan`}>
          Attack Plan view
        </a>
        .
      </p>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export function SessionDetail({ sessionId }: SessionDetailProps) {
  const [session, setSession] = useState<Session | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [tab, setTab] = useState<Tab>("findings");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    setError(null);

    Promise.all([
      api.sessions.get(sessionId),
      api.sessions.findings(sessionId),
      api.sessions.assets(sessionId),
      api.scans.list(),
    ])
      .then(([sess, finds, assts, allScans]) => {
        setSession(sess);
        setFindings(finds);
        setAssets(assts);
        // Filter scans by session_id
        setScans(allScans.filter((s) => s.session_id === sessionId));
        setLoading(false);
      })
      .catch((e: Error) => {
        setError(e.message);
        setLoading(false);
      });
  }, [sessionId]);

  if (loading) {
    return (
      <div class="page">
        <p style={{ color: "var(--text-secondary)" }}>Loading session…</p>
      </div>
    );
  }

  if (error) {
    return (
      <div class="page">
        <p style={{ color: "var(--danger)" }}>Error: {error}</p>
      </div>
    );
  }

  if (!session) return null;

  const tabs: { id: Tab; label: string; count: number | null }[] = [
    { id: "findings", label: "Findings", count: findings.length },
    { id: "assets", label: "Assets", count: assets.length },
    { id: "scans", label: "Scan History", count: scans.length },
    { id: "plan", label: "Attack Plan", count: null },
  ];

  return (
    <div class="page">
      {/* Header */}
      <div class="page-header">
        <div>
          <h2 style={{ fontSize: "18px", fontWeight: 600, marginBottom: "4px" }}>
            {session.target}
          </h2>
          <div style={{ color: "var(--text-secondary)", fontSize: "12px" }}>
            {formatDate(session.created_at)} &nbsp;·&nbsp;
            <span class={`badge badge-${session.status === "active" ? "info" : session.status === "completed" ? "low" : "high"}`}>
              {session.status}
            </span>
          </div>
        </div>
        <a
          class="btn btn-primary btn-sm"
          href={`#/sessions/${sessionId}/report`}
        >
          View Report
        </a>
      </div>

      {/* Tab bar */}
      <div
        style={{
          display: "flex",
          gap: "4px",
          marginBottom: "16px",
          borderBottom: "1px solid var(--border)",
          paddingBottom: "0",
        }}
      >
        {tabs.map((t) => (
          <button
            key={t.id}
            class="btn btn-sm"
            style={{
              borderBottom: tab === t.id ? "2px solid var(--accent)" : "2px solid transparent",
              borderRadius: "var(--radius-sm) var(--radius-sm) 0 0",
              color: tab === t.id ? "var(--accent)" : "var(--text-secondary)",
              backgroundColor: "transparent",
              borderLeft: "none",
              borderRight: "none",
              borderTop: "none",
            }}
            onClick={() => setTab(t.id)}
          >
            {t.label}
            {t.count !== null && (
              <span
                style={{
                  marginLeft: "5px",
                  background: "var(--border)",
                  borderRadius: "8px",
                  padding: "0 5px",
                  fontSize: "10px",
                  color: "var(--text-secondary)",
                }}
              >
                {t.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === "findings" && <FindingsTab findings={findings} sessionId={sessionId} />}
      {tab === "assets" && <AssetsTab assets={assets} />}
      {tab === "scans" && <ScansTab scans={scans} />}
      {tab === "plan" && <AttackPlanTab scans={scans} />}
    </div>
  );
}
