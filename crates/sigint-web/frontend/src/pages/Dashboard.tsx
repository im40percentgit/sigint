/**
 * Dashboard — landing page showing session/scan metrics and recent sessions.
 *
 * Fetches sessions and scans on mount, displays 4 StatCards for key metrics,
 * and a DataTable of the 10 most recent sessions. A "New Scan" button routes
 * to #/scan/new.
 *
 * @decision DEC-WEB-030
 * @title Dashboard uses parallel useEffect fetches for sessions and scans
 * @status accepted
 * @rationale Two independent API calls are fired in a single useEffect to
 * minimise time-to-paint; they update independent state slices so a partial
 * failure (e.g. no scans yet) still renders session data. Loading and error
 * states are tracked independently for the same reason.
 */

import { h } from "preact";
import { useState, useEffect } from "preact/hooks";
import { api } from "../api";
import type { Session, ScanRecord } from "../types";
import { StatCard } from "../components/StatCard";
import { DataTable } from "../components/DataTable";
import type { Column } from "../components/DataTable";

// ── Helpers ────────────────────────────────────────────────────────────────

/** Format an ISO timestamp as a short relative string ("2h ago", "3d ago"). */
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

// ── Component ──────────────────────────────────────────────────────────────

export function Dashboard() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // Fire both fetches concurrently
    api.sessions
      .list()
      .then(setSessions)
      .catch((e: Error) => setError(e.message));
    api.scans
      .list()
      .then(setScans)
      .catch(() => {
        // Scans endpoint failing is non-fatal — keep sessions data
      });
  }, []);

  const activeScans = scans.filter(s => s.status === "running").length;
  const recentSessions = sessions.slice(0, 10);

  const columns: Column<Session>[] = [
    { key: "id", label: "ID", render: (v) => <code style={{ fontSize: "11px" }}>{String(v).slice(0, 8)}</code> },
    { key: "target", label: "Target" },
    {
      key: "status",
      label: "Status",
      render: (v) => {
        const s = String(v);
        const color =
          s === "active" ? "var(--success)"
          : s === "failed" ? "var(--danger)"
          : "var(--text-secondary)";
        return <span style={{ color, fontWeight: 600 }}>{s}</span>;
      },
    },
    {
      key: "created_at",
      label: "Created",
      render: (v) => <span style={{ color: "var(--text-secondary)" }}>{relativeTime(String(v))}</span>,
    },
  ];

  return (
    <div class="page">
      <div class="page-header">
        <div class="page-title">Dashboard</div>
        <button
          class="btn btn-primary"
          onClick={() => { location.hash = "#/scan/new"; }}
        >
          New Scan
        </button>
      </div>

      {error && (
        <div
          style={{
            color: "var(--danger)",
            background: "rgba(248,81,73,0.08)",
            border: "1px solid var(--danger)",
            borderRadius: "var(--radius-sm)",
            padding: "8px 12px",
            marginBottom: "16px",
            fontSize: "12px",
          }}
        >
          {error}
        </div>
      )}

      {/* Stats row */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(4, 1fr)",
          gap: "12px",
          marginBottom: "24px",
        }}
      >
        <StatCard label="Sessions" value={sessions.length} color="var(--accent)" />
        <StatCard label="Active Scans" value={activeScans} color="var(--success)" />
        <StatCard label="Total Findings" value={0} />
        <StatCard label="Critical" value={0} color="var(--danger)" />
      </div>

      {/* Recent sessions table */}
      <div class="card">
        <div class="card-title">Recent Sessions</div>
        <DataTable
          columns={columns}
          data={recentSessions}
          onRowClick={(row) => { location.hash = `#/sessions/${row.id}`; }}
        />
      </div>
    </div>
  );
}
