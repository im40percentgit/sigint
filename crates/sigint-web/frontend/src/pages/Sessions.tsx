/**
 * Sessions — full list of all sessions with a trainable toggle column.
 *
 * Fetches all sessions on mount and renders them in a DataTable.
 * The "Harvest" column shows a toggle that calls api.train.harvest / unharvest.
 * Optimistic UI: the row flips immediately; on error the flip reverts and an
 * inline error banner is shown.
 *
 * @decision DEC-P26-T5-001
 * @title Sessions page uses optimistic toggle with revert-on-error
 * @status accepted
 * @rationale Harvest/unharvest operations are fast (single SQLite UPDATE).
 * Optimistic UI avoids a perceived lag on the toggle while still being safe:
 * any backend error (network, 404) reverts the row to its pre-click state and
 * surfaces a banner. The banner is dismissed on the next successful action or
 * on manual close, keeping the UI uncluttered for the happy path.
 */

import { h } from "preact";
import { useState, useEffect, useCallback } from "preact/hooks";
import { api } from "../api";
import type { Session } from "../types";
import { DataTable } from "../components/DataTable";
import type { Column } from "../components/DataTable";

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

// ── Toggle cell component ──────────────────────────────────────────────────

interface HarvestToggleProps {
  session: Session;
  onToggle: (id: string, newValue: boolean) => Promise<void>;
  pending: boolean;
}

function HarvestToggle({ session, onToggle, pending }: HarvestToggleProps) {
  return (
    <label
      title={
        session.trainable
          ? "Remove from harvest pool"
          : "Add to harvest pool"
      }
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: "6px",
        cursor: pending ? "wait" : "pointer",
        opacity: pending ? 0.5 : 1,
        userSelect: "none",
      }}
      onClick={(e) => {
        // Stop row-click propagation so we don't navigate to SessionDetail
        e.stopPropagation();
      }}
    >
      <input
        type="checkbox"
        checked={session.trainable}
        disabled={pending}
        style={{ accentColor: "var(--accent)", cursor: "inherit" }}
        onChange={(e) => {
          e.stopPropagation();
          void onToggle(session.id, (e.target as HTMLInputElement).checked);
        }}
      />
      <span
        style={{
          fontSize: "11px",
          color: session.trainable ? "var(--accent)" : "var(--text-secondary)",
          fontWeight: session.trainable ? 600 : 400,
        }}
      >
        {session.trainable ? "Yes" : "No"}
      </span>
    </label>
  );
}

// ── Main component ─────────────────────────────────────────────────────────

export function Sessions() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // Track which session IDs have an in-flight toggle request
  const [pending, setPending] = useState<Set<string>>(new Set());

  useEffect(() => {
    setLoading(true);
    api.sessions
      .list()
      .then((data) => {
        setSessions(data);
        setLoading(false);
      })
      .catch((e: Error) => {
        setError(e.message);
        setLoading(false);
      });
  }, []);

  const handleToggle = useCallback(
    async (sessionId: string, newValue: boolean) => {
      // Optimistic update
      setSessions((prev) =>
        prev.map((s) =>
          s.id === sessionId ? { ...s, trainable: newValue } : s
        )
      );
      setPending((prev) => new Set(prev).add(sessionId));

      try {
        if (newValue) {
          await api.train.harvest(sessionId);
        } else {
          await api.train.unharvest(sessionId);
        }
      } catch (e: unknown) {
        // Revert on error
        setSessions((prev) =>
          prev.map((s) =>
            s.id === sessionId ? { ...s, trainable: !newValue } : s
          )
        );
        const msg = e instanceof Error ? e.message : String(e);
        setError(`Failed to update harvest status: ${msg}`);
      } finally {
        setPending((prev) => {
          const next = new Set(prev);
          next.delete(sessionId);
          return next;
        });
      }
    },
    []
  );

  const columns: Column<Session>[] = [
    {
      key: "id",
      label: "ID",
      render: (v) => (
        <code style={{ fontSize: "11px" }}>{String(v).slice(0, 8)}</code>
      ),
    },
    { key: "target", label: "Target" },
    {
      key: "status",
      label: "Status",
      render: (v) => {
        const s = String(v);
        const color =
          s === "active"
            ? "var(--success)"
            : s === "failed"
            ? "var(--danger)"
            : "var(--text-secondary)";
        return (
          <span style={{ color, fontWeight: 600 }}>
            {s}
          </span>
        );
      },
    },
    {
      key: "created_at",
      label: "Created",
      render: (v) => (
        <span style={{ color: "var(--text-secondary)" }}>
          {relativeTime(String(v))}
        </span>
      ),
    },
    {
      key: "trainable",
      label: "Harvest",
      headerTitle:
        "Enables this session's scan history for fine-tune export. Data may contain PII — review before sharing.",
      render: (_v, row) => (
        <HarvestToggle
          session={row}
          onToggle={handleToggle}
          pending={pending.has(row.id)}
        />
      ),
    },
  ];

  return (
    <div class="page">
      <div class="page-header">
        <div class="page-title">Sessions</div>
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
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <span>{error}</span>
          <button
            style={{
              background: "none",
              border: "none",
              color: "var(--danger)",
              cursor: "pointer",
              fontSize: "14px",
              padding: "0 4px",
            }}
            onClick={() => setError(null)}
            aria-label="Dismiss error"
          >
            ×
          </button>
        </div>
      )}

      {loading ? (
        <p style={{ color: "var(--text-secondary)" }}>Loading sessions…</p>
      ) : (
        <DataTable
          columns={columns}
          data={sessions}
          onRowClick={(row) => {
            window.location.hash = `#/sessions/${row.id}`;
          }}
        />
      )}
    </div>
  );
}
