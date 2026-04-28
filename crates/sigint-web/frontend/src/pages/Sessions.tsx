/**
 * Sessions — full list of all sessions with a trainable toggle column.
 *
 * Fetches all sessions on mount and renders them in a DataTable.
 * The "Harvest" column shows a per-row toggle that calls api.train.harvest /
 * unharvest. Optimistic UI: the row flips immediately; on error the flip
 * reverts and an inline error banner is shown.
 *
 * Bulk-harvest: when ≥1 row is selected via the DataTable row-selection
 * primitive, a sticky action bar appears at the bottom of the table offering
 * "Harvest selected" and "Unharvest selected" buttons. Calls are dispatched
 * in parallel (Promise.allSettled) so a single failure never blocks the rest.
 *
 * @decision DEC-P26-T5-001
 * @title Sessions page uses optimistic toggle with revert-on-error
 * @status accepted
 * @rationale Harvest/unharvest operations are fast (single SQLite UPDATE).
 * Optimistic UI avoids a perceived lag on the toggle while still being safe:
 * any backend error (network, 404) reverts the row to its pre-click state and
 * surfaces a banner. The banner is dismissed on the next successful action or
 * on manual close, keeping the UI uncluttered for the happy path.
 *
 * @decision REQ-P26-P1-002-bulk
 * @title Bulk harvest uses Promise.allSettled + frontend loop (option a)
 * @status accepted
 * @rationale For typical N < 50 sessions the per-request overhead is under
 * 100 ms each against a local SQLite backend. Adding a batch endpoint would
 * require a new route, handler, and backend tests for negligible UX gain.
 * Promise.allSettled is preferred over Promise.all so a single failure
 * (e.g. one session no longer exists) does not cancel the rest. The caller
 * receives a full success/failure breakdown and surfaces a clear count banner.
 */

import { h } from "preact";
import { useState, useEffect, useCallback } from "preact/hooks";
import { api } from "../api";
import type { Session } from "../types";
import { DataTable } from "../components/DataTable";
import type { Column, RowSelectionProps } from "../components/DataTable";

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

// ── Bulk-action bar ────────────────────────────────────────────────────────

interface BulkActionBarProps {
  selectedCount: number;
  allHarvested: boolean;
  bulkPending: boolean;
  onHarvest: () => void;
  onUnharvest: () => void;
  onClear: () => void;
}

function BulkActionBar({
  selectedCount,
  allHarvested,
  bulkPending,
  onHarvest,
  onUnharvest,
  onClear,
}: BulkActionBarProps) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        gap: "12px",
        padding: "10px 14px",
        marginTop: "8px",
        background: "var(--bg-elevated, var(--card-bg, #161b22))",
        border: "1px solid var(--accent)",
        borderRadius: "var(--radius-sm)",
        fontSize: "12px",
        flexWrap: "wrap",
      }}
      role="toolbar"
      aria-label="Bulk session actions"
    >
      <span style={{ color: "var(--text)", fontWeight: 600 }}>
        {selectedCount} session{selectedCount !== 1 ? "s" : ""} selected
      </span>

      <div style={{ display: "flex", gap: "8px", marginLeft: "auto" }}>
        <button
          class="btn btn-primary"
          style={{ fontSize: "12px", padding: "4px 10px" }}
          disabled={bulkPending}
          onClick={onHarvest}
          title="Add all selected sessions to the harvest pool"
        >
          {bulkPending ? "Working…" : "Harvest selected"}
        </button>

        {allHarvested && (
          <button
            class="btn"
            style={{
              fontSize: "12px",
              padding: "4px 10px",
              background: "none",
              border: "1px solid var(--border)",
              color: "var(--text-secondary)",
            }}
            disabled={bulkPending}
            onClick={onUnharvest}
            title="Remove all selected sessions from the harvest pool"
          >
            Unharvest selected
          </button>
        )}

        <button
          class="btn"
          style={{
            fontSize: "12px",
            padding: "4px 10px",
            background: "none",
            border: "1px solid var(--border)",
            color: "var(--text-secondary)",
          }}
          disabled={bulkPending}
          onClick={onClear}
          aria-label="Clear selection"
          title="Clear selection"
        >
          Clear selection
        </button>
      </div>
    </div>
  );
}

// ── Main component ─────────────────────────────────────────────────────────

export function Sessions() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // Track which session IDs have an in-flight per-row toggle request
  const [pending, setPending] = useState<Set<string>>(new Set());

  // Bulk-selection state (controlled by this component, passed into DataTable)
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [bulkPending, setBulkPending] = useState(false);
  const [bulkResult, setBulkResult] = useState<string | null>(null);

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

  // ── Per-row toggle ──────────────────────────────────────────────────────

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

  // ── Bulk harvest / unharvest ────────────────────────────────────────────

  const handleBulkAction = useCallback(
    async (targetValue: boolean) => {
      if (selectedIds.size === 0) return;
      setBulkPending(true);
      setBulkResult(null);
      setError(null);

      const ids = Array.from(selectedIds);

      // Optimistic: flip all selected rows immediately
      setSessions((prev) =>
        prev.map((s) =>
          selectedIds.has(s.id) ? { ...s, trainable: targetValue } : s
        )
      );

      // Fire all requests in parallel; allSettled so one failure doesn't abort others
      const results = await Promise.allSettled(
        ids.map((id) =>
          targetValue ? api.train.harvest(id) : api.train.unharvest(id)
        )
      );

      // Collect failed IDs and their error messages in a single pass
      const failedIds = new Set<string>();
      const failureMessages: string[] = [];
      results.forEach((r, idx) => {
        if (r.status === "rejected") {
          failedIds.add(ids[idx]);
          const msg =
            r.reason instanceof Error ? r.reason.message : String(r.reason);
          failureMessages.push(`${ids[idx].slice(0, 8)}: ${msg}`);
        }
      });

      const successCount = results.length - failedIds.size;

      if (failedIds.size > 0) {
        // Revert only the rows whose requests failed
        setSessions((prev) =>
          prev.map((s) =>
            failedIds.has(s.id) ? { ...s, trainable: !targetValue } : s
          )
        );
        setError(
          `${successCount} of ${ids.length} succeeded; ${failedIds.size} failed: ${failureMessages.join(", ")}`
        );
      } else {
        const verb = targetValue ? "Harvested" : "Unharvested";
        setBulkResult(`${verb} ${successCount} session${successCount !== 1 ? "s" : ""}`);
      }

      setSelectedIds(new Set());
      setBulkPending(false);
    },
    [selectedIds]
  );

  // ── Derived state for bulk bar ──────────────────────────────────────────

  // "Unharvest selected" only shown when ALL selected rows are currently trainable
  const allSelectedHarvested =
    selectedIds.size > 0 &&
    Array.from(selectedIds).every(
      (id) => sessions.find((s) => s.id === id)?.trainable === true
    );

  // ── Row selection config ────────────────────────────────────────────────

  const rowSelection: RowSelectionProps<Session> = {
    selectedIds,
    onChange: setSelectedIds,
    getRowId: (row) => row.id,
  };

  // ── Columns ──────────────────────────────────────────────────────────────

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

  // ── Render ──────────────────────────────────────────────────────────────

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

      {bulkResult && (
        <div
          style={{
            color: "var(--success)",
            background: "rgba(63,185,80,0.08)",
            border: "1px solid var(--success)",
            borderRadius: "var(--radius-sm)",
            padding: "8px 12px",
            marginBottom: "16px",
            fontSize: "12px",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
          }}
        >
          <span>{bulkResult}</span>
          <button
            style={{
              background: "none",
              border: "none",
              color: "var(--success)",
              cursor: "pointer",
              fontSize: "14px",
              padding: "0 4px",
            }}
            onClick={() => setBulkResult(null)}
            aria-label="Dismiss"
          >
            ×
          </button>
        </div>
      )}

      {loading ? (
        <p style={{ color: "var(--text-secondary)" }}>Loading sessions…</p>
      ) : (
        <>
          <DataTable
            columns={columns}
            data={sessions}
            rowSelection={rowSelection}
            onRowClick={(row) => {
              window.location.hash = `#/sessions/${row.id}`;
            }}
          />
          {selectedIds.size > 0 && (
            <BulkActionBar
              selectedCount={selectedIds.size}
              allHarvested={allSelectedHarvested}
              bulkPending={bulkPending}
              onHarvest={() => void handleBulkAction(true)}
              onUnharvest={() => void handleBulkAction(false)}
              onClear={() => setSelectedIds(new Set())}
            />
          )}
        </>
      )}
    </div>
  );
}
