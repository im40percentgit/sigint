/**
 * Models — active model status + promotion history + rollback UI.
 *
 * Sections:
 *   1. Active Model — fetches /api/health to surface provider + model name
 *      (same shape as Settings.tsx, avoids a dedicated config endpoint).
 *   2. Promotion History — api.model.promotions() renders chronological log
 *      with action badges (promote / rollback), old→new model columns, and an
 *      eval_result_ref link when present.
 *   3. Rollback button — ONLY visible on the most-recent "promote" entry.
 *      Older entries and "rollback" entries do not show the button.  Rollback
 *      opens ApprovalModal with tier="ROLLBACK".
 *
 * @decision DEC-P26-006
 * @title Models page uses /api/health for active-model data — no new endpoint
 * @status accepted
 * @rationale The /api/health endpoint already exposes `llm.provider` and
 * `llm.model`; adding a dedicated /api/model/active endpoint solely for display
 * would add Rust surface with no behavioral difference.  The Settings page uses
 * the same pattern; mirroring it keeps the two pages consistent and avoids
 * endpoint proliferation.  The rollback-only-on-most-recent rule is enforced
 * in the UI layer — the backend allows rollback at any time, so it is strictly
 * a UX safety guard (prevents cascading multi-rollbacks via accidental clicks).
 */

import { h } from "preact";
import { useState, useEffect, useCallback } from "preact/hooks";
import { api } from "../api";
import type { PromotionEntry, ModelSwapResult } from "../types";
import { ApprovalModal } from "../components/ApprovalModal";

// ── HealthResponse (same shape as Settings.tsx) ───────────────────────────────

interface HealthResponse {
  status: string;
  llm?: {
    provider?: string;
    model?: string;
    base_url?: string;
  };
}

// ── Action badge ──────────────────────────────────────────────────────────────

function ActionBadge({ action }: { action: PromotionEntry["action"] }) {
  const isPromote = action === "promote";
  return (
    <span
      class="badge"
      style={{
        background: isPromote ? "rgba(63,185,80,0.12)" : "rgba(240,136,62,0.12)",
        border: `1px solid ${isPromote ? "var(--success)" : "var(--warning)"}`,
        color: isPromote ? "var(--success)" : "var(--warning)",
      }}
    >
      {action}
    </span>
  );
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

// ── Main component ────────────────────────────────────────────────────────────

export function Models() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthLoading, setHealthLoading] = useState(true);

  const [promotions, setPromotions] = useState<PromotionEntry[]>([]);
  const [promosLoading, setPromosLoading] = useState(true);
  const [promosError, setPromosError] = useState<string | null>(null);

  // Rollback modal state
  const [rollbackOpen, setRollbackOpen] = useState(false);
  const [rollbackError, setRollbackError] = useState<string | null>(null);
  const [rollbackResult, setRollbackResult] = useState<ModelSwapResult | null>(null);

  // ── Data fetch on mount ───────────────────────────────────────────────────

  useEffect(() => {
    fetch("/api/health")
      .then(r => r.json() as Promise<HealthResponse>)
      .then(h => {
        setHealth(h);
        setHealthLoading(false);
      })
      .catch(() => {
        setHealth({ status: "unreachable" });
        setHealthLoading(false);
      });

    api.model.promotions()
      .then(entries => {
        setPromotions(entries);
        setPromosLoading(false);
      })
      .catch(err => {
        setPromosError(String(err));
        setPromosLoading(false);
      });
  }, []);

  // Reload promotions after a rollback completes.
  function reloadPromotions() {
    setPromosLoading(true);
    api.model.promotions()
      .then(entries => {
        setPromotions(entries);
        setPromosLoading(false);
      })
      .catch(err => {
        setPromosError(String(err));
        setPromosLoading(false);
      });
  }

  // ── Determine which entry gets the rollback button ────────────────────────
  //
  // The rollback button appears ONLY on the most-recent "promote" entry.
  // We find the index of the first entry (newest-first from the API) whose
  // action is "promote".

  const mostRecentPromoteIdx = promotions.findIndex(e => e.action === "promote");

  // ── Rollback handler ──────────────────────────────────────────────────────

  const rollbackEntry = mostRecentPromoteIdx >= 0
    ? promotions[mostRecentPromoteIdx]
    : null;

  const rollbackRationale = rollbackEntry
    ? `Revert to ${rollbackEntry.old_model} (${rollbackEntry.old_provider}). Undoes promotion of ${rollbackEntry.new_model}.`
    : "";

  const handleRollbackConfirm = useCallback(() => {
    api.model.rollback()
      .then(result => {
        setRollbackOpen(false);
        setRollbackResult(result);
        setRollbackError(null);
        // Reload history so the new rollback entry appears.
        reloadPromotions();
        // Also refresh health so the active model display updates.
        fetch("/api/health")
          .then(r => r.json() as Promise<HealthResponse>)
          .then(h => setHealth(h))
          .catch(() => {});
      })
      .catch(err => {
        setRollbackOpen(false);
        setRollbackError(String(err));
      });
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div class="page">
      <div class="page-title">Models</div>

      {/* Active Model */}
      <div class="card" style={{ marginBottom: "16px" }}>
        <div class="card-title">Active Model</div>

        {healthLoading ? (
          <div style={{ color: "var(--text-secondary)", fontSize: "12px" }}>Loading…</div>
        ) : (
          <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "12px", padding: "8px 0", borderBottom: "1px solid var(--border)", fontSize: "12px" }}>
              <span style={{ color: "var(--text-secondary)", width: "80px", flexShrink: 0 }}>Provider</span>
              <code style={{ fontFamily: "var(--font-mono)", color: "var(--accent)" }}>
                {health?.llm?.provider ?? "ollama"}
              </code>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: "12px", padding: "8px 0", fontSize: "12px" }}>
              <span style={{ color: "var(--text-secondary)", width: "80px", flexShrink: 0 }}>Model</span>
              <code style={{ fontFamily: "var(--font-mono)", color: "var(--accent)" }}>
                {health?.llm?.model ?? "—"}
              </code>
            </div>
          </div>
        )}
      </div>

      {/* Rollback feedback */}
      {rollbackResult && (
        <div
          style={{
            background: "rgba(63,185,80,0.10)",
            border: "1px solid var(--success)",
            borderRadius: "var(--radius-sm)",
            padding: "10px 12px",
            fontSize: "12px",
            color: "var(--success)",
            marginBottom: "16px",
          }}
        >
          Rolled back: {rollbackResult.old_model} → {rollbackResult.new_model}
        </div>
      )}
      {rollbackError && (
        <div
          style={{
            background: "rgba(248,81,73,0.10)",
            border: "1px solid var(--danger)",
            borderRadius: "var(--radius-sm)",
            padding: "10px 12px",
            fontSize: "12px",
            color: "var(--danger)",
            marginBottom: "16px",
          }}
        >
          Rollback failed: {rollbackError}
        </div>
      )}

      {/* Promotion History */}
      <div class="card">
        <div class="card-title">
          Promotion History{" "}
          {!promosLoading && (
            <span style={{ fontSize: "10px", color: "var(--text-secondary)", fontWeight: 400, textTransform: "none", letterSpacing: 0 }}>
              ({promotions.length})
            </span>
          )}
        </div>

        {promosLoading && (
          <div style={{ color: "var(--text-secondary)", fontSize: "12px" }}>Loading…</div>
        )}

        {promosError && (
          <div style={{ color: "var(--danger)", fontSize: "12px" }}>{promosError}</div>
        )}

        {!promosLoading && !promosError && promotions.length === 0 && (
          <div style={{ color: "var(--text-secondary)", fontSize: "12px" }}>
            No promotions yet. Run an evaluation and promote a candidate.
          </div>
        )}

        {!promosLoading && !promosError && promotions.length > 0 && (
          <div style={{ overflowX: "auto" }}>
            <table style={{ minWidth: "680px" }}>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Action</th>
                  <th>Old Model</th>
                  <th>New Model</th>
                  <th>Eval Ref</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {promotions.map((entry, idx) => {
                  const isRollbackTarget = idx === mostRecentPromoteIdx;
                  return (
                    <tr key={`${entry.ts}-${idx}`}>
                      <td style={{ padding: "8px 12px", borderBottom: "1px solid var(--border)", fontSize: "11px", color: "var(--text-secondary)", whiteSpace: "nowrap" }}>
                        {fmtDate(entry.ts)}
                      </td>
                      <td style={{ padding: "8px 12px", borderBottom: "1px solid var(--border)" }}>
                        <ActionBadge action={entry.action} />
                      </td>
                      <td style={{ padding: "8px 12px", borderBottom: "1px solid var(--border)", fontSize: "12px", fontFamily: "var(--font-mono)" }}>
                        <span style={{ color: "var(--text-secondary)", fontSize: "10px" }}>
                          {entry.old_provider}/
                        </span>
                        {entry.old_model}
                      </td>
                      <td style={{ padding: "8px 12px", borderBottom: "1px solid var(--border)", fontSize: "12px", fontFamily: "var(--font-mono)" }}>
                        <span style={{ color: "var(--text-secondary)", fontSize: "10px" }}>
                          {entry.new_provider}/
                        </span>
                        {entry.new_model}
                      </td>
                      <td style={{ padding: "8px 12px", borderBottom: "1px solid var(--border)", fontSize: "11px" }}>
                        {entry.eval_result_ref ? (
                          <code style={{ color: "var(--accent)", fontFamily: "var(--font-mono)", fontSize: "11px" }}>
                            {entry.eval_result_ref}
                          </code>
                        ) : (
                          <span style={{ color: "var(--text-secondary)" }}>—</span>
                        )}
                      </td>
                      <td style={{ padding: "8px 12px", borderBottom: "1px solid var(--border)" }}>
                        {isRollbackTarget ? (
                          <button
                            class="btn btn-sm btn-danger"
                            onClick={() => {
                              setRollbackError(null);
                              setRollbackResult(null);
                              setRollbackOpen(true);
                            }}
                          >
                            Rollback
                          </button>
                        ) : (
                          <span />
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Rollback approval modal */}
      {rollbackOpen && rollbackEntry && (
        <ApprovalModal
          requestId={`rollback-${rollbackEntry.ts}`}
          tier="ROLLBACK"
          rationale={rollbackRationale}
          onApprove={handleRollbackConfirm}
          onDeny={() => setRollbackOpen(false)}
        />
      )}
    </div>
  );
}
