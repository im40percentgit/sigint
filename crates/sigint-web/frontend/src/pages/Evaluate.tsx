/**
 * Evaluate — A/B evaluation diff page for fine-tuned model comparison.
 *
 * Two modes:
 *   1. No query params → form with base/candidate inputs + "Run Evaluation" button.
 *   2. ?base=&candidate= present → trigger evaluate, subscribe to WS progress
 *      events, then fetch + render the EvaluationReport diff table on completion.
 *
 * URL format: #/train/evaluate?base=<tag>&candidate=<tag>
 * Query params are parsed from window.location.href (raw URL) because hash
 * routing strips the search portion from window.location.search.
 *
 * Promote flow: "Promote candidate" opens ApprovalModal with the optional
 * warning banner and force checkbox when total_examples < MIN_EVAL_THRESHOLD
 * (10 examples), per Risk #4 in the Phase 26 plan.
 *
 * @decision DEC-P26-003
 * @title Evaluate page parses query params from raw href behind the hash fragment
 * @status accepted
 * @rationale Hash routing places the query string inside the fragment
 * (`#/train/evaluate?base=x&candidate=y`), so window.location.search is always
 * empty. Parsing the portion after `?` in window.location.href is the correct
 * approach for hash-routed SPAs; the alternative (encoding params as path
 * segments) would require more invasive routing changes.
 */

import { h } from "preact";
import { useState, useEffect, useCallback } from "preact/hooks";
import { api } from "../api";
import { wsManager } from "../ws";
import type { EvaluationReport, WsEvent } from "../types";
import { ApprovalModal } from "../components/ApprovalModal";

/** Minimum examples below which we show the Risk #4 warning. */
const MIN_EVAL_THRESHOLD = 10;

// ── Query-param helpers ────────────────────────────────────────────────────────

/**
 * Parse query params from a hash-routed URL.
 * e.g. "http://host/#/train/evaluate?base=foo&candidate=bar"
 * → { base: "foo", candidate: "bar" }
 */
function parseHashQuery(href: string): Record<string, string> {
  const qIdx = href.indexOf("?");
  if (qIdx === -1) return {};
  const search = href.slice(qIdx + 1);
  // Strip any trailing fragment that might appear after another #
  const fragIdx = search.indexOf("#");
  const qs = fragIdx === -1 ? search : search.slice(0, fragIdx);
  const params: Record<string, string> = {};
  for (const part of qs.split("&")) {
    const eqIdx = part.indexOf("=");
    if (eqIdx === -1) continue;
    const key = decodeURIComponent(part.slice(0, eqIdx));
    const val = decodeURIComponent(part.slice(eqIdx + 1));
    if (key) params[key] = val;
  }
  return params;
}

// ── Delta formatting ──────────────────────────────────────────────────────────

function formatPct(n: number): string {
  return (n * 100).toFixed(1) + "%";
}

function DeltaCell({ delta }: { delta: number }) {
  const sign = delta >= 0 ? "+" : "";
  const color = delta > 0 ? "var(--success)" : delta < 0 ? "var(--danger)" : "var(--text-secondary)";
  return (
    <td
      style={{
        padding: "8px 12px",
        borderBottom: "1px solid var(--border)",
        fontFamily: "var(--font-mono)",
        fontSize: "12px",
        fontWeight: 700,
        color,
      }}
    >
      {sign}{formatPct(delta)}
    </td>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

type EvalState =
  | { phase: "idle" }
  | { phase: "running"; evalId: string; done: number; total: number }
  | { phase: "done"; report: EvaluationReport }
  | { phase: "error"; message: string };

export function Evaluate() {
  // Parse current query params from the live URL (re-parse on each render is
  // cheap and ensures we catch navigations without a full page reload).
  const query = parseHashQuery(window.location.href);
  const initBase = query["base"] ?? "";
  const initCandidate = query["candidate"] ?? "";
  const hasParams = initBase !== "" && initCandidate !== "";

  const [baseTag, setBaseTag] = useState(initBase);
  const [candidateTag, setCandidateTag] = useState(initCandidate);
  const [evalState, setEvalState] = useState<EvalState>({ phase: "idle" });

  // Promote modal state
  const [modalOpen, setModalOpen] = useState(false);
  const [force, setForce] = useState(false);
  const [promoteError, setPromoteError] = useState<string | null>(null);
  const [promoted, setPromoted] = useState(false);

  // ── WebSocket subscription ────────────────────────────────────────────────

  useEffect(() => {
    const unsub = wsManager.subscribe((event: WsEvent) => {
      if (event.type === "evaluation_started") {
        setEvalState({
          phase: "running",
          evalId: event.data.eval_id,
          done: 0,
          total: event.data.total_examples,
        });
      } else if (event.type === "evaluation_progress") {
        setEvalState(prev =>
          prev.phase === "running"
            ? { ...prev, done: event.data.examples_done }
            : prev
        );
      } else if (event.type === "evaluation_completed") {
        // Fetch the full report now that the backend has written it.
        api.train.lastEvaluation()
          .then(report => setEvalState({ phase: "done", report }))
          .catch(err => setEvalState({ phase: "error", message: String(err) }));
      }
    });
    return unsub;
  }, []);

  // ── Trigger evaluation on mount when params are present ───────────────────

  useEffect(() => {
    if (!hasParams) return;
    if (evalState.phase !== "idle") return;

    // Attempt to load the last evaluation first — if it matches our tags we can
    // show it immediately without re-running.
    api.train.lastEvaluation()
      .then(report => {
        if (report.base_tag === initBase && report.candidate_tag === initCandidate) {
          setEvalState({ phase: "done", report });
        } else {
          triggerEval(initBase, initCandidate);
        }
      })
      .catch(() => {
        // No prior report — trigger fresh evaluation.
        triggerEval(initBase, initCandidate);
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []); // only on mount

  // ── Helpers ───────────────────────────────────────────────────────────────

  function triggerEval(base: string, candidate: string) {
    setEvalState({ phase: "running", evalId: "", done: 0, total: 0 });
    api.train.evaluate({ base, candidate })
      .catch(err => setEvalState({ phase: "error", message: String(err) }));
  }

  function handleRunEval() {
    if (!baseTag.trim() || !candidateTag.trim()) return;
    // Navigate to the parameterised URL so the page is bookmarkable.
    window.location.hash = `#/train/evaluate?base=${encodeURIComponent(baseTag)}&candidate=${encodeURIComponent(candidateTag)}`;
    setForce(false);
    setPromoted(false);
    setPromoteError(null);
    triggerEval(baseTag.trim(), candidateTag.trim());
  }

  const handlePromoteConfirm = useCallback(() => {
    if (evalState.phase !== "done") return;
    const tag = evalState.report.candidate_tag;
    api.model.promote({ tag, force })
      .then(() => {
        setModalOpen(false);
        setPromoted(true);
        setPromoteError(null);
      })
      .catch(err => {
        setModalOpen(false);
        setPromoteError(String(err));
      });
  }, [evalState, force]);

  // ── Render: form (no params) ─────────────────────────────────────────────

  if (!hasParams && evalState.phase === "idle") {
    return (
      <div class="page">
        <div class="page-title">Evaluate Models</div>
        <p style={{ color: "var(--text-secondary)", fontSize: "12px", marginBottom: "24px" }}>
          Compare a base model against a fine-tuned candidate on the harvested evaluation set.
        </p>
        <div class="card" style={{ maxWidth: "480px" }}>
          <div class="card-title">Run A/B Evaluation</div>
          <div class="form-group">
            <label>Base model tag</label>
            <input
              type="text"
              value={baseTag}
              onInput={(e) => setBaseTag((e.target as HTMLInputElement).value)}
              placeholder="e.g. llama3.2:8b"
              style={{ width: "100%" }}
            />
          </div>
          <div class="form-group">
            <label>Candidate model tag</label>
            <input
              type="text"
              value={candidateTag}
              onInput={(e) => setCandidateTag((e.target as HTMLInputElement).value)}
              placeholder="e.g. sigint-ft:latest"
              style={{ width: "100%" }}
            />
          </div>
          <button
            class="btn btn-primary"
            onClick={handleRunEval}
            disabled={!baseTag.trim() || !candidateTag.trim()}
          >
            Run Evaluation
          </button>
        </div>
      </div>
    );
  }

  // ── Render: running ──────────────────────────────────────────────────────

  if (evalState.phase === "running") {
    const { done, total } = evalState;
    const pct = total > 0 ? Math.round((done / total) * 100) : 0;
    return (
      <div class="page">
        <div class="page-title">Evaluating…</div>
        <div class="card" style={{ maxWidth: "480px" }}>
          <div style={{ fontSize: "12px", color: "var(--text-secondary)", marginBottom: "12px" }}>
            Running A/B evaluation: <code style={{ color: "var(--accent)" }}>{baseTag}</code>
            {" "} vs <code style={{ color: "var(--accent)" }}>{candidateTag}</code>
          </div>
          {total > 0 && (
            <div style={{ marginBottom: "8px" }}>
              <div style={{
                background: "var(--bg)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-sm)",
                height: "8px",
                overflow: "hidden",
              }}>
                <div style={{
                  height: "100%",
                  width: `${pct}%`,
                  background: "var(--accent)",
                  transition: "width 300ms ease",
                }} />
              </div>
              <div style={{ fontSize: "11px", color: "var(--text-secondary)", marginTop: "4px" }}>
                {done} / {total} examples ({pct}%)
              </div>
            </div>
          )}
          {total === 0 && (
            <div style={{ fontSize: "11px", color: "var(--text-secondary)" }}>
              Starting evaluation…
            </div>
          )}
        </div>
      </div>
    );
  }

  // ── Render: error ────────────────────────────────────────────────────────

  if (evalState.phase === "error") {
    return (
      <div class="page">
        <div class="page-title">Evaluation Failed</div>
        <div class="card" style={{ borderColor: "var(--danger)", maxWidth: "480px" }}>
          <div style={{ color: "var(--danger)", fontSize: "12px" }}>{evalState.message}</div>
          <div style={{ marginTop: "12px" }}>
            <button class="btn" onClick={() => setEvalState({ phase: "idle" })}>
              Try Again
            </button>
          </div>
        </div>
      </div>
    );
  }

  // ── Render: done — diff table ────────────────────────────────────────────

  if (evalState.phase !== "done") return null;
  const { report } = evalState;

  const isSmallSample = report.total_examples < MIN_EVAL_THRESHOLD;
  const warningText = isSmallSample
    ? `Only ${report.total_examples} evaluation examples — below the ${MIN_EVAL_THRESHOLD}-sample threshold. Model quality is not guaranteed.`
    : undefined;

  const promoteRationale = `Δ tool-accuracy: ${report.tool_accuracy_delta >= 0 ? "+" : ""}${formatPct(report.tool_accuracy_delta)}, Δ argument-match: ${report.argument_match_delta >= 0 ? "+" : ""}${formatPct(report.argument_match_delta)}. Promotes ${report.base_tag} → ${report.candidate_tag}.`;

  return (
    <div class="page">
      <div class="page-title">Evaluation Results</div>

      {/* Header meta */}
      <div
        style={{
          display: "flex",
          gap: "24px",
          alignItems: "center",
          marginBottom: "20px",
          flexWrap: "wrap",
        }}
      >
        <div style={{ fontSize: "12px" }}>
          <span style={{ color: "var(--text-secondary)" }}>Base: </span>
          <code style={{ color: "var(--text)", fontFamily: "var(--font-mono)" }}>{report.base_tag}</code>
        </div>
        <div style={{ fontSize: "12px" }}>
          <span style={{ color: "var(--text-secondary)" }}>Candidate: </span>
          <code style={{ color: "var(--accent)", fontFamily: "var(--font-mono)" }}>{report.candidate_tag}</code>
        </div>
        <div style={{ fontSize: "12px" }}>
          <span style={{ color: "var(--text-secondary)" }}>Examples: </span>
          <span style={{ color: report.total_examples < MIN_EVAL_THRESHOLD ? "var(--warning)" : "var(--text)" }}>
            {report.total_examples}
          </span>
        </div>
        <div style={{ fontSize: "12px", color: "var(--text-secondary)" }}>
          {new Date(report.evaluated_at).toLocaleString()}
        </div>
      </div>

      {/* Small-sample warning above the table */}
      {isSmallSample && (
        <div
          style={{
            background: "rgba(240,136,62,0.10)",
            border: "1px solid var(--warning)",
            borderRadius: "var(--radius-sm)",
            padding: "10px 12px",
            fontSize: "12px",
            color: "var(--warning)",
            marginBottom: "16px",
          }}
        >
          {warningText}
        </div>
      )}

      {/* Diff table */}
      <div class="card" style={{ marginBottom: "16px", overflowX: "auto" }}>
        <div class="card-title">Metric Comparison</div>
        <table style={{ minWidth: "500px" }}>
          <thead>
            <tr>
              <th style={{ textAlign: "left" }}>Metric</th>
              <th>Base ({report.base_tag})</th>
              <th>Candidate ({report.candidate_tag})</th>
              <th>Delta</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td style={{ padding: "8px 12px", borderBottom: "1px solid var(--border)", fontSize: "12px", fontWeight: 600 }}>
                Tool Accuracy
              </td>
              <td style={{ padding: "8px 12px", borderBottom: "1px solid var(--border)", fontSize: "12px", fontFamily: "var(--font-mono)", textAlign: "center" }}>
                {formatPct(report.base_results.tool_accuracy)}
              </td>
              <td style={{ padding: "8px 12px", borderBottom: "1px solid var(--border)", fontSize: "12px", fontFamily: "var(--font-mono)", textAlign: "center" }}>
                {formatPct(report.candidate_results.tool_accuracy)}
              </td>
              <DeltaCell delta={report.tool_accuracy_delta} />
            </tr>
            <tr>
              <td style={{ padding: "8px 12px", borderBottom: "1px solid var(--border)", fontSize: "12px", fontWeight: 600 }}>
                Argument Match
              </td>
              <td style={{ padding: "8px 12px", borderBottom: "1px solid var(--border)", fontSize: "12px", fontFamily: "var(--font-mono)", textAlign: "center" }}>
                {formatPct(report.base_results.argument_accuracy)}
              </td>
              <td style={{ padding: "8px 12px", borderBottom: "1px solid var(--border)", fontSize: "12px", fontFamily: "var(--font-mono)", textAlign: "center" }}>
                {formatPct(report.candidate_results.argument_accuracy)}
              </td>
              <DeltaCell delta={report.argument_match_delta} />
            </tr>
            <tr>
              <td style={{ padding: "8px 12px", fontSize: "12px", color: "var(--text-secondary)" }}>
                Total examples
              </td>
              <td style={{ padding: "8px 12px", fontSize: "12px", fontFamily: "var(--font-mono)", textAlign: "center", color: "var(--text-secondary)" }}>
                {report.base_results.total_examples}
              </td>
              <td style={{ padding: "8px 12px", fontSize: "12px", fontFamily: "var(--font-mono)", textAlign: "center", color: "var(--text-secondary)" }}>
                {report.candidate_results.total_examples}
              </td>
              <td style={{ padding: "8px 12px", fontSize: "12px", color: "var(--text-secondary)", textAlign: "center" }}>
                —
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      {/* Promote button + feedback */}
      {promoted ? (
        <div style={{ color: "var(--success)", fontSize: "13px" }}>
          Candidate promoted to active model.{" "}
          <a href="#/models" style={{ color: "var(--accent)" }}>View promotion history</a>
        </div>
      ) : (
        <div style={{ display: "flex", alignItems: "center", gap: "12px", flexWrap: "wrap" }}>
          <button
            class="btn btn-primary"
            onClick={() => {
              setForce(false);
              setModalOpen(true);
            }}
          >
            Promote candidate
          </button>
          <button
            class="btn"
            onClick={() => {
              setEvalState({ phase: "idle" });
              window.location.hash = "#/train/evaluate";
            }}
          >
            Run new evaluation
          </button>
          {promoteError && (
            <span style={{ fontSize: "12px", color: "var(--danger)" }}>{promoteError}</span>
          )}
        </div>
      )}

      {/* Approval modal — opened by "Promote candidate" */}
      {modalOpen && (
        <ApprovalModal
          requestId={report.candidate_tag}
          tier="PROMOTE"
          rationale={promoteRationale}
          warning={warningText}
          extraField={
            isSmallSample
              ? {
                  type: "checkbox",
                  label: "Force promotion despite small sample (acknowledges Risk #4)",
                  required: true,
                  checked: force,
                  onChange: setForce,
                }
              : undefined
          }
          onApprove={handlePromoteConfirm}
          onDeny={() => setModalOpen(false)}
        />
      )}
    </div>
  );
}
