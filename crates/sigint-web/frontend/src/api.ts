/**
 * Typed fetch wrappers for the SIGINT REST API.
 *
 * All requests target the same origin at base path /api. Returns typed
 * Promises — callers receive domain objects directly, not raw Response.
 * Errors throw with a message string extracted from the JSON body when
 * available, or the HTTP status text otherwise.
 *
 * @decision DEC-WEB-022
 * @title Hash-based SPA routing via window.location.hash and hashchange event
 * @status accepted
 * @rationale Hash routing requires no server-side route configuration — the
 * static file server's SPA fallback (serve index.html for unknown paths)
 * already handles all routes; hashchange + useState provides a clean reactive
 * routing model in Preact without a router library dependency.
 */

import type {
  Session,
  Finding,
  Asset,
  ScanRecord,
  DiffResult,
  StartScanParams,
  ReportFormat,
  ModelInfo,
  TrainStats,
  ExportResult,
  TrainingJob,
  EvaluationReport,
  PromotionEntry,
  ModelSwapResult,
} from "./types";

const BASE = "/api";

// ── Helpers ────────────────────────────────────────────────────────────────

async function request<T>(
  method: string,
  path: string,
  body?: unknown
): Promise<T> {
  const init: RequestInit = { method };
  if (body !== undefined) {
    init.headers = { "Content-Type": "application/json" };
    init.body = JSON.stringify(body);
  }
  const res = await fetch(`${BASE}${path}`, init);
  if (!res.ok) {
    let msg = res.statusText;
    try {
      const json = await res.json();
      msg = json.error ?? json.message ?? msg;
    } catch {
      // ignore parse errors — use statusText
    }
    throw new Error(`${res.status} ${msg}`);
  }
  // 204 No Content — return undefined cast as T
  if (res.status === 204) return undefined as unknown as T;
  return res.json() as Promise<T>;
}

function get<T>(path: string): Promise<T> {
  return request<T>("GET", path);
}

function post<T>(path: string, body?: unknown): Promise<T> {
  return request<T>("POST", path, body);
}

function del<T>(path: string): Promise<T> {
  return request<T>("DELETE", path);
}

// ── API Namespaces ─────────────────────────────────────────────────────────

export const api = {
  sessions: {
    /** List all sessions, newest first. */
    list(): Promise<Session[]> {
      return get<Session[]>("/sessions");
    },

    /** Get a single session by ID. */
    get(id: string): Promise<Session> {
      return get<Session>(`/sessions/${id}`);
    },

    /** Delete a session and all associated data. */
    delete(id: string): Promise<void> {
      return del<void>(`/sessions/${id}`);
    },

    /** List findings for a session. */
    findings(id: string): Promise<Finding[]> {
      return get<Finding[]>(`/sessions/${id}/findings`);
    },

    /** List assets discovered in a session. */
    assets(id: string): Promise<Asset[]> {
      return get<Asset[]>(`/sessions/${id}/assets`);
    },
  },

  scans: {
    /** Start a new scan. Returns the created ScanRecord. */
    start(params: StartScanParams): Promise<ScanRecord> {
      return post<ScanRecord>("/scan", params);
    },

    /** Get the status of a running or completed scan. */
    status(id: string): Promise<ScanRecord> {
      return get<ScanRecord>(`/scan/${id}/status`);
    },

    /** Cancel a running scan. */
    cancel(id: string): Promise<void> {
      return post<void>(`/scan/${id}/cancel`);
    },

    /** List all scan records. */
    list(): Promise<ScanRecord[]> {
      return get<ScanRecord[]>("/scan");
    },
  },

  /**
   * Generate a report for a session.
   * Returns the raw report text (Markdown or HTML).
   */
  async report(
    sessionId: string,
    template: string,
    format: ReportFormat
  ): Promise<string> {
    const res = await fetch(
      `${BASE}/sessions/${sessionId}/report?template=${encodeURIComponent(template)}&format=${encodeURIComponent(format)}`
    );
    if (!res.ok) {
      throw new Error(`${res.status} ${res.statusText}`);
    }
    return res.text();
  },

  /**
   * Compute the diff between two sessions.
   */
  diff(sessionA: string, sessionB: string): Promise<DiffResult> {
    return get<DiffResult>(`/diff?a=${encodeURIComponent(sessionA)}&b=${encodeURIComponent(sessionB)}`);
  },

  models: {
    /** List available GGUF models in the server's models directory. */
    list(): Promise<ModelInfo[]> {
      return get<ModelInfo[]>("/models");
    },
  },

  /**
   * Training pipeline endpoints — Phase 26.
   *
   * All routes are under `/api/train/*`.  Return types mirror the Rust serde
   * structs verified against the source; see types.ts for field-level notes.
   */
  train: {
    /**
     * `POST /api/train/harvest/:id` — opt a session into the training pool.
     * Returns `{ harvested: true, session_id: string }`.
     */
    harvest(sessionId: string): Promise<{ harvested: boolean; session_id: string }> {
      return post(`/train/harvest/${sessionId}`);
    },

    /**
     * `POST /api/train/unharvest/:id` — remove a session from the training pool.
     * Returns `{ harvested: false, session_id: string }`.
     */
    unharvest(sessionId: string): Promise<{ harvested: boolean; session_id: string }> {
      return post(`/train/unharvest/${sessionId}`);
    },

    /**
     * `GET /api/train/stats` — return training dataset counts (no files written).
     * Returns `TrainStats` (mirrors `TrainStatsResponse` in routes.rs).
     */
    stats(): Promise<TrainStats> {
      return get<TrainStats>("/train/stats");
    },

    /**
     * `POST /api/train/export` — extract training data and write JSONL files.
     * Returns `ExportResult` with paths and sample counts.
     */
    export(): Promise<ExportResult> {
      return post<ExportResult>("/train/export");
    },

    /**
     * `POST /api/train/finetune` — start an async fine-tuning job.
     *
     * Request body: `{ base_model, output_name }`.
     * Note: the field is `output_name` (a safe filename token), not `output_path`.
     * Returns `{ job_id: string }` immediately with `202 Accepted`.
     */
    finetune(req: { base_model: string; output_name: string }): Promise<{ job_id: string }> {
      return post<{ job_id: string }>("/train/finetune", req);
    },

    /**
     * `GET /api/train/jobs` — list training job records, newest first.
     * Supports optional `?page=N&page_size=N` query params (not typed here —
     * callers may append them manually if needed).
     */
    jobs(): Promise<TrainingJob[]> {
      return get<TrainingJob[]>("/train/jobs");
    },

    /**
     * `GET /api/train/jobs/:id` — fetch a single job record by ID.
     * Returns `TrainingJob` or throws on 404.
     */
    job(jobId: string): Promise<TrainingJob> {
      return get<TrainingJob>(`/train/jobs/${jobId}`);
    },

    /**
     * `POST /api/train/evaluate` — start an async A/B evaluation.
     * Returns `{ eval_id: string }` immediately with `202 Accepted`.
     */
    evaluate(req: { base: string; candidate: string }): Promise<{ eval_id: string }> {
      return post<{ eval_id: string }>("/train/evaluate", req);
    },

    /**
     * `GET /api/train/evaluations/last` — fetch the most recent evaluation report.
     * Returns `EvaluationReport` (mirrors `ComparisonReport` in evaluate.rs).
     * Throws on 404 if no evaluation has been run yet.
     */
    lastEvaluation(): Promise<EvaluationReport> {
      return get<EvaluationReport>("/train/evaluations/last");
    },
  },

  /**
   * Model promotion/rollback endpoints — Phase 26.
   *
   * All routes are under `/api/model/*`.
   */
  model: {
    /**
     * `POST /api/model/promote` — promote a fine-tuned model to active use.
     *
     * Pass `force: true` to skip the P1 gate (min_eval_examples check).
     * Returns `ModelSwapResult` on success.
     * Throws 409 if config.toml is locked or the eval gate fails.
     */
    promote(req: { tag: string; force: boolean }): Promise<ModelSwapResult> {
      return post<ModelSwapResult>("/model/promote", req);
    },

    /**
     * `POST /api/model/rollback` — revert to the model before the last promotion.
     * Returns `ModelSwapResult` on success.
     * Throws 404 if `promotion.log` is empty.
     */
    rollback(): Promise<ModelSwapResult> {
      return post<ModelSwapResult>("/model/rollback");
    },

    /**
     * `GET /api/model/promotions` — list all promotion and rollback log entries.
     * Returns an empty array when no promotions have been made.
     */
    promotions(): Promise<PromotionEntry[]> {
      return get<PromotionEntry[]>("/model/promotions");
    },
  },
} as const;
