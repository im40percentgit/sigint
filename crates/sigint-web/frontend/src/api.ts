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
} as const;
