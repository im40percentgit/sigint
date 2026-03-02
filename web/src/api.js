// api.js — Typed fetch wrappers for all SIGINT REST endpoints.
//
// @decision DEC-WEB-002
// @title Same-origin fetch wrappers with no external HTTP client library
// @status accepted
// @rationale The frontend is served from the same origin as the API, so
// all requests are same-origin. The native fetch API is sufficient; adding
// axios or another HTTP client would bloat the bundle for no benefit.
// Error handling normalises all non-2xx responses into thrown Errors so
// components only need to handle one error type.
//
// All functions return plain JSON or throw an Error with a human-readable
// message. Callers handle loading/error state in their components.

const BASE = '';  // same-origin — no cross-origin needed

async function request(method, path, body) {
  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' },
  };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const res = await fetch(BASE + path, opts);
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new Error(`${method} ${path} → ${res.status}: ${text}`);
  }
  const ct = res.headers.get('content-type') || '';
  if (ct.includes('application/json')) return res.json();
  return res.text();
}

// ── Health ────────────────────────────────────────────────

export function apiHealth() {
  return request('GET', '/api/health');
}

// ── Sessions ──────────────────────────────────────────────

/** Returns Session[] sorted newest-first */
export function apiListSessions() {
  return request('GET', '/api/sessions');
}

/** Returns a single Session or throws 404 */
export function apiGetSession(id) {
  return request('GET', `/api/sessions/${id}`);
}

/** Deletes a session (204 No Content) */
export function apiDeleteSession(id) {
  return request('DELETE', `/api/sessions/${id}`);
}

// ── Assets & Findings ─────────────────────────────────────

/** Returns Asset[] for a session */
export function apiGetAssets(sessionId) {
  return request('GET', `/api/sessions/${sessionId}/assets`);
}

/** Returns Finding[] for a session */
export function apiGetFindings(sessionId) {
  return request('GET', `/api/sessions/${sessionId}/findings`);
}

// ── Reports ───────────────────────────────────────────────

/**
 * Returns report text (markdown or HTML).
 * @param {string} sessionId
 * @param {'markdown'|'html'} format
 * @param {'executive'|'detailed'|'technical'} template
 */
export function apiGetReport(sessionId, format = 'markdown', template = 'detailed') {
  return request('GET', `/api/report/${sessionId}?format=${format}&template=${template}`);
}
