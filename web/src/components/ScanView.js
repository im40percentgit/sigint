// ScanView.js — Live event stream, findings table, and assets for one session.
//
// @decision DEC-WEB-006
// @title ScanView subscribes to the shared WS connection; events filtered by session
// @status accepted
// @rationale All sessions share a single /ws/events connection (created once in
// app.js and passed via props). ScanView listens to all events and displays those
// matching the current session id. This avoids per-session WebSocket connections
// and keeps reconnect logic centralised in ws.js. The event log is capped at 200
// entries to prevent unbounded memory growth during long scans.

import { h } from 'preact';
import { useState, useEffect, useRef } from 'preact/hooks';
import htm from 'htm';
import { apiGetSession, apiGetAssets, apiGetFindings } from '../api.js';

const html = htm.bind(h);

const MAX_EVENTS = 200;

export function ScanView({ sessionId, ws }) {
  const [session, setSession] = useState(null);
  const [assets, setAssets] = useState([]);
  const [findings, setFindings] = useState([]);
  const [events, setEvents] = useState([]);
  const [error, setError] = useState(null);
  const logRef = useRef(null);

  // Load session metadata and initial data
  useEffect(() => {
    if (!sessionId) return;
    Promise.all([
      apiGetSession(sessionId),
      apiGetAssets(sessionId),
      apiGetFindings(sessionId),
    ])
      .then(([s, a, f]) => { setSession(s); setAssets(a); setFindings(f); })
      .catch(e => setError(e.message));
  }, [sessionId]);

  // Subscribe to WebSocket events, filter by session
  useEffect(() => {
    if (!ws) return;
    const unsub = ws.subscribe(msg => {
      if (msg.type !== 'event') return;
      const ev = msg.data;
      // Accept events for this session or broadcast events (no session_id)
      if (ev.session_id && ev.session_id !== sessionId) return;
      setEvents(prev => {
        const next = [...prev, { ...ev, _ts: new Date().toISOString() }];
        return next.length > MAX_EVENTS ? next.slice(-MAX_EVENTS) : next;
      });
      // Refresh assets/findings when relevant events arrive
      if (ev.kind === 'asset_found') {
        apiGetAssets(sessionId).then(setAssets).catch(() => {});
      }
      if (ev.kind === 'finding') {
        apiGetFindings(sessionId).then(setFindings).catch(() => {});
      }
    });
    return unsub;
  }, [ws, sessionId]);

  // Auto-scroll event log
  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [events]);

  if (error) return html`<div class="error-banner">${error}</div>`;
  if (!session) return html`<div class="loading">Loading session…</div>`;

  return html`
    <div>
      <div class="page-header">
        <div>
          <div class="page-title">${session.name}</div>
          <div class="page-subtitle">Target: ${session.target || '—'}</div>
        </div>
        <div style="display:flex;gap:0.5rem;">
          <a href=${'#/reports/' + sessionId} class="btn btn-sm">Generate Report</a>
          <a href="#/sessions" class="btn btn-sm">← Back</a>
        </div>
      </div>

      <div class="grid-3" style="margin-bottom:1.5rem;">
        <div class="card">
          <div class="stat-value">${findings.length}</div>
          <div class="stat-label">Findings</div>
        </div>
        <div class="card">
          <div class="stat-value">${assets.length}</div>
          <div class="stat-label">Assets</div>
        </div>
        <div class="card">
          <div class="stat-value">${events.length}</div>
          <div class="stat-label">Events (live)</div>
        </div>
      </div>

      <!-- Live event log -->
      <div class="card" style="margin-bottom:1rem;">
        <div class="card-header">
          <span class="card-title">Live Event Stream</span>
          <button class="btn btn-sm" onClick=${() => setEvents([])}>Clear</button>
        </div>
        <div class="event-log" ref=${logRef}>
          ${events.length === 0
            ? html`<div class="text-dim" style="text-align:center;padding:1rem;">Waiting for events…</div>`
            : events.map((ev, i) => html`
              <div class="event-entry" key=${i}>
                <span class="event-time">${shortTime(ev._ts)}</span>
                <span class="event-kind">${ev.kind || 'event'}</span>
                <span class="event-body">${summarise(ev)}</span>
              </div>
            `)
          }
        </div>
      </div>

      <!-- Findings -->
      <div class="card" style="margin-bottom:1rem;">
        <div class="card-header">
          <span class="card-title">Findings (${findings.length})</span>
        </div>
        ${findings.length === 0
          ? html`<div class="empty-state">No findings yet.</div>`
          : html`
            <table>
              <thead><tr><th>Severity</th><th>Title</th><th>Asset</th></tr></thead>
              <tbody>
                ${findings.map((f, i) => html`
                  <tr key=${i}>
                    <td><${SeverityBadge} sev=${f.severity} /></td>
                    <td>${f.title}</td>
                    <td class="text-dim">${f.asset || '—'}</td>
                  </tr>
                `)}
              </tbody>
            </table>
          `}
      </div>

      <!-- Assets -->
      <div class="card">
        <div class="card-header">
          <span class="card-title">Assets (${assets.length})</span>
        </div>
        ${assets.length === 0
          ? html`<div class="empty-state">No assets discovered yet.</div>`
          : html`
            <table>
              <thead><tr><th>Kind</th><th>Value</th></tr></thead>
              <tbody>
                ${assets.map((a, i) => html`
                  <tr key=${i}>
                    <td><span class="badge badge-info">${a.kind}</span></td>
                    <td class="mono">${a.value}</td>
                  </tr>
                `)}
              </tbody>
            </table>
          `}
      </div>
    </div>
  `;
}

function SeverityBadge({ sev }) {
  const s = (sev || '').toLowerCase();
  const cls = s === 'critical' ? 'badge-critical'
    : s === 'high' ? 'badge-high'
    : s === 'medium' ? 'badge-medium'
    : s === 'low' ? 'badge-low'
    : 'badge-info';
  return html`<span class=${'badge ' + cls}>${sev || 'info'}</span>`;
}

function shortTime(iso) {
  if (!iso) return '';
  try { return new Date(iso).toLocaleTimeString(); } catch { return ''; }
}

function summarise(ev) {
  // Best-effort one-line summary of an event payload
  if (ev.message) return ev.message;
  if (ev.data && typeof ev.data === 'string') return ev.data;
  if (ev.data) return JSON.stringify(ev.data).slice(0, 120);
  const { kind, session_id, _ts, ...rest } = ev;
  const s = JSON.stringify(rest);
  return s.length > 120 ? s.slice(0, 117) + '…' : s;
}
