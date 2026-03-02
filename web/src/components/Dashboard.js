// Dashboard.js — Overview: session count, recent activity, quick stats.
//
// @decision DEC-WEB-004
// @title Dashboard fetches session list only; per-session detail fetched on demand
// @status accepted
// @rationale Eagerly fetching findings/assets for every session on the dashboard
// would be O(n) API calls. The dashboard shows aggregate counts from the session
// list alone. Drill-down data is fetched in ScanView when the user navigates to
// a specific session. This keeps the dashboard fast regardless of session count.

import { h } from 'preact';
import { useState, useEffect } from 'preact/hooks';
import htm from 'htm';
import { apiListSessions } from '../api.js';

const html = htm.bind(h);

export function Dashboard() {
  const [sessions, setSessions] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    apiListSessions()
      .then(setSessions)
      .catch(e => setError(e.message));
  }, []);

  if (error) return html`<div class="error-banner">${error}</div>`;
  if (!sessions) return html`<div class="loading">Loading...</div>`;

  const active = sessions.filter(s => s.status === 'active' || s.status === 'running');
  const recent = sessions.slice(0, 5);

  const totalSessions = sessions.length;
  const activeSessions = active.length;

  return html`
    <div>
      <div class="page-header">
        <div>
          <div class="page-title">Dashboard</div>
          <div class="page-subtitle">SIGINT pentest intelligence platform</div>
        </div>
      </div>

      <div class="grid-4" style="margin-bottom: 1.5rem;">
        <div class="card">
          <div class="stat-value">${totalSessions}</div>
          <div class="stat-label">Total Sessions</div>
        </div>
        <div class="card">
          <div class="stat-value text-green">${activeSessions}</div>
          <div class="stat-label">Active Scans</div>
        </div>
        <div class="card">
          <div class="stat-value text-accent">--</div>
          <div class="stat-label">Findings Today</div>
        </div>
        <div class="card">
          <div class="stat-value text-blue">--</div>
          <div class="stat-label">Assets Discovered</div>
        </div>
      </div>

      <div class="card">
        <div class="card-header">
          <span class="card-title">Recent Sessions</span>
          <a href="#/sessions" class="btn btn-sm">View All</a>
        </div>
        ${recent.length === 0
          ? html`<div class="empty-state">No sessions yet.<br/><br/>Start a scan from the CLI to see data here.</div>`
          : html`
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Target</th>
                  <th>Status</th>
                  <th>Created</th>
                </tr>
              </thead>
              <tbody>
                ${recent.map(s => html`
                  <tr>
                    <td><a href=${'#/sessions/' + s.id} style="color:var(--blue);text-decoration:none;">${s.name}</a></td>
                    <td class="text-dim">${s.target || '—'}</td>
                    <td><${StatusBadge} status=${s.status} /></td>
                    <td class="text-dim">${formatDate(s.created_at)}</td>
                  </tr>
                `)}
              </tbody>
            </table>
          `}
      </div>
    </div>
  `;
}

function StatusBadge({ status }) {
  const cls = status === 'active' || status === 'running' ? 'badge-active'
    : status === 'complete' || status === 'completed' ? 'badge-low'
    : 'badge-info';
  return html`<span class=${'badge ' + cls}>${status || 'unknown'}</span>`;
}

function formatDate(iso) {
  if (!iso) return '—';
  try {
    return new Date(iso).toLocaleString(undefined, {
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
    });
  } catch { return iso; }
}
