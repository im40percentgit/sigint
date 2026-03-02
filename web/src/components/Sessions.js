// Sessions.js — List, search, and delete scan sessions.
//
// @decision DEC-WEB-005
// @title Client-side search filter over full session list
// @status accepted
// @rationale Session counts for a pentest tool are typically small (tens to low
// hundreds). Filtering client-side avoids a round-trip and keeps the UI snappy.
// If session counts grow into thousands, a server-side search query param can be
// added to the API without changing the component interface.

import { h } from 'preact';
import { useState, useEffect, useCallback } from 'preact/hooks';
import htm from 'htm';
import { apiListSessions, apiDeleteSession } from '../api.js';

const html = htm.bind(h);

export function Sessions() {
  const [sessions, setSessions] = useState(null);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState('');
  const [deleting, setDeleting] = useState(null);

  const load = useCallback(() => {
    setError(null);
    apiListSessions()
      .then(setSessions)
      .catch(e => setError(e.message));
  }, []);

  useEffect(() => { load(); }, [load]);

  async function handleDelete(id, name) {
    if (!confirm(`Delete session "${name}"? This cannot be undone.`)) return;
    setDeleting(id);
    try {
      await apiDeleteSession(id);
      setSessions(prev => prev.filter(s => s.id !== id));
    } catch (e) {
      setError(e.message);
    } finally {
      setDeleting(null);
    }
  }

  const filtered = sessions
    ? sessions.filter(s =>
        !filter ||
        s.name?.toLowerCase().includes(filter.toLowerCase()) ||
        s.target?.toLowerCase().includes(filter.toLowerCase())
      )
    : [];

  return html`
    <div>
      <div class="page-header">
        <div>
          <div class="page-title">Sessions</div>
          <div class="page-subtitle">${sessions ? sessions.length : '…'} total sessions</div>
        </div>
        <button class="btn" onClick=${load}>Refresh</button>
      </div>

      ${error && html`<div class="error-banner">${error}</div>`}

      <div class="card">
        <div class="card-header">
          <span class="card-title">All Sessions</span>
          <input
            class="input"
            placeholder="Filter by name or target…"
            value=${filter}
            onInput=${e => setFilter(e.target.value)}
            style="width: 260px;"
          />
        </div>

        ${!sessions
          ? html`<div class="loading">Loading sessions…</div>`
          : filtered.length === 0
          ? html`<div class="empty-state">${filter ? 'No sessions match that filter.' : 'No sessions yet.'}</div>`
          : html`
            <table>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Target</th>
                  <th>Status</th>
                  <th>Created</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                ${filtered.map(s => html`
                  <tr>
                    <td>
                      <a href=${'#/sessions/' + s.id} style="color:var(--blue);text-decoration:none;">
                        ${s.name}
                      </a>
                    </td>
                    <td class="text-dim">${s.target || '—'}</td>
                    <td><${StatusBadge} status=${s.status} /></td>
                    <td class="text-dim">${formatDate(s.created_at)}</td>
                    <td>
                      <button
                        class="btn btn-sm btn-danger"
                        disabled=${deleting === s.id}
                        onClick=${() => handleDelete(s.id, s.name)}
                      >
                        ${deleting === s.id ? 'Deleting…' : 'Delete'}
                      </button>
                    </td>
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
