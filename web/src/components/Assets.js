// Assets.js — Asset overview grouped by kind across all sessions.
//
// @decision DEC-WEB-007
// @title Assets page aggregates across sessions with client-side grouping
// @status accepted
// @rationale The API provides per-session asset endpoints. Rather than adding a
// cross-session asset query to the backend (which would require a new DB query),
// the frontend loads all sessions and fans out per-session asset requests in
// parallel. For typical pentest session counts this is fast enough; a dedicated
// /api/assets endpoint can replace this if scale requires it.

import { h } from 'preact';
import { useState, useEffect } from 'preact/hooks';
import htm from 'htm';
import { apiListSessions, apiGetAssets } from '../api.js';

const html = htm.bind(h);

export function Assets() {
  const [assets, setAssets] = useState(null);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState('');

  useEffect(() => {
    apiListSessions()
      .then(sessions =>
        Promise.all(sessions.map(s =>
          apiGetAssets(s.id).then(a => a.map(asset => ({ ...asset, sessionName: s.name }))).catch(() => [])
        ))
      )
      .then(results => {
        const all = results.flat();
        setAssets(all);
      })
      .catch(e => setError(e.message));
  }, []);

  if (error) return html`<div class="error-banner">${error}</div>`;
  if (!assets) return html`<div class="loading">Loading assets…</div>`;

  // Group by kind
  const filtered = filter
    ? assets.filter(a =>
        a.value?.toLowerCase().includes(filter.toLowerCase()) ||
        a.kind?.toLowerCase().includes(filter.toLowerCase())
      )
    : assets;

  const byKind = {};
  for (const a of filtered) {
    (byKind[a.kind] = byKind[a.kind] || []).push(a);
  }
  const kinds = Object.keys(byKind).sort();

  return html`
    <div>
      <div class="page-header">
        <div>
          <div class="page-title">Assets</div>
          <div class="page-subtitle">${assets.length} total across all sessions</div>
        </div>
        <input
          class="input"
          placeholder="Filter assets…"
          value=${filter}
          onInput=${e => setFilter(e.target.value)}
          style="width: 240px;"
        />
      </div>

      ${kinds.length === 0
        ? html`
          <div class="card">
            <div class="empty-state">
              ${filter ? 'No assets match that filter.' : 'No assets discovered yet.'}
            </div>
          </div>
        `
        : kinds.map(kind => html`
          <div class="card" key=${kind} style="margin-bottom:1rem;">
            <div class="card-header">
              <span class="card-title">${kind}</span>
              <span class="text-dim" style="font-size:12px;">${byKind[kind].length} asset${byKind[kind].length !== 1 ? 's' : ''}</span>
            </div>
            <table>
              <thead>
                <tr>
                  <th>Value</th>
                  <th>Session</th>
                </tr>
              </thead>
              <tbody>
                ${byKind[kind].map((a, i) => html`
                  <tr key=${i}>
                    <td class="mono">${a.value}</td>
                    <td class="text-dim">${a.sessionName || '—'}</td>
                  </tr>
                `)}
              </tbody>
            </table>
          </div>
        `)
      }
    </div>
  `;
}
