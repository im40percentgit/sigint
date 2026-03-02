// Reports.js — Generate and download session reports.
//
// @decision DEC-WEB-008
// @title Reports rendered server-side; browser downloads via Blob URL
// @status accepted
// @rationale Report generation (markdown templating, HTML rendering) is done in
// sigint-report on the server. The frontend simply POSTs query params and receives
// text/markdown or text/html. Downloading is done by creating a temporary object
// URL from the response blob — no server-side file storage needed. This keeps the
// backend stateless for report generation.

import { h } from 'preact';
import { useState, useEffect } from 'preact/hooks';
import htm from 'htm';
import { apiListSessions, apiGetReport } from '../api.js';

const html = htm.bind(h);

export function Reports() {
  const [sessions, setSessions] = useState(null);
  const [selectedId, setSelectedId] = useState('');
  const [format, setFormat] = useState('markdown');
  const [template, setTemplate] = useState('detailed');
  const [generating, setGenerating] = useState(false);
  const [preview, setPreview] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    apiListSessions()
      .then(s => {
        setSessions(s);
        if (s.length > 0) setSelectedId(s[0].id);
      })
      .catch(e => setError(e.message));
  }, []);

  async function generate(download) {
    if (!selectedId) return;
    setGenerating(true);
    setError(null);
    setPreview(null);
    try {
      const text = await apiGetReport(selectedId, format, template);
      if (download) {
        const ext = format === 'html' ? 'html' : 'md';
        const blob = new Blob([text], { type: format === 'html' ? 'text/html' : 'text/markdown' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `sigint-report-${selectedId.slice(0, 8)}.${ext}`;
        a.click();
        URL.revokeObjectURL(url);
      } else {
        setPreview(text);
      }
    } catch (e) {
      setError(e.message);
    } finally {
      setGenerating(false);
    }
  }

  return html`
    <div>
      <div class="page-header">
        <div>
          <div class="page-title">Reports</div>
          <div class="page-subtitle">Generate markdown or HTML reports for any session</div>
        </div>
      </div>

      ${error && html`<div class="error-banner">${error}</div>`}

      <div class="card" style="margin-bottom:1rem;">
        <div class="card-header">
          <span class="card-title">Report Options</span>
        </div>

        <div style="display:flex;flex-direction:column;gap:1rem;">
          <div style="display:flex;gap:1rem;align-items:center;flex-wrap:wrap;">
            <label style="display:flex;flex-direction:column;gap:4px;font-size:12px;color:var(--text-dim);">
              Session
              <select
                class="input"
                value=${selectedId}
                onChange=${e => setSelectedId(e.target.value)}
                style="min-width:200px;"
                disabled=${!sessions}
              >
                ${!sessions
                  ? html`<option>Loading…</option>`
                  : sessions.length === 0
                  ? html`<option value="">No sessions</option>`
                  : sessions.map(s => html`<option value=${s.id} key=${s.id}>${s.name}</option>`)
                }
              </select>
            </label>

            <label style="display:flex;flex-direction:column;gap:4px;font-size:12px;color:var(--text-dim);">
              Format
              <select class="input" value=${format} onChange=${e => setFormat(e.target.value)}>
                <option value="markdown">Markdown</option>
                <option value="html">HTML</option>
              </select>
            </label>

            <label style="display:flex;flex-direction:column;gap:4px;font-size:12px;color:var(--text-dim);">
              Template
              <select class="input" value=${template} onChange=${e => setTemplate(e.target.value)}>
                <option value="executive">Executive</option>
                <option value="detailed">Detailed</option>
                <option value="technical">Technical</option>
              </select>
            </label>
          </div>

          <div style="display:flex;gap:0.75rem;">
            <button
              class="btn btn-primary"
              onClick=${() => generate(false)}
              disabled=${generating || !selectedId}
            >
              ${generating ? 'Generating…' : 'Preview'}
            </button>
            <button
              class="btn"
              onClick=${() => generate(true)}
              disabled=${generating || !selectedId}
            >
              Download
            </button>
          </div>
        </div>
      </div>

      ${preview && html`
        <div class="card">
          <div class="card-header">
            <span class="card-title">Preview</span>
            <button class="btn btn-sm" onClick=${() => setPreview(null)}>Close</button>
          </div>
          <pre style="white-space:pre-wrap;font-size:12px;line-height:1.7;color:var(--text);overflow-x:auto;">${preview}</pre>
        </div>
      `}
    </div>
  `;
}
