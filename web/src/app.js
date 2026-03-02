// app.js — SIGINT SPA entry point with Preact + HTM and hash-based router.
//
// @decision DEC-WEB-009
// @title Hash-based routing with no router library; single WS connection shared globally
// @status accepted
// @rationale A hash router (#/path) requires zero server configuration — the
// server always serves index.html and the fragment never leaves the browser. This
// matches the rust-embed SPA fallback. A full router library (react-router etc.)
// would be overkill for 5 routes. The WebSocket connection is created once at app
// level and passed to ScanView; this avoids duplicate connections when the user
// navigates between sessions.

import { h, render } from 'preact';
import { useState, useEffect } from 'preact/hooks';
import htm from 'htm';

import { Dashboard } from './components/Dashboard.js';
import { Sessions } from './components/Sessions.js';
import { ScanView } from './components/ScanView.js';
import { Assets } from './components/Assets.js';
import { Reports } from './components/Reports.js';
import { createWsConnection } from './ws.js';

const html = htm.bind(h);

// ── Hash router ───────────────────────────────────────────

function parseRoute(hash) {
  // Strip leading #
  const path = hash.replace(/^#\/?/, '') || '';
  if (!path) return { page: 'dashboard', id: null };
  const parts = path.split('/');
  if (parts[0] === 'sessions' && parts[1]) return { page: 'scan', id: parts[1] };
  if (parts[0] === 'sessions') return { page: 'sessions', id: null };
  if (parts[0] === 'assets') return { page: 'assets', id: null };
  if (parts[0] === 'reports' && parts[1]) return { page: 'reports', id: parts[1] };
  if (parts[0] === 'reports') return { page: 'reports', id: null };
  return { page: 'dashboard', id: null };
}

function useRoute() {
  const [route, setRoute] = useState(() => parseRoute(location.hash));
  useEffect(() => {
    const handler = () => setRoute(parseRoute(location.hash));
    window.addEventListener('hashchange', handler);
    return () => window.removeEventListener('hashchange', handler);
  }, []);
  return route;
}

// ── WS status indicator ───────────────────────────────────

function WsIndicator({ ws }) {
  const [status, setStatus] = useState('disconnected');
  useEffect(() => {
    if (!ws) return;
    return ws.subscribe(msg => {
      if (msg.type === 'status') setStatus(msg.status);
    });
  }, [ws]);

  const label = status === 'connected' ? 'Live'
    : status === 'connecting' ? 'Connecting…'
    : 'Disconnected';
  const cls = status === 'connected' ? 'connected'
    : status === 'connecting' ? ''
    : 'error';

  return html`
    <div class="ws-indicator">
      <span class=${'ws-dot ' + cls}></span>
      <span class="text-dim">${label}</span>
    </div>
  `;
}

// ── Nav ───────────────────────────────────────────────────

function Nav({ page, ws }) {
  const link = (href, label, p) =>
    html`<a href=${href} class=${page === p ? 'active' : ''}>${label}</a>`;

  return html`
    <nav class="nav">
      <span class="nav-brand">SIGINT</span>
      ${link('#/', 'Dashboard', 'dashboard')}
      ${link('#/sessions', 'Sessions', 'sessions')}
      ${link('#/assets', 'Assets', 'assets')}
      ${link('#/reports', 'Reports', 'reports')}
      <${WsIndicator} ws=${ws} />
    </nav>
  `;
}

// ── App root ──────────────────────────────────────────────

function App() {
  const route = useRoute();
  // Single shared WS connection for the lifetime of the app
  const [ws] = useState(() => createWsConnection());

  let content;
  if (route.page === 'dashboard') {
    content = html`<${Dashboard} />`;
  } else if (route.page === 'sessions') {
    content = html`<${Sessions} />`;
  } else if (route.page === 'scan') {
    content = html`<${ScanView} sessionId=${route.id} ws=${ws} />`;
  } else if (route.page === 'assets') {
    content = html`<${Assets} />`;
  } else if (route.page === 'reports') {
    content = html`<${Reports} />`;
  } else {
    content = html`<div class="empty-state">Page not found.</div>`;
  }

  return html`
    <div id="app">
      <${Nav} page=${route.page} ws=${ws} />
      <main class="main">
        ${content}
      </main>
    </div>
  `;
}

render(html`<${App} />`, document.getElementById('app'));
