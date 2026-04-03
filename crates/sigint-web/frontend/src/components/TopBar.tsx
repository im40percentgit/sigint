/**
 * TopBar — persistent horizontal bar at the top of the app shell.
 *
 * Shows: SIGINT logo, current page name, spacer, live scan indicator
 * (animated dot + target when a scan is active), and WebSocket status badge.
 *
 * @decision DEC-WEB-026
 * @title TopBar carries WebSocket status badge and live scan indicator
 * @status accepted
 * @rationale Persistent top-of-screen visibility ensures operators always
 * know connection state and whether a scan is active without having to
 * navigate to a specific page; avoids burying status in a sidebar or modal.
 */

import { h } from "preact";

interface TopBarProps {
  pageName: string;
  wsConnected: boolean;
  /** When non-null, a scan is active against this target. */
  scanTarget: string | null;
}

export function TopBar({ pageName, wsConnected, scanTarget }: TopBarProps) {
  return (
    <header class="topbar">
      <span class="topbar-logo">SIGINT</span>
      <span class="topbar-page">{pageName}</span>
      <span class="topbar-spacer" />
      {scanTarget && (
        <span class="topbar-scan-indicator">
          <span class="status-dot scanning" />
          <span class="topbar-scan-target">{scanTarget}</span>
        </span>
      )}
      <span class={`topbar-ws-badge ${wsConnected ? "topbar-ws-badge--up" : "topbar-ws-badge--down"}`}>
        <span class={`status-dot ${wsConnected ? "connected" : "disconnected"}`} />
        {wsConnected ? "live" : "offline"}
      </span>
      <style>{`
        .topbar {
          display: flex;
          align-items: center;
          height: var(--topbar-height);
          padding: 0 16px;
          background-color: var(--surface);
          border-bottom: 1px solid var(--border);
          gap: 12px;
          flex-shrink: 0;
          z-index: 10;
        }
        .topbar-logo {
          font-size: 14px;
          font-weight: 700;
          color: var(--accent);
          letter-spacing: 0.1em;
          text-transform: uppercase;
        }
        .topbar-page {
          font-size: 13px;
          color: var(--text-secondary);
        }
        .topbar-spacer {
          flex: 1;
        }
        .topbar-scan-indicator {
          display: flex;
          align-items: center;
          gap: 6px;
          font-size: 12px;
          color: var(--warning);
          padding: 3px 8px;
          background-color: rgba(240,136,62,0.1);
          border: 1px solid rgba(240,136,62,0.3);
          border-radius: var(--radius-sm);
        }
        .topbar-scan-target {
          max-width: 200px;
          overflow: hidden;
          text-overflow: ellipsis;
          white-space: nowrap;
        }
        .topbar-ws-badge {
          display: flex;
          align-items: center;
          gap: 5px;
          font-size: 11px;
          font-weight: 600;
          text-transform: uppercase;
          letter-spacing: 0.05em;
          padding: 3px 8px;
          border-radius: var(--radius-sm);
          border: 1px solid var(--border);
        }
        .topbar-ws-badge--up {
          color: var(--success);
          border-color: rgba(63,185,80,0.3);
          background-color: rgba(63,185,80,0.08);
        }
        .topbar-ws-badge--down {
          color: var(--danger);
          border-color: rgba(248,81,73,0.3);
          background-color: rgba(248,81,73,0.08);
        }
      `}</style>
    </header>
  );
}
