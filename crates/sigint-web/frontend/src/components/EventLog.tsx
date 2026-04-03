/**
 * EventLog — scrolling event feed for a live scan.
 *
 * Renders a list of WsEvent objects from the WebSocket stream. Each event
 * type is styled distinctly:
 *   scan_started      — accent left border, target + tool
 *   scan_completed    — success left border, summary line
 *   finding_discovered — severity badge + title
 *   asset_discovered  — info color, asset type + value
 *   approval_required — warning border, step description
 *   log_line          — monospace pre block, level-coloured border
 *   session_updated   — gray text, status note
 *   error             — danger color
 *
 * Auto-scrolls to the bottom on new events unless the user has manually
 * scrolled up, in which case a "Jump to latest" button appears.
 *
 * @decision DEC-WEB-033
 * @title EventLog auto-scroll uses a sentinel div + scrollIntoView
 * @status accepted
 * @rationale A zero-height sentinel div at the bottom of the list combined
 * with scrollIntoView({ behavior: "smooth" }) is the idiomatic Preact/React
 * pattern for auto-scroll. It avoids manual scrollTop arithmetic and handles
 * dynamic item heights correctly.
 */

import { h } from "preact";
import { useEffect, useRef, useState } from "preact/hooks";
import type { WsEvent } from "../types";
import { SeverityBadge } from "./SeverityBadge";

// ── Helpers ────────────────────────────────────────────────────────────────

function fmtTime(iso?: string): string {
  const d = iso ? new Date(iso) : new Date();
  return d.toTimeString().slice(0, 8); // HH:MM:SS
}

// ── Event row renderers ────────────────────────────────────────────────────

function EventRow({ event }: { event: WsEvent }) {
  const ts = (
    <span
      style={{
        color: "var(--text-secondary)",
        fontSize: "10px",
        marginRight: "8px",
        flexShrink: 0,
      }}
    >
      {fmtTime()}
    </span>
  );

  switch (event.type) {
    case "scan_started":
      return (
        <div
          style={{
            borderLeft: "3px solid var(--accent)",
            paddingLeft: "10px",
            marginBottom: "6px",
          }}
        >
          {ts}
          <span style={{ color: "var(--accent)", fontWeight: 600 }}>
            Scan started
          </span>
          {" — "}
          <span style={{ color: "var(--text)" }}>
            {event.data.target}
          </span>
          <span style={{ color: "var(--text-secondary)", marginLeft: "6px" }}>
            [{event.data.tool}]
          </span>
        </div>
      );

    case "scan_completed":
      return (
        <div
          style={{
            borderLeft: "3px solid var(--success)",
            paddingLeft: "10px",
            marginBottom: "6px",
          }}
        >
          {ts}
          <span style={{ color: "var(--success)", fontWeight: 600 }}>
            Scan complete
          </span>
          {" — "}
          <span style={{ color: "var(--text)" }}>
            {event.data.target}
          </span>
          <span style={{ color: "var(--text-secondary)", marginLeft: "6px" }}>
            {event.data.finding_count} finding
            {event.data.finding_count !== 1 ? "s" : ""}
          </span>
        </div>
      );

    case "finding_discovered":
      return (
        <div
          style={{
            borderLeft: "3px solid var(--warning)",
            paddingLeft: "10px",
            marginBottom: "6px",
            display: "flex",
            alignItems: "center",
            gap: "8px",
            flexWrap: "wrap",
          }}
        >
          {ts}
          <SeverityBadge severity={event.data.severity} />
          <span style={{ color: "var(--text)" }}>{event.data.title}</span>
        </div>
      );

    case "asset_discovered":
      return (
        <div
          style={{
            borderLeft: "3px solid var(--accent)",
            paddingLeft: "10px",
            marginBottom: "6px",
            opacity: 0.85,
          }}
        >
          {ts}
          <span style={{ color: "var(--accent)", fontSize: "11px" }}>
            [{event.data.asset_type}]
          </span>
          {" "}
          <span style={{ color: "var(--text)" }}>{event.data.value}</span>
        </div>
      );

    case "approval_required":
      return (
        <div
          style={{
            borderLeft: "3px solid var(--warning)",
            paddingLeft: "10px",
            marginBottom: "6px",
            background: "rgba(240,136,62,0.06)",
            borderRadius: "0 var(--radius-sm) var(--radius-sm) 0",
            padding: "6px 10px",
          }}
        >
          {ts}
          <span style={{ color: "var(--warning)", fontWeight: 600 }}>
            Approval required
          </span>
          {" — "}
          <span style={{ color: "var(--text)" }}>
            {event.data.description}
          </span>
        </div>
      );

    case "log_line": {
      const levelColor =
        event.data.level === "error"
          ? "var(--danger)"
          : event.data.level === "warn"
          ? "var(--warning)"
          : "var(--border)";
      return (
        <div
          style={{
            borderLeft: `3px solid ${levelColor}`,
            paddingLeft: "10px",
            marginBottom: "4px",
          }}
        >
          {ts}
          <pre
            style={{
              display: "inline",
              fontFamily: "var(--font-mono)",
              fontSize: "12px",
              color:
                event.data.level === "error"
                  ? "var(--danger)"
                  : event.data.level === "warn"
                  ? "var(--warning)"
                  : "var(--text-secondary)",
              whiteSpace: "pre-wrap",
              wordBreak: "break-all",
            }}
          >
            {event.data.line}
          </pre>
        </div>
      );
    }

    case "session_updated":
      return (
        <div
          style={{
            color: "var(--text-secondary)",
            fontSize: "11px",
            marginBottom: "4px",
            paddingLeft: "13px",
          }}
        >
          {ts}
          <span>Session updated — status: {event.data.status}</span>
        </div>
      );

    case "error":
      return (
        <div
          style={{
            borderLeft: "3px solid var(--danger)",
            paddingLeft: "10px",
            marginBottom: "6px",
            color: "var(--danger)",
          }}
        >
          {ts}
          <span style={{ fontWeight: 600 }}>Error</span>
          {event.data.code && (
            <span style={{ color: "var(--text-secondary)", marginLeft: "4px" }}>
              [{event.data.code}]
            </span>
          )}
          {" "}
          {event.data.message}
        </div>
      );

    default:
      return null;
  }
}

// ── Main component ─────────────────────────────────────────────────────────

interface EventLogProps {
  events: WsEvent[];
}

export function EventLog({ events }: EventLogProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const sentinelRef = useRef<HTMLDivElement>(null);
  const [userScrolled, setUserScrolled] = useState(false);

  // Auto-scroll when new events arrive (unless user scrolled up)
  useEffect(() => {
    if (!userScrolled && sentinelRef.current) {
      sentinelRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [events.length, userScrolled]);

  function handleScroll() {
    const el = containerRef.current;
    if (!el) return;
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
    setUserScrolled(!atBottom);
  }

  function jumpToLatest() {
    setUserScrolled(false);
    sentinelRef.current?.scrollIntoView({ behavior: "smooth" });
  }

  return (
    <div style={{ position: "relative", flex: 1, overflow: "hidden" }}>
      <div
        ref={containerRef}
        onScroll={handleScroll}
        style={{
          overflowY: "auto",
          height: "100%",
          maxHeight: "calc(100vh - 120px)",
          padding: "16px",
          fontFamily: "var(--font-mono)",
          fontSize: "12px",
          lineHeight: 1.7,
        }}
      >
        {events.length === 0 && (
          <div
            style={{
              color: "var(--text-secondary)",
              fontSize: "12px",
              paddingTop: "24px",
              textAlign: "center",
            }}
          >
            Waiting for events…
          </div>
        )}
        {events.map((ev, i) => (
          <EventRow key={i} event={ev} />
        ))}
        <div ref={sentinelRef} style={{ height: "1px" }} />
      </div>

      {/* Jump to latest button — shown when scrolled away from bottom */}
      {userScrolled && (
        <button
          class="btn btn-sm"
          onClick={jumpToLatest}
          style={{
            position: "absolute",
            bottom: "16px",
            right: "24px",
            background: "var(--surface)",
            border: "1px solid var(--accent)",
            color: "var(--accent)",
            zIndex: 10,
          }}
        >
          Jump to latest
        </button>
      )}
    </div>
  );
}
