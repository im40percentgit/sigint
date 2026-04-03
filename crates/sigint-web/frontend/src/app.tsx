/**
 * App — root layout shell with hash-based router.
 *
 * Renders TopBar + Sidebar + main content area. Reads window.location.hash
 * to determine the current route and re-renders on hashchange.
 *
 * Pages not yet implemented render a "Coming soon" placeholder.
 *
 * @decision DEC-WEB-027
 * @title App shell uses hash router with useState + hashchange listener
 * @status accepted
 * @rationale Hash routing requires no server configuration; a single
 * hashchange listener + useState(location.hash) is the minimal correct
 * Preact implementation; cleanup via removeEventListener in useEffect
 * return prevents listener accumulation on hot-reload.
 */

import { h, Fragment } from "preact";
import { useState, useEffect } from "preact/hooks";
import { TopBar } from "./components/TopBar";
import { Sidebar } from "./components/Sidebar";
import { wsManager } from "./ws";
import { Dashboard } from "./pages/Dashboard";
import { NewScan } from "./pages/NewScan";
import { ScanLive } from "./pages/ScanLive";
import { SessionDetail } from "./pages/SessionDetail";
import { ReportViewer } from "./pages/ReportViewer";
import { FindingsDetail } from "./pages/FindingsDetail";
import { AttackPlanView } from "./pages/AttackPlanView";
import { ScanDiff } from "./pages/ScanDiff";
import { Settings } from "./pages/Settings";

// ── Fallback placeholder for unimplemented pages ───────────────────────────

function Placeholder({ name }: { name: string }) {
  return (
    <div class="page">
      <div class="page-title">{name}</div>
      <div style={{ color: "var(--text-secondary)", fontSize: "13px" }}>
        Coming soon: {name}
      </div>
    </div>
  );
}

// ── Route resolution ───────────────────────────────────────────────────────

interface Route {
  name: string;
  component: h.JSX.Element;
}

function resolveRoute(hash: string): Route {
  const h2 = hash.replace(/^#\/?/, "") || "";

  if (h2 === "" || h2 === "/") {
    return { name: "Dashboard", component: <Dashboard /> };
  }
  if (h2 === "scan/new") {
    return { name: "New Scan", component: <NewScan /> };
  }
  if (h2.startsWith("scan/") && !h2.startsWith("scan/new")) {
    const id = h2.slice(5);
    return { name: "Scan", component: <ScanLive scanId={id} /> };
  }
  if (h2 === "sessions") {
    return { name: "Sessions", component: <Placeholder name="Sessions" /> };
  }
  if (h2.startsWith("sessions/")) {
    const rest = h2.slice(9); // strip "sessions/"
    const slashIdx = rest.indexOf("/");
    if (slashIdx === -1) {
      // #/sessions/:id — session detail
      return { name: "Session", component: <SessionDetail sessionId={rest} /> };
    }
    const sessionId = rest.slice(0, slashIdx);
    const sub = rest.slice(slashIdx + 1);
    if (sub === "report") {
      return { name: "Report", component: <ReportViewer sessionId={sessionId} /> };
    }
    if (sub.startsWith("findings/")) {
      const fid = sub.slice(9);
      return { name: "Finding", component: <FindingsDetail sessionId={sessionId} findingId={fid} /> };
    }
    if (sub === "plan") {
      return { name: "Attack Plan", component: <AttackPlanView sessionId={sessionId} /> };
    }
    return { name: "Session", component: <SessionDetail sessionId={sessionId} /> };
  }
  if (h2 === "diff") {
    return { name: "Scan Diff", component: <ScanDiff /> };
  }
  if (h2 === "reports") {
    return { name: "Reports", component: <Placeholder name="Reports" /> };
  }
  if (h2 === "settings") {
    return { name: "Settings", component: <Settings /> };
  }

  return { name: "Not Found", component: <Placeholder name="Not Found" /> };
}

// ── App root ───────────────────────────────────────────────────────────────

export function App() {
  const [hash, setHash] = useState<string>(window.location.hash);
  const [wsConnected, setWsConnected] = useState<boolean>(wsManager.connected);
  const [scanTarget, setScanTarget] = useState<string | null>(null);

  // Hash router listener
  useEffect(() => {
    function onHashChange() {
      setHash(window.location.hash);
    }
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  // WebSocket status + live scan indicator
  useEffect(() => {
    const unsub = wsManager.subscribe(event => {
      setWsConnected(wsManager.connected);
      if (event.type === "scan_started") {
        setScanTarget(event.data.target);
      } else if (event.type === "scan_completed") {
        setScanTarget(null);
      }
    });
    return unsub;
  }, []);

  // Poll WS connected state (catches reconnect without an event)
  useEffect(() => {
    const id = setInterval(() => setWsConnected(wsManager.connected), 2000);
    return () => clearInterval(id);
  }, []);

  const route = resolveRoute(hash);

  return (
    <div class="app-shell">
      <TopBar
        pageName={route.name}
        wsConnected={wsConnected}
        scanTarget={scanTarget}
      />
      <div class="app-body">
        <Sidebar currentHash={hash} />
        <main class="app-main">
          {route.component}
        </main>
      </div>
    </div>
  );
}
