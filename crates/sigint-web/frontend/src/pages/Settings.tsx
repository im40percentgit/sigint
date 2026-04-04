/**
 * Settings — read-only configuration display page.
 *
 * Fetches /api/health on mount to surface server status and any available
 * configuration data. All other settings sections display hardcoded defaults
 * matching the sigint-core default configuration since there is no dedicated
 * config endpoint.
 *
 * @decision DEC-WEB-035
 * @title Settings page is read-only and sourced from /api/health + hardcoded defaults
 * @status accepted
 * @rationale sigint-web exposes no /api/config endpoint. Health check provides
 * server status and partial config data. Hardcoding known defaults is preferable
 * to either omitting the section or implementing a new endpoint solely for display.
 * Read-only avoids accidental misconfiguration from the UI.
 */

import { h } from "preact";
import { useState, useEffect } from "preact/hooks";
import { wsManager } from "../ws";
import { api } from "../api";
import type { ModelInfo } from "../types";

interface HealthResponse {
  status: string;
  version?: string;
  uptime_secs?: number;
  active_scans?: number;
  llm?: {
    provider?: string;
    model?: string;
    base_url?: string;
  };
  agents?: {
    auto_approve?: boolean;
    memory_default?: boolean;
    recon_default?: boolean;
  };
}

/** 29 registered tools from the sigint-tools catalog */
const REGISTERED_TOOLS = [
  "nmap",
  "gobuster",
  "feroxbuster",
  "nikto",
  "nuclei",
  "ffuf",
  "httpx",
  "subfinder",
  "amass",
  "masscan",
  "rustscan",
  "whatweb",
  "wafw00f",
  "dirb",
  "wfuzz",
  "sqlmap",
  "xsstrike",
  "dalfox",
  "ghauri",
  "commix",
  "dnsx",
  "dnsenum",
  "dnsrecon",
  "fierce",
  "theHarvester",
  "shodan",
  "censys",
  "wpscan",
  "joomscan",
];

function formatUptime(secs: number): string {
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m ${secs % 60}s`;
  const h = Math.floor(secs / 3600);
  const m = Math.floor((secs % 3600) / 60);
  return `${h}h ${m}m`;
}

function CodeValue({ children }: { children: string }) {
  return (
    <code
      style={{
        fontFamily: "var(--font-mono)",
        fontSize: "12px",
        backgroundColor: "var(--bg)",
        border: "1px solid var(--border)",
        borderRadius: "var(--radius-sm)",
        padding: "2px 6px",
        color: "var(--accent)",
      }}
    >
      {children}
    </code>
  );
}

function ConfigRow({ label, children }: { label: string; children: h.JSX.Element | string }) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "8px 0",
        borderBottom: "1px solid var(--border)",
        fontSize: "12px",
        gap: "16px",
      }}
    >
      <span style={{ color: "var(--text-secondary)" }}>{label}</span>
      <span>{children}</span>
    </div>
  );
}

export function Settings() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [wsConnected, setWsConnected] = useState<boolean>(wsManager.connected);
  const [loading, setLoading] = useState(true);
  const [models, setModels] = useState<ModelInfo[]>([]);

  useEffect(() => {
    fetch("/api/health")
      .then((r) => r.json() as Promise<HealthResponse>)
      .then((h) => {
        setHealth(h);
        setLoading(false);
      })
      .catch(() => {
        setHealth({ status: "unreachable" });
        setLoading(false);
      });

    // Fetch available embedded models (best-effort)
    api.models
      .list()
      .then((m) => setModels(m))
      .catch(() => setModels([]));
  }, []);

  // Poll WS connected state
  useEffect(() => {
    const id = setInterval(() => setWsConnected(wsManager.connected), 2000);
    return () => clearInterval(id);
  }, []);

  return (
    <div class="page">
      <div class="page-title">Settings</div>
      <p style={{ color: "var(--text-secondary)", fontSize: "12px", marginBottom: "24px" }}>
        Read-only configuration view. To change settings, edit the server configuration file.
      </p>

      {/* Server Status */}
      <div class="card" style={{ marginBottom: "16px" }}>
        <div class="card-title">Server Status</div>

        <ConfigRow label="API status">
          {loading ? (
            <span style={{ color: "var(--text-secondary)" }}>checking…</span>
          ) : (
            <span
              style={{
                color: health?.status === "ok" ? "var(--success)" : "var(--danger)",
                fontWeight: 600,
              }}
            >
              {health?.status ?? "unknown"}
            </span>
          )}
        </ConfigRow>

        <ConfigRow label="WebSocket">
          <span style={{ display: "inline-flex", alignItems: "center", gap: "6px" }}>
            <span
              class={`status-dot ${wsConnected ? "connected" : "disconnected"}`}
            />
            {wsConnected ? "connected" : "disconnected"}
          </span>
        </ConfigRow>

        {health?.version && (
          <ConfigRow label="Version">
            <CodeValue>{health.version}</CodeValue>
          </ConfigRow>
        )}

        {health?.uptime_secs != null && (
          <ConfigRow label="Uptime">
            <span>{formatUptime(health.uptime_secs)}</span>
          </ConfigRow>
        )}

        {health?.active_scans != null && (
          <ConfigRow label="Active scans">
            <span
              style={{
                color: health.active_scans > 0 ? "var(--warning)" : "var(--text-secondary)",
              }}
            >
              {health.active_scans}
            </span>
          </ConfigRow>
        )}
      </div>

      {/* LLM Configuration */}
      <div class="card" style={{ marginBottom: "16px" }}>
        <div class="card-title">LLM Configuration</div>

        <ConfigRow label="Provider">
          <CodeValue>{health?.llm?.provider ?? "ollama"}</CodeValue>
        </ConfigRow>

        <ConfigRow label="Model">
          <CodeValue>{health?.llm?.model ?? "llama3.1:8b"}</CodeValue>
        </ConfigRow>

        <ConfigRow label="Base URL">
          <CodeValue>{health?.llm?.base_url ?? "http://localhost:11434"}</CodeValue>
        </ConfigRow>
      </div>

      {/* Embedded Models */}
      <div class="card" style={{ marginBottom: "16px" }}>
        <div class="card-title">
          Embedded Models{" "}
          <span
            style={{
              fontSize: "10px",
              color: "var(--text-secondary)",
              fontWeight: 400,
              textTransform: "none",
              letterSpacing: 0,
            }}
          >
            ({models.length})
          </span>
        </div>

        {models.length === 0 ? (
          <p style={{ color: "var(--text-secondary)", fontSize: "12px", margin: "8px 0" }}>
            No GGUF models found. Download one with:{" "}
            <code style={{ fontFamily: "var(--font-mono)", fontSize: "11px" }}>
              sigint model pull meta-llama/Llama-3.2-8B-GGUF
            </code>
          </p>
        ) : (
          <div style={{ marginTop: "4px" }}>
            {models.map((m) => (
              <div
                key={m.filename}
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  padding: "6px 0",
                  borderBottom: "1px solid var(--border)",
                  fontSize: "12px",
                  gap: "12px",
                }}
              >
                <span style={{ fontFamily: "var(--font-mono)", color: "var(--accent)" }}>
                  {m.filename}
                </span>
                <span style={{ color: "var(--text-secondary)", whiteSpace: "nowrap" }}>
                  {m.quantization ?? "?"} &middot;{" "}
                  {m.context_length ? `${m.context_length} ctx` : "?"} &middot;{" "}
                  {(m.size_bytes / (1024 * 1024 * 1024)).toFixed(1)} GiB
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Agent Configuration */}
      <div class="card" style={{ marginBottom: "16px" }}>
        <div class="card-title">Agent Configuration</div>

        <ConfigRow label="Auto-approve steps">
          <span
            style={{
              color:
                health?.agents?.auto_approve === true
                  ? "var(--warning)"
                  : "var(--success)",
            }}
          >
            {health?.agents?.auto_approve === true ? "enabled" : "disabled"}
          </span>
        </ConfigRow>

        <ConfigRow label="Memory agent">
          <span>
            {health?.agents?.memory_default === false ? "disabled" : "enabled"}
          </span>
        </ConfigRow>

        <ConfigRow label="Recon agent">
          <span>
            {health?.agents?.recon_default === false ? "disabled" : "enabled"}
          </span>
        </ConfigRow>
      </div>

      {/* Tools */}
      <div class="card">
        <div class="card-title">
          Registered Tools{" "}
          <span
            style={{
              fontSize: "10px",
              color: "var(--text-secondary)",
              fontWeight: 400,
              textTransform: "none",
              letterSpacing: 0,
            }}
          >
            ({REGISTERED_TOOLS.length})
          </span>
        </div>

        <ConfigRow label="Default output cap">
          <CodeValue>1 MB</CodeValue>
        </ConfigRow>

        <div style={{ marginTop: "12px", display: "flex", flexWrap: "wrap", gap: "6px" }}>
          {REGISTERED_TOOLS.map((t) => (
            <span
              key={t}
              style={{
                padding: "2px 8px",
                borderRadius: "var(--radius-sm)",
                backgroundColor: "rgba(88,166,255,0.08)",
                border: "1px solid rgba(88,166,255,0.2)",
                color: "var(--accent)",
                fontSize: "11px",
                fontFamily: "var(--font-mono)",
              }}
            >
              {t}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}
