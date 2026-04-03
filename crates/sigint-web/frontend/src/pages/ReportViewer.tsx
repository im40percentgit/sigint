/**
 * ReportViewer — generates and displays session reports in an iframe.
 *
 * Supports three templates (executive, detailed, technical) with a default
 * of "detailed". Renders HTML reports via the srcdoc attribute in a sandboxed
 * iframe to prevent script execution from report content. Download buttons
 * use the Blob URL pattern to trigger browser file saves.
 *
 * @decision DEC-WEB-031
 * @title ReportViewer uses srcdoc iframe with sandbox="allow-same-origin"
 * @status accepted
 * @rationale srcdoc injects arbitrary HTML safely — sandbox prevents script
 * execution from the report body while allow-same-origin lets the iframe
 * inherit CSS custom properties from the parent document for themed rendering.
 * Blob URL download avoids a second network round-trip for the same content.
 */

import { h } from "preact";
import { useState, useEffect } from "preact/hooks";
import { api } from "../api";

interface ReportViewerProps {
  sessionId: string;
}

type Template = "executive" | "detailed" | "technical";

const TEMPLATES: { id: Template; label: string }[] = [
  { id: "executive", label: "Executive" },
  { id: "detailed", label: "Detailed" },
  { id: "technical", label: "Technical" },
];

/** Trigger a browser file download from a string blob. */
function downloadBlob(content: string, filename: string, mimeType: string): void {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.style.display = "none";
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export function ReportViewer({ sessionId }: ReportViewerProps) {
  const [template, setTemplate] = useState<Template>("detailed");
  const [htmlContent, setHtmlContent] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    setError(null);
    setHtmlContent(null);

    api
      .report(sessionId, template, "html")
      .then((html) => {
        setHtmlContent(html);
        setLoading(false);
      })
      .catch((e: Error) => {
        setError(e.message);
        setLoading(false);
      });
  }, [sessionId, template]);

  async function handleDownload(format: "markdown" | "html"): Promise<void> {
    try {
      const content = await api.report(sessionId, template, format);
      const ext = format === "markdown" ? "md" : "html";
      const mime = format === "markdown" ? "text/markdown" : "text/html";
      downloadBlob(content, `report-${sessionId}.${ext}`, mime);
    } catch (e) {
      alert(`Download failed: ${(e as Error).message}`);
    }
  }

  return (
    <div class="page" style={{ maxWidth: "100%", padding: "24px" }}>
      {/* Header */}
      <div class="page-header">
        <div>
          <div class="page-title" style={{ marginBottom: "4px" }}>Report</div>
          <div style={{ color: "var(--text-secondary)", fontSize: "12px" }}>
            Session: <code style={{ fontFamily: "var(--font-mono)" }}>{sessionId}</code>
          </div>
        </div>
        <div style={{ display: "flex", gap: "8px", alignItems: "center" }}>
          <button class="btn btn-sm" onClick={() => handleDownload("markdown")}>
            Download MD
          </button>
          <button class="btn btn-sm" onClick={() => handleDownload("html")}>
            Download HTML
          </button>
          <a
            class="btn btn-sm"
            href={`#/sessions/${sessionId}`}
            style={{ marginLeft: "8px" }}
          >
            ← Back
          </a>
        </div>
      </div>

      {/* Template selector */}
      <div style={{ display: "flex", gap: "4px", marginBottom: "16px" }}>
        {TEMPLATES.map((t) => (
          <button
            key={t.id}
            class="btn btn-sm"
            style={{
              backgroundColor: template === t.id ? "var(--accent)" : "var(--surface)",
              color: template === t.id ? "#0d1117" : "var(--text)",
              borderColor: template === t.id ? "var(--accent)" : "var(--border)",
            }}
            onClick={() => setTemplate(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Content area */}
      {loading && (
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            height: "calc(100vh - 220px)",
            color: "var(--text-secondary)",
          }}
        >
          Generating report…
        </div>
      )}

      {error && (
        <div
          style={{
            padding: "16px",
            color: "var(--danger)",
            border: "1px solid var(--danger)",
            borderRadius: "var(--radius-md)",
            backgroundColor: "rgba(248, 81, 73, 0.05)",
          }}
        >
          Error generating report: {error}
        </div>
      )}

      {htmlContent && !loading && (
        <iframe
          srcdoc={htmlContent}
          sandbox="allow-same-origin"
          style={{
            width: "100%",
            height: "calc(100vh - 200px)",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius-md)",
            backgroundColor: "#fff",
          }}
          title={`Report — ${template}`}
        />
      )}
    </div>
  );
}
