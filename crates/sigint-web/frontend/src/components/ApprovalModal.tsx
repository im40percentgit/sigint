/**
 * ApprovalModal — full-screen overlay for escalation approval requests.
 *
 * Shown when the scan agent requests human approval before executing a
 * sensitive action (approval_required WsEvent). The user can approve or
 * deny; the parent component sends the response over the WebSocket.
 *
 * @decision DEC-WEB-034
 * @title ApprovalModal is a pure presentational component — parent owns WS send
 * @status accepted
 * @rationale Keeping the modal free of WebSocket knowledge makes it testable
 * in isolation and reusable. The parent (ScanLive) constructs the approval
 * payload and calls wsManager.send(); the modal simply fires onApprove/onDeny
 * callbacks.
 */

import { h } from "preact";

interface ApprovalModalProps {
  requestId: string;
  tier: string;
  rationale: string;
  onApprove: () => void;
  onDeny: () => void;
}

export function ApprovalModal({
  requestId,
  tier,
  rationale,
  onApprove,
  onDeny,
}: ApprovalModalProps) {
  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.70)",
        zIndex: 1000,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: "24px",
      }}
      // Click outside does nothing — requires explicit approve/deny
    >
      <div
        class="card"
        style={{
          maxWidth: "500px",
          width: "100%",
          display: "flex",
          flexDirection: "column",
          gap: "16px",
        }}
      >
        {/* Header */}
        <div>
          <div
            style={{
              fontSize: "15px",
              fontWeight: 700,
              color: "var(--danger)",
              marginBottom: "8px",
            }}
          >
            Escalation Approval Required
          </div>
          <span
            class="badge"
            style={{
              background: "rgba(248,81,73,0.12)",
              border: "1px solid var(--danger)",
              color: "var(--danger)",
            }}
          >
            {tier.toUpperCase()}
          </span>
        </div>

        {/* Rationale */}
        <div>
          <div
            style={{
              fontSize: "11px",
              fontWeight: 600,
              textTransform: "uppercase",
              letterSpacing: "0.06em",
              color: "var(--text-secondary)",
              marginBottom: "6px",
            }}
          >
            Rationale
          </div>
          <pre
            style={{
              whiteSpace: "pre-wrap",
              wordBreak: "break-word",
              fontFamily: "var(--font-mono)",
              fontSize: "12px",
              color: "var(--text)",
              lineHeight: 1.6,
              background: "var(--bg)",
              border: "1px solid var(--border)",
              borderRadius: "var(--radius-sm)",
              padding: "10px 12px",
            }}
          >
            {rationale}
          </pre>
        </div>

        {/* Request ID (small, for auditability) */}
        <div style={{ fontSize: "10px", color: "var(--text-secondary)" }}>
          Request ID: <code>{requestId}</code>
        </div>

        {/* Actions */}
        <div style={{ display: "flex", gap: "10px" }}>
          <button class="btn btn-primary" onClick={onApprove}>
            Approve
          </button>
          <button class="btn btn-danger" onClick={onDeny}>
            Deny
          </button>
        </div>
      </div>
    </div>
  );
}
