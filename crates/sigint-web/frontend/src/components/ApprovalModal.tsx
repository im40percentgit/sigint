/**
 * ApprovalModal — full-screen overlay for escalation approval requests.
 *
 * Shown when the scan agent requests human approval before executing a
 * sensitive action (approval_required WsEvent). The user can approve or
 * deny; the parent component sends the response over the WebSocket.
 *
 * Extended in Phase 26 T7 (DEC-P26-004) to support an optional warning
 * banner and a required force-acknowledgement checkbox for model promotion
 * flows. Backward compatible — all new props are optional.
 *
 * @decision DEC-WEB-034
 * @title ApprovalModal is a pure presentational component — parent owns WS send
 * @status accepted
 * @rationale Keeping the modal free of WebSocket knowledge makes it testable
 * in isolation and reusable. The parent (ScanLive) constructs the approval
 * payload and calls wsManager.send(); the modal simply fires onApprove/onDeny
 * callbacks.
 *
 * @decision DEC-P26-004
 * @title ApprovalModal extended with optional warning banner + force checkbox
 * @status accepted
 * @rationale Per Risk #4 (small-sample promotion gate), the warning + force
 * checkbox must be atomic with the Approve button — a separate banner/button
 * outside the modal would allow a user to skip the acknowledgement.  Extending
 * ApprovalModal with optional props preserves backward compatibility (all
 * existing callers pass nothing for the new fields) and keeps the approval
 * UX in a single focused overlay.  `extraField.required = true` disables the
 * Approve button until the checkbox is checked, enforcing the two-distinct-click
 * requirement from the plan.
 */

import { h } from "preact";

/** Optional checkbox field rendered inside the modal above the action buttons. */
export interface ApprovalModalExtraField {
  type: "checkbox";
  label: string;
  /** When true, the Approve button is disabled until the checkbox is checked. */
  required: boolean;
  checked: boolean;
  onChange: (checked: boolean) => void;
}

export interface ApprovalModalProps {
  requestId: string;
  tier: string;
  rationale: string;
  onApprove: () => void;
  onDeny: () => void;
  /** Optional warning banner shown above the action buttons (red/warn style). */
  warning?: string;
  /** Optional extra field (currently only "checkbox" is supported). */
  extraField?: ApprovalModalExtraField;
}

export function ApprovalModal({
  requestId,
  tier,
  rationale,
  onApprove,
  onDeny,
  warning,
  extraField,
}: ApprovalModalProps) {
  // Approve is disabled if there is a required checkbox that isn't checked yet.
  const approveDisabled =
    extraField !== undefined &&
    extraField.required &&
    !extraField.checked;

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

        {/* Optional warning banner — shown when small-sample or other risks apply */}
        {warning && (
          <div
            style={{
              background: "rgba(248,81,73,0.10)",
              border: "1px solid var(--danger)",
              borderRadius: "var(--radius-sm)",
              padding: "10px 12px",
              fontSize: "12px",
              color: "var(--danger)",
              lineHeight: 1.5,
            }}
          >
            {warning}
          </div>
        )}

        {/* Optional extra field — currently only "checkbox" is supported */}
        {extraField && extraField.type === "checkbox" && (
          <label
            style={{
              display: "flex",
              alignItems: "flex-start",
              gap: "10px",
              fontSize: "12px",
              color: "var(--text)",
              cursor: "pointer",
            }}
          >
            <input
              type="checkbox"
              checked={extraField.checked}
              onChange={(e) =>
                extraField.onChange((e.target as HTMLInputElement).checked)
              }
              style={{
                marginTop: "2px",
                accentColor: "var(--accent)",
                flexShrink: 0,
              }}
            />
            <span>{extraField.label}</span>
          </label>
        )}

        {/* Actions */}
        <div style={{ display: "flex", gap: "10px" }}>
          <button
            class="btn btn-primary"
            onClick={onApprove}
            disabled={approveDisabled}
          >
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
