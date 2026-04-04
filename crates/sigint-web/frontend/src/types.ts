/**
 * Shared TypeScript interfaces for the SIGINT web UI.
 *
 * These mirror the JSON shapes returned by the sigint-web REST API and
 * the WebSocket event stream. Keep in sync with the Rust serde types in
 * crates/sigint-web/src/routes.rs.
 *
 * @decision DEC-WEB-021
 * @title Discriminated union for WebSocket events using `type` literal field
 * @status accepted
 * @rationale A discriminated union on `type` lets TypeScript narrow the event
 * payload with a switch statement, producing fully type-safe handlers without
 * runtime casting.
 */

// ── Core Domain Types ──────────────────────────────────────────────────────

export interface Session {
  id: string;
  target: string;
  created_at: string;
  updated_at: string;
  status: "active" | "completed" | "failed";
  finding_count: number;
  asset_count: number;
}

export interface Finding {
  id: string;
  session_id: string;
  title: string;
  description: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  tool: string;
  evidence: string | null;
  created_at: string;
  cve: string | null;
  url: string | null;
  ip: string | null;
  port: number | null;
}

export interface Asset {
  id: string;
  session_id: string;
  asset_type: string;
  value: string;
  metadata: Record<string, string> | null;
  discovered_at: string;
  last_seen: string;
}

export interface ScanRecord {
  id: string;
  session_id: string;
  tool: string;
  target: string;
  status: "pending" | "running" | "complete" | "failed" | "cancelled";
  started_at: string;
  finished_at: string | null;
  exit_code: number | null;
  output_truncated: boolean;
}

export interface AttackStep {
  id: string;
  session_id: string;
  step_number: number;
  description: string;
  tool: string | null;
  status: "pending" | "approved" | "rejected" | "complete" | "failed";
  reasoning: string | null;
  created_at: string;
  completed_at: string | null;
}

export interface ScanInfo {
  scan_id: string;
  session_id: string;
  tool: string;
  target: string;
  status: ScanRecord["status"];
  elapsed_secs: number | null;
}

export interface DiffResult {
  session_a: string;
  session_b: string;
  new_findings: Finding[];
  resolved_findings: Finding[];
  new_assets: Asset[];
  removed_assets: Asset[];
}

// ── WebSocket Event Types ──────────────────────────────────────────────────

export interface WsEventScanStarted {
  type: "scan_started";
  data: ScanInfo;
}

export interface WsEventScanCompleted {
  type: "scan_completed";
  data: ScanInfo & { finding_count: number };
}

export interface WsEventFindingDiscovered {
  type: "finding_discovered";
  data: Finding;
}

export interface WsEventAssetDiscovered {
  type: "asset_discovered";
  data: Asset;
}

export interface WsEventApprovalRequired {
  type: "approval_required";
  data: AttackStep;
}

export interface WsEventLogLine {
  type: "log_line";
  data: { scan_id: string; line: string; level: "info" | "warn" | "error" };
}

export interface WsEventSessionUpdated {
  type: "session_updated";
  data: Session;
}

export interface WsEventError {
  type: "error";
  data: { message: string; code: string | null };
}

/** Discriminated union of all WebSocket event shapes. */
export type WsEvent =
  | WsEventScanStarted
  | WsEventScanCompleted
  | WsEventFindingDiscovered
  | WsEventAssetDiscovered
  | WsEventApprovalRequired
  | WsEventLogLine
  | WsEventSessionUpdated
  | WsEventError;

// ── Model Types ────────────────────────────────────────────────────────────

export interface ModelInfo {
  name: string;
  filename: string;
  size_bytes: number;
  quantization: string | null;
  context_length: number | null;
}

// ── API Param Types ────────────────────────────────────────────────────────

export interface StartScanParams {
  session_id?: string;
  target: string;
  tool: string;
  options?: Record<string, string>;
}

export type ReportFormat = "markdown" | "html";

export interface ApprovalResponse {
  step_id: string;
  approved: boolean;
}
