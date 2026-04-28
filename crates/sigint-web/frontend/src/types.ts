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
  /**
   * Whether this session is opted into fine-tune training harvest.
   * Defaults to false. Set via POST /api/train/harvest/:id (DEC-P24-002).
   */
  trainable: boolean;
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

// ── Phase 26: Training lifecycle WebSocket event types ────────────────────
// These mirror the Rust Event enum variants added in Phase 26 (DEC-P26-001).
// The discriminator field `type` uses snake_case to match the existing WsEvent
// naming convention established for this UI layer.

export interface WsEventTrainingJobStarted {
  type: "training_job_started";
  data: { job_id: string; base_model: string; output_path: string };
}

export interface WsEventTrainingJobProgress {
  type: "training_job_progress";
  data: {
    job_id: string;
    /** Unix epoch seconds at the time of the heartbeat. */
    heartbeat_at: number;
    stdout_tail: string;
  };
}

export interface WsEventTrainingJobCompleted {
  type: "training_job_completed";
  data: { job_id: string; exit_code: number; duration_secs: number };
}

export interface WsEventTrainingJobFailed {
  type: "training_job_failed";
  data: { job_id: string; error: string };
}

export interface WsEventEvaluationStarted {
  type: "evaluation_started";
  data: {
    eval_id: string;
    base_tag: string;
    candidate_tag: string;
    total_examples: number;
  };
}

export interface WsEventEvaluationProgress {
  type: "evaluation_progress";
  data: { eval_id: string; examples_done: number };
}

export interface WsEventEvaluationCompleted {
  type: "evaluation_completed";
  data: { eval_id: string; report_path: string };
}

export interface WsEventModelPromoted {
  type: "model_promoted";
  data: {
    old_provider: string;
    old_model: string;
    new_provider: string;
    new_model: string;
  };
}

export interface WsEventModelRolledBack {
  type: "model_rolled_back";
  data: {
    old_provider: string;
    old_model: string;
    new_provider: string;
    new_model: string;
  };
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
  | WsEventError
  | WsEventTrainingJobStarted
  | WsEventTrainingJobProgress
  | WsEventTrainingJobCompleted
  | WsEventTrainingJobFailed
  | WsEventEvaluationStarted
  | WsEventEvaluationProgress
  | WsEventEvaluationCompleted
  | WsEventModelPromoted
  | WsEventModelRolledBack;

// ── Model Types ────────────────────────────────────────────────────────────

export interface ModelInfo {
  name: string;
  filename: string;
  size_bytes: number;
  quantization: string | null;
  context_length: number | null;
}

// ── Phase 26: Training REST API types ─────────────────────────────────────
//
// These mirror the Rust serde types in crates/sigint-web/src/routes.rs and
// crates/sigint-train/src/{finetune,promotion,evaluate}.rs.  Field names and
// types are derived directly from the Rust source, not guessed from the spec.
//
// Divergences from the issue spec (T4) that were corrected to match Rust:
//   - `TrainStats` (spec) → `TrainStats` (kept) but field set matches
//     `TrainStatsResponse` in routes.rs (adds `trainable_session_count`,
//     `examples_per_agent`, `examples_per_tool`).
//   - `TrainingJob.job_id` (spec) → `TrainingJob.id` — `JobRecord` in
//     finetune.rs uses the field name `id`, not `job_id`.
//   - `JobStatus` serializes as an internally-tagged object
//     `{"status":"Running"|"Success"|"Failed"}` per `#[serde(tag="status")]`
//     in finetune.rs — NOT a flat bare string.
//   - `PromotionEntry.ts` is an ISO 8601 datetime string (DateTime<Utc>),
//     not a Unix epoch number.
//   - `PromotionEntry.eval_result_ref` is `string | undefined` (skip_serializing_if
//     = Option::is_none in Rust), not a required string.
//   - Response type for promote/rollback is `ModelSwapResult` (Rust name); the
//     shape is the same as the spec's `ModelState`.
//   - `finetune` request body uses `output_name: string` not `output_path`.
//
// @decision DEC-P26-T4-001
// @title TypeScript training types match Rust serde shapes exactly
// @status accepted
// @rationale Any divergence between the TS API client and the Rust handler
// response shape produces silent type unsafety at runtime (no compile error
// on the caller side when assigning to the wrong field).  All fields were
// verified against the Rust source before being written here.

/** Inline assessment results snapshot — mirrors SerializableAssessResults. */
export interface SerializableAssessResults {
  total_examples: number;
  correct_tool: number;
  tool_accuracy: number;
  argument_exact_match: number;
  argument_accuracy: number;
}

/**
 * Response of `GET /api/train/stats`.
 * Mirrors `TrainStatsResponse` in routes.rs.
 * Note: spec called this `TrainStats`; the Rust struct adds
 * `trainable_session_count`, `examples_per_agent`, `examples_per_tool`.
 */
export interface TrainStats {
  total_examples: number;
  total_sessions: number;
  trainable_session_count: number;
  examples_per_agent: Record<string, number>;
  examples_per_tool: Record<string, number>;
}

/**
 * Response of `POST /api/train/export`.
 * Mirrors `ExportResult` in routes.rs.
 */
export interface ExportResult {
  train_count: number;
  test_count: number;
  train_path: string;
  test_path: string;
}

/**
 * Internally-tagged status for a fine-tuning job.
 * Rust: `#[serde(tag = "status")]` → serializes as `{"status":"Running"}` etc.
 * NOT a bare string — the `status` discriminator is a key in the outer object.
 */
export type JobStatus = { status: "Running" } | { status: "Success" } | { status: "Failed" };

/**
 * Convenience type alias for the status discriminator string.
 * Useful for `switch` exhaustiveness checks.
 */
export type JobStatusKind = JobStatus["status"];

/**
 * A single fine-tuning job record.
 * Mirrors `JobRecord` in crates/sigint-train/src/finetune.rs.
 *
 * Note: the Rust field is `id` (not `job_id` as the spec suggested).
 * Fields with `#[serde(skip_serializing_if = "Option::is_none")]` are
 * optional (absent when None) and typed as `... | undefined` here.
 */
export interface TrainingJob {
  id: string;
  started_at: string;
  finished_at?: string;
  command: string;
  base_model: string;
  output_path: string;
  exit_code?: number;
  /** Internally-tagged: `{"status":"Running"}` | `{"status":"Success"}` | `{"status":"Failed"}` */
  status: JobStatus;
  failure_reason?: string;
  /**
   * Last N bytes of stdout+stderr captured during streaming execution.
   * Absent (undefined) for sync CLI-initiated jobs that use Stdio::inherit().
   * Populated by run_finetune_streaming at job completion (DEC-P26-T6-002).
   */
  stdout_tail?: string;
}

/**
 * A/B evaluation comparison report.
 * Mirrors `ComparisonReport` in crates/sigint-train/src/evaluate.rs.
 * Returned by `GET /api/train/evaluations/last`.
 */
export interface EvaluationReport {
  base_tag: string;
  candidate_tag: string;
  base_results: SerializableAssessResults;
  candidate_results: SerializableAssessResults;
  /** candidate.tool_accuracy - base.tool_accuracy (fraction in [-1, 1]). */
  tool_accuracy_delta: number;
  /** candidate.argument_accuracy - base.argument_accuracy (fraction in [-1, 1]). */
  argument_match_delta: number;
  total_examples: number;
  evaluated_at: string;
}

/**
 * Action type in a promotion log entry.
 * Rust: `#[serde(rename_all = "lowercase")]` on unit-variant enum
 * → serializes as `"promote"` or `"rollback"` (bare lowercase string).
 */
export type PromotionAction = "promote" | "rollback";

/**
 * One entry in the append-only `promotion.log`.
 * Mirrors `PromotionEntry` in crates/sigint-train/src/promotion.rs.
 *
 * Note: `ts` is an ISO 8601 datetime string (DateTime<Utc>), not a Unix
 * epoch number. `eval_result_ref` is absent when the field was None in Rust.
 */
export interface PromotionEntry {
  ts: string;
  action: PromotionAction;
  old_provider: string;
  old_model: string;
  new_provider: string;
  new_model: string;
  eval_result_ref?: string;
}

/**
 * Response body for `POST /api/model/promote` and `POST /api/model/rollback`.
 * Mirrors `ModelSwapResult` in routes.rs (spec called this `ModelState`).
 */
export interface ModelSwapResult {
  old_provider: string;
  old_model: string;
  new_provider: string;
  new_model: string;
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
