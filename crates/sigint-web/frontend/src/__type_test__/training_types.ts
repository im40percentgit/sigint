/**
 * Compile-time type exhaustiveness tests for Phase 26 training types.
 *
 * This file is never executed at runtime — it exists solely to prove that
 * the TypeScript types are correctly shaped and exhaustive. If a future Rust
 * change adds a new variant or renames a field, `tsc --noEmit` will fail here
 * before a broken build ships.
 *
 * Pattern: `assertNever` causes a compile error if the switch is non-exhaustive.
 * Any type assertion that compiles proves the type is correctly defined.
 *
 * @decision DEC-P26-T4-002
 * @title Compile-time type tests as the only test surface for a TS-only task
 * @status accepted
 * @rationale The frontend has no Jest/Vitest suite. The accepted pattern is
 * `tsc --noEmit` as the verification gate. Exhaustiveness checks (`assertNever`
 * on every union) and structural shape assertions (object literals assigned to
 * typed constants) make it impossible for a Rust serde change to silently drift
 * from the TS types — `npm run typecheck` will fail with a clear error message
 * pointing to this file. This is cheaper than a full test runner and provides
 * equal coverage for the interface contract.
 */

import type {
  JobStatusKind,
  PromotionAction,
  TrainStats,
  ExportResult,
  TrainingJob,
  EvaluationReport,
  PromotionEntry,
  ModelSwapResult,
  SerializableAssessResults,
} from "../types";
import { api } from "../api";

// ── assertNever helper ────────────────────────────────────────────────────────

function assertNever(x: never): never {
  throw new Error("Unreachable: " + String(x));
}

// ── JobStatusKind exhaustiveness ──────────────────────────────────────────────

function checkJobStatus(s: JobStatusKind): string {
  switch (s) {
    case "Running": return "r";
    case "Success": return "s";
    case "Failed":  return "f";
    default: return assertNever(s);
  }
}

// ── PromotionAction exhaustiveness ────────────────────────────────────────────

function checkPromotionAction(a: PromotionAction): string {
  switch (a) {
    case "promote":  return "p";
    case "rollback": return "r";
    default: return assertNever(a);
  }
}

// ── Structural shape assertions ───────────────────────────────────────────────
// These assignments compile only when each interface has exactly the required
// fields with the correct types.

const _trainStats: TrainStats = {
  total_examples: 0,
  total_sessions: 0,
  trainable_session_count: 0,
  examples_per_agent: {},
  examples_per_tool: {},
};

const _exportResult: ExportResult = {
  train_count: 0,
  test_count: 0,
  train_path: "/tmp/train.jsonl",
  test_path: "/tmp/test.jsonl",
};

const _assessResults: SerializableAssessResults = {
  total_examples: 0,
  correct_tool: 0,
  tool_accuracy: 0.0,
  argument_exact_match: 0,
  argument_accuracy: 0.0,
};

const _evalReport: EvaluationReport = {
  base_tag: "llama3.2:8b",
  candidate_tag: "sigint-ft:latest",
  base_results: _assessResults,
  candidate_results: _assessResults,
  tool_accuracy_delta: 0.1,
  argument_match_delta: 0.05,
  total_examples: 50,
  evaluated_at: "2026-04-24T00:00:00Z",
};

const _promoEntry: PromotionEntry = {
  ts: "2026-04-24T00:00:00Z",
  action: "promote",
  old_provider: "ollama",
  old_model: "llama3.2:8b",
  new_provider: "embedded",
  new_model: "/models/ft.gguf",
  // eval_result_ref is optional — omit to prove it is not required
};

const _modelSwapResult: ModelSwapResult = {
  old_provider: "ollama",
  old_model: "llama3.2:8b",
  new_provider: "embedded",
  new_model: "/models/ft.gguf",
};

const _trainingJob: TrainingJob = {
  id: "some-uuid",
  started_at: "2026-04-24T00:00:00Z",
  command: "unsloth-cli --train train.jsonl",
  base_model: "llama3.2:8b",
  output_path: "/models/ft.gguf",
  status: { status: "Running" },
  // finished_at, exit_code, failure_reason are optional — omit to prove it
};

// ── api.train shape compile-test ──────────────────────────────────────────────
// Each call must type-check against the declared signature.
// These are NOT executed — the file is never imported by the app bundle.

void (async () => {
  // harvest / unharvest accept a session ID string
  const _h: { harvested: boolean; session_id: string } =
    await api.train.harvest("session-uuid");
  const _u: { harvested: boolean; session_id: string } =
    await api.train.unharvest("session-uuid");

  // stats returns TrainStats
  const _s: TrainStats = await api.train.stats();

  // export returns ExportResult
  const _e: ExportResult = await api.train.export();

  // finetune requires base_model + output_name, returns { job_id }
  const _f: { job_id: string } = await api.train.finetune({
    base_model: "llama3.2:8b",
    output_name: "ft-v1",
  });

  // jobs returns TrainingJob[]
  const _j: TrainingJob[] = await api.train.jobs();

  // job returns a single TrainingJob
  const _jj: TrainingJob = await api.train.job("job-uuid");

  // evaluate requires base + candidate, returns { eval_id }
  const _ev: { eval_id: string } = await api.train.evaluate({
    base: "llama3.2:8b",
    candidate: "sigint-ft:latest",
  });

  // lastEvaluation returns EvaluationReport
  const _le: EvaluationReport = await api.train.lastEvaluation();

  // ── api.model ──────────────────────────────────────────────────────────────

  // promote requires tag + force, returns ModelSwapResult
  const _p: ModelSwapResult = await api.model.promote({
    tag: "ft-v1",
    force: false,
  });

  // rollback takes no arguments, returns ModelSwapResult
  const _rb: ModelSwapResult = await api.model.rollback();

  // promotions returns PromotionEntry[]
  const _promo: PromotionEntry[] = await api.model.promotions();

  // Suppress unused-variable warnings in tsc
  void _h; void _u; void _s; void _e; void _f; void _j; void _jj;
  void _ev; void _le; void _p; void _rb; void _promo;
  void checkJobStatus; void checkPromotionAction;
  void _trainStats; void _exportResult; void _evalReport;
  void _promoEntry; void _modelSwapResult; void _trainingJob;
})();
