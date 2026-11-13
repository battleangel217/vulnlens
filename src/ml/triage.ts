import { MAX_SNIPPET_CHARS } from '../lm/candidates';
import type { Chunk } from '../types';

/**
 * Local-model triage.
 *
 * The ONNX classifier is a candidate generator, not a diagnostic. It says
 * "this function looks suspicious"; the rule engine supplies precise checks and
 * the LLM supplies the explanation. Keeping the model out of the diagnostic
 * path means a badly calibrated model can raise cost, but cannot invent
 * findings on its own.
 */

export interface TriageOptions {
  /** Maximum functions to score per file. Default 40. */
  readonly maxChunks?: number;
  /** Snippets shorter than this are not worth a tokenisation pass. Default 20. */
  readonly minChars?: number;
  /** Per-function timeout. The pool has its own; this protects other scorers. */
  readonly timeoutMs?: number;
}

export interface TriageSummary {
  /** chunk.startLine -> P(vulnerable), clamped to 0..1. */
  readonly scores: ReadonlyMap<number, number>;
  readonly scored: number;
  readonly skipped: number;
  readonly failed: number;
}

export type ScoreFn = (code: string) => Promise<number>;

export function clampProbability(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.min(1, Math.max(0, value));
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  if (timeoutMs <= 0) return promise;

  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new Error(`triage timed out after ${timeoutMs}ms`)), timeoutMs);
  });

  try {
    return await Promise.race([promise, timeout]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

export async function triageChunks(
  chunks: readonly Chunk[],
  score: ScoreFn,
  options: TriageOptions = {},
): Promise<TriageSummary> {
  const maxChunks = Math.max(1, options.maxChunks ?? 40);
  const minChars = Math.max(1, options.minChars ?? 20);
  const timeoutMs = options.timeoutMs ?? 0;

  const eligible = chunks.filter((chunk) => {
    const length = chunk.lines.reduce((sum, line) => sum + line.text.length + 1, 0);
    return length >= minChars && length <= MAX_SNIPPET_CHARS;
  });

  const selected = eligible.slice(0, maxChunks);
  const scores = new Map<number, number>();
  let failed = 0;

  await Promise.all(
    selected.map(async (chunk) => {
      const code = chunk.lines.map((line) => line.text).join('\n');
      try {
        const probability = await withTimeout(score(code), timeoutMs);
        scores.set(chunk.startLine, clampProbability(probability));
      } catch {
        failed += 1;
      }
    }),
  );

  return {
    scores,
    scored: scores.size,
    skipped: chunks.length - selected.length,
    failed,
  };
}