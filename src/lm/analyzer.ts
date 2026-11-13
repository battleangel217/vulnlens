import { createHash } from 'node:crypto';
import { isAbortError } from './types';
import type { AnalyzeRequest, LlmProvider } from './types';
import type { LlmVerdict } from './verdict';

export interface Candidate {
  /** Stable identifier, also used as a cache key. */
  readonly key: string;
  readonly startLine: number;
  readonly endLine: number;
  readonly request: AnalyzeRequest;
}

export interface AnalysisResult {
  readonly candidate: Candidate;
  readonly verdict: LlmVerdict;
  readonly providerId: string;
  readonly model: string;
  readonly latencyMs: number;
  readonly cached: boolean;
}

export interface AnalyzerOptions {
  readonly concurrency?: number;
  readonly timeoutMs?: number;
  readonly signal?: AbortSignal;
  /** Persisting cache owned by the caller so it can survive re-scans. */
  readonly cache?: Map<string, LlmVerdict>;
  readonly onProgress?: (completed: number, total: number) => void;
  readonly onError?: (candidate: Candidate, error: unknown) => void;
}

/** Cache key: provider + model + code + hints. Identical input must never be re-billed. */
export function cacheKey(providerId: string, model: string, request: AnalyzeRequest): string {
  const hints = request.ruleHints
    .map((hint) => `${hint.cwe}@${hint.line}`)
    .join(',');
  return createHash('sha256')
    .update(providerId)
    .update('\u0000')
    .update(model)
    .update('\u0000')
    .update(request.functionName)
    .update('\u0000')
    .update(request.code)
    .update('\u0000')
    .update(hints)
    .digest('hex');
}

async function withTimeout<T>(
  run: (signal: AbortSignal) => Promise<T>,
  timeoutMs: number,
  outer?: AbortSignal,
): Promise<T> {
  const controller = new AbortController();
  const onOuterAbort = () => controller.abort();
  outer?.addEventListener('abort', onOuterAbort, { once: true });
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  try {
    return await run(controller.signal);
  } finally {
    clearTimeout(timer);
    outer?.removeEventListener('abort', onOuterAbort);
  }
}

/**
 * Run model requests with bounded concurrency, a per-request timeout, cache
 * reuse, and cooperative cancellation.
 *
 * A failure on one function never sinks the whole file: errors are reported
 * through `onError` and the remaining candidates still get analysed.
 */
export async function analyzeCandidates(
  candidates: readonly Candidate[],
  provider: LlmProvider,
  options: AnalyzerOptions = {},
): Promise<AnalysisResult[]> {
  if (candidates.length === 0) return [];

  const timeoutMs = options.timeoutMs ?? 25_000;
  const concurrency = Math.max(
    1,
    Math.min(options.concurrency ?? 2, candidates.length),
  );

  const queue = [...candidates];
  const results: AnalysisResult[] = [];
  let completed = 0;

  const report = (): void => {
    completed += 1;
    options.onProgress?.(completed, candidates.length);
  };

  const worker = async (): Promise<void> => {
    for (;;) {
      if (options.signal?.aborted) return;
      const candidate = queue.shift();
      if (!candidate) return;

      const key = cacheKey(provider.id, provider.model, candidate.request);
      const cached = options.cache?.get(key);
      if (cached) {
        results.push({
          candidate,
          verdict: cached,
          providerId: provider.id,
          model: provider.model,
          latencyMs: 0,
          cached: true,
        });
        report();
        continue;
      }

      const startedAt = Date.now();
      try {
        const verdict = await withTimeout(
          (signal) => provider.analyze(candidate.request, signal),
          timeoutMs,
          options.signal,
        );
        options.cache?.set(key, verdict);
        results.push({
          candidate,
          verdict,
          providerId: provider.id,
          model: provider.model,
          latencyMs: Date.now() - startedAt,
          cached: false,
        });
        report();
      } catch (error) {
        report();
        if (isAbortError(error) || options.signal?.aborted) return;
        options.onError?.(candidate, error);
      }
    }
  };

  await Promise.all(Array.from({ length: concurrency }, () => worker()));
  return results;
}
