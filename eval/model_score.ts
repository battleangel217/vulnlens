/**
 * Metrics for the local triage model.
 *
 * The model does not predict CWE or a line, so the useful questions are:
 *  1. At threshold t, which files does it flag? (file-level precision/recall)
 *  2. Does the highest-scoring chunk cover each labelled issue? (function-level
 *     recall, which is what the AI verifier actually depends on)
 */

export interface ScoredChunk {
  readonly startLine: number;
  readonly endLine: number;
  readonly probability: number;
}

export interface ModelFile {
  readonly file: string;
  readonly category: 'vulnerable' | 'clean';
  readonly issues: readonly { readonly line: number }[];
  readonly chunks: readonly ScoredChunk[];
}

export interface FileCounts {
  tp: number;
  fp: number;
  fn: number;
  tn: number;
}

export interface ThresholdResult {
  readonly threshold: number;
  readonly files: FileCounts;
  readonly coveredIssues: number;
  readonly totalIssues: number;
}

/** A file is as suspicious as its most suspicious function. */
export function fileProbability(chunks: readonly ScoredChunk[]): number {
  let best = 0;
  for (const chunk of chunks) best = Math.max(best, chunk.probability);
  return best;
}

export function issueCovered(
  chunks: readonly ScoredChunk[],
  line: number,
  threshold: number,
): boolean {
  return chunks.some(
    (chunk) => line >= chunk.startLine && line <= chunk.endLine && chunk.probability >= threshold,
  );
}

export function evaluateThreshold(
  files: readonly ModelFile[],
  threshold: number,
): ThresholdResult {
  const counts: FileCounts = { tp: 0, fp: 0, fn: 0, tn: 0 };
  let coveredIssues = 0;
  let totalIssues = 0;

  for (const file of files) {
    const flagged = fileProbability(file.chunks) >= threshold;

    if (file.category === 'vulnerable') {
      if (flagged) counts.tp += 1;
      else counts.fn += 1;

      for (const issue of file.issues) {
        totalIssues += 1;
        if (issueCovered(file.chunks, issue.line, threshold)) coveredIssues += 1;
      }
    } else if (flagged) {
      counts.fp += 1;
    } else {
      counts.tn += 1;
    }
  }

  return { threshold, files: counts, coveredIssues, totalIssues };
}

export function sweep(files: readonly ModelFile[], thresholds: readonly number[]): ThresholdResult[] {
  return [...thresholds].sort((a, b) => a - b).map((threshold) => evaluateThreshold(files, threshold));
}

/** Linear-interpolated quantile of an ascending array (numpy's default). */
export function quantile(sorted: readonly number[], q: number): number {
  if (sorted.length === 0) return 0;
  const position = (sorted.length - 1) * Math.min(1, Math.max(0, q));
  const lower = Math.floor(position);
  const upper = Math.ceil(position);
  if (lower === upper) return sorted[lower];
  const weight = position - lower;
  return sorted[lower] * (1 - weight) + sorted[upper] * weight;
}

export interface ScoreDistribution {
  readonly category: 'vulnerable' | 'clean';
  readonly files: number;
  readonly min: number;
  readonly median: number;
  readonly max: number;
}

/**
 * Per-category spread of file scores. A model whose whole range sits below the
 * fixed sweep grid can look like "zero at every threshold" while still ranking
 * a little; showing the range makes that difference visible.
 */
export function scoreDistribution(files: readonly ModelFile[]): ScoreDistribution[] {
  return (['vulnerable', 'clean'] as const).map((category) => {
    const scores = files
      .filter((file) => file.category === category)
      .map((file) => fileProbability(file.chunks))
      .sort((a, b) => a - b);
    if (scores.length === 0) {
      return { category, files: 0, min: 0, median: 0, max: 0 };
    }
    return {
      category,
      files: scores.length,
      min: scores[0],
      median: quantile(scores, 0.5),
      max: scores[scores.length - 1],
    };
  });
}

/**
 * Thresholds drawn from the model's own chunk-score quantiles. Fixed grids
 * (0.1..0.9) are useful for a calibrated model but miss a model whose scores
 * are all near the base rate.
 */
export function scoreQuantileThresholds(
  files: readonly ModelFile[],
  quantiles: readonly number[] = [0.5, 0.75, 0.9, 0.95, 0.99],
): number[] {
  const scores = files
    .flatMap((file) => file.chunks.map((chunk) => chunk.probability))
    .sort((a, b) => a - b);
  if (scores.length === 0) return [];
  return [...new Set(quantiles.map((q) => Number(quantile(scores, q).toFixed(5))))];
}

export function filePrecision(counts: FileCounts): number {
  const denominator = counts.tp + counts.fp;
  return denominator === 0 ? 1 : counts.tp / denominator;
}

export function fileRecall(counts: FileCounts): number {
  const denominator = counts.tp + counts.fn;
  return denominator === 0 ? 1 : counts.tp / denominator;
}

export function fileF1(counts: FileCounts): number {
  const precision = filePrecision(counts);
  const recall = fileRecall(counts);
  return precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);
}