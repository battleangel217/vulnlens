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