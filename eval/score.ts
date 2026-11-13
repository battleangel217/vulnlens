/**
 * Scoring for the evaluation harness, kept separate from the runner so the
 * arithmetic that produces the published numbers is itself tested.
 */

export interface LabelledIssue {
  line: number;
  cwe: string;
}

export interface Prediction {
  line: number;
  cwe: string | null;
  severity: string;
  source: string;
}

export interface Counts {
  tp: number;
  fp: number;
  fn: number;
}

export interface ScoredFile {
  counts: Counts;
  falsePositives: Prediction[];
  missed: LabelledIssue[];
}

export function emptyCounts(): Counts {
  return { tp: 0, fp: 0, fn: 0 };
}

export function addCounts(target: Counts, source: Counts): void {
  target.tp += source.tp;
  target.fp += source.fp;
  target.fn += source.fn;
}

/**
 * Match each label to at most one prediction of the same CWE within
 * `tolerance` lines. A prediction can only satisfy one label, so duplicate
 * findings do not count as extra recall.
 */
export function scoreFile(
  expected: readonly LabelledIssue[],
  predicted: readonly Prediction[],
  tolerance: number,
): ScoredFile {
  const used = new Set<number>();
  const missed: LabelledIssue[] = [];
  let tp = 0;

  for (const issue of expected) {
    const index = predicted.findIndex(
      (prediction, candidateIndex) =>
        !used.has(candidateIndex) &&
        prediction.cwe === issue.cwe &&
        Math.abs(prediction.line - issue.line) <= tolerance,
    );
    if (index >= 0) {
      used.add(index);
      tp += 1;
    } else {
      missed.push(issue);
    }
  }

  const falsePositives = predicted.filter((_, index) => !used.has(index));
  return {
    counts: { tp, fp: falsePositives.length, fn: missed.length },
    falsePositives,
    missed,
  };
}

export function precision(counts: Counts): number {
  const denominator = counts.tp + counts.fp;
  return denominator === 0 ? 1 : counts.tp / denominator;
}

export function recall(counts: Counts): number {
  const denominator = counts.tp + counts.fn;
  return denominator === 0 ? 1 : counts.tp / denominator;
}

export function f1(counts: Counts): number {
  const p = precision(counts);
  const r = recall(counts);
  return p + r === 0 ? 0 : (2 * p * r) / (p + r);
}

export function percent(value: number): string {
  return `${(value * 100).toFixed(1)}%`;
}