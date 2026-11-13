import { describe, expect, it } from 'vitest';
import {
  addCounts,
  emptyCounts,
  f1,
  precision,
  recall,
  scoreFile,
  type Prediction,
} from '../eval/score';

function prediction(line: number, cwe: string | null): Prediction {
  return { line, cwe, severity: 'high', source: 'rules' };
}

describe('scoreFile', () => {
  it('matches a label to one prediction of the same CWE within tolerance', () => {
    const score = scoreFile([{ line: 10, cwe: 'CWE-89' }], [prediction(12, 'CWE-89')], 2);
    expect(score.counts).toEqual({ tp: 1, fp: 0, fn: 0 });
  });

  it('rejects a match outside tolerance', () => {
    const score = scoreFile([{ line: 10, cwe: 'CWE-89' }], [prediction(13, 'CWE-89')], 2);
    expect(score.counts).toEqual({ tp: 0, fp: 1, fn: 1 });
    expect(score.missed).toEqual([{ line: 10, cwe: 'CWE-89' }]);
    expect(score.falsePositives).toHaveLength(1);
  });

  it('does not accept the right line with the wrong CWE', () => {
    const score = scoreFile([{ line: 10, cwe: 'CWE-89' }], [prediction(10, 'CWE-78')], 2);
    expect(score.counts).toEqual({ tp: 0, fp: 1, fn: 1 });
  });

  it('counts duplicate findings as false positives, not extra recall', () => {
    const score = scoreFile(
      [{ line: 10, cwe: 'CWE-89' }],
      [prediction(10, 'CWE-89'), prediction(11, 'CWE-89')],
      2,
    );
    expect(score.counts).toEqual({ tp: 1, fp: 1, fn: 0 });
  });

  it('treats an unpredicted clean file as a perfect score', () => {
    const score = scoreFile([], [], 2);
    expect(score.counts).toEqual({ tp: 0, fp: 0, fn: 0 });
  });

  it('ignores findings with no CWE for matching, but counts them as false positives', () => {
    const score = scoreFile([{ line: 10, cwe: 'CWE-89' }], [prediction(10, null)], 2);
    expect(score.counts).toEqual({ tp: 0, fp: 1, fn: 1 });
  });
});

describe('metrics', () => {
  it('computes precision, recall, and F1', () => {
    const counts = { tp: 22, fp: 2, fn: 7 };
    expect(precision(counts)).toBeCloseTo(22 / 24);
    expect(recall(counts)).toBeCloseTo(22 / 29);
    expect(f1(counts)).toBeCloseTo((2 * (22 / 24) * (22 / 29)) / (22 / 24 + 22 / 29));
  });

  it('defines empty denominators as 1 rather than NaN', () => {
    expect(precision({ tp: 0, fp: 0, fn: 3 })).toBe(1);
    expect(recall({ tp: 0, fp: 2, fn: 0 })).toBe(1);
    expect(f1({ tp: 0, fp: 0, fn: 0 })).toBe(1);
  });

  it('accumulates counts without mutating the source', () => {
    const target = emptyCounts();
    const source = { tp: 2, fp: 1, fn: 3 };
    addCounts(target, source);
    addCounts(target, source);
    expect(target).toEqual({ tp: 4, fp: 2, fn: 6 });
    expect(source).toEqual({ tp: 2, fp: 1, fn: 3 });
  });
});