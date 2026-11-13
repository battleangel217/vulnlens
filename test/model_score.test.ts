import { describe, expect, it } from 'vitest';
import {
  evaluateThreshold,
  fileF1,
  filePrecision,
  fileProbability,
  fileRecall,
  issueCovered,
  sweep,
  type ModelFile,
} from '../eval/model_score';

function file(
  name: string,
  category: ModelFile['category'],
  chunks: { startLine: number; endLine: number; probability: number }[],
  issues: { line: number }[] = [],
): ModelFile {
  return { file: name, category, chunks, issues };
}

describe('fileProbability', () => {
  it('uses the maximum chunk score', () => {
    expect(fileProbability([{ startLine: 0, endLine: 2, probability: 0.2 }, { startLine: 5, endLine: 9, probability: 0.83 }])).toBeCloseTo(0.83);
  });

  it('is zero when nothing was scored', () => {
    expect(fileProbability([])).toBe(0);
  });
});

describe('issueCovered', () => {
  const chunks = [
    { startLine: 2, endLine: 6, probability: 0.9 },
    { startLine: 8, endLine: 12, probability: 0.1 },
  ];

  it('requires both containment and the threshold', () => {
    expect(issueCovered(chunks, 4, 0.5)).toBe(true);
    expect(issueCovered(chunks, 4, 0.95)).toBe(false);
    expect(issueCovered(chunks, 10, 0.05)).toBe(true);
    expect(issueCovered(chunks, 7, 0.5)).toBe(false);
  });
});

describe('evaluateThreshold', () => {
  const files = [
    file('v1', 'vulnerable', [{ startLine: 0, endLine: 3, probability: 0.9 }], [{ line: 2 }, { line: 9 }]),
    file('v2', 'vulnerable', [{ startLine: 0, endLine: 3, probability: 0.3 }], [{ line: 1 }]),
    file('c1', 'clean', [{ startLine: 0, endLine: 3, probability: 0.2 }]),
    file('c2', 'clean', [{ startLine: 0, endLine: 3, probability: 0.8 }]),
  ];

  it('counts file-level outcomes at 0.5', () => {
    const result = evaluateThreshold(files, 0.5);
    expect(result.files).toEqual({ tp: 1, fp: 1, fn: 1, tn: 1 });
    expect(result.totalIssues).toBe(3);
    expect(result.coveredIssues).toBe(1);
  });

  it('trades recall for precision as the threshold rises', () => {
    expect(evaluateThreshold(files, 0.95).files).toEqual({ tp: 0, fp: 0, fn: 2, tn: 2 });
    expect(evaluateThreshold(files, 0.1).files).toEqual({ tp: 2, fp: 2, fn: 0, tn: 0 });
  });

  it('sorts a sweep ascending and evaluates every point', () => {
    const results = sweep(files, [0.9, 0.1, 0.5]);
    expect(results.map((result) => result.threshold)).toEqual([0.1, 0.5, 0.9]);
    expect(results).toHaveLength(3);
  });
});

describe('file metrics', () => {
  it('computes precision, recall, and F1 with safe empty denominators', () => {
    expect(filePrecision({ tp: 3, fp: 1, fn: 0, tn: 0 })).toBeCloseTo(0.75);
    expect(fileRecall({ tp: 3, fp: 0, fn: 1, tn: 0 })).toBeCloseTo(0.75);
    expect(fileF1({ tp: 3, fp: 1, fn: 1, tn: 0 })).toBeCloseTo(0.75);
    expect(filePrecision({ tp: 0, fp: 0, fn: 0, tn: 4 })).toBe(1);
    expect(fileRecall({ tp: 0, fp: 0, fn: 0, tn: 4 })).toBe(1);
  });
});