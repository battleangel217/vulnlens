import { describe, expect, it } from 'vitest';
import { clampProbability, triageChunks } from '../src/ml/triage';
import type { Chunk } from '../src/types';

function chunk(name: string, startLine: number, body: readonly string[]): Chunk {
  return {
    name,
    kind: 'function',
    startLine,
    endLine: startLine + body.length - 1,
    lines: body.map((text, index) => ({ line: startLine + index, text })),
  };
}

function reasonablyLong(name: string, startLine: number): Chunk {
  return chunk(name, startLine, [
    `def ${name}(value):`,
    '    processed = transform(value)',
    '    return processed',
  ]);
}

describe('clampProbability', () => {
  it('keeps values inside 0..1 and rejects NaN', () => {
    expect(clampProbability(0.4)).toBe(0.4);
    expect(clampProbability(1.7)).toBe(1);
    expect(clampProbability(-2)).toBe(0);
    expect(clampProbability(Number.NaN)).toBe(0);
    expect(clampProbability(Number.POSITIVE_INFINITY)).toBe(0);
  });
});

describe('triageChunks', () => {
  it('scores every eligible chunk and keys results by start line', async () => {
    const chunks = [reasonablyLong('a', 0), reasonablyLong('b', 10)];
    const summary = await triageChunks(chunks, async (code) => (code.includes('def a(') ? 0.9 : 0.2));

    expect(summary.scored).toBe(2);
    expect(summary.scores.get(0)).toBeCloseTo(0.9);
    expect(summary.scores.get(10)).toBeCloseTo(0.2);
    expect(summary.failed).toBe(0);
    expect(summary.skipped).toBe(0);
  });

  it('skips snippets too short to carry signal', async () => {
    const tiny = chunk('tiny', 0, ['def f():', '    pass']);
    const calls: string[] = [];
    const summary = await triageChunks([tiny, reasonablyLong('a', 10)], async (code) => {
      calls.push(code);
      return 0.5;
    });

    expect(summary.skipped).toBe(1);
    expect(summary.scored).toBe(1);
    expect(calls).toHaveLength(1);
  });

  it('caps the number of scored chunks', async () => {
    const chunks = Array.from({ length: 5 }, (_, index) => reasonablyLong(`f${index}`, index * 10));
    const summary = await triageChunks(chunks, async () => 0.5, { maxChunks: 2 });
    expect(summary.scored).toBe(2);
    expect(summary.skipped).toBe(3);
  });

  it('counts a failure without losing the other scores', async () => {
    const chunks = [reasonablyLong('bad', 0), reasonablyLong('good', 10)];
    const summary = await triageChunks(chunks, async (code) => {
      if (code.includes('bad')) throw new Error('inference exploded');
      return 0.7;
    });

    expect(summary.failed).toBe(1);
    expect(summary.scores.size).toBe(1);
    expect(summary.scores.get(10)).toBeCloseTo(0.7);
  });

  it('enforces a timeout for a scorer that never settles', async () => {
    const chunks = [reasonablyLong('hang', 0)];
    const summary = await triageChunks(chunks, () => new Promise<number>(() => {}), {
      timeoutMs: 25,
    });

    expect(summary.failed).toBe(1);
    expect(summary.scored).toBe(0);
  });

  it('returns an empty summary for an empty file', async () => {
    const summary = await triageChunks([], async () => 1);
    expect(summary.scores.size).toBe(0);
    expect(summary.scored).toBe(0);
    expect(summary.failed).toBe(0);
  });
});