import { describe, expect, it } from 'vitest';
import { buildCandidates, MAX_SNIPPET_CHARS } from '../src/lm/candidates';
import { chunkPython } from '../src/scan/chunker';
import { scanPython } from '../src/scan/scanner';
import type { Chunk } from '../src/types';

const source = [
  'import os',
  '',
  'def safe():',
  '    return os.getcwd()',
  '',
  'def bad():',
  '    return hashlib.md5(b"x")',
].join('\n');

describe('buildCandidates', () => {
  const chunks = chunkPython(source);
  const hits = scanPython(source);

  it('only sends flagged functions by default', () => {
    expect(hits).toHaveLength(1);

    const candidates = buildCandidates({ chunks, hits, deep: false, max: 10 });
    expect(candidates).toHaveLength(1);
    expect(candidates[0].request.functionName).toBe('bad');
    expect(candidates[0].startLine).toBe(5);
  });

  it('expresses hint lines relative to the snippet', () => {
    const [candidate] = buildCandidates({ chunks, hits, deep: false, max: 10 });
    expect(candidate.request.ruleHints[0].cwe).toBe('CWE-327');
    expect(candidate.request.ruleHints[0].line).toBe(2); // def bad() is line 1
    expect(candidate.request.code).toContain('hashlib.md5');
    expect(candidate.request.code.startsWith('def bad():')).toBe(true);
  });

  it('sends every long-enough chunk in deep mode', () => {
    const candidates = buildCandidates({ chunks, hits: [], deep: true, max: 10 });
    const names = candidates.map((candidate) => candidate.request.functionName);
    expect(names).toEqual(['safe', 'bad']); // the "import os" module chunk is too short
  });

  it('honours the request cap', () => {
    const candidates = buildCandidates({ chunks, hits, deep: true, max: 1 });
    expect(candidates).toHaveLength(1);
  });

  it('skips trivial and oversized snippets', () => {
    const trivial: Chunk = {
      name: 'tiny',
      kind: 'function',
      startLine: 0,
      endLine: 0,
      lines: [{ line: 0, text: 'def tiny(): pass' }],
    };
    const huge: Chunk = {
      name: 'huge',
      kind: 'function',
      startLine: 0,
      endLine: 1,
      lines: [
        { line: 0, text: 'def huge():' },
        { line: 1, text: `    x = "${'a'.repeat(MAX_SNIPPET_CHARS)}"` },
      ],
    };

    expect(buildCandidates({ chunks: [trivial, huge], hits: [], deep: true, max: 5 })).toEqual([]);
  });
});
