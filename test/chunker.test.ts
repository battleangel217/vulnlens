import { describe, expect, it } from 'vitest';
import { chunkPython } from '../src/scan/chunker';

describe('chunkPython', () => {
  it('splits functions and keeps top-level statements in module chunks', () => {
    const source = [
      'import os',
      '',
      'BASE = "/srv"',
      '',
      'def alpha(x):',
      '    return x + 1',
      '',
      'def beta(y):',
      '    return y * 2',
      '',
      'print("ready")',
    ].join('\n');

    const chunks = chunkPython(source);
    const names = chunks.map((chunk) => chunk.name);

    expect(names).toContain('alpha');
    expect(names).toContain('beta');
    expect(names.filter((name) => name === '<module>')).toHaveLength(2);

    const alpha = chunks.find((chunk) => chunk.name === 'alpha')!;
    expect(alpha.startLine).toBe(4);
    expect(alpha.endLine).toBe(5);
    expect(alpha.lines.map((line) => line.line)).toEqual([4, 5]);
  });

  it('includes decorators in the function chunk', () => {
    const source = ['@app.route("/x")', 'def handler():', '    return 1'].join('\n');
    const [chunk] = chunkPython(source);
    expect(chunk.startLine).toBe(0);
    expect(chunk.lines[0].text).toBe('@app.route("/x")');
  });

  it('gives class methods their own chunk', () => {
    const source = [
      'class Repo:',
      '    def __init__(self):',
      '        self.db = None',
      '',
      '    def load(self, key):',
      '        return key',
    ].join('\n');

    const chunks = chunkPython(source);
    const methods = chunks.filter((chunk) => chunk.kind === 'function').map((chunk) => chunk.name);
    expect(methods).toEqual(['__init__', 'load']);
  });

  it('returns nothing for an empty file', () => {
    expect(chunkPython('')).toEqual([]);
    expect(chunkPython('\n\n')).toEqual([]);
  });
});
