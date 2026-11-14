import { describe, expect, it } from 'vitest';
import { rewriteCandidate } from '../src/lm/rewrite';

const source = [
  'import os',
  '',
  'def lookup(cursor, name):',
  '    query = "SELECT * FROM users WHERE name = \'" + name + "\'"',
  '    return cursor.execute(query)',
  '',
  'def add(a, b):',
  '    return a + b',
  '',
  'os.system("echo hi")',
].join('\n');

describe('rewriteCandidate', () => {
  it('builds a request for the function under the cursor', () => {
    const candidate = rewriteCandidate(source, 3);
    expect(candidate).toBeDefined();
    expect(candidate!.request.functionName).toBe('lookup');
    expect(candidate!.startLine).toBe(2);
    expect(candidate!.endLine).toBe(4);
    expect(candidate!.request.code).toContain('SELECT * FROM users');
  });

  it('expresses rule hints relative to the snippet', () => {
    const candidate = rewriteCandidate(source, 3);
    const hint = candidate!.request.ruleHints.find((item) => item.cwe === 'CWE-89');
    expect(hint).toBeDefined();
    expect(hint!.line).toBe(2);
  });

  it('does not attach hints from a different function', () => {
    const candidate = rewriteCandidate(source, 7);
    expect(candidate!.request.functionName).toBe('add');
    expect(candidate!.request.ruleHints).toEqual([]);
  });

  it('returns undefined outside a function', () => {
    expect(rewriteCandidate(source, 0)).toBeUndefined();
    expect(rewriteCandidate(source, 9)).toBeUndefined();
  });

  it('skips functions that are too small to be worth a request', () => {
    expect(rewriteCandidate('def f():\n    pass\n', 0)).toBeUndefined();
  });
});
