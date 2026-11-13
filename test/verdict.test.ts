import { describe, expect, it } from 'vitest';
import { cleanFix, extractJsonObject, parseVerdict } from '../src/lm/verdict';

const valid = JSON.stringify({
  verdict: 'vulnerable',
  cwe: 'CWE-89',
  severity: 'high',
  confidence: 0.82,
  line: 3,
  reason: 'term is interpolated into the query',
  fix: 'def search():\n    pass',
});

describe('parseVerdict', () => {
  it('parses a bare JSON object', () => {
    const result = parseVerdict(valid);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.verdict.cwe).toBe('CWE-89');
    expect(result.verdict.confidence).toBeCloseTo(0.82);
    expect(result.verdict.line).toBe(3);
  });

  it('parses fenced JSON', () => {
    const result = parseVerdict('```json\n' + valid + '\n```');
    expect(result.ok).toBe(true);
  });

  it('ignores prose around the object', () => {
    const result = parseVerdict(`Sure, here is my analysis.\n${valid}\nHope that helps!`);
    expect(result.ok).toBe(true);
  });

  it('coerces confidence percentages and numeric strings', () => {
    const percent = parseVerdict(valid.replace('0.82', '"82%"'));
    expect(percent.ok && percent.verdict.confidence).toBeCloseTo(0.82);

    const stringy = parseVerdict(valid.replace('0.82', '"0.6"'));
    expect(stringy.ok && stringy.verdict.confidence).toBeCloseTo(0.6);
  });

  it('normalises cwe casing and coerces string line numbers', () => {
    const result = parseVerdict(valid.replace('"CWE-89"', '"cwe-89"').replace('3', '"7"'));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.verdict.cwe).toBe('CWE-89');
    expect(result.verdict.line).toBe(7);
  });

  it('treats line 0 as unknown instead of failing', () => {
    const result = parseVerdict(valid.replace('"line":3', '"line":0'));
    expect(result.ok && result.verdict.line).toBeNull();
  });

  it('drops unknown keys', () => {
    const result = parseVerdict(valid.replace('{', '{"extra":"ignored",'));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(Object.keys(result.verdict)).not.toContain('extra');
  });

  it('reports a useful error for missing fields', () => {
    const result = parseVerdict('{"verdict":"vulnerable"}');
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.error).toContain('reason');
  });

  it('rejects an invalid verdict value', () => {
    const result = parseVerdict(valid.replace('"vulnerable"', '"exploitable"'));
    expect(result.ok).toBe(false);
  });

  it('rejects a response with no JSON at all', () => {
    const result = parseVerdict('I cannot help with that.');
    expect(result).toEqual({ ok: false, error: 'response contained no JSON object' });
  });
});

describe('extractJsonObject', () => {
  it('keeps nested braces intact', () => {
    const text = 'noise {"a":{"b":1},"c":2} trailing';
    expect(extractJsonObject(text)).toBe('{"a":{"b":1},"c":2}');
  });
});

describe('cleanFix', () => {
  it('strips python fences', () => {
    expect(cleanFix('```python\ndef f():\n    return 1\n```')).toBe('def f():\n    return 1');
  });

  it('returns undefined for empty input', () => {
    expect(cleanFix(null)).toBeUndefined();
    expect(cleanFix('   ')).toBeUndefined();
  });
});
