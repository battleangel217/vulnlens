import { describe, expect, it } from 'vitest';
import type { AnalysisResult } from '../src/lm/analyzer';
import type { LlmVerdict } from '../src/lm/verdict';
import { chunkPython } from '../src/scan/chunker';
import { scanPython } from '../src/scan/scanner';
import { presentFindings } from '../src/ui/present';

const sqlSource = [
  'def search():',
  '    cursor.execute(f"SELECT * FROM t WHERE id = {uid}")',
].join('\n');

function analysis(init: {
  verdict: Partial<LlmVerdict>;
  startLine: number;
  endLine: number;
  code: string;
  functionName?: string;
}): AnalysisResult {
  const verdict: LlmVerdict = {
    verdict: 'vulnerable',
    cwe: null,
    severity: null,
    confidence: 0.8,
    line: 1,
    reason: 'because',
    fix: null,
    ...init.verdict,
  };

  return {
    candidate: {
      key: `${init.startLine}:${init.endLine}`,
      startLine: init.startLine,
      endLine: init.endLine,
      request: {
        code: init.code,
        functionName: init.functionName ?? 'fn',
        ruleHints: [],
      },
    },
    verdict,
    providerId: 'ollama',
    model: 'qwen2.5-coder:7b',
    latencyMs: 42,
    cached: false,
  };
}

describe('presentFindings', () => {
  const chunks = chunkPython(sqlSource);
  const hits = scanPython(sqlSource);

  it('passes rule findings through unchanged when no analysis exists', () => {
    const [finding] = presentFindings({ hits, chunks, analyses: [] });
    expect(finding.source).toBe('rules');
    expect(finding.severity).toBe('high');
    expect(finding.dismissed).toBe(false);
    expect(finding.message).toContain('SQL injection (CWE-89)');
  });

  it('upgrades severity and attaches the model explanation when confirmed', () => {
    const [finding] = presentFindings({
      hits,
      chunks,
      analyses: [
        analysis({
          startLine: 0,
          endLine: 1,
          code: sqlSource,
          verdict: {
            verdict: 'vulnerable',
            cwe: 'CWE-89',
            severity: 'critical',
            confidence: 0.91,
            reason: 'uid is interpolated into the query',
            fix: '```python\ndef search():\n    pass\n```',
          },
        }),
      ],
    });

    expect(finding.source).toBe('rules+ai');
    expect(finding.severity).toBe('critical');
    expect(finding.confidence).toBeCloseTo(0.91);
    expect(finding.message).toContain('91% confidence');
    expect(finding.message).toContain('uid is interpolated');
    expect(finding.fix).toBe('def search():\n    pass');
    expect(finding.chunkCode).toBe(sqlSource);
    expect(finding.provider).toBe('ollama/qwen2.5-coder:7b');
  });

  it('marks a confident "safe" verdict as dismissed', () => {
    const [finding] = presentFindings({
      hits,
      chunks,
      analyses: [
        analysis({
          startLine: 0,
          endLine: 1,
          code: sqlSource,
          verdict: {
            verdict: 'safe',
            cwe: 'CWE-89',
            confidence: 0.9,
            reason: 'the parameter is an int from a path converter',
          },
        }),
      ],
    });

    expect(finding.dismissed).toBe(true);
    expect(finding.severity).toBe('low');
    expect(finding.message).toContain('likely a false positive');
    expect(finding.message).toContain('path converter');
  });

  it('keeps the finding when the model is not confident enough to dismiss', () => {
    const [finding] = presentFindings({
      hits,
      chunks,
      analyses: [
        analysis({
          startLine: 0,
          endLine: 1,
          code: sqlSource,
          verdict: { verdict: 'safe', confidence: 0.3, reason: 'unsure' },
        }),
      ],
      minConfidence: 0.6,
    });

    expect(finding.dismissed).toBe(false);
    expect(finding.severity).toBe('high');
  });

  it('adds findings the rules missed', () => {
    const source = ['def handler():', '    return compute(data)'].join('\n');
    const localChunks = chunkPython(source);

    const findings = presentFindings({
      hits: scanPython(source),
      chunks: localChunks,
      analyses: [
        analysis({
          startLine: 0,
          endLine: 1,
          code: source,
          verdict: {
            verdict: 'vulnerable',
            cwe: 'CWE-89',
            severity: 'high',
            confidence: 0.75,
            line: 2,
            reason: 'data reaches a query',
          },
        }),
      ],
    });

    expect(findings).toHaveLength(1);
    expect(findings[0].source).toBe('ai');
    expect(findings[0].title).toBe('SQL injection');
    expect(findings[0].line).toBe(1);
    expect(findings[0].message).toContain('AI found');
  });

  it('does not duplicate a rule finding the model reported on a nearby line', () => {
    const findings = presentFindings({
      hits,
      chunks,
      analyses: [
        analysis({
          startLine: 0,
          endLine: 1,
          code: sqlSource,
          verdict: { verdict: 'vulnerable', cwe: 'CWE-89', line: 2, confidence: 0.9 },
        }),
      ],
    });

    expect(findings).toHaveLength(1);
    expect(findings[0].source).toBe('rules+ai');
  });

  it('still adds an AI finding for a different CWE in the same function', () => {
    const source = ['def digest(data):', '    return hashlib.md5(data).hexdigest()'].join('\n');
    const localChunks = chunkPython(source);

    const findings = presentFindings({
      hits: scanPython(source),
      chunks: localChunks,
      analyses: [
        analysis({
          startLine: 0,
          endLine: 1,
          code: source,
          verdict: { verdict: 'vulnerable', cwe: 'CWE-328', confidence: 0.7, line: 2 },
        }),
      ],
    });

    expect(findings.map((finding) => finding.cwe)).toEqual(['CWE-327', 'CWE-328']);
  });

  it('clamps an out-of-range model line to the analysed function', () => {
    const findings = presentFindings({
      hits: [],
      chunks,
      analyses: [
        analysis({
          startLine: 0,
          endLine: 1,
          code: sqlSource,
          verdict: { verdict: 'vulnerable', cwe: 'CWE-78', line: 99, confidence: 0.8 },
        }),
      ],
    });

    expect(findings[0].line).toBe(1);
  });

  it('labels a finding with no CWE generically', () => {
    const findings = presentFindings({
      hits: [],
      chunks,
      analyses: [
        analysis({
          startLine: 0,
          endLine: 1,
          code: sqlSource,
          verdict: { verdict: 'vulnerable', cwe: null, confidence: 0.7 },
        }),
      ],
    });

    expect(findings[0].title).toBe('Potential vulnerability');
    expect(findings[0].cwe).toBeNull();
  });

  it('sorts by line and then severity', () => {
    const source = ['def f():', '    password = "hunter2-prod"', '    return hashlib.md5(b"x")'].join(
      '\n',
    );
    const findings = presentFindings({
      hits: scanPython(source),
      chunks: chunkPython(source),
      analyses: [],
    });

    expect(findings.map((finding) => finding.line)).toEqual([1, 2]);
  });
});
