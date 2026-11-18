import { describe, expect, it } from 'vitest';
import { buildJson, exitCode, formatText, sortFindings, summarize } from '../src/cli/format';
import { buildSarif } from '../src/cli/sarif';
import type { FileResult } from '../src/cli/sarif';
import type { RuleHit } from '../src/types';

const hit = (over: Partial<RuleHit> = {}): RuleHit => ({
  ruleId: 'py.sql-injection',
  cwe: 'CWE-89',
  title: 'SQL injection',
  message: 'Query is built from an f-string.',
  severity: 'high',
  line: 9,
  endLine: 9,
  ...over,
});

const files: FileResult[] = [
  {
    path: 'src/app db.py',
    findings: [
      hit(),
      hit({ ruleId: 'py.weak-crypto', cwe: 'CWE-327', title: 'Weak crypto', severity: 'low', line: 20 }),
    ],
  },
  { path: 'src/clean.py', findings: [] },
];

describe('SARIF output', () => {
  const sarif = buildSarif(files, { version: '9.9.9' }) as any;
  const run = sarif.runs[0];

  it('is SARIF 2.1.0 with the tool metadata', () => {
    expect(sarif.version).toBe('2.1.0');
    expect(run.tool.driver.name).toBe('VulnLens');
    expect(run.tool.driver.version).toBe('9.9.9');
  });

  it('declares every rule once with a CWE link', () => {
    expect(run.tool.driver.rules).toHaveLength(6);
    const sql = run.tool.driver.rules.find((rule: any) => rule.id === 'py.sql-injection');
    expect(sql.properties.cwe).toBe('CWE-89');
    expect(sql.helpUri).toBe('https://cwe.mitre.org/data/definitions/89.html');
  });

  it('maps findings to 1-based lines and encoded URIs', () => {
    expect(run.results).toHaveLength(2);
    const first = run.results[0];
    expect(first.locations[0].physicalLocation.artifactLocation.uri).toBe('src/app%20db.py');
    expect(first.locations[0].physicalLocation.region.startLine).toBe(10);
    expect(first.ruleIndex).toBeGreaterThanOrEqual(0);
  });

  it('maps severity to SARIF level', () => {
    expect(run.results[0].level).toBe('error');
    expect(run.results[1].level).toBe('note');
  });

  it('produces no results for clean files', () => {
    const clean = buildSarif([{ path: 'a.py', findings: [] }], { version: '1' }) as any;
    expect(clean.runs[0].results).toEqual([]);
  });
});

describe('text and JSON output', () => {
  it('counts findings and affected files', () => {
    const summary = summarize(files);
    expect(summary.files).toBe(2);
    expect(summary.filesWithFindings).toBe(1);
    expect(summary.findings).toBe(2);
    expect(summary.bySeverity.high).toBe(1);
    expect(summary.bySeverity.low).toBe(1);
  });

  it('prints a location and a summary', () => {
    const text = formatText(files);
    expect(text).toContain('src/app db.py:10');
    expect(text).toContain('CWE-89');
    expect(text).toContain('2 finding(s) in 1 of 2 file(s)');
  });

  it('says so when nothing is found', () => {
    expect(formatText([{ path: 'a.py', findings: [] }])).toBe('No findings in 1 file(s).');
  });

  it('exits 1 only when findings exist', () => {
    expect(exitCode(files)).toBe(1);
    expect(exitCode([{ path: 'a.py', findings: [] }])).toBe(0);
  });

  it('sorts by severity before line', () => {
    const sorted = sortFindings(files);
    expect(sorted[0].findings.map((finding) => finding.severity)).toEqual(['high', 'low']);
  });

  it('builds a JSON report with the version', () => {
    expect(buildJson(files, '1.2.3')).toMatchObject({
      tool: 'vulnlens',
      version: '1.2.3',
      summary: { findings: 2 },
    });
  });
});
