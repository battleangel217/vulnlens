import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

import { scanPython } from '../src/scan/scanner';

const fixtureRoot = fileURLToPath(new URL('./fixtures', import.meta.url));

function pythonFiles(directory: string): { name: string; source: string }[] {
  return readdirSync(join(fixtureRoot, directory))
    .filter((name) => name.endsWith('.py'))
    .sort()
    .map((name) => ({
      name,
      source: readFileSync(join(fixtureRoot, directory, name), 'utf8'),
    }));
}

describe('safe fixtures', () => {
  const safeFiles = pythonFiles('safe');

  it('has fixtures to check', () => {
    expect(safeFiles.length).toBeGreaterThan(0);
  });

  for (const { name, source } of safeFiles) {
    it(`reports nothing for ${name}`, () => {
      const findings = scanPython(source);
      const report = findings
        .map((finding) => `line ${finding.line + 1}: ${finding.cwe} ${finding.title}`)
        .join('\n');
      expect(findings, `${name} produced false positives:\n${report}`).toEqual([]);
    });
  }
});

describe('demo app', () => {
  it('reports exactly the four documented findings', () => {
    const source = readFileSync(
      fileURLToPath(new URL('../demo/orders_api.py', import.meta.url)),
      'utf8',
    );
    const findings = scanPython(source);
    const report = findings.map((f) => `${f.cwe} line ${f.line + 1}: ${f.title}`).join('\n');

    expect(findings, report).toHaveLength(4);
    expect(new Set(findings.map((f) => f.cwe))).toEqual(
      new Set(['CWE-89', 'CWE-78', 'CWE-502', 'CWE-798']),
    );
  });
});

describe('vulnerable fixture', () => {
  const source = readFileSync(join(fixtureRoot, 'vulnerable', 'app.py'), 'utf8');
  const findings = scanPython(source);

  it('covers all six v1 CWE classes', () => {
    expect(new Set(findings.map((finding) => finding.cwe))).toEqual(
      new Set(['CWE-89', 'CWE-78', 'CWE-22', 'CWE-502', 'CWE-798', 'CWE-327']),
    );
  });

  it('finds each hardcoded credential', () => {
    expect(findings.filter((finding) => finding.cwe === 'CWE-798')).toHaveLength(3);
  });

  it('points at the right lines', () => {
    const byCwe = new Map<string, number[]>();
    for (const finding of findings) {
      byCwe.set(finding.cwe, [...(byCwe.get(finding.cwe) ?? []), finding.line + 1]);
    }

    expect(byCwe.get('CWE-89')).toContain(23); // query = f"SELECT ...
    expect(byCwe.get('CWE-78')).toContain(30); // os.system("ping " + host)
    expect(byCwe.get('CWE-22')).toContain(16); // open(os.path.join("/srv/data", user_id))
    expect(byCwe.get('CWE-502')).toContain(35); // pickle.loads
    expect(byCwe.get('CWE-327')).toContain(39); // hashlib.md5
  });

  it('ignores the intentional suppression comment', () => {
    const withSuppression = scanPython(
      [
        'disable = "hunter2-prod"  # vuln-ignore: CWE-798',
        'digest = hashlib.md5(b"x")',
      ].join('\n'),
    );
    expect(withSuppression.map((finding) => finding.cwe)).toEqual(['CWE-327']);
  });
});
