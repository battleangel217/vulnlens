import type { RuleHit, Severity } from '../types';
import { pythonRules } from '../scan/rules/python';

/** A file and the findings the scanner produced for it. */
export interface FileResult {
  /** Repository-relative path, using forward slashes. */
  readonly path: string;
  readonly findings: readonly RuleHit[];
}

export interface SarifOptions {
  readonly version: string;
  readonly informationUri?: string;
}

const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
};

function ruleName(id: string): string {
  return id
    .split(/[.\-_]/)
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join('');
}

function helpUri(cwe: string): string {
  const match = /^CWE-(\d+)$/i.exec(cwe);
  return match
    ? `https://cwe.mitre.org/data/definitions/${match[1]}.html`
    : 'https://cwe.mitre.org/';
}

function artifactUri(path: string): string {
  // SARIF wants a URI reference. Keep the path relative to the repository root
  // and percent-encode the characters GitHub rejects in a URI.
  return encodeURI(path.replace(/\\/g, '/')).replace(/#/g, '%23');
}

/**
 * Build a SARIF 2.1.0 log for GitHub code scanning.
 *
 * Pure: no file system, no editor API. The CLI owns walking the tree and
 * reading files; this function only shapes the report.
 */
export function buildSarif(
  files: readonly FileResult[],
  options: SarifOptions,
): Record<string, unknown> {
  const rules = pythonRules.map((rule) => ({
    id: rule.id,
    name: ruleName(rule.id),
    shortDescription: { text: rule.title },
    fullDescription: { text: `${rule.title} (${rule.cwe})` },
    helpUri: helpUri(rule.cwe),
    defaultConfiguration: { level: LEVEL[rule.severity] },
    properties: { cwe: rule.cwe, severity: rule.severity, tags: ['security', rule.cwe] },
  }));

  const index = new Map(pythonRules.map((rule, i) => [rule.id, i]));

  const results = files.flatMap((file) =>
    file.findings.map((finding) => ({
      ruleId: finding.ruleId,
      ruleIndex: index.get(finding.ruleId) ?? -1,
      level: LEVEL[finding.severity],
      message: { text: finding.message },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: artifactUri(file.path), uriBaseId: '%SRCROOT%' },
            region: { startLine: finding.line + 1, endLine: finding.endLine + 1 },
          },
        },
      ],
      properties: { cwe: finding.cwe, severity: finding.severity },
    })),
  );

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'VulnLens',
            informationUri:
              options.informationUri ?? 'https://github.com/battleangel217/vulnlens',
            version: options.version,
            rules,
          },
        },
        columnKind: 'utf16CodeUnits',
        results,
      },
    ],
  };
}
