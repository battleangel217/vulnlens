import { SEVERITY_ORDER, type CodeRule, type RuleHit, type Severity } from '../types';
import { chunkPython } from './chunker';
import { pythonRules } from './rules/python';

export interface ScanOptions {
  /** Override the rule set (tests use this to isolate a single rule). */
  readonly rules?: readonly CodeRule[];
  /** Findings below this severity are dropped. Defaults to "low". */
  readonly minSeverity?: Severity;
  /** Set to false to ignore `# vuln-ignore` comments. Defaults to true. */
  readonly respectSuppressions?: boolean;
}

export const SUPPRESSION_RE = /vuln-ignore(?::\s*(CWE-\d+))?/i;

/**
 * Scan Python source and return findings sorted by line.
 *
 * Pure function: same input always produces the same output, no `vscode`
 * import, no I/O. Everything that talks to the editor lives outside this file.
 */
export function scanPython(source: string, options: ScanOptions = {}): RuleHit[] {
  const rules = options.rules ?? pythonRules;
  const minSeverity = options.minSeverity ?? 'low';
  const sourceLines = source.split(/\r?\n/);
  const chunks = chunkPython(source);

  // Chunks can overlap (a nested def is also inside its parent), so collapse
  // duplicate findings for the same rule and line, keeping the worst severity.
  const deduped = new Map<string, RuleHit>();

  for (const chunk of chunks) {
    for (const rule of rules) {
      for (const finding of rule.run(chunk)) {
        const key = `${finding.ruleId}:${finding.line}`;
        const existing = deduped.get(key);
        if (!existing || SEVERITY_ORDER[finding.severity] > SEVERITY_ORDER[existing.severity]) {
          deduped.set(key, finding);
        }
      }
    }
  }

  let findings = [...deduped.values()];

  if (options.respectSuppressions !== false) {
    findings = findings.filter((finding) => !isSuppressed(finding, sourceLines));
  }

  return findings
    .filter((finding) => SEVERITY_ORDER[finding.severity] >= SEVERITY_ORDER[minSeverity])
    .sort(
      (a, b) => a.line - b.line || SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity],
    );
}

function isSuppressed(finding: RuleHit, lines: readonly string[]): boolean {
  // Same line (trailing comment) or the line directly above (standalone comment).
  for (const index of [finding.line - 1, finding.line]) {
    if (index < 0 || index >= lines.length) continue;
    const match = SUPPRESSION_RE.exec(lines[index]);
    if (!match) continue;
    if (!match[1] || match[1].toUpperCase() === finding.cwe.toUpperCase()) return true;
  }
  return false;
}

/** Convenience for callers that only need counts. */
export function summarize(findings: readonly RuleHit[]): Record<Severity, number> {
  const summary: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const finding of findings) summary[finding.severity] += 1;
  return summary;
}
