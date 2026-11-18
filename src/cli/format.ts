import { SEVERITY_ORDER, type Severity } from '../types';
import type { FileResult } from './sarif';

export interface Summary {
  readonly files: number;
  readonly filesWithFindings: number;
  readonly findings: number;
  readonly bySeverity: Record<Severity, number>;
}

export function summarize(files: readonly FileResult[]): Summary {
  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  let findings = 0;
  let filesWithFindings = 0;

  for (const file of files) {
    if (file.findings.length > 0) filesWithFindings += 1;
    for (const finding of file.findings) {
      findings += 1;
      bySeverity[finding.severity] += 1;
    }
  }

  return { files: files.length, filesWithFindings, findings, bySeverity };
}

/** Human-readable report, one block per finding, followed by a summary line. */
export function formatText(files: readonly FileResult[]): string {
  const lines: string[] = [];

  for (const file of files) {
    for (const finding of file.findings) {
      const location =
        finding.endLine === finding.line
          ? `${file.path}:${finding.line + 1}`
          : `${file.path}:${finding.line + 1}-${finding.endLine + 1}`;
      lines.push(
        `${location}  ${finding.severity.padEnd(8)} ${finding.cwe.padEnd(8)} ${finding.title}`,
      );
      lines.push(`  ${finding.message}`);
    }
  }

  const summary = summarize(files);
  if (lines.length > 0) lines.push('');

  lines.push(
    summary.findings === 0
      ? `No findings in ${summary.files} file(s).`
      : `${summary.findings} finding(s) in ${summary.filesWithFindings} of ${summary.files} file(s): ` +
          (['critical', 'high', 'medium', 'low'] as const)
            .filter((severity) => summary.bySeverity[severity] > 0)
            .map((severity) => `${summary.bySeverity[severity]} ${severity}`)
            .join(', '),
  );

  return lines.join('\n');
}

export interface JsonReport {
  readonly tool: 'vulnlens';
  readonly version: string;
  readonly summary: Summary;
  readonly files: readonly FileResult[];
}

export function buildJson(
  files: readonly FileResult[],
  version: string,
): JsonReport {
  return { tool: 'vulnlens', version, summary: summarize(files), files };
}

/** Exit code helper: 1 when anything was found, so CI fails the build. */
export function exitCode(files: readonly FileResult[]): number {
  return files.some((file) => file.findings.length > 0) ? 1 : 0;
}

/** Sort by severity, then path, then line. */
export function sortFindings(files: readonly FileResult[]): FileResult[] {
  return files.map((file) => ({
    path: file.path,
    findings: [...file.findings].sort(
      (a, b) =>
        SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity] ||
        a.line - b.line ||
        a.ruleId.localeCompare(b.ruleId),
    ),
  }));
}
