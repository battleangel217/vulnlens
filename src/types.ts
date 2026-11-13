/**
 * Shared vocabulary for the scanner.
 *
 * Everything in src/scan/ is pure TypeScript with no `vscode` import so it can
 * be unit tested without an extension host. The vscode layer lives in src/ui/
 * and src/extension.ts.
 */

export type Severity = 'critical' | 'high' | 'medium' | 'low';

/** Higher number = more severe. */
export const SEVERITY_ORDER: Record<Severity, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

/** A line of source code, tagged with its absolute 0-based line number. */
export interface SourceLine {
  readonly line: number;
  readonly text: string;
}

/**
 * A unit handed to the rules. Functions are chunked individually so the same
 * text can later be sent to an LLM without dragging the whole file along.
 */
export interface Chunk {
  readonly name: string;
  readonly kind: 'function' | 'module';
  readonly startLine: number;
  readonly endLine: number;
  readonly lines: readonly SourceLine[];
}

export interface RuleHit {
  readonly ruleId: string;
  /** CWE identifier, e.g. "CWE-89". */
  readonly cwe: string;
  readonly title: string;
  readonly message: string;
  readonly severity: Severity;
  /** Absolute 0-based line number. */
  readonly line: number;
  /** Last line covered by the finding (equal to `line` for single-line matches). */
  readonly endLine: number;
}

export interface CodeRule {
  readonly id: string;
  readonly cwe: string;
  readonly title: string;
  readonly severity: Severity;
  run(chunk: Chunk): RuleHit[];
}

/** Convenience constructor so rules stay declarative. */
export function hit(
  rule: Pick<CodeRule, 'id' | 'cwe' | 'title' | 'severity'>,
  line: number,
  message: string,
  endLine: number = line,
): RuleHit {
  return {
    ruleId: rule.id,
    cwe: rule.cwe,
    title: rule.title,
    severity: rule.severity,
    message,
    line,
    endLine,
  };
}
