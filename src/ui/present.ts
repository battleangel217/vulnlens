import { SEVERITY_ORDER } from '../types';
import type { Chunk, RuleHit, Severity } from '../types';
import type { AnalysisResult } from '../lm/analyzer';
import type { LlmVerdict } from '../lm/verdict';
import { cleanFix } from '../lm/verdict';
import { CWE_TITLES } from '../scan/rules/python';

export type FindingSource = 'rules' | 'rules+ai' | 'ai';

/**
 * A finding ready to render. Kept free of `vscode` types so the merge logic can
 * be unit tested; `extension.ts` turns these into Diagnostics.
 */
export interface PresentedFinding {
  readonly cwe: string | null;
  readonly title: string;
  readonly severity: Severity;
  readonly line: number;
  readonly endLine: number;
  readonly message: string;
  readonly reason?: string;
  readonly confidence?: number;
  readonly fix?: string;
  readonly source: FindingSource;
  readonly dismissed: boolean;
  readonly chunkStartLine: number;
  readonly chunkEndLine: number;
  /** Exact text the analysis saw, used to refuse stale whole-function fixes. */
  readonly chunkCode: string;
  readonly provider?: string;
  readonly latencyMs?: number;
}

export interface PresentOptions {
  readonly hits: readonly RuleHit[];
  readonly chunks: readonly Chunk[];
  readonly analyses: readonly AnalysisResult[];
  /** Below this confidence, a "safe" verdict does not dismiss a rule finding. */
  readonly minConfidence?: number;
}

function chunkForLine(chunks: readonly Chunk[], line: number): Chunk | undefined {
  let best: Chunk | undefined;
  for (const chunk of chunks) {
    if (line < chunk.startLine || line > chunk.endLine) continue;
    if (!best || chunk.endLine - chunk.startLine < best.endLine - best.startLine) best = chunk;
  }
  return best;
}

function maxSeverity(a: Severity, b: Severity): Severity {
  return SEVERITY_ORDER[a] >= SEVERITY_ORDER[b] ? a : b;
}

function percent(confidence: number | null): number {
  return Math.round((confidence ?? 0.5) * 100);
}

function providerLabel(analysis: AnalysisResult): string {
  return `${analysis.providerId}/${analysis.model}`;
}

function titleFor(cwe: string | null, fallback: string): string {
  if (!fallback) return (cwe ? CWE_TITLES[cwe] : undefined) ?? 'Potential vulnerability';
  return fallback;
}

/**
 * Merge deterministic findings with model verdicts.
 *
 * Three outcomes:
 *  - model says vulnerable  -> rule finding is kept, severity may be raised, and
 *    the explanation from the model is attached
 *  - model says safe        -> rule finding is kept but marked as dismissed so
 *    the UI can render it as a struck-through hint instead of an error
 *  - model finds something the rules missed -> a new finding is added
 */
export function presentFindings(options: PresentOptions): PresentedFinding[] {
  const minConfidence = options.minConfidence ?? 0.6;
  const analysesByStart = new Map<number, AnalysisResult>();
  for (const analysis of options.analyses) {
    analysesByStart.set(analysis.candidate.startLine, analysis);
  }

  const presented: PresentedFinding[] = [];
  const reported = new Set<string>();
  /** chunk start line -> CWEs already reported there, so one CWE yields one finding per function. */
  const reportedByChunk = new Map<number, Set<string>>();
  const mark = (startLine: number, cwe: string | null): void => {
    if (!cwe) return;
    const existing = reportedByChunk.get(startLine) ?? new Set<string>();
    existing.add(cwe);
    reportedByChunk.set(startLine, existing);
  };

  for (const hit of options.hits) {
    const chunk = chunkForLine(options.chunks, hit.line);
    const analysis = chunk ? analysesByStart.get(chunk.startLine) : undefined;
    const verdict: LlmVerdict | undefined = analysis?.verdict;
    const chunkCode = chunk ? chunk.lines.map((line) => line.text).join('\n') : '';

    const base = {
      cwe: hit.cwe as string | null,
      title: hit.title,
      line: hit.line,
      endLine: hit.endLine,
      chunkStartLine: chunk?.startLine ?? hit.line,
      chunkEndLine: chunk?.endLine ?? hit.endLine,
      chunkCode,
      provider: analysis ? providerLabel(analysis) : undefined,
      latencyMs: analysis && !analysis.cached ? analysis.latencyMs : undefined,
    };

    mark(base.chunkStartLine, hit.cwe);

    if (verdict && verdict.verdict === 'safe' && verdict.confidence >= minConfidence) {
      presented.push({
        ...base,
        severity: 'low',
        message: `${hit.title} (${hit.cwe}) — likely a false positive. ${verdict.reason}`,
        reason: verdict.reason,
        confidence: verdict.confidence,
        source: 'rules+ai',
        dismissed: true,
      });
      reported.add(`${hit.cwe}:${hit.line}`);
      continue;
    }

    if (verdict && verdict.verdict === 'vulnerable') {
      presented.push({
        ...base,
        severity: maxSeverity(hit.severity, verdict.severity ?? hit.severity),
        message: `${hit.title} (${hit.cwe}) — ${percent(verdict.confidence)}% confidence. ${verdict.reason}`,
        reason: verdict.reason,
        confidence: verdict.confidence,
        fix: cleanFix(verdict.fix),
        source: 'rules+ai',
        dismissed: false,
      });
      reported.add(`${hit.cwe}:${hit.line}`);
      continue;
    }

    presented.push({
      ...base,
      severity: hit.severity,
      message: `${hit.title} (${hit.cwe}). ${hit.message}`,
      source: 'rules',
      dismissed: false,
    });
    reported.add(`${hit.cwe}:${hit.line}`);
  }

  for (const analysis of options.analyses) {
    const verdict = analysis.verdict;
    if (verdict.verdict !== 'vulnerable') continue;

    const { candidate } = analysis;
    const relative = verdict.line ?? 1;
    const line = Math.min(
      Math.max(candidate.startLine + relative - 1, candidate.startLine),
      candidate.endLine,
    );

    const cwe = verdict.cwe;
    if (cwe && reportedByChunk.get(candidate.startLine)?.has(cwe)) continue;
    if (cwe && reported.has(`${cwe}:${line}`)) continue;

    presented.push({
      cwe,
      title: titleFor(cwe, ''),
      severity: verdict.severity ?? 'medium',
      line,
      endLine: line,
      message: `AI found ${titleFor(cwe, '')}${cwe ? ` (${cwe})` : ''} — ${percent(verdict.confidence)}% confidence. ${verdict.reason}`,
      reason: verdict.reason,
      confidence: verdict.confidence,
      fix: cleanFix(verdict.fix),
      source: 'ai',
      dismissed: false,
      chunkStartLine: candidate.startLine,
      chunkEndLine: candidate.endLine,
      chunkCode: candidate.request.code,
      provider: providerLabel(analysis),
      latencyMs: analysis.cached ? undefined : analysis.latencyMs,
    });
    mark(candidate.startLine, cwe);
  }

  return presented.sort(
    (a, b) => a.line - b.line || SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity],
  );
}
