import type { Chunk, RuleHit } from '../types';
import type { Candidate } from './analyzer';
import type { RuleHint } from './types';

/** Snippets longer than this are skipped rather than truncated mid-function. */
export const MAX_SNIPPET_CHARS = 12_000;

export interface CandidateOptions {
  readonly chunks: readonly Chunk[];
  readonly hits: readonly RuleHit[];
  /** Analyse every function, not only the ones a rule flagged. */
  readonly deep: boolean;
  /** Safety cap on requests per file. */
  readonly max: number;
  /**
   * Local model output: chunk.startLine -> P(vulnerable). When present, a
   * function above `triageThreshold` is sent even if no rule matched it.
   */
  readonly triage?: ReadonlyMap<number, number>;
  readonly triageThreshold?: number;
}

function hitsInside(chunk: Chunk, hits: readonly RuleHit[]): RuleHint[] {
  return hits
    .filter((hit) => hit.line >= chunk.startLine && hit.line <= chunk.endLine)
    .map((hit) => ({
      cwe: hit.cwe,
      title: hit.title,
      severity: hit.severity,
      line: hit.line - chunk.startLine + 1,
      message: hit.message,
    }));
}

/**
 * Decide which chunks are worth an LLM request.
 *
 * Default mode only sends functions that a deterministic rule already flagged,
 * which keeps cost proportional to findings rather than to file size. `deep`
 * mode sends everything so the rules can be measured on what they missed. A
 * local-model triage map adds individual functions without paying for the whole
 * file; rule hits always win the request budget.
 */
export function buildCandidates(options: CandidateOptions): Candidate[] {
  const { chunks, hits, deep, max } = options;
  const threshold = options.triageThreshold ?? 0.5;

  interface Entry {
    readonly chunk: Chunk;
    readonly hints: RuleHint[];
    readonly score: number;
  }

  let entries: Entry[] = [];

  for (const chunk of chunks) {
    const hints = hitsInside(chunk, hits);
    const score = options.triage?.get(chunk.startLine) ?? 0;
    if (!deep && hints.length === 0 && score < threshold) continue;

    const code = chunk.lines.map((line) => line.text).join('\n');
    if (code.length < 20) continue;
    if (code.length > MAX_SNIPPET_CHARS) continue;

    entries.push({ chunk, hints, score });
  }

  if (entries.length > Math.max(1, max)) {
    entries = entries
      .slice()
      .sort(
        (a, b) =>
          Number(b.hints.length > 0) - Number(a.hints.length > 0) ||
          b.score - a.score ||
          a.chunk.startLine - b.chunk.startLine,
      )
      .slice(0, Math.max(1, max));
  }

  return entries
    .sort((a, b) => a.chunk.startLine - b.chunk.startLine)
    .map(({ chunk, hints }) => ({
      key: `${chunk.startLine}:${chunk.endLine}`,
      startLine: chunk.startLine,
      endLine: chunk.endLine,
      request: {
        code: chunk.lines.map((line) => line.text).join('\n'),
        functionName: chunk.name,
        ruleHints: hints,
      },
    }));
}
