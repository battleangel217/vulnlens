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
 * mode sends everything so the rules can be measured on what they missed.
 */
export function buildCandidates(options: CandidateOptions): Candidate[] {
  const { chunks, hits, deep, max } = options;

  const candidates: Candidate[] = [];

  for (const chunk of chunks) {
    const hints = hitsInside(chunk, hits);
    if (!deep && hints.length === 0) continue;

    const code = chunk.lines.map((line) => line.text).join('\n');
    if (code.length < 20) continue;
    if (code.length > MAX_SNIPPET_CHARS) continue;

    candidates.push({
      key: `${chunk.startLine}:${chunk.endLine}`,
      startLine: chunk.startLine,
      endLine: chunk.endLine,
      request: {
        code,
        functionName: chunk.name,
        ruleHints: hints,
      },
    });
  }

  candidates.sort((a, b) => a.startLine - b.startLine);
  return candidates.slice(0, Math.max(1, max));
}
