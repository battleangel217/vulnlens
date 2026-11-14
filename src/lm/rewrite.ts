import type { Chunk, RuleHit } from '../types';
import { chunkPython } from '../scan/chunker';
import { scanPython } from '../scan/scanner';
import type { Candidate } from './analyzer';
import { MAX_SNIPPET_CHARS } from './candidates';

/** Smallest snippet worth an LLM request, matching the candidate builder. */
const MIN_SNIPPET_CHARS = 20;

export function chunkAtLine(chunks: readonly Chunk[], line: number): Chunk | undefined {
  return chunks.find(
    (chunk) => chunk.kind === 'function' && line >= chunk.startLine && line <= chunk.endLine,
  );
}

function hintsFor(chunk: Chunk, hits: readonly RuleHit[]) {
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
 * Build a single "rewrite this function" request for the cursor line.
 *
 * Unlike `buildCandidates`, this ignores the request budget and the local
 * triage map: the user explicitly asked for this function, so it is the one
 * that gets sent. Returns undefined when the cursor is not inside a function
 * or the function is too large to send safely.
 */
export function rewriteCandidate(source: string, line: number): Candidate | undefined {
  const chunk = chunkAtLine(chunkPython(source), line);
  if (!chunk) return undefined;

  const code = chunk.lines.map((item) => item.text).join('\n');
  if (code.length < MIN_SNIPPET_CHARS || code.length > MAX_SNIPPET_CHARS) return undefined;

  return {
    key: `rewrite:${chunk.startLine}:${chunk.endLine}`,
    startLine: chunk.startLine,
    endLine: chunk.endLine,
    request: {
      code,
      functionName: chunk.name,
      ruleHints: hintsFor(chunk, scanPython(source)),
    },
  };
}
