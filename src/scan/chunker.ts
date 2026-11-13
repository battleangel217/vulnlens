import type { Chunk, SourceLine } from '../types';

const DEF_RE = /^([ \t]*)(?:async[ \t]+)?def[ \t]+([A-Za-z_]\w*)[ \t]*\(/;
const DECORATOR_RE = /^[ \t]*@/;

interface Block {
  readonly name: string;
  readonly start: number;
  readonly end: number;
  readonly indent: number;
}

function indentOf(text: string): number {
  let n = 0;
  for (const ch of text) {
    if (ch === ' ') n += 1;
    else if (ch === '\t') n += 4;
    else break;
  }
  return n;
}

function isBlank(text: string): boolean {
  return text.trim().length === 0;
}

/**
 * Split Python source into function-level chunks plus "module" chunks for any
 * top-level statements that are not inside a function.
 *
 * This is deliberately a small indentation-based splitter rather than a real
 * parser: it must run on every save with no native dependency, and a full
 * tree-sitter WASM build is a v2 concern.
 *
 * Known limitation: a function whose block ends with a dedent is detected, but
 * semantically nested code inside multi-line strings can confuse the indent
 * scan. Acceptable for v1, and it fails by scanning *more*, not less.
 */
export function chunkPython(source: string): Chunk[] {
  const texts = source.split(/\r?\n/);
  const blocks: Block[] = [];

  for (let i = 0; i < texts.length; i++) {
    const match = DEF_RE.exec(texts[i]);
    if (!match) continue;

    const indent = indentOf(match[1]);
    // Pull in contiguous decorators directly above the def.
    let start = i;
    while (start > 0 && DECORATOR_RE.test(texts[start - 1])) start -= 1;

    let end = i;
    for (let j = i + 1; j < texts.length; j++) {
      if (isBlank(texts[j])) continue;
      if (indentOf(texts[j]) <= indent) break;
      end = j;
    }

    blocks.push({ name: match[2], start, end, indent });
  }

  const chunks: Chunk[] = [];
  const make = (name: string, kind: Chunk['kind'], start: number, end: number): Chunk => {
    const lines: SourceLine[] = [];
    for (let i = start; i <= end; i++) lines.push({ line: i, text: texts[i] });
    return { name, kind, startLine: start, endLine: end, lines };
  };

  for (const block of blocks) {
    chunks.push(make(block.name, 'function', block.start, block.end));
  }

  // Lines covered by top-level blocks. Nested defs are scanned twice (once by
  // their enclosing chunk, once on their own) and de-duplicated by the scanner,
  // which is cheaper than trying to carve them out.
  const covered = new Array<boolean>(texts.length).fill(false);
  for (const block of blocks) {
    if (block.indent !== 0) continue;
    for (let i = block.start; i <= block.end; i++) covered[i] = true;
  }

  let gapStart = -1;
  const flush = (end: number) => {
    if (gapStart < 0) return;
    // Trim blank lines from both ends of the gap.
    let s = gapStart;
    let e = end;
    while (s <= e && isBlank(texts[s])) s += 1;
    while (e >= s && isBlank(texts[e])) e -= 1;
    if (s <= e) chunks.push(make('<module>', 'module', s, e));
    gapStart = -1;
  };

  for (let i = 0; i < texts.length; i++) {
    if (covered[i]) {
      flush(i - 1);
    } else if (gapStart < 0) {
      gapStart = i;
    }
  }
  flush(texts.length - 1);

  chunks.sort((a, b) => a.startLine - b.startLine);
  return chunks;
}
