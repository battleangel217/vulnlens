/**
 * Small, dependency-free helpers for reading Python call expressions on a
 * single line.
 *
 * v1 deliberately only inspects single-line expressions. That covers the vast
 * majority of hand-written vulnerable snippets and keeps the scanner pure and
 * instant. Multi-line calls are a v2 item (and belong with the real parser).
 */

export interface CallMatch {
  readonly callee: string;
  readonly index: number;
  /** Top-level arguments, raw source text, in order. */
  readonly args: readonly string[];
  readonly firstArg: string | null;
}

function skipHorizontalWhitespace(text: string, i: number): number {
  while (i < text.length && (text[i] === ' ' || text[i] === '\t')) i += 1;
  return i;
}

/**
 * Split the argument list of a call, starting at `openParen` (the index of the
 * opening parenthesis). Quote- and bracket-aware.
 */
export function splitTopLevelArgs(
  text: string,
  openParen: number,
): { args: string[]; end: number } {
  const args: string[] = [];
  let current = '';
  let depth = 0;
  let quote: string | null = null;

  for (let i = openParen; i < text.length; i += 1) {
    const ch = text[i];
    const next = text[i + 1];

    if (quote) {
      current += ch;
      if (ch === '\\') {
        current += next ?? '';
        i += 1;
      } else if (ch === quote) {
        quote = null;
      }
      continue;
    }

    if (ch === '"' || ch === "'") {
      quote = ch;
      current += ch;
      continue;
    }

    if (ch === '(' || ch === '[' || ch === '{') {
      depth += 1;
      if (depth === 1) continue; // the call's own opening paren
      current += ch;
      continue;
    }

    if (ch === ')' || ch === ']' || ch === '}') {
      depth -= 1;
      if (depth === 0) {
        const trimmed = current.trim();
        if (trimmed) args.push(trimmed);
        return { args, end: i };
      }
      current += ch;
      continue;
    }

    if (ch === ',' && depth === 1) {
      args.push(current.trim());
      current = '';
      continue;
    }

    current += ch;
  }

  if (current.trim()) args.push(current.trim());
  return { args, end: text.length };
}

/**
 * Find calls matching a callee pattern on one line, e.g.
 * `callsInLine(line, /\bos\.system\b/g)`.
 */
export function callsInLine(text: string, callee: RegExp): CallMatch[] {
  const flags = callee.flags.includes('g') ? callee.flags : `${callee.flags}g`;
  const re = new RegExp(callee.source, flags);
  const found: CallMatch[] = [];
  let match: RegExpExecArray | null;

  while ((match = re.exec(text)) !== null) {
    if (match[0].length === 0) {
      re.lastIndex += 1;
      continue;
    }
    const open = skipHorizontalWhitespace(text, match.index + match[0].length);
    if (text[open] !== '(') continue;
    const { args } = splitTopLevelArgs(text, open);
    found.push({
      callee: match[0],
      index: match.index,
      args,
      firstArg: args[0] ?? null,
    });
  }

  return found;
}

/** Replace string literals with `""` so structure can be inspected safely. */
export function stripStringLiterals(expression: string): string {
  let out = '';
  let quote: string | null = null;

  for (let i = 0; i < expression.length; i += 1) {
    const ch = expression[i];

    if (quote) {
      if (ch === '\\') {
        i += 1;
        continue;
      }
      if (ch === quote) {
        quote = null;
        out += '""';
      }
      continue;
    }

    if (ch === '"' || ch === "'") {
      quote = ch;
      continue;
    }

    out += ch;
  }

  return out;
}

/** True for `f"..."`, `rf"..."`, `F'...'` and friends. */
export function isFString(expression: string): boolean {
  return /^\s*[rRbBuU]*[fF][rRbBuU]*\s*["']/.test(expression);
}

/**
 * True when a string expression is built at runtime rather than being a plain
 * literal: f-strings, `%` formatting, `.format(...)`, or `+` concatenation.
 */
export function looksInterpolated(expression: string): boolean {
  if (isFString(expression)) return true;
  const stripped = stripStringLiterals(expression);
  return /\.format\s*\(/.test(stripped) || /[+%]/.test(stripped);
}

/** True for list/tuple literals, which are the safe form for subprocess. */
export function isSequenceLiteral(expression: string): boolean {
  const trimmed = expression.trim();
  return trimmed.startsWith('[') || (trimmed.startsWith('(') && trimmed.endsWith(')'));
}

/** Extract the text of the string literal body, or null when not a literal. */
export function stringLiteralValue(expression: string): string | null {
  const match = /^\s*[rRbBuU]*(["'])([\s\S]*)\1\s*$/.exec(expression);
  return match ? match[2] : null;
}
