import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Byte-level BPE tokenizer matching the RoBERTa tokenizer that CodeBERT ships
 * with. Implemented here, in ~200 lines, so the extension needs no native
 * tokenizer dependency and no network access at runtime.
 *
 * Reference: openai/gpt-2 `encoder.py`. The pre-tokenizer regex and the merge
 * loop are the same; the only difference is that this is TypeScript.
 */

/** GPT-2's reversible byte -> printable unicode mapping. */
export function bytesToUnicode(): string[] {
  const bytes: number[] = [];
  for (let value = 33; value <= 126; value += 1) bytes.push(value);
  for (let value = 161; value <= 172; value += 1) bytes.push(value);
  for (let value = 174; value <= 255; value += 1) bytes.push(value);

  const chars = [...bytes];
  let extra = 0;
  for (let value = 0; value < 256; value += 1) {
    if (bytes.includes(value)) continue;
    bytes.push(value);
    chars.push(256 + extra);
    extra += 1;
  }

  const map = new Array<string>(256);
  for (let index = 0; index < bytes.length; index += 1) {
    map[bytes[index]] = String.fromCharCode(chars[index]);
  }
  return map;
}

const BYTE_ENCODER = bytesToUnicode();

/** GPT-2 pre-tokenization, adapted to JavaScript's Unicode regex support. */
const PRE_TOKENIZE =
  /'s|'t|'re|'ve|'m|'ll|'d| ?\p{L}+| ?\p{N}+| ?[^\s\p{L}\p{N}]+|\s+(?!\S)|\s+/gu;

const mergeKey = (left: string, right: string): string => `${left}\u0000${right}`;

export interface BpeFiles {
  readonly vocab: Record<string, number>;
  readonly merges: string;
}

/** Parse `merges.txt`, ignoring the optional `#version:` header. */
export function parseMerges(text: string): Map<string, number> {
  const ranks = new Map<string, number>();
  let rank = 0;
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const [left, right] = trimmed.split(' ');
    if (!left || !right) continue;
    ranks.set(mergeKey(left, right), rank);
    rank += 1;
  }
  return ranks;
}

export interface TokenizerOptions {
  /** Total sequence length including the two special tokens. Default 512. */
  readonly maxLength?: number;
}

export class BpeTokenizer {
  private readonly vocab: Map<string, number>;
  private readonly ranks: Map<string, number>;
  private readonly maxLength: number;
  private readonly special: { bos: number; eos: number; pad: number; unk: number };
  private reverse: Map<number, string> | undefined;

  constructor(vocab: Record<string, number>, merges: string, options: TokenizerOptions = {}) {
    this.vocab = new Map(Object.entries(vocab));
    this.ranks = parseMerges(merges);
    this.maxLength = Math.max(8, options.maxLength ?? 512);

    const lookup = (token: string, fallback: number): number =>
      this.vocab.get(token) ?? fallback;

    this.special = {
      bos: lookup('<s>', 0),
      pad: lookup('<pad>', 1),
      eos: lookup('</s>', 2),
      unk: lookup('<unk>', 3),
    };
  }

  static fromDirectory(directory: string, options: TokenizerOptions = {}): BpeTokenizer {
    const vocab = JSON.parse(readFileSync(join(directory, 'vocab.json'), 'utf8')) as Record<
      string,
      number
    >;
    const merges = readFileSync(join(directory, 'merges.txt'), 'utf8');
    return new BpeTokenizer(vocab, merges, options);
  }

  get vocabularySize(): number {
    return this.vocab.size;
  }

  /** Encode to fixed-width input ids and attention mask, ready for ONNX. */
  encode(text: string): { inputIds: number[]; attentionMask: number[] } {
    const budget = this.maxLength - 2;
    const ids: number[] = [this.special.bos];

    for (const piece of this.preTokenize(text)) {
      if (ids.length - 1 >= budget) break;
      for (const id of this.tokenizePiece(piece)) {
        if (ids.length - 1 >= budget) break;
        ids.push(id);
      }
    }

    ids.push(this.special.eos);

    const attentionMask = new Array<number>(ids.length).fill(1);
    while (ids.length < this.maxLength) {
      ids.push(this.special.pad);
      attentionMask.push(0);
    }

    return { inputIds: ids.slice(0, this.maxLength), attentionMask };
  }

  /** Visible for tests; the intermediate token strings are useful to inspect. */
  tokenize(text: string): string[] {
    const tokens: string[] = [];
    for (const piece of this.preTokenize(text)) {
      for (const id of this.tokenizePiece(piece)) {
        tokens.push(this.idToToken(id) ?? '<unk>');
      }
    }
    return tokens;
  }

  private preTokenize(text: string): string[] {
    if (!text) return [];
    // Same normalisation RoBERTa's byte-level BPE effectively relies on: the
    // text is consumed as UTF-8 bytes, so we only collapse runs of whitespace
    // that the pre-tokenizer would otherwise split into many tiny tokens.
    const normalized = text.replace(/\r\n?/g, '\n');
    return normalized.match(PRE_TOKENIZE) ?? [];
  }

  private tokenizePiece(piece: string): number[] {
    const chars = this.byteEncode(piece);
    const merged = this.applyMerges(chars);
    return merged.map((token) => this.vocab.get(token) ?? this.special.unk);
  }

  private byteEncode(piece: string): string[] {
    const bytes = Buffer.from(piece, 'utf8');
    const chars: string[] = [];
    for (const byte of bytes) chars.push(BYTE_ENCODER[byte]);
    return chars;
  }

  private applyMerges(chars: string[]): string[] {
    if (chars.length < 2) return chars;

    let symbols = chars;
    for (;;) {
      let bestRank = Number.POSITIVE_INFINITY;
      let bestIndex = -1;

      for (let index = 0; index < symbols.length - 1; index += 1) {
        const rank = this.ranks.get(mergeKey(symbols[index], symbols[index + 1]));
        if (rank !== undefined && rank < bestRank) {
          bestRank = rank;
          bestIndex = index;
        }
      }

      if (bestIndex === -1) return symbols;

      const left = symbols[bestIndex];
      const right = symbols[bestIndex + 1];
      const next: string[] = [];

      for (let index = 0; index < symbols.length; ) {
        if (
          index < symbols.length - 1 &&
          symbols[index] === left &&
          symbols[index + 1] === right
        ) {
          next.push(left + right);
          index += 2;
        } else {
          next.push(symbols[index]);
          index += 1;
        }
      }

      symbols = next;
    }
  }

  private idToToken(id: number): string | undefined {
    if (!this.reverse) {
      this.reverse = new Map();
      for (const [token, value] of this.vocab) this.reverse.set(value, token);
    }
    return this.reverse.get(id);
  }
}