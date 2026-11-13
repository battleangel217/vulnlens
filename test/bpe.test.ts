import { describe, expect, it } from 'vitest';
import { BpeTokenizer, bytesToUnicode, parseMerges } from '../src/ml/bpe';

/**
 * Builds a miniature byte-level BPE vocabulary from a list of words by merging
 * each word's byte pieces left to right. This mirrors what a trained BPE
 * vocabulary does, without shipping a 50k-token file in the repository.
 */
function learn(words: readonly string[]): { vocab: Record<string, number>; merges: string } {
  const vocab: Record<string, number> = {};
  const reverse = bytesToUnicode();
  let next = 0;
  const add = (token: string): void => {
    if (vocab[token] === undefined) vocab[token] = next++;
  };

  add('<s>');
  add('<pad>');
  add('</s>');
  add('<unk>');

  const mergeLines: string[] = [];

  for (const word of words) {
    const chars = Array.from(Buffer.from(word, 'utf8')).map((byte) => reverse[byte]);
    for (const char of chars) add(char);

    let symbols = chars;
    while (symbols.length > 1) {
      const left = symbols[0];
      const right = symbols[1];
      const merged = left + right;
      mergeLines.push(`${left} ${right}`);
      symbols = [merged, ...symbols.slice(2)];
      add(merged);
    }
  }

  return { vocab, merges: mergeLines.join('\n') };
}

const corpus = [' hello', ' world', ' x', 'hello', 'def', 'return', 'f', '(', ')', ':', 'x', '=', '1'];
const { vocab, merges } = learn(corpus);

describe('bytesToUnicode', () => {
  it('maps every byte to a distinct printable character', () => {
    const map = bytesToUnicode();
    expect(map).toHaveLength(256);
    expect(new Set(map).size).toBe(256);
    expect(map[32]).toBe('Ġ');
  });
});

describe('parseMerges', () => {
  it('skips headers and blank lines and preserves rank order', () => {
    const ranks = parseMerges('#version: 0.2\nĠ t\n\nh e\n');
    expect(ranks.get('Ġ\u0000t')).toBe(0);
    expect(ranks.get('h\u0000e')).toBe(1);
    expect(ranks.size).toBe(2);
  });
});

describe('BpeTokenizer', () => {
  const tokenizer = new BpeTokenizer(vocab, merges, { maxLength: 16 });

  it('encodes special tokens around the content and pads to a fixed width', () => {
    const { inputIds, attentionMask } = tokenizer.encode('hello world');

    expect(inputIds[0]).toBe(vocab['<s>']);
    expect(inputIds[1]).toBe(vocab.hello);
    expect(inputIds[2]).toBe(vocab['Ġworld']);
    expect(inputIds[3]).toBe(vocab['</s>']);
    expect(inputIds).toHaveLength(16);
    expect(attentionMask.slice(0, 4)).toEqual([1, 1, 1, 1]);
    expect(attentionMask.slice(4).every((value) => value === 0)).toBe(true);
    expect(inputIds.slice(4).every((id) => id === vocab['<pad>'])).toBe(true);
  });

  it('keeps indentation as its own whitespace token', () => {
    const tokens = tokenizer.tokenize('    return x');
    expect(tokens[0]).toBe('Ġ');
    expect(tokens).toContain('return');
    expect(tokens.at(-1)).toBe('Ġx');
  });

  it('splits punctuation and numbers the way the GPT-2 pre-tokenizer does', () => {
    expect(tokenizer.tokenize('f(x):=1')).toEqual(['f', '(', 'x', ')', ':', '=', '1']);
  });

  it('merges greedily along the learned ranks', () => {
    expect(tokenizer.tokenize('hello')).toEqual(['hello']);
    expect(tokenizer.tokenize('hell')).toEqual(['hell']);
  });

  it('emits <unk> for bytes the vocabulary never saw', () => {
    const tokens = tokenizer.tokenize('hello 😀');
    expect(tokens).toContain('<unk>');
  });

  it('truncates long input to the configured width without splitting specials', () => {
    const narrow = new BpeTokenizer(vocab, merges, { maxLength: 8 });
    const { inputIds } = narrow.encode('hello hello hello hello');
    expect(inputIds).toHaveLength(8);
    expect(inputIds[0]).toBe(vocab['<s>']);
    expect(inputIds.at(-1)).toBe(vocab['<pad>']);
  });

  it('matches the vocabulary size it was built from', () => {
    expect(tokenizer.vocabularySize).toBe(Object.keys(vocab).length);
  });
});