import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { BpeTokenizer } from './bpe';

/**
 * Local, offline classifier: a fine-tuned CodeBERT exported to ONNX.
 *
 * The ONNX runtime is loaded lazily and is not a hard dependency of the
 * extension. If `onnxruntime-node` is absent or the model directory is
 * incomplete, `createClassifier` fails with an actionable `LocalModelError`
 * instead of breaking activation.
 */

export interface ClassifierScore {
  readonly safe: number;
  readonly vulnerable: number;
}

export interface TensorLike {
  readonly data: Float32Array | BigInt64Array;
  readonly dims: readonly number[];
}

export interface SessionLike {
  run(feeds: Record<string, unknown>): Promise<Record<string, TensorLike>>;
  release?(): Promise<void>;
}

export interface RuntimeLike {
  readonly InferenceSession: {
    create(modelPath: string, options?: unknown): Promise<SessionLike>;
  };
  readonly Tensor: new (
    type: 'int64' | 'float32',
    data: BigInt64Array | Float32Array,
    dims: readonly number[],
  ) => unknown;
}

export type LocalModelErrorKind =
  | 'missing-runtime'
  | 'missing-model'
  | 'bad-model'
  | 'inference';

export class LocalModelError extends Error {
  constructor(
    message: string,
    readonly kind: LocalModelErrorKind,
  ) {
    super(message);
    this.name = 'LocalModelError';
  }
}

export interface ClassifierOptions {
  readonly directory: string;
  readonly maxLength?: number;
  /** Injected by tests; production resolves `onnxruntime-node` lazily. */
  readonly runtime?: RuntimeLike;
}

export interface LocalClassifier {
  readonly directory: string;
  readonly maxLength: number;
  score(code: string): Promise<ClassifierScore>;
  close(): Promise<void>;
}

export function sigmoid(value: number): number {
  return 1 / (1 + Math.exp(-value));
}

export function softmax(logits: readonly number[]): number[] {
  if (logits.length === 0) return [];
  const max = Math.max(...logits);
  const exponents = logits.map((value) => Math.exp(value - max));
  const total = exponents.reduce((sum, value) => sum + value, 0);
  return exponents.map((value) => value / total);
}

/**
 * Turn model output into named probabilities.
 *
 * Handles three exports people actually produce:
 *  - two logits, `[safe, vulnerable]` (the default fine-tuning head)
 *  - one logit (a sigmoid head)
 *  - labels.json reordering the two classes
 */
export function scoresFromLogits(
  logits: readonly number[],
  labels: readonly string[] = ['safe', 'vulnerable'],
): ClassifierScore {
  if (logits.length === 0) {
    throw new LocalModelError('model returned no logits', 'bad-model');
  }

  if (logits.length === 1) {
    const vulnerable = sigmoid(logits[0]);
    return { safe: 1 - vulnerable, vulnerable };
  }

  if (logits.length < labels.length) {
    throw new LocalModelError(
      `model returned ${logits.length} logits for ${labels.length} labels`,
      'bad-model',
    );
  }

  const probabilities = softmax(logits.slice(0, labels.length));
  const vulnerableIndex = labels.findIndex((label) => label.toLowerCase() === 'vulnerable');
  const safeIndex = labels.findIndex((label) => label.toLowerCase() === 'safe');

  const vulnerable = probabilities[vulnerableIndex === -1 ? probabilities.length - 1 : vulnerableIndex];
  const safe = probabilities[safeIndex === -1 ? 0 : safeIndex];
  return { safe, vulnerable };
}

function loadRuntime(): RuntimeLike {
  try {
    // Kept as a runtime require so the extension installs without ~100 MB of
    // ONNX binaries. `npm run check` and the default rules-only path never
    // reach this function.
    return require('onnxruntime-node') as RuntimeLike;
  } catch {
    throw new LocalModelError(
      'onnxruntime-node is not installed. Run: npm install onnxruntime-node',
      'missing-runtime',
    );
  }
}

function readLabels(directory: string): string[] {
  const path = join(directory, 'labels.json');
  if (!existsSync(path)) return ['safe', 'vulnerable'];

  try {
    const parsed = JSON.parse(readFileSync(path, 'utf8')) as { labels?: unknown };
    if (Array.isArray(parsed.labels) && parsed.labels.every((value) => typeof value === 'string')) {
      return parsed.labels as string[];
    }
  } catch {
    // Fall through to the default: a malformed labels file should not make a
    // model silently look broken when the default order is the common one.
  }
  return ['safe', 'vulnerable'];
}

export async function createClassifier(options: ClassifierOptions): Promise<LocalClassifier> {
  const { directory } = options;
  const modelPath = join(directory, 'model.onnx');

  for (const required of [modelPath, join(directory, 'vocab.json'), join(directory, 'merges.txt')]) {
    if (!existsSync(required)) {
      throw new LocalModelError(
        `missing ${required}. Export the model with ml/kaggle/export_onnx.py`,
        'missing-model',
      );
    }
  }

  const runtime = options.runtime ?? loadRuntime();
  const maxLength = options.maxLength ?? 512;
  const tokenizer = BpeTokenizer.fromDirectory(directory, { maxLength });
  const labels = readLabels(directory);

  let session: SessionLike;
  try {
    session = await runtime.InferenceSession.create(modelPath, {
      intraOpNumThreads: 1,
      interOpNumThreads: 1,
    });
  } catch (error) {
    throw new LocalModelError(
      `could not load ${modelPath}: ${error instanceof Error ? error.message : String(error)}`,
      'bad-model',
    );
  }

  return {
    directory,
    maxLength,
    async score(code: string): Promise<ClassifierScore> {
      const { inputIds, attentionMask } = tokenizer.encode(code);

      const feeds = {
        input_ids: new runtime.Tensor(
          'int64',
          BigInt64Array.from(inputIds, (id) => BigInt(id)),
          [1, inputIds.length],
        ),
        attention_mask: new runtime.Tensor(
          'int64',
          BigInt64Array.from(attentionMask, (value) => BigInt(value)),
          [1, attentionMask.length],
        ),
      };

      let output: Record<string, TensorLike>;
      try {
        output = await session.run(feeds);
      } catch (error) {
        throw new LocalModelError(
          `inference failed: ${error instanceof Error ? error.message : String(error)}`,
          'inference',
        );
      }

      const tensor = output.logits ?? Object.values(output)[0];
      if (!tensor) throw new LocalModelError('model produced no output tensor', 'bad-model');

      const logits = Array.from(tensor.data as Float32Array);
      return scoresFromLogits(logits, labels);
    },
    async close(): Promise<void> {
      await session.release?.();
    },
  };
}