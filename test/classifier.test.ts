import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  createClassifier,
  LocalModelError,
  scoresFromLogits,
  sigmoid,
  softmax,
  type RuntimeLike,
  type TensorLike,
} from '../src/ml/classifier';

function modelDirectory(vocab: Record<string, number> = { '<s>': 0, '<pad>': 1, '</s>': 2, '<unk>': 3 }): string {
  const directory = mkdtempSync(join(tmpdir(), 'vuln-guard-model-'));
  writeFileSync(join(directory, 'vocab.json'), JSON.stringify(vocab));
  writeFileSync(join(directory, 'merges.txt'), '');
  writeFileSync(join(directory, 'model.onnx'), 'stub');
  return directory;
}

interface Recorded {
  type: string;
  data: Float32Array | BigInt64Array;
  dims: readonly number[];
}

class FakeTensor {
  constructor(
    readonly type: string,
    readonly data: Float32Array | BigInt64Array,
    readonly dims: readonly number[],
  ) {}
}

function fakeRuntime(
  logits: number[],
  behavior: 'ok' | 'throw-on-run' | 'throw-on-create' = 'ok',
): { runtime: RuntimeLike; recorded: Recorded[]; released: () => number } {
  const recorded: Recorded[] = [];
  let releases = 0;

  const runtime: RuntimeLike = {
    Tensor: FakeTensor as unknown as RuntimeLike['Tensor'],
    InferenceSession: {
      async create() {
        if (behavior === 'throw-on-create') throw new Error('corrupt graph');
        return {
          async run(feeds: Record<string, unknown>) {
            for (const value of Object.values(feeds)) {
              const tensor = value as FakeTensor;
              recorded.push({ type: tensor.type, data: tensor.data, dims: tensor.dims });
            }
            if (behavior === 'throw-on-run') throw new Error('bad input shape');
            const tensor: TensorLike = { data: new Float32Array(logits), dims: [1, logits.length] };
            return { logits: tensor };
          },
          async release() {
            releases += 1;
          },
        };
      },
    },
  };

  return { runtime, recorded, released: () => releases };
}

const directories: string[] = [];

afterEach(() => {
  for (const directory of directories) rmSync(directory, { recursive: true, force: true });
  directories.length = 0;
});

describe('probabilities', () => {
  it('normalises two logits with softmax', () => {
    const probabilities = softmax([0, 0]);
    expect(probabilities).toEqual([0.5, 0.5]);

    const [safe, vulnerable] = softmax([-1, 1]);
    expect(safe + vulnerable).toBeCloseTo(1);
    expect(vulnerable).toBeGreaterThan(0.8);
  });

  it('names the vulnerable class from labels, not position', () => {
    const normal = scoresFromLogits([2, 0]);
    expect(normal.vulnerable).toBeCloseTo(0.12, 2);
    expect(normal.safe).toBeCloseTo(0.88, 2);

    const reversed = scoresFromLogits([2, 0], ['vulnerable', 'safe']);
    expect(reversed.vulnerable).toBeCloseTo(0.88, 2);
    expect(reversed.safe).toBeCloseTo(0.12, 2);
  });

  it('treats a single logit as a sigmoid head', () => {
    expect(scoresFromLogits([0]).vulnerable).toBeCloseTo(0.5);
    expect(scoresFromLogits([4]).vulnerable).toBeCloseTo(sigmoid(4));
    expect(scoresFromLogits([-4]).safe).toBeCloseTo(sigmoid(4));
  });

  it('rejects output that cannot be mapped to the labels', () => {
    expect(() => scoresFromLogits([])).toThrow(LocalModelError);
    expect(() => scoresFromLogits([1], ['safe', 'vulnerable'])).not.toThrow();
    expect(() => scoresFromLogits([1, 2, 3], ['safe', 'vulnerable', 'unknown', 'x'])).toThrow(
      LocalModelError,
    );
  });
});

describe('createClassifier', () => {
  it('fails with an actionable error when the model directory is incomplete', async () => {
    await expect(createClassifier({ directory: '/nonexistent/vuln-guard' })).rejects.toMatchObject({
      name: 'LocalModelError',
      kind: 'missing-model',
    });
  });

  it('feeds fixed-width int64 tensors and returns named probabilities', async () => {
    const directory = modelDirectory({ '<s>': 0, '<pad>': 1, '</s>': 2, '<unk>': 3, def: 4 });
    directories.push(directory);
    const { runtime, recorded, released } = fakeRuntime([-1, 2]);

    const classifier = await createClassifier({ directory, runtime, maxLength: 32 });
    const score = await classifier.score('def f(): return 1');

    expect(score.vulnerable).toBeGreaterThan(0.9);
    expect(score.safe + score.vulnerable).toBeCloseTo(1);

    expect(recorded).toHaveLength(2);
    expect(recorded[0].type).toBe('int64');
    expect(recorded[0].dims).toEqual([1, 32]);
    expect(recorded[1].dims).toEqual([1, 32]);
    expect(Array.from(recorded[0].data as BigInt64Array)[0]).toBe(0n);

    await classifier.close();
    expect(released()).toBe(1);
  });

  it('honours a reordered labels.json', async () => {
    const directory = modelDirectory();
    directories.push(directory);
    writeFileSync(join(directory, 'labels.json'), JSON.stringify({ labels: ['vulnerable', 'safe'] }));

    const { runtime } = fakeRuntime([2, -1]);
    const classifier = await createClassifier({ directory, runtime, maxLength: 8 });
    const score = await classifier.score('x');
    expect(score.vulnerable).toBeGreaterThan(0.9);
  });

  it('wraps a corrupt model in a bad-model error', async () => {
    const directory = modelDirectory();
    directories.push(directory);
    const { runtime } = fakeRuntime([0, 0], 'throw-on-create');

    await expect(createClassifier({ directory, runtime })).rejects.toMatchObject({
      name: 'LocalModelError',
      kind: 'bad-model',
    });
  });

  it('wraps an inference failure without leaking a stack trace', async () => {
    const directory = modelDirectory();
    directories.push(directory);
    const { runtime } = fakeRuntime([0, 0], 'throw-on-run');

    const classifier = await createClassifier({ directory, runtime, maxLength: 8 });
    await expect(classifier.score('x')).rejects.toMatchObject({
      name: 'LocalModelError',
      kind: 'inference',
      message: 'inference failed: bad input shape',
    });
  });
});