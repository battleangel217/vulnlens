import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { ClassifierPool } from '../src/ml/pool';
import { LocalModelError } from '../src/ml/classifier';

const scriptPath = fileURLToPath(new URL('./fixtures/worker-score.cjs', import.meta.url));

let pool: ClassifierPool | undefined;
let directory: string;

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), 'vuln-guard-pool-'));
  process.env.VG_POOL_TEST_LOG = join(directory, 'threads.log');
  process.env.VG_POOL_TEST_DELAY = '20';
});

afterEach(async () => {
  await pool?.close();
  pool = undefined;
  delete process.env.VG_POOL_TEST_LOG;
  delete process.env.VG_POOL_TEST_DELAY;
  rmSync(directory, { recursive: true, force: true });
});

function threadLog(): number[] {
  try {
    return readFileSync(process.env.VG_POOL_TEST_LOG!, 'utf8')
      .trim()
      .split('\n')
      .filter(Boolean)
      .map(Number);
  } catch {
    return [];
  }
}

describe('ClassifierPool', () => {
  it('starts the requested number of workers and scores on them', async () => {
    pool = await ClassifierPool.create({
      modelDir: 'stub',
      workers: 2,
      scriptPath,
    });

    expect(pool.stats.workers).toBe(2);
    await expect(pool.score('this is vuln')).resolves.toBeCloseTo(0.9);
    await expect(pool.score('this is fine')).resolves.toBeCloseTo(0.1);
    expect(pool.stats.completed).toBe(2);
  });

  it('actually shares work across threads', async () => {
    process.env.VG_POOL_TEST_DELAY = '40';
    pool = await ClassifierPool.create({
      modelDir: 'stub',
      workers: 2,
      scriptPath,
    });

    await Promise.all(Array.from({ length: 4 }, (_, index) => pool!.score(`task ${index}`)));

    expect(new Set(threadLog()).size).toBeGreaterThanOrEqual(2);
  });

  it('rejects the in-flight request when a worker crashes, then replaces it', async () => {
    pool = await ClassifierPool.create({
      modelDir: 'stub',
      workers: 1,
      scriptPath,
      requestTimeoutMs: 5000,
    });

    await expect(pool.score('boom')).rejects.toMatchObject({ name: 'LocalModelError' });
    await expect(pool.score('still vuln')).resolves.toBeCloseTo(0.9);
    expect(pool.stats.workers).toBe(1);
  });

  it('enforces a per-request timeout and recovers', async () => {
    pool = await ClassifierPool.create({
      modelDir: 'stub',
      workers: 1,
      scriptPath,
      requestTimeoutMs: 120,
    });

    await expect(pool.score('hang')).rejects.toMatchObject({
      name: 'LocalModelError',
      message: 'inference timed out after 120ms',
    });

    await expect(pool.score('vuln')).resolves.toBeCloseTo(0.9);
    expect(pool.stats.failed).toBe(1);
  });

  it('fails startup when the worker cannot load the model', async () => {
    await expect(
      ClassifierPool.create({ modelDir: 'missing', workers: 2, scriptPath }),
    ).rejects.toMatchObject({ name: 'LocalModelError', kind: 'missing-model' });
  });

  it('rejects queued work when closed', async () => {
    const local = await ClassifierPool.create({ modelDir: 'stub', workers: 1, scriptPath });
    pool = local;

    const pending = local.score('hang');
    const closing = local.close();

    await expect(pending).rejects.toBeInstanceOf(LocalModelError);
    await closing;
    await expect(local.score('x')).rejects.toBeInstanceOf(LocalModelError);
  });
});