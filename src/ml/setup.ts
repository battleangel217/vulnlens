import * as vscode from 'vscode';
import { ClassifierPool } from './pool';

/**
 * Owns the process-wide classifier pool. Configuration is read through VS Code
 * so the rest of the ML modules stay free of editor imports.
 */

export interface LocalModelConfig {
  readonly enabled: boolean;
  readonly directory: string;
  readonly threshold: number;
  readonly maxChunks: number;
  readonly workers: number;
  readonly timeoutMs: number;
}

export interface PoolOutcome {
  readonly pool: ClassifierPool | null;
  readonly error?: string;
}

export function localModelConfig(): LocalModelConfig {
  const config = vscode.workspace.getConfiguration('vulnLens.localModel');
  return {
    enabled: config.get<boolean>('enabled', false),
    directory: config.get<string>('path', '').trim(),
    threshold: config.get<number>('threshold', 0.5),
    maxChunks: config.get<number>('maxChunks', 40),
    workers: config.get<number>('workers', 2),
    timeoutMs: config.get<number>('timeoutMs', 10_000),
  };
}

type Logger = (line: string) => void;

let current: ClassifierPool | null = null;
let cached: { key: string; outcome: PoolOutcome } | undefined;
let starting: Promise<PoolOutcome> | undefined;

function keyFor(config: LocalModelConfig): string {
  return [config.directory, config.workers, config.timeoutMs].join('|');
}

async function start(config: LocalModelConfig, log: Logger): Promise<PoolOutcome> {
  try {
    const pool = await ClassifierPool.create({
      modelDir: config.directory,
      workers: config.workers,
      requestTimeoutMs: config.timeoutMs,
    });

    current = pool;
    log(
      `[vuln-lens] local model ready: ${config.directory} (${pool.stats.workers} worker thread(s))`,
    );
    return { pool };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    log(`[vuln-lens] local model unavailable: ${message}`);
    return { pool: null, error: message };
  }
}

export async function ensurePool(log: Logger): Promise<PoolOutcome> {
  const config = localModelConfig();

  if (!config.enabled) return { pool: null, error: 'vulnLens.localModel.enabled is false' };
  if (!config.directory) {
    return { pool: null, error: 'Set vulnLens.localModel.path to an exported model directory' };
  }

  const key = keyFor(config);
  if (cached?.key === key) return cached.outcome;
  if (starting) return starting;

  const promise = (async () => {
    await closePool();
    const outcome = await start(config, log);
    cached = { key, outcome };
    return outcome;
  })();

  starting = promise;

  try {
    return await promise;
  } finally {
    if (starting === promise) starting = undefined;
  }
}

export async function closePool(): Promise<void> {
  const pool = current;
  current = null;
  if (pool) await pool.close();
}

/** Called when settings change: the model path or thread count may differ. */
export function resetPool(): void {
  cached = undefined;
  starting = undefined;
  void closePool();
}

export async function probeLocalModel(log: Logger): Promise<{ outcome: PoolOutcome; ms: number; probability: number }> {
  resetPool();
  const outcome = await ensurePool(log);

  if (!outcome.pool) return { outcome, ms: 0, probability: 0 };

  const startedAt = Date.now();
  const probability = await outcome.pool.score(
    [
      'def lookup(cursor, name):',
      '    cursor.execute("SELECT * FROM users WHERE name = \'" + name + "\'")',
      '    return cursor.fetchone()',
    ].join('\n'),
  );

  return { outcome, ms: Date.now() - startedAt, probability };
}