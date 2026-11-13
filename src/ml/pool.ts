import { join } from 'node:path';
import { Worker } from 'node:worker_threads';
import { LocalModelError, type LocalModelErrorKind } from './classifier';
import type { WorkerResponse } from './protocol';

/**
 * A small worker pool around the ONNX classifier.
 *
 * Why threads: tokenising a 512-token snippet and running CodeBERT takes tens of
 * milliseconds, which is long enough to drop frames in the extension host.
 * `worker_threads` also gives each model its own heap and lets a hung request
 * be killed without taking the editor down with it.
 */

const ERROR_KINDS = new Set<string>([
  'missing-runtime',
  'missing-model',
  'bad-model',
  'inference',
]);

function asKind(value: string): LocalModelErrorKind {
  return ERROR_KINDS.has(value) ? (value as LocalModelErrorKind) : 'inference';
}

export interface PoolOptions {
  readonly modelDir: string;
  /** Number of worker threads. Default 2, clamped to 1..8. */
  readonly workers?: number;
  /** Per-request timeout once a worker picks the task up. Default 10000 ms. */
  readonly requestTimeoutMs?: number;
  /** Test seam: path to the compiled worker entry point. */
  readonly scriptPath?: string;
  readonly maxLength?: number;
}

interface Task {
  readonly id: number;
  readonly code: string;
  readonly resolve: (probability: number) => void;
  readonly reject: (error: unknown) => void;
}

interface Slot {
  readonly worker: Worker;
  ready: boolean;
  task?: Task;
  timer?: NodeJS.Timeout;
}

export interface PoolStats {
  readonly workers: number;
  readonly queued: number;
  readonly completed: number;
  readonly failed: number;
}

export class ClassifierPool {
  private readonly slots: Slot[] = [];
  private readonly queue: Task[] = [];
  private readonly scriptPath: string;
  private readonly workerCount: number;
  private readonly requestTimeoutMs: number;
  private readonly maxLength: number | undefined;
  private readonly modelDir: string;

  private nextId = 1;
  private completed = 0;
  private failed = 0;
  private restarts = 0;
  private closing = false;

  private constructor(options: PoolOptions) {
    this.modelDir = options.modelDir;
    this.workerCount = Math.max(1, Math.min(options.workers ?? 2, 8));
    this.requestTimeoutMs = options.requestTimeoutMs ?? 10_000;
    this.maxLength = options.maxLength;
    this.scriptPath =
      options.scriptPath ??
      join(typeof __dirname === 'string' ? __dirname : process.cwd(), 'ml-worker.js');
  }

  static async create(options: PoolOptions): Promise<ClassifierPool> {
    const pool = new ClassifierPool(options);
    await pool.start();
    return pool;
  }

  get stats(): PoolStats {
    return {
      workers: this.slots.length,
      queued: this.queue.length,
      completed: this.completed,
      failed: this.failed,
    };
  }

  get threads(): number {
    return this.workerCount;
  }

  score(code: string): Promise<number> {
    if (this.closing) {
      return Promise.reject(new LocalModelError('classifier pool is closed', 'inference'));
    }

    return new Promise<number>((resolve, reject) => {
      this.queue.push({ id: this.nextId++, code, resolve, reject });
      this.dispatch();
    });
  }

  async close(): Promise<void> {
    if (this.closing) return;
    this.closing = true;

    const closed = new LocalModelError('classifier pool is closed', 'inference');
    for (const task of this.queue.splice(0)) task.reject(closed);

    await Promise.all(
      this.slots.splice(0).map((slot) => {
        if (slot.timer) clearTimeout(slot.timer);
        slot.task?.reject(closed);
        return slot.worker.terminate();
      }),
    );
  }

  private start(): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      let remaining = this.workerCount;
      let settled = false;

      const fail = (error: unknown): void => {
        if (settled) return;
        settled = true;
        reject(error);
        void this.close();
      };

      const ready = (): void => {
        if (settled) return;
        remaining -= 1;
        if (remaining === 0) {
          settled = true;
          resolve();
        }
      };

      for (let index = 0; index < this.workerCount; index += 1) {
        this.spawn(ready, fail);
      }
    });
  }

  private spawn(onReady: () => void, onStartupFailure: (error: unknown) => void): void {
    let worker: Worker;
    try {
      worker = new Worker(this.scriptPath, {
        workerData: { modelDir: this.modelDir, maxLength: this.maxLength },
      });
    } catch (error) {
      onStartupFailure(error);
      return;
    }

    const slot: Slot = { worker, ready: false };
    this.slots.push(slot);

    worker.on('message', (message: WorkerResponse) =>
      this.onMessage(slot, message, onReady, onStartupFailure),
    );

    worker.on('error', (error) => {
      if (!slot.ready) {
        onStartupFailure(
          error instanceof LocalModelError
            ? error
            : new LocalModelError(error.message, 'bad-model'),
        );
        return;
      }
      this.failSlot(slot, error);
    });

    worker.on('exit', (code) => {
      if (this.closing) return;

      this.remove(slot);

      if (!slot.ready) {
        onStartupFailure(
          new LocalModelError(`classifier worker exited during startup (code ${code})`, 'bad-model'),
        );
        return;
      }

      if (slot.task) {
        this.failed += 1;
        slot.task.reject(
          new LocalModelError(`classifier worker exited (code ${code})`, 'inference'),
        );
        slot.task = undefined;
      }

      // Replace the worker so a single crash does not permanently halve
      // throughput. The restart budget stops a crash loop from spinning.
      if (this.restarts < this.workerCount * 3) {
        this.restarts += 1;
        this.spawn(onReady, onStartupFailure);
        this.dispatch();
      } else {
        const error = new LocalModelError('classifier workers keep crashing', 'inference');
        for (const task of this.queue.splice(0)) task.reject(error);
      }
    });

    worker.postMessage({
      type: 'init',
      modelDir: this.modelDir,
      maxLength: this.maxLength,
    });
  }

  private onMessage(
    slot: Slot,
    message: WorkerResponse,
    onReady: () => void,
    onStartupFailure: (error: unknown) => void,
  ): void {
    if (message.type === 'ready') {
      slot.ready = true;
      onReady();
      this.dispatch();
      return;
    }

    if (message.type === 'closed') return;

    if (message.type === 'error') {
      const error = new LocalModelError(message.message, asKind(message.kind));

      if (!slot.ready) {
        onStartupFailure(error);
        this.remove(slot);
        void slot.worker.terminate();
        return;
      }

      if (slot.task && (message.id === undefined || slot.task.id === message.id)) {
        this.settle(slot, error);
      }
      return;
    }

    if (slot.task?.id !== message.id) return;

    this.completed += 1;
    this.finish(slot, () => slot.task?.resolve(message.vulnerable));
  }

  private dispatch(): void {
    if (this.closing) return;

    for (const slot of this.slots) {
      if (!slot.ready || slot.task) continue;
      const task = this.queue.shift();
      if (!task) return;

      slot.task = task;
      slot.timer = setTimeout(() => {
        if (slot.task !== task) return;
        slot.task = undefined;
        this.failed += 1;
        task.reject(
          new LocalModelError(`inference timed out after ${this.requestTimeoutMs}ms`, 'inference'),
        );
        this.replace(slot);
      }, this.requestTimeoutMs);

      slot.worker.postMessage({ type: 'score', id: task.id, code: task.code });
    }
  }

  private finish(slot: Slot, settle: () => void): void {
    if (slot.timer) clearTimeout(slot.timer);
    slot.timer = undefined;
    if (slot.task) settle();
    slot.task = undefined;
    this.dispatch();
  }

  private settle(slot: Slot, error: unknown): void {
    this.failed += 1;
    const task = slot.task;
    this.finish(slot, () => task?.reject(error));
  }

  private failSlot(slot: Slot, error: unknown): void {
    if (slot.task) {
      this.settle(slot, error);
    }
    this.replace(slot);
  }

  private replace(slot: Slot): void {
    if (this.closing || !this.slots.includes(slot)) return;
    this.remove(slot);
    void slot.worker.terminate();

    if (this.restarts < this.workerCount * 3) {
      this.restarts += 1;
      this.spawn(() => {}, () => {});
      this.dispatch();
    }
  }

  private remove(slot: Slot): void {
    if (slot.timer) clearTimeout(slot.timer);
    const index = this.slots.indexOf(slot);
    if (index !== -1) this.slots.splice(index, 1);
  }
}