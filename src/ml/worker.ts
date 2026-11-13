import { parentPort } from 'node:worker_threads';
import { createClassifier, LocalModelError, type LocalClassifier } from './classifier';
import type { ScoreMessage, WorkerRequest, WorkerResponse } from './protocol';

/**
 * Worker entry point. One model loaded per thread; the main thread never blocks
 * on tokenisation or inference.
 *
 * Messages that arrive before the model finishes loading are queued rather than
 * rejected, so the pool can dispatch as soon as a slot reports ready.
 */
const port = parentPort;

if (port) {
  let classifier: LocalClassifier | undefined;
  let pending: ScoreMessage[] = [];

  const send = (message: WorkerResponse): void => port.postMessage(message);

  const score = async (message: ScoreMessage): Promise<void> => {
    if (!classifier) {
      pending.push(message);
      return;
    }
    try {
      const result = await classifier.score(message.code);
      send({ type: 'result', id: message.id, vulnerable: result.vulnerable, safe: result.safe });
    } catch (error) {
      send({
        type: 'error',
        id: message.id,
        message: error instanceof Error ? error.message : String(error),
        kind: error instanceof LocalModelError ? error.kind : 'inference',
      });
    }
  };

  const flush = (): void => {
    const queue = pending;
    pending = [];
    for (const message of queue) void score(message);
  };

  port.on('message', (message: WorkerRequest) => {
    if (message.type === 'init') {
      createClassifier({ directory: message.modelDir, maxLength: message.maxLength })
        .then((created) => {
          classifier = created;
          send({ type: 'ready', maxLength: created.maxLength });
          flush();
        })
        .catch((error: unknown) => {
          send({
            type: 'error',
            message: error instanceof Error ? error.message : String(error),
            kind: error instanceof LocalModelError ? error.kind : 'bad-model',
          });
        });
      return;
    }

    if (message.type === 'score') {
      void score(message);
      return;
    }

    if (message.type === 'close') {
      void classifier?.close().finally(() => {
        send({ type: 'closed' });
        process.exit(0);
      });
    }
  });
}