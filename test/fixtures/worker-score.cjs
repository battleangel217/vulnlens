const { appendFileSync } = require('node:fs');
const { parentPort, workerData, threadId } = require('node:worker_threads');

const log = process.env.VG_POOL_TEST_LOG;

function note() {
  if (log) appendFileSync(log, `${threadId}\n`);
}

parentPort.on('message', async (message) => {
  if (message.type === 'init') {
    if (message.modelDir === 'missing') {
      parentPort.postMessage({ type: 'error', message: 'stub model is missing', kind: 'missing-model' });
      return;
    }
    if (message.modelDir === 'corrupt') {
      parentPort.postMessage({ type: 'error', message: 'stub model is corrupt', kind: 'bad-model' });
      return;
    }
    parentPort.postMessage({ type: 'ready', maxLength: workerData.maxLength ?? 8 });
    return;
  }

  if (message.type === 'close') {
    process.exit(0);
  }

  if (message.type !== 'score') return;

  if (message.code === 'boom') {
    process.exit(3);
  }

  if (message.code === 'hang') {
    return;
  }

  await new Promise((resolve) =>
    setTimeout(resolve, workerData.delay ?? Number(process.env.VG_POOL_TEST_DELAY ?? 20)),
  );
  note();

  const vulnerable = message.code.includes('vuln') ? 0.9 : 0.1;
  parentPort.postMessage({ type: 'result', id: message.id, vulnerable, safe: 1 - vulnerable });
});