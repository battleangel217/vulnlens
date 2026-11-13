import * as esbuild from 'esbuild';

const watch = process.argv.includes('--watch');

const shared = {
  bundle: true,
  platform: 'node',
  format: 'cjs',
  target: 'node18',
  sourcemap: true,
  logLevel: 'info',
};

/** @type {import('esbuild').BuildOptions} */
const extension = {
  ...shared,
  entryPoints: ['src/extension.ts'],
  outfile: 'dist/extension.js',
  external: ['vscode', 'onnxruntime-node'],
  minify: !watch,
};

/** Headless evaluation runner: same scanner code, no editor API. */
const evaluator = {
  ...shared,
  entryPoints: ['eval/run_eval.ts'],
  outfile: 'dist/eval.js',
  minify: false,
};

/** Local-model evaluation: needs onnxruntime-node at runtime only. */
const modelEvaluator = {
  ...shared,
  entryPoints: ['eval/run_model_eval.ts'],
  outfile: 'dist/eval-model.js',
  external: ['onnxruntime-node'],
  minify: false,
};

/** Worker entry point that owns the ONNX session. */
const worker = {
  ...shared,
  entryPoints: ['src/ml/worker.ts'],
  outfile: 'dist/ml-worker.js',
  external: ['onnxruntime-node'],
  minify: !watch,
};

if (watch) {
  for (const options of [extension, worker, evaluator, modelEvaluator]) {
    const context = await esbuild.context(options);
    await context.watch();
  }
} else {
  for (const options of [extension, worker, evaluator, modelEvaluator]) {
    await esbuild.build(options);
  }
}