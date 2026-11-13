import * as esbuild from 'esbuild';

const watch = process.argv.includes('--watch');

/** @type {import('esbuild').BuildOptions} */
const extension = {
  entryPoints: ['src/extension.ts'],
  bundle: true,
  platform: 'node',
  format: 'cjs',
  target: 'node18',
  outfile: 'dist/extension.js',
  external: ['vscode'],
  sourcemap: true,
  minify: !watch,
  logLevel: 'info',
};

/** Headless evaluation runner: same scanner code, no editor API. */
const evaluator = {
  entryPoints: ['eval/run_eval.ts'],
  bundle: true,
  platform: 'node',
  format: 'cjs',
  target: 'node18',
  outfile: 'dist/eval.js',
  sourcemap: true,
  minify: false,
  logLevel: 'info',
};

if (watch) {
  const ctx = await esbuild.context(extension);
  await ctx.watch();
} else {
  await esbuild.build(extension);
  await esbuild.build(evaluator);
}
