/**
 * Evaluates the local ONNX triage model on the labelled corpus.
 *
 *   npm run eval:model -- --model ml/out
 *
 * Unlike `run_eval.ts`, this does not pretend the model produces CWE findings.
 * It reports file-level precision/recall at a threshold sweep, plus how many
 * labelled issues sit inside a chunk the model scored above the threshold. That
 * second number is the one that matters: the model's job is to nominate
 * functions for the AI verifier, not to name the bug.
 */
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { ClassifierPool } from '../src/ml/pool';
import { triageChunks } from '../src/ml/triage';
import { chunkPython } from '../src/scan/chunker';
import {
  fileF1,
  filePrecision,
  fileRecall,
  sweep,
  type ModelFile,
  type ThresholdResult,
} from './model_score';
import { percent } from './score';

interface LabelEntry {
  file: string;
  category: 'vulnerable' | 'clean';
  issues: { line: number; cwe: string }[];
}

interface Labels {
  files: LabelEntry[];
}

interface Options {
  modelDir: string;
  thresholds: number[];
  workers: number;
  outDir: string;
}

function parseArgs(argv: string[]): Options {
  const options: Options = {
    modelDir: process.env.VG_MODEL_DIR ?? '',
    thresholds: Array.from({ length: 9 }, (_, index) => Number(((index + 1) / 10).toFixed(1))),
    workers: 2,
    outDir: join(process.cwd(), 'eval', 'results'),
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--model') options.modelDir = argv[++index] ?? '';
    else if (arg === '--workers') options.workers = Number.parseInt(argv[++index] ?? '2', 10);
    else if (arg === '--out') options.outDir = argv[++index] ?? options.outDir;
    else if (arg === '--thresholds') {
      options.thresholds = (argv[++index] ?? '')
        .split(',')
        .map((value) => Number.parseFloat(value.trim()))
        .filter((value) => Number.isFinite(value) && value >= 0 && value <= 1);
    }
  }

  return options;
}

function markdown(options: Options, files: ModelFile[], results: ThresholdResult[]): string {
  const clean = files.filter((file) => file.category === 'clean').length;
  const issues = files.reduce((sum, file) => sum + file.issues.length, 0);

  const best = [...results].sort((a, b) => fileF1(b.files) - fileF1(a.files))[0];

  const lines: string[] = [];
  lines.push('# Local model evaluation', '');
  lines.push(`Model: \`${options.modelDir}\``);
  lines.push(
    `Corpus: **${files.length} files** (${files.length - clean} vulnerable, ${clean} clean), **${issues} labelled issues**.`,
  );
  lines.push(
    'File-level prediction uses the maximum chunk probability. Issue coverage counts a label as covered only when the chunk containing it scores at or above the threshold.',
    '',
  );
  lines.push('| Threshold | TP | FP | FN | TN | Precision | Recall | F1 | Issue coverage |');
  lines.push('|---|---|---|---|---|---|---|---|---|');

  for (const result of results) {
    const coverage =
      result.totalIssues === 0
        ? '—'
        : `${result.coveredIssues}/${result.totalIssues} (${percent(result.coveredIssues / result.totalIssues)})`;
    lines.push(
      `| ${result.threshold.toFixed(2)} | ${result.files.tp} | ${result.files.fp} | ${result.files.fn} | ${result.files.tn} | ${percent(filePrecision(result.files))} | ${percent(fileRecall(result.files))} | ${percent(fileF1(result.files))} | ${coverage} |`,
    );
  }

  if (best) {
    lines.push(
      '',
      `Highest file-level F1: **${best.threshold.toFixed(2)}** (${percent(fileF1(best.files))}).`,
      'For triage, prefer a lower threshold than the F1 optimum: a missed function never reaches the verifier.',
    );
  }

  return `${lines.join('\n')}\n`;
}

async function main(): Promise<void> {
  const options = parseArgs(process.argv.slice(2));

  if (!options.modelDir) {
    process.stderr.write(
      'No model directory. Pass --model <dir> or set VG_MODEL_DIR.\n' +
        'The directory must contain model.onnx, vocab.json and merges.txt (see ml/README.md).\n',
    );
    process.exitCode = 1;
    return;
  }

  const labels = JSON.parse(
    readFileSync(join(process.cwd(), 'eval', 'labels.json'), 'utf8'),
  ) as Labels;

  let pool: ClassifierPool;
  try {
    pool = await ClassifierPool.create({
      modelDir: options.modelDir,
      workers: options.workers,
      requestTimeoutMs: 30_000,
    });
  } catch (error) {
    process.stderr.write(
      `Could not load the local model: ${error instanceof Error ? error.message : String(error)}\n`,
    );
    process.exitCode = 1;
    return;
  }

  const files: ModelFile[] = [];
  let failures = 0;

  try {
    for (const [index, entry] of labels.files.entries()) {
      const source = readFileSync(join(process.cwd(), 'eval', 'corpus', entry.file), 'utf8');
      const chunks = chunkPython(source);

      const summary = await triageChunks(chunks, (code) => pool.score(code), {
        maxChunks: 1000,
      });
      failures += summary.failed;

      files.push({
        file: entry.file,
        category: entry.category,
        issues: entry.issues,
        chunks: chunks
          .filter((chunk) => summary.scores.has(chunk.startLine))
          .map((chunk) => ({
            startLine: chunk.startLine,
            endLine: chunk.endLine,
            probability: summary.scores.get(chunk.startLine)!,
          })),
      });

      process.stderr.write(
        `\r[model] ${index + 1}/${labels.files.length} ${entry.file}${entry.category === 'clean' ? ' (clean)' : ''}   `,
      );
    }
  } finally {
    await pool.close();
  }

  process.stderr.write('\n');

  const results = sweep(files, options.thresholds);
  const output = markdown(options, files, results);

  mkdirSync(options.outDir, { recursive: true });
  writeFileSync(join(options.outDir, 'model.json'), `${JSON.stringify({ options, files, results }, null, 2)}\n`);
  writeFileSync(join(process.cwd(), 'eval', 'MODEL_RESULTS.md'), output);

  process.stdout.write(output);

  if (failures > 0) {
    process.stderr.write(`${failures} chunk(s) failed to score\n`);
  }
  process.stderr.write(
    `Wrote eval/MODEL_RESULTS.md and ${join(options.outDir, 'model.json')}\n`,
  );
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
  process.exitCode = 1;
});