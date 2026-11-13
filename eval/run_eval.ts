/**
 * Headless evaluation harness.
 *
 * Runs the exact production pipeline (rules -> candidates -> provider ->
 * presentFindings) over a labelled corpus and reports precision, recall, and
 * false positives on clean files.
 *
 *   npm run eval                 # rules only
 *   npm run eval:ai              # rules, rules+ollama, rules+deep scan
 *
 * Configuration comes from flags and environment variables, never from
 * VS Code settings, so results are reproducible outside the editor:
 *
 *   OLLAMA_BASE_URL   default http://127.0.0.1:11434
 *   OLLAMA_MODEL      default qwen2.5-coder:7b
 *   OPENAI_API_KEY    enables the `byok` mode
 *   OPENAI_BASE_URL   default https://api.openai.com/v1
 *   OPENAI_MODEL      default gpt-4o-mini
 */
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { analyzeCandidates, type AnalysisResult } from '../src/lm/analyzer';
import { buildCandidates } from '../src/lm/candidates';
import { OllamaProvider } from '../src/lm/ollama';
import { OpenAiCompatibleProvider } from '../src/lm/openai';
import { describeError } from '../src/lm/types';
import type { LlmProvider } from '../src/lm/types';
import type { LlmVerdict } from '../src/lm/verdict';
import { chunkPython } from '../src/scan/chunker';
import { scanPython } from '../src/scan/scanner';
import type { Severity } from '../src/types';
import { presentFindings, type FindingSource } from '../src/ui/present';
import {
  addCounts,
  emptyCounts,
  f1,
  percent,
  precision,
  recall,
  scoreFile as scorePredictions,
  type Counts,
  type LabelledIssue,
  type Prediction as ScoredPrediction,
} from './score';

/* ------------------------------------------------------------------ *
 * Corpus
 * ------------------------------------------------------------------ */

interface LabelEntry {
  file: string;
  category: 'vulnerable' | 'clean';
  issues: LabelledIssue[];
}

interface Labels {
  version: number;
  tolerance: number;
  files: LabelEntry[];
}

interface Prediction extends ScoredPrediction {
  severity: Severity;
  source: FindingSource;
}

interface FileRun {
  file: string;
  category: LabelEntry['category'];
  expected: LabelledIssue[];
  predicted: Prediction[];
  dismissed: Prediction[];
  requests: number;
  ms: number;
  error?: string;
}

/* ------------------------------------------------------------------ *
 * Scoring
 * ------------------------------------------------------------------ */

function scoreFile(run: FileRun, tolerance: number) {
  return scorePredictions(run.expected, run.predicted, tolerance);
}

interface ModeReport {
  mode: string;
  provider: string;
  skipped?: string;
  files: FileRun[];
  totals: Counts;
  perCwe: Record<string, Counts>;
  cleanFalsePositives: number;
  cleanFilesWithFalsePositive: number;
  requests: number;
  ms: number;
}

/* ------------------------------------------------------------------ *
 * Providers
 * ------------------------------------------------------------------ */

type ModeName = 'rules' | 'ollama' | 'deep' | 'byok';

function makeProvider(mode: ModeName): LlmProvider | null {
  if (mode === 'ollama' || mode === 'deep') {
    return new OllamaProvider({
      baseUrl: process.env.OLLAMA_BASE_URL ?? 'http://127.0.0.1:11434',
      model: process.env.OLLAMA_MODEL ?? 'qwen2.5-coder:7b',
    });
  }

  if (mode === 'byok') {
    const apiKey = process.env.OPENAI_API_KEY;
    if (!apiKey) return null;
    return new OpenAiCompatibleProvider({
      baseUrl: process.env.OPENAI_BASE_URL ?? 'https://api.openai.com/v1',
      model: process.env.OPENAI_MODEL ?? 'gpt-4o-mini',
      apiKey,
    });
  }

  return null;
}

/* ------------------------------------------------------------------ *
 * Runner
 * ------------------------------------------------------------------ */

interface Options {
  modes: ModeName[];
  limit: number;
  outDir: string;
  tolerance: number;
}

function parseArgs(argv: string[], defaults: Labels): Options {
  const options: Options = {
    modes: ['rules'],
    limit: Number.POSITIVE_INFINITY,
    outDir: join(process.cwd(), 'eval', 'results'),
    tolerance: defaults.tolerance,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === '--modes') {
      options.modes = (argv[++index] ?? 'rules')
        .split(',')
        .map((mode) => mode.trim() as ModeName)
        .filter(Boolean);
    } else if (arg === '--limit') {
      options.limit = Number.parseInt(argv[++index] ?? '0', 10) || Number.POSITIVE_INFINITY;
    } else if (arg === '--out') {
      options.outDir = argv[++index] ?? options.outDir;
    } else if (arg === '--tolerance') {
      options.tolerance = Number.parseInt(argv[++index] ?? '2', 10);
    }
  }

  return options;
}

async function runMode(
  mode: ModeName,
  labels: Labels,
  options: Options,
): Promise<ModeReport> {
  const provider = makeProvider(mode);
  const report: ModeReport = {
    mode,
    provider: provider ? `${provider.label} · ${provider.model}` : 'none',
    files: [],
    totals: emptyCounts(),
    perCwe: {},
    cleanFalsePositives: 0,
    cleanFilesWithFalsePositive: 0,
    requests: 0,
    ms: 0,
  };

  if (mode !== 'rules') {
    if (!provider) {
      report.skipped = mode === 'byok' ? 'OPENAI_API_KEY is not set' : 'no provider';
      return report;
    }
    const status = await provider.status();
    if (!status.available) {
      report.skipped = status.detail;
      return report;
    }
    report.provider = `${provider.label} · ${provider.model}`;
  }

  const cache = new Map<string, LlmVerdict>();
  const files = labels.files.slice(0, options.limit);

  for (const [index, entry] of files.entries()) {
    const source = readFileSync(join(process.cwd(), 'eval', 'corpus', entry.file), 'utf8');
    const started = performance.now();

    const hits = scanPython(source);
    const chunks = chunkPython(source);

    let analyses: AnalysisResult[] = [];
    let requests = 0;
    let error: string | undefined;

    if (provider) {
      const candidates = buildCandidates({
        chunks,
        hits,
        deep: mode === 'deep',
        max: 40,
      });
      requests = candidates.length;

      const failures: string[] = [];
      analyses = await analyzeCandidates(candidates, provider, {
        concurrency: 2,
        timeoutMs: 120_000,
        cache,
        onError: (candidate, failure) => {
          failures.push(`${candidate.request.functionName}: ${describeError(failure)}`);
        },
      });
      if (failures.length > 0) error = failures.join('; ');
    }

    const presented = presentFindings({ hits, chunks, analyses, minConfidence: 0.6 });
    const predicted: Prediction[] = presented
      .filter((finding) => !finding.dismissed)
      .map((finding) => ({
        line: finding.line + 1,
        cwe: finding.cwe,
        severity: finding.severity,
        source: finding.source,
      }));

    const dismissed: Prediction[] = presented
      .filter((finding) => finding.dismissed)
      .map((finding) => ({
        line: finding.line + 1,
        cwe: finding.cwe,
        severity: finding.severity,
        source: finding.source,
      }));

    const run: FileRun = {
      file: entry.file,
      category: entry.category,
      expected: entry.issues,
      predicted,
      dismissed,
      requests,
      ms: Math.round(performance.now() - started),
      ...(error ? { error } : {}),
    };

    report.files.push(run);
    report.requests += requests;
    report.ms += run.ms;

    const score = scoreFile(run, options.tolerance);
    addCounts(report.totals, score.counts);

    if (entry.category === 'clean') {
      report.cleanFalsePositives += score.counts.fp;
      if (score.counts.fp > 0) report.cleanFilesWithFalsePositive += 1;
    }

    // Recount per CWE with explicit attribution.
    const used = new Set<number>();
    for (const issue of entry.issues) {
      const index = run.predicted.findIndex(
        (prediction, candidateIndex) =>
          !used.has(candidateIndex) &&
          prediction.cwe === issue.cwe &&
          Math.abs(prediction.line - issue.line) <= options.tolerance,
      );
      const bucket = (report.perCwe[issue.cwe] ??= emptyCounts());
      if (index >= 0) {
        used.add(index);
        bucket.tp += 1;
      } else {
        bucket.fn += 1;
      }
    }
    for (const [index, prediction] of run.predicted.entries()) {
      if (used.has(index)) continue;
      const key = prediction.cwe ?? 'unknown';
      const bucket = (report.perCwe[key] ??= emptyCounts());
      bucket.fp += 1;
    }

    process.stderr.write(
      `\r[${mode}] ${index + 1}/${files.length} ${entry.file}${entry.category === 'clean' ? ' (clean)' : ''}   `,
    );
  }

  process.stderr.write('\n');
  return report;
}

/* ------------------------------------------------------------------ *
 * Reporting
 * ------------------------------------------------------------------ */

function summaryRow(report: ModeReport, files: number): string {
  const { totals } = report;
  return [
    report.mode + (report.skipped ? ' *(skipped)*' : ''),
    String(totals.tp),
    String(totals.fp),
    String(totals.fn),
    percent(precision(totals)),
    percent(recall(totals)),
    percent(f1(totals)),
    String(report.cleanFalsePositives),
    `${report.cleanFilesWithFalsePositive}`,
    files === 0 ? '—' : String(Math.round(report.ms / files)),
    String(report.requests),
  ].join(' | ');
}

function buildMarkdown(reports: ModeReport[], labels: Labels, options: Options): string {
  const files = Math.min(labels.files.length, options.limit);
  const issueCount = labels.files
    .slice(0, options.limit)
    .reduce((sum, entry) => sum + entry.issues.length, 0);
  const clean = labels.files
    .slice(0, options.limit)
    .filter((entry) => entry.category === 'clean').length;

  const lines: string[] = [];
  lines.push('# VulnGuard evaluation', '');
  lines.push(`Corpus: **${files} files** (${files - clean} vulnerable, ${clean} clean), **${issueCount} labelled issues**.`);
  lines.push(`Matching: same CWE within ±${options.tolerance} lines. A finding dismissed by the AI counts as a miss, not a false positive.`);
  lines.push('');

  lines.push('| Mode | TP | FP | FN | Precision | Recall | F1 | FP on clean | Clean files with FP | ms/file | requests |');
  lines.push('|---|---|---|---|---|---|---|---|---|---|---|');
  for (const report of reports) {
    lines.push(`| ${summaryRow(report, files)} |`);
  }
  lines.push('');

  for (const report of reports) {
    lines.push(`## ${report.mode}`, '');
    if (report.skipped) {
      lines.push(`Skipped: ${report.skipped}`, '');
      continue;
    }
    lines.push(`Provider: ${report.provider}`, '');

    const cwes = Object.keys(report.perCwe).sort();
    if (cwes.length > 0) {
      lines.push('| CWE | TP | FP | FN | Recall |');
      lines.push('|---|---|---|---|---|');
      for (const cwe of cwes) {
        const counts = report.perCwe[cwe];
        lines.push(
          `| ${cwe} | ${counts.tp} | ${counts.fp} | ${counts.fn} | ${percent(recall(counts))} |`,
        );
      }
      lines.push('');
    }

    const missed = report.files.flatMap((run) =>
      scoreFile(run, options.tolerance).missed.map((issue) => ({ file: run.file, issue })),
    );
    const falsePositives = report.files.flatMap((run) =>
      scoreFile(run, options.tolerance).falsePositives.map((prediction) => ({
        file: run.file,
        prediction,
        clean: run.category === 'clean',
      })),
    );

    if (missed.length > 0) {
      lines.push('**Missed:**');
      for (const entry of missed) {
        lines.push(`- \`${entry.file}:${entry.issue.line}\` ${entry.issue.cwe}`);
      }
      lines.push('');
    }

    if (falsePositives.length > 0) {
      lines.push('**False positives:**');
      for (const entry of falsePositives) {
        lines.push(
          `- \`${entry.file}:${entry.prediction.line}\` ${entry.prediction.cwe ?? 'unknown'} (${entry.clean ? 'clean file' : 'vulnerable file'}, ${entry.prediction.source})`,
        );
      }
      lines.push('');
    }

    const dismissed = report.files.flatMap((run) =>
      run.dismissed.map((prediction) => ({ file: run.file, prediction })),
    );
    if (dismissed.length > 0) {
      lines.push('**Dismissed by AI as false positives:**');
      for (const entry of dismissed) {
        lines.push(`- \`${entry.file}:${entry.prediction.line}\` ${entry.prediction.cwe ?? 'unknown'}`);
      }
      lines.push('');
    }
  }

  return `${lines.join('\n')}\n`;
}

/* ------------------------------------------------------------------ *
 * Main
 * ------------------------------------------------------------------ */

async function main(): Promise<void> {
  const labels = JSON.parse(
    readFileSync(join(process.cwd(), 'eval', 'labels.json'), 'utf8'),
  ) as Labels;

  const options = parseArgs(process.argv.slice(2), labels);
  const reports: ModeReport[] = [];

  for (const mode of options.modes) {
    reports.push(await runMode(mode, labels, options));
  }

  const markdown = buildMarkdown(reports, labels, options);

  mkdirSync(options.outDir, { recursive: true });
  writeFileSync(join(options.outDir, 'results.json'), `${JSON.stringify({ options, reports }, null, 2)}\n`);
  writeFileSync(join(process.cwd(), 'eval', 'RESULTS.md'), markdown);

  process.stdout.write(markdown);
  process.stderr.write(`\nWrote eval/RESULTS.md and ${join(options.outDir, 'results.json')}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
  process.exitCode = 1;
});
