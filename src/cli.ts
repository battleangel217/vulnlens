import * as fs from 'node:fs';
import * as path from 'node:path';
import { buildJson, exitCode, formatText, sortFindings, summarize } from './cli/format';
import { buildSarif, type FileResult } from './cli/sarif';
import { scanPython } from './scan/scanner';
import type { Severity } from './types';

const MAX_FILE_BYTES = 2 * 1024 * 1024;
const SEVERITIES: readonly Severity[] = ['low', 'medium', 'high', 'critical'];

const SKIP_DIRS = new Set([
  '.git',
  '.hg',
  '.svn',
  '.mypy_cache',
  '.pytest_cache',
  '.tox',
  '.venv',
  '__pycache__',
  'build',
  'dist',
  'env',
  'node_modules',
  'site-packages',
  'venv',
]);

interface Options {
  readonly paths: string[];
  readonly format: 'text' | 'json' | 'sarif';
  readonly output?: string;
  readonly minSeverity: Severity;
  readonly suppressions: boolean;
  readonly fail: boolean;
}

const HELP = `VulnLens — deterministic CWE rules for Python

Usage:
  vulnlens [paths...] [options]

Options:
  --format <text|json|sarif>   Report format (default: text)
  --output <file>              Write the report to a file instead of stdout
  --min-severity <level>       low | medium | high | critical (default: low)
  --no-suppressions           Ignore "# vuln-ignore" comments
  --no-fail                   Exit 0 even when findings exist
  --version                   Print the version
  --help                      Show this help

Paths may be files or directories. Directories are walked recursively and
node_modules, virtualenvs, caches, and build output are skipped.

Exit codes: 0 clean, 1 findings, 2 usage or read error.`;

function fail(message: string): never {
  process.stderr.write(`vulnlens: ${message}\n`);
  process.exit(2);
}

function readVersion(): string {
  for (const candidate of [
    path.join(__dirname, '..', 'package.json'),
    path.join(__dirname, '..', '..', 'package.json'),
  ]) {
    try {
      const parsed = JSON.parse(fs.readFileSync(candidate, 'utf8')) as { version?: string };
      if (parsed.version) return parsed.version;
    } catch {
      // Try the next location.
    }
  }
  return 'unknown';
}

function parseArgs(argv: readonly string[]): Options {
  const paths: string[] = [];
  let format: Options['format'] = 'text';
  let output: string | undefined;
  let minSeverity: Severity = 'low';
  let suppressions = true;
  let failOnFindings = true;

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    switch (arg) {
      case '--help':
      case '-h':
        process.stdout.write(`${HELP}\n`);
        process.exit(0);
        break;
      case '--version':
      case '-v':
        process.stdout.write(`${readVersion()}\n`);
        process.exit(0);
        break;
      case '--format': {
        const value = argv[++i];
        if (value !== 'text' && value !== 'json' && value !== 'sarif') {
          fail('--format must be text, json, or sarif');
        }
        format = value;
        break;
      }
      case '--output':
      case '-o':
        output = argv[++i];
        if (!output) fail('--output needs a file name');
        break;
      case '--min-severity': {
        const value = argv[++i] as Severity;
        if (!SEVERITIES.includes(value)) fail('--min-severity must be low, medium, high, or critical');
        minSeverity = value;
        break;
      }
      case '--no-suppressions':
        suppressions = false;
        break;
      case '--no-fail':
        failOnFindings = false;
        break;
      default:
        if (arg.startsWith('-')) fail(`unknown option ${arg}`);
        paths.push(arg);
    }
  }

  return {
    paths: paths.length > 0 ? paths : ['.'],
    format,
    output,
    minSeverity,
    suppressions,
    fail: failOnFindings,
  };
}

function* pythonFiles(target: string): Generator<string> {
  let stat: fs.Stats;
  try {
    stat = fs.statSync(target);
  } catch (error) {
    fail(`cannot read ${target}: ${(error as Error).message}`);
  }

  if (stat.isFile()) {
    if (path.extname(target).toLowerCase() === '.py') yield target;
    else fail(`${target} is not a Python file`);
    return;
  }

  if (!stat.isDirectory()) return;

  for (const entry of fs.readdirSync(target, { withFileTypes: true })) {
    const child = path.join(target, entry.name);
    if (entry.isSymbolicLink()) continue;
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      yield* pythonFiles(child);
    } else if (entry.isFile() && entry.name.toLowerCase().endsWith('.py')) {
      yield child;
    }
  }
}

function main(): void {
  const options = parseArgs(process.argv.slice(2));
  const results: FileResult[] = [];
  let scanned = 0;

  for (const target of options.paths) {
    for (const file of pythonFiles(target)) {
      let source: string;
      try {
        const stat = fs.statSync(file);
        if (stat.size > MAX_FILE_BYTES) {
          process.stderr.write(`vulnlens: skipped ${file}: larger than 2 MB\n`);
          continue;
        }
        source = fs.readFileSync(file, 'utf8');
      } catch (error) {
        fail(`cannot read ${file}: ${(error as Error).message}`);
      }

      scanned += 1;
      const relative = path.relative(process.cwd(), path.resolve(file)).replace(/\\/g, '/');
      results.push({
        path: relative || path.basename(file),
        findings: scanPython(source, {
          minSeverity: options.minSeverity,
          respectSuppressions: options.suppressions,
        }),
      });
    }
  }

  const sorted = sortFindings(results);
  const version = readVersion();

  const body =
    options.format === 'sarif'
      ? JSON.stringify(buildSarif(sorted, { version }), null, 2)
      : options.format === 'json'
        ? JSON.stringify(buildJson(sorted, version), null, 2)
        : formatText(sorted);

  if (options.output) {
    fs.writeFileSync(options.output, `${body}\n`, 'utf8');
    const summary = summarize(sorted);
    process.stderr.write(
      `vulnlens: ${summary.findings} finding(s) in ${summary.filesWithFindings} of ${scanned} file(s) -> ${options.output}\n`,
    );
  } else {
    process.stdout.write(`${body}\n`);
  }

  if (options.fail && exitCode(sorted) !== 0) process.exitCode = 1;
}

main();
