/**
 * Builds eval/labels.json from inline `# KLABEL CWE-xxx` markers and writes
 * marker-free copies to eval/corpus/ for the evaluator to read.
 *
 * Why: hand-maintaining 50 sets of line numbers invites silent drift, and
 * leaving "this line is vulnerable" comments in the snippets would leak the
 * answer into the AI prompt. The marked files stay as the single source of
 * truth; the stamped copies are disposable. Re-running is idempotent.
 *
 * Usage: node eval/extract-labels.mjs
 */
import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('.', import.meta.url));
const labeledDir = join(root, 'labeled');
const corpusDir = join(root, 'corpus');
const MARKER = /[ \t]*#\s*KLABEL\s+(CWE-\d+)[ \t]*$/;

rmSync(corpusDir, { recursive: true, force: true });
mkdirSync(corpusDir, { recursive: true });

const files = readdirSync(labeledDir)
  .filter((name) => name.endsWith('.py'))
  .sort();

const entries = [];

for (const file of files) {
  const raw = readFileSync(join(labeledDir, file), 'utf8');
  const lines = raw.split('\n');
  const issues = [];

  const cleaned = lines.map((line, index) => {
    const match = MARKER.exec(line);
    if (!match) return line;
    issues.push({ line: index + 1, cwe: match[1] });
    return line.replace(MARKER, '');
  });

  writeFileSync(join(corpusDir, file), cleaned.join('\n'));

  entries.push({
    file,
    category: issues.length > 0 ? 'vulnerable' : 'clean',
    issues,
  });
}

const payload = {
  version: 1,
  tolerance: 2,
  files: entries,
};

writeFileSync(join(root, 'labels.json'), `${JSON.stringify(payload, null, 2)}\n`);

const issueCount = entries.reduce((sum, entry) => sum + entry.issues.length, 0);
const vulnerable = entries.filter((entry) => entry.category === 'vulnerable').length;
console.log(
  `labels.json: ${entries.length} files (${vulnerable} vulnerable, ${entries.length - vulnerable} clean), ${issueCount} labelled issues`,
);