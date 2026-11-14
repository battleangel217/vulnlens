import * as vscode from 'vscode';
import { analyzeCandidates, type AnalysisResult } from './lm/analyzer';
import { buildCandidates } from './lm/candidates';
import {
  API_KEY_SECRET,
  aiMode,
  describeProvider,
  resetCopilotInstance,
  resolveProvider,
} from './lm';
import { describeError } from './lm/types';
import { cleanFix, type LlmVerdict } from './lm/verdict';
import { rewriteCandidate } from './lm/rewrite';
import { localModelConfig, closePool, ensurePool, probeLocalModel, resetPool } from './ml/setup';
import { triageChunks } from './ml/triage';
import { chunkPython } from './scan/chunker';
import { scanPython } from './scan/scanner';
import { SEVERITY_ORDER, type Severity } from './types';
import { registerCodeActions } from './ui/codeActions';
import { registerHoverProvider } from './ui/hover';
import { presentFindings, type PresentedFinding } from './ui/present';

const LANGUAGE_ID = 'python';
const MAX_FILE_BYTES = 2 * 1024 * 1024;

interface DocumentState {
  version: number;
  findings: PresentedFinding[];
  analyses: AnalysisResult[];
  abort?: AbortController;
  providerLabel?: string;
}

let extensionContext: vscode.ExtensionContext;
let diagnostics: vscode.DiagnosticCollection;
let statusBar: vscode.StatusBarItem;
let output: vscode.OutputChannel;

const documents = new Map<string, DocumentState>();
const verdictCache = new Map<string, LlmVerdict>();
const warned = new Set<string>();

export function activate(context: vscode.ExtensionContext): void {
  extensionContext = context;
  diagnostics = vscode.languages.createDiagnosticCollection('vuln-lens');
  output = vscode.window.createOutputChannel('VulnLens');
  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBar.command = 'vulnLens.scanFile';
  statusBar.show();

  const getFindings = (uri: vscode.Uri): readonly PresentedFinding[] =>
    documents.get(uri.toString())?.findings ?? [];

  context.subscriptions.push(
    diagnostics,
    output,
    statusBar,
    registerHoverProvider(getFindings),
    registerCodeActions(getFindings, 'vulnLens.analyzeFile'),

    vscode.commands.registerCommand('vulnLens.scanFile', () =>
      scanActive({ announce: true }),
    ),

    vscode.commands.registerCommand('vulnLens.analyzeFile', () =>
      scanActive({ announce: true, forceAi: true, allowPrompt: true }),
    ),

    vscode.commands.registerCommand('vulnLens.clearDiagnostics', () => {
      for (const state of documents.values()) state.abort?.abort();
      documents.clear();
      diagnostics.clear();
      updateStatusBar();
      output.appendLine('[vuln-lens] diagnostics cleared');
    }),

    vscode.commands.registerCommand('vulnLens.setApiKey', () => setApiKey()),

    vscode.commands.registerCommand('vulnLens.clearApiKey', async () => {
      await context.secrets.delete(API_KEY_SECRET);
      warned.clear();
      void vscode.window.showInformationMessage('VulnLens: stored API key removed.');
    }),

    vscode.commands.registerCommand('vulnLens.checkProvider', () => checkProvider()),

    vscode.commands.registerCommand('vulnLens.checkLocalModel', () => checkLocalModel()),

    vscode.commands.registerCommand('vulnLens.suggestFix', () => suggestRewrite()),

    vscode.commands.registerCommand('vulnLens.showReport', () => writeReport()),

    vscode.workspace.onDidOpenTextDocument((document) => {
      if (config().get<boolean>('scanOnOpen', true)) void scanDocument(document);
    }),

    vscode.workspace.onDidSaveTextDocument((document) => {
      if (config().get<boolean>('scanOnSave', true)) void scanDocument(document);
    }),

    vscode.workspace.onDidCloseTextDocument((document) => {
      const key = document.uri.toString();
      documents.get(key)?.abort?.abort();
      documents.delete(key);
      diagnostics.delete(document.uri);
      updateStatusBar();
    }),

    vscode.workspace.onDidChangeConfiguration((event) => {
      if (!event.affectsConfiguration('vulnLens')) return;
      warned.clear();
      resetCopilotInstance();
      resetPool();
      for (const document of vscode.workspace.textDocuments) {
        void scanDocument(document, { forceAi: true });
      }
      updateStatusBar();
    }),

    vscode.window.onDidChangeActiveTextEditor(() => updateStatusBar()),
  );

  for (const document of vscode.workspace.textDocuments) {
    if (config().get<boolean>('scanOnOpen', true)) void scanDocument(document);
  }

  updateStatusBar();
  output.appendLine(
    '[vuln-lens] activated (6 rules, AI mode: ' +
      aiMode() +
      ', local model: ' +
      (localModelConfig().enabled ? 'on' : 'off') +
      ')',
  );
}

export function deactivate(): void {
  for (const state of documents.values()) state.abort?.abort();
  documents.clear();
  diagnostics?.clear();
  void closePool();
}

function config(): vscode.WorkspaceConfiguration {
  return vscode.workspace.getConfiguration('vulnLens');
}

function scanActive(options: Parameters<typeof scanDocument>[1]): void {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    void vscode.window.showInformationMessage('VulnLens: open a Python file first.');
    return;
  }
  void scanDocument(editor.document, options);
}

/**
 * Rules run synchronously and publish immediately, so the editor never waits on
 * a model. AI verification then replaces those diagnostics when it finishes.
 */
async function scanDocument(
  document: vscode.TextDocument,
  options: { announce?: boolean; forceAi?: boolean; allowPrompt?: boolean; deep?: boolean } = {},
): Promise<void> {
  if (document.languageId !== LANGUAGE_ID) return;

  const key = document.uri.toString();
  const previous = documents.get(key);
  previous?.abort?.abort();

  if (!config().get<boolean>('enable', true)) {
    diagnostics.delete(document.uri);
    documents.delete(key);
    updateStatusBar();
    return;
  }

  const source = document.getText();
  if (Buffer.byteLength(source, 'utf8') > MAX_FILE_BYTES) {
    output.appendLine(`[vuln-lens] skipped ${vscode.workspace.asRelativePath(document.uri)}: file too large`);
    if (options.announce) void vscode.window.showWarningMessage('VulnLens: file is too large to scan.');
    return;
  }

  const startedAt = Date.now();
  const hitList = scanPython(source, {
    minSeverity: config().get<Severity>('minSeverity', 'low'),
  });
  const chunks = chunkPython(source);

  const state: DocumentState = {
    version: (previous?.version ?? 0) + 1,
    findings: [],
    analyses: [],
    abort: new AbortController(),
  };
  documents.set(key, state);

  // Instant, offline feedback.
  publish(document, presentFindings({ hits: hitList, chunks, analyses: [] }), state);
  output.appendLine(
    `[vuln-lens] ${vscode.workspace.asRelativePath(document.uri)}: ${hitList.length} rule finding(s) in ${Date.now() - startedAt}ms`,
  );

  const mode = aiMode();
  const wantAi =
    mode !== 'off' && (options.forceAi === true || config().get<boolean>('ai.analyzeOnSave', true));

  if (!wantAi) {
    if (options.announce) {
      void vscode.window.showInformationMessage(
        hitList.length === 0
          ? 'VulnLens: no findings.'
          : `VulnLens: ${hitList.length} finding(s). AI verification is ${mode === 'off' ? 'off' : 'disabled for saves'}.`,
      );
    }
    return;
  }

  const provider = await resolveProvider(
    extensionContext.secrets,
    mode,
    options.allowPrompt === true,
  );

  if (!provider) {
    warnOnce(
      `provider:${mode}`,
      mode === 'copilot'
        ? 'VulnLens: no Copilot model is available yet. Run "VulnLens: Analyze Current File with AI" to request access.'
        : 'VulnLens: no AI provider is configured. Run "VulnLens: Check AI Provider".',
      'Check Provider',
    );
    return;
  }

  const status = await provider.status();
  if (!status.available) {
    warnOnce(`status:${status.detail}`, `VulnLens: ${status.detail}`, 'Check Provider');
    return;
  }

  const maxChunks = config().get<number>('ai.maxChunks', 40);
  const deep = options.deep ?? config().get<boolean>('ai.deepScan', false);
  const local = localModelConfig();

  let triage: ReadonlyMap<number, number> | undefined;
  let triageThreshold = local.threshold;

  if (!deep && local.enabled && local.directory) {
    statusBar.text = '$(sync~spin) VulnLens: local triage';
    const { pool, error } = await ensurePool((line) => output.appendLine(line));

    if (pool) {
      const triageStartedAt = Date.now();
      const summary = await triageChunks(chunks, (code) => pool.score(code), {
        maxChunks: local.maxChunks,
        timeoutMs: local.timeoutMs,
      });
      triage = summary.scores;
      output.appendLine(
        `[vuln-lens] local triage: ${summary.scored} function(s) scored, ${summary.failed} failed, ${Date.now() - triageStartedAt}ms`,
      );
    } else if (error) {
      warnOnce(`local:${error}`, `VulnLens: local model unavailable (${error})`, 'Open Settings');
    }
  }

  const candidates = buildCandidates({
    chunks,
    hits: hitList,
    deep,
    max: maxChunks,
    triage,
    triageThreshold,
  });

  if (candidates.length === 0) return;

  state.providerLabel = `${provider.label} · ${provider.model}`;
  statusBar.text = `$(sync~spin) VulnLens: 0/${candidates.length}`;
  output.appendLine(
    `[vuln-lens] analysing ${candidates.length} function(s) with ${provider.id}/${provider.model}`,
  );

  let failures = 0;
  const results = await analyzeCandidates(candidates, provider, {
    concurrency: config().get<number>('ai.concurrency', 2),
    timeoutMs: config().get<number>('ai.timeoutMs', 25_000),
    signal: state.abort?.signal,
    cache: verdictCache,
    onProgress: (done, total) => {
      statusBar.text = `$(sync~spin) VulnLens: ${done}/${total}`;
    },
    onError: (candidate, error) => {
      failures += 1;
      output.appendLine(
        `[vuln-lens] ${candidate.request.functionName}: ${describeError(error)}`,
      );
    },
  });

  // A newer scan superseded this one.
  if (documents.get(key) !== state) return;

  state.analyses = results;
  publish(
    document,
    presentFindings({
      hits: hitList,
      chunks,
      analyses: results,
      minConfidence: config().get<number>('ai.minConfidence', 0.6),
    }),
    state,
  );

  const budget = Math.max(0, candidates.length - results.length);
  if (failures > 0) {
    warnOnce(
      `failures:${failures}`,
      `VulnLens: ${failures} of ${candidates.length} AI request(s) failed. See the VulnLens output log.`,
      'Show Log',
    );
  } else if (budget > 0) {
    output.appendLine(`[vuln-lens] ${budget} function(s) were not analysed`);
  }

  if (options.announce) {
    const active = state.findings.filter((finding) => !finding.dismissed).length;
    void vscode.window.showInformationMessage(
      `VulnLens: ${active} finding(s) after AI verification (${results.length} function(s) analysed).`,
    );
  }
}

function publish(
  document: vscode.TextDocument,
  findings: PresentedFinding[],
  state: DocumentState,
): void {
  state.findings = findings;
  diagnostics.set(document.uri, findings.map((finding) => toDiagnostic(document, finding)));
  updateStatusBar();

  for (const finding of findings) {
    const mark = finding.dismissed ? 'dismissed' : finding.source;
    output.appendLine(
      `  line ${finding.line + 1} ${finding.cwe ?? '-'} ${finding.severity.padEnd(8)} ${mark}: ${finding.title}`,
    );
  }
}

function toDiagnostic(document: vscode.TextDocument, finding: PresentedFinding): vscode.Diagnostic {
  const lastLine = Math.max(0, document.lineCount - 1);
  const startLine = Math.min(finding.line, lastLine);
  const endLine = Math.min(Math.max(finding.endLine, finding.line), lastLine);
  const startText = document.lineAt(startLine).text;
  const column = startText.length - startText.trimStart().length;

  const range = new vscode.Range(startLine, column, endLine, document.lineAt(endLine).text.length);
  const severity = finding.dismissed
    ? vscode.DiagnosticSeverity.Hint
    : mapSeverity(finding.severity);

  const diagnostic = new vscode.Diagnostic(range, finding.message, severity);
  diagnostic.source = 'vuln-lens';
  diagnostic.code = finding.cwe ?? 'vuln-lens';
  if (finding.dismissed) diagnostic.tags = [vscode.DiagnosticTag.Unnecessary];
  return diagnostic;
}

function mapSeverity(severity: Severity): vscode.DiagnosticSeverity {
  switch (severity) {
    case 'critical':
    case 'high':
      return vscode.DiagnosticSeverity.Error;
    case 'medium':
      return vscode.DiagnosticSeverity.Warning;
    case 'low':
      return vscode.DiagnosticSeverity.Information;
  }
}

function updateStatusBar(): void {
  const document = vscode.window.activeTextEditor?.document;

  if (!document || document.languageId !== LANGUAGE_ID) {
    statusBar.text = '$(shield) VulnLens';
    statusBar.tooltip = 'VulnLens: no Python file active';
    statusBar.backgroundColor = undefined;
    return;
  }

  const state = documents.get(document.uri.toString());
  const findings = state?.findings ?? [];
  const active = findings.filter((finding) => !finding.dismissed).length;
  const dismissed = findings.length - active;

  statusBar.text =
    active > 0
      ? `$(shield) VulnLens: ${active}`
      : dismissed > 0
        ? `$(shield) VulnLens: clean (${dismissed} dismissed)`
        : '$(shield) VulnLens: clean';

  statusBar.tooltip = [
    'VulnLens',
    state?.providerLabel ? `AI: ${state.providerLabel}` : `AI mode: ${aiMode()}`,
    localModelConfig().enabled ? 'Local model: on' : undefined,
    dismissed > 0 ? `${dismissed} rule finding(s) rejected by AI` : undefined,
    'Click to rescan',
  ]
    .filter(Boolean)
    .join('\n');

  statusBar.backgroundColor =
    active > 0 ? new vscode.ThemeColor('statusBarItem.warningBackground') : undefined;
}

async function setApiKey(): Promise<void> {
  const value = await vscode.window.showInputBox({
    title: 'VulnLens: API key',
    prompt: 'Key for your OpenAI-compatible endpoint. Stored in the OS keychain, never in settings.',
    password: true,
    ignoreFocusOut: true,
    placeHolder: 'sk-...',
    validateInput: (input) => (input.trim().length < 8 ? 'That looks too short.' : undefined),
  });

  if (!value) return;

  await extensionContext.secrets.store(API_KEY_SECRET, value.trim());
  warned.clear();

  const choice = await vscode.window.showInformationMessage(
    'VulnLens: API key stored.',
    aiMode() === 'byok' ? 'Check Provider' : 'Switch to BYOK mode',
  );
  if (choice === 'Switch to BYOK mode') {
    await vscode.workspace
      .getConfiguration('vulnLens')
      .update('ai.mode', 'byok', vscode.ConfigurationTarget.Global);
  } else if (choice === 'Check Provider') {
    await checkProvider();
  }
}

async function checkProvider(): Promise<void> {
  resetCopilotInstance();
  const status = await describeProvider(extensionContext.secrets);
  const summary = `${status.label}${status.model ? ` (${status.model})` : ''} — ${status.detail}`;

  output.appendLine(`[vuln-lens] provider: ${status.available ? 'ready' : 'unavailable'} · ${summary}`);

  if (status.available) {
    void vscode.window.showInformationMessage(`VulnLens: ${summary}`);
    return;
  }

  const choice = await vscode.window.showWarningMessage(
    `VulnLens: ${summary}`,
    aiMode() === 'byok' ? 'Set API Key' : 'Open Settings',
    'Show Log',
  );
  if (choice === 'Set API Key') await setApiKey();
  else if (choice === 'Show Log') output.show(true);
}

async function checkLocalModel(): Promise<void> {
  const config = localModelConfig();

  if (!config.enabled) {
    const choice = await vscode.window.showWarningMessage(
      'VulnLens: the local model is disabled. Enable vulnLens.localModel.enabled and set a model path.',
      'Open Settings',
      'Show Log',
    );
    if (choice === 'Open Settings') {
      await vscode.commands.executeCommand(
        'workbench.action.openSettings',
        'vulnLens.localModel',
      );
    }
    return;
  }

  if (!config.directory) {
    const choice = await vscode.window.showWarningMessage(
      'VulnLens: set vulnLens.localModel.path to a directory containing model.onnx, vocab.json and merges.txt.',
      'Open Settings',
      'Show Log',
    );
    if (choice === 'Open Settings') {
      await vscode.commands.executeCommand(
        'workbench.action.openSettings',
        'vulnLens.localModel.path',
      );
    }
    return;
  }

  output.appendLine(`[vuln-lens] checking local model at ${config.directory}`);

  try {
    const { outcome, ms, probability } = await probeLocalModel((line) => output.appendLine(line));
    const pool = outcome.pool;

    if (!pool) {
      const choice = await vscode.window.showWarningMessage(
        `VulnLens: local model unavailable — ${outcome.error ?? 'unknown error'}`,
        'Open Settings',
        'Show Log',
      );
      if (choice === 'Open Settings') {
        await vscode.commands.executeCommand(
          'workbench.action.openSettings',
          'vulnLens.localModel',
        );
      } else if (choice === 'Show Log') {
        output.show(true);
      }
      return;
    }

    const below = probability < config.threshold;
    const summary =
      `local model ready — ${pool.stats.workers} worker(s), ` +
      `probe ${(probability * 100).toFixed(1)}% vulnerable in ${ms}ms, ` +
      `threshold ${(config.threshold * 100).toFixed(0)}%` +
      (below
        ? ' — probe is below the threshold, so this model will not nominate a known SQL-injection sample'
        : '');

    output.appendLine(`[vuln-lens] ${summary}`);
    void vscode.window.showInformationMessage(`VulnLens: ${summary}`);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    output.appendLine(`[vuln-lens] local model probe failed: ${message}`);
    void vscode.window.showWarningMessage(`VulnLens: local model probe failed — ${message}`);
  }
}

/** A rewrite must look like a whole definition, never a bare fragment. */
const DEFINITION_RE = /\b(?:def|class)\s+[A-Za-z_]\w*/;

function rangeForChunk(
  document: vscode.TextDocument,
  startLine: number,
  endLine: number,
): vscode.Range {
  const last = Math.max(0, document.lineCount - 1);
  const start = Math.min(startLine, last);
  const end = Math.min(Math.max(endLine, start), last);
  return new vscode.Range(start, 0, end, document.lineAt(end).text.length);
}

/**
 * Ask the configured provider for a secure rewrite of the function under the
 * cursor. This is the proactive counterpart to the quick fix: it does not wait
 * for a rule to fire, so it can suggest a safer shape for code the heuristics
 * did not flag.
 */
async function suggestRewrite(): Promise<void> {
  const editor = vscode.window.activeTextEditor;
  if (!editor || editor.document.languageId !== LANGUAGE_ID) {
    void vscode.window.showWarningMessage('VulnLens: open a Python file first.');
    return;
  }

  const document = editor.document;
  const source = document.getText();
  if (source.length > MAX_FILE_BYTES) {
    void vscode.window.showWarningMessage('VulnLens: file is too large to rewrite.');
    return;
  }

  const mode = aiMode();
  if (mode === 'off') {
    const choice = await vscode.window.showWarningMessage(
      'VulnLens: AI is off. Set vulnLens.ai.mode to ollama, byok, or copilot.',
      'Open Settings',
    );
    if (choice === 'Open Settings') {
      await vscode.commands.executeCommand('workbench.action.openSettings', 'vulnLens.ai');
    }
    return;
  }

  const provider = await resolveProvider(extensionContext.secrets, mode, true);
  if (!provider) {
    void vscode.window.showWarningMessage(
      'VulnLens: no AI provider is configured. Run "VulnLens: Check AI Provider".',
    );
    return;
  }

  const status = await provider.status();
  if (!status.available) {
    void vscode.window.showWarningMessage(`VulnLens: ${status.detail}`);
    return;
  }

  const candidate = rewriteCandidate(source, editor.selection.active.line);
  if (!candidate) {
    void vscode.window.showWarningMessage(
      'VulnLens: put the cursor inside a function (and keep it under 12,000 characters).',
    );
    return;
  }

  const controller = new AbortController();
  statusBar.text = '$(sync~spin) VulnLens: requesting rewrite';

  try {
    const results = await vscode.window.withProgress(
      {
        location: vscode.ProgressLocation.Notification,
        title: `VulnLens: rewriting ${candidate.request.functionName}`,
        cancellable: true,
      },
      (_progress, token) => {
        token.onCancellationRequested(() => controller.abort());
        return analyzeCandidates([candidate], provider, {
          concurrency: 1,
          timeoutMs: config().get<number>('ai.timeoutMs', 25_000),
          signal: controller.signal,
          cache: verdictCache,
        });
      },
    );

    const verdict = results[0]?.verdict;
    if (!verdict) {
      void vscode.window.showWarningMessage('VulnLens: no rewrite returned.');
      return;
    }

    const fix = cleanFix(verdict.fix);
    if (!fix || !DEFINITION_RE.test(fix)) {
      void vscode.window.showInformationMessage(
        verdict.verdict === 'safe'
          ? `VulnLens: no exploitable issue found in ${candidate.request.functionName}.`
          : `VulnLens: ${candidate.request.functionName} looks vulnerable, but the model returned no complete function. ${verdict.reason}`,
      );
      return;
    }

    const preview = await vscode.workspace.openTextDocument({ language: 'python', content: fix });
    await vscode.window.showTextDocument(preview, {
      preview: true,
      viewColumn: vscode.ViewColumn.Beside,
    });

    const choice = await vscode.window.showInformationMessage(
      `VulnLens: suggested rewrite for ${candidate.request.functionName}. ${verdict.reason}`,
      'Apply',
      'Dismiss',
    );
    if (choice !== 'Apply') return;

    const range = rangeForChunk(document, candidate.startLine, candidate.endLine);
    if (document.getText(range) !== candidate.request.code) {
      void vscode.window.showWarningMessage(
        'VulnLens: the function changed while the rewrite was being generated. Run it again.',
      );
      return;
    }

    const edit = new vscode.WorkspaceEdit();
    edit.replace(document.uri, range, fix);
    if (!(await vscode.workspace.applyEdit(edit))) {
      void vscode.window.showWarningMessage('VulnLens: could not apply the rewrite.');
    }
  } catch (error) {
    const message = describeError(error);
    if (message.toLowerCase().includes('abort')) {
      output.appendLine('[vuln-lens] rewrite cancelled');
    } else {
      output.appendLine(`[vuln-lens] rewrite failed: ${message}`);
      void vscode.window.showWarningMessage(`VulnLens: rewrite failed — ${message}`);
    }
  } finally {
    updateStatusBar();
  }
}

function writeReport(): void {
  const document = vscode.window.activeTextEditor?.document;
  output.clear();

  if (!document || document.languageId !== LANGUAGE_ID) {
    output.appendLine('VulnLens: no active Python file.');
    output.show(true);
    return;
  }

  const state = documents.get(document.uri.toString());
  const findings = state?.findings ?? [];
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };

  output.appendLine('VulnLens report');
  output.appendLine(`File:    ${vscode.workspace.asRelativePath(document.uri)}`);
  output.appendLine(`AI mode: ${aiMode()}${state?.providerLabel ? ` (${state.providerLabel})` : ''}`);
  output.appendLine(
    `Local:   ${localModelConfig().enabled ? localModelConfig().directory || '(no path set)' : 'off'}`,
  );
  output.appendLine(`Rules:   6 CWEs`);
  output.appendLine('');

  if (findings.length === 0) {
    output.appendLine('No findings.');
    output.show(true);
    return;
  }

  for (const finding of findings) {
    if (!finding.dismissed) counts[finding.severity] += 1;
  }

  const dismissed = findings.filter((finding) => finding.dismissed).length;
  output.appendLine(
    `Summary: ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low` +
      (dismissed > 0 ? `, ${dismissed} dismissed by AI` : ''),
  );
  output.appendLine('');

  for (const finding of findings) {
    const marker = finding.dismissed ? '[dismissed]' : `[${finding.severity}]`;
    output.appendLine(
      `line ${String(finding.line + 1).padStart(4)}  ${marker.padEnd(12)} ${finding.cwe ?? '-'}  ${finding.title}`,
    );
    output.appendLine(`            ${finding.message}`);
    if (finding.fix) output.appendLine('            suggested fix available (Quick Fix)');
    output.appendLine('');
  }

  const order = findings
    .filter((finding) => !finding.dismissed)
    .sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]);
  if (order.length > 0) {
    output.appendLine(`Highest severity: ${order[0].severity} at line ${order[0].line + 1}`);
  }

  output.show(true);
}

function warnOnce(key: string, message: string, action: string): void {
  output.appendLine(`[vuln-lens] ${message}`);
  if (warned.has(key)) return;
  warned.add(key);

  void vscode.window.showWarningMessage(message, action).then((choice) => {
    if (!choice) return;
    if (choice === 'Check Provider') void checkProvider();
    else if (choice === 'Show Log') output.show(true);
    else if (choice === 'Open Settings') {
      void vscode.commands.executeCommand(
        'workbench.action.openSettings',
        'vulnLens.localModel',
      );
    }
  });
}
