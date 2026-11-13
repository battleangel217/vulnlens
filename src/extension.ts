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
import type { LlmVerdict } from './lm/verdict';
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
  diagnostics = vscode.languages.createDiagnosticCollection('vuln-guard');
  output = vscode.window.createOutputChannel('VulnGuard');
  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBar.command = 'vulnGuard.scanFile';
  statusBar.show();

  const getFindings = (uri: vscode.Uri): readonly PresentedFinding[] =>
    documents.get(uri.toString())?.findings ?? [];

  context.subscriptions.push(
    diagnostics,
    output,
    statusBar,
    registerHoverProvider(getFindings),
    registerCodeActions(getFindings, 'vulnGuard.analyzeFile'),

    vscode.commands.registerCommand('vulnGuard.scanFile', () =>
      scanActive({ announce: true }),
    ),

    vscode.commands.registerCommand('vulnGuard.analyzeFile', () =>
      scanActive({ announce: true, forceAi: true, allowPrompt: true }),
    ),

    vscode.commands.registerCommand('vulnGuard.clearDiagnostics', () => {
      for (const state of documents.values()) state.abort?.abort();
      documents.clear();
      diagnostics.clear();
      updateStatusBar();
      output.appendLine('[vuln-guard] diagnostics cleared');
    }),

    vscode.commands.registerCommand('vulnGuard.setApiKey', () => setApiKey()),

    vscode.commands.registerCommand('vulnGuard.clearApiKey', async () => {
      await context.secrets.delete(API_KEY_SECRET);
      warned.clear();
      void vscode.window.showInformationMessage('VulnGuard: stored API key removed.');
    }),

    vscode.commands.registerCommand('vulnGuard.checkProvider', () => checkProvider()),

    vscode.commands.registerCommand('vulnGuard.showReport', () => writeReport()),

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
      if (!event.affectsConfiguration('vulnGuard')) return;
      warned.clear();
      resetCopilotInstance();
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
  output.appendLine('[vuln-guard] activated (6 rules, AI mode: ' + aiMode() + ')');
}

export function deactivate(): void {
  for (const state of documents.values()) state.abort?.abort();
  documents.clear();
  diagnostics?.clear();
}

function config(): vscode.WorkspaceConfiguration {
  return vscode.workspace.getConfiguration('vulnGuard');
}

function scanActive(options: Parameters<typeof scanDocument>[1]): void {
  const editor = vscode.window.activeTextEditor;
  if (!editor) {
    void vscode.window.showInformationMessage('VulnGuard: open a Python file first.');
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
    output.appendLine(`[vuln-guard] skipped ${vscode.workspace.asRelativePath(document.uri)}: file too large`);
    if (options.announce) void vscode.window.showWarningMessage('VulnGuard: file is too large to scan.');
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
    `[vuln-guard] ${vscode.workspace.asRelativePath(document.uri)}: ${hitList.length} rule finding(s) in ${Date.now() - startedAt}ms`,
  );

  const mode = aiMode();
  const wantAi =
    mode !== 'off' && (options.forceAi === true || config().get<boolean>('ai.analyzeOnSave', true));

  if (!wantAi) {
    if (options.announce) {
      void vscode.window.showInformationMessage(
        hitList.length === 0
          ? 'VulnGuard: no findings.'
          : `VulnGuard: ${hitList.length} finding(s). AI verification is ${mode === 'off' ? 'off' : 'disabled for saves'}.`,
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
        ? 'VulnGuard: no Copilot model is available yet. Run "VulnGuard: Analyze Current File with AI" to request access.'
        : 'VulnGuard: no AI provider is configured. Run "VulnGuard: Check AI Provider".',
      'Check Provider',
    );
    return;
  }

  const status = await provider.status();
  if (!status.available) {
    warnOnce(`status:${status.detail}`, `VulnGuard: ${status.detail}`, 'Check Provider');
    return;
  }

  const maxChunks = config().get<number>('ai.maxChunks', 40);
  const candidates = buildCandidates({
    chunks,
    hits: hitList,
    deep: options.deep ?? config().get<boolean>('ai.deepScan', false),
    max: maxChunks,
  });

  if (candidates.length === 0) return;

  state.providerLabel = `${provider.label} · ${provider.model}`;
  statusBar.text = `$(sync~spin) VulnGuard: 0/${candidates.length}`;
  output.appendLine(
    `[vuln-guard] analysing ${candidates.length} function(s) with ${provider.id}/${provider.model}`,
  );

  let failures = 0;
  const results = await analyzeCandidates(candidates, provider, {
    concurrency: config().get<number>('ai.concurrency', 2),
    timeoutMs: config().get<number>('ai.timeoutMs', 25_000),
    signal: state.abort?.signal,
    cache: verdictCache,
    onProgress: (done, total) => {
      statusBar.text = `$(sync~spin) VulnGuard: ${done}/${total}`;
    },
    onError: (candidate, error) => {
      failures += 1;
      output.appendLine(
        `[vuln-guard] ${candidate.request.functionName}: ${describeError(error)}`,
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
      `VulnGuard: ${failures} of ${candidates.length} AI request(s) failed. See the VulnGuard output log.`,
      'Show Log',
    );
  } else if (budget > 0) {
    output.appendLine(`[vuln-guard] ${budget} function(s) were not analysed`);
  }

  if (options.announce) {
    const active = state.findings.filter((finding) => !finding.dismissed).length;
    void vscode.window.showInformationMessage(
      `VulnGuard: ${active} finding(s) after AI verification (${results.length} function(s) analysed).`,
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
  diagnostic.source = 'vuln-guard';
  diagnostic.code = finding.cwe ?? 'vuln-guard';
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
    statusBar.text = '$(shield) VulnGuard';
    statusBar.tooltip = 'VulnGuard: no Python file active';
    statusBar.backgroundColor = undefined;
    return;
  }

  const state = documents.get(document.uri.toString());
  const findings = state?.findings ?? [];
  const active = findings.filter((finding) => !finding.dismissed).length;
  const dismissed = findings.length - active;

  statusBar.text =
    active > 0
      ? `$(shield) VulnGuard: ${active}`
      : dismissed > 0
        ? `$(shield) VulnGuard: clean (${dismissed} dismissed)`
        : '$(shield) VulnGuard: clean';

  statusBar.tooltip = [
    'VulnGuard',
    state?.providerLabel ? `AI: ${state.providerLabel}` : `AI mode: ${aiMode()}`,
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
    title: 'VulnGuard: API key',
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
    'VulnGuard: API key stored.',
    aiMode() === 'byok' ? 'Check Provider' : 'Switch to BYOK mode',
  );
  if (choice === 'Switch to BYOK mode') {
    await vscode.workspace
      .getConfiguration('vulnGuard')
      .update('ai.mode', 'byok', vscode.ConfigurationTarget.Global);
  } else if (choice === 'Check Provider') {
    await checkProvider();
  }
}

async function checkProvider(): Promise<void> {
  resetCopilotInstance();
  const status = await describeProvider(extensionContext.secrets);
  const summary = `${status.label}${status.model ? ` (${status.model})` : ''} — ${status.detail}`;

  output.appendLine(`[vuln-guard] provider: ${status.available ? 'ready' : 'unavailable'} · ${summary}`);

  if (status.available) {
    void vscode.window.showInformationMessage(`VulnGuard: ${summary}`);
    return;
  }

  const choice = await vscode.window.showWarningMessage(
    `VulnGuard: ${summary}`,
    aiMode() === 'byok' ? 'Set API Key' : 'Open Settings',
    'Show Log',
  );
  if (choice === 'Set API Key') await setApiKey();
  else if (choice === 'Show Log') output.show(true);
}

function writeReport(): void {
  const document = vscode.window.activeTextEditor?.document;
  output.clear();

  if (!document || document.languageId !== LANGUAGE_ID) {
    output.appendLine('VulnGuard: no active Python file.');
    output.show(true);
    return;
  }

  const state = documents.get(document.uri.toString());
  const findings = state?.findings ?? [];
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };

  output.appendLine('VulnGuard report');
  output.appendLine(`File:    ${vscode.workspace.asRelativePath(document.uri)}`);
  output.appendLine(`AI mode: ${aiMode()}${state?.providerLabel ? ` (${state.providerLabel})` : ''}`);
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
  output.appendLine(`[vuln-guard] ${message}`);
  if (warned.has(key)) return;
  warned.add(key);

  void vscode.window.showWarningMessage(message, action).then((choice) => {
    if (!choice) return;
    if (choice === 'Check Provider') void checkProvider();
    else if (choice === 'Show Log') output.show(true);
  });
}
