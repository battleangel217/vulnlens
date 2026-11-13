import * as vscode from 'vscode';
import { scanPython } from './scan/scanner';
import type { RuleHit, Severity } from './types';

const LANGUAGE_ID = 'python';
const MAX_FILE_BYTES = 2 * 1024 * 1024;

let diagnostics: vscode.DiagnosticCollection;
let statusBar: vscode.StatusBarItem;
let output: vscode.OutputChannel;

/** Finding count per document URI, used by the status bar item. */
const counts = new Map<string, number>();

export function activate(context: vscode.ExtensionContext): void {
  diagnostics = vscode.languages.createDiagnosticCollection('vuln-guard');
  output = vscode.window.createOutputChannel('VulnGuard');
  statusBar = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  statusBar.command = 'vulnGuard.scanFile';
  statusBar.show();

  context.subscriptions.push(
    diagnostics,
    output,
    statusBar,

    vscode.commands.registerCommand('vulnGuard.scanFile', () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        void vscode.window.showInformationMessage('VulnGuard: open a Python file first.');
        return;
      }
      const count = scanDocument(editor.document, true);
      vscode.window.setStatusBarMessage(
        count === 0 ? 'VulnGuard: no findings' : `VulnGuard: ${count} finding(s)`,
        4000,
      );
    }),

    vscode.commands.registerCommand('vulnGuard.clearDiagnostics', () => {
      diagnostics.clear();
      counts.clear();
      updateStatusBar();
      output.appendLine('[vuln-guard] diagnostics cleared');
    }),

    vscode.workspace.onDidOpenTextDocument((document) => {
      if (config().get<boolean>('scanOnOpen', true)) scanDocument(document);
    }),

    vscode.workspace.onDidSaveTextDocument((document) => {
      if (config().get<boolean>('scanOnSave', true)) scanDocument(document);
    }),

    vscode.workspace.onDidCloseTextDocument((document) => {
      diagnostics.delete(document.uri);
      counts.delete(document.uri.toString());
      updateStatusBar();
    }),

    vscode.workspace.onDidChangeConfiguration((event) => {
      if (!event.affectsConfiguration('vulnGuard')) return;
      for (const document of vscode.workspace.textDocuments) scanDocument(document);
      updateStatusBar();
    }),

    vscode.window.onDidChangeActiveTextEditor(() => updateStatusBar()),
  );

  for (const document of vscode.workspace.textDocuments) {
    if (config().get<boolean>('scanOnOpen', true)) scanDocument(document);
  }

  updateStatusBar();
  output.appendLine('[vuln-guard] activated (rules: python, 6 CWEs)');
}

export function deactivate(): void {
  diagnostics?.clear();
  counts.clear();
}

function config(): vscode.WorkspaceConfiguration {
  return vscode.workspace.getConfiguration('vulnGuard');
}

/** Returns the number of findings, or -1 when the document was skipped. */
function scanDocument(document: vscode.TextDocument, announce = false): number {
  if (document.languageId !== LANGUAGE_ID) return -1;

  if (!config().get<boolean>('enable', true)) {
    diagnostics.delete(document.uri);
    counts.delete(document.uri.toString());
    return 0;
  }

  const key = document.uri.toString();
  const source = document.getText();

  if (Buffer.byteLength(source, 'utf8') > MAX_FILE_BYTES) {
    output.appendLine(`[vuln-guard] skipped ${vscode.workspace.asRelativePath(document.uri)}: larger than ${MAX_FILE_BYTES} bytes`);
    if (announce) void vscode.window.showWarningMessage('VulnGuard: file is too large to scan.');
    return -1;
  }

  const minSeverity = config().get<Severity>('minSeverity', 'low');
  const startedAt = Date.now();
  const findings = scanPython(source, { minSeverity });
  const elapsed = Date.now() - startedAt;

  diagnostics.set(document.uri, findings.map((finding) => toDiagnostic(document, finding)));
  counts.set(key, findings.length);
  updateStatusBar();

  output.appendLine(
    `[vuln-guard] ${vscode.workspace.asRelativePath(document.uri)}: ${findings.length} finding(s) in ${elapsed}ms`,
  );
  for (const finding of findings) {
    output.appendLine(
      `  ${finding.cwe} ${finding.severity.padEnd(8)} line ${finding.line + 1}: ${finding.title}`,
    );
  }

  return findings.length;
}

function toDiagnostic(document: vscode.TextDocument, finding: RuleHit): vscode.Diagnostic {
  const lastLine = Math.max(0, document.lineCount - 1);
  const startLine = Math.min(finding.line, lastLine);
  const endLine = Math.min(Math.max(finding.endLine, finding.line), lastLine);

  const startText = document.lineAt(startLine).text;
  const endText = document.lineAt(endLine).text;
  const startColumn = startText.length - startText.trimStart().length;

  const range = new vscode.Range(startLine, startColumn, endLine, endText.length);
  const diagnostic = new vscode.Diagnostic(
    range,
    `${finding.title} (${finding.cwe}). ${finding.message}`,
    diagnosticSeverity(finding.severity),
  );

  diagnostic.source = 'vuln-guard';
  diagnostic.code = finding.cwe;
  return diagnostic;
}

function diagnosticSeverity(severity: Severity): vscode.DiagnosticSeverity {
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

  const count = counts.get(document.uri.toString()) ?? 0;
  statusBar.text = count === 0 ? '$(shield) VulnGuard: clean' : `$(shield) VulnGuard: ${count}`;
  statusBar.tooltip = 'VulnGuard: click to rescan the current file';
  statusBar.backgroundColor =
    count > 0 ? new vscode.ThemeColor('statusBarItem.warningBackground') : undefined;
}
