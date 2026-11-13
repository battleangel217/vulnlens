import * as vscode from 'vscode';
import type { PresentedFinding } from './present';

export type FindingsLookup = (uri: vscode.Uri) => readonly PresentedFinding[];

/** A fix must look like a whole definition, never a bare fragment. */
const DEFINITION_RE = /\b(?:def|class)\s+[A-Za-z_]\w*/;

function chunkRange(document: vscode.TextDocument, finding: PresentedFinding): vscode.Range {
  const lastLine = Math.max(0, document.lineCount - 1);
  const start = Math.min(finding.chunkStartLine, lastLine);
  const end = Math.min(Math.max(finding.chunkEndLine, start), lastLine);
  return new vscode.Range(start, 0, end, document.lineAt(end).text.length);
}

function matchFinding(
  findings: readonly PresentedFinding[],
  diagnostic: vscode.Diagnostic,
): PresentedFinding | undefined {
  const code = String(diagnostic.code ?? 'vuln-guard');
  return findings.find(
    (finding) =>
      finding.line === diagnostic.range.start.line && (finding.cwe ?? 'vuln-guard') === code,
  );
}

function isFixApplicable(
  document: vscode.TextDocument,
  finding: PresentedFinding,
): boolean {
  if (!finding.fix) return false;
  if (!DEFINITION_RE.test(finding.fix)) return false;
  // Refuse to replace code that changed since the analysis ran.
  return document.getText(chunkRange(document, finding)) === finding.chunkCode;
}

export function registerCodeActions(
  getFindings: FindingsLookup,
  reanalyzeCommand: string,
): vscode.Disposable {
  return vscode.languages.registerCodeActionsProvider(
    'python',
    {
      provideCodeActions(document, _range, context) {
        const actions: vscode.CodeAction[] = [];
        const findings = getFindings(document.uri);
        const handled = new Set<PresentedFinding>();

        for (const diagnostic of context.diagnostics) {
          if (diagnostic.source !== 'vuln-guard') continue;
          const finding = matchFinding(findings, diagnostic);
          if (!finding || handled.has(finding)) continue;
          handled.add(finding);

          if (isFixApplicable(document, finding)) {
            const action = new vscode.CodeAction(
              'VulnGuard: Apply suggested fix',
              vscode.CodeActionKind.QuickFix,
            );
            action.isPreferred = true;
            action.diagnostics = [diagnostic];
            const edit = new vscode.WorkspaceEdit();
            edit.replace(document.uri, chunkRange(document, finding), finding.fix!);
            action.edit = edit;
            actions.push(action);
          }

          const line = document.lineAt(Math.min(finding.line, document.lineCount - 1));
          if (!line.text.includes('vuln-ignore')) {
            const action = new vscode.CodeAction(
              'VulnGuard: Ignore this finding',
              vscode.CodeActionKind.QuickFix,
            );
            action.diagnostics = [diagnostic];
            const edit = new vscode.WorkspaceEdit();
            const suffix = `  # vuln-ignore${finding.cwe ? `: ${finding.cwe}` : ''}`;
            edit.insert(document.uri, line.range.end, suffix);
            action.edit = edit;
            actions.push(action);
          }

          const reanalyze = new vscode.CodeAction(
            'VulnGuard: Re-analyze this file with AI',
            vscode.CodeActionKind.QuickFix,
          );
          reanalyze.diagnostics = [diagnostic];
          reanalyze.command = {
            command: reanalyzeCommand,
            title: 'Re-analyze with AI',
          };
          actions.push(reanalyze);
        }

        return actions;
      },
    },
    { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] },
  );
}
