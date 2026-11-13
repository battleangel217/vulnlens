import * as vscode from 'vscode';
import type { PresentedFinding } from './present';

export type FindingsLookup = (uri: vscode.Uri) => readonly PresentedFinding[];

function rangeForLine(document: vscode.TextDocument, line: number): vscode.Range {
  const safeLine = Math.min(Math.max(line, 0), Math.max(0, document.lineCount - 1));
  const text = document.lineAt(safeLine).text;
  const start = text.length - text.trimStart().length;
  return new vscode.Range(safeLine, start, safeLine, text.length);
}

function toMarkdown(finding: PresentedFinding): vscode.MarkdownString {
  const markdown = new vscode.MarkdownString();
  markdown.isTrusted = false;
  markdown.supportHtml = false;

  const heading = `**${finding.title}**${finding.cwe ? ` · ${finding.cwe}` : ''}`;
  const confidence =
    finding.confidence !== undefined ? ` · ${Math.round(finding.confidence * 100)}% confidence` : '';
  const origin =
    finding.source === 'rules+ai'
      ? `$(verified-filled) ${finding.provider ?? 'AI verified'}`
      : finding.source === 'ai'
        ? `$(sparkle) ${finding.provider ?? 'AI'}`
        : '$(shield) rule match only';

  markdown.appendMarkdown(`${heading}\n\n`);

  if (finding.dismissed) {
    markdown.appendMarkdown(
      `$(pass-filled) **Likely a false positive** — the model rejected this rule match.\n\n`,
    );
  } else {
    const icon = finding.severity === 'medium' || finding.severity === 'low' ? '$(warning)' : '$(error)';
    markdown.appendMarkdown(`${icon} ${finding.severity}${confidence} · ${origin}\n\n`);
  }

  markdown.appendMarkdown(`${finding.reason ?? finding.message}\n\n`);

  if (finding.fix) {
    markdown.appendMarkdown(`$(wrench) **Suggested fix**\n\n`);
    markdown.appendCodeblock(finding.fix, 'python');
    markdown.appendMarkdown('\n');
  }

  const footer = [
    finding.latencyMs !== undefined ? `${finding.latencyMs}ms` : undefined,
    finding.source === 'rules' ? 'no AI verification' : 'AI output — verify before applying',
  ]
    .filter(Boolean)
    .join(' · ');

  markdown.appendMarkdown(`\n---\n_${footer}_`);
  return markdown;
}

export function registerHoverProvider(getFindings: FindingsLookup): vscode.Disposable {
  return vscode.languages.registerHoverProvider('python', {
    provideHover(document, position) {
      const findings = getFindings(document.uri).filter(
        (finding) => position.line >= finding.line && position.line <= finding.endLine,
      );
      if (findings.length === 0) return undefined;

      return new vscode.Hover(
        findings.map(toMarkdown),
        rangeForLine(document, findings[0].line),
      );
    },
  });
}
