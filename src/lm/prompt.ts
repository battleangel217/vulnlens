import type { AnalyzeRequest, RuleHint } from './types';

export const SYSTEM_PROMPT = [
  'You are a Python application security reviewer. You decide whether a specific function is actually exploitable.',
  '',
  'Decision rules:',
  '1. Only call code vulnerable when untrusted input can reach a dangerous sink, or when a credential is literally embedded in the source.',
  '2. These are NOT vulnerabilities: SQL with bound parameters, subprocess calls that pass an argument list, yaml.safe_load / Loader=yaml.SafeLoader, json deserialization, credentials read from environment variables or a secret manager, SHA-256 or stronger hashing, AES-GCM or ChaCha20-Poly1305.',
  '3. If the linter hint below is a false positive, answer "safe" and say why in one sentence.',
  '4. Never invent line numbers. A line number must point at code that exists in the snippet.',
  '5. When a fix is possible, return a complete corrected function, not a fragment or a diff.',
  '',
  'Reply with exactly one JSON object and nothing else. No markdown fences, no commentary.',
].join('\n');

const OUTPUT_CONTRACT = [
  '{',
  '  "verdict": "vulnerable" | "safe",',
  '  "cwe": "CWE-89" | null,',
  '  "severity": "critical" | "high" | "medium" | "low" | null,',
  '  "confidence": 0.0 to 1.0,',
  '  "line": <1-based line inside the snippet, or null>,',
  '  "reason": "one or two sentences naming the data flow",',
  '  "fix": "<complete corrected function, or null>"',
  '}',
].join('\n');

function describeHint(hint: RuleHint): string {
  return `- ${hint.cwe} ${hint.title} (${hint.severity}) at snippet line ${hint.line}: ${hint.message}`;
}

export function buildPrompt(request: AnalyzeRequest): { system: string; user: string } {
  const hints =
    request.ruleHints.length > 0
      ? [
          'A deterministic linter reported the following. Confirm or reject each one:',
          ...request.ruleHints.map(describeHint),
        ].join('\n')
      : 'No deterministic rule matched this function. Look for anything genuinely exploitable; prefer "safe" when unsure.';

  const user = [
    `Function: ${request.functionName}`,
    '',
    hints,
    '',
    `Code (${request.code.split(/\r?\n/).length} lines, line 1 is the first line below):`,
    '```python',
    request.code,
    '```',
    '',
    'Return JSON matching this shape:',
    OUTPUT_CONTRACT,
  ].join('\n');

  return { system: SYSTEM_PROMPT, user };
}

export interface ChatMessage {
  readonly role: 'system' | 'user' | 'assistant';
  readonly content: string;
}

export function toMessages(request: AnalyzeRequest): ChatMessage[] {
  const { system, user } = buildPrompt(request);
  return [
    { role: 'system', content: system },
    { role: 'user', content: user },
  ];
}
