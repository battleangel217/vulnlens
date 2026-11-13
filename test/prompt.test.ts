import { describe, expect, it } from 'vitest';
import { buildPrompt, toMessages } from '../src/lm/prompt';
import type { AnalyzeRequest } from '../src/lm/types';

const request: AnalyzeRequest = {
  functionName: 'search',
  code: ['def search():', '    cursor.execute(f"SELECT * FROM t WHERE id = {uid}")'].join('\n'),
  ruleHints: [
    {
      cwe: 'CWE-89',
      title: 'SQL injection',
      severity: 'high',
      line: 2,
      message: 'Query is built from interpolated text.',
    },
  ],
};

describe('buildPrompt', () => {
  it('includes the function, the code and the rule hint', () => {
    const { user } = buildPrompt(request);
    expect(user).toContain('Function: search');
    expect(user).toContain('CWE-89 SQL injection');
    expect(user).toContain('snippet line 2');
    expect(user).toContain('cursor.execute');
    expect(user).toContain('line 1 is the first line below');
  });

  it('asks for JSON only', () => {
    const { system, user } = buildPrompt(request);
    expect(system).toContain('exactly one JSON object');
    expect(user).toContain('"verdict": "vulnerable" | "safe"');
  });

  it('tells the model what is not a vulnerability', () => {
    const { system } = buildPrompt(request);
    for (const phrase of ['bound parameters', 'argument list', 'yaml.safe_load', 'environment variables']) {
      expect(system).toContain(phrase);
    }
  });

  it('handles the no-hints case', () => {
    const { user } = buildPrompt({ ...request, ruleHints: [] });
    expect(user).toContain('No deterministic rule matched');
    expect(user).not.toContain('A deterministic linter reported');
  });
});

describe('toMessages', () => {
  it('puts instructions in a system message and code in a user message', () => {
    const messages = toMessages(request);
    expect(messages.map((message) => message.role)).toEqual(['system', 'user']);
    expect(messages[1].content).toContain('cursor.execute');
  });
});
