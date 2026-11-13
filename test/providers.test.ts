import { describe, expect, it } from 'vitest';
import { OllamaProvider, type FetchLike } from '../src/lm/ollama';
import { OpenAiCompatibleProvider } from '../src/lm/openai';
import { ProviderError } from '../src/lm/types';
import type { AnalyzeRequest } from '../src/lm/types';

const request: AnalyzeRequest = {
  functionName: 'search',
  code: 'def search():\n    cursor.execute(f"SELECT * FROM t WHERE id = {uid}")',
  ruleHints: [
    { cwe: 'CWE-89', title: 'SQL injection', severity: 'high', line: 2, message: 'interpolated' },
  ],
};

const valid = JSON.stringify({
  verdict: 'vulnerable',
  cwe: 'CWE-89',
  severity: 'high',
  confidence: 0.9,
  line: 2,
  reason: 'uid reaches the query',
  fix: 'def search():\n    pass',
});

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

interface Recorded {
  url: string;
  init?: RequestInit;
}

function stubFetch(handler: (call: Recorded) => Response): { fetchImpl: FetchLike; calls: Recorded[] } {
  const calls: Recorded[] = [];
  const fetchImpl: FetchLike = async (url, init) => {
    const call = { url, init };
    calls.push(call);
    return handler(call);
  };
  return { fetchImpl, calls };
}

describe('OllamaProvider', () => {
  it('reports ready when the configured model is installed', async () => {
    const { fetchImpl } = stubFetch(() =>
      jsonResponse({ models: [{ name: 'llama3:8b' }, { name: 'qwen2.5-coder:7b' }] }),
    );
    const provider = new OllamaProvider({
      baseUrl: 'http://127.0.0.1:11434/',
      model: 'qwen2.5-coder:7b',
      fetchImpl,
    });

    const status = await provider.status();
    expect(status.available).toBe(true);
    expect(status.detail).toContain('Ollama ready');
  });

  it('explains how to pull a missing model', async () => {
    const { fetchImpl } = stubFetch(() => jsonResponse({ models: [] }));
    const provider = new OllamaProvider({
      baseUrl: 'http://127.0.0.1:11434',
      model: 'qwen2.5-coder:7b',
      fetchImpl,
    });

    const status = await provider.status();
    expect(status.available).toBe(false);
    expect(status.detail).toContain('ollama pull qwen2.5-coder:7b');
  });

  it('explains how to start an unreachable server', async () => {
    const fetchImpl: FetchLike = async () => {
      throw new Error('ECONNREFUSED');
    };
    const provider = new OllamaProvider({
      baseUrl: 'http://127.0.0.1:11434',
      model: 'qwen2.5-coder:7b',
      fetchImpl,
    });

    const status = await provider.status();
    expect(status.available).toBe(false);
    expect(status.detail).toContain('ollama serve');
  });

  it('sends a non-streaming, temperature-0, json-formatted request', async () => {
    const { fetchImpl, calls } = stubFetch(() => jsonResponse({ message: { content: valid } }));
    const provider = new OllamaProvider({
      baseUrl: 'http://127.0.0.1:11434',
      model: 'qwen2.5-coder:7b',
      fetchImpl,
    });

    const verdict = await provider.analyze(request, new AbortController().signal);
    expect(verdict.verdict).toBe('vulnerable');
    expect(verdict.confidence).toBeCloseTo(0.9);

    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe('http://127.0.0.1:11434/api/chat');
    const body = JSON.parse(String(calls[0].init?.body));
    expect(body.stream).toBe(false);
    expect(body.format).toBe('json');
    expect(body.options.temperature).toBe(0);
    expect(body.messages[0].role).toBe('system');
  });

  it('retries once when the first reply is not JSON', async () => {
    let call = 0;
    const { fetchImpl, calls } = stubFetch(() => {
      call += 1;
      return jsonResponse({
        message: { content: call === 1 ? 'Here is my analysis: definitely bad!' : valid },
      });
    });
    const provider = new OllamaProvider({
      baseUrl: 'http://127.0.0.1:11434',
      model: 'qwen2.5-coder:7b',
      fetchImpl,
    });

    const verdict = await provider.analyze(request, new AbortController().signal);
    expect(verdict.verdict).toBe('vulnerable');
    expect(calls).toHaveLength(2);

    const retryBody = JSON.parse(String(calls[1].init?.body));
    expect(retryBody.messages.at(-1).content).toContain('could not be parsed');
  });

  it('fails clearly after two unparseable replies', async () => {
    const { fetchImpl } = stubFetch(() => jsonResponse({ message: { content: 'nope' } }));
    const provider = new OllamaProvider({
      baseUrl: 'http://127.0.0.1:11434',
      model: 'qwen2.5-coder:7b',
      fetchImpl,
    });

    await expect(provider.analyze(request, new AbortController().signal)).rejects.toMatchObject({
      name: 'ProviderError',
      kind: 'invalid-response',
    });
  });

  it('maps HTTP 429 to a rate-limit error', async () => {
    const { fetchImpl } = stubFetch(() => jsonResponse({ error: 'busy' }, 429));
    const provider = new OllamaProvider({
      baseUrl: 'http://127.0.0.1:11434',
      model: 'qwen2.5-coder:7b',
      fetchImpl,
    });

    await expect(provider.analyze(request, new AbortController().signal)).rejects.toBeInstanceOf(
      ProviderError,
    );
  });
});

describe('OpenAiCompatibleProvider', () => {
  const options = {
    baseUrl: 'https://api.example.com/v1',
    model: 'gpt-test',
    apiKey: 'sk-test-1234',
  };

  it('reports unavailable without a key', async () => {
    const provider = new OpenAiCompatibleProvider({ ...options, apiKey: '' });
    const status = await provider.status();
    expect(status.available).toBe(false);
    expect(status.detail).toContain('Set API Key');
  });

  it('sends the bearer token and asks for a JSON object', async () => {
    const { fetchImpl, calls } = stubFetch(() =>
      jsonResponse({ choices: [{ message: { content: valid } }] }),
    );
    const provider = new OpenAiCompatibleProvider({ ...options, fetchImpl });

    const verdict = await provider.analyze(request, new AbortController().signal);
    expect(verdict.cwe).toBe('CWE-89');

    expect(calls[0].url).toBe('https://api.example.com/v1/chat/completions');
    const headers = calls[0].init?.headers as Record<string, string>;
    expect(headers.authorization).toBe('Bearer sk-test-1234');

    const body = JSON.parse(String(calls[0].init?.body));
    expect(body.response_format).toEqual({ type: 'json_object' });
    expect(body.temperature).toBe(0);
  });

  it('retries without response_format when the server rejects it', async () => {
    let call = 0;
    const { fetchImpl, calls } = stubFetch(() => {
      call += 1;
      if (call === 1) return jsonResponse({ error: 'unknown field response_format' }, 400);
      return jsonResponse({ choices: [{ message: { content: valid } }] });
    });
    const provider = new OpenAiCompatibleProvider({ ...options, fetchImpl });

    const verdict = await provider.analyze(request, new AbortController().signal);
    expect(verdict.verdict).toBe('vulnerable');
    expect(calls).toHaveLength(2);
    expect(JSON.parse(String(calls[1].init?.body)).response_format).toBeUndefined();
  });

  it('points at the stored key on 401', async () => {
    const { fetchImpl } = stubFetch(() => jsonResponse({ error: 'nope' }, 401));
    const provider = new OpenAiCompatibleProvider({ ...options, fetchImpl });

    await expect(provider.analyze(request, new AbortController().signal)).rejects.toThrow(
      /check the stored API key/,
    );
  });
});
