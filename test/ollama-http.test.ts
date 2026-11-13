import { createServer, type IncomingMessage, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { OllamaProvider } from '../src/lm/ollama';
import type { AnalyzeRequest } from '../src/lm/types';
import { parseVerdict } from '../src/lm/verdict';

/**
 * End-to-end check over a real socket: the provider uses the global `fetch`
 * against a stub Ollama server. This is the closest we can get to the real
 * thing without requiring Ollama to be installed on the machine running CI.
 */

const request: AnalyzeRequest = {
  functionName: 'ping',
  code: 'def ping():\n    os.system("ping " + host)',
  ruleHints: [
    { cwe: 'CWE-78', title: 'OS command injection', severity: 'high', line: 2, message: 'interpolated' },
  ],
};

const verdict = {
  verdict: 'vulnerable',
  cwe: 'CWE-78',
  severity: 'high',
  confidence: 0.93,
  line: 2,
  reason: 'host is interpolated into a shell command',
  fix: null,
};

function readBody(request_: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = '';
    request_.on('data', (chunk) => (body += chunk));
    request_.on('end', () => resolve(body));
    request_.on('error', reject);
  });
}

let server: Server | undefined;

async function startServer(
  handler: (path: string, body: string) => unknown,
): Promise<{ url: string; paths: string[]; bodies: string[] }> {
  const paths: string[] = [];
  const bodies: string[] = [];

  server = createServer(async (incoming, response) => {
    const path = incoming.url ?? '/';
    const body = await readBody(incoming);
    paths.push(path);
    bodies.push(body);
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify(handler(path, body)));
  });

  await new Promise<void>((resolve) => server!.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return { url: `http://127.0.0.1:${port}`, paths, bodies };
}

afterEach(async () => {
  if (!server) return;
  await new Promise<void>((resolve, reject) =>
    server!.close((error) => (error ? reject(error) : resolve())),
  );
  server = undefined;
});

describe('OllamaProvider over HTTP', () => {
  it('discovers the model and returns a parsed verdict', async () => {
    const { url, paths, bodies } = await startServer((path) => {
      if (path === '/api/tags') {
        return { models: [{ name: 'qwen2.5-coder:7b', model: 'qwen2.5-coder:7b' }] };
      }
      return { message: { role: 'assistant', content: JSON.stringify(verdict) } };
    });

    const provider = new OllamaProvider({ baseUrl: url, model: 'qwen2.5-coder:7b' });

    const status = await provider.status();
    expect(status.available).toBe(true);
    expect(status.detail).toContain(url);

    const result = await provider.analyze(request, new AbortController().signal);
    expect(parseVerdict(JSON.stringify(result)).ok).toBe(true);
    expect(result.cwe).toBe('CWE-78');
    expect(result.confidence).toBeCloseTo(0.93);

    expect(paths).toEqual(['/api/tags', '/api/chat']);
    const chatBody = JSON.parse(bodies[1]);
    expect(chatBody.model).toBe('qwen2.5-coder:7b');
    expect(chatBody.messages).toHaveLength(2);
    expect(chatBody.messages[1].content).toContain('os.system');
  });

  it('recovers when the model wraps its reply in prose', async () => {
    let chatCalls = 0;
    const { url } = await startServer((path) => {
      if (path === '/api/tags') return { models: [{ name: 'm:latest' }] };
      chatCalls += 1;
      return {
        message: {
          content:
            chatCalls === 1
              ? 'Analysis: this is vulnerable because host is user controlled.'
              : `Here you go: ${JSON.stringify(verdict)}`,
        },
      };
    });

    const provider = new OllamaProvider({ baseUrl: url, model: 'm' });
    const result = await provider.analyze(request, new AbortController().signal);

    expect(result.verdict).toBe('vulnerable');
    expect(chatCalls).toBe(2);
  });

  it('surfaces a missing model as an actionable status', async () => {
    const { url } = await startServer(() => ({ models: [{ name: 'other:latest' }] }));
    const provider = new OllamaProvider({ baseUrl: url, model: 'qwen2.5-coder:7b' });

    const status = await provider.status();
    expect(status.available).toBe(false);
    expect(status.detail).toContain('ollama pull qwen2.5-coder:7b');
  });
});
