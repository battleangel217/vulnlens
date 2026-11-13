import { describe, expect, it } from 'vitest';
import { analyzeCandidates, cacheKey, type Candidate } from '../src/lm/analyzer';
import type { AnalyzeRequest, LlmProvider, ProviderStatus } from '../src/lm/types';
import type { LlmVerdict } from '../src/lm/verdict';

function verdict(overrides: Partial<LlmVerdict> = {}): LlmVerdict {
  return {
    verdict: 'vulnerable',
    cwe: 'CWE-89',
    severity: 'high',
    confidence: 0.8,
    line: 1,
    reason: 'reason',
    fix: null,
    ...overrides,
  };
}

function candidate(index: number): Candidate {
  return {
    key: `k${index}`,
    startLine: index * 10,
    endLine: index * 10 + 5,
    request: {
      functionName: `fn${index}`,
      code: `def fn${index}():\n    return ${index}`,
      ruleHints: [],
    },
  };
}

class FakeProvider implements LlmProvider {
  readonly id = 'ollama' as const;
  readonly label = 'Fake';
  readonly model = 'fake-1';

  calls = 0;
  active = 0;
  maxActive = 0;

  constructor(
    private readonly behavior: (signal: AbortSignal) => Promise<LlmVerdict> = async () =>
      verdict(),
  ) {}

  async status(): Promise<ProviderStatus> {
    return { available: true, label: this.label, model: this.model, detail: 'ok' };
  }

  async analyze(_request: AnalyzeRequest, signal: AbortSignal): Promise<LlmVerdict> {
    this.calls += 1;
    this.active += 1;
    this.maxActive = Math.max(this.maxActive, this.active);
    try {
      return await this.behavior(signal);
    } finally {
      this.active -= 1;
    }
  }
}

describe('cacheKey', () => {
  it('is stable for identical input', () => {
    const a = candidate(0).request;
    const b = { ...a };
    expect(cacheKey('ollama', 'm1', a)).toBe(cacheKey('ollama', 'm1', b));
  });

  it('changes with provider, model, code, or hints', () => {
    const base = candidate(0).request;
    const key = cacheKey('ollama', 'm1', base);
    expect(cacheKey('byok', 'm1', base)).not.toBe(key);
    expect(cacheKey('ollama', 'm2', base)).not.toBe(key);
    expect(cacheKey('ollama', 'm1', { ...base, code: `${base.code} ` })).not.toBe(key);
    expect(
      cacheKey('ollama', 'm1', {
        ...base,
        ruleHints: [{ cwe: 'CWE-89', title: 't', severity: 'high', line: 1, message: 'm' }],
      }),
    ).not.toBe(key);
  });
});

describe('analyzeCandidates', () => {
  it('returns an empty list for no candidates', async () => {
    const provider = new FakeProvider();
    await expect(analyzeCandidates([], provider)).resolves.toEqual([]);
    expect(provider.calls).toBe(0);
  });

  it('reuses the cache instead of re-requesting', async () => {
    const provider = new FakeProvider();
    const cache = new Map<string, LlmVerdict>();
    const candidates = [candidate(0)];

    const first = await analyzeCandidates(candidates, provider, { cache });
    expect(first[0].cached).toBe(false);

    // Same request text, different chunk position: still a cache hit.
    const moved = { ...candidate(0), key: 'moved', startLine: 100, endLine: 105 };
    const second = await analyzeCandidates([moved], provider, { cache });

    expect(provider.calls).toBe(1);
    expect(second[0].cached).toBe(true);
    expect(second[0].latencyMs).toBe(0);
  });

  it('never exceeds the concurrency limit', async () => {
    const provider = new FakeProvider(
      async () => new Promise((resolve) => setTimeout(() => resolve(verdict()), 10)),
    );
    const candidates = Array.from({ length: 6 }, (_, index) => candidate(index));

    const results = await analyzeCandidates(candidates, provider, { concurrency: 2 });
    expect(results).toHaveLength(6);
    expect(provider.maxActive).toBeLessThanOrEqual(2);
  });

  it('reports a timeout without failing the run', async () => {
    const errors: string[] = [];
    const provider = new FakeProvider(
      (signal) =>
        new Promise((_resolve, reject) => {
          signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
        }),
    );

    const results = await analyzeCandidates([candidate(0)], provider, {
      timeoutMs: 20,
      onError: (failed) => errors.push(failed.key),
    });

    expect(results).toEqual([]);
    expect(errors).toEqual(['k0']);
  });

  it('stops immediately when the run is already aborted', async () => {
    const provider = new FakeProvider();
    const controller = new AbortController();
    controller.abort();

    const results = await analyzeCandidates([candidate(0)], provider, {
      signal: controller.signal,
    });

    expect(results).toEqual([]);
    expect(provider.calls).toBe(0);
  });

  it('reports progress once per settled candidate', async () => {
    const provider = new FakeProvider();
    const progress: number[] = [];
    const candidates = Array.from({ length: 3 }, (_, index) => candidate(index));

    await analyzeCandidates(candidates, provider, {
      concurrency: 1,
      onProgress: (completed) => progress.push(completed),
    });

    expect(progress).toEqual([1, 2, 3]);
  });
});
