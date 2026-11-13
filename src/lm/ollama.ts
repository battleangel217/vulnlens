import { converseForVerdict } from './complete';
import type { ChatMessage } from './prompt';
import { ProviderError } from './types';
import type { AnalyzeRequest, LlmProvider, ProviderStatus } from './types';
import type { LlmVerdict } from './verdict';

export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface OllamaOptions {
  readonly baseUrl: string;
  readonly model: string;
  readonly fetchImpl?: FetchLike;
}

interface TagsResponse {
  models?: { name?: string; model?: string }[];
}

function trimBase(baseUrl: string): string {
  return baseUrl.replace(/\/+$/, '');
}

/**
 * Local Ollama backend. Nothing leaves the machine, so this is the default
 * suggestion for anyone who does not want to paste code into an API.
 */
export class OllamaProvider implements LlmProvider {
  readonly id = 'ollama' as const;
  readonly label = 'Ollama';
  readonly model: string;

  private readonly baseUrl: string;
  private readonly doFetch: FetchLike;

  constructor(options: OllamaOptions) {
    this.baseUrl = trimBase(options.baseUrl);
    this.model = options.model;
    this.doFetch = options.fetchImpl ?? ((input, init) => fetch(input, init));
  }

  async status(): Promise<ProviderStatus> {
    try {
      const response = await this.doFetch(`${this.baseUrl}/api/tags`, {
        signal: AbortSignal.timeout(1500),
      });

      if (!response.ok) {
        return {
          available: false,
          label: this.label,
          model: this.model,
          detail: `Ollama answered HTTP ${response.status} at ${this.baseUrl}`,
        };
      }

      const body = (await response.json()) as TagsResponse;
      const names = (body.models ?? [])
        .flatMap((entry) => [entry.name, entry.model])
        .filter((name): name is string => typeof name === 'string');

      const installed = names.some(
        (name) => name === this.model || name.startsWith(`${this.model}:`),
      );

      return {
        available: installed,
        label: this.label,
        model: this.model,
        detail: installed
          ? `Ollama ready at ${this.baseUrl}`
          : `Ollama is running but "${this.model}" is not installed. Run: ollama pull ${this.model}`,
      };
    } catch {
      return {
        available: false,
        label: this.label,
        model: this.model,
        detail: `Ollama is not reachable at ${this.baseUrl}. Start it with: ollama serve`,
      };
    }
  }

  async analyze(request: AnalyzeRequest, signal: AbortSignal): Promise<LlmVerdict> {
    const complete = async (messages: readonly ChatMessage[], inner: AbortSignal): Promise<string> => {
      let response: Response;
      try {
        response = await this.doFetch(`${this.baseUrl}/api/chat`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          signal: inner,
          body: JSON.stringify({
            model: this.model,
            stream: false,
            format: 'json',
            options: { temperature: 0 },
            messages,
          }),
        });
      } catch (error) {
        if (inner.aborted) throw new ProviderError('request aborted', 'aborted');
        throw new ProviderError(`could not reach Ollama at ${this.baseUrl}`, 'unavailable');
      }

      if (!response.ok) {
        throw new ProviderError(
          `Ollama returned HTTP ${response.status}${response.status === 404 ? ` (model "${this.model}" missing?)` : ''}`,
          response.status === 429 ? 'rate-limit' : 'http',
          response.status,
        );
      }

      const body = (await response.json()) as { message?: { content?: string } };
      const content = body.message?.content;
      if (typeof content !== 'string' || content.length === 0) {
        throw new ProviderError('Ollama returned an empty message', 'invalid-response');
      }
      return content;
    };

    return converseForVerdict(request, complete, signal);
  }
}
