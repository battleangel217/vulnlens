import { converseForVerdict } from './complete';
import type { ChatMessage } from './prompt';
import { ProviderError } from './types';
import type { AnalyzeRequest, LlmProvider, ProviderStatus } from './types';
import type { LlmVerdict } from './verdict';
import type { FetchLike } from './ollama';

export interface OpenAiOptions {
  readonly baseUrl: string;
  readonly model: string;
  readonly apiKey: string;
  readonly fetchImpl?: FetchLike;
}

function trimBase(baseUrl: string): string {
  return baseUrl.replace(/\/+$/, '');
}

/**
 * Any OpenAI-compatible chat-completions endpoint: OpenAI, Groq, Together,
 * OpenRouter, LM Studio, llama.cpp's server. Keeping this generic means the
 * extension is not coupled to one vendor's pricing or availability.
 */
export class OpenAiCompatibleProvider implements LlmProvider {
  readonly id = 'byok' as const;
  readonly label = 'OpenAI-compatible';
  readonly model: string;

  private readonly baseUrl: string;
  private readonly apiKey: string;
  private readonly doFetch: FetchLike;

  constructor(options: OpenAiOptions) {
    this.baseUrl = trimBase(options.baseUrl);
    this.model = options.model;
    this.apiKey = options.apiKey;
    this.doFetch = options.fetchImpl ?? ((input, init) => fetch(input, init));
  }

  async status(): Promise<ProviderStatus> {
    return {
      available: this.apiKey.length > 0,
      label: this.label,
      model: this.model,
      detail: this.apiKey
        ? `Using ${this.model} via ${this.baseUrl}`
        : 'No API key stored. Run: VulnLens: Set API Key',
    };
  }

  async analyze(request: AnalyzeRequest, signal: AbortSignal): Promise<LlmVerdict> {
    let jsonMode = true;

    const complete = async (messages: readonly ChatMessage[], inner: AbortSignal): Promise<string> => {
      let response: Response;
      try {
        response = await this.doFetch(`${this.baseUrl}/chat/completions`, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            authorization: `Bearer ${this.apiKey}`,
          },
          signal: inner,
          body: JSON.stringify({
            model: this.model,
            temperature: 0,
            ...(jsonMode ? { response_format: { type: 'json_object' } } : {}),
            messages,
          }),
        });
      } catch (error) {
        if (inner.aborted) throw new ProviderError('request aborted', 'aborted');
        throw new ProviderError(`could not reach ${this.baseUrl}`, 'unavailable');
      }

      // Some compatible servers reject `response_format`. Retry once without it.
      if (response.status === 400 && jsonMode) {
        jsonMode = false;
        return complete(messages, inner);
      }

      if (!response.ok) {
        const hint =
          response.status === 401
            ? ' (check the stored API key)'
            : response.status === 429
              ? ' (rate limited)'
              : '';
        throw new ProviderError(
          `${this.baseUrl} returned HTTP ${response.status}${hint}`,
          response.status === 429 ? 'rate-limit' : 'http',
          response.status,
        );
      }

      const body = (await response.json()) as {
        choices?: { message?: { content?: string } }[];
      };
      const content = body.choices?.[0]?.message?.content;
      if (typeof content !== 'string' || content.length === 0) {
        throw new ProviderError('endpoint returned an empty message', 'invalid-response');
      }
      return content;
    };

    return converseForVerdict(request, complete, signal);
  }
}
