import * as vscode from 'vscode';
import { buildPrompt } from './prompt';
import { parseVerdict } from './verdict';
import { ProviderError } from './types';
import type { AnalyzeRequest, LlmProvider, ProviderStatus } from './types';
import type { LlmVerdict } from './verdict';

/**
 * GitHub Copilot backend via the stable `vscode.lm` API.
 *
 * Two hard constraints shape this adapter:
 *  - `selectChatModels` can prompt for consent, so it must run from a user
 *    action. `create()` is therefore called lazily, never during activation.
 *  - Copilot does not accept system messages; instructions are folded into the
 *    first user message.
 */
export class CopilotProvider implements LlmProvider {
  readonly id = 'copilot' as const;
  readonly label = 'GitHub Copilot';

  private constructor(private readonly chat: vscode.LanguageModelChat) {}

  get model(): string {
    return this.chat.id;
  }

  static async create(): Promise<CopilotProvider | null> {
    try {
      const models = await vscode.lm.selectChatModels({ vendor: 'copilot' });
      const model = models[0];
      return model ? new CopilotProvider(model) : null;
    } catch {
      return null;
    }
  }

  async status(): Promise<ProviderStatus> {
    return {
      available: true,
      label: this.label,
      model: this.model,
      detail: `Using Copilot model ${this.chat.name ?? this.model}`,
    };
  }

  async analyze(request: AnalyzeRequest, signal: AbortSignal): Promise<LlmVerdict> {
    const { system, user } = buildPrompt(request);
    const source = new vscode.CancellationTokenSource();
    const onAbort = () => source.cancel();
    signal.addEventListener('abort', onAbort, { once: true });

    try {
      const response = await this.chat.sendRequest(
        [vscode.LanguageModelChatMessage.User(`${system}\n\n${user}`)],
        {},
        source.token,
      );

      let text = '';
      for await (const fragment of response.text) text += fragment;

      const parsed = parseVerdict(text);
      if (!parsed.ok) {
        // No retry here: each Copilot request spends premium quota, and the
        // user can always re-run the analysis from the command palette.
        throw new ProviderError(
          `Copilot returned an unparseable verdict: ${parsed.error}`,
          'invalid-response',
        );
      }
      return parsed.verdict;
    } catch (error) {
      if (error instanceof ProviderError) throw error;
      if (signal.aborted) throw new ProviderError('request aborted', 'aborted');
      if (error instanceof vscode.LanguageModelError) {
        const message = error.message.toLowerCase();
        if (message.includes('quota') || message.includes('rate')) {
          throw new ProviderError('Copilot quota exceeded', 'rate-limit');
        }
        if (message.includes('consent') || message.includes('not authorized')) {
          throw new ProviderError('Copilot access was not granted', 'unavailable');
        }
        throw new ProviderError(`Copilot error: ${error.message}`, 'http');
      }
      throw new ProviderError(
        error instanceof Error ? error.message : 'unknown Copilot failure',
        'http',
      );
    } finally {
      signal.removeEventListener('abort', onAbort);
      source.dispose();
    }
  }
}
