import * as vscode from 'vscode';
import { CopilotProvider } from './copilot';
import { OllamaProvider } from './ollama';
import { OpenAiCompatibleProvider } from './openai';
import type { LlmProvider, ProviderStatus } from './types';

export const API_KEY_SECRET = 'vulnGuard.byok.apiKey';

export type AiMode = 'off' | 'ollama' | 'byok' | 'copilot';

function config(): vscode.WorkspaceConfiguration {
  return vscode.workspace.getConfiguration('vulnGuard');
}

export function aiMode(): AiMode {
  return config().get<AiMode>('ai.mode', 'off');
}

export function ollamaProvider(): LlmProvider {
  return new OllamaProvider({
    baseUrl: config().get<string>('ollama.baseUrl', 'http://127.0.0.1:11434'),
    model: config().get<string>('ollama.model', 'qwen2.5-coder:7b'),
  });
}

export async function byokProvider(secrets: vscode.SecretStorage): Promise<LlmProvider | null> {
  const apiKey = await secrets.get(API_KEY_SECRET);
  if (!apiKey) return null;
  return new OpenAiCompatibleProvider({
    baseUrl: config().get<string>('byok.baseUrl', 'https://api.openai.com/v1'),
    model: config().get<string>('byok.model', 'gpt-4o-mini'),
    apiKey,
  });
}

/**
 * Copilot model selection can show a consent dialog, so it is memoized and only
 * resolved from an explicit user action (`allowPrompt`). Background scans reuse
 * the memoized instance and stay silent when none exists yet.
 */
let copilotInstance: CopilotProvider | null | undefined;

export function resetCopilotInstance(): void {
  copilotInstance = undefined;
}

export async function resolveProvider(
  secrets: vscode.SecretStorage,
  mode: AiMode = aiMode(),
  allowPrompt = false,
): Promise<LlmProvider | null> {
  switch (mode) {
    case 'ollama':
      return ollamaProvider();
    case 'byok':
      return byokProvider(secrets);
    case 'copilot': {
      if (copilotInstance === undefined) {
        if (!allowPrompt) return null;
        copilotInstance = await CopilotProvider.create();
      }
      return copilotInstance;
    }
    default:
      return null;
  }
}

export async function describeProvider(secrets: vscode.SecretStorage): Promise<ProviderStatus> {
  const mode = aiMode();

  if (mode === 'off') {
    return {
      available: false,
      label: 'Off',
      model: '',
      detail:
        'AI verification is off. Set "vulnGuard.ai.mode" to ollama, byok, or copilot to enable it.',
    };
  }

  const provider = await resolveProvider(secrets, mode, true);
  if (provider) return provider.status();

  if (mode === 'byok') {
    return {
      available: false,
      label: 'OpenAI-compatible',
      model: config().get<string>('byok.model', 'gpt-4o-mini'),
      detail: 'No API key stored. Run "VulnGuard: Set API Key (BYOK)".',
    };
  }

  return {
    available: false,
    label: 'GitHub Copilot',
    model: '',
    detail:
      'No Copilot model available. Install GitHub Copilot Chat, sign in, then run the check again. Note: code-oss builds do not include Copilot Chat.',
  };
}
