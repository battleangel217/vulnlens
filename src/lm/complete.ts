import { parseVerdict, type LlmVerdict } from './verdict';
import { ProviderError } from './types';
import type { AnalyzeRequest } from './types';
import { toMessages, type ChatMessage } from './prompt';

export type Complete = (
  messages: readonly ChatMessage[],
  signal: AbortSignal,
) => Promise<string>;

/**
 * Ask a provider for a verdict and, if the reply is not valid JSON, retry once
 * with the parser's complaint appended. One retry is cheap compared to showing
 * the user a broken diagnostic, and it catches the common "sure, here you go:"
 * preamble without spending a second request every time.
 */
export async function converseForVerdict(
  request: AnalyzeRequest,
  complete: Complete,
  signal: AbortSignal,
): Promise<LlmVerdict> {
  const messages = toMessages(request);

  const first = await complete(messages, signal);
  const parsed = parseVerdict(first);
  if (parsed.ok) return parsed.verdict;

  const retryMessages: ChatMessage[] = [
    ...messages,
    { role: 'assistant', content: first.slice(0, 4000) },
    {
      role: 'user',
      content: `That reply could not be parsed: ${parsed.error}. Reply again with a single JSON object only, matching the contract exactly.`,
    },
  ];

  const second = await complete(retryMessages, signal);
  const retried = parseVerdict(second);
  if (retried.ok) return retried.verdict;

  throw new ProviderError(
    `model did not return a valid verdict (${retried.error})`,
    'invalid-response',
  );
}
