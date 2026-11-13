import type { Severity } from '../types';
import type { LlmVerdict } from './verdict';

export type ProviderId = 'ollama' | 'byok' | 'copilot';

/** A rule finding, expressed relative to the snippet that will be sent. */
export interface RuleHint {
  readonly cwe: string;
  readonly title: string;
  readonly severity: Severity;
  /** 1-based line number relative to the snippet. */
  readonly line: number;
  readonly message: string;
}

export interface AnalyzeRequest {
  readonly code: string;
  readonly functionName: string;
  readonly ruleHints: readonly RuleHint[];
}

export interface ProviderStatus {
  readonly available: boolean;
  readonly label: string;
  readonly model: string;
  /** Human-readable detail, shown in notifications and the output log. */
  readonly detail: string;
}

export interface LlmProvider {
  readonly id: ProviderId;
  readonly label: string;
  readonly model: string;
  status(): Promise<ProviderStatus>;
  analyze(request: AnalyzeRequest, signal: AbortSignal): Promise<LlmVerdict>;
}

export type ProviderErrorKind = 'unavailable' | 'http' | 'rate-limit' | 'invalid-response' | 'aborted';

export class ProviderError extends Error {
  constructor(
    message: string,
    readonly kind: ProviderErrorKind = 'http',
    readonly status?: number,
  ) {
    super(message);
    this.name = 'ProviderError';
  }
}

export function isAbortError(error: unknown): boolean {
  return (
    error instanceof ProviderError &&
    error.kind === 'aborted'
  ) || (error instanceof Error && error.name === 'AbortError');
}

/** Keeps a failed request from leaking an API key or a wall of text. */
export function describeError(error: unknown): string {
  if (error instanceof ProviderError) return error.message;
  if (error instanceof Error) return error.message;
  return String(error);
}
