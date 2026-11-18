import * as vscode from 'vscode';
import { chooseValue, isRestrictedInUntrusted } from './trust-policy';

/**
 * Read a VulnLens setting, honouring the Workspace Trust policy.
 *
 * `section` is the dotted configuration section (`vulnLens`,
 * `vulnLens.localModel`) and `key` is the leaf name. Restricted settings fall
 * back to user scope when the workspace is untrusted; see `trust-policy.ts`.
 */
export function readSetting<T>(section: string, key: string, fallback: T): T {
  const config = vscode.workspace.getConfiguration(section);
  const qualified = `${section}.${key}`;

  if (vscode.workspace.isTrusted !== false || !isRestrictedInUntrusted(qualified)) {
    return config.get<T>(key, fallback);
  }

  const inspected = config.inspect<T>(key);
  return chooseValue(
    false,
    qualified,
    {
      global: inspected?.globalValue,
      defaultValue: inspected?.defaultValue,
      effective: config.get<T>(key, fallback),
    },
    fallback,
  );
}
