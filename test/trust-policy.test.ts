import { describe, expect, it } from 'vitest';
import {
  RESTRICTED_IN_UNTRUSTED_WORKSPACES,
  chooseValue,
  isRestrictedInUntrusted,
} from '../src/trust-policy';

describe('workspace trust policy', () => {
  it('restricts every setting that can send code or load a model', () => {
    for (const key of [
      'vulnLens.ai.mode',
      'vulnLens.ai.analyzeOnSave',
      'vulnLens.byok.baseUrl',
      'vulnLens.byok.model',
      'vulnLens.ollama.baseUrl',
      'vulnLens.ollama.model',
      'vulnLens.localModel.enabled',
      'vulnLens.localModel.path',
    ]) {
      expect(isRestrictedInUntrusted(key)).toBe(true);
    }
  });

  it('leaves local display and scan settings alone', () => {
    for (const key of [
      'vulnLens.enable',
      'vulnLens.scanOnOpen',
      'vulnLens.scanOnSave',
      'vulnLens.minSeverity',
    ]) {
      expect(isRestrictedInUntrusted(key)).toBe(false);
    }
  });

  it('declares no duplicates', () => {
    expect(new Set(RESTRICTED_IN_UNTRUSTED_WORKSPACES).size).toBe(
      RESTRICTED_IN_UNTRUSTED_WORKSPACES.length,
    );
  });

  it('uses the effective value in a trusted workspace', () => {
    expect(
      chooseValue(true, 'vulnLens.byok.baseUrl', {
        global: 'https://user.example/v1',
        defaultValue: undefined,
        effective: 'https://workspace.example/v1',
      }, 'https://api.openai.com/v1'),
    ).toBe('https://workspace.example/v1');
  });

  it('ignores a workspace override for a restricted setting when untrusted', () => {
    expect(
      chooseValue(false, 'vulnLens.byok.baseUrl', {
        global: 'https://user.example/v1',
        defaultValue: undefined,
        effective: 'https://attacker.example/v1',
      }, 'https://api.openai.com/v1'),
    ).toBe('https://user.example/v1');
  });

  it('falls back to the declared default when the user has no value', () => {
    expect(
      chooseValue(false, 'vulnLens.ai.mode', {
        global: undefined,
        defaultValue: 'off',
        effective: 'byok',
      }, 'off'),
    ).toBe('off');
  });

  it('falls back to the caller default when nothing is declared', () => {
    expect(
      chooseValue(false, 'vulnLens.ai.timeoutMs', {
        global: undefined,
        defaultValue: undefined,
        effective: 1,
      }, 25_000),
    ).toBe(25_000);
  });

  it('still uses the effective value for unrestricted settings when untrusted', () => {
    expect(
      chooseValue(false, 'vulnLens.minSeverity', {
        global: 'low',
        defaultValue: 'low',
        effective: 'high',
      }, 'low'),
    ).toBe('high');
  });
});
