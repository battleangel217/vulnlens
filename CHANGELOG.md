# Changelog

## 0.2.2

- **First-run provider picker.** Running an AI command while
  `vulnLens.ai.mode` is `off` now offers *own API key / Copilot / Ollama /
  settings* instead of sending the user to a settings key. Choosing *own API
  key* prompts for the key immediately.
- Promote GitHub Copilot to Option B in the docs. It is the fastest path for
  people who already have Copilot Chat, and it needs no key.
- Ollama is Option C: the privacy option, but the heaviest to set up.

## 0.2.1

Documentation-only release. No behaviour change.

- Recommend BYOK as the first path, with a worked Groq example. It needs no
  model download and works on any machine; Ollama remains the private option.
- Reorder the provider docs to match: own API key, Ollama, Copilot.
- Update the Marketplace description to match the new order.

## 0.2.0

First packaged release.

### Added

- Deterministic Python rules for CWE-89, CWE-78, CWE-22, CWE-502, CWE-798, and
  CWE-327, running on save with no network access.
- AI verification through Ollama, any OpenAI-compatible BYOK endpoint, or GitHub
  Copilot (dormant unless selected).
- `VulnLens: Suggest Secure Rewrite` for the function under the cursor, with a
  side-by-side preview before the edit is applied.
- Diagnostics, hover text, code actions, and a report command.
- Evaluation harness over a 50-file Python corpus. Rules score 22 TP / 2 FP /
  7 FN (91.7% precision, 75.9% recall).
- Experimental local ONNX triage, off by default.

### Known limitations

- Taint tracking is intraprocedural and single-line.
- The PrimeVul-trained local model does not transfer to Python. It is kept off
  by default; the measured result is in `eval/MODEL_RESULTS.md`.
