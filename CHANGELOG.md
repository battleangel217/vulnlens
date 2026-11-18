# Changelog

## 0.3.0

Headless CLI and code scanning.

- **`vulnlens` CLI.** Scan files or directories with the same rules, no editor
  and no AI layer. Text, JSON, and SARIF output, `--min-severity`,
  `--no-suppressions`, and meaningful exit codes (`0` clean, `1` findings,
  `2` usage error).
- **SARIF 2.1.0** with rule metadata, CWE help links, and 1-based regions, ready
  for `github/codeql-action/upload-sarif`.
- **Composite GitHub Action** (`action.yml`). Runs the scanner on a checkout and
  uploads the report to code scanning. Findings show up under *Security → Code
  scanning alerts*.
- CI smoke-tests the CLI and the SARIF output.

## 0.2.4

Security and trust release.

- **Workspace Trust.** `vulnLens.ai.*`, `vulnLens.ollama.*`,
  `vulnLens.byok.*` and `vulnLens.localModel.*` are restricted in untrusted
  workspaces and fall back to user scope. Previously a repository could set
  `vulnLens.byok.baseUrl` and enable `vulnLens.ai.analyzeOnSave` to send the
  file under review to an arbitrary endpoint without a prompt.
- **CI.** GitHub Actions runs the typecheck, the test suite, and packages the
  VSIX on every push and pull request.
- Add `marketing/checkpoints/` snapshots and version anchors for the launch
  posts. No product change.

## 0.2.3

- Document the first-run provider picker on the Marketplace page: what it
  offers, that it prompts for the key when BYOK is chosen, and that cancelling
  returns the mode to `off`. Documentation only; no behaviour change.

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
